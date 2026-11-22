#!/usr/bin/env python3
"""Attack Exposure Score: agrega la evidencia **local** ya recogida y la puntúa.

No hace ninguna llamada de red: sólo lee los artefactos que el auditor ya tiene
en disco (TSV de ``probe_exposure.py``, JSON de ``secrets_scan.py``, volcados de
cabeceras, JSON de InternetDB / crt.sh, ``dns_mailsec.txt``,
``tls_versions.txt``, JSON de ``js_intel.py``).

Reglas duras del informe:

* **Sin datos no hay puntos.** Si un componente no tiene evidencia, vale 0 y se
  marca ``sin datos``. Nunca se inventa un número.
* Cada línea del informe lleva su **fuente**: ``evidencia: <fichero>`` o
  ``sin datos``.
* Los puntos de bonificación (lo que está bien) sólo se conceden con evidencia
  que los respalde.
* Si no hay ninguna evidencia, la banda es *No evaluable*: un 0 sin datos **no**
  significa «seguro».

Uso::

    python3 attack_surface_report.py --probe-tsv evidencia/probe_exposure.tsv \\
        --secrets-json evidencia/secrets.json --headers evidencia/headers.txt \\
        --out ./informe
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

if __package__ in (None, ""):  # ejecución como script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from header_tls_report import (  # noqa: E402
    HeaderBlock,
    parse_header_dump,
)
from _common_headers import (  # noqa: E402
    CORE_HEADERS,
    core_headers_status,
)

__all__ = ["Component", "build_report", "main", "EXIT_OK", "EXIT_ERROR"]

EXIT_OK = 0
EXIT_ERROR = 2

# --------------------------------------------------------------------------- #
# Pesos
# --------------------------------------------------------------------------- #

#: Puntos por severidad de secreto (secrets_scan).
SECRET_WEIGHT: dict[str, float] = {
    "critico": 6.0,
    "alto": 4.0,
    "medio": 2.0,
    "bajo": 1.0,
    "info": 0.0,
}

#: Puntos por severidad de ruta expuesta (probe_exposure).
PATH_WEIGHT: dict[str, float] = {
    "critico": 5.0,
    "alto": 4.0,
    "medio": 2.0,
    "bajo": 1.0,
    "info": 0.0,
}

#: Puertos administrativos: no se escanean (RoE 1.5), sólo se **describen** los
#: que un tercero ya indexó.
ADMIN_PORTS: frozenset[int] = frozenset(
    {21, 22, 23, 25, 110, 143, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5672,
     5900, 6379, 9200, 9300, 11211, 15672, 27017, 27018, 2375, 2376, 9200,
     8080, 8443, 8000, 8081}
)

#: Huellas de CDN/WAF en las cabeceras.
CDN_HEADERS: tuple[str, ...] = (
    "cf-ray", "cf-cache-status", "x-amz-cf-id", "x-sucuri-id", "x-sucuri-cache",
    "x-vercel-id", "x-nf-request-id", "x-fastly-request-id", "x-akamai-transformed",
    "x-iinfo", "x-cdn-request-id", "x-azure-ref", "x-ms-ref",
)

#: Cabeceras que cuentan como «cabeceras completas»: la lista vive en
#: ``_common_headers`` (compartida con ``header_tls_report.py``) para que ambos
#: scripts informen del mismo número de cabeceras ausentes con la misma
#: evidencia. Se reexporta aquí por compatibilidad.

#: Bandas del índice final.
BANDS: tuple[tuple[float, float, str], ...] = (
    (0, 19.9, "Bajo"),
    (20, 39.9, "Moderado"),
    (40, 59.9, "Alto"),
    (60, 79.9, "Crítico"),
    (80, 100, "Severo"),
)

MAX_BONUS = 30.0


@dataclass
class Component:
    """Un componente del score, con su puntuación y su fuente."""

    key: str
    name: str
    max_points: float
    kind: str  # "riesgo" | "bonificacion"
    justification: str
    source: str = "sin datos"
    points: float = 0.0
    detail: str = ""

    @property
    def has_data(self) -> bool:
        """¿El componente tiene evidencia detrás?"""
        return self.source != "sin datos"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "kind": self.kind,
            "points": round(self.points, 2),
            "max_points": self.max_points,
            "source": self.source,
            "justification": self.justification,
            "detail": self.detail,
            "has_data": self.has_data,
        }


# --------------------------------------------------------------------------- #
# Parseadores de entrada
# --------------------------------------------------------------------------- #


def parse_probe_tsv(path: str | Path) -> list[dict[str, str]]:
    """Lee el TSV de ``probe_exposure.py`` (tolerante al formato)."""
    file_path = Path(path)
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    if not lines:
        return []
    header = lines[0].split("\t")
    if header and header[0].strip().lower() in ("host", "path", "#path"):
        body = lines[1:]
    else:
        body = lines
    rows: list[dict[str, str]] = []
    for line in body:
        if not line.strip():
            continue
        parts = line.split("\t")
        row = {header[i].strip(): parts[i].strip() for i in range(min(len(header), len(parts)))}
        row["_file"] = str(file_path)
        rows.append(row)
    return rows


def load_secrets_json(path: str | Path) -> list[dict[str, Any]]:
    """Lee el JSON de ``secrets_scan.py`` (o una lista de hallazgos)."""
    file_path = Path(path)
    try:
        data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, Mapping):
        findings = data.get("findings", [])
    elif isinstance(data, list):
        findings = data
    else:
        findings = []
    return [f for f in findings if isinstance(f, Mapping)]


def load_header_blocks(path: str | Path) -> list[HeaderBlock]:
    """Lee un volcado de cabeceras y devuelve sus respuestas."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_header_dump(text, source=str(file_path))


def load_json_list(path: str | Path) -> list[dict[str, Any]]:
    """Carga un JSON que debe ser una lista de objetos."""
    file_path = Path(path)
    try:
        data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, Mapping)]
    if isinstance(data, Mapping):
        for key in ("results", "data", "entries"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, Mapping)]
    return []


def parse_dns_sections(path: str | Path) -> dict[str, str]:
    """Divide un fichero ``dns_mailsec.txt`` en secciones ``=== NOMBRE ===``."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    sections: dict[str, str] = {}
    current: str | None = None
    buffer: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^\s*={2,}\s*(.+?)\s*={2,}\s*$", line)
        if match:
            if current is not None:
                sections[current] = "\n".join(buffer).strip()
            current = match.group(1).strip().lower()
            buffer = []
            continue
        if current is not None:
            buffer.append(line)
    if current is not None:
        sections[current] = "\n".join(buffer).strip()
    return sections


def parse_tls_versions(path: str | Path) -> dict[str, bool]:
    """Extrae qué versiones de TLS admite el objetivo.

    Acepta el formato ``-tls1_2 => New, TLSv1.2, ...`` (la salida de un
    ``openssl s_client`` por versión) y el formato ``Protocol: TLSv1.3``.
    """
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    results: dict[str, bool] = {}
    for line in text.splitlines():
        match = re.match(r"^\s*-tls(1|1_1|1_2|1_3)\b\s*=>\s*(.*)$", line)
        if match:
            key = match.group(1).replace("_", ".")
            payload = match.group(2)
            supported = bool(re.search(r"New,\s*TLSv1", payload)) and not re.search(
                r"error:|\(NONE\)", payload
            )
            results[key] = supported
            continue
        match = re.search(r"Protocol:\s*TLSv?(\d(?:\.\d)?)", line)
        if match:
            raw = match.group(1)
            key = raw if "." in raw else f"{raw}.0"
            results[key] = True
    return results


def _version_tuple(value: str) -> tuple[int, ...]:
    """Convierte ``1.22.1`` en ``(1, 22, 1)``."""
    parts = re.findall(r"\d+", value)
    return tuple(int(part) for part in parts) if parts else ()


def detect_stack_versions(blocks: Sequence[HeaderBlock]) -> list[tuple[str, str, float]]:
    """Detecta versiones de stack en las cabeceras y las puntúa por antigüedad.

    La puntuación es un **indicador de antigüedad**, no un CVE verificado: el
    informe lo dice explícitamente para no sobre-afirmar.
    """
    findings: list[tuple[str, str, float]] = []
    seen: set[str] = set()
    for block in blocks:
        for header in ("server", "x-powered-by", "x-aspnet-version"):
            value = block.get(header)
            if not value or value in seen:
                continue
            seen.add(value)
            product, _, version = value.partition("/")
            product = product.strip().lower()
            numbers = _version_tuple(version)
            points = 1.0
            if product == "nginx":
                if numbers < (1, 20):
                    points = 6.0
                elif numbers < (1, 24):
                    points = 4.0
                elif numbers < (1, 26):
                    points = 2.0
            elif product == "php":
                if numbers < (8, 1):
                    points = 5.0
                elif numbers < (8, 3):
                    points = 3.0
            elif product == "apache":
                if numbers < (2, 4, 49):
                    points = 5.0
                elif numbers < (2, 4, 58):
                    points = 3.0
            elif "iis" in product or "microsoft-iis" in product:
                if numbers < (10,):
                    points = 4.0
            findings.append((product, version, points))
    return findings


# --------------------------------------------------------------------------- #
# Construcción del informe
# --------------------------------------------------------------------------- #


def _source(paths: Sequence[str]) -> str:
    """Etiqueta de fuente para un componente con datos."""
    if not paths:
        return "sin datos"
    if len(paths) == 1:
        return f"evidencia: {paths[0]}"
    return "evidencia: " + ", ".join(paths)


def build_report(
    *,
    probe_tsv: Sequence[str] = (),
    secrets_json: Sequence[str] = (),
    headers: Sequence[str] = (),
    internetdb: Sequence[str] = (),
    crtsh: Sequence[str] = (),
    dns_mailsec: Sequence[str] = (),
    tls_versions: Sequence[str] = (),
    js_intel: Sequence[str] = (),
) -> dict[str, Any]:
    """Construye el informe completo (componentes, fórmula, total y banda)."""
    components: list[Component] = []

    # -- carga de la evidencia --------------------------------------------- #
    probe_rows: list[dict[str, str]] = []
    for path in probe_tsv:
        probe_rows.extend(parse_probe_tsv(path))

    secrets: list[dict[str, Any]] = []
    for path in secrets_json:
        secrets.extend(load_secrets_json(path))

    header_blocks: list[HeaderBlock] = []
    for path in headers:
        header_blocks.extend(load_header_blocks(path))

    crt_entries: list[dict[str, Any]] = []
    for path in crtsh:
        crt_entries.extend(load_json_list(path))

    db_entries: list[dict[str, Any]] = []
    for path in internetdb:
        db_entries.extend(load_json_list(path))

    dns_sections: dict[str, str] = {}
    for path in dns_mailsec:
        dns_sections.update(parse_dns_sections(path))

    tls_map: dict[str, bool] = {}
    for path in tls_versions:
        tls_map.update(parse_tls_versions(path))

    js_data: list[dict[str, Any]] = []
    for path in js_intel:
        js_data.extend(load_json_list(path))

    any_evidence = bool(
        probe_rows
        or secrets
        or header_blocks
        or crt_entries
        or db_entries
        or dns_sections
        or tls_map
        or js_data
    )

    # -- 1. Secretos expuestos ---------------------------------------------- #
    component = Component(
        key="secretos_expuestos",
        name="Secretos expuestos",
        max_points=18.0,
        kind="riesgo",
        justification=(
            "Un secreto en un fichero público equivale a una credencial "
            "filtrada: hay que rotarla, no «borrar el fichero»."
        ),
    )
    if secrets:
        total = 0.0
        by_severity: dict[str, int] = {}
        for finding in secrets:
            severity = str(finding.get("severity", "info")).lower()
            by_severity[severity] = by_severity.get(severity, 0) + 1
            total += SECRET_WEIGHT.get(severity, 0.0)
        component.points = min(component.max_points, total)
        component.source = _source(secrets_json)
        component.detail = (
            f"{len(secrets)} hallazgo(s): "
            + ", ".join(
                f"{count} {severity}"
                for severity, count in sorted(by_severity.items())
            )
        )
    else:
        component.detail = "Sin fichero de secretos fourni: no se puntúa."
    components.append(component)

    # -- 2. Ficheros/rutas expuestas ----------------------------------------- #
    component = Component(
        key="ficheros_expuestos",
        name="Ficheros de backup o configuración expuestos",
        max_points=16.0,
        kind="riesgo",
        justification=(
            "Un `.env` o un `.sql` descargable expone credenciales de base de "
            "datos y, en una clínica, datos de pacientes."
        ),
    )
    if probe_rows:
        total = 0.0
        exposed: list[str] = []
        for row in probe_rows:
            verdict = (row.get("verdict") or "").lower()
            severity = (row.get("severity") or "").lower()
            if verdict != "expuesto":
                continue
            total += PATH_WEIGHT.get(severity, 0.0)
            exposed.append(f"{row.get('path', '?')} ({severity})")
        component.points = min(component.max_points, total)
        component.source = _source(probe_tsv)
        component.detail = (
            f"{len(exposed)} ruta(s) expuesta(s): " + ", ".join(exposed[:8])
            if exposed
            else "Ninguna ruta expuesta en la sonda (soft-404 excluidos)."
        )
    else:
        component.detail = "Sin TSV de sonda: no se puntúa."
    components.append(component)

    # -- 3. Versiones del stack --------------------------------------------- #
    component = Component(
        key="versiones_stack",
        name="Versiones de stack potencialmente desactualizadas",
        max_points=12.0,
        kind="riesgo",
        justification=(
            "Una versión visible en la cabecera permite correlacionar CVEs. "
            "**Indicador de antigüedad, no CVE verificado**: hay que "
            "contrastarlo con el NVD y con la versión real del servidor."
        ),
    )
    stack = detect_stack_versions(header_blocks)
    if stack:
        total = sum(points for _, _, points in stack)
        component.points = min(component.max_points, total)
        component.source = _source(headers)
        component.detail = ", ".join(
            f"{product} {version}" for product, version, _ in stack
        )
    else:
        component.detail = "Sin cabeceras o sin versiones visibles: no se puntúa."
    components.append(component)

    # -- 4. Ausencia de WAF/CDN ---------------------------------------------- #
    component = Component(
        key="ausencia_waf_cdn",
        name="Sin CDN/WAF detectable",
        max_points=8.0,
        kind="riesgo",
        justification=(
            "Sin CDN delante, el servidor origen queda expuesto directamente. "
            "Ojo: un CDN no es un WAF, y su ausencia sólo se afirma si hay "
            "cabeceras que lo delaten."
        ),
    )
    if header_blocks:
        detected: list[str] = []
        for block in header_blocks:
            for header in CDN_HEADERS:
                if block.has(header):
                    detected.append(header)
            server = block.get("server").lower()
            if any(marker in server for marker in ("cloudflare", "akamai", "varnish", "fastly")):
                detected.append(f"server: {server}")
        if detected:
            component.points = 0.0
            component.source = _source(headers)
            component.detail = "CDN/WAF detectado: " + ", ".join(sorted(set(detected))[:6])
        else:
            component.points = component.max_points
            component.source = _source(headers)
            component.detail = (
                "Ninguna cabecera de CDN/WAF en las respuestas analizadas "
                f"({len(header_blocks)} respuesta(s))."
            )
    else:
        component.detail = "Sin cabeceras: no se puede afirmar la ausencia."
    components.append(component)

    # -- 5. Superficie de subdominios ----------------------------------------- #
    component = Component(
        key="superficie_subdominios",
        name="Amplitud de la superficie de subdominios",
        max_points=10.0,
        kind="riesgo",
        justification=(
            "Cada subdominio es una puerta de entrada y, en un hosting "
            "multi-tenant, un riesgo de blast radius para otros inquilinos."
        ),
    )
    if crt_entries:
        names: set[str] = set()
        for entry in crt_entries:
            value = entry.get("name_value") or entry.get("name_value") or ""
            for name in re.split(r"[\s,]+", str(value)):
                name = name.strip().lower()
                if name:
                    names.add(name)
        count = len(names)
        if count > 30:
            component.points = 10.0
        elif count > 10:
            component.points = 6.0
        elif count > 3:
            component.points = 3.0
        else:
            component.points = 1.0
        component.source = _source(crtsh)
        component.detail = f"{count} nombre(s) distinto(s) en los certificados CT."
    else:
        component.detail = "Sin datos de Certificate Transparency: no se puntúa."
    components.append(component)

    # -- 6. Puertos administrativos -------------------------------------------- #
    component = Component(
        key="puertos_administrativos",
        name="Puertos administrativos expuestos",
        max_points=8.0,
        kind="riesgo",
        justification=(
            "Puertos de administración visibles desde Internet amplifican la "
            "superficie. Se **describen** (dato de un tercero), no se escanean: "
            "RoE 1.5."
        ),
    )
    if db_entries:
        ports: set[int] = set()
        vulns: list[str] = []
        for entry in db_entries:
            for port in entry.get("ports", []) or []:
                try:
                    ports.add(int(port))
                except (TypeError, ValueError):
                    continue
            vulns.extend(str(v) for v in (entry.get("vulns") or []))
        admin = sorted(p for p in ports if p in ADMIN_PORTS)
        points = min(component.max_points, len(admin) * 2.0 + len(vulns) * 2.0)
        component.points = points
        component.source = _source(internetdb)
        component.detail = (
            f"puertos administrativos: {admin or 'ninguno'}; "
            f"CVE indexados por terceros: {len(vulns)}"
        )
    else:
        component.detail = "Sin datos de InternetDB: no se puntúa."
    components.append(component)

    # -- 7. Ausencia de MFA (deducida) ------------------------------------------ #
    component = Component(
        key="ausencia_mfa",
        name="Ausencia de MFA en la superficie de login",
        max_points=8.0,
        kind="riesgo",
        justification=(
            "Si hay panel de administración accesible y nada apunta a un segundo "
            "factor, la probabilidad de credencial robada es alta. **Deducido, "
            "no verificado**: confirmar con el cliente."
        ),
    )
    login_pattern = re.compile(
        r"(?i)(/admin/?|/wp-admin/?|/wp-login\.php|/login/?|/administrator/?|"
        r"/signin|/panel)"
    )
    mfa_pattern = re.compile(r"(?i)(mfa|2fa|totp|otp|dos\s*factores|second\s*factor)")
    login_paths: list[str] = []
    for row in probe_rows:
        path = row.get("path", "")
        if login_pattern.search(path):
            login_paths.append(path)
    mfa_hints: list[str] = []
    for row in probe_rows:
        if mfa_pattern.search(row.get("path", "")):
            mfa_hints.append(row.get("path", ""))
    for entry in js_data:
        blob = json.dumps(entry, ensure_ascii=False)
        if mfa_pattern.search(blob):
            mfa_hints.append("js_intel")
    if login_paths and not mfa_hints:
        component.points = component.max_points
        component.source = _source(probe_tsv)
        component.detail = (
            "Superficie de login expuesta sin indicios de MFA: "
            + ", ".join(sorted(set(login_paths))[:5])
        )
    elif login_paths and mfa_hints:
        component.points = 0.0
        component.source = _source(list(probe_tsv) + list(js_intel))
        component.detail = "Hay indicios de MFA en la evidencia: no se penaliza."
    else:
        component.detail = (
            "Sin superficie de login en la evidencia: no se puede afirmar la "
            "ausencia de MFA."
        )
    components.append(component)

    # -- 8. Ausencia de logging/monitorización ----------------------------------- #
    component = Component(
        key="ausencia_logging_monitoring",
        name="Ausencia de logging o monitorización detectable",
        max_points=6.0,
        kind="riesgo",
        justification=(
            "Sin registro de accesos, una brecha pasa desapercibida: el tiempo "
            "de detección se convierte en el tiempo de exposición real."
        ),
    )
    monitoring_hints: list[str] = []
    for row in probe_rows:
        if re.search(r"(?i)(log|monitor|grafana|kibana|prometheus|sentry|/metrics)",
                     row.get("path", "")):
            monitoring_hints.append(row.get("path", ""))
    for finding in secrets:
        if "sentry" in str(finding.get("type", "")).lower():
            monitoring_hints.append(str(finding.get("type", "")))
    # Sólo el código y la superficie de la aplicación dicen algo sobre
    # monitorización; un volcado de cabeceras, no.
    app_evidence = bool(probe_rows or secrets or js_data)
    if app_evidence and not monitoring_hints:
        component.points = component.max_points
        component.source = _source(
            list(probe_tsv) + list(secrets_json) + list(js_intel)
        )
        component.detail = (
            "Ningún indicador de logging/monitorización en la evidencia "
            "analizada (no demuestra que no exista: no se deja ver el interior)."
        )
    elif monitoring_hints:
        component.points = 0.0
        component.source = _source(list(probe_tsv) + list(secrets_json))
        component.detail = "Indicadores de monitorización: " + ", ".join(
            sorted(set(monitoring_hints))[:5]
        )
    else:
        component.detail = "Sin evidencia de partida: no se puntúa."
    components.append(component)

    # -- 9. Ausencia de DMARC -------------------------------------------------------- #
    component = Component(
        key="ausencia_dmarc",
        name="Ausencia de DMARC",
        max_points=6.0,
        kind="riesgo",
        justification=(
            "Sin DMARC, un atacante puede enviar correo en nombre de la clínica "
            "con los datos que le robó (suplantación de pacientes y phishing)."
        ),
    )
    dmarc_record = ""
    for section, content in dns_sections.items():
        if "dmarc" in section:
            dmarc_record = content
            break
    dmarc_present = "v=DMARC1" in dmarc_record
    if dmarc_present:
        policy = ""
        match = re.search(r"p=([a-z]+)", dmarc_record, re.IGNORECASE)
        if match:
            policy = match.group(1).lower()
        component.points = 0.0
        component.source = _source(dns_mailsec)
        component.detail = f"DMARC presente (p={policy or 'desconocida'})."
        components.append(component)
        # La bonificación se calcula más abajo con la misma evidencia.
    elif dmarc_record != "" or any("dmarc" in key for key in dns_sections):
        component.points = component.max_points
        component.source = _source(dns_mailsec)
        component.detail = (
            "Sección DMARC presente en el fichero pero sin registro "
            "`v=DMARC1`: la política no está publicada."
        )
    else:
        component.detail = (
            "Sin sección DMARC en la evidencia: no se puede afirmar su ausencia."
        )
    components.append(component)

    # -- 10. Ausencia de CSP/HSTS ---------------------------------------------------- #
    component = Component(
        key="ausencia_csp_hsts",
        name="Ausencia de CSP y HSTS",
        max_points=8.0,
        kind="riesgo",
        justification=(
            "La CSP limita el daño de un XSS; el HSTS impide el descenso a HTTP "
            "en el portal del paciente. Son las dos cabeceras con más retorno."
        ),
    )
    if header_blocks:
        missing: list[str] = []
        for block in header_blocks:
            if not block.has("content-security-policy"):
                missing.append("CSP")
            if not block.has("strict-transport-security"):
                missing.append("HSTS")
        unique_missing = sorted(set(missing))
        component.points = min(component.max_points, 4.0 * len(unique_missing))
        component.source = _source(headers)
        component.detail = (
            "Ausentes en alguna respuesta: " + ", ".join(unique_missing)
            if unique_missing
            else "CSP y HSTS presentes en todas las respuestas analizadas."
        )
    else:
        component.detail = "Sin cabeceras: no se puntúa."
    components.append(component)

    # -- 11. CORS mal configurado ------------------------------------------------------ #
    component = Component(
        key="cors_inseguro",
        name="CORS permisivo",
        max_points=6.0,
        kind="riesgo",
        justification=(
            "Con `Access-Control-Allow-Origin: *` y credenciales, cualquier "
            "sitio puede leer las respuestas de la API del portal de pacientes."
        ),
    )
    if header_blocks:
        points = 0.0
        notes: list[str] = []
        for block in header_blocks:
            origin = block.get("access-control-allow-origin")
            credentials = block.get("access-control-allow-credentials").lower()
            if not origin:
                continue
            if origin.strip() == "*":
                if credentials == "true":
                    points = max(points, 6.0)
                    notes.append("ACAO * con credenciales")
                else:
                    points = max(points, 3.0)
                    notes.append("ACAO *")
            elif origin.strip() == "null":
                points = max(points, 4.0)
                notes.append("ACAO null")
            elif "origin" not in block.get("vary").lower():
                points = max(points, 2.0)
                notes.append("origen específico sin Vary: Origin")
        component.points = min(component.max_points, points)
        component.source = _source(headers)
        component.detail = ", ".join(sorted(set(notes))) or "CORS no permisivo."
    else:
        component.detail = "Sin cabeceras: no se puntúa."
    components.append(component)

    # -- 12. TLS débil ------------------------------------------------------------------- #
    component = Component(
        key="tls_debil",
        name="Versiones de TLS obsoletas admitidas",
        max_points=8.0,
        kind="riesgo",
        justification=(
            "TLS 1.0/1.1 están roto por diseño (BEAST, POODLE). En un portal "
            "que transporta expedientes, no es negociable."
        ),
    )
    if tls_map:
        legacy = [v for v in ("1.0", "1.1") if tls_map.get(v)]
        modern = [v for v in ("1.2", "1.3") if tls_map.get(v)]
        if legacy:
            component.points = component.max_points
        elif not modern:
            component.points = component.max_points
        elif modern == ["1.2"]:
            component.points = 3.0
        component.source = _source(tls_versions)
        component.detail = "Versiones detectadas: " + ", ".join(
            sorted(v for v, ok in tls_map.items() if ok)
        )
    else:
        component.detail = "Sin datos de versiones TLS: no se puntúa."
    components.append(component)

    # -- 13. Cookies inseguras ---------------------------------------------------------- #
    component = Component(
        key="cookies_inseguras",
        name="Cookies sin los atributos de seguridad",
        max_points=6.0,
        kind="riesgo",
        justification=(
            "Una cookie de sesión sin `Secure`/`HttpOnly`/`SameSite` se puede "
            "filtrar, leer desde JavaScript o enviar en peticiones cross-site."
        ),
    )
    if header_blocks:
        insecure = 0
        names: list[str] = []
        for block in header_blocks:
            for raw in block.set_cookies:
                lowered = raw.lower()
                problems = (
                    ("secure" not in lowered)
                    + ("httponly" not in lowered)
                    + ("samesite" not in lowered)
                )
                if problems:
                    insecure += 1
                    names.append(raw.split("=", 1)[0].strip() or "(cookie)")
        component.points = min(component.max_points, insecure * 2.0)
        component.source = _source(headers)
        component.detail = (
            f"{insecure} cookie(s) sin atributos completos: {', '.join(sorted(set(names))[:6])}"
            if insecure
            else "Todas las cookies analyzed llevan Secure/HttpOnly/SameSite."
        )
    else:
        component.detail = "Sin cabeceras: no se puntúa."
    components.append(component)

    # ================================================================== #
    # Bonificaciones (lo que está bien)
    # ================================================================== #

    bonus_components: list[Component] = []

    component = Component(
        key="cookies_seguras",
        name="Cookies con Secure + HttpOnly + SameSite",
        max_points=8.0,
        kind="bonificacion",
        justification="Cada cookie bien marcada reduce una vía de fuga real.",
    )
    if header_blocks:
        total_cookies = 0
        good_cookies = 0
        for block in header_blocks:
            for raw in block.set_cookies:
                total_cookies += 1
                lowered = raw.lower()
                if (
                    "secure" in lowered
                    and "httponly" in lowered
                    and "samesite" in lowered
                ):
                    good_cookies += 1
        if total_cookies:
            ratio = good_cookies / total_cookies
            component.points = -round(component.max_points * ratio)
            component.source = _source(headers)
            component.detail = f"{good_cookies}/{total_cookies} cookie(s) bien configuradas."
    else:
        component.detail = "Sin cabeceras: sin bonificación."
    bonus_components.append(component)

    component = Component(
        key="tls_fuerte",
        name="TLS 1.3 disponible y sin versiones legacy",
        max_points=6.0,
        kind="bonificacion",
        justification="Modernizar el transporte es la medida de mejor coste/beneficio.",
    )
    if tls_map:
        legacy = [v for v in ("1.0", "1.1") if tls_map.get(v)]
        if tls_map.get("1.3") and not legacy:
            component.points = -component.max_points
        elif tls_map.get("1.2") and not legacy and not tls_map.get("1.3"):
            component.points = -3.0
        component.source = _source(tls_versions)
        component.detail = "Versiones: " + ", ".join(
            sorted(v for v, ok in tls_map.items() if ok)
        )
    else:
        component.detail = "Sin datos de TLS: sin bonificación."
    bonus_components.append(component)

    component = Component(
        key="sri_presente",
        name="SRI en todos los scripts externos",
        max_points=4.0,
        kind="bonificacion",
        justification=(
            "Con `integrity`, un CDN comprometido no puede inyectar código en "
            "el portal del paciente."
        ),
    )
    if js_data:
        external = 0
        with_sri = 0
        for entry in js_data:
            for script in entry.get("scripts", []) or []:
                if not isinstance(script, Mapping):
                    continue
                if script.get("src"):
                    external += 1
                    if script.get("sri"):
                        with_sri += 1
        if external:
            ratio = with_sri / external
            component.points = -round(component.max_points * ratio)
            component.source = _source(js_intel)
            component.detail = f"{with_sri}/{external} script(s) externos con SRI."
    else:
        component.detail = "Sin datos de js_intel: sin bonificación."
    bonus_components.append(component)

    component = Component(
        key="cabeceras_completas",
        name="Cabeceras de seguridad completas",
        max_points=8.0,
        kind="bonificacion",
        justification=(
            "Tener las cabeceras base presentes es la línea base razonable de "
            "cualquier portal que maneje datos de pacientes."
        ),
    )
    if header_blocks:
        present = 0
        total = 0
        missing_total = 0
        for block in header_blocks:
            status = core_headers_status(block.has)
            total += status["total"]
            present += len(status["present"])
            missing_total += status["missing_count"]
        if total:
            ratio = present / total
            component.points = -round(component.max_points * ratio)
            component.source = _source(headers)
            component.detail = (
                f"{present}/{total} cabeceras base presentes "
                f"({missing_total} ausente(s))."
            )
    else:
        component.detail = "Sin cabeceras: sin bonificación."
    bonus_components.append(component)

    component = Component(
        key="dmarc_presente",
        name="DMARC con política activa",
        max_points=4.0,
        kind="bonificacion",
        justification="Una política DMARC restrictiva corta el phishing de marca.",
    )
    if dmarc_present:
        match = re.search(r"p=([a-z]+)", dmarc_record, re.IGNORECASE)
        policy = match.group(1).lower() if match else ""
        component.points = -4.0 if policy == "reject" else (-3.0 if policy == "quarantine" else -1.0)
        component.source = _source(dns_mailsec)
        component.detail = f"DMARC con p={policy or 'none'}."
    else:
        component.detail = "Sin DMARC publicado: sin bonificación."
    bonus_components.append(component)

    component = Component(
        key="sin_secretos_criticos",
        name="Sin secretos críticos en el código",
        max_points=4.0,
        kind="bonificacion",
        justification="La ausencia de credenciales en el código es una buena señal.",
    )
    if secrets:
        critical = sum(
            1
            for finding in secrets
            if str(finding.get("severity", "")).lower() == "critico"
        )
        if critical == 0:
            component.points = -component.max_points
        component.source = _source(secrets_json)
        component.detail = f"{critical} secreto(s) crítico(s) en la evidencia."
    else:
        component.detail = "Sin datos de secretos: sin bonificación."
    bonus_components.append(component)

    components.extend(bonus_components)

    # ================================================================== #
    # Fórmula
    # ================================================================== #

    risk_points = sum(c.points for c in components if c.kind == "riesgo")
    risk_max = sum(c.max_points for c in components if c.kind == "riesgo")
    bonus_points = sum(c.points for c in components if c.kind == "bonificacion")
    bonus_abs = max(0.0, min(-bonus_points, MAX_BONUS))
    raw_total = risk_points - bonus_abs
    total = max(0.0, min(100.0, raw_total))

    band = "No evaluable (sin evidencia)"
    for low, high, label in BANDS:
        if low <= total <= high:
            band = label
            break

    coverage = {
        "probe_tsv": list(probe_tsv),
        "secrets_json": list(secrets_json),
        "headers": list(headers),
        "internetdb": list(internetdb),
        "crtsh": list(crtsh),
        "dns_mailsec": list(dns_mailsec),
        "tls_versions": list(tls_versions),
        "js_intel": list(js_intel),
    }

    return {
        "tool": "attack_surface_report",
        "score": round(total, 1),
        "band": band,
        "evaluable": any_evidence,
        "formula": {
            "risk_points": round(risk_points, 2),
            "risk_max": round(risk_max, 2),
            "bonus_points": round(bonus_abs, 2),
            "bonus_max": MAX_BONUS,
            "raw": round(raw_total, 2),
            "total": round(total, 1),
            "expression": (
                f"total = min(100, max(0, {risk_points:.1f} (riesgo) "
                f"− {bonus_abs:.1f} (bonificación))"
            ),
        },
        "components": [component.to_dict() for component in components],
        "coverage": coverage,
        "any_evidence": any_evidence,
    }


# --------------------------------------------------------------------------- #
# Informe Markdown
# --------------------------------------------------------------------------- #


def render_markdown(report: Mapping[str, Any]) -> str:
    """Genera el informe en Markdown."""
    lines: list[str] = ["# Attack Exposure Score", ""]
    score = report["score"]
    band = report["band"]
    lines.append(f"## Índice: **{score}/100** — banda **{band}**")
    lines.append("")

    formula = report["formula"]
    lines.append("### Fórmula")
    lines.append("")
    lines.append("```")
    lines.append(
        f"total = min(100, max(0, {formula['risk_points']:.1f} "
        f"[riesgo, máx {formula['risk_max']:.0f}] "
        f"− {formula['bonus_points']:.1f} [bonificación, máx {formula['bonus_max']:.0f}]) "
        f"= {formula['total']:.1f}"
    )
    lines.append("```")
    lines.append("")

    if not report.get("evaluable"):
        lines.append(
            "> ⚠️ **No hay evidencia.** Un 0 aquí **no** significa «seguro»: "
            "significa que no hay nada que puntuar. Recoge evidencia "
            "(sonda, secretos, cabeceras) y vuelve a ejecutar."
        )
        lines.append("")

    lines.append("### Desglose por componente")
    lines.append("")
    lines.append("| Componente | Puntos | Máx | Fuente | Justificación |")
    lines.append("|---|---|---|---|---|")
    for component in report["components"]:
        kind = "riesgo" if component["kind"] == "riesgo" else "bonif."
        lines.append(
            "| {name} | {points:+.1f} ({kind}) | {max:.0f} | {source} | {just} |".format(
                name=component["name"],
                points=component["points"],
                kind=kind,
                max=component["max_points"],
                source=component["source"],
                just=component["justification"],
            )
        )
    lines.append("")

    lines.append("### Detalle de cada componente")
    lines.append("")
    for component in report["components"]:
        lines.append(f"- **{component['name']}** ({component['points']:+.1f} puntos)")
        lines.append(f"  - Fuente: {component['source']}")
        if component["detail"]:
            lines.append(f"  - Observación: {component['detail']}")
    lines.append("")

    lines.append("### Cobertura de la evidencia")
    lines.append("")
    lines.append("| Entrada | Ficheros |")
    lines.append("|---|---|")
    for key, paths in report["coverage"].items():
        rendered = ", ".join(f"`{p}`" for p in paths) if paths else "_sin datos_"
        lines.append(f"| {key} | {rendered} |")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*Score calculado exclusivamente a partir de evidencia local ya "
        "recogida. Los componentes sin evidencia valen 0 y no se inventan "
        "números. Este índice no sustituye al juicio profesional del auditor.*"
    )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack_surface_report.py",
        description=(
            "Agrega la evidencia local (sonda, secretos, cabeceras, InternetDB, "
            "crt.sh, DNS/DMARC, TLS, js_intel) y produce el Attack Exposure "
            "Score en Markdown + JSON. No hace ninguna llamada de red."
        ),
        epilog=(
            "Ejemplo:\n"
            "  python3 attack_surface_report.py \\\n"
            "      --probe-tsv evidencia/probe_exposure.tsv \\\n"
            "      --secrets-json evidencia/secrets.json \\\n"
            "      --headers evidencia/headers.txt \\\n"
            "      --out ./informe\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--probe-tsv",
        action="append",
        default=[],
        help="TSV de probe_exposure.py (repetible).",
    )
    parser.add_argument(
        "--secrets-json",
        action="append",
        default=[],
        help="JSON de secrets_scan.py (repetible).",
    )
    parser.add_argument(
        "--headers",
        action="append",
        default=[],
        help="Volcado de cabeceras HTTP (repetible).",
    )
    parser.add_argument(
        "--internetdb",
        action="append",
        default=[],
        help="JSON de Shodan InternetDB (repetible).",
    )
    parser.add_argument(
        "--crtsh",
        action="append",
        default=[],
        help="JSON de crt.sh (repetible).",
    )
    parser.add_argument(
        "--dns-mailsec",
        action="append",
        default=[],
        help="Fichero dns_mailsec.txt (repetible).",
    )
    parser.add_argument(
        "--tls-versions",
        action="append",
        default=[],
        help="Fichero tls_versions.txt (repetible).",
    )
    parser.add_argument(
        "--js-intel",
        action="append",
        default=[],
        help="JSON de js_intel.py (repetible).",
    )
    parser.add_argument(
        "--out",
        metavar="DIR",
        default=None,
        help="Directorio donde escribir el informe (.md y .json).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida en JSON por pantalla.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    missing: list[str] = []
    for label, paths in (
        ("--probe-tsv", args.probe_tsv),
        ("--secrets-json", args.secrets_json),
        ("--headers", args.headers),
        ("--internetdb", args.internetdb),
        ("--crtsh", args.crtsh),
        ("--dns-mailsec", args.dns_mailsec),
        ("--tls-versions", args.tls_versions),
        ("--js-intel", args.js_intel),
    ):
        for path in paths:
            if not Path(path).exists():
                missing.append(f"{label}: {path}")
    if missing:
        for item in missing:
            print(f"AVISO: entrada no encontrada, se ignora — {item}", file=sys.stderr)

    report = build_report(
        probe_tsv=args.probe_tsv,
        secrets_json=args.secrets_json,
        headers=args.headers,
        internetdb=args.internetdb,
        crtsh=args.crtsh,
        dns_mailsec=args.dns_mailsec,
        tls_versions=args.tls_versions,
        js_intel=args.js_intel,
    )
    markdown = render_markdown(report)

    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "attack_surface_report.md").write_text(markdown, encoding="utf-8")
        (out_dir / "attack_surface_report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(markdown)
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
