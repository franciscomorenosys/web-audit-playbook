#!/usr/bin/env python3
"""Sonda de exposición de ficheros y rutas sensibles (sólo GET/HEAD).

Herramienta de **tasa baja**: recorre una lista corta y fija de rutas conocidas
—no hace fuzzing, no enumera, no fuerza bruta— contra los hosts que aparecen en
el fichero de autorización firmado.

Garantías:

* Todo el tráfico pasa por :mod:`scope_guard`: sin autorización válida, **no hay
  petición**. Si un host no está en el allowlist, se aborta.
* Sólo ``GET`` (o ``HEAD`` con ``--head``). Nunca POST/PUT/PATCH/DELETE.
* Intervalo mínimo de 1 s entre peticiones y User-Agent honesto.
* **El cuerpo de las rutas sensibles no se guarda nunca.** Sólo se almacenan los
  cuerpos de las rutas seguras (robots.txt, sitemap.xml, security.txt) y sólo si
  se piden explícitamente.
* Detección de *soft-404*: si la respuesta tiene el mismo ``sha256`` que la
  página 404 de referencia, la ruta se marca ``soft_404`` y **no** cuenta como
  exposición. Sin esto, cualquier sitio que devuelva la misma página de error
  para todo genera cientos de falsos positivos.
* **Lectura acotada y declarada**: ``length`` son los **bytes leídos** (tope
  ``max_bytes``, 1 MB por defecto), no el tamaño real del fichero. El tamaño
  que declara el servidor va aparte en ``content_length_header`` (alias
  ``length_reported``) y ``truncated`` dice si la lectura quedó incompleta. Si
  además la ruta está expuesta, el veredicto es ``exposed_truncated``: el
  fichero es **mayor** de lo que se leyó.

Uso::

    python3 probe_exposure.py --authorization auth.json --host www.ejemplo.mx
    python3 probe_exposure.py -a auth.json --host www.ejemplo.mx --out ./evidencia
    python3 probe_exposure.py -a auth.json --host www.ejemplo.mx --json
    python3 probe_exposure.py -a auth.json --host www.ejemplo.mx --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

if __package__ in (None, ""):  # ejecución como script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from scope_guard import (  # noqa: E402  (import tras ajuste de sys.path)
    EXIT_CONFIG,
    EXIT_OK,
    EXIT_VIOLATION,
    MIN_INTERVAL_FLOOR,
    AuthorizationError,
    FetchError,
    Guard,
    ScopeViolation,
)

__all__ = [
    "DEFAULT_PATHS",
    "PathProfile",
    "probe",
    "EXIT_OK",
    "EXIT_VIOLATION",
    "EXIT_CONFIG",
]

# --------------------------------------------------------------------------- #
# Catálogo de rutas
# --------------------------------------------------------------------------- #

#: Rutas por defecto con su severidad intrínseca si se encuentran expuestas.
#: Lista **fija y corta**: esto no es un escáner de rutas, es una sonda de
#: exposición sobre rutas conocidas (RoE: nada de fuzzing).
DEFAULT_PATHS: tuple[tuple[str, str], ...] = (
    # --- Ficheros de entorno y configuración -------------------------------- #
    ("/.env", "critico"),
    ("/.env.local", "critico"),
    ("/.env.production", "critico"),
    ("/.env.development", "critico"),
    # --- Control de versiones --------------------------------------------- #
    ("/.git/HEAD", "critico"),
    ("/.git/config", "critico"),
    ("/.svn/entries", "alto"),
    ("/.hg/requires", "alto"),
    # --- Ruido del sistema operativo --------------------------------------- #
    ("/.DS_Store", "bajo"),
    # --- Copias de seguridad y volcados -------------------------------------- #
    ("/backup.zip", "critico"),
    ("/backup.tar.gz", "critico"),
    ("/db.sql", "critico"),
    ("/dump.sql", "critico"),
    ("/wp-config.php.bak", "critico"),
    ("/wp-config.php~", "critico"),
    ("/config.php.bak", "alto"),
    # --- Servidor web ------------------------------------------------------- #
    ("/.htaccess", "alto"),
    ("/web.config", "alto"),
    ("/config.json", "alto"),
    # --- Paquetes y dependencias --------------------------------------------- #
    ("/package.json", "bajo"),
    ("/composer.lock", "bajo"),
    ("/package-lock.json", "bajo"),
    ("/yarn.lock", "bajo"),
    # --- Documentación de API ------------------------------------------------ #
    ("/swagger.json", "medio"),
    ("/openapi.json", "medio"),
    ("/api-docs", "medio"),
    ("/swagger-ui/", "medio"),
    ("/graphql", "medio"),
    ("/graphiql", "medio"),
    ("/graphql/playground", "medio"),
    # --- Endpoints de diagnóstico (Spring Boot, PHP, .NET) -------------------- #
    ("/actuator/env", "critico"),
    ("/actuator/health", "medio"),
    ("/actuator/mappings", "medio"),
    ("/server-status", "medio"),
    ("/phpinfo.php", "critico"),
    # --- Paneles de administración -------------------------------------------- #
    ("/admin/", "medio"),
    ("/administrator/", "medio"),
    ("/wp-admin/", "medio"),
    ("/phpmyadmin/", "medio"),
    ("/adminer.php", "medio"),
    # --- Ficheros públicos de referencia ---------------------------------------- #
    ("/.well-known/security.txt", "bajo"),
    ("/security.txt", "bajo"),
    ("/sitemap.xml", "bajo"),
    ("/robots.txt", "bajo"),
    ("/crossdomain.xml", "bajo"),
    ("/clientaccesspolicy.xml", "bajo"),
    # --- Diagnóstico y monitorización ---------------------------------------------- #
    ("/elmah.axd", "medio"),
    ("/trace.axd", "medio"),
    ("/metrics", "medio"),
    ("/health", "bajo"),
    # --- API genérica ------------------------------------------------------------- #
    ("/api/", "bajo"),
    ("/api/v1/", "bajo"),
    ("/api/v2/", "bajo"),
)

#: Rutas cuyo cuerpo **sí** se guarda en la evidencia (son públicas por
#: definición y no contienen datos de pacientes).
SAFE_BODY_PATHS: frozenset[str] = frozenset(
    {
        "/robots.txt",
        "/sitemap.xml",
        "/security.txt",
        "/.well-known/security.txt",
    }
)

TSV_HEADER = (
    "host\tpath\tcode\tcontent_type\tlength\tcontent_length_header\tsha256\t"
    "soft_404\ttruncated\tverdict\tseverity"
)

#: Veredictos que cuentan como «la ruta está expuesta».
EXPOSED_VERDICTS: frozenset[str] = frozenset({"expuesto", "exposed_truncated"})


@dataclass(frozen=True)
class PathProfile:
    """Ruta a sondear con su severidad intrínseca."""

    path: str
    severity: str

    @property
    def stores_body(self) -> bool:
        """¿Su cuerpo puede guardarse en la evidencia?"""
        return self.path in SAFE_BODY_PATHS


@dataclass
class ProbeResult:
    """Resultado de sondear una ruta.

    Ojo con ``length``: es el **número de bytes leídos**, no el tamaño real
    del fichero. Con ``max_bytes`` (1 MB por defecto) una copia de seguridad de
    48 MB aparece como ``length=1000000`` y su ``sha256`` es el del primer
    megabyte. El tamaño **declarado** por el servidor va aparte, en
    :attr:`content_length_header` (alias :attr:`length_reported`), y
    :attr:`truncated` dice si la lectura se cortó por el tope.
    """

    host: str
    path: str
    code: int
    content_type: str
    length: int
    sha256: str
    soft_404: bool
    verdict: str
    severity: str
    final_url: str = ""
    error: str = ""
    body_saved: str = ""
    #: ``Content-Length`` declarado por el servidor (``None`` si no viene).
    content_length_header: int | None = None
    #: ¿Se alcanzó ``max_bytes`` y la lectura quedó incompleta?
    truncated: bool = False

    @property
    def length_reported(self) -> int | None:
        """Tamaño **declarado** por el servidor (alias de ``content_length_header``)."""
        return self.content_length_header

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "path": self.path,
            "code": self.code,
            "content_type": self.content_type,
            "length": self.length,
            "content_length_header": self.content_length_header,
            "length_reported": self.length_reported,
            "sha256": self.sha256,
            "soft_404": self.soft_404,
            "truncated": self.truncated,
            "verdict": self.verdict,
            "severity": self.severity,
            "final_url": self.final_url,
            "error": self.error,
            "body_saved": self.body_saved,
        }


# --------------------------------------------------------------------------- #
# Lógica de veredicto
# --------------------------------------------------------------------------- #


def _parse_content_length(value: str) -> int | None:
    """Interpreta el ``Content-Length`` declarado por el servidor.

    Devuelve ``None`` si la cabecera no viene o no es un entero válido (un
    servidor puede mandar cualquier cosa; no vale la pena mentir en el
    informe).
    """
    text = (value or "").strip()
    if not text:
        return None
    try:
        number = int(text)
    except ValueError:
        return None
    return number if number >= 0 else None


def classify(
    code: int,
    sha256: str,
    fingerprint: str | None,
    is_head: bool,
    truncated: bool = False,
) -> tuple[str, bool]:
    """Determina el veredicto de una respuesta.

    Devuelve ``(verdict, soft_404)``.

    Si la lectura quedó **truncada** por ``max_bytes`` y la ruta está
    expuesta, el veredicto es ``exposed_truncated``: el fichero es **mayor**
    de lo que se leyó y el auditor tiene que saberlo antes de dar el
    hallazgo por cerrado.
    """
    if fingerprint is not None and not is_head and sha256 == fingerprint:
        # Mismo cuerpo que la página 404 de referencia → NO es una exposición.
        if code in (200, 201, 204):
            return "soft_404", True
    if 200 <= code < 300:
        return ("exposed_truncated" if truncated else "expuesto"), False
    if code in (401, 403):
        return "protegido", False
    if code == 404:
        return "no_encontrado", False
    if code in (301, 302, 303, 307, 308):
        return "redireccion", False
    if 500 <= code < 600:
        return "error_servidor", False
    return "otro", False


def _sanitise_for_filename(path: str) -> str:
    """Convierte una ruta en un nombre de fichero seguro."""
    cleaned = path.strip("/").replace("/", "_") or "raiz"
    cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in cleaned)
    return cleaned[:120]


# --------------------------------------------------------------------------- #
# Sonda
# --------------------------------------------------------------------------- #


def probe(
    guard: Guard,
    hosts: Sequence[str],
    profiles: Sequence[PathProfile],
    *,
    method: str = "GET",
    scheme: str = "https",
    port: int | None = None,
    delay: float = 1.0,
    evidence_dir: Path | None = None,
    store_bodies: Iterable[str] = (),
    verbose: bool = True,
) -> list[ProbeResult]:
    """Ejecuta la sonda contra los hosts indicados.

    Lanza :class:`ScopeViolation` si algún host no está autorizado (abortando
    antes de la primera petición).
    """
    method = method.upper()
    is_head = method == "HEAD"
    extra_store = {p.strip() for p in store_bodies}

    # El intervalo efectivo nunca baja del suelo del RoE (1 s).
    guard.min_interval_s = max(guard.min_interval_s, delay, MIN_INTERVAL_FLOOR)

    suffix = f":{port}" if port else ""

    # Validación previa: si un host no está autorizado, se aborta ANTES de
    # hacer ninguna petición.
    for host in hosts:
        guard.check(f"{scheme}://{host}{suffix}/", "GET")

    results: list[ProbeResult] = []
    for host in hosts:
        base = f"{scheme}://{host}{suffix}"

        # -- referencia 404 (una petición por host) ---------------------------- #
        # La referencia sirve para dos casos de *soft-404*:
        #   a) el servidor devuelve 404 de verdad → la huella es la de ese 404;
        #   b) el servidor devuelve 200 con la misma página de "no encontrado"
        #      para todo (catch-all) → la huella es la de ese cuerpo.
        fingerprint: str | None = None
        reference_path = "/__audit_soft404_ref_404_probe"
        try:
            reference = guard.fetch(base + reference_path, method="GET")
            if reference.status in (200, 404) and reference.body:
                fingerprint = reference.sha256
            elif verbose:
                print(
                    f"[probe] AVISO: {host} devolvió {reference.status} para la "
                    f"referencia 404; la detección de soft-404 queda desactivada "
                    "para este host.",
                    file=sys.stderr,
                )
        except ScopeViolation:
            raise
        except FetchError as exc:
            if verbose:
                print(f"[probe] AVISO: no se pudo obtener la referencia 404 de "
                      f"{host}: {exc}", file=sys.stderr)

        for profile in profiles:
            url = f"{base}{profile.path}"
            try:
                response = guard.fetch(url, method=method, allow_redirects=False)
            except ScopeViolation:
                raise
            except FetchError as exc:
                results.append(
                    ProbeResult(
                        host=host,
                        path=profile.path,
                        code=0,
                        content_type="",
                        length=0,
                        sha256="",
                        soft_404=False,
                        verdict="error_conexion",
                        severity="info",
                        error=str(exc),
                    )
                )
                continue

            verdict, soft_404 = classify(
                response.status,
                response.sha256,
                fingerprint,
                is_head,
                truncated=response.truncated,
            )
            severity = profile.severity if verdict in EXPOSED_VERDICTS else "info"
            content_length = _parse_content_length(
                response.headers.get("content-length", "")
            )

            body_saved = ""
            if (
                evidence_dir is not None
                and not is_head
                and (profile.stores_body or profile.path in extra_store)
                and verdict in EXPOSED_VERDICTS
            ):
                body_dir = evidence_dir / "bodies" / host
                body_dir.mkdir(parents=True, exist_ok=True)
                body_path = body_dir / f"{_sanitise_for_filename(profile.path)}.txt"
                body_path.write_bytes(response.body)
                body_saved = str(body_path)

            results.append(
                ProbeResult(
                    host=host,
                    path=profile.path,
                    code=response.status,
                    content_type=response.content_type,
                    length=len(response.body),
                    sha256=response.sha256[:12],
                    soft_404=soft_404,
                    verdict=verdict,
                    severity=severity,
                    final_url=response.final_url,
                    body_saved=body_saved,
                    content_length_header=content_length,
                    truncated=response.truncated,
                )
            )
            if verbose:
                marker = "!!" if verdict in EXPOSED_VERDICTS else "  "
                print(
                    f"[probe] {marker} {host}{profile.path} → {response.status} "
                    f"{response.content_type or '-'} {len(response.body)}B "
                    f"{verdict}",
                    file=sys.stderr,
                )
    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="probe_exposure.py",
        description=(
            "Sonda de exposición de rutas sensibles con GET (o HEAD). Requiere "
            "un fichero de autorización firmado; fuera del allowlist no se hace "
            "ninguna petición."
        ),
        epilog=(
            "Ejemplos:\n"
            "  python3 probe_exposure.py -a auth.json --host www.ejemplo.mx\n"
            "  python3 probe_exposure.py -a auth.json --host www.ejemplo.mx --out ./evidencia\n"
            "  python3 probe_exposure.py -a auth.json --host www.ejemplo.mx --path-list rutas.txt\n"
            "  python3 probe_exposure.py -a auth.json --host www.ejemplo.mx --dry-run\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-a",
        "--authorization",
        required=True,
        help="Ruta del JSON de autorización firmado.",
    )
    parser.add_argument(
        "--host",
        action="append",
        default=[],
        help="Host a sondear (repetible). Debe estar en el allowlist.",
    )
    parser.add_argument(
        "--path-list",
        metavar="FILE",
        default=None,
        help="Fichero con la lista de rutas (una por línea). Si se omite, se usa "
        "la lista por defecto.",
    )
    parser.add_argument(
        "--scheme",
        default="https",
        choices=["https", "http"],
        help="Esquema base (por defecto https).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=(
            "Puerto no estándar (por defecto, el del esquema). Útil para "
            "servidores de pruebas locales."
        ),
    )
    parser.add_argument(
        "--head",
        action="store_true",
        help="Usar HEAD en lugar de GET (no se guarda ningún cuerpo).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help=(
            "Segundos entre peticiones (por defecto 1.0). El valor efectivo "
            "nunca baja de 1 s ni del mínimo del fichero de autorización."
        ),
    )
    parser.add_argument(
        "--out",
        metavar="DIR",
        default=None,
        help="Directorio de evidencia (TSV + JSON + cuerpos seguros).",
    )
    parser.add_argument(
        "--also-store",
        action="append",
        default=[],
        metavar="RUTA",
        help="Ruta adicional cuyo cuerpo sí se guarda. Repetible.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra el plan de sondeo (hosts y rutas) y sale SIN hacer peticiones.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida en JSON.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="No escribir el progreso por stderr.",
    )
    return parser


def _load_profiles(path_list: str | None) -> list[PathProfile]:
    """Carga la lista de rutas (propia o por defecto)."""
    if not path_list:
        return [PathProfile(path=path, severity=severity) for path, severity in DEFAULT_PATHS]
    file_path = Path(path_list)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AuthorizationError(
            f"No se puede leer la lista de rutas '{file_path}': {exc}"
        ) from exc
    profiles: list[PathProfile] = []
    for line in raw.splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        severity = "medio"
        parts = text.split()
        if len(parts) == 2 and parts[1].lower() in {
            "critico", "alto", "medio", "bajo",
        }:
            text, severity = parts[0], parts[1].lower()
        if not text.startswith("/"):
            text = "/" + text
        profiles.append(PathProfile(path=text, severity=severity))
    if not profiles:
        raise AuthorizationError(f"La lista de rutas '{file_path}' está vacía.")
    return profiles


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        guard = Guard.from_file(args.authorization)
        profiles = _load_profiles(args.path_list)
    except AuthorizationError as exc:
        print(f"ERROR DE CONFIGURACIÓN: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    hosts = list(dict.fromkeys(args.host))
    if not hosts:
        hosts = guard.concrete_hosts
    if not hosts:
        print(
            "ERROR DE CONFIGURACIÓN: no hay hosts concretos que sondear. Indica "
            "--host o añade hosts sin comodín a la autorización.",
            file=sys.stderr,
        )
        return EXIT_CONFIG

    if args.dry_run:
        payload = {
            "tool": "probe_exposure",
            "dry_run": True,
            "hosts": hosts,
            "paths": [{"path": p.path, "severity": p.severity} for p in profiles],
            "method": "HEAD" if args.head else "GET",
            "authorization": guard.authorization.to_dict(),
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Plan de sondeo ({len(hosts)} host(s) × {len(profiles)} rutas):")
            for host in hosts:
                print(f"  {host}")
                for profile in profiles:
                    print(f"    {profile.path} ({profile.severity})")
            print("Dry-run: no se ha realizado ninguna petición.")
        return EXIT_OK

    evidence_dir = Path(args.out) if args.out else None
    if evidence_dir:
        evidence_dir.mkdir(parents=True, exist_ok=True)

    try:
        results = probe(
            guard,
            hosts,
            profiles,
            method="HEAD" if args.head else "GET",
            scheme=args.scheme,
            port=args.port,
            delay=args.delay,
            evidence_dir=evidence_dir,
            store_bodies=args.also_store,
            verbose=not args.quiet,
        )
    except ScopeViolation as exc:
        print(f"FUERA DE ALCANCE — operación abortada.", file=sys.stderr)
        print(f"Motivo: {exc.motivo}", file=sys.stderr)
        return EXIT_VIOLATION

    by_severity: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    for result in results:
        by_severity[result.severity] = by_severity.get(result.severity, 0) + 1
        by_verdict[result.verdict] = by_verdict.get(result.verdict, 0) + 1

    payload = {
        "tool": "probe_exposure",
        "authorization": guard.authorization.to_dict(),
        "hosts": hosts,
        "method": "HEAD" if args.head else "GET",
        "results": [result.to_dict() for result in results],
        "summary": {
            "total": len(results),
            "by_severity": by_severity,
            "by_verdict": by_verdict,
            "exposed": sum(1 for r in results if r.verdict in EXPOSED_VERDICTS),
            "exposed_truncated": sum(
                1 for r in results if r.verdict == "exposed_truncated"
            ),
            "soft_404": sum(1 for r in results if r.soft_404),
        },
        "note": (
            "El cuerpo de las rutas sensibles no se guarda. Sólo se almacenan "
            "los cuerpos de las rutas seguras (robots.txt, sitemap.xml, "
            "security.txt). 'length' son los bytes leídos (tope 'max_bytes'); "
            "el tamaño real declarado por el servidor va en "
            "'content_length_header' y 'truncated' indica lectura incompleta."
        ),
    }

    if evidence_dir:
        tsv_path = evidence_dir / "probe_exposure.tsv"
        tsv_path.write_text(_render_tsv(results), encoding="utf-8")
        (evidence_dir / "probe_exposure.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(_render_tsv(results))
        print("", file=sys.stderr)
        print(
            f"[probe] {len(results)} ruta(s) sondeada(s) en {len(hosts)} host(s).",
            file=sys.stderr,
        )
        for severity in ("critico", "alto", "medio", "bajo", "info"):
            if by_severity.get(severity):
                print(f"  {severity}: {by_severity[severity]}", file=sys.stderr)
        print(
            f"  soft_404 (NO son hallazgos): {by_verdict.get('soft_404', 0)}",
            file=sys.stderr,
        )

    return EXIT_OK


def _render_tsv(results: Sequence[ProbeResult]) -> str:
    """Serializa los resultados en TSV.

    ``length`` son los **bytes leídos**; ``content_length_header`` es el
    tamaño declarado por el servidor y ``truncated`` dice si la lectura se
    cortó por ``max_bytes``.
    """
    lines = [TSV_HEADER]
    for result in results:
        lines.append(
            "\t".join(
                [
                    result.host,
                    result.path,
                    str(result.code),
                    result.content_type or "-",
                    str(result.length),
                    str(result.length_reported) if result.length_reported is not None else "-",
                    result.sha256[:12],
                    "si" if result.soft_404 else "no",
                    "si" if result.truncated else "no",
                    result.verdict,
                    result.severity,
                ]
            )
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
