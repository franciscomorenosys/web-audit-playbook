#!/usr/bin/env python3
"""Auto-prueba del toolkit de auditoría — **sin ninguna llamada de red**.

Comprueba los invariantes que la doctrina exige:

1. ``secrets_scan.py`` detecta los secretos del fixture y **no imprime nunca el
   valor completo**.
2. ``pii_redact.py`` redacta la PII y **el JSON sigue siendo JSON válido**.
3. ``header_tls_report.py`` marca HSTS como ausente.
4. ``scope_guard.py`` **rechaza** un host no autorizado y **acepta** uno
   autorizado.
5. ``probe_exposure.py`` **rechaza** salir del allowlist (y no hace red).

Uso::

    python3 tests/selftest.py
    python3 tests/selftest.py --verbose

Código de salida: ``0`` si todo PASS, ``1`` si algún check falla.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

SCRIPTS_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

EXIT_OK = 0
EXIT_FAIL = 1

#: Valores completos de los secretos de ejemplo. Si alguno aparece en una
#: salida del toolkit, el test falla.
FAKE_SECRET_VALUES: tuple[str, ...] = (
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "sk_live_51HqFakeFakeFakeFakeFakeFakeFAKEFAKE",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "AIzaSyD-EXAMPLEKEY0123456789abcdefghijk",
)

#: Datos de paciente del fixture JSON.
FAKE_PII_VALUES: tuple[str, ...] = (
    "María Fernanda López Ramírez",
    "LORM870412MDFRPN08",
    "LOMR870412HDFRPN08",
    "maria.lopez@example.mx",
    "jorge.ramirez@example.mx",
    "4111111111111111",
    "12345678901",
    "189.203.45.67",
)


@dataclass
class Check:
    """Resultado de un check individual."""

    name: str
    passed: bool
    detail: str = ""


class Runner:
    """Acumula checks y los imprime como PASS/FAIL."""

    def __init__(self, verbose: bool = False) -> None:
        self.checks: list[Check] = []
        self.verbose = verbose

    def run(self, name: str, function: Callable[[], tuple[bool, str]]) -> Check:
        """Ejecuta un check y registra el resultado."""
        try:
            passed, detail = function()
        except Exception as exc:  # noqa: BLE001 — un check que revienta es un FAIL
            passed, detail = False, f"excepción: {exc!r}"
        check = Check(name=name, passed=passed, detail=detail)
        self.checks.append(check)
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
        return check

    @property
    def failed(self) -> list[Check]:
        """Checks que fallaron."""
        return [check for check in self.checks if not check.passed]

    def summary(self) -> int:
        """Imprime el resumen y devuelve el código de salida."""
        total = len(self.checks)
        failed = len(self.failed)
        print("")
        print(f"{total - failed}/{total} checks PASS")
        if failed:
            print("Checks fallidos:")
            for check in self.failed:
                print(f"  - {check.name}: {check.detail}")
            return EXIT_FAIL
        print("Todos los checks PASS.")
        return EXIT_OK


def run_python(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Ejecuta un script del toolkit con el intérprete actual."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SCRIPTS_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #


def check_secrets_scan() -> tuple[bool, str]:
    """Detecta secretos de ejemplo y no imprime su valor completo."""
    result = run_python(
        [str(SCRIPTS_DIR / "secrets_scan.py"), str(FIXTURES_DIR / "app.html"), "--json"]
    )
    if result.returncode != 0:
        return False, f"secrets_scan terminó con {result.returncode}: {result.stderr[:200]}"
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return False, f"la salida no es JSON válido: {exc}"

    findings = payload.get("findings", [])
    types = {finding.get("type") for finding in findings}
    expected = {"aws_access_key_id", "stripe_secret_key", "jwt"}
    missing = expected - types
    if missing:
        return False, f"no se detectaron: {', '.join(sorted(missing))}"

    output = result.stdout + result.stderr
    leaked = [value for value in FAKE_SECRET_VALUES if value in output]
    if leaked:
        return False, f"se filtró el valor completo de {len(leaked)} secreto(s)"

    for finding in findings:
        masked = str(finding.get("masked", ""))
        if len(masked) >= len("AKIAIOSFODNN7EXAMPLE"):
            return False, f"la máscara es demasiado larga: {masked!r}"
        if not re.search(r"[0-9a-f]{12}", str(finding.get("sha256", ""))):
            return False, "falta el sha256[:12] del hallazgo"
    return True, f"{len(findings)} hallazgo(s) sin filtrar valores"


def check_secrets_redacted_copy() -> tuple[bool, str]:
    """``--redact-in-place`` escribe una copia sin el valor completo."""
    with tempfile.TemporaryDirectory() as tmp:
        result = run_python(
            [
                str(SCRIPTS_DIR / "secrets_scan.py"),
                str(FIXTURES_DIR / "app.html"),
                "--redact-in-place",
                "--redact-out",
                tmp,
                "--json",
            ]
        )
        if result.returncode != 0:
            return False, f"secrets_scan terminó con {result.returncode}"
        copies = list(Path(tmp).glob("*.redacted"))
        if not copies:
            return False, "no se escribió ninguna copia redactada"
        content = copies[0].read_text(encoding="utf-8")
        leaked = [value for value in FAKE_SECRET_VALUES if value in content]
        if leaked:
            return False, "la copia redactada conserva un valor completo"
        if "REDACT" not in content:
            return False, "la copia redactada no contiene marcadores de redacción"
    return True, "copia redactada sin valores completos"


def check_pii_redact() -> tuple[bool, str]:
    """Redacta la PII y el JSON resultante sigue siendo parseable."""
    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp) / "redactado"
        result = run_python(
            [
                str(SCRIPTS_DIR / "pii_redact.py"),
                str(FIXTURES_DIR / "patient.json"),
                "--out-dir",
                str(out_dir),
                "--report",
                str(Path(tmp) / "informe.json"),
                "--json",
            ]
        )
        if result.returncode != 0:
            return False, f"pii_redact terminó con {result.returncode}: {result.stderr[:200]}"
        target = out_dir / "patient.json"
        if not target.exists():
            return False, "no se escribió el fichero redactado"
        try:
            redacted = json.loads(target.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return False, f"el JSON redactado ya no es parseable: {exc}"
        if not isinstance(redacted, dict):
            return False, "el JSON redactado no es un objeto"

        content = target.read_text(encoding="utf-8")
        leaked = [value for value in FAKE_PII_VALUES if value in content]
        if leaked:
            return False, f"se filtraron {len(leaked)} dato(s) personal(es)"

        patient = redacted.get("paciente")
        if not isinstance(patient, dict):
            return False, "la estructura del JSON se destruyó"
        name_value = patient.get("nombre")
        if (
            isinstance(name_value, str)
            and name_value.startswith("[REDACT")
            and name_value.endswith("]")
            and "dato_personal_json" in name_value
        ):
            return True, "PII redactada y JSON válido"
        return False, f"el campo 'nombre' no se redactó: {name_value!r}"


def check_pii_report_has_no_values() -> tuple[bool, str]:
    """El informe de conteos no contiene valores."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "informe.json"
        result = run_python(
            [
                str(SCRIPTS_DIR / "pii_redact.py"),
                str(FIXTURES_DIR / "patient.json"),
                "--out-dir",
                str(Path(tmp) / "out"),
                "--report",
                str(report),
            ]
        )
        if result.returncode != 0:
            return False, f"pii_redact terminó con {result.returncode}"
        content = report.read_text(encoding="utf-8")
        leaked = [value for value in FAKE_PII_VALUES if value in content]
        if leaked:
            return False, "el informe contiene valores personales"
        if "counts_by_category" not in content:
            return False, "el informe no tiene el recuento por categoría"
    return True, "informe con conteos y sin valores"


def check_header_tls_report() -> tuple[bool, str]:
    """Marca HSTS como ausente en el fixture de cabeceras."""
    result = run_python(
        [
            str(SCRIPTS_DIR / "header_tls_report.py"),
            str(FIXTURES_DIR / "headers_no_hsts.txt"),
            "--json",
        ]
    )
    if result.returncode != 0:
        return False, f"header_tls_report terminó con {result.returncode}: {result.stderr[:200]}"
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return False, f"la salida no es JSON válido: {exc}"
    findings = payload["responses"][0]["findings"]
    hsts = [f for f in findings if "HSTS" in f["check"]]
    if not hsts:
        return False, "no se evaluó HSTS"
    absent = [f for f in hsts if f["value"] == "(ausente)"]
    if not absent:
        return False, "HSTS no se marcó como ausente"
    severities = {f["severity"] for f in absent}
    if "alto" not in severities:
        return False, f"HSTS ausente no tiene severidad 'alto': {severities}"
    return True, f"HSTS ausente detectado ({len(findings)} observaciones)"


def _write_authorization(directory: Path, hosts: Sequence[str]) -> Path:
    """Escribe un fichero de autorización temporal para los tests."""
    payload = {
        "authorization_ref": "SELFTEST-0001",
        "client": "Cliente de Autotest",
        "signed_by": "QA interno",
        "signed_at": "2020-01-01T00:00:00Z",
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_to": "2099-12-31T23:59:59Z",
        "hosts": list(hosts),
        "allowed_methods": ["GET", "HEAD"],
        "max_bytes": 100000,
        "min_interval_s": 1.0,
    }
    path = directory / "authorization.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def check_scope_guard_rejects_unknown_host() -> tuple[bool, str]:
    """Rechaza un host que no está en el allowlist."""
    with tempfile.TemporaryDirectory() as tmp:
        auth = _write_authorization(Path(tmp), ["www.ejemplo-auditoria.mx"])
        result = run_python(
            [
                str(SCRIPTS_DIR / "scope_guard.py"),
                "-a",
                str(auth),
                "--check",
                "https://host-fuera-de-alcance.example.com/x",
            ]
        )
        if result.returncode != 1:
            return False, f"código de salida {result.returncode} (se esperaba 1)"
        combined = result.stdout + result.stderr
        if "FUERA DE ALCANCE" not in combined:
            return False, "no se informó de la violación de alcance"
    return True, "host no autorizado rechazado (exit 1)"


def check_scope_guard_accepts_allowed_host() -> tuple[bool, str]:
    """Acepta un host que sí está en el allowlist."""
    with tempfile.TemporaryDirectory() as tmp:
        auth = _write_authorization(Path(tmp), ["www.ejemplo-auditoria.mx"])
        result = run_python(
            [
                str(SCRIPTS_DIR / "scope_guard.py"),
                "-a",
                str(auth),
                "--check",
                "https://www.ejemplo-auditoria.mx/ruta-propia",
                "--json",
            ]
        )
        if result.returncode != 0:
            return False, f"código de salida {result.returncode}: {result.stderr[:200]}"
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return False, f"la salida no es JSON válido: {exc}"
        if not payload.get("ok"):
            return False, "la validación no devolvió ok=true"
    return True, "host autorizado aceptado (exit 0)"


def check_scope_guard_requires_signature() -> tuple[bool, str]:
    """Sin firma o sin fichero, el error es de configuración (exit 2)."""
    with tempfile.TemporaryDirectory() as tmp:
        missing = run_python(
            [
                str(SCRIPTS_DIR / "scope_guard.py"),
                "-a",
                str(Path(tmp) / "no-existe.json"),
                "--check",
                "https://www.ejemplo-auditoria.mx/",
            ]
        )
        if missing.returncode != 2:
            return False, f"fichero ausente → exit {missing.returncode} (se esperaba 2)"

        unsigned = Path(tmp) / "sin-firma.json"
        unsigned.write_text(
            json.dumps(
                {
                    "authorization_ref": "X",
                    "client": "Y",
                    "valid_from": "2020-01-01T00:00:00Z",
                    "valid_to": "2099-01-01T00:00:00Z",
                    "hosts": ["ejemplo.mx"],
                }
            ),
            encoding="utf-8",
        )
        result = run_python(
            [
                str(SCRIPTS_DIR / "scope_guard.py"),
                "-a",
                str(unsigned),
                "--check",
                "https://ejemplo.mx/",
            ]
        )
        if result.returncode != 2:
            return False, f"sin firma → exit {result.returncode} (se esperaba 2)"
        if "firma" not in (result.stdout + result.stderr).lower():
            return False, "el error no menciona la firma"
    return True, "fichero ausente y sin firma → exit 2"


def check_scope_guard_rejects_write_methods() -> tuple[bool, str]:
    """Nunca permite POST/PUT/PATCH/DELETE aunque la autorización los liste."""
    with tempfile.TemporaryDirectory() as tmp:
        auth = Path(tmp) / "authorization.json"
        auth.write_text(
            json.dumps(
                {
                    "authorization_ref": "SELFTEST-0002",
                    "client": "Cliente de Autotest",
                    "signed_by": "QA interno",
                    "signed_at": "2020-01-01T00:00:00Z",
                    "valid_from": "2020-01-01T00:00:00Z",
                    "valid_to": "2099-12-31T23:59:59Z",
                    "hosts": ["www.ejemplo-auditoria.mx"],
                    "allowed_methods": ["GET", "HEAD", "POST", "PUT", "DELETE"],
                }
            ),
            encoding="utf-8",
        )
        sys.path.insert(0, str(SCRIPTS_DIR))
        try:
            from scope_guard import Guard, ScopeViolation  # type: ignore
        except ImportError as exc:  # pragma: no cover - defensivo
            return False, f"no se pudo importar scope_guard: {exc}"
        guard = Guard.from_file(auth)
        if "POST" in guard.allowed_methods:
            return False, "POST quedó permitido pese a la RoE"
        try:
            guard.check("https://www.ejemplo-auditoria.mx/api", "POST")
        except ScopeViolation:
            return True, "POST rechazado pese a estar en allowed_methods"
        return False, "Guard.check aceptó un POST"


def check_probe_rejects_out_of_scope_host() -> tuple[bool, str]:
    """La sonda aborta si el host no está en el allowlist (y no hace red)."""
    with tempfile.TemporaryDirectory() as tmp:
        auth = _write_authorization(Path(tmp), ["www.ejemplo-auditoria.mx"])
        result = run_python(
            [
                str(SCRIPTS_DIR / "probe_exposure.py"),
                "-a",
                str(auth),
                "--host",
                "host-fuera-de-alcance.example.com",
            ]
        )
        if result.returncode != 1:
            return False, f"código de salida {result.returncode} (se esperaba 1)"
        combined = result.stdout + result.stderr
        if "FUERA DE ALCANCE" not in combined:
            return False, "no se informó de la violación de alcance"
    return True, "host fuera del allowlist abortado (exit 1, sin peticiones)"


def check_probe_dry_run_lists_paths() -> tuple[bool, str]:
    """El plan de sondeo incluye las rutas sensibles esperadas."""
    with tempfile.TemporaryDirectory() as tmp:
        auth = _write_authorization(Path(tmp), ["www.ejemplo-auditoria.mx"])
        result = run_python(
            [
                str(SCRIPTS_DIR / "probe_exposure.py"),
                "-a",
                str(auth),
                "--host",
                "www.ejemplo-auditoria.mx",
                "--dry-run",
                "--json",
            ]
        )
        if result.returncode != 0:
            return False, f"código de salida {result.returncode}: {result.stderr[:200]}"
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return False, f"la salida no es JSON válido: {exc}"
        paths = {entry["path"] for entry in payload["paths"]}
        expected = {"/.env", "/.git/HEAD", "/wp-admin/", "/robots.txt"}
        missing = expected - paths
        if missing:
            return False, f"faltan rutas en el plan: {', '.join(sorted(missing))}"
    return True, f"plan con {len(paths)} rutas"


def check_js_intel() -> tuple[bool, str]:
    """Extrae endpoints, terceros, GraphQL y SRI del fixture HTML."""
    result = run_python(
        [
            str(SCRIPTS_DIR / "js_intel.py"),
            str(FIXTURES_DIR / "app.html"),
            "--base-host",
            "ejemplo-auditoria.mx",
            "--json",
        ]
    )
    if result.returncode != 0:
        return False, f"js_intel terminó con {result.returncode}: {result.stderr[:200]}"
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return False, f"la salida no es JSON válido: {exc}"
    data = payload["files"][0]
    endpoints = " ".join(data["api_endpoints"])
    if "/api/v1/citas" not in endpoints:
        return False, "no se extrajo el endpoint /api/v1/citas"
    if not data["sensitive_routes"]:
        return False, "no se detectaron rutas sensibles"
    if not data["third_party_hosts"]:
        return False, "no se detectaron hosts de terceros"
    if not data["graphql_operations"]:
        return False, "no se detectaron operaciones GraphQL"
    if payload["summary"]["scripts_without_sri"] < 1:
        return False, "no se detectaron scripts externos sin SRI"
    output = result.stdout + result.stderr
    leaked = [value for value in FAKE_SECRET_VALUES if value in output]
    if leaked:
        return False, "se filtró el valor completo de un secreto"
    return True, (
        f"{len(data['api_endpoints'])} endpoints, "
        f"{len(data['third_party_hosts'])} terceros"
    )


def check_attack_surface_report() -> tuple[bool, str]:
    """El score se calcula sólo con los datos disponibles y cita su fuente."""
    with tempfile.TemporaryDirectory() as tmp:
        result = run_python(
            [
                str(SCRIPTS_DIR / "attack_surface_report.py"),
                "--headers",
                str(FIXTURES_DIR / "headers_no_hsts.txt"),
                "--json",
            ]
        )
        if result.returncode != 0:
            return False, f"terminó con {result.returncode}: {result.stderr[:200]}"
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return False, f"la salida no es JSON válido: {exc}"
        if not isinstance(payload.get("score"), (int, float)):
            return False, "el score no es numérico"
        if not payload.get("band"):
            return False, "falta la banda"
        components = payload["components"]
        without_data = [c for c in components if c["source"] == "sin datos"]
        for component in without_data:
            if component["points"] != 0:
                return False, (
                    f"el componente '{component['name']}' sin datos tiene "
                    f"{component['points']} puntos"
                )
        with_data = [c for c in components if c["source"] != "sin datos"]
        for component in with_data:
            if not component["source"].startswith("evidencia:"):
                return False, f"fuente mal formada: {component['source']}"
    return True, f"score {payload['score']} ({payload['band']})"


def check_no_network_in_tests() -> tuple[bool, str]:
    """Los scripts de análisis local no deben abrir sockets."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    try:
        import socket  # noqa: PLC0415
    except ImportError:  # pragma: no cover - defensivo
        return False, "no se pudo importar socket"

    original = socket.socket

    class _Blocked(original):  # type: ignore[misc, valid-type]
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("se intentó abrir un socket durante el selftest")

    socket.socket = _Blocked  # type: ignore[misc]
    try:
        import attack_surface_report  # noqa: PLC0415
        import header_tls_report  # noqa: PLC0415
        import js_intel  # noqa: PLC0415
        import pii_redact  # noqa: PLC0415
        import secrets_scan  # noqa: PLC0415

        secrets_scan.scan_text("AKIAIOSFODNN7EXAMPLE")
        pii_redact.redact_text("correo: maria.lopez@example.mx")
        js_intel.analyse_text("<script src='https://cdn.ejemplo.mx/x.js'></script>")
        header_tls_report.parse_header_dump("HTTP/2 200\nserver: nginx\n")
        attack_surface_report.build_report(
            headers=[str(FIXTURES_DIR / "headers_no_hsts.txt")]
        )
    except AssertionError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        return False, f"excepción inesperada: {exc!r}"
    finally:
        socket.socket = original  # type: ignore[misc]
    return True, "ningún script local abrió un socket"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

CHECKS: tuple[tuple[str, Callable[[], tuple[bool, str]]], ...] = (
    ("secrets_scan detecta secretos y no imprime el valor completo", check_secrets_scan),
    ("secrets_scan --redact-in-place escribe copia sin valores", check_secrets_redacted_copy),
    ("pii_redact redacta y el JSON sigue siendo válido", check_pii_redact),
    ("pii_redact informe sin valores (sólo conteos)", check_pii_report_has_no_values),
    ("header_tls_report marca HSTS ausente", check_header_tls_report),
    ("scope_guard rechaza host no autorizado", check_scope_guard_rejects_unknown_host),
    ("scope_guard acepta host autorizado", check_scope_guard_accepts_allowed_host),
    ("scope_guard exige autorización firmada (exit 2)", check_scope_guard_requires_signature),
    ("scope_guard descarta POST aunque esté en allowed_methods", check_scope_guard_rejects_write_methods),
    ("probe_exposure rechaza salir del allowlist", check_probe_rejects_out_of_scope_host),
    ("probe_exposure --dry-run lista las rutas esperadas", check_probe_dry_run_lists_paths),
    ("js_intel extrae endpoints, terceros, GraphQL y SRI", check_js_intel),
    ("attack_surface_report puntúa y cita la fuente", check_attack_surface_report),
    ("los scripts locales no abren sockets", check_no_network_in_tests),
)


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del selftest."""
    parser = argparse.ArgumentParser(
        prog="selftest.py",
        description="Auto-prueba del toolkit de auditoría (sin red).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Salida más detallada.",
    )
    args = parser.parse_args(argv)

    print("=== Selftest del toolkit de auditoría web ===")
    print(f"Python {sys.version.split()[0]} · scripts en {SCRIPTS_DIR}")
    print("")

    runner = Runner(verbose=args.verbose)
    for name, function in CHECKS:
        runner.run(name, function)
    return runner.summary()


if __name__ == "__main__":
    raise SystemExit(main())
