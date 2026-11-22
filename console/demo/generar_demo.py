#!/usr/bin/env python3
"""Genera el conjunto de evidencia **SINTÉTICA** que carga la consola en modo demo.

No inventa cifras: todo lo que acaba en ``console/demo/evidencia/`` lo produce
el propio toolchain de ``01-tooling/scripts/`` ejecutándose contra material
sintético (los *fixtures* del repo y un sitio local efímero en
``127.0.0.1``). Lo único escrito a mano son los artefactos de *recon pasivo*
—que no tienen generador— y el RoE de ejemplo, ambos marcados como sintéticos.

Uso::

    python3 console/demo/generar_demo.py
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator, Sequence

__all__ = ["generar", "main"]

RAIZ_DEMO = Path(__file__).resolve().parent
RAIZ_CONSOLA = RAIZ_DEMO.parent
RAIZ_PLAYBOOK = RAIZ_CONSOLA.parent
SCRIPTS = RAIZ_PLAYBOOK / "01-tooling" / "scripts"
FIXTURES = SCRIPTS / "tests" / "fixtures"
EVIDENCIA = RAIZ_DEMO / "evidencia"
#: Corpus crudo: vive DENTRO del directorio de evidencia a propósito, para que
#: la consola demonstrates su regla: lo que no tiene estado de redacción
#: verificable queda oculto por defecto.
CRUDO = EVIDENCIA / "crudo"

#: Cabecera que se repite en todo el material sintético.
MARCA_SINTETICA = "SINTETICO — conjunto de demostración. No contiene datos reales."


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #


def _run(comando: Sequence[str], *, capturar: bool = False) -> str:
    """Ejecuta un comando del toolchain y devuelve su salida (si se pide)."""
    proceso = subprocess.run(
        list(comando),
        cwd=str(RAIZ_PLAYBOOK),
        check=False,
        capture_output=True,
        text=True,
    )
    if proceso.returncode != 0:
        raise RuntimeError(
            f"El comando falló ({proceso.returncode}): {' '.join(comando)}\n"
            f"{proceso.stdout}\n{proceso.stderr}"
        )
    if proceso.stderr.strip():
        print(f"    · {proceso.stderr.strip().splitlines()[-1]}")
    return proceso.stdout if capturar else ""


def _escribir(ruta: Path, contenido: str) -> None:
    """Escribe un fichero de texto creando los directorios necesarios."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(contenido, encoding="utf-8")


# --------------------------------------------------------------------------- #
# 1. Material sintético local
# --------------------------------------------------------------------------- #


def _preparar_crudo() -> None:
    """Copia los fixtures del toolchain y añade material sintético propio."""
    if EVIDENCIA.exists():
        shutil.rmtree(EVIDENCIA)
    EVIDENCIA.mkdir(parents=True)
    if CRUDO.exists():
        shutil.rmtree(CRUDO)
    CRUDO.mkdir(parents=True)

    # Los fixtures del propio repo: material sintético por construcción.
    for nombre in ("app.html", "patient.json", "expediente_clinico.json", "tarjetas_texto.txt"):
        origen = FIXTURES / nombre
        if origen.is_file():
            shutil.copy2(origen, CRUDO / nombre)

    _escribir(
        CRUDO / "config_sintetica.json",
        json.dumps(
            {
                "_aviso": MARCA_SINTETICA,
                "servidor": "127.0.0.1:8801",
                "bd": {
                    "host": "db.sintetico.invalid",
                    "usuario": "clinica_demo",
                    "clave": "CLAVE_SINTETICA_NO_USABLE_0001",
                },
                "tokens": {
                    "stripe_test": "sk_test_SINTETICO0000000000000000000000",
                    "jwt_admin": (
                        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                        "eyJzdWIiOiJkZW1vIiwicm9sIjoiYWRtaW4ifQ."
                        "SINTETICO_NO_FIRMA_NADA_0000000000000000"
                    ),
                },
                "integraciones": {
                    "pacientes": "/api/v1/pacientes",
                    "citas": "/api/v1/citas",
                    "expedientes": "/api/v1/expedientes/{id}",
                    "resultados": "/api/v1/resultados-laboratorio",
                    "administracion": "/admin/pacientes",
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
    )

    _escribir(
        CRUDO / "notas_sinteticas.txt",
        "\n".join(
            [
                f"# {MARCA_SINTETICA}",
                "# Contacto de la cuenta de pruebas: auditor.demo@sintetico.invalid",
                "# Teléfono de la reception (ficticio): +52 55 0000 0000",
                "# Este fichero sólo sirve para que pii_redact.py tenga algo que redactar.",
            ]
        )
        + "\n",
    )


# --------------------------------------------------------------------------- #
# 2. Sitio sintético local (para la sonda)
# --------------------------------------------------------------------------- #

#: Respuestas del sitio sintético: ruta -> (código, tipo MIME, cuerpo).
RUTAS_SINTETICAS: dict[str, tuple[int, str, bytes]] = {
    "/.env": (
        200,
        "text/plain; charset=utf-8",
        b"APP_ENV=production\nDB_HOST=db.sintetico.invalid\nDB_USER=clinica_demo\n"
        b"DB_PASSWORD=CLAVE_SINTETICA_NO_USABLE_0001\nSTRIPE_KEY=sk_test_SINTETICO0000\n",
    ),
    "/.git/HEAD": (200, "text/plain; charset=utf-8", b"ref: refs/heads/main\n"),
    "/.git/config": (
        200,
        "text/plain; charset=utf-8",
        b"[core]\n\trepositoryformatversion = 0\n",
    ),
    "/backup.zip": (200, "application/zip", b"PK\x03\x04SINTETICO-BACKUP-SIN-DATOS-REALES"),
    "/db.sql": (
        200,
        "application/sql; charset=utf-8",
        b"-- SINTETICO. Dump ficticio sin datos de pacientes reales.\n"
        b"INSERT INTO pacientes VALUES (1, 'PACIENTE SINTETICO UNO', '1985-11-02');\n",
    ),
    "/wp-config.php.bak": (
        200,
        "text/plain; charset=utf-8",
        b"<?php define('DB_NAME','clinica'); define('DB_USER','clinica_demo');\n",
    ),
    "/.htaccess": (200, "text/plain; charset=utf-8", b"# SINTETICO\nOptions -Indexes\n"),
    "/config.json": (
        200,
        "application/json; charset=utf-8",
        b'{"_aviso":"SINTETICO","db":{"user":"clinica_demo"},"debug":true}',
    ),
    "/package.json": (
        200,
        "application/json; charset=utf-8",
        b'{"name":"clinica-demo-sintetico","version":"0.1.0"}',
    ),
    "/swagger.json": (
        200,
        "application/json; charset=utf-8",
        b'{"openapi":"3.0.0","paths":{"/api/v1/pacientes":{"get":{}}}}',
    ),
    "/server-status": (
        200,
        "text/plain; charset=utf-8",
        b"Apache Server Status - SINTETICO\n",
    ),
    "/metrics": (
        200,
        "text/plain; charset=utf-8",
        b"# SINTETICO\nhttp_requests_total 42\n",
    ),
    "/api/v1/": (
        200,
        "application/json; charset=utf-8",
        b'{"_aviso":"SINTETICO","recursos":["pacientes","citas"]}',
    ),
    "/robots.txt": (
        200,
        "text/plain; charset=utf-8",
        b"User-agent: *\nDisallow: /admin/\nDisallow: /api/\n",
    ),
    "/sitemap.xml": (
        200,
        "application/xml; charset=utf-8",
        b'<?xml version="1.0"?><urlset><url><loc>/</loc></url></urlset>',
    ),
    "/index.html": (
        200,
        "text/html; charset=utf-8",
        b"<!DOCTYPE html><html lang=\"es\"><head><title>Sintetico</title></head>"
        b"<body><h1>Sitio sintetico de demostracion</h1></body></html>",
    ),
    # Ruta «protegida»: responde 403, no es una exposición.
    "/admin/": (403, "text/plain; charset=utf-8", b"Prohibido"),
}

#: Cuerpo fijo de la página de error: sirve para detectar *soft-404*.
CUERPO_404 = (
    b"<!DOCTYPE html><html lang=\"es\"><head><title>404 - No encontrado</title></head>"
    b"<body><h1>404 - No encontrado</h1><p>Sitio sintetico de demostracion.</p>"
    b"</body></html>"
)


class _HandlerSitio(BaseHTTPRequestHandler):
    """Servidor mínimo que imita un sitio con fugas sintéticas."""

    protocol_version = "HTTP/1.1"

    def log_message(self, formato: str, *args: object) -> None:
        """Silencia el log de acceso: el ruido no aporta al demo."""
        return

    def do_GET(self) -> None:  # noqa: N802
        """Responde GET con el cuerpo sintético o la página de error."""
        ruta = self.path.split("?", 1)[0]
        if ruta == "/phpmyadmin/":
            # Mismo cuerpo que el 404 pero con 200: el toolchain debe marcarlo
            # como soft-404 y NO contarlo como exposición.
            self._responder(200, "text/html; charset=utf-8", CUERPO_404)
            return
        entrada = RUTAS_SINTETICAS.get(ruta)
        if entrada is None:
            self._responder(404, "text/html; charset=utf-8", CUERPO_404)
            return
        codigo, tipo, cuerpo = entrada
        self._responder(codigo, tipo, cuerpo)

    def do_HEAD(self) -> None:  # noqa: N802
        """Responde HEAD con las mismas cabeceras, sin cuerpo."""
        self.do_GET()

    def _responder(self, codigo: int, tipo: str, cuerpo: bytes) -> None:
        """Escribe la respuesta HTTP con longitud explícita."""
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)


@contextmanager
def _sitio_local() -> Iterator[int]:
    """Levanta el sitio sintético en 127.0.0.1 y devuelve su puerto."""
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), _HandlerSitio)
    servidor.daemon_threads = True
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        yield int(servidor.server_address[1])
    finally:
        servidor.shutdown()
        servidor.server_close()
        hilo.join(timeout=5)


# --------------------------------------------------------------------------- #
# 3. RoE sintético y artefactos de recon pasivo
# --------------------------------------------------------------------------- #


def _autorizacion_sintetica(puerto: int) -> dict[str, object]:
    """RoE sintético con ventana de validez viva (para la cuenta atrás)."""
    ahora = datetime.now(timezone.utc)
    return {
        "authorization_ref": "ROE-SINTETICO-2026-001",
        "client": "Clínica Demo (entorno SINTÉTICO — no es un cliente real)",
        "signed_by": "QA interno del toolkit (firma sintética de demostración)",
        "signed_at": (ahora - timedelta(days=45)).isoformat().replace("+00:00", "Z"),
        "valid_from": (ahora - timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        "valid_to": (ahora + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        "hosts": ["127.0.0.1"],
        "allowed_methods": ["GET", "HEAD"],
        "max_bytes": 1048576,
        "min_interval_s": 1.0,
        "timeout_s": 20,
        "user_agent": (
            "ClientSecurityAudit/1.0 (consola de operaciones; entorno SINTETICO)"
        ),
        "notes": (
            "Autorización SINTÉTICA de demostración. El objetivo es 127.0.0.1, "
            "un servidor efímero que levanta este mismo generador."
        ),
    }


def _dns_sintetico() -> str:
    """Volcado DNS/DMARC sintético con las secciones que espera el toolchain."""
    return (
        f"# {MARCA_SINTETICA}\n"
        "=== A ===\nclinica-demo.sintetico.invalid. IN A 127.0.0.1\n"
        "=== AAAA ===\nclinica-demo.sintetico.invalid. IN AAAA ::1\n"
        "=== MX ===\nclinica-demo.sintetico.invalid. IN MX 10 mx1.sintetico.invalid.\n"
        "=== TXT ===\nclinica-demo.sintetico.invalid. IN TXT "
        '"v=spf1 include:_spf.sintetico.invalid -all"'
        "\n"
        "=== DMARC ===\n_dmarc.clinica-demo.sintetico.invalid. IN TXT "
        '"v=DMARC1; p=none; rua=mailto:dmarc@sintetico.invalid"'
        "\n"
    )


def _tls_sintetico() -> str:
    """Salida de ``openssl s_client`` sintética (versiones TLS admitidas)."""
    return (
        f"# {MARCA_SINTETICA}\n"
        "-tls1_0 => New, TLSv1, Cipher is ECDHE-RSA-AES256-SHA\n"
        "-tls1_1 => New, TLSv1.1, Cipher is ECDHE-RSA-AES256-SHA\n"
        "-tls1_2 => New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n"
        "-tls1_3 => New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
    )


def _crt_sintetico() -> list[dict[str, object]]:
    """Certificados sintéticos de Certificate Transparency."""
    nombres = [
        "clinica-demo.sintetico.invalid",
        "www.clinica-demo.sintetico.invalid",
        "api.clinica-demo.sintetico.invalid",
        "admin.clinica-demo.sintetico.invalid",
        "login.clinica-demo.sintetico.invalid",
        "portal-pacientes.clinica-demo.sintetico.invalid",
        "cdn.clinica-demo.sintetico.invalid",
        "antiguo.clinica-demo.sintetico.invalid",
        "dev.clinica-demo.sintetico.invalid",
        "staging.clinica-demo.sintetico.invalid",
        "intranet.clinica-demo.sintetico.invalid",
        "vpn.clinica-demo.sintetico.invalid",
    ]
    return [
        {
            "issuer_name": "SYNTHETIC-CA-DEMO",
            "common_name": nombre,
            "name_value": nombre,
            "not_before": "2026-01-10T00:00:00Z",
            "not_after": "2026-04-10T00:00:00Z",
        }
        for nombre in nombres
    ]


def _internetdb_sintetico() -> list[dict[str, object]]:
    """Salida sintética de InternetDB (tercero: se describe, no se escanea)."""
    return [
        {
            "ip": "127.0.0.1",
            "hostnames": ["clinica-demo.sintetico.invalid"],
            "ports": [80, 443, 3306, 8080],
            "cves": [
                {"id": "SINTETICO-CVE-0001", "cvss": 5.3},
                {"id": "SINTETICO-CVE-0002", "cvss": 7.5},
            ],
            "tags": ["demo"],
        }
    ]


# --------------------------------------------------------------------------- #
# 4. Generación
# --------------------------------------------------------------------------- #


def _hallazgos_sinteticos() -> None:
    """Escribe ``hallazgos.json`` a partir de la evidencia realmente generada.

    No se inventan cifras: los tres hallazgos que no se pueden derivar
    automáticos (un refutado, uno no verificado y uno en curso) se apoyan en
    filas concretas del TSV y del JSON de secretos.
    """
    import hashlib

    def hash_de(ruta: str) -> str:
        fichero = EVIDENCIA / ruta
        return hashlib.sha256(fichero.read_bytes()).hexdigest()[:12] if fichero.is_file() else ""

    hallazgos = [
        {
            "id": "MAN-001",
            "titulo": "Refutado: el panel administrativo no es accesible sin credenciales",
            "severidad": "info",
            "categoria": "acceso",
            "estado": "refutado",
            "owner": "equipo técnico",
            "descripcion": (
                "La ruta /admin/ respondió 403 en la sonda: no se puede leer el "
                "panel sin autenticación. Se descarta la hipótesis de exposición "
                "del panel; queda fuera de alcance el interior tras el 403."
            ),
            "evidencia": [
                {
                    "fichero": "probe_exposure.tsv",
                    "referencia": "host=127.0.0.1 path=/admin/ code=403",
                }
            ],
            "comando": (
                "python3 probe_exposure.py -a authorization.json --host 127.0.0.1 "
                "--path-list rutas_demo.txt"
            ),
            "footprint": "1 petición GET. No se intentó ninguna autenticación.",
        },
        {
            "id": "MAN-002",
            "titulo": "No verificado: MFA en la superficie de login",
            "severidad": "medio",
            "categoria": "acceso",
            "estado": "no verificado",
            "owner": "equipo técnico",
            "descripcion": (
                "El componente «ausencia de MFA» del score vale 8 puntos porque "
                "DEDUCE que no hay indicio de MFA en la sonda ni en el JS. "
                "Deducido no es verificado: hace falta que el cliente confirme si "
                "el login exige segundo factor."
            ),
            "evidencia": [
                {"fichero": "probe_exposure.tsv", "referencia": "host=127.0.0.1"},
                {"fichero": "js_intel.json", "referencia": "endpoints de login"},
            ],
            "comando": "python3 attack_surface_report.py --probe-tsv probe_exposure.tsv",
            "footprint": "Sin peticiones: sólo lectura del material ya descargado.",
        },
        {
            "id": "MAN-003",
            "titulo": "En curso: rotación de la clave de Stripe expuesta",
            "severidad": "critico",
            "categoria": "secreto",
            "estado": "en curso",
            "owner": "equipo técnico",
            "descripcion": (
                "La clave de Stripe detectada en el JS es sintética y no se ha "
                "usado, pero el procedimiento es el mismo: rotar en el panel y "
                "revocar la anterior. No se ha podido verificar el alcance real "
                "sin acceso al panel del cliente."
            ),
            "evidencia": [
                {"fichero": "secrets.json", "referencia": "stripe_secret_key"},
            ],
            "comando": "python3 secrets_scan.py . --json --out secrets.json",
            "footprint": "La credencial NO se usó en ningún momento (RoE 1.3).",
        },
    ]
    for hallazgo in hallazgos:
        for entrada in hallazgo["evidencia"]:
            entrada["hash"] = hash_de(entrada["fichero"])
    _escribir(
        EVIDENCIA / "hallazgos.json",
        json.dumps({"items": hallazgos}, ensure_ascii=False, indent=2),
    )


def _generar_score() -> None:
    """Calcula el Attack Exposure Score con el script del toolchain."""
    _run(
        [
            sys.executable,
            str(SCRIPTS / "attack_surface_report.py"),
            "--probe-tsv",
            str(EVIDENCIA / "probe_exposure.tsv"),
            "--secrets-json",
            str(EVIDENCIA / "secrets.json"),
            "--headers",
            str(EVIDENCIA / "headers.txt"),
            "--dns-mailsec",
            str(EVIDENCIA / "dns_mailsec.txt"),
            "--tls-versions",
            str(EVIDENCIA / "tls_versions.txt"),
            "--crtsh",
            str(EVIDENCIA / "crt.json"),
            "--internetdb",
            str(EVIDENCIA / "internetdb.json"),
            "--js-intel",
            str(EVIDENCIA / "js_intel.json"),
            "--out",
            str(EVIDENCIA),
        ]
    )


def _manifiesto_redaccion() -> None:
    """Escribe el manifiesto que declara qué artefactos están ya saneados.

    Los JSON que produce el toolchain son seguros **por construcción** (sólo
    máscaras, hashes, recuentos y metadatos), pero eso no lo puede verificar
    una heurística de nombres: lo declara el manifiesto, con su sha256.
    """
    import hashlib

    declarados = [
        ("probe_exposure.tsv", "salida de probe_exposure.py: metadatos de respuesta y sha256 parcial"),
        ("probe_exposure.json", "salida de probe_exposure.py: metadatos de respuesta y sha256 parcial"),
        ("secrets.json", "salida de secrets_scan.py: sólo máscara y sha256[:12], nunca el valor"),
        ("js_intel.json", "salida de js_intel.py: endpoints y hosts de terceros"),
        ("header_tls.json", "salida de header_tls_report.py: tabla de comprobaciones"),
        ("attack_surface_report.json", "salida de attack_surface_report.py: componentes y puntos"),
        ("attack_surface_report.md", "salida de attack_surface_report.py: informe en Markdown"),
        ("redaccion.json", "salida de pii_redact.py: recuentos por categoría, nunca valores"),
        ("dns_mailsec.txt", "recon pasivo sintético: registros DNS sin datos de pacientes"),
        ("tls_versions.txt", "recon pasivo sintético: versiones TLS, sin datos de pacientes"),
        ("crt.json", "recon pasivo sintético: nombres de certificado, sin datos de pacientes"),
        ("internetdb.json", "recon pasivo sintético: metadatos de terceros, sin datos de pacientes"),
        ("authorization.json", "RoE sintético: referencia, cliente y hosts de prueba"),
        ("registro-de-acciones-fase-2.csv", "plantilla sintética del playbook: registros de prueba"),
        ("hallazgos.json", "hallazgos redactados a mano sobre la evidencia sintética"),
        ("README-SINTETICO.txt", "marca de conjunto sintético"),
        ("headers.txt", "volcado de cabeceras del fixture sintético del toolchain"),
    ]
    # Los cuerpos «seguros» que guarda la sonda (robots.txt, sitemap.xml) sólo
    # se archivan por diseño del toolchain: se declaran uno a uno.
    for cuerpo in sorted((EVIDENCIA / "bodies").rglob("*")):
        if cuerpo.is_file():
            declarados.append(
                (
                    str(cuerpo.relative_to(EVIDENCIA)),
                    "cuerpo seguro por diseño de probe_exposure.py (sólo robots.txt, sitemap.xml y security.txt)",
                )
            )
    entradas = []
    for ruta, motivo in declarados:
        fichero = EVIDENCIA / ruta
        if not fichero.is_file():
            continue
        entradas.append(
            {
                "ruta": ruta,
                "sha256": hashlib.sha256(fichero.read_bytes()).hexdigest(),
                "motivo": motivo,
            }
        )
    _escribir(
        EVIDENCIA / "manifiesto-redaccion.json",
        json.dumps(
            {
                "tool": "manifiesto-redaccion",
                "nota": (
                    "Declaración explícita del auditor de qué artefactos están ya "
                    "sanitizados y por qué. La consola verifica el sha256 de cada "
                    "uno: si no cuadra, el artefacto vuelve a «SIN REDACTAR»."
                ),
                "artefactos": entradas,
            },
            ensure_ascii=False,
            indent=2,
        ),
    )


def generar() -> Path:
    """Genera todo el conjunto sintético y devuelve la ruta de la evidencia."""
    print("[demo] 1/9 preparando material sintético local")
    _preparar_crudo()

    print("[demo] 2/9 levantando el sitio sintético local")
    with _sitio_local() as puerto:
        print(f"[demo] 3/9 sondeando 127.0.0.1:{puerto} con probe_exposure.py")
        _escribir(
            CRUDO / "rutas_demo.txt",
            "\n".join(
                [
                    "/.env critico",
                    "/.git/HEAD critico",
                    "/.git/config critico",
                    "/backup.zip critico",
                    "/db.sql critico",
                    "/wp-config.php.bak critico",
                    "/.htaccess alto",
                    "/config.json alto",
                    "/package.json bajo",
                    "/swagger.json medio",
                    "/actuator/env critico",
                    "/server-status medio",
                    "/admin/ medio",
                    "/phpmyadmin/ medio",
                    "/robots.txt bajo",
                    "/sitemap.xml bajo",
                    "/metrics medio",
                    "/api/v1/ bajo",
                ]
            )
            + "\n",
        )
        _escribir(
            EVIDENCIA / "authorization.json",
            json.dumps(_autorizacion_sintetica(puerto), ensure_ascii=False, indent=2),
        )
        _run(
            [
                sys.executable,
                str(SCRIPTS / "probe_exposure.py"),
                "-a",
                str(EVIDENCIA / "authorization.json"),
                "--host",
                "127.0.0.1",
                "--scheme",
                "http",
                "--port",
                str(puerto),
                "--path-list",
                str(CRUDO / "rutas_demo.txt"),
                "--out",
                str(EVIDENCIA),
                "--quiet",
            ]
        )

    print("[demo] 4/9 escaneando secretos con secrets_scan.py")
    _run(
        [
            sys.executable,
            str(SCRIPTS / "secrets_scan.py"),
            str(CRUDO),
            "--json",
            "--out",
            str(EVIDENCIA / "secrets.json"),
            "--no-gitignore",
        ]
    )

    print("[demo] 5/9 analizando HTML/JS con js_intel.py")
    _run(
        [
            sys.executable,
            str(SCRIPTS / "js_intel.py"),
            str(CRUDO),
            "--base-host",
            "sintetico.invalid",
            "--json-out",
            str(EVIDENCIA / "js_intel.json"),
        ]
    )

    print("[demo] 6/9 redactando con pii_redact.py")
    _run(
        [
            sys.executable,
            str(SCRIPTS / "pii_redact.py"),
            str(CRUDO),
            "--out-dir",
            str(EVIDENCIA / "sanitizada"),
            "--report",
            str(EVIDENCIA / "redaccion.json"),
        ]
    )

    print("[demo] 7/9 copiando cabeceras, RoE y registro de acciones")
    cabeceras = FIXTURES / "headers_no_hsts.txt"
    if cabeceras.is_file():
        shutil.copy2(cabeceras, EVIDENCIA / "headers.txt")
    _escribir(EVIDENCIA / "dns_mailsec.txt", _dns_sintetico())
    _escribir(EVIDENCIA / "tls_versions.txt", _tls_sintetico())
    _escribir(
        EVIDENCIA / "crt.json", json.dumps(_crt_sintetico(), ensure_ascii=False, indent=2)
    )
    _escribir(
        EVIDENCIA / "internetdb.json",
        json.dumps(_internetdb_sintetico(), ensure_ascii=False, indent=2),
    )
    acciones = RAIZ_PLAYBOOK / "05-plantillas-de-trabajo" / "registro-de-acciones-fase-2.csv"
    if acciones.is_file():
        shutil.copy2(acciones, EVIDENCIA / "registro-de-acciones-fase-2.csv")
    _escribir(
        EVIDENCIA / "README-SINTETICO.txt",
        "\n".join(
            [
                MARCA_SINTETICA,
                "",
                "Este directorio lo genera `console/demo/generar_demo.py` ejecutando",
                "el toolchain de `01-tooling/scripts/` sobre los fixtures del repo y",
                "un sitio efímero en 127.0.0.1. Ningún dato procede de un cliente real.",
            ]
        )
        + "\n",
    )

    print("[demo] 8/9 analizando cabeceras con header_tls_report.py")
    cabecera_json = _run(
        [
            sys.executable,
            str(SCRIPTS / "header_tls_report.py"),
            str(EVIDENCIA / "headers.txt"),
            "--json",
        ],
        capturar=True,
    )
    _escribir(EVIDENCIA / "header_tls.json", cabecera_json)

    print("[demo] 9/9 calculando el score y el manifiesto de redacción")
    _generar_score()
    _hallazgos_sinteticos()
    _manifiesto_redaccion()
    return EVIDENCIA


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del generador."""
    print(f"[demo] toolchain: {SCRIPTS}")
    if not SCRIPTS.is_dir():
        print(
            "ERROR: no se encuentra 01-tooling/scripts/ en el playbook.",
            file=sys.stderr,
        )
        return 2
    destino = generar()
    print(f"[demo] evidencia sintética lista en {destino}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
