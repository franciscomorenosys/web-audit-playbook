#!/usr/bin/env python3
"""Consola de Operaciones de Seguridad — servidor local.

Sirve la interfaz estática y expone ``/api/*`` leyendo **sólo** un directorio
de evidencia local. Cero dependencias de runtime, cero peticiones externas y
cero escritura sobre la evidencia.

Uso::

    python3 console/server.py --demo --port 8787
    python3 console/server.py --evidence ./mi-evidencia --port 8787 --no-open
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import socket
import sys
import threading
import webbrowser
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Sequence

if __package__ in (None, ""):  # ejecución como script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from api import EvidenceStore  # noqa: E402

__all__ = ["build_server", "main", "RUTAS_API"]

RAIZ_CONSOLA = Path(__file__).resolve().parent

#: Directorio de la interfaz estática (HTML, CSS, JS, fuentes).
DIR_ESTATICO = RAIZ_CONSOLA

#: Mapa ``ruta de la API -> método del almacén de evidencia``.
RUTAS_API: dict[str, str] = {
    "/api/summary": "summary",
    "/api/score": "score",
    "/api/findings": "findings",
    "/api/secrets": "secrets",
    "/api/api-surface": "api_surface",
    "/api/iocs": "iocs",
    "/api/evidence": "evidence",
    "/api/authorization": "authorization",
    "/api/actions": "actions",
}


class ConsolaHandler(BaseHTTPRequestHandler):
    """Sirve la UI estática y las rutas ``/api/*``.

    La interfaz se sirve siempre desde el disco de la consola; la API sólo
    lee el directorio de evidencia configurado al arrancar.
    """

    server_version = "ConsolaOperaciones/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- utilidades ---------------------------------------------------------- #

    def log_message(self, formato: str, *args: Any) -> None:
        """Log de acceso en formato compacto (una línea por petición)."""
        print(f"[consola] {self.address_string()} {formato % args}", file=sys.stderr)

    def _cabeceras_comunes(self, longitud: int, tipo: str) -> None:
        """Cabeceras de respuesta. Sin CDN, sin referencias externas."""
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(longitud))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; font-src 'self'; connect-src 'self'; "
            "form-action 'none'; frame-ancestors 'none'",
        )

    def _responder_json(self, datos: Any, codigo: int = 200) -> None:
        """Responde con JSON UTF-8."""
        cuerpo = json.dumps(datos, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(codigo)
        self._cabeceras_comunes(len(cuerpo), "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(cuerpo)

    def _responder_texto(self, cuerpo: bytes, tipo: str, codigo: int = 200) -> None:
        """Responde con bytes y un tipo MIME."""
        self.send_response(codigo)
        self._cabeceras_comunes(len(cuerpo), tipo)
        self.end_headers()
        self.wfile.write(cuerpo)

    # -- rutas ---------------------------------------------------------------- #

    def do_GET(self) -> None:  # noqa: N802 - firma impuesta por BaseHTTPRequestHandler
        """Atiende GET: API o fichero estático."""
        ruta = self.path.split("?", 1)[0].split("#", 1)[0]
        if ruta in RUTAS_API:
            self._servir_api(ruta)
            return
        if ruta == "/api/health":
            self._responder_json({"ok": True, "servicio": "consola-operaciones"})
            return
        if ruta == "/favicon.ico":
            # La consola no lleva icono: se responde 204 para no ensuciar el log.
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._servir_estatico(ruta)

    def do_HEAD(self) -> None:  # noqa: N802
        """Atiende HEAD (mismo enrutado, sin cuerpo)."""
        self.do_GET()

    def _servir_api(self, ruta: str) -> None:
        """Ejecuta el método del almacén correspondiente a la ruta."""
        metodo = getattr(self.server.store, RUTAS_API[ruta])  # type: ignore[attr-defined]
        try:
            datos = metodo()
        except Exception as exc:  # noqa: BLE001 - la API nunca debe caer
            self._responder_json(
                {
                    "error": "fallo_calculando_la_vista",
                    "detalle": str(exc),
                    "nota": "El resto de la consola sigue funcionando.",
                },
                codigo=500,
            )
            return
        self._responder_json(datos)

    def _servir_estatico(self, ruta: str) -> None:
        """Sirve un fichero de la interfaz estática (sin salir de la consola)."""
        relativa = ruta.lstrip("/") or "index.html"
        destino = (DIR_ESTATICO / relativa).resolve()
        try:
            destino.relative_to(DIR_ESTATICO)
        except ValueError:
            self._responder_texto(b"Ruta no permitida", "text/plain; charset=utf-8", 403)
            return
        if not destino.is_file():
            self._responder_texto(
                b"No encontrado", "text/plain; charset=utf-8", 404
            )
            return
        tipo, _ = mimetypes.guess_type(str(destino))
        if tipo is None:
            tipo = "application/octet-stream"
        if destino.suffix == ".woff2":
            tipo = "font/woff2"
        elif destino.suffix == ".js":
            tipo = "text/javascript; charset=utf-8"
        elif destino.suffix == ".css":
            tipo = "text/css; charset=utf-8"
        elif destino.suffix == ".html":
            tipo = "text/html; charset=utf-8"
        self._responder_texto(destino.read_bytes(), tipo)


class ConsolaServer(ThreadingHTTPServer):
    """Servidor que lleva dentro el almacén de evidencia."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, direccion: tuple[str, int], store: EvidenceStore) -> None:
        super().__init__(direccion, ConsolaHandler)
        self.store = store


def _abrir_navegador(url: str) -> None:
    """Abre el navegador del auditor en la consola (si el entorno lo permite)."""
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001 - es una cortesía, no un requisito
        pass


def _puerto_libre(preferido: int, host: str) -> int:
    """Devuelve el puerto pedido; si está ocupado, prueba el siguiente."""
    for candidato in range(preferido, preferido + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, candidato))
            except OSError:
                continue
            return candidato
    return preferido


def build_server(
    *,
    evidence: str | Path | None = None,
    demo: bool = False,
    host: str = "127.0.0.1",
    port: int = 8787,
) -> tuple[ConsolaServer, EvidenceStore]:
    """Construye el servidor y el almacén de evidencia.

    En modo ``demo`` se carga el conjunto sintético de ``console/demo/evidencia``;
    en modo real, el directorio indicado con ``--evidence``.
    """
    if demo:
        raiz = RAIZ_CONSOLA / "demo" / "evidencia"
        store = EvidenceStore(raiz, demo=True)
    elif evidence:
        store = EvidenceStore(evidence, demo=False)
    else:
        store = EvidenceStore(RAIZ_CONSOLA / "demo" / "evidencia", demo=True)

    if not store.existe:
        print(
            f"AVISO: el directorio de evidencia '{store.root}' no existe. "
            "La consola arrancará vacía y lo dirá en cada vista.",
            file=sys.stderr,
        )
    puerto = _puerto_libre(port, host)
    return ConsolaServer((host, puerto), store), store


def _parser() -> argparse.ArgumentParser:
    """Constructor del CLI."""
    parser = argparse.ArgumentParser(
        prog="console/server.py",
        description=(
            "Consola interna de operaciones de seguridad. Sirve la UI estática "
            "y expone /api/* leyendo un directorio de evidencia ya redactada. "
            "No hace ninguna petición externa."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python3 console/server.py --demo --port 8787\n"
            "  python3 console/server.py --evidence ./evidencia --no-open\n"
        ),
    )
    parser.add_argument(
        "--evidence",
        metavar="DIR",
        default=None,
        help="Directorio de evidencia a leer (modo real).",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Cargar el conjunto sintético de console/demo/evidencia.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Interfaz de escucha (por defecto 127.0.0.1: sólo local).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8787,
        help="Puerto de escucha (por defecto 8787).",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="No abrir el navegador al arrancar.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI."""
    args = _parser().parse_args(argv)
    servidor, store = build_server(
        evidence=args.evidence, demo=args.demo, host=args.host, port=args.port
    )
    url = f"http://{args.host}:{servidor.server_address[1]}/"
    modo = "DEMO SINTÉTICA" if store.demo else "EVIDENCIA REAL"
    print(f"[consola] modo: {modo}")
    print(f"[consola] evidencia: {store.root}")
    print(f"[consola] escuchando en {url}")
    if not args.no_open:
        threading.Timer(0.4, _abrir_navegador, args=(url,)).start()
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[consola] parada.")
    finally:
        servidor.shutdown()
        servidor.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
