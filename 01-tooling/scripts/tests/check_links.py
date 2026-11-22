#!/usr/bin/env python3
"""Chequeo de **enlaces relativos** en los ficheros Markdown del repositorio.

Verifica que cada enlace relativo ``[texto](ruta)`` apunta a un fichero o
directorio que:

1. existe en el disco, y
2. **no está ignorado por el ``.gitignore``**.

El segundo punto es el importante: un enlace a un fichero que existe en el
disco del auditor pero que está en ``.gitignore`` (por ejemplo
``03-casos/…/evidencia/``) está **roto para quien clone el repositorio**, y
la CI debe avisar de eso antes de que lo descubra un visitante.

El script **no hace ninguna llamada de red**: los enlaces ``http(s)`` se
comprueban sólo sintácticamente (que estén bien formados), no se resuelven.

Uso::

    python3 check_links.py                 # todo el repositorio
    python3 check_links.py README.md       # sólo un fichero
    python3 check_links.py --quiet         # sólo el resumen

Código de salida: ``0`` si todos los enlaces resuelven, ``1`` si hay alguno
roto, ``2`` si el repositorio no es un checkout de git.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence

EXIT_OK = 0
EXIT_BROKEN = 1
EXIT_ERROR = 2

REPO_ROOT = Path(__file__).resolve().parents[3]

#: ``[texto](destino)`` — se admiten títulos entre comillas y <>.
LINK_RE = re.compile(r"(?<!\!)\[(?P<text>[^\]]*)\]\((?P<target>[^)]+)\)")

#: Bloques de código delimitados por ``` o ~~~ (se ignoran al buscar enlaces).
FENCE_RE = re.compile(r"^(?:```|~~~).*?^(?:```|~~~)\s*$", re.MULTILINE | re.DOTALL)


def _strip_code_blocks(text: str) -> str:
    """Sustituye los bloques de código por texto vacío."""
    return FENCE_RE.sub("", text)


def _clean_target(raw: str) -> str:
    """Normaliza el destino de un enlace: sin título, sin fragmento."""
    target = raw.strip()
    # ``<ruta con espacios>``
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    else:
        # Quita el título: ``ruta "titulo"`` o ``ruta 'titulo'``
        match = re.match(r"^(\S+)\s+[\"'].*[\"']$", target)
        if match:
            target = match.group(1)
    # Quita el fragmento (#seccion) y la query (?x=1)
    target = target.split("#", 1)[0].split("?", 1)[0]
    return target.strip()


def _is_external(target: str) -> bool:
    """¿El destino es una URL externa o un ancla? (no se comprueba en disco)."""
    if not target:
        return True
    return bool(
        re.match(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*:|//)", target)
    )


def _git(*args: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
    """Ejecuta un comando de git y devuelve el resultado (sin excepción)."""
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        check=False,
    )


def _tracked_files(suffixes: Iterable[str]) -> list[Path]:
    """Lista los ficheros versionados con las extensiones indicadas."""
    result = _git("ls-files", "-z")
    if result.returncode != 0:
        return []
    wanted = tuple(suffixes)
    paths: list[Path] = []
    for chunk in result.stdout.split("\0"):
        if not chunk:
            continue
        if chunk.endswith(wanted):
            paths.append(REPO_ROOT / chunk)
    return sorted(paths)


def _is_ignored(path: Path) -> bool:
    """¿El path está ignorado por el .gitignore? (relativo a la raíz del repo)."""
    try:
        relative = path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return False
    result = _git("check-ignore", "--quiet", "--", relative.as_posix())
    return result.returncode == 0


def _resolve(source: Path, target: str) -> Path:
    """Resuelve un destino relativo respecto al fichero que lo contiene."""
    from urllib.parse import unquote

    decoded = unquote(target)
    if decoded.startswith("/"):
        return REPO_ROOT / decoded.lstrip("/")
    return (source.parent / decoded).resolve()


def check_file(source: Path) -> list[str]:
    """Devuelve la lista de enlaces rotos de un fichero Markdown."""
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:  # pragma: no cover - defensivo
        return [f"{source}: no se pudo leer ({exc})"]

    broken: list[str] = []
    for match in LINK_RE.finditer(_strip_code_blocks(text)):
        target = _clean_target(match.group("target"))
        if _is_external(target):
            continue
        resolved = _resolve(source, target)
        if not resolved.exists():
            broken.append(
                f"{source.relative_to(REPO_ROOT)}: no existe → {target}"
            )
            continue
        if _is_ignored(resolved):
            broken.append(
                f"{source.relative_to(REPO_ROOT)}: está en .gitignore "
                f"(roto en el repo clonado) → {target}"
            )
    return broken


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI."""
    parser = argparse.ArgumentParser(
        prog="check_links.py",
        description="Comprueba que los enlaces relativos del repo resuelven.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Ficheros Markdown a comprobar (por defecto, todos los versionados).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Sólo imprime el resumen.",
    )
    args = parser.parse_args(argv)

    if args.paths:
        targets = [Path(item).resolve() for item in args.paths]
    else:
        if not (REPO_ROOT / ".git").exists():
            print(
                "ERROR: no es un checkout de git; no se puede usar "
                "`git ls-files` para enumerar los ficheros.",
                file=sys.stderr,
            )
            return EXIT_ERROR
        targets = _tracked_files((".md", ".markdown"))

    if not targets:
        print("No hay ficheros Markdown que comprobar.")
        return EXIT_OK

    broken: list[str] = []
    for target in targets:
        broken.extend(check_file(target))

    if broken:
        print(f"[check_links] {len(broken)} enlace(s) roto(s):", file=sys.stderr)
        for item in broken:
            print(f"  - {item}", file=sys.stderr)
        return EXIT_BROKEN

    if not args.quiet:
        print(
            f"[check_links] {len(targets)} fichero(s) Markdown, "
            "todos los enlaces relativos resuelven."
        )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
