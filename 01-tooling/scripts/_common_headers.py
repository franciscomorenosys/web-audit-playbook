#!/usr/bin/env python3
"""Catálogo **compartido** de cabeceras de seguridad «núcleo».

Este módulo es la única fuente de verdad sobre qué cabeceras se consideran
núcleo (las que cualquier portal que maneje datos de pacientes debería
publicar). Lo importan tanto ``header_tls_report.py`` (que las audita una a
una) como ``attack_surface_report.py`` (que las puntúa), de modo que **con la
misma evidencia los dos scripts informen exactamente del mismo recuento**.

Sin este módulo compartido, cada script llevaba su propia lista y acabaron
divergiendo: ``header_tls_report.py`` informaba de 9 cabeceras ausentes y
``attack_surface_report.py`` puntuaba sobre 8 (a ``COEP`` se le olvidó). Dos
números distintos para la misma evidencia es exactamente el tipo de
contradicción que un cliente detecta en el informe.

Uso::

    from _common_headers import CORE_HEADERS, core_headers_status

    estado = core_headers_status(block.has)   # {"present": [...], "missing": [...]}
"""

from __future__ import annotations

from typing import Any, Callable

__all__ = [
    "CORE_HEADERS",
    "CORE_HEADER_LABELS",
    "missing_core_headers",
    "present_core_headers",
    "core_headers_status",
]

#: Cabeceras núcleo. El orden es el de presentación en los informes.
CORE_HEADERS: tuple[str, ...] = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
)

#: Etiqueta con la que cada cabecera núcleo aparece en las observaciones de
#: ``header_tls_report.py``. Permite comprobar que el informe detail **todas**
#: las cabeceras del catálogo y ninguna de más.
CORE_HEADER_LABELS: dict[str, str] = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}


def missing_core_headers(has: Callable[[str], bool]) -> list[str]:
    """Cabeceras núcleo **ausentes** según un predicado de presencia.

    ``has`` recibe el nombre de la cabecera (en minúsculas) y devuelve si está
    presente en la respuesta.
    """
    return [name for name in CORE_HEADERS if not has(name)]


def present_core_headers(has: Callable[[str], bool]) -> list[str]:
    """Cabeceras núcleo **presentes** según un predicado de presencia."""
    return [name for name in CORE_HEADERS if has(name)]


def core_headers_status(has: Callable[[str], bool]) -> dict[str, Any]:
    """Resumen del estado de las cabeceras núcleo (sin valores).

    Es la función que usan **los dos** informes, así que el recuento de
    cabeceras ausentes es idéntico por construcción.
    """
    missing = missing_core_headers(has)
    return {
        "total": len(CORE_HEADERS),
        "present": present_core_headers(has),
        "missing": missing,
        "missing_count": len(missing),
    }
