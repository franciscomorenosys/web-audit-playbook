#!/usr/bin/env python3
"""Informe de cabeceras de seguridad y TLS sobre volcados **locales**.

Entrada: ficheros de texto con la respuesta HTTP cruda (``curl -D``, ``httpx -D``,
la salida de ``probe_exposure.py`` con ``--keep-headers``…). **No hace ninguna
llamada de red**: el auditor ya tiene la evidencia y esta herramienta la lee.

Analiza:

* Cabeceras de seguridad: CSP (parseando directivas), HSTS (con ``max-age``,
  ``includeSubDomains`` y ``preload``), ``X-Content-Type-Options``,
  ``X-Frame-Options`` y ``frame-ancestors``, ``Referrer-Policy``,
  ``Permissions-Policy``, ``Cross-Origin-Opener-Policy``,
  ``Cross-Origin-Embedder-Policy``, ``Cross-Origin-Resource-Policy`` y
  ``X-XSS-Protection`` (obsoleto: se recomienda retirarlo).
* Cookies: ``Secure``, ``HttpOnly``, ``SameSite`` y prefijos ``__Host-`` /
  ``__Secure-``.
* Fuga de información: ``Server``, ``X-Powered-By``, ``X-AspNet-Version``,
  ``X-Runtime``, ``Via``.
* Cache: ``Cache-Control``, ``Vary``, ``Age``, ``X-Cache`` y coherencia
  ``http://`` vs ``https://``.
* CORS: ``Access-Control-Allow-Origin: *`` junto con credenciales, origen
  dinámico reflejado y ``Vary: Origin`` ausente.

Uso::

    python3 header_tls_report.py cabeceras.txt
    python3 header_tls_report.py evidencia/ --json --out informe.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

if __package__ in (None, ""):  # ejecución como script
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common_headers import (  # noqa: E402  (import tras ajuste de sys.path)
    CORE_HEADER_LABELS,
    CORE_HEADERS,
    core_headers_status,
)

__all__ = [
    "HeaderBlock",
    "Finding",
    "parse_header_dump",
    "analyse_block",
    "core_headers_of_block",
    "CORE_HEADERS",
    "SEVERITY_ORDER",
    "EXIT_OK",
    "EXIT_ERROR",
]

EXIT_OK = 0
EXIT_ERROR = 2

SEVERITY_ORDER: dict[str, int] = {
    "ok": 0,
    "info": 1,
    "bajo": 2,
    "medio": 3,
    "alto": 4,
    "critico": 5,
}

SEVERITY_LABEL: dict[str, str] = {
    "ok": "OK",
    "info": "INFO",
    "bajo": "BAJO",
    "medio": "MEDIO",
    "alto": "ALTO",
    "critico": "CRÍTICO",
}

HSTS_MIN_AGE = 31536000  # un año

#: Cabeceras que contienen versiones de software (fuga de información).
VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


@dataclass(frozen=True)
class Finding:
    """Resultado de un check sobre una respuesta."""

    check: str
    value: str
    severity: str
    remediation: str = ""
    category: str = "general"

    def to_dict(self) -> dict[str, str]:
        return {
            "check": self.check,
            "value": self.value,
            "severity": self.severity,
            "remediation": self.remediation,
            "category": self.category,
        }


@dataclass
class HeaderBlock:
    """Una respuesta HTTP completa dentro de un volcado de texto."""

    source: str
    status_line: str = ""
    status: int = 0
    url: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    set_cookies: list[str] = field(default_factory=list)

    def get(self, name: str) -> str:
        """Valor de una cabecera (última gana), o cadena vacía."""
        key = name.lower()
        value = ""
        for header, raw in self.headers:
            if header.lower() == key:
                value = raw
        return value.strip()

    def get_all(self, name: str) -> list[str]:
        """Todos los valores de una cabecera (``Set-Cookie`` puede repetirse)."""
        key = name.lower()
        return [raw for header, raw in self.headers if header.lower() == key]

    def has(self, name: str) -> bool:
        """¿Existe la cabecera?"""
        key = name.lower()
        return any(header.lower() == key for header, _ in self.headers)


def core_headers_of_block(block: HeaderBlock) -> dict[str, Any]:
    """Estado de las cabeceras **núcleo** de una respuesta.

    Usa el catálogo compartido con ``attack_surface_report.py``: con la misma
    evidencia, los dos scripts dan el **mismo** número de cabeceras ausentes.
    """
    return {
        "source": block.source,
        "url": block.url,
        **core_headers_status(block.has),
    }


_STATUS_RE = re.compile(r"^HTTP/(\d(?:\.\d)?)\s+(\d{3})\s*(.*)$")
_URL_COMMENT_RE = re.compile(r"https?://[^\s)\"']+")


def parse_header_dump(text: str, source: str = "<memoria>") -> list[HeaderBlock]:
    """Divide un volcado de cabeceras en una o más respuestas HTTP."""
    blocks: list[HeaderBlock] = []
    current: HeaderBlock | None = None
    pending_url = ""

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        status_match = _STATUS_RE.match(line.strip())
        if status_match:
            current = HeaderBlock(
                source=source,
                status_line=line.strip(),
                status=int(status_match.group(2)),
                url=pending_url,
            )
            blocks.append(current)
            pending_url = ""
            continue
        if current is None:
            found = _URL_COMMENT_RE.search(line)
            if found:
                pending_url = found.group(0).rstrip("/") or found.group(0)
            continue
        if not line.strip():
            # Una línea en blanco puede separar respuestas encadenadas; se
            # conserva el bloque actual y se empieza otro si aparece un status.
            continue
        if ":" not in line:
            continue
        header, _, value = line.partition(":")
        header = header.strip()
        value = value.strip()
        if not header:
            continue
        current.headers.append((header, value))
        if header.lower() == "set-cookie":
            current.set_cookies.append(value)

    return blocks


# --------------------------------------------------------------------------- #
# Chequeos
# --------------------------------------------------------------------------- #


def _parse_csp(value: str) -> dict[str, list[str]]:
    """Divide una CSP en directivas y sus fuentes."""
    directives: dict[str, list[str]] = {}
    for chunk in value.split(";"):
        parts = chunk.split()
        if not parts:
            continue
        directives[parts[0].lower()] = [p.lower() for p in parts[1:]]
    return directives


def _check_csp(block: HeaderBlock) -> list[Finding]:
    """Evalúa la Content-Security-Policy."""
    findings: list[Finding] = []
    value = block.get("content-security-policy")
    if not value:
        findings.append(
            Finding(
                check="Content-Security-Policy",
                value="(ausente)",
                severity="medio",
                remediation=(
                    "Publica una CSP con `default-src 'self'` y directivas "
                    "explícitas para script-src, style-src, object-src y "
                    "base-uri. Sin CSP, un XSS inyectado puede ejecutarse "
                    "libremente en el navegador del paciente."
                ),
                category="cabeceras",
            )
        )
        return findings

    directives = _parse_csp(value)
    directives_text = ", ".join(
        f"{name}: {' '.join(sources)}" for name, sources in directives.items()
    )
    findings.append(
        Finding(
            check="Content-Security-Policy",
            value=directives_text,
            severity="ok",
            remediation="Seguir vigilando: la CSP sólo es tan fuerte como su "
            "directiva más permisiva.",
            category="cabeceras",
        )
    )

    if "default-src" not in directives and "script-src" not in directives:
        findings.append(
            Finding(
                check="CSP — default-src / script-src",
                value="sin default-src ni script-src",
                severity="alto",
                remediation="Añade `default-src 'self'` y `script-src` explícito.",
                category="cabeceras",
            )
        )
    script_src = directives.get("script-src", directives.get("default-src", []))
    if "unsafe-inline" in script_src:
        findings.append(
            Finding(
                check="CSP — script-src sin 'unsafe-inline'",
                value="script-src contiene 'unsafe-inline'",
                severity="medio",
                remediation=(
                    "Sustituye 'unsafe-inline' por nonces (`nonce-...`) o "
                    "hashes por script."
                ),
                category="cabeceras",
            )
        )
    if "unsafe-eval" in script_src:
        findings.append(
            Finding(
                check="CSP — script-src sin 'unsafe-eval'",
                value="script-src contiene 'unsafe-eval'",
                severity="medio",
                remediation="Elimina 'unsafe-eval' salvo que el stack lo exija.",
                category="cabeceras",
            )
        )
    if not directives.get("object-src"):
        findings.append(
            Finding(
                check="CSP — object-src",
                value="(ausente)",
                severity="bajo",
                remediation="Declara `object-src 'none'` para cerrar la vía de "
                "plugins y objetos embebidos.",
                category="cabeceras",
            )
        )
    if not directives.get("base-uri"):
        findings.append(
            Finding(
                check="CSP — base-uri",
                value="(ausente)",
                severity="bajo",
                remediation="Declara `base-uri 'self'` para evitar redirecciones "
                "de rutas relativas.",
                category="cabeceras",
            )
        )
    if "frame-ancestors" not in directives:
        findings.append(
            Finding(
                check="CSP — frame-ancestors",
                value="(ausente)",
                severity="medio",
                remediation="Añade `frame-ancestors 'none'` (o 'self') para "
                "evitar clickjacking sobre el portal de pacientes.",
                category="cabeceras",
            )
        )
    if "upgrade-insecure-requests" not in directives:
        findings.append(
            Finding(
                check="CSP — upgrade-insecure-requests",
                value="(ausente)",
                severity="bajo",
                remediation="Considera `upgrade-insecure-requests` para forzar "
                "recursos por HTTPS.",
                category="cabeceras",
            )
        )
    return findings


def _check_hsts(block: HeaderBlock) -> list[Finding]:
    """Evalúa Strict-Transport-Security."""
    value = block.get("strict-transport-security")
    if not value:
        return [
            Finding(
                check="Strict-Transport-Security (HSTS)",
                value="(ausente)",
                severity="alto",
                remediation=(
                    "Publica `Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains` (y `preload` si el dominio es "
                    "completamente HTTPS)."
                ),
                category="cabeceras",
            )
        ]
    parts = [p.strip() for p in value.split(";") if p.strip()]
    max_age = 0
    for part in parts:
        if part.lower().startswith("max-age"):
            try:
                max_age = int(part.split("=", 1)[1].strip().strip('"'))
            except (IndexError, ValueError):
                max_age = 0
    include_sub = any(p.lower() == "includeSubDomains" for p in parts)
    preload = any(p.lower() == "preload" for p in parts)
    findings = [
        Finding(
            check="Strict-Transport-Security (HSTS)",
            value=value,
            severity="ok",
            remediation="Correcto: los navegadores fuerzan HTTPS en este host.",
            category="cabeceras",
        )
    ]
    if max_age < HSTS_MIN_AGE:
        findings.append(
            Finding(
                check="HSTS — max-age",
                value=f"max-age={max_age}",
                severity="medio",
                remediation=(
                    f"Usa max-age={HSTS_MIN_AGE} (o mayor). Con valores cortos "
                    "la protección caduca antes de que el visitante vuelva."
                ),
                category="cabeceras",
            )
        )
    if not include_sub:
        findings.append(
            Finding(
                check="HSTS — includeSubDomains",
                value="(ausente)",
                severity="medio",
                remediation="Añade `includeSubDomains` si todos los subdominios "
                "sirven HTTPS (citas, panel, api).",
                category="cabeceras",
            )
        )
    if not preload:
        findings.append(
            Finding(
                check="HSTS — preload",
                value="(ausente)",
                severity="bajo",
                remediation="Considera `preload` y el envío a hstspreload.org "
                "cuando el dominio completo esté en HTTPS.",
                category="cabeceras",
            )
        )
    return findings


def _check_simple_headers(block: HeaderBlock) -> list[Finding]:
    """Chequeos de cabeceras de una línea."""
    findings: list[Finding] = []

    xcto = block.get("x-content-type-options")
    if not xcto:
        findings.append(
            Finding(
                check="X-Content-Type-Options",
                value="(ausente)",
                severity="medio",
                remediation="Publica `X-Content-Type-Options: nosniff` para "
                "evitar que el navegador interprete un fichero como otro tipo.",
                category="cabeceras",
            )
        )
    elif "nosniff" not in xcto.lower():
        findings.append(
            Finding(
                check="X-Content-Type-Options",
                value=xcto,
                severity="medio",
                remediation="El valor debe ser exactamente `nosniff`.",
                category="cabeceras",
            )
        )
    else:
        findings.append(
            Finding(
                check="X-Content-Type-Options",
                value=xcto,
                severity="ok",
                remediation="Correcto.",
                category="cabeceras",
            )
        )

    xfo = block.get("x-frame-options")
    csp_value = block.get("content-security-policy")
    frame_ancestors = ""
    if csp_value:
        frame_ancestors = " ".join(
            _parse_csp(csp_value).get("frame-ancestors", [])
        )
    if xfo:
        if xfo.upper() not in ("DENY", "SAMEORIGIN"):
            findings.append(
                Finding(
                    check="X-Frame-Options",
                    value=xfo,
                    severity="medio",
                    remediation="Usa `DENY` o `SAMEORIGIN`.",
                    category="cabeceras",
                )
            )
        else:
            findings.append(
                Finding(
                    check="X-Frame-Options",
                    value=xfo,
                    severity="ok",
                    remediation="Correcto.",
                    category="cabeceras",
                )
            )
    elif frame_ancestors:
        findings.append(
            Finding(
                check="X-Frame-Options",
                value="(ausente) — cubierto por CSP frame-ancestors",
                severity="ok",
                remediation="La CSP cubre el clickjacking; X-Frame-Options es "
                "recomendable para clientes antiguos.",
                category="cabeceras",
            )
        )
    else:
        findings.append(
            Finding(
                check="X-Frame-Options",
                value="(ausente)",
                severity="medio",
                remediation="Publica `X-Frame-Options: DENY` y `frame-ancestors` "
                "en la CSP.",
                category="cabeceras",
            )
        )

    referrer = block.get("referrer-policy")
    valid_referrer = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "origin",
        "origin-when-cross-origin",
    }
    if not referrer:
        findings.append(
            Finding(
                check="Referrer-Policy",
                value="(ausente)",
                severity="medio",
                remediation=(
                    "Publica `Referrer-Policy: strict-origin-when-cross-origin` "
                    "para que las URLs de las páginas de pacientes no viajen a "
                    "terceros en la cabecera Referer."
                ),
                category="cabeceras",
            )
        )
    elif referrer.lower() not in valid_referrer:
        findings.append(
            Finding(
                check="Referrer-Policy",
                value=referrer,
                severity="bajo",
                remediation="Usa una política de la lista recomendada por la "
                "especificación (por ejemplo `strict-origin`).",
                category="cabeceras",
            )
        )
    else:
        findings.append(
            Finding(
                check="Referrer-Policy",
                value=referrer,
                severity="ok",
                remediation="Correcto.",
                category="cabeceras",
            )
        )

    permissions = block.get("permissions-policy")
    if not permissions:
        findings.append(
            Finding(
                check="Permissions-Policy",
                value="(ausente)",
                severity="bajo",
                remediation="Declara `Permissions-Policy: camera=(), "
                "microphone=(), geolocation=()` según las funciones reales del "
                "portal.",
                category="cabeceras",
            )
        )
    else:
        findings.append(
            Finding(
                check="Permissions-Policy",
                value=permissions,
                severity="ok",
                remediation="Revisa que las capacidades declaradas coincidan con "
                "el uso real.",
                category="cabeceras",
            )
        )

    for header, label, remediation in (
        (
            "cross-origin-opener-policy",
            "Cross-Origin-Opener-Policy",
            "Declara `same-origin` para aislar la ventana de los pacientes.",
        ),
        (
            "cross-origin-embedder-policy",
            "Cross-Origin-Embedder-Policy",
            "Declara `require-corp` si usas SharedArrayBuffer o Web Workers.",
        ),
        (
            "cross-origin-resource-policy",
            "Cross-Origin-Resource-Policy",
            "Declara `same-origin` o `same-site` para los recursos con datos.",
        ),
    ):
        value = block.get(header)
        if not value:
            findings.append(
                Finding(
                    check=label,
                    value="(ausente)",
                    severity="bajo",
                    remediation=remediation,
                    category="cabeceras",
                )
            )
        else:
            findings.append(
                Finding(
                    check=label,
                    value=value,
                    severity="ok",
                    remediation="Correcto.",
                    category="cabeceras",
                )
            )

    xss = block.get("x-xss-protection")
    if xss:
        findings.append(
            Finding(
                check="X-XSS-Protection",
                value=f"{xss} (cabecera obsoleta)",
                severity="info",
                remediation=(
                    "Esta cabecera está obsoleta y en algunos navegadores "
                    "puede *habilitar* filtros antiguos con bugs. Retírala y "
                    "apóyate en la CSP."
                ),
                category="cabeceras",
            )
        )
    else:
        findings.append(
            Finding(
                check="X-XSS-Protection",
                value="(ausente)",
                severity="ok",
                remediation="Correcto: la cabecera obsoleta ya no se publica.",
                category="cabeceras",
            )
        )
    return findings


def _check_cookies(block: HeaderBlock) -> list[Finding]:
    """Chequeos de cookies (``Set-Cookie``)."""
    findings: list[Finding] = []
    cookies = block.set_cookies
    if not cookies:
        findings.append(
            Finding(
                check="Cookies — Set-Cookie",
                value="(sin cookies en esta respuesta)",
                severity="info",
                remediation="Sin observaciones en esta respuesta.",
                category="cookies",
            )
        )
        return findings

    for raw in cookies:
        name = raw.split("=", 1)[0].strip() or "(sin nombre)"
        lowered = raw.lower()
        secure = "secure" in lowered
        httponly = "httponly" in lowered
        samesite = re.search(r"samesite\s*=\s*([a-z]+)", lowered)
        samesite_value = samesite.group(1) if samesite else ""
        problems: list[str] = []
        if not secure:
            problems.append("sin Secure")
        if not httponly:
            problems.append("sin HttpOnly")
        if not samesite:
            problems.append("sin SameSite")
        elif samesite_value not in ("strict", "lax"):
            problems.append(f"SameSite={samesite_value}")
        if name.startswith("__Host-") and not (
            secure and "path=/" in lowered and "domain=" not in lowered
        ):
            problems.append("prefijo __Host- incompleto")
        if name.startswith("__Secure-") and not secure:
            problems.append("prefijo __Secure- sin Secure")

        if problems:
            severity = "alto" if ("sin Secure" in problems and "sin HttpOnly" in problems) else "medio"
            findings.append(
                Finding(
                    check=f"Cookie '{name}'",
                    value=", ".join(problems),
                    severity=severity,
                    remediation=(
                        "Marca la cookie con `Secure; HttpOnly; SameSite=Lax` "
                        "(o `Strict`). Para cookies de sesión, usa el prefijo "
                        "`__Host-`."
                    ),
                    category="cookies",
                )
            )
        else:
            findings.append(
                Finding(
                    check=f"Cookie '{name}'",
                    value="Secure, HttpOnly y SameSite presentes",
                    severity="ok",
                    remediation="Correcto.",
                    category="cookies",
                )
            )
    return findings


def _check_info_leak(block: HeaderBlock) -> list[Finding]:
    """Fuga de información por cabeceras de versión."""
    findings: list[Finding] = []
    for header, remediation in (
        ("server", "Oculta la versión exacta del servidor si el stack lo permite."),
        ("x-powered-by", "Elimínala: delata el lenguaje y la versión."),
        ("x-aspnet-version", "Elimínala: permite encadenar exploits de ASP.NET."),
        ("x-aspnetmvc-version", "Elimínala: delata la versión de ASP.NET MVC."),
        ("x-runtime", "Elimínala: delata el runtime."),
        ("via", "Elimina o minimiza la cabecera `Via` (proxy/CDN)."),
        ("x-generator", "Elimina `X-Generator` si la plataforma la añade."),
    ):
        value = block.get(header)
        if not value:
            continue
        severity = "alto" if header in ("x-aspnet-version", "x-aspnetmvc-version") else "bajo"
        findings.append(
            Finding(
                check=f"Fuga de información — {header}",
                value=value,
                severity=severity,
                remediation=remediation,
                category="fuga",
            )
        )
    if not findings:
        findings.append(
            Finding(
                check="Fuga de información — versiones",
                value="(ninguna cabecera de versión detectada)",
                severity="ok",
                remediation="Correcto: no se expone la pila del servidor.",
                category="fuga",
            )
        )
    return findings


def _check_cache(block: HeaderBlock) -> list[Finding]:
    """Coherencia de caché."""
    findings: list[Finding] = []
    cache_control = block.get("cache-control")
    vary = block.get("vary")
    age = block.get("age")
    x_cache = block.get("x-cache")

    if cache_control:
        lowered = cache_control.lower()
        findings.append(
            Finding(
                check="Cache-Control",
                value=cache_control,
                severity="ok",
                remediation="Revisa que las páginas con datos de pacientes no "
                "se cacheen en shared proxies.",
                category="cache",
            )
        )
        if "no-store" not in lowered and "private" not in lowered:
            findings.append(
                Finding(
                    check="Cache-Control — datos sensibles",
                    value="sin no-store ni private",
                    severity="medio",
                    remediation=(
                        "En páginas con expediente o datos de pago usa "
                        "`Cache-Control: no-store, private`."
                    ),
                    category="cache",
                )
            )
    else:
        findings.append(
            Finding(
                check="Cache-Control",
                value="(ausente)",
                severity="bajo",
                remediation="Declara la política de caché explícitamente "
                "(`no-store` en páginas con datos de pacientes).",
                category="cache",
            )
        )

    if vary:
        findings.append(
            Finding(
                check="Vary",
                value=vary,
                severity="ok",
                remediation="Si la respuesta varía por `Origin` o por cookies, "
                "asegúrate de que figuren en `Vary`.",
                category="cache",
            )
        )
    else:
        findings.append(
            Finding(
                check="Vary",
                value="(ausente)",
                severity="bajo",
                remediation="Declara `Vary` cuando la respuesta dependa de la "
                "petición (idioma, cookies, Origin).",
                category="cache",
            )
        )

    cache_state = []
    if age:
        cache_state.append(f"Age: {age}")
    if x_cache:
        cache_state.append(f"X-Cache: {x_cache}")
    if cache_state:
        findings.append(
            Finding(
                check="Estado de caché (Age / X-Cache)",
                value="; ".join(cache_state),
                severity="info",
                remediation="Informativo: indica si la respuesta fue servida "
                "desde caché.",
                category="cache",
            )
        )

    url = block.url.lower()
    if url.startswith("http://") and not block.has("strict-transport-security"):
        findings.append(
            Finding(
                check="Coherencia http:// vs https://",
                value="la evidencia es HTTP y no hay HSTS",
                severity="alto",
                remediation="Sirve el sitio en HTTPS y redirige (301) todo el "
                "tráfico HTTP.",
                category="cache",
            )
        )
    elif url.startswith("https://"):
        findings.append(
            Finding(
                check="Coherencia http:// vs https://",
                value="la evidencia es HTTPS",
                severity="ok",
                remediation="Correcto.",
                category="cache",
            )
        )
    return findings


def _check_cors(block: HeaderBlock) -> list[Finding]:
    """Chequeos de CORS."""
    findings: list[Finding] = []
    allow_origin = block.get("access-control-allow-origin")
    allow_credentials = block.get("access-control-allow-credentials").lower()
    vary = block.get("vary").lower()

    if not allow_origin:
        findings.append(
            Finding(
                check="CORS — Access-Control-Allow-Origin",
                value="(ausente)",
                severity="info",
                remediation="Sin CORS: correcto si la API no la consume un "
                "frontend de otro origen.",
                category="cors",
            )
        )
        return findings

    if allow_origin.strip() == "*":
        if allow_credentials == "true":
            findings.append(
                Finding(
                    check="CORS — ACAO '*' con credenciales",
                    value=f"Allow-Origin: * | Allow-Credentials: {allow_credentials}",
                    severity="critico",
                    remediation=(
                        "`*` con credenciales es una configuración peligrosa: "
                        "deja que cualquier sitio lea respuestas con "
                        "cookies de sesión. Usa una lista explícita de "
                        "orígenes."
                    ),
                    category="cors",
                )
            )
        else:
            findings.append(
                Finding(
                    check="CORS — Access-Control-Allow-Origin",
                    value="*",
                    severity="medio",
                    remediation=(
                        "Restringe el origen a los que la clínica use "
                        "(portal, app) si la API devuelve datos de pacientes."
                    ),
                    category="cors",
                )
            )
        return findings

    if allow_origin.strip() in ("null", "null,"):
        findings.append(
            Finding(
                check="CORS — origen nulo",
                value=allow_origin,
                severity="alto",
                remediation=(
                    "`Access-Control-Allow-Origin: null` permite el acceso desde "
                    "contextos opaque (sandboxes, some file://). Elimínalo."
                ),
                category="cors",
            )
        )
        return findings

    # Origen específico: un volcado de una sola respuesta **no** permite
    # distinguir un allowlist estático de un `Origin` reflejado sin ver la
    # petición. Se reporta el hecho y se marca la comprobación pendiente.
    findings.append(
        Finding(
            check="CORS — Access-Control-Allow-Origin",
            value=allow_origin,
            severity="info",
            remediation=(
                "Origen específico. Verifica con la cabecera `Origin` de la "
                "petición que la respuesta NO lo refleja sin validar: si lo "
                "hace, cualquier sitio puede leer la respuesta con la "
                "cookie de sesión."
            ),
            category="cors",
        )
    )
    if "origin" not in vary:
        findings.append(
            Finding(
                check="CORS — Vary: Origin",
                value="(ausente)",
                severity="medio",
                remediation=(
                    "Añade `Vary: Origin` cuando la respuesta dependa del "
                    "origen: sin ello una caché puede servir la respuesta de "
                    "un origen a otro."
                ),
                category="cors",
            )
        )
    if allow_credentials == "true":
        findings.append(
            Finding(
                check="CORS — credenciales con origen específico",
                value=f"Allow-Origin: {allow_origin} | Allow-Credentials: true",
                severity="medio",
                remediation=(
                    "Verifica que el origen servido esté en una lista blanca "
                    "antes de permitir credenciales."
                ),
                category="cors",
            )
        )
    return findings


def analyse_block(block: HeaderBlock) -> list[Finding]:
    """Ejecuta todos los chequeos sobre una respuesta HTTP."""
    findings: list[Finding] = []
    findings.extend(_check_csp(block))
    findings.extend(_check_hsts(block))
    findings.extend(_check_simple_headers(block))
    findings.extend(_check_cookies(block))
    findings.extend(_check_info_leak(block))
    findings.extend(_check_cache(block))
    findings.extend(_check_cors(block))
    return findings


# --------------------------------------------------------------------------- #
# Salida
# --------------------------------------------------------------------------- #


def _escape(value: str) -> str:
    """Escapa los pipes para no romper las tablas Markdown."""
    return value.replace("|", "\\|").replace("\n", " ")


def render_markdown(results: Sequence[tuple[HeaderBlock, list[Finding]]]) -> str:
    """Genera el informe en Markdown."""
    lines: list[str] = ["# Informe de cabeceras de seguridad y TLS", ""]
    total_findings = sum(
        1 for _, findings in results for f in findings if f.severity != "ok"
    )
    lines.append(
        f"Respuestas analizadas: **{len(results)}** · "
        f"observaciones: **{total_findings}**"
    )
    lines.append("")

    by_severity: dict[str, int] = {}
    for _, findings in results:
        for finding in findings:
            if finding.severity == "ok":
                continue
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    if by_severity:
        lines.append("## Resumen por severidad")
        lines.append("")
        lines.append("| Severidad | Nº |")
        lines.append("|---|---|")
        for severity in ("critico", "alto", "medio", "bajo", "info"):
            if by_severity.get(severity):
                lines.append(f"| {SEVERITY_LABEL[severity]} | {by_severity[severity]} |")
        lines.append("")

    for block, findings in results:
        lines.append(f"## {block.source}")
        lines.append("")
        title = block.url or "(URL no documentada en el volcado)"
        lines.append(f"- URL: `{title}`")
        lines.append(f"- Estado: `{block.status_line or 'desconocido'}`")
        core = core_headers_of_block(block)
        lines.append(
            "- Cabeceras núcleo: **{present}/{total}** presentes "
            "({missing} ausente(s): {names})".format(
                present=core["total"] - core["missing_count"],
                total=core["total"],
                missing=core["missing_count"],
                names=", ".join(f"`{name}`" for name in core["missing"]) or "—",
            )
        )
        lines.append("")
        lines.append("| Check | Valor | Severidad | Remediación |")
        lines.append("|---|---|---|---|")
        for finding in findings:
            lines.append(
                "| {check} | `{value}` | {sev} | {rem} |".format(
                    check=_escape(finding.check),
                    value=_escape(finding.value or "(vacío)"),
                    sev=SEVERITY_LABEL.get(finding.severity, finding.severity),
                    rem=_escape(finding.remediation),
                )
            )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*Informe generado sobre volcados de cabeceras ya existentes. "
        "No se ha realizado ninguna petición de red durante el análisis.*"
    )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="header_tls_report.py",
        description=(
            "Analiza volcados de cabeceras HTTP ya guardados en local y emite "
            "un informe Markdown + JSON. No hace ninguna llamada de red."
        ),
        epilog=(
            "Ejemplos:\n"
            "  python3 header_tls_report.py cabeceras.txt\n"
            "  python3 header_tls_report.py evidencia/ --json --out informe.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Ficheros o directorios con volcados de cabeceras.",
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        default=None,
        help="Fichero Markdown donde escribir el informe (además de la pantalla).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida en JSON.",
    )
    return parser


def _collect_files(paths: Sequence[str]) -> list[Path]:
    """Expande rutas a ficheros de texto legibles."""
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in {
                    ".txt", ".headers", ".hdr", ".http", ".log", ""
                }:
                    files.append(child)
        else:
            raise FileNotFoundError(raw)
    return files


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        files = _collect_files(args.paths)
    except FileNotFoundError as exc:
        print(f"ERROR: no existe la ruta '{exc}'.", file=sys.stderr)
        return EXIT_ERROR

    results: list[tuple[HeaderBlock, list[Finding]]] = []
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"ERROR: no se pudo leer '{file_path}': {exc}", file=sys.stderr)
            return EXIT_ERROR
        for block in parse_header_dump(text, source=str(file_path)):
            results.append((block, analyse_block(block)))

    if not results:
        print(
            "AVISO: no se encontró ninguna respuesta HTTP en los ficheros indicados.",
            file=sys.stderr,
        )

    markdown = render_markdown(results)
    payload = {
        "tool": "header_tls_report",
        "responses": [
            {
                "source": block.source,
                "url": block.url,
                "status": block.status,
                "status_line": block.status_line,
                "core_headers": core_headers_of_block(block),
                "findings": [finding.to_dict() for finding in findings],
            }
            for block, findings in results
        ],
        "summary": {
            "responses": len(results),
            "by_severity": _count_severity(results),
        },
    }

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(markdown, encoding="utf-8")

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(markdown)
    return EXIT_OK


def _count_severity(results: Sequence[tuple[HeaderBlock, list[Finding]]]) -> dict[str, int]:
    """Cuenta las observaciones por severidad (excluye los OK)."""
    counts: dict[str, int] = {}
    for _, findings in results:
        for finding in findings:
            if finding.severity == "ok":
                continue
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
