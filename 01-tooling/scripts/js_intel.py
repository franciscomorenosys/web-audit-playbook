#!/usr/bin/env python3
"""Análisis **local** de HTML y JavaScript ya descargados (sin red).

Trabaja sobre ficheros del disco (HTML, JS, bundles) y extrae la superficie que
suele quedarse fuera de una revisión visual:

* endpoints de API (absolutos y relativos);
* rutas administrativas o sensibles;
* hosts de terceros (analítica, CDN, pagos, mapas, fuentes, formularios…), con la
  pregunta de fondo: *¿a dónde salen los datos del navegador del paciente?*;
* operaciones GraphQL;
* referencias a ``sourceMappingURL`` (los mapas source exponen el código
  original y, a veces, secretos);
* etiquetas ``<script src>`` y ``<link href>``;
* si los scripts externos llevan **SRI** (``integrity``) y ``crossorigin``;
* si algún script *inline* contiene secretos (reutiliza los patrones de
  ``secrets_scan.py``).

No hace ninguna llamada de red.

Uso::

    python3 js_intel.py ./evidencia/home.html
    python3 js_intel.py ./evidencia/ --json --out js_intel.json
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

from secrets_scan import PATTERNS as SECRET_PATTERNS  # noqa: E402
from secrets_scan import scan_text  # noqa: E402

__all__ = ["JsIntel", "analyse_text", "main", "EXIT_OK", "EXIT_ERROR"]

EXIT_OK = 0
EXIT_ERROR = 2

# --------------------------------------------------------------------------- #
# Patrones de extracción
# --------------------------------------------------------------------------- #

ABS_URL_RE = re.compile(r"https?://[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*")

FETCH_LIKE_RE = re.compile(
    r"(?:(?:fetch|axios(?:\.\w+)?|jQuery\.ajax|\$\.(?:get|post|getJSON|ajax)|"
    r"XMLHttpRequest|\.open)\s*\(?\s*)[\"'`]([^\"'`\s]{2,})",
    re.IGNORECASE,
)

XHR_OPEN_RE = re.compile(
    r"\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['\"]\s*,\s*"
    r"['\"]([^'\"\s]{2,})",
    re.IGNORECASE,
)

#: Valores que no son endpoints (métodos HTTP capturados por error).
HTTP_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}
)

URL_PROP_RE = re.compile(r"\burl\s*:\s*[\"'`]([^\"'`\s]{2,})", re.IGNORECASE)

QUOTED_PATH_RE = re.compile(r"[\"'`](/[A-Za-z0-9_\-./{}:$?&=]{2,})[\"'`]")

SCRIPT_TAG_RE = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
LINK_TAG_RE = re.compile(r"<link\b([^>]*)>", re.IGNORECASE)
INLINE_SCRIPT_RE = re.compile(
    r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL
)
ATTR_RE = re.compile(
    r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"""
)
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")

GRAPHQL_OP_RE = re.compile(
    r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)?\s*[({]",
    re.IGNORECASE,
)
GRAPHQL_MARKERS = ("__typename", "__schema", "__type", "gql`", "graphql")

#: Rutas administrativas o sensibles.
SENSITIVE_ROUTE_RE = re.compile(
    r"(?i)^/?(?:"
    r"admin|administrator|administracion|wp-admin|phpmyadmin|adminer|"
    r"manager/html|actuator|internal|intranet|debug|config|configuration|"
    r"console|backoffice|dashboard|panel|cpanel|webadmin|filemanager|"
    r"swagger|swagger-ui|api-docs|openapi|graphql|graphiql|graphql/playground|"
    r"server-status|phpinfo|elmah|trace|metrics|healthcheck"
    r")(?:/|$|\.)"
)
SENSITIVE_FRAGMENT_RE = re.compile(
    r"(?i)(?:^|/)"
    r"(?:\.env|\.git|\.svn|\.hg|backup|dump|export|credentials|secrets?|"
    r"id_rsa|\.pem$|wp-config|database|db_backup)"
)

#: Categorías de terceros. La pregunta es siempre: ¿de quién son estos datos?
THIRD_PARTY_CATEGORIES: dict[str, tuple[str, ...]] = {
    "analitica": (
        "google-analytics.com", "googletagmanager.com", "analytics.google",
        "doubleclick.net", "facebook.net", "clarity.ms", "hotjar.com", "matomo",
        "piwik", "posthog", "umami.is", "mixpanel", "segment.io", "amplitude",
        "fullstory", "logrocket", "newrelic.com", "sentry.io", "bugsnag",
    ),
    "cdn": (
        "cdnjs.cloudflare.com", "unpkg.com", "jsdelivr.net", "cloudflare.com",
        "googleapis.com", "gstatic.com", "bootstrapcdn.com", "statically.io",
        "bunny.net", "fastly.net", "akamaized.net", "akamai", "cloudfront.net",
        "cdn.", "jsdelivr",
    ),
    "pagos": (
        "stripe.com", "paypal.com", "paypalobjects.com", "mercadopago",
        "conekta.com", "clip.mx", "seamless", "squareup.com", "razorpay",
    ),
    "mapas": ("mapbox.com", "mapbox", "openstreetmap.org", "here.com"),
    "fuentes": ("fonts.googleapis", "fonts.gstatic", "typekit.net", "fontawesome"),
    "formularios": ("recaptcha", "hcaptcha.com", "turnstile.cloudflare.com"),
    "citas": (
        "calendly.com", "cal.com", "simplybook.it", "setmore.com", "nylas.com",
        "jotform.com", "typeform.com", "acuityscheduling.com",
    ),
    "correo": ("mailchimp.com", "sendgrid.net", "mailgun.org", "hubspot.com",
               "klaviyo.com", "sendinblue.com"),
    "redes_sociales": (
        "facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com",
        "youtube.com", "tiktok.com", "wa.me", "whatsapp.com",
    ),
    "soporte": (
        "intercom.io", "zendesk.com", "crisp.chat", "tawk.to", "livechatinc.com",
        "drift.com", "hubspot.com",
    ),
}

#: Extensiones que se analizan cuando se pasa un directorio.
CODE_SUFFIXES: frozenset[str] = frozenset(
    {".html", ".htm", ".xhtml", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue"}
)


@dataclass
class JsIntel:
    """Resultado del análisis de un fichero."""

    file: str
    api_endpoints: list[str] = field(default_factory=list)
    sensitive_routes: list[str] = field(default_factory=list)
    third_party_hosts: list[dict[str, str]] = field(default_factory=list)
    graphql_operations: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    scripts: list[dict[str, Any]] = field(default_factory=list)
    stylesheets: list[str] = field(default_factory=list)
    inline_secrets: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "api_endpoints": self.api_endpoints,
            "sensitive_routes": self.sensitive_routes,
            "third_party_hosts": self.third_party_hosts,
            "graphql_operations": self.graphql_operations,
            "source_maps": self.source_maps,
            "scripts": self.scripts,
            "stylesheets": self.stylesheets,
            "inline_secrets": self.inline_secrets,
        }


def _attrs(fragment: str) -> dict[str, str]:
    """Extrae los atributos de una etiqueta HTML."""
    attributes: dict[str, str] = {}
    for match in ATTR_RE.finditer(fragment):
        name = match.group(1).lower()
        value = match.group(2) or match.group(3) or match.group(4) or ""
        attributes[name] = value
    return attributes


def _host_of(url: str) -> str:
    """Extrae el host de una URL (vacío si es relativa)."""
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/:?#]+)", url)
    if match:
        return match.group(1).lower()
    return ""


def _path_of(url: str) -> str:
    """Extrae la ruta de una URL (o la propia ruta relativa)."""
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/]*([^?#]*)", url)
    if match:
        return match.group(1) or "/"
    return url.split("?", 1)[0].split("#", 1)[0]


def _classify_third_party(host: str) -> str:
    """Clasifica un host de terceros por categoría."""
    for category, fragments in THIRD_PARTY_CATEGORIES.items():
        for fragment in fragments:
            if fragment in host:
                return category
    return "otro"


def _is_own_host(host: str, own: Iterable[str]) -> bool:
    """¿El host es del propio cliente (o de un subdominio suyo)?"""
    for candidate in own:
        if host == candidate or host.endswith("." + candidate):
            return True
    return False


def _is_sensitive_path(path: str) -> bool:
    """¿La ruta es administrativa o sensible?"""
    if SENSITIVE_ROUTE_RE.match(path):
        return True
    return bool(SENSITIVE_FRAGMENT_RE.search(path))


def analyse_text(
    text: str, filename: str = "<memoria>", base_hosts: Iterable[str] = ()
) -> JsIntel:
    """Analiza un documento HTML/JS y devuelve la superficie detectada.

    ``base_hosts`` son los hosts **propios** del cliente: no se cuentan como
    terceros (el resto sí, que es la pregunta que importa: ¿a dónde salen los
    datos del navegador del paciente?).
    """
    intel = JsIntel(file=filename)
    own = {host.strip().lower() for host in base_hosts if host.strip()}

    # -- URLs absolutas ------------------------------------------------------ #
    absolute = {m.group(0).rstrip(".,;)'\"") for m in ABS_URL_RE.finditer(text)}

    # -- Endpoints ------------------------------------------------------------ #
    candidates: set[str] = set()
    for match in FETCH_LIKE_RE.finditer(text):
        candidates.add(match.group(1))
    for match in XHR_OPEN_RE.finditer(text):
        candidates.add(match.group(1))
    for match in URL_PROP_RE.finditer(text):
        candidates.add(match.group(1))
    for match in QUOTED_PATH_RE.finditer(text):
        candidates.add(match.group(1))
    candidates.update(absolute)

    for candidate in sorted(candidates):
        candidate = candidate.strip()
        if not candidate or candidate.startswith(("data:", "javascript:", "#")):
            continue
        if candidate.upper() in HTTP_METHODS:
            continue
        if candidate.startswith(("http://", "https://")):
            host = _host_of(candidate)
            path = _path_of(candidate)
            intel.api_endpoints.append(candidate)
            if host:
                if not _is_own_host(host, own):
                    intel.third_party_hosts.append(
                        {"host": host, "categoria": _classify_third_party(host)}
                    )
            if _is_sensitive_path(path):
                intel.sensitive_routes.append(candidate)
        elif candidate.startswith("/"):
            intel.api_endpoints.append(candidate)
            if _is_sensitive_path(candidate):
                intel.sensitive_routes.append(candidate)

    # -- Deduplicación -------------------------------------------------------- #
    intel.api_endpoints = sorted(set(intel.api_endpoints))
    intel.sensitive_routes = sorted(set(intel.sensitive_routes))
    seen_hosts: dict[str, dict[str, str]] = {}
    for entry in intel.third_party_hosts:
        seen_hosts.setdefault(entry["host"], entry)
    intel.third_party_hosts = [
        seen_hosts[host] for host in sorted(seen_hosts)
    ]

    # -- GraphQL --------------------------------------------------------------- #
    operations: list[str] = []
    for match in GRAPHQL_OP_RE.finditer(text):
        name = match.group(2) or "(anónimo)"
        operations.append(f"{match.group(1).lower()} {name}")
    for marker in GRAPHQL_MARKERS:
        if marker in text:
            operations.append(f"marcador:{marker}")
    intel.graphql_operations = sorted(set(operations))

    # -- Source maps ------------------------------------------------------------ #
    intel.source_maps = sorted({m.group(1) for m in SOURCEMAP_RE.finditer(text)})

    # -- Scripts y hojas de estilo ----------------------------------------------- #
    for match in SCRIPT_TAG_RE.finditer(text):
        attributes = _attrs(match.group(1))
        src = attributes.get("src", "").strip()
        integrity = attributes.get("integrity", "").strip()
        crossorigin = attributes.get("crossorigin", "").strip()
        intel.scripts.append(
            {
                "src": src,
                "integrity": integrity,
                "crossorigin": crossorigin,
                "sri": bool(integrity),
                "crossorigin_presente": bool(crossorigin),
                "inline": not src,
            }
        )
    for match in LINK_TAG_RE.finditer(text):
        attributes = _attrs(match.group(1))
        href = attributes.get("href", "").strip()
        rel = attributes.get("rel", "").lower()
        if href and ("stylesheet" in rel or href.endswith(".css")):
            intel.stylesheets.append(href)

    # -- Secretos en scripts inline ---------------------------------------------- #
    inline_blocks = [m.group(1) for m in INLINE_SCRIPT_RE.finditer(text)]
    if inline_blocks:
        findings = scan_text(
            "\n".join(inline_blocks),
            patterns=SECRET_PATTERNS,
            filename=filename,
        )
        intel.inline_secrets = [
            {
                "line": finding.line,
                "type": finding.type,
                "severity": finding.severity,
                "masked": finding.masked,
                "sha256": finding.sha256,
                "context": finding.context,
            }
            for finding in findings
        ]
    return intel


# --------------------------------------------------------------------------- #
# Informe
# --------------------------------------------------------------------------- #


def render_markdown(results: Sequence[JsIntel]) -> str:
    """Genera el informe en Markdown."""
    lines: list[str] = ["# Informe de inteligencia de HTML/JS", ""]
    lines.append(
        f"Ficheros analizados: **{len(results)}** · "
        f"endpoints: **{sum(len(r.api_endpoints) for r in results)}** · "
        f"scripts sin SRI: "
        f"**{sum(1 for r in results for s in r.scripts if s['src'] and not s['sri'])}**"
    )
    lines.append("")

    total_third_party: dict[str, set[str]] = {}
    total_secrets = 0
    for result in results:
        for entry in result.third_party_hosts:
            total_third_party.setdefault(entry["categoria"], set()).add(entry["host"])
        total_secrets += len(result.inline_secrets)

    lines.append("## Hosts de terceros detectados")
    lines.append("")
    if total_third_party:
        lines.append("| Categoría | Hosts |")
        lines.append("|---|---|")
        for category in sorted(total_third_party):
            hosts = ", ".join(f"`{h}`" for h in sorted(total_third_party[category]))
            lines.append(f"| {category} | {hosts} |")
    else:
        lines.append("_(ninguno)_")
    lines.append("")

    if total_secrets:
        lines.append(
            f"> **Aviso:** {total_secrets} secreto(s) potencial(es) en scripts "
            "inline. Los valores están enmascarados; consúltese "
            "`secrets_scan.py` para el detalle."
        )
        lines.append("")

    for result in results:
        lines.append(f"## {result.file}")
        lines.append("")
        lines.append(f"- Endpoints detectados: **{len(result.api_endpoints)}**")
        lines.append(
            f"- Rutas sensibles/administrativas: **{len(result.sensitive_routes)}**"
        )
        lines.append(f"- Hosts de terceros: **{len(result.third_party_hosts)}**")
        lines.append(f"- Operaciones GraphQL: **{len(result.graphql_operations)}**")
        lines.append(
            f"- Scripts externos sin SRI: "
            f"**{sum(1 for s in result.scripts if s['src'] and not s['sri'])}**"
            f" de {sum(1 for s in result.scripts if s['src'])}"
        )
        lines.append("")

        if result.api_endpoints:
            lines.append("### Endpoints")
            lines.append("")
            for endpoint in result.api_endpoints[:80]:
                lines.append(f"- `{endpoint}`")
            if len(result.api_endpoints) > 80:
                lines.append(f"- _… y {len(result.api_endpoints) - 80} más_")
            lines.append("")

        if result.sensitive_routes:
            lines.append("### Rutas sensibles")
            lines.append("")
            for route in result.sensitive_routes:
                lines.append(f"- `{route}`")
            lines.append("")

        if result.scripts:
            lines.append("### Scripts")
            lines.append("")
            lines.append("| src | SRI | crossorigin |")
            lines.append("|---|---|---|")
            for script in result.scripts:
                if not script["src"]:
                    continue
                lines.append(
                    f"| `{script['src']}` | "
                    f"{'sí' if script['sri'] else 'NO'} | "
                    f"{script['crossorigin'] or '—'} |"
                )
            lines.append("")

        if result.graphql_operations:
            lines.append("### GraphQL")
            lines.append("")
            for operation in result.graphql_operations:
                lines.append(f"- `{operation}`")
            lines.append("")

        if result.source_maps:
            lines.append("### Source maps")
            lines.append("")
            for source_map in result.source_maps:
                lines.append(f"- `{source_map}`")
            lines.append("")

        if result.inline_secrets:
            lines.append("### Secretos en scripts inline")
            lines.append("")
            lines.append("| Línea | Tipo | Severidad | Máscara |")
            lines.append("|---|---|---|---|")
            for secret in result.inline_secrets:
                lines.append(
                    f"| {secret['line']} | {secret['type']} | "
                    f"{secret['severity']} | `{secret['masked']}` |"
                )
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*Análisis estático sobre ficheros locales. No se ha realizado ninguna "
        "petición de red.*"
    )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="js_intel.py",
        description=(
            "Analiza HTML/JS ya descargados y extrae endpoints, terceros, "
            "GraphQL, source maps, SRI y secretos en scripts inline. Sin red."
        ),
        epilog=(
            "Ejemplos:\n"
            "  python3 js_intel.py ./evidencia/home.html\n"
            "  python3 js_intel.py ./evidencia/ --json --out js_intel.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Ficheros o directorios con HTML/JS.",
    )
    parser.add_argument(
        "--base-host",
        action="append",
        default=[],
        metavar="HOST",
        help=(
            "Host propio del cliente: no se contará como tercero (repetible). "
            "Ej.: --base-host ejemplo-auditoria.mx"
        ),
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        default=None,
        help="Fichero Markdown donde escribir el informe.",
    )
    parser.add_argument(
        "--json-out",
        metavar="FILE",
        default=None,
        help="Fichero JSON donde escribir los datos.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida en JSON por pantalla.",
    )
    return parser


def _collect(paths: Sequence[str]) -> list[Path]:
    """Expande las rutas de entrada a ficheros de código."""
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if not child.is_file():
                    continue
                if child.suffix.lower() in CODE_SUFFIXES:
                    files.append(child)
        else:
            raise FileNotFoundError(raw)
    return files


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        files = _collect(args.paths)
    except FileNotFoundError as exc:
        print(f"ERROR: no existe la ruta '{exc}'.", file=sys.stderr)
        return EXIT_ERROR

    results: list[JsIntel] = []
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"ERROR: no se pudo leer '{file_path}': {exc}", file=sys.stderr)
            return EXIT_ERROR
        results.append(
            analyse_text(text, filename=str(file_path), base_hosts=args.base_host)
        )

    markdown = render_markdown(results)
    payload = {
        "tool": "js_intel",
        "files": [result.to_dict() for result in results],
        "summary": {
            "files": len(results),
            "api_endpoints": sum(len(r.api_endpoints) for r in results),
            "sensitive_routes": sum(len(r.sensitive_routes) for r in results),
            "third_party_hosts": sum(len(r.third_party_hosts) for r in results),
            "graphql_operations": sum(len(r.graphql_operations) for r in results),
            "scripts_without_sri": sum(
                1 for r in results for s in r.scripts if s["src"] and not s["sri"]
            ),
            "inline_secrets": sum(len(r.inline_secrets) for r in results),
        },
    }

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(markdown, encoding="utf-8")
    if args.json_out:
        json_path = Path(args.json_out)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(markdown)
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
