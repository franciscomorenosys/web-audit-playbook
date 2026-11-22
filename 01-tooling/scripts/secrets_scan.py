#!/usr/bin/env python3
"""Escaneo **local** de ficheros en busca de secretos expuestos.

Esta herramienta **no toca la red**: sólo lee ficheros del disco (repositorios,
volcados de HTML/JS descargados, ficheros de configuración) y busca credenciales
que se hayan quedado exposed.

Garantías duras del RoE:

* El valor completo de un secreto **nunca** se escribe ni en la salida ni en el
  fichero generado. Sólo se muestra una máscara (4 primeros + 2 últimos) y el
  ``sha256[:12]`` de su hash, para poder correlacionar sin revelar.
* El contexto que se muestra también se raspa: se re-redactan todos los secretos
  que aparezcan en la línea de contexto.
* No se intenta **verificar** ninguna credencial contra su proveedor (eso sería
  de-anonimización, RoE 1.3).

Uso::

    python3 secrets_scan.py ./mi-repositorio
    python3 secrets_scan.py ./evidencia --json --out secretos.json
    python3 secrets_scan.py ./evidencia --redact-in-place --redact-out ./copia
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

__all__ = [
    "SecretPattern",
    "PATTERNS",
    "Finding",
    "AllowlistRule",
    "load_allowlist",
    "scan_text",
    "scan_file",
    "scan_path",
    "mask_value",
    "shannon_entropy",
    "SEVERITY_ORDER",
    "EXIT_OK",
    "EXIT_FINDINGS",
    "EXIT_ERROR",
]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

SEVERITY_ORDER: dict[str, int] = {
    "critico": 4,
    "alto": 3,
    "medio": 2,
    "bajo": 1,
    "info": 0,
}

#: Directorios que nunca se recorren (ruido, volumen y dependencias).
DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "dist",
        "build",
        "out",
        "vendor",
        ".next",
        ".nuxt",
        ".cache",
        ".idea",
        ".vscode",
        "coverage",
        "site-packages",
    }
)

#: Extensionestreated como texto. Cualquier otra se salta (binarios, comprimidos).
TEXT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".txt", ".md", ".markdown", ".rst", ".csv", ".tsv", ".log",
        ".json", ".json5", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg",
        ".conf", ".env", ".properties", ".xml", ".html", ".htm", ".xhtml",
        ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".astro",
        ".py", ".rb", ".php", ".java", ".kt", ".kts", ".go", ".rs", ".c", ".h",
        ".cc", ".cpp", ".hpp", ".cs", ".swift", ".sql", ".sh", ".bash", ".zsh",
        ".ps1", ".bat", ".cmd", ".gradle", ".dockerfile", ".tf", ".tfvars",
        ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".jks", ".keystore",
        ".npmrc", ".pypirc", ".netrc", ".envrc", ".gitconfig", ".htpasswd",
        ".editorconfig", ".babelrc", ".eslintrc", ".gitignore", ".dockerignore",
        ".apk", ".ipa", ".map", ".lock", ".txt",
    }
)

#: Nombres de fichero sin extensión que sí son texto.
TEXT_FILENAMES: frozenset[str] = frozenset(
    {
        "dockerfile",
        "makefile",
        "jenkinsfile",
        "procfile",
        "license",
        "readme",
        "npmrc",
        "pypirc",
        "netrc",
        "env",
        "htaccess",
        "web.config",
    }
)

MAX_FILE_BYTES = 4_000_000
MAX_CONTEXT_CHARS = 160


@dataclass(frozen=True)
class SecretPattern:
    """Regla de detección de un tipo de secreto."""

    name: str
    regex: re.Pattern[str]
    severity: str
    description: str = ""
    #: Si es ``False`` el filtro de entropía no se aplica (el formato ya es
    #: suficientemente específico: ``AKIA...``, ``sk_live_...``...).
    entropy_check: bool = True
    #: Grupo del regex que contiene el valor real (por defecto, el grupo 1).
    group: int = 1


def _p(
    name: str,
    pattern: str,
    severity: str,
    description: str = "",
    *,
    flags: int = 0,
    entropy_check: bool = True,
    group: int = 1,
) -> SecretPattern:
    """Ayudante para declarar patrones de forma compacta."""
    return SecretPattern(
        name=name,
        regex=re.compile(pattern, flags),
        severity=severity,
        description=description,
        entropy_check=entropy_check,
        group=group,
    )


#: Catálogo de patrones. El orden importa: los más específicos primero.
PATTERNS: tuple[SecretPattern, ...] = (
    # -- AWS ---------------------------------------------------------------- #
    _p(
        "aws_access_key_id",
        r"\b((?:AKIA|ASIA|AIDA|AROA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16})\b",
        "critico",
        "Clave de acceso AWS (access key id).",
        entropy_check=False,
    ),
    _p(
        "aws_secret_access_key",
        r"(?i)aws[\w\- ]{0,24}?(?:secret|sk)[\w\- =]{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]",
        "critico",
        "Clave secreta de acceso AWS junto a su etiqueta.",
    ),
    # -- Google / Firebase -------------------------------------------------- #
    _p(
        "google_api_key",
        r"\b(AIza[0-9A-Za-z\-_]{35})\b",
        "alto",
        "Clave de API de Google.",
        entropy_check=False,
    ),
    _p(
        "firebase_url",
        r"\b(https?://[a-z0-9\-]+\.firebaseio\.com)",
        "alto",
        "URL de base de datos Firebase.",
        entropy_check=False,
    ),
    _p(
        "service_account_json",
        r"[\"']private_key[\"']\s*:\s*[\"'](-----BEGIN [A-Z ]*PRIVATE KEY-----)",
        "critico",
        "Service account JSON de Google Cloud.",
        entropy_check=False,
    ),
    _p(
        "service_account_client_email",
        r"[\"']client_email[\"']\s*:\s*[\"']([^\"'@\s]+@[^\"'@\s]+\.iam\.gserviceaccount\.com)[\"']",
        "alto",
        "Correo de una service account de GCP.",
        entropy_check=False,
    ),
    # -- Pagos -------------------------------------------------------------- #
    _p(
        "stripe_secret_key",
        r"\b((?:sk|rk)_live_[0-9A-Za-z]{10,})\b",
        "critico",
        "Clave secreta de Stripe en modo live.",
        entropy_check=False,
    ),
    _p(
        "stripe_webhook_secret",
        r"\b(whsec_[0-9A-Za-z]{16,})\b",
        "alto",
        "Secreto de webhook de Stripe.",
        entropy_check=False,
    ),
    # -- IA ----------------------------------------------------------------- #
    _p(
        "openai_api_key",
        r"\b((?:sk-proj-)?sk-[A-Za-z0-9]{32,})\b",
        "critico",
        "Clave de API de OpenAI.",
        entropy_check=False,
    ),
    _p(
        "anthropic_api_key",
        r"\b(sk-ant-[A-Za-z0-9_\-]{24,})\b",
        "critico",
        "Clave de API de Anthropic.",
        entropy_check=False,
    ),
    # -- GitHub / GitLab ---------------------------------------------------- #
    _p(
        "github_token",
        r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
        "critico",
        "Token personal de GitHub.",
        entropy_check=False,
    ),
    _p(
        "gitlab_token",
        r"\b(glpat-[A-Za-z0-9_\-]{20,})\b",
        "critico",
        "Token de acceso personal de GitLab.",
        entropy_check=False,
    ),
    # -- Mensajería --------------------------------------------------------- #
    _p(
        "slack_token",
        r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b",
        "critico",
        "Token de Slack.",
        entropy_check=False,
    ),
    _p(
        "slack_webhook",
        r"\b(https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+)",
        "alto",
        "Webhook de entrada de Slack.",
        entropy_check=False,
    ),
    _p(
        "discord_webhook",
        r"\b(https://discord(?:app)?\.com/api/webhooks/[0-9]{6,}/[0-9A-Za-z_\-]{20,})",
        "alto",
        "Webhook de Discord.",
        entropy_check=False,
    ),
    _p(
        "twilio_account_sid",
        r"\b(AC[0-9a-fA-F]{32})\b",
        "medio",
        "Account SID de Twilio.",
        entropy_check=False,
    ),
    _p(
        "twilio_auth_token",
        r"\b(SK[0-9a-fA-F]{32})\b",
        "critico",
        "Auth token de Twilio.",
        entropy_check=False,
    ),
    _p(
        "sendgrid_api_key",
        r"\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b",
        "critico",
        "Clave de API de SendGrid.",
        entropy_check=False,
    ),
    _p(
        "mailgun_api_key",
        r"\b(key-[0-9a-zA-Z]{32})\b",
        "alto",
        "Clave de API de Mailgun.",
        entropy_check=False,
    ),
    # -- Observabilidad / mapas --------------------------------------------- #
    _p(
        "sentry_dsn",
        r"\b(https://[0-9a-f]{16,}@[A-Za-z0-9.\-]+\.ingest\.sentry\.io/[0-9]+)",
        "medio",
        "DSN de Sentry (permite envío de eventos, no acceso).",
        entropy_check=False,
    ),
    _p(
        "mapbox_token",
        r"\b((?:sk|pk)\.[A-Za-z0-9]{20,}\.[A-Za-z0-9\-]{10,})\b",
        "medio",
        "Token de Mapbox.",
        entropy_check=False,
    ),
    # -- Tokens genéricos --------------------------------------------------- #
    _p(
        "jwt",
        r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b",
        "alto",
        "JWT (puede contener datos y permisos).",
        entropy_check=False,
    ),
    _p(
        "private_key_block",
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
        "critico",
        "Cabecera de un bloque de clave privada.",
        entropy_check=False,
    ),
    _p(
        "connection_uri_credentials",
        r"\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|mssql)://[^\s:@/'\"]+:[^\s:@/'\"]+@[A-Za-z0-9.\-]+)",
        "critico",
        "URI de conexión con usuario y contraseña embebidos.",
        entropy_check=False,
    ),
    _p(
        "url_embedded_credentials",
        r"\b(https?://[^\s:/@'\"]+:[^\s:/@'\"]+@[A-Za-z0-9.\-]+)",
        "alto",
        "URL con credenciales embebidas.",
        entropy_check=False,
    ),
    # -- Ficheros de paquete / registries ----------------------------------- #
    _p(
        "npm_auth_token",
        r"(?im)^\s*(_authToken|_auth|_password)\s*=\s*(\S{8,})",
        "critico",
        "Token de autenticación en .npmrc.",
        group=2,
    ),
    _p(
        "pypi_password",
        r"(?im)^\s*(pypi-[A-Za-z0-9_\-]+)\s*=\s*(.+)$",
        "alto",
        "Contraseña de un registro en .pypirc.",
        group=2,
    ),
    _p(
        "git_token",
        r"(?i)\b(?:git[_\-]?token|gitlab[_\-]?token|gl[_\-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})",
        "alto",
        "Token de Git (Lab/GitHub) asignado a una variable.",
    ),
    # -- Asignaciones genéricas ---------------------------------------------- #
    _p(
        "generic_credential_assignment",
        r"(?i)\b((?:password|passwd|pwd|api[_\-]?key|apikey|api[_\-]?token|secret[_\-]?key|secret|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|private[_\-]?key|passphrase)\b\s*[:=]\s*['\"]?([^\s'\";,<>)]{6,}))",
        "medio",
        "Asignación de credencial genérica.",
        group=2,
    ),
)


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #


def shannon_entropy(value: str) -> float:
    """Entropía de Shannon (bits por carácter) de una cadena."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def mask_value(value: str) -> str:
    """Máscara segura: 4 primeros + 2 últimos caracteres, resto oculto."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * 6}{value[-2:]}"


def value_hash(value: str) -> str:
    """SHA-256 (12 hex) del valor, para correlacionar sin revelar."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def _looks_like_placeholder(value: str) -> bool:
    """Filtra valores obviously no-secrets (``changeme``, ``xxxx``, ``null``...)."""
    lowered = value.strip().lower()
    if lowered in {
        "none", "null", "true", "false", "undefined", "example", "test",
        "changeme", "change_me", "your_password", "yourpassword", "password",
        "secret", "todo", "xxx", "insert", "placeholder",
    }:
        return True
    if len(set(lowered)) <= 2:
        return True
    if re.fullmatch(r"[\*xX\.\-_]+", value):
        return True
    # Referencias a variables o plantillas: `${VAR}`, `{{var}}`, `<valor>`,
    # `$VAR`. No son secretos: son huecos que rellena el shell o la plantilla.
    if re.fullmatch(
        r"\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>]*>|\$[A-Za-z_][A-Za-z0-9_]*", value
    ):
        return True
    # Valores YA redactados (`[REDACTED:...]`, `***REDACTED***`): el marcador
    # está puesto, luego no hay nada que proteger en ese fragmento.
    if "redacted" in lowered or "redactado" in lowered:
        return True
    return False


# --------------------------------------------------------------------------- #
# Allowlist de secretos sintéticos
# --------------------------------------------------------------------------- #
#
# Un proyecto puede tener secretos **ficticios** que existen a propósito:
# los fixtures de la auto-prueba, el ejercicio de la guía de formación o los
# ejemplos documentados. Esos valores ya están declarados en el fichero
# `.gitleaks.toml` del proyecto —la lista de allowlist que usa Gitleaks en la
# CI—, así que este escáner la reutiliza en lugar de mantener una segunda.
#
# Semántica (la misma que Gitleaks): un hallazgo se descarta si la RUTA del
# fichero casa con `paths` Y el valor detectado casa con alguno de los
# `regexes`. La comparación del valor se hace contra la LÍNEA donde aparece
# (Gitleaks compara sólo el grupo capturado): es algo más amplia, pero las
# rutas acotan el alcance a las rutas declaradas.
#
# El fichero de allowlist **no se escanea**: contiene literalmente los valores
# que declara, igual que Gitleaks lo excluye de su propio análisis.


@dataclass(frozen=True)
class AllowlistRule:
    """Un bloque ``[[allowlists]]`` de Gitleaks: rutas + valores conocidos."""

    description: str
    paths: tuple[re.Pattern[str], ...]
    regexes: tuple[re.Pattern[str], ...]

    def allows(self, file_path: str, line: str) -> bool:
        """¿Este hallazgo está permitido en este fichero?"""
        if not self.paths or not self.regexes:
            return False
        if not any(pattern.search(file_path) for pattern in self.paths):
            return False
        return any(pattern.search(line) for pattern in self.regexes)


def load_allowlist(config_path: str | Path) -> list[AllowlistRule]:
    """Lee los bloques ``[[allowlists]]`` de un fichero ``.gitleaks.toml``."""
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
        return []
    try:
        with Path(config_path).open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError):
        return []
    rules: list[AllowlistRule] = []
    for block in data.get("allowlists", []) or []:
        raw_paths = block.get("paths") or []
        raw_regexes = block.get("regexes") or []
        if not raw_paths or not raw_regexes:
            continue
        try:
            paths = tuple(re.compile(str(item)) for item in raw_paths)
            regexes = tuple(re.compile(str(item)) for item in raw_regexes)
        except re.error:
            continue
        rules.append(
            AllowlistRule(
                description=str(block.get("description", "")),
                paths=paths,
                regexes=regexes,
            )
        )
    return rules


def _auto_allowlist(target: Path) -> tuple[list[AllowlistRule], Path | None]:
    """Allowlist declarada en la raíz del proyecto escaneado (si la hay).

    Sólo se busca en la raíz del **directorio** escaneado: escanear un fichero
    suelto no activa ninguna allowlist, porque el fichero puede ser un
    fragmento de evidencia que no tiene nada que ver con el repositorio.
    """
    if not target.is_dir():
        return [], None
    config = target / ".gitleaks.toml"
    if not config.is_file():
        return [], None
    return load_allowlist(config), config


# --------------------------------------------------------------------------- #
# Modelo de hallazgo
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Finding:
    """Un secreto detectado. **Nunca contiene el valor completo.**"""

    file: str
    line: int
    column: int
    type: str
    severity: str
    masked: str
    sha256: str
    context: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Vista serializable (sin el valor original)."""
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "type": self.type,
            "severity": self.severity,
            "masked": self.masked,
            "sha256": self.sha256,
            "context": self.context,
            "description": self.description,
        }


def _collect_matches(
    text: str,
    patterns: Sequence[SecretPattern],
    min_entropy: float,
) -> list[tuple[int, int, int, str, str]]:
    """Localiza los secretos sin solapamientos.

    Devuelve ``(inicio, fin, índice_de_patrón, nombre, valor)``. Cuando dos
    patrones chocan sobre el mismo fragmento gana **el más específico**, que es
    el que aparece antes en :data:`PATTERNS` (una clave de AWS no debe quedar
    tapada por la regla genérica de «password =»).
    """
    candidates: list[tuple[int, int, int, str, str]] = []
    for index, pattern in enumerate(patterns):
        for match in pattern.regex.finditer(text):
            try:
                value = match.group(pattern.group)
            except (IndexError, re.error):
                continue
            if not value or _looks_like_placeholder(value):
                continue
            if pattern.entropy_check and shannon_entropy(value) < min_entropy:
                continue
            candidates.append((match.start(), match.end(), index, pattern.name, value))

    candidates.sort(key=lambda item: (item[2], item[0]))
    accepted: list[tuple[int, int, int, str, str]] = []
    for candidate in candidates:
        start, end = candidate[0], candidate[1]
        if any(start < other[1] and other[0] < end for other in accepted):
            continue
        accepted.append(candidate)
    accepted.sort(key=lambda item: item[0])
    return accepted


def _apply_matches(
    text: str, matches: Sequence[tuple[int, int, int, str, str]]
) -> str:
    """Sustituye los fragmentos encontrados por su marca redactada."""
    result = text
    for start, end, _index, name, value in reversed(matches):
        result = result[:start] + f"[REDACTED:{name}:{mask_value(value)}]" + result[end:]
    return result


def _scrub(text: str, patterns: Sequence[SecretPattern]) -> str:
    """Vuelve a redactar todos los secretos presentes en un fragmento de texto."""
    matches = _collect_matches(text, patterns, min_entropy=0.0)
    return _apply_matches(text, matches)


# --------------------------------------------------------------------------- #
# Escaneo
# --------------------------------------------------------------------------- #


def scan_text(
    text: str,
    *,
    patterns: Sequence[SecretPattern] = PATTERNS,
    min_entropy: float = 3.0,
    filename: str = "<memoria>",
    max_context: int = MAX_CONTEXT_CHARS,
    allowlist: Sequence[AllowlistRule] = (),
) -> list[Finding]:
    """Busca secretos en un texto y devuelve hallazgos sin valores completos."""
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    lines = text.splitlines()

    for pattern in patterns:
        for match in pattern.regex.finditer(text):
            try:
                value = match.group(pattern.group)
            except (IndexError, re.error):
                continue
            if not value:
                continue
            if _looks_like_placeholder(value):
                continue
            if pattern.entropy_check and shannon_entropy(value) < min_entropy:
                continue

            line_no = text.count("\n", 0, match.start()) + 1
            column = match.start() - (text.rfind("\n", 0, match.start()) + 1) + 1
            key = (line_no, value)
            if key in seen:
                continue
            seen.add(key)

            raw_context = ""
            if 0 < line_no <= len(lines):
                raw_context = lines[line_no - 1].strip()
            # Valor declarado como sintético en la allowlist del proyecto:
            # no es un secreto, es un ejemplo. No se reporta.
            if allowlist and any(
                rule.allows(filename, raw_context) for rule in allowlist
            ):
                continue
            # Se raspa la línea COMPLETA y luego se recorta: si se recortase
            # antes, un secreto partido por el corte podría quedar sin enmascarar.
            context = _scrub(raw_context, patterns)
            if len(context) > max_context:
                context = context[:max_context] + "…"

            findings.append(
                Finding(
                    file=filename,
                    line=line_no,
                    column=column,
                    type=pattern.name,
                    severity=pattern.severity,
                    masked=mask_value(value),
                    sha256=value_hash(value),
                    context=context,
                    description=pattern.description,
                )
            )

    findings.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line, f.column)
    )
    return findings


def _looks_binary(chunk: bytes) -> bool:
    """Detecta binarios por el byte nulo (heurística simple y suficiente)."""
    return b"\x00" in chunk


def scan_file(
    path: str | Path,
    *,
    patterns: Sequence[SecretPattern] = PATTERNS,
    min_entropy: float = 3.0,
    max_file_bytes: int = MAX_FILE_BYTES,
    allowlist: Sequence[AllowlistRule] = (),
) -> list[Finding]:
    """Escanea un fichero local. Devuelve ``[]`` si es binario o ilegible."""
    p = Path(path)
    try:
        if p.stat().st_size > max_file_bytes:
            return []
        raw = p.read_bytes()
    except OSError:
        return []
    if _looks_binary(raw[:4096]):
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except Exception:  # pragma: no cover - defensivo
            return []
    return scan_text(
        text,
        patterns=patterns,
        min_entropy=min_entropy,
        filename=str(p),
        allowlist=allowlist,
    )


def _is_text_file(path: Path) -> bool:
    """Decide si un fichero merece la pena abrirse como texto."""
    name = path.name.lower()
    if name in TEXT_FILENAMES:
        return True
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    # Ficheros sin extensión que claramente son texto de config.
    if not path.suffix:
        try:
            with path.open("rb") as handle:
                return not _looks_binary(handle.read(2048))
        except OSError:
            return False
    return False


class _GitIgnore:
    """Interpretación *básica* de un ``.gitignore`` (suficiente para el caso)."""

    def __init__(self, base: Path, lines: Sequence[str]) -> None:
        self.base = base
        self.rules: list[tuple[str, bool, bool, bool]] = []
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            if negated:
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            anchored = "/" in line
            if line.startswith("/"):
                line = line.lstrip("/")
            self.rules.append((line, negated, dir_only, anchored))

    @classmethod
    def load(cls, base: Path) -> "_GitIgnore":
        """Carga el ``.gitignore`` de un directorio (si existe)."""
        candidate = base / ".gitignore"
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        return cls(base, lines)

    def ignores(self, path: Path, is_dir: bool) -> bool:
        """Indica si un ruta queda excluida por las reglas."""
        try:
            relative = path.relative_to(self.base)
        except ValueError:
            return False
        rel_str = relative.as_posix()
        ignored = False
        for pattern, negated, dir_only, anchored in self.rules:
            if dir_only and not is_dir:
                continue
            if anchored:
                matched = fnmatch.fnmatch(rel_str, pattern)
            else:
                matched = fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(
                    path.name, pattern
                )
                if not matched:
                    parts = rel_str.split("/")
                    matched = any(
                        fnmatch.fnmatch(part, pattern) for part in parts[:-1]
                    ) or fnmatch.fnmatch(parts[-1], pattern)
            if matched:
                ignored = not negated
        return ignored


def _iter_files(
    root: Path,
    *,
    excluded_dirs: Iterable[str] = DEFAULT_EXCLUDED_DIRS,
    respect_gitignore: bool = True,
    extra_excludes: Iterable[str] = (),
) -> Iterator[Path]:
    """Recorre un árbol de directorios respetando exclusiones y ``.gitignore``."""
    excluded = set(excluded_dirs)
    extra = {str(item) for item in extra_excludes}
    root = root.resolve()

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        ignore = _GitIgnore.load(current) if respect_gitignore else None

        kept: list[str] = []
        for name in sorted(dirnames):
            child = current / name
            if name in excluded or name in extra:
                continue
            if ignore is not None and ignore.ignores(child, True):
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in sorted(filenames):
            child = current / name
            if name in extra:
                continue
            if ignore is not None and ignore.ignores(child, False):
                continue
            if not _is_text_file(child):
                continue
            yield child


def scan_path(
    target: str | Path,
    *,
    patterns: Sequence[SecretPattern] = PATTERNS,
    min_entropy: float = 3.0,
    exclude: Iterable[str] = (),
    respect_gitignore: bool = True,
    max_file_bytes: int = MAX_FILE_BYTES,
    allowlist: Sequence[AllowlistRule] = (),
) -> list[Finding]:
    """Escanea un fichero o un directorio completo."""
    path = Path(target)
    findings: list[Finding] = []
    if path.is_file():
        return scan_file(
            path,
            patterns=patterns,
            min_entropy=min_entropy,
            max_file_bytes=max_file_bytes,
            allowlist=allowlist,
        )
    if not path.is_dir():
        return findings
    rules = list(allowlist)
    config_path = None
    if not rules:
        rules, config_path = _auto_allowlist(path)
    for file_path in _iter_files(
        path,
        respect_gitignore=respect_gitignore,
        extra_excludes=exclude,
    ):
        # El fichero de allowlist contiene los valores que declara: no se escanea.
        if config_path is not None and file_path.resolve() == config_path.resolve():
            continue
        findings.extend(
            scan_file(
                file_path,
                patterns=patterns,
                min_entropy=min_entropy,
                max_file_bytes=max_file_bytes,
                allowlist=rules,
            )
        )
    findings.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line, f.column)
    )
    return findings


def redact_text(
    text: str,
    *,
    patterns: Sequence[SecretPattern] = PATTERNS,
    min_entropy: float = 3.0,
) -> str:
    """Devuelve el texto con **todos** los secretos reemplazados por su máscara."""
    matches = _collect_matches(text, patterns, min_entropy=min_entropy)
    return _apply_matches(text, matches)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


TSV_HEADER = "file\tline\ttype\tseverity\tmasked\tsha256\tcontext"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrets_scan.py",
        description=(
            "Escaneo local de ficheros en busca de secretos expuestos. "
            "No hace ninguna llamada de red y nunca imprime el valor completo "
            "de un secreto."
        ),
        epilog=(
            "Ejemplos:\n"
            "  python3 secrets_scan.py ./mi-repo\n"
            "  python3 secrets_scan.py ./evidencia --json --out secretos.json\n"
            "  python3 secrets_scan.py ./evidencia --min-entropy 3.5 --ignore '*.lock'\n"
            "  python3 secrets_scan.py ./evidencia --redact-in-place --redact-out ./copia\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Ficheros o directorios a escanear (locales).",
    )
    parser.add_argument(
        "--min-entropy",
        type=float,
        default=3.0,
        help=(
            "Entropía mínima (bits) para aceptar un valor genérico. "
            "Subirla reduce falsos positivos (por defecto 3.0)."
        ),
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="PATRON",
        help="Patrón de exclusión (glob). Se puede repetir.",
    )
    parser.add_argument(
        "--no-gitignore",
        action="store_true",
        help="Ignorar las reglas del .gitignore del directorio escaneado.",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=MAX_FILE_BYTES,
        help=f"Tamaño máximo de fichero a escanear en bytes (por defecto {MAX_FILE_BYTES}).",
    )
    parser.add_argument(
        "--redact-in-place",
        action="store_true",
        help=(
            "Escribir una COPIA redactada de cada fichero encontrado "
            "(el original nunca se sobrescribe)."
        ),
    )
    parser.add_argument(
        "--redact-out",
        metavar="DIR",
        default=None,
        help="Directorio donde escribir las copias redactadas.",
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        default=None,
        help="Fichero donde escribir el informe (además de la salida por pantalla).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida en JSON.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["nunca", "critico", "alto", "medio", "bajo"],
        default="nunca",
        help="Nivel de severidad a partir del cual el script devuelve código 1.",
    )
    parser.add_argument(
        "--allowlist",
        metavar="FICHERO",
        default=None,
        help=(
            "Fichero de allowlist de secretos sintéticos (formato .gitleaks.toml). "
            "Por defecto se busca `.gitleaks.toml` en la raíz del directorio escaneado."
        ),
    )
    parser.add_argument(
        "--no-allowlist",
        action="store_true",
        help=(
            "No aplicar ninguna allowlist: reportar también los secretos "
            "sintéticos declarados en el proyecto."
        ),
    )
    return parser


def _severity_threshold(name: str) -> int:
    return {"nunca": 99, "critico": 4, "alto": 3, "medio": 2, "bajo": 1}[name]


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    scanned_files = 0

    # -- allowlist de secretos sintéticos ----------------------------------- #
    # Se lee la misma lista que usa Gitleaks en la CI (`.gitleaks.toml`), para
    # que no haya dos listas que mantener. Sólo se aplica al escanear un
    # DIRECTORIO: un fichero suelto no se presume parte de un proyecto con
    # allowlist.
    rules: list[AllowlistRule] = []
    config_files: set[str] = set()
    if not args.no_allowlist:
        for target in args.paths:
            path = Path(target)
            if args.allowlist:
                config = Path(args.allowlist)
            elif path.is_dir():
                config = path / ".gitleaks.toml"
            else:
                continue
            if not config.is_file():
                continue
            key = str(config.resolve())
            if key in config_files:
                continue
            config_files.add(key)
            rules.extend(load_allowlist(config))

    for target in args.paths:
        path = Path(target)
        if not path.exists():
            print(
                f"ERROR: no existe la ruta '{target}'.",
                file=sys.stderr,
            )
            return EXIT_ERROR
        if path.is_dir():
            for file_path in _iter_files(
                path,
                respect_gitignore=not args.no_gitignore,
                extra_excludes=args.ignore,
            ):
                # El fichero de allowlist contiene los valores que declara.
                if str(file_path.resolve()) in config_files:
                    continue
                scanned_files += 1
                findings.extend(
                    scan_file(
                        file_path,
                        min_entropy=args.min_entropy,
                        max_file_bytes=args.max_file_size,
                        allowlist=rules,
                    )
                )
        else:
            scanned_files += 1
            findings.extend(
                scan_file(
                    path,
                    min_entropy=args.min_entropy,
                    max_file_bytes=args.max_file_size,
                    allowlist=rules,
                )
            )

    findings.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line, f.column)
    )

    # -- copia redactada ---------------------------------------------------- #
    redacted_written: list[str] = []
    if args.redact_in_place:
        out_dir = Path(args.redact_out) if args.redact_out else None
        written: set[str] = set()
        for finding in findings:
            source = Path(finding.file)
            if not source.is_file():
                continue
            name = f"{source.name}.redacted"
            target = (out_dir / name) if out_dir else source.with_name(name)
            key = str(target.resolve())
            if key in written:
                continue
            if target.exists() and target.resolve() == source.resolve():
                continue
            try:
                original = source.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            safe = redact_text(original, min_entropy=args.min_entropy)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(safe, encoding="utf-8")
            written.add(key)
            redacted_written.append(str(target))

    # -- recuento ----------------------------------------------------------- #
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_type[finding.type] = by_type.get(finding.type, 0) + 1

    payload: dict[str, Any] = {
        "tool": "secrets_scan",
        "paths": list(args.paths),
        "files_scanned": scanned_files,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_type": by_type,
        },
        "redacted_copies": redacted_written,
        "note": (
            "Los valores originales nunca se incluyen en la salida: sólo la "
            "máscara y el sha256[:12] del valor detectado."
        ),
    }

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(TSV_HEADER)
        for finding in findings:
            print(
                "\t".join(
                    [
                        finding.file,
                        str(finding.line),
                        finding.type,
                        finding.severity,
                        finding.masked,
                        finding.sha256,
                        finding.context.replace("\t", " ").replace("\n", " "),
                    ]
                )
            )
        print("", file=sys.stderr)
        print(
            f"[secrets_scan] {len(findings)} hallazgo(s) en {scanned_files} fichero(s).",
            file=sys.stderr,
        )
        for severity in ("critico", "alto", "medio", "bajo"):
            if by_severity.get(severity):
                print(f"  {severity}: {by_severity[severity]}", file=sys.stderr)
        if redacted_written:
            print(
                f"  copias redactadas: {len(redacted_written)}", file=sys.stderr
            )

    threshold = _severity_threshold(args.fail_on)
    if any(
        SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in findings
    ) and threshold != 99:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
