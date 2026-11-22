#!/usr/bin/env python3
"""Núcleo de seguridad (scope guard) de las sondas del playbook de auditoría web.

Este módulo es la **única puerta a la red** del toolkit. Todo lo que golpea la red
pasa por :class:`Guard`, que se encarga de hacer cumplir la doctrina de
``00-metodologia/reglas-de-autorizacion-y-roe.md``:

* Exige un fichero de autorización **firmado** (``authorization_ref``, ``client``,
  ``signed_by``, ``signed_at``, ``valid_from``, ``valid_to``, ``hosts``).
* Recorta los métodos a los seguros: sólo ``GET`` y ``HEAD``. Aunque el fichero de
  autorización liste otros métodos, quedan fuera (RoE 1.1).
* Respeta la ventana de validez de la autorización.
* **Aborta** (no «advierte y sigue») si el host no casa con la lista de hosts
  permitidos.
* Impone un intervalo mínimo entre peticiones: el mayor entre el valor del
  fichero de autorización y el suelo de 1 s que fija el RoE.
* Limita los bytes leídos por respuesta (``max_bytes``).
* Envía un User-Agent honesto y contactable; si el fichero de autorización quiere
  sustituirlo, se exige que siga identificando a la auditoría.
* No sigue redirecciones fuera del *allowlist*: lanza :class:`ScopeViolation`.

Uso como CLI::

    python3 scope_guard.py --authorization auth.json --check https://host/ruta
    python3 scope_guard.py --authorization auth.json --probe https://host/ruta

Códigos de salida: ``0`` correcto, ``1`` violación de alcance / error de red,
``2`` error de configuración (fichero ausente, inválido o sin firma).
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

__all__ = [
    "Authorization",
    "AuthorizationError",
    "Guard",
    "FetchError",
    "Response",
    "ScopeViolation",
    "DEFAULT_USER_AGENT",
    "EXIT_OK",
    "EXIT_VIOLATION",
    "EXIT_CONFIG",
]

# --------------------------------------------------------------------------- #
# Constantes de política
# --------------------------------------------------------------------------- #

#: User-Agent honesto y contactable exigido por el RoE (sección 2).
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (compatible; ClientSecurityAudit/1.0; "
    "+https://ejemplo-auditoria.mx)"
)

#: Únicos métodos que el RoE permite (sección 1.1). El resto se descarta siempre.
SAFE_METHODS: tuple[str, ...] = ("GET", "HEAD")

#: Suelo del intervalo entre peticiones, en segundos (RoE sección 2: ">= 1 s").
MIN_INTERVAL_FLOOR = 1.0

#: Timeout por defecto de las peticiones (segundos).
DEFAULT_TIMEOUT = 20.0

#: Máximo de redirecciones seguidas dentro del allowlist.
DEFAULT_MAX_REDIRECTS = 3

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_CONFIG = 2


# --------------------------------------------------------------------------- #
# Excepciones
# --------------------------------------------------------------------------- #


class ScopeViolation(Exception):
    """Se ha pedido algo fuera del alcance autorizado.

    Siempre es **abortante**: la doctrina dice «si el host no está en la lista,
    abortar, nunca advertir y continuar».
    """

    def __init__(self, motivo: str, detail: Mapping[str, Any] | None = None) -> None:
        super().__init__(motivo)
        self.motivo = motivo
        self.detail: dict[str, Any] = dict(detail or {})

    def to_dict(self) -> dict[str, Any]:
        """Representación serializable del incumplimiento."""
        return {"error": "scope_violation", "motivo": self.motivo, **self.detail}


class AuthorizationError(Exception):
    """Error de configuración: falta el fichero, es inválido o no está firmado.

    Se traduce a código de salida ``2`` porque no es un «no found» del objetivo
    sino un problema del auditor.
    """


class FetchError(Exception):
    """Error de transporte (DNS, TLS, timeout). No es una violación de alcance."""


# --------------------------------------------------------------------------- #
# Modelo de datos
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Authorization:
    """Autorización firmada que delimita el alcance de las sondas."""

    authorization_ref: str
    client: str
    signed_by: str
    signed_at: datetime
    valid_from: datetime
    valid_to: datetime
    hosts: tuple[str, ...]
    allowed_methods: tuple[str, ...] = SAFE_METHODS
    max_bytes: int = 1_000_000
    min_interval_s: float = MIN_INTERVAL_FLOOR
    timeout_s: float = DEFAULT_TIMEOUT
    user_agent: str = DEFAULT_USER_AGENT
    notes: str = ""
    source_path: str = ""

    # -- serialización ----------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        """Vista serializable (sin datos sensibles más allá de lo ya público)."""
        return {
            "authorization_ref": self.authorization_ref,
            "client": self.client,
            "signed_by": self.signed_by,
            "signed_at": _iso(self.signed_at),
            "valid_from": _iso(self.valid_from),
            "valid_to": _iso(self.valid_to),
            "hosts": list(self.hosts),
            "allowed_methods": list(self.allowed_methods),
            "max_bytes": self.max_bytes,
            "min_interval_s": self.min_interval_s,
            "timeout_s": self.timeout_s,
            "user_agent": self.user_agent,
            "source": self.source_path,
        }

    # -- carga -------------------------------------------------------------- #

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        source_path: str = "",
    ) -> "Authorization":
        """Construye la autorización a partir de un diccionario JSON.

        Lanza :class:`AuthorizationError` con un mensaje explícito si falta
        cualquier campo obligatorio o si la firma no es verificable.
        """
        if not isinstance(data, Mapping):
            raise AuthorizationError(
                "El fichero de autorización debe contener un objeto JSON."
            )

        def _require_text(key: str) -> str:
            value = data.get(key)
            if not isinstance(value, str) or not value.strip():
                hint = ""
                if key in ("signed_by", "signed_at"):
                    hint = (
                        " (sin este campo la autorización no está firmada y no "
                        "puede usarse)"
                    )
                raise AuthorizationError(
                    f"Falta el campo obligatorio '{key}' en la autorización.{hint}"
                )
            return value.strip()

        authorization_ref = _require_text("authorization_ref")
        client = _require_text("client")
        signed_by = _require_text("signed_by")
        signed_at_raw = _require_text("signed_at")

        # La firma puede venir como bloque `signature` o como par signed_by/signed_at.
        signature = data.get("signature")
        if signature is not None and not isinstance(signature, Mapping):
            raise AuthorizationError(
                "El campo 'signature' debe ser un objeto con los datos de la firma."
            )

        signed_at = _parse_datetime(signed_at_raw, "signed_at")

        valid_from_raw = data.get("valid_from")
        valid_to_raw = data.get("valid_to")
        if not valid_from_raw or not valid_to_raw:
            raise AuthorizationError(
                "La autorización debe declarar 'valid_from' y 'valid_to' "
                "(ventana de validez)."
            )
        valid_from = _parse_datetime(valid_from_raw, "valid_from")
        valid_to = _parse_datetime(valid_to_raw, "valid_to")
        if valid_to <= valid_from:
            raise AuthorizationError(
                "'valid_to' debe ser posterior a 'valid_from' en la autorización."
            )

        hosts_raw = data.get("hosts")
        if not isinstance(hosts_raw, (list, tuple)) or not hosts_raw:
            raise AuthorizationError(
                "La autorización debe incluir una lista no vacía de 'hosts' "
                "permitidos (admite comodines tipo '*.ejemplo.mx')."
            )
        hosts: list[str] = []
        for host in hosts_raw:
            if not isinstance(host, str) or not host.strip():
                raise AuthorizationError("Cada entrada de 'hosts' debe ser texto.")
            normalised = _normalise_pattern(host)
            if normalised and normalised not in hosts:
                hosts.append(normalised)
        if not hosts:
            raise AuthorizationError("La lista 'hosts' de la autorización está vacía.")

        methods_raw = data.get("allowed_methods", list(SAFE_METHODS))
        if isinstance(methods_raw, str):
            methods_raw = [methods_raw]
        if not isinstance(methods_raw, (list, tuple)):
            raise AuthorizationError("'allowed_methods' debe ser una lista de métodos.")
        requested_methods = {
            str(m).strip().upper() for m in methods_raw if str(m).strip()
        }
        # Los métodos peligrosos se descartan siempre (RoE 1.1).
        effective_methods = tuple(m for m in SAFE_METHODS if m in requested_methods)
        if not effective_methods:
            raise AuthorizationError(
                "La autorización no permite ningún método seguro (GET/HEAD)."
            )

        max_bytes = _positive_int(data.get("max_bytes", 1_000_000), "max_bytes")
        min_interval = _positive_float(
            data.get("min_interval_s", MIN_INTERVAL_FLOOR), "min_interval_s"
        )
        timeout = _positive_float(data.get("timeout_s", DEFAULT_TIMEOUT), "timeout_s")

        user_agent = data.get("user_agent") or DEFAULT_USER_AGENT
        if not isinstance(user_agent, str):
            raise AuthorizationError("'user_agent' debe ser texto.")
        if "clientsecurityaudit" not in user_agent.lower():
            raise AuthorizationError(
                "El 'user_agent' de la autorización debe seguir identificando a la "
                "auditoría (debe contener 'ClientSecurityAudit'); no se permite "
                "suplantar el navegador del cliente (RoE sección 2)."
            )
        if _looks_like_browser_ua(user_agent):
            raise AuthorizationError(
                "El 'user_agent' de la autorización suplanta un navegador real. "
                "El RoE exige un UA honesto y contactable (RoE sección 2)."
            )

        notes = data.get("notes", "")
        if not isinstance(notes, str):
            notes = str(notes)

        return cls(
            authorization_ref=authorization_ref,
            client=client,
            signed_by=signed_by,
            signed_at=signed_at,
            valid_from=valid_from,
            valid_to=valid_to,
            hosts=tuple(hosts),
            allowed_methods=effective_methods,
            max_bytes=max_bytes,
            min_interval_s=min_interval,
            timeout_s=timeout,
            user_agent=user_agent,
            notes=notes,
            source_path=source_path,
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Authorization":
        """Carga la autorización desde un fichero JSON.

        Lanza :class:`AuthorizationError` si el fichero no existe, no es JSON
        válido, o no está firmado.
        """
        p = Path(path)
        try:
            raw = p.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise AuthorizationError(
                f"No existe el fichero de autorización: {p}. "
                "Sin RoE firmado no se empieza (RoE, sección 5.1)."
            ) from exc
        except OSError as exc:
            raise AuthorizationError(
                f"No se puede leer el fichero de autorización {p}: {exc}"
            ) from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthorizationError(
                f"El fichero de autorización {p} no es JSON válido: {exc}"
            ) from exc
        return cls.from_mapping(data, source_path=str(p))


@dataclass(frozen=True)
class Response:
    """Respuesta HTTP acotada y segura."""

    status: int
    headers: dict[str, str]
    body: bytes
    final_url: str
    elapsed: float
    method: str = "GET"
    truncated: bool = False
    raw_headers: tuple[tuple[str, str], ...] = ()

    @property
    def content_type(self) -> str:
        """Valor de ``Content-Type`` sin parámetros (``; charset=...``)."""
        value = self.headers.get("content-type", "")
        return value.split(";")[0].strip().lower()

    @property
    def charset(self) -> str:
        """Charset declarado en ``Content-Type`` (``utf-8`` por defecto)."""
        for part in self.headers.get("content-type", "").split(";")[1:]:
            key, _, value = part.strip().partition("=")
            if key.strip().lower() == "charset":
                return value.strip().strip('"').lower() or "utf-8"
        return "utf-8"

    @property
    def sha256(self) -> str:
        """Huella SHA-256 del cuerpo leído (truncado)."""
        import hashlib

        return hashlib.sha256(self.body).hexdigest()

    def text(self, errors: str = "replace") -> str:
        """Cuerpo decodificado con el charset declarado."""
        try:
            return self.body.decode(self.charset, errors=errors)
        except LookupError:
            return self.body.decode("utf-8", errors=errors)

    def to_dict(self, *, include_body: bool = False, max_body: int = 512) -> dict[str, Any]:
        """Vista serializable; el cuerpo sólo si se pide explícitamente."""
        data: dict[str, Any] = {
            "status": self.status,
            "method": self.method,
            "final_url": self.final_url,
            "elapsed_s": round(self.elapsed, 4),
            "truncated": self.truncated,
            "content_type": self.content_type,
            "length": len(self.body),
            "sha256": self.sha256,
            "headers": dict(self.headers),
        }
        if include_body:
            data["body_preview"] = self.text()[:max_body]
        return data


@dataclass(frozen=True)
class CheckResult:
    """Resultado de una validación de alcance (sin efectos de red)."""

    url: str
    host: str
    method: str
    pattern: str
    now: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "method": self.method,
            "pattern": self.pattern,
            "checked_at": self.now,
            "in_scope": True,
        }


# --------------------------------------------------------------------------- #
# Utilidades internas
# --------------------------------------------------------------------------- #


def _iso(value: datetime) -> str:
    """Serializa un datetime en ISO-8601 con `Z`."""
    text = value.astimezone(timezone.utc).isoformat()
    return text.replace("+00:00", "Z")


def _parse_datetime(value: Any, field_name: str) -> datetime:
    """Parsea una fecha ISO-8601 (con `Z` o con offset) o `YYYY-MM-DD`."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise AuthorizationError(f"El campo '{field_name}' está vacío.")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise AuthorizationError(
                f"El campo '{field_name}' no es una fecha ISO-8601 válida: {value!r}"
            ) from exc
    else:
        raise AuthorizationError(
            f"El campo '{field_name}' debe ser una fecha en texto (ISO-8601)."
        )
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _positive_int(value: Any, field_name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise AuthorizationError(
            f"El campo '{field_name}' debe ser un entero positivo."
        ) from exc
    if number <= 0:
        raise AuthorizationError(f"El campo '{field_name}' debe ser mayor que cero.")
    return number


def _positive_float(value: Any, field_name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise AuthorizationError(
            f"El campo '{field_name}' debe ser un número positivo."
        ) from exc
    if number <= 0:
        raise AuthorizationError(f"El campo '{field_name}' debe ser mayor que zero.")
    return number


def _idna(host: str) -> str:
    """Normaliza un host a su forma punycode si es posible."""
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return host.lower()


def _normalise_pattern(pattern: str) -> str:
    """Normaliza un patrón de host: quita esquema, puerto, ruta y barra final."""
    text = pattern.strip().lower()
    if not text:
        return ""
    if "://" in text:
        parsed = urllib.parse.urlsplit(text)
        text = parsed.hostname or ""
    else:
        text = text.split("/", 1)[0]
        if text.startswith("["):  # IPv6 literal
            text = text.split("]", 1)[0] + "]"
        elif text.count(":") == 1:
            text = text.split(":", 1)[0]
    return text.rstrip(".")


def host_matches(host: str, pattern: str) -> bool:
    """Indica si ``host`` casa con el patrón autorizado.

    * ``ejemplo.mx``  → sólo el host exacto.
    * ``*.ejemplo.mx`` → cualquier subdominio (``a.ejemplo.mx``, ``a.b.ejemplo.mx``),
      **no** el ápex: si se necesita el ápex, hay que listarlo explícitamente.
    """
    h = _idna(host.strip())
    p = _normalise_pattern(pattern)
    if not h or not p:
        return False
    if p.startswith("*."):
        suffix = p[2:]
        return h.endswith("." + suffix)
    return h == p


def _looks_like_browser_ua(ua: str) -> bool:
    """Detecta un UA que suplanta un navegador real (no se permite)."""
    lowered = ua.lower()
    return any(
        token in lowered
        for token in ("mozilla/5.0 (", "chrome/", "safari/", "firefox/", "edg/")
    ) and "clientsecurityaudit" not in lowered


# --------------------------------------------------------------------------- #
# El guardián
# --------------------------------------------------------------------------- #


class Guard:
    """Punto único de acceso a la red, gobernado por la autorización firmada."""

    def __init__(
        self,
        authorization: Authorization,
        *,
        now_fn: Callable[[], datetime] | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.authorization = authorization
        self._now_fn = now_fn or (lambda: datetime.now(timezone.utc))
        self._sleep = sleep_fn
        self._last_request_at: float | None = None
        self.request_count = 0
        self.bytes_read = 0
        self.notes: list[str] = []

        methods = set(authorization.allowed_methods)
        requested = set(authorization.allowed_methods)
        if requested - set(SAFE_METHODS):
            self.notes.append(
                "Métodos no permitidos por el RoE descartados de 'allowed_methods': "
                + ", ".join(sorted(requested - set(SAFE_METHODS)))
            )
        self.allowed_methods: frozenset[str] = frozenset(
            m for m in methods if m in SAFE_METHODS
        ) or frozenset({"GET"})
        if authorization.min_interval_s < MIN_INTERVAL_FLOOR:
            self.notes.append(
                f"min_interval_s={authorization.min_interval_s} sube al suelo de "
                f"{MIN_INTERVAL_FLOOR}s que fija el RoE."
            )
        self.min_interval_s = max(authorization.min_interval_s, MIN_INTERVAL_FLOOR)

    # -- construcción ------------------------------------------------------- #

    @classmethod
    def from_file(cls, path: str | Path, **kwargs: Any) -> "Guard":
        """Construye el guard a partir del fichero de autorización."""
        return cls(Authorization.from_file(path), **kwargs)

    # -- consultas ---------------------------------------------------------- #

    @property
    def concrete_hosts(self) -> list[str]:
        """Hosts sin comodín que se pueden sondear directamente."""
        return [h for h in self.authorization.hosts if not h.startswith("*.")]

    def now(self) -> datetime:
        """Instante actual (UTC) tal y como lo ve el guard."""
        return self._now_fn()

    # -- validaciones ------------------------------------------------------- #

    def check(self, url: str, method: str = "GET") -> CheckResult:
        """Valida una URL contra la autorización.

        Comprueba, en este orden: (1) ventana de validez, (2) host dentro del
        allowlist, (3) método permitido. Lanza :class:`ScopeViolation` con un
        motivo explícito en cuanto algo no cuadra.
        """
        method = (method or "GET").strip().upper()
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ScopeViolation(
                f"Esquema no permitido ('{parsed.scheme or 'vacío'}'): sólo http y https.",
                {"url": url, "rule": "scheme"},
            )
        host = parsed.hostname
        if not host:
            raise ScopeViolation(
                f"La URL no tiene host: {url}", {"url": url, "rule": "host"}
            )
        host = _idna(host)

        # (1) ventana de validez
        now = self.now()
        if now < self.authorization.valid_from:
            raise ScopeViolation(
                f"La autorización {self.authorization.authorization_ref} todavía no "
                f"está en vigor (válida desde {self.authorization.valid_from.isoformat()}, "
                f"ahora {_iso(now)}).",
                {"rule": "fecha", "now": _iso(now)},
            )
        if now > self.authorization.valid_to:
            raise ScopeViolation(
                f"La autorización {self.authorization.authorization_ref} ha caducado "
                f"(válida hasta {self.authorization.valid_to.isoformat()}, "
                f"ahora {_iso(now)}).",
                {"rule": "fecha", "now": _iso(now)},
            )

        # (2) host en el allowlist
        matched = None
        for pattern in self.authorization.hosts:
            if host_matches(host, pattern):
                matched = pattern
                break
        if matched is None:
            allowed = ", ".join(self.authorization.hosts)
            raise ScopeViolation(
                f"El host '{host}' NO está en la lista de hosts autorizados "
                f"({allowed}). Se aborta: nunca se advierte y se continúa.",
                {"rule": "host", "host": host, "allowed_hosts": allowed},
            )

        # (3) método permitido
        if method not in self.allowed_methods:
            raise ScopeViolation(
                f"El método {method} no está permitido. Sólo se permiten "
                f"{', '.join(sorted(self.allowed_methods))} (RoE 1.1: nunca POST).",
                {"rule": "metodo", "method": method},
            )

        return CheckResult(
            url=url,
            host=host,
            method=method,
            pattern=matched or "",
            now=_iso(now),
        )

    def in_scope(self, url: str, method: str = "GET") -> bool:
        """``True`` si la URL y el método son válidos (no lanza excepciones)."""
        try:
            self.check(url, method)
        except ScopeViolation:
            return False
        return True

    def resolve_redirect(
        self, base_url: str, location: str, method: str = "GET"
    ) -> str:
        """Resuelve una cabecera ``Location`` y valida que siga en el alcance."""
        resolved = urllib.parse.urljoin(base_url, location)
        self.check(resolved, method)
        return resolved

    # -- ritmo -------------------------------------------------------------- #

    def _respect_interval(self) -> None:
        """Espera lo necesario para mantener el intervalo mínimo (RoE sección 2)."""
        if self._last_request_at is None:
            return
        elapsed = time.monotonic() - self._last_request_at
        remaining = self.min_interval_s - elapsed
        if remaining > 0:
            self._sleep(remaining)

    # -- red ---------------------------------------------------------------- #

    def _opener(self) -> urllib.request.OpenerDirector:
        """Opener con verificación TLS activa y sin seguir redirecciones."""
        context = ssl.create_default_context()
        handler = urllib.request.HTTPSHandler(context=context)
        return urllib.request.build_opener(_NoRedirectHandler(), handler)

    def fetch(
        self,
        url: str,
        method: str = "GET",
        *,
        timeout: float | None = None,
        max_bytes: int | None = None,
        allow_redirects: bool = True,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        extra_headers: Mapping[str, str] | None = None,
    ) -> Response:
        """Realiza una petición acotada y conforme al RoE.

        Aplica User-Agent honesto, intervalo mínimo entre peticiones, límite de
        bytes, timeout y comprobación de alcance en cada salto de redirección.
        """
        method = (method or "GET").strip().upper()
        limit = max_bytes if max_bytes is not None else self.authorization.max_bytes
        wait = timeout if timeout is not None else self.authorization.timeout_s
        current = url
        hops = 0

        while True:
            self.check(current, method)
            self._respect_interval()

            headers = {
                "User-Agent": self.authorization.user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
            }
            if extra_headers:
                headers.update({str(k): str(v) for k, v in extra_headers.items()})

            request = urllib.request.Request(current, method=method, headers=headers)
            started = time.monotonic()
            status, raw_headers, body, truncated = self._perform(request, wait, limit)
            elapsed = time.monotonic() - started
            self._last_request_at = time.monotonic()
            self.request_count += 1
            self.bytes_read += len(body)

            header_map: dict[str, str] = {}
            for key, value in raw_headers:
                lowered = key.lower()
                if lowered in header_map:
                    header_map[lowered] = f"{header_map[lowered]}, {value}"
                else:
                    header_map[lowered] = value

            if status in (301, 302, 303, 307, 308) and header_map.get("location"):
                location = header_map["location"]
                # Se valida SIEMPRE: una redirección fuera del allowlist aborta.
                resolved = self.resolve_redirect(current, location, method)
                if allow_redirects and hops < max_redirects:
                    hops += 1
                    current = resolved
                    continue
                return Response(
                    status=status,
                    headers=header_map,
                    body=body,
                    final_url=current,
                    elapsed=elapsed,
                    method=method,
                    truncated=truncated,
                    raw_headers=tuple(raw_headers),
                )

            return Response(
                status=status,
                headers=header_map,
                body=body,
                final_url=current,
                elapsed=elapsed,
                method=method,
                truncated=truncated,
                raw_headers=tuple(raw_headers),
            )

    def _perform(
        self, request: urllib.request.Request, timeout: float, limit: int
    ) -> tuple[int, list[tuple[str, str]], bytes, bool]:
        """Ejecuta la petición y devuelve (status, cabeceras, cuerpo, truncado)."""
        opener = self._opener()
        try:
            with opener.open(request, timeout=timeout) as response:
                status = int(getattr(response, "status", response.getcode()))
                raw_headers = list(response.headers.items())
                payload = response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            raw_headers = list(exc.headers.items()) if exc.headers else []
            try:
                payload = exc.read(limit + 1)
            except Exception:  # pragma: no cover - defensivo
                payload = b""
        except urllib.error.URLError as exc:
            raise FetchError(
                f"Error de red en {request.full_url}: {exc.reason}"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise FetchError(
                f"Error de transporte en {request.full_url}: {exc}"
            ) from exc

        truncated = len(payload) > limit
        return status, raw_headers, payload[:limit], truncated


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Impide que urllib siga redirecciones automáticamente.

    El guard decide qué hacer con cada salto: si la URL destino sigue dentro
    del allowlist se sigue a mano (con control de ritmo); si no, se aborta con
    :class:`ScopeViolation`.
    """

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scope_guard.py",
        description=(
            "Comprueba (y opcionalmente ejecuta) una URL contra un fichero de "
            "autorización firmado. Aborta si el host no está en el allowlist."
        ),
        epilog=(
            "Ejemplos:\n"
            "  python3 scope_guard.py --authorization auth.json --check https://host/ruta\n"
            "  python3 scope_guard.py --authorization auth.json --probe https://host/ruta\n"
            "  python3 scope_guard.py --authorization auth.json --list-hosts --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--authorization",
        "-a",
        required=True,
        help="Ruta del JSON de autorización firmado.",
    )
    parser.add_argument(
        "--check",
        metavar="URL",
        help="Valida la URL contra la autorización SIN hacer la petición.",
    )
    parser.add_argument(
        "--probe",
        metavar="URL",
        help="Valida y ejecuta un GET acotado contra la URL.",
    )
    parser.add_argument(
        "--method",
        default="GET",
        choices=["GET", "HEAD"],
        help="Método para --probe (por defecto GET). Nunca POST/PUT/PATCH/DELETE.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="Máximo de bytes a leer (si no, el valor del fichero de autorización).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Timeout en segundos (si no, el valor del fichero de autorización).",
    )
    parser.add_argument(
        "--list-hosts",
        action="store_true",
        help="Muestra los hosts autorizados y sale.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida en JSON.",
    )
    return parser


def _emit(payload: dict[str, Any], as_json: bool, text_lines: Iterable[str]) -> None:
    """Imprime la salida en JSON o en texto plano."""
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for line in text_lines:
            print(line)


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        guard = Guard.from_file(args.authorization)
    except AuthorizationError as exc:
        print(f"ERROR DE CONFIGURACIÓN: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    auth = guard.authorization
    payload: dict[str, Any] = {
        "authorization": auth.to_dict(),
        "notes": guard.notes,
    }

    if args.list_hosts:
        payload["hosts"] = list(auth.hosts)
        payload["allowed_methods"] = sorted(guard.allowed_methods)
        _emit(
            payload,
            args.json,
            [
                f"Autorización: {auth.authorization_ref} ({auth.client})",
                f"Hosts autorizados: {', '.join(auth.hosts)}",
                f"Métodos permitidos: {', '.join(sorted(guard.allowed_methods))}",
                f"Válida: {auth.valid_from.isoformat()} → {auth.valid_to.isoformat()}",
            ],
        )
        return EXIT_OK

    target = args.check or args.probe
    if not target:
        parser.print_help()
        return EXIT_CONFIG

    method = args.method.upper()

    try:
        result = guard.check(target, method)
    except ScopeViolation as exc:
        payload["ok"] = False
        payload.update(exc.to_dict())
        _emit(
            payload,
            args.json,
            [
                "FUERA DE ALCANCE — operación abortada.",
                f"Motivo: {exc.motivo}",
            ],
        )
        return EXIT_VIOLATION

    if args.check:
        payload["ok"] = True
        payload["check"] = result.to_dict()
        _emit(
            payload,
            args.json,
            [
                "DENTRO DE ALCANCE.",
                f"URL: {target}",
                f"Host: {result.host} (patrón: {result.pattern})",
                f"Método: {result.method}",
            ],
        )
        return EXIT_OK

    try:
        response = guard.fetch(
            target,
            method,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
        )
    except ScopeViolation as exc:
        payload["ok"] = False
        payload.update(exc.to_dict())
        _emit(
            payload,
            args.json,
            ["FUERA DE ALCANCE — operación abortada.", f"Motivo: {exc.motivo}"],
        )
        return EXIT_VIOLATION
    except FetchError as exc:
        payload["ok"] = False
        payload["error"] = "fetch_error"
        payload["motivo"] = str(exc)
        _emit(
            payload,
            args.json,
            [f"ERROR DE RED: {exc}"],
        )
        return EXIT_VIOLATION

    payload["ok"] = True
    payload["response"] = response.to_dict(include_body=True)
    _emit(
        payload,
        args.json,
        [
            f"HTTP {response.status} — {response.final_url}",
            f"Tipo: {response.content_type or '(sin content-type)'}",
            f"Bytes leídos: {len(response.body)}"
            + (" (truncado)" if response.truncated else ""),
            f"Tiempo: {response.elapsed:.3f}s",
            "",
            "Cabeceras:",
            *(f"  {k}: {v}" for k, v in sorted(response.headers.items())),
        ],
    )
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
