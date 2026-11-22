#!/usr/bin/env python3
"""Redactor de datos personales (PII) para la evidencia de auditoría.

Reglas del RoE que aplica:

* Los datos personales descubiertos se reportan **minimizados**: aquí la
  herramienta se encarga de que la evidencia que sale del escritorio del auditor
  no arrastre datos de pacientes.
* El informe de conteo **nunca** contiene valores: sólo categorías y cantidades.
* El informe distingue **coincidencias detectadas** de **redacciones
  aplicadas**: un valor que encaja con un patrón pero que la regla de contexto
  deja intacto cuenta como coincidencia, no como redacción.

Qué redacta:

* emails, teléfonos (MX/ES/US), RFC/NIF/DNI/NIE/CUIT, IPs (opcionalmente
  conservables), números de tarjeta (validados con Luhn), fechas de nacimiento,
  códigos postales, URLs con credenciales embebidas;
* claves JSON/HTML cuyos nombres son típicos de dato personal o clínico
  (``nombre``, ``apellido``, ``telefono``, ``email``, ``diagnostico``,
  ``expediente``, ``curp``, ``rfc``, ``nss``, ``paciente``, ``dob``, ``ssn``…).

Garantía crítica: **el formato del fichero se preserva**. Un JSON redactado
sigue siendo JSON válido y parseable; el HTML sigue siendo HTML y el texto
sigue siendo texto.

Uso::

    python3 pii_redact.py evidencia/paciente.json --out-dir ./redactado
    python3 pii_redact.py evidencia/ --out-dir ./redactado --report informe.json
    python3 pii_redact.py notas.txt --keep-ips
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

__all__ = [
    "Redactor",
    "PERSONAL_KEYS",
    "redact_text",
    "redact_json",
    "EXIT_OK",
    "EXIT_ERROR",
]

EXIT_OK = 0
EXIT_ERROR = 2

#: Claves cuyos valores se consideran dato personal o clínico.
#:
#: El catálogo cubre tanto los nombres "canónicos" (``nombre``, ``telefono``,
#: ``expediente``) como los **alias** que aparecen en los JSON de expediente
#: reales y en la documentación del playbook
#: (``00-metodologia/exposicion-de-secretos.md`` §6.4): ``num_tarjeta`` y
#: ``numero_tarjeta`` son la misma clave con dos grafías y **las dos** tienen
#: que redactarse, igual que ``grupo_sanguineo`` y ``grupo_sangre``.
PERSONAL_KEYS: frozenset[str] = frozenset(
    {
        # -- identidad ------------------------------------------------------------ #
        "nombre", "nombres", "nombre_completo", "nombre_paciente",
        "nombre_cliente", "nombre_contacto", "nombre_emergencia",
        "apellido", "apellidos", "apellido_paterno", "apellido_materno",
        "genero", "sexo", "edad", "estado_civil",
        "curp", "rfc", "nss", "nhis",
        # -- contacto --------------------------------------------------------------- #
        "telefono", "telefonos", "telefono_movil", "telefono_casa",
        "tel", "celular", "movil", "whatsapp",
        "telefono_emergencia", "contacto_emergencia",
        "email", "correo", "correo_electronico", "email_address",
        # -- domicilio ---------------------------------------------------------------- #
        "direccion", "domicilio", "direccion_domicilio", "calle",
        "numero", "colonia", "municipio", "cp", "codigo_postal",
        # -- expediente --------------------------------------------------------------- #
        "expediente", "expediente_clinico", "num_expediente", "expediente_id",
        "id_paciente", "paciente_id", "record_id",
        "paciente", "pacientes", "patient", "patient_id", "patient_name",
        # -- fechas --------------------------------------------------------------------- #
        "fecha_nacimiento", "fecha_de_nacimiento", "fecha_nac",
        "nacimiento", "nacido_en", "dob", "ssn",
        "address", "phone",
        # -- clínico --------------------------------------------------------------------- #
        "diagnostico", "diagnosticos", "cie", "cve",
        "antecedentes", "preexistencias", "tratamiento", "receta",
        "medicamento", "medicamentos", "alergias", "alergia",
        "doctor", "medico", "especialidad", "motivo_consulta",
        "grupo_sanguineo", "grupo_sangre", "tipo_sangre", "rh",
        "altura", "peso",
        # -- aseguramiento ------------------------------------------------------------------ #
        "seguro", "poliza", "numero_poliza", "afiliado",
        # -- tutores y familiares ---------------------------------------------------------------- #
        "padre", "madre", "tutor", "familiar",
        # -- red ---------------------------------------------------------------------------------- #
        "ip", "ip_address", "direccion_ip",
        # -- pago ------------------------------------------------------------------------------------ #
        "tarjeta", "numero_tarjeta", "num_tarjeta", "card_number", "cvv", "cvc",
    }
)

#: Categorías del informe (no contienen valores, sólo el recuento).
CATEGORIES: tuple[str, ...] = (
    "email",
    "telefono",
    "rfc_nif_dni_cuit",
    "ip",
    "tarjeta",
    "fecha_nacimiento",
    "codigo_postal",
    "url_credenciales",
    "dato_personal_json",
)

_PLACEHOLDER = "[REDACTADO:{category}]"

#: Claves que son IP: se respetan ``--keep-ips``.
IP_KEYS: frozenset[str] = frozenset({"ip", "ipaddress", "direccionip"})

#: Categoría del informe a la que corresponde cada clave personal.
#: Las claves normalizadas que **no** aparecen aquí caen en
#: ``dato_personal_json``.
KEY_CATEGORY: dict[str, str] = {
    "email": "email",
    "correo": "email",
    "correoelectronico": "email",
    "emailaddress": "email",
    "telefono": "telefono",
    "telefonos": "telefono",
    "telefonomovil": "telefono",
    "telefonocasa": "telefono",
    "telefonoemergencia": "telefono",
    "tel": "telefono",
    "celular": "telefono",
    "movil": "telefono",
    "whatsapp": "telefono",
    "phone": "telefono",
    "rfc": "rfc_nif_dni_cuit",
    "curp": "rfc_nif_dni_cuit",
    "nss": "rfc_nif_dni_cuit",
    "nhis": "rfc_nif_dni_cuit",
    "ip": "ip",
    "ipaddress": "ip",
    "direccionip": "ip",
    "tarjeta": "tarjeta",
    "numerotarjeta": "tarjeta",
    "numtarjeta": "tarjeta",
    "cardnumber": "tarjeta",
    "cvv": "tarjeta",
    "cvc": "tarjeta",
    "fechanacimiento": "fecha_nacimiento",
    "fechadenacimiento": "fecha_nacimiento",
    "fechanac": "fecha_nacimiento",
    "nacidoen": "fecha_nacimiento",
    "nacimiento": "fecha_nacimiento",
    "dob": "fecha_nacimiento",
    "cp": "codigo_postal",
    "codigopostal": "codigo_postal",
}

# --------------------------------------------------------------------------- #
# Patrones
# --------------------------------------------------------------------------- #

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# Teléfonos: prefijos opcionales y los tres agrupamientos habituales
# (3-3-4 en ES/US, 2-4-4 en MX, 3-4 con paréntesis).
PHONE_RE = re.compile(
    r"(?<![\w\-])"
    r"(?:\+|00)?"
    r"(?:\(?\d{2,3}\)?[\s.\-])?"
    r"(?:"
    r"\d{3}[\s.\-]\d{3}[\s.\-]\d{4}"
    r"|\d{2}[\s.\-]\d{4}[\s.\-]\d{4}"
    r"|\d{3}[\s.\-]\d{4}"
    r")"
    r"(?![\w\-])"
)

# Identificadores nacionales. Formatos largos primero para no comerse subcadenas.
RFC_MX_RE = re.compile(r"\b[A-ZÑ&]{4}\d{6}[A-Z0-9]{3}\b")
NIE_ES_RE = re.compile(r"\b[XYZ]\d{7}[A-Z]\b")
NIF_DNI_ES_RE = re.compile(r"\b\d{8}[A-HJ-NP-TV-Z]\b")
CUIT_AR_RE = re.compile(r"\b\d{2}\d{8}\d\b")

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

CARD_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

#: Contexto que confirma que un número suelto es una tarjeta y no un teléfono.
CARD_CONTEXT_RE = re.compile(
    r"(?i)\b(visa|mastercard|master\s*card|amex|american\s*express|card|"
    r"tarjeta|pan|\bcc\b|n[uú]mero\s*de\s*tarjeta|d[oó]lares?\b)"
)

ISO_DATE_RE = re.compile(r"\b(19[0-9]{2}|20[0-2][0-9])-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\b")
SLASH_DATE_RE = re.compile(r"\b([0-3]?\d)[/.\-]([01]?\d)[/.\-](19\d{2}|20[0-2]\d)\b")
TEXT_DATE_RE = re.compile(
    r"\b([0-3]?\d)\s+de\s+"
    r"(enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|"
    r"octubre|noviembre|diciembre)\s+de\s+(19\d{2}|20[0-2]\d)\b",
    re.IGNORECASE,
)

#: Contexto que delata una fecha de nacimiento (si no, la fecha se conserva:
#: una fecha de cita no es un dato de paciente).
BIRTH_CONTEXT_RE = re.compile(
    r"(?i)nacimi|nacid[oa]s?|fech[ae]?[_\s]?de[_\s]?nac|birth|\bdob\b|"
    r"naci[óo]n|edad"
)

# Código postal: exige una palabra clave nearby para no comerse cualquier
# número de 5 dígitos (folios, IDs, precios…).
POSTAL_KEYWORD_RE = re.compile(
    r"(?i)\b(?:cp|c\.?p\.?|c[oó]d(?:igo)?\s+postal|zip(?:\s*code)?)\b"
    r"\s*[:#]?\s*(\d{5}(?:-\d{4})?|\d{4}\s?\d{2})"
)

URL_CREDENTIALS_RE = re.compile(
    r"\b([a-zA-Z][a-zA-Z0-9+.\-]*://)([^\s:/@'\"]+):([^\s:/@'\"]+)@"
)

JSON_PERSONAL_RE = re.compile(
    r"([\"'])([A-Za-z_][A-Za-z0-9_\-]*)\1\s*:\s*"
    r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^,}\]\s]+)"
)


def _normalise_key(key: str) -> str:
    """Normaliza el nombre de una clave para comparar sin tildes ni separadores."""
    return re.sub(r"[^a-z0-9]", "", key.lower())


def luhn_valid(digits: str) -> bool:
    """Valida un número de tarjeta con el algoritmo de Luhn."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _mask_card(value: str) -> str:
    """Enmascara un número de tarjeta dejando sólo los 4 últimos dígitos."""
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return _PLACEHOLDER.format(category="tarjeta")
    return f"«tarjeta:****{digits[-4:]}»"


# --------------------------------------------------------------------------- #
# Redactor
# --------------------------------------------------------------------------- #


@dataclass
class Redactor:
    """Redactor de PII con recuento por categoría.

    Lleva **dos** contadores por categoría, porque no son lo mismo:

    * :attr:`matches` → **coincidencias detectadas**: cuántas veces el patrón
      (o el nombre de clave) encajó con un dato personal.
    * :attr:`counts` → **redacciones aplicadas**: cuántas veces el valor se
      sustituyó de verdad.

    La diferencia es real y hay que poder verla: un número de 16 dígitos que
    pasa el patrón de tarjeta pero **no** pasa Luhn se *detecta* y **no** se
    redacta; una clave ``ip`` con ``--keep-ips`` se detecta y no se redacta;
    una clave personal cuyo valor es un objeto se detecta y se conserva
    (para no destruir la estructura del documento). Un informe que sólo dijera
    «tarjeta: 2» daría a entender que se redactaron dos tarjetas.
    """

    keep_ips: bool = False
    extra_keys: frozenset[str] = frozenset()
    #: Redacciones **aplicadas** por categoría (nunca contiene valores).
    counts: dict[str, int] = field(default_factory=dict)
    #: Coincidencias **detectadas** por categoría (nunca contiene valores).
    matches: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalised = {_normalise_key(key) for key in (PERSONAL_KEYS | self.extra_keys)}
        self.personal_keys: frozenset[str] = frozenset(normalised)
        self.ip_keys: frozenset[str] = frozenset(_normalise_key(k) for k in IP_KEYS)
        for category in CATEGORIES:
            self.counts.setdefault(category, 0)
            self.matches.setdefault(category, 0)

    # -- utilidades --------------------------------------------------------- #

    def _bump_match(self, category: str, amount: int = 1) -> None:
        """Suma **coincidencias detectadas** en una categoría."""
        self.matches[category] = self.matches.get(category, 0) + amount

    def _bump_redaction(self, category: str, amount: int = 1) -> None:
        """Suma **redacciones aplicadas** en una categoría."""
        self.counts[category] = self.counts.get(category, 0) + amount

    def _is_personal_key(self, key: str) -> bool:
        return _normalise_key(key) in self.personal_keys

    def _is_ip_key(self, key: str) -> bool:
        return _normalise_key(key) in self.ip_keys

    # -- texto -------------------------------------------------------------- #

    def redact_text(self, text: str, *, include_json_keys: bool = True) -> str:
        """Redacta la PII de un fragmento de texto/HTML.

        ``include_json_keys`` activa el tratamiento de pares ``"clave": valor``
        presentes en texto plano (HTML, JS, logs). En JSON estructurado el
        tratamiento lo hace :meth:`redact_json`, que preserva la validez.
        """
        if not text:
            return text
        result = text

        # -- emails --------------------------------------------------------- #
        result, count = EMAIL_RE.subn(
            lambda _m: _PLACEHOLDER.format(category="email"), result
        )
        self._bump_match("email", count)
        self._bump_redaction("email", count)

        # -- URLs con credenciales ------------------------------------------- #
        def _url_repl(match: re.Match[str]) -> str:
            return (
                f"{match.group(1)}{match.group(2)}:"
                f"{_PLACEHOLDER.format(category='url_credenciales')}@"
            )

        result, count = URL_CREDENTIALS_RE.subn(_url_repl, result)
        self._bump_match("url_credenciales", count)
        self._bump_redaction("url_credenciales", count)

        # -- tarjetas (Luhn) -------------------------------------------------- #
        # El patrón puede encajar con algo que **no** es una tarjeta (Luhn
        # inválido o sin contexto): eso es una coincidencia, no una redacción.
        masked_cards = 0

        def _card_repl(match: re.Match[str]) -> str:
            nonlocal masked_cards
            raw = match.group(0)
            core = raw
            trailing = ""
            tail = re.search(r"[\s\-]$", raw)
            if tail:
                core = raw[: tail.start()]
                trailing = tail.group(0)
            digits = re.sub(r"\D", "", core)
            if not luhn_valid(digits):
                return raw
            # Un número sin separadores y sin contexto de tarjeta es, con
            # frecuencia, un teléfono en formato E.164: redactarlo destrozaría
            # la evidencia sin proteger nada.
            if "-" not in core and " " not in core:
                window = result[max(0, match.start() - 60) : match.start()]
                if not CARD_CONTEXT_RE.search(window):
                    return raw
            masked_cards += 1
            return _mask_card(core) + trailing

        result, count = CARD_RE.subn(_card_repl, result)
        self._bump_match("tarjeta", count)
        self._bump_redaction("tarjeta", masked_cards)

        # -- IPs --------------------------------------------------------------- #
        if not self.keep_ips:
            result, count = IPV4_RE.subn(
                lambda _m: _PLACEHOLDER.format(category="ip"), result
            )
            self._bump_match("ip", count)
            self._bump_redaction("ip", count)
        else:
            # Con --keep-ips se detectan pero no se tocan: cuenta como
            # coincidencia, no como redacción.
            self._bump_match("ip", len(IPV4_RE.findall(result)))

        # -- identificadores nacionales ------------------------------------------ #
        for regex in (RFC_MX_RE, NIE_ES_RE, CUIT_AR_RE, NIF_DNI_ES_RE):
            result, count = regex.subn(
                lambda _m: _PLACEHOLDER.format(category="rfc_nif_dni_cuit"), result
            )
            self._bump_match("rfc_nif_dni_cuit", count)
            self._bump_redaction("rfc_nif_dni_cuit", count)

        # -- teléfonos ------------------------------------------------------------ #
        result, count = PHONE_RE.subn(
            lambda _m: _PLACEHOLDER.format(category="telefono"), result
        )
        self._bump_match("telefono", count)
        self._bump_redaction("telefono", count)

        # -- fechas de nacimiento (sólo cuando el contexto lo indica) ------------- #
        result = self._redact_birth_dates(result)

        # -- códigos postales ------------------------------------------------------ #
        def _postal_repl(match: re.Match[str]) -> str:
            return match.group(0).replace(
                match.group(1), _PLACEHOLDER.format(category="codigo_postal")
            )

        result, count = POSTAL_KEYWORD_RE.subn(_postal_repl, result)
        self._bump_match("codigo_postal", count)
        self._bump_redaction("codigo_postal", count)

        # -- claves JSON con nombre de dato personal -------------------------------- #
        if include_json_keys:

            def _json_repl(match: re.Match[str]) -> str:
                key = match.group(2)
                if not self._is_personal_key(key):
                    return match.group(0)
                self._bump_match("dato_personal_json")
                if self.keep_ips and self._is_ip_key(key):
                    return match.group(0)
                self._bump_redaction("dato_personal_json")
                return (
                    f"{match.group(1)}{key}{match.group(3)}: "
                    f"{_PLACEHOLDER.format(category='dato_personal_json')}"
                )

            result = JSON_PERSONAL_RE.sub(_json_repl, result)
        return result

    def _redact_birth_dates(self, text: str) -> str:
        """Redacta fechas sólo cuando el contexto sugiere fecha de nacimiento.

        Una fecha que el contexto no confirma (una cita, una factura) no es una
        coincidencia de esta categoría: no cuenta ni como detección ni como
        redacción.
        """
        lines = text.split("\n")
        output: list[str] = []
        for line in lines:
            masked = line
            for regex in (ISO_DATE_RE, SLASH_DATE_RE, TEXT_DATE_RE):
                def _replace(match: re.Match[str]) -> str:
                    start = match.start()
                    window = line[max(0, start - 80) : start]
                    if not BIRTH_CONTEXT_RE.search(window):
                        return match.group(0)
                    self._bump_match("fecha_nacimiento")
                    self._bump_redaction("fecha_nacimiento")
                    return _PLACEHOLDER.format(category="fecha_nacimiento")

                masked = regex.sub(_replace, masked)
            output.append(masked)
        return "\n".join(output)

    # -- JSON ---------------------------------------------------------------- #

    def redact_json(self, data: Any) -> Any:
        """Redacta recursivamente una estructura JSON manteniendo su validez."""
        if isinstance(data, dict):
            out: dict[str, Any] = {}
            for key, value in data.items():
                if isinstance(key, str) and self._is_personal_key(key):
                    category = KEY_CATEGORY.get(
                        _normalise_key(key), "dato_personal_json"
                    )
                    self._bump_match(category)
                    if self.keep_ips and self._is_ip_key(key):
                        out[key] = self.redact_json(value)
                        continue
                    # Los contenedores (objetos/listas) se recorren para no
                    # destruir la estructura del documento; los escalares se
                    # sustituyen por completo. Un contenedor es una coincidencia
                    # detectada, pero no una redacción.
                    if isinstance(value, (dict, list)):
                        out[key] = self.redact_json(value)
                        continue
                    self._bump_redaction(category)
                    out[key] = _PLACEHOLDER.format(category=category)
                    continue
                out[key] = self.redact_json(value)
            return out
        if isinstance(data, list):
            return [self.redact_json(item) for item in data]
        if isinstance(data, str):
            return self.redact_text(data, include_json_keys=False)
        return data



# --------------------------------------------------------------------------- #
# Funciones de conveniencia
# --------------------------------------------------------------------------- #


def redact_text(text: str, **kwargs: Any) -> str:
    """Redacta un texto suelto (atajo sobre :class:`Redactor`)."""
    return Redactor(**kwargs).redact_text(text)


def redact_json(data: Any, **kwargs: Any) -> Any:
    """Redacta una estructura JSON (atajo sobre :class:`Redactor`)."""
    return Redactor(**kwargs).redact_json(data)


def redact_file(
    source: Path,
    target: Path,
    *,
    keep_ips: bool = False,
    extra_keys: Iterable[str] = (),
) -> dict[str, Any]:
    """Redacta un fichero y lo escribe en ``target``.

    Si el fichero es JSON válido, se redacta como JSON (y el resultado sigue
    siendo JSON válido). Si no, se redacta como texto.
    """
    redactor = Redactor(keep_ips=keep_ips, extra_keys=frozenset(extra_keys))
    raw = source.read_text(encoding="utf-8", errors="replace")
    is_json = False
    parsed: Any = None
    if raw.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(raw)
            is_json = True
        except json.JSONDecodeError:
            is_json = False

    if is_json:
        redacted = redactor.redact_json(parsed)
        output = json.dumps(redacted, ensure_ascii=False, indent=2)
    else:
        output = redactor.redact_text(raw)

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(output, encoding="utf-8")

    return {
        "source": str(source),
        "output": str(target),
        "format": "json" if is_json else "texto",
        "counts": {k: v for k, v in redactor.counts.items() if v},
        "matches": {k: v for k, v in redactor.matches.items() if v},
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii_redact.py",
        description=(
            "Redacta datos personales y clínicos de ficheros de texto/JSON/HTML. "
            "El informe sólo contiene recuentos por categoría, nunca valores."
        ),
        epilog=(
            "Ejemplos:\n"
            "  python3 pii_redact.py evidencia/paciente.json --out-dir ./redactado\n"
            "  python3 pii_redact.py evidencia/ --out-dir ./redactado --report informe.json\n"
            "  python3 pii_redact.py notas.txt --keep-ips --json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Ficheros o directorios a redactar.",
    )
    parser.add_argument(
        "--out-dir",
        default="redactado",
        help="Directorio donde escribir las copias redactadas (por defecto ./redactado).",
    )
    parser.add_argument(
        "--report",
        metavar="FILE",
        default=None,
        help="Fichero JSON con el informe de conteos (sin valores).",
    )
    parser.add_argument(
        "--keep-ips",
        action="store_true",
        help="No redactar direcciones IP.",
    )
    parser.add_argument(
        "--extra-key",
        action="append",
        default=[],
        metavar="CLAVE",
        help="Clave JSON adicional a considerar dato personal. Repetible.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Salida en JSON.",
    )
    return parser


def _collect(base: Path) -> list[Path]:
    """Lista los ficheros a procesar dentro de un directorio base."""
    files: list[Path] = []
    for child in sorted(base.rglob("*")):
        if not child.is_file():
            continue
        if any(
            part in {".git", "node_modules", ".venv", "__pycache__", ".mypy_cache"}
            for part in child.parts
        ):
            continue
        files.append(child)
    return files


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada del CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    results: list[dict[str, Any]] = []
    total_counts: dict[str, int] = {}
    total_matches: dict[str, int] = {}

    for raw_path in args.paths:
        source = Path(raw_path)
        if source.is_file():
            base = source.parent
            targets = [source]
        elif source.is_dir():
            base = source
            targets = _collect(source)
        else:
            print(f"ERROR: no existe la ruta '{raw_path}'.", file=sys.stderr)
            return EXIT_ERROR

        for item in targets:
            try:
                relative = item.relative_to(base)
            except ValueError:  # pragma: no cover - defensivo
                relative = Path(item.name)
            target = out_dir / relative
            try:
                result = redact_file(
                    item,
                    target,
                    keep_ips=args.keep_ips,
                    extra_keys=args.extra_key,
                )
            except OSError as exc:
                print(
                    f"ERROR: no se pudo procesar '{item}': {exc}", file=sys.stderr
                )
                return EXIT_ERROR
            results.append(result)
            for category, count in result["counts"].items():
                total_counts[category] = total_counts.get(category, 0) + count
            for category, count in result["matches"].items():
                total_matches[category] = total_matches.get(category, 0) + count

    payload = {
        "tool": "pii_redact",
        "output_dir": str(out_dir),
        "files": results,
        "total_redactions": sum(total_counts.values()),
        "counts_by_category": total_counts,
        "total_matches": sum(total_matches.values()),
        "matches_by_category": total_matches,
        "note": (
            "El informe contiene conteos por categoría; nunca contiene valores. "
            "'counts_by_category' cuenta redacciones aplicadas y "
            "'matches_by_category' cuenta coincidencias detectadas: no son lo "
            "mismo (una coincidencia puede no redactarse porque la regla de "
            "contexto la deja intacta)."
        ),
    }

    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"[pii_redact] {len(results)} fichero(s) procesado(s) → {out_dir}")
        if total_counts or total_matches:
            print("Redacciones aplicadas por categoría (sin valores):")
            for category, count in sorted(
                total_counts.items(), key=lambda kv: (-kv[1], kv[0])
            ):
                print(f"  {category}: {count}")
            print("Coincidencias detectadas por categoría (sin valores):")
            for category, count in sorted(
                total_matches.items(), key=lambda kv: (-kv[1], kv[0])
            ):
                print(f"  {category}: {count}")
        else:
            print("  (sin datos personales detectados)")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
