"""Carga y normaliza la evidencia para la consola de operaciones.

Este módulo es el **único** que sabe cómo se ven los artefactos en disco.
Convierte el directorio de evidencia (el que produce el toolchain de
``01-tooling/scripts/``) en un esquema JSON estable que la interfaz consume
sin interpretar nada por su cuenta.

Reglas duras del módulo:

* **Cero red.** Sólo se leen ficheros locales.
* **Cero datos inventados.** Si un artefacto no existe, su sección se devuelve
  vacía con el motivo explícito, nunca con un 0 que se parezca a un dato.
* **Regla de redacción.** Todo artefacto lleva un estado de redacción
  verificable (``redactado`` / ``sin_verificar`` / ``desconocido``). El que no
  lo tiene se marca como **SIN REDACTAR** y la interfaz lo oculta por defecto.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "BANDS",
    "EvidenceStore",
    "SEVERIDADES",
    "ESTADOS_FINDING",
    "FileRef",
]

#: Bandas reales del Attack Exposure Score (``attack_surface_report.py``).
BANDS: tuple[tuple[float, float, str], ...] = (
    (0.0, 19.9, "Bajo"),
    (20.0, 39.9, "Moderado"),
    (40.0, 59.9, "Alto"),
    (60.0, 79.9, "Crítico"),
    (80.0, 100.0, "Severo"),
)

#: Orden de severidad usado para ordenar tablas (de más a menos grave).
SEVERIDADES: tuple[str, ...] = ("critico", "alto", "medio", "bajo", "info")

#: Estados admitidos por un hallazgo del playbook.
ESTADOS_FINDING: tuple[str, ...] = ("hallazgo", "refutado", "no verificado", "en curso")

#: Estados de redacción de un artefacto.
REDACTADO = "redactado"
SIN_VERIFICAR = "sin_verificar"
DESCONOCIDO = "desconocido"

#: Nombres de fichero que el backend busca dentro del directorio de evidencia.
#: El primero que exista (buscando en profundidad) es el que se usa.
FICHERO_PROBE_TSV = "probe_exposure.tsv"
FICHERO_PROBE_JSON = "probe_exposure.json"
FICHERO_SECRETS = "secrets.json"
FICHERO_SCORE = "attack_surface_report.json"
FICHERO_HEADERS = "headers.txt"
FICHERO_JS_INTEL = "js_intel.json"
FICHERO_HEADER_REPORT = "header_tls.json"
FICHERO_DNS = "dns_mailsec.txt"
FICHERO_TLS = "tls_versions.txt"
FICHERO_CRT = "crt.json"
FICHERO_INTERNETDB = "internetdb.json"
FICHERO_REDACCION = "redaccion.json"
FICHERO_ACCIONES = "registro-de-acciones-fase-2.csv"
FICHERO_AUTORIZACION = "authorization.json"
FICHERO_HALLAZGOS = "hallazgos.json"
FICHERO_MANIFIESTO = "manifiesto-redaccion.json"
FICHERO_VERIF_SECRETS = "secrets-verificacion.json"

#: Alternativas aceptadas para el informe de redacción y el registro de acciones.
ALIAS_REDACCION: tuple[str, ...] = (
    "redaccion.json",
    "redaction.json",
    "pii_redact.json",
    "informe_redaccion.json",
)
ALIAS_ACCIONES: tuple[str, ...] = (
    "registro-de-acciones-fase-2.csv",
    "registro-de-acciones.csv",
)

#: Palabras que delatan un directorio ya saneado por ``pii_redact.py``.
_MARCA_REDACCION = re.compile(r"redact|sanitiz|sanitari", re.IGNORECASE)

#: Rutas que delatan datos personales o clínicos (para la vista de API).
_MARCA_PII = re.compile(
    r"paciente|expedient|histori|clin|cita|medic|alergi|diagnost|laborator|"
    r"resultado|radiograf|receta|orden|pago|tarjeta|factura|nomina",
    re.IGNORECASE,
)

#: Rutas administrativas o sensibles.
_MARCA_SENSIBLE = re.compile(
    r"^/(admin|administrator|wp-admin|phpmyadmin|panel|dashboard|api|internal|"
    r"config|actuator|metrics|server-status|graphql|wp-json)",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #


def _sha256_short(data: bytes, length: int = 12) -> str:
    """Devuelve los primeros ``length`` caracteres del sha256 en hexadecimal."""
    return hashlib.sha256(data).hexdigest()[:length]


def _now_iso() -> str:
    """Marca temporal ISO-8601 en UTC, con precisión de segundos."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _severity_rank(value: str) -> int:
    """Posición de una severidad en el orden de gravedad (mayor = peor)."""
    try:
        return SEVERIDADES.index(str(value).lower())
    except ValueError:
        return len(SEVERIDADES)


def _band_for(score: float) -> str:
    """Banda del Attack Exposure Score para un valor dado."""
    for low, high, label in BANDS:
        if low <= score <= high:
            return label
    return BANDS[-1][2]


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convierte a float tolerando ``None``, cadenas vacías y basura."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    """Convierte a int tolerando basura."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _host_of(url: str) -> str:
    """Extrae el host de una URL absoluta (o devuelve la entrada tal cual)."""
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)", url or "")
    if match:
        return match.group(1).lower()
    return (url or "").split("/")[0].lower()


# --------------------------------------------------------------------------- #
# Modelo de artefacto
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FileRef:
    """Un artefacto del directorio de evidencia, con su estado de redacción."""

    path: str
    size: int
    sha256: str
    mtime: float
    redaction: str
    redaction_reason: str

    def to_dict(self) -> dict[str, Any]:
        """Vista serializable del artefacto."""
        return {
            "ruta": self.path,
            "tamano": self.size,
            "sha256": self.sha256,
            "hash_corto": self.sha256[:12],
            "mtime": self.mtime,
            "mtime_iso": datetime.fromtimestamp(self.mtime, timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "redaccion": self.redaction,
            "redaccion_motivo": self.redaction_reason,
            "sin_redactar": self.redaction != REDACTADO,
        }


# --------------------------------------------------------------------------- #
# Almacén de evidencia
# --------------------------------------------------------------------------- #


class EvidenceStore:
    """Directorio de evidencia leído en modo sólo-lectura.

    No hace ninguna llamada de red y nunca modifica los artefactos que lee.
    """

    def __init__(self, root: str | Path, *, demo: bool = False) -> None:
        self.root = Path(root).expanduser().resolve()
        self.demo = demo
        self._cache: dict[str, Any] = {}
        self._redaction_cache: dict[str, str] = {}

    # -- basics ------------------------------------------------------------- #

    @property
    def existe(self) -> bool:
        """¿Existe el directorio de evidencia?"""
        return self.root.is_dir()

    def etiqueta_modo(self) -> str:
        """Etiqueta de modo para la interfaz: ``demo`` o ``evidencia``."""
        return "demo" if self.demo else "evidencia"

    def _abs(self, relative: str) -> Path:
        """Ruta absoluta dentro del directorio de evidencia."""
        return self.root / relative

    # -- búsqueda ----------------------------------------------------------- #

    def buscar(self, *nombres: str) -> Path | None:
        """Devuelve el primer fichero existente cuyo nombre coincide.

        La búsqueda es por nombre de base y recorre el directorio en
        profundidad, de forma que la evidencia puede estar suelta o dentro
        de subcarpetas (``evidencia/``, ``informe/``…).
        """
        for nombre in nombres:
            directo = self.root / nombre
            if directo.is_file():
                return directo
        for nombre in nombres:
            for encontrado in sorted(self.root.rglob(nombre)):
                if encontrado.is_file():
                    return encontrado
        return None

    def ruta_relativa(self, path: Path | None) -> str:
        """Ruta de un artefacto relativa al directorio de evidencia."""
        if path is None:
            return ""
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    # -- lectura ------------------------------------------------------------ #

    def leer_texto(self, path: Path | None) -> str:
        """Lee un artefacto como texto (tolerante a errores de decodificación)."""
        if path is None:
            return ""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def leer_json(self, path: Path | None) -> Any:
        """Lee un artefacto JSON; si está corrupto devuelve ``None``."""
        texto = self.leer_texto(path)
        if not texto.strip():
            return None
        try:
            return json.loads(texto)
        except json.JSONDecodeError:
            return None

    def leer_tsv(self, path: Path | None) -> list[dict[str, str]]:
        """Lee el TSV de la sonda devolviendo filas como diccionarios."""
        texto = self.leer_texto(path)
        if not texto.strip():
            return []
        lineas = texto.splitlines()
        cabecera = [c.strip() for c in lineas[0].split("\t")]
        filas: list[dict[str, str]] = []
        for linea in lineas[1:]:
            if not linea.strip():
                continue
            partes = linea.split("\t")
            fila = {
                cabecera[i]: partes[i].strip()
                for i in range(min(len(cabecera), len(partes)))
            }
            fila["_archivo"] = self.ruta_relativa(path)
            filas.append(fila)
        return filas

    # -- estado de redacción ------------------------------------------------ #

    def _informe_redaccion(self) -> Mapping[str, Any]:
        """Informe de ``pii_redact.py`` si existe en el directorio."""
        if "informe_redaccion" in self._cache:
            return self._cache["informe_redaccion"]
        path = self.buscar(*ALIAS_REDACCION)
        datos = self.leer_json(path)
        informe: Mapping[str, Any] = datos if isinstance(datos, Mapping) else {}
        self._cache["informe_redaccion"] = informe
        self._cache["_ruta_redaccion"] = path
        return informe

    def _salidas_redactadas(self) -> dict[str, str]:
        """Mapa ``ruta de salida -> ruta de origen`` del informe de redacción."""
        if "salidas_redactadas" in self._cache:
            return self._cache["salidas_redactadas"]
        informe = self._informe_redaccion()
        mapa: dict[str, str] = {}
        for entrada in informe.get("files", []) or []:
            if not isinstance(entrada, Mapping):
                continue
            origen = str(entrada.get("source", ""))
            destino = str(entrada.get("output", ""))
            if not destino:
                continue
            mapa[self._normalizar_ruta(destino)] = self._normalizar_ruta(origen)
        self._cache["salidas_redactadas"] = mapa
        return mapa

    def _manifiesto_redaccion(self) -> dict[str, str]:
        """Mapa ``ruta -> motivo`` declarado en el manifiesto de redacción.

        El manifiesto es la declaración explícita del auditor de qué
        artefactos ya están saneados. Cada entrada lleva su ``sha256``: si no
        cuadra con el fichero real, la declaración no vale y el artefacto
        vuelve a «SIN REDACTAR».
        """
        if "manifiesto_redaccion" in self._cache:
            return self._cache["manifiesto_redaccion"]
        path = self.buscar(FICHERO_MANIFIESTO)
        datos = self.leer_json(path)
        mapa: dict[str, str] = {}
        if isinstance(datos, Mapping):
            for entrada in datos.get("artefactos", []) or []:
                if not isinstance(entrada, Mapping):
                    continue
                ruta = self._normalizar_ruta(str(entrada.get("ruta", "")))
                if not ruta:
                    continue
                mapa[ruta] = str(entrada.get("motivo", "declarado en el manifiesto"))
        self._cache["manifiesto_redaccion"] = mapa
        return mapa

    def _normalizar_ruta(self, ruta: str) -> str:
        """Normaliza una ruta para comparar (separadores y prefijo del directorio)."""
        limpia = (ruta or "").replace("\\", "/").strip()
        try:
            limpia = str(Path(limpia).resolve().relative_to(self.root))
        except (ValueError, OSError):
            pass
        return limpia.lstrip("./")

    def estado_redaccion(self, path: Path) -> tuple[str, str]:
        """Estado de redacción de un artefacto y el motivo de la decisión.

        Reglas, en orden de preferencia:

        1. La salida aparece en el informe de ``pii_redact.py`` → ``redactado``.
        2. El artefacto vive dentro de un directorio ya saneado (nombre con
           «redact»/«sanitiz») o su nombre acaba en ``.redacted`` → ``redactado``.
        3. El artefacto **es** un informe de redacción → ``redactado`` (sólo
           contiene recuentos, nunca valores).
        4. El artefacto está declarado en el manifiesto de redacción **y** su
           ``sha256`` cuadra → ``redactado``.
        5. Cualquier otro caso → ``sin_verificar``: no hay prueba de que esté
           redactado, así que no se puede mostrar.
        """
        relativa = self.ruta_relativa(path)
        if not relativa:
            return DESCONOCIDO, "ruta fuera del directorio de evidencia"

        mapa = self._salidas_redactadas()
        clave = self._normalizar_ruta(relativa)
        if clave in mapa:
            return REDACTADO, f"salida de pii_redact.py (origen: {mapa[clave]})"

        partes = Path(relativa).parts
        if any(_MARCA_REDACCION.search(parte) for parte in partes[:-1]):
            return REDACTADO, "directorio de evidencia saneada"
        if partes[-1].endswith(".redacted"):
            return REDACTADO, "copia redactada por pii_redact.py"

        ruta_redaccion = self._cache.get("_ruta_redaccion")
        if ruta_redaccion is not None and path == ruta_redaccion:
            return REDACTADO, "informe de redacción (sólo recuentos, sin valores)"

        manifiesto = self.buscar(FICHERO_MANIFIESTO)
        if manifiesto is not None and path == manifiesto:
            return REDACTADO, "manifiesto de redacción (sólo hashes y motivos)"

        motivo = self._manifiesto_redaccion().get(clave)
        if motivo:
            declarado = self._manifiesto_sha256().get(clave, "")
            if declarado:
                real = self.hash_completo(path)
                if real and real != declarado:
                    return (
                        SIN_VERIFICAR,
                        "declarado en el manifiesto, pero el sha256 no cuadra: "
                        "el artefacto cambió después de declararse",
                    )
            return REDACTADO, f"declarado en el manifiesto de redacción: {motivo}"

        return SIN_VERIFICAR, "sin estado de redacción verificable"

    def hash_completo(self, path: Path) -> str:
        """sha256 completo de un artefacto (para verificar el manifiesto)."""
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return ""

    def _manifiesto_sha256(self) -> dict[str, str]:
        """Mapa ``ruta -> sha256 declarado`` del manifiesto de redacción."""
        if "manifiesto_sha256" in self._cache:
            return self._cache["manifiesto_sha256"]
        path = self.buscar(FICHERO_MANIFIESTO)
        datos = self.leer_json(path)
        mapa: dict[str, str] = {}
        if isinstance(datos, Mapping):
            for entrada in datos.get("artefactos", []) or []:
                if not isinstance(entrada, Mapping):
                    continue
                ruta = self._normalizar_ruta(str(entrada.get("ruta", "")))
                if ruta:
                    mapa[ruta] = str(entrada.get("sha256", ""))
        self._cache["manifiesto_sha256"] = mapa
        return mapa

    # -- índice de artefactos ------------------------------------------------ #

    def indice_artefactos(self) -> list[FileRef]:
        """Índice de todos los ficheros del directorio con su estado."""
        refs: list[FileRef] = []
        if not self.existe:
            return refs
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            estado, motivo = self.estado_redaccion(path)
            refs.append(
                FileRef(
                    path=self.ruta_relativa(path),
                    size=stat.st_size,
                    sha256=_sha256_short(path.read_bytes()) if stat.st_size < 4_000_000 else "",
                    mtime=stat.st_mtime,
                    redaction=estado,
                    redaction_reason=motivo,
                )
            )
        return refs

    def hash_de(self, ruta_relativa: str) -> str:
        """Hash corto (12) de un artefacto del directorio, o cadena vacía."""
        path = self._abs(ruta_relativa)
        if not path.is_file():
            return ""
        try:
            data = path.read_bytes()
        except OSError:
            return ""
        return _sha256_short(data)

    def subdominios(self) -> list[dict[str, Any]]:
        """Subdominios conocidos y su estado de exposición.

        Viene de ``crt.json`` (Certificate Transparency) contrastado con la
        sonda. Lo que no tiene evidencia se marca como tal: un nombre en CT
        **no** es un subdominio vivo ni comprometido.
        """
        if "subdominios" in self._cache:
            return self._cache["subdominios"]
        crt = self.leer_json(self.buscar(FICHERO_CRT))
        nombres = sorted(_nombres_ct(crt))
        filas = self.leer_tsv(self.buscar(FICHERO_PROBE_TSV))
        hosts_sonda = {
            f.get("host", "").lower()
            for f in filas
            if (f.get("verdict") or "").lower() in ("expuesto", "exposed_truncated")
        }
        hosts_probeados = {f.get("host", "").lower() for f in filas}
        autorizacion = self.authorization()
        permitidos = {h.lower() for h in autorizacion.get("hosts", [])}

        salida: list[dict[str, Any]] = []
        for nombre in nombres:
            if nombre in hosts_sonda:
                nivel, severidad = "expuesto", "alto"
            elif re.search(r"(login|verify|secure|support|confirm|recupera)", nombre):
                nivel, severidad = "sospechoso", "medio"
            elif nombre in hosts_probeados:
                nivel, severidad = "evaluado", "info"
            elif nombre in permitidos:
                nivel, severidad = "autorizado", "info"
            else:
                nivel, severidad = "inventario", "info"
            salida.append(
                {
                    "nombre": nombre,
                    "nivel": nivel,
                    "severidad": severidad,
                    "evidencia": (
                        "probe_exposure.tsv"
                        if nombre in hosts_probeados
                        else ("crt.json" if nombres else "")
                    ),
                }
            )
        self._cache["subdominios"] = salida
        return salida

    # -- score --------------------------------------------------------------- #

    def _script_score(self) -> Path | None:
        """Localiza ``attack_surface_report.py`` del toolchain propio."""
        candidatos = (
            self.root.parent / "01-tooling" / "scripts" / "attack_surface_report.py",
            self.root.parent.parent / "01-tooling" / "scripts" / "attack_surface_report.py",
            Path(__file__).resolve().parent.parent
            / "01-tooling"
            / "scripts"
            / "attack_surface_report.py",
        )
        for candidato in candidatos:
            if candidato.is_file():
                return candidato
        return None

    def _calcular_score(self) -> Mapping[str, Any] | None:
        """Calcula el score con el script propio, si está disponible.

        El script no hace red: sólo agrega los artefactos locales.
        """
        script = self._script_score()
        if script is None:
            return None
        try:
            spec = importlib.util.spec_from_file_location(
                "console_attack_surface_report", script
            )
            if spec is None or spec.loader is None:
                return None
            modulo = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = modulo
            spec.loader.exec_module(modulo)
            informe = modulo.build_report(
                probe_tsv=self._rutas_de(FICHERO_PROBE_TSV),
                secrets_json=self._rutas_de(FICHERO_SECRETS),
                headers=self._rutas_de(FICHERO_HEADERS),
                internetdb=self._rutas_de(FICHERO_INTERNETDB),
                crtsh=self._rutas_de(FICHERO_CRT),
                dns_mailsec=self._rutas_de(FICHERO_DNS),
                tls_versions=self._rutas_de(FICHERO_TLS),
                js_intel=self._rutas_de(FICHERO_JS_INTEL),
            )
            return informe
        except Exception:  # noqa: BLE001 - el score nunca debe tumbar la consola
            return None

    def _rutas_de(self, nombre: str) -> list[str]:
        """Rutas (relativas) de todos los ficheros con ese nombre."""
        if not self.existe:
            return []
        return [
            self.ruta_relativa(path)
            for path in sorted(self.root.rglob(nombre))
            if path.is_file()
        ]

    def score(self) -> dict[str, Any]:
        """Attack Exposure Score normalizado.

        Prioridad: el JSON ya calculado en el directorio de evidencia; si no
        existe, se calcula con el script propio; si tampoco, se dice que no
        hay score en lugar de inventar un 0.
        """
        if "score" in self._cache:
            return self._cache["score"]

        ruta_json = self.buscar(FICHERO_SCORE)
        informe = self.leer_json(ruta_json)
        origen = ""
        if not isinstance(informe, Mapping) or "score" not in informe:
            calculado = self._calcular_score()
            if calculado is not None:
                informe = calculado
                origen = "attack_surface_report.py (cálculo local)"

        respuesta: dict[str, Any] = {
            "disponible": False,
            "evaluable": False,
            "valor": None,
            "banda": "No evaluable",
            "bandas": [
                {"min": low, "max": high, "label": label} for low, high, label in BANDS
            ],
            "formula": {},
            "componentes": [],
            "riesgo": [],
            "bonificacion": [],
            "cobertura": {},
            "fuente": origen or self.ruta_relativa(ruta_json),
            "mensaje": None,
        }

        if not isinstance(informe, Mapping) or "score" not in informe:
            respuesta["mensaje"] = (
                "sin score: ejecuta attack_surface_report.py sobre la evidencia "
                "o deja su JSON (attack_surface_report.json) en el directorio."
            )
            self._cache["score"] = respuesta
            return respuesta

        valor = _safe_float(informe.get("score"))
        evaluable = bool(informe.get("evaluable", informe.get("any_evidence")))
        componentes, duplicados = self._normalizar_componentes(
            list(informe.get("components", []) or [])
        )
        # Sin evidencia, el script deja el total en 0 y marca `evaluable: false`.
        # La consola NO lo presenta como un 0 de seguridad: la banda es
        # «No evaluable» y el valor no se muestra.
        if not evaluable:
            valor_calculado = valor
            valor = None
            banda = "No evaluable"
        else:
            valor_calculado = valor
            banda = str(informe.get("band") or _band_for(valor))
        respuesta.update(
            {
                "disponible": True,
                "evaluable": evaluable,
                "valor": valor,
                "valor_calculado": valor_calculado,
                "banda": banda,
                "formula": dict(informe.get("formula", {}) or {}),
                "componentes": componentes,
                "riesgo": [c for c in componentes if c.get("kind") == "riesgo"],
                "bonificacion": [c for c in componentes if c.get("kind") == "bonificacion"],
                "cobertura": self._normalizar_cobertura(
                    dict(informe.get("coverage", {}) or {})
                ),
                "subdominios": self.subdominios(),
                "fuente": origen or self.ruta_relativa(ruta_json),
                "duplicados": duplicados,
                "mensaje": None,
            }
        )
        if not respuesta["evaluable"]:
            respuesta["mensaje"] = (
                "No hay evidencia: un 0 aquí no significa «seguro», significa "
                "que no hay nada que puntuar."
            )
        self._cache["score"] = respuesta
        return respuesta

    def _normalizar_componentes(
        self, componentes: list[Mapping[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Normaliza los componentes del score.

        Dos cosas, y sólo dos:

        * las rutas de la fuente se expresan **relativas** al directorio de
          evidencia (la ruta absoluta del portátil del auditor no viaja en la
          interfaz);
        * si un ``key`` aparece repetido —el script ``attack_surface_report.py``
          puede emitir dos veces ``ausencia_dmarc``— se muestra una sola vez y
          se anota el duplicado. Los puntos no cambian: el duplicado siempre
          vale 0.
        """
        vistos: set[str] = set()
        duplicados: list[str] = []
        salida: list[dict[str, Any]] = []
        for componente in componentes:
            if not isinstance(componente, Mapping):
                continue
            clave = str(componente.get("key", ""))
            if clave and clave in vistos:
                duplicados.append(clave)
                continue
            if clave:
                vistos.add(clave)
            normalizado = dict(componente)
            normalizado["source"] = self._normalizar_fuente(
                str(componente.get("source", "sin datos"))
            )
            salida.append(normalizado)
        return salida, duplicados

    def _normalizar_fuente(self, fuente: str) -> str:
        """Convierte una ruta absoluta de evidencia en ruta relativa."""
        if not fuente or fuente == "sin datos":
            return fuente
        raiz = str(self.root)
        if raiz and raiz in fuente:
            return fuente.replace(raiz + "/", "").replace(raiz, ".")
        return fuente

    def _normalizar_cobertura(self, cobertura: Mapping[str, Any]) -> dict[str, Any]:
        """Normaliza las rutas de la tabla de cobertura a rutas relativas."""
        normalizada: dict[str, Any] = {}
        for clave, valor in cobertura.items():
            if isinstance(valor, (list, tuple)):
                normalizada[clave] = [self._normalizar_fuente(str(v)) for v in valor]
            else:
                normalizada[clave] = valor
        return normalizada


    # -- endpoints de la API -------------------------------------------------- #

    def summary(self) -> dict[str, Any]:
        """Resumen global de la consola: estado, recuentos y alertas."""
        score = self.score()
        hallazgos = self.findings()
        secretos = self.secrets()
        api_surface = self.api_surface()
        iocs = self.iocs()
        evidencia = self.evidence()
        autorizacion = self.authorization()
        acciones = self.actions()

        alertas: list[dict[str, str]] = []

        if not score["disponible"]:
            alertas.append(
                {
                    "nivel": "aviso",
                    "titulo": "Sin score",
                    "detalle": score["mensaje"] or "",
                }
            )
        elif not score["evaluable"]:
            alertas.append(
                {
                    "nivel": "aviso",
                    "titulo": "Score no evaluable",
                    "detalle": "Sin evidencia suficiente: la banda no es «seguro».",
                }
            )

        sin_redactar = [a for a in evidencia["artefactos"] if a["sin_redactar"]]
        if sin_redactar:
            alertas.append(
                {
                    "nivel": "critico",
                    "titulo": f"{len(sin_redactar)} artefacto(s) SIN REDACTAR",
                    "detalle": (
                        "Están ocultos por defecto. Sin estado de redacción "
                        "verificable no se muestran."
                    ),
                }
            )

        if not autorizacion.get("disponible"):
            alertas.append(
                {
                    "nivel": "critico",
                    "titulo": "Sin autorización",
                    "detalle": "No hay authorization.json: no hay RoE que mostrar.",
                }
            )
        elif autorizacion.get("fase2_bloqueada"):
            alertas.append(
                {
                    "nivel": "critico",
                    "titulo": "FASE 2 BLOQUEADA — sin addendum firmado",
                    "detalle": "Solo Fase 1 (GET/HEAD). No se amplía el RoE.",
                }
            )
        elif autorizacion.get("fuera_de_ventana"):
            alertas.append(
                {
                    "nivel": "critico",
                    "titulo": "Ventana de autorización expirada",
                    "detalle": "La ventana del RoE no cubre el momento actual.",
                }
            )

        pendientes = [
            h for h in hallazgos["items"] if h["estado"] in ("no verificado", "en curso")
        ]
        if pendientes:
            alertas.append(
                {
                    "nivel": "aviso",
                    "titulo": f"{len(pendientes)} hallazgo(s) sin cerrar",
                    "detalle": "Estado «no verificado» o «en curso»: no son conclusiones.",
                }
            )

        return {
            "consola": "Consola de Operaciones de Seguridad",
            "modo": self.etiqueta_modo(),
            "sintetico": self.demo,
            "directorio_evidencia": str(self.root),
            "directorio_existe": self.existe,
            "generado": _now_iso(),
            "score": {
                "valor": score["valor"],
                "banda": score["banda"],
                "evaluable": score["evaluable"],
                "disponible": score["disponible"],
            },
            "recuento": {
                "hallazgos": len(hallazgos["items"]),
                "secretos": len(secretos["items"]),
                "endpoints": len(api_surface["items"]),
                "artefactos": len(evidencia["artefactos"]),
                "acciones": len(acciones["items"]),
                "iocs_no_verificados": len(
                    [i for i in iocs["items"] if i["estado"] != "confirmado"]
                ),
            },
            "redaccion": evidencia["resumen_redaccion"],
            "alertas": alertas,
            "ficheros_esperados": self.archivos_esperados(),
        }

    def archivos_esperados(self) -> list[dict[str, Any]]:
        """Qué artefactos esperaba el backend y cuáles están presentes."""
        esperados = [
            ("probe_exposure.tsv", "Sonda de exposición (TSV)"),
            ("secrets.json", "Registro de secretos (enmascarados)"),
            ("attack_surface_report.json", "Score ya calculado"),
            ("headers.txt", "Volcado de cabeceras HTTP"),
            ("js_intel.json", "Inteligencia de HTML/JS"),
            ("dns_mailsec.txt", "DNS / DMARC"),
            ("tls_versions.txt", "Versiones TLS"),
            ("crt.json", "Certificate Transparency"),
            ("redaccion.json", "Informe de redacción"),
            ("registro-de-acciones-fase-2.csv", "Registro de acciones Fase 2"),
            ("authorization.json", "Autorización firmada (RoE)"),
            ("hallazgos.json", "Hallazgos redactados a mano (opcional)"),
        ]
        resultado: list[dict[str, Any]] = []
        for nombre, descripcion in esperados:
            path = self.buscar(nombre)
            estado, motivo = (
                self.estado_redaccion(path)
                if path is not None
                else (DESCONOCIDO, "fichero ausente")
            )
            resultado.append(
                {
                    "nombre": nombre,
                    "descripcion": descripcion,
                    "presente": path is not None,
                    "ruta": self.ruta_relativa(path),
                    "redaccion": estado,
                    "redaccion_motivo": motivo,
                }
            )
        return resultado

    def findings(self) -> dict[str, Any]:
        """Hallazgos normalizados, derivados de la evidencia y de ``hallazgos.json``."""
        if "findings" in self._cache:
            return self._cache["findings"]

        items: list[dict[str, Any]] = []
        items.extend(self._hallazgos_de_sonda())
        items.extend(self._hallazgos_de_secretos())
        items.extend(self._hallazgos_de_cabeceras())
        items.extend(self._hallazgos_de_score())
        items.extend(self._hallazgos_manuales())

        # Si el fichero manual repite un id, su versión sustituye a la derivada.
        index_manual = {h["id"]: h for h in items if h["origen"] == "hallazgos.json"}
        if index_manual:
            items = [index_manual.get(h["id"], h) for h in items]

        for numero, hallazgo in enumerate(items, start=1):
            hallazgo.setdefault("id", f"H-{numero:03d}")
            hallazgo.setdefault("estado", "no verificado")
            hallazgo.setdefault("evidencia", [])
            hallazgo.setdefault("comando", "")
            hallazgo.setdefault("footprint", "")
            hallazgo.setdefault("owner", "sin asignar")
            hallazgo.setdefault("categoria", "otro")

        items.sort(
            key=lambda h: (
                _severity_rank(h.get("severidad", "info")),
                h.get("id", ""),
            )
        )

        por_estado: dict[str, int] = {}
        por_severidad: dict[str, int] = {}
        for hallazgo in items:
            por_estado[hallazgo["estado"]] = por_estado.get(hallazgo["estado"], 0) + 1
            severidad = str(hallazgo.get("severidad", "info")).lower()
            por_severidad[severidad] = por_severidad.get(severidad, 0) + 1

        respuesta = {
            "items": items,
            "resumen": {
                "total": len(items),
                "por_estado": por_estado,
                "por_severidad": por_severidad,
                "estados": list(ESTADOS_FINDING),
            },
        }
        self._cache["findings"] = respuesta
        return respuesta

    def _hallazgos_de_sonda(self) -> list[dict[str, Any]]:
        """Hallazgos derivados del TSV de la sonda (rutas realmente expuestas)."""
        path = self.buscar(FICHERO_PROBE_TSV)
        if path is None:
            return []
        archivo = self.ruta_relativa(path)
        hash_archivo = self.hash_de(archivo)
        salida: list[dict[str, Any]] = []
        for indice, fila in enumerate(self.leer_tsv(path), start=1):
            veredicto = (fila.get("verdict") or "").lower()
            if veredicto not in ("expuesto", "exposed_truncated"):
                continue
            ruta = fila.get("path", "?")
            host = fila.get("host", "?")
            truncado = (fila.get("truncated") or "").lower() in ("true", "1", "yes")
            severidad = (fila.get("severity") or "medio").lower()
            descripcion = (
                f"La ruta `{ruta}` del host `{host}` responde "
                f"{fila.get('code', '?')} sin autenticación. "
                f"Tipo de contenido: `{fila.get('content_type', '?')}`. "
                f"Bytes leídos: {fila.get('length', '0')}."
            )
            if truncado:
                descripcion += (
                    " La lectura se truncó en el tope de bytes: el fichero real "
                    "es MAYOR que lo leído, y su sha256 es sólo del primer "
                    "fragmento. El tamaño declarado por el servidor es "
                    f"{fila.get('content_length_header', '?')}."
                )
            salida.append(
                {
                    "id": f"RUTA-{indice:03d}",
                    "titulo": f"Ruta expuesta: {ruta}",
                    "severidad": severidad,
                    "categoria": "ruta",
                    "estado": "hallazgo",
                    "owner": self._owner_por_ruta(ruta),
                    "descripcion": descripcion,
                    "evidencia": [
                        {
                            "fichero": archivo,
                            "hash": hash_archivo,
                            "referencia": f"host={host} path={ruta}",
                        }
                    ],
                    "comando": (
                        f"python3 probe_exposure.py -a authorization.json "
                        f"--host {host} --path-list rutas.txt"
                    ),
                    "footprint": (
                        "1 petición GET; el cuerpo de la ruta sensible no se "
                        "guarda en disco."
                    ),
                    "fuente": archivo,
                    "origen": "probe_exposure.tsv",
                }
            )
        return salida

    def _hallazgos_de_secretos(self) -> list[dict[str, Any]]:
        """Hallazgos derivados del registro de secretos."""
        path = self.buscar(FICHERO_SECRETS)
        if path is None:
            return []
        archivo = self.ruta_relativa(path)
        hash_archivo = self.hash_de(archivo)
        datos = self.leer_json(path)
        if not isinstance(datos, Mapping):
            return []
        salida: list[dict[str, Any]] = []
        for indice, hallazgo in enumerate(datos.get("findings", []) or [], start=1):
            if not isinstance(hallazgo, Mapping):
                continue
            tipo = str(hallazgo.get("type", "desconocido"))
            severidad = str(hallazgo.get("severity", "info")).lower()
            fichero = self._ruta_legible(str(hallazgo.get("file", "?")))
            salida.append(
                {
                    "id": f"SEC-{indice:03d}",
                    "titulo": f"Secreto expuesto: {tipo}",
                    "severidad": severidad,
                    "categoria": "secreto",
                    "estado": "hallazgo",
                    "owner": self._owner_por_ruta(fichero),
                    "descripcion": (
                        f"Tipo `{tipo}` detectado en `{fichero}` "
                        f"línea {hallazgo.get('line', '?')}. Valor: "
                        f"`{hallazgo.get('masked', '')}` (enmascarado; nunca el "
                        "valor completo). Huella sha256[:12]: "
                        f"`{hallazgo.get('sha256', '')}`."
                    ),
                    "evidencia": [
                        {
                            "fichero": archivo,
                            "hash": hash_archivo,
                            "referencia": f"{fichero}:{hallazgo.get('line', '?')}",
                        }
                    ],
                    "comando": (
                        f"python3 secrets_scan.py {fichero} "
                        f"--json --out {archivo}"
                    ),
                    "footprint": "Escaneo local, sin red. No se usa la credencial.",
                    "fuente": archivo,
                    "origen": "secrets.json",
                }
            )
        return salida

    def _hallazgos_de_score(self) -> list[dict[str, Any]]:
        """Hallazgos derivados de los componentes de riesgo con puntos."""
        score = self.score()
        salida: list[dict[str, Any]] = []
        for indice, componente in enumerate(score.get("riesgo", []), start=1):
            puntos = _safe_float(componente.get("points"))
            if puntos <= 0:
                continue
            fuente = str(componente.get("source", "sin datos"))
            severidad = self._severidad_por_puntos(puntos)
            salida.append(
                {
                    "id": f"SCO-{indice:03d}",
                    "titulo": str(componente.get("name", "componente")),
                    "severidad": severidad,
                    "categoria": "configuracion",
                    "estado": "hallazgo",
                    "owner": "equipo técnico",
                    "descripcion": (
                        f"{componente.get('justification', '')} "
                        f"Detalle: {componente.get('detail', 'sin detalle')}. "
                        f"Puntuación: {puntos} de {componente.get('max_points', 0)}."
                    ),
                    "evidencia": [
                        {
                            "fichero": fuente.replace("evidencia: ", ""),
                            "hash": self.hash_de(fuente.replace("evidencia: ", "")),
                            "referencia": str(componente.get("key", "")),
                        }
                    ],
                    "comando": "",
                    "footprint": "Cálculo local sobre evidencia ya recogida.",
                    "fuente": fuente,
                    "origen": "attack_surface_report",
                }
            )
        return salida

    def _hallazgos_manuales(self) -> list[dict[str, Any]]:
        """Hallazgos escritos a mano por el auditor (``hallazgos.json``)."""
        path = self.buscar(FICHERO_HALLAZGOS)
        if path is None:
            return []
        archivo = self.ruta_relativa(path)
        hash_archivo = self.hash_de(archivo)
        datos = self.leer_json(path)
        if isinstance(datos, Mapping):
            datos = datos.get("items", datos.get("hallazgos", []))
        if not isinstance(datos, list):
            return []
        salida: list[dict[str, Any]] = []
        for indice, hallazgo in enumerate(datos, start=1):
            if not isinstance(hallazgo, Mapping):
                continue
            evidencia = hallazgo.get("evidencia", [])
            if isinstance(evidencia, str):
                evidencia = [{"fichero": evidencia, "hash": "", "referencia": ""}]
            if not isinstance(evidencia, list):
                evidencia = []
            evidencia_normalizada = []
            for entrada in evidencia:
                if isinstance(entrada, str):
                    evidencia_normalizada.append(
                        {
                            "fichero": entrada,
                            "hash": self.hash_de(entrada),
                            "referencia": "",
                        }
                    )
                elif isinstance(entrada, Mapping):
                    fichero = str(entrada.get("fichero", entrada.get("file", "")))
                    evidencia_normalizada.append(
                        {
                            "fichero": fichero,
                            "hash": str(entrada.get("hash", "")) or self.hash_de(fichero),
                            "referencia": str(entrada.get("referencia", "")),
                        }
                    )
            estado = str(hallazgo.get("estado", "no verificado")).lower()
            if estado not in ESTADOS_FINDING:
                estado = "no verificado"
            salida.append(
                {
                    "id": str(hallazgo.get("id", f"MAN-{indice:03d}")),
                    "titulo": str(hallazgo.get("titulo", hallazgo.get("title", "sin título"))),
                    "severidad": str(hallazgo.get("severidad", "info")).lower(),
                    "categoria": str(hallazgo.get("categoria", "otro")).lower(),
                    "estado": estado,
                    "owner": str(hallazgo.get("owner", "sin asignar")),
                    "descripcion": str(hallazgo.get("descripcion", "")),
                    "evidencia": evidencia_normalizada,
                    "comando": str(hallazgo.get("comando", "")),
                    "footprint": str(hallazgo.get("footprint", "")),
                    "fuente": archivo,
                    "origen": "hallazgos.json",
                }
            )
        return salida

    def _hallazgos_de_cabeceras(self) -> list[dict[str, Any]]:
        """Hallazgos derivados del informe de cabeceras de seguridad."""
        path = self.buscar(FICHERO_HEADER_REPORT)
        if path is None:
            return []
        archivo = self.ruta_relativa(path)
        hash_archivo = self.hash_de(archivo)
        datos = self.leer_json(path)
        if not isinstance(datos, Mapping):
            return []
        salida: list[dict[str, Any]] = []
        indice = 0
        for respuesta in datos.get("responses", []) or []:
            if not isinstance(respuesta, Mapping):
                continue
            for finding in respuesta.get("findings", []) or []:
                if not isinstance(finding, Mapping):
                    continue
                severidad = str(finding.get("severity", "info")).lower()
                if severidad == "ok":
                    continue
                indice += 1
                salida.append(
                    {
                        "id": f"CAB-{indice:03d}",
                        "titulo": str(finding.get("check", "comprobación de cabecera")),
                        "severidad": severidad,
                        "categoria": str(finding.get("category", "cabeceras")).lower(),
                        "estado": "hallazgo",
                        "owner": "equipo técnico",
                        "descripcion": (
                            f"Comprobación `{finding.get('check', '?')}`: valor "
                            f"«{finding.get('value', '?')}». "
                            f"Remediación: {finding.get('remediation', 'sin indicar')}."
                        ),
                        "evidencia": [
                            {
                                "fichero": archivo,
                                "hash": hash_archivo,
                                "referencia": str(respuesta.get("url", "")),
                            }
                        ],
                        "comando": (
                            "python3 header_tls_report.py headers.txt --json"
                        ),
                        "footprint": "Análisis local de un volcado de cabeceras.",
                        "fuente": archivo,
                        "origen": "header_tls.json",
                    }
                )
        return salida

    def _ruta_legible(self, ruta: str) -> str:
        """Convierte una ruta absoluta en algo mostrable sin filtrar el disco.

        Las rutas que caen dentro del directorio de evidencia se expresan
        relativas a él; las demás se acortan a ``~/…`` o al nombre del
        fichero. La consola no muestra la estructura del portátil del auditor.
        """
        texto = str(ruta or "")
        if not texto:
            return ""
        try:
            ruta_abs = Path(texto)
            if ruta_abs.is_absolute():
                try:
                    return str(ruta_abs.relative_to(self.root))
                except ValueError:
                    pass
                try:
                    return "~/" + str(ruta_abs.relative_to(Path.home()))
                except ValueError:
                    return ruta_abs.name
        except OSError:
            pass
        return texto

    def _severidad_por_puntos(self, puntos: float) -> str:
        """Traduce los puntos de un componente a una severidad operativa."""
        if puntos >= 12:
            return "critico"
        if puntos >= 8:
            return "alto"
        if puntos >= 4:
            return "medio"
        if puntos > 0:
            return "bajo"
        return "info"

    def _owner_por_ruta(self, ruta: str) -> str:
        """Owner por defecto según la familia de ruta (no se inventa una persona)."""
        minuscula = ruta.lower()
        if "wp-content" in minuscula or "backup" in minuscula or "dump" in minuscula:
            return "equipo técnico / hosting"
        if "js" in minuscula or ".env" in minuscula or "config" in minuscula:
            return "equipo técnico"
        if "panel" in minuscula or "admin" in minuscula:
            return "equipo técnico"
        return "sin asignar"

    # -- registro de secretos -------------------------------------------------- #

    def secrets(self) -> dict[str, Any]:
        """Secret Register de 12 columnas (``exposicion-de-secretos.md`` §8)."""
        if "secrets" in self._cache:
            return self._cache["secrets"]
        path = self.buscar(FICHERO_SECRETS)
        archivo = self.ruta_relativa(path)
        hash_archivo = self.hash_de(archivo)
        datos = self.leer_json(path)
        brutos = datos.get("findings", []) if isinstance(datos, Mapping) else []
        if not isinstance(brutos, list):
            brutos = []

        items: list[dict[str, Any]] = []
        verificaciones = self._verificaciones_secretos()
        for indice, hallazgo in enumerate(brutos, start=1):
            if not isinstance(hallazgo, Mapping):
                continue
            tipo = str(hallazgo.get("type", "desconocido"))
            ubicacion = self._ruta_legible(str(hallazgo.get("file", "?")))
            if hallazgo.get("line"):
                ubicacion = f"{ubicacion} (línea {hallazgo['line']})"
            severidad = str(hallazgo.get("severity", "info")).lower()
            huella = str(hallazgo.get("sha256", ""))[:12]
            nota = verificaciones.get(huella) or verificaciones.get(f"S-{indice:02d}") or {}
            items.append(
                {
                    "id": f"S-{indice:02d}",
                    "tipo": tipo,
                    "vector": self._vector_de(tipo),
                    "ubicacion": ubicacion,
                    "masked": str(hallazgo.get("masked", "")),
                    "fingerprint": huella,
                    "vive": str(nota.get("vive", "no probado")),
                    "vive_detalle": str(
                        nota.get(
                            "nota",
                            "No se usó la credencial: RoE 1.3. Sin verificación, "
                            "no se puede afirmar que esté viva ni muerta.",
                        )
                    ),
                    "alcance_real": str(
                        nota.get(
                            "alcance_real",
                            "Alcance real: POR CONFIRMAR con el panel del cliente.",
                        )
                    ),
                    "criticidad": severidad.upper() if severidad != "info" else "INFO",
                    "rotacion_urgente": str(
                        nota.get("rotacion_urgente", self._rotacion(severidad))
                    ),
                    "owner": str(nota.get("owner", self._owner_por_ruta(ubicacion))),
                    "evidencia": [
                        {
                            "fichero": archivo,
                            "hash": hash_archivo,
                            "referencia": ubicacion,
                        }
                    ],
                    "contexto": str(hallazgo.get("context", ""))[:160],
                    "descripcion": str(hallazgo.get("description", "")),
                }
            )

        respuesta = {
            "items": items,
            "columnas": [
                "id",
                "tipo",
                "vector",
                "ubicacion",
                "masked",
                "fingerprint",
                "vive",
                "alcance_real",
                "criticidad",
                "rotacion_urgente",
                "owner",
                "evidencia",
            ],
            "fuente": archivo,
            "hash_archivo": hash_archivo,
            "mensaje": (
                None
                if items
                else "Sin secrets.json: no se ha ejecutado secrets_scan.py sobre la evidencia."
            ),
        }
        self._cache["secrets"] = respuesta
        return respuesta

    def _verificaciones_secretos(self) -> dict[str, Mapping[str, Any]]:
        """Verificaciones manuales de secretos (``secrets-verificacion.json``).

        La tríada «sí / no / no probado» no se puede deducir de un escaneo
        local: hace falta una comprobación explícita y autorizada. Este
        fichero es donde el auditor deja esa constancia.
        """
        if "verificaciones_secretos" in self._cache:
            return self._cache["verificaciones_secretos"]
        datos = self.leer_json(self.buscar(FICHERO_VERIF_SECRETS))
        notas: dict[str, Mapping[str, Any]] = {}
        if isinstance(datos, Mapping):
            for clave, valor in (datos.get("notas", {}) or {}).items():
                if isinstance(valor, Mapping):
                    notas[str(clave)] = valor
        self._cache["verificaciones_secretos"] = notas
        return notas

    def _vector_de(self, tipo: str) -> str:
        """Vector de exposición deducido del tipo de secreto."""
        tabla = {
            "aws_access_key_id": "V01 · JS de cliente",
            "aws_secret_access_key": "V01 · JS de cliente",
            "stripe_secret_key": "V01 · JS de cliente",
            "connection_uri_credentials": "V03 · Fichero de configuración publicado",
            "private_key_block": "V06 · Repositorio o configuración",
            "jwt": "V08 · Log público",
            "slack_webhook": "V11 · HTML inline",
            "discord_webhook": "V11 · HTML inline",
            "npm_auth_token": "V09 · Fichero de proyecto",
            "google_api_key": "V01 · JS de cliente",
            "firebase_database_url": "V12 · Configuración de cliente",
        }
        return tabla.get(tipo, "V00 · Vector por clasificar")

    def _rotacion(self, severidad: str) -> str:
        """Plazo de rotación recomendado por severidad."""
        return {
            "critico": "sí — inmediata",
            "alto": "sí — 24 h",
            "medio": "sí — 7 días",
            "bajo": "pendiente de confirmar",
            "info": "no",
        }.get(severidad, "pendiente de confirmar")

    # -- superficie de API ------------------------------------------------------ #

    def api_surface(self) -> dict[str, Any]:
        """Endpoints descubiertos, con método, auth, PII y severidad."""
        if "api_surface" in self._cache:
            return self._cache["api_surface"]
        path = self.buscar(FICHERO_JS_INTEL)
        archivo = self.ruta_relativa(path)
        hash_archivo = self.hash_de(archivo)
        datos = self.leer_json(path)

        collected: dict[str, dict[str, Any]] = {}
        if isinstance(datos, Mapping):
            for fichero in datos.get("files", []) or []:
                if not isinstance(fichero, Mapping):
                    continue
                origen = self._ruta_legible(str(fichero.get("file", "?")))
                for endpoint in fichero.get("api_endpoints", []) or []:
                    self._registrar_endpoint(collected, str(endpoint), origen)
                for endpoint in fichero.get("sensitive_routes", []) or []:
                    self._registrar_endpoint(
                        collected, str(endpoint), origen, sensible=True
                    )

        items = sorted(collected.values(), key=lambda e: (e["host"], e["ruta"]))
        respuesta = {
            "items": items,
            "fuente": archivo,
            "hash_archivo": hash_archivo,
            "mensaje": (
                None
                if items
                else "Sin js_intel.json: ejecuta js_intel.py sobre el material descargado."
            ),
        }
        self._cache["api_surface"] = respuesta
        return respuesta

    def _registrar_endpoint(
        self,
        collected: dict[str, dict[str, Any]],
        endpoint: str,
        origen: str,
        *,
        sensible: bool = False,
    ) -> None:
        """Añade un endpoint al diccionario normalizado (deduplicado)."""
        if not endpoint or endpoint.startswith(("data:", "javascript:", "#")):
            return
        absoluto = endpoint.startswith(("http://", "https://"))
        host = _host_of(endpoint) if absoluto else "propio"
        ruta = endpoint
        if absoluto:
            partes = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+(.*)$", endpoint)
            ruta = (partes.group(1) if partes else "/") or "/"
        ruta = ruta.split("?")[0]
        clave = f"{host}{ruta}"
        pii = bool(_MARCA_PII.search(ruta))
        admin = bool(_MARCA_SENSIBLE.search(ruta))
        metodo = self._metodo_de(ruta)
        auth = "no" if (admin or pii) else "no verificable"
        severidad = self._severidad_endpoint(pii, admin, absoluto)
        entrada = collected.get(clave)
        if entrada is None:
            collected[clave] = {
                "metodo": metodo,
                "ruta": ruta,
                "host": host,
                "auth": auth,
                "pii": pii,
                "sensible": admin,
                "severidad": severidad,
                "origen": origen,
                "fuente": origen,
            }
        else:
            entrada["sensible"] = entrada["sensible"] or admin
            if admin and not entrada["auth"].startswith("no "):
                entrada["auth"] = "no"
            if origen not in str(entrada.get("origen", "")):
                entrada["origen"] = f"{entrada['origen']}, {origen}"

    def _metodo_de(self, ruta: str) -> str:
        """Método HTTP deducido de la ruta (lo que se ve, no lo que se prueba)."""
        if re.search(r"/(nuevo|crear|alta|registro|login|logout|guardar)", ruta, re.I):
            return "POST?"
        return "GET?"

    def _severidad_endpoint(self, pii: bool, admin: bool, absoluto: bool) -> str:
        """Severidad de un endpoint según si toca PII o es administrativo."""
        if pii and admin:
            return "critico"
        if pii:
            return "alto"
        if admin:
            return "medio"
        if absoluto:
            return "bajo"
        return "info"

    # -- IoC -------------------------------------------------------------------- #

    def iocs(self) -> dict[str, Any]:
        """Checklist de 18 IoC, tabla de afirmaciones y límites de la vista."""
        if "iocs" in self._cache:
            return self._cache["iocs"]
        ts = self.buscar(FICHERO_PROBE_TSV)
        filas = self.leer_tsv(ts)
        cabeceras = self.leer_texto(self.buscar(FICHERO_HEADERS))
        dns = self.leer_texto(self.buscar(FICHERO_DNS))
        crt = self.leer_json(self.buscar(FICHERO_CRT))
        artefactos = self.indice_artefactos()

        items: list[dict[str, Any]] = []
        for numero, indicador, donde, severidad in IOCS:
            items.append(
                {
                    "numero": numero,
                    "indicador": indicador,
                    "donde": donde,
                    "severidad": severidad,
                    "estado": self._estado_ioc(
                        numero, filas, cabeceras, dns, crt, artefactos
                    ),
                    "evidencia": [],
                    "nota": "Un IoC no confirmado por el cliente se reporta como "
                    "«indicador pendiente de confirmación», no como hallazgo cerrado.",
                }
            )

        respuesta = {
            "items": items,
            "afirmaciones": AFIRMACIONES,
            "no_verificable": NO_VERIFICABLE,
            "frase_cierre": FRASE_CIERRE_IOC,
            "mensaje": (
                "La lista es el checklist del módulo; el estado se deriva de la "
                "evidencia disponible. Sin logs del cliente, ningún IoC se "
                "confirma: se queda «pendiente de confirmación»."
            ),
        }
        self._cache["iocs"] = respuesta
        return respuesta

    def _estado_ioc(
        self,
        numero: int,
        filas: list[dict[str, str]],
        cabeceras: str,
        dns: str,
        crt: Any,
        artefactos: list[FileRef],
    ) -> str:
        """Estado del IoC derivado de la evidencia realmente disponible."""
        exposed = [
            f
            for f in filas
            if (f.get("verdict") or "").lower() in ("expuesto", "exposed_truncated")
        ]
        rutas = {f.get("path", "") for f in exposed}

        if numero == 1:  # subdominio inesperado
            nombres = _nombres_ct(crt)
            if not nombres:
                return "no evaluable"
            return "pendiente de confirmación"
        if numero == 2:  # ruta que no debería existir
            if rutas:
                return "indicador pendiente"
            return "no evaluable" if not filas else "sin indicador"
        if numero == 3:  # fichero ejecutable subido
            if any(r.endswith((".php", ".exe", ".sh")) for r in rutas):
                return "indicador pendiente"
            return "sin indicador"
        if numero == 4:  # wp-config.php modificado
            if any("wp-config" in r for r in rutas):
                return "indicador pendiente"
            return "no evaluable"
        if numero == 5:  # ficheros por defecto de WordPress
            if any(r in ("/readme.html", "/license.txt", "/wp-admin/install.php") for r in rutas):
                return "indicador pendiente"
            return "sin indicador"
        if numero == 6:  # pico de 404
            return "no evaluable"  # requiere access log
        if numero == 7:  # .htaccess defensivo
            return "no evaluable"
        if numero == 8:  # cron jobs nuevos
            return "no evaluable"
        if numero == 9:  # usuarios nuevos
            return "no evaluable"
        if numero == 10:  # claves rotadas sin explicación
            return "no evaluable"
        if numero == 11:  # notas de ransomware
            if any("ransom" in a.path.lower() or "readme.txt" in a.path.lower() for a in artefactos):
                return "indicador pendiente"
            return "sin indicador"
        if numero == 12:  # cambios en DNS
            if "DMARC1" in dns:
                return "sin indicador"
            return "no evaluable" if not dns else "indicador pendiente"
        if numero == 13:  # correo saliente
            return "no evaluable"  # requiere DMARC RPT
        if numero == 14:  # repositorio .git publicado
            if any(r.startswith("/.git") for r in rutas):
                return "indicador pendiente"
            return "sin indicador"
        if numero == 15:  # backups accesibles
            if any("backup" in r or r.endswith((".sql", ".zip", ".tar.gz")) for r in rutas):
                return "indicador pendiente"
            return "sin indicador"
        if numero == 16:  # configuración de framework expuesta
            if any(r in ("/.env", "/actuator/env", "/config.json", "/web.config") for r in rutas):
                return "indicador pendiente"
            return "sin indicador"
        if numero == 17:  # métricas públicas
            if any(r in ("/metrics", "/actuator/health", "/server-status") for r in rutas):
                return "indicador pendiente"
            return "sin indicador"
        if numero == 18:  # ficheros subidos por terceros
            return "no evaluable"  # requiere histórico de terceros
        if cabeceras:
            return "no evaluable"
        return "no evaluable"

    # -- evidencia -------------------------------------------------------------- #

    def evidence(self) -> dict[str, Any]:
        """Índice del directorio de evidencia con el estado de redacción."""
        if "evidence" in self._cache:
            return self._cache["evidence"]
        artefactos = [ref.to_dict() for ref in self.indice_artefactos()]
        redactados = [a for a in artefactos if a["redaccion"] == REDACTADO]
        sin_verificar = [a for a in artefactos if a["redaccion"] == SIN_VERIFICAR]
        desconocidos = [a for a in artefactos if a["redaccion"] == DESCONOCIDO]
        total = len(artefactos)
        respuesta = {
            "artefactos": artefactos,
            "resumen_redaccion": {
                "total": total,
                "redactados": len(redactados),
                "sin_verificar": len(sin_verificar),
                "desconocidos": len(desconocidos),
                "cobertura_pct": round(100.0 * len(redactados) / total, 1) if total else 0.0,
            },
            "sin_redactar": [a["ruta"] for a in sin_verificar + desconocidos],
            "aviso": (
                "Hay artefactos sin estado de redacción verificable: están "
                "ocultos por defecto. La consola sólo muestra evidencia "
                "redactada."
                if sin_verificar or desconocidos
                else "Todos los artefactos tienen estado de redacción verificable."
            ),
        }
        self._cache["evidence"] = respuesta
        return respuesta

    # -- autorización ------------------------------------------------------------ #

    def authorization(self) -> dict[str, Any]:
        """Panel del RoE: cliente, referencia, ventana, hosts y métodos."""
        if "authorization" in self._cache:
            return self._cache["authorization"]
        path = self.buscar(FICHERO_AUTORIZACION)
        archivo = self.ruta_relativa(path)
        datos = self.leer_json(path)
        datos = datos if isinstance(datos, Mapping) else {}

        ahora = datetime.now(timezone.utc)
        valida_desde = _parseo_iso(str(datos.get("valid_from", "")))
        valida_hasta = _parseo_iso(str(datos.get("valid_to", "")))
        en_ventana = (
            valida_desde is not None
            and valida_hasta is not None
            and valida_desde <= ahora <= valida_hasta
        )
        segundos = (
            int((valida_hasta - ahora).total_seconds()) if valida_hasta is not None else None
        )

        hosts = [str(h) for h in datos.get("hosts", []) or []]
        metodos = [str(m).upper() for m in datos.get("allowed_methods", []) or []]
        addendum = self.buscar("addendum-fase2-firmado.md", "addendum-fase2*.md")

        # Hosts que aparecen en la sonda: si alguno no está en el allowlist,
        # la consola lo marca en rojo.
        hosts_observados = sorted(
            {
                str(fila.get("host", "")).lower()
                for fila in self.leer_tsv(self.buscar(FICHERO_PROBE_TSV))
                if fila.get("host")
            }
        )

        respuesta = {
            "disponible": bool(datos),
            "fuente": archivo,
            "hash_archivo": self.hash_de(archivo),
            "authorization_ref": str(datos.get("authorization_ref", "")),
            "client": str(datos.get("client", "")),
            "signed_by": str(datos.get("signed_by", "")),
            "signed_at": str(datos.get("signed_at", "")),
            "valid_from": str(datos.get("valid_from", "")),
            "valid_to": str(datos.get("valid_to", "")),
            "hosts": hosts,
            "hosts_observados": hosts_observados,
            "allowed_methods": metodos,
            "metodos_efectivos": ["GET", "HEAD"],
            "max_bytes": _safe_int(datos.get("max_bytes", 0)),
            "min_interval_s": _safe_float(datos.get("min_interval_s", 0.0)),
            "timeout_s": _safe_float(datos.get("timeout_s", 0.0)),
            "user_agent": str(datos.get("user_agent", "")),
            "notes": str(datos.get("notes", "")),
            "en_ventana": en_ventana,
            "fuera_de_ventana": bool(datos) and not en_ventana,
            "segundos_restantes": segundos,
            "fase2_bloqueada": addendum is None,
            "fase2_addendum": self.ruta_relativa(addendum) if addendum else "",
            "estado_fase2": (
                "FASE 2 AUTORIZADA — addendum firmado presente"
                if addendum is not None
                else "FASE 2 BLOQUEADA — sin addendum firmado"
            ),
            "doctrina": [
                "Sólo GET y HEAD. Nunca POST, PUT, PATCH ni DELETE.",
                "≥ 1 s entre peticiones y User-Agent honesto y contactable.",
                "Nada de fuerza bruta, fuzzing masivo ni escaneo de puertos.",
                "No se recolectan datos personales: todo lo que sale va redactado.",
                "Lo que pertenece a terceros se describe, no se ataca.",
            ],
        }
        self._cache["authorization"] = respuesta
        return respuesta

    # -- registro de acciones ------------------------------------------------------ #

    def actions(self) -> dict[str, Any]:
        """Filas del registro de acciones de Fase 2, tal cual, con su huella."""
        if "actions" in self._cache:
            return self._cache["actions"]
        path = self.buscar(*ALIAS_ACCIONES)
        archivo = self.ruta_relativa(path)
        hash_archivo = self.hash_de(archivo)
        texto = self.leer_texto(path)
        items: list[dict[str, Any]] = []
        if texto.strip():
            try:
                lector = csv.DictReader(texto.splitlines())
                for indice, fila in enumerate(lector, start=1):
                    fila = {k: (v if v is not None else "") for k, v in fila.items()}
                    fila["_id"] = fila.get("id") or f"A-{indice:03d}"
                    fila["_archivo"] = archivo
                    items.append(fila)
            except csv.Error:
                items = []
        respuesta = {
            "items": items,
            "fuente": archivo,
            "hash_archivo": hash_archivo,
            "columnas": [
                "id",
                "fecha_hora",
                "host",
                "endpoint",
                "tecnica",
                "metodo_http",
                "cuenta_usada",
                "tipo_cuenta",
                "datos_tocados",
                "resultado",
                "evidencia_archivo",
                "footprint",
                "rollback_hecho",
                "severidad",
                "estado",
                "notas",
            ],
            "mensaje": (
                None
                if items
                else "Sin registro-de-acciones-fase-2.csv: no hay acciones registradas."
            ),
        }
        self._cache["actions"] = respuesta
        return respuesta


# --------------------------------------------------------------------------- #
# Catálogos de método (texto fijo del playbook, no datos del cliente)
# --------------------------------------------------------------------------- #

#: Los 18 IoC del módulo ``exposicion-a-ataques.md`` §5.
IOCS: tuple[tuple[int, str, str, str], ...] = (
    (1, "Subdominio inesperado", "crt.sh, dig, histórico DNS", "ALTO (phishing activo) / MEDIO (subdominio abandonado)"),
    (2, "Ruta que no debería existir", "Sitemap, Wayback CDX, Common Crawl, urlscan", "ALTO si sirve phishing; MEDIO si es una ruta técnica filtrada"),
    (3, "Fichero ejecutable subido", "wp-content/uploads/, /media/, cualquier directorio de subida", "CRÍTICO (ejecución de código en el servidor)"),
    (4, "wp-config.php modificado", "Fichero de configuración de WordPress", "ALTO (o CRÍTICO si además se añadió un usuario)"),
    (5, "Ficheros por defecto de WordPress presentes o ausentes", "Raíz del sitio", "MEDIO / INFO según el caso"),
    (6, "Pico de 404 en rutas de administración", "Access log, WAF", "MEDIO (patrón) — sube a ALTO si hay algún 200"),
    (7, ".htaccess defensivo inesperado", "wp-content/uploads/.htaccess", "INFO como positivo; ALTO si hay .php coexistiendo"),
    (8, "Cron jobs nuevos", "crontab, wp-cron, panel de hosting", "ALTO (persistencia)"),
    (9, "Usuarios nuevos en WordPress", "wp-json/wp/v2/users (sin autenticación) o export del panel", "ALTO / CRÍTICO según rol"),
    (10, "Claves de API rotadas sin explicación", "Inventario del cliente vs. estado actual", "ALTO"),
    (11, "Notas de ransomware", "Extensiones habituales de nota, en la raíz y en directorios de datos", "CRÍTICO"),
    (12, "Cambios en DNS (MX/TXT)", "Histórico DNS, panel del proveedor", "ALTO / CRÍTICO"),
    (13, "Correo saliente en nombre del dominio", "DMARC aggregate reports (RPT)", "ALTO"),
    (14, "Repositorio .git publicado", "/.git/HEAD, /.git/config", "MEDIO (exposición) / ALTO si hay secretos en el histórico"),
    (15, "Backups o volcados de base de datos accesibles", "/backup.zip, /db.sql, /dump.sql", "CRÍTICO"),
    (16, "Archivos de configuración de framework expuestos", "/.env, /actuator/env, /config.json, /web.config", "CRÍTICO"),
    (17, "Servidor de métricas o monitorización público", "/metrics, /actuator/health, /server-status", "MEDIO"),
    (18, "Archivos subidos por terceros (histórico)", "urlscan.io, Wayback", "ALTO"),
)

#: La tabla «afirmación vs. lo que la evidencia sí sostiene» (§1.4).
AFIRMACIONES: tuple[tuple[str, str, str], ...] = (
    ("Su web ha recibido 12 000 ataques.", "En la ventana del 1 al 30 de octubre, el servidor registró X peticiones a rutas de autenticación desde Y direcciones IP distintas.", "Access log del cliente (autorizado)"),
    ("Su web es segura.", "No se identificó ninguna exposición crítica en la superficie pública revisada. Revisión cerrada el <fecha>; no cubre autenticación, API interna ni red.", "Evidencia propia + fecha"),
    ("Nadie ha atacado su sitio.", "No se encontraron indicadores de compromiso observables desde fuera hasta la fecha. Esto no descarta actividad interna o ataques sin huella.", "CT + DNS + histórico + urlscan"),
    ("Su sitio lleva 5 años sin brechas.", "No hay forma de verificarlo desde fuera. El histórico disponible arranca en <fecha> y sólo cubre rutas indexadas por terceros.", "Wayback CDX / Common Crawl"),
    ("Nadie ha entrado.", "No hay evidencia de acceso no autorizado en los logs revisados (rango <fecha>, <n> registros). Fuera de alcance: la red interna.", "Logs de autenticación del cliente"),
    ("Hay 34 subdominios.", "Certificate Transparency registra 34 nombres distintos para ejemplo.mx hasta la fecha. 13 no resuelven hoy.", "crt.sh + dig"),
    ("Están expuestos los datos de los pacientes.", "El endpoint X responde 200 y devuelve el esquema de la tabla de pacientes. No se descargó ningún registro (fuera de alcance: datos de terceros).", "curl -D + sonda"),
    ("El sitio tiene una vulnerabilidad crítica.", "El parámetro X se refleja sin codificar en la respuesta de Y. No se explotó; no se comprobó alcanzabilidad de datos.", "Evidencia + comando reproducible"),
    ("Google no lo marca como malware.", "A la fecha de la consulta, el dominio no aparecía en el informe de Safe Browsing. Es una fotografía de un momento.", "Transparency Report"),
    ("Nadie ha usado su dominio para phishing.", "No se detectaron subdominios sospechosos en CT ni cambios de MX/TXT en la ventana revisada. No es prueba de ausencia.", "crt.sh + histórico DNS"),
    ("El TLS está roto.", "El servidor rechaza TLS 1.0 y 1.1 (alert 70) y negocia 1.2/1.3 con cipher suites de la lista…", "openssl s_client + tls_versions.txt"),
    ("Su base de datos está expuesta.", "El puerto 3306 aparece publicado en el escaneo de Shodan (dato de un tercero). No se escaneó ni se intentó conectar.", "InternetDB"),
    ("Su web recibe X visitas al día.", "No se midió. No hay acceso a analítica y no se debe inferir del número de subdominios.", "—"),
    ("La auditoría confirma que están hackeados.", "La auditoría confirma exposición. El compromiso se evalúa con los indicadores de la §5 y, cuando el cliente aporta logs, con la §4.", "—"),
)

#: Lo que ningún auditor externo puede ver (por qué el número no se puede contar).
NO_VERIFICABLE: tuple[tuple[str, str], ...] = (
    ("Volumen de ataque", "El contador más fiel es el access.log del servidor, el log del WAF o el log de autenticación. Un tercero que mira desde fuera no tiene ninguno de los tres."),
    ("La mayoría de los ataques", "Un intento de credenciales, una enumeración de identificadores o una inyección que falla no modifican nada del estado público. Quien llega después no puede saberlo."),
    ("El ritmo del atacante", "Los intentos útiles son de baja tasa, repartidos en el tiempo y desde IP dispersas: justo los que no dejan rastro en los índices públicos."),
    ("Activos que no son el sitio web", "Correo corporativo, formularios de reserva de un proveedor, la nube donde vive el sitio, la cuenta del hosting. Ninguno es «la página web» y ninguno es observable desde fuera."),
    ("El propio tráfico del auditor", "Si el equipo del cliente ve tus GET, tú apareces como un visitante más. Ninguna de tus peticiones cuenta como ataque, y hay que decirlo en el informe."),
)

#: Frase de cierre obligatoria de la sección de IoC (§5.2).
FRASE_CIERRE_IOC = (
    "En la superficie revisada, hasta la fecha de cierre, no se identificaron "
    "indicadores de compromiso. Este resultado no equivale a «no hubo "
    "incidentes»: elude a intrusiones que no dejan rastro público y a toda la "
    "actividad dentro de la red del cliente. Con los logs de las §4, esta misma "
    "sección se convierte en una verificación con fecha y número."
)


# --------------------------------------------------------------------------- #
# Ayudantes de módulo
# --------------------------------------------------------------------------- #


def _parseo_iso(texto: str) -> datetime | None:
    """Parsea una fecha ISO-8601; devuelve ``None`` si no es válida."""
    if not texto:
        return None
    limpio = texto.strip().replace("Z", "+00:00")
    try:
        fecha = datetime.fromisoformat(limpio)
    except ValueError:
        return None
    if fecha.tzinfo is None:
        fecha = fecha.replace(tzinfo=timezone.utc)
    return fecha.astimezone(timezone.utc)


def _nombres_ct(crt: Any) -> set[str]:
    """Nombres de host de un JSON de Certificate Transparency."""
    nombres: set[str] = set()
    if isinstance(crt, list):
        entradas: Iterable[Any] = crt
    elif isinstance(crt, Mapping):
        entradas = crt.get("results", crt.get("data", [])) or []
    else:
        entradas = []
    for entrada in entradas:
        if isinstance(entrada, Mapping):
            nombre = str(entrada.get("name_value", "") or entrada.get("common_name", ""))
        else:
            nombre = str(entrada)
        for parte in nombre.replace("\n", ",").split(","):
            parte = parte.strip().lower()
            if parte:
                nombres.add(parte)
    return nombres
