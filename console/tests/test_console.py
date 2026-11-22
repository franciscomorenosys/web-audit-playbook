"""Pruebas de la consola de operaciones (unittest de la stdlib, sin red).

Se comprueban tres cosas:

* el backend **tolera** un directorio de evidencia vacío o incompleto y
  devuelve estados vacíos honestos (nunca un 0 disfrazado de dato);
* la **regla de redacción** se cumple: lo que no tiene estado verificable se
  marca «SIN REDACTAR» y no se da por bueno;
* la interfaz **no referencia ningún recurso externo** y el servidor sirve
  la UI y la API sin salir a la red.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

RAIZ_CONSOLA = Path(__file__).resolve().parent.parent
RAIZ_PLAYBOOK = RAIZ_CONSOLA.parent
if str(RAIZ_CONSOLA) not in sys.path:
    sys.path.insert(0, str(RAIZ_CONSOLA))

from api import BANDS, EvidenceStore  # noqa: E402
from server import RUTAS_API, ConsolaHandler  # noqa: E402


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #


def escribir(directorio: Path, nombre: str, contenido: str) -> Path:
    """Escribe un fichero dentro de un directorio temporal."""
    ruta = directorio / nombre
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(contenido, encoding="utf-8")
    return ruta


class ConsolaDePrueba:
    """Levanta la consola en un hilo para las pruebas HTTP."""

    def __init__(self, directorio: Path) -> None:
        self.store = EvidenceStore(directorio, demo=False)
        self.servidor = ThreadingHTTPServer(("127.0.0.1", 0), ConsolaHandler)
        self.servidor.store = self.store  # type: ignore[attr-defined]
        self.servidor.daemon_threads = True
        self.hilo = threading.Thread(target=self.servidor.serve_forever, daemon=True)
        self.hilo.start()

    @property
    def base(self) -> str:
        """URL base del servidor de pruebas."""
        return f"http://127.0.0.1:{self.servidor.server_address[1]}"

    def pedir(self, ruta: str) -> tuple[int, str]:
        """Pide una ruta de texto y devuelve (código, cuerpo)."""
        with urllib.request.urlopen(f"{self.base}{ruta}", timeout=10) as respuesta:
            return respuesta.status, respuesta.read().decode("utf-8")

    def pedir_bytes(self, ruta: str) -> tuple[int, bytes]:
        """Pide una ruta binaria y devuelve (código, cuerpo)."""
        with urllib.request.urlopen(f"{self.base}{ruta}", timeout=10) as respuesta:
            return respuesta.status, respuesta.read()

    def cerrar(self) -> None:
        """Apaga el servidor."""
        self.servidor.shutdown()
        self.servidor.server_close()
        self.hilo.join(timeout=5)


# --------------------------------------------------------------------------- #
# Backend
# --------------------------------------------------------------------------- #


class TestBackendVacio(unittest.TestCase):
    """Un directorio de evidencia vacío no puede romper la consola."""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.store = EvidenceStore(self.dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_todas_las_vistas_responden_sin_crashear(self) -> None:
        for metodo in (
            "summary",
            "score",
            "findings",
            "secrets",
            "api_surface",
            "iocs",
            "evidence",
            "authorization",
            "actions",
        ):
            with self.subTest(vista=metodo):
                datos = getattr(self.store, metodo)()
                self.assertIsInstance(datos, dict)
                json.dumps(datos, ensure_ascii=False)  # debe ser serializable

    def test_sin_score_no_se_inventa_un_cero(self) -> None:
        """Sin evidencia, el score no puede ser un 0 de seguridad."""
        score = self.store.score()
        if not score["disponible"]:
            # No hay script del toolchain ni JSON: se dice qué ejecutar.
            self.assertIsNone(score["valor"])
            self.assertEqual(score["banda"], "No evaluable")
            self.assertIn("sin score", score["mensaje"].lower())
            return
        # Con el toolchain disponible: el script corre y no encuentra nada.
        self.assertFalse(score["evaluable"])
        self.assertIsNone(score["valor"])
        self.assertEqual(score["banda"], "No evaluable")
        self.assertIn("no significa", score["mensaje"].lower())

    def test_sin_evidencia_la_banda_es_no_evaluable(self) -> None:
        self.assertEqual(self.store.score()["banda"], "No evaluable")

    def test_sin_autorizacion_no_se_inventan_hosts(self) -> None:
        roe = self.store.authorization()
        self.assertFalse(roe["disponible"])
        self.assertEqual(roe["hosts"], [])
        self.assertTrue(roe["fase2_bloqueada"])

    def test_hallazgos_vacios_no_es_cero_falso(self) -> None:
        hallazgos = self.store.findings()
        self.assertEqual(hallazgos["items"], [])
        self.assertEqual(hallazgos["resumen"]["total"], 0)

    def test_secretos_nunca_incluyen_el_valor_completo(self) -> None:
        escribir(
            self.dir,
            "secrets.json",
            json.dumps(
                {
                    "tool": "secrets_scan",
                    "findings": [
                        {
                            "file": "app.js",
                            "line": 3,
                            "column": 1,
                            "type": "aws_access_key_id",
                            "severity": "critico",
                            "masked": "AKIA******LE",
                            "sha256": "0123456789abcdef",
                            "context": 'var AWS = "AKIA...";',
                            "description": "",
                        }
                    ],
                }
            ),
        )
        store = EvidenceStore(self.dir)
        items = store.secrets()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["masked"], "AKIA******LE")
        self.assertEqual(len(items[0]["fingerprint"]), 12)
        # La tríada honesta: sin verificación, «no probado».
        self.assertEqual(items[0]["vive"], "no probado")
        # El valor completo no aparece en ningún sitio de la respuesta.
        respuesta = json.dumps(store.secrets(), ensure_ascii=False)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", respuesta)

    def test_iocs_los_18_del_modulo(self) -> None:
        iocs = self.store.iocs()["items"]
        self.assertEqual(len(iocs), 18)
        self.assertEqual(iocs[0]["numero"], 1)
        self.assertEqual(iocs[-1]["numero"], 18)

    def test_seccion_de_lo_que_no_se_puede_ver(self) -> None:
        iocs = self.store.iocs()
        self.assertGreaterEqual(len(iocs["no_verificable"]), 5)
        self.assertTrue(iocs["frase_cierre"])


class TestReglaDeRedaccion(unittest.TestCase):
    """Lo que no tiene estado de redacción verificable no se da por bueno."""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_artefacto_sin_estado_queda_sin_verificar(self) -> None:
        escribir(self.dir, "notas.txt", "contenido cualquiera")
        store = EvidenceStore(self.dir)
        artefactos = store.evidence()["artefactos"]
        self.assertEqual(len(artefactos), 1)
        self.assertEqual(artefactos[0]["redaccion"], "sin_verificar")
        self.assertTrue(artefactos[0]["sin_redactar"])

    def test_copia_redactada_por_pii_redact_cuenta(self) -> None:
        origen = escribir(self.dir, "crudo/paciente.json", '{"nombre": "Ana"}')
        destino = escribir(self.dir, "sanitizada/paciente.json", '{"nombre": "[REDACTADO]"}')
        escribir(
            self.dir,
            "redaccion.json",
            json.dumps(
                {
                    "tool": "pii_redact",
                    "files": [
                        {"source": str(origen), "output": str(destino), "counts": {}, "matches": {}}
                    ],
                    "total_redactions": 1,
                }
            ),
        )
        store = EvidenceStore(self.dir)
        estados = {a["ruta"]: a["redaccion"] for a in store.evidence()["artefactos"]}
        self.assertEqual(estados["sanitizada/paciente.json"], "redactado")
        self.assertEqual(estados["crudo/paciente.json"], "sin_verificar")

    def test_manifiesto_verifica_el_sha256(self) -> None:
        import hashlib

        ruta = escribir(self.dir, "salida.json", '{"a": 1}')
        escribir(
            self.dir,
            "manifiesto-redaccion.json",
            json.dumps(
                {
                    "artefactos": [
                        {
                            "ruta": "salida.json",
                            "sha256": hashlib.sha256(ruta.read_bytes()).hexdigest(),
                            "motivo": "salida del toolchain",
                        }
                    ]
                }
            ),
        )
        store = EvidenceStore(self.dir)
        estados = {a["ruta"]: a["redaccion"] for a in store.evidence()["artefactos"]}
        self.assertEqual(estados["salida.json"], "redactado")

    def test_manifiesto_con_sha256_desfasado_no_sirve(self) -> None:
        escribir(self.dir, "salida.json", '{"a": 1}')
        escribir(
            self.dir,
            "manifiesto-redaccion.json",
            json.dumps(
                {"artefactos": [{"ruta": "salida.json", "sha256": "0" * 64, "motivo": "x"}]}
            ),
        )
        store = EvidenceStore(self.dir)
        estados = {a["ruta"]: a["redaccion"] for a in store.evidence()["artefactos"]}
        self.assertEqual(estados["salida.json"], "sin_verificar")


class TestBandas(unittest.TestCase):
    """Las bandas de la consola son las del script, no una invención."""

    def test_cinco_bandas_con_sus_rangos(self) -> None:
        self.assertEqual(
            [(bajo, alto, etiqueta) for bajo, alto, etiqueta in BANDS],
            [
                (0.0, 19.9, "Bajo"),
                (20.0, 39.9, "Moderado"),
                (40.0, 59.9, "Alto"),
                (60.0, 79.9, "Crítico"),
                (80.0, 100.0, "Severo"),
            ],
        )

    def test_las_bandas_coinciden_con_el_script_del_toolchain(self) -> None:
        script = RAIZ_PLAYBOOK / "01-tooling" / "scripts" / "attack_surface_report.py"
        if not script.is_file():
            self.skipTest("el toolchain no está disponible en este entorno")
        texto = script.read_text(encoding="utf-8")
        for _, _, etiqueta in BANDS:
            self.assertIn(f'"{etiqueta}"', texto)


class TestNormalizacion(unittest.TestCase):
    """La normalización de la evidencia produce un esquema estable."""

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.store = EvidenceStore(self.dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_tsv_de_sonda_se_normaliza(self) -> None:
        escribir(
            self.dir,
            "probe_exposure.tsv",
            "host\tpath\tcode\tcontent_type\tlength\tcontent_length_header\tsha256\t"
            "soft_404\ttruncated\tverdict\tseverity\n"
            "ejemplo.mx\t/.env\t200\ttext/plain\t120\t120\tabcdef123456\tno\tno\t"
            "expuesto\tcritico\n",
        )
        store = EvidenceStore(self.dir)
        hallazgos = store.findings()["items"]
        self.assertEqual(len(hallazgos), 1)
        self.assertEqual(hallazgos[0]["severidad"], "critico")
        self.assertEqual(hallazgos[0]["categoria"], "ruta")
        self.assertEqual(hallazgos[0]["estado"], "hallazgo")
        self.assertTrue(hallazgos[0]["evidencia"][0]["fichero"])
        self.assertRegex(hallazgos[0]["evidencia"][0]["hash"], r"^[0-9a-f]{12}$")

    def test_hallazgos_manuales_respetan_los_estados_del_playbook(self) -> None:
        escribir(
            self.dir,
            "hallazgos.json",
            json.dumps(
                {
                    "items": [
                        {
                            "id": "MAN-001",
                            "titulo": "Prueba",
                            "severidad": "medio",
                            "estado": "refutado",
                            "descripcion": "x",
                            "evidencia": ["probe_exposure.tsv"],
                        }
                    ]
                }
            ),
        )
        store = EvidenceStore(self.dir)
        items = store.findings()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["estado"], "refutado")

    def test_registro_de_acciones_se_lee_como_csv(self) -> None:
        escribir(
            self.dir,
            "registro-de-acciones-fase-2.csv",
            "id,fecha_hora,host,endpoint,tecnica,datos_tocados,resultado\n"
            "F2-01,2026-01-01T00:00:00Z,ejemplo.mx,/api/v1/x,idor,ninguno,CONFIRMADO\n",
        )
        store = EvidenceStore(self.dir)
        items = store.actions()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], "F2-01")
        self.assertEqual(items[0]["datos_tocados"], "ninguno")

    def test_autorizacion_calcula_la_ventana(self) -> None:
        escribir(
            self.dir,
            "authorization.json",
            json.dumps(
                {
                    "authorization_ref": "ROE-TEST",
                    "client": "Cliente de prueba",
                    "signed_by": "QA",
                    "signed_at": "2020-01-01T00:00:00Z",
                    "valid_from": "2020-01-01T00:00:00Z",
                    "valid_to": "2099-01-01T00:00:00Z",
                    "hosts": ["ejemplo.mx"],
                    "allowed_methods": ["GET", "POST"],
                }
            ),
        )
        store = EvidenceStore(self.dir)
        roe = store.authorization()
        self.assertTrue(roe["en_ventana"])
        self.assertFalse(roe["fuera_de_ventana"])
        self.assertTrue(roe["fase2_bloqueada"])
        # Los métodos con cuerpo se descartan aunque el fichero los liste.
        self.assertEqual(roe["metodos_efectivos"], ["GET", "HEAD"])


# --------------------------------------------------------------------------- #
# Interfaz: cero recursos externos
# --------------------------------------------------------------------------- #


class TestSinRecursosExternos(unittest.TestCase):
    """La interfaz no puede referenciar nada que esté fuera de la consola."""

    RUTA_URL = re.compile(r"https?://", re.IGNORECASE)

    def _ficheros(self) -> list[Path]:
        return [
            RAIZ_CONSOLA / "index.html",
            *sorted((RAIZ_CONSOLA / "assets").rglob("*.css")),
            *sorted((RAIZ_CONSOLA / "assets").rglob("*.js")),
        ]

    def test_ninguna_url_externa_en_html_css_ni_js(self) -> None:
        for ruta in self._ficheros():
            with self.subTest(fichero=ruta.name):
                texto = ruta.read_text(encoding="utf-8")
                for numero, linea in enumerate(texto.splitlines(), start=1):
                    self.assertIsNone(
                        self.RUTA_URL.search(linea),
                        f"{ruta.name}:{numero} referencia un recurso externo: {linea.strip()}",
                    )

    def test_las_fuentes_son_locales(self) -> None:
        css = (RAIZ_CONSOLA / "assets" / "css" / "console.css").read_text(encoding="utf-8")
        for url in re.findall(r"url\(\s*[\"']?([^\"')]+)", css):
            with self.subTest(url=url):
                self.assertTrue(
                    url.startswith("/assets/") or url.startswith("data:"),
                    f"la fuente no es local: {url}",
                )

    def test_no_hay_import_de_google_apis(self) -> None:
        for ruta in self._ficheros():
            texto = ruta.read_text(encoding="utf-8").lower()
            for prohibido in ("googleapis", "gstatic", "cdn.", "unpkg", "jsdelivr", "bootstrap"):
                with self.subTest(fichero=ruta.name, token=prohibido):
                    self.assertNotIn(prohibido, texto)

    def test_el_js_solo_pide_rutas_relativas_de_la_api(self) -> None:
        data = (RAIZ_CONSOLA / "assets" / "js" / "data.js").read_text(encoding="utf-8")
        self.assertIn("/api/", data)
        # No debe haber ninguna URL absoluta en el cliente.
        for ruta in sorted((RAIZ_CONSOLA / "assets" / "js").rglob("*.js")):
            texto = ruta.read_text(encoding="utf-8")
            for numero, linea in enumerate(texto.splitlines(), start=1):
                if "http://" in linea or "https://" in linea:
                    self.fail(f"{ruta.name}:{numero} contiene una URL absoluta: {linea.strip()}")

    def test_las_fuentes_woff2_existen(self) -> None:
        fuentes = sorted((RAIZ_CONSOLA / "assets" / "fonts").glob("*.woff2"))
        self.assertGreaterEqual(len(fuentes), 4)
        self.assertTrue((RAIZ_CONSOLA / "assets" / "fonts" / "OFL.txt").is_file())


# --------------------------------------------------------------------------- #
# Servidor
# --------------------------------------------------------------------------- #


class TestServidor(unittest.TestCase):
    """El servidor sirve la UI y la API sin pedir nada a internet."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = TemporaryDirectory()
        directorio = Path(cls._tmp.name)
        escribir(directorio, "probe_exposure.tsv", "host\tpath\tverdict\tseverity\n")
        cls.consola = ConsolaDePrueba(directorio)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.consola.cerrar()
        cls._tmp.cleanup()

    def test_raiz_devuelve_html(self) -> None:
        codigo, cuerpo = self.consola.pedir("/")
        self.assertEqual(codigo, 200)
        self.assertIn("Consola de Operaciones de Seguridad", cuerpo)

    def test_todas_las_rutas_de_api_responden_json(self) -> None:
        for ruta in RUTAS_API:
            with self.subTest(ruta=ruta):
                codigo, cuerpo = self.consola.pedir(ruta)
                self.assertEqual(codigo, 200)
                json.loads(cuerpo)

    def test_los_estilos_y_el_js_se_sirven(self) -> None:
        for ruta, tipo in (
            ("/assets/css/console.css", "text/css"),
            ("/assets/js/app.js", "text/javascript"),
            ("/assets/fonts/IBMPlexMono-Regular-latin.woff2", "font/woff2"),
        ):
            with self.subTest(ruta=ruta):
                codigo, _ = self.consola.pedir_bytes(ruta)
                self.assertEqual(codigo, 200)

    def test_no_se_sirven_ficheros_fuera_de_la_consola(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as contexto:
            self.consola.pedir("/../../etc/passwd")
        self.assertIn(contexto.exception.code, (403, 404))

    def test_la_cabecera_csp_prohibe_lo_externo(self) -> None:
        peticion = urllib.request.Request(f"{self.consola.base}/")
        with urllib.request.urlopen(peticion, timeout=10) as respuesta:
            csp = respuesta.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)


class TestDemo(unittest.TestCase):
    """El conjunto de demostración existe y es sintético."""

    def test_el_demo_carga_y_esta_marcado_como_sintetico(self) -> None:
        demo = RAIZ_CONSOLA / "demo" / "evidencia"
        if not demo.is_dir():
            self.skipTest("el conjunto demo no está generado en este entorno")
        store = EvidenceStore(demo, demo=True)
        resumen = store.summary()
        self.assertTrue(resumen["sintetico"])
        self.assertEqual(resumen["modo"], "demo")
        self.assertGreater(resumen["recuento"]["artefactos"], 0)
        # El demo tiene que tener score real, calculado por el script.
        self.assertTrue(resumen["score"]["disponible"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
