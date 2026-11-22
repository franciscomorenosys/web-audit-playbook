# Capturas de la consola de operaciones

Capturas de las ocho vistas de `console/`, tomadas con Chromium (Playwright,
headless) contra el servidor en **modo demo**:

```bash
python3 console/server.py --demo --port 8799 --no-open
```

- **Viewports:** 1600×1000 y 390×844, `device_scale_factor = 2` (las imágenes
  son el doble de resolución que el viewport).
- **Espera de render:** `networkidle` + `.vista__interna` con hijos +
  `document.fonts.ready` + 450 ms, para que las animaciones de entrada y el
  contador del dial hayan terminado.
- **Todas salvo el drawer** son capturas de página completa (`full_page`).
- **Los datos son sintéticos**: el banner «CONJUNJO SINTÉTICO» de la propia
  consola lo dice en cada captura. Ningún dato procede de un cliente real.

> **Estas capturas NO se versionan.** Son 8,8 MB de artefactos de desarrollo
> regenerables: el `.gitignore` de la raíz excluye
> `console/docs/screenshots/*` (sólo sobrevive este README). Las tres
> capturas que sí se versionan, porque las ilustran y no llegan a 1 MB en
> total, están en `console/docs/vista-previa/`.

## Cómo regenerarlas

Con el servidor levantado en `--demo` (ojo: `--demo`, nunca evidencia real):

```bash
python3 console/server.py --demo --port 8799 --no-open &
```

Y después, el script de Playwright que toma las diez capturas:

```python
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8799/"
SHOTS = "console/docs/screenshots/"

# nombre del fichero, ruta de la vista, ancho, alto, página completa, drawer
VISTAS = [
    ("01-superficie", "superficie", 1600, 1000, True, False),
    ("01-superficie-movil", "superficie", 390, 844, True, False),
    ("02-hallazgos", "hallazgos", 1600, 1000, True, False),
    ("02-hallazgos-drawer", "hallazgos", 1600, 1000, False, True),
    ("03-secretos", "secretos", 1600, 1000, True, False),
    ("04-api-surface", "api-surface", 1600, 1000, True, False),
    ("05-exposicion", "exposicion", 1600, 1000, True, False),
    ("06-evidencia", "evidencia", 1600, 1000, True, False),
    ("07-autorizacion", "autorizacion", 1600, 1000, True, False),
    ("08-acciones", "acciones", 1600, 1000, True, False),
]

with sync_playwright() as p:
    nav = p.chromium.launch()
    for nombre, ruta, ancho, alto, completa, drawer in VISTAS:
        ctx = nav.new_context(viewport={"width": ancho, "height": alto},
                              device_scale_factor=2)
        pg = ctx.new_page()
        pg.goto(f"{BASE}#/{ruta}", wait_until="networkidle")
        pg.wait_for_selector(".vista__interna > *")
        pg.evaluate("document.fonts.ready")
        pg.wait_for_timeout(450)
        if drawer:
            # el drawer se abre con un clic en la primera fila de la tabla
            pg.locator("table tbody tr").first.click()
            pg.wait_for_timeout(300)
        pg.screenshot(path=f"{SHOTS}{nombre}.png", full_page=completa)
        ctx.close()
    nav.close()
```

`02-hallazgos-drawer.png` es la única captura a viewport, no a página
completa: con el drawer abierto, la tabla es larga y la captura entera no
aportaría nada.

## Índice

| Fichero | Vista | Ruta | Qué muestra |
|---|---|---|---|
| `01-superficie.png` | 01 SUPERFICIE | `#/superficie` | Dial del Attack Exposure Score, fórmula y cobertura, hex-grid de subdominios y desglose de los 13 componentes de riesgo + la bonificación. |
| `01-superficie-movil.png` | 01 SUPERFICIE | `#/superficie` | La misma vista a 390×844. |
| `02-hallazgos.png` | 02 HALLAZGOS | `#/hallazgos` | Tabla densa de 55 hallazgos con los cinco filtros. |
| `02-hallazgos-drawer.png` | 02 HALLAZGOS | `#/hallazgos` | Drawer de detalle abierto sobre la primera fila (captura a viewport, no a página completa). |
| `03-secretos.png` | 03 SECRET REGISTER | `#/secretos` | Las doce columnas del registro de secretos, con valores enmascarados y su fingerprint. |
| `04-api-surface.png` | 04 API SURFACE | `#/api-surface` | Los 13 endpoints descubiertos con método, ruta, auth, PII y severidad. |
| `05-exposicion.png` | 05 EXPOSICIÓN | `#/exposicion` | Checklist de los 18 IoC, tabla «afirmación vs. evidencia» y la sección «LO QUE NO PUEDO VER». |
| `06-evidencia.png` | 06 EVIDENCIA | `#/evidencia` | Índice de los 34 artefactos con estado de redacción y los ficheros que la consola espera. |
| `07-autorizacion.png` | 07 AUTORIZACIÓN | `#/autorizacion` | El RoE: ventana con cuenta atrás, hosts permitidos, métodos efectivos y el estado de Fase 2. |
| `08-acciones.png` | 08 ACCIONES | `#/acciones` | El registro de acciones de Fase 2 como flujo de terminal. |

## Tamaño

| Fichero | Píxeles | Peso |
|---|---|---|
| `01-superficie.png` | 3200×4528 | 913 KB |
| `01-superficie-movil.png` | 780×7730 | 798 KB |
| `02-hallazgos.png` | 3200×5274 | 2060 KB |
| `02-hallazgos-drawer.png` | 3200×2000 | 608 KB |
| `03-secretos.png` | 3200×2000 | 664 KB |
| `04-api-surface.png` | 3200×2000 | 524 KB |
| `05-exposicion.png` | 3200×5960 | 1288 KB |
| `06-evidencia.png` | 3200×3836 | 1076 KB |
| `07-autorizacion.png` | 3200×2006 | 596 KB |
| `08-acciones.png` | 3200×3342 | 1036 KB |

Las mediciones que salen de estas capturas (contraste, desbordamiento, red,
fuentes y errores de consola) están en `console/docs/QA-VISUAL.md`.

> **Nota sobre `01-superficie.png`:** la columna izquierda (dial + fórmula) es
> **pegajosa** (`position: sticky`): al hacer scroll sigue a la vista, junto
> con la barra y la navegación. Una captura a página completa no puede
> mostrarlo —el scroll no existe en ella—, así que el vacío del tercio
> inferior izquierdo es esperable en el fichero: la columna se queda pegada
> arriba mientras se recorre la columna derecha.
