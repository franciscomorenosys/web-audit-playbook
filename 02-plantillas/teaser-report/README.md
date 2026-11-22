# Plantilla — Teaser de auditoría de seguridad (PDF)

Documento de venta de 13 páginas generado desde HTML + CSS y renderizado a PDF
con Chromium headless. Pensado para enviarse a un cliente no técnico (p. ej. una
clínica) **sin revelar el detalle técnico**: solo categorías, conteos,
severidad, exposición legal y la oferta.

## Archivos

| Archivo | Qué es |
|---|---|
| `teaser-dental-easy.html` | Fuente. HTML semántico + CSS embebido, sin JS. |
| `Evaluacion-Seguridad-Clinica-Dental-Easy.pdf` | Entregable. |
| `make-charts.py` | Genera los tres gráficos en `assets/` (matplotlib, 300 dpi). |
| `build.py` | Renderiza el HTML a PDF y sanea los metadatos. |
| `verify.py` | Verificación previa a entregar (ver abajo). |
| `assets/` | Gráficos PNG + subconjuntos de fuente woff2 + `fonts.css`. |

## Requisitos

> ### ⚠️ El `.venv/` NO está en el repositorio
>
> El entorno local de esta plantilla pesa **~196 MB** (2 494 archivos). Es
> **totalmente regenerable** y está excluido por el `.gitignore` del raíz del
> playbook (`.venv/`). Clonar el playbook **no** lo trae. Recréalo así:
>
> ```bash
> cd 02-plantillas/teaser-report
> python3 -m venv .venv
> .venv/bin/pip install -r requirements.txt   # o: pip install playwright pypdf \
>                                            #    pypdfium2 pillow fonttools brotli matplotlib
> .venv/bin/playwright install chromium       # descarga el Chromium de headless
> ```
>
> El PDF ya generado (`Evaluacion-Seguridad-Clinica-Dental-Easy.pdf`) **sí** está
> versionado: se entrega aunque no tengas el entorno. El `.venv` solo hace falta
> para *regenerar* o *editar* el documento.

Con el entorno en su sitio:

```bash
.venv/bin/python make-charts.py   # regenera los gráficos
.venv/bin/python build.py         # regenera el PDF
.venv/bin/python verify.py        # valida antes de entregar
```

Paquetes: `playwright` (con Chromium), `pypdf`, `pypdfium2`, `pillow`,
`fonttools`, `brotli`. Tipografías: Inter e IBM Plex Serif (SIL OFL 1.1),
subconjuntos `latin` y `latin-ext` descargados de Google Fonts y alojados
localmente en `assets/fonts/`.

> matplotlib no puede cargar la variable woff2 de Inter, así que las
> **etiquetas de los gráficos usan Helvetica Neue**. A tamaño de etiqueta es
> visualmente equivalente; el cuerpo del documento sí usa Inter.

## Reglas de contenido (no negociables en un teaser)

El teaser es material de venta. **Nunca** debe incluir:

- identificadores de vulnerabilidad ni puntajes de severidad estándar
- números de versión de software ni de protocolos
- rutas de archivos, URLs, endpoints o direcciones de servicios
- comandos de reproducción ni salidas de herramientas
- usuarios, correos, teléfonos ni identificadores del cliente
- nombres de herramientas de terceros usadas en la revisión
- la lista completa de hallazgos individuales

Sí debe incluir: las cifras legales exactas (son ley pública, no una
vulnerabilidad), el costo del negocio, el resumen por categoría, la
distribución por severidad, **lo que ya está bien**, la oferta y la
convocatoria a reunión.

`verify.py` extrae el texto del PDF, lo pasa por la lista de cadenas
prohibidas y además revisa los bytes del archivo y los metadatos. Correrlo
antes de entregar.

## Notas de diseño

- A4, márgenes generosos, 10.4 pt de cuerpo.
- Titulares en IBM Plex Serif, texto en Inter.
- Una sola rampa de acento para riesgo (ámbar → rojo); gris pizarra para todo
  lo demás. Sin degradados decorativos, sin sombras sobre texto.
- Gráficos generados con matplotlib, nunca emojis ni recuadros de «chart here».
- La marca de agua `CONFIDENCIAL` y el pie con «Página N de M» se aplican en
  cada página (elemento `position: fixed` + plantilla de pie de Chromium).