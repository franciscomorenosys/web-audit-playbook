# QA visual de la consola de operaciones

Revisión visual y de accesibilidad de `console/` con **Chromium real** (Playwright,
headless), con captura de pantalla de las ocho vistas, medición de contraste
WCAG sobre el color de fondo **real computado**, detección de desbordamiento
horizontal, control de red y de errores de consola.

- **Fecha:** 2026-11-22
- **Servidor:** `python3 console/server.py --demo --port 8799` (modo demo, datos sintéticos)
- **Navegador:** Chromium 1248 (Playwright), headless
- **Viewports:** 1600×1000 y 390×844, `device_scale_factor = 2`
- **Ficheros modificados por esta revisión:** sólo `console/assets/css/console.css` y
  `console/assets/js/components/*.js`. **No** se ha tocado `api.py`, `server.py`,
  `index.html` ni ningún documento de método.

> Las capturas son del **modo demo** (`--demo`): el conjunto sintético que
> genera `console/demo/generar_demo.py`. La propia consola lo etiqueta con el
> banner permanente «CONJUNTO SINTÉTICO». Ningún dato procede de un cliente real.

---

## 1. Método

### 1.1 Recorrido

1. Se levantó el servidor en modo demo y se comprobó que `/api/summary` devuelve
   `modo: demo`, 55 hallazgos, 8 secretos, 13 endpoints, 34 artefactos y 6 acciones.
2. Para **cada** una de las ocho rutas se abrió una pestaña nueva de Playwright con
   sus propios escuchas (`page.on("request")`, `page.on("console")`,
   `page.on("pageerror")`, `page.on("requestfailed")`), de modo que las
   measurements de red y de consola quedan aisladas por vista.
3. Se esperó a `networkidle` + a que `.vista__interna` tuviera hijos + a
   `document.fonts.ready` + 450 ms de margen, para que las animaciones de
   entrada (`revelar`) y el contador del dial hubieran terminado.
4. Captura a página completa (`full_page=True`), salvo el drawer, que se capturó
   a viewport para que la capa modal se vea como la ve el auditor.
5. Se repitió el recorrido a 390×844 para el control de desbordamiento y el
   contraste en móvil.

### 1.2 Cómo se midió el contraste

El contraste **no** se calculó sobre el token de la variable CSS, sino sobre lo
que el navegador dice que se está pintando:

- Para cada nodo de texto con contenido se toma el `color` computado — o el
  `fill` computado si el nodo es un elemento SVG, porque el texto del dial y
  del hex-grid se pinta con `fill`, no con `color` — y se descartan los nodos
  con `display:none`, `visibility:hidden` o con caja de tamaño cero.
- El **fondo efectivo** se compone subiendo por el árbol: se recorren todos los
  ancestros desde `<html>` y se alfa-compone cada `background-color` no
  transparente sobre el acumulado. Así, un chip rojo se mide sobre
  `rgba(229,72,77,.12)` compuesto con `--surface`, no sobre el color del token.
- La ratio se calcula con la fórmula WCAG 2.x:
  `ratio = (L_claro + 0.05) / (L_oscuro + 0.05)`,
  con `L = 0.2126·R + 0.7152·G + 0.0722·B` sobre canales linealizados con
  `c ≤ 0.03928 ? c/12.92 : ((c+0.055)/1.055)^2.4`.
- El umbral es **4.5:1** para texto normal y **3.0:1** para texto grande
  (≥ 24 px, o ≥ 18.66 px con peso ≥ 700).

### 1.3 Cómo se midió el desbordamiento

`document.documentElement.scrollWidth > window.innerWidth + 2` en las ocho
vistas, a 1600 px y a 390 px. Además se recorrió `body *` buscando elementos
cuyo borde derecho rebase `innerWidth + 2`, excluyendo a propósito los que
viven dentro de un contenedor con scroll horizontal propio (`.nav`,
`.tabla-envoltura`), porque ahí el rebase es intencionado.

### 1.4 Fuentes y red

- Fuentes: `document.fonts.check('12px "IBM Plex Mono"')`,
  `document.fonts.check('12px "IBM Plex Sans Condensed"')` y las variantes de
  peso, más el recuento de `document.fonts.size` y de las familias cargadas.
- Red: se interceptan **todas** las peticiones (`page.on("request")`) y se
  comprueba que su URL empieza por `http://127.0.0.1:8799/`.

---

## 2. Hallazgos

### 2.1 Lo que ya estaba bien

| Comprobación | Resultado |
|---|---|
| Peticiones externas | **0** en las 8 vistas (39 URLs distintas, todas `http://127.0.0.1:8799/…`) |
| Peticiones fallidas | 0 |
| Errores de consola (`console.error`/`warning`) | 0 |
| Excepciones de página (`pageerror`) | 0 |
| Fuentes woff2 | `IBM Plex Mono` y `IBM Plex Sans Condensed` cargadas en las 8 vistas (14 faces) |
| Desbordamiento horizontal de página | 0 vistas con `scrollWidth > innerWidth` (ni a 1600 ni a 390) |
| Dial SVG | `viewBox="0 0 400 292"`, 6 `<path>` con trazo, 22 `<line>`, 1 `<polygon>`, 8 `<text>`, aguja presente con 4 hijos y `transform` resuelto |
| Hex-grid | 18 celdas, 12 con `<title>` de evidencia, `viewBox` válido |
| Backend | `python3 -m unittest discover console/tests` → 29 tests OK |

### 2.2 Contraste — la tabla de las ocho vistas

«Principal» es el texto de contenido de cada vista (no la nota de cabecera).
«Peor» es el par texto/fondo con menor ratio de toda la vista.

| Vista | Selector del texto principal | Ratio antes | Ratio después | Peor antes | Peor después | Nodos por debajo de AA (antes → después) |
|---|---|---|---|---|---|---|
| 01 SUPERFICIE | `.componente__nombre` | 13.68 | 13.68 | **2.20** (`.metrica__etiqueta`) | 4.77 | 80 → **0** |
| 02 HALLAZGOS | `.celda-truncar.tenue` | 4.02 | 6.13 | **2.20** | 4.77 | 142 → **0** |
| 03 SECRETOS | `.celda-truncar` | 7.54 | 7.54 | **2.20** | 4.77 | 40 → **0** |
| 04 API SURFACE | `.celda-truncar.mono` | 7.54 | 7.54 | **2.20** | 4.77 | 53 → **0** |
| 05 EXPOSICIÓN | `.check__titulo` | 13.68 | 13.68 | **2.20** | 4.77 | 108 → **0** |
| 06 EVIDENCIA | `.celda-truncar.tenue` | 4.02 | 6.13 | **2.20** | 4.77 | 65 → **0** |
| 07 AUTORIZACIÓN | `.componente__nombre` | 13.68 | 13.68 | **2.20** | 4.77 | 30 → **0** |
| 08 ACCIONES | `.flujo__titulo` | 13.68 | 13.68 | **2.20** | 4.77 | 130 → **0** |

**Sí había vistas por debajo de 4.5:1 — las ocho.** Los pares que fallaban, con
sus valores reales:

| Texto | Token | Fondo real | Ratio | Dónde se usa |
|---|---|---|---|---|
| `#474f59` (gris) | `--texto-tenuisimo` | `#12151a` | **2.20** | `.metrica__etiqueta`, `.panel__nota`, `.componente__detalle`, `.dato__clave`, `.flujo__linea b`, `.afirmaciones__fuente`, `.afirmaciones__cabecera`, `.dial__marca-texto`, `.dial__centro-unidad`, `.check__num`, `.nav__idx`, `.pie__meta` |
| `#474f59` | `--texto-tenuisimo` | `#0e1013` | **2.30** | `.componente__detalle`, `.dial__pie`, `.flujo__linea b`, `.afirmaciones__fuente` |
| `#6b7480` | `--texto-tenue` | `#12151a` | **3.86** | `.componente__fuente`, `.pie`, `.flujo__linea` |
| `#6b7480` | `--texto-tenue` | `#0e1013` | **4.02** | `.componente__fuente`, `.componente__detalle` (`.tenue`) |
| `#e5484d` | `--rojo` | `rgba(229,72,77,.12)` sobre `#0e1013` | **4.38** | `.etiqueta--critico`, `.etiqueta--bloqueo`, `.aviso-critico strong`, `.fase2__texto` |
| `#a83238` | `--banda-severo` | `#0e1013` | **2.88** | `.dial__centro-banda` (el nombre de la banda dentro del dial) |

Después de las correcciones, los cuatro pares que quedaban en el suelo son:

| Texto | Fondo real | Ratio | Nodos |
|---|---|---|---|
| `#7a838f` (`--texto-tenuisimo`) | `#12151a` | **4.77** | 6–87 por vista |
| `#7a838f` | `#0e1013` | **4.96** | 1–60 por vista |
| `#8a939f` (`--texto-tenue`) | `#12151a` | **5.88** | 7–23 por vista |
| `#8a939f` | `#0e1013` | **6.13** | 2–55 por vista |

Es decir: **ninguna vista baja de 4.5:1** después de los cambios, y el mínimo
global de la consola pasa de 2.20:1 a **4.77:1**. En móvil (390×844) el
resultado es el mismo: de 28–135 nodos por debajo de AA por vista a **0**.

### 2.3 Desbordamiento horizontal

| Vista | `scrollWidth` 1600 | desborda | `scrollWidth` 390 | desborda |
|---|---|---|---|---|
| 01 SUPERFICIE | 1600 | No | 390 | No |
| 02 HALLAZGOS | 1600 | No | 390 | No |
| 03 SECRETOS | 1600 | No | 390 | No |
| 04 API SURFACE | 1600 | No | 390 | No |
| 05 EXPOSICIÓN | 1600 | No | 390 | No |
| 06 EVIDENCIA | 1600 | No | 390 | No |
| 07 AUTORIZACIÓN | 1600 | No | 390 | No |
| 08 ACCIONES | 1600 | No | 390 | No |

**El documento nunca desborda**, pero eso escondía dos recortes reales:

- **Secret Register a 1600 px:** la tabla mide 1687 px dentro de un panel de
  1566 px. Las columnas **OWNER** (x 1550–1616) y **EVIDENCIA** (x 1616–1704)
  quedaban **fuera de pantalla**, con un scrollbar de overlay que en macOS no
  se ve. El auditor veía una tabla truncada sin ninguna señal de que le
  faltaban columnas.
- **Checklist de IoC a 390 px:** `.check` era
  `grid-template-columns: 26px minmax(0,1fr) 128px`. El chip
  «PENDIENTE DE CONFIRMACIÓN» mide 189 px, así que se salía de su celda
  (`chipRight 430 > ckRight 381`) y lo cortaba `.panel { overflow: hidden }`,
  con 40 px por fuera del viewport. El chip se leía incompleto.

### 2.4 Otros defectos de ejecución medidos

| Defecto | Medición |
|---|---|
| Placeholder del buscador cortado a media palabra | input de 167 px con el rótulo «Buscar en título, descripción, evidencia…» → se veía «Buscar en título, (« |
| Rótulos del hex-grid fuera de su celda | `clinica-demo` (87 px de texto) en una celda de 67 px: se derramaba sobre las celdas vecinas |
| Descripción de hallazgo desperdiciando la celda | `.celda-truncar` con tope fijo de 340 px dentro de una columna de 627 px: 287 px de celda vacía a la vez que se perdía texto |
| Chip de estado de IoC descolgado de su texto | el estado estaba en una columna fija a la derecha: ~950 px de hueco entre el indicador y su chip, en las 18 filas |
| Flecha del `select` sobre la última letra | relleno derecho de 16 px con la flecha dibujada en `calc(100% - 12px)` |
| Nombre de la banda dentro del dial ilegible | «Severo» en `--banda-severo` `#a83238` sobre `#0e1013` = 2.88:1 |
| Hueco muerto en la rejilla de SUPERFICIE | la columna izquierda (`dial` + `fórmula`) termina ~900 px antes que la derecha (`hex-grid` + 18 componentes) |
| Columna OWNER del Secret Register partida en dos líneas | «sin» / «asignar» |

---

## 3. Crítica de diseño

### 3.1 ¿Instrumento profesional o plantilla de IA?

**Instrumento, pero con una firma que lo delata: la densidad se ha obtenido
apagando el texto, no ajustando la maquetación.**

Lo que lo hace leer como instrumento:

- El dial no es un adorno: cinco bandas con los cortes reales del script, 22
  marcas, aguja con contrapeso, `tabular-nums` y el valor repetido como texto.
  Un instrumento real enseña su escala.
- La rejilla hexadecimal obedece a una regla semántica, no estética: cada
  celda iluminada es un nombre que viene de la evidencia, y el resto es
  superficie sin exposición conocida.
- El registro de acciones se lee como una terminal: hora, técnica, chips de
  resultado, y las líneas que tocaron datos resaltadas con borde ámbar.
- La honestidad epistémica está en la interfaz y no en un pie de página: la
  sección «LO QUE NO PUEDO VER» es un bloque de primer nivel, y el estado
  vacío dice por qué está vacío en vez de mostrar un 0.

Lo que lo hace flaquear:

- **La jerarquía está bien planteada pero mal repartida.** El score se dice
  tres veces (barra «SCORE 94.0 · SEVERO», mosaico «94.0», dial «94.0») y la
  vista se abre con un bloque de avisos de tres líneas que empuja el
  contenido real por debajo del pliegue. Redundancia donde debería haber
  refuerzo.
- **La densidad es tipográfica, no espacial.** 55 hallazgos × 7 columnas en
  1600 px está bien resuelto; el problema es que la legibilidad se compró
  bajando el color: `.metrica__etiqueta` a 10 px en `#474f59` sobre `#12151a`
  son 2.20:1. Ese rótulo es la leyenda de la cifra que tiene encima; ilegible,
  la cifra pierde su unidad. En una consola, el micro-rótulo **es** la
  navegación.
- **El acento ámbar está sobreempleado y ha perdido su significado.** El
  ámbar aparece en: la nav activa, el valor del score, la aguja, las barras de
  componentes, la cuenta atrás, el borde de `.u-pre`, y —esto es lo grave—
  **los chips de estado por defecto**. `estado("hallazgo")` devuelve la clase
  `medio` y `vivo("no probado")` devuelve `alto`: así, los 55 chips
  «HALLAZGO» de la tabla de hallazgos y los 8 chips «NUNCA PROBADO» del
  registro de secretos son ámbar. Cuando el color de «mira aquí» está en
  cada fila, no marca nada: marca «soy un chip».
- **La monoespaciada está bien elegida y mal limitada.** IBM Plex Mono con
  `letter-spacing` amplio y versalitas da el tono de sala de operaciones, pero
  el suelo de 10 px (`--fs-micro`) se aplicó a los rótulos que el auditor usa
  para orientarse (`--texto-tenuisimo`).
- **Los estados vacíos están bien resueltos** — `.vacio` con borde discontinuo,
  título en versalitas y motivo explícito; nunca un 0 disfrazado de dato—,
  pero **no se pueden juzgar en esta revisión**: el conjunto demo llena las
  ocho vistas, así que el estado vacío no sale ni una vez en las capturas.

### 3.2 ¿Funciona el dial como elemento memorable?

**Sí, y es lo mejor de la consola.** Es el único elemento que podría sostener
una portada: tiene escala graduada, bandas con los cortes reales del script, y
un valor numérico grande que se lee de un vistazo. Como memoria visual
funciona porque no se parece a nada de la web de consumo.

Pero tiene dos problemas de ejecución:

1. **La aguja y la lectura central compiten por el mismo espacio.** La punta
   de la aguja cae en x 293–312 y la caja del valor «94.0» en x 164–268: 25 px
   de aire; el rótulo de graduación «100» cae en x 275–290, a 7 px de la cifra.
   Con cuatro dígitos («100.0») el rótulo se solapa con el número. La causa es
   de colocación: el valor está en `y = CY + 70`, en la misma banda vertical
   por la que barre la aguja, y el centro del dial (250 × 180 px) está vacío.
   El valor debería ir en el centro, no en el fondo del barrido.
2. **El nombre de la banda («Severo») salía a 2.88:1**, en el color profundo
   de la banda, que es correcto para el arco y ilegible como texto. Corregido
   con un tono aclarado del mismo color.

### 3.3 ¿Y el hex-grid?

**La idea es buena; la ejecución no.** La teselación es correcta (hexágonos de
tapa plana, escalonados, sin huecos ni solapes) y la regla «cada celda
iluminada es un nombre real» es la que convierte un adorno en información. Pero:

- **Los rótulos se salían de sus celdas.** Con radio 20 la celda mide 40 px y
  «clinica-demo» mide 58 px: el texto se derramaba sobre los hexágonos
  vecinos y el auditor ya no podía saber a qué celda pertenecía cada nombre.
  Es el fallo que más daña la confianza en el instrumento, porque el
  hex-grid miente sobre su propia topología.
- **El barrido es un artefacto, no un efecto.** La banda ámbar horizontal que
  cruza las celdas se lee como un fallo de render, no como un radar.
- **El panel es de ~1000 px y el grid estaba capado a 560 px**, centrado: unos
  440 px de vacío a cada lado del instrumento.
- **La mitad de las celdas están vacías** (18 celdas para 12 nombres): el
  campo se lee mayoritariamente como «nada».

### 3.4 Problemas de ejecución detectados (resumen)

1. Secret Register pierde las columnas OWNER y EVIDENCIA a 1600 px sin aviso.
2. El placeholder del buscador se corta a media palabra.
3. Micro-texto por debajo de AA en las ocho vistas (2.20:1 en el peor caso).
4. El chip de estado del checklist se recorta a 390 px y está a ~950 px de su texto.
5. `.celda-truncar` recorta a 340 px en columnas de 627 px.
6. Los rótulos del hex-grid se salen de sus hexágonos.
7. La aguja y el rótulo «100» quedan a 7–25 px de la cifra del dial.
8. «Severo» (nombre de la banda) a 2.88:1.
9. ~900 px de hueco en la columna izquierda de SUPERFICIE.
10. El ámbar marca el estado por defecto (55 chips en una columna), no la excepción.

---

## 4. Correcciones aplicadas

Cinco correcciones, todas de presentación (CSS y JS de `components/`).
**No** se ha tocado `api.py`, `server.py`, `index.html` ni la estructura de las
vistas.

### C1 — El micro-texto está por debajo de WCAG AA

- **Fichero:** `console/assets/css/console.css`
- **Selectores / clases:** `:root` (`--texto-tenuisimo`, `--texto-tenue`,
  `--rojo-claro`), `.etiqueta--critico`, `.etiqueta--bloqueo`,
  `.aviso-critico strong`, `.fase2__texto`, `.metrica--rojo .metrica__valor`,
  `.cuenta__valor[data-critico="true"]`, `.boton--peligro:hover`
- **Fichero:** `console/assets/js/components/dial.js`
- **Clase / símbolo:** `COLOR_BANDA_TEXTO` (nuevo mapa de color legible del
  nombre de banda, usado por `.dial__centro-banda`)

Qué hace: `--texto-tenuisimo` pasa de `#474f59` (2.20:1) a `#7a838f` (4.77:1) y
`--texto-tenue` de `#6b7480` (3.86:1) a `#8a939f` (5.88:1); se añade
`--rojo-claro: #ff7a7e` para el rojo sobre tinte rojo (4.38 → 6.81:1) y un mapa
de color de banda aclarado para el texto del dial (2.88 → 9.40:1).
**Resultado: 0 nodos de texto por debajo de AA en las ocho vistas.**

### C2 — La tabla de 12 columnas no cabe y las celdas desperdician ancho

- **Fichero:** `console/assets/css/console.css`
- **Selectores / clases:** `.tabla-envoltura` (sombra de scroll),
  `table.tabla--registro` y sus subselectores (nuevo),
  `.celda-truncar` (`max-width` 340 px → 560 px)
- **Fichero:** `console/assets/js/components/comunes.js`
- **Símbolo:** `tabla()` acepta ahora la opción `clase`, que se añade al
  `className` de la `<table>`
- **Fichero:** `console/assets/js/components/secretos.js`
- **Clase aplicada:** `tabla--registro` en el Secret Register

Qué hace: `.tabla-envoltura` recibe las sombras de desplazamiento que
revelan el contenido que queda fuera del panel; la variante `tabla--registro`
compacta el relleno (8 → 5 px) y acota las celdas largas a 210 px; `.celda-truncar`
deja de cortar a 340 px fijos y usa 560 px.
**Resultado: el Secret Register pasa de 1687 px de tabla a 1566 px — las doce
columnas, incluidas OWNER y EVIDENCIA, caben sin scroll horizontal.**

### C3 — El estado de cada IoC, a 950 px de su texto y recortado en móvil

- **Fichero:** `console/assets/js/components/exposicion.js`
- **Clases:** `.check` → nueva clase `.check__cabecera` que agrupa
  `.check__titulo` y `.check__estado` en la misma línea
- **Fichero:** `console/assets/css/console.css`
- **Selectores / clases:** `.check` (de 3 columnas a 2),
  `.check__cabecera` (nuevo, flex con wrap), `.check__cabecera .check__estado`

Qué hace: el chip de estado pasa a la línea del indicador, con lo que la
asociación es inmediata y el chip hereda el ancho de su texto en vez de
caber en 128 px fijos.
**Resultado: a 390 px ningún chip se sale de su celda (antes 40 px fuera del
viewport y recortado) y desaparece el hueco de ~950 px.**

### C4 — Los rótulos del hex-grid se salen de sus hexágonos

- **Fichero:** `console/assets/js/components/hexgrid.js`
- **Símbolos:** `radio` (20 → 30), `etiquetaCorta()` (12 → 10 caracteres)
- **Fichero:** `console/assets/css/console.css`
- **Selectores / clases:** `.hexpanel__svg` (`max-width` 560 px → 720 px)

Qué hace: la celda pasa de 40 a 60 px de ancho, que es lo que hace falta para
que un rótulo de 10 caracteres quepa dentro sin tocar la celda vecina; la
etiqueta se acota a 10 caracteres (el nombre entero sigue en el `title` de cada
polígono) y el grid crece para dejar de flotar en 440 px de vacío.
**Resultado: `viewBox` pasa de `0 0 246 145` a `0 0 361 210`; ningún rótulo
supera ya el ancho de su celda.**

### C5 — El buscador se corta a media palabra y los filtros son más estrechos que su etiqueta

- **Fichero:** `console/assets/css/console.css`
- **Selectores / clases:** `.campo input[type="text"]`,
  `.campo input[type="search"]` (`width: 260px`), `.campo select`
  (`padding-right` 16 → 24 px y flecha desplazada), y en la media query de
  ≤ 860 px el input pasa a `width: 100%`
- **Fichero:** `console/assets/js/components/hallazgos.js`
- **Símbolo:** `placeholder` del buscador →
  «Buscar en título o evidencia…»

Qué hace: el campo pasa de 167 a 260 px y su rótulo se acorta para que quepa
entero; el `select` deja de dibujar la flecha encima de la última letra.
**Resultado: el placeholder se ve completo; ningún control se recorta.**

### Ficheros tocados

```
console/assets/css/console.css
console/assets/js/components/comunes.js
console/assets/js/components/dial.js
console/assets/js/components/exposicion.js
console/assets/js/components/hexgrid.js
console/assets/js/components/hallazgos.js
console/assets/js/components/secretos.js
```

### No aplicado (detectado, fuera del alcance de esta revisión)

| Hallazgo | Por qué no se aplicó |
|---|---|
| El ámbar marca el estado por defecto (55 chips «HALLAZGO» en una columna) | Es una decisión de **semántica de producto**, no de presentación: vive en `console/assets/js/format.js` (`estado()`, `vivo()`), fuera del alcance de `components/` que fijó la revisión. Recomendación: `estado("hallazgo")` debería usar una variante neutra y reservar el ámbar para «pendiente» y «requiere atención». |
| La aguja y la cifra del dial están a 7–25 px | Reubicar la lectura en el centro del dial exige cambiar la geometría del SVG (`dial.js`, `CX/CY/R`, posición de la lectura y de la graduación). Es un cambio de riesgo medio con beneficio real, pero no es una corrección de bajo riesgo. |
| ~900 px de hueco en la columna izquierda de SUPERFICIE | Es un problema de **balance de rejilla**, no de una clase concreta: la rejilla `rejilla--dial` reparte dos bloques de altura muy distinta. Se puede acotar limitando la altura del hex-grid, pero la solución correcta (reordenar el desglose del score al panel izquierdo) ya es un rediseño de la vista. |
| El barrido del hex-grid se lee como un artefacto | La animación (`mix-blend-mode: screen` + `linear-gradient`) está bien escrita; el problema es que el gradiente tiene bordes duros. Ajustarlo es cosmético y no prioritario frente a los cinco anteriores. |
| La columna OWNER se parte en dos líneas («sin» / «asignar») | Consecuencia de compactar el Secret Register. Se resolvería con un `min-width` mayor en esa columna, a costa de volver a empujar las doce columnas fuera del panel. |

---

## 5. Antes / después — resumen

| Métrica | Antes | Después |
|---|---|---|
| Vistas por debajo de 4.5:1 | **8 de 8** | **0 de 8** |
| Ratio mínimo de la consola | **2.20:1** | **4.77:1** |
| Nodos de texto por debajo de AA (1600 px) | 30–142 por vista | **0** |
| Nodos de texto por debajo de AA (390 px) | 28–135 por vista | **0** |
| Secret Register: columnas fuera de pantalla a 1600 px | **2** (OWNER, EVIDENCIA) | **0** |
| Chips de IoC recortados a 390 px | **18 filas** | **0** |
| Rótulos del hex-grid fuera de su celda | **3** (`clinica-demo`, `intranet`, `portal-paci…`) | **0** |
| Placeholder del buscador | cortado a media palabra | completo |
| Peticiones externas | 0 | 0 |
| Errores de consola / `pageerror` | 0 | 0 |
| Desbordamiento horizontal de documento | 0 | 0 |
| Fuentes woff2 cargadas | 14 faces | 14 faces |
| Tests del backend | 29 OK | 29 OK |

---

## 6. Limitaciones de esta revisión

1. **El contraste se midió sobre el color de fondo real computado**, no sobre
   el token de la variable CSS. Es lo correcto (mide lo pintado), pero significa
   que el valor depende de la composición alfa de cada capa: por ejemplo, el
   chip rojo se midió sobre `#271719` (rojo al 12 % compuesto con
   `--surface`), no sobre `#0e1013`. La fórmula es la de WCAG 2.x y el umbral
   es 4.5:1 (3.0:1 para texto grande), pero **no es una auditoría WCAG
   completa**: no se comprobó contraste no textual, foco visible, nombre
   accesible, orden de encabezados ni objetivo de tamaño táctil.
2. **La capa de textura del fondo** (`.textura`, dither diagonal + scanlines a
   ~0.016 de alfa) y la rejilla de fondo de `.vista::before` se ignoraron en
   el cálculo: son capas decorativas por encima del contenido con un alfa
   combinación de menos de 0.02, que baja la ratio real en < 0.05. Se documenta
   como limitación, no como error.
3. **El SVG se mide por `fill`, no por `color`.** La primera pasada de medición
   leyó `color` en el dial y en el hex-grid y dio ratios falsamente altos
   (por ejemplo, «Severo» como 13.68:1). La medición final lee `fill` para
   elementos SVG. Cualquier re-medición debe mantener esa distinción.
4. **Sólo se midió Chromium 1248 en headless**, sobre el conjunto **demo**
   (sintético). No se probó Firefox, WebKit, ni Chromium con GPU, ni un
   navegador real con la consola abierta durante una auditoría.
5. **No se midió el contraste del texto dentro de los PNG**, sino el de los
   estilos computados. Un difuminado o un fondo con imagen podría alterar el
   resultado; aquí los fondos son todos planos.
6. **El scroll horizontal del Secret Register** se resolvió compactando, no
   rediseñando la tabla de doce columnas. Con un conjunto de evidencia real
   (más secretos, más owners largos) la tabla volvería a desbordar: la sombra
   de scroll de `.tabla-envoltura` es la red de seguridad, no la solución.
7. **La captura del drawer es a viewport**, no a página completa, para que la
   capa modal se vea como la ve el auditor; las otras siete son a página
   completa.
8. **No se evaluó el comportamiento con `prefers-reduced-motion`**, ni el
   teclado, ni el contraste en el estado de foco.
9. El puerto 8799 estaba ocupado por un proceso huérfano de una sesión
   anterior (`/private/tmp/loopback.py`, ya borrado del disco). Se detuvo ese
   huérfano para poder auditar en el puerto pedido. El servidor de la consola
   que se usó es el de esta revisión y quedó apagado al terminar.

---

## 7. Reproducir

```bash
python3 console/demo/generar_demo.py          # sólo si no existe el conjunto
python3 console/server.py --demo --port 8799 --no-open &
# Playwright: 8 rutas por hash, viewport 1600x1000 @2x, networkidle + 450 ms
# después: contrast (WCAG), overflow, console, red, fuentes, dial
kill %1
```

Las capturas de este documento están en `console/docs/screenshots/`
(índice en `console/docs/screenshots/README.md`).
