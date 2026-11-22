# Changelog

Todas las novedades relevantes de este proyecto se documentan en este
fichero.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y
el proyecto adheres a [Semantic Versioning](https://semver.org/lang/es/).

> **Nota de versión.** La numeración de fases que aparece en este changelog
> (Fase 0/1/2) es la **comercial** — los paquetes que se contratan. No es la
> numeración de las 11 fases del ciclo de auditoría. Ver
> [`00-metodologia/ciclo-de-auditoria.md`](00-metodologia/ciclo-de-auditoria.md).

## [No publicado]

Trabajo en curso. Lo que se incorpore a partir de aquí se anotará en su
propia versión, con su fecha.

## [v0.2.1] - 2026-11-22

Pase de pulido sobre la v0.2: la consola pasa una **auditoría visual con
navegador real** y corrige lo que encontró, el stack de la VPS deja de
depender de un `Dockerfile` que no existía, y el repositorio deja de
contradecirse a sí mismo sobre cuántas auto-pruebas tiene.

### Corregido

- **Contraste WCAG en las 8 vistas de la consola.** La auditoría con Chromium
  headless medió **608 nodos por debajo de 4.5:1**; el peor caso era
  **2.20:1**. Los tokens `--texto-tenuisimo`, `--texto-tenue` y `--rojo-claro`
  se corrigieron y el mínimo global pasa a **4.77:1**. En móvil (390 px) los
  fallos por vista bajan de 28–135 a **0**.
- **Recortes que `scrollWidth` no detectaba.** El *Secret Register* perdía las
  columnas OWNER y EVIDENCIA (1 687 px de tabla en 1 566 de panel) y los chips
  de IoC se cortaban a 390 px. Ahora hay sombra de scroll en las tablas
  envueltas y el grid de IoC pasa a 2 columnas.
- **Vacío de ~1 135 px en la columna izquierda de SUPERFICIE.** La columna del
  dial era `position: static` y se iba con la página. Ahora es `sticky`
  (`top: 80 px`, justo bajo la navegación) y **el score sigue visible al
  final del scroll**; en móvil (< 900 px) el sticky se desactiva.
- **Aire muerto sobre el hex-grid.** El `viewBox` reservado no contabilizaba
  el desfase vertical de las columnas impares y **la última fila salía
  cortada**. El `viewBox` se ajusta al dibujo real con `getBBox()` y el panel
  centra el SVG verticalmente.
- **`console/Dockerfile` no existía**, de modo que `docker compose up` fallaba
  aunque el compose lo declarara. Ahora la imagen **construye y arranca**:
  `python:3.13-slim`, usuario no-root, healthcheck sin `curl` y evidencia
  montada en **solo lectura**. También se corrigieron dos fallos del compose
  que bloqueaban el arranque: el `command:` usaba una ruta relativa al
  `WORKDIR` equivocado y el healthcheck llamaba a `wget`, que la imagen slim
  no trae.
- **El repositorio se contradecía sobre el número de auto-pruebas.** Ocho
  referencias seguían diciendo *«14 checks»* en `00-metodologia/`,
  `04-formacion/`, `PLAN-MAESTRO.md`, `README.md`, `.github/` y
  `01-tooling/scripts/README.md`. Todas alineadas a **19**.

### Añadido

- **`console/docs/QA-VISUAL.md`** — la auditoría visual documentada: método,
  mediciones de contraste por vista, desbordamientos, cargas de red, errores
  de consola y las cinco correcciones aplicadas con fichero y selector.
- **`console/docs/vista-previa/`** — tres capturas reducidas (< 400 KB) de
  SUPERFICIE, AUTORIZACIÓN y HALLAZGOS, referenciadas desde el README raíz y
  el de la consola.

### Seguridad

- **`.dockerignore` en la raíz como lista blanca.** El contexto de build es la
  raíz del repo (la imagen necesita `console/` **y** `01-tooling/scripts/`),
  así que se excluye todo y se re-incluye sólo lo necesario. Medido: **842,8
  kB** de contexto, frente a los 3,9 MB de `03-casos/` y los 8,8 MB de
  capturas que quedan fuera. `03-casos/` no entra nunca en una imagen.

## [v0.2.0] - 2026-11-22

Cierra el perímetro de la v0.2: la **consola interna de operaciones**, el
**stack en Docker** que la sostiene en la VPS del auditor y el **plan maestro
de 90 días** que ordena lo que viene después. El método no cambia: lo que
cambia es que, por fin, **se ve**. Además, el toolchain cierra los tres bugs
abiertos y su auto-prueba sube de 14 a 19 checks.

### Añadido

#### Consola de operaciones — `console/`

- **Consola interna de 8 vistas** (`console/`): no es una landing page ni un
  producto que se venda: es el instrumento que el auditor abre en su VPS
  mientras trabaja sobre un expediente. Las ocho vistas son **SUPERFICIE**
  (el *Attack Exposure Score* como dial, con los 13 componentes de riesgo y
  su fuente), **HALLAZGOS**, **SECRET REGISTER** (máscaras y `sha256[:12]`,
  nunca el valor), **API SURFACE**, **EXPOSICIÓN A ATAQUES** (los 18 IoC y lo
  que ningún auditor externo puede saber), **EVIDENCIA**, **AUTORIZACIÓN**
  (RoE, ventana en vivo y el estado *«FASE 2 BLOQUEADA — sin addendum
  firmado»*) y **REGISTRO DE ACCIONES**.
- **Servidor propio de la stdlib** (`console/server.py`, `console/api.py`):
  `python3 console/server.py --demo --port 8787`. Cero dependencias de
  runtime, cero peticiones externas, CSP `default-src 'self'` y tipografías
  *self-hosted*.
- **La regla de redacción, aplicada por defecto**: un artefacto sin estado de
  redacción verificable sale como **SIN REDACTAR** y **oculto** hasta que el
  auditor lo revela. Es una regla de seguridad, no una preferencia de
  maquetación.
- **Conjunto de demostración sintético** (`console/demo/generar_demo.py`): lo
  genera el propio toolchain ejecutándose contra fixtures sintéticos y un
  sitio local efímero. **Ningún número de la demo está escrito a mano.**
- **29 comprobaciones** de la stdlib (`console/tests/test_console.py`), sin
  red.

#### Toolchain — `01-tooling/`

- **Auto-prueba de 19 checks** (antes 14), sin ninguna llamada de red: cinco
  checks nuevos (`check_pii_redact_catalogo_expediente`,
  `check_pii_redact_matches_vs_redactions`,
  `check_pii_report_sin_valores_en_nuevos_campos`,
  `check_probe_exposure_truncation` y `check_core_headers_coinciden`) y dos
  fixtures sintéticos nuevos (`expediente_clinico.json`,
  `tarjetas_texto.txt`).

#### Research del stack — `research/`

- **`research/06-stack-y-ecosistema.md`**: la investigación que sostiene cada
  decisión de stack, **verificada el 2026-11-22** contra las fuentes
  primarias — repos de runtime LLM autoalojado (Ollama / llama.cpp), modelos
  y sus tamaños, repos de ciberseguridad, las tres piezas de UI de la
  consola, la arquitectura objetivo de la VPS, el punto de seguridad crítico
  (qué ve el LLM), el análisis de licencias copyleft y lo que **no** se
  adopta, con el porqué.

#### Stack de la VPS en Docker — `deploy/`

- **`deploy/docker-compose.yml`**: el stack completo —runtime de LLM local,
  consola interna y almacén de hallazgos— con la regla que lo gobierna
  (*nada de lo del cliente sale de esta máquina*) implementada por
  construcción: ningún puerto de administración publicado en `0.0.0.0`, la
  API de Ollama sin publicar, y la evidencia cruda montada en **solo
  lectura**.
- **`console/Dockerfile`**: imagen `python:3.13-slim`, usuario no-root,
  *healthcheck* sin dependencias externas y el servidor arrancando en modo
  real (nunca en modo demo) sobre el volumen de evidencia.
- **`deploy/README.md`**: guía de despliegue completa — requisitos, arranque,
  comprobación del perímetro, backup y restauración, rotación de secretos,
  firewall, por qué SQLite y no Postgres y diagnóstico.
- **`deploy/hardening.md`**: el checklist de endurecimiento de la VPS.
- **`deploy/Makefile`** y **`deploy/.env.example`**: los comandos repetidos y
  las variables, con los secretos de fábrica.

#### Plan maestro de 90 días — `PLAN-MAESTRO.md`

- **`PLAN-MAESTRO.md`**: el marco de negocio, arquitectura y gobierno que
  ordena lo que ya existe y define lo que falta. Los tres hitos de las
  próximas 90 días, los trece sprints, el runbook de un engagement, el
  perímetro de confianza enunciado como regla de oro y los riesgos de cada
  decisión. **Cero datos inventados**: todo dato legal va marcado
  **NO VERIFICADO** con su fuente primaria.

### Corregido

- **Cabeceras núcleo incoherentes entre los dos informes (#5)**: a COEP se le
  había olvidado, así que `header_tls_report.py` informaba de 9 cabeceras
  ausentes y `attack_surface_report.py` puntuaba sobre 8. Dos números
  distintos para la misma evidencia es exactamente el tipo de contradicción
  que un cliente detecta en el mismo informe. Ahora ambos derivan del módulo
  compartido `_common_headers.py` y un check comprueba que **coinciden**.
- **Copia de seguridad truncada mal reportada (#6)**: `probe_exposure.py`
  guardaba como `length` los bytes leídos (tope de 1 MB), de modo que una
  copia de 48 MB aparecía como `length=1000000`, con el `sha256` del primer
  megabyte, indistinguible de un fichero de 1 MB. Ahora `length` son los
  **bytes leídos**, el tamaño **declarado** va aparte en
  `content_length_header`, el booleano `truncated` dice si la lectura quedó
  incompleta y el veredicto pasa a `exposed_truncated`: el fichero es *mayor*
  de lo que se leyó, y el auditor tiene que saberlo antes de cerrar el
  hallazgo.
- **Catálogo de PII incompleto (#4)**: `pii_redact.py` no cubría las grafías
  con las que un JSON de cliente trae la misma clave (`grupo_sanguineo` /
  `grupo_sangre` / `tipo_sangre`, `num_tarjeta` / `card_number`,
  `num_expediente`, `fecha_nac` / `nacido_en` / `dob`). **Lo que no estaba en
  el catálogo no se redactaba.** Ahora el catálogo admite alias, las listas de
  escalares se redactan elemento a elemento y los objetos se recorren por
  clave sin destruir la estructura del JSON.
- **Informe de redacción que confunde coincidencia con redacción**: decía
  «16 tarjetas» para 16 *coincidencias* cuando sólo se habían redactado 14. El
  informe distingue ahora `matches_by_category` (coincidencias detectadas) de
  `counts_by_category` (redacciones aplicadas), y **sigue sin contener ningún
  valor**.

### Seguridad

- La consola **no escribe la evidencia cruda**: el directorio se monta en
  solo lectura y la interfaz sólo muestra lo que la evidencia sostiene.
- El stack de `deploy/` publica los puertos administrativos **únicamente** en
  `127.0.0.1` del host: el acceso es por túnel SSH o VPN.
- Los pesos del LLM se verifican por `sha256` y la base de hallazgos guarda
  el **hash** de la evidencia cruda, nunca su contenido.

## [0.1.0] - 2026-11-22

Primera publicación pública del playbook. Todo lo que se publica aquí nace de
una auditoría real (Clínica Dental Easy, `dentaleasy.mx`, octubre 2026) y se
reorganiza para que el proceso se repita en el siguiente cliente sin
re-aprenderlo.

### Añadido

#### Metodología — `00-metodologia/`

- **Ciclo de auditoría de 11 fases** (`ciclo-de-auditoria.md`): objetivo,
  herramientas, evidencia y lección aprendida de cada fase, incluidas las dos
  lecciones duras — contrastar toda versión con la fuente primaria y la
  semántica real de `curl --tlsv1.x` (que produjo un falso positivo).
- **Reglas de autorización y RoE** (`reglas-de-autorizacion-y-roe.md`): las
  5 prohibiciones duras, el ritmo de trabajo, la regla de decisión para
  hallazgos de terceros y la plantilla de RoE.
- **Cómo presentar resultados** (`como-presentar-resultados.md`): matriz de
  severidad, por qué ICE y no RICE, las tres capas de entregable y la
  obligatoriedad de «Lo que ya está bien».
- **Módulo de exposición de secretos** (`exposicion-de-secretos.md`):
  verificación de credenciales sin usarlas, *Secret Register*, superficie de
  API, credenciales de BD y reglas de redacción de la evidencia.
- **Módulo de exposición a ataques** (`exposicion-a-ataques.md`): qué se ve
  desde fuera y qué no, IoC, fuentes pasivas y el *Attack Exposure Score*.
- **Fase 2 — explotación autorizada** (`fase-2-explotacion-autorizada.md`):
  prueba sin daño, matriz de destructividad, ventana de 3 h, «go» por prueba,
  criterio de abort y checklist de salida.
- **Modelo de servicio y escalabilidad** (`modelo-de-servicio-y-escalabilidad.md`):
  los 3 paquetes comerciales, precios, marco legal previo a la venta, unidad
  económica, riesgos y plan de 30 días.

#### Toolchain — `01-tooling/`

- **7 scripts de Python 3.13, stdlib, cero dependencias**:
  - `scope_guard.py` — la única puerta a la red: valida la autorización
    firmada (ventana, host, método, intervalo, UA) y aborta si no cuadra.
  - `probe_exposure.py` — sonda de 53 rutas sensibles con detección de
    *soft-404* por `sha256`; no guarda el cuerpo de las rutas sensibles.
  - `secrets_scan.py` — escaneo local de secretos (AWS, Stripe, GCP, JWT,
    claves privadas…); escribe sólo `4+2` caracteres y el `sha256[:12]`.
  - `js_intel.py` — inteligencia del JavaScript público: endpoints,
    integraciones de terceros, destinos de formularios, GraphQL y SRI.
  - `header_tls_report.py` — postura de cabeceras y TLS sobre la evidencia ya
    descargada; no hace llamadas propias.
  - `pii_redact.py` — redacción de PII y secretos antes de compartir
    evidencia; genera la copia sanitizada y el informe de conteos.
  - `attack_surface_report.py` — consolida sonda + secretos + cabeceras en el
    *Attack Exposure Score* con informe Markdown/JSON.
- `authorization.example.json` — formato de la autorización firmada que
  consume `scope_guard.py`.
- `manifiesto-de-herramientas.md` — catálogo de herramientas de terceros con
  para-qué, licencia, carácter pasivo/activo, fase y aviso de licencias
  copyleft/AGPL.
- **14 auto-pruebas sin ninguna llamada de red** en
  `01-tooling/scripts/tests/selftest.py`, con fixtures sintéticos en
  `tests/fixtures/`.

#### Plantillas — `02-plantillas/`

- **Teaser** (`teaser-report/`): plantilla HTML→PDF de 13 páginas con
  gráficos, `build.py`, `make-charts.py` y `verify.py` (reglas de contenido
  «cero técnico» verificadas automáticamente). Ejemplo ya construido.
- **Informe técnico** (`informe-completo/`): estructura de 10 secciones
  (§0–§9) más el anexo de explotación limitada de Fase 2.
- **Propuesta comercial** (`propuesta-comercial/`): estructura de la propuesta
  y los 3 paquetes con precios, inclusiones, exclusiones y camino recomendado
  (fuente autoritativa de precios).

#### Formación — `04-formacion/`

- Guía de formación del auditor (`guia-de-formacion-auditor.md`).
- Laboratorio seguro (`01-lab-seguro.md`): dónde practicar sin tocar objetivos
  reales.
- Toolkit de terceros (`02-herramientas-y-python.md`) con la línea de
  autorización dibujada en cada herramienta.
- Modelo de negocio y marco legal mexicano (`03-modelo-de-negocio-y-legal-mx.md`).

#### Formatos de trabajo — `05-plantillas-de-trabajo/`

- RoE rellenable (`alcance-y-roe.EJEMPLO.md`).
- Addendum de Fase 2 firmado por tres partes
  (`addendum-fase-2-explotacion-limitada.EJEMPLO.md`): 6 técnicas con casilla
  de rechazo, 11 prohibiciones que no se levantan, ventana, «go», criterio de
  abort, minimización, retención y firmas.
- Registros de acciones (`registro-de-acciones.EXAMPLE.csv`,
  `registro-de-acciones-fase-2.csv`).
- Contexto, bucle de corrección, mapa de redacción y preguntas de revisión
  para trabajar con un LLM externo.

#### Proyecto y comunidad

- `LICENSE` (MIT) para el código y `LICENSE-DOCS.md` (CC BY-NC-ND 4.0) para la
  metodología: el método puede circular y ser usado por otros profesionales y
  por clientes, pero no se puede revender como servicio.
- `SECURITY.md` con la política de reporte responsable, la tabla de severidades
  y la declaración de la empresa: **no se audita, pentestea ni explora nada sin
  autorización escrita del propietario; RoE y addendum firmados antes de
  cualquier prueba.**
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` y este `CHANGELOG.md`.
- CI con `py_compile`, auto-prueba, chequeo de enlaces relativos y `gitleaks`.

### Seguridad

- `03-casos/` (evidencia de un cliente real y confidencial) **no se versiona**:
  está en `.gitignore` y verificado con `git status` y con el árbol del
  remoto.
- El mapa de redacción (`MAPA-DE-REDACCION.md`), que es la clave inversa del
  sanitizado, tampoco se versiona.
- Los fixtures de test contienen secretos **sintéticos** y están declarados en
  la allowlist de `.gitleaks.toml` por valor y por ruta.

[No publicado]: https://github.com/franciscomorenosys/web-audit-playbook/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/franciscomorenosys/web-audit-playbook/releases/tag/v0.2.0
[0.1.0]: https://github.com/franciscomorenosys/web-audit-playbook/releases/tag/v0.1.0
