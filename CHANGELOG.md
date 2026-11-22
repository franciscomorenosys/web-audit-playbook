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

Nada todavía.

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

[No publicado]: https://github.com/franciscomorenosys/web-audit-playbook/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/franciscomorenosys/web-audit-playbook/releases/tag/v0.1.0
