# Modelo de servicio y escalabilidad

Cómo se convierte una metodología de auditoría en **un negocio vendible**: los tres
paquetes, la escalera de valor, el marco legal que tiene que existir antes de
facturar, la unidad económica, la escalabilidad operativa y los primeros 30 días.

Doctrina: [`reglas-de-autorizacion-y-roe.md`](reglas-de-autorizacion-y-roe.md) ·
[`ciclo-de-auditoria.md`](ciclo-de-auditoria.md) ·
[`como-presentar-resultados.md`](como-presentar-resultados.md)

Comercial: [`../02-plantillas/propuesta-comercial/paquetes-por-fase.md`](../02-plantillas/propuesta-comercial/paquetes-por-fase.md)
— **fuente autoritativa de precios**. Legal y negocio:
[`../04-formacion/03-modelo-de-negocio-y-legal-mx.md`](../04-formacion/03-modelo-de-negocio-y-legal-mx.md).

> **Nota de alcance y de precedencia.**
>
> 1. **Los precios de este documento son los de `paquetes-por-fase.md`.** No se
>    modifican aquí. Si un día cambian, cambian en ese archivo y en
>    `04-formacion/03-modelo-de-negocio-y-legal-mx.md` §3.1, y no en este.
> 2. **Lo que hay en `research/` es de otra línea de producto** (SaaS de
>    assessments de personalidad para selección de personal: BUO, Pangolin,
>    Talenty, Hirint, baremos, validez predictiva). Sus precios, sus cifras de
>    mercado y sus segmentos **no son trasladables a esta auditoría**. Los
>    documentos de `research/` se citan aquí sólo como advertencia de no
>    contaminación cruzada. Cualquier número de este playbook tiene su origen
>    en el playbook o en el caso real, no en `research/`.
> 3. **Este documento no es asesoría legal.** Es orientación operativa de
>    negocio. La parte legal la revisa un abogado (ver §4.i).

---

## 1. La tesis del servicio

### 1.1 La respuesta directa a la pregunta del cliente

> *«¿Podemos investigar vulnerabilidades en sitios web con datos de pacientes para
> vender planes de soluciones? Fase de reconocimiento, y en una segunda etapa
> autorizada explotación y escalabilidad (pensando en las tres fases de
> vulnerabilidad)?»*

**Sí. Y la forma correcta de decirlo es esta:**

Sí se puede, y la operación ya es legalizable y vendible — pero **no como
"hackeo"**. Se vende como **una revisión de seguridad autorizada, por fases,
con alcance cerrado y evidencia trazable**. La fase de reconocimiento es el
paquete de entrada; la explotación es una fase posterior, separada, con su
propio addendum firmado; y la "escalabilidad" no es una fase de prueba sino
**la capacidad del negocio de repetirse** con calidad constante (que es la §6
de este documento).

Las tres fases ya están definidas y documentadas en el playbook:

| Fase | Nombre comercial | Qué es | Precio de lista (MXN) |
|---|---|---|---|
| **0** | **Recon & Superficie** | Qué está expuesto | **12,000** |
| **1** | **Validación** | Qué está mal y con qué base legal | **28,000** |
| **2** | **Explotación Limitada** | Cuánto cuesta de verdad | **60,000** |
| — | **Ruta completa 0→1→2** | Las tres, con 10 % de descuento sobre el total | **90,000** |
| — | **Re-test** | Verificar que el arreglo funcionó | **12,000** |
| — | **Retainer** | Vigilancia de exposición | **4,000–12,000 / mes** |

(Fuente: [`../02-plantillas/propuesta-comercial/paquetes-por-fase.md`](../02-plantillas/propuesta-comercial/paquetes-por-fase.md). No se cambian aquí.)

### 1.2 El posicionamiento honesto

La frase que sostiene todo el modelo:

> **No necesitas hackear un sitio para demostrar que está expuesto. El valor
> está en medir la superficie, priorizar el riesgo y demostrar el impacto de
> forma controlada.**

Desglosada, en tres afirmaciones que se pueden defender una por una:

| # | Afirmación | Por qué es defendible | Dónde está el respaldo en el playbook |
|---|---|---|---|
| 1 | **No necesitas hackear un sitio para demostrar que está expuesto.** | La superficie expuesta es observable sin autenticación ni escritura: Ficheros de respaldo accesibles, endpoints REST sin control de acceso, secretos en el JavaScript público, dominios de pacientes que salen a un endpoint que el cliente no controla, ausencia de DMARC, TLS negociado. Todo eso se ve con peticiones de lectura. | `00-metodologia/ciclo-de-auditoria.md` fases 2–7 · `01-tooling/scripts/probe_exposure.py`, `js_intel.py`, `secrets_scan.py` |
| 2 | **El valor está en priorizar.** | Un escáner produce una lista. Un informe produce una **cola de trabajo ordenada por riesgo removido por hora** (`rr_por_hora`, método ICE) con dueño asignado y comando reproducible. Esa cola es lo que un dueño de clínica puede ejecutar. | `00-metodologia/como-presentar-resultados.md` §2 · `05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv` |
| 3 | **El impacto se demuestra de forma controlada.** | Cuando hace falta prueba de impacto, existe una **modalidad de pruebas activas controladas** con seis técnicas acotadas, ventana horaria de 3 horas, "go" del cliente prueba por prueba, criterio de abort inmediato y declaración de limpieza firmada. | `00-metodologia/reglas-de-autorizacion-y-roe.md` §5 · `05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md` |

### 1.3 Contra qué se diferencia: dos contornos que hay que saber dibujar

**Contra (a) la oferta de "hackeo".**

| La oferta de "hackeo" | Este servicio |
|---|---|
| Promete entrar. | Promete **medir, priorizar y demostrar en condiciones controladas**. |
| No hay papel: se opera "porque el dueño lo pidió". | RoE firmado por engagement, con hosts exactos, técnicas enumeradas una por una, ventana y criterio de parada. |
| Entrega credenciales o accesos. | Entrega **evidencia enmascarada, tickets y una cola de trabajo**. El secreto encontrado se rota; no se usa. |
| Escala a "casi todo". | Escala a "lo que está en alcance, en la ventana, con el "go" del cliente". |
| Resultado: el dueño tiene una duda nueva ("¿y si me cuelgo más?"). | Resultado: el dueño tiene una **lista ordenada con dueño y horas**. |

La diferencia no es de marketing: es de **estructura de prueba**. Un aceite es
legítimo; apagar un incendio con gasolina no lo es aunque el fuego sea real.

**Contra (b) el escáner automático, que es commodity.**

Aquí hay que ser directo: **cualquiera puede bajar un escáner**. Lo que no se
puede commodities es el trabajo de criterio. La tabla comparativa:

| Capacidad | Escáner automático | Este servicio |
|---|---|---|
| Inventario de superficie | Parcial (sólo lo que el escáner sabe preguntar) | Completo: pasivo (certificados, historiales, DNS) + sonda de rutas expuestas con detección de soft-404 |
| Versiones y CVE | **Pueba pertenencia a un rango, no alcanzabilidad.** Una versión dentro de un rango vulnerable no es un fallo explotable. | **Contraste contra la fuente primaria** del proyecto (tabla oficial de avisos, API de versiones), con la discrepancia documentada. Es la lección (a) del ciclo de auditoría. |
| TLS | Suele concluir por error a partir de flags mal entendidos. | Se **fija el máximo** (`--tls-max`), se fuerza el provider legacy si hace falta y se lee la versión **realmente negociada**. Es la lección (b). |
| Severidad | Heredada de una escala genérica. | **Calibrada por contenido**: exposición × efecto × contexto (¿hay datos de pacientes detrás?). Un hallazgo honesto en LOW vale más que uno inflado. |
| Legal | No la toca, o la inventa. | Mapeo a norma **con cita y enlace a la fuente primaria**, y **refutaciones explícitas** donde la obligación no existe. |
| Resultado | Un PDF que el cliente no sabe qué hacer con él. | **Tres capas**: resumen ejecutivo (dueño), informe técnico (equipo/hosting/agencia), brief en lenguaje llano (dueño) + borradores de ticket. |

> **Lo que el escáner no puede hacer y nunca va a hacer:** decidir qué tiene
> detrás un endpoint, calibrar si un backup expuesto contiene expedientes de
> pacientes o plantillas, decidir si un certificado compartido es un riesgo del
> cliente o del hosting, y decidir qué se le dice a un dueño que no va a leer
> nada técnico. Eso es criterio humano, y es el producto.

**Por qué la versionación en fases es la ventaja, y no un rodeo.**

1. **Reduce el riesgo legal por fase.** Las Fases 0 y 1 no necesitan
   credenciales ni escritura ni ventana nocturno. La Fase 2 sí. Separar las
   fases significa que el 80 % del encargo (en ingresos y en horas) ocurre bajo
   un RoE de lectura, que es mucho más fácil de defender y de cubrir para un
   cliente de salud.
2. **Reduce el riesgo de la promesa mal calibrada.** "Revisión autorizada de
   superficie" y "revisión de seguridad" son expectativas que se pueden cumplir.
   "Prueba de penetración" es una expectativa que exige más cobertura de la
   que este modelo entrega — y eso produce quejas y riesgo de clawback, no ventas.
3. **Convierte un cliente berisiko en una progresión.** El cliente que no
   quiere (o no puede) firmar un addendum de explotación sigue siendo cliente
   de Fase 0 y Fase 1. No se pierde: se degrada con elegancia.
4. **Escalona la evidencia.** Fase 0 = qué existe. Fase 1 = qué está mal.
   Fase 2 = qué pasa si no se arregla. Cada fase justifica la siguiente con
   hechos ya entregados, no con publicidad.
5. **Permite un precio por profundidad, no un precio por alarming.** Es la
   diferencia entre un modelo vendible a PyME y uno que sólo vive de
   empresas grandes.

### 1.4 Qué NO es este negocio

- **No es pentesting como producto.** La Fase 2 es *explotación limitada*: seis
  técnicas, tres horas de ventana, sin extracción de datos, sin persistencia.
- **No es un SaaS de escaneo.** No hay software que se venda por suscripción
  a cualquier cliente que quiera "un scan". El negocio es un encargo de
  consultoría con metodología repetible.
- **No es asesoría legal.** Se entrega el mapeo normativo con cita; la
  interpretación es del abogado del cliente.
- **No es pentest para bancos.** El encuadre es SMB de salud
  mexicano: un sitio, un dueño que decide, datos sensibles.

---

## 2. Los tres paquetes

Los tres paquetes están definidos en detalle en
[`../02-plantillas/propuesta-comercial/paquetes-por-fase.md`](../02-plantillas/propuesta-comercial/paquetes-por-fase.md).
Aquí se añade la capa de negocio: personal, carga de trabajo, precondiciones
económicas y qué no se puede prometer. **Los precios son los de ese archivo.**

### 2.0 Tabla resumen (la que va en la respuesta al cliente)

| | **Fase 0 — Recon & Superficie** | **Fase 1 — Validación** | **Fase 2 — Explotación Limitada** |
|---|---|---|---|
| **La pregunta que responde** | ¿Qué está expuesto? | ¿Qué está mal y qué dice la norma? | ¿Cuál es el impacto real? |
| **Modalidad** | **PASIVA + ACTIVA-L** | **ACTIVA-L** | **ACTIVA-A** (activa controlada) |
| **Métodos HTTP** | GET / HEAD | GET / HEAD | GET / HEAD (+ 1 POST acotado y opcional, en entorno de pruebas designado) |
| **Autenticación** | No | No | Sí, con cuentas de prueba del cliente |
| **Duración** | 5–8 días hábiles | 10–15 días hábiles | 5–8 días calendario, con ventana de ejecución de 3 h |
| **Carga de trabajo estimada** ⚠️ | 10–18 h | 20–35 h | 16–28 h |
| **Entregables** | Mapa de superficie (doc + CSV), hallazgos priorizados con evidencia, plan de remediación ola 1, sesión de entrega de 60 min | Las **tres capas** (resumen ejecutivo PDF, informe técnico Markdown, brief llano), hoja de ruta en 3 olas por ICE, borradores de ticket para hosting y agencia | Anexo de explotación limitada, registro de acciones (CSV), declaración de limpieza firmada, sesión de cierre de 60 min |
| **Abre datos de pacientes** | No | No | **No — prohibido por escrito** |
| **Riesgo de causar daño** | Nulo | Nulo | **Controlado y acotado** |
| **RoE requerido** | Sí (firmado) | Sí (firmado) | **Sí + addendum de Fase 2 firmado por tres partes** |
| **Precio de lista** | **MXN 12,000** | **MXN 28,000** | **MXN 60,000** |
| **Rango de cotización** | 9,000–15,000 | 22,000–35,000 | 50,000–85,000 |

⚠️ **Las cargas de trabajo son estimaciones internas ilustrativas**, no un
compromiso contractual. La cifra que se firma es el **precio**, no las horas.
§5 enseña a convertirlas en margen con tus números reales.

**Extras, cotizados aparte:**

| Servicio | Precio | Cuándo tiene sentido |
|---|---|---|
| **Re-test** de hallazgos cerrados | **MXN 12,000** | Tras corregir: demuestra que el arreglo funcionó. Es el mejor gancho de renovación. |
| **Retainer de vigilancia de exposición** | **MXN 4,000–12,000 / mes** | Recaneo trimestral, vigilancia de DNS/TLS/certificados/subdominios, canal prioritario, seguimiento de arreglos. **No es un pentest mensual** y no se vende como tal. |
| **Fase 1 en marca blanca** | **MXN 28,000** | La agencia re-cobra a su cliente final. Es el mejor cliente recurrente. |

**Ruta completa:** contratar las tres fases en un mismo encargo da **10 % sobre
el total**: **MXN 90,000** en lugar de MXN 100,000. El descuento aplica al
total del encargo, no a cada fase por separado.

### 2.1 Fase 0 — Recon & Superficie

| Campo | Contenido |
|---|---|
| **Nombre comercial** | Recon & Superficie (Fase 0) |
| **Objetivo del cliente** | «No sé qué está expuesto y no tengo un diagnóstico.» El dueño de una clínica, un consultorio o centro de atención. También la **agencia web** que necesita el mapa del cliente antes de cotizar mantenimiento. |
| **Duración** | 5–8 días hábiles |
| **Personal** | 1 auditor principal. Sin equipo de apoyo. Sin sesión de exploitation. |
| **Carga de trabajo estimada** | 10–18 h (⚠️ ilustrativa) |
| **Modalidad** | **PASIVA + ACTIVA-L**: sólo fuentes de terceros y lo ya público + peticiones de lectura (`GET`/`HEAD`), ≥1 s entre peticiones, User-Agent honesto y contactable |
| **Entregables** | 1) Mapa de superficie (documento + CSV de activos). 2) Informe de hallazgos priorizado con evidencia por archivo y comando reproducible. 3) Plan de remediación de la primera ola con horas y dueño. 4) Sesión de entrega de 60 min con el equipo técnico. |
| **Incluye** | Inventario de superficie (certificados públicos, historiales de archivo, DNS, URLs indexadas, endpoints, formularios, integraciones de terceros y sus destinos) · Huella de plataforma con versiones contrastadas contra fuente primaria · Postura de transporte y DNS (TLS negociado realmente, suite de cifrados, HSTS, cabeceras, SPF/DKIM/DMARC/CAA/BIMI) · Verificaciones de bajo riesgo (backups expuestos, configuración accesible, listados de directorio, superficies de autenticación, endpoints de administración, metadatos en ficheros subidos) · Barrido de secretos con valores enmascarados · Mapa de riesgo priorizado y plan de la primera ola |
| **Excluye (explícitamente)** | **No hay login, no hay credenciales, no hay formularios, no hay autenticación** · **No hay POST ni ningún método con cuerpo** · **No hay explotación, no hay pentest, no hay prueba de concepto** · **No hay escaneo de puertos, de red ni de la infraestructura del hosting** · **No hay análisis de código fuente, de la aplicación ni del panel** (salvo que el cliente los comparta) · **No hay auditoría de cumplimiento** (eso es Fase 1) · **No hay rendimiento, SEO ni accesibilidad** |
| **Qué NO se puede prometer** | Que un fallo sea explotable (esta fase **no lo demuestra**) · Que un CVE aplique a la versión detectada (se contrasta, y si no se alcanza la fuente primaria se marca *no verificado*) · Que se arreglará todo lo que hay en la plataforma (mucho queda en el hosting y la agencia: se reporta como escalación, no como arreglo del cliente) · Que la auditoría cubra la aplicación o el panel · Que el teaser revele técnicas: el teaser es capa 1, cero técnico |
| **Precondiciones** | RoE firmado **antes de la primera petición** · Un contacto técnico que pueda escalar en el momento · Opcional: logs de acceso (si se comparten, el informe mejora; si no, el trabajo se hace igual con lo público) |
| **Precio** | **MXN 12,000** (rango 9,000–15,000) |

**Fundamento del precio (del archivo comercial):** es una revisión de
superficie de sitio en hosting compartido, cotizada en el tramo bajo del
mercado; esta fase se sitúa en el extremo superior de esa banda y en el
inferior de la banda de "revisión completa". Incluye mapa de superficie, plan
de remediación y sesión de entrega, pero **no** incluye explotación ni tickets
de escalación, que son lo que hace subir el precio.

### 2.2 Fase 1 — Validación

| Campo | Contenido |
|---|---|
| **Nombre comercial** | Validación (Fase 1) |
| **Objetivo del cliente** | «Sé que hay algo sospechoso y necesito un documento formal que pueda mandar a mi hosting, a mi agencia o a mi aseguradora.» Responsable técnico, hosting, agencia, y el dueño que necesita papel. |
| **Duración** | 10–15 días hábiles, **contando el tiempo de revisión legal del cliente** (el informe se entrega con los huecos legales marcados) |
| **Personal** | 1 auditor principal (redacción e investigación) + revisión legal externa o del cliente. En equipos con más de un auditor, el revisor de calidad es una persona distinta del redactor. |
| **Carga de trabajo estimada** | 20–35 h (⚠️ ilustrativa) |
| **Modalidad** | **ACTIVA-L**: sólo peticiones de lectura, ≥1 s entre peticiones, UA honesto, ritmo lento y nunca masivo |
| **Entregables** | Las **tres capas**: (1) resumen ejecutivo PDF para el dueño, (2) informe técnico Markdown para equipo/hosting/agencia — **confidencial, no al dueño**, (3) brief en lenguaje llano de 2–3 páginas para el dueño. Más: hoja de ruta en 3 olas por ICE, registro de riesgos puntuado, borradores de ticket listos para enviar. |
| **Incluye** | Verificación activa de baja tasa de los candidatos de la Fase 0, sin ninguna acción con efecto sobre el servicio · Investigación contra **fuente primaria** de cada componente, con enlace y marca *no verificado* + ticket de 60 segundos cuando no se puede cerrar · Mapeo a cumplimiento (marco mexicano de protección de datos y de publicidad sanitaria) con cita y enlace, y **refutaciones explícitas** donde la obligación no existe · Fichas de hallazgo completas (evidencia literal, comando de reproducción, severidad calibrada por contenido, dueño, horas) · Registro de riesgos puntuado, separando lo que arregla el cliente, lo que se exige al hosting y lo que se exige a la agencia · Hoja de ruta en tres olas (hoy / este mes / este trimestre) ordenada por **ICE** (`rr_por_hora`) · Borradores de ticket para hosting y agencia · Entrega en tres capas |
| **Excluye (explícitamente)** | **No hay explotación, no hay PoC, no hay bypass de control de acceso** · **No hay POST, ni login, ni credenciales, ni formularios** · **No hay pruebas de carga, de denegación de servicio ni de disponibilidad** · **No hay escaneo de puertos, ni fuzzing de rutas, ni fuerza bruta** · **No hay acceso a la red interna, al panel del hosting ni al servidor** · **No hay análisis de código fuente ni de repositorios** (salvo que el cliente los comparta) · **No hay opinión legal ni asesoría jurídica** · **No hay pentest, ni red team, ni simulación de phishing** |
| **Qué NO se puede prometer** | Que un hallazgo sea explotable · Que la закон aplicable sea la que el cliente cree (hay **refutaciones** que contradicen la creencia del cliente; eso es valor, no un problema) · Que el informe diga «esto está bien y no hay nada que hacer» si no es así · Que el **informe técnico lo reciba el dueño**: va a su equipo técnico, por confidencialidad. Enviarlo al dueño es un error de manejo, no una cortesía. |
| **Precondiciones** | RoE firmado y vigente · Responsable técnico identificado que reciba las escalaciones · El RoE define qué es "fuera de alcance": si aparece un host de un tercero (hosting, agencia, SaaS), **se describe, no se ataca**; si no está listado, **se para y se pregunta** · Opcional pero recomendado: logs de acceso y contacto del hosting, para escalar el mismo día |
| **Precio** | **MXN 28,000** (rango 22,000–35,000) |

**Fundamento del precio (del archivo comercial):** es el precio de una revisión
completa con tres capas, hoja de ruta y tickets, en el tramo que paga el
cliente pequeño y mediano mexicano para este tipo de encargo. Contratar Fase 0
y Fase 1 juntas cuesta **MXN 40,000**, que es el piso de la banda de "revisión
completa" para una boutique.

### 2.3 Fase 2 — Explotación Limitada

| Campo | Contenido |
|---|---|
| **Nombre comercial** | Explotación Limitada (Fase 2) |
| **Objetivo del cliente** | «Tengo hallazgos altos confirmados y necesito demostrar el impacto real: para priorizar internamente, para justificar una inversión ante la junta, para una póliza de seguro cibernético o para una revisión de un tercero.» |
| **Duración** | 5–8 días hábiles de calendario; **la ejecución técnica ocurre en una ventana de 3 horas** (típicamente de noche o fin de semana), con ventana de respaldo acordada |
| **Personal** | **2 personas mínimo**: auditor ejecutor + analista de apoyo (evidencia, registro, notas). **El responsable técnico del cliente está presente y da el "go" durante toda la ventana.** Sin eso, la fase no se ejecuta. |
| **Carga de trabajo estimada** | 16–28 h (⚠️ ilustrativa; la ventana de ejecución son 145 min de tiempo activo autorizado según el addendum, el resto es preparación, coordinación y redacción) |
| **Modalidad** | **ACTIVA-A** (activa controlada): la única modalidad que este playbook admite, y sólo con addendum de RoE específico firmado por las tres partes |
| **Entregables** | 1) Anexo de explotación limitada (sección nueva del informe técnico) con tabla de hallazgos explotados, ficha por hallazgo con evidencia enmascarada, **impacto real vs. impacto máximo teórico**, sección **«Lo que NO se hizo»**, datos reales expuestos (SI/NO + categoría, **nunca el valor**), limitaciones, plan de remediación priorizado por ICE y re-test. 2) Registro de acciones de Fase 2 (CSV) con las seis técnicas, incluidas las refutadas y las no ejecutadas. 3) Declaración de limpieza firmada. 4) Sesión de cierre de 60 min. |
| **Incluye** | Las **seis técnicas acotadas**, una por una y sólo sobre hallazgos ya identificados en Fase 1: **T1** IDOR/BOLA con cuentas de prueba (variante de escritura sólo en entorno de pruebas designado por escrito); **T2** SQLi no destructivo por comparación booleana, sin `UNION`, sin consultas apiladas, sin extraer filas, sin contar registros; **T3** XSS con payload inocuo contra la cuenta propia del auditor; **T4** bypass de control de acceso administrativo con cuenta admin de prueba y cuenta de paciente; **T5** confirmación de fichero de backup expuesto leyendo **1 KB** con `Range`, sin descargar el fichero; **T6** validación de una credencial expuesta con **una sola** llamada de lectura a la API que el cliente indique por escrito · Ejecución bajo **"go" por prueba** · Ventana horaria acordada y contacto de emergencia en ambos lados · Registro de acciones completo con hora, cuenta, huella y rollback · Anexo con **«Lo que NO se hizo»** · Declaración de limpieza firmada |
| **Excluye (explícitamente)** | **No hay denegación de servicio, ni estrés, ni pruebas de carga** · **No hay escritura, modificación ni borrado de datos de producción** (la única escritura posible es 1 artefacto propio en el entorno de pruebas designado) · **No hay acceso a cuentas de terceros**: ni personal, ni pacientes, ni proveedores · **No hay extracción de datos personales ni clínicos**: ni una fila, ni un conteo · **No hay persistencia**: sin webshells, sin tareas programadas, sin usuarios creados, sin claves nuevas · **No hay movimiento lateral** ni sondeo de infraestructura de terceros · **No hay cracking de hashes, ni bypass de MFA, ni ingeniería social al personal** · **El secreto encontrado no se usa más allá de la validación de lectura autorizada ni se comunica a ningún tercero** · **No es un pentest completo ni una simulación de intrusión** |
| **Qué NO se puede prometer** | Que se vaya a "entrar al sistema" — no hay acceso persistente y no se busca · Que se vaya a obtener o demostrar la cantidad de datos expuestos: **contar también está prohibido** · Que la prueba sirva para un informe pericial o para una denuncia: es evidencia técnica de remediación, no peritaje · Que se pueda repetir en cualquier fecha: depende de la ventana y de las cuentas de prueba del cliente · Que el resultado sea idéntico en otro sitio: es evidencia de **este** activo en **esta** ventana |
| **Precondiciones (todas obligatorias; si falta una, la fase no se ejecuta)** | 1) RoE base firmado y vigente. 2) **Addendum de Fase 2 firmado por las tres partes** (cliente, responsable técnico y auditor), con las técnicas marcadas una por una como autorizadas o rechazadas — **el cliente puede rechazar técnicas; las rechazadas se reportan como *no ejecutadas*, nunca como *no encontradas*.** 3) Cuentas de prueba del cliente verificadas como sintéticas: al menos dos de paciente, una de administrador y una del auditor. 4) Ventana horaria acordada y contacto de emergencia probado en ambos lados. 5) Para T6: endpoint de lectura autorizado **indicado por escrito**. 6) Para T1-B: entorno de pruebas designado por escrito; si no se designa, la variante no se ejecuta y se reporta como no ejecutada. 7) Continuidad del responsable técnico durante la ventana: **sin "go", no hay prueba**. |
| **Precio** | **MXN 60,000** (rango 50,000–85,000) |

**Fundamento del precio (del archivo comercial):** una prueba de penetración con
explotación y credenciales provistas por el cliente se cotiza en un rango de
USD 5,000–15,000 en consultoría independiente. **Esta fase se cotiza por debajo
de ese rango a propósito**, y la razón es el alcance: seis técnicas acotadas,
sin carga, sin extracción de datos, sin persistencia y con una ventana de tres
horas. No es un pentest, y no se factura como un pentest.

### 2.4 Las tres prohibiciones que aparecen en los tres paquetes

Están en los tres, en todos los casos, y no se levantan por consecuencia del tamaño
del cliente:

1. **No se abre, copia, transcribe, resume ni cuenta** ningún dato de paciente
   o de un tercero.
2. **No se ejecuta ninguna acción con efecto sobre el servicio** en Fases 0 y 1;
   en Fase 2, sólo las seis técnicas enumeradas, en la ventana y con "go".
3. **No se comunica la información encontrada a ningún tercero** sin
   autorización escrita del cliente, y no se reutiliza en material comercial ni
   en formación.

Ver §4.h para el tratamiento contractual de estas tres.

---

## 3. La escalera de valor y cómo se vende la progresión

### 3.1 Por qué el cliente de Fase 0 casi siempre necesita Fase 1

No es venta por embudo. Es que **las dos fases responden a preguntas
distintas y una sin la otra no sirve**:

> **Tu Fase 0 te dice que hay 12 problemas. Fase 1 te dice cuáles son reales y
> cuáles son ruido. Fase 2 te dice qué pasa si no los arreglas.**

La progresión se sostiene sobre tres hechos que el cliente no puede obtener de
otra forma:

| Hecho | Por qué importa comercial y técnicamente |
|---|---|
| **La Fase 0 produce candidatos, no hallazgos.** Una ruta que devuelve 200 puede ser un soft-404; una versión dentro de un rango vulnerable puede no ser alcanzable; un backup "expuesto" puede ser una plantilla. | El cliente paga por saber qué tiene que arreglar **antes** de pagar un arreglo: si se compra una remediación sobre un falso positivo, la confianza se pierde y no vuelve. |
| **La Fase 1 produce la cola de trabajo ejecutable** (ICE, dueño, horas, tickets) y la **capa legal con cita**, que es lo que un dueño de clínica puede entregar a su aseguradora, a su junta o a su abogado. | Sin Fase 1, el cliente tiene una lista de rutas y una sensación de miedo. Con Fase 1 tiene un plan con horas. El plan es lo que se compra en un retainer y lo que se renueva. |
| **La Fase 2 convierte severidad en impacto** y da la evidencia que un tercero (aseguradora, auditor externo, junta) exige. | El cliente tiene hallazgos altos confirmados y no sabe por dónde empezar; la Fase 2 le da el **impacto real vs. el máximo teórico**, que es el argumento que mueve presupuesto. |

**El argumento de venta, en una línea:** *«La Fase 0 es un mapa. El mapa no
explica por qué tu sitio de citas manda el expediente del paciente a un
endpoint que no controlas. Eso lo responde la Fase 1, con la norma citada.»*

### 3.2 La progresión completa, vista como producto

```
   FASE 0                      FASE 1                       FASE 2
   MXN 12,000                 MXN 28,000                   MXN 60,000
       │                          │                            │
       ▼                          ▼                            ▼
  Qué existe y              Qué está mal,                Cuánto cuesta
  qué está expuesto    →    con evidencia y           →   de verdad y qué
                             con la norma                    se arregla primero
       │                          │                            │
       │                          │                            ▼
       │                          │                     RE-TEST  MXN 12,000
       │                          │                     (¿funcionó el arreglo?)
       │                          │                            │
       │                          └──────── RETAINER MXN 4,000–12,000/mes
       │                                    (vigilancia continua)
       └──────────────────────────────────── RUTA COMPLETA: MXN 90,000
                                            (10 % de descuento sobre el total)
```

**El orden natural es ese, y la razón es de eficiencia, no de venta:** sin
Fase 0, la Fase 1 empieza desde cero y cobra por el mismo recon otra vez. Sin
Fase 1, la Fase 2 no tiene sobre qué demostrar el impacto: se demuestra el
impacto de lo que ya se sabe que está mal, no se buscan cosas nuevas. **Si la
Fase 1 no dejó ningún hallazgo alto abierto, la Fase 2 no aporta** y lo que
conviene es un re-test o un retainer.

### 3.3 Guion de la llamada de venta (30 minutos)

**Objetivo de la llamada: no cerrar. Conseguir que el cliente autorice una
Fase 0 y firme el RoE.** La propuesta comercial va después, con el RoE
adjunto.

---

**Apertura (2 min).** Presentación y encuadre en una frase:

> *«Hago revisiones de seguridad autorizadas de sitios web, no pentests. Trabajo
> con un documento de reglas que firma usted antes de que yo toque nada, y entrego
> tres documentos: un resumen para usted, un informe técnico para su hosting o su
> agencia, y un plan de arreglo con horas. Lo primero es entender si esto le
> sirve; no le voy a pedir una decisión hoy.»*

**Bloque 1 — El problema en su lenguaje (8 min).** Preguntas, no discurso:

- *¿Quién ve el sitio hoy?* (¿El sitio es el canal de pacientes o es un folleto?)
- *¿Cuándo fue la última vez que alguien revisó la seguridad?* (casi siempre: nunca, o antes de cambiar de hosting/agencia)
- *¿Quién administra el sitio y quién tiene las claves?* (define el alcance real del RoE y la mitad de las escalaciones)
- *¿Tienen datos de pacientes en el sitio o en formularios que salen a otro servicio?* (esto abre el marco de datos sensibles con una frase, sin alarmismo)

**Bloque 2 — Qué es y qué no es (8 min).** Aquí se gana o se pierde el negocio:

> *«Esto no es una prueba de penetración. No vamos a romper nada, no vamos a
> entrar a cuentas, no vamos a tocar datos de sus pacientes. Vamos a medir qué
> está expuesto, a confirmarlo contra la fuente oficial de cada componente, y a
> darle un plan ordenado por lo que quita más riesgo por hora de trabajo.»*

Y la frase que más confianza genera en un cliente de salud:

> *«El informe técnico no se lo mando a usted, sino a su equipo técnico, a su
> hosting o a su agencia. Usted recibe el resumen y el brief. Los datos de
> pacientes que se encuentre, si se encontrara alguno, se reportan sin
> contenido y no se guardan.»*

**Bloque 3 — La escalera y el primer paso (8 min).** Un solo paquete en la mesa:

> *«Hay tres formas de trabajar esto. La primera —la Fase 0— es un mapa de
> superficie: qué está expuesto y qué hay que arreglar primero. La segunda
> valida ese mapa uno por uno contra la fuente oficial y añade el mapeo legal,
> con el informe que puede mandar a su hosting. La tercera, si tiene hallazgos
> altos confirmados, demuestra el impacto en una ventana de tres horas, por
> escrito, con usted autorizando cada prueba. Lo que tiene sentido para empezar
> es la primera, y con lo que salga decidimos si hace falta la segunda.»*

**Cierre (4 min).** Compromiso pequeño y verificable:

> *«Le mando la propuesta con el documento de reglas adjunto. Si lo firma, en
> cinco a ocho días hábiles tiene el mapa y una sesión de entrega de una hora.
> De mi lado necesito un correo con su autorización y un responsable técnico
> disponible para escalar en el momento.»*

**Si pide "más información":** se manda el RoE y la propuesta, no un
documento de credenciales. La credibilidad de este servicio **es** el RoE.

### 3.4 Las 5 objeciones y su respuesta

**1. «Es caro.»**

> *«Va a ver el número al lado del riesgo. Una clínica con un sitio que manda
> expedientes de pacientes a un endpoint que nadie controla tiene un problema
> de datos personales que no se arregla con un plugin barato de WooCommerce. La
> Fase 0 son MXN 12,000 y termina con un plan: qué arreglar primero, cuánto
> cuesta en horas y a quién le toca. Ese plan suele traer cinco o seis
> correcciones de menos de una hora que nadie estaba haciendo. Si después de
> ver el plan decide que no lo continúa, esos cinco arreglos ya los hizo.»*

Internamente: **el precio es de lista y el rango es real** (9–15 k / 22–35 k /
50–85 k). No hay descuento para cerrar: lo que se negocia es el **alcance**, no el
precio por debajo del piso de coste. Y si el cliente pide "más barato", la
herramienta real es **Fase 0 en vez de ruta completa**, no un descuento.

**2. «Mi hosting dice que está seguro.»**

> *«Su hosting le dice que su servidor está bien. Eso es verdad y no es la
> pregunta. Lo que casi nunca se revisa es lo que el sitio expone de sí mismo:
> si hay un archivo de respaldo accesible, si el listado de usuarios del panel
> está abierto, si hay una clave de API en el JavaScript, si el certificado
> comparte con otras veinte marcas de su agencia, si el sitio manda los datos
> del paciente a una cuenta que no es de usted. Eso no lo ve el hosting porque
> no es suyo. El informe técnico va justamente a su hosting para que lo
> arregle.»*

Internamente: el playbook ya tiene esta lección incorporada. En el caso real,
**12 de las filas más graves del registro eran escalaciones que el cliente no
podía ejecutar solo** (hosting y agencia). Decirle al dueño "esto no lo puedes
arreglar tú" es parte del producto.

**3. «No tenemos tiempo.»**

> *«Por eso existe la Fase 0: no necesita su equipo ni acceso al panel. Cinco
> a ocho días hábiles, una hora de su responsable técnico en la entrega y ya.
> Si prefiere no hacer nada todavía, al menos podemos dejar constancia de que
> el sitio no se ha revisado nunca, y eso ya loinco para su aseguradora y para
> una eventual revisión externa.»*

Internamente: la Fase 0 **no requiere acceso al panel** ni logs; el único
requerimiento del cliente es un correo y una hora. La Fase 1 sí es la que
exige más del cliente, y por eso la Fase 1 va después de que el cliente ya
vio valor en la Fase 0.

**4. «No quiero que me hackeen.»**

> *«Ninguna de las fases rompe nada. La Fase 0 y la Fase 1 son peticiones de
> lectura, con un segundo de separación entre cada una y con un User-Agent que
> dice quién soy y cómo contactarme. La Fase 2, que es la única que hace
> pruebas, se hace en una ventana de tres horas que usted elige, de noche o en
> fin de semana, con su responsable técnico en la llamada dando el "go" a cada
> prueba, con un criterio de parada inmediata pactado y con la declaración de
> limpieza firmada al final. Y hay tres cosas que no hacemos nunca, ni si usted
> lo pide: no tocamos datos de pacientes reales, no ejecutamos acciones
> destructivas, y no compartimos ni usamos la información que encontramos.»*

Internamente: el **addendum de Fase 2** (`05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md`)
ya trae todo esto: §4.4 (quién da el "go"), §4.5 (criterios de abort inmediato),
§3 (11 prohibiciones que no se levantan), §5.3 (retención y destrucción) y
§6 (no divulgación).

**5. «¿Y si hay datos de pacientes?»**

> *«Es el motivo por el que existe este tipo de revisión y también la razón por
> la que el procedimiento es tan estricto. Dos cosas: la primera, la auditoría
> no necesita ver datos de pacientes para cumplir su objetivo — necesita ver
> rutas, controles y configuración. Si alguna respuesta trae un dato de
> paciente por error, se descarta sin conservarse, se anota en el registro de
> acciones y se le avisa el mismo día. La segunda, la parte legal: la revisión
> incluye el mapeo de lo que aplica a datos sensibles con la cita de la norma,
> para que su abogado lo revise. Eso es una observación documentada, no una
> asesoría legal; la estrategia legal la decide su abogado con ese insumo.»*

Internamente: §5.2 del addendum (prohibición de registrar PII), §5.1
(minimización: qué se guarda y qué se redacta), §6.3 (escalada inmediata sin
difusión). Y `00-metodologia/como-presentar-resultados.md` §4: **«Lo que ya
está bien» es obligatorio**, porque un informe que sólo enumera problemas se
lee como marketing y destruye la confianza.

### 3.5 Qué se hace cuando la objeción no se resuelve

| Situación | Movimiento correcto | Movimiento **incorrecto** |
|---|---|---|
| El precio no encaja | Bajar a Fase 0. **Nunca** bajar el precio por debajo del piso de coste. | Descuento sobre el alcance sin un cambio de alcance por escrito: es trabajo gratis disfrazado. |
| El hosting dice que no | Pedir el nombre del producto del hosting y documentarlo en el informe. | Dejar la Fase sin hacer "porque el hosting dijo que no". |
| No hay tiempo | Fase 0. O retainer ligero al final de la Fase 0. | Aceptar el encargo grande con un plazo que el cliente no va a cumplir: deriva de alcance garantizada. |
| Miedo a que le hackeen | Fase 0 y 1, carta de autorización y RoE firmado. | Ofrecer Fase 2 para "que veas que no pasa nada". Eso es peor: es Fase 2 para demos. |
| Preocupación por datos | Fase 0 y 1, más el anexo de tratamiento de datos (§4.d). | Ofrecer "accedemos a la base de datos para verificar que está bien". **Nunca.** |

---

## 4. Contratación y marco legal: qué hay que tener resuelto ANTES de vender

Este es el bloque que decide si el negocio es una consultoría o un problema.
**Ninguna fase se vende antes de que su marco esté resuelto.** Lo que sigue es
orientación operativa: para la parte legal hay que involucrar a un abogado
(§4.i).

### 4.a Autorización escrita y RoE firmado, por engagement

**Estado de hecho.** El playbook separa tres modalidades y cada una exige su
propio papel:

| Modalidad | Qué autoriza | Documento | ¿Hace falta firma? |
|---|---|---|---|
| **PASIVA** | Sólo fuentes de terceros y lo ya público | RoE base | Sí |
| **ACTIVA-L** | Peticiones de lectura (`GET`/`HEAD`), ≥1 s, UA honesto | RoE base | Sí |
| **ACTIVA-A** | Pruebas controladas de la Fase 2 | RoE base **+ addendum de Fase 2** | Sí, **por las tres partes** |

**Documentos del repositorio que lo gobiernan:**

| Documento | Qué aporta |
|---|---|
| [`reglas-de-autorizacion-y-roe.md`](reglas-de-autorizacion-y-roe.md) | La doctrina: 5 prohibiciones duras, ritmo y cortesía, regla de decisión para hallazgos de terceros, y la **plantilla de RoE** que hay que rellenar y firmar. |
| [`../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md`](../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md) | RoE relleno con un cliente hipotético: hosts en/fuera de alcance, modalidad, permitido, prohibido, manejo de datos, cláusula de terceros, firmas, check-list de arranque. |
| [`../05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md`](../05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md) | Addendum de Fase 2: las 6 técnicas con su condición de ejecución, 11 prohibiciones que no se levantan, ventana, participantes, criterio de abort, minimización, retención, no divulgación, casillas de rechazo de técnicas y firmas. |
| [`../01-tooling/scripts/authorization.example.json`](../01-tooling/scripts/authorization.example.json) + [`scope_guard.py`](../01-tooling/scripts/scope_guard.py) | La traducción **técnicamente exigible**: `scope_guard.py` aborta si el host no está en la lista, si el RoE no tiene firma, si se pide un método distinto de GET/HEAD, si el intervalo es menor de 1 s o si el UA suplanta un navegador. |

**Reglas operativas que no se negocian:**

1. **RoE firmado antes de la primera petición.** No hay excepción. Un "sí,
   sigue" por correo vale si queda registro escrito; un WhatsApp no vale.
2. **El RoE es por engagement, no por cliente.** Si cambia el alcance (hosts,
   técnicas, ventana), **se modifica y se firma**. El addendum de Fase 2 no
   sustituye al RoE base: lo amplía en un punto concreto y deja el resto
   intacto.
3. **El alcance es por FQDN exacto**, no "su empresa". Los comodines
   (`*.ejemplo.mx`) no cubren el apex. Los hosts de terceros (hosting, agencia,
   API de reservas) se declaran **fuera de alcance** y se describen, no se
   atacan.
4. **El RoE identifica quién firma y con qué facultad.** La formación lo pide
   explícitamente (`04-formacion/03-modelo-de-negocio-y-legal-mx.md` §1.2):
   quién firma, con qué facultad, y evidencia de esa facultad (poderes,
   contrato). Un RoE firmado por alguien sin facultades es papel que no
   protege.
5. **El RoE se archiva con la evidencia.** Es la primera línea de defensa y lo
   que la aseguradora pedirá.

**Lo que el RoE no puede hacer:** authorizing a un tercero. El RoE del
cliente autoriza al auditor sobre los hosts del cliente. No autoriza al
auditor sobre el hosting, sobre la agencia, sobre los demás inquilinos del
servidor compartido, ni sobre los pacientes. (Ver §4.b y §4.g.)

### 4.b Responsabilidad civil y penal del tester: la línea que separa el oficio del delito

**Por qué esto no es negociable.** El acceso no autorizado a un sistema de
información es una conducta tipificada penalmente en México y en España. En
México, el marco de referencia del playbook es la **Ley Federal de
Penalizaciones en Materia de Cibernética**, cuyo artículo 6 tipifica el acceso
a sistemas de información sin autorización del propietario o del usuario
legítimo; los artículos 7 a 11 cubren daño a sistemas, interceptación de
comunicaciones, uso malicioso de credenciales, manipulación o introducción de
código malicioso y suplantación de identidad. En el Código Penal Federal
aplicable se suman, entre otros, el fraude por medios electrónicos
(art. 388 Bis), la violación a la correspondencia (art. 173), el hurto
(art. 365) y el daño (art. 367).

> **⚠️ NO VERIFICADO — toda la numeración de artículos de este párrafo.**
> No he leído el texto vigente de ninguna fuente primaria en este entorno. Lo
> anterior está transcrito del marco que el propio playbook documenta
> (`04-formacion/03-modelo-de-negocio-y-legal-mx.md` §2.1), y ese documento
> advierte explícitamente que hay que **descargar el texto vigente antes de
> citar artículos**.
> **Fuentes primarias que hay que leer antes de usar esto comercialmente:**
> - Ley Federal de Penalizaciones en Materia de Cibernética — texto vigente en
>   el DOF y en `diputados.gob.mx/LeyesBiblio/` (buscar "Ley Federal de
>   Penalizaciones en Materia de Cibernética").
> - Código Penal Federal — texto vigente en `diputados.gob.mx/LeyesBiblio/pdf/CPF.pdf`.
> - En España: Código Penal, Ley Orgánica 10/1995, título sobre delitos
>   informáticos (el artículo 197 y siguientes tipifican daños a sistemas
>   informáticos y tipificados aquí). **NO VERIFICADO**: no he leído el texto consolidado
>   en BOE. Fuente primaria: `boe.es` → LO 10/1995, texto consolidado.
> **Nunca copies estos números a una propuesta comercial sin abrirlos.**

**Qué protege la autorización escrita.** Es la frontera, y funciona en una
sola dirección: te protege de la acusación de haber actuado **sin
autorización**, es decir, del artículo de acceso no autorizado. Para que
proteja tiene que ser:

1. **Escrita** (no verbal, no por mensaje).
2. **Del titular o de quien tenga facultad expresa** para autorizar.
3. **Identificada en sistemas exactos** (FQDN), no "la empresa del cliente".
4. **Con técnicas enumeradas una por una** y una lista de prohibiciones.
5. **Con ventana de ejecución y contacto de emergencia**.
6. **Con tu nombre y el del auditor** (quién va a tocar y a qué hora).
7. **Con vigencia temporal** y con copia archivada.

> **El mejor resumen operativo:** *la autorización escrita no es un permiso
> genérico, es un permiso con forma.* Un correo que dice "sí, haz lo que
> necesites" **no tiene forma**: no identifica sistemas, ni técnicas, ni
> ventana. Con ese correo, el auditor está exactamente en la misma posición
> jurídica que sin él, y además pierde el activo probatorio.

**Qué NO protege la autorización escrita.** Esto es lo que hay que explicar en
la primera reunión, porque es donde se cae la_naive:

| No cubre | Por qué | Qué hacer en su lugar |
|---|---|---|
| **Actuar fuera del alcance** (un host no listado, una técnica no enumerada, una prueba fuera de la ventana) | Fuera del alcance = fuera de la autorización. El papel no se estira por cortesía. | Regla del playbook: **si no está listado, se para y se pregunta**. Se modifica el RoE y se firma. |
| **Causar daño por negligencia** (una prueba que degrada el servicio, un artefacto que no se limpia, un correo disparado por un formulario) | La autorización es un permiso de actuar, **no una exención de responsabilidad**. El daño causado sigue siendo responsabilidad contractual y civil del auditor (responsabilidad civil profesional y theory del daño, Código Civil Federal). | Criterio de abort inmediato, ventana, "go" por prueba, declaración de limpieza, y **seguro de RC profesional** (§4.c). |
| **Tocar datos de terceros** (pacientes, personal, otros inquilinos del hosting compartido) | La autorización es del **dominio del cliente**, no de las personas ni de los terceros que hay dentro. | Regla 1.2 del RoE: se reporta la existencia de la ruta, no se solicita su contenido. Minimización y redacción (`pii_redact.py`). |
| **Reutilizar o divulgar la información encontrada** | La autorización es para esa auditoría, no para el marketing de otra. | Cláusula de confidencialidad y no divulgación (§4.e) + compromiso de no reutilización en material comercial o formación. |
| **Reutilizar el secreto encontrado** para otra cosa | La credencial expuesta sólo se usa una vez, en modo lectura, sobre el endpoint que el cliente indique por escrito. | Addendum de Fase 2 §3.10 y T6. |
| **El incumplimiento del propio cliente** (el RoE firmado por alguien sin facultad; el cliente miente sobre la titularidad del dominio) | El RoE es un.safe harbor, **no un seguro**. El cliente declara ser titular o tener autorización de los titulares; el auditor no puede verificarlo. | Cláusula de declaración de titularidad/autorización del cliente, y evidencia de la facultad de quien firma. |

**La línea de la documentación legal tiene que ser visible en el contrato**, en
tres frases: (a) qué se autoriza y hasta cuándo; (b) qué no se autoriza;
(c) qué pasa si el alcance cambia.

### 4.c Seguro de responsabilidad civil profesional (RC / E&O)

**Por qué se necesita.** Porque lo anterior no es lo mismo. El contrato reparte
el riesgo; **el seguro lo absorbe**. Sin seguro:

- Un error propio (una sonda que golpea más fuerte de lo debido, una cabecera
  mal formada, un artefacto que no se limpió) es un pasivo personal ilimitado.
- Ante un cliente de salud, un cliente potential no compra a un consultor sin
  cobertura: **es un requisito de credibilidad, no un requisito legal**.
- La aseguradora del cliente (y el propio RoE firmado) exigirán la póliza
  vigente: es exactamente lo que el playbook pide guardar.

**Cobertura mínima que hay que tener contratada** (ajustar a la póliza real,
no a este texto):

| Elemento | Mínimo razonable | Comentario |
|---|---|---|
| **Ramo** | Responsabilidad civil profesional (E&O / Errors & Omissions) — y, por separado, RC por incidentes cibernéticos | Son dos ramos distintos. El primero cubre el error profesional; el segundo, el incidente. |
| **Actividad declarada** | «Consultoría de seguridad de la información / revisión autorizada de seguridad web», **declarando que la revisión se realiza bajo RoE firmado** | El playbook ya lo recomienda: pedir que describan la actividad así y declarar el RoE. Muchas pólizas excluyen *pentest* o el sector healthcare/medical: **hay que leer la exclusión antes de firmar**, no después. |
| **Límite de indemnización** | Suficiente para el tamaño de los encargos que aceptas y para el daño plausible más grave que puedes causar | Los rangos que el playbook maneja como referencia interna van de MXN 1 a 5 millones para RC profesional individual, y de USD 1 a 10 millones para cyber/RC cibernético. **⚠️ NO VERIFICADO**: son rangos transcritos de `04-formacion/03-modelo-de-negocio-y-legal-mx.md` §2.4, no cotizados en este entorno. **La fuente primaria es el corredor de seguros y la póliza misma**, no este documento. |
| **Prima** | Referencia interna del playbook: **MXN 8,000–35,000/año** para RC profesional de un consultorio individual, y **MXN 25,000–120,000+** para cyber/RC. **⚠️ NO VERIFICADO**: no hay cotización en este entorno. | Cotizar con corredor que entienda E&O tecnológico y tener a la mano RoE firmado, contrato, CV y política de datos. |
| **Vigencia** | Vigente **durante** la ejecución y **hasta el final del plazo de retención de la evidencia** | Un seguro que expira el día de la entrega deja descubierto el periodo de reclamaciones. |
| **Franquicia** | La más baja que se pueda | En un consultorio individual la franquicia se paga de tu bolsillo. |

**Qué hay que tener resuelto antes de vender:**

- Póliza de RC profesional contratada, con la actividad bien declarada.
- Si se va a vender Fase 2 (explotación), confirmar por escrito con la
  aseguradora que la actividad está cubierta **y** que el sector del cliente
  (salud) no está excluido. **Si la excluye, o vendes Fase 2 sin seguro o no
  vendes Fase 2.** No hay tercera opción.
- Procedimiento de aviso de siniestro a la aseguradora (plazo) en la carpeta de
  cada engagement, con la persona responsable de dar el aviso.

> **⚠️ NO VERIFICADO:** todos los números de prima y de límites de este
> apartado son rangos internos transcritos del playbook (§2.4 de
> `04-formacion/03-modelo-de-negocio-y-legal-mx.md`), no cotizaciones
> verificadas. Lo que hay que consultar: la póliza y el corredor de seguros.
> Lo que **no** hay que hacer: prometer en una propuesta que "estamos
> asegurados" sin tener la póliza vigente a la vista.

### 4.d DPA / contrato de tratamiento de datos

**El problema.** Si el auditor llega a **acceder a datos personales** del
cliente —porque una Fase 2 toca una respuesta con un dato de paciente, porque
el cliente comparte logs con correos y teléfonos, o porque una credencial
expuesta expone un directorio con nombres—, el auditor **no sale limpio de la
posición de "sólo consulta"**. Entra en una relación de tratamiento de datos.

**Posiciones que hay que resolver por escrito en el contrato:**

| Posición | Qué se pacta | Nota |
|---|---|---|
| **¿El auditor trata datos personales?** | En Fases 0 y 1, la regla es que no: sólo se reportan de forma agregada, con minimización y redacción. En Fase 2, está prohibido explícitamente; si por error aparece un dato, se descarta, se anota y se avisa. | El playbook ya lo resuelve en la técnica (§5.1, §5.2 del addendum). |
| **Rol del auditor** | En términos de GDPR (ES/UE), el auditor puede ser **encargado** del tratamiento (art. 28) si trata datos por cuenta del cliente; o **independiente** si determina finalidades y medios. En México, la LFPDPPP obliga al responsable aitech — | **NO VERIFICADO**: la numeración de artículos y la configuración vigente de la LFPDPPP (que según `04-formacion/03` fue sustituida por un ordenamiento publicado en el DOF en 2025, con cambio de autoridad) hay que leerlas en la fuente primaria: `diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf` y el DOF. |
| **Finalidades yudget** | El auditor trata datos **sólo para ejecutar la auditoría y sólo con las instrucciones documentadas del cliente**. Nada de reutilización, nada de mejora del producto, nada de "aprendizaje". | Es la columna vertebral del anexo de tratamiento. |
| **Subencargados y herramientas** | Si el auditor usa un SaaS, un repositorio o un servicio externo para procesar evidencia (hosting del expediente, gestor de tickets, IA de apoyo), hay que declararlos o garantizar que no los usa. | **Decisión interna que hay que tomar antes de vender**: ¿la evidencia vive en un servidor de terceros? Si sí, ese tercero es subencargado y hay que decirlo. |
| **Medidas de seguridad** | Cifrado en reposo y en tránsito de la evidencia, control de acceso, registro de accesos, política de retención. | `pii_redact.py` es la herramienta que materializa la minimización; el cifrado del expediente es una decisión de infraestructura que hay que documentar. |
| **Notificación de incidentes** | Si durante la auditoría aparece un incidente de seguridad que afecta datos personales, el auditor **notifica al cliente de inmediato** y **no difunde**. | El addendum §6.3 ya lo fija: escala inmediata, notificación escrita en plazo corto definido, sin contactar a la autoridad por cuenta propia. La decisión sobre notificación a titulares y a la autoridad la toma el cliente con su asesoría legal. |
| **Fin del encargo** | Devolución o destrucción de la evidencia al término del plazo de retención, con confirmación escrita. | Ver §4.f. |
| **Ubicación de los datos** | Dónde se procesa y dónde se guarda la evidencia (país, infraestructura). Relevante si el cliente tiene obligaciones de transferencia. | En el caso real, la geolocalización del hosting ya resultó ser un hallazgo de cumplimiento en sí mismo. |

> **⚠️ NO VERIFICADO — bloque legal completo.** No he leído en este entorno
> ninguna fuente primaria de: RGPD (Reglamento (UE) 2016/679) ni LOPDGDD
> (Ley Orgánica 3/2018) ni sus artículos sobre encargado, medidas de seguridad
> y notificación de brechas; ni los plazos que esos textos fijan (por ejemplo,
> el plazo de notificación a la autoridad de control); ni el articulado vigente
> de la LFPDPPP mexicana ni de la NOM-004-SSA3-2012 sobre expediente clínico.
> **Fuentes primarias que hay que consultar:**
> - RGPD — EUR-Lex (`eur-lex.europa.eu`), texto oficial del Reglamento (UE)
>   2016/679; para el texto consolidado en España, BOE.
> - LOPDGDD — BOE, Ley Orgánica 3/2018.
> - LFPDPPP — `diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf` + el DOF de la
>   reforma vigente. **La numeración de artículos y la autoridad competente
>   cambian con las reformas: verifícalas cada vez.**
> - NOM-004-SSA3-2012 — DOF.
> En España, además, conviene revisar la **LSSI-LGDD** (Ley 34/2002) y la
> **RGPD** en su aplicación a las NTIC.
> **Todo esto lo redacta y valida un abogado. Este apartado es la lista de
> qué preguntar, no la respuesta.**

### 4.e Cláusula de confidencialidad y no divulgación

Es la cláusula que más peso tiene en salud, y la que más souvent se olvida.

**Contenido mínimo:**

1. **La evidencia y los informes son confidenciales**, y el informe técnico
   **no se envía al cliente final ni a terceros** sin autorización escrita
   (destinatario: equipo técnico / hosting / agencia).
2. **No difusión**: sin publicar capturas, sin pegarlas en tickets abiertos,
   sin usarlas como ejemplo en publicaciones, sin redes, foros, wikis, grupos
   de mensajes ni presentaciones (addendum §6.1).
3. **No contacto con terceros**: sin comunicar hallazgos a hosting, agencia,
   certificadoras o auditorías ajenas sin autorización escrita previa (addendum
   §6.2).
4. **No reutilización**: el material del cliente no se reutiliza en otro
   encargo, en material comercial ni en formación, salvo autorización escrita
   (addendum §6.4). **Esto tiene una consecuencia operativa que hay que
   asumir desde el día uno: §6.e de escalabilidad dice que los casos sirven
   para vender, pero sólo en forma anonimizada y con permiso.**
5. **Supervivencia**: la confidencialidad sobrevive a la finalización del
   encargo.
6. **Excepciones**: lo que la ley exige (obligación legal o de autoridad
   competente) — y el compromiso de avisar al cliente lo antes posible, salvo
   que la ley lo prohíba.

### 4.f Cadena de custodia de la evidencia, retención y destrucción

**Cadena de custodia.** Es la pregunta "¿de dónde sale esta evidencia y quién
la ha tenido?". El playbook ya la resuelve por diseño:

| Elemento | Cómo está resuelto en el playbook |
|---|---|
| **Origen** | Cada afirmación apunta a un archivo de evidencia (`ciclo-de-auditoria.md`, "regla de oro"). Sin archivo, no hay hallazgo. |
| **Integridad** | Los nombres de archivo son por contenido, no por herramienta. Los **falsos positivos se conservan** (`tls_floor.txt`): una carpeta donde todo salió bien a la primera es sospechosa. |
| **Registro de acciones** | `05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv` y `registro-de-acciones-fase-2.csv`: id, fecha_hora, host, endpoint, técnica, método, cuenta usada, tipo de cuenta, datos tocados, resultado, archivo de evidencia, footprint, rollback, severidad, estado, notas. |
| **Hash / no alteración** | La evidencia cruda se conserva; la sanitizada se genera como **copia** (`pii_redact.py --out-dir`), nunca sobrescribiendo el original. Los secretos se enmascaran en el momento de guardarlos (prefijo + sufijo + `sha256[:12]`), no en la redacción posterior. |
| **Acceso** | Carpetas de caso por cliente (`03-casos/<cliente>/evidencia/`). **La carpeta `03-casos/clinica-dental-easy/` es confidencial.** |

> **⚠️ Inconsistencia a resolver antes de vender (no se modifica aquí):** los
> plazos de retención **no coinciden** entre documentos. El RoE de ejemplo
> (`alcance-y-roe.EJEMPLO.md` §6) fija **12 meses** tras la entrega para la
> evidencia general, mientras que el addendum de Fase 2 §5.3 fija **30 días
> naturales** para la evidencia de Fase 2, con destrucción o anonimización
> verificable y confirmación escrita al cliente. Son compatibles (la evidencia
> de Fase 2 se destruye antes), pero **hay que decirlo así explícitamente en el
> contrato** para que no parezca una contradicción. Y hay que fijar en el
> contrato principal el plazo aplicable a Fases 0 y 1, que hoy sólo existe en
> un ejemplo.

**Retención y destrucción — el bloque que va al contrato:**

| Concepto | Regla recomendada |
|---|---|
| **Retención de la evidencia (Fases 0 y 1)** | Un plazo fijo y escrito, contado desde la entrega. **Nada de "hasta que se borre el caso"**: sin plazo no hay control. |
| **Retención de la evidencia de Fase 2** | 30 días naturales desde la entrega del anexo, con destrucción o anonimización verificable. |
| **Excepciones** | Sólo lo que el cliente pida expresamente conservar para su propio expediente (p. ej. la copia enmascarada de la credencial expuesta). |
| **Entrega** | El cliente recibe la evidencia **enmascarada** y el registro de acciones. Las capturas originales con valores completos **no se entregan**: se archivan con el auditor hasta el fin del plazo. |
| **Confirmación** | Al cumplirse el plazo: destrucción o anonimización **verificable** y confirmación **escrita** al cliente. |
| **Cambio de alcance** | Si el alcance del encargo cambia, se modifica el RoE y **se firma**; no se extiende el alcance de hecho. |

### 4.g Qué pasa si el cliente pide algo ilegal

El caso que el cliente trae a la mesa: *«demuestra que puedes entrar a la cuenta
de mi socio»*.

**La regla:** hay que poder decir que no **sin perder el encargo**. Eso exige
que el "no" esté en el contrato desde el principio, no que sea un improviso.

**Procedimiento de escalado, en cuatro pasos:**

| Paso | Acción | Salida |
|---|---|---|
| **1. Reconocer y clasificar** | Determinar qué se pide exactamente: ¿acceso a una cuenta de un tercero (el socio) que no es el sistema del cliente? ¿Es un tercero con relación contractual? ¿Hay autorización del titular de esa cuenta? | Clasificación interna. **Si la cuenta es de un tercero que no ha autorizado, es "no".** |
| **2. No en la primera reunión** | No se ejecuta y no se promete en la llamada. Se responde con la pregunta correcta: *«¿el socio ha autorizado por escrito? ¿la cuenta es del negocio o personal?»* | Pregunta documentada en el expediente. |
| **3. Negativa documentada** | Si no hay autorización del titular, se **declina por escrito y se documenta**. El contrato prevé que el auditor puede negarse a una prueba que exceda el alcance o que sea ilegal, sin que ello rompa el encargo ni la facturación de lo ya entregado. | Correo de negativa, archivado. |
| **4. Sustitución** | Se ofrece lo que **sí** es posible dentro del alcance: demostrar el control de acceso sobre **cuentas de prueba** que el cliente designe; medir el impacto de un fallo de control de acceso con datos sintéticos; o escalar el caso al responsable legal del cliente. | Prueba de impacto legítima, entregada. |

**Lo que el contrato tiene que decir explícitamente (cláusula de alcance y de
no ejecución):**

1. El auditor puede rechazar una prueba que no esté en el alcance o que sea
   ilegal, y hacerlo no extingue el encargo ni altera el precio de lo ya
   ejecutado.
2. El cliente **declara** ser titular de los sistemas en alcance o tener
   autorización de los titulares.
3. Lo que se encuentra en un tercero se **describe, no se ataca**, y no se
   comunica al tercero sin autorización escrita del cliente.
4. Los hallazgos que pertenecen a un tercero se reportan como **riesgo de
   terceros** —relación y acción concreta que el cliente debe exigir a su
   proveedor— **sin** entregar datos del tercero. (Es la regla del playbook:
   informar de que existe un riesgo que no es tuyo sí; entregar los datos de
   otro, no.)

**Y el borde que sí se puede tocar:** cuando el "tercero" es un empleado del
propio cliente y la petición es de ingeniería social → **prohibido sin
excepción** (RoE 1.5 / addendum §3.9). Cuando el tercero es un **inquilino del
mismo hosting** → prohibido sondearlo (RoE 1.4 / 1.5). Cuando el tercero es un
proveedor externo del cliente (CDN, API de reservas) → se describe la relación
y se le indica al cliente qué contrato debe exigir; no se audita al proveedor.

### 4.h Las 3 prohibiciones que no se negocian, aunque el cliente insista

Estas tres están en **todos** los paquetes y **no se levantan**. No hay "excepción
por urgencia", ni "excepción por autorización del dueño", ni "excepción por
tamaño del cliente". Si una prueba requiere una de ellas, **la prueba no se
hace y se reporta como no verificada**.

| # | Prohibición | Por qué no es negociable | Dónde está |
|---|---|---|---|
| **1** | **No tocar datos de pacientes reales.** No se descarga, copia, transcribe, resume, cuenta ni almacena ningún expediente, historial clínico, archivo o registro. **Contar cuántos hay también está prohibido.** | Es la línea que separa una auditoría legítima de un incidente causado por el auditor. La autorización del cliente es del **sitio**, no de los pacientes que hay dentro. Un solo dato de paciente retenido convierte el encargo en un problema de protección de datos. | Addendum §3.4, §5.1, §5.2 · RoE 1.2 |
| **2** | **No ejecutar acciones destructivas.** Nada de denegación de servicio, estrés, carga, borrado, modificación de datos de producción, persistencia (webshells, tareas programadas, usuarios creados, claves nuevas), ni movimiento lateral fuera del alcance. La única escritura autorizada es el artefacto único de T1-B en el entorno de pruebas designado, con limpieza obligatoria. | El daño > el hallazgo. Un hallazgo perdido cuesta un email; el daño cuesta el contrato, la aseguradora y una conversación con el paciente afectado. Además, la autorización es un permiso de actuar, **no una exención de responsabilidad**: el auditor responde por el daño que causa. | Addendum §3.1, §3.2, §3.5, §3.6 · RoE §1 y §2 |
| **3** | **No compartir ni explotar la información encontrada.** No se comunica a terceros (proveedores, hosting, agencia, certificadoras), no se publica, no se difunde, no se reutiliza en otro encargo ni en material comercial o formación, y el secreto encontrado no se usa más allá de la validación de lectura autorizada. | La confianza del cliente es el activo del negocio. Un hallazgo que sale del expediente es un hallazgo que se convierte en Material de otro, y entonces ya no puedes cobrarle a nadie por honesto. | Addendum §3.10, §3.11, §6 · RoE §6, §7 |

**Cómo se aplican en la práctica, para que no parezcan retórica:**

- **Prohibición 1 → herramienta.** `pii_redact.py` redacta antes de compartir;
  `secrets_scan.py` nunca escribe el valor completo; el addendum §5.1 define
  qué se guarda y qué se redacta en cada categoría.
- **Prohibición 2 → herramienta + procedimiento.** `scope_guard.py` recorta los
  métodos a `GET`/`HEAD` y aborta fuera de alcance; el addendum define
  ventana, "go" por prueba y **criterio de abort inmediato** (§4.5) con tres
  disparadores: dato de paciente o de tercero en una respuesta, efecto no
  previsto real, o cualquier señal de degradación o alarma.
- **Prohibición 3 → contrato + cláusula.** Addendum §6, RoE §6 y §7, más el
  compromiso de no reutilización en material comercial o formación (§6.e
  abajo).

**Y lo que sí se puede hacer, para que el "no" sea útil:** cada vez que una
prohibición bloquea una prueba, se escribe en el informe **qué se iba a hacer,
por qué no se hizo y cómo puede hacerla el cliente** con su propio equipo. Eso
convierte una limitación en una tarea ejecutable — y es exactamente lo que el
playbook llama «reportar la capacidad, no ejecutar la capacidad».

### 4.i Aviso: esto es orientación operativa, no asesoría legal

**Todo este §4 es orientación de negocio y proceso.** No es asesoría legal, no
es un dictamen, y no reemplaza a un abogado.

- Los artículos, leyes, plazos, sanciones y nombres de norma que se mencionan
  aquí están marcados **NO VERIFICADO** y **no se han leído en fuente primaria
  en este entorno**. Antes de poner cualquiera de ellos en una propuesta, en un
  informe o en una conversación con un cliente, hay que abrir la fuente
  primaria (DOF, `diputados.gob.mx/LeyesBiblio`, BOE, EUR-Lex) y anotar la
  fecha de la última reforma. **Principio 7 del README: nunca cites una ley de
  memoria.**
- La distinción entre **observación verificable** (esto es lo que entrega el
  servicio) y **dictamen jurídico** (esto es lo que entrega el abogado) está
  escrita en el paquete comercial y debe estarlo también en la página de
  precios: «La parte legal es un mapeo a la normatividad aplicable, con cita y
  enlace a la fuente oficial, y una lista explícita de lo que **no** es
  obligación. La interpretación y la estrategia legal las revisa su abogado con
  ese insumo.»
- **Qué hay que pedirle a un abogado antes del primer encargo** (lista de
  preguntas, no conclusión):
  1. Validez de la autorización: ¿qué documento y qué firma sí acreditan
     autorización suficiente en MX y, si aplica, en ES?
  2. Configuración del contrato: ¿el auditor, ¿es encargado del tratamiento
     de datos o independiente? ¿Qué anexo hace falta?
  3. Riesgo penal: ¿la redacción del addendum de Fase 2 y del RoE es
     suficiente para el artículo de acceso no autorizado? ¿Falta algo (p. ej.
     declaración de titularidad, compromiso del cliente de no interferir,
     cláusula de *"safe harbor"*)?
  4. Responsabilidad civil: ¿cómo se limita la responsabilidad del auditor?
     ¿Qué exclusiones (lucro cesante) son defendibles? ¿Qué indemnización es
     razonable?
  5. Confidencialidad y datos de salud: ¿qué cláusulas adicionales exige el
     sector?
  6. Propiedad intelectual y uso de evidencia: ¿el cliente es titular del
     informe? ¿puede el auditor usarlo como caso anonimizado? (esto tiene que
     estar escrito, no supuesto: §4.e)
  7. Fiscalidad: ¿qué efectos tiene la relación en México y, si el cliente es
     español, en España? ¿Hay que=[[conversación]] sobre IVA/retenciones? No se
     responde aquí.

---

## 5. Unidad económica del negocio

> **⚠️ TODO EL NÚMERO DE ESTA SECCIÓN ES ILUSTRATIVO.**
> Los números de abajo son **inventados para enseñar el cálculo**. No son
> datos de mercado, no son benchmarks, no provienen de `research/` y no
> describen a ningún competidor. **Sustituye cada variable por tu número real**
> (la columna «qué poner» dice cuál es) y el modelo te da tu margen. El único
> dato que no es inventado es el **precio de lista**, que viene de
> `paquetes-por-fase.md`.

### 5.1 Las variables del modelo

| Símbolo | Qué significa | Unidad | Qué poner (tu número real) |
|---|---|---|---|
| `P_i` | Precio cobrado por el paquete `i` | MXN | El precio de lista, **o el precio con descuento si hay ruta completa** |
| `h_i` | Horas de trabajo **efectivas** del paquete `i` (no las facturables: incluye Reuniones, redacción, coordinación, travelling) | h | Tu promedio real medido (ver §8) |
| `c_hora` | Coste efectivo de tu hora de trabajo | MXN/h | **No es tu salario**: es tu precio de oportunidad. Si tu alternativa es X MXN/h, pon X. |
| `c_herr_i` | Coste de herramientas y servicios del paquete `i` (dominios, VPS, API de terceros, lab, licencias) | MXN | Suma real de un mes ÷ número de paquetes de ese tipo |
| `G_mes` | Gastos fijos mensuales del negocio (seguro RC, contador, teléfono, hosting de tu web, herramientas suscritas, IVA) | MXN/mes | Tu gasto fijo real |
  | `CAC` | Coste de adquisición: horas de venta ÷ horas facturables + cualquier gasto de adquisición | MXN | Calculado en §5.4 |

### 5.2 El cálculo, paso a paso

**Margen bruto de un paquete:**

```
margen_bruto_i  =  P_i  −  (h_i × c_hora)  −  c_herr_i
```

**Margen bruto de un mes (con `n_i` paquetes de cada tipo):**

```
margen_bruto_mes  =  Σ ( n_i × margen_bruto_i )  −  G_mes
```

**Punto de equilibrio — cuántos clientes al mes hay que vender para vivir:**

```
n_clientes_por_mes  =  G_mes  ÷  margen_medio_por_engagement
```

donde

```
margen_medio_por_engagement  =  Σ (n_i × margen_bruto_i)  ÷  Σ n_i
```

**Punto de equilibrio en facturación (alternativa, si prefieres mirar ingresos):**

```
ingresos_mensuales_necessarios  =  G_mes  ÷  margen_medio_por_engagement  ×  precio_medio
```

**Aviso importante sobre la última fórmula:** el orden importa. Primero
`G_mes ÷ margen_medio` da **clientes**; sólo después se multiplica por el
precio medio para obtener **ingreso**. Si divides ingresos por margen,
obtienes ingreso, no clientes. Es un error fácil de cometer y que produce
metas inalcanzables.

### 5.3 Ejemplo trabajado (con variables inventadas y explícitas)

**Valores inventados para este ejemplo:**

| Variable | Valor inventado | Por qué ese número (es una suposición, no un dato) |
|---|---|---|
| `c_hora` | **MXN 400 / h** | Coste de oportunidad: lo que vale tu hora en otra cosa. Inventado. |
| `c_herr_F0` | **MXN 300** | Dominio de pruebas, un VPS pequeño, alguna consulta a API. Inventado. |
| `c_herr_F1` | **MXN 300** | Igual: la mayor parte del coste de esta fase es tu tiempo. Inventado. |
| `c_herr_F2` | **MXN 400** | Más coordinación: ventana, entornos, backups. Inventado. |
| `c_herr_retest` | **MXN 150** | Inventado. |
| `c_herr_retainer` | **MXN 200 / mes** | Inventado. |
| `G_mes` | **MXN 45,000 / mes** | Seguro RC, contador, hosting de tu web, teléfono, servicios suscritos, un VPS de lab. Inventado. |
| `h_F0` | **14 h** | Dentro del rango 10–18 h de §2.0. Inventado. |
| `h_F1` | **26 h** | Dentro del rango 20–35 h. Inventado. |
| `h_F2` | **22 h** | Dentro del rango 16–28 h. Inventado. |

**Aplicación:**

| Paquete | `P_i` | `h_i × c_hora` | `c_herr_i` | **Margen bruto** | Margen % |
|---|---|---|---|---|---|
| Fase 0 | 12,000 | 14 × 400 = 5,600 | 300 | **6,100** | 51 % |
| Fase 1 | 28,000 | 26 × 400 = 10,400 | 300 | **17,300** | 62 % |
| Fase 2 | 60,000 | 22 × 400 = 8,800 | 400 | **50,800** | 85 % |
| **Ruta completa (0+1+2)** | **90,000** | 62 × 400 = 24,800 | 1,000 | **64,200** | 71 % |
| Re-test | 12,000 | 6 × 400 = 2,400 | 150 | **9,450** | 79 % |
| Retainer (punto medio, 8,000/mes) | 8,000/mes | 6 × 400 = 2,400 | 200 | **5,400 / mes** | 68 % |

*Comprobación:* `6,100 + 17,300 + 50,800 = 74,200`; la ruta completa da
`64,200`. La diferencia son **10,000 MXN**, que es exactamente el **10 % de
MXN 100,000** (la suma de las tres fases a precio de lista). El descuento de
ruta **no rompe el margen** con estos números: pasa del 74 % al 71 % de margen
bruto, pero el cliente recibe un 10 % y la conversión sube.

**Punto de equilibrio — cuántos clientes al mes:**

| Composición de un mes | Margen bruto del mes | ¿Llega a G_mes = 45,000? |
|---|---|---|
| 1 × ruta completa | 64,200 | **Sí.** Margen del mes: 64,200 − 45,000 = **19,200** |
| 2 × Fase 0 + 1 × Fase 1 | 29,500 | No (−15,500) |
| 1 × Fase 0 + 1 × Fase 1 + 1 × Fase 2 (a precio de lista, **sin** descuento de ruta) | 74,200 | **Sí.** Margen del mes: 74,200 − 45,000 = **29,200** |
| 3 × Fase 0 + 1 × Fase 1 + 1 × Fase 2 | 86,400 | **Sí.** Margen del mes: **41,400** |
| 1 × Fase 1 + 1 × Fase 2 | 68,100 | **Sí.** Margen del mes: **23,100** |
| 4 × Fase 0 | 24,400 | No (−20,600) |
| 1 × ruta completa + 1 × retainer (8k) | 69,600 | **Sí.** Margen: **24,600** |

**Lectura honesta de esta tabla, que es la parte importante:**

> **Vivir de Fases 0 sueltas no da de comer.** Con estos números, 4 fases 0 al
> mes dejan **−20,600 MXN**. El negocio se sostiene con **una ruta completa al
> mes** o con **una combinación de 1 Fase 1 + 1 Fase 2**. Eso tiene dos
> consecuencias operativas:
>
> 1. **La Fase 0 es un gancho, no el negocio.** Su margen del 51 % es bajo
>    porque su precio es bajo, y su función comercial es conseguir la Fase 1.
> 2. **Si el modelo de negocio se apoya sólo en Fase 0, hay que cambiar el
>    precio de la Fase 0 o el número de paquetes.** Una de las dos. Y eso es
>    una decisión, no un accidente.
>
> **Esto es el argumento cuantitativo detrás de §3: la escalera no es una
> metáfora de venta, es la condición para que el negocio tenga margen.**

**La fórmula que hay que reescribir con tus números:**

```
n_clientes_por_mes  =  G_mes  ÷  margen_medio_por_engagement
```

Si con tus números salen 3 clientes al mes, tu meta del §9 (semana 4: 5
propuestas) es coherente. Si salen 1,5, tu meta de 5 propuestas es una meta
de conversión muy alta y necesitas más leads, no más propuestas. **Haz esta
división antes de fijar objetivos de venta.**

### 5.4 El coste de aprender a vender: la curva de los primeros 3 clientes

Los tres primeros clientes no cuestan lo mismo que el cuarto. El sobrecoste
tiene tres componentes, y conviene estimarlos **separados** para no
confundirlos con el margen:

| Componente | Qué es | Cómo se mide |
|---|---|---|
| **Sobrecoste de ejecución** | Las primeras auditorías tardan más: se reintenta, se pregunta, se relee la metodología. | `h_1 > h_2 > h_3 > h_normal`. Se registra el número real de horas del primer engagement y se usa como línea base. |
| **Coste de venta** | Horas dedicated a vender (llamadas, propuestas, propuestas que no se cierran) + tiempo de aprender a escribir la propuesta y el teaser. | `horas_venta × c_hora` + (lo que cueste la herramienta de propuesta). |
| **Sobrecosto de cumplimiento** | Seguro RC (prima mínima), contador, alta de instancia,(template) de contrato, alta en el bank. | Gastos fijos de arranque, una vez. |

**Ejemplo inventado (los tres primeros clientes, Fase 0):**

| Cliente | `h_F0` real (inventado) | Diferencia vs. `h` normal (14 h) | Sobrecoste a `c_hora` = 400 | Valor de Fase 0 |
|---|---|---|---|---|
| Cliente 1 | **22 h** | +8 h | 3,200 | 12,000 |
| Cliente 2 | **18 h** | +4 h | 1,600 | 12,000 |
| Cliente 3 | **15 h** | +1 h | 400 | 12,000 |
| **Total** | 55 h | **+13 h** | **5,200** | 36,000 |

**Más el coste de venta de ese mismo periodo (inventado):**

| Concepto | Horas (inventado) | Coste (inventado) |
|---|---|---|
| Llamadas de prospección, propuestas escritas, propuestas no ganadas | 40 h | 16,000 |
| Escribir y afinar la propuesta comercial y el teaser (una vez) | 12 h | 4,800 |
| **Total coste de aprender a vender (3 clientes)** | **52 h** | **20,800** |

**Y el resultado, que es el número que importa:**

| Concepto | MXN (inventado) |
|---|---|
| Ingreso de los 3 clientes de Fase 0 | 36,000 |
| Coste de ejecución (55 h × 400) | −22,000 |
| Coste de herramientas (3 × 300) | −900 |
| Sobrecoste de aprender a vender | −20,800 |
| **Resultado de los 3 primeros meses** | **−7,700** |

> **Lección que hay que leer en ese −7,700:** los tres primeros clientes
> **no dan de comer**. El negocio empieza a respirar con el **cuarto**, y
> con un cliente de Fase 1 o una ruta completa. Esto significa dos cosas
> concretas:
>
> 1. **El ingreso de los primeros meses tiene que venir de otro sitio**
>    (trabajo salariado, un cliente que ya cubre el gasto) o **hay que
>    financiarlo explícitamente**. Decidir esto antes es barato; descubrirlo
>    en el mes 3 es caro.
> 2. **El primer cliente no se busca como cliente: se busca como método.**
>    Se cobra, pero a precio de lista, y a cambio se acepta documentar el
>    proceso (con su permiso) para que el segundo sea más rápido.
>
> **El error clásico:** mirar el mes 1, ver que no salió, y subir el precio
> para compensar. El precio no es la variable; el **nº de horas por paquete** y
> el **nº de propuestas** sí.

### 5.5 El "cliente gratis" como herramienta de venta

Un caso gratuito bien hecho es el mejor prospecto del embudo: produce un
teaser real (capa 1) que se puede enseñar a otro cliente, valida el pipeline
de extremo a extremo y da una referencia real.

**Reglas (todas obligatorias):**

| # | Regla | Por qué |
|---|---|---|
| 1 | **Nunca sin autorización escrita.** Un "cliente gratis" sin RoE firmado es exactamente el delito que este servicio no cometió nunca. Se usa el RoE normal, con el mismo rigor. | La marca se construye sobre la línea que no se cruza. Si "gratis" fuera una excepción al RoE, la línea no existe. |
| 2 | **Nunca con datos reales de pacientes.** El sitio debe ser un entorno de demostración, un sitio propio, un laboratorio propio, o un cliente cuyo permiso escrito cubre el uso de su caso. | La casually del cliente no reduce el riesgo: el dato es del paciente, no del cliente. |
| 3 | **Límite de 1–2 casos.** Y en total, no 2 por mes. | El objetivo es validar el método y producir una muestra, no trabajo auxiliar disfrazado de marketing. |
| 4 | **Sólo Fase 0.** Nunca Fase 1 ni Fase 2 gratis. La Fase 1 requiere revisión legal; la Fase 2 requiere seguro, addendum y cuentas de prueba. | El coste de una Fase 2 sin cobrar (preparación, coordinación, seguro) es alto y el precedente es mala: si regalas la fase cara, la vendes a 0. |
| 5 | **Alcance mínimo, con entregable mínimo.** Un mapa de superficie + un teaser. Nada de informe técnico completo gratis. | El teaser (capa 1) es exactamente lo que convierte; el informe técnico es lo que se cobra. |
| 6 | **Permiso escrito de uso.** Antes de usar nada de ese caso como muestra, autorización escrita del cliente para anonimizarlo. | Sin permiso, es una violation de confidencialidad (§4.e) y, para el cliente de salud, un problema serio. |
| 7 | **Cero datos reales en el material compartido.** Se anonimiza con `pii_redact.py` y se usa un cliente genérico («una clínica dental en hosting compartido»), nunca el nombre, el dominio ni el dominio de la agencia. | §6.e. |
| 8 | **Se contabiliza.** Un caso gratuito es una inversión: se le asignan horas de venta y se le resta del CAC, en lugar de tratarlo como gratis. | Si no se contabiliza, el CAC real es invisible. |

---

## 6. Escalabilidad operativa: cómo se repite sin que se degrade la calidad

El riesgo real de un negocio de metodología no es no tener clientes: es
**entregar peor con el cuarto cliente que con el primero**. Las cinco palancas
están pensadas para que eso no ocurra.

### 6.a Palanca 1 — Playbook reutilizable

**Qué se automatiza (y por tanto no se degrada con el volumen):**

| Automatizable | Cómo | Por qué es seguro automatizarlo |
|---|---|---|
| Recolección de evidencia | `scope_guard.py`, `probe_exposure.py`, volcados de cabeceras, `dig`, `openssl s_client` | Es determinista, es de lectura y está gobernado por el RoE. |
| Análisis local de lo descargado | `secrets_scan.py`, `js_intel.py`, `header_tls_report.py` | Es análisis estático sobre ficheros ya típicos; no toca la red. |
| Redacción y sanitización | `pii_redact.py` | Formato preservado, salida determinista, informe de conteos. |
| Agregación de severidad | `attack_surface_report.py` | Calcula un índice con la fuente de cada línea. |
| Construcción del teaser | `02-plantillas/teaser-report/build.py` + `make-charts.py` | Render determinista a partir de una plantilla. |
| Control del teaser | `verify.py` | Lista de cadenas prohibidas + metadatos + bytes. Es la red de seguridad de la capa 1. |
| Estructura de los entregables | Las tres plantillas de `02-plantillas/` | El formato es fijo; lo que cambia es el contenido. |
| Registro de acciones | Los CSV de `05-plantillas-de-trabajo/` | Estructura de captura con evidencia y comando. |

**Qué NO se automatiza nunca (es el criterio, y es el producto):**

| No automatizable | Por qué |
|---|---|
| **Decidir qué es del cliente y qué es de un tercero** | Es una decisión de alcance con consecuencias legales. El playbook da la tabla (§3 de las reglas de RoE), no la respuesta. |
| **Contrastar versión y CVE contra la fuente primaria** | Es la lección (a) del ciclo. Automatizarlo es exactamente lo que hace un escáner: probar pertenencia a un rango, no alcanzabilidad. |
| **Determinar la versión TLS realmente negociada** | La lección (b): un flag mal entendido produce un falso positivo. El script no lee la versión negociada; hay que forzarla y leerla. |
| **Calibrar la severidad por contenido** | Un endpoint de media expone 66 ficheros de plantilla (BAJO) o radiografías con nombre de paciente (CRÍTICO). Sólo un humano mira qué hay detrás. |
| **El mapeo legal y sus refutaciones** | Hay que leer la fuente primaria y **refutar** lo que no aplica. Una ley inventada es peor que una ley omitida. |
| **La sección «Lo que ya está bien»** | Requiere juicio y es la que da credibilidad al informe. |
| **La llamada, el RoE, la negociación, el escalado** | Son relación humana. |
| **El «go» de cada prueba en Fase 2** | Es una decisión en vivo del cliente, con criterio de abort. |

**La regla de la palanca:** *automatiza la coleta, la forma y el control;
deja el criterio a las personas.* Cada hora que un script ahorra es una hora
que se puede dedicar a mirar qué hay detrás del hallazgo — que es lo que el
cliente paga.

### 6.b Palanca 2 — Toolchain propia

El repo ya tiene **siete scripts propios**, en Python 3.13 de biblioteca
estándar, sin dependencias, con auto-prueba de 14 checks sin llamadas de red
(`python3 tests/selftest.py`). Es la ventaja estructural frente a un consultor
que depende de un escáner de pago: **el coste marginal de la Fase 0 es
prácticamente cero en licencias**.

| Script | Qué parte del trabajo cubre | Qué NO cubre (queda en criterio humano) |
|---|---|---|
| **`scope_guard.py`** | **La única puerta a la red.** Valida ventana de vigencia, host contra la lista (con comodines), recorta métodos a `GET`/`HEAD`, impone ≥1 s entre peticiones, rechaza UA que suplanta un navegador, limita bytes, no sigue redirecciones fuera de la allowlist. Aborta (código 2) si el fichero de autorización no tiene firma. | Si un host **es** del cliente. Si el comodín cubre el apex. Si el RoE tiene la forma jurídica correcta. La validación de la **lista** de hosts es humana; la validación del **uso** es de código. |
| **`probe_exposure.py`** | Recorre una lista fija y corta de 53 rutas conocidas (backups, `.env`, `.git/HEAD`, `wp-config.php.bak`, `phpinfo.php`, `actuator/env`, paneles, documentación de API). Sólo `GET`. **Nunca guarda el cuerpo** de rutas sensibles. Detecta **soft-404** comparando `sha256` contra una 404 de referencia. | Rutas fuera de la lista. Superficies autenticadas. Si el fichero "expuesto" contiene expedientes o plantillas. La severidad, el dueño y las horas. |
| **`secrets_scan.py`** | Escaneo **local** de ~20+ familias de claves (AWS, Google/Firebase, service accounts, Stripe, OpenAI, Anthropic, GitHub/GitLab, Slack, Discord, Twilio, SendGrid, Mailgun, Sentry, Mapbox, JWT, claves privadas RSA/EC/PKCS8/OpenSSH, URIs con credenciales, `_authToken` de npm, `.pypirc`, tokens genéricos, webhooks). **Nunca escribe el valor completo**: 4 primeros + 2 últimos + `sha256[:12]`. Filtro de entropía `--min-entropy`. `--redact-in-place` escribe una **copia**. | Si la clave está **viva**. De qué proveedor es. Qué hacer con ella (rotar, revocar, reemitir) — eso es una decisión con el cliente, y es un ticket, no un hallazgo. |
| **`js_intel.py`** | Análisis estático (sin red): endpoints absolutos y relativos (`fetch`, `axios`, `$.ajax`, `XMLHttpRequest.open`), rutas administrativas, **hosts de terceros clasificados** (analítica, CDN, pagos, mapas, fuentes, formularios, citas, correo, redes, soporte), operaciones GraphQL, `sourceMappingURL`, `<script src>` con comprobación de **SRI** y `crossorigin`, secretos en scripts inline. | La pregunta de fondo —**«¿a dónde salen los datos del navegador del paciente?»**— es una clasificación con criterio, no un regex. El runtime, el JS ofuscado y el servidor quedan fuera. |
| **`header_tls_report.py`** | Analiza volcados de cabeceras ya guardados (**no hace peticiones**): CSP con directivas parseadas, HSTS (`max-age`, `includeSubDomains`, `preload`), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/COEP/CORP, `X-XSS-Protection` (obsoleta), cookies (`Secure`, `HttpOnly`, `SameSite`, `__Host-`/`__Secure-`), fuga de información (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`, `Via`), caché (`Cache-Control`, `Vary`, `Age`, coherencia `http://` vs `https://`), CORS (`ACAO: *` con credenciales, origen `null`, `Vary: Origin` ausente). Salida Markdown con las columnas `check`, `valor`, `severidad` y `remediación`. | **La versión TLS realmente negociada** (eso lo hace `openssl s_client`/`curl` con `--tls-max` y provider legacy forzado — la lección (b)). **CORS con origen reflejado**: con un solo volcado no se distingue allowlist de reflejo; el script lo marca como pendiente, no lo afirma. |
| **`pii_redact.py`** | Redacta emails, teléfonos (MX/ES/US), RFC/NIF/DNI/NIE/CUIT, IPs (`--keep-ips`), tarjetas **validadas con Luhn**, fechas de nacimiento, códigos postales, URLs con credenciales, y claves JSON/HTML con nombres típicos de dato personal o clínico (`nombre`, `telefono`, `diagnostico`, `expediente`, `curp`, `rfc`, `paciente`, `dob`, `ssn`…). **El formato se preserva**: el JSON sigue siendo JSON válido, el HTML sigue siendo HTML. El informe sólo tiene **conteos**, nunca valores. | **Nombres de personas en texto libre** (no hay NER en la stdlib). **Teléfonos sin separadores** (indistinguibles de otros identificadores). Hay que **revisar la copia sanitizada antes de entregarla**: la sobre-redacción es el riesgo aceptado, la sub-redacción es el peligro. |
| **`attack_surface_report.py`** | Agrega la evidencia local y calcula un **Attack Exposure Score 0–100** en cinco bandas (Bajo/Moderado/Alto/Crítico/Severo), con el desglose de la fórmula y la fuente de cada línea. Regla dura: sin datos, el componente vale **0** y se marca `sin datos`; si no hay evidencia, la banda es **No evaluable** — un 0 sin datos **no** significa "seguro". Bonificación por lo que está bien (cookies seguras, TLS fuerte, SRI, cabeceras completas, DMARC activo, sin secretos críticos). | **No tiene base de datos de CVEs**: el componente de versiones puntúa por **antigüedad**, no por vulnerabilidad verificada. La detección de CDN/WAF por cabeceras no detecta un WAF que no firme (y la ausencia de firma no es prueba de ausencia). La MFA se **deduce**, nunca se verifica. **El score no es el informe**: el score es la foto; el informe es el diagnóstico. |

**El reparto que hay que tener claro al_internalizar esto:**

| Cubierto por código | Cubierto por criterio humano |
|---|---|
| Recolectar, medir, contar, comparar, redactar, puntuar, formatear, verificar el teaser | Decidir el alcance, contrastar contra fuente primaria, calibrar severidad por contenido, mapear la ley y refutar, escribir «Lo que ya está bien», hablar con el cliente, decidir el «go» |
| Escala con el volumen sin degradarse | No escala: por eso hay que **estandarizar el criterio** (palanca 4) y **formar** (palanca 3) |

**Y un beneficio colateral que vale dinero:** el `scope_guard.py` es la
materialización de la promesa comercial. La propuesta dice "sólo GET/HEAD, ≥1 s,
sin salir del alcance" y el código **lo hace cumplir**, no lo promete. Eso es
un argumento de venta en sí mismo: el control no es una promesa, es una
restricción técnica.

### 6.c Palanca 3 — Formación

**Lo que hay que saber para ser auditor en este modelo** (mínimo aceptable):

| Bloque | Qué hay que saber | Dónde está |
|---|---|---|
| **Fundamentos de HTTP/TLS/DNS** | Por qué `curl --tlsv1.2` no prueba nada; qué es un SAN; qué hace CAA; por qué un CNAME que resuelve no es un takeover. | `04-formacion/01-lab-seguro.md` (red y TLS) y `04-formacion/02-herramientas-y-python.md` |
| **Las 5 prohibiciones duras** | Que no se levantan nunca, ni por insistencia del cliente. Es lo que separa al auditor del incidente que él mismo causa. | `00-metodologia/reglas-de-autorizacion-y-roe.md` §1 |
| **Verificar contra fuente primaria** | Pertenencia vs. alcanzabilidad. El ejemplo de `retire.js` y jQuery está documentado y es el mejor caso de entrenamiento que hay. | `00-metodologia/ciclo-de-auditoria.md` fase 5, lección (a) |
| **El falso positivo de TLS** | `--tls-max`, provider legacy, leer la versión negociada. | `00-metodologia/ciclo-de-auditoria.md` fase 4, lección (b) |
| **Calibración de severidad** | Los tres ejes y los anti-patrones (no inflar, no calibrar sin mirar el contenido, si no se puede verificar es INFO). | `00-metodologia/como-presentar-resultados.md` §1 |
| **ICE y no RICE** | Por qué reach e impact inventados son peores que no priorizar. | `00-metodologia/como-presentar-resultados.md` §2 |
| **Las tres capas y «Lo que ya está bien»** | Qué va a quién, y por qué los positivos son obligatorios. | `00-metodologia/como-presentar-resultados.md` §3 y §4 |
| **El RoE y cuándo escalar** | Cuándo se para y se pregunta. | `00-metodologia/reglas-de-autorizacion-y-roe.md` §3 y §5 |
| **El marco legal** | Dónde está la línea en MX (y en ES si el cliente es español). **Con las fuentes primarias, no con el resumen.** | `04-formacion/03-modelo-de-negocio-y-legal-mx.md` §2 · y este documento §4 |
| **Laboratorio propio** | Practicar sin tocar clientes. WordPress vulnerable propio, Juice Shop, DVWA, lab de red y TLS. | `04-formacion/01-lab-seguro.md` |
| **Escribir las tres capas** | Redactar un teaser que no filtre técnica, un informe técnico que el hosting pueda ejecutar, y un brief que el dueño entienda. | `02-plantillas/` |

> **⚠️ Estado real de la formación en el repo:** `04-formacion/LEEME.md` es
> un **placeholder**: la guía lineal de formación **todavía no está escrita**
> (el propio README lo dice). `01-lab-seguro.md`,
> `02-herramientas-y-python.md` y `03-modelo-de-negocio-y-legal-mx.md` sí están
> escritos y son buenos. **Antes de contratar a un segundo auditor hay que
> escribir la guía de formación** (el LEEME ya tiene el alcance definido: 6
> apartados). Es una de las tres tareas de la semana 1 del §9.

**El coste de formar a un auditor nuevo, medido:** el tiempo de leer la
metodología + el tiempo de supervisión en un primer engagement. Es la segunda
curva de aprendizaje del negocio (la primera es la de aprender a vender, §5.4).
Antes de contratar, calcula ambas.

### 6.d Palanca 4 — Estandarización de entregables

**Las tres capas y quién las recibe:**

| Capa | Documento | Para quién | Qué lleva | Qué **no** lleva |
|---|---|---|---|---|
| **1 — Teaser** | PDF corto (el caso real: 13 páginas) | Dueño / primer contacto / venta | Cifras legales exactas, costo del negocio del riesgo, resumen por categoría, distribución por severidad, **«Lo que ya está bien»**, la oferta, la convocatoria a reunión | Identificadores de vulnerabilidad, severidad estándar, versiones, rutas/URLs/endpoints, comandos, salidas de herramientas, usuarios/emails/teléfonos, nombres de herramientas de terceros, la lista completa de hallazgos |
| **2 — Informe técnico** | Markdown largo (§0–§11) | Equipo técnico, hosting, agencia | Mapeo OWASP/WSTG con razonamiento (incluido qué filas están forzadas), investigación de CVE contra fuente primaria, modelado de amenazas de phishing, mapeo legal con cita de artículo, registro de riesgo puntuado, hoja de ruta por olas, borradores de ticket, refutaciones legales | **Nada de esto va al dueño.** Va marcado **CONFIDENCIAL**. |
| **3 — Brief llano** | 2–3 páginas | Dueño | Sin jerga: qué significa cada problema en dinero y en riesgo, y qué se le pide hacer hoy/este mes/este trimestre, con horas | Ninguna jerga sin traducir. Cada afirmación va acompañada de «esto es lo que significa para ti». |

**Por qué el teaser PDF es lo que cierra la venta:**

1. **Es el único documento que el dueño puede leer.** El informe técnico es
   para el hosting; el brief es para después de la decisión.
2. **Es la prueba de capacidad sin revelar nada.** Demuestra rigor, método y
   criterio **sin** filtrar un endpoint, una versión o una credencial. El
   cliente recibe confianza sin recibir información utilizable.
3. **Es un artefacto, no una promesa.** Un PDF de 13 páginas con gráficos,
   «lo que ya está bien» y una oferta se puede mandar, volver a abrir y
   enseñar a un socio. Una llamada de ventas no.
4. **Es la prueba de que las otras dos capas existen.** El teaser sin informe
   técnico detrás es publicidad; con él detrás, es el resumen de un trabajo
   real.
5. **Está verificado antes de salir.** `verify.py` extrae el texto del PDF, lo
   pasa por la lista de cadenas prohibidas y revisa bytes y metadatos. Es la
   única comprobación automática que impide el error más caro del negocio:
   filtrar un detalle técnico al cliente equivocado.
6. **Su coste marginal es cero.** El HTML, los gráficos y la construcción son
   plantillas; lo que cambia son los datos.

> **Consecuencia operativa de estandarizar:** el tiempo de redactar la capa 2
> y la capa 3 **no** escala con el volumen si las plantillas están hechas. Lo
> que no escala es el criterio, y por eso la palanca 3 (formación) es la
> condición de esta palanca.

### 6.e Palanca 5 — La evidencia como activo

**La idea.** Cada caso cerrado en `03-casos/` hace el siguiente más rápido: el
recon ya está hecho, la metodología ya está probada, las plantillas ya están
llenas, los falsos positivos ya están documentados. El primer engagement costó
55 h; el cuarto puede costar 14 h.

**El flujo que hay que montar:**

```
   Caso cerrado en 03-casos/
            │
            ▼
   ¿El cliente autoriza por escrito su uso anonimizado?
            │ sí
            ▼
   Anonimización (pii_redact.py + reescritura manual)
            │
            ▼
   Muestra de marketing: teaser sin el nombre del cliente,
   sin el dominio, sin la agencia, sin la IP, sin la ciudad
            │
            ▼
   Carpeta de muestras (FUERA de 03-casos/, porque 03-casos/ es confidencial)
```

**El riesgo, que es serio: la confidencialidad.** Un caso de salud con datos de
pacientes puede filtrar información identificable por vías que nadie mide:
un nombre en un pie de foto, un dominio en un titular, una IP en una captura,
el nombre de la agencia en un certificado, un identificador de paciente en un
JSON de ejemplo.

**Checklist de anonimización de un caso para usarlo como marketing:**

| Qué anonimizar | Cómo |
|---|---|
| Nombre del cliente, razón social, RFC | Texto genérico: «una clínica dental en hosting compartido» |
| Dominio y subdominios | Sustitución estable por un marcador (`cliente-a.mx`, `ejemplo-auditoria.mx`) |
| IP y geolocalización | Sustitución; se puede conservar la *relación* («hosting en el extranjero») porque es el hallazgo |
| Nombre de la agencia, del hosting, del proveedor de SaaS | Sustitución por «la agencia web» / «el hosting» / «un proveedor externo» |
| Nombres de la plantilla, temas, plugins | Se pueden conservar: son públicos y son precisamente el valor técnico |
| Datos de pacientes o personal | **Nunca se publican.** Ni como ejemplo, ni como «ejemplo de un nombre», ni difuminados. Si un dato real aparece en una captura, se regenera la captura. |
| Secretos, tokens, credenciales | Enmascarados por diseño (prefijo + sufijo + hash). Verificar. |
| Rutas y endpoints concretos | **Depende del caso:** en un teaser, están prohibidos; en el material técnico de marca blanca, se pueden conservar si el cliente lo autorizó. |
| Capturas de pantalla | Recorte a la zona relevante; nunca una pantalla completa con datos visibles. |
| Nombres del personal del auditor | Opcionalmente, si se usa como portfolio. |
| Nombres del equipo del cliente | Sustitución por rol («responsable de sistemas»). |

**Y las tres condiciones para que un caso sirva como muestra:**

1. **Autorización escrita del cliente** para usar el caso anonimizado en
   material comercial. (En el RoE: §6, «no se reutiliza en material comercial
   ni en formación salvo autorización escrita del cliente». Es una condición
   de plantilla, no un supuesto.)
2. **Anonimización verificable**: una segunda persona del equipo (o el propio
   auditor, con una checklist distinta) revisa que no queda nada identificable.
3. **Las tres capas se rehacen para el material de marketing**: el teaser del
   caso real se puede reutilizar con otro nombre de cliente, pero hay que volver a
   pasar `verify.py` sobre el PDF resultante.

> **Regla dura, y es la que más se gana y más se pierde:** `03-casos/` es
> **confidencial**. Las muestras van en **otra carpeta** (`02-plantillas/teaser-report/`
> o una `muestras/` nueva), con la autorización del cliente y sin rastro de
> que corresponden a un caso real identificable. **No se publica un teaser de
> un cliente de salud sin su papel.**

### 6.f Las cinco palancas en una tabla

| Palanca | Qué resuelve | Qué NO resuelve |
|---|---|---|
| **(a) Playbook reutilizable** | Que el proceso no se re-contrate cada vez | El criterio humano |
| **(b) Toolchain propia** | Que el coste marginal sea bajo y que el alcance sea técnicamente exigible | La verificación de versiones ni la severidad |
| **(c) Formación** | Que el criterio se pueda enseñar y trasmitir | La motivación comercial |
| **(d) Estandarización de entregables** | Que la calidad de forma no dependa de quién redacta | La profundidad del análisis |
| **(e) Evidencia como activo** | Que cada caso haga el siguiente más rápido | El pipeline comercial |

---

## 7. Riesgos del negocio y cómo se mitigan

| # | Riesgo | Impacto | Mitigación | Responsable |
|:-:|---|---|---|---|
| 1 | **Perfil público del tester.** El trabajo técnico (scripts, repos, publicaciones) puede leerse como el de un atacante, y en este nicho los clientes de salud son *prey* de solicitudes de extorsionadores que empiezan por «te hago un pentest gratis». | Alto: reputacional. Un cliente que ve un perfil de atacante no compra un RoE, lo tira. Y un cliente potencial que ve tu perfil se asusta. | **Marca explícita de consultoría autorizada** en todo el material público: nombre, sector, «servicio de revisión autorizada». · **La web pública con la metodología y la política de autorización**: «no auditamos sin autorización escrita; puede leer nuestro RoE» (§7, más abajo). · **El RoE como carta de presentación**: se manda firmado en la primera llamada. · **Nunca publicar capturas de objetivos reales** (§6.e). · **El informe técnico lleva marca CONFIDENCIAL** y destinatario explícito. | Consultor principal (marca y web) |
| 2 | **Un cliente pide algo ilegal o fuera de alcance** (p. ej. «demuestra que puedes entrar a la cuenta de mi socio»). | Muy alto: penal y reputacional. | Procedimiento de escalado con **negativa documentada** (§4.g), cláusula contractual de no ejecución, y las 3 prohibiciones no negociables (§4.h). **El RoE firmado no es la defensa**: lo que salva es haber negada por escrito y documentado. | Auditor principal + Consultor principal |
| 3 | **Fuga de evidencia o de datos personales** (carpeta mal compartida, captura con datos, backup en la nube personal, cliente que difunde su informe). | Muy alto: contrato, salud, posible responsabilidad. | RoE firmado con cláusula de confidencialidad y no divulgación (§4.e) · Retention y destrucción con confirmación escrita (§4.f) · `pii_redact.py` **antes** de compartir cualquier evidencia · Capturas recortadas, nunca de pantalla completa · Evidencia en el expediente del engagement, no en el portátil personal · Regla de las tres prohibiciones (§4.h) | Todos. Cada auditor, en cada caso. |
| 4 | **Un tester junior rompe algo en Fase 2.** | Alto: daño al cliente, pérdida del contrato, y quizá de la sesión. | Addendum de Fase 2 firmado por tres partes · "go" por prueba, con el **responsable técnico presente** · criterio de **abort inmediato** en tres casos · ventana de 3 h · **dos personas mínimo** en la ejecución · registro de acciones con rollback · declaración de limpieza · **Fase 2 sólo la ejecuta un auditor con al menos un engagement supervisado de Fase 1** (regla interna de asignación, no del RoE). | QA / auditor principal |
| 5 | **El cliente no paga.** | Medio-alto: es el riesgo financiero más directo de una consultoría. | **Fase 0 y Fase 1 se cobran por adelantado (100 % antes de empezar)** · Fase 2: 50 % al firmar el addendum, 50 % contra entrega · Contrato con hitos de pago y penalización por retraso · Facturación con datos fiscales correctos desde el primer cliente · La evidencia se entrega **redactada y con el informe**, pero **las capturas originales con valores completos no se entregan** hasta que el pago está liquidado (§4.f) — y eso se pacta así, por escrito, en el contrato, no se improvisa. | Administración / Consultor principal |
| 6 | **Dependencia de un solo framework o hosting.** (Todo el conocimiento en WordPress + cPanel, o todo en un hosting.) | Medio: si el cliente tiene otra pila, el servicio se cae en la Fase 1 y la reputation se resiente. | El playbook ya tiene dos counters: **el certificado compartido y el blast radius** (que es un finding, no un crash) y la regla de que "lo que pertenece a un tercero se describe, no se ataca". · Formación: `04-formacion/01-lab-seguro.md` cubre WordPress y otros. · Documentar por stack lo que se sabe y lo que no, y decirlo en la propuesta. · **Nunca scrapear una metodología nueva por urgencia**: si el stack está fuera, se dice en la propuesta antes de firmar. | Consultor principal + formación |
| 7 | **Rotación de plantillas que se detecta.** (Firmas, User-Agent, ritmo, cabeceras.) | Medio: el cliente bloquea al auditor o, peor, un tercero lo bloquea thinking que es un ataque. | User-Agent **honesto y contactable** (`Mozilla/5.0 (compatible; ClientSecurityAudit/1.0; +contacto)`) · ≥1 s entre peticiones, sin concurrencia, sin reintentos automáticos · `scope_guard.py` **impone** el ritmo y **rechaza** los UA que suplantan navegador · Si el servidor bloquea, **eso se reporta como señal y se escala la decisión; no se esquiva** (RoE §2). · Nunca fuzzing masivo, nunca Nuclei/dirsearch/ffuf contra el objetivo. | Auditor principal |
| 8 | **Conflicto de interés: el auditor audita a un competidor del cliente, o a un tercero del cliente.** (La agencia web es cliente y es un tercero del hosting.) | Medio-alto: pérdida de confianza y de negocio repetido. | Declaración de conflictos antes de aceptar el encargo · Separar "cliente" de "tercero" en el RoE · **Nunca aceptar un encargo contra un tercero sin su autorización escrita** · §4.g: el tercero se describe, no se ataca. | Consultor principal |
| 9 | **El cliente publica su informe completo en redes o lo filtra a su competencia.** | Medio: se pierde la confidencialidad y el activo de marketing. | El informe técnico lleva marca CONFIDENCIAL y destinatario explícito · **El teaser es lo que el cliente puede compartir** (cero técnico, por diseño) · En el RoE, la confidencialidad sobrevive a la finalización · El cliente comparte **el teaser**, no el informe. | Todos |
| 10 | **Sobreventa de capacidad: aceptar más encargos de los que se pueden entregar bien.** | Alto: es la vía más directa a degradar la calidad y a perder la metodología. | Capacidad por semana explícita en el calendario · Un encargo activo como máximo a la vez si no hay segundo auditor · **La calidad es un criterio de aceptación, no un extra**: si el número de horas por paquete sube, se sube el precio o se baja el ritmo de venta (§8). | Consultor principal |
| 11 | **El negocio depende de un solo cliente grande o de una sola plataforma (WordPress).** | Medio: si ese cliente se va, el negocio se cae. | Diversificar stack y segmento · El **retainer** y el **re-test** generan ingreso recurrente que no depende de cerrar ventas nuevas · Marcar blanca para agencias: convierte al cliente en canal. | Consultor principal |
| 12 | **Confusión entre "orientación" y "dictamen":** el cliente interpreta el mapeo legal como una opinión jurídica y actúa sobre ella. | Medio-alto: claim de calidad y riesgo de daño al cliente. | La cláusula de no asesoría legal en el contrato, en la propuesta y en el informe · La regla de refutar explícitamente lo que no es obligación · `verify.py` y la revisión del teaser. | Todos |

### 7.1 Cómo reducir específicamente el riesgo de "parecer un atacante"

Cuatro mecanismos, todos Ellos documentados y comprobables:

| Mecanismo | Qué es | Por qué reduce el riesgo |
|---|---|---|
| **1. La marca** | El material público dice claramente qué es la empresa: consultoría de seguridad **autorizada**, no "hackeo". Sin ambigüedad en el nombre, en el encabezado y en el pie. | Separa la categoría antes de que el cliente tenga que preguntar. Un cliente que cree que habla con un atacante no firma RoE. |
| **2. El contrato** | RoE + addendum + contrato + anexo de tratamiento. Documentos con fecha, alcance, exclusiones y firmas. | El expediente en papel es la diferencia entre un profesional y un amateur. Es lo que pide la aseguradora y lo que el cliente le enseña a su banco. |
| **3. La carta de autorización** | Un documento corto, imprimible, en español llano: «La empresa X autoriza a Y a revisar el sitio Z entre el día A y el día B, con estas técnicas y sin tocar datos de pacientes. Esta carta la puede mostrar a su hosting, a su aseguradora o a quien la pida.» | Resuelve el miedo del cliente a que le "hackeen", y le da un instrumento para enseñar. Es también la primera pregunta del cliente potencial: si no la tienes, no hay venta. |
| **4. La web pública con la metodología y la política de autorización** | Una página pública con: qué es la metodología, qué incluye y qué no, y **«no auditamos sin autorización escrita; puede leer nuestro RoE»**, con el RoE completo publicado para descargar. | Poner la política a la vista es lo que separa a un consultor de un atacante. Un atacante no publica sus reglas ni su autorización previa: publica sus resultados. Publicar el RoE es la demostración de que **el proceso es lo que garantiza la legalidad**, y de paso convierte la web en un activo de venta: el RoE descargable es el primer material que un lead se lleva. |

**Y un quinto, que no es marketing:** **el User-Agent honesto**. Que cada
petición diga quién eres y cómo contactarte es, en la práctica, la prueba
diurna de que no estás atacando.

---

## 8. Qué medir para saber si el negocio funciona

### 8.1 El cuadro de mando

| Métrica | Definición | Cómo se mide | Por qué importa | Frecuencia |
|---|---|---|---|---|
| **Clientes cualificados / mes** | Leads que tienen dominio, tienen un decisor identificable, y encajan en el perfil (clínica/consultorio/agencia). No es "leads": es "leads que pasarían el filtro del RoE". | Lista de pipeline con los 6 campos que exige el RoE (dominio, hosts, decisor, stack, datos personales, deadline). | Es el **embudo real**. Contar "interesados" sin esto es contarse a uno mismo. | Semanal |
| **Conversión lead → propuesta** | `propuestas enviadas / cualificados` | CRM o hoja de cálculo. | Si es baja, el problema es el mensaje o el filtro, no el precio. | Mensual |
| **Conversión propuesta → Fase 0** | `Fases 0 contratadas / propuestas enviadas` | Igual. | Si es baja: el RoE asusta, el precio asusta o la propuesta no explica qué recibe. | Mensual |
| **Conversión Fase 0 → Fase 1** | `Fases 1 contratadas / Fases 0 entregadas` | Igual. **Es la métrica más importante del negocio** (ver §5.3: vivir de Fases 0 sueltas no da de comer). | Dice si el producto cumple. Si es baja, el teaser o el informe no están PRIORIZANDO bien. | Por cliente y mensual |
| **Conversión Fase 1 → Fase 2** | `Fases 2 contratadas / Fases 1 entregadas` | Igual. | Dice si la evidencia de Fase 1 genera urgencia real. | Por cliente |
| **Conversión Fase 2 → re-test / retainer** | `re-tests + retainers / Fases 2 entregadas` | Igual. | El ingreso recurrente. Si es cero, el engagement terminó sin relación. | Por cliente |
| **Ticket medio** | `ingresos facturados / número de engagements` | Facturación. | Detecta si el negocio se está llenando de Fase 0 baratas. | Mensual |
| **Horas por paquete** | `h_F0`, `h_F1`, `h_F2` reales, comparadas con las estimadas de §2.0 | Del registro de acciones y del tiempo. **Es el indicador de deriva de alcance.** | Ver la regla de abajo. | Por engagement |
| **Margen bruto por paquete** | El de §5.2, con datos reales | El de §5.2. | Convierte el modelo en dinero real. | Mensual |
| **Tasa de re-test** | `re-tests contratados / engagements cerrados con hallazgos corregibles` | Por cliente. | Es la prueba de que el arreglo funcionó y la mejor fuente de renovación. | Trimestral |
| **Referidos** | Clientes que trajectories sin que se les pregunte, o referreds explícitos | Lista. | El canal más barato y el más creíble en salud (los colegas se recomiendan). | Trimestral |
| **NPS** | Una pregunta al final de la entrega: «¿recomendaría esta revisión a otro dueño de clínica?» | Una pregunta, no un cuestionario. Se pide **al final de la sesión de entrega**, en persona o por correo, y se registra tal cual. | En este nicho, un referido vale más que una campaña. | Por engagement |

### 8.2 La regla de control: si las horas suben y el ticket no, estás regalando trabajo

> **Regla de una línea:**
>
> **Si las horas por paquete suben y el ticket no, estás regalando trabajo: revisa
> el RoE.**

**Cómo se aplica (paso a paso):**

| # | Paso | Qué hacer |
|:-:|---|---|
| 1 | **Detecta** | Compara `h_i` real contra `h_i` estimado en §2.0 (10–18 / 20–35 / 16–28 h). Una desviación sostenida de más de un 30 % en tres engagements seguidos es una señal, no ruido. |
| 2 | **Diagnosis — ¿por qué?** | (a) **RoE flojo**: el alcance no define hosts ni técnicas → se amplía de facto. (b) **Descubrimiento nuevo**: apareció una plataforma o una capa no contemplada → es un cambio de alcance y hay que cotizarlo aparte. (c) **Derivación del cliente**: el cliente pide extras durante la fase. (d) **Falta de criterio**: se re-hace trabajo porque no estaba claro qué buscar → es formación, no cobro. (e) **Herramienta que no funciona**: el script falla y se hace a mano. |
| 3 | **Decide, por orden de prioridad** | (i) Si es (a) o (c): **se corrige el RoE** y se renegocia el alcance de las fases siguientes. Es lo que el paquete comercial ya dice: «cualquier trabajo fuera del alcance escrito se cotiza por separado y se acuerda antes de ejecutarlo». (ii) Si es (b): **se cotiza aparte** y se avisa al cliente antes de ejecutarlo. (iii) Si es (d): es un coste de formación y hay que **materializar la lección** (anotarla en el playbook y en `04-formacion/`), no volver a cobrarlo. (iv) Si es (e): es un bug de la toolchain y se arregla. |
| 4 | **Actúa sobre el precio si hace falta** | Si el RoE ya está bien y las horas siguen subiendo, el problema es el **precio de lista**, no el RoE. Entonces se corrige una de dos variables: **el precio** (subir el de lista dentro del rango ya fijado en `paquetes-por-fase.md`, y con él el de `04-formacion/03` §3.1, para que no se contradigan) o **el alcance** (menos hosts, sin DOMINIOS adicionales, sin más plataformas). Lo que no se hace es seguir vendiendo al mismo precio con más horas. |
| 5 | **Cierra el ciclo** | Deja la corrección escrita en el RoE, en la propuesta y en el playbook. **Un hallazgo de proceso que no se escribe, se repite.** |

**La versión corta para el día a día:**

| Situación | Respuesta |
|---|---|
| `h_i` sube, `P_i` igual | Revisa el RoE. Si el RoE está bien, sube el precio o baja el alcance. No sigas regalando trabajo. |
| `h_i` sube y `P_i` sube con ella | Normal al principio (curva de aprendizaje). Si persiste, es alcance. |
| `h_i` baja y `P_i` igual | **Márgenes reais**: el playbook está funcionando. Documenta qué cambió y estandarízalo. |

### 8.3 El panel de una página

Si sólo puedes mirar cinco números todas las semanas, que sean estos:

| # | Número | Por qué ese |
|:-:|---|---|
| 1 | **Clientes cualificados** que entran al mes | Sin pipeline no hay nada que medir |
| 2 | **Propuestas enviadas** | La palanca de salida |
| 3 | **Fase 0 → Fase 1** (conversión %) | La métrica de salud del producto |
| 4 | **Ticket medio** | Si baja, estás vendiendo Fase 0 y nada más |
| 5 | **`h_i` real por paquete** | La early warning de la deriva de alcance |

Los dos últimos son los que se miran con miedo y los que más valen.

---

## 9. Los primeros 30 días

Un plan de arranque **secuencial**. Cada semana depende de la anterior: no se
vende antes de tener el método cerrado y una carta de autorización; no se
publica antes de tener un caso; no se persiguen cinco propuestas antes de saber
cuánto cuesta una.

> **Objetivo realista a los 30 días:** **1 caso piloto de Fase 0 cerrado y
> facturado**, la metodología pública publicada, y **5 propuestas comerciales
> enviadas**. No es un objetivo de facturación: es un objetivo de
> **validación del embudo**. La facturación llega en el mes 2.

### 9.1 Semana 1 — Cerrar el método, la toolchain y las plantillas

| # | Tarea | Entregable verificable | Por qué en la semana 1 |
|:-:|---|---|---|
| 1 | **Escribir la guía de formación** que `04-formacion/LEEME.md` deja como placeholder | Guía lineal con los 6 apartados que el LEEME ya define | Sin ella no hay segundo auditor, y sin segundo auditor no hay escalabilidad (§6.c) |
| 2 | **Cerrar el RoE base y el addendum de Fase 2** como plantillas operativas | `05-plantillas-de-trabajo/roe-modelo.md` (versión firmable) + el addendum ya existente revisado | Es el primer documento que ve un cliente. Si no está cerrado, no hay venta |
| 3 | **Alinear los plazos de retención** (12 meses en el RoE de ejemplo vs. 30 días en el addendum) y fijar el plazo de Fases 0 y 1 en el contrato principal | Un párrafo único y consistente en los tres documentos | Es una inconsistencia real del repo (§4.f). Se arregla antes de que la contradicción llegue a un contrato |
| 4 | **Aprobar el marco legal con un abogado**: las 7 preguntas de §4.i | Una hoja con las respuestas por escrito | Es el bloque que §4.i dice que no se puede cerrar solo. **Es la semana 1, no la semana 4** |
| 5 | **Contratar la póliza de RC profesional** y confirmar por escrito que la actividad declarada cubre la fase de explotación y el sector salud | Póliza en firme + respuesta de la aseguradora por escrito | Sin seguro, la Fase 2 no se vende (§4.c) |
| 6 | **Correr la auto-prueba del toolkit** | `python3 tests/selftest.py` en verde, y los 7 scripts documentados con un ejemplo de salida | La toolchain es la ventaja de coste marginal; tiene que estar verificada antes del primer cliente |
| 7 | **Medir las horas reales de la re-auditoría del caso piloto** (tu propio `dentaleasy.mx`, con RoE firmado) | `h_F0` real, con el desglose | Da el número real para §5.3. Todo lo demás en §5 depende de este dato |
| 8 | **Cerrar la propuesta comercial con los precios ya fijados** y el re-test y el retainer | `02-plantillas/propuesta-comercial/paquetes-por-fase.md` revisado + versión imprimible | Los precios ya están decididos; no se rediseña la oferta en el mes 1 |

**Criterio de fin de semana 1:** un paquete de Fase 0 se puede **ejecutar de
principio a fin** con los documentos de la repo, sin improvisar nada, y
**firmar** el RoE de un cliente hipotético sin ayuda.

### 9.2 Semana 2 — Un caso piloto de Fase 0, con autorización

| # | Tarea | Entregable verificable |
|:-:|---|---|
| 1 | **Conseguir el primer cliente piloto** (ideal: un sitio propio, un laboratorio propio o un colega con un sitio pequeño y sin datos reales) | RoE **firmado** antes de la primera petición |
| 2 | **Ejecutar la Fase 0 completa** con la toolchain | `03-casos/<cliente>/evidencia/` con la evidencia cruda, el registro de acciones y el RoE firmado archivado |
| 3 | **Medir las horas por fase, en detalle** | `h_F0` real, desglosado en: setup + recon + sondas + análisis + redacción + sesión de entrega |
| 4 | **Redactar las tres capas** | Teaser (PDF, pasado por `verify.py`), informe técnico, brief llano |
| 5 | **Entregar y pedir el re-test** | Sesión de entrega de 60 min + la pregunta de NPS + el pedido explícito de re-test |
| 6 | **Documentar el proceso completo** | Qué salió mal, qué se repitió, qué falta en las plantillas. **Esto es lo que convierte el piloto en método** |
| 7 | **Pedir la autorización de uso anonimizado** (para muestra) | Sí/No por escrito, con fecha |

**Criterio de fin de semana 2:** un engagement de Fase 0 **cerrado, entregado y
facturado**, con las horas medidas y con al menos tres correcciones
identificadas al proceso. Y una cifra real: `h_F0` = X horas.

**Lo que NO se hace en la semana 2:** ninguna auditoría a un tercero sin
autorización. Ni un "solo una mirada rápida". Ni un cliente real de salud con
datos reales en el piloto: el primer piloto debe ser un sitio sin datos de
pacientes, o con el permiso explícito del cliente para usar su caso.

### 9.3 Semana 3 — Publicar la metodología y la carta de autorización

| # | Tarea | Entregable verificable |
|:-:|---|---|
| 1 | **Escribir la web pública** con: qué es el servicio, qué incluye y qué no, la metodología resumida, las tres capas de entregable, los precios (o su banda), y la **política de autorización** | Página pública + el **RoE descargable** en PDF |
| 2 | **Redactar la carta de autorización** de una página | PDF imprimible que el cliente pueda mostrar a su hosting, su aseguradora o su junta |
| 3 | **Publicar la política de autorización** | «No auditamos sin autorización escrita. Puede leer nuestro RoE aquí.» Con el enlace al documento |
| 4 | **Preparar los perfiles con contenido educativo** (LinkedIn, X, GitHub, un blog) | 4–5 publicaciones de contenido técnico educativo, **sin revelar objetivos reales** |
| 5 | **Convertir el piloto en una muestra anonimizada** | Teaser con el cliente sustituido, pasado por `verify.py`, **sólo si hay autorización escrita** (§6.e) |
| 6 | **Hacer el teaser descargable** sin romper la regla de no filtrar | PDF del teaser público + el checklist de `verify.py` en verde |

**Sobre las publicaciones con contenido educativo (punto delicado):**

- **Qué sí:** explicar *cómo se verifica una versión contra la fuente primaria*,
  *qué es una comparación booleana*, *por qué `--tlsv1.0` no prueba nada*, *qué
  es un soft-404*, *qué es IDOR*. Es educación sobre método, y es el contenido
  que hace que un cliente entienda por qué tu informe no es el output de un
  escáner.
- **Qué no:** capturas de objetivos reales, credenciales, cadenas de
  explotación, exfiltración de datos, o "así hackeé X". Todo eso es material de
  otro y rompe la confidencialidad (§4.e).
- **El criterio simple:** si la publicación no podría salir en la web sin RoE,
  no sale. Y la regla de la línea 4 de §7.1: **publicar el método es lo que
  te hace conservador; publicar resultados es lo que te hace sospechoso.**

**Criterio de fin de semana 3:** alguien que te encuentre en Google puede
leer tu metodología, **descargar tu RoE** y entender exactamente qué haces y
qué no haces antes de escribirte.

### 9.4 Semana 4 — Cinco propuestas comerciales

| # | Tarea | Entregable verificable |
|:-:|---|---|
| 1 | **Construir la lista de 20–30 prospectos cualificados** | Lista con los campos del RoE: dominio, hosts, decisor, stack, si maneja datos personales, señal de urgencia |
| 2 | **Enviar 5 propuestas comerciales** (con el RoE adjunto) | 5 propuestas enviadas, con fecha y canal registrados |
| 3 | **Hacer 3–5 llamadas de descubrimiento** de 30 min con el guion de §3.3 | 3–5 llamadas hechas, con notas de lo que se objetó en cada llamada |
| 4 | **Anotar cada objeción real** | Registro de objeciones: las 5 de §3.4 y **las que no estaban previstas**. Esto es lo que mejora el guion para el mes 2 |
| 5 | **Cerrar el primer RoE firmado** | Al menos un RoE firmado, listo para arrancar |

**Objetivo de conversión realista a los 30 días:**

| Métrica | Objetivo | Nota |
|---|---|---|
| Propuestas enviadas | **5** | Es un número pequeño y deliberado: 5 propuestas bien hechas informan más que 30 genéricas |
| Respuestas / llamadas | 2–3 | Si no llega ni una, el problema es el mensaje o el canal, no el precio |
| Propuestas que avanzan a RoE | 1 | Una es realista en el primer mes |
| **Clientes de Fase 0 facturados en el mes 2** | **1–2** | No 5. La curva del §5.4 dice que los primeros meses no dan de comer |

**La conversión que hay que esperar (y no hay que inventarla):** no se cita
ninguna tasa de conversión de mercado, porque no hay ninguna verificada para
este nicho y no se va a inventar una. Lo que sí se puede afirmar es la
**dirección** que deben tener los números, y sale de §5.3:

| Métrica | Lo que el modelo implica | Lo que significa si no se cumple |
|---|---|---|
| Fase 0 → Fase 1 | **Alta.** Es la conversión que sostiene el negocio | El teaser o el informe no priorizan lo suficiente. Revisar §3.1 y §6.d |
| Fase 1 → Fase 2 | **Media.** No todos los clientes necesitan demostrar impacto | Normal. No es un fallo |
| Fase 2 → re-test / retainer | **Alta.** Es la prueba de que el arreglo funcionó | El engagement terminó sin relación. Revisar la sesión de cierre |

### 9.5 Lo que NO hay que hacer

Esta lista es tan importante como el plan.

| ❌ No hagas esto | Por qué |
|---|---|
| **No publiques datos reales** (nombres de pacientes, dominios, IPs, capturas de objetivos reales, credenciales) | Es la ruptura de confidencialidad que destruye el negocio en salud (§4.e, §6.e). Y un solo dato filtrado en público es irreversible |
| **No «hackees» cuentas propias para generar contenido** | El material se confunde con el de un atacante. El contenido educativo va sobre **técnica y método**, no sobre **objetivos y resultados**. Y aunque sea tu cuenta: si no hay RoE firmado, no hay RoE, y el ejemplo que das es el ejemplo que no quieres que te copien |
| **No compres bases de datos** (de contactos, de emails de empresas, de posibles pacientes) | Además del problema de datos personales, es el patrón exacto del atacante. El playbook tiene una regla explícita: **tu autorización es el dominio del cliente**; los terceros se describen, no se atacan |
| **No audites sitios de terceros sin autorización** | Es delito (§4.b), y además destruye la marca en el momento en que la marca es el activo (§7, riesgo 1) |
| **No uses herramientas de carga, fuzzing masivo o escáneres de peso contra el cliente** | RoE §2: nada de Nuclei, dirsearch ni ffuf contra el objetivo. Si el servidor bloquea, **se reporta como señal y se escala**, no se esquiva |
| **No aceptes un encargo sin RoE firmado, ni aunque el cliente insista** | Es la línea. El paquete comercial lo dice: la autorización es un anexo de la propuesta, «para que la firme antes de empezar» |
| **No vendas Fase 2 sin seguro vigente y cobertura confirmada para el sector salud** | §4.c. No hay tercera opción |
| **No cites leyes de memoria** | Principio 7 del README. Se lee la fuente primaria o se marca *no verificado* con el enlace |
| **No uses las cifras de `research/` para justificar precios de este servicio** | Son de otra línea de producto (assessments de personalidad). Cualquier comparación con ellas es un error y un riesgo de credibilidad |
| **No aceptes más encargos de los que puedes entregar bien** | La calidad es el criterio de aceptación del negocio (§7, riesgo 10) |
| **No regales la fase cara** | El "cliente gratis" es sólo Fase 0, con autorización, sin datos reales, máximo 1–2 casos (§5.5) |

### 9.6 Criterio de éxito a los 30 días

Seis preguntas, sí o no:

| # | Pregunta | Si es NO, el mes 2 empieza arreglando esto |
|:-:|---|---|
| 1 | ¿Tengo el RoE base y el addendum de Fase 2 cerrados y firmables? | Nada se vende hasta que esto esté |
| 2 | ¿Tengo la póliza de RC profesional vigente y la cobertura confirmada por escrito? | No se vende Fase 2 |
| 3 | ¿Tengo las 7 preguntas legales respondidas por escrito por un abogado? | Se vende, pero con riesgo propio. **Hay que hacerlo en el mes 2** |
| 4 | ¿He cerrado y facturado un engagement de Fase 0 con horas medidas? | No hay método, sólo teoría |
| 5 | ¿Mi web tiene la metodología y el RoE descargable? | No hay cliente entrante sin esto; no hay venta entrante |
| 6 | ¿He enviado 5 propuestas? | Sin propuestas no hay embudo. Esto es lo único que depende 100 % de la acción del mes 4 |

---

## Apéndice — Trazabilidad del documento

**De dónde sale cada cosa:**

| Bloque | Fuente en el repo |
|---|---|
| Los 3 paquetes, sus precios, exclusiones y precondiciones | [`../02-plantillas/propuesta-comercial/paquetes-por-fase.md`](../02-plantillas/propuesta-comercial/paquetes-por-fase.md) — **fuente autoritativa de precios** |
| Doctrina de severidad, ICE, las tres capas, «Lo que ya está bien» | [`como-presentar-resultados.md`](como-presentar-resultados.md) |
| Prohibiciones duras, ritmo, hallazgos de terceros, plantilla de RoE | [`reglas-de-autorizacion-y-roe.md`](reglas-de-autorizacion-y-roe.md) |
| Las 11 fases y las dos lecciones duras | [`ciclo-de-auditoria.md`](ciclo-de-auditoria.md) |
| Las 6 técnicas de Fase 2, ventana, "go", abort, minimización, no divulgación, retención | [`../05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md`](../05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md) |
| RoE de ejemplo, check-list de arranque, plazo de retención de 12 meses | [`../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md`](../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md) |
| Marco legal en México, seguros, precios por profundidad, retainer, y la ruta de aprendizaje | [`../04-formacion/03-modelo-de-negocio-y-legal-mx.md`](../04-formacion/03-modelo-de-negocio-y-legal-mx.md) |
| Los 7 scripts, su alcance, sus limitaciones | [`../01-tooling/scripts/README.md`](../01-tooling/scripts/README.md) |
| Contenido de las tres capas, reglas del teaser, `verify.py` | [`../02-plantillas/teaser-report/README.md`](../02-plantillas/teaser-report/README.md) |
| Estructura de la propuesta comercial | [`../02-plantillas/propuesta-comercial/README.md`](../02-plantillas/propuesta-comercial/README.md) |
| Laboratorio, herramientas, formación | [`../04-formacion/01-lab-seguro.md`](../04-formacion/01-lab-seguro.md) · [`../04-formacion/02-herramientas-y-python.md`](../04-formacion/02-herramientas-y-python.md) |
| Estado real de la formación (guía pendiente) | [`../04-formacion/LEEME.md`](../04-formacion/LEEME.md) |

**Lo que este documento NO cambia:** ningún otro archivo del repositorio. Los
precios que aquí se citan son los que ya estaban fijados; si mañana cambian,
cambian en `paquetes-por-fase.md` y en `04-formacion/03` §3.1, y este
documento se actualiza.

**Lo que este documento NO es:** asesoría legal, un estudio de mercado, ni una
propuesta comercial. Es el método para convertir la metodología en negocio.

**⚠️ Un pendiente heredado, señalado aquí para que no se pierda:** el teaser ya
publicado (`../02-plantillas/teaser-report/`) cita **cifras de coste de
filtración** procedentes de un informe de mercado de terceros. Este documento
**no las repite** por ninguna razón, y no las he verificado en fuente primaria
en este entorno. **Antes de reutilizar esas cifras en material comercial nuevo
—otra propuesta, otra web, otro perfil— hay que volver al informe original,
comprobar que la edición y la metodología siguen siendo las que se citan y
actualizar la referencia.** Es exactamente el mismo principio que §4.b aplica a
la ley: *nunca cites de memoria, ni de segunda mano, lo que no has abierto*.

**Inconsistencias detectadas en el repo (no modificadas aquí, sólo señaladas):**

| # | Inconsistencia | Dónde | Qué hacer |
|:-:|---|---|---|
| 1 | **Plazos de retención de la evidencia distintos**: 12 meses tras la entrega en el RoE de ejemplo, frente a 30 días naturales para la evidencia de Fase 2 en el addendum. | `05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md` §6 vs. `addendum-fase-2-explotacion-limitada.EJEMPLO.md` §5.3 | No es contradictorio (la evidencia de Fase 2 se destruye antes), pero **hay que decirlo así en el contrato** y **fijar el plazo de Fases 0 y 1**, que hoy sólo existe en un ejemplo |
| 2 | **Las horas por paquete no estaban fijadas** en ningún archivo. | Este documento las introduce como rangos **ilustrativos** (10–18 / 20–35 / 16–28 h) | Medir `h_i` real en el primer engagement y corregir el rango en §2.0 y §5 |
| 3 | **La guía de formación no está escrita**: `04-formacion/LEEME.md` es un placeholder que dice que la guía falta. | `04-formacion/LEEME.md` | Es la tarea #1 de la semana 1 (§9.1). Sin ella no hay segundo auditor y no hay escalabilidad |
| 4 | **`research/` es de otra línea de producto** (assessments de personalidad / HR-tech). | `research/01`, `02`, `03`, `04`, `07` | No traslado ninguna cifra. Si alguien compara este modelo con un precio de `research/`, la comparación es un error |
