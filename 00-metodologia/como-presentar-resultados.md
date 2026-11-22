# Cómo presentar resultados

La auditoría no se vende con hallazgos: se vende con **decisiones que el cliente
puede tomar**. Este documento es la doctrina de presentación que se usó en
`dentaleasy.mx` y que sostiene las tres plantillas de `02-plantillas/`.

---

## 1. La matriz de severidad

La severidad se calcula sobre **tres ejes, en este orden**. No es una escala
arbitraria, es el resultado de responder tres preguntas.

| Eje | Pregunta | Ejemplo en `dentaleasy.mx` |
|---|---|---|
| **Exposición** | ¿Qué necesita el atacante para llegar? | ¿Está expuesto a internet? ¿Necesita autenticación? ¿Necesita interacción de la víctima? |
| **Severidad del efecto** | Si se explota, ¿qué pasa? | Ejecución remota de código >Robo de PII >Robo de datos internos >Fuga de versión |
| **Contexto y datos** | ¿Qué hay detrás? | ¿Es una clínica con datos de pacientes? ¿Es una IP compartida? |

### La escala (5 niveles)

| Nivel | Definición operativa | Ejemplo |
|---|---|---|
| **CRÍTICO** | Ejecución remota sin autenticación, o exposición directa de datos sensibles de pacientes con capacidad de lectura/escritura probada. | Endpoint de Apps Script que acepta el expediente del paciente y es públicamente invocable (F25). |
| **ALTO** | Compromiso de cuenta o suplantación trivial de la identidad del cliente, o exposición de datos personales, o vulnerabilidad con severidad upstream alta alcanzable desde internet. | Sin DMARC → el dominio es completamente falsificable (F01). Hash de Gravatar + slug predecible (F08). CN del certificado apunta a otro inquilino (F32). |
| **MEDIO** | Degrada la postura de seguridad o la confianza, y/o viola una obligación legal, pero no da control directo. | SPF en `~all` (F02). Hardening de cabeceras ausente (F22). Datos en Brasil bajo LFPDPPP (F30). |
| **BAJO** | Defense-in-depth ausente, o higiene. Sin impacto directo por sí solo. | Sin HSTS (F19). Sin CAA (F05). Sin stapling OCSP (F21). |
| **INFO** | Observación,Good practice o corrección metodológica. No requiere acción. | **TLS 1.0/1.1 rechazados correctamente** (F23 — un *falso positivo* corregido). |

### Tres reglas de calibración que se aplicaron de verdad

1. **Nunca infles.** El `xmlrpc.php` devolvía `405` en GET, que es **mejor que el
   de la mayoría de sitios**, y así se escribió: «no lo voy a inflar»
   (F15). Un hallazgo honesto de LOW genera más confianza que uno inflado.
2. **Mira el contenido antes de calibrar.** `/wp-json/wp/v2/media` era
   listable (66 ítems) — si hubieraeu patients, sería CRÍTICO. Como todos eran
   ficheros de plantilla (`portada-1`, `dentist-02`), se reportó **LOW** (F10).
   *La severidad viene de lo que hay detrás, no del tipo de endpoint.*
3. **Si no lo puedes verificar, es INFO.** Un hallazgo que depende de una
   versión de PHP que no puedes ver no es ALTO: es **NO VERIFICADO** con la
   comprobación de 60 segundos que hay que hacer (§2.6 del caso). Reportar la
   comprobación pendiente vale más que reportar una hipótesis como hecho.

---

## 2. Priorización: por qué ICE (Risk×Effort) y no RICE

**RICE** = Reach × Impact × Confidence ÷ Effort. Es el framework de
priorización de producto de Intercom.

**Por qué no serve aquí.** RICE necesita *Reach* (cuántos usuarios tocan el
problema) e *Impact* (cuánto les importa). **Una auditoría de seguridad no tiene
ninguna de las dos métricas**, y no las puede inventar:

- *Reach* para «DMARC ausente» — ¿cuántos correos phishing llegan a los pacientes
  de la clínica? No lo sabes. Inventar «todos los clientes» o «el 20%» sería
  fabricar datos.
- *Impact* para «falta HSTS» — medido en qué? En puntos? En euros? No hay un
  modelo de impacto validado para un sitio de clínica sin datos de tráfico reales.

Meter un Reach inventado es **peor que no usar RICE**: produce unapriorización
que parece cuantitativa y que en realidad está arbitraria con dos decimales.

**Lo que sí tienes, y es real:** un **impacto de seguridad** (severidad de la
vulnerabilidad × exposición) y un **effort** (horas estimadas de remediación,
que sí sabes estimar en un sitio web).

> **Por eso se usa `rr_por_hora` — reducción de riesgo por hora:**
>
> ```
> rr_por_hora  =  riesgo_puntual  /  effort_hrs
> ```
>
> Donde `riesgo_puntual` es la severidad ponderada por exposición. La idea es
> simple: **ordena el trabajo por cuánto riesgo quita por cada hora que
> invierte el cliente**, no por «cuál suena más grave».

**Cómo se aplicó.** El riesgo agregado se calculó como Σ (severidad ×
exposición) = **1 029 puntos** en 38 filas, con **~120 h** de remediación total.
La cola de trabajo real salió ordenada por `rr_por_hora`:

| # | Acción | RR/h |
|:-:|---|:-:|
| 1 | Verificar versión de PHP · cambiar contraseña admin + MFA · purgar caché · redirección HTTPS | **20.0** |
| 2 | Quitar dos frases de claims prohibidas | **16.0** |
| 3 | Deshabilitar TLS 1.0/1.1 | 15.0 |
| 4 | Arreglar el calendario de reservas roto | 15.0 |
| 5 | Publicar DMARC | 10.0 |
| 6 | Arreglar los tres números de teléfono | 10.0 |
| … | … | … |

**El hallazgo honesto que sale de ordenar así:**
> *«Cinco de los primeros once ítems son gratuitos o casi gratuitos, toman menos
> de una hora cada uno, y paran un daño en curso o retiran una violación legal
> cierta. Este sitio no está en problemas por atacantes sofisticados: está en
> problemas por omisiones pequeñas, baratas y poco vistosas que se han
> acumulado.»*

Esa frase es **más vendible que cualquier CVE** y es más útil para el cliente.

**Ice sobre RICE, resumido:** RICE ordena *features*; ICE ordena *arreglos*.
No mezcles los dos frameworks en el mismo informe.

---

## 3. Las tres capas del reporte

Un solo documento no puede hablarle simultáneamente a un dueño de clínica, a
un técnico de hosting y a una agencia. Por eso el resultado son **tres
documentos para tres audiencias**, cada uno con su grado de detalle.

### Capa 1 — Teaser (venta / primer contacto)

- **Para quién:** el dueño, el primer contacto. **Nivel técnico: cero.**
- **Formato:** PDF corto (aquí 13 páginas). Plantilla y reglas de contenido en
  `02-plantillas/teaser-report/README.md`.
- **Incluye:** cifras legales exactas, costo del negocio del riesgo, resumen por
  categoría, distribución por severidad, **lo que ya está bien**, la oferta, y
  la convocatoria a reunión.
- **Nunca incluye:** identificadores de vulnerabilidad, severidad estándar,
  versiones de software o protocolos, rutas/URLs/endpoints, comandos, salidas de
  herramientas, usuarios/emails/teléfonos, nombres de herramientas de terceros,
  ni la lista completa de hallazgos individuales.
- **Se valida con `verify.py` antes de entregar**, que extrae el texto del PDF y
  lo pasa por la lista de cadenas prohibidas, además de revisar bytes y
  metadatos. **Correrlo siempre. Es la red de seguridad de la capa 1.**

### Capa 2 — Informe técnico completo

- **Para quién:** técnico del cliente, hosting, agencia. **Detalle máximo.**
- **Formato:** Markdown largo, con tabla de contenidos por secciones (§0–§11).
- **Incluye:** OWASP/WSTG mapping con razonamiento (incluido **qué filas están
  «forzadas» y por qué**), investigación de CVE contra fuente primaria,
  modelado de amenazas de phishing, mapeo legal con cita de artículo, registro
  de riesgo puntuado, hoja de ruta por olas, y **borradores de ticket
  listos para enviar** al host y a la agencia.
- **Marca:** **CONFIDENCIAL. No enviar al dueño final ni a terceros.**
  Va al equipo técnico que puede actuar sobre él.

### Capa 3 — Brief en lenguaje llano (el dueño no técnico)

- **Para quién:** el dueño que va a abrir el teaser. Sin saber leer un `curl`.
- **Formato:** un documento corto, en lenguaje de calle, **sin jerga**.
- **Estructura** (la del caso, que funciona):
  1. «Por qué le escribimos» — en 2 frases, sin jerga.
  2. **«Mozilla dice que nuestro sitio es grado F» — qué significa de verdad.**
     Traducir la métrica a consecuencias.
  3. **«Alguien puede hacerse pasar por nosotros en un correo»** — el problema de
     DMARC explicado como una-persona.
  4. **«La información de pacientes va a una cuenta de Google»** — la parte que
     más preocupa (y que el dueño no sabía).
  5. Dos frases de la web que pueden causar problemas legales.
  6. Lo que pasa si hackean el sitio.
  7. Los números de teléfono como puerta abierta para fraudes.
  8. **Qué le pedimos que haga** — hoy / este mes / este trimestre, **con horas**.
  9. **El resumen honesto.**
- **Regla de oro de esta capa:** cada Affirmation va acompañada de «esto es lo que
  significa para ti», no de «esto es lo que hace la herramienta». Nunca jerga sin
  traducir.

---

## 4. «Lo que ya está bien» es OBLIGATORIO

Una sección/sección-parte llamada **«Lo que ya está bien»** (o «Lo que está
sólido») no es cortesía: es **requisito metodológico**.

**Por qué es obligatorio.**
1. **Credibilidad.** Si solo enumeras problemas, el cliente sospecha que estás
   vendiendo. Enseñar que valoras lo que funciona demuestra que tu juicio es
   real.
2. **T calibrate la severidad.** Reconocer «el cifrado de este sitio es
   fuerte» da peso a «aquí el cifrado es débil». Sin un positivo, tus negativos
   no tienen referencia.
3. **No diseñar el miedo.** Un informe que solo asusta manipula. Reconocer lo
   bueno es lo que hace que el dueño te crea cuando dices «esto sí es grave».

**Qué se incluyó en el caso** (y por qué importa mencionarlo):
- La **suite de cifrados era fuerte** — sólo ECDHE/DHE + AES-GCM, con secreto
  hacia adelante y AEAD. Ningún CBC, ningún RSA estático (F24).
- **No había fugas en la biblioteca de medios** — 66 ficheros, todos de plantilla,
  ningún nombre de paciente (F10).
- **La capa de caché estaba bien arquitectada**, aunque mal purgada (el
  problema era la purga, no el diseño).
- **La versión actual de WordPress estaba al día** (7.1.3); el problema era la
  caché, no WordPress.
- **No se encontraron subdominios colgantes** — ningún candidato a takeover (F35).

**Regla de redacción:** cada positivo se dice **con la misma precisión que un
negativo**, no como adorno. «El cifrado es fuerte porque sólo acepta
ECDHE/DHE+AES-GCM y ningún CBC ni RSA estático» — no «el cifrado está bien».

---

## 5. Reglas de redacción transversales

- **Trazabilidad absoluta.** Todo hallazgo lleva `evidencia` (archivo) y
  `comando_reproduccion`. Lo que no se puede reproducir, no se afirma.
- **Sé honesto sobre los límites.** Si no pudiste verificar algo, escribe
  «no verificado» y di **cómo verificarlo y quién puede hacerlo** (un ticket
  de 60 segundos). La incertidumbre declarada es una debilidad; la
  incertidumbre disfrazada de certeza es una trampa.
- **Distingue los mapeos forzados.** Si un hallazgo **no** encaja en OWASP,
  dilo y mapea al marco que sí (NIST, CIS, MITRE ATT&CK). Una auditoría
  honesta dice «esto no es un OWASP Top 10». Una floja estira el mapeo hasta
  que encaje.
- **Verifica o refuta, explícitamente.** Si alguien pregunta «¿existe obligación
  legal de X?», **responde sí o no, con la fuente**, aunque la respuesta sea
  «no». Un refute sólido genera más confianza que un hallazgo dudoso.
- **Separa lo que el cliente arregla de lo que no.** Enseña al dueño que, de los
  12 hallazgos más graves, varios son escalaciones a HostGator y a la agencia.
  Eso dirige su energía y es parte del servicio.
- **Incluye los borradores de ticket.** El dueño no sabe escribir un ticket
  técnico. Si le mandas el informe sin los tickets redactados, pierde el impulso
  de redactarlos y no hace nada.

---

## 6. Anti-patrones (no hacer esto)

| ❌ No | ✅ Haz esto |
|---|---|
| Inflar severidad para justificar la factura | Calibrar por contenido; un LOW honesto compra la confianza para el resto |
| Pegar la salida del escáner como informe | Contrastar con fuente primaria; el escáner propone, la fuente dispone |
| Escribir «prueba de penetración» | Escribir «revisión pasiva»; no hiciste una pentest y decirlo protege legalmente |
| Findings sin evidencia | Findings con evidencia + comando reproducible |
| Sólo capa 1 (teaser) | Las tres capas; el teaser sin las otras dos es publicidad |
| Costrar el miedo | Priorizar por rr_por_hora y ser honesto sobre qué es barato |
| Dar HTML bonito sin lógica de remediación | Cada hallazgo con owner y horas; la lógica de remediación es el producto |