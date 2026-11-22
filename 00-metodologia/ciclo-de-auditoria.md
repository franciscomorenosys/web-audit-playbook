# Ciclo de auditoría

El proceso real, fase por fase, generalizado a partir de dos pasadas sobre
`dentaleasy.mx` (octubre 2026). No es un check-list teórico: cada fase dice qué
se hizo, qué se guardó y **qué salió mal** para que no se repita.

Cada fase produce un bloque de evidencia con nombre estable dentro de
`03-casos/<cliente>/evidencia/`. Nombra los archivos por lo que son, no por la
herramienta que los produjo (`tls_versions.txt`, no `openssl.txt`).

---

## Regla de oro que gobierna las 11 fases

> **Cada afirmación del informe debe poder rastrearse a un archivo de evidencia.**
> Si no hay archivo, no hay hallazgo. Si no hay hallazgo, no hay severidad.

Por eso el registro de acciones (`05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv`)
lleva una columna `evidencia` y otra `comando_reproduccion`. Un hallazgo sin
comando reproducible se puede reproducir —o refutar— por cualquiera. Uno sin
comando es una opinión, y las opiniones no se venden como auditorías.

---

## Fase 1 — Alcance y autorización

**Objetivo.** Nada empieza hasta que está escrito qué se puede tocar y qué no.

**Acciones.**
1. Identificar el dominio raíz y **todos** los hosts que pertenecen al cliente
   (apex, `www`, y subdominios que el cliente confirme). Distinguir
   explícitamente «dominio del cliente» de «dominio de terceros que el cliente
   usa» (agencia, hosting, SaaS de reservas).
2. Redactar y **firmar** el RoE. Plantilla en
   `00-metodologia/reglas-de-autorizacion-y-roe.md`; ejemplo relleno en
   `05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md`.
3. Fijar la **modalidad**: pasiva / activa-baja tasa / activa-controlada.
   Cambiar de modalidad requiere una nueva firma, no una decisión a mitad de
   camino.
4. Nombrar al **responsable técnico del cliente** que receive las escalaciones.
   En este caso la mayoría del riesgo no estaba en el cliente: estaba en
   HostGator y en la agencia web. Sin saber a quién escalar, la auditoría
   produce un informe que nadie puede ejecutar.

**Evidencia.** Copia firmada del RoE; tabla de hosts en alcance / fuera de
alcance.

**Lección aprendida.** El RoE no es un trámite: define qué puedes decir «no
probé». Aquí eso salvó dos decisiones (F15 XML-RPC y F25 Apps Script): sin RoE
explícito, la tentación de hacer un POST «solo para ver» era real, y un POST
contra un endpoint con datos de pacientes puede tener consecuencias que ninguna
región gris cubre.

---

## Fase 2 — Reconocimiento pasivo

**Objetivo.** Mapear la superficie sin tocar el objetivo.

**Herramientas.** crt.sh, Wayback CDX, `gau`/`waybackurls`, Common Crawl,
urlscan.io (**solo búsqueda**), ipinfo, `retire.js` sobre JS ya descargado.

**Acciones.**
- crt.sh con `%` para listar todos los subdominios alguna vez certificados.
- CDX de Wayback filtrando por código de estado y extensión: buscar
  `*.sql`, `*.bak`, `wp-config`, `pruebas`, `dev`, `beta`, `staging`.
- Descargar el HTML de las páginas principales. **Guardar el HTML crudo tal
  cual** — es la evidencia de todo lo que viene después. En este caso
  `home.html` + `pages/*.html` + `js/*` son la base de las fases 5 y 6.

**Evidencia.** `crtsh_*.json`, `cdx*.json`, `wb*.json`, `pages/`, `js/`.

**Lección aprendida.** Descargar el HTML y guardarlo **antes** de analizarlo es
lo que hizo posible la fase 6 (secretos) y la fase 5 (on-page) sin volver a
golpear el servidor. Cada petición es gratis de hacer y cara de repetir.

---

## Fase 3 — Infraestructura y DNS

**Objetivo.** Resolver a quién pertenece la infraestructura, dónde vive y qué
superficie extra expone.

**Herramientas.** `dig`, Shodan InternetDB, ipinfo.io, `openssl s_client` (para
el certificado).

**Acciones.**
- `dig` para A, AAAA, MX, TXT, NS, CAA, CNAME.
- Repetir las consultas de email (SPF/DKIM/DMARC) contra **8.8.8.8, 1.1.1.1 y
  9.9.9.9**, no solo contra el resolver local. Un NXDOMAIN de un solo resolver
  puede ser caché o filtrado; tres resolvers independientes coincidentes es
  evidencia.
- Comprobar si el CNAME de `webmail` apunta a infraestructura viva
  (aquí: `titan.hostgator.mx` → CloudFront). Un CNAME que no resuelve es un
  candidato a *subdomain takeover*; uno que sí resuelve no lo es. **No se
  intentó tomar el control de nada.**
- Cruzar el certificado (SAN) con crt.sh para descubrir **otros inquilinos del
  mismo host**. Esto es lo que destapó F31/F32.

**Evidencia.** `dns_*.txt`, `dns_mailsec.txt`, `tls_cert.txt`, `crtsh_*.json`.

**Lección aprendida.** La geolocalización de la IP (São Paulo, BR) no es un
detalle: bajo LFPDPPP, dónde se almacenan los datos de pacientes es un hallazgo
de cumplimiento, no de infraestructura. Y el CN del certificado
(`mail.ortopedista-trauma.com.mx` en el certificado de `dentaleasy.mx`) no es un
detalle de configuración: significa que los nombres de los inquilinos
validados cruzados entre sí. **El certificado es el objeto que más tenants
revela en una auditoría pasiva.**

---

## Fase 4 — Transporte y TLS

**Objetivo.** Determinar versiones, cipher suites, redirección HTTP→HTTPS,
HSTS, OCSP/SCT stapling y cabeceras de seguridad.

**Herramientas.** `openssl s_client`, `curl`, Mozilla Observatory, SSL Labs API,
internet.nl.

### 🔴 La lección (b): el falso positivo de `--tlsv1.0`

**Lo que pasó.** En la primera pasada, esta secuencia:

```bash
curl -s --tlsv1.0 https://dentaleasy.mx/ -w '%{http_code} ssl=%{ssl_verify_result}'
# -> 200
```

se interpretó como *«el servidor acepta TLS 1.0»*, y se escribió como hallazgo.
**Era falso, por dos razones independientes que se refuerzan:**

1. **`--tlsv1.0` es un MÍNIMO, no un valor exacto.** En curl, `--tlsv1.x` fija
   la versión *mínima* negociable; no restringe a esa versión. El servidor
   happily negocia **TLS 1.3** y devuelve 200. El test no probaba nada sobre
   1.0. Para *fijar* la versión máxima hay que combinarla con `--tls-max`:
   `--tlsv1.0 --tls-max 1.0`. *(Y aun así curl suele necesitar `--ciphers` o el
   proveedor legacy de OpenSSL.)*
2. **`ssl=0` del propio curl lo delataba y no se leyó.** `ssl_verify_result=0`
   significa «verificación SSL correcta», no «se usó SSL»; la señal de que la
   conexión **no** fue TLS era que no aparecía el indicador correspondiente. Se
   ignoró.

3. **El lado OpenSSL también mentía, por otra razón.** `openssl s_client -tls1`
   devolvía `no protocols available` — eso es la **política local** del OpenSSL
   3.x (`SECLEVEL`, provider `legacy` deshabilitado), no el servidor rechazando
   nada. Sin forzar `-provider legacy -provider default`, ese error dice
   *nada* del servidor.

**Cómo se corrigió.** Con el proveedor legacy forzado y la versión fijada de
verdad, el servidor responde `tlsv1 alert protocol version` (**alert 70**) para
1.0 y 1.1 → **el servidor los RECHAZA correctamente**. El hallazgo original era
falso y se corrigió a LOW/informativo en la pasada 2 (F23, explícitamente
rotulado «CORRECTION to prior pass»).

**La regla que sale de aquí:**

> **Nunca afirmes qué versiones TLS acepta un servidor a partir de un cliente
> que puede tenerlas deshabilitadas, ni a partir de un flag que significa
> “mínimo”.** Para cada versión, hay que *fijar* el máximo (`--tls-max`), *forzar*
> el provider legacy si el error es local, y *leer* qué versión se negoció
> realmente (`%{ssl_version}` / la línea `New, TLSv1.x` de `s_client`).
> Si el cliente no puede ni intentar la versión, el resultado es
> **inconcluyente, no negativo ni positivo.**

La lección mayor no es sobre TLS: es que **un resultado que no se puede
distinguir de un error del propio cliente nunca debe convertirse en un
hallazgo.** Cuando dudes, es `INFO`, no `MEDIUM`.

**Evidencia.** `tls_versions.txt` (el bueno, con `New, TLSv1.x` explícito),
`tls_floor.txt` (el de la pasada 1, conservado *a propósito* para que el
falso positivo quede documentado), `tls12.txt`, `tlsfull.txt`, `headers_https.txt`,
`obs.json`, `observatory_*.txt`.

---

## Fase 5 — Análisis de plataforma web

**Objetivo.** Identificar el stack (versión, plugins, temas, JS), el
comportamiento del caché y la calidad on-page.

**Herramientas.** `curl`, `whatweb`, WPScan, Lighthouse, PSI API, `analyze.py`,
`water.py`, `audit2/probe.sh`.

**Acciones.**
- Extraer versiones del `<meta name="generator">`, `readme.txt`, y los headers
  `X-Powered-By`. **Guardar los valores literales** — luego la fase 6 los
  contrasta contra fuentes primarias.
- Descargar los sitemaps (`sm/`) para ver el índice real de páginas.
- Ejecutar el waterfall de peso por clase de asset y separar los third-party.
- Buscar las incoherencias de caché: contenido byte-idéntico entre `http://` y
  `https://` (mismo sha256), soft-404 (`/administrator/` → 200 con template 404),
  y respuestas 404 que se sirven cacheadas.

**Evidencia.** `home.html`, `pages/`, `js/`, `sm/`, `onpage.json`,
`onpage_report.txt`, `waterfall.txt`, `wpjson.json`, `headers_https.txt`,
`redirect_chain.txt`.

**Lección aprendida.** **Los valores de versión vienen de HTML cacheado, no del
servidor en ejecución.** Aquí la caché servía *seis* valores distintos de
`generator`. Por eso el informe no dice «el sitio corre 6.8.1» sino «la caché
contiene instantáneas de seis puntos de la historia del sitio». Esta distinción
-es de precisión, no de estilo- se mantuvo en cada fila del registro de riesgo.

### 🔴 La lección (a): verificar contra la fuente primaria

**Lo que pasó.** `retire.js` marcó jQuery 3.7.1 con `CVE-2020-11022` y
`CVE-2020-11023` (ambas XSS en `htmlPrefilter`, ambas **fijadas en 3.5.0**).
Reportarlo como vulnerabilidad habría sido un falso positivo de tabla de rangos
desactualizada: 3.7.1 > 3.5.0, no vulnerable.

**¿Cuál es la regla general que sale de aquí?**

> **Las herramientas de identificación hacen pruebas de *pertenencia*, no de
> *alcanzabilidad*.** Que «el string 6.8.1 cae en el rango 6.8.0–6.8.9» no dice
> que el código vulnerable sea alcanzable, que sus precondiciones se cumplan, ni
> que se haya explotado. Contrasta **toda** afirmación de versión y **todo** CVE
> contra la fuente primaria: la tabla oficial de CVEs del proyecto, el aviso del
> proveedor, la API de versiones. En este caso:
> - WordPress → `api.wordpress.org/core/version-check/1.7/` + los avisos oficiales.
> - PHP → `php.net/archive/2026.php` (el aviso de emergencia, no un scanner).
> - jQuery → la fecha de cada fix en el release oficial.
>
> Cuando la fuente primaria y el scanner discrepan, **gana la fuente primaria
> y se documenta la discrepancia.** Si no puedes llegar a la fuente primaria,
> el hallazgo se marca **«NO VERIFICADO»**, no se da por hecho.

La lección mayor: **el escáner propone, la fuente primaria dispone.** Un informe
que se limita a pegar la salida de un scanner no es una auditoría.

---

## Fase 6 — Divulgación de información

**Objetivo.** Enumerar lo que el sitio expone que no debería: usuarios, medios,
secretos en JS, endpoints, ficheros por defecto, contenido noindexado.

**Herramientas.** Sonda de la REST API de WordPress (`curl`), `scan.py`,
LinkFinder/SecretFinder (si hay bundles), Gitleaks/TruffleHog (si hay código),
`retire.js`.

**Acciones.**
- `/wp-json/wp/v2/users` y el atajo `/?rest_route=`. Comprobar si el atajo elude
  el mismo filtro que la ruta canónica — aquí **eludía el filtro: los dos
  devolvían lo mismo**, lo que significa que no había regla de borde.
- Barrido de regex de secretos en el HTML/JS descargado (`scan.py`): claves AWS,
  Google API keys, Stripe, Slack, GitHub, JWT, claves privadas, URLs firmadas
  S3, deployments de Apps Script. **Redacta** (`xxxx…yy`).
- Enumeración de medios con `x-wp-total` y **revisar los nombres** — si fueran
  nombres de pacientes sería crítico; aquí eran todos de plantilla, así que se
  reportó como LOW y no como HIGH. *Revisar el contenido antes de calibrar la
  severidad.*

**Evidencia.** `users.json`, `wpjson.json`, `media100.json`, `secret_scan.txt`,
`scan.py` y su salida, `pages/` (contenido por defecto), `sm/`.

**Lección aprendida.** El hash MD5 de Gravatar que WordPress sirve en cada
respuesta de la API de usuarios es **un oráculo reutilizable y reversible
offline** para enumerar emails. Eso es un hallazgo, y está reportado como
riesgo — **pero nadie lo ejecutó.** La postura correcta es reportar la
*capacidad*, nunca *demostrar* la preoperative. Ver Fase 6 del RoE.

---

## Fase 7 — Postura de email y phishing

**Objetivo.** ¿Se puede suplantar el dominio por email? ¿Qué material de
pretexting publica el propio sitio?

**Herramientas.** `dig` (SPF/DKIM/DMARC/CAA/BIMI/MTA-STS/TLS-RPT), internet.nl.

**Acciones.**
- `_dmarc.<dominio>` TXT: ausente = dominio completamente falsificable.
- SPF: terminar en `~all` es *softfail*; muchos receptores lo entregan igual.
  Contar los lookups de la cadena `include:` contra el límite de RFC 7208 (10).
- DKIM: ¿cuántos selectores? ¿solo uno? (solo uno impide rotar sin añadir
  registros).
- CAA ausente = cualquier CA pública puede emitir para el dominio.
- BIMI / MTA-STS / TLS-RPT: ausentes = sin TLS entrante forzado y sin indicador
  de marca.

**Evidencia.** `dns_mailsec.txt`, y las filas F01–F06 del registro.

**Lección aprendida.** **DMARC ausente (HIGH) eclipsa todo lo demás de esta
fase.** Un dominio de clínica sin DMARC es un domainspoofing trivial, y el
material de pretexting (teléfonos inconsistentes, «resultados visibles desde el
primer día») amplifica el impacto. En una fase de email, el orden de las
preguntas es: DMARC → SPF strictness → DKIM selectors → CAA → el resto.

---

## Fase 8 — Mapeo a cumplimiento (ley mexicana)

**Objetivo.** Traducir hallazgos técnicos a obligaciones legales concretas y
citables. **Esto es lo que convierte un informe técnico en algo que un dueño de
negocio puede actuar.**

**Herramientas.** Lecta directa de las leyes (fuente primaria, no resúmenes).
Internet para *verificar el texto vigente*, no blogs.

**Marco aplicado.**
- **LFPDPPP (Ley Federal de Protección de Datos Personales en Posesión de los
  Particulares, y sus reformas 2025)** — aviso de privacidad, consentimiento,
  transferencias, ARCO, aviso de vulneraciones. Datos de salud = datos
  sensibles.
- **Ley General de Salud (LGS)** y su Reglamento en Materia de Publicidad —
  cédula profesional obligatoria en publicidad (§2.2); claims prohibidas
  (art. 6 fr. I: «sin dolor»), claims que deben ser comprobables (art. 306).
- **LFPC (Ley Federal de Protección al Consumidor)** — precios, ofertas,
  publicidad engañosa (art. 48–50).
- **LGS art. 83** — cédula profesional.
- **El «debe existir cookie banner en México?»** — se verificó y se **refutó**
  explícitamente: no hay obligación general de banner de cookies en México
  (salvo el aviso de privacidad LFPDPPP). Un hallazgo legal inventado es peor que
  un hallazgo legal omitido.

**Evidencia.** §4 del informe técnico, con cita del artículo y enlace a la
fuente primaria.

**Lección aprendida.** **Verificar o refutar, explícitamente.** Dos preguntas se
plantearon («¿hay obligación de publicar precios?» «¿hay ley que prohíba fotos
antes/después?») y la respuesta fue *refutar* con base en la fuente. Reportar
un refute tan sólido como un hallazgo positivo demuestra rigor y genera confianza
en el resto del informe. **Nunca cites una ley de memoria: léela y enlaza.**

---

## Fase 9 — Registro de riesgos y puntuación

**Objetivo.** Convertir hallazgos en un registro con severidad, probabilidad,
impacto y dueño.

**Herramientas.** `05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv`
como formato de captura.

**Acciones.**
- Cada fila: `id`, `severidad`, `categoría`, `hallazgo`, `evidencia`,
  `comando_reproduccion`, `owner`, `effort_hrs`, `rr_por_hora`, `estado`.
- Puntuación de riesgo agregado = Σ (severidad × exposición).
- **Separa lo que el cliente puede arreglar de lo que no.** Aquí 12 filas eran
  escalaciones que el cliente no podía ejecutar solo (HostGator, agencia) y
  valían la mayoría del riesgo. **Decirle al dueño «esto no lo puedes arreglar
  tú» es uno de los servicios de más valor que puedes dar**, porque dirige su
  energía.

**Evidencia.** `audit2/findings2.tsv`, §5 del informe.

**Lección aprendida.** Calibra la severidad por **contenido**, no por tipo.
El hash de Gravatar «encontrado» es LOW si solo lo vas a reportar; el mismo
hash, más un hallazgo de credenciales expuestas, es HIGH. Mira qué hay
*realmente* detrás del hallazgo antes de calibrarlo.

---

## Fase 10 — Hoja de ruta de remediación

**Objetivo.** Una lista ordenada que el cliente pueda ejecutar, con horas
estimadas y dueño.

**Método: Risk×Effort (ICE), no RICE.** La priorización por
`rr_por_hora` (reducción de riesgo por hora) ordena la cola de trabajo real.
Se eligió ICE sobre RICE porque **RICE necesita reach e impact, métricas de
producto que una auditoría de seguridad no tiene y no puede inventar** — meter
reach inventado es peor que no usar RICE. Ver el detalle en
`00-metodologia/como-presentar-resultados.md`.

**Estructura.** Tres olas:
- 🔴 **OLA 1 — HOY** (~13 h): lo que para daño en curso o retira una violación
  legal cierta.
- 🟧 **OLA 2 — ESTE MES** (~45 h): lo que reduce superficie y riesgo de forma
  estructural.
- 🟩 **OLA 3 — ESTE TRIMESTRE** (~62 h): lo que es:''' hardening y mejora
  sostenida.

**Lección aprendida.** **Cinco de los primeros once ítems de la cola eran
gratuitos o casi gratuitos, de menos de una hora, y detenían un daño en curso o
retiraban una violación legal.** Ese es el hallazgo real de muchos sitios: no
ataques sofisticados, sino omisiones pequeñas y baratas que se acumulan. Di esto
al dueño; cambia la conversación de «hackearon mi web» a «hay veinte cosas
baratas que hacer esta semana».

**Escalaciones.** Además de la hoja de ruta, redacta los **borradores de
ticket** listos para enviar al host y a la agencia (§7 del informe), porque el
dueño no sabe escribir un ticket técnico y perderá el momentum si tiene que
redactarlo él.

---

## Fase 11 — Reporte

**Objetivo.** Comunicar el resultado en **tres capas** para tres audiencias.

**Las tres capas.**
1. **Teaser** (1–13 págs, PDF): venta. Categorías, conteos, severidad,
   exposición legal, **lo que ya está bien**, oferta. **Cero detalle técnico.**
   Plantilla: `02-plantillas/teaser-report/`.
2. **Informe técnico completo** (el §1–§11): para el equipo técnico, hosting,
   agencia. Todo el detalle, comandos, evidencia, refs.
3. **Brief en lenguaje llano** (el §8): para el dueño no técnico. Sin jerga;
   «lo que dice Mozilla es grado F» explicado, «alguien puede suplantar
   nuestro correo» explicado, «la información de pacientes va a una cuenta de
   Google» explicado.

**Lección aprendida.** **«Lo que ya está bien» es obligatorio.** Una auditoría que
solo enumera problemas se lee como marketing y destruye la confianza en las
partes que sí importan. Aquí se documentó explícitamente que el cifrado era fuerte,
que la capa de caché estaba bien arquitectada, que no había fugas de medio
público. Un cliente que ve que valoras lo que funciona, confía en que valoras
lo que no funciona.

**Antes de entregar, siempre:**
- `verify.py` sobre el teaser (cadenas prohibidas + metadatos).
- Verificar que el informe técnico **no** va al cliente, sino a su equipo
  técnico/hosting (banner CONFIDENCIAL).

---

## Apéndice — Qué se conserva y por qué

`evidencia/` guarda **todo**, incluido lo que seopcodeбай resultara erróneo
(`tls_floor.txt`, el falso positivo). Preservar los falsos positivos y las
correcciones **es** la metodología: permite a un tercero auditar tu auditoría.
Un directorio de evidencia donde todo salió bien a la primera es sospechoso.