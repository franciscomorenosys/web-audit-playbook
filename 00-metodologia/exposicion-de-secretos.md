# Exposición de secretos, datos personales y superficie de API

Módulo metodológico que convierte la Fase 6 («Divulgación de información») en una
**disciplina repetible, auditable y vendible**. No sustituye a la Fase 6: la ejecuta
con más profundidad, la separa en tres clases de exposición que exigen herramientas y
tratamiento distintos, y le añade las tres cosas que faltaban en el caso de
`dentaleasy.mx`:

1. **Verificación segura de credenciales** — un protocolo escalonado de cinco niveles
   que permite afirmar *«esta credencial está viva y esto es lo que expone»* sin
   autenticarse contra ningún recurso ajeno, sin escribir nada y sin que el valor
   completo del secreto salga jamás del escritorio del auditor.
2. **Descubrimiento de superficie de API** — de «hay un endpoint raro» a un inventario
   documentado de endpoints con método, autenticación, parámetros, datos que devuelve
   y severidad.
3. **Tratamiento explícito de la exposición de IPs y datos personales** — la parte que
   más fácilmente se hace mal, porque el auditor se convierte sin querer en el primer
   atacante que recolecta datos de pacientes.

---

## Marco de referencia

`reglas-de-autorizacion-y-roe.md` (las cinco prohibiciones duras, el ritmo, el UA
honesto: este módulo **no las relaja**, las aplica) · `ciclo-de-auditoria.md` (Fase 6 y
las lecciones (a) «verificar contra la fuente primaria» y (b) «un resultado
inconcluyente no es un hallazgo») · `fase-2-explotacion-autorizada.md` (**protocolo de
Fase 2**: los Niveles 2/3/4 se ejecutan bajo ese documento, no se duplica aquí) ·
`01-tooling/manifiesto-de-herramientas.md` (§4 herramientas de secretos, §7 candidatas
vetadas) · `01-tooling/scripts/README.md` (el flujo
`scope_guard → probe_exposure → secrets_scan → js_intel → pii_redact → attack_surface_report`) ·
`addendum-fase-2-explotacion-limitada.EJEMPLO.md` (técnicas T1–T6; este módulo **se
apoya en T5 y T6**, no las reescribe) · `como-presentar-resultados.md` (matriz de
severidad de 5 niveles y escala ICE).

### Doctrina que este módulo hereda sin cambiar

**El daño > el hallazgo.** **Reporta la capacidad, no la explotación.** **El escáner
propone, la fuente primaria dispone.** **Verificar o refutar, explícitamente.** Y:
**un resultado que no se puede distinguir de un error del propio cliente nunca se
convierte en un hallazgo** — si dudas, es `INFO`, no `MEDIUM`.

> **Un secreto publicado no es un hallazgo; un secreto publicado *vivo*, con alcance
> conocido, es un hallazgo. Y un hallazgo cuyo valor completo vive en tu disco es un
> problema de tu escritorio, no del cliente.**

---

## 1. El modelo mental: tres clases de exposición

La Fase 6 original era una lista: «esto se busca, esto se encontró». Este módulo la
organiza en **tres clases**. La razón de la taxonomía no es estética: cada clase
tiene una **prueba distinta**, un **riesgo distinto de causar daño al investigarla** y
un **destinatario distinto** en el informe.

| Clase | Qué es | Riesgo de la investigación | Destinatario en el informe |
|---|---|---|---|
| **(a) Secreto publicado** | Credencial o clave en un lugar público: JS, `.env`, repo, backup, log público, source map, sitemap. | Bajo si sólo se lee. **Alto** si se intenta usar la credencial contra algo que no sea del cliente. | Equipo técnico. Rotación inmediata. |
| **(b) Dato personal expuesto** | IP sin enmascarar, email, identificador de expediente, historial clínico, cookie de sesión. | **Muy alto**: cualquier recolecta del auditor crea un fichero de datos personales que no tenías derecho a tener. | DPO / responsable legal, con datos minimizados. |
| **(c) Superficie de API descubierta** | Endpoints no documentados, paneles, GraphQL, OpenAPI, actuator. | Medio: probar sin cuenta puede tocar recursos de terceros. | Equipo técnico + §7 del informe. |

### 1.1 Clase (a) — Secreto publicado

**Qué se busca.** Cualquier cadena con **prefijo o formato reconocible** de proveedor
(`sk_live_`, `sk-ant-`, `AIza`, `ghp_`, `AKIA`, `xox`, `SG.`, `whsec_`, `glpat-`,
`AC`/`SK` de Twilio); con **entropía alta** y longitud compatible con una credencial; un
**bloque de clave privada** (`-----BEGIN … PRIVATE KEY-----`); una **URI de conexión
con usuario y contraseña embebidos**; un **JWT** (tres segmentos, cabecera base64url
`eyJ`); un **token de registry** (`_authToken` en `.npmrc`, `pypi-…` en `.pypirc`); o
una **asignación a variable con nombre de credencial** (`password=`, `api_key=`,
`client_secret=`).

**Qué evidencia lo prueba.**
- La **existencia del fichero o ruta** con su código de respuesta, `Content-Type`,
  `Content-Length` y `ETag`.
- El **fichero local** con el hallazgo: ruta, línea, tipo de patrón, valor **enmascarado**
  (`abcd******yz`) y `sha256[:12]` del valor. Esto lo produce `secrets_scan.py`.
- El **hash del cuerpo** para que la evidencia sea reproducible sin volver a descargarlo.
- En Fase 2, la **respuesta de la API del proveedor** (código + nombres de campo, nunca
  el cuerpo).

**Qué NO se hace con ello.**
- No se usa el secreto contra **ningún recurso que no sea del cliente** (prohibiciones
  1.2 y 1.4), ni se escribe o revierte para «ver si funciona» fuera del protocolo §3.
- No se fuerza bruta: **nunca** se prueba un par usuario/contraseña contra la base de
  datos, la API de login o el buzón. `h8mail` está vetado por el manifiesto (§7) y este
  módulo lo mantiene vetado.
- No se transcribe el valor completo ni en una nota interna. La rotación la hace el
  cliente.

### 1.2 Clase (b) — Dato personal expuesto

**Qué se busca.** Exposición de identificadores que permitan reconstruir quién fue el
paciente, dónde estuvo, qué se le hizo o qué se le recetó:
- **IP del visitante** sin enmascarar en logs, cabeceras de respuesta, páginas de error,
  analítica, correos de error o cabeceras `X-Forwarded-For` reflejadas.
- **Email y teléfono** de pacientes en HTML público, en `mailto:` de terceros, en
  comentarios, en `sitemap.xml` o en un JSON de contenido.
- **Identificadores de expediente**, CURP/RFC/NSS, números de póliza, fechas de
  nacimiento, diagnósticos.
- **Historial de navegación o de citas** (cookies de sesión, `localStorage`,
  `sessionStorage`, parámetros `?token=`/`?session=` en URLs de terceros).
- **Cookies de sesión** de administración servidas en respuestas que se pueden guardar.

**Qué evidencia lo prueba.**
- **La presencia del patrón**, con su categoría y su **conteo**, y el fichero o ruta
  donde aparece. `pii_redact.py` produce exactamente esto: un informe de **conteos por
  categoría, nunca valores**.
- La **cabecera o el fragmento de código** con el valor enmascarado.
- El **código de estado y el `Content-Type`** del endpoint que lo sirve.
- Para la IP del visitante: la **cabecera de respuesta** que la refleja, o la
  **plantilla del log** que la vuelca.

**Qué NO se hace con ello.**
- **No se recolectan IPs de pacientes para «ver qué tan expuesto» está.** Eso crea un
  fichero de datos personales que el auditor no tenía derecho a tener. La demostración
  es **contar, no recolectar**: se demuestra que la IP aparece sin enmascarar; no se
  hace una lista de las IPs de los pacientes que visitan el sitio.
- No se recuperan historiales, no se descargan adjuntos clínicos, no se enumeran
  expedientes, no se copian datos a un gestor de tareas, a un chat, a un drive ni a un
  servicio de IA externo.
- La evidencia que sale del escritorio del auditor **pasa por `pii_redact.py` antes**
  de compartirse. Ver §9.

### 1.3 Clase (c) — Superficie de API descubierta

**Qué se busca.** Rutas y capacidades que el cliente no documenta y que pueden ampliar
la superficie de forma notable:
- endpoints **sin autenticación** que devuelven datos de pacientes;
- endpoints **sin control de acceso por objeto** (IDOR/BOLA);
- **documentación viva** (OpenAPI/Swagger, GraphQL introspection, `api-docs`);
- **paneles de administración** y de base de datos;
- **endpoints de diagnóstico** (`actuator/*`, `phpinfo.php`, `server-status`,
  `elmah.axd`, `trace.axd`);
- **superficie de terceros** a la que el navegador del paciente envía datos
  (Apps Script, webhooks, CRM, pasarelas de pago).

**Qué evidencia lo prueba.**
- El **código de respuesta, `Content-Type`, tamaño y forma** de la respuesta (para
  GraphQL, la presencia de `__schema` en la respuesta; para REST, el **conjunto de
  claves del JSON**, no sus valores).
- El **TSV de `probe_exposure.py`** con `host path code content_type length sha256
  soft_404 verdict severity`.
- La **extracción de `js_intel.py`**: endpoints absolutos y relativos, rutas sensibles,
  operaciones GraphQL, hosts de terceros clasificados, source maps, scripts sin SRI.

**Qué NO se hace con ello.**
- No se **lista** un endpoint que devuelve datos de pacientes: se reporta ruta, código
  y tipo. Si exige autenticación, se reporta `401` y se para.
- No se enumeran IDs masivamente (RoE: nada de fuerza bruta de rutas ni de IDs).
- No se prueba IDOR sin **dos cuentas de prueba** entregadas por el cliente.
- No se mide el rate limiting: medirlo exige muchas peticiones y está prohibido.

### 1.4 La regla que une las tres clases

> **El valor de un hallazgo no es el hallazgo; es el daño que el hallazgo permite y la
> facilidad con que se puede ejecutar.**

Esa frase se operacionaliza en tres preguntas obligatorias antes de escribir cualquier
fila de severidad:

1. **¿Qué se necesita para llegar?** (internet, sin autenticación, con una cuenta
   cualquiera, con una cuenta del cliente)
2. **¿Qué pasa si se llega?** (nada / exposición de datos de pacientes / control de la
   cuenta / control del servidor)
3. **¿Qué hay detrás?** (datos de salud, facturación, una IP compartida, un proveedor
   externo)

Las respuestas dan la severidad según la matriz de
`00-metodologia/como-presentar-resultados.md` §1. **Un secreto en una página que no
carga en ningún sitio es MEDIO; el mismo secreto en el `main.js` que carga en todas
las páginas es CRÍTICO.** La severidad viene de **lo que hay detrás**, no del tipo de
vector.

---

## 2. Inventario de vectores de exposición

### 2.1 La tabla

Cómo se detecta cada vector, con qué herramienta, en qué modo, qué evidencia produce y
la nota de licencia de la herramienta. La columna **modo** usa la taxonomía del
manifiesto: `PASIVA` (sólo terceros o material ya descargado) y `ACTIVA-L` (GET/HEAD
al objetivo, ≥1 s de espaciado).

> **Ninguna de estas filas se ejecuta sin RoE firmado.** `probe_exposure.py` y
> `scope_guard.py` exigen un `authorization.json` con firma; sin él abortan con
> código 2 y no hacen ninguna petición.

| # | Vector | Cómo se detecta | Herramienta | Modo | Evidencia que produce | Nota de licencia |
|:-:|---|---|---|---|---|---|
| V01 | **`.env`** y variantes (`.env.local`, `.env.production`, `.env.development`, `.env.backup`, `.env.example` con valores reales, `.env.dist`) | GET directo a la ruta; detección por nombre de variable en HTML/JS descargado | `probe_exposure.py` (`/.env`, `/.env.local`, `/.env.production`, `/.env.development`) + `secrets_scan.py` | ACTIVA-L (ruta) + PASIVA (escaneo local) | TSV con `code`, `content_type`, `length`, `sha256`; `secrets.json` con tipo, línea, `masked`, `sha256` | Script propio — Python stdlib, sin dependencia externa |
| V02 | **`.git/`** (`HEAD`, `config`, `index`) | GET a `/.git/HEAD` y `/.git/config`; si responde `200`, el repo es descargable | `probe_exposure.py` | ACTIVA-L | Código, `Content-Type` (`text/plain`), longitud, `sha256` | Script propio |
| V03 | **`.svn/entries`**, **`.hg/requires`** | GET directo; típico de repositorios anticuados en hosting compartido | `probe_exposure.py` | ACTIVA-L | Código y longitud | Script propio |
| V04 | **`.DS_Store`** | GET directo. Fuga de nombres de fichero y estructura de carpetas (nombres de pacientes en la carмена del cliente) | `probe_exposure.py` | ACTIVA-L | Código, `length`, `sha256` | Script propio |
| V05 | **Backups genéricos** (`.bak`, `.old`, `~`, `.zip`, `.tar.gz`, `.sql`, `.swp`) · **`wp-config.php.bak`**, `wp-config.php~`, `config.php.bak` | Lista fija de rutas + derivación del nombre desde `sitemap.xml` y enlaces del HTML. El backup de WordPress es el patrón más común del ecosistema | `probe_exposure.py` (`/backup.zip`, `/backup.tar.gz`, `/db.sql`, `/dump.sql`, `/wp-config.php.bak`) + `curl -r 0-1023` | ACTIVA-L | Existencia con `Range: bytes=0-1023`; **no** el fichero completo. Si un `wp-config` da `200`, ver §4 | Script propio |
| V07 | **`phpinfo.php`** | GET directo. Expone `php.ini`, variables de entorno, rutas absolutas, módulos cargados y **credenciales de BD en `$_SERVER`/`$_ENV`** | `probe_exposure.py` (`critico`) | ACTIVA-L | Código, `length`. **El cuerpo no se guarda** salvo `--also-store` explícito | Script propio |
| V08 | **`composer.lock`**, **`package-lock.json`**, **`yarn.lock`** → dependencias → CVE | GET directo (existencia) + lectura local para extraer versiones exactas | `probe_exposure.py` + `secrets_scan.py` (para credenciales en `resolved`/URLs de registry) | ACTIVA-L (ruta) + PASIVA (local) | Lista de paquetes con versión exacta → **contrastar cada CVE contra la fuente primaria del proyecto** (lección (a)) | Script propio. Los lockfiles son del proyecto cliente: no hay licencia que redistribuir |
| V09 | **Source maps** (`*.js.map`, `*.map`) | `js_intel.py` busca `//# sourceMappingURL=`; si aparece, GET al `.map` | `js_intel.py` + `probe_exposure.py --path-list` | ACTIVA-L | Presencia del `.map`, tamaño. Un source map puede contener **el código original completo**, rutas, y a veces constantes | Script propio |
| V10 | **`config.json`** · **ficheros de configuración de framework**: `.htaccess`, `web.config`, `nginx.conf` publicado | GET directo; búsqueda de nombres típicos en HTML/JS | `probe_exposure.py` (`/config.json`, `/.htaccess`, `/web.config`) + `secrets_scan.py` | ACTIVA-L + PASIVA | Código, `length`, patrones encontrados. Un `web.config` publicado puede contener `<add key="connectionString" …>` | Script propio |
| V11 | **`.npmrc` con `_authToken`**, **`.pypirc`** | En repositorio: `secrets_scan.py` (patrones `npm_auth_token`, `pypi_password`). En web: GET a `/.npmrc`, `/.pypirc` | `secrets_scan.py` + `probe_exposure.py --path-list` | PASIVA (repo) / ACTIVA-L (web) | `masked` + `sha256[:12]`. **Nunca** se ejecutan `npm publish` ni `pip upload` con esas credenciales | Script propio. La regla general de AGPL/GPL del manifiesto §6 aplica a la herramienta, no al token |
| V12 | **`credentials.json` de service accounts** (GCP) | En repo: patrón `service_account_json` + `service_account_client_email`. En web: GET a rutas típicas (`/credentials.json`, `/service-account.json`, `/gcp-credentials.json`) | `secrets_scan.py` + `probe_exposure.py --path-list` | PASIVA / ACTIVA-L | Presencia de `private_key` y `client_email` (el email de la SA **no es secreto** y sí es evidencia) | Script propio |
| V13 | **`firebase-messaging-sw.js`** · **`manifest.json`** (PWA) | GET o referencias desde el HTML; búsqueda de `firebase` en el JS. El manifest a veces referencia endpoints, imágenes de splash con datos, o `start_url` con token | `probe_exposure.py --path-list` + `js_intel.py` | ACTIVA-L + PASIVA | Código, `length`. Verificar `databaseRules` de Firebase **separadamente** — es la parte crítica | Script propio |
| V15 | **`sitemap.xml`** · **`robots.txt`** | GET directo. El sitemap es **la fuente más barata del vector V05**: de aquí salen los nombres reales de los ficheros de backup. Un `Disallow: /backup/` en el robots es una **declaración de que ese directorio existe** | `probe_exposure.py` (ambos guardan el cuerpo: son `SAFE_BODY_PATHS`) | ACTIVA-L | Cuerpos completos en evidencia (públicos por definición) | Script propio |
| V16 | **`humans.txt`** · **`security.txt`** (`.well-known/security.txt` y `/security.txt`) | GET directo. `humans.txt` sirve para inventariar autores declarados. `security.txt` es **vector positivo**: es el canal que el cliente tiene para reportar incidentes, y se audita para verificar que exista y sea alcanzable | `probe_exposure.py` (`security.txt` guarda el cuerpo; `humans.txt` vía `--path-list`) | ACTIVA-L | Cuerpos; en `security.txt`, fecha de expiración y canal de contacto | Script propio |
| V19 | **`crossdomain.xml`**, **`clientaccesspolicy.xml`** | GET directo. Permiten a un origen externo pedir datos a la política del cliente | `probe_exposure.py` | ACTIVA-L | Cuerpo. Si permiten `allow-access-from domain="*"`, es un hallazgo de configuración de origen | Script propio |
| V20 | **`swagger.json`**, **`openapi.json`**, **`api-docs`**, **`swagger-ui/`**, **`redoc`** | GET directo. Documentan el contrato de la API: rutas, parámetros, **esquemas de respuesta** | `probe_exposure.py` (`/swagger.json`, `/openapi.json`, `/api-docs`, `/swagger-ui/`); `redoc` vía `--path-list` | ACTIVA-L | Código, `length`, y (sólo si el cliente lo pide) la lista de rutas. **Ver §7** | Script propio |
| V21 | **`graphql`**, **`graphiql`**, **`playground`** | GET directo; `js_intel.py` detecta operaciones GraphQL en el JS | `probe_exposure.py` + `js_intel.py` | ACTIVA-L + PASIVA | Código, `length`, presencia de `__schema` | Script propio |
| V22 | **`actuator/env`** · **`actuator/health`** · **`actuator/mappings`** · **`server-status`** | GET directo (Spring Boot / Apache `mod_status`). `actuator/env` expone el entorno de la aplicación, **incluidas credenciales**; `actuator/mappings` expone el mapa de rutas = inventario de API; `server-status` expone peticiones en curso, VirtualHost, user-agent y **IP de origen** | `probe_exposure.py` | ACTIVA-L | Código, `length`. **El cuerpo no se guarda por defecto.** Si `server-status` devuelve `200`, su cuerpo contiene IPs de visitantes → activo clase (b) | Script propio |
| V24 | **Paneles**: `/admin/`, `/administrator/`, `/wp-admin/`, `/phpmyadmin/`, `/adminer.php` | GET directo. Un panel de base de datos expuesto es crítico por definición | `probe_exposure.py` | ACTIVA-L | Código, `length`, `Location` de la redirección a login. **No se introduce usuario ni contraseña** | Script propio |
| V25 | **Fugas del propio cliente en GitHub** | Búsqueda del nombre del dominio, del nombre comercial y de correos `*@dominio` en la búsqueda de código de GitHub. **Sólo del cliente** | API de búsqueda de GitHub (con token) o `gitleaks` sobre un repo propio | PASIVA | URLs y repos. El token del auditor **no** es el del cliente | Gitleaks **MIT**. La API de GitHub es SaaS propietario con límites de tasa |
| V26 | **Google dorks** — **sólo del propio cliente** | Operadores `site:` restringidos al dominio del cliente, combinados con `ext:`, `filetype:`, `inurl:`. **Nunca** contra dominios de terceros | Búsqueda web manual | PASIVA | URLs indexadas. La sesión del buscador es la del auditor: **no se automatiza ni se escala** | Motor de búsqueda: SaaS propietario. Sus Términos de Servicio regulan el uso automatizado → **nunca automatizar** |
| V27 | **Webhooks Discord / Slack** en código o HTML | `secrets_scan.py` (patrones `discord_webhook`, `slack_webhook`) | `secrets_scan.py` | PASIVA | `masked` + `sha256[:12]`. **No se envía ningún mensaje de prueba al webhook** — escribir en un canal del cliente es escribir en un tercero | Script propio. Slack y Discord: SaaS propietario, ToS |
| V28 | **Tokens de proveedor** — Stripe, Twilio, Google Cloud, OpenAI, Anthropic, Firebase, Sentry, Mapbox, SendGrid, Mailgun, Azure | `secrets_scan.py` sobre el HTML/JS descargado y sobre el repo del cliente | `secrets_scan.py` (25+ patrones) | PASIVA | `masked` + `sha256[:12]` + tipo. El prefijo identifica al proveedor | Script propio. Las APIs de cada proveedor tienen licencia/ToS propios: **consultar la API oficial, no un wrapper de terceros** |
| V29 | **JWT malformados o expirados** · **tokens de servicio y credenciales de CI/CD** (`.github/workflows/*.yml`, `.gitlab-ci.yml`, Jenkins, Docker registry) | `secrets_scan.py` (patrón `jwt`). Decodificar **offline** cabecera y payload (base64url), sin verificar firma. En CI/CD, buscar `${{ secrets.` y `password` en YAML de pipeline | `secrets_scan.py` + decodificador local | PASIVA | `alg`, `exp`, `nbf`, `iss`, `aud`, `sub` (enmascarado) y claims de rol; en CI/CD, la **referencia** a un secreto con nombre aunque el valor no esté, porque indica qué existe | Script propio |
| V30 | **Credenciales en logs públicos** | Ficheros de log servidos por web (`/logs/`, `/error_log`, `/debug.log`, `/app.log`), paneles de error públicos (Sentry, `elmah.axd`, `trace.axd`) | `probe_exposure.py --path-list` + `secrets_scan.py` | ACTIVA-L + PASIVA | Presencia de líneas con patrón de credencial. **Nunca** se copia el log entero a la evidencia: se extrae la línea enmascarada | Script propio. Sentry: SaaS propietario |
| V31 | **Fugas del propio cliente en Wayback / Common Crawl** | CDX de Wayback filtrando por extensión y estado; índice de Common Crawl por patrón de URL | `gau` / `waybackurls` / CDX API | PASIVA | URLs archivadas. **Un secreto que estuvo en Wayback sigue siendo público aunque se rotó**: se reporta la fecha de la captura | `gau` **MIT**, `waybackurls` **MIT**. Wayback: dominio público, API sin SL explícita, sujeto a las condiciones de archive.org. Common Crawl: condiciones de uso propias, leer antes de automatizar |

**Notas sobre la tabla.**

1. **Licencia de la herramienta ≠ licencia del hallazgo.** Las herramientas son
   procesos separados; su copyleft (AGPL-3.0 de TruffleHog, GPL-3.0 de SecretFinder) no
   se propaga al informe. Ver el manifiesto §6. Lo que **no** se puede hacer es
   reempaquetar el binario dentro de un producto que vendas.
2. **Las herramientas de terceros de §4 del manifiesto son alternativas**, no adiciones
   obligatorias: `secrets_scan.py` cubre lo mismo en local y **nunca escribe el valor
   completo**. Su salida se trata con `pii_redact.py` y **no** se pega cruda.
3. **Las candidatas del §7 siguen vetadas**: Nuclei, Nikto, sqlmap, ffuf, dirsearch,
   `h8mail` (verificar credenciales contra un buzón es de-anonimización: regla 1.3).
4. **Google dorks y GitHub code search son sólo del cliente.** Si el dominio que buscas
   no es del cliente, no se busca.

### 2.2 Cómo `probe_exposure.py` complementa la tabla manual

`probe_exposure.py` recorre una lista **fija y corta de 53 rutas** contra los hosts
autorizados. No es un escáner de rutas: es una sonda de exposición sobre rutas
conocidas, y su lista se puede sustituir por completo con `--path-list`.

**Lo que el script ya cubre:** 53 rutas fijas agrupadas por familia — entorno (4),
control de versiones (4), sistema operativo (1), backups y volcados (7), servidor web
(3), paquetes y dependencias (4), documentación de API (7), diagnóstico (5), paneles de
administración (5), ficheros públicos de referencia (6), monitorización (5), API
genérica (3).

**Lo que la tabla manual añade por encima del script**, y cómo se cubre:

| Ruta de la tabla | Por qué no está en el script | Cómo se cubre |
|---|---|---|
| V09 source maps | La ruta del `.map` **depende del nombre del bundle**, no se puede adivinar | `js_intel.py` extrae el `//# sourceMappingURL=` y de ahí la ruta exacta |
| V11 `.npmrc` / `.pypirc` | Viven en el **repo**, no en el servidor web | `secrets_scan.py` sobre el repo del cliente |
| V12 `credentials.json` de SA | Ruta arbitraria | `secrets_scan.py` (patrón `service_account_json`) + `--path-list` |
| V13 `firebase-messaging-sw.js` · V14 `manifest.json` · V17 `humans.txt` · V20 `redoc` · V30 logs públicos | Rutas arbitrarias | `--path-list` + búsqueda en el JS |
| V25 GitHub · V26 dorks · V31 Wayback/CC | Son fuentes de terceros, no rutas del servidor | Recon de Fase 2 (ciclo §2) |
| V29 JWT · V32 CI/CD | Son contenido, no rutas | `secrets_scan.py` |

**Lo que el script añade por encima de la tabla manual** (rutas que nadie lista a mano
pero que aparecen en hosting compartido y en stacks .NET/JVM):
`/.htaccess`, `/web.config`, `/package.json`, `/api/`, `/api/v1/`, `/api/v2/`,
`/elmah.axd`, `/trace.axd`, `/metrics`, `/health`, `/swagger-ui/`,
`/graphql/playground`, `/.well-known/security.txt`, `/package-lock.json`,
`/yarn.lock`, `/backup.tar.gz`, `/dump.sql`, `/config.php.bak`, `/.env.local`,
`/.env.production`, `/.env.development`, `/.git/config`.

**Tres garantías del script que hay que conocer y explicar en el informe:**

1. **No guarda el cuerpo de las rutas sensibles.** Sólo se almacenan los cuerpos de
   `robots.txt`, `sitemap.xml`, `security.txt` y `.well-known/security.txt` (y los que
   se pidan explícitamente con `--also-store`). Esto es lo que hace que la sonda sea
   compatible con la prohibición 1.2: **el auditor nunca ve el contenido del backup**.
2. **Detecta soft-404.** Pide una ruta 404 de referencia y compara el `sha256` del
   cuerpo. Si coincide, marca `soft_404` y **no cuenta como exposición**. Sin esto,
   cualquier sitio con un *catch-all* generaría cientos de falsos positivos.
3. **Escribe TSV con la cabecera estable**
   `host path code content_type length sha256 soft_404 verdict severity`, más un
   `--json` equivalente y el fichero de evidencia en `--out`.

**El comando de siempre:**

```bash
python3 probe_exposure.py -a auth.json --host www.clinica-ejemplo.mx --out evidencia/
python3 probe_exposure.py -a auth.json --host www.clinica-ejemplo.mx --dry-run   # plan, sin red
```

`--dry-run` **siempre primero**: imprime el plan de sondeo (hosts y rutas) sin hacer
una sola petición. Es la forma de revisar que ninguna de las 53 rutas sale del
allowlist antes de golpear nada.

---

## 3. Verificación de credenciales SIN usarlas

Esta es la sección técnica central del módulo. El objetivo es poder escribir en el
informe:

> *«La clave `sk_live_…` encontrada en `main.js` es **viva**: la API del proveedor la
> reconoce. Declara los permisos que el propio proveedor expone en su panel. Su
> rotación es urgente.»*

sin haber autenticado contra un solo recurso ajeno, sin haber escrito nada, sin haber
pagado nada, y sin que el valor completo de la clave exista fuera de la memoria del
proceso que la usó.

### 3.0 La puerta: qué nivel se ejecuta en qué fase

| Nivel | Fase | Autorización que exige | Qué ejecuta |
|:-:|---|---|---|
| **0 — ¿está expuesto?** | 1 | RoE firmado (autoriza GET/HEAD) | Sondas de existencia |
| **1 — ¿es plausible?** | 1 | Ninguna adicional (análisis local) | `secrets_scan.py` |
| **2 — ¿está vivo?** | 1 **sólo** con autorización escrita **nombrando esa credencial y ese endpoint**; en caso contrario, Fase 2 bajo el addendum (técnica T6) | Permiso explícito del cliente | Una llamada de lectura a la API del proveedor |
| **3 — ¿qué alcance tiene?** | 1 (sólo desde el panel/documentación que el cliente proporcione) o Fase 2 | Enviado por el cliente | Lectura de scopes/roles declarados |
| **4 — demostración + rotación** | **2 únicamente** | Addendum firmado, cliente presente, ventana, contacto de emergencia | **Una** acción de lectura no mutante + rotación coordinada |

> **El protocolo de ejecución de Fase 2 (ventana, abort, roles, registro de acciones) no
> se redescribe aquí.** Está en `00-metodologia/fase-2-explotacion-autorizada.md` y en
> `05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md`. Este
> módulo define **qué** se verifica, en qué orden y **qué se registra**; el otro
> documento define **cuándo, con quién y con qué criterio de Abort**.

### 3.1 Nivel 0 — ¿está expuesto?

**Pregunta.** ¿Existe el recurso y lo sirve el servidor, o es un 404 con página de
error?

**Cómo.** GET o HEAD. **Nunca** se descarga el cuerpo de una ruta sensible. Lo que se
necesita de la respuesta es un **metadato**:

| Dato | Para qué |
|---|---|
| Código de estado | Distingue `200` (expuesto), `401`/`403` (protegido), `404` (no existe), `3xx` (redirección) |
| `Content-Type` | Un `.env` que devuelve `text/html` probablemente sea un *soft-404*; un `application/json` con `text/plain` es sospechoso |
| `Content-Length` / `Transfer-Encoding` | Tamaño del fichero: un backup de 800 MB es un hallazgo mayor que uno de 2 KB |
| `ETag` / `Last-Modified` | Fecha de la última modificación: un backup de 2019 es un hecho histórico |
| `sha256` del cuerpo | Reproducibilidad de la evidencia sin volver a descargarlo |
| `Location` (en redirección) | Si `/admin/` redirige a `/wp-login.php`, el panel existe |

**Request de ejemplo.**

```bash
# Existencia pura, sin cuerpo en disco
curl -sS -o /dev/null -D - -A "$UA" https://clinica-ejemplo.mx/.env

# Para ficheros potencialmente pesados: sólo el primer kilobyte
curl -sS -r 0-1023 -D - -A "$UA" https://clinica-ejemplo.mx/backup.zip | head -c 1024
```

**Qué se registra.** `host`, `ruta`, `método`, `código`, `content_type`, `length`,
`etag`, `last_modified`, `sha256` (sólo de cuerpos públicos por definición), marca de
tiempo y número de petición — que ya son las columnas `code content_type length
sha256 soft_404 verdict severity` del TSV de `probe_exposure.py`.

**Qué NO se registra.** El cuerpo de ninguna ruta sensible, los `Set-Cookie` recibidos
y ningún valor de credencial.

**Criterio de parada.**
- `200` + `Content-Type` coherente → **pasa a Nivel 1** (análisis local) y se anota
  como *expuesto*.
- `401`/`403` → la ruta **existe y está protegida**. Se reporta como «exposición de
  existencia» (MEDIUM): el inventario de rutas de la aplicación es un activo. **No se
  intenta autenticarse.**
- `404` → no existe. Se cierra.
- `soft_404` → no existe. Se cierra. **Este es el motivo por el que `probe_exposure.py`
  compara hashes**: sin esa comprobación, `/admin/` devolvería `200` en casi todos los
  sitios y el informe sería ruido.
- `5xx` → se anota como error de servidor y **se para**: reintentar un `5xx` puede
  agravar una carga. Si hay que reintentar, es una sola vez y fuera de horario de
  carga.

### 3.2 Nivel 1 — ¿es plausible?

**Pregunta.** ¿Lo que encontré es realmente una credencial, o es un placeholder, un
hash de ejemplo o un texto que sólo *parece* una clave?

**Cómo.** **Cero red.** Análisis local con `secrets_scan.py`.

```bash
python3 secrets_scan.py ./evidencia --json --out evidencia/secrets.json
python3 secrets_scan.py ./evidencia --min-entropy 3.5 --ignore '*.lock'
python3 secrets_scan.py ./evidencia --redact-in-place --redact-out ./evidencia-redactada
python3 secrets_scan.py ./evidencia --fail-on critico    # devuelve código 1 si hay críticos
```

Los cuatro criterios de plausibilidad, en orden:

| # | Criterio | Cómo se evalúa | Ejemplo |
|:-:|---|---|---|
| 1 | **Prefijo conocido del proveedor** | El patrón de la regla | `sk_live_` → Stripe live; `sk-ant-` → Anthropic; `AIza` → Google API key |
| 2 | **Formato** | Expresión regular específica del proveedor | `AKIA` + 16 `[0-9A-Z]` → access key AWS |
| 3 | **Longitud** | Longitud mínima y máxima del formato | Un `sk-ant-` de 12 caracteres no es una clave Anthropic |
| 4 | **Entropía de Shannon** | `--min-entropy` (por defecto **3.0 bits/carácter**) para las reglas genéricas | Una contraseña `Password123!` no pasa el filtro; un token aleatorio sí |

**El descarte de placeholders.** `secrets_scan.py` filtra explícitamente los valores
que no son secretos: `changeme`, `change_me`, `your_password`, `password`, `secret`,
`todo`, `placeholder`, `xxx`, `example`, `test`, `none`, `null`, `undefined`, y
cualquier valor con ≤2 caracteres distintos. Si un valor cae aquí, **es INFO, no un
hallazgo**: «el placeholder `changeme` está sin sustituir en producción» es un
hallazgo de configuración, no una credencial expuesta.

**Qué se registra.** Tipo de patrón, fichero, línea, columna, severidad, `masked`
(**4 primeros + 2 últimos**, el resto oculto), `sha256[:12]` del valor y la
**clasificación de plausibilidad** (prefijo conocido: sí/no; entropía; longitud;
placeholder: sí/no).

**Qué NO se registra.** El valor completo: ni en el informe, ni en la evidencia, ni en
un fichero temporal, ni en un chat de equipo, ni en un ticket. **La regla es dura y no
admite excepción por comodidad:**

> **El valor completo de un secreto no sale nunca del proceso que lo leyó.** En el
> informe y en la evidencia sólo existen dos artefactos: la máscara (`abcd******yz`)
> y la huella (`sha256[:12]`), que permite correlacionar dos apariciones del mismo
> secreto sin revelarlo.

**Criterio de parada.** Si el valor es un placeholder → INFO, se cierra. Si el valor
es un **hash** (no reversible como credencial, pero sí atacable) → se registra como
«material de autenticación expuesto» y se escala a la §5. Si el valor es un **token
de terceros** (Stripe live, AWS) → pasa a Nivel 2, **siempre bajo autorización**.

### 3.3 Nivel 2 — ¿está vivo?

**Pregunta.** ¿El proveedor reconoce esta credencial, o es un string obsoleto que
quedó en un fichero y ya no corresponde a nada?

**Por qué importa.** La diferencia entre «hay una cadena con formato de clave de
Stripe en un bundle» y «esa clave sigue activa y tiene permisos de cobro» es **la
diferencia entre un informe mediocre y uno que se cobra**. Y esa diferencia sólo se
obtiene de la fuente primaria: **el propio proveedor**.

**Reglas duras del Nivel 2.**

1. La llamada va **al API del proveedor de la credencial**, no a un recurso del
   cliente ni de un tercero.
2. Es **una lectura**: listar lo que la credencial puede ver de sí misma. **Nunca**
   escritura, **nunca** pago, **nunca** alta de recursos.
3. **Nunca contra recursos ajenos.** Si el endpoint devuelve una lista de recursos
   del cliente, se registra **la categoría y el conteo**, no los nombres, no los
   identificadores, no el contenido.
4. **Una sola llamada** por credencial. Si la primera no responde de forma concluyente,
   se para y se reporta como *no verificado*.
5. La llamada **queda registrada en el log del proveedor** con la IP y la hora del
   auditor. Eso es inevitable y hay que decirlo al cliente en el informe: es una de
   las razones por las que esta verificación requiere autorización escrita.
6. El secreto **no se escribe en disco** para poder usarlo: se lee de forma
   interactiva y se descarta.

**Requests de ejemplo.** *La forma exacta del endpoint debe confirmarse en la
documentación vigente del proveedor el día de la ejecución; el escáner propone, la
fuente primaria dispone.*

```bash
# Stripe — cuenta asociada a la clave. Fuente primaria: https://docs.stripe.com/api/account
read -rs SK; echo
curl -sS -A "$UA" -H "Authorization: Bearer ${SK}" \
     https://api.stripe.com/v1/account \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sorted(d.keys()))'
unset SK

# Google Cloud — proyectos visibles con la service account. Fuentes primarias:
#   https://cloud.google.com/resource-manager/reference/rest/v1/projects/list
#   https://cloud.google.com/iam/docs/roles-overview
gcloud auth activate-service-account --key-file=/ruta/efimera/sa.json
gcloud projects list --format="value(projectId)" | wc -l   # CONTEO, no nombres
```

| Proveedor | Lectura de ejemplo | Fuente primaria |
|---|---|---|
| Stripe | `GET https://api.stripe.com/v1/account` con `Authorization: Bearer` | <https://docs.stripe.com/api/account> |
| OpenAI | `GET https://api.openai.com/v1/models` → **conteo** de modelos, no la lista | <https://platform.openai.com/docs/api-reference> |
| Anthropic | `GET https://api.anthropic.com/v1/models` + cabecera de organización | <https://docs.anthropic.com/en/api/getting-started> |
| Twilio | `GET https://api.twilio.com/2010-04-01/Accounts.json` con `-u <SID>:<token>` → **conteo** | <https://www.twilio.com/docs/api> |
| Google Cloud | `gcloud projects list` con la service account → **conteo** | <https://cloud.google.com/resource-manager/reference/rest/v1/projects/list> |
| Azure | Listado de suscripciones de la identidad → **conteo** | Documentación de Azure Resource Manager |

> **Los anteriores son ejemplos de forma, no de resultado.** La respuesta real de cada
> API depende de la versión del proveedor y del tipo de credencial. El auditor debe
> **leer la documentación del proveedor el día de la ejecución**, ajustar el endpoint y
> —si el proveedor no ofrece un endpoint de lectura evidente— **preguntar al cliente**
> cuál es. Lo que **no** se hace es improvisar: inventar un endpoint y probarlo es
> fuerza bruta contra la API del proveedor.

**Qué se registra.** Proveedor, endpoint usado, fecha y hora, código de respuesta; **los
nombres de campo** de la respuesta (no los valores); la **categoría de recurso** a la
que da acceso y **el conteo** de elementos de cada categoría; el **identificador de la
cuenta/proyecto** enmascarado (`proyecto-…-a3f1`); y el `sha256[:12]` del secreto usado,
para que el cliente confirme que se verificó **la misma** credencial del hallazgo. Si el
proveedor devolvió `401`/`403`, la credencial **está revocada o nunca existió** → el
hallazgo **baja** de severidad, y eso se dice.

**Qué NO se registra.** El cuerpo crudo de la respuesta; nombres, correos, teléfonos o
identificadores de los recursos listados; el secreto; y la clave privada de la service
account (jamás se lee para «verificar»: se verifica con `gcloud auth
activate-service-account` sobre un fichero efímero que se borra).

**Criterio de parada.**
- `200` con datos → la credencial **está viva**. Se anota y se pasa al Nivel 3.
- `401` → **muerta o revocada**. Se documenta la **fecha de la captura** y se dice
  que la exposición histórica es real pero el riesgo actual es menor.
- `403` → viva pero sin permiso para lo que se pidió. Se anota como viva, con alcance
  **cero o parcial**.
- `429` / `5xx` → se para. **Un solo reintento**, y se registra como *no verificado*.
- Respuesta ambigua → se para. *«No pude verificar si esta credencial está viva»* es
  un resultado honesto y **no verificado**, no un hallazgo.

### 3.4 Nivel 3 — ¿qué alcance tiene?

**Pregunta.** Si la credencial está viva, **qué puede hacer**?

**Regla que gobierna este nivel:** el alcance se determina con **las declaraciones del
propio proveedor**, no con exploración.

| Proveedor | Dónde está la declaración de permisos | Cómo se obtiene sin explorar recursos |
|---|---|---|
| Stripe | La propia clave (una *restricted key* tiene permisos declarados) o el panel de la cuenta | El cliente comparte captura del panel, o la respuesta de `/v1/account` incluye los flags de la clave |
| OpenAI / Anthropic | Scopes del token y la organización asociada | El `scope`/`org_id` que devuelve la propia API de la credencial |
| Google Cloud | **Roles IAM** predefinidos y policies de IAM del proyecto | `gcloud projects get-iam-policy <proyecto>` — policy **del propio proyecto**, con los roles, no los miembros ajenos. Docs: https://cloud.google.com/iam/docs/roles-overview |
| Azure | Roles asignados al service principal | Portal del cliente / Microsoft Graph, sólo para el service principal propio |
| GitHub / GitLab | Scopes del token | La propia API devuelve los scopes (`X-OAuth-Scopes` en GitHub) |
| Twilio | Tipo de credencial (API Key vs Auth Token) y sus políticas | El panel de la cuenta |

**Qué se registra.** La lista de **roles/scopes** tal cual los declara el proveedor
(p. ej. `roles/storage.objectViewer`), la **cuenta o proyecto** al que pertenece
(enmascarada) y la traducción a lenguaje de negocio: «permite leer objetos del bucket»,
«permite listar modelos», «permite leer pero no escribir».

**Qué NO se registra.** La **key completa** de la service account, la lista de miembros
de la policy IAM (pueden ser correos de terceros) y cualquier recurso individual.

**Criterio de parada.** Cuando el proveedor declara el alcance. **No se sigue
explorando para «confirmar» el alcance.** Si el proveedor no expone el alcance de
forma legible, se escribe: *«alcance no determinable con la evidencia disponible»* y
se pide al cliente una captura del panel de permisos. **Pedirle al cliente una captura
es más rápido, más honesto y más seguro que explorar su cuenta con su credencial.**

### 3.5 Nivel 4 — demostración y rotación coordinada (Fase 2)

**Condiciones acumulativas.** Addendum de Fase 2 firmado · cliente presente · ventana
definida · contacto de emergencia disponible · una **única** acción de lectura no
mutante.

**Qué es exactamente.** (1) **Una** acción de lectura sobre un **recurso propio del
cliente**, elegido por él, con datos que **el cliente ha confirmado que son
sintéticos**. (2) **Coordinación previa**: el recurso a leer, la hora y qué se va a
registrar. (3) **Rotación coordinada**: el cliente rota la credencial durante la
ventana o inmediatamente después, y se verifica que la antigua **dejó de funcionar**
(una sola llamada de lectura, misma forma, ahora debe fallar).

> **La rotación la hace el cliente, no el auditor.** El auditor **no** revoca, **no**
> regenera, **no** edita credenciales en el panel del cliente. Ni siquiera si se lo
> piden. El auditor no tiene por qué tener acceso al panel, y un token regenerado por
> un tercero suele quedar sin registrar en el cambio de inventario.

**Qué se registra.** La acción ejecutada, la cuenta, el código de respuesta, la **forma**
de la respuesta (claves, no valores), la huella, la fecha/hora de la rotación por el
cliente y el resultado de la verificación posterior.

**Qué NO se registra.** El contenido leído, si es clínico; la credencial nueva; la
credencial antigua.

**Criterio de parada.** Inmediato, si: la respuesta contiene datos de un paciente real
→ se descarta y se reporta; el cliente no confirma la ventana → no se ejecuta; aparece
un `5xx` → se para; el `Abort` del RoE se activa → se aborta todo y se notifica al
contacto de emergencia.

> **El protocolo completo de Fase 2 — ventana, abort, roles, registro de acciones y
> técnicas T1–T6 — está en `00-metodologia/fase-2-explotacion-autorizada.md`.** Este
> módulo no lo duplica.

### 3.6 La regla dura, resumida

| Regla | Formulación operativa |
|---|---|
| **No escribir el valor** | Ni en informe, ni en evidencia, ni en notas, ni en tickets, ni en chats. Sólo `masked` (4+6+2) y `sha256[:12]`. |
| **No usarlo fuera de su contexto** | La credencial se usa, como mucho, **una vez**, contra la API de su propio proveedor, en lectura. |
| **No rotar** | La rotación es del cliente. El auditor entrega el hallazgo y el plan, no el cambio. |
| **No enumerar** | Se reportan **categorías** y **conteos**, nunca listas de recursos. |
| **No explorar recursos ajenos** | Ni en el proveedor, ni en la nube del cliente, ni en el panel de un tercero. |
| **Degradar es honesto** | «No verificado» es un resultado válido. «Probablemente no» no lo es. |

---

## 4. `.env` y credenciales de base de datos

### 4.1 Por qué esta clase merece un módulo aparte

Un `.env` expuesto no es «un secreto más». Es, con frecuencia, **la credencial de la
base de datos que contiene los expedientes de todos los pacientes**. Y la diferencia
entre «hay una variable `DB_PASSWORD` en un fichero» y «hay una cadena de conexión
completa con usuario y contraseña, apuntando al host de producción» es la diferencia
entre MEDIO y **CRÍTICO con asumir compromiso**.

### 4.2 Vías de detección

| Vía | Indicador | Evidencia |
|---|---|---|
| **Fichero publicado** | `/.env`, `/.env.production`, `/.env.local`, `/.env.backup` | Código, `Content-Type`, `length`, `ETag` |
| **Stack trace de PHP / Django / ASP.NET** | `Fatal error: Uncaught Error: ... in /var/www/html/wp-config.php on line 42`; `ImproperlyConfigured` + `DATABASES`; `Server Error in '/' Application` + `<add key="ConnectionString" …>` | No lo detecta `probe_exposure.py`: se ve en un `GET` a una ruta que rompe el backend |
| **Página de debug** | `phpinfo()` (V07), `actuator/env` (V22), Django `debug=True` (`DEBUG=True` en el HTML) | Cuerpo de la página de debug. **Es clase (a) y clase (b) a la vez** |
| **Endpoint de healthcheck** | `/health`, `/healthcheck`, `/status`, `/actuator/health` que filtran variables | `probe_exposure.py` cubre `/health` y `/actuator/health` |
| **Source map** | El `.map` con la configuración original del front | `js_intel.py` → `sourceMappingURL` |
| **Repo del cliente** | `.env` commiteado, `.env.example` con valores reales | `secrets_scan.py` + `git log` |

### 4.3 Qué se prueba — y qué no

**Se prueba (todo esto es local o pasivo):**

| Pregunta | Cómo se responde | Restricción |
|---|---|---|
| ¿La variable existe? | El nombre de la clave en el fichero o en el trace | — |
| ¿Parece una credencial? | Formato, prefijo, longitud, entropía (`secrets_scan.py`) | — |
| ¿En qué motor corre? | El **esquema de la URI**: `postgres(ql)://` → PostgreSQL; `mysql://`/`mariadb://` → MySQL/MariaDB; `mongodb://`/`mongodb+srv://` → MongoDB; `redis(s)://` → Redis; `sqlserver://` → MS SQL; `amqp(s)://` → RabbitMQ | **Inferencia del formato**, no una conexión |
| ¿El host es interno o externo? | Lectura del string: RFC1918 (`10.`, `172.16-31.`, `192.168.`), `localhost`, o nombre de servicio de cloud | No se resuelve ni se conecta |
| ¿El esquema es consistente? | Que el motor declarado por la URI acepte ese formato de URI | **Nunca** se hace una conexión |
| ¿Hay más de una credencial de BD? | Recuento por variable (`DB_PASSWORD`, `DATABASE_URL`, `MYSQL_ROOT_PASSWORD`) | Recuento, no volcado |

> **Nunca se intenta autenticar contra la base de datos.** Ni una conexión TCP, ni un
> `psql`, ni un `mysql`, ni un `mongosh`. Abrir una sesión contra la BD del cliente
> —aunque sólo sea un `SELECT 1`— es autenticación contra un sistema que contiene datos
> de pacientes sin autorización específica, es una acción que queda en el log de
> auditoría del cliente, y es exactamente lo que el RoE prohíbe. Además es
> **innecesario**: la credencial expuesta en un `.env` **no necesita estar viva para
> ser crítica**. Puede estar viva, puede estar revocada, o puede ser la credencial de
> un entorno que ya no existe. En los tres casos la **acción correcta es la misma**:
> rotar.

### 4.4 La prueba de existencia sin descargar contenido

Para un fichero potencialmente enorme (`.sql` de 900 MB, `backup.zip`), la prueba de
existencia se hace con **`Range: bytes=0-1023`**:

```bash
curl -sS -r 0-1023 -D - -A "$UA" https://clinica-ejemplo.mx/db.sql | head -c 1024
```

Qué demuestra y qué no:

| Lo que demuestra | Lo que NO demuestra |
|---|---|
| Que el fichero existe y el servidor lo sirve | Nada sobre su contenido |
| Su `Content-Type` (¿`text/plain`? ¿`application/zip`?) y su `Content-Length` real | Que tenga credenciales dentro ni qué datos contiene |
| Si soporta rangos (`206 Partial Content`) o no (`200` + cuerpo completo) | — |

**Qué se hace con los primeros 1 024 bytes.** Se mira **el tipo de contenido**, no el
contenido. Si en esas primeras líneas aparece una cadena con **formato de credencial**,
la regla es la del addendum de Fase 2 (técnica T5): **no se transcribe**. Se anota
*«se observa material sensible en las primeras líneas»*, se enmascara y se entrega así.

**Qué NO se hace.** No se descarga el fichero. No se descomprime. No se extraen
credenciales, hashes ni datos de dentro. No se persiste una copia ni siquiera
temporal. Si el primer kilobyte ya es un volcado SQL con nombres de pacientes, ese
kilobyte **se destruye**: no se guarda, no se pega, no se reporta.

> **La eliminación del fichero la decide el cliente, no el auditor.** En el informe va
> la ruta exacta, el comando de borrado y el aviso de que la exposición puede datar de
> años (copias en Wayback, en cachés, en backups del hosting).

### 4.5 Cómo se reporta

**Severidad.** Credencial de base de datos expuesta = **CRÍTICO**, sin excepción de
contexto, en una clínica. La matriz de severidad califica CRÍTICO como «exposición
directa de datos sensibles de pacientes con capacidad de lectura/escritura probada».
Una credencial de BD **no necesita estar probada** para ser CRÍTICA: es la credencial
del almacén que contiene los expedientes.

**Postura: asumir compromiso.** El párrafo que va al informe, literal:

> **Asumir compromiso.** La credencial de base de datos publicada en
> `https://clinica-ejemplo.mx/.env` (descubierta el `<FECHA>`, respuesta `200
> text/plain`, <N> bytes) debe tratarse como **comprometida desde el momento de su
> publicación**, no desde el momento en que se detecta. El cliente debe: (1) **rotar
> la credencial de inmediato** y actualizar todas las aplicaciones que la usan;
> (2) **revisar los logs de acceso a la base de datos** desde la fecha más antigua
> disponible hasta la rotación, buscando accesos desde orígenes no reconocidos;
> (3) **auditar el contenido** de las tablas de pacientes en busca de modificaciones o
> lecturas anómalas; (4) **asumir que cualquier dato que la base contenga ha sido
> potencialmente accesible** y **evaluar si procede la notificación de la brecha a los
> pacientes afectados** conforme al marco aplicable (ver §6 de este módulo, artículos
> marcados **NO VERIFICADO**); (5) **eliminar el fichero del servidor** y cualquier
> copia en caché, y solicitar formalmente al servicio la eliminación de las copias en
> Wayback/Common Crawl.
>
> La rotación **no** espera a la auditoría: se puede hacer en paralelo, sin esperar a
> este informe.

**Redacción.** En la tabla de secretos, la credencial de BD aparece como:

| Campo | Valor |
|---|---|
| tipo | `connection_uri_credentials` / `generic_credential_assignment` |
| ubicación | `https://clinica-ejemplo.mx/.env` (o `repo:config/database.php`) |
| masked | `post******xy` |
| fingerprint | `sha256[:12]` |
| ¿vive? | **no probado** (no se abre conexión — §4.3) |
| alcance real | «acceso completo al almacén de datos de pacientes, según el nombre y esquema de la variable» |
| criticidad | **CRÍTICO** |
| rotación urgente | **sí — inmediata** |
| owner | equipo técnico / hosting del cliente |

Nótese la honestidad de la fila `¿vive?`: **«no probado»**. No se abrió una conexión
—porque está prohibido— y no se va a abrir. Esa celda no es una laguna: es la
evidencia de que el auditor se detuvo donde debía.

---

## 5. Tokens administrativos y sesiones

### 5.1 La taxonomía

No todos los «tokens» valen lo mismo. Confundirlos es la causa más común de
sobrerreacción (un token público de Mapbox reportado como CRÍTICO) y de
subreacción (una clave de firma de cookie reportada como BAJO). Esta tabla es la
discriminante:

| Tipo | Qué es | Dónde aparece | Severidad intrínseca | Cómo se demuestra **sin usurpar** |
|---|---|---|---|---|
| **Token de servicio** (machine-to-machine) | Credencial que autentica a un proceso, no a una persona: service account, bot token, client credentials de OAuth | `credentials.json`, `.env`, CI/CD, `service-account.json` | **CRÍTICO** si está expuesto: no tiene dueño humano, no expira solo, no tiene MFA | Se demuestra su **existencia y formato**; su vida se verifica por la API del proveedor (§3.3). No se ejecutan acciones con él |
| **Token de API con permisos amplios** | PAT (GitHub/GitLab), API key sin restricción, unrestricted key de Stripe | JS de cliente, repositorio, `.env` | **ALTO→CRÍTICO** según el alcance declarado | Se lee el **scope/permiso declarado** en el panel del cliente. No se enumeran recursos con él |
| **Token embebido en JS de cliente** | Clave *publicable* que viaja en el navegador de **cada visitante** | `main.js`, bundle, `firebase-messaging-sw.js`, `manifest.json` | **INFO por sí mismo** (es público por diseño) — **ALTO** si el backend lo trata como secreto | Se verifica la **configuración del backend**: ¿el token está restringido a origen, a cuota, a permisos? Si el backend confía en él, se reporta la restricción ausente |
| **Cookie de sesión de administración** | Cookie `HttpOnly` de una sesión con rol admin | Respuesta de un login, `Set-Cookie` en un panel, HTML volcado | **ALTO** si se reproduce; **CRÍTICO** si la clave de firma está expuesta | **No se crea** una sesión admin. Se verifica la **protección de la cookie** (`Secure`, `HttpOnly`, `SameSite`, prefijo `__Host-`) y la **expiración** |
| **JWT con algoritmo `none`** o con confusión HS/RS | Token firmado sin firma, o firmado con HMAC usando la clave pública RSA como secreto | Token en JS, en un enlace, en un log, en un `localStorage` | **CRÍTICO** si acepta `alg:none`; **ALTO** si es vulnerable a confusión HS/RS | **Decodificación offline** de cabecera y payload: se lee `alg`. La **aceptación** por el servidor se prueba en Fase 2 con token propio (§3.5) |
| **Secreto de firma de cookie de sesión** | La clave con la que el servidor firma/valida la cookie (`SESSION_SECRET`, `SECRET_KEY`, `APP_KEY`, `JWT_SECRET` en Laravel) | `.env`, `wp-config.php`, `config.php`, bundle de cliente, `credentials.json` | **CRÍTICO — el peor caso** | Se demuestra que la clave está **expuesta** o es **débil** (longitud, entropía, ausencia de rotación). **No se falsifica ninguna cookie** en Fase 1 |

### 5.2 El peor caso, en detalle: la clave de firma de cookie

Si la clave con la que el servidor firma sus cookies de sesión está publicada, el
atacante puede **fabricar una cookie admin válida** sin tocar el sistema, sin
registrar actividad y sin dejar rastro en los logs de autenticación. Todos los
controles de acceso quedan anulados de una vez: MFA, bloqueo por intentos, CAPTCHA,
registro de sesión, notificaciones de inicio de sesión. **Todo el esquema de
autenticación pasa a depender de que nadie lea un fichero.**

Por eso es el peor caso y por eso tiene un tratamiento propio:

| Paso | Qué se hace | Prohibición que respeta |
|:-:|---|---|
| 1 | Localizar la clave y **documentar su ubicación** con `masked` + `sha256[:12]` | — |
| 2 | Medir su **longitud** y **entropía** (local, offline) | — |
| 3 | Determinar **qué tecnología la usa** (Django `SECRET_KEY`, Laravel `APP_KEY`, Rails `secret_key_base`, Spring `jwt.secret`, WordPress salt, ASP.NET Data Protection) | — |
| 4 | Comprobar si es la **misma** que aparece en otro sitio del mismo cliente (correlación por `sha256[:12]`) | 1.4 — no se toca a otros inquilinos |
| 5 | **Verificar si el framework expone la clave al cliente** (Laravel `APP_KEY` visible en el bundle, `.env` público) | — |
| 6 | En **Fase 2**, con la cuenta propia del auditor y el addendum firmado, comprobar si una cookie firmada con esa clave es aceptada | Protocolo de Fase 2 |

**Lo que nunca se hace:** fabricar una cookie admin y usarla. Ni una vez, ni «sólo
para ver», ni «con una cuenta de prueba que ya tengo». Fabricar una sesión
administrativa **es usurpar**, y el RoE lo prohíbe en los términos de la regla 1.3
(*«reporta la capacidad, no la explotación»*), aunque la cuenta sea del propio
auditor. La demostración se hace con la cuenta propia del auditor y el resultado se
limita a *«la cookie fabricada por la clave expuesta es aceptada»* o *«no lo es»*.

### 5.3 JWT: qué se comprueba sin red

Todo lo siguiente es **offline**, sobre el token que ya está en la evidencia:

```bash
# Decodificar cabecera y payload (base64url) SIN verificar la firma
python3 - <<'EOF'
import base64, json
h, p, s = open('evidencia/jwt.txt').read().strip().split('.')
d = lambda x: json.loads(base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)))
print("header :", d(h))
print("payload:", {k: v for k, v in d(p).items() if k not in ("sub", "email", "name")})
print("firma presente:", bool(s), "| longitud:", len(s))
EOF
```

| Comprobación | Signal de problema | Lectura correcta |
|---|---|---|
| `alg` = `none` | El token no lleva firma: cualquiera puede emitirlo | **CRÍTICO** si el servidor lo acepta (Fase 2) |
| `alg` = `HS256` en un servicio que sólo usa claves RSA | Posible confusión HS/RS: el atacante usa la clave pública del JWKS como secreto HMAC | **ALTO**; aceptación = Fase 2 |
| `exp` ausente | Token sin expiración | **MEDIO** |
| `exp` en el pasado | Token expirado | **INFO** — se documenta que el token ya no sirve, pero **no se elimina del fichero**: sigue siendo PII y sigue siendo un vector de reuso |
| `nbf` en el futuro | Token con ventana de no validez | INFO |
| `iss`/`aud` ausente o genérico | Token válido en cualquier contexto | **MEDIO** |
| `sub`, `email`, `name` | Datos personales dentro del token | Se enmascaran antes de escribir el informe |
| Claims de rol/permiso | `scope`, `roles`, `permissions` | Es la **declaración del alcance** del token (Nivel 3 aplicado a JWT) |

> **Un JWT expirado sigue siendo un hallazgo de clase (b).** Contiene identificadores
> personales y a veces información de salud. Se enmascara, se reporta y se redacta.
> «Expirado» no significa «inofensivo».

### 5.4 Cookies de sesión: qué se comprueba

Sobre las cabeceras de respuesta ya capturadas (`curl -D`), `header_tls_report.py`
hace el trabajo mecánico. Lo que hay que mirar y razonar:

| Atributo | Pregunta | Si falta |
|---|---|---|
| `HttpOnly` | ¿El JavaScript puede leer la cookie? | **ALTO** si además hay XSS: la sesión se roba desde el navegador |
| `Secure` | ¿Se envía en claro sobre HTTP? | **MEDIO** |
| `SameSite` | ¿Se envía en peticiones iniciadas por terceros? | **MEDIO** (CSRF) |
| `__Host-` / `__Secure-` | ¿Prefijo de protección del navegador? | **BAJO** (defensa en profundidad) |
| `Path=/` y `Domain` | ¿El alcance de la cookie es el mínimo posible? | **BAJO/MEDIO** |
| `Max-Age`/`Expires` | ¿La sesión expira? | **MEDIO** |
| `Clear-Site-Data` en logout | ¿Se invalidan las cookies al cerrar sesión? | **BAJO** |

Y una comprobación que no es de cookie pero va con ella: **¿la sesión sobrevive a un
cambio de contraseña?** Eso se verifica en Fase 2 con cuenta propia, o se le pregunta
al cliente. **Nunca** se comprueba con una cuenta ajena.

---

## 6. IPs y datos personales no enmascarados

### 6.1 Por qué esta sección existe

Esta es la parte de la auditoría donde el propio auditor es el riesgo. Leer un `.env`
o listar rutas deja como máximo una huella en el log del servidor. Aquí, una operación
de «investigación» puede producir **un fichero con las IPs de los pacientes que
visitan la web de una clínica**: datos personales que el auditor no tenía derecho a
tener, que no pidió a nadie, y que no puede devolver.

**La regla que lo resuelve: demostrar sin copiar; contar, no recolectar.**

| Se demuestra | No se hace |
|---|---|
| Que la cabecera `X-Forwarded-For` se devuelve **sin enmascarar** en la respuesta | Acumular las IPs que se han visto en 50 peticiones |
| Que la plantilla de log escribe la IP completa | Extraer las IPs de un log descargado |
| Que la página de error incluye la IP del visitante | Recolectar las IPs de los visitantes |
| Que `server-status` es accesible y muestra IPs de origen | Capturar un listado de visitantes |
| Que el parámetro `?ip=` de una herramienta de prueba de IP devuelve la IP del visitante | Usar esa herramienta 100 veces para tener una lista |

### 6.2 Vectores de exposición de IP y datos personales

| Vector | Cómo se detecta | Modo | Qué se registra | Qué NO |
|---|---|---|---|---|
| **IP en log de servidor servido por web** (`/logs/`, `/error_log`, `/debug.log`, `/app.log`) | GET a rutas de log vía `probe_exposure.py --path-list`; `secrets_scan.py` para credenciales dentro | ACTIVA-L + PASIVA | Presencia del patrón y **conteo de líneas** | No se copia el log. No se extraen IPs |
| **`X-Forwarded-For` / `X-Real-IP` reflejados** en la respuesta | Lectura de las cabeceras ya capturadas; página «tu IP es X» | ACTIVA-L (1 petición) | La cabecera tal cual, con la IP **enmascarada** | No se hacen 50 peticiones para acumular IPs |
| **Analytics** | `js_intel.py` clasifica el host de terceros (`analitica`) y detecta si hay cookies o IP en la URL | PASIVA | Qué analítica y qué **categoría** de dato envía. **Un píxel que manda la URL completa con `?paciente=…` es un hallazgo** | No se envían eventos de prueba |
| **Cabecera de error** (`Server`, `X-Powered-By`, `X-ASP.NET-Version`, stack trace) | `header_tls_report.py` + lectura de cabeceras | PASIVA | Los nombres de cabeceras y sus valores | — |
| **Query string con identificadores** (`Referer`, `?token=`, `?session=`) | Lectura del HTML y de los enlaces | PASIVA | Presencia de identificadores en query strings | No se enumeran ni se siguen los enlaces con datos |
| **Correo de error** (el cliente lo reenvía) | Lectura del correo que el cliente aporta | PASIVA | El **patrón** (`IP del visitante`, `User-Agent`, `Referer`) | No se transcribe el correo ni las IPs |
| **CORS `*` con credenciales** | `header_tls_report.py` marca `ACAO: *` + `ACAC: true` | PASIVA | La combinación de cabeceras | No se intenta el *cross-origin read* desde un navegador ajeno |
| **Cookies de sesión** servidas en respuestas guardables | Inspección de cabeceras | PASIVA | Atributos de la cookie | **No se guarda el valor de la cookie** |
| **`Referer` con query string sensible** | Lectura del HTML | PASIVA | Presencia de identificadores en query strings | No se enumeran |
| **Endpoints que devuelven datos de pacientes** (IDOR potencial) | `probe_exposure.py` + `js_intel.py` | ACTIVA-L | Ruta, código, **claves del JSON** | No se listan ni se descargan registros |

### 6.3 Marco legal aplicable — y lo que hay que leer

> **Todo lo de este apartado está marcado **NO VERIFICADO**.** No se cita un artículo
> concreto sin haberlo leído en la fuente primaria vigente. La doctrina del playbook es
> explícita: *«Nunca cites una ley de memoria: léela y enlaza.»*

#### México — LFPDPPP

| Punto | Estado | Fuente primaria a leer |
|---|---|---|
| Qué ley rige la protección de datos personales en posesión de particulares en México | **NO VERIFICADO** — el playbook recoge que la ley fue **reformada en marzo de 2025** (DOF 20-mar-2025, en vigor desde el 21-mar-2025) y que **el INAI ya no existe**: sus funciones corresponden a la **Secretaría Anticorrupción y Buen Gobierno**. **Hay que verificar el texto vigente y el nombre exacto de la autoridad** | **DOF** — texto vigente de la LFPDPPP y sus reformas; Cámara de Diputados: <https://www.diputados.gob.mx/LeyesBiblio/> |
| Qué artículo tipifica la falta de aviso de privacidad | **NO VERIFICADO** — el playbook recoge el art. 58 fr. V. **A confirmar** | DOF / LeyesBiblio, art. 58 |
| Qué artículo regula la transferencia internacional de datos | **NO VERIFICADO** — el playbook recoge art. 35 + art. 58 fr. X. **A confirmar** | DOF / LeyesBiblio, art. 35 y 58 |
| Qué artículo obliga a notificar la brecha | **NO VERIFICADO** — el playbook recoge el art. 19 (notificación a los pacientes afectados). **A confirmar, incluido el plazo y el destinatario** | DOF / LeyesBiblio, art. 19 |
| Cuál es la sanción máxima y si se duplica para datos sensibles | **NO VERIFICADO** — el playbook recoge art. 59 fr. III con duplicación en fr. IV. **El valor en UMA y la actualización del INEGI hay que leerlos el día del informe** | DOF / LeyesBiblio, art. 59 |
| Que los **datos de salud son datos sensibles** | **NO VERIFICADO** en el artículo concreto, aunque la calificación como *datos sensibles* es la base de todo el análisis de riesgo del playbook | DOF / LeyesBiblio, parte definitoria |
| Marco de salud y del expediente clínico | **NO VERIFICADO** — serie **NOM-004-SSA3** y normativa de interoperabilidad del expediente clínico electrónico. **No se cita un número de norma sin comprobarlo** | DOF, búsqueda de la norma vigente; CEN de la Secretaría de Salud |

#### España — RGPD y LOPDGDD

| Punto | Estado | Fuente primaria a leer |
|---|---|---|
| Que una IP es un dato personal, y que los datos sobre salud son una categoría especial | **NO VERIFICADO** en la redacción de los artículos, aunque es la interpretación consolidada. **A confirmar** | **EUR-Lex**: Reglamento (UE) 2016/679 (RGPD), texto consolidado: <https://eur-lex.europa.eu/eli/reg/2016/679/oj> — art. 4 y cap. IX |
| Principios de tratamiento (minimización, finalidad, seguridad) y obligación de notificación de brecha | **NO VERIFICADO** en los números de artículo concretos | EUR-Lex, RGPD |
| Ley Orgánica de Protección de Datos y Garantía de los Derechos Digitales | **NO VERIFICADO** en los números de artículo | **BOE**: <https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673> |
| Marco europeo de datos de salud interconectados | **NO VERIFICADO** — existe un Reglamento europeo sobre el espacio europeo de datos sobre la salud, pero **no se cita su número de Reglamento sin comprobarlo en EUR-Lex** | EUR-Lex, búsqueda de «espacio europeo de datos sobre la salud» |

> **Cómo se redacta en el informe.** En el bloque legal del informe, cada afirmación
> legal lleva (a) el artículo **sólo si se leyó la fuente primaria en esta auditoría**,
> (b) el **enlace** a esa fuente, y (c) la marca **NO VERIFICADO** si no se leyó. Un
> informe con una columna «artículo» vacía y una columna «qué hay que leer para
> cerrarlo» es **mejor** que un informe con un artículo inventado: el primero es una
> lista de trabajo para el abogado del cliente; el segundo es un pasivo legal para el
> auditor.

### 6.4 La redacción: el pasa-mustras obligatorio

**Regla.** Ninguna evidencia que contenga datos personales sale del escritorio del
auditor sin pasar por `pii_redact.py`.

```bash
python3 pii_redact.py evidencia-cruda/ --out-dir evidencia-sanitizada --report evidencia/redaccion.json
```

Lo que `pii_redact.py` redacta, **categorías reales del script**: `email`,
`telefono`, `rfc_nif_dni_cuit`, `ip`, `tarjeta`, `fecha_nacimiento`, `codigo_postal`,
`url_credenciales`, `dato_personal_json`. Y en claves JSON/HTML con nombre típico de
dato personal o clínico: `nombre`, `apellido`, `nombre_paciente`, `telefono`, `email`,
`direccion`, `diagnostico`, `expediente`, `num_expediente`, `fecha_nacimiento`, `curp`,
`rfc`, `nss`, `nhis`, `paciente`, `patient`, `patient_id`, `dob`, `ssn`, `address`,
`phone`, `genero`, `sexo`, `edad`, `alergias`, `antecedentes`, `tratamiento`,
`receta`, `medicamento`, `grupo_sanguineo`, `seguro`, `poliza`, `padre`, `madre`,
`tutor`, `familiar`, `tarjeta`, `num_tarjeta`, `card_number`, `cvv`, `cvc`.

Dos banderas que se usan en la práctica:

| Bandera | Cuándo | Efecto |
|---|---|---|
| `--keep-ips` | Cuando las IPs **del cliente y su infraestructura** son el objeto del hallazgo y hay que mostrarlas completas | Conserva las IPs. **Nunca** se usa para una captura que también contenga IPs de visitantes |
| `--extra-key "clave"` | Cuando el JSON del cliente usa un nombre de campo no estándar para un dato personal (p. ej. `id_expediente`, `ficha`) | Añade esa clave al catálogo |

**El informe de redacción contiene conteos, nunca valores.** Eso es lo que permite
adjuntar el informe de redacción al informe técnico: demuestra *qué* se encontró y
*cuánto*, sin filtrar nada.

**Limitación que hay que declarar.** `pii_redact.py` no tiene NER: **no detecta
nombres de personas en texto libre**. Un nombre propio en medio de un párrafo no se
redacta. Consecuencia práctica: **las capturas y los extractos de texto libre se
revisan a mano antes de entregarlos**, y si contienen un nombre de paciente se
sustituye por `[PACIENTE]` a mano y se anota en el registro de acciones. Es una
limitación del script, no una garantía: **no se confunde «el script no lo detectó» con
«no hay datos personales»**.

---

## 7. Superficie de API: descubrimiento y modelo de riesgo

### 7.1 Cómo mapear la API

Cuatro fuentes, en este orden. Las dos primeras son locales y no cuestan ni una
petición.

| # | Fuente | Herramienta | Qué produce |
|:-:|---|---|---|
| 1 | **JavaScript y HTML ya descargados** | `js_intel.py` | Endpoints absolutos y relativos extraídos de `fetch`, `axios`, `$.ajax`, `url:`, `XMLHttpRequest.open` y cadenas que parecen rutas; **rutas sensibles**; operaciones GraphQL; hosts de terceros clasificados; `//# sourceMappingURL=`; `<script src>` con comprobación de SRI; secretos en scripts *inline* |
| 2 | **Documentación publicada** | `probe_exposure.py` | `/swagger.json`, `/openapi.json`, `/api-docs`, `/swagger-ui/`, `/graphql`, `/graphiql` |
| 3 | **WordPress REST** | `curl` + `js_intel.py` | `/wp-json/wp/v2/*` y el atajo `/?rest_route=`. **Comprobar si el atajo elude el mismo filtro que la ruta canónica** — en el caso de referencia eludía el filtro: ambos devolvían lo mismo, lo que significa que no había regla de borde |
| 4 | **Convenciones de ruta** | `probe_exposure.py` | `/api/`, `/api/v1/`, `/api/v2/` |

```bash
python3 js_intel.py ./evidencia/ --base-host clinica-ejemplo.mx \
        --json-out evidencia/js_intel.json --out evidencia/js_intel.md
```

> `--base-host` **no cuenta como tercero** los hosts del propio cliente. Es el detalle
> que evita que el informe liste `clinica-ejemplo.mx` como «sitio de terceros» y que
> el lector pierda la confianza en el resto de la tabla.

### 7.2 Cómo se documenta

**Una sola tabla**, con estas columnas. Es el formato que va al informe:

| endpoint | método | auth | params | datos que devuelve | PII sí/no | severidad |
|---|---|---|---|---|---|---|
| `/api/v1/pacientes/{id}` | GET | Bearer (JWT) | `id` (path) | Ficha de paciente | **SÍ** (datos de salud) | ALTO — IDOR potencial |
| `/api/v1/citas` | GET | Bearer (JWT) | `fecha`, `pagina` | Listado de citas | **SÍ** | MEDIO |
| `/api/v2/config` | GET | ninguna | — | Configuración de cliente, endpoint de terceros | NO | MEDIO |
| `/wp-json/wp/v2/users` | GET | ninguna | `per_page` | Login, slug, avatar URL (hash MD5 del email) | **SÍ** (email derivable) | ALTO — oráculo de enumeración |
| `/api/v1/admin/reportes` | GET | ninguna | `?desde=` | Volcado de reportes | **SÍ** | CRÍTICO si devuelve datos reales |

**Reglas de llenado.** `auth`: `ninguna` / `cookie` / `bearer` / `api-key` / `¿?`.
`params`: los que **se observan** en el JS o en la documentación; no se inventan por
conjetura. `datos que devuelve`: **nombres de campos**, no valores — «`nombre`,
`telefono`, `fecha_cita`» es correcto; ««Juan Pérez», 555…»» es una filtración de datos.
`PII sí/no`: la pregunta es *«¿esta ruta puede devolver datos de una persona
identificable?»*, no *«¿lo dice la documentación?»*; si no se sabe, **«probable — no
verificado»**. `severidad`: la matriz de `como-presentar-resultados.md` §1, y **no** lo
que suene la ruta.

### 7.3 Las pruebas seguras, una por una

**Regla que gobierna esta tabla:** cada prueba tiene un **proxy de severidad** (la
evidencia que permite calibrar sin manejar el dato real) y un **criterio de
no-verificación** (qué se escribe cuando no se puede ejecutar). Este último es lo que
impide que un «no lo probé» se convierta en un «no pasa nada».

| Prueba | Cómo se hace **sin tocar datos de terceros** | Proxy de severidad | Criterio de no-verificación |
|---|---|---|---|
| **IDOR / BOLA** | **Dos cuentas de prueba** entregadas por el cliente, con datos sintéticos y contrato escrito de que sus registros no contienen datos de pacientes reales. `GET /api/v1/pacientes/{id-A}` con la cuenta A y con la cuenta B. Se comparan **códigos, longitudes y claves del JSON**. No se transcribe el contenido | **La diferencia de respuesta**: si B obtiene el registro de A, el control de acceso por objeto no existe. La severidad no depende del contenido, sólo de que **los dos obtain** | Sin dos cuentas de prueba → **NO VERIFICADO**, con el motivo y la cuenta que hace falta. **Nunca** se prueban IDs de pacientes reales para «ver si hay alguno accesible» |
| **Mass assignment** (sobreescritura de campos) | Con la **cuenta propia del auditor**, en un recurso propio, se envía un campo de control (`role`, `is_admin`, `precio`, `estatus`) con un valor inocuo. Se comprueba si el servidor lo acepta | **Si el servidor persiste un campo que el cliente no debería controlar**, el control de acceso horizontal/vertical falla. Con datos propios, no hay exposición | Sin cuenta de prueba → **NO VERIFICADO**. **Nunca** sobre un registro ajeno. Y en Fase 1 (sin POST) el campo ni siquiera se puede probar → se marca «no probado por RoE» |
| **JWT / cookie en endpoints** | Lectura de las cabeceras: ¿el endpoint con `Authorization` inventado devuelve `401` o `200` con datos? Un `GET` con un token **deformado** (no un token de otra persona) | **El código de respuesta con credencial inválida**: `401`/`403` = control presente; `200` con contenido = **el endpoint no exige autenticación**, que es un hallazgo por sí mismo | Si el endpoint devuelve datos sin autenticación, **no se listan**. Se reporta la ruta, el código y las claves |
| **GraphQL — introspection** | `GET` con la query de introspección estándar. Se registra **si el esquema se expone** y **cuántos tipos** hay | **La disponibilidad de la introspección** en producción es el hallazgo (superficie no documentada). La profundidad del esquema es dato, no daño | Si `introspection` está deshabilitada → **INFO**, y se documenta como buena práctica |
| **GraphQL — profundidad excesiva** | **NO se mide en Fase 1.** Medición = enviar consultas anidadas = carga. En Fase 2, con cuenta propia y consultas de complejidad acotada y **una sola** por punto | **El resultado de la consulta acotada**: si el servidor la acepta sin límite ni timeout, la capacidad está presente | En Fase 1: **NO VERIFICADO** con el comando de 60 segundos que se le da al cliente para probarlo él mismo |
| **Ausencia de rate limiting** | **NO se mide.** Medir = muchas peticiones = carga masiva, prohibida | Un único intento con credencial inválida **no dice nada** sobre el límite. Por eso **no se mide** | **NO VERIFICADO**, con el comando de 60 segundos para el cliente. Se escribe explícitamente: *«no se mide porque medirlo requiere un volumen de peticiones incompatible con el RoE»* |
| **CORS** | Se observa la cabecera `Access-Control-Allow-Origin` en la respuesta a un `GET` con un `Origin` **del propio cliente** o vacío. Nunca con el `Origin` de un atacante | **La combinación**: `ACAO: *` + `Access-Control-Allow-Credentials: true` = configuración insostenible; `ACAO` con origen fijo = política explícita; `ACAO` que **refleja** el `Origin` sin `Vary: Origin` = permisiva | Con **un solo volcado** no se puede distinguir una allowlist estática de un origen reflejado. Se marca **pendiente de verificación** (es una limitación conocida del propio `header_tls_report.py`) |
| **Enumeración de usuarios / comentarios** | Se **cuenta** el número de respuestas, no se listan | El **conteo** es el proxy: «el endpoint devuelve N elementos sin autenticación» | Si los elementos son datos de pacientes, se reporta **N** y la **categoría**, nunca los elementos |

### 7.4 El proxy de severidad, en una frase

> **La severidad de un hallazgo de API se calibra por la diferencia observable —código,
> longitud, claves, conteo—, nunca por el dato devuelto.** Un endpoint que devuelve
> 50 expedientes tiene la misma severidad se reporte como «50 registros accesibles sin
> autenticación» o como «los 50 nombres». La primera es un hallazgo; la segunda es una
> filtración de datos que el auditor ha causado.

### 7.5 «No lo pruebo porque no tengo cuenta de prueba»

Ésta es una frase que **se escribe en el informe**, con este formato exacto:

> **NO VERIFICADO — `<prueba>`**: requiere `<requisito que falta>`.
> **No se ejecutó porque:** `<motivo literal, sin eufemismo>`.
> **No se ejecutó porque habría supuesto:** `<el daño concreto que la prueba habría
> causado>`.
> **Cómo cerrarlo (el cliente, en 60 segundos):** `<comando o ticket>`.
> **Severidad si se confirma:** `<valor>` — **no es un riesgo bajo; es un riesgo sin
> medir.**

Ese último renglón es el que importa comercialmente: **«no verificado» no es «bajo»**.
Es un riesgo **sin medir**, y se presenta con la misma prominencia que los demás. Un
informe que confunde «no medido» con «no hay problema» es exactamente el tipo de
informe que un cliente no vuelve a contratar.

---

## 8. El «Secret Register»

### 8.1 El formato

Una sola tabla, en el informe técnico, en el bloque de exposición de secretos. Es el
artefacto que el cliente rota contra.

| id | tipo | vector | ubicación | masked | fingerprint | ¿vive? | alcance real | criticidad | rotación urgente | owner | evidencia |
|---|---|---|---|---|---|---|---|---|---|---|---|
| S-01 | `stripe_secret_key` | JS de cliente | `https://clinica-ejemplo.mx/assets/main.js` (línea 1) | `sk_l******9x` | `a1b2c3d4e5f6` | **sí** (200 en `/v1/account`) | Cuenta de cobro del cliente; clave sin restricción de permisos | **CRÍTICO** | **sí — 24 h** | equipo técnico | `evidencia/secrets.json`, `evidencia/s3_stripe.json` |
| S-02 | `connection_uri_credentials` | `.env` publicado | `https://clinica-ejemplo.mx/.env` | `post******xy` | `f6e5d4c3b2a1` | **no probado** (no se abre conexión) | Acceso al almacén de datos de pacientes | **CRÍTICO** | **sí — inmediata** | hosting / equipo técnico | `evidencia/probe_exposure.tsv` |
| S-03 | `jwt` | log público | `https://clinica-ejemplo.mx/logs/app.log` | `eyJhbG******k3` | `1a2b3c4d5e6f` | **no** (`exp` en el pasado) | Claims de rol `admin` | **ALTO** | **sí — 72 h** | equipo técnico | `evidencia/secrets.json` |
| S-04 | `slack_webhook` | HTML inline | `https://clinica-ejemplo.mx/contacto.html` | `http******3f` | `9f8e7d6c5b4a` | **no probado** (no se envía mensaje) | Permite escribir en un canal del cliente | **MEDIO** | **sí — 7 días** | agencia web | `evidencia/secrets.json` |

### 8.2 Columna por columna

| Columna | Qué va | Qué NO va |
|---|---|---|
| **id** | `S-01`, `S-02`… estable entre versiones del informe | Nombres de fichero del cliente |
| **tipo** | El patrón de `secrets_scan.py` (`stripe_secret_key`, `jwt`, `aws_secret_access_key`, `connection_uri_credentials`, `private_key_block`, `discord_webhook`, `npm_auth_token`…) o el vector | Descripción en prosa |
| **vector** | De dónde salió (V01–V33, §2.1) | — |
| **ubicación** | Ruta exacta (`host/path`) + línea si es local. **URL del cliente**, nunca de un tercero | Contenido del fichero |
| **masked** | `abcd******yz` (4 + 6 + 2) | El valor |
| **fingerprint** | `sha256[:12]`. Correlaciona dos apariciones sin mostrarlo | Un hash truncado a 4 que colisiona |
| **¿vive?** | `sí` / `no` / `no probado` / `no aplica` (placeholder, JWT expirado) | Celda vacía, que se lee como «no se comprobó» |
| **alcance real** | **La categoría de recurso**, en lenguaje de negocio | La lista de recursos |
| **criticidad** | CRÍTICO / ALTO / MEDIO / BAJO / INFO según la matriz | «Crítico (probable)» |
| **rotación urgente** | `sí — inmediata` / `sí — 24 h` / `sí — 7 días` / `no` / `pendiente de confirmar` | — |
| **owner** | Quién rota: hosting, agencia, equipo interno, proveedor | «El cliente» (no es accionable) |
| **evidencia** | Ruta del fichero de evidencia | Contenido pegado |

### 8.3 Cómo se rellena «alcance real» sin enumerar recursos ajenos

Esta es la columna que más se malinterpreta y la que más información da. La regla:

> **El alcance se describe por CATEGORÍA y por DECLARACIÓN, nunca por INVENTARIO.**

| Lo que el auditor SÍ escribe | Lo que el auditor NO escribe |
|---|---|
| «Acceso completo a la cuenta de cobro de Stripe del cliente» | «Puede cobrar a los pacientes 4281» |
| «Lectura de objetos del bucket `…` del proyecto `…`» (roles IAM declarados) | «Puede leer el bucket que contiene las radiografías de 2019–2026» (ni el nombre del bucket si no es necesario) |
| «Emite eventos de Sentry del proyecto del cliente» | «Puede leer los eventos con los datos que los pacientes escribieron en los formularios» |
| «Permiso de lectura en la API de la clínica (rol `reader` según el panel del cliente)» | «Puede leer los expedientes de los 12 000 pacientes» |
| «Permiso `storage.objectViewer` en el proyecto del cliente» | La policy IAM completa con los miembros (que pueden ser correos de terceros) |
| «Token de solo envío según el panel del cliente» | La lista de endpoints a los que puede enviar |

**La fuente de la columna «alcance real» es una de estas tres**, y en el informe se dice
cuál:

| Fuente | Cómo se obtiene | Cuándo se usa |
|---|---|---|
| **Panel del cliente** | El cliente comparte una captura de la sección de permisos de la credencial | Siempre que sea posible: es la fuente primaria y no genera ninguna petición |
| **Documentación del proveedor** | Los scopes que declara la propia credencial en la respuesta de su API | Cuando el panel no está disponible |
| **Rol IAM / policy del proyecto** | `gcloud projects get-iam-policy <proyecto>` — **sólo del proyecto del cliente** | Credenciales de Google Cloud |

> **Prioridad práctica: preguntarle al cliente.** Un correo de 60 segundos al
> responsable técnico —*«¿puedes compartir la captura de los permisos de esta clave?»*—
> produce mejor evidencia que cualquier exploración, y **no genera ni una petición**.

---

## 9. Reglas de redacción y manejo de evidencia

### 9.1 Qué se enmascara siempre

| Elemento | Cómo se enmascara | Por qué |
|---|---|---|
| **Valor completo de cualquier secreto** | `abcd******yz` + `sha256[:12]` | Es la credencial. Su valor completo es un activo del atacante, no del informe |
| **Token de API / bearer / sesión** | Ídem | Ídem |
| **Cookie de sesión** (valor) | **No se copia**; se registra el nombre de la cookie y sus atributos | Es una credencial viva |
| **IP de persona identificable** (visitante, paciente) | `198.51.100.0/24` con los 3 últimos octetos enmascarados, o `[IP-ENMASCARADA]` | Es dato personal. Una IP puede identificar a un paciente que consultó en una clínica de salud mental o de enfermedades infecciosas |
| **IP del cliente / su infraestructura** | **Se conserva completa** si es el objeto del hallazgo (`--keep-ips` sólo para estos ficheros, nunca para una captura con IPs de visitantes) | Es la evidencia técnica del hallazgo |
| **Email de paciente** | `j***@correo.mx` o `[EMAIL-REDACTADO]` | Dato personal |
| **Email de personal del cliente** | Se conserva en el informe técnico (son datos de la empresa cliente), **se redacta en la copia que va a terceros** | El cliente es el destinatario |
| **Identificador de expediente** | `EXP-2024-00***` | Puede llevar nombre en algunos sistemas |
| **RFC / CURP / NSS / NIE / NIF / CUIT** | `[REDACTADO:rfc_nif_dni_cuit]` | Identificadores nacionales |
| **Teléfono** | `[REDACTADO:telefono]` o `+52 55 *** ** 89` | Dato personal |
| **Fecha de nacimiento** | `[REDACTADO:fecha_nacimiento]` | Dato personal y de salud |
| **Diagnóstico, tratamiento, receta, alergias** | `[REDACTADO:dato_personal_json]` | **Dato de salud: el más sensible de todos** |
| **Tarjeta / CVV** | `[REDACTADO:tarjeta]` | Datos de pago |
| **Nombre de paciente en texto libre** | `[PACIENTE]` — **a mano** | `pii_redact.py` no tiene NER (§6.4) |
| **URL con credenciales embebidas** | `postgresql://[REDACTADO:url_credenciales]@host` | Contiene la contraseña |

### 9.2 Qué sí puede mostrarse

| Elemento | Por qué se puede mostrar |
|---|---|
| **Prefijo del proveedor** (`sk_live_`, `AIza`, `ghp_`) | Identifica el proveedor y el modo (`live` vs `test`), que es la mitad del diagnóstico |
| **Longitud** del valor | Distingue una clave de 20 caracteres de una de 40 |
| **`sha256[:12]`** (fingerprint) | Correlaciona dos apariciones del mismo secreto sin revelarlo. Es la pieza que permite decir «la misma clave aparece en 3 ficheros» |
| **Tipo de patrón** | Dice qué hacer |
| **Código de estado, `Content-Type`, tamaño, `ETag`** | Evidencia de existencia, sin contenido |
| **Nombres de campo** de un JSON | Evidencia de qué devuelve un endpoint, sin devolver nada |
| **Conteos** (`x-OAuth-Scopes: read, write`, `total: 66`) | Evidencia de volumen sin contenido |
| **Roles/scopes declarados** | Evidencia de alcance sin exploración |
| **Un fragmento de código** con el secreto ya enmascarado | Contexto para el dueño |
| **Hash del cuerpo de un recurso público** | Reproducibilidad |

### 9.3 Por qué la evidencia nunca se entrega sin `pii_redact.py`

| Sin redacción | Con redacción |
|---|---|
| Un fichero de evidencia con un `.env` crudo viaja al hosting, a la agencia y al cliente. En el camino pasa por un correo, un ticket de Jira, un Drive compartido y un chat de equipo. **Cada salto es una copia más de la credencial** | El `.env` se entrega con los valores enmascarados y con un **inventario de variables** (`DB_HOST`, `DB_USER`, `DB_PASSWORD=[REDACTADO]`) |
| Un informe con el `.env` crudo **es un segundo `.env` publicado**, en un sitio con más audiencia que el original | Un informe con el `.env` enmascarado es un informe |
| Un ticket que pegue un token de Stripe **es una credencial viva en un sistema de ticketing**, con retención y búsqueda | El ticket dice: «clave de Stripe live en `main.js`, prefijo `sk_live_`, fingerprint `a1b2c3d4e5f6`, rotar ahora» |
| El correo de error que el cliente reenvió, con IPs de visitantes, se queda en la carpeta de correo del auditor | La captura va redactada y el informe sólo dice «la plantilla de log incluye la IP completa del visitante» |

> **El auditor no es un archivo de credenciales.** La evidencia cruda se queda en el
> disco cifrado del auditor, con retención definida en el RoE (§6 del RoE: «Retención de
> evidencia: [N] meses tras la entrega»), y **fuera de ella** sólo sale la copia
> redactada.

### 9.4 Qué NO es aceptable en un entregable

Tabla de control de calidad. Se recorre **antes** de cada entrega, con `grep` sobre
el fichero final.

| # | No es aceptable | Por qué | Cómo se comprueba |
|:-:|---|---|---|
| 1 | El valor completo de un secreto | Es una credencial viva en un PDF que se manda por correo | `grep -nE 'sk_live_[0-9A-Za-z]{10,}\|sk-ant-[A-Za-z0-9_-]{20,}\|AIza[0-9A-Za-z_-]{30,}\|ghp_[A-Za-z0-9]{30,}\|AKIA[0-9A-Z]{16}\|xox[baprs]-[A-Za-z0-9-]{10,}' informe.md` |
| 2 | Una URI de conexión con contraseña | Ídem | `grep -nE '://[^:/@ ]+:[^@/ ]+@' informe.md` |
| 3 | Un bloque de clave privada | Ídem | `grep -n 'BEGIN .*PRIVATE KEY' informe.md` |
| 4 | El valor de una cookie de sesión | Es una credencial | `grep -nE '(PHPSESSID\|JSESSIONID\|session\|csrf)[^A-Za-z0-9]{1,4}[A-Za-z0-9]{16,}' informe.md` |
| 5 | Un JWT completo | Contiene datos personales y claims de rol | `grep -nE 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.' informe.md` |
| 6 | Una IP de visitante sin enmascarar | Dato personal | `grep -nE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' informe.md` y revisión manual: las IPs de infraestructura **sí** se conservan |
| 7 | Un email de paciente | Dato personal y, cuando viene con diagnóstico, dato de salud | `grep -nE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' informe.md` — cada coincidencia se revisa una por una (los emails **del cliente** son legítimos) |
| 8 | Un identificador de expediente, CURP, RFC o NSS | Dato personal; el identificador de expediente suele permitir el acceso al registro | `grep -nE '\b[A-ZÑ&]{4}[0-9]{6}[A-Z0-9]{3}\b' informe.md` |
| 9 | Un diagnóstico, tratamiento o receta | **Dato de salud**: la categoría más sensible | Revisión manual de las capturas. `pii_redact.py` sólo los coge en claves JSON con nombre típico (`diagnostico`, `tratamiento`, `receta`, `alergias`) |
| 10 | Un volcado de `wp-json/wp/v2/media` o de un listado de pacientes | Es el dato de por sí | El informe describe **categorías y conteos**; el volcado no se pega |
| 11 | Un nombre de paciente en texto libre | `pii_redact.py` no tiene NER | Revisión manual de cada captura |
| 12 | El contenido íntegro de un backup, volcado SQL o log | Puede contener credenciales y PII | En el informe: ruta, código, tamaño, `ETag`. Nada más |
| 13 | Una credencial de un tercero (agencia, hosting, proveedor) | No es del cliente y su dueño no autorizó la auditoría | Se reporta la **relación** (el cliente manda datos a un tercero que no controla) y se redacta el borrador de ticket para el proveedor. **No** se publica el valor |
| 14 | Un dato de un inquilino del hosting compartido | Es de otro negocio | No se incluye: sólo la relación (comparten IP/cert) |
| 15 | Una URL real de un tercero como ejemplo | Puede ser un sitio real con datos reales | Se usan `clinica-ejemplo.mx` y marcadores `[CLIENTE]` / `[TERCERO]` |
| 16 | Un CVE sin fuente primaria | Es una afirmación no verificada | Cada CVE lleva su URL oficial del proyecto o del NVD |
| 17 | Una afirmación legal sin artículo y enlace | Es un pasivo legal | Cada afirmación legal lleva artículo **o** la marca **NO VERIFICADO** + fuente a leer |
| 18 | Un dato de paciente en la copia del teaser | El teaser no lleva dato técnico ni personal | El teaser se verifica con el script de verificación de la plantilla |

**El control de calidad es un paso con nombre.** En el registro de acciones (Fase 11)
hay una fila: *«Control de redacción del entregable»*, con los `grep` ejecutados, su
salida y la fecha. **Una tabla de QA que no se ejecuta es una tabla decorativa.**

### 9.5 La comprobación que ningún script hace

Los `grep` del §9.4 y del §11 (paso 12) comprueban **patrones**, no **contexto**. Hay
que **leer el informe entero** buscando cadenas de datos personales que ningún patrón
reconoce: un nombre de paciente en medio de un párrafo, un número de expediente con
otro formato. **El script garantiza las categorías; los ojos y el criterio especializado
garantizan el resto.**

---

## 10. Plantilla de informe para este módulo

El bloque que se pega en el informe técnico. Va como sección propia (por ejemplo
`§5.3 Exposición de secretos, datos personales y superficie de API`) o como anexo.
**Va al equipo técnico, nunca al dueño no técnico y nunca a un tercero.**

```markdown
## §X. Exposición de secretos, datos personales y superficie de API

### §X.1 Resumen de exposición

| Criticidad | Secretos | Datos personales expuestos | Endpoints de API | Total |
|---|---:|---:|---:|---:|
| CRÍTICO · ALTO · MEDIO · BAJO · INFO | <n> | <n> | <n> | <n> |
| **Total** | **<n>** | **<n>** | **<n>** | **<n>** |

**<1-3 frases>:** qué es lo que más importa de esta sección y qué hay que hacer hoy. Si
no hay secretos críticos, decirlo: *«No se encontró ninguna credencial viva»* es una
frase que hay que poder escribir, y escribirla con la evidencia encima es lo que da
credibilidad al resto del informe.

> **<N> hallazgos marcados NO VERIFICADO.** Cada uno lleva el requisito que falta y el
> comando de 60 segundos para cerrarlo. *«No verificado» no significa «seguro».*

### §X.2 Secretos expuestos (Secret Register)

| id | tipo | vector | ubicación | masked | fingerprint | ¿vive? | alcance real | criticidad | rotación urgente | owner | evidencia |
|---|---|---|---|---|---|---|---|---|---|---|---|
| S-01 |  |  |  |  |  |  |  |  |  |  |  |

### §X.3 Superficie de API

| endpoint | método | auth | params | datos que devuelve | PII sí/no | severidad |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |

**Pruebas de control de acceso no ejecutables sin cuentas de prueba:**

| prueba | estado | requisito que falta | severidad si se confirma |
|---|---|---|---|
| IDOR / BOLA | NO VERIFICADO | dos cuentas de prueba con datos sintéticos | <valor> |
| Mass assignment | NO VERIFICADO | cuenta de prueba + Fase 2 | <valor> |
| Rate limiting | NO VERIFICADO | requiere volumen de peticiones incompatible con el RoE | <valor> |
| GraphQL — profundidad | NO VERIFICADO | requiere Fase 2 y cuenta propia | <valor> |

### §X.4 Datos personales expuestos

| vector | dónde | qué se expone | prueba (sin copiar el dato) | criticidad | remediación |
|---|---|---|---|---|---|
| IP sin enmascarar | cabecera `X-Forwarded-For` en la respuesta de `/x` | IP completa del visitante | la cabecera devuelta tal cual | MEDIO | enmascarar en el borde |
|  |  |  |  |  |  |

**Recuento, no inventario.** En el informe **no** hay ninguna lista de IPs, emails ni
identificadores de pacientes: hay **conteos** y **descripciones del vector**.

### §X.5 Plan de rotación priorizado

| # | Credencial / activo | Por qué en este orden | Acción | Quién | Cuándo | Effort |
|:-:|---|---|---|---|---|---|---|
| 1 | <cred> | activa y con permisos de <categoría> | rotar + revocar la anterior + actualizar consumidores | <owner> | <plazo> | <h> |

**La rotación la ejecuta el cliente.** La auditoría entrega el inventario, el orden y
el comprobante de "rotado"; no el cambio.

### §X.6 Asumir compromiso

> **<Se escribe sólo si hay credenciales de base de datos, claves de firma de sesión o
> tokens administrativos vivos.>** Ver §4.5 para el texto de la credencial de base de
> datos. Adaptar el resto con la misma estructura: (1) rotar ahora; (2) revisar logs
> desde la fecha más antigua disponible; (3) auditar el contenido; (4) evaluar la
> notificación de la brecha (artículos **NO VERIFICADOS**: ver §X.7); (5) eliminar el
> fichero y solicitar la eliminación de las copias en Wayback/Common Crawl.

### §X.7 Cumplimiento — qué está verificado y qué no

| Afirmación | Estado | Fuente primaria a leer |
|---|---|---|
|  | **NO VERIFICADO** | <DOF / EUR-Lex / BOE + artículo> |

> Ninguna afirmación legal de esta auditoría se ha citado de memoria. Las marcadas
> **NO VERIFICADO** deben leerse en la fuente primaria antes de que el informe se use
> para una decisión con efectos jurídicos. Ver §6.3.

### §X.8 Qué NO se hizo

No se abrió ninguna conexión a la base de datos · no se usó ninguna credencial contra un
recurso ajeno al cliente · no se fabricó ninguna sesión ni cookie de administración · no
se enumeraron identificadores de pacientes ni se descargó ningún registro · no se
recolectaron IPs de visitantes más allá de la comprobación puntual · no se enviaron
mensajes a webhooks de Slack o Discord · no se enumeraron recursos con ninguna
credencial.
```

### 10.1 Notas de redacción del bloque

- **Los conteos van primero.** El lector decide si sigue leyendo en función del número;
  un informe que empieza por la tabla de 40 secretos hace que nadie llegue al CRÍTICO.
- **«No se encontró ninguna credencial viva» se escribe explícitamente.** Es lo que hace
  creíble el resto: una auditoría que sólo enumera problemas se lee como marketing.
- **La columna `¿vive?` admite tres valores** (`sí` / `no` / `no probado`). La ambigüedad
  aquí es una trampa: «no probado» leído como «no».
- **El plan de rotación va con dueño y plazo.** Un plan sin dueño no se ejecuta.
- **«Qué NO se hizo» es obligatorio.** Demuestra el alcance real del trabajo y
  **reduce el riesgo del auditor**: si algo se explotó, el informe lo dice.
- **El bloque legal va aparte y marcado.** Un artículo inventado en medio de un informe
  técnico degrada todo el documento.

---

## 11. Procedimiento reproducible

Doce pasos. Cada uno tiene **comando concreto**, **evidencia que produce** y
**condición de parada**. Es el flujo del README de `01-tooling/scripts`, reordenado para
que la exposición de secretos sea la fase central.

> **Precondición absoluta:** RoE firmado + `authorization.json` con firma. Sin eso,
> `scope_guard.py` y `probe_exposure.py` abortan con código 2 y no hacen ninguna
> petición. Si el RoE no está firmado, el procedimiento no empieza.

### Paso 0 — Autorización

```bash
python3 scope_guard.py --authorization auth.json --list-hosts --json
python3 scope_guard.py --authorization auth.json --check https://www.clinica-ejemplo.mx/.env
```

**Evidencia:** `evidencia/auth_verificada.txt`. **Parada:** si falta `signed_by`,
`signed_at`, `valid_from`, `valid_to` u `hosts`, el script falla con código 2. Se
arregla la autorización, no el script.

### Paso 1 — Recon pasivo (ya hecho en Fase 2 del ciclo)

```bash
curl -sS "https://crt.sh/?q=%25.clinica-ejemplo.mx&output=json" -o evidencia/crtsh.json
curl -sS "https://web.archive.org/cdx/search/cdx?url=clinica-ejemplo.mx/*&output=json&filter=statuscode:200" -o evidencia/cdx.json
```

**Evidencia:** `crtsh.json`, `cdx.json` (hosts y URLs históricas). **Parada:** ninguna;
es pasivo y va antes de tocar el objetivo. Un secreto que estuvo en Wayback **sigue
siendo público aunque se haya rotado**: se reporta la fecha de la captura.

### Paso 2 — Material local (HTML/JS descargado)

```bash
curl -sS -A "$UA" https://www.clinica-ejemplo.mx/ -o evidencia/home.html
# … el resto de páginas y bundles, uno por uno, con sleep 1 entre peticiones
```

**Evidencia:** `evidencia/home.html`, `evidencia/pages/*.html`, `evidencia/js/*.js`.
**Parada:** cuando se ha descargado la home, las páginas del menú y **todos los bundles
que la home referencia**. No se descarga el sitio entero.

### Paso 3 — Plan de sondeo (sin red)

```bash
python3 probe_exposure.py -a auth.json --host www.clinica-ejemplo.mx --dry-run
```

**Evidencia:** el plan impreso (hosts y las 53 rutas). **Parada:** **si alguna ruta del
plan no corresponde al alcance, se para aquí** y se corrige el `authorization.json` o se
añade la ruta con `--path-list`.

### Paso 4 — Sonda de exposición

```bash
python3 probe_exposure.py -a auth.json --host www.clinica-ejemplo.mx --out evidencia/
```

**Evidencia:** `evidencia/probe_exposure.tsv` (`host path code content_type length sha256
soft_404 verdict severity`), `evidencia/probe_exposure.json` y los cuerpos seguros
(`robots.txt`, `sitemap.xml`, `security.txt`). **Parada:** si la sonda encuentra un
`200` donde debería haber `403`, se documenta y **no se insiste**: no se reintenta la
ruta ni se prueban variantes. El RoE prohíbe el fuzzing de rutas.

### Paso 5 — Barrido de secretos en el material local

```bash
python3 secrets_scan.py ./evidencia --json --out evidencia/secrets.json
python3 secrets_scan.py ./evidencia --min-entropy 3.5 --ignore '*.lock'
```

**Evidencia:** `evidencia/secrets.json` con `file`, `line`, `type`, `severity`,
`masked`, `sha256`, `context` (ya redactado). **Parada:** ninguna; es local.
**Nota:** si el cliente aporta su repositorio, se escanea también
(`python3 secrets_scan.py ./repo-cliente --json --out evidencia/secrets_repo.json`),
respetando el `.gitignore` y saltando `node_modules`, `.venv`, `__pycache__`.

### Paso 6 — Inteligencia de JS (endpoints, terceros, source maps)

```bash
python3 js_intel.py ./evidencia/ --base-host clinica-ejemplo.mx \
        --json-out evidencia/js_intel.json --out evidencia/js_intel.md
```

**Evidencia:** `evidencia/js_intel.json` (`api_endpoints`, `sensitive_routes`,
`third_party_hosts` con categoría, `graphql_operations`, `source_maps`, `scripts` con
SRI, `inline_secrets`) y `evidencia/js_intel.md`. **Parada:** ninguna; es local.

### Paso 7 — Rutas derivadas de los hallazgos (segunda pasada, acotada)

```bash
printf '%s\n' /.source.map /credentials.json /.npmrc /.pypirc \
    /firebase-messaging-sw.js /manifest.json /humans.txt /redoc /logs/ /error_log \
  > /tmp/rutas.txt
python3 probe_exposure.py -a auth.json --host www.clinica-ejemplo.mx \
        --path-list /tmp/rutas.txt --out evidencia/
```

**Evidencia:** segunda vuelta de `evidencia/probe_exposure.tsv` (se renombra a
`probe_exposure_extra.tsv`). **Parada:** **≤ 20 rutas**. Cada ruta extra sale de un
hallazgo concreto del paso 5 o 6; si la lista crece, se recorta. La sonda es de rutas
conocidas, no un escáner.

### Paso 8 — Nivel 0: prueba de existencia sin descargar contenido

```bash
curl -sS -r 0-1023 -D - -A "$UA" https://clinica-ejemplo.mx/backup.zip | head -c 1024
```

**Evidencia:** cabecera + `sha256` del primer kilobyte, en `evidencia/nivel0.txt`.
**Parada:** un `5xx` o un `429` → se anota y se para. Un `200` → se registra la
existencia y se pasa al paso 9 con **el contenido ya descargado**, no se vuelve a bajar.

### Paso 9 — Nivel 1: plausibilidad (local, sin red)

Resuelto por el paso 5 y **enriquecido** con la tabla de plausibilidad (prefijo
conocido, longitud, entropía, placeholder):

```bash
python3 -c 'import json; d=json.load(open("evidencia/secrets.json")); [print(f["type"], "|", f["masked"], "|", f["sha256"], "|", f["file"], f["line"]) for f in d.get("findings", [])[:50]]'
```

**Evidencia:** la tabla de plausibilidad que se pega en el Secret Register. **Parada:**
los placeholders se descartan aquí (INFO) y **no pasan** al paso 10.

### Paso 10 — Nivel 2/3: verificación de vida y alcance

```bash
# Sólo con autorización escrita que nombre ESTA credencial y ESTE endpoint. Ver §3.3.
read -rs SK; echo
curl -sS -A "$UA" -H "Authorization: Bearer ${SK}" https://api.stripe.com/v1/account \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sorted(d.keys()))'
unset SK
```

**Evidencia:** `evidencia/nivel2_<proveedor>.json` con **código, nombres de campo,
conteos y fingerprint**; nunca el cuerpo crudo. **Parada:** una sola llamada por
credencial. `401` → se documenta como muerta. `429`/`5xx` → un reintento y se marca
*no verificado*. **Sin autorización escrita para esa credencial, este paso no se
ejecuta y el hallazgo queda como «no probado»** — que es el resultado honesto.

### Paso 11 — Redacción de la evidencia

```bash
python3 pii_redact.py evidencia-cruda/ --out-dir evidencia-sanitizada --report evidencia/redaccion.json
```

**Evidencia:** `evidencia-sanitizada/**` + `evidencia/redaccion.json` (conteos por
categoría, nunca valores). **Parada:** ninguna. **Este paso es bloqueante**: la
evidencia cruda no se comparte con nadie hasta que se ejecuta. Si el informe va a un
tercero, lo que sale es `evidencia-sanitizada/`.

### Paso 12 — Score, informe y control de calidad

```bash
python3 attack_surface_report.py \
    --probe-tsv evidencia/probe_exposure.tsv \
    --secrets-json evidencia/secrets.json \
    --headers evidencia/headers.txt \
    --dns-mailsec evidencia/dns_mailsec.txt \
    --tls-versions evidencia/tls_versions.txt \
    --crtsh evidencia/crtsh.json \
    --out informe/

# Control de calidad del entregable (§9.4)
grep -nE 'sk_live_[0-9A-Za-z]{10,}|sk-ant-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|ghp_[A-Za-z0-9]{30,}' informe/informe.md
grep -nE '://[^:/@ ]+:[^@/ ]+@' informe/informe.md
grep -n 'BEGIN .*PRIVATE KEY' informe/informe.md
```

**Evidencia:** `informe/attack_surface_report.md` + `.json` y el log del control de
calidad. **Parada:** **si el `grep` de secretos devuelve una coincidencia, el informe
no se entrega.** Se corrige el origen (el texto que pegó el valor) y se repite el
control. Un entregable con una credencial viva es un incidente, no un error de formato.

---

### 11.1 Resumen del protocolo de credenciales

El recorrido completo, en una línea por rama:

```
Credencial encontrada en material público
  -> ¿Placeholder (changeme / xxx / example / <=2 chars distintos)?  -> INFO, cerrar
  -> Nivel 0 (GET/HEAD, sin leer cuerpo): 404/soft-404 -> no existe, cerrar
                                            401/403      -> «existe y está protegida»
                                            5xx / 429    -> se anota y se para
                                            200          -> Nivel 1
  -> Nivel 1 (local: formato, prefijo, longitud, entropía)
                                            no plausible / hash / JWT expirado
                                               -> INFO o «exposición histórica»
                                            plausible y de proveedor -> Nivel 2
  -> Nivel 2 (1 lectura a la API del proveedor)
                                            sin autorización escrita -> «no probado»
                                            200 -> Nivel 3
                                            401 -> «muerta o revocada»: baja de severidad
                                            403 -> viva, alcance parcial
                                            429/5xx/ambigua -> un reintento, NO VERIFICADO
  -> Nivel 3 (declaración del proveedor, no exploración)
                                            declarado -> «alcance real» = categoría + scopes
                                            no determinable -> se pide captura al cliente (60 s)
  -> Nivel 4 (Fase 2: addendum firmado, cliente presente)
                                            SÍ -> 1 lectura no mutante + rotación DEL CLIENTE
                                            NO -> «NO VERIFICADO» + severidad si se confirma
```

---

## Fuentes primarias que hay que leer antes de citar

Este módulo **no sustituye** la lectura de la fuente primaria: la exige. Esta es la
lista que un auditor debe abrir **antes** de escribir el bloque legal del informe.

| Tema | Fuente primaria | Qué se verifica allí |
|---|---|---|
| LFPDPPP (MX) — texto vigente, definiciones, arts. 19 / 22 / 35 / 58 / 59 | **DOF** y Cámara de Diputados: <https://www.diputados.gob.mx/LeyesBiblio/> | Artículo y redacción exacta. **NO VERIFICADO** |
| Autoridad responsable de la protección de datos en MX | DOF / sitio de la autoridad competente | El nombre vigente de la autoridad. **NO VERIFICADO** |
| Norma del expediente clínico (MX) | **DOF** — serie NOM-004-SSA3 e interoperabilidad del expediente clínico electrónico | Vigencia y reformas. **NO VERIFICADO** |
| RGPD (UE) — datos personales, datos de salud, principios, seguridad, notificación de brecha | **EUR-Lex**: <https://eur-lex.europa.eu/eli/reg/2016/679/oj> | Artículos concretos. **NO VERIFICADO** |
| LOPDGDD (ES) · espacio europeo de datos sobre la salud | **BOE**: <https://www.boe.es/buscar/act.php?id=BOE-A-2018-16673> · EUR-Lex | Artículos y número de Reglamento. **NO VERIFICADO** |
| **Stripe** — endpoint de cuenta y permisos de las claves | <https://docs.stripe.com/api/account> | Forma del endpoint y qué devuelve. **NO VERIFICADO** para versiones concretas |
| **OpenAI / Anthropic / Twilio** — referencia de API y tipo de credencial | <https://platform.openai.com/docs/api-reference> · <https://docs.anthropic.com/en/api/getting-started> · <https://www.twilio.com/docs/api> | Endpoint de lectura, organización asociada y diferencia SID / Auth Token / API Key |
| **Google Cloud** — roles IAM y listado de proyectos | <https://cloud.google.com/iam/docs/roles-overview> · <https://cloud.google.com/resource-manager/reference/rest/v1/projects/list> | Qué roles existen y qué devuelve el listado. **NO VERIFICADO** para la versión concreta |
| **AWS / GitHub / GitLab** — identificadores y scopes de un token | <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html> · <https://docs.github.com/en/rest> · <https://docs.gitlab.com/ee/api/> | Prefijos de access key y cómo leer los scopes de un PAT |
| **Slack / Discord / Sentry** — webhooks y DSN | <https://api.slack.com/methods/auth.test> · <https://discord.com/developers/docs> · <https://docs.sentry.io/product/sentry-basics/dsn-explainer/> | Que el webhook es unidireccional y que el DSN **no** da lectura de eventos |
| **OpenAPI / GraphQL / Actuator / `mod_status`** | <https://spec.openapis.org/oas/latest.html> · <https://spec.graphql.org/> · <https://docs.spring.io/spring-boot/reference/actuator/endpoints.html> · <https://httpd.apache.org/docs/current/mod/mod_status.html> | Semántica de los campos, formato de la introspección y qué expone cada endpoint |
| **JWT** — buenas prácticas (`alg: none`, confusión HS/RS) | **RFC 8725**: <https://www.rfc-editor.org/rfc/rfc8725> | Qué se considera vulnerable y por qué. **NO VERIFICADO** |
| **OWASP** — hojas de referencia | <https://cheatsheetseries.owasp.org/> | `Secrets Management`, `GraphQL`, `Logging`, `Authorization`. Material de apoyo, **no fuente primaria** |
| **URIs de conexión** — esquemas por motor | <https://www.postgresql.org/docs/current/libpq-connect.html> · <https://www.mongodb.com/docs/manual/reference/connection-string/> | Qué motor corresponde a cada esquema |

---

## Anexo A — Errores frecuentes en esta fase

| # | Error | Por qué se cuela | Cómo se evita |
|:-:|---|---|---|
| 1 | Confundir **token público** con secreto | `pk.` de Mapbox, la clave de Firebase, el DSN de Sentry están **diseñados** para ser públicos | Preguntar: *¿esta credencial está pensada para ir en el navegador de cada visitante?* Si la respuesta es sí, por sí sola **no es un hallazgo** |
| 2 | Reportar un **JWT expirado** como activo | El token está en un fichero y «se ve grave» | Verificar `exp` **offline** y reportarlo como expirado. Sigue siendo PII → se redacta |
| 3 | Confiar en un **escáner** para el alcance | «La clave da acceso a 12 buckets» | El alcance lo declara el proveedor (Nivel 3). **Nunca** se enumera |
| 4 | **Pegar el `.env` crudo** en el informe | «El equipo técnico lo necesita» | El equipo técnico lo necesita **enmascarado**. Si necesita el real, lo tiene en su servidor |
| 5 | **Conectar a la BD** para «comprobar que la clave vive» | Parece inocuo y es una autenticación no autorizada | La credencial expuesta es crítica esté viva o no. La rotación es la misma |
| 6 | **Bajar el backup entero** «sólo para ver qué tiene» | Una descarga de 900 MB que además contiene datos de pacientes | `Range: bytes=0-1023`. Existencia y tipo, no contenido |
| 7 | **Pegar la IP de un paciente** en el informe para «documentar la fuga» | Un dato personal nuevo en un PDF que viaja por correo | `pii_redact.py` y enmascarado manual |
| 8 | **Recolectar IPs** de visitantes para «medir» la exposición | Parece la forma más rigurosa de demostrar el impacto | **Contar, no recolectar.** La demostración no necesita una lista |
| 9 | Confundir **soft-404** con exposición | `/admin/` devuelve `200` en casi todos los sitios | `probe_exposure.py` compara `sha256` con la referencia 404. Sin esa comparación, el informe es ruido |
| 10 | **Medir el rate limiting** | «Necesito saber si hay límite» | Medir = volumen de peticiones = RoE. Se marca **NO VERIFICADO** y se le da el comando al cliente |
| 11 | Escribir **«seguro»** donde no se comprobó | La presión comercial por cerrar el informe | *«No verificado»* es un resultado. *«No hay problema»* sin prueba no es un resultado |
| 12 | **Rotar** una credencial desde el panel del cliente | «Es un favor, lo hago en un minuto» | El auditor no rota. Rotar sin registrar el cambio deja la credencial nueva fuera del inventario del cliente |
| 13 | **Citar un artículo legal** de memoria | La ley cambió y el artículo cambió con ella | Se lee en DOF/EUR-Lex/BOE y se enlaza, o se marca **NO VERIFICADO** |

---
