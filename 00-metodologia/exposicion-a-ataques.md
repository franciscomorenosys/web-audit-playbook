# Exposición a ataques: cómo responder a «¿cuántos ataques ha recibido mi página?»

> **Para qué sirve este documento.** Es la respuesta operativa a la pregunta más
> frecuente y más difícil de los clientes de consultoría en seguridad:
> *«¿cuántos ataques ha recibido mi web?»*. La respuesta corta es que **ese
> número no se puede medir desde fuera**. Lo que sí se puede medir son tres
> cosas distintas, y confundirlas es la causa número uno de informes que
> suenan a venta de humo.
>
> **Cómo se usa.** Este documento es un módulo de `00-metodologia/`. Define la
> postura epistémica (qué se afirma y qué no), inventaría las fuentes —pasivas
> y con acceso del cliente—, define el indicador numérico que sí es
> defendible (`Attack Exposure Score`), y da el procedimiento reproducible con
> el comando de cada paso.
>
> **Doctrina que lo gobierna.** `reglas-de-autorizacion-y-roe.md` (prohibiciones
> duras, ritmo, regla de terceros), `ciclo-de-auditoria.md` (cada afirmación se
> traza a un archivo de evidencia; el escáner propone, la fuente primaria
> dispone) y `como-presentar-resultados.md` (verificar o refutar explícitamente;
> «lo que ya está bien» es obligatorio).

---

## 1. La pregunta y la respuesta honesta

### 1.1 La pregunta literal del cliente

> «Cómo ver cuántos ataques ha recibido la página web (¿se podrá ver?) y datos
> reales y cosas así... riesgos posibles, apis etc.»

Traducida a lenguaje técnico, la pregunta tiene cuatro partes que se responden
con métodos distintos:

| Parte de la pregunta | ¿Se puede responder? | Con qué |
|---|---|---|
| «¿Cuántos ataques ha recibido mi página?» | **No, desde fuera.** | Nada externo da el número. El número vive en los logs del cliente. |
| «¿Se podrá ver?» | **Sí, parcialmente.** | Superficie expuesta + indicadores de compromiso + volumen aproximado vía terceros. |
| «¿Y datos reales?» | **Sí, con autorización.** | Logs del cliente, con acceso autorizado y minimización. |
| «¿Riesgos posibles, APIs?» | **Sí.** | Es el objeto de la Fase 1: superficie, superficie de API y severidad. |

### 1.2 Por qué el número de ataques NO se puede contar desde fuera

Cinco razones, todas verificables, y ninguna es una excusa del auditor:

1. **El volumen de ataque es una propiedad de la telemetría del defensor, no
   de internet.** El contador más fiel de los intentos contra un sitio es el
   `access.log` del servidor, el log del WAF o el log de autenticación de la
   aplicación. Un tercero que mira desde fuera no tiene ninguno de esos tres.
2. **La mayoría de los ataques no dejan huella pública.** Un intento de
   credenciales contra `wp-login.php`, una enumeración de identificadores de
   paciente contra la API o un intento de inyección que falla no modifican nada
   del estado público del sitio. Un crawler externo que llega después no puede
   saber que ocurrió.
3. **El atacante controla su propio ritmo y su propia huella.** Los intentos
   útiles para un atacante son los de baja tasa, repartidos en el tiempo y
   provenientes de IP dispersas. Justo los que no dejan rastro en los índices
   públicos.
4. **Una parte importante de los ataques ocurre contra activos que no son el
   sitio web.** Correo corporativo con el nombre del dominio, formularios de
   reserva de un proveedor, la nube donde vive el sitio, la cuenta del hosting,
   el correo de la Reception. Ninguno de esos es «la página web» y ninguno es
   observable desde fuera.
5. **El propio tráfico del auditor falsea el recuento.** Si el equipo del cliente
   ve tus `GET`, tú apareces como un visitante más; si haces 300 peticiones
   para mapear el sitio, apareces como 300 peticiones. **Ninguna de tus
   peticiones cuenta como ataque** y hay que decirlo explícitamente en el
   informe para que el cliente no infiera un volumen distorsionado.

### 1.3 Lo que sí es medible (las tres cosas)

| # | Objeto medible | Cómo se mide | Quién lo mide |
|:-:|---|---|---|
| **1** | **Superficie de ataque expuesta** — todo lo que un atacante puede alcanzar sin autenticación: rutas, ficheros, subdominios, puertos, APIs, cabeceras. | Recon pasivo + sonda GET/HEAD sobre lista fija de rutas. | El auditor, desde fuera. |
| **2** | **Indicadores de compromiso (IoC)** — evidencia de que el activo ya fue tocado o usado por un tercero. | CT, DNS, histórico, logs internos, comparación de inventario. | Auditor (fuera) + cliente (dentro). |
| **3** | **Volumen de ataque aproximado** — interés externo y actividad observada por terceros. | urlscan.io, InternetDB, Censys, Safe Browsing, DMARC RPT. | Terceros. Es una **cota inferior sesgada**, no un volumen. |

> ### 🟢 Regla de oro de este documento
>
> ***«No afirmes un volumen de ataques que no has medido; afirma una superficie
> de ataque expuesta y cita la fuente de cada dato.»***
>
> Si el cliente insiste en el número, la respuesta profesional es: *«Ese
> número existe y es real, pero sólo lo tienen los logs del servidor. Lo que
> sí puedo darle hoy, con evidencia fechada y reproducible, es esto: su
> superficie, su estado de compromiso y una cota inferior del interés
> externo. Y si me autoriza los logs, le doy el número real en 48 horas.»*

### 1.4 Afirmación vs. lo que la evidencia sí sostiene

Esta tabla es la que se copia al informe. Cada fila es un hallazgo que un
auditor novel escribiría y la redacción correcta que lo sustituye.

| ❌ Afirmación que NO se sostiene | ✅ Lo que la evidencia sí sostiene | Fuente mínima |
|---|---|---|
| «Su web ha recibido 12 000 ataques.» | «En la ventana del 1 al 30 de octubre, el servidor registró **X** peticiones a rutas de autenticación desde **Y** direcciones IP distintas.» | Access log del cliente (autorizado) |
| «Su web es segura.» | «No se identificó ninguna exposición crítica en la superficie pública revisada. Revisión cerrada el *fecha*; no cubre autenticación, API interna ni red.» | Evidencia propia + fecha |
| «Nadie ha atacado su sitio.» | «No se encontraron indicadores de compromiso observables desde fuera hasta la fecha. Esto **no** descarta actividad interna o ataques sin huella.» | CT + DNS + histórico + urlscan |
| «Su sitio lleva 5 años sin brechas.» | «No hay forma de verificarlo desde fuera. El histórico disponible arranca en *fecha* y sólo cubre rutas indexadas por terceros.» | Wayback CDX / Common Crawl |
| «Nadie ha entrado.» | «No hay evidencia de acceso no autorizado en los logs revisados (rango *fecha*, *n* registros). Fuera de alcance: la red interna.» | Logs de autenticación del cliente |
| «Hay 34 subdominios.» | «Certificate Transparency registra **34** nombres distintos para `ejemplo.mx` hasta la fecha. **13** no resuelven hoy.» | crt.sh + `dig` |
| «Están expuestos los datos de los pacientes.» | «El endpoint `X` responde 200 y devuelve el esquema de la tabla de pacientes. **No se descargó ningún registro** (fuera de alcance: datos de terceros).» | `curl -D` + sonda |
| «El sitio tiene una vulnerabilidad crítica.» | «El parámetro `X` se refleja sin codificar en la respuesta de `Y`. **No se explotó**; no se comprobó alcanzabilidad de datos.» | Evidencia + comando reproducible |
| «Google no lo marca como malware.» | «A la fecha de la consulta, el dominio no aparecía en el informe de Safe Browsing. Es una fotografía de un momento.» | Transparency Report |
| «Nadie ha usado su dominio para phishing.» | «No se detectaron subdominios sospechosos en CT ni cambios de MX/TXT en la ventana revisada. No es prueba de ausencia.» | crt.sh + histórico DNS |
| «El TLS está roto.» | «El servidor **rechaza** TLS 1.0 y 1.1 (alert 70) y negocia 1.2/1.3 con cipher suites de la lista…» | `openssl s_client` + `tls_versions.txt` |
| «Su base de datos está expuesta.» | «El puerto 3306 aparece publicado en el escaneo de Shodan (dato de un tercero). No se escaneó ni se intentó conectar.» | InternetDB |
| «Su web recibe X visitas al día.» | «No se midió. No hay acceso a analítica y no se debe inferir del número de subdominios.» | — |
| «La auditoría confirma que están hackeados.» | «La auditoría confirma **exposición**. El compromiso se evalúa con los indicadores de la §5 y, cuando el cliente aporta logs, con la §4.» | — |

### 1.5 Dos precisiones que evitan la mayoría de los malentendidos

- **Todo dato externo es una fotografía fechada.** Cada fuente de §3 se cita
  con la fecha de consulta. Un informe que dice «crt.sh: 34 subdominios» sin
  fecha es un dato que caduca; uno que dice «crt.sh, consultado el
  2026-11-21: 34 nombres» es un dato reutilizable.
- **La ausencia de evidencia no es evidencia de ausencia.** Cuando una
  comprobación no se pudo hacer (API sin credencial, log no entregado, fuente
  caída), se escribe **NO VERIFICADO** con la comprobación pendiente y quién
  puede hacerla. Nunca se sustituye por un «no se encontró nada».

---

## 2. Taxonomía: exposición ≠ compromiso ≠ ataque

Cuatro conceptos que se confunden constantemente en los informes de seguridad
de sitios web. La confusión entre ellos es la que permite decir «recibió
12 000 ataques» cuando en realidad se han medido 12 000 rutas expuestas.

| Concepto | Definición | Señal concreta | Fuente | Cómo se prueba sin daño |
|---|---|---|---|---|
| **(a) Superficie expuesta** | Todo lo que un atacante puede **alcanzar** desde Internet sin credenciales. No implica que nadie lo haya hecho. | Ruta que responde 200; subdominio que resuelve; puerto publicado; API documentada; panel de login alcanzable. | Sonda GET/HEAD con lista fija; crt.sh; InternetDB; `dig`. | `probe_exposure.py` (53 rutas conocidas, sin fuzzing); consulta de CT y de portsindexados por terceros. |
| **(b) Indicador de compromise** | Evidencia de que **ya** hubo interacción anómala o persistencia. Implica que alguien actuó sobre el activo. | Fichero ejecutable subido; usuario admin nuevo; `wp-config.php` con hash distinto; cron nuevo; subdominio recién emitido; clave rotada sin explicación. | Logs del cliente; comparación de inventario; CT/DNS histórico; contraste con el proveedor. | Comparación de hashes con una copia conocida; `ls -la` de directorios de subida; export de usuarios; histórico de DNS. **Nunca se ejecuta el payload.** |
| **(c) Volumen de ataque** | Número de **intentos**. Requiere telemetría del defensor. | Peticiones a `wp-login.php`; POST a endpoints de API; 404 en masa sobre rutas de admin. | Access log; WAF/CDN; log de autenticación; IdP/MFA. | Agregación local de los logs del cliente (no hay que atacar nada). |
| **(d) Capacidad latente** | Lo que **daría** al atacante si explotara lo que encontró. Es un escenario, no un evento. | Cadena de enumeración de usuarios; API que acepta un token de un tercero; CORS `*` con credenciales. | Análisis del HTML/JS descargado; `js_intel.py`; lectura de cabeceras. | Se **describe** la cadena y se **rechaza** ejecutarla (RoE 1.3). La capacidad es el hallazgo; el resultado es el daño. |

### 2.1 Cómo se escribe cada uno en el informe

| Concepto | Redacción correcta | Redacción prohibida |
|---|---|---|
| Superficie | «El endpoint `X` está **expuesto**: responde 200 sin autenticación.» | «El endpoint `X` **fue hackeado**.» |
| Compromiso | «Hay un **indicador** de acceso no autorizado en `Y` (fichero `Z`, fecha `F`). Pendiente de confirmar por el cliente.» | «El sitio **está compromise**ido.» |
| Volumen | «El servidor registró **N** intentos de autenticación fallidos en la ventana `F`–`G`.» | «El sitio recibió **muchos ataques**.» |
| Capacidad | «La cadena `A→B→C` **permitiría** enumerar correos. No se ejecutó.» | «Se obtuvieron los correos.» |

### 2.2 La escalera que hay que tener clara al escribir

```
  Capacidad latente ──► Superficie expuesta ──► Volumen de intento ──► Compromiso ──► Impacto
   (puede existir)         (se mide desde           (sólo con logs)       (IoC)          (daño a datos)
                            fuera, sin daño)
```

- La auditoría pasiva vive en las **dos primeras casillas**: capacidad y
  superficie. Es un trabajo real y vendible.
- La tercera casilla (volumen) necesita acceso autorizado a logs. Es un
  upgrade de valor, no un supuesto.
- La cuarta (compromiso) requiere IoC y, para confirmarlos, al cliente.
- La quinta (impacto) es la Fase 2 y requiere RoE específico.

**Nunca se retrocede en la escalera.** Si un informe mezcla casillas —dice
«comprometido» porque encontró un `.env` descargable, o dice «12 000 ataques»
porque vio 34 subdominios— el cliente no sabe qué comprar.

---

## 3. Fuentes externas: lo que se ve desde fuera (PASIVA)

Todas las fuentes de esta sección son consultas a terceros. **Ninguna hace una
petición al activo del cliente**, salvo las marcadas como *activa de baja tasa*
en §11. Todas son compatibles con el RoE §1.4 y §1.5 (no se toca infraestructura
de terceros; no se escanea).

### 3.1 Tabla de fuentes externas

| Fuente | Qué revela | URL / API | Limitaciones | Uso en el informe |
|---|---|---|---|---|
| **crt.sh** (Certificate Transparency) | Todos los nombres DNS que **alguna vez** se certificaron bajo el dominio, incluidos los que ya no existen y los que nunca se enlazaron. | `https://crt.sh/?q=%25.ejemplo.mx&output=json` | Sólo muestra lo que se certificó; los subdominios que nunca se certificaron no aparecen. La emisión la hace **una CA**, no el propietario. | Inventario de subdominios + **detección de subdominio sospechoso emitido por un atacante** (nombre con `login`, `verify`, `secure`, `support`, `cdn-` + fecha muy posterior al resto). Base del componente `superficie_subdominios`. |
| **Shodan InternetDB** | Puertos abiertos, CVEs que Shodan asocia al software, hostnames del TLS y CPE del host, para **una IP**. | `https://internetdb.shodan.io/<IP>` | Es el **escaneo de Shodan, no el tuyo**: la foto es de la fecha del escaneo de ellos, no de ahora. No devuelve banners. Actualización semanal. No requiere API key. | Puertos administrativos publicados y CVEs ya indexados. Base del componente `puertos_administrativos`. **Se describe, no se escanea** (RoE 1.5: IP compartida = cero escaneo activo). |
| **Censys** | Similar a Shodan con más contexto: historial de servicios, historial de certificados, DNS histórico, reputación de host, riesgo de DNS colgante. | API de la plataforma; credenciales obligatorias. Referencia: `https://docs.censys.com/` | Requiere cuenta y créditos. **NO VERIFICADO** en este entorno: rutas exactas del endpoint, modelo de autenticación y límites de tasa concretos. | Historial de DNS y de certificados: es la fuente para «¿este CNAME existió antes y a dónde apuntaba?». |
| **urlscan.io** (búsqueda, nunca envío) | Historial de **escaneos hechos por terceros** sobre el dominio: URLs concretas visitadas, títulos, cabeceras, tecnologías, y los **parámetros de la petición** que el escáner usó. | `https://urlscan.io/docs/api/` | Sólo ve lo que un tercero escaneó y lo que se dejó en el registro público. Muestreo no aleatorio. **NO VERIFICADO**: sintaxis exacta de la consulta, campos disponibles y límites de tasa; la página de documentación respondió 429 al consultarla desde este entorno. | La fuente más reveladora de **intentos**: URLs con payloads de inyección, paneles de login clonados, ficheros subidos por otros. **Cota inferior sesgada**, nunca «número de ataques». |
| **Wayback CDX** | Índice histórico completo de URLs que un tercero capturó. Permite filtrar por código de estado, extensión y patrón. | `https://web.archive.org/cdx/search/cdx?url=ejemplo.mx/*&output=json&fl=original,statuscode,mimetype,timestamp&collapse=urlkey&filter=statuscode:200` | Sólo lo que el crawler capturó; sin garantía de continuidad. Sin API key, pero con condiciones de uso de archive.org. | **Rutas que ya estuvieron expuestas**: `/admin`, `/backup`, `/api/v1/users`, `/.env`, `/wp-config.php.bak`. Esto es **exposición histórica**, no «ataque». |
| **Common Crawl** | Corpus masivo y más reciente que Wayback; útil cuando Wayback no capturó nada o cuando se busca en varios corpus. | `https://index.commoncrawl.org/` (índice CDX de cada corpus) | El propio índice pide no sobrecargarlo. **NO VERIFICADO**: el nombre del corpus vigente cambia; hay que consultarlo en la lista de la instancia. | Segundo corte histórico; útil para saber si una ruta existió y ya no. |
| **VirusTotal** | Correlación de dominio, IP o URL con detecciones de múltiples motores; relaciones entre activos. | API v3; clave gratuita limitada. Referencia: `https://docs.virustotal.com/reference/overview` | Confirmación **secundaria**, nunca primaria. **NO VERIFICADO**: cuota y límites de tasa del plan gratuito. | Confirmar si el propio dominio o un subdominio está listado como malicioso. Útil cuando Safe Browsing marca algo. |
| **Google Safe Browsing / Transparency Report** | Si el dominio está listado por malware o phishing, y el estado del aviso de Search Console. | `https://transparencyreport.google.com/safe-browsing/search` (consulta manual). API: `https://developers.google.com/safe-browsing/v4/lookup-api` | Es una fotografía. La Lookup API exige **POST a Google** (no al cliente): no hay problema con el RoE, que prohíbe métodos con cuerpo **contra el activo**, pero conviene usar la interfaz manual. **NO VERIFICADO**: la ruta `…/search/docs/safety-reporting-in-search-console` indicada en el encargo devolvió **404** al comprobarla; debe localizarse la ruta vigente en el menú de la documentación. | Evidencia de phishing o malware detectado por Google. Alto valor de confianza para el cliente. |
| **Monitorización de CT (continua)** | La aparición de un subdominio nuevo que **el cliente no reconoce** es, en la práctica, phishing con el nombre de su marca. | Mismo endpoint de crt.sh, comparado entre dos fechas. | No distingue emisión legítima de abusiva. | Alerta de phishing de marca: `login-ejemplo.mx`, `verificacion-cuenta.mx`. Severidad ALTO si el dominio se resuelve y sirve contenido. |
| **Historial de DNS / DNS colgante** | Si un CNAME de un subdominio apunta a un servicio de terceros que **ya no existe**, el atacante puede tomar el control de ese subdominio. | `dig` actual + histórico (Censys, o el propio proveedor DNS del cliente). | El «colgante» sólo se confirma cuando el destino está realmente liberado. | Subdomain takeover → phishing con el dominio del cliente. En el caso de referencia **no se encontró ninguno** (positivo que hay que documentar). |
| **Credenciales filtradas (HIBP)** | Cuántas cuentas **del propio dominio del cliente** aparecen en filtraciones públicas. | `GET https://haveibeenpwned.com/api/v3/breachedDomain/<dominio>` con cabecera `hibp-api-key`. Referencia: `https://haveibeenpwned.com/API/v3` | **Sólo con API key de pago y con el dominio verificado** (el cliente demuestra control del dominio en su propio panel: si no, la API responde 403). Devuelve **alias**, no direcciones completas. **NO VERIFICADO**: coste y cuota del plan Core Pro. | Sólo para las cuentas del cliente, sólo si el cliente lo pide por escrito, y sólo el recuento agregado. **Nunca contra cuentas de terceros** (RoE 1.2). |

### 3.2 Cómo se usa urlscan.io como «cota inferior de intentos»

Es la fuente que más se acerca a «cuántos intentos ha habido», y por eso hay que
tratarla con cuidado:

| Lo que urlscan muestra | Lo que **significa** | Lo que **NO** significa |
|---|---|---|
| N escaneos del dominio por terceros | «Al menos N personas (o sistemas) han explorado el dominio y lo han dejado registrado.» | «N ataques» ni «N atacantes». |
| Una URL con `?id=1' OR '1'='1` | «Alguien escaneó probando inyección.» | «Alguien entró» ni «hubo exfiltración». |
| Un `wp-login.php` clonado con el logo del cliente | «Hay un phishing en marcha que usa su marca.» | «Su servidor fue comprometido.» |
| Un `admin/` con un panel distinto al real | «Alguien está buscando paneles de administración.» | «Ese panel existe en su servidor.» |

**Redacción correcta:**
> «El historial público de urlscan.io muestra **N** escaneos del dominio entre
> *fecha* y *fecha*, entre ellos **M** intentos con payloads de inyección sobre
> rutas `X` y **K** accesos a rutas de panel de administración. Esto es una
> **cota inferior observable del interés externo**, no un volumen de ataques:
> los escaneos que no se reportan no existen en este recuento.»

**Redacción prohibida:**
> «Han intentado hackear su web al menos N veces.»

### 3.3 Límites generales de todo lo pasivo

| Límite | Consecuencia para el informe |
|---|---|
| **Muestreo no aleatorio** | Los terceros escanean lo que les interesa (sitios populares, dominios confiltrados, objetivos de investigación). Un sitio de clínica pequeña puede tener **cero** escaneos registrados y eso **no** significa que nadie lo attacke. |
| **Asimetría temporal** | Los datos tienen fecha de captura distinta de la fecha de publicación. Un certificado puede llevar meses emitido. |
| **Vistas de terceros** | Los índices sondea desde IP de terceros, no desde el país del cliente: la geolocalización de la IP del auditor no dice dónde está el cliente ni dónde está su hosting (que puede estar en el extranjero — hallazgo de cumplimiento, no cosmético). |
| **Sesgo de lo visible** | Lo que se expone en CT, Wayback o urlscan es lo que un tercero **notó**. Lo que nadie notó no aparece. |
| **Dependencia de terceros** | Si crt.sh o InternetDB están caídos o requieren cuenta, ese componente queda **NO VERIFICADO**, no «0». |

---

## 4. Fuentes internas: lo que se ve con acceso del cliente (requiere autorización de logs)

### 4.1 Por qué esta sección cambia el valor del encargo

Hasta aquí, todo es observación de terceros. **Con los logs del cliente se
puede dar, por fin, un número real de ataques** — intentos de login fallidos,
IPs únicas, ratios éxito/fallo, rutas más golpeadas, correlación horaria. Es
el upgrade que convierte «te digo qué está expuesto» en «te digo qué te están
atacando y desde cuándo».

Y es también la sección donde el servicio se vuelve más caro y más útil: el
cliente tiene que entregar logs, lo cual requiere confianza, y hay que
tratarlos con cuidado porque **contienen datos personales de pacientes**.

### 4.2 Tabla de fuentes internas

| Fuente | Qué da | Granularidad | Cómo pedirlo sin asustarlo | Qué NO pedir |
|---|---|---|---|---|
| **Access log del servidor web** (Apache/nginx) | Cada petición: IP, fecha/hora, método, ruta, status, user agent, referer, bytes. | Por petición | «Nos ayuda a distinguir el tráfico real de los intentos automatizados. Nos comprometemos a entregarte un **resumen agregado**, no el log.» | El volcado completo sin procesar, con query strings, cookies y referers de pacientes. |
| **Access/error log del proxy inverso o CDN** | Lo mismo, pero antes de la caché y del WAF: es donde se ven los intentos que la CDN bloqueó. | Por petición | «Estos logs son los que muestran los ataques que nunca llegaron a tu servidor.» | Logs de otros inquilinos del hosting compartido (RoE 1.4/1.5). |
| **Logs de WAF / CDN** | Reglas disparadas, IPs bloqueadas, GeoIP, UA, y las **reglas que no dispararon**. | Por regla | «Estos logs son los que nos dicen qué patrones se están probando.» | Nada restringido; es el log que más conviene tener. |
| **Logs de autenticación de la aplicación** | Successful/failed login, usuario, IP, MFA, lockout, reset de contraseña. | Por evento | «Nos dicen si hay intentos de fuerza bruta contra las cuentas del personal.» | Volcado con contraseñas hasheadas o tokens de sesión. |
| **Logs del IdP / OIDC y MFA** | Challenges servidos, factores usados, fallos, enrolaciones, sesiones suspiciousas. | Por evento | «Es donde se ve si alguien está Trying to reuse credenciales robadas.» | Datos de autenticación de terceros (Google, Microsoft) que no pertenecen al cliente. |
| **Logs del CMS** (WordPress: `security*.log`, `wp-login.php` hits) | Intentos de login, enumeración de autores, cambios de contraseña, creación de usuarios. | Por evento | Formato estándar de WordPress; el cliente lo puede exportar en un minuto desde el hosting. | El `wp-config.php` (nunca: contiene las claves de la base de datos). |
| **Logs de firewall / IDS del hosting** | Conexiones entrantes, puertos intentados, firmas. | Por conexión | «Los que ven los intentos que ni siquiera llegaron al servidor web.» | Logs del firewall del hosting que incluyan a otros inquilinos. |
| **Honeypots** (castillos, cadenas, ficheros señuelo) | Intentos contra recursos que **sólo un bot** encontraría. | Por intento | «Si instalamos un señuelo y alguien lo toca, sabremos que hay escaneo automatizado.» | No es una petición al cliente: es una propuesta de la Fase 1/2. |
| **Error tracking** (Sentry y similares) | Excepciones, stack traces, IPs y usuarios afectados. | Por error | «Las excepciones con IP y usuario nos dicen qué rutas se están rompiendo por ataque.» | **Nunca** el `request body` ni los `headers` completos: ahí están los datos del paciente. |
| **Logs del proveedor DNS** | Cambios en registros A/AAAA/MX/TXT/NS/CNAME, y desde qué cuenta. | Por cambio | «Cada cambio de DNS es una de las tres puertas de entrada al phishing.» | Nada sensible; pero el cliente debe confirmar el historial, no lo genera el auditor. |
| **Reportes agregados de DMARC (RPT)** | Quién envía correo **usando el dominio del cliente** y si el receptor lo acepta. | Por receptor | «Estos reportes dicen si alguien está suplantando su correo y cuántos correos se Accepted.» | El contenido de los correos: sólo los conteos y las IPs de origem. |

### 4.3 Lo que se hace con los logs: agregación simple, sin inventar un dashboard

El error típico aquí es pedir un dashboard carísimo y no entregar nada. No hace
falta: cinco métricas bien calculadas sobre un fichero de texto dan el 90% del
valor, y son **reproducibles** con un comando que el cliente puede volver a
ejecutar.

**Las cinco métricas (y nada más):**

| Métrica | Definición | Para qué sirve | Campo de la agregación |
|---|---|---|---|
| **Intentos/hora** | Peticiones por hora contra rutas de autenticación o de API sensible. | Ver la ventana horaria del ataque: manual, automatizado o de rebote. | Fecha-hora de la petición. |
| **IPs únicas** | Direcciones IP distintas que intentaron autenticarse. | Distingue un atacante de un usuario que se equivoca seis veces. | IP de origen. |
| **Ratio éxito/fallo** | Autenticaciones fallidas ÷ total, y los casos en que **un fallo** terminó en **éxito**. | Detecta credential stuffing exitoso y ataques a baja tasa que sí entraron. | Resultado de la autenticación. |
| **Rutas más golpeadas** | Ranking de rutas por número de peticiones, con su status. | Señala la superficie que el atacante está explorando y la que funciona. | Ruta + status. |
| **Correlación horaria** | Volumen por franja (hora del día / día de la semana). | Distingue ruido de fonda de la mañana de ataque focalizado. | Timestamp. |

**Agregaciones de referencia (locales, sin red, sobre el log que entrega el cliente).**

```bash
# 0) Contexto del fichero: formato, tamaño y ventana temporal que cubre
wc -l evidencia/access.log
head -1 evidencia/access.log            # una línea de ejemplo -> formato (Combined?)
tail -1 evidencia/access.log            # ventana temporal real

# 1) IPs únicas en toda la ventana
awk '{print $1}' evidencia/access.log | sort -u | wc -l

# 2) Top 20 de rutas golpeadas (con su status)
awk '{print $7, $9}' evidencia/access.log | sort | uniq -c | sort -rn | head -20

# 3) Intentos por hora contra rutas de autenticación
awk '$7 ~ /wp-login\.php|\/admin\/|\/login|\/api\/v[0-9]+\/auth/ {split($4,a,":"); print a[2]}' \
    evidencia/access.log | sort | uniq -c

# 4) IPs únicas por hora en rutas de autenticación
awk '$7 ~ /wp-login\.php|\/login/ {split($4,a,":"); print $1, a[2]}' \
    evidencia/access.log | sort -u | cut -d' ' -f2 | sort | uniq -c

# 5) Ratio éxito/fallo sobre rutas de autenticación
awk '$7 ~ /wp-login\.php|\/login/ {if ($9 ~ /^(200|302)$/) ok++; else fail++}
     END {printf "ok=%d fail=%d ratio_fallo=%.2f%%\n", ok, fail, (ok+fail)?100*fail/(ok+fail):0}' \
    evidencia/access.log

# 6) Pico de 404 (patrón de bruteforce sobre rutas de administración)
awk '$9=="404" {print $7}' evidencia/access.log | sort | uniq -c | sort -rn | head -20

# 7) User agents más repetidos (identifica crawlers y scrapers)
awk -F'"' '{print $6}' evidencia/access.log | sort | uniq -c | sort -rn | head -10

# 8) Analítica de terminal si se prefiere: GoAccess (ya está en el manifiesto)
goaccess evidencia/access.log --log-format=COMBINED -o evidencia/goaccess.html
```

**Reglas al agregar:**

1. **No se entrega el log al cliente ni a terceros.** Se entrega el resumen. El
   log crudo queda en la carpeta de evidencia, con acceso restringido y
   retención definida en el RoE (§6 de la plantilla).
2. **Las IPs se pueden mantener** (`pii_redact.py --keep-ips`): no son datos
   personales en el sentido de la LFPDPPP en la práctica, pero sí son
   identificadores indirectos. Se tratan como confidenciales.
3. **El tráfico del auditor se excluye.** Si el cliente busca tus IP o tu
   User-Agent (`ClientSecurityAudit/1.0`), loExclude. Mejor: que el cliente te
   marque la ventana de auditoría en el log, o que tú filtres tu propio rango
   de IPs. Sin eso, las métricas de «intentos» están contaminadas.
4. **Una sola ventana, una sola vez.** Se agreega sobre un rango acotado (30
   días recommended) y se documenta. Recalcular con otra ventana cambia el
   número y eso invalida la comparación con el informe.
5. **El número se publica con su definición.** «1 284 intentos de
   autenticación fallidos en 30 días desde 96 IPs distintas» es un dato
   auditable. «1 284 ataques» no lo es: el mismo log también contiene las
   1 284 *peticiones correctas* de los pacientes reales.

### 4.4 Cómo pedirlo al cliente sin asustarlo

El correo (o el mensaje) que funciona:

> **Asunto: datos que nos ayudan a medir el riesgo real**
>
> Para poder decirles **cuánto** y **qué tipo** de intentos ha recibido el
> sitio, necesitamos los registros de acceso del servidor (Apache o nginx) de
> los **últimos 30 días**, en texto plano.
>
> - **Qué necesitamos:** el fichero de access log, tal cual sale del servidor.
> - **Qué NO necesitamos:** base de datos, correos de pacientes, ni acceso a
>   ninguna cuenta.
> - **Qué hace-mos con él:** agregarlo en cinco números (intentos por hora,
>   IPs distintas, ratio de éxito/fallo, rutas más golpeadas y correlación
>   horaria).
> - **Qué le entregamos a usted:** ese resumen en una página, no el log.
> - **Confidencialidad:** el log se queda en la carpeta de evidencia del
>   encargo, con acceso restringido y retención de [N] meses.
> - **Un detalle:** si nos dice las fechas y horas en que nosotros estuvimos
>   haciendo la revisión, descartamos ese tráfico de los cálculos, para que
>   nuestras propias peticiones no se cuenten como intentos.

**Y lo que NO se pide nunca:**

| No pedir | Por qué |
|---|---|
| Volcado completo de access logs con PII sin acotar | Contiene datos personales de pacientes (LFPDPPP) y una ventana indefinida; el riesgo legal del auditor supera el valor del dato. |
| `wp-config.php` | Contiene las credenciales de la base de datos. **Nunca**, ni para "verificar el hash". |
| Credenciales de acceso a WordPress, al hosting o al panel | No hacen falta para una revisión pasiva y crean una responsabilidad de custodia que no se pidió. |
| Correos de pacientes, historiales clínicos, exportaciones de la tabla de pacientes | RoE 1.2: son datos de terceros. Se reporta la existencia del endpoint y se detiene. |
| Los logs de otros inquilinos del hosting compartido | RoE 1.4/1.5: no fueron autorizados por el cliente. |
| Grabaciones de sesión (session replay) | Pueden contener lo que el paciente escribió en un formulario. Se pide el conteo, no la grabación. |

---

## 5. Indicadores de compromiso: el checklist de «ya lo tocaron»

Esta es la lista de comprobación que se recorre cuando el cliente entrega
acceso interno, o cuando una fuente externa delata algo. Cada fila dice dónde
mirar, cómo confirmar **sin causar daño** y qué severidad merece.

| # | Indicador | Dónde se busca | Cómo se confirma (sin daño) | Severidad |
|:-:|---|---|---|---|
| 1 | **Subdominio inesperado** | crt.sh, `dig`, histórico DNS | Comparar la lista de CT contra el inventario del cliente. Si el cliente no lo reconoce, es phishing o typosquatting hasta que se demuestre lo contrario. | ALTO ( phishing activo ) / MEDIO (subdominio abandonado) |
| 2 | **Ruta que no debería existir** | Sitemap, Wayback CDX, Common Crawl, urlscan | Comparar contra el sitemap y el inventario. Ejemplos: `/login-clinica`, `/recuperar-cuenta`, `/wp-content/uploads/2026/x.php`. | ALTO si sirve contenido de phishing; MEDIO si es una ruta técnica filtrada |
| 3 | **Fichero ejecutable subido** | `wp-content/uploads/`, `/media/`, cualquier directorio de subida | `find` por extensión y por fecha de modificación; comparar con el hash de un fichero equivalente del cliente. **No ejecutar el fichero.** | CRÍTICO (ejecución de código en el servidor) |
| 4 | **`wp-config.php` modificado** | Fichero de configuración de WordPress | Comparar `sha256` con la copia de referencia del cliente o con el backup de la semana anterior. Diferencia = cambio no explicado. | ALTO (o CRÍTICO si además se añadió un usuario) |
| 5 | **Ficheros por defecto de WordPress presentes o ausentes** | Raíz del sitio | `readme.html` / `license.txt` / `wp-admin/install.php` presentes = instalación reciente o desatendida; **ausentes** = alguien los borró (o es una instalación endurecida: hay que distinguir). | MEDIO / INFO según el caso |
| 6 | **Pico de 404 en rutas de administración** | Access log, WAF | Pico de 404 sobre `/wp-admin`, `/administrator`, `/phpmyadmin` con IP rotando = bruteforce de rutas. | MEDIO (patrón) — sube a ALTO si hay algún 200 |
| 7 | **`.htaccess` defensivo inesperado** | `wp-content/uploads/.htaccess` | Un `.htaccess` que bloquea la ejecución de PHP en el directorio de subidas es la **contramedida** del ransomware: si existe y el directorio sigue con `.php`, el ataque ya pasó. | INFO como positivo; ALTO si hay `.php` coexistiendo |
| 8 | **Cron jobs nuevos** | `crontab`, wp-cron, panel de hosting | Comparar contra la lista de tareas que el cliente reconoce. | ALTO (persistencia) |
| 9 | **Usuarios nuevos en WordPress** | `wp-json/wp/v2/users` (sin autenticación), o export del panel | Comparar contra la lista de personal. El rol importa: un `administrator` no reconocido es CRÍTICO. | ALTO / CRÍTICO según rol |
| 10 | **Claves de API rotadas sin explicación** | Inventario del cliente vs. estado actual | El cliente debería tener inventario de credenciales. Una rotación sin causa registrada = o negligencia o alguien entró. | ALTO |
| 11 | **Notas de ransomware** | Extensiones habituales de nota, en la raíz y en directorios de datos | Buscar por nombre; **no abrir el contenido más allá de lo necesario**, y no negociar ni contactar al atacante. | CRÍTICO |
| 12 | **Cambios en DNS (MX/TXT)** | Histórico DNS, panel del proveedor | Un cambio de MX o un TXT nuevo = suplantación de correo o exfiltración de datos por DNS. | ALTO / CRÍTICO |
| 13 | **Correo saliente en nombre del dominio** | DMARC aggregate reports (RPT) | El reporte dice quién envía y si el receptor lo aceptó. Aceptado = suplantación efectiva. | ALTO |
| 14 | **Repositorio `.git` publicado** | `/.git/HEAD`, `/.git/config` | Si responde 200, es exposición de código y de secretos (no compromiso). Se reporta como exposición y se recommends removing + **rotar todo secreto del repo**. | MEDIO (exposición) / ALTO si hay secretos en el histórico |
| 15 | **Backups o volcados de base de datos accesibles** | `/backup.zip`, `/db.sql`, `/dump.sql` | Verificar la respuesta sin descargar el cuerpo: status, tipo MIME y longitud bastan. Si contiene datos de pacientes, la severidad es CRÍTICA. | CRÍTICO |
| 16 | **Archivos de configuración de framework expuestos** | `/.env`, `/actuator/env`, `/config.json`, `/web.config` | Igual: status y tipo. `.env` con claves de BD = CRÍTICO. | CRÍTICO |
| 17 | **Servidor de métricas o monitorización público** | `/metrics`, `/actuator/health`, `/server-status` | Si expone `/metrics` con labels que contienen rutas internas o nombres de usuario: fuga de topología. | MEDIO |
| 18 | **Archivos subidos por terceros** (histórico) | urlscan.io, Wayback | Ficheros con nombres de plantilla de phishing o con el logo del cliente en `uploads`. | ALTO |

### 5.1 Cómo se calibra la severidad de un IoC

La misma doctrina que en `como-presentar-resultados.md`: **la severidad viene
del contenido, no del tipo**.

- Un `.env` encontrado en una landing que no tiene datos de pacientes: ALTO.
- El mismo `.env` en una clínica con tabla de pacientes: CRÍTICO, porque la
  consecuencia legal es directa.
- Un subdominio no reconocido: ALTO si resuelve y sirve contenido; INFO si es un
  nombre histórico sin resolver.
- **Un IoC no confirmado por el cliente se reporta como «indicador pendiente de
  confirmación», no como hallazgo cerrado.** La confirmación la hace el cliente
  en 60 segundos: es el ticket más corto y más rentable de todo el informe.

### 5.2 La frase de cierre obligatoria para la sección de IoC

> «En la superficie revisada, hasta la fecha de cierre, **no** se identificaron
> indicadores de compromiso. Este resultado **no** equivale a «no hubo
> incidentes»: elude a intrusiones que no dejan rastro público y a toda la
> actividad dentro de la red del cliente. Con los logs de las §4, esta misma
> sección se convierte en una verificación con fecha y número.»

---

## 6. El «Attack Exposure Score»: cómo convertir esto en un número vendible sin inventar

### 6.1 Qué es y qué no es

| | |
|---|---|
| **Nombre** | **Attack Exposure Score** (índice de exposición a ataques) |
| **Script que lo calcula** | `01-tooling/scripts/attack_surface_report.py` |
| **Qué hace** | Agrega la **evidencia local ya recogida** y produce un índice 0-100 con cinco bandas. **No hace ninguna llamada de red.** |
| **Qué NO es** | No es un número de ataques. No es un CVSS. No es una probabilidad de compromiso. No es comparable entre clientes con distinta cobertura de evidencia. |
| **Salida** | `attack_surface_report.md` + `attack_surface_report.json` ( `--out DIR` ), o JSON por pantalla ( `--json` ). |

### 6.2 La fórmula (tal como está implementada)

```
total = min(100, max(0, Σ riesgo − Σ bonificación))
```

| Magnitud | Valor | Nota |
|---|---|---|
| `risk_points` | Σ de los 13 componentes de riesgo | Tope de 120 puntos brutos. |
| `risk_max` | 120 | **Informativo**: no entra en el cálculo del total. Se reporta en la fórmula. |
| `bonus_points` | Σ de los 6 componentes de bonificación (valores negativos) | Tope duro: `MAX_BONUS = 30`. |
| `total` | `min(100, max(0, risk − bonus))` | Recortado a [0, 100]. |

**Dos propiedades que hay que conocer y que se deben decir al cliente si pregunta:**

- **El índice tiene techo y suelo.** Un sitio catastrófico no puede pasar de
  100 (la bonificación no puede «rescatarlo» más de 30 puntos), y un sitio
  excelente puede llegar a 0.
- **El índice no está normalizado por la cobertura de evidencia.** El máximo
  de riesgo (120) es constante, pero cada componente sin evidencia vale 0. Un
  cliente auditado con 8 ficheros de evidencia tiene más componentes que pueden
  disparar que uno auditado con 2. **Por eso dos puntuaciones de clientes
  distintos no son comparables entre sí** salvo que la cobertura de evidencia
  sea equivalente. Se resuelve publicando siempre la tabla de cobertura.

### 6.3 Los 13 componentes de riesgo y sus pesos reales

| # | Componente (`key`) | Máx | Cómo se calcula (código) | Evidencia que lo activa |
|:-:|---|:-:|---|---|
| 1 | Secretos expuestos (`secretos_expuestos`) | **18** | Σ por hallazgo: `critico` 6 · `alto` 4 · `medio` 2 · `bajo` 1 · `info` 0. Tope 18. | `secrets.json` |
| 2 | Ficheros de backup o configuración expuestos (`ficheros_expuestos`) | **16** | Σ por fila del TSV con `verdict = expuesto`: `critico` 5 · `alto` 4 · `medio` 2 · `bajo` 1 · `info` 0. Tope 16. Los `soft_404` no cuentan. | `probe_exposure.tsv` |
| 3 | Versiones de stack potencialmente desactualizadas (`versiones_stack`) | **12** | Σ por valor de cabecera distinto (`server`, `x-powered-by`, `x-aspnet-version`): nginx <1.20→6, <1.24→4, <1.26→2 · php <8.1→5, <8.3→3 · apache <2.4.49→5, <2.4.58→3 · iis <10→4 · base 1. Tope 12. | `headers.txt` |
| 4 | Sin CDN/WAF detectable (`ausencia_waf_cdn`) | **8** | 0 si hay cabecera de CDN/WAF (`cf-ray`, `x-vercel-id`, …) o `server` contiene `cloudflare`/`akamai`/`varnish`/`fastly`; 8 si hay respuestas y ninguna de esas firmas. | `headers.txt` |
| 5 | Amplitud de la superficie de subdominios (`superficie_subdominios`) | **10** | Nº de nombres distintos en los certificados CT: >30→10 · >10→6 · >3→3 · resto→1. | `crt.json` |
| 6 | Puertos administrativos expuestos (`puertos_administrativos`) | **8** | `min(8, puertos_administrativos × 2 + CVEs indexados × 2)`. | `internetdb.json` |
| 7 | Ausencia de MFA en la superficie de login (`ausencia_mfa`) | **8** | 8 si hay rutas de login en el TSV de sonda y ningún indicio de MFA en sonda ni en `js_intel`; 0 si hay indicio. **Deducido, no verificado.** | `probe_exposure.tsv` + `js_intel.json` |
| 8 | Ausencia de logging o monitorización detectable (`ausencia_logging_monitoring`) | **6** | 6 si hay evidencia de aplicación (sonda, secretos o JS) y ningún indicio de monitorización. | sonda + secretos + JS |
| 9 | Ausencia de DMARC (`ausencia_dmarc`) | **6** | 6 si la sección DMARC del fichero de DNS no contiene `v=DMARC1`; 0 si lo contiene. | `dns_mailsec.txt` |
| 10 | Ausencia de CSP y HSTS (`ausencia_csp_hsts`) | **8** | `min(8, 4 × nº de ausentes entre {CSP, HSTS})`. | `headers.txt` |
| 11 | CORS permisivo (`cors_inseguro`) | **6** | `ACAO: *` con credenciales→6 · `ACAO: null`→4 · `ACAO: *`→3 · origen específico sin `Vary: Origin`→2. | `headers.txt` |
| 12 | Versiones de TLS obsoletas admitidas (`tls_debil`) | **8** | 8 si admite 1.0/1.1 o ninguna moderna; 3 si sólo 1.2; 0 si 1.2 y 1.3. | `tls_versions.txt` |
| 13 | Cookies sin los atributos de seguridad (`cookies_inseguras`) | **6** | `min(6, 2 × nº de cookies sin `Secure`/`HttpOnly`/`SameSite`)`. | `headers.txt` |
| | **Suma de máximos** | **120** | | |

### 6.4 La bonificación por lo que está bien (obligatoria)

> **«Lo que ya está bien» no es cortesía: es requisito metodológico**
> (`como-presentar-resultados.md` §4). El índice lo implementa con una
> bonificación explícita, con su propio tope de 30 puntos.

| Componente (`key`) | Máx | Cómo se calcula | Condición para concederla |
|---|:-:|---|---|
| Cookies con `Secure` + `HttpOnly` + `SameSite` (`cookies_seguras`) | **8** | `−round(8 × (cookies bien configuradas / total de cookies))` | Que haya al menos una cookie en la evidencia |
| TLS 1.3 sin versiones legacy (`tls_fuerte`) | **6** | −6 si hay 1.3 y no hay 1.0/1.1; −3 si sólo 1.2 sin legacy | Datos de versiones TLS |
| SRI en scripts externos (`sri_presente`) | **4** | `−round(4 × (scripts con `integrity` / scripts externos))` | Que haya scripts externos en `js_intel` |
| Cabeceras de seguridad completas (`cabeceras_completas`) | **8** | `−round(8 × (cabeceras base presentes / (8 × nº de respuestas)))`. Las 8 base: CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP | Que haya respuestas con cabeceras |
| DMARC con política activa (`dmarc_presente`) | **4** | −4 si `p=reject` · −3 si `p=quarantine` · −1 si `p=none` | Registro DMARC publicado |
| Sin secretos críticos en el código (`sin_secretos_criticos`) | **4** | −4 si hay ≥1 hallazgo en el JSON y ninguno es `critico` | Que el JSON de secretos tenga hallazgos |
| | **34** | **Tope efectivo del script: `MAX_BONUS = 30`** | |

### 6.5 Las cinco bandas

| Banda | Rango | Qué significa en la conversación con el cliente | Qué hacer |
|---|---|---|---|
| **Bajo** | 0 – 19.9 | «La puerta está bien cerrada en lo que se puede ver desde fuera.» | Plan de mantenimiento + verificar lo que no se pudo ver. |
| **Moderado** | 20 – 39.9 | «Hay puertas abiertas y ninguna es urgente, pero se acumulan.» | Ola 2 del roadmap: endurecimiento. |
| **Alto** | 40 – 59.9 | «Hay superficies que un atacante puede usar sin autenticación.» | Ola 1 + Ola 2. Revisión de credenciales y MFA ya. |
| **Crítico** | 60 – 79.9 | «Hay exposición directa de credenciales o de datos.» | Ola 1 inmediata. Rotación de secretos y de claves. |
| **Severo** | 80 – 100 | «Varios puntos de entrada críticos a la vez.» | Contención y remediación inmediata; es una emergencia de seguridad. |

> ⚠️ **Una advertencia sobre las bandas que hay que conocer antes de publicar.**
> La etiqueta de banda se calcula **a partir del número**, y el número es 0
> cuando no hay evidencia. Ejecutado sin ningún fichero de entrada, el script
> imprime `banda **Bajo**` con `evaluable: false` y añade el aviso
> «⚠ No hay evidencia. Un 0 aquí **no** significa «seguro»». Es decir: **la
> etiqueta sola no protege de una mala lectura.**
> **Regla operativa:** antes de citar una banda, comprueba `evaluable` en el
> JSON (o la presencia del aviso ⚠ en el Markdown). Si `evaluable` es `false`,
> en el informe se escribe **«No evaluable»**, nunca «Bajo».

### 6.6 Tres ejemplos de cálculo (datos **ficticios**, verificados ejecutando el script)

> **Los tres ejemplos usan datos inventados y etiquetados como tales.** Se
> ejecutaron con el script real del playbook para comprobar la aritmética; los
> dominios son de reserva y no corresponden a ningún cliente.

#### Ejemplo A — «Consultorio Dental Norte» — **51/100 · banda Alto**

Evidencia de entrada (ficticia):

| Fichero | Contenido relevante |
|---|---|
| `probe_exposure.tsv` | 5 rutas sondadas: `/.git/HEAD` expuesta (crítico), `/swagger.json` expuesta (medio), `/wp-admin/` no expuesta, `/.env` no expuesta, `/api/v1/` no expuesta |
| `secrets.json` | 1 hallazgo `medio` (API key de Google en JS) |
| `headers.txt` | `server: nginx/1.18.0`, `x-powered-by: PHP/8.0.30`, HSTS sí, CSP no, 2 cookies sin atributos, 3 de las 8 cabeceras base |
| `internetdb.json` | puertos `[80, 443, 3306, 8080]`, 0 CVEs |
| `crt.json` | 12 nombres distintos |
| `dns_mailsec.txt` | sección `=== DMARC ===` sin `v=DMARC1` |
| `tls_versions.txt` | 1.2 y 1.3, sin legacy |
| `js_intel.json` | 2 scripts externos, 1 con SRI |

| Componente | Puntos |
|---|---:|
| Secretos expuestos | +2.0 |
| Ficheros de backup/config expuestos | +7.0 |
| Versiones de stack | +11.0 |
| Sin CDN/WAF detectable | +8.0 |
| Superficie de subdominios | +6.0 |
| Puertos administrativos | +4.0 |
| Ausencia de MFA | +8.0 |
| Ausencia de logging/monitorización | +6.0 |
| Ausencia de DMARC | +6.0 |
| Ausencia de CSP/HSTS | +4.0 |
| CORS permisivo | +0.0 |
| TLS obsoleto | +0.0 |
| Cookies inseguras | +4.0 |
| **Σ riesgo** | **66.0** |
| Bonificación (TLS −6, SRI −2, cabeceras −3, sin secretos críticos −4) | **−15.0** |
| **Total** | **51.0 → banda «Alto»** |

#### Ejemplo B — «Clínica Vida Integral» — **100/100 · banda Severo**

Evidencia de entrada (ficticia): `/.env`, `/db.sql`, `/.git/HEAD` y
`/wp-config.php.bak` expuestas (todas `crítico`); `/graphql` y `/api/v1/`
expuestas; secretos: 1 `crítico` + 1 `alto` + 1 `medio`; `nginx/1.22.1` +
`PHP/7.4.33`; sin CDN; sin CSP ni HSTS; `ACAO: *` **con credenciales**; 2
cookies sin atributos; 13 puertos con 11 administrativos y 3 CVEs indexados;
34 nombres en CT; DMARC ausente; TLS 1.0 y 1.1 aceptadas; 3 scripts externos
sin SRI.

| Bloque | Resultado |
|---|---|
| Σ riesgo | **109.0** |
| Σ bonificación | **0.0** (nada que bonificar: cookies sin atributos, TLS legacy, sin SRI, 0 de 8 cabeceras, sin DMARC, hay un secreto crítico) |
| Bruto | 109.0 → **recortado a 100.0** |
| **Total** | **100.0 → banda «Severo»** |

#### Ejemplo C — «Centro Médico Aurora» — **0/100 · banda Bajo**

Evidencia de entrada (ficticia): ninguna ruta expuesta (`.env` 404, `wp-admin/`
redirige, `/metrics` 403); 1 secreto de severidad `bajo`; `server: cloudflare`
con `PHP/8.3.12`; las **8** cabeceras base presentes; 3 cookies con
`Secure`+`HttpOnly`+`SameSite`; CORS con origen específico y `Vary: Origin`;
sólo 80/443 publicados; 4 nombres en CT; DMARC `p=reject`; TLS 1.2 + 1.3; 2
scripts externos con SRI; la superficie de login muestra indicios de MFA.

| Bloque | Resultado |
|---|---|
| Σ riesgo | **6.0** (1 secreto bajo + 2 de antigüedad de stack + 3 de amplitud de subdominios) |
| Σ bonificación | −34.0 teórica → **−30.0** por el tope `MAX_BONUS` |
| Bruto | **−24.0** → recortado a **0.0** |
| **Total** | **0.0 → banda «Bajo»** |

> **Qué hay que leer en el ejemplo C:** un 0 **con evidencia completa** (o sea,
> `evaluable: true` y las 8 entradas presentes) es un resultado real y positivo.
> Un 0 **sin evidencia** no es nada. Los dos ceros se ven idénticos en la
> cifra y son opposites en el significado. Por eso el informe publica siempre
> la tabla de cobertura de evidencia que el script genera.

### 6.7 El comportamiento real del script (observado al ejecutarlo)

Documentado tal cual, sin maquillar, porque el que va a publicar el informe
necesita saberlo:

| Comportamiento | Detalle |
|---|---|
| **Sin evidencia** | `score = 0.0`, `band = "Bajo"`, `evaluable = false`, y el Markdown lleva el aviso «⚠ No hay evidencia…». El total no es un dato. |
| **Componente DMARC duplicado** | Cuando la evidencia contiene `v=DMARC1`, el componente `ausencia_dmarc` se añade **dos veces** a la lista (se anexa dentro del bloque `if dmarc_present` y otra vez al final). Efecto: `risk_max` se reporta como **126** en lugar de 120 y la fila aparece duplicada en la tabla. **El total no se ve afectado** (el duplicado puntúa 0), pero el «máx» que se publica no es 120. |
| **JSON de secretos vacío** | Un `secrets.json` con `[]` se trata como **«sin datos»**: no hay bonificación «sin secretos críticos» y el componente de riesgo queda sin fuente. Para que la bonificación se conceda hace falta al menos un hallazgo de severidad distinta de `critico`. |
| **Stack moderno** | Un producto sin versión (p. ej. `server: cloudflare`) o con versión reciente recibe la **puntuación base de 1 punto** por producto. Un stack al día nunca puntúa 0 en ese componente. |
| **Riesgo máximo real** | 120 puntos si no hay `v=DMARC1` en la evidencia; 126 si lo hay (por el duplicado). |
| **Puntos base de antigüedad** | El componente de versiones puntúa por **antigüedad**, no por CVE verificado. Hay que contrastarlo contra el NVD y contra la versión real del servidor (lección (a) del ciclo). |

### 6.8 Por qué este índice **no** es un CVSS

| | CVSS | Attack Exposure Score |
|---|---|---|
| **Qué mide** | La severidad técnica de *una* vulnerabilidad: vector de ataque, privilegios, interacción, alcance, impacto en C/I/A. | El **estado de la superficie** de un activo: qué está expuesto y qué defensas faltan. |
| **Unidad** | Una vulnerabilidad. | Un activo completo. |
| **Datos que exige** | Pruebas de alcanzabilidad de la vulnerabilidad concreta. | Evidencia local agregada; ninguna prueba de explotación. |
| **Qué significa un 8.8** | «Esta vulnerabilidad, si se explota, es grave.» | — |
| **Qué significa un 51** | — | «Este activo tiene Superficie expuesta, sin CDN, sin MFA deducida, sin DMARC, sin logging visible, con 2 rutas y 1 secreto expuestos.» |
| **Comparabilidad** | Comparable entre vulnerabilidades (misma métrica). | **No comparable entre clientes** con distinta cobertura de evidencia. |
| **Utilidad para el dueño** | Ninguna sin traducción. | Directa: es el número que se pone en la primera página del teaser, **con su desglose debajo**. |

El CVSS responde «¿qué tan grave es este fallo?». Este índice responde «¿qué
tan expuesta está esta puerta y qué tan bien cerrada está la casa?». Son
preguntas distintas y se responden con escalas distintas. **Meter un CVSS en un
informe comercial de una clínica es ruido; meter este índice con su desglose
es una decisión de cliente.**

### 6.9 Cómo se comunica el número (plantilla literal)

> **Índice de Exposición a Ataques: 51/100 — banda «Alto».**
> Calculado el *fecha* a partir de 8 ficheros de evidencia (sonda, secretos,
> cabeceras, InternetDB, CT, DNS, TLS, JS). No es un número de ataques: es una
> medida de **cuánta superficie está abierta y qué defensas faltan**.
> Desglose: 6 componentes bonificados por lo que ya está bien (TLS 1.3,
> SRI parcial, 3 de 8 cabeceras base, HSTS presente, sin secretos críticos)
> frente a 8 componentes penalizados (rutas y un secreto expuestos, stack
> antiguo, sin CDN, sin MFA deducida, sin DMARC, sin monitorización visible).
> El detalle componente a componente, con su fichero de evidencia, está en el
> anexo técnico.

### 6.10 Reglas de uso del índice (no negociables)

1. **Se publica con su desglose.** Un número sin desglose es marketing.
2. **Se publica con su cobertura.** La tabla `coverage` del JSON es obligatoria
   en el anexo.
3. **Se publica con su fecha.** Es una fotografía.
4. **No se compara entre clientes** sin cobertura equivalente.
5. **No se llama «nivel de riesgo»** sin decir que es exposición. Se llama
   **índice de exposición a ataques**.
6. **No sustituye al juicio profesional.** El propio script lo dice en su
   pie: «Este índice no sustituye al juicio profesional del auditor».
7. **Nunca se inventa un componente.** Si no hay evidencia, 0 y «sin datos».
8. **El 0 sin evidencia no se publica como 0.** Se publica como «No
   evaluable».

---

## 7. Lo que NO puedes ver

Lista explícita. Esta sección es la que evita el sobre-compromiso y es la que
sostiene la honestidad del informe.

| Lo que no se puede saber desde fuera | Por qué no se puede | Cómo se redacta en el informe |
|---|---|---|
| **El volumen real de intentos de ataque** | Requiere los logs del defensor. | «No es medible desde fuera. Con acceso a logs, sí (ver §4).» |
| **Si algún dato fue exfiltrado** | No hay ninguna señal pública de una descarga masiva si la ruta ya era pública. | «Fuera de alcance: no se puede determinar si hubo descarga de datos. Se revisó la existencia de rutas exposed y su contenido no se descargó.» |
| **Qué pasó dentro de la red del cliente** | La red interna no es visible desde internet y su análisis es otro encargo. | «Fuera de alcance: el interior de la red, los sistemas internos y la segmentación.» |
| **Ataques sin huella** | Los intentos que no modifican nada y que nadie reporta a un índice público. | «El recuento de ataques sin huella es siempre desconocido; no se afirma ninguno.» |
| **Uso de credenciales robadas** | El uso de una credencial válida en otro servicio no aparece en los logs del cliente (aparece en el servicio ajeno). | «Fuera de alcance. Si el cliente tiene cuenta en un tercero, es un encargo de due diligence con ese proveedor.» |
| **Quién es el atacante** | No se puede atribuir sin evidencia forense, y atribuir es un riesgo legal y reputacional. | «No se atribuye autoría. Se describen patrones.» |
| **El estado interno del panel de administración** | Requiere autenticarse. | «Fuera de alcance: nunca se autentica. La ausencia de MFA es *deducida*, no verificada.» |
| **Los logs que el cliente no tiene** | Si el servidor no registra, no hay registro. | «No hay logging de aplicación: la ausencia de trazabilidad es en sí misma un hallazgo (componente 8 del índice).» |
| **La postura de la red del hosting o de los proveedores** | Auditoría de terceros. | «Fuera de alcance: se reportan relaciones y riesgos, no se sondea la infraestructura de terceros.» |
| **El contenido de los datos de pacientes** | Datos de terceros (RoE 1.2). | «Se documenta la existencia y el esquema; no se descargan registros.» |

### 7.1 La redacción correcta: «fuera de alcance», nunca «no pasa nada»

| ❌ Prohibido | ✅ Correcto |
|---|---|
| «No se han producido ataques.» | «El volumen de ataques no es observable desde fuera. Fuera de alcance.» |
| «No hubo ningún incidente.» | «No se identificaron indicadores observables desde fuera hasta la fecha. No es prueba de ausencia.» |
| «El sitio es seguro.» | «La superficie pública revisada no presenta hallazgos críticos. Lo no revisado está enumerado.» |
| «No hay datos de pacientes expuestos.» | «No se identificaron rutas que devuelvan datos de pacientes. Las rutas existentes se documentaron sin descargar su contenido.» |
| «Su web no fue hackeada.» | «No hay evidencia de compromiso en la superficie pública revisada. La confirmación definitiva requiere los logs de la §4.» |

La diferencia entre las dos columnas no es de estilo: la columna de la derecha
es **verificable por un tercero** con la evidencia que se entrega; la de la
izquierda no es verificable por nadie y por eso es irresponsable.

---

## 8. Cómo presentarlo al dueño no técnico

### 8.1 El guion de tres frases

La pregunta del cliente se responde en tres frases, en este orden. Ni uno más.

> **1. «Esto es tu puerta.»**
> «Desde el internet se ven [N] entradas a tu sitio: [X] páginas internas que
> no deberían estar abiertas, [Y] subdominios y [Z] puertos de administración
> publicados. Cualquiera que te quiera atacar puede encontrar esas entradas sin
> ayuda; no hace falta ser un genio, sólo tener tiempo.»
>
> **2. «Esto es lo que ya entró.»**
> «Revisamos las señales públicas de que alguien ya haya tocado o imitado tu
> sitio: [ejemplos concretos]. [Resultado: no encontramos señales / sí
> encontramos X]. Y revisamos lo que el sistema te puede contar por dentro:
> [lo que nos dieron / lo que no nos dieron].»
>
> **3. «Esto es lo que no puedo ver.»**
> «Cuántos intentos de ataque ha recibido tu página no se puede saber desde
> afuera. Ese número está en los registros del servidor, y con ellos te lo
> damos en 48 horas. Lo que sí puedo asegurarte hoy es que la puerta está
> [estado], y que [acción concreta].»

### 8.2 Ejemplo de párrafo en lenguaje llano (para el brief del dueño)

> Revisamos su sitio por fuera, sin tocarlo y sin hacer nada que pueda
> dañarlo. Lo que encontramos es que hay [6] rutas internas accesibles que
> no deberían estarlo, una carpeta de configuración que un visitante
> podría descargarse, y [2] puertos de administración del servidor
> publicados en internet. Eso no significa que su sitio haya sido hackeado:
> significa que **las puertas están abiertas y se sabría entrar por
> ellas**. Por otra parte, no encontramos señales de que alguien haya
> entrado ya — ni en el sitio, ni con un phishing usando su nombre, ni
> correos falsos enviados en nombre de la clínica. Lo que **no** podemos
> saber desde afuera es cuántos intentos de ataque ha recibido el sitio:
> ese dato vive en el registro de su servidor y lo podemos sacar en un día
> si nos lo comparten. Con lo que sí sabemos, la recomendación es [acción
> 1: rotar la clave de la base de datos que estaba publicada] y [acción 2:
> activar el segundo factor de verificación en el panel] — las dos cuestan
> menos de una hora de trabajo.

### 8.3 Ejemplo de párrafo para el equipo técnico

> El `Attack Exposure Score` de este activo es **51/100 (banda «Alto»)**
> sobre 8 ficheros de evidencia (sonda, secretos, cabeceras, InternetDB, CT,
> DNS, TLS, JS). El desglose está en el anexo: los puntos positivos son
> 2 rutas y 1 secreto expuestos, versiones de nginx/PHP por debajo de la
> última rama estable, ausencia de CDN/WAF detectable, ausencia de MFA
> **deducida** (no verificada — confirmar), ausencia de DMARC, ausencia de
> monitorización visible y ausencia de CSP. Los puntos negativos son TLS
> 1.3 disponible, SRI en 1 de 2 scripts, 3 de 8 cabeceras base presentes,
> HSTS activo y ningún secreto crítico. La exposición **histórica** incluye
> [rutas que constan en Wayback] y la **cota inferior de interés externo**
> observable en urlscan es de [N] escaneos en la ventana revisada. Lo que
> **no** afirmamos: volumen de ataques, exfiltración y estado interno; para
> esos hace falta el access log (solicitado) y el log de autenticación.

### 8.4 Tres frases que no hay que decir nunca

| No decir | Por qué | En su lugar |
|---|---|---|
| «Su sitio ha sido atacado [N] veces.» | No es medible desde fuera. | «El registro del servidor muestra [N] intentos…» (o «no es medible desde fuera»). |
| «Estamos 100 % seguros.» | Ninguna auditoría lo está. | «La superficie pública revisada no tiene hallazgos críticos.» |
| «Si lo hackearan, pasarían esto.» | Promete una capacidad no probada. | «La puerta [X] está expuesta: [qué se vería]. No se explotó.» |

---

## 9. Cómo se usa esto comercialmente

### 9.1 Encaje con los paquetes

| Paquete | Qué entrega este documento | Lo que el cliente se lleva |
|---|---|---|
| **Recon pasivo** | Toda la §3: la superficie completa, sin tocar el activo. El índice como línea de base y su desglose. | «Esto es lo que el mundo puede ver de tu sitio.» Mapa de subdominios, puertos, rutas, cabeceras, DNS. |
| **Fase 1 — Revisión completa** | §3 + §4 + §5 + §6 con la cobertura de evidencia completa. | Los mismos números **con el interior**: el volumen real de intentos, los IoC, y el índice con todos los componentes evaluables. |
| **Fase 2 — Validación de impacto** | La §6 y la §5 como línea de base contra la que se demuestra el impacto. | «Los hallazgos de la Fase 1 son reales y aquí está el impacto medido.» |

### 9.2 El argumento de venta honesto

> **El auditor externo no necesita «hackearte» para saber que estás expuesto.**
> Y eso es exactamente lo que el cliente está pagando: **no** necesita abrir un
> boquete en su sitio para enterarse de que tiene la puerta abierta. La Fase 2
> existe para **probar el impacto de los hallazgos de la Fase 1**, no para
> buscar vulnerabilidades nuevas.

Tres argumentos que se sostienen delante de un dueño de clínica:

1. **Es más barato conocer la puerta que reconstruir la casa.** Una Fase 1
   entrega el 90 % del valor de la Fase 2 sin tocar el activo: la lista de
   puertas, su criticidad y el orden de arreglo. La Fase 2 sólo tiene sentido
   sobre esa lista.
2. **Evita el daño.** Un pentest mal hecho en una web de pacientes puede
   tumbar el portal de citas, disparar correos de verdad a los pacientes o
   escribir datos en un sistema de terceros. Una revisión pasiva no puede
   hacer ninguna de las tres cosas: el RoE lo prohíbe explícitamente y el
   cliente lo firma.
3. **El número que el dueño entiende se produce en la Fase 1.** La superficie
   expuesta, el índice 0-100 y el «esto ya lo tocaron» son entregables de la
   Fase 1. El volumen de ataques es un upgrade de la Fase 1 con logs, no un
   premio reservado a la Fase 2.

### 9.3 Cómo se evita la sobreventa

| Trampa | Cómo se evita |
|---|---|
| «Te digo cuántos ataques han recibido.» | No. Se dice: superficie + IoC + cota inferior + (con logs) volumen real. |
| «Somos una prueba de penetración.» | No. Se dice: revisión de seguridad pasiva y autorizada. La propia propuesta comercial lo exige (§3 de la plantilla de propuesta). |
| «Con este score estás en riesgo X.» | Se dice: «El índice mide exposición, no probabilidad de incidente.» |
| Vender la Fase 2 como «el paso siguiente obligatorio». | Se vende como opcional y justificado por impacto: sólo tiene sentido si hay hallazgos con impacto que demostrar. |
| Comparar el score de un cliente con el de otro. | No es comparable sin cobertura equivalente. La comparación honesta es cliente contra **su propia** línea de base tras remediar. |

### 9.4 Nota de licencia para el uso comercial de las fuentes

- **Shodan InternetDB** declara en su propia documentación que es **gratuito
  para uso no comercial** y que el uso comercial requiere licencia
  empresarial. Verificado en `https://internetdb.shodan.io/` el 2026-11-21.
  **Antes de usar InternetDB en un encargo de pago hay que confirmar las
  condiciones vigentes** (o usar la API de pago de Shodan, o la alternativa
  comercial que corresponda). **NO VERIFICADO**: la redacción exacta y vigente
  de los términos en la fecha de cada encargo.
- **ipinfo.io**, **InternetDB** y **Censys** publican sus datos bajo licencias
  con atribución y, en algunos casos, *share-alike*. Al pegar datos
  textuales en un entregable hay que **citar la fuente y parafrasear**
  cuando se pueda (`manifiesto-de-herramientas.md` §6).
- **Common Crawl** pide expresamente no sobrecargar su índice: las consultas
  automatizadas deben espaciarse y limitarse.
- **HIBP** y **urlscan.io** requieren cuenta de pago o API key: su coste es
  parte del coste del paquete y debe estar previsto en la propuesta.

---

## 10. Checklist de datos

Lista para la reunión de alcance. Formato pensado para que el cliente lo
complete marcando. **Se entrega marcada: «Sí / No / Se puede conseguir en 48 h
/ No existe».**

### 10.1 Bloque A — Lo que ya está disponible (para el recon pasivo)

| # | Dato | ¿Lo tiene? | Notas |
|:-:|---|---|---|
| A1 | Dominio raíz y **lista de subdominios que el cliente reconoce** | ☐ Sí ☐ No | Sin esta lista, cualquier subdominio es «desconocido» y el IoC #1 no se puede calibrar. |
| A2 | IPs / CNAME de cada subdominio | ☐ Sí ☐ No | |
| A3 | Proveedor de hosting y de DNS (nombres, no credenciales) | ☐ Sí ☐ No | Para atribuir la infraestructura y preparar las escalaciones. |
| A4 | **Proveedor de correo** (Google Workspace, Microsoft 365, otro) y si hay **DMARC aggregate reports** | ☐ Sí ☐ No | Los RPT son el indicador #13. |
| A5 | Contacto técnico que puede escalar a hosting y agencia | ☐ Sí ☐ No | El caso de referencia: el 80 % del riesgo no estaba en el cliente. |
| A6 | Plataforma y stack (WordPress, otro), versiones aproximadas | ☐ Sí ☐ No | Para contrastar con lo que se ve desde fuera. |
| A7 | ¿Existe inventario de credenciales y claves (rotaciones)? | ☐ Sí ☐ No | Sin inventario, el IoC #10 no se puede confirmar. |

### 10.2 Bloque B — Lo que abre la puerta al bloque de logs (Fase 1 ampliada)

> **Se pide sólo lo marcado. Cada línea lleva su motivo; el cliente decide.**

| # | Dato | ¿Lo puede compartir? | Motivo de la petición |
|:-:|---|---|---|
| B1 | **Access log del servidor web** (Apache/nginx), **últimos 30 días**, texto plano | ☐ Sí ☐ No | Es lo único que convierte «superficie» en «volumen real de intentos». |
| B2 | Access log del **proxy inverso / CDN** (mismo periodo) | ☐ Sí ☐ No | Muestra los intentos que la CDN bloqueó antes de llegar al origen. |
| B3 | Logs del **WAF** (mismo periodo) | ☐ Sí ☐ No | Patrones de ataque y reglas disparadas. |
| B4 | Logs de **autenticación de la aplicación** | ☐ Sí ☐ No | Fuerza bruta y credential stuffing con éxito. |
| B5 | Logs del **IdP/OIDC y MFA** | ☐ Sí ☐ No | Reutilización de credenciales robadas. |
| B6 | Logs del **CMS** (WordPress: `security*.log`) | ☐ Sí ☐ No | Enumeración de usuarios y cambios de contraseña. |
| B7 | Logs de **firewall/IDS** del hosting | ☐ Sí ☐ No | Intentos que ni siquiera llegaron al puerto 443. |
| B8 | Logs de **monitorización de errores** (Sentry y similares) — **sólo metadatos**, sin cuerpos de petición | ☐ Sí ☐ No | Patrones de ataque en la aplicación. **Sin los cuerpos**, que contienen datos de pacientes. |
| B9 | Historial de **cambios DNS** (panel del proveedor o export) | ☐ Sí ☐ No | Persistencia por DNS y cambios de MX/TXT. |
| B10 | **Inventario de usuarios** del CMS (export de roles, sin contraseñas) | ☐ Sí ☐ No | IoC #9: usuarios no reconocidos. |
| B11 | **Hash de referencia** de `wp-config.php` o de la configuración de la app | ☐ Sí ☐ No | IoC #4: comparación de integridad. |
| B12 | Confirmación de si existe **segundo factor** en el panel | ☐ Sí ☐ No | Convierte el componente «MFA deducida» en verificado. |

### 10.3 Bloque C — Lo que se pide explícitamente por escrito (o NO se pide)

| # | Dato | Decisión | Nota |
|:-:|---|---|---|
| C1 | Consulta a **HIBP** de las cuentas del propio dominio | ☐ Autorizado por escrito ☐ **No autorizado** | Requiere que el cliente **verifique el control del dominio** en su panel de HIBP y aporte una API key. Se entrega **sólo el recuento agregado**, nunca las cuentas. |
| C2 | **Sesión de Administrador** para consultar el panel | ☐ Autorizado ☐ **No autorizado** | Recomendación del playbook: **no**. La ausencia de MFA se deduce y se confirma preguntando. |
| C3 | **Descarga de datos de pacientes** para confirmar exposición | ☐ Autorizado ☐ **No autorizado** | Recomendación: **no**. Se documenta la existencia de la ruta; no se baja un solo registro (RoE 1.2). |
| C4 | Instalación de un **honeypot** en el hosting | ☐ Autorizado ☐ **No autorizado** | Requiere RoE específico. |
| C5 | Pruebas **activas controladas** (Fase 2) | ☐ Autorizado ☐ **No autorizado** | Requiere la §5 del RoE firmada, con ventana y contacto de emergencia. |
| C6 | Análisis de **volcados de base de datos** para confirmar el impacto | ☐ Autorizado ☐ **No autorizado** | Recomendación: **no** en Fase 1. En Fase 2 sólo con autorización expresa y con copia de la base. |

### 10.4 Cómo se rellena y qué pasa con cada respuesta

| Respuesta del cliente | Qué significa | Qué se hace |
|---|---|---|
| **Sí** a B1-B3 | Se puede dar el **volumen real de ataques**. | Upgrade de la Fase 1: §4.3 completa, con las cinco métricas. |
| **No** a B1-B3 | El volumen queda **fuera de alcance** y se dice así. | Se entrega §3 + §5 + §6 y se propone B1 para la siguiente fase. |
| **No sé** a A1 | La superficie de subdominios es **desconocida**, no «limpia». | Se audita CT + DNS y se reporta el inventario con la marca «no verificado por el cliente». |
| **No** a C1 | El dato de credenciales filtradas no se trabaja. | No se insiste. Es una decisión del cliente y se respeta. |
| **Sí** a C2 | El auditor entra al panel. | **Se desaconseja por escrito.** Preferible: que el cliente exporte la lista de usuarios y las políticas de MFA. |

---

## 11. Procedimiento reproducible

Diez pasos. Cada uno con su comando, la evidencia que produce y su **condición
de parada**. Los pasos 1 y 2 no se saltan; si se saltan, el resto del
procedimiento no es defendible.

> **Variables de entorno** (se fijan una vez por caso):
> ```bash
> export UA='Mozilla/5.0 (compatible; ClientSecurityAudit/1.0; +https://tu-dominio-de-auditoria.mx)'
> export DOMINIO='ejemplo.mx'
> export HOST='www.ejemplo.mx'
> export IP='203.0.113.10'          # sólo si el cliente confirma que es suya
> export EVID='03-casos/ejemplo/evidencia'
> ```

### Paso 1 — Autorización y allowlist (sin red)

```bash
cp 05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md evidencia/roe.md
# (rellenar, imprimir y firmar; el RoE va a la evidencia antes de empezar)
python3 01-tooling/scripts/scope_guard.py --authorization evidencia/auth.json \
        --list-hosts --json
```

- **Evidencia:** `roe.md` firmado, `auth.json` con `authorization_ref`, `signed_by`,
  `valid_from`, `valid_to`, `hosts`.
- **Condición de parada:** sin RoE firmado y sin `auth.json` con firma, **no se
  hace ninguna petición**. El script aborta con código 2.

### Paso 2 — Recon pasivo de superficie (sólo terceros)

```bash
# 2.1 Certificate Transparency: todos los nombres alguna vez certificados
curl -sS "https://crt.sh/?q=%25.${DOMINIO}&output=json" -o "${EVID}/crt.json"

# 2.2 Puertos y CVEs ya indexados por un tercero (NO es escaneo nuestro)
curl -sS "https://internetdb.shodan.io/${IP}" -o "${EVID}/internetdb.json"

# 2.3 Histórico de URLs (exposición histórica, NO ataques)
curl -sS "https://web.archive.org/cdx/search/cdx?url=${DOMINIO}/*&output=json\
&fl=original,statuscode,mimetype,timestamp&collapse=urlkey&filter=statuscode:200" \
       -o "${EVID}/cdx.json"

# 2.4 Escaneos de terceros sobre el dominio (cota inferior de interés)
curl -sS -H "API-Key: ${URLSCAN_KEY}" \
     "https://urlscan.io/api/v1/search/?q=domain:${DOMINIO}&size=100" \
     -o "${EVID}/urlscan.json"

# 2.5 Geolocalización y ASN de la IP (comprobación de cumplimiento)
curl -sS "https://ipinfo.io/${IP}/json" -o "${EVID}/ipinfo.json"

# 2.6 Common Crawl: segundo corte histórico (revisar el corpus vigente)
curl -sS "https://index.commoncrawl.org/collinfo.json" -o "${EVID}/cc_collindex.json"
```

- **Evidencia:** `crt.json`, `internetdb.json`, `cdx.json`, `urlscan.json`,
  `ipinfo.json`, `cc_collindex.json`.
- **Condición de parada:** si `crt.sh` o `urlscan` devuelven error o exigen
  API key, ese componente queda **NO VERIFICADO**; no se sustituye por una
  estimación.
- **⚠️ Nota de uso comercial:** InternetDB es gratuito para uso **no
  comercial** (verificado el 2026-11-21); para un encargo de pago hay que
  confirmar la licencia vigente.

### Paso 3 — DNS y posture de correo (Fase 3 y Fase 7)

```bash
for r in 8.8.8.8 1.1.1.1 9.9.9.9; do
  { echo "=== DMARC ==="; dig +short DMARC.${DOMINIO} TXT @$r; } >> "${EVID}/dns_mailsec.txt"
  dig +short MX ${DOMINIO} @$r            >> "${EVID}/dns_mailsec.txt"
  dig +short CAA ${DOMINIO} @$r           >> "${EVID}/dns_mailsec.txt"
  dig +short TXT ${DOMINIO} @$r           >> "${EVID}/dns_mailsec.txt"
done
# DKIM: los selectores reales los publica el proveedor de correo
dig +short default._domainkey.${DOMINIO} TXT @8.8.8.8 >> "${EVID}/dns_mailsec.txt"
```

- **Evidencia:** `dns_mailsec.txt` **con secciones `=== NOMBRE ===`** — el
  formato importa: el índice lee las secciones y sólo puede afirmar la
  ausencia de DMARC si encuentra una sección DMARC **sin** `v=DMARC1`.
- **Condición de parada:** tres resolvers coincidentes = evidencia. Un solo
  resolver = **inconcluyente**.

### Paso 4 — TLS y versiones (Fase 4, con la lección (b) del playbook)

```bash
for v in "-tls1 --tls-max 1.0" "-tls1_1 --tls-max 1.1" "-tls1_2 --tls-max 1.2" "-tls1_3 --tls-max 1.3"; do
  echo "$v =>" >> "${EVID}/tls_versions.txt"
  openssl s_client $v -provider legacy -provider default \
    -connect ${HOST}:443 -servername ${HOST} </dev/null 2>&1 \
    | grep -E 'New, TLSv|error:|alert protocol version' >> "${EVID}/tls_versions.txt"
  sleep 1
done
```

- **Evidencia:** `tls_versions.txt` con líneas `-tls1_2 => New, TLSv1.2, …`
  (formato que el índice sabe leer).
- **Condición de parada:** si el cliente local no puede ofrecer TLS 1.0
  (proveedor legacy deshabilitado), el resultado es **inconcluyente**, no
  «el servidor lo rechaza». Fijar `--tls-max` es obligatorio: `--tlsv1.0`
  sólo fija un mínimo.

### Paso 5 — Sonda de exposición (Fase 5/6, lista fija, sin fuzzing)

```bash
python3 01-tooling/scripts/probe_exposure.py -a "${EVID}/auth.json" \
        --host "${HOST}" --out "${EVID}/" --dry-run     # 1) ver el plan, sin red
python3 01-tooling/scripts/probe_exposure.py -a "${EVID}/auth.json" \
        --host "${HOST}" --out "${EVID}/"                # 2) ejecutar
```

- **Evidencia:** `probe_exposure.tsv` (columnas `host path code content_type
  length sha256 soft_404 verdict severity`), `probe_exposure.json`.
- **Condición de parada:** el script aborta si el host no está en el
  allowlist; nunca sale de la lista de 53 rutas; nunca guarda el cuerpo de una
  ruta sensible; marca `soft_404` para no generar falsos positivos.

### Paso 6 — Cabeceras y descarga del HTML crudo (la evidencia base)

```bash
curl -sS -A "$UA" -D "${EVID}/headers.txt" -o /dev/null "https://${HOST}/"
sleep 1
curl -sS -A "$UA" "https://${HOST}/" -o "${EVID}/home.html"
sleep 1
curl -sS -A "$UA" "https://${HOST}/robots.txt" -o "${EVID}/robots.txt"
```

- **Evidencia:** `headers.txt` (volcado con líneas `HTTP/1.1 …` y
  `Cabecera: valor` — formato que el índice y `header_tls_report.py` leen),
  `home.html`, `robots.txt`.
- **Condición de parada:** ≥1 s entre peticiones, User-Agent honesto y
  contactable. Si el servidor bloquea, **eso se reporta**; no se suplanta un
  navegador para saltarse el bloqueo.

### Paso 7 — Análisis local (sin red)

```bash
python3 01-tooling/scripts/secrets_scan.py "${EVID}" --json --out "${EVID}/secrets.json"
python3 01-tooling/scripts/js_intel.py "${EVID}" --base-host "${DOMINIO}" \
        --json-out "${EVID}/js_intel.json" --out "${EVID}/js_intel.md"
python3 01-tooling/scripts/header_tls_report.py "${EVID}/headers.txt" \
        --out "${EVID}/header_tls.md"
```

- **Evidencia:** `secrets.json` (nunca el valor completo de un secreto),
  `js_intel.json` + `js_intel.md`, `header_tls.md`.
- **Condición de parada:** si el escáner propone una versión o un CVE, se
  contrasta contra la **fuente primaria** antes de escribirlo. Si no se puede
  llegar a la fuente primaria, el hallazgo va como **NO VERIFICADO**.

### Paso 8 — Redacción de PII (antes de compartir cualquier cosa)

```bash
python3 01-tooling/scripts/pii_redact.py "${EVID}-cruda" \
        --out-dir "${EVID}-sanitizada" --report "${EVID}/redaccion.json"
```

- **Evidencia:** copia sanitizada + `redaccion.json` (sólo conteos por
  categoría, nunca valores).
- **Condición de parada:** **ninguna** evidencia con PII sale de la carpeta
  del caso sin pasar por aquí.

### Paso 9 — Índice de exposición a ataques

```bash
python3 01-tooling/scripts/attack_surface_report.py \
    --probe-tsv  "${EVID}/probe_exposure.tsv" \
    --secrets-json "${EVID}/secrets.json" \
    --headers    "${EVID}/headers.txt" \
    --internetdb "${EVID}/internetdb.json" \
    --crtsh      "${EVID}/crt.json" \
    --dns-mailsec "${EVID}/dns_mailsec.txt" \
    --tls-versions "${EVID}/tls_versions.txt" \
    --js-intel   "${EVID}/js_intel.json" \
    --out informe/
```

- **Evidencia:** `informe/attack_surface_report.md` +
  `informe/attack_surface_report.json` (con `score`, `band`, `evaluable`,
  `formula`, `components` y `coverage`).
- **Condición de parada (epistémica, la más importante del procedimiento):**
  - Si `evaluable` es `false` → en el informe se escribe **«No evaluable»**,
    **nunca** «Bajo».
  - Si un componente sale con `source = "sin datos"` → no se cuenta como
    ausencia de riesgo: es ausencia de dato.
  - El número se publica **con su desglose, su cobertura y su fecha**.

### Paso 10 — Cierre: qué se dice y qué no

```bash
# (opcional) agregación local de los logs que entregó el cliente
awk '{print $1}' "${EVID}/access.log" | sort -u | wc -l
awk '$7 ~ /wp-login\.php|\/login/ {split($4,a,":"); print a[2]}' \
    "${EVID}/access.log" | sort | uniq -c
```

Y en el informe, tres secciones obligatorias:

1. **Superficie expuesta** — con fuente y fecha por cada dato.
2. **Lo que ya entró** — los IoC confirmados, o la frase de no-evidencia con
   su alcance.
3. **Lo que no se puede ver** — la §7, redactada como «fuera de alcance».

**Checklist de cierre (verificación final antes de entregar):**

| # | Verificación | ☐ |
|:-:|---|:-:|
| 1 | Todo número del informe tiene fichero de evidencia y fecha | ☐ |
| 2 | Ninguna afirmación de «nº de ataques» sin logs | ☐ |
| 3 | Ninguna afirmación de compromiso sin confirmación del cliente | ☐ |
| 4 | Los componentes «sin datos» no se presentan como ausencia de riesgo | ☐ |
| 5 | El índice va con desglose, cobertura y fecha | ☐ |
| 6 | Los falsos positivos se conservan en la evidencia | ☐ |
| 7 | Existe una sección **«Lo que ya está bien»** | ☐ |
| 8 | La evidencia sensible está redactada | ☐ |
| 9 | El informe técnico va al equipo técnico, **no** al dueño final | ☐ |
| 10 | Lo no verificado está marcado **NO VERIFICADO** con su comprobación pendiente | ☐ |

---

## 12. Anexo: registro de verificaciones y puntos NO VERIFICADOS

### 12.1 Comprobaciones hechas al escribir este documento

| Fuente | Qué se comprobó | Resultado |
|---|---|---|
| `attack_surface_report.py` | Componentes, pesos, fórmula, bandas, comportamiento sin evidencia, duplicado de DMARC, JSON de secretos vacío | **Verificado por ejecución** (3 fixtures + caso sin evidencia) |
| `https://internetdb.shodan.io/` | Campos devueltos (`ip`, `ports`, `cpes`, `hostnames`, `tags`, `vulns`), ausencia de API key, actualización semanal, **condición de uso comercial** | **Verificado** 2026-11-21 |
| `https://index.commoncrawl.org/` | Servidor de índice CDX operativo; advertencia de no sobrecargarlo | **Verificado** 2026-11-21 |
| `https://haveibeenpwned.com/API/v3` | Base URL, endpoint `GET /breachedDomain/{dominio}`, cabecera `hibp-api-key`, **requiere dominio verificado** (403 si no), devuelve alias, key de 32 hex, user-agent obligatorio, planes Core Pro / Pro | **Verificado** 2026-11-21 |
| `https://docs.censys.com/` | Existencia de la API de plataforma v3, historial de servicios y de certificados, DNS histórico, riesgo de DNS colgante, modelo de créditos | **Verificado** 2026-11-21 (índice de documentación) |
| `https://docs.virustotal.com/reference/overview` | API v3 como versión por defecto; endpoints de dominio, IP y URL | **Verificado** 2026-11-21 |
| `https://transparencyreport.google.com/safe-browsing/search` | URL operativa | **Verificado** 2026-11-21 |
| `https://developers.google.com/safe-browsing/v4/lookup-api` | Existence de la Lookup API v4 (POST a `safebrowsing.googleapis.com`, hasta 500 URL por petición, `threatTypes` `MALWARE`/`SOCIAL_ENGINEERING`) | **Verificado** 2026-11-21 |

### 12.2 Puntos NO VERIFICADOS (qué habría que comprobar y dónde)

| # | Punto no verificado | Por qué no se pudo comprobar aquí | Cómo comprobarlo |
|:-:|---|---|---|
| 1 | `https://developers.google.com/search/docs/safety-reporting-in-search-console` (URL indicada en el encargo) | Devolvió **404** en la comprobación del 2026-11-21 | Localizar la ruta vigente en el índice de `https://developers.google.com/search/docs` y verificar el flujo de Search Console |
| 2 | Límites de tasa concretos de la API de urlscan.io | La página de documentación respondió **429** al consultarla | Consultar `https://urlscan.io/docs/api/` con pacing y leer la sección de límites; verificar la sintaxis de `q=domain:` y los campos de respuesta |
| 3 | Rutas exactas del endpoint de Censys, esquema de autenticación y créditos por consulta | Sólo se verificó el índice de la documentación | `https://docs.censys.com/reference/get-started.md` y la página de créditos, con una cuenta de prueba |
| 4 | Cuota y límites de tasa del plan gratuito de VirusTotal | No se authenticated | Página de API key / planes de VT Enterprise |
| 5 | Coste, cuota y **límite de tamaño de dominio** del plan Core Pro de HIBP | Requiere suscripción | Página de suscripción de HIBP; probar la búsqueda de dominio con una key de test |
| 6 | Nombre del corpus vigente de Common Crawl | Cambia con cada publicación | `https://index.commoncrawl.org/collinfo.json` (el propio índice lo lista) |
| 7 | Condiciones de uso vigentes de InternetDB para uso comercial | La página dice «free for non-commercial use… enterprise license», pero los términos pueden cambiar | Sección de licensing/precios de Shodan en la fecha de cada encargo; alternativa: API de pago de Shodan |
| 8 | Campos que expone el informe de DMARC aggregate (RPT) y su granularidad exacta | Requiere una cuenta de correo con RPT configurado | Configurar `rua=` y leer el primer reporte XML |
| 9 | Comportamiento exacto de los logs `security*.log` de WordPress en la versión del cliente | Depende de la versión y del hosting | WordPress: revisar el formato de `wp-content/debug.log` y del log del servidor para `wp-login.php` |
| 10 | Si el `Attack Exposure Score` es el índice que se publica comercialmente | Este documento lo propone; el playbook no fija todavía una cifra de mercado | Decisión comercial de la consultoría; el índice está listo para usarse tal cual |

### 12.3 Referencias internas del playbook

| Documento | Qué aporta a este |
|---|---|
| `00-metodologia/reglas-de-autorizacion-y-roe.md` | Prohibiciones duras (§1.1-1.5), ritmo, regla de terceros (§3), plantilla de RoE (§4) |
| `00-metodologia/ciclo-de-auditoria.md` | Fases 3 (DNS/infra), 4 (TLS), 5 (plataforma), 7 (email/phishing); lecciones (a) y (b) |
| `00-metodologia/como-presentar-resultados.md` | Matriz de severidad, ICE, tres capas, obligatoriedad de «lo que ya está bien» |
| `01-tooling/manifiesto-de-herramientas.md` | Catálogo, licencias, modo (PASIVA/ACTIVA-L/ACTIVA-A) y notas de copyleft |
| `01-tooling/scripts/README.md` | Flujo de 9 pasos del toolkit, auto-prueba y limitaciones conocidas |
| `01-tooling/scripts/attack_surface_report.py` | **El índice de §6**: componentes, pesos, fórmula y bandas |
| `01-tooling/scripts/probe_exposure.py` | La sonda de 53 rutas, `soft_404` y detección de exposición |
| `01-tooling/scripts/pii_redact.py` | La redacción de PII que hace posible compartir evidencia |
| `01-tooling/scripts/secrets_scan.py`, `js_intel.py`, `header_tls_report.py` | Las entradas del índice: secretos, JS/terceros/SRI, cabeceras |

---

*Documento de metodología. Todas las cifras de ejemplo están etiquetadas como
ficticias y fueron verificadas ejecutando `01-tooling/scripts/attack_surface_report.py`
sobre artefactos de prueba. Ninguna cifra de mercado, porcentaje de
incidencia o estadística externa se afirma en este documento: cuando un dato no
se pudo comprobar, aparece marcado **NO VERIFICADO** con su comprobación
pendiente.*
