# Manifiesto de herramientas

Catálogo de todo lo que se usó (o se consideró) en las dos pasadas de la
auditoría de `dentaleasy.mx`, más el material de apoyo de presentación.

**Derivado de los artefactos en disco, no de memoria.** Cada fila corresponde a
algo que aparece en `03-casos/clinica-dental-easy/evidencia/` o en el informe
técnico. Donde la licencia no pude confirmarla leyendo la fuente primaria, está
marcada **no verificado**  trátalo como pendiente, no como certeza.

- **Modo** define si la herramienta hace peticiones al objetivo o no:
  - `PASIVA`  solo consulta servicios de terceros o lo que ya es público.
  - `ACTIVA-L`  tasa baja: peticiones GET/HEAD al objetivo, espaciadas 1 s.
  - `ACTIVA-A`  **no usada en este engagement**. Requiere autorización
    explícita y por escrito. Ver `00-metodologia/reglas-de-autorizacion-y-roe.md`.
- **Fase** corresponde a la numeración de `00-metodologia/ciclo-de-auditoria.md`.

---

## 1. Reconocimiento pasivo y descubrimiento de superficie

Ninguna de estas hace una petición al objetivo. Se interrogan bases de datos de
terceros. Es la fase donde más se gana y menos se arriesga.

| Herramienta | Para qué sirve | URL | Licencia | Modo | Fase |
|---|---|---|---|---|---|
| **crt.sh** | Registros de CT: cada certificado emitido revela subdominios que normalmente no están enlazados ni aparecen en DNS. | https://crt.sh/ · datos vía https://crt.sh/?q=%25.dentaleasy.mx&output=json | Servicio de Sectigo. El *scanner* Cert Spotter que lo alimenta es **MPL-2.0** | PASIVA | 2, 3 |
| **Wayback CDX API** | Índice completo del archivo histórico. La API CDX permite filtrar por código de estado, extensión y patrón  es la forma de buscar `*.sql`, `wp-config` o URLs de staging en el historial. | https://web.archive.org/cdx/search/cdx | Dominio público; API sin SL explícita  **uso sujeto a las condiciones de archive.org** | PASIVA | 2, 6 |
| **Wayback availability API** | ¿Fue el sitio capturado alguna vez? Útil para saber si un hallazgo histórico existe antes de escribir sobre él. | https://archive.org/wayback/available |ídem | PASIVA | 2 |
| **gau** (`getallurls`) | Historical URL fetcher: Wayback + Common Crawl + Arquivo + AlienVault en un comando. Busca endpoints olvidados. | https://github.com/lc/gau | **MIT** | PASIVA | 2, 6 |
| **waybackurls** | Alternativa ligera a `gau`: solo Wayback. Más fácil de auditar y de limitar. | https://github.com/tomnomnom/waybackurls | **MIT** | PASIVA | 2, 6 |
| **Common Crawl index** | Corpus masivo. El índice es consultable por patrón con filtros de status/tipo MIME; útil cuando Wayback no capturó nada. | https://index.commoncrawl.org/ | Corpus con condiciones de uso propias  leer antes de automatizar | PASIVA | 2, 6 |
| **urlscan.io**  **solo búsqueda** | Historial de escaneos de terceros sobre el dominio. Delata tecnologías, endpoints y ficheros ya subidos por otros. | https://urlscan.io/ · API https://urlscan.io/docs/api/ | SaaS propietario, con API key. **Solo lectura desde el panel/API de búsqueda** | PASIVA | 2, 5 |
| **Shodan InternetDB** | API gratuita y sin autenticación que responde por una IP: puertos abiertos, CVEs del software expuesto, hostnames del TLS. | https://internetdb.shodan.io/ · https://www.shodan.io/ | Datos con licencia CC BY-SA 4.0; API gratuita con límite de tasa | PASIVA | 3 |
| **ipinfo.io** | Geolocalización, ASN y organización de una IP. Necesario aquí porque "datos de pacientes en México" servidos desde Brasil es un hallazgo de cumplimiento, no un dato cosmético. | https://ipinfo.io · https://ipinfo.io/developers | Datos **CC BY-SA 4.0**; cuenta gratuita hasta 50k/mes | PASIVA | 3, 8 |
| **VirusTotal** | Correlación de dominio/IP/URL con detecciones. Útil como confirmación secundaria. | https://www.virustotal.com/ | SaaS propietario; nivel de API gratuito limitado | PASIVA | 2, 3 |

---

## 2. Infraestructura, DNS y TLS

| Herramienta | Para qué sirve | URL | Licencia | Modo | Fase |
|---|---|---|---|---|---|
| **`dig`** / BIND | Consulta DNS autoritativa y recursiva. Imprescindible para DMARC/SPF/DKIM/CAA porque hay que preguntar a varios resolvers: un NXDOMAIN de un solo resolver puede ser caché o filtrado. | https://bind9.readthedocs.io/ | ISC License (libre) / `dig` de macOS y Linux | PASIVA | 3, 7 |
| **`openssl s_client`** | Habla TLS a mano. Permite forzar versión y cipher exactos, ver la cadena completa y pedir el estado OCSP. **Es la herramienta que produjo el falso positivo TLS-1.0 y su corrección**  ver §Fase 4 en el ciclo. | https://www.openssl.org/docs/manmaster/man1/openssl-s_client.html | Apache-2.0 | ACTIVA-L | 4 |
| **Mozilla Observatory (MDN)** | Scoring de configuración web de un vistazo. En `dentaleasy.mx` dio **grade F** (6 de 12 controles fallando: CSP, redirección, HSTS, SRI, XCTO, XFO). **No es un resultado de OWASP Top 10**  es un proyecto hermano. | https://observatory.mozilla.org/ | **MPL-2.0** (weak copyleft) | PASIVA (consulta a un tercero) | 4, 5 |
| **SSL Labs API** | Análisis profundo de TLS: cipher suites enumeradas, handshake simulado, BEAST/POODLE. Complementa a `openssl` con más recorrido, pero tiene que devolver el resultado asíncrono. | https://api.ssllabs.com/api/v3/analyze?host=ejemplo.com | API gratuita de Qualys; los resultados se pueden publicar con atribución | PASIVA (consulta a un tercero) | 4 |
| **internet.nl** | Escaneo de componentes por separado: HTTPS, DKIM/DMARC/SPF, DNSSEC, IPv6, etc. Reporta en ABNF (neerlandés) y da remediaciones concretas. | https://internet.nl/ · https://github.com/internetnl/internet.nl | Servicio gratuito de NLnet Labs. Licencia del código **no verificado** | PASIVA (consulta a un tercero) | 4, 7 |

---

## 3. Análisis de plataforma web y rendimiento

| Herramienta | Para qué sirve | URL | Licencia | Modo | Fase |
|---|---|---|---|---|---|
| **`curl`** | El caballo de batalla. No una petición: con `-D`, `-w`, `-o`, `--compressed` es sonda de cabeceras, medidor de waterfall y descargador de evidencia. **Toolbox base de todo lo pasivo-tolerante.** | https://curl.se/docs/manpage.html | curl license (permiso X) | ACTIVA-L | 3, 4, 5, 6, 7 |
| **WhatWeb** | Fingerprinting de stack por coincidencia de patrones. **Advertencia metodológica**: su versión es una *coincidencia de cadena de texto*; ver la lección (a) del ciclo de auditoría. | https://github.com/urbanadventurer/WhatWeb | **MIT** | ACTIVA-L (modo pasivo/ `--log-json=`) | 5 |
| **WPScan** | Enumeración de WordPress: temas, plugins, usuarios, versión. **Requiere API token.** La edición gratuita da buen inventario pero deja fuera buena parte del escaneo de vulnerabilidades. | https://wpscan.com · https://github.com/wpscanteam/wpscan | **GPL-3.0** (copyleft) | ACTIVA-L | 5, 6 |
| **Sonda manual de la REST API de WordPress** | No es una herramienta: es `curl` contra `/wp-json/wp/v2/*` y el atajo `/?rest_route=`. Lo que salió de aquí fue la cadena completa de enumeración de usuarios (§F06F09 del caso). | https://developer.wordpress.org/rest-api/ | Técnica sobre API pública  MIT WordPress | ACTIVA-L | 5, 6 |
| **Lighthouse** (CLI) | Auditoría de performance/SEO/accesibilidad conChrome headless. **Activa requests** a la página y carga todos los recursos. | https://developer.chrome.com/docs/lighthouse/overview · https://github.com/GoogleChrome/lighthouse | **Apache-2.0** | ACTIVA-L (recurso-pesado) | 5 |
| **PSI API** (PageSpeed Insights) | Mismo CORE Web Vitals desde la API de Google, sin lanzar un navegador. Ideal para medir línea base y para re-medir tras los fixes sin instalar nada. | https://developers.google.com/speed/docs/insights/v5/get-started | API gratuita, sujeta a cuota | PASIVA (consulta a un tercero) | 5 |
| **GoAccess** | Analizador de logs de servidor en terminal. Útil si el cliente puede compartir access logs: convierte el comportamiento en hallazgos reales en vez de inferencias desde fuera. | https://goaccess.io · https://github.com/allinurl/goaccess | **GPL-2.0** (copyleft) | Pasiva (procesa logs locales) | 5 |
| **Retire.js** | Cruza las librerías JS servidas contra una tabla de CVEs. **La lección (a) vive aquí**: para jQuery 3.7.1 marca `CVE-2020-11022/11023` (fijadas en 3.5.0)  un falso positivo por tabla de rangos desactualizada. | https://retirejs.github.io/retire.js/ · https://github.com/RetireJS/retire.js | **Apache-2.0** | ACTIVA-L (o local sobre `js/` ya descargado) | 2, 5 |

### Scripts propios escritos durante el caso

Estos no son herramientas de terceros; son scripts ad-hoc que quedaron en
`evidencia/` y son parte del método. **Reutilizarlos es la idea del playbook.**

| Script | Qué hace | Licencia | Modo | Fase |
|---|---|---|---|---|
| `evidencia/analyze.py` | Auditoría on-page en Python puro sobre el HTML ya descargado: title/description/H1-H3/canonical/robots/img alt/schema JSON-LD/forms/iframes por URL. Salida: `onpage_report.txt` + `onpage.json`. | Python stdlib | Pasiva (local) | 5 |
| `evidencia/scan.py` | Regex de secretos sobre el HTML/JS descargado  AWS, Google API key, Stripe, Slack, GitHub, JWT, private keys, URLs firmadas S3, deployments de Apps Script. **Redacta** a `xxxxyy`. | Python stdlib | Pasiva (local) | 6 |
| `evidencia/water.py` | Waterfall de peso: extrae src/href de la home, hace `curl -w` a cada asset con `sleep 0.6`, agrega por clase (js/css/img/font) y separa los third-party. Salida: `waterfall.txt`. | Python stdlib | ACTIVA-L | 5 |
| `evidencia/audit2/probe.sh` | Sonda GET/HEAD genérica que escribe TSV `path\tcode\tctype\tlen\tprimeros200`. **El `sleep 1` al final es la aplicación literal del RoE.** | Bash | ACTIVA-L | 5, 6 |

---

## 4. Divulgación de secretos y superficie de código

| Herramienta | Para qué sirve | URL | Licencia | Modo | Fase |
|---|---|---|---|---|---|
| **Gitleaks** | Escaneo de secretos en repositorios, por historial. Cuando el código del cliente es accesible, es la forma rápida de cerrar el hallazgo sin reinventar reglas. | https://github.com/gitleaks/gitleaks | **MIT** | Pasiva (local) | 6 |
| **TruffleHog** | Escaneo de secretos con verificación de vida opcional. Más profundo que Gitleaks y produce muchos falsos positivos si no verificas. | https://github.com/trufflesecurity/trufflehog | **AGPL-3.0** ️ | Pasiva (local) | 6 |
| **LinkFinder** | Extrae endpoints de archivos JS (routes, APIs). Complementa a `scan.py` cuando hay bundles. | https://github.com/GerbenJavado/LinkFinder | **MIT** | Pasiva (local) | 6 |
| **SecretFinder** | Variantes de regex para claves en JS. | https://github.com/maheshcode/secretfinder | **GPL-3.0** (copyleft) | Pasiva (local) | 6 |

---

## 5. Analítica y terceros

Identificar qué analítica carga un sitio esseo la pregunta "¿qué datos de
pacientes salen del navegador?". En este caso la respuesta fue un endpoint de
Google Apps Script con PII de pacientes (F25).

| Herramienta / servicio | Para qué sirve | URL | Licencia | Modo | Fase |
|---|---|---|---|---|---|
| **Matomo** | Analítica autoalojada con IP anonimizada. Su presencia es una señal *positiva* de privacidad. | https://matomo.org | **GPL-3.0** (copyleft) | Detección por string | 6 |
| **PostHog** | Product analytics. Self-host posible. | https://posthog.com · https://github.com/PostHog/posthog | MIT (core) | Detección por string | 6 |
| **Umami** | Analítica ligera y sin cookies. | https://umami.is | MIT | Detección por string | 6 |
| **OpenReplay** | Session replay + error tracking autoalojado. Relevante cuando graba formularios con datos sensibles. | https://openreplay.com · https://github.com/openreplay/openreplay | **AGPL-3.0** ️ | Detección por string | 6 |
| **Microsoft Clarity** | Session replay gratuito de MS. Mismo riesgo que OpenReplay: graba la interacción del usuario. | https://clarity.microsoft.com | SaaS propietario, ToS | Detección por string | 6 |
| **Google Analytics** | Referencia de facto; identificador de medición como cadena de detección. | https://marketingplatform.google.com/about/analytics/ | SaaS propietario | Detección por string | 6 |

---

## 6. Nota sobre licencias copyleft (AGPL / GPL / MPL)

**Lectura para el caso de uso habitual de esta consultoría: Usually no hay
problema.** La causa es que estas herramientas se ejecutan como procesos
separados para producir findings; la licencia copyleft del código de la
herramienta no se propaga al informe que tú escribes a partir de su salida. Un
PDF, un `.md` o un CSV no es un «derivative work» de GoAccess.

**Cuándo sí importa:**

1. **No vincules ni copies su código** en un entregable propietario (p.ej.
   pegar `TruffleHog` en un pipeline cerrado que le vendes a un cliente).
2. **No reempaquetes ni revendas los binarios** dentro de una herramienta que
   entregues al cliente. Si distribuyes binarios GPL, debes ofrecer el código
   fuente.
3. **AGPL §13 es el único con riesgo de red real**: si modificas OpenReplay o
   TruffleHog y lo ofreces como servicio a través de una red, la obligación
   copyleft se extiende a los usuarios de ese servicio. En un flujo de consultoría
   interno esto nunca se dispara; en un producto SaaS propio, sí.
4. **Atribución y licencias de datos:** los datos de Shodan InternetDB e
   ipinfo.io son CC BY-SA 4.0. Si los pegas textualmente en un entregable hay
   que atribuir y, por ser *ShareAlike*, el uso debe ser compatible. Cita la
   fuente y parafrasea cuando puedas.

**Lista de copyleft en este manifiesto:**

| Herramienta | Licencia | Tipo | Riesgo al reempacar |
|---|---|---|---|
| GoAccess | GPL-2.0 | Copyleft fuerte | Binario GPL en tu paquete  ofrece el código fuente |
| WPScan | GPL-3.0 | Copyleft fuerte | ídem |
| SecretFinder | GPL-3.0 | Copyleft fuerte | ídem |
| Matomo | GPL-3.0 | Copyleft fuerte | Solo si lo reempaquetas |
| TruffleHog | AGPL-3.0 | Copyleft de red | Él link/integración + uso en red de versión modificada |
| OpenReplay | AGPL-3.0 | Copyleft de red | ídem |
| Mozilla Observatory | MPL-2.0 | Copyleft *weak* (archivo) | Solo si copias sus archivos a otros; reportar cambios en los modificados |

---

## 7. Candidatas para futuras auditorías

Identificadas durante el caso pero **no utilizadas**. Anotadas con el motivo para
no perderlas de vista y para que el siguiente engagement sepa que existen.

| Herramienta | Para qué serviría | Por qué no se usó aquí |
|---|---|---|
| **Nuclei** | Escaneo basado en plantillas; enorme cobertura de CVEs y tecnologías de plataforma. | Es **activo**. Estuvo fuera del alcance pasivo. Candidata natural si un cliente firma RoE que permita pruebas controladas. |
| **Nikto** / **sqlmap** / **ffuf** / **dirsearch** | Escaneo activo de vulnerabilidades y fuzzing de rutas. | **Activos y ruidosos.** Requieren autorización expresa. En una auditoría pasiva, introducir Canonical False Positives. |
| **testssl.sh** | Automatiza un exhaustivo test de TLS/ciphers en una línea. | Habría resuelto la fase 4 de una; se hizo a mano con `openssl s_client` + curl para no meter una herramienta que golpea muchas veces el host. El valor real fue **verificar a mano** el TLS-1.0. |
| **Subfinder / Amass** | Enumeración de subdominios activa (DNS brute, certificate transparency). | El lado pasivo ya cubrió lo necesario con crt.sh + `dig`. Los activos tocan servidores del cliente. |
| **Burp Suite Community** | Proxy para interceptar y manipular peticiones. | Su valor real está en pruebas autenticadas/manipulación. No autorizado en este engagement. |
| **ZAP / nuclei / Nikto** | Cobertura DAST. | Ídem: DAST presupone permiso para enviar peticiones manipuladas. |
| **Kabouzer / Wapiti** | DAST automatizado. | Ídem. |
| **SecurityHeaders.com** | Quickly report missing headers. | Ya cubierto por Observatory + `curl -D`. Solapamiento. |
| **h8mail** | Verificar credenciales filtradas contra un buzón. | **De-anonimización / verificación de credenciales.** Prohibido por RoE, y no hay ningún caso legítimo de auditoría pasiva donde sea necesario. No se permite. |
| **theHarvester** | OSINT de subdominios y emails. | Su parte de enumeración de correo es una técnica de spearphishing. Se usa la mitad OSINT (subdominios) y **nunca** la mitad de emails. |
| **Google dorks / GitHub code search** | Buscar credenciales en repos públicos. | Para este cliente no procedía: no es cliente de GitHub y no hay código que volumetriciar. En un cliente *de software*, es fase 6 de primera línea. |
| **Playwright / Puppeteer (uso limitado)** | Ya se usó para el PDF del teaser; en auditoría sólo para renderizar JS. | Un navegador headless ejecuta el JS y por tanto dispara peticiones POST y beacons de analítica desde una IP que no es el cliente. Sólo con RoE explícita. |

---

## 8. Cómo mantener este manifiesto

- **Al cerrar cada auditoría**, añade una fila por cada herramienta nueva.
- **No borras** herramientas que dejaste de usar: muévelas a «candidatas».
- **Verifica la licencia antes de reempaquetar** algo para un cliente.
- Si una URL no está verificada contra su fuente primaria, deja la marca
  **no verificado** en lugar de adivinarla.