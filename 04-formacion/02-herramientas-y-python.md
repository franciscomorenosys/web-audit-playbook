# 02 — Herramientas y Python

Toolkit curado para auditorías web de SMB, **con la línea de autorización
dibujada en cada herramienta**. No es un catálogo: es un inventario con
responsabilidad. Cada fila dice contra quién puedes usarla.

Doctrina complementaria: [`../00-metodologia/reglas-de-autorizacion-y-roe.md`](../00-metodologia/reglas-de-autorizacion-y-roe.md)
· catálogo ya usado en un caso real:
[`../01-tooling/manifiesto-de-herramientas.md`](../01-tooling/manifiesto-de-herramientas.md)

---

## 0. La línea de autorización (léase primero)

**Una herramienta no es buena o mala: es legal, gris o ilegal según contra quién
la apuntes.** La misma línea de comandos que es una auditoría el lunes es un
ataque el martes. Por eso toda entrada trae su etiqueta de autorización: es lo
que separa un consultor de un incidente.

| Etiqueta | Qué hace la herramienta | Contra quién | ¿RoE firmado? |
|---|---|---|---|
| **PASIVA-SEGURO** | Solo lee índices públicos de terceros (Shodan, crt.sh, Wayback, Common Crawl, Censys). **Cero peticiones al objetivo.** | Cualquiera, incluso sin que te contrate. | No hace falta |
| **AUTORIZACIÓN REQUERIDA** | Envía peticiones al objetivo (HTTP, escaneo, fuzzing) o consulta su zona DNS. | Solo tus objetivos propios o con **autorización escrita que nombre esa técnica**. | **Sí, siempre** |
| **LAB ÚNICAMENTE** | Explota, fuerza bruta, descifra hashes, envenena. | Solo en tu laboratorio (DVWA, Juice Shop, Metasploitable, HTB, tu VM). | Fuera del alcance del cliente, siempre |

**La regla de una frase:** *si la acción deja un registro en la infraestructura
del cliente, necesita autorización; si solo deja un registro en el índice de un
tercero, no.*

### Por qué esto importa profesionalmente

1. **Responsabilidad profesional.** Tu entregable es un reporte firmado por ti.
   Una auditoría que cruza la línea no produce un hallazgo: produce un
   incidente que tú causaste, y destroza el valor de los otros veinte.
2. **Riesgo legal.** En México, la auditoría no autorizada puede tipificar
   como delito contra la información (arts. 218 y 220 del Código Penal Federal)
   y, en datos de salud, activa obligaciones de la **LFPDPPP** y la **LGS**.
   Ningún contrato de consultoría te cubre de esa sección penal.
3. **El cliente que se siente vulnerado no renueva.** Y no se lo cuenta a ti
   solo: se lo cuenta al NIST, a la cámara, al proveedor de hosting. Un
   consultor web vive de repetibilidad; un solo «nos tocó producción a las
   3am» se convierte en tu marca. La reputación se construye con RoE.

> Regla operativa del playbook: si tienes duda de si algo está permitido,
> **no lo hagas y pregunta**. Una pregunta al cliente cuesta un email. Un
> hallazgo extra cuesta cero. Un problema legal cuesta el contrato.

---

## 1. Pasivo / OSINT (seguro)

| Herramienta | Repo / servicio | Licencia | Fase | ¿Autorización? | Uso en una línea |
|---|---|---|---|---|---|
| **theHarvester** | [github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) | GPL-2.0 | 2 | **PASIVA-SEGURO** ⚠️DNS | OSINT de subdominios y correos; la mitad de correos no se usa (spearphishing). |
| **Amass (OWASP)** | [github.com/owasp-amass/amass](https://github.com/owasp-amass/amass) | Apache-2.0 | 2 | **PASIVA-SEGURO** ⚠️DNS | Enumeración profunda de subdominios; `amass enum -passive` solo consulta terceros. |
| **subfinder** | [github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) | MIT | 2 | **PASIVA-SEGURO** ⚠️DNS | Subdominios desde ~90 fuentes pasivas (CT, buscadores, WHOIS). |
| **uncover** | [github.com/projectdiscovery/uncover](https://github.com/projectdiscovery/uncover) | MIT | 3 | **PASIVA-SEGURO** | Busca dominio/IP en Shodan, Censys, FOFA, Hunter, Netlas y Quake. |
| **dnsx** | [github.com/projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) | MIT | 3 | **PASIVA-SEGURO** ⚠️DNS | Resuelve y valida subdominios (A/AAAA/CNAME) a gran velocidad. |
| **gau** | [github.com/lc/gau](https://github.com/lc/gau) | MIT | 2, 6 | **PASIVA-SEGURO** | URLs históricas de Wayback, Common Crawl, Arquivo y OTX en un comando. |
| **waybackurls** | [github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) | MIT | 2, 6 | **PASIVA-SEGURO** | Solo Wayback: más fácil de limitar y de auditar que `gau`. |
| **katana** | [github.com/projectdiscovery/katana](https://github.com/projectdiscovery/katana) | MIT | 5 | ⚠️ **AUTORIZACIÓN REQUERIDA** | Crawler de endpoints: **pide URLs al objetivo**, no es pasivo. |
| **shodan** (lib Python) | [PyPI shodan](https://pypi.org/project/shodan/) · [achillean/shodan-python](https://github.com/achillean/shodan-python) | MIT | 3 | **PASIVA-SEGURO** | API de Shodan desde Python: hosts, DNS, certificados, InternetDB. |
| **censys** (SDK) | [github.com/censys/censys-python](https://github.com/censys/censys-python) | Apache-2.0 | 3 | **PASIVA-SEGURO** | Certificados, banners y servicios expuestos vía API. |

> **⚠️DNS: el matiz que nadie dice.** Una consulta DNS no toca el servidor web
> del cliente, pero **sí llega a su autoritativo** y queda en sus logs.
> Enumerar subdominios masivamente se ve como reconocimiento hostil, y el RoE
> de este playbook prohíbe «escanear subdominios por fuerza bruta». Regla
> práctica: DNS pasivo contra tu dominio o el de terceros, sin problema; contra
> la zona del cliente, solo con autorización que lo nombre y con ritmo
> (`dnsx -rate-limit 20`).

> **theHarvester: la mitad que no se usa.** El submódulo de correos devuelve
> buzones del dominio: es material de spearphishing. Se usa para inventariar
> subdominios; los correos se reportan como *capacidad*, nunca se prueban.

### Common Crawl: sintaxis del índice

```bash
# 1) Los IDs de índice cambian cada mes: SIEMPRE empieza por la lista.
curl -s https://index.commoncrawl.org/collinfo.json | jq -r '.[0].id'   # p.ej. CC-MAIN-2025-30

# 2) URLs de un dominio (prefijo), solo 200, deduplicadas.
curl -s "https://index.commoncrawl.org/CC-MAIN-2025-30-index?url=ejemplo.mx/*&output=json&filter=status:200&collapse=urlkey"

# 3) Afinar por tipo MIME y paginar (findings antiguos: .sql, .bak, .zip).
curl -s "https://index.commoncrawl.org/CC-MAIN-2025-30-index?url=ejemplo.mx/*&output=json&filter=mime:application/zip&showNumPages=true"
```

Parámetros que importan: `url` + `matchType` (`domain|prefix|host|exact`),
`output` (`json|csv`), `filter` (`status:`, `mime:`), `collapse`, `pageSize`,
`page`. Common Crawl es **pasivo por definición**: lees un índice, no tocas a
nadie.

---

## 2. Activo de bajo ruido (AUTORIZACIÓN REQUERIDA)

| Herramienta | Repo | Licencia | Fase | ¿Autorización? | Uso en una línea |
|---|---|---|---|---|---|
| **httpx** | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) | MIT | 3, 5 | **REQUERIDA** | Sondeo HTTP: alive, código, título, stack, TLS, CDN, IP resuelta. |
| **nuclei** | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | MIT | 6 | **REQUERIDA** (ver §2.1) | Plantillas de CVEs, misconfigs y exposición. |
| **ffuf** | [ffuf/ffuf](https://github.com/ffuf/ffuf) | MIT | 6 | **REQUERIDA** | Fuzzing de rutas y parámetros; controla con `-rate` y `-mc`. |
| **gobuster** | [OJ/gobuster](https://github.com/OJ/gobuster) | Apache-2.0 | 6 | **REQUERIDA** | Directorios y archivos por wordlist; también modo DNS. |
| **dirsearch** | [maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) | GPL-3.0 | 6 | **REQUERIDA** | Recorrido de directorios con plantillas de cientos de extensiones. |
| **feroxbuster** | [benperley/feroxbuster](https://github.com/benperley/feroxbuster) | MIT | 6 | **REQUERIDA** | Recorrido recursivo, rápido y con límite de profundidad controlable. |
| **nikto** | [sulov/nikto](https://github.com/sulov/nikto) | GPL-2.0 | 6 | **REQUERIDA** | Scanner web clásico: mucho ruido, base de checks envejecida. |
| **WhatWeb** | [urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb) | GPL-2.0 | 5 | **REQUERIDA** | Fingerprinting de stack; `--log-json` deja evidencia en JSON. |
| **wappalyzergo** | [projectdiscovery/wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) | MIT | 5 | **REQUERIDA** | Fingerprinting por firma de tecnología, sin parsear todo el body. |
| **gospider** | [jaeles-project/gospider](https://github.com/jaeles-project/gospider) | MIT | 6 | **REQUERIDA** | Crawler que extrae endpoints de JS y de formularios. |
| **arjun** | [s0md3v/Arjun](https://github.com/s0md3v/Arjun) | MIT | 6 | **REQUERIDA** | Descubre parámetros ocultos; **muy** ruidoso, solo con ventana. |
| **WPScan** | [wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) | GPL-3.0 | 5, 6 | **REQUERIDA** (ver §2.2) | Enumeración de WordPress: temas, plugins, versiones, usuarios. |

> Nota: los modos «pasivos» de varias de estas herramientas **siguen enviando
> peticiones** para fingerprintear. «Passive» en el marketing significa «no
> escanea», no «no contacta».

### 2.1 Nuclei: la herramienta más abusada del ecosistema

Nuclei es útil y es peligroso, y por eso casi siempre se usa mal: con los
valores por defecto envía **plantillas de fuzzing, DoS y headless**, con
`POST`, y a una velocidad propia. Un `nuclei -u https://cliente.mx` sin filtro
en horario laboral puede tumbar la web de una clínica un martes a las 11:00.
Eso no es un hallazgo: es un incidente de disponibilidad con tu nombre encima.

**Reglas no negociables**

| Regla | Por qué |
|---|---|
| Nunca contra el sitio de un cliente sin autorización escrita que **nombre `nuclei` explícitamente** | Un RoE genérico («haz pruebas de seguridad») no cubre un escáner de plantillas. |
| Solo `-severity high,critical` | Menos ruido y menos riesgo; lo demás ya lo chequeas tú. |
| `-exclude-tags fuzz,dos,intrusive,headless` | Las plantillas de fuzzing y DoS matan la producción. |
| `-rate-limit` bajo + `-c` bajo + `-delay` | El RoE exige ≥1 s entre peticiones. |
| Ventana acordada y cliente avisado | Aborta si sube el 5xx o la latencia. |
| Plantillas fijadas (commit/tag) | Reproducibilidad: `-t nuclei-templates@v3.x`. |
| Guardar el `.jsonl` como evidencia | Un hallazgo sin evidencia no es hallazgo. |

```bash
# Ventana autorizada 02:00-04:00, cliente avisado, con abort si sube el 5xx.
nuclei -u https://www.ejemplo.mx \
  -severity high,critical \
  -exclude-tags fuzz,dos,intrusive,headless \
  -rate-limit 20 -c 5 -delay 1 -timeout 10 -retries 1 \
  -stats -o evidencia/nuclei-hc.txt
```

Y después: **todo hallazgo de nuclei se contrasta contra la fuente primaria**
(NVD, aviso del proveedor). Un `CVE-2021-XXXX` en el `.txt` no es un hallazgo
hasta que verificas la versión instalada y la alcanzabilidad.

### 2.2 WPScan: nivel gratuito, token y `--enumerate vp`

- **Sin token** la base de datos de vulnerabilidades se corta y el uso pesado
  se bloquea; con **API token** (`WPSCAN_API_TOKEN` en el entorno o
  `--api-token`) obtienes el catálogo completo de CVEs. La diferencia práctica
  es enorme: sin token sabes *qué plugins hay*; con token sabes *que ese plugin
  tiene una CVE concreta y qué versión la corrige*.
- **`--enumerate vp`** = plugins (con sus vulnerabilidades). Combinaciones
  útiles: `--enumerate vp,vt` (plugins + temas), `--enumerate u` (usuarios).
- **Nunca** `--passwords`/`--users` con diccionario: es fuerza bruta de
  credenciales, prohibida por el RoE §1.3 y por la LFPDPPP.
- WPScan **crawlea la instalación** y sondea rutas de login: es activo, luego
  **requiere autorización**.

---

## 3. Proxy / intercepción (AUTORIZACIÓN REQUERIDA)

| Herramienta | Repo / web | Licencia | Fase | ¿Autorización? | Uso en una línea |
|---|---|---|---|---|---|
| **OWASP ZAP** (+ `zap-baseline.py`) | [github.com/zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) | Apache-2.0 | 4, 5 | **REQUERIDA** | DAST con modo pasivo (spider) y línea base reproducible. |
| **mitmproxy** | [github.com/mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) | MIT | 5 | **REQUERIDA** | Proxy programable en Python: reescribe, cronometra y automatiza peticiones. |
| **Burp Suite Community** | [portswigger.net/burp](https://portswigger.net/burp) | Propietaria (gratis con registro) | 5, 6 | **REQUERIDA** | Proxy para interceptar y manipular peticiones; el escáner no viene en Community. |

**Recomendación para un principiante: OWASP ZAP.** Tres razones: tiene GUI y
modo **pasivo** que ya genera una línea base sin atacar nada; `zap-baseline.py`
te da un **script reproducible** que va a la carpeta de evidencia; y es
Apache-2.0, sin cuenta ni licencias que gestionar. Burp es más potente pero su
versión gratuita no trae escáner y su modelo mental (proxy manual) cuesta dos
días. mitmproxy gana cuando necesitas **automatizar** transformaciones o
mediciones: es un instrumento de scripting, no de descubrimiento.

> ⚠️ Interceptar TLS exige **instalar una CA raíz** en el navegador o equipo.
> Instalar una CA en el equipo de producción del cliente es acción de alto
> impacto: aunque la quites, puede quedar en el almacén del sistema. Pide
> autorización explícita y hazlo en una máquina de pruebas, no en producción.

---

## 4. Análisis de lo ya descargado (generalmente seguro)

| Herramienta | Repo | Licencia | Fase | ¿Autorización? | Uso en una línea |
|---|---|---|---|---|---|
| **trufflehog** | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | **AGPL-3.0** | 6 | **No** (local) | Secretos en repos y filesystem, con verificación de vida opcional. |
| **gitleaks** | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT | 6 | **No** (local) | Secretos por historial de git; rápido y con pocas dependencias. |
| **LinkFinder** | [GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder) | MIT | 6 | **No** (local) | Extrae endpoints, rutas API y URLs de un JS. |
| **SecretFinder** | [maheshcode/secretfinder](https://github.com/maheshcode/secretfinder) | GPL-3.0 | 6 | **No** (local) | Variantes de regex para llaves en JS y HTML. |
| **retire.js** | [github.com/RetireJS/retire.js](https://github.com/RetireJS/retire.js) | Apache-2.0 | 2, 5 | **No** (si es local) | Cruza las librerías JS contra la tabla de CVEs. |
| **retire-site-scanner** | [github.com/RetireJS/retire-site-scanner](https://github.com/RetireJS/retire-site-scanner) | Apache-2.0 | 5 | **REQUERIDA** si escanea in situ | CLI de retire.js: sobre **copia local** es pasivo; sobre la web, activo. |

> **Honestidad sobre gitleaks.** Su propio README declara el proyecto
> *«feature-complete, security-patches-only»*: está en mantenimiento. Es
> estable y rápido, pero **ya no recibe reglas de detección nuevas**. Si
> necesitas cobertura actual, usa TruffleHog o tus propias regex. No lo
> presentes como «el escáner de secretos», sino como «escáner de secretos en
> historial de repositorio».

### La técnica que hace esto reproducible

**Descarga el JS una vez, con 1–2 s de separación; escanea la copia local.**

```bash
mkdir -p evidencia/js
for u in $(cat evidencia/urls_js.txt); do
  f="evidencia/js/$(basename "$u")"
  curl -sSL --compressed -o "$f" "$u"
  sleep 1.5                       # ritmo: RoE §2, ≥1 s entre peticiones
  sha256sum "$f" >> evidencia/js/SHA256SUMS.txt
done

# Todo lo de aquí ya no toca el origen.
python3 -m linkfinder -i evidencia/js/app.min.js -o cli -d 3
python3 scan.py evidencia/js/            # tus regex + redacción
npx retire --path evidencia/js --outputformat json --outputpath evidencia/retire.json
```

Por qué funciona así: (a) **el origen queda intacto**: solo GETs espaciados,
ya autorizados en modo pasivo; (b) **el trabajo es reproducible**: cualquiera
puede volver a correr los analizadores sobre la misma copia; (c) la **evidencia
es el artefacto** (tus `SHA256SUMS` prueban que analizaste *ese* archivo);
(d) **re-analizar es gratis y sin riesgo** — cuando actualices las reglas de
secretos, no vuelves a golpear al servidor.

---

## 5. Explotación — LAB ÚNICAMENTE

| Herramienta | Repo | Licencia | Fase | ¿Autorización? | Uso en una línea |
|---|---|---|---|---|---|
| **Metasploit** | [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework) | BSD-3-Clause (Rapid7; el API marca NOASSERTION) | Lab | **LAB ÚNICAMENTE** | Framework modular de explotación: auxiliary, payloads y sesiones. |
| **searchsploit** | [gitlab.com/exploit-database/exploitdb](https://gitlab.com/exploit-database/exploitdb) | GPL-2.0 | Lab | **LAB ÚNICAMENTE** | Busca exploits públicos por CVE o keyword, **offline**. |
| **sqlmap** | [swisskyrepo/sqlmap](https://github.com/swisskyrepo/sqlmap) | GPL-2.0 | Lab | **LAB ÚNICAMENTE** | Inyección SQL automatizada: puede leer, alterar y **escribir** datos. |
| **hydra** (THC) | [vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) | **AGPL-3.0** | Lab | **LAB ÚNICAMENTE** | Fuerza bruta de credenciales sobre servicios. |
| **john the ripper** | [openwall/john](https://github.com/openwall/john) | GPL-2.0 | Lab | **LAB ÚNICAMENTE** | Descifrado de hashes **offline** por CPU. |
| **hashcat** | [hashcat/hashcat](https://github.com/hashcat/hashcat) | MIT | Lab | **LAB ÚNICAMENTE** | Descifrado de hashes **offline** por GPU. |
| **responder** | [lanmaster53/Responder-SMB](https://github.com/lanmaster53/Responder-SMB) | GPL-3.0 | Lab | **LAB ÚNICAMENTE** | Captura y envenenamiento de hashes NTLM en la LAN. |

**Sin ambigüedad:** estas herramientas **no** son «para usar con permiso del
cliente». Lanzar `hydra` contra el login del cliente es un incidente de
seguridad, no un hallazgo; `sqlmap` puede escribir en la base de datos de
pacientes; `responder` envenena la red interna. En un informe de auditoría
ninguna puede aparecer como *prueba*.

Úsalas **solo en tu laboratorio** (DVWA, Juice Shop, Metasploitable, SpiderLab,
HackTheBox, una VM tuya) y usa lo aprendido para **redactar la mitigación**:
«su WordPress corre 5.8, hay CVE pública para esa versión, aquí está el
parche». Eso es un hallazgo. Lo otro es un delito.

**Regla sobre hashes:** `john`/`hashcat` solo contra hashes **que el cliente te
entregó por escrito y cuyo acceso documentaste**. Romper un hash encontrado en
un bucket público o en un `.env` filtrado es **de-anonimización** (RoE §1.3) y
está prohibido aunque la capacidad ya exista sin tu ayuda.

---

## 6. Librerías Python

| Librería | PyPI / GitHub | Licencia | Qué construirías con esto |
|---|---|---|---|
| **requests** | [PyPI](https://pypi.org/project/requests/) · [requests/requests](https://github.com/requests/requests) | Apache-2.0 | Cliente HTTP síncrono: descarga de JS, cabeceras, POST a tus APIs. |
| **httpx** (Python) | [PyPI](https://pypi.org/project/httpx/) · [encode/httpx](https://github.com/encode/httpx) | BSD-3-Clause | HTTP moderno sync **y** async, HTTP/2, timeouts finos. No confundir con el `httpx` de Go. |
| **aiohttp** | [PyPI](https://pypi.org/project/aiohttp/) · [aio-libs](https://github.com/aio-libs/aiohttp) | Apache-2.0 | Cliente async de alto rendimiento para barrer muchas URLs con concurrencia acotada. |
| **beautifulsoup4** | [PyPI](https://pypi.org/project/beautifulsoup4/) · [bs4](https://github.com/beautifulsoup/bs4) | MIT | Parseo de HTML: títulos, metadatos, forms, iframes, on-page. |
| **lxml** | [PyPI](https://pypi.org/project/lxml/) · [lxml/lxml](https://github.com/lxml/lxml) | BSD-3-Clause | XPath rápido y parseo de XML (sitemap.xml, robots, feeds). |
| **PyYAML** | [PyPI](https://pypi.org/project/PyYAML/) · [yaml/pyyaml](https://github.com/yaml/pyyaml) | MIT | Reglas, umbrales y findings en YAML: versionables y legibles. |
| **python-nmap** | [PyPI](https://pypi.org/project/python-nmap/) · [home-assistant-libs](https://github.com/home-assistant-libs/python-nmap) | **GPL-3.0** ⚠️ | Enviar sondeos Nmap y parsear su XML. Copyleft: ver la regla de las tres capas. |
| **dnspython** | [PyPI](https://pypi.org/project/dnspython/) · [dns/python-dnspython](https://github.com/dns/python-dnspython) | ISC en 1.x · **BSD-3-Clause desde 2.x** | Consultas DNS propias: SPF/DMARC/DKIM/CAA, conteo de lookups, resolución. |
| **shodan** | [PyPI](https://pypi.org/project/shodan/) · [achillean/shodan-python](https://github.com/achillean/shodan-python) | MIT | Automatizar Shodan: hosts, DNS, certificados, InternetDB. |
| **selenium** | [PyPI](https://pypi.org/project/selenium/) · [seleniumhq](https://github.com/seleniumhq/selenium) | Apache-2.0 | Navegador real: render de JS, capturas, auditoría on-page. |
| **playwright** | [PyPI](https://pypi.org/project/playwright/) · [microsoft/playwright](https://github.com/microsoft/playwright) | Apache-2.0 | Como Selenium pero más rápido y con **control de red**: puedes bloquear beacons a terceros. |
| **pyppeteer** | [PyPI](https://pypi.org/project/pyppeteer/) · [pyppeteer](https://github.com/pyppeteer/pyppeteer) | MIT | Alternativa ligera con Chrome DevTools; casi en desuso frente a Playwright. |
| **tenacity** | [PyPI](https://pypi.org/project/tenacity/) · [jd/tenacity](https://github.com/jd/tenacity) | Apache-2.0 | Reintentos con backoff exponencial: **clave para no martillar el servidor**. |
| **rich** | [PyPI](https://pypi.org/project/rich/) · [Textualize/rich](https://github.com/Textualize/rich) | MIT | Salida de consola con tablas y paneles: tus scripts se ven profesionales. |
| **jinja2** | [PyPI](https://pypi.org/project/Jinja2/) · [pallets/jinja2](https://github.com/pallets/jinja2) | BSD-3-Clause | Plantillas de informe: el `.md` final sale de Jinja + un YAML de findings. |
| **weasyprint** | [PyPI](https://pypi.org/project/weasyprint/) · [weasyprint](https://github.com/weasyprint/weasyprint) | BSD-3-Clause ⚠️ (arrastra Pango/cairo **LGPL-2.1**) | HTML → PDF de tu informe (el teaser) sin headless browser. |
| **matplotlib** | [PyPI](https://pypi.org/project/matplotlib/) · [matplotlib](https://github.com/matplotlib/matplotlib) | Licencia Matplotlib (BSD-like, con atribución) | Gráficas: severidad, waterfall de peso, curva de riesgo. |
| **pandas** | [PyPI](https://pypi.org/project/pandas/) · [pandas-dev](https://github.com/pandas-dev/pandas) | BSD-3-Clause | Tabla de findings, cortes por severidad, priorización ICE. |
| **networkx** | [PyPI](https://pypi.org/project/networkx/) · [networkx](https://github.com/networkx/networkx) | BSD-3-Clause | Grafo de superficie: subdominio ↔ IP ↔ servicio ↔ secreto. |
| **websockets** | [PyPI](https://pypi.org/project/websockets/) · [python-websockets](https://github.com/python-websockets/websockets) | BSD-3-Clause | Cliente WS para apps modernas y proxy simple. |
| **fake-useragent** | [PyPI](https://pypi.org/project/fake-useragent/) · [thombashi](https://github.com/thombashi/fake-useragent) | MIT | Rotar User-Agents. **No lo uses para ocultarte**: el RoE exige UA honesto y contactable. |
| **loguru** | [PyPI](https://pypi.org/project/loguru/) · [Delgan/loguru](https://github.com/Delgan/loguru) | MIT | Logging estructurado con rotación: evidencia reproducible. |
| **colorama** | [PyPI](https://pypi.org/project/colorama/) · [tonyqus](https://github.com/tonyqus/ncl-colorama) | BSD-3-Clause | Color en terminal Windows (si la sesión se ve desde un escritorio). |
| **python-dotenv** | [PyPI](https://pypi.org/project/python-dotenv/) · [python-dotenv](https://github.com/python-dotenv/python-dotenv) | BSD-3-Clause | API keys en `.env`, nunca en el código. |
| **reportlab** | [PyPI](https://pypi.org/project/reportlab/) · [reportlab](https://github.com/reportlab/reportlab) | BSD-3-Clause | PDF nativo sin dependencias del sistema; alternativa a WeasyPrint. |

### La regla de las tres capas (qué significa la licencia en la práctica)

| Cómo lo usas | Consecuencia de la licencia |
|---|---|
| **Uso interno** (tus scripts, tu pipeline, nadie más lo ve) | Sin obligaciones: no se distribuye nada. *Excepción:* AGPL §13 solo se dispara si sirves una versión **modificada** por red. |
| **Entregar scripts al cliente** (le das tu `scanner.py`) | **Importar** una librería GPL/AGPL es uso como usuario: no te obliga a licencia tu script. **Copiar/pegar** su código dentro de tu script sí: hereda la copyleft y debes entregar el fuente. |
| **Empaquetarlo en un producto de pago** (SaaS, CLI que vendes, Dockerfile) | Aquí duele: (a) **AGPL §13** — si sirves por red una versión modificada de un componente AGPL, **el cliente tiene derecho al código de esa versión**; (b) empaquetar un binario GPL/AGPL implica **ofrecer el código fuente** del componente; (c) **LGPL** (Pango/cairo vía WeasyPrint) permite distribuir, pero debes permitir que el usuario sustituya la biblioteca y cumplir los avisos. |

**El caso AGPL, sin rodeos:** *AGPL = si lo empaquetas en un producto de pago y
lo sirves por red, el cliente tiene derecho al código.* Ese es el escenario
del §13 y el motivo por el que TruffleHog y hydra (ambas AGPL-3.0) **nunca**
se vinculan en un producto propietario: se ejecutan como proceso externo, y tu
informe no es obra derivada de ellos.

| Componente | Licencia | Riesgo al empacar |
|---|---|---|
| python-nmap | GPL-3.0 | Si lo empaquetas, **ofrece su fuente**; si lo vinculas, el derivado va a GPL. |
| weasyprint (+ Pango/cairo) | BSD-3-Clause + LGPL-2.1 | WeasyPrint es permisiva; el LGPL de Pango/cairo exige permitir la sustitución del componente (binarios dinámicos + avisos). |
| TruffleHog / hydra (herramientas) | AGPL-3.0 | Prohibido integrarlos en un SaaS o producto modificado. |
| Todo lo demás de la tabla | Apache-2.0 / BSD / MIT / ISC | Uso comercial libre; conserva los avisos de licencia al redistribuir. |

---

## 7. Construye tus propias — 4 herramientas

Lo que te diferencia de un escáner más es el software propio: sale con tu
metodología, tu severidad y tu formato. Estas cuatro cubren el 80% de un
sitio SMB.

### 7.1 Auditor de posture HTTP + TLS (`http_posture`)

| | |
|---|---|
| **Qué hace** | Una URL entra; sale un **reporte puntuado**: cabeceras de seguridad, cookies, TLS, redirecciones, CORS, mixed content, `security.txt`. |
| **Input** | `python -m http_posture https://www.ejemplo.mx --rate 1 --json out.json` (o una lista por stdin). |
| **Output** | `posture.json` + `posture.md` (Jinja2) + exit code por severidad máxima. |
| **Arquitectura** | `cli.py` (argparse) · `http_probe.py` (httpx: una conexión, cadena TLS, redirects) · `checks/` (`headers.py`, `cookies.py`, `tls.py`, `cors.py`, `redirects.py`) · `scoring.py` (peso por control y por negocio) · `report.py` · `rules/policy.yaml` (umbrales versionados). |
| **Librerías** | `httpx`, `PyYAML`, `Jinja2`, `rich`, `tenacity`. |
| **Testing** | Cada control es una **función pura** `(respuesta, policy) -> Finding`, testeable sin red. Fixtures `tests/fixtures/site_bueno/` y `site_malo/` servidos por un estático local; lo que sí pega al objetivo va marcado `@pytest.mark.network` y solo corre con `-m network`. |

### 7.2 Enumerador de subdominios + CT (`subenum`)

| | |
|---|---|
| **Qué hace** | crt.sh + Wayback + DNS pasivo → normaliza → resuelve CNAME → **detecta candidatos a *subdomain takeover*** y los reporta **sin tocar el servicio**. |
| **Input** | `python -m subenum ejemplo.mx --out evidencia/subenum` |
| **Output** | `subs.txt`, `subs.json` (con origen: crt.sh / CT / pasivo), `takeover_candidates.csv`. |
| **Arquitectura** | `cli.py` · `sources/` (`crtsh.py`, `wayback.py`) · `normalize.py` (wildcards `*.dev.x` → `dev.x`, punycode, dedupe) · `resolve.py` (dnspython: cadena CNAME) · `takeover.py` (fingerprints por servicio, en YAML) · `graph.py` (networkx) · `report.py`. |
| **Librerías** | `httpx`, `dnspython`, `PyYAML`, `networkx`, `rich`, `tenacity`. |
| **Testing** | Fixtures con respuestas **grabadas** de crt.sh (`tests/fixtures/crtsh/*.json`); DNS con un autoritativo local de prueba o monkeypatch de `resolve()`; test de normalización de wildcards; fingerprints contra un catálogo YAML congelado. |

> **Por qué NO debes tomar el control del subdominio abandonado.** Es el
> ejemplo perfecto de *unethical overreach*: demostrar el takeover exige
> **reclamar** un recurso del cliente (o de su proveedor) sin su
> autorización; en ese momento tú eres el atacante que acabas de describir, y
> en nombre propio. Lo correcto es documentar: *«dev.ejemplo.mx → CNAME a un
> recurso liberado en Heroku; un tercero podría reclamarlo»*, con la
> remediación **reclamar o eliminar el registro DNS**. El riesgo se reporta;
> la capacidad no se ejecuta.

### 7.3 Escáner de secrets/API keys en JS (`jssecrets`)

| | |
|---|---|
| **Qué hace** | Descarga el JS (con ritmo), extrae endpoints y llaves, y **redacta antes de reportar**: nunca escribe la llave completa en el informe. |
| **Input** | `python -m jssecrets https://www.ejemplo.mx --sleep 1.5 --out evidencia/secrets` |
| **Output** | `secrets.json` (redactado: prefijo + sha256[:12]), `endpoints.txt`, `evidence/js/` (copia local + `SHA256SUMS`). |
| **Arquitectura** | `cli.py` · `fetcher.py` (ritmo, caché, hash del contenido) · `extract/endpoints.py` · `extract/secrets.py` (regex + validadores: AWS `AKIA`, Google `AIza`, Stripe `sk_live`, Slack `xox`, JWT, claves privadas) · `redact.py` · `report.py` · `rules/secrets.yaml`. |
| **Librerías** | `httpx`, `re` y `hashlib` (stdlib), `PyYAML`, `rich`, `jinja2`. |
| **Testing** | Fixtures con JS sintéticos que contienen llaves **de formato válido pero valor inventado** (jamás llaves reales en el repo). Test clave: `assert secret not in output`. Test de falsos positivos con placeholders (`YOUR_API_KEY_HERE`). Test de idempotencia: dos corridas → mismo hash de evidencia. |

> Si el secreto es real, se reporta **al cliente** (es su credencial) y se le
> pide rotarla. El auditor **no lo usa** para autenticarse ni para validar
> que funciona: RoE §1.3.

### 7.4 Checker de posture DNS + autenticación de correo (`mailposture`)

| | |
|---|---|
| **Qué hace** | Parsea **SPF con conteo de lookups** (límite **10** de RFC 7208 §4.6.4), enumera **selectores DKIM** candidatos, revisa **política DMARC** (`p=`, `rua`/`ruf`, `adkim`/`aspf`, `sp`), presencia y política de **BIMI**, **MTA-STS** y **CAA**. |
| **Input** | `python -m mailposture ejemplo.mx --out evidencia/mail` |
| **Output** | `mail_posture.json` + `mail_posture.md` (tabla: control, estado, severidad, remediación). |
| **Arquitectura** | `cli.py` · `dns_client.py` (dnspython: TXT/CNAME; **varios resolvers** — 1.1.1.1, 8.8.8.8 y el autoritativo — porque un NXDOMAIN puede ser caché o filtrado) · `spf.py` (parser: `include`, `a`, `mx`, `ptr`, `exists`, `redirect`; cuenta lookups y detecta `+all`) · `dkim.py` (selectores: `default`, `google`, `selector1/2`, `k1`, `mail`, `s1/s2`) · `dmarc.py` · `bimi.py` · `mta_sts.py` · `caa.py` · `scoring.py` · `report.py`. |
| **Librerías** | `dnspython`, `PyYAML`, `jinja2`, `rich`, `tenacity`. |
| **Testing** | El parser de SPF es **función pura sobre strings**: fixtures con SPF de 10 lookups, `+all`, `~all`, `?all`, `redirect` anidado y `v=spf1` malformado. Tests de DMARC válido/inválido y de `rua` externo. Integración marcada `network` contra un dominio de prueba. |

### Estructura de carpetas sugerida (las cuatro)

```
herramienta/
├── pyproject.toml            # deps fijadas, sin "latest"
├── src/<paquete>/            # cli.py, checks/, sources/, extract/, rules/
├── rules/                    # YAML de umbrales y severidades  (versionado)
├── tests/
│   ├── fixtures/             # HTML, JSON, TXT, JS  grabados
│   ├── test_<control>.py     # unitarios sin red
│   └── conftest.py           # marca 'network' y helpers de servidor local
└── README.md                 # qué hace, qué NO hace y en qué tier cae
```

Regla: **cada control de scoring es una función pura con su test**, y la
fixture es un archivo en disco, nunca una llamada en vivo. La red solo entra en
la capa de *fetches*, y esa capa se puede desligar para reproducir el análisis.

---

## 8. Cómo formarte (y qué comprar primero)

**No todo se necesita al inicio.** La trampa del consultor es instalar 40
herramientas y no saber ninguna. Este es el orden real de aprendizaje:

| Etapa | Instala / aprende | Por qué en este orden |
|---|---|---|
| **Día 1–2** | `curl`, `dig`, `openssl s_client`, `httpx`/`requests`, crt.sh, Wayback | Es el 70% de los hallazgos de un sitio SMB: cabeceras, TLS, DNS, subdominios. Nada de esto pide autorización. |
| **Semana 1** | Tus 4 scripts propios (§7) | Te dan un método, no una caja negra. El auditor de posture va primero: es la base de cualquier informe. |
| **Semana 2** | ZAP, mitmproxy, `retire.js`, `LinkFinder`, tus reglas de secretos | Cubren superficie y JavaScript; `retire.js` sobre copia local, sin riesgo. |
| **Mes 1** | `uncover` + API key de Shodan/Censys, `nuclei` **con autorización**, WPScan con token | Los activos solo cuando el RoE los ampara. |
| **Mes 2+** | Fuzzing (`ffuf`/`feroxbuster`) y un laboratorio propio | Ruido alto: solo cuando ya sabes qué buscas y el cliente lo pide. |

| Presupuesto | Qué alcanza | Qué te falta |
|---|---|---|
| **$0** | Todo lo pasivo + tus scripts + Burp/ZAP Community + `DVWA`/`Juice Shop` en local. | Un VPS barato para practicar proxy fuera de tu red. |
| **~$30–50/mes** | API key de Shodan o Censys; token de WPScan; un VPS con laboratorio y un dominio de pruebas. | Nada bloqueante. La inversión que más retorno da. |
| **~$200/mes** | Burp Pro, proxy remoto si viajas, más entornos. | Solo si lo **cobras** al cliente. |

**Opcional hasta que tengas 2–3 clientes:** fuzzing agresivo, escaneo de
puertos, proxies interceptores en sesiones autenticadas, frameworks de
explotación — todo lo que «golpea» el servidor. **No vale la pena todavía:**
comprar Burp Pro antes de tener el flujo de trabajo, montar un pipeline de 40
herramientas, un «scanner de IA» para el informe antes de tener el método, o
un homelab enorme en vez de un laboratorio de una sola VM.

**La regla de oro del playbook:** toda herramienta nueva entra al
[manifiesto](../01-tooling/manifiesto-de-herramientas.md) con su **etiqueta de
autorización**, su licencia y su fase. Si no puedes defender esa etiqueta en
una reunión con el cliente, **no la instalas**.
