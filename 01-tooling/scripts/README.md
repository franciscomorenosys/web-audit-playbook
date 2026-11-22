# Tooling de auditoría — scripts del playbook

Herramientas propias para la fase técnica de una auditoría web de **consultoría
en México**, con sitios que manejan datos sensibles de pacientes.

Todas son **Python 3.13 de biblioteca estándar** (cero `pip install`, cero
dependencias externas) y todas corren en macOS sin configuración.

---

## ⚠️ Aviso legal y de alcance

> **Estas herramientas sólo se usan contra objetivos con autorización escrita y
> RoE firmado.**
>
> Sin RoE firmado no se empieza. La metodología que gobierna este toolkit está
> en `../../00-metodologia/reglas-de-autorizacion-y-roe.md`. En resumen:
>
> * Sólo `GET` y `HEAD`. **Nunca** `POST`, `PUT`, `PATCH` ni `DELETE`.
> * ≥ 1 segundo entre peticiones y User-Agent honesto y contactable.
> * Nada de fuerza bruta, fuzzing masivo ni escaneo de puertos.
> * No se recolectan datos personales: todo lo que sale del escritorio del
>   auditor va redactado o enmascarado.
> * Lo que pertenece a terceros se **describe**, no se ataca.
>
> El uso de estas herramientas sin autorización es un delito en México (Ley
> Federal de Protección de Datos Personales en Posesión de los Particulares y
> Código Penal, Título IX) y en la mayoría de las jurisdicciones. Si tienes
> dudas sobre si una prueba está permitida: no la hagas y pregunta. Una
> pregunta al cliente cuesta un correo; un problema legal cuesta el contrato.

---

## Flujo de trabajo completo

```
     1. AUTORIZACIÓN                2. RECON (pasivo)          3. SONDAS (GET/HEAD)
   ┌─────────────────────┐        ┌──────────────────┐        ┌──────────────────────┐
   │ RoE firmado         │──────▶ │ crt.sh, Wayback, │──────▶ │ scope_guard.py       │
   │ + authorization.json│        │ InternetDB, DNS  │        │ probe_exposure.py    │
   └─────────────────────┘        └──────────────────┘        └──────────┬───────────┘
                                                                          │
   6. INFORME                    5. REDACCIÓN             4. ANÁLISIS LOCAL │
   ┌─────────────────────┐      ┌──────────────────┐      ┌──────────────────┐
   │attack_surface_report│◀─────│ pii_redact.py    │◀─────│ secrets_scan.py   │
   │      .py            │      │ (evidencia)      │      │ js_intel.py       │
   └─────────────────────┘      └──────────────────┘      │ header_tls_report │
                                                          └──────────────────┘
```

Paso a paso:

| # | Paso | Comando | Qué produce |
|---|------|---------|-------------|
| 0 | **Autorización** | (manual) | `authorization.json` firmado + RoE archivado |
| 1 | **Recon pasivo** | (herramientas de terceros) | `crt.json`, `dns_mailsec.txt`, `tls_versions.txt`, `internetdb.json` |
| 2 | **Sonda de exposición** | `python3 probe_exposure.py -a auth.json --host www.clinica.mx --out evidencia/` | `evidencia/probe_exposure.tsv`, `.json`, cuerpos seguros |
| 3 | **Cabeceras** | `curl -sS -D evidencia/headers.txt -o /dev/null -A "$UA" https://www.clinica.mx/` | `evidencia/headers.txt` |
| 4 | **Secretos** | `python3 secrets_scan.py ./evidencia --json --out evidencia/secrets.json` | `evidencia/secrets.json` |
| 5 | **Intel de JS/HTML** | `python3 js_intel.py ./evidencia --json-out evidencia/js_intel.json --base-host clinica.mx` | `evidencia/js_intel.json` + informe Markdown |
| 6 | **Cabeceras de seguridad** | `python3 header_tls_report.py evidencia/headers.txt --out evidencia/header_tls.md` | `evidencia/header_tls.md` |
| 7 | **Redacción** | `python3 pii_redact.py ./evidencia-cruda --out-dir ./evidencia-sanitizada --report evidencia/redaccion.json` | copia redactada + informe de conteos |
| 8 | **Score** | `python3 attack_surface_report.py --probe-tsv evidencia/probe_exposure.tsv --secrets-json evidencia/secrets.json --headers evidencia/headers.txt --out informe/` | `informe/attack_surface_report.md` + `.json` |

> **Orden importante:** el paso 7 (redacción) va **antes** de compartir
> cualquier evidencia con el cliente o con un tercero. El paso 8 puede leer
> tanto la evidencia cruda como la redactada.

---

## Los scripts

### `scope_guard.py` — la única puerta a la red

Núcleo compartido. Carga un fichero de **autorización firmada** y valida cada
URL antes de tocarla.

* Comprueba la **ventana de validez** (`valid_from` / `valid_to`).
* Comprueba que el **host** case con la lista `hosts` (admite comodines
  `*.ejemplo.mx`). Si no casa → **aborta** (nunca «advierte y sigue»).
* Recorta los métodos a `GET`/`HEAD` aunque el fichero liste otros (RoE 1.1).
* Impone el intervalo mínimo entre peticiones (suelo de **1 s**, aunque el
  fichero pida menos) y un **User-Agent honesto** (`ClientSecurityAudit/1.0`).
  Un `user_agent` que suplante un navegador es **rechazado**.
* Limita los bytes leídos (`max_bytes`), aplica timeout y **no sigue
  redirecciones fuera del allowlist**.

```bash
# Validar sin hacer la petición
python3 scope_guard.py --authorization auth.json --check https://www.ejemplo.mx/ruta

# Validar y hacer un GET acotado
python3 scope_guard.py --authorization auth.json --probe https://www.ejemplo.mx/ruta

# Ver los hosts autorizados
python3 scope_guard.py --authorization auth.json --list-hosts --json
```

Códigos de salida: `0` correcto · `1` violación de alcance o error de red ·
`2` error de configuración (fichero ausente, inválido o **sin firma**).

### `probe_exposure.py` — sonda de exposición

Recorre una lista **fija y corta** de 53 rutas conocidas (`.env`, `.git/HEAD`,
backups, `wp-config.php.bak`, `phpinfo.php`, `actuator/env`, paneles de
administración, documentación de API…) contra los hosts autorizados.

* Sólo `GET` (`--head` para HEAD).
* **Nunca guarda el cuerpo** de las rutas sensibles. Sólo se almacenan los
  cuerpos de `robots.txt`, `sitemap.xml` y `security.txt` (y los que se pidan
  con `--also-store`).
* **Detecta soft-404**: pide una ruta 404 de referencia y compara el `sha256`.
  Si la respuesta tiene el mismo cuerpo, se marca `soft_404` y **no cuenta como
  exposición**. Sin esto, cualquier sitio que devuelva la misma página de error
  para todo generaría cientos de falsos positivos.
* Sale en **TSV** (`host path code content_type length sha256 soft_404 verdict
  severity`), en `--json`, y deja el fichero de evidencia en `--out`.

```bash
python3 probe_exposure.py -a auth.json --host www.ejemplo.mx --out evidencia/
python3 probe_exposure.py -a auth.json --host www.ejemplo.mx --dry-run   # plan, sin red
python3 probe_exposure.py -a auth.json --host www.ejemplo.mx --path-list rutas.txt
python3 probe_exposure.py -a auth.json --host 127.0.0.1 --scheme http --port 8801  # pruebas locales
```

### `secrets_scan.py` — escaneo local de secretos

Recorre ficheros locales (repos, HTML/JS descargados, configuración) buscando
AWS, Google/Firebase, service accounts, Stripe, OpenAI, Anthropic, GitHub,
GitLab, Slack, Discord, Twilio, SendGrid, Mailgun, Sentry, Mapbox, JWTs, claves
privadas (RSA/EC/PKCS8/OpenSSH), URIs con credenciales, `_authToken` de npm,
`.pypirc`, tokens genéricos y webhooks.

* **Nunca escribe el valor completo**: sólo `4 primeros + 2 últimos` y el
  `sha256[:12]`, para poder correlacionar sin revelar.
* El **contexto** también se raspa: se vuelven a redactar todos los secretos que
  aparezcan en la línea mostrada.
* `--min-entropy` filtra los falsos positivos de las reglas genéricas.
* `--ignore` excluye rutas; respeta el `.gitignore` básico y salta
  `node_modules`, `.venv`, `__pycache__`, `.git`, etc.
* `--redact-in-place` escribe una **copia** redactada (el original nunca se
  sobrescribe).
* **Allowlist de secretos sintéticos.** Al escanear un **directorio**, el
  script lee el `.gitleaks.toml` de esa raíz (la misma lista que usa Gitleaks
  en la CI) y no reporta los valores que ahí estén declarados como ficticios:
  los de los fixtures de prueba y los del ejercicio de formación. Un hallazgo
  se descarta si **la ruta** del fichero casa con `paths` **y el valor** casa
  con alguno de los `regexes`. `--no-allowlist` desactiva ese comportamiento y
  `--allowlist FICHERO` apunta a otra lista.

```bash
python3 secrets_scan.py ./mi-repo
python3 secrets_scan.py ./evidencia --json --out evidencia/secrets.json
python3 secrets_scan.py ./evidencia --min-entropy 3.5 --ignore '*.lock'
python3 secrets_scan.py ./evidencia --redact-in-place --redact-out ./copia
python3 secrets_scan.py . --fail-on alto          # falla si aparece algo real
```

### `js_intel.py` — inteligencia de HTML/JS

Análisis estático (sin red) de los ficheros ya descargados:

* endpoints de API absolutos y relativos (extraídos de `fetch`, `axios`,
  `$.ajax`, `url:`, `XMLHttpRequest.open`, cadenas que parecen rutas);
* rutas administrativas o sensibles;
* **hosts de terceros**, clasificados (analítica, CDN, pagos, mapas, fuentes,
  formularios, citas, correo, redes sociales, soporte) — la pregunta de fondo es
  *¿a dónde salen los datos del navegador del paciente?*;
* operaciones GraphQL;
* `//# sourceMappingURL=`;
* `<script src>` y `<link href>`, con la comprobación de **SRI**
  (`integrity=`) y `crossorigin`;
* secretos en scripts *inline* (reutiliza los patrones de `secrets_scan.py`).

```bash
python3 js_intel.py ./evidencia/home.html
python3 js_intel.py ./evidencia/ --base-host clinica.mx --json-out evidencia/js_intel.json
```

### `header_tls_report.py` — informe de cabeceras

Analiza **volcados de cabeceras ya guardados** (`curl -D`, `httpx -D`). No hace
ninguna petición.

* CSP (parseando directivas: `default-src`, `script-src`, `unsafe-inline`,
  `unsafe-eval`, `object-src`, `base-uri`, `frame-ancestors`,
  `upgrade-insecure-requests`).
* HSTS (`max-age`, `includeSubDomains`, `preload`).
* `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy`, `COOP`/`COEP`/`CORP`, `X-XSS-Protection` (obsoleta: se
  recomienda retirarla).
* Cookies: `Secure`, `HttpOnly`, `SameSite`, prefijos `__Host-`/`__Secure-`.
* Fuga de información: `Server`, `X-Powered-By`, `X-AspNet-Version`,
  `X-Runtime`, `Via`.
* Caché: `Cache-Control`, `Vary`, `Age`, `X-Cache`, coherencia `http://` vs
  `https://`.
* CORS: `ACAO: *` con credenciales, origen `null`, `Vary: Origin` ausente.

Salida: informe **Markdown** con tabla `check | valor | severidad | remediación`
(+ `--json`).

```bash
python3 header_tls_report.py evidencia/headers.txt --out evidencia/header_tls.md
```

### `pii_redact.py` — el guardián de los datos

Redacta PII de ficheros de texto/JSON/HTML:

* emails, teléfonos (MX/ES/US), RFC/NIF/DNI/NIE/CUIT, IPs (`--keep-ips` para no
  tocarlas), tarjetas **validadas con Luhn**, fechas de nacimiento, códigos
  postales y URLs con credenciales;
* claves JSON/HTML con nombres típicos de dato personal o clínico (`nombre`,
  `apellido`, `nombre_paciente`, `telefono`, `email`, `direccion`,
  `diagnostico`, `expediente`, `fecha_nacimiento`, `curp`, `rfc`, `nss`,
  `paciente`, `patient`, `dob`, `ssn`, `address`, `phone`…).

**El formato se preserva**: un JSON redactado sigue siendo JSON válido y
parseable; el HTML sigue siendo HTML. El informe sólo contiene **conteos por
categoría**, nunca valores.

```bash
python3 pii_redact.py evidencia-cruda/ --out-dir evidencia-sanitizada --report informe.json
python3 pii_redact.py notas.txt --keep-ips --extra-key "numero_seguro"
```

### `attack_surface_report.py` — Attack Exposure Score

Agrega la evidencia local y calcula un índice **0-100** en cinco bandas
(Bajo / Moderado / Alto / Crítico / Severo), con el desglose de la fórmula.

Componentes (con su peso): secretos expuestos, ficheros de backup/config
expuestos, versiones de stack, ausencia de CDN/WAF, amplitud de subdominios,
puertos administrativos, ausencia de MFA (deducida), ausencia de
logging/monitorización, ausencia de DMARC, ausencia de CSP/HSTS, CORS
permisivo, TLS obsoleto y cookies inseguras. **Bonificación** por lo que está
bien: cookies seguras, TLS fuerte, SRI presente, cabeceras completas, DMARC
activo y ausencia de secretos críticos.

**Regla dura:** sin datos, el componente vale **0** y se marca `sin datos`. Cada
línea del informe lleva su fuente (`evidencia: <fichero>`). Si no hay ninguna
evidencia, la banda es *No evaluable*: un 0 sin datos **no** significa
«seguro».

```bash
python3 attack_surface_report.py \
    --probe-tsv evidencia/probe_exposure.tsv \
    --secrets-json evidencia/secrets.json \
    --headers evidencia/headers.txt \
    --dns-mailsec evidencia/dns_mailsec.txt \
    --tls-versions evidencia/tls_versions.txt \
    --crtsh evidencia/crt.json \
    --out informe/
```

---

## El flujo de autorización

`scope_guard.py` y `probe_exposure.py` **no hacen nada** sin un fichero de
autorización. Plantilla en [`authorization.example.json`](./authorization.example.json):

```json
{
  "authorization_ref": "ROE-2026-001",
  "client": "Clínica Ejemplo SA de CV",
  "signed_by": "Dirección de Sistemas — Clínica Ejemplo (firma en RoE firmado)",
  "signed_at": "2026-01-15T10:00:00Z",
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_to": "2026-12-31T23:59:59Z",
  "hosts": ["ejemplo-auditoria.mx", "*.ejemplo-auditoria.mx"],
  "allowed_methods": ["GET", "HEAD"],
  "max_bytes": 1048576,
  "min_interval_s": 1.0,
  "timeout_s": 20,
  "user_agent": "Mozilla/5.0 (compatible; ClientSecurityAudit/1.0; +https://ejemplo-auditoria.mx)"
}
```

Campos obligatorios: `authorization_ref`, `client`, `signed_by`, `signed_at`,
`valid_from`, `valid_to` y `hosts` (lista no vacía). Si falta cualquiera de
ellos —incluida la firma— el script **falla con código 2** y no hace ninguna
petición.

Notas de diseño:

* El comodín `*.ejemplo.mx` cubre **cualquier subdominio** pero **no** el ápex:
  si también se va a auditar `ejemplo.mx`, hay que listarlo explícitamente.
* `allowed_methods` se **recorta** a `GET`/`HEAD` aunque el fichero liste
  `POST`: la restricción es del RoE, no del cliente.
* `min_interval_s` se eleva al suelo de **1 s** aunque el fichero pida menos.
* `user_agent` debe seguir identificando a la auditoría: un UA que suplanta
  Chrome/Safari es rechazado.

---

## Auto-prueba

```bash
cd 01-tooling/scripts
python3 tests/selftest.py
```

14 checks, **sin ninguna llamada de red** (uno de ellos bloquea `socket` para
comprobarlo). Cubre: detección de secretos sin filtrar valores, redacción de
PII con JSON válido, HSTS ausente, host no autorizado rechazado, host
autorizado aceptado, autorización sin firma rechazada, `POST` descartado,
sonda que no sale del allowlist, extracción de JS, y el score con su fuente.

Código de salida `0` si todo PASS, `1` si algún check falla.

---

## Limitaciones conocidas

* **Sin base de datos de CVEs.** El componente de «versiones de stack» puntúa
  por **antigüedad**, no por CVE verificado. Hay que contrastarlo con el NVD y
  con la versión real del servidor.
* **Sin NER.** `pii_redact.py` no detecta nombres de personas en texto libre
  (no hay modelo de lenguaje en la stdlib): los nombres sólo se redactan cuando
  van en una clave JSON con nombre típico o cuando el patrón es inequívoco
  (RFC, CURP, email, teléfono, tarjeta).
* **Teléfonos sin separadores.** Un número en formato E.164 sin guiones ni
  espacios (`5215555555555`) es indistinguible de un NSS o de un número de
  factura: **no** se redacta en texto libre (sí en claves JSON como
  `telefono` o `whatsapp`). Las tarjetas sólo se redaccionan si pasan Luhn
  **y** llevan separadores o contexto explícito (`tarjeta`, `visa`, `cc`…), para
  no destrozar un teléfono que casualmente cumple Luhn.
* **Sobre-redacción de 11 dígitos.** El patrón de CUIT/identificador puede
  coincidir con un número de 11 cifras que no lo sea (folio, factura). Se
  prefiere redactar de más: el coste de un dato de más es menor que el de un
  dato de paciente en la evidencia.
* **Soft-404 por `sha256` exacto.** Si el servidor devuelve el mismo 404 con
  diferencias de espaciado o de contenido dinámico, la comparación falla y
  aparece como falso positivo. Es el trade-off de no hacer *fuzzy* matching.
  La referencia se pide una vez por host (una petición extra) y sirve para los
  dos casos: 404 real y *catch-all* que devuelve 200 con la página de error.
* **CORS: origen reflejado.** Con un solo volcado de respuesta **no** se puede
  distinguir un allowlist estático de un `Origin` reflejado sin ver la petición.
  El informe lo marca como pendiente de verificación en lugar de afirmarlo.
* **Deteción de CDN/WAF por cabeceras.** Un WAF que no firme sus respuestas no
  se detecta. La ausencia de firma **no** es prueba de ausencia de WAF.
* **MFA deducida, nunca verificada.** La puntuación de MFA se deduce de la
  superficie de login; hay que confirmarla con el cliente.
* **`allowed_methods` no amplía el RoE.** Está en el formato por
  trazabilidad, pero el recorte a `GET`/`HEAD` es fijo.

---

## Referencias

* `../../00-metodologia/reglas-de-autorizacion-y-roe.md` — doctrina y RoE.
* `../../00-metodologia/ciclo-de-auditoria.md` — fases de la auditoría.
* `../../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md` — RoE relleno.
* `../manifiesto-de-herramientas.md` — catálogo de herramientas de terceros.
