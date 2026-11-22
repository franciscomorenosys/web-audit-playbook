# Guía de formación del auditor

**Cómo se ejecuta este playbook sin repetir los errores del caso de referencia.**

Este documento es el **libro de formación** del playbook. No es la referencia
operativa: la referencia operativa está en
[`../00-metodologia/`](../00-metodologia/) y en
[`../01-tooling/scripts/README.md`](../01-tooling/scripts/README.md). Aquí se
aprende **a hacer el trabajo**, no a leer el manual de la máquina.

> **Para quién:** el auditor que va a firmar su primer RoE y su primera
> auditoría de principio a fin, con supervisión.
> **Qué la distingue del resto del playbook:** es la única parte del repositorio
> que se lee **en orden**. Todo lo demás se consulta.

**Cómo se relaciona con el resto del repositorio:**

| Si quieres… | Ve a |
|---|---|
| La doctrina de seguridad y la plantilla de RoE | [`../00-metodologia/reglas-de-autorizacion-y-roe.md`](../00-metodologia/reglas-de-autorizacion-y-roe.md) |
| Las 11 fases del ciclo y las dos lecciones duras | [`../00-metodologia/ciclo-de-auditoria.md`](../00-metodologia/ciclo-de-auditoria.md) |
| El protocolo de prueba sin daño (Fase 2) | [`../00-metodologia/fase-2-explotacion-autorizada.md`](../00-metodologia/fase-2-explotacion-autorizada.md) |
| Secretos, credenciales y PII | [`../00-metodologia/exposicion-de-secretos.md`](../00-metodologia/exposicion-de-secretos.md) |
| Qué se puede decir sobre ataques | [`../00-metodologia/exposicion-a-ataques.md`](../00-metodologia/exposicion-a-ataques.md) |
| Severidad, ICE y las tres capas del informe | [`../00-metodologia/como-presentar-resultados.md`](../00-metodologia/como-presentar-resultados.md) |
| Cómo se convierte esto en un negocio | [`../00-metodologia/modelo-de-servicio-y-escalabilidad.md`](../00-metodologia/modelo-de-servicio-y-escalabilidad.md) |
| Los scripts y sus límites | [`../01-tooling/scripts/README.md`](../01-tooling/scripts/README.md) |
| Dónde practicar sin riesgo | [`01-lab-seguro.md`](01-lab-seguro.md) |
| Qué herramientas existen y contra quién | [`02-herramientas-y-python.md`](02-herramientas-y-python.md) |
| Contratar, Cobrar y el marco legal de México | [`03-modelo-de-negocio-y-legal-mx.md`](03-modelo-de-negocio-y-legal-mx.md) |

---

## 1. Para quién es esta guía y qué NO es

### 1.1 El perfil de entrada: qué se supone que ya sabes

| Área | Lo que se supone | Por qué hace falta |
|---|---|---|
| **HTTP** | Qué es un método (`GET`, `HEAD`, `POST`), qué es un código de estado, qué es una cabecera de respuesta, qué es una redirección | Toda la evidencia del playbook son respuestas HTTP. Sin esto no se sabe leer un volcado de cabeceras |
| **Línea de comandos** | Ejecutar un comando, leer su salida, encadenar con `\|`, grep de un fichero, mover ficheros | La toolchain es `python3 script.py …` y `curl`; el trabajo real es leer lo que devuelven |
| **JSON y TSV** | Abrir un JSON, entender una lista de objetos, leer un TSV con cabecera | `secrets.json`, `js_intel.json`, `probe_exposure.tsv` son la materia prima del informe |
| **El navegador como inspector** | Abrir las herramientas de desarrollo, ver la pestaña Network y la pestaña Sources | Es el equivalente gráfico de la Fase 0: ves el HTML y el JS que se sirven |
| **Qué es una API y un endpoint** | Que una ruta devuelve datos y que puede requerir sesión | Toda la capa de superficie de API |
| **HTML y JS básicos** | Saber qué es un `<script src>`, un `<form>`, un `fetch()` | Es la materia prima del análisis de secretos y de endpoints |

**Lo que NO hace falta saber para empezar:** pentest, autenticación, inyección
SQL, XSS, bcrypt, redes, Linux avanzado, o cualquier framework de seguridad.
Nada de eso se necesita para los módulos M0–M3, que son donde se decide si el
trabajo va a ser correcto o un incidente.

### 1.2 Lo que hay que tener resuelto antes de la primera auditoría

| # | Requisito | Por qué |
|:-:|---|---|
| 1 | **Energía y tiempo para 3–5 días** de trabajo concentrado por auditoría | El playbook no se ejecuta «un rato». La Fase 0 son 10–18 h y la Fase 1, 20–35 h de carga estimadas (orientativas) |
| 2 | **Un laboratorio propio** | Toda la práctica se hace contra [`01-lab-seguro.md`](01-lab-seguro.md). Practicar contra un sitio ajeno es un delito, no una práctica |
| 3 | **Python 3.13** y la toolchain del playbook ejecutándose | `python3 tests/selftest.py` debe dar 19/19 antes de la primera petición real |
| 4 | **Una carpeta de trabajo cifrada** para la evidencia cruda | La evidencia cruda puede contener datos de pacientes. Sale de tu disco redactada o no sale |
| 5 | **Un seguro de responsabilidad civil profesional** | Ver [`../00-metodologia/modelo-de-servicio-y-escalabilidad.md`](../00-metodologia/modelo-de-servicio-y-escalabilidad.md) §4.c. No es un requisito legal comprobado aquí: es un **requisito de credibilidad** ante un cliente de salud |
| 6 | **Un mentor disponible** | El plan de la §7 presupone que hay alguien que revise tu trabajo antes de que salga del escritorio |

### 1.3 Qué NO es esta guía

Esto es tan importante como lo que sí es:

| No es… | Por qué no |
|---|---|
| **Un curso de hacking** | No enseña a gainedar acceso, a persistir, a moverse lateralmente ni a escalar privilegios. Todo lo que el playbook hace de eso es **describirlo, no ejecutarlo** |
| **Un tutorial de exploits** | Las seis técnicas de Fase 2 son seis pruebas acotadas con condiciones, tiempos y criterios de abort. No hay payloads reutilizables aquí, y no debe haberlos: la metodología está en [`../00-metodologia/fase-2-explotacion-autorizada.md`](../00-metodologia/fase-2-explotacion-autorizada.md), no en unos comandos |
| **Un sustituto de la autorización** | **Nada** de lo que se lee aquí habilita una sola petición. El habilitador es el RoE firmado. Esta guía explica cómo llegar hasta ese RoE, no cómo prescindir de él |
| **Una asesoría legal** | El marco legal que se cita es **orientación operativa** y va marcado **NO VERIFICADO** donde no se ha leído la fuente primaria. La estrategia legal la decide el abogado del cliente |
| **Una sustituta del RoE** | El RoE es un documento firmado por tres partes con fechas, hosts y técnicas. Ningún documento de este repositorio lo reemplaza |
| **Un curso de negocio** | Cobro, precios y escalabilidad están en [`03-modelo-de-negocio-y-legal-mx.md`](03-modelo-de-negocio-y-legal-mx.md) y en [`../00-metodologia/modelo-de-servicio-y-escalabilidad.md`](../00-metodologia/modelo-de-servicio-y-escalabilidad.md) |
| **Un exhaustivo** | El playbook tiene lagunas declaradas: no mide rate limiting, no prueba ciegas ni basadas en tiempo, no verifica la firma de un JWT sin la clave. Esas lagunas se **documentan como lagunas**, no se disimulan |

### 1.4 Cómo usar esta guía

1. **Los módulos M0–M3, en orden y sin saltar.** M0 es el que decide si el
   trabajo es legal; los otros tres son los que deciden si el trabajo es
   correcto.
2. **Los ejercicios se resuelven antes de la segunda auditoría.** Un ejercicio
   sin resolver es una deuda que se paga en el cliente.
3. **La rúbrica (§6) se usa en la auditoría 3 y en la 4.** Antes de eso,
   autoevaluación.
4. **El checklist (§9) se relee el día antes de firmar el RoE.**

---

## 2. El mapa de la formación

Seis módulos. Las duraciones son **orientativas**: sirven para planificar, no
para certificar. Un módulo está «superado» cuando su entregable existe y su
mentor lo ha validado, no cuando han pasado las horas.

### 2.0 Tabla resumen

| Módulo | Nombre | Objetivo en una frase | Duración orientativa | Entregable | Se valida en |
|---|---|---|---:|---|---|
| **M0** | Marco deontológico y legal | Por qué la autorización escrita es la frontera entre un auditor y un atacante, y qué se hace cuando el cliente pide algo ilegal | 4–6 h | RoE personal firmado: un RoE de ejemplo para `clinica-ejemplo.mx` con las prohibiciones marcadas y la cláusula de negativa | Auditoría 2 |
| **M1** | Recon pasivo | Mapear la superficie sin tocar el objetivo, con las 11 fases del ciclo y el peso de las fases 2–7 | 8–12 h | Bitácora de Fase 0: inventario de superficie con la evidencia de cada línea y el origen de cada dato | Auditoría 2 |
| **M2** | Toolchain | Usar los 7 scripts propios, entender qué no automatizan y qué recortan | 4–6 h + 2 h de selftest | `probe_exposure.tsv` y `secrets.json` de un objetivo de laboratorio, con una nota que clasifique cada línea como hallazgo real, falso positivo o «no verificado» | Auditoría 3 |
| **M3** | Lectura de evidencia y redacción | Leer una respuesta como evidencia, redactarla y detectar las 4 falsificaciones propias del playbook | 6–8 h | Un informe de una página sobre un objetivo de laboratorio: 3 hallazgos, 1 refutación, 1 positivo, todo con evidencia | Auditoría 3 |
| **M4** | Fase 2: prueba sin daño | Ejecutar el protocolo de las 6 técnicas bajo addendum, con "go" por prueba y criterio de abort | 8–10 h + una ventana | Registro de acciones de Fase 2 (CSV) y una ficha de anexo con el apartado **«Lo que NO se hizo»** | Auditoría 4 |
| **M5** | Reporte y venta | Entregar las tres capas, puntuar con ICE y hablar con el dueño no técnico | 6–8 h | Teaser + informe técnico + brief de lenguaje llano del ejercicio E8, revisados | Auditoría 4 |

**Carga total orientativa:** 36–50 h repartidas en 4 auditorías. No es un curso
de fin de semana, y no debería serlo.

### 2.1 M0 — Marco deontológico y legal

**Objetivo.** Interiorizar que **la frontera entre un auditor y un atacante no es
la técnica: es el papel firmado**. La misma petición `GET` es una revisión de
seguridad el día 1 y, el día 2, una conducta que el marco penal tipifica como
acceso no autorizado a sistemas de información **si cambia quién firmó**.
*(Marco y fuentes primarias:
[`../00-metodologia/modelo-de-servicio-y-escalabilidad.md`](../00-metodologia/modelo-de-servicio-y-escalabilidad.md)
§4.b — **NO VERIFICADO** en esta guía: no se ha leído aquí el texto vigente de
ninguna norma. Se lee antes de citarlo.)*

**Qué se estudia.**

- Las **cinco prohibiciones duras** de [`../00-metodologia/reglas-de-autorizacion-y-roe.md`](../00-metodologia/reglas-de-autorizacion-y-roe.md) §1: nunca
  POST, nunca tocar datos de terceros, nunca des-anonimizar, nunca sondear
  infraestructura de terceros, nunca escanear una IP compartida. Y por qué
  **tres de ellas no se relajan nunca**, ni en Fase 2.
- La tabla de decisión para **hallazgos de terceros** (RoE §3): cuatro situaciones,
  cuatro tratamientos distintos.
- El ritmo: ≥ 1 s entre peticiones, User-Agent honesto y contactable, nada
  masivo, nada de fuzzing.
- **Qué pasa cuando el cliente pide algo ilegal o dañino.** El caso de
  referencia: un `POST` de prueba contra un endpoint público de Google Apps
  Script que recibe el expediente del paciente. Un `POST` no es «una prueba más»:
  escribe. En una clínica, un POST puede disparar un correo, un SMS o una
  reserva real que el cliente tiene que responder.

**Qué NO se afirma aquí, y por qué.** Este módulo **no** cita artículos de ley
como si fueran un dictamen. El marco aplicable —incluido lo relativo a acceso
no autorizado a sistemas de información— está en
[`../00-metodologia/modelo-de-servicio-y-escalabilidad.md`](../00-metodologia/modelo-de-servicio-y-escalabilidad.md)
§4, y todo lo que allí aparece marcado **NO VERIFICADO** sigue sin verificar en
este documento. **Regla del playbook: nunca cites una ley de memoria: léela y
enlaza.** Las fuentes primarias a abrir antes de escribir el bloque legal están
listadas en [`../00-metodologia/exposicion-de-secretos.md`](../00-metodologia/exposicion-de-secretos.md)
§«Fuentes primarias que hay que leer antes de citar». Si no llegaste a la fuente
primaria en esta auditoría, la afirmación va marcada **NO VERIFICADO** con el
enlace y la fecha de lectura.

**El artefacto de este módulo: la negativa documentada.**
Cuando el cliente pide algo que el RoE prohíbe, la negativa se escribe. No es
un correo de cortesía: es un registro con cuatro campos.

| Campo | Contenido |
|---|---|
| Qué se pidió | La petición literal del cliente, con fecha y canal |
| Por qué no se hace | La prohibición concreta del RoE que lo impide (§1.1 a §1.5) y el daño concreto que habría causado |
| Qué se ofrece en su lugar | La alternativa que sí está autorizada (diseño revisado leyendo el JS público, una prueba de Fase 2 con addendum, una pregunta al proveedor) |
| Quién decide | Si el RoE puede modificarse, quién tiene la facultad para firmarlo |

**Entregable de M0.** Un RoE de ejemplo para `clinica-ejemplo.mx` en el que
las cinco prohibiciones están marcadas como «no negociables» y una
**cláusula de negativa** escrita, con la regla de que toda escalada por
solicitud fuera de RoE se documenta en el registro de acciones antes de
contestar.

**Remisión.** RoE §1, §2, §3 y la plantilla §4 ·
[`../00-metodologia/modelo-de-servicio-y-escalabilidad.md`](../00-metodologia/modelo-de-servicio-y-escalabilidad.md) §4 ·
[`../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md`](../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md).

### 2.2 M1 — Recon pasivo

**Objetivo.** Mapear la superficie **sin tocar el objetivo** y entender por qué
esta fase es la que más se gana y la que menos se arriesga.

**Qué se estudia.**

- Las **11 fases del ciclo** de
  [`../00-metodologia/ciclo-de-auditoria.md`](../00-metodologia/ciclo-de-auditoria.md),
  con foco en las **fases 2 a 7**: Reconocimiento pasivo (2), Infraestructura y
  DNS (3), Transporte y TLS (4), Plataforma web (5), Divulgación (6) y Postura
  de email (7).
- **Las fuentes de terceros** y qué aporta cada una: crt.sh (subdominios que
  alguna vez se certificaron), Wayback CDX y Common Crawl (URLs históricas,
  ficheros que se publicaron y se olvidaron), InternetDB de Shodan (puertos que
  **otro** ya escaneó), ipinfo (geolocalización de la IP — que en el caso de
  referencia fue un hallazgo de cumplimiento, no de infraestructura), urlscan.io
  **en modo búsqueda solamente**.
- **La lección (a)**, que es la más importante del módulo: *el escáner propone,
  la fuente primaria dispone*. Una herramienta de identificación prueba
  **pertenencia a un rango**, no **alcanzabilidad**. La versión hay que
  contrastarla contra la API de versiones del proyecto o el aviso oficial del
  proveedor, y si no se llega a la fuente primaria, el hallazgo va marcado
  **NO VERIFICADO**.
- **Por qué esta fase gana y arriesga poco.** Ganar: el 100 % de la superficie
  pública —certificados, historiales, DNS, índices de terceros, HTML y JS
  descargados— está disponible sin tocar al objetivo. Arriesgar: cero peticiones
  al cliente, cero huella en su log, cero probabilidad de romper nada. El coste
  es que **no demuestra nada**: produce candidatos, no hallazgos.

**El entregable de M1: la bitácora de Fase 0.**
Una tabla con una línea por activo, y **cinco columnas obligatorias**:

| activo | tipo | cómo se obtuvo (comando o URL de tercero) | fichero de evidencia | qué **NO** se sabe todavía |
|---|---|---|---|---|
| `www.clinica-ejemplo.mx` | host del cliente | RoE §1 | `00-metodologia/...` / `alcance-y-roe.EJEMPLO.md` | si responde por detrás de un CDN |
| `api.ejemplo.mx` | subdominio | crt.sh | `evidencia/crtsh_www_clinica-ejemplo_mx.json` | si lo opera el cliente o un tercero |

La quinta columna es la que enseña: **cada línea dice lo que falta**, y esa
columna es la lista de trabajo de la Fase 1.

**Remisión.** Ciclo Fases 2–7 · lección (a) del ciclo ·
[`../01-tooling/manifiesto-de-herramientas.md`](../01-tooling/manifiesto-de-herramientas.md) ·
[`../00-metodologia/exposicion-a-ataques.md`](../00-metodologia/exposicion-a-ataques.md) §1.

### 2.3 M2 — Toolchain

**Objetivo.** Manejar los **7 scripts propios** con criterio, entender qué
automatizan y —más importante— **qué no**.

| # | Script | Qué hace | Qué NO hace (y por qué importa) |
|:-:|---|---|---|
| 1 | **`scope_guard.py`** | La única puerta a la red: valida ventana, host, método, intervalo y User-Agent antes de cada petición | No sabe si la ruta que le pides es prudente. Recorta los métodos a `GET`/`HEAD` **aunque el `authorization.json` liste otros**, eleva el intervalo al suelo de 1 s aunque el fichero pida menos, y rechaza un User-Agent que suplanta un navegador |
| 2 | **`probe_exposure.py`** | Sondea una lista **fija y corta de 53 rutas** conocidas y escribe un TSV | No es un escáner de rutas: no adivina. **Detecta soft-404** comparando el `sha256` con la referencia 404 del host. No guarda el cuerpo de las rutas sensibles. Recorta la lectura a `max_bytes` (1 MB por defecto), así que el `length` del TSV es **el tope, no el tamaño real** |
| 3 | **`secrets_scan.py`** | Escaneo **local** de secretos (25+ familias de patrones) | No hace red. Nunca escribe el valor completo: sólo máscara `abcd******yz` y `sha256[:12]`. Filtra placeholders. Puntuera antigüedad de versiones, **no CVE verificado** |
| 4 | **`js_intel.py`** | Analítica estática del HTML/JS ya descargado: endpoints, rutas sensibles, GraphQL, hosts de terceros, source maps, SRI | No hace red. No sabe si un endpoint devuelve datos de pacientes: eso hay que deducirlo del nombre, la documentación o la Fase 2 |
| 5 | **`header_tls_report.py`** | Informe de cabeceras: CSP, HSTS, cookies, fuga de información, caché, CORS | Trabaja sobre volcados ya guardados. **No hace peticiones.** Con un solo volcado no puede distinguir un allowlist CORS estático de un `Origin` reflejado: lo marca como pendiente de verificación |
| 6 | **`pii_redact.py`** | Redacta PII de texto, JSON y HTML; genera un informe de **conteos**, nunca de valores | **No tiene NER**: no detecta nombres de personas en texto libre. Su catálogo de claves JSON es una lista, no un estándar: una clave no contemplada pasa intacta |
| 7 | **`attack_surface_report.py`** | Agrega la evidencia local y calcula el índice 0–100 con cinco bandas | **Sin datos no hay puntos**: cada componente vale 0 y se marca «sin datos». El 0 sin datos **no** significa «seguro»: la banda pasa a «No evaluable». No verifica CVEs |

**El criterio humano es el producto.** Lo que los 7 scripts **no** hacen, y
que es exactamente el valor que se vende:

| Decisión | Por qué la hace una persona |
|---|---|
| ¿Esto que devuelve `200` es un fichero real o la página de error? | Porque el soft-404 se detecta por comparación de `sha256`, y eso falla cuando el servidor personaliza la página de error |
| ¿Este backup contiene expedientes de pacientes o plantillas del tema? | Porque la severidad depende del **contenido**, y el script no descarga el fichero a propósito |
| ¿Este certificado compartido es un riesgo del cliente o un problema del hosting? | Porque es una relación, no una vulnerabilidad del cliente |
| ¿La versión 6.8.1 está en un rango vulnerable? | Porque hace falta llegar a la fuente primaria del proyecto |
| ¿Qué le digo a un dueño que no va a leer nada técnico? | Porque eso no es un problema de información, es de criterio |

**El selftest es la puerta.** Antes de la primera petición real:

```bash
cd 01-tooling/scripts
python3 tests/selftest.py
```

Debe dar **19/19 checks PASS**. El check que importa no es que pasen: es el
que **bloquea `socket`** para comprobar que los scripts locales no abren
conexiones. Un toolkit que abre sockets sin que tú lo sepas es un problema de
alcance, no una comodidad.

**El truncamiento de métodos, en una frase.** `scope_guard.py` recorta los
métodos a `GET`/`HEAD` **aunque el `authorization.json` liste `POST`**. La
restricción es del RoE, no del cliente: un fichero de autorización que autoriza
algo de más no amplía nada, lo ignora. Si necesitas POST, no es un fichero de
autorización: es un **addendum de Fase 2**.

**Entregable de M2.** Un `probe_exposure.tsv` y un `secrets.json` de un
objetivo de laboratorio, con una nota que clasifique cada línea
como hallazgo real, falso positivo o «no verificado», y con la razon escrita.

**Remisión.** [`../01-tooling/scripts/README.md`](../01-tooling/scripts/README.md) ·
[`../01-tooling/scripts/authorization.example.json`](../01-tooling/scripts/authorization.example.json) ·
[`../01-tooling/scripts/tests/selftest.py`](../01-tooling/scripts/tests/selftest.py).

### 2.4 M3 — Lectura de evidencia y redacción

**Objetivo.** Convertir una respuesta técnica en una afirmación defendible, y
convertir la evidencia en algo que se puede entregar.

**Nombrar la evidencia.** El playbook nombra los ficheros **por lo que son**,
no por la herramienta que los produjo: `tls_versions.txt`, no `openssl.txt`;
`probe_exposure.tsv`, no `scan.tsv`. El nombre es la primera capa de
trazabilidad. Reglas de la casa:

| Regla | Ejemplo |
|---|---|
| Nombre por contenido | `tls_versions.txt`, `probe_exposure.tsv`, `secrets.json` |
| **Un bloque por fase, nombre estable** | Todo dentro de `evidencia/` con el mismo nombre en todos los clientes |
| **Los falsos positivos se conservan** | `tls_floor.txt` (el TLS de la pasada 1, que era un falso positivo) se queda, renombrado y con una nota de por qué se conserva |
| Nada pesado | Ni volcados de bases de datos, ni capturas de pantalla gigantes, ni PDFs |

Una carpeta de evidencia donde todo salió bien a la primera es **sospechosa**.

**Redactar con `pii_redact.py`.** Dos reglas, una mecánica y una de criterio:

1. **Mecánica.** Ninguna evidencia con datos personales sale del escritorio
   sin pasar por `pii_redact.py`, y lo que sale es la **copia redactada**, con
   el informe de conteos adjunto. El original no se sobrescribe nunca.
2. **De criterio.** El script **no tiene NER**: no detecta nombres de personas
   en texto libre. Su catálogo de claves JSON es una lista cerrada, y una clave
   que no esté en ella pasa intacta (el ejercicio E4 lo demuestra con tres
   claves reales). Por eso **la revisión manual es obligatoria**: el script
   garantiza las categorías; los ojos y el criterio garantizan el resto.

**Las 4 falsificaciones propias del playbook.** Son los cuatro errores que este
mismo playbook cometió en el caso de referencia. Un auditor nuevo tiene que
saber detectarlas porque van a aparecer en su propia evidencia.

| # | Falsificación | Cómo se produce | Cómo se detecta | Qué hacer |
|:-:|---|---|---|---|
| **1** | **Soft-404** | El servidor devuelve `200` con la página de error para cualquier ruta (*catch-all*). Sin la comparación de `sha256`, **todas** las rutas parecen expuestas | `probe_exposure.py` marca `soft_404=yes` y `verdict=soft_404`; las filas con `severity=info` son candidatas a ruido | Descartar la ruta. **Nunca** contarla como exposición |
| **2** | **`--tlsv1.0` como mínimo** | `curl --tlsv1.0` fija la versión **mínima** negociable, no la exacta. El servidor negocia TLS 1.3 y devuelve `200`: el test no probó nada sobre 1.0 | El `%{ssl_version}` de la propia respuesta (`version=TLSv1.3`) delata el engaño; `ssl_verify_result=0` significa «verificación correcta», no «se usó TLS» | Fijar el máximo (`--tlsv1.0 --tls-max 1.0`), forzar `-provider legacy -provider default` si OpenSSL 3.x no tiene el protocolo, y **leer la versión realmente negociada**. Si el cliente no puede ni intentar la versión, el resultado es **inconcluyente**, no «no vulnerable» |
| **3** | **Versiones de caché** | Los valores de versión salen de **HTML cacheado**, no del servidor en ejecución. El caso de referencia tenía **seis** valores distintos de `generator` en la caché | `Vary: User-Agent` o `Vary: Accept-Encoding` en la respuesta, `Age` alto, `X-Cache`, y la comparación de `sha256` entre la copia cacheada y una segunda pasada | No decir «el sitio corre 6.8.1». Decir: *«la caché contiene instantáneas de seis puntos de la historia del sitio»*. Y purgar la caché es parte de la remediación |
| **4** | **El string de la herramienta** | Una herramienta de identificación afirma «este string está en el rango vulnerable». Eso es **pertenencia**, no **alcanzabilidad** | Requiere llegar a la fuente primaria (API de versiones, aviso oficial) y comparar | Contrastar contra la fuente primaria. Si no se llega, **NO VERIFICADO**. Gana la fuente primaria y se documenta la discrepancia |

> **Las cuatro se reducen a una frase:** *un resultado que no se puede
> distinguir de un error del propio cliente o de un artefacto de la plataforma
> nunca debe convertirse en un hallazgo.* Cuando dudes, es `INFO`, no `MEDIO`.

**El bloque de «lo que NO se hizo».** No es una cortesía: es una **sección
obligatoria** del anexo y del informe. Reduce el riesgo del auditor y demuestra
el alcance real del trabajo. En el caso de referencia, esa sección decía, en
plano, que no se había roto ningún hash, no se había probado ningún email
candidato, no se había hecho login, no se había enviado ningún mensaje a
ningún webhook, no se había enumerado ningún identificador y no se había
abierto ninguna conexión a la base de datos.

**Entregable de M3.** Un informe de una página sobre un objetivo de
laboratorio con: 3 hallazgos (uno de ellos con su evidencia enlazada), 1
**refutación** («esto no es un problema, y aquí está la prueba»), 1 positivo
(«esto ya está bien»), la sección «lo que NO se hizo» y el bloque legal con
**NO VERIFICADO** donde corresponda.

**Remisión.** Ciclo Fases 4–6 (lecciones (a) y (b)) ·
[`../00-metodologia/exposicion-de-secretos.md`](../00-metodologia/exposicion-de-secretos.md) §9 ·
[`../00-metodologia/como-presentar-resultados.md`](../00-metodologia/como-presentar-resultados.md) §1, §4, §5.

### 2.5 M4 — Fase 2: la prueba sin daño

**Objetivo.** Ejecutar, sin causar daño, un impacto ya identificado, con el
cliente presente y con el derecho a parar en cualquier momento.

**La escalera.** El playbook tiene **dos ejes distintos** y no deben
confundirse:

| Ciclo de 11 fases | Escalera de vulnerabilidad |
|---|---|
| Fase 2 del ciclo = **Reconocimiento pasivo** | Fase 0 de la escalera = **Recon pasivo** |
| — | Fase 1 de la escalera = **Validación activa** (GET/HEAD, superficie conocida) |
| — | Fase 2 de la escalera = **Explotación autorizada y limitada** |

> **Regla de escritura, desde el día 1.** En la metodología y en el addendum:
> «Fase 0 / Fase 1 / Fase 2 **de vulnerabilidad**». En el informe: «Fase 0 (recon)»,
> «Fase 1 (validación)», «Fase 2 (explotación)». El ciclo se cita «fase 5 del
> ciclo», «fase 7 del ciclo». **Nunca** «la fase 6» a secas: en una ventana con
> reloj, la ambigüedad se paga cara.

**Las seis técnicas del addendum.** T1 IDOR/BOLA, T2 SQLi no destructivo, T3 XSS
con payload inocuo, T4 bypass de control de acceso administrativo, T5 fichero de
backup/configuración expuesto, T6 validación de credencial expuesta vía API del
proveedor. **T1–T6 son una lista cerrada**: lo que no aparece en §2 del
addendum firmado **no existe**, aunque lo estés viendo en pantalla y aunque el
cliente te lo pida de viva voz.

**El protocolo, en orden.**

| Paso | Qué pasa | Condición |
|:-:|---|---|
| 1 | Se ejecuta **una** técnica, en **un** endpoint, con **un** método | Todo lo que haya en el addendum |
| 2 | El responsable técnico del cliente da el **"go" por prueba**, con hora | «El silencio no es un "go"»: si no contesta en 10 minutos, la prueba **no se ejecuta** y se anota *no ejecutada — sin go* |
| 3 | Se ejecuta **una acción**: un par de peticiones comparables | No se repite «para confirmar» ni para «tirar una segunda muestra» |
| 4 | Se recoge la evidencia mínima que dice la matriz de destructividad | Una fila en `registro-de-acciones-fase-2.csv` |
| 5 | Se comprueban los **criterios de abort** | Si la respuesta trae algo inesperado, el tamaño no cuadra o el servicio se mueve: **se para todo**, no se interpreta y no se ajusta el payload |
| 6 | Al cerrar: **declaración de limpieza firmada** | El auditor dice qué queda, quién lo retira y qué no es retirable por él |

**La matriz de destructividad** es la tabla que decide, antes de cada prueba,
cuál es el impacto máximo tolerado, qué hay que cumplir, qué evidencia mínima
deja, quién debe estar presente, qué huella se permite y cómo se revierte. Las
tres últimas filas de esa tabla —enumeración de identificadores, extracción de
filas, prueba de carga— no tienen impacto máximo: están **PROIBIDAS**, y no se
levantan por urgencia, ni por autorización del dueño, ni por tamaño del cliente.

**El manejo de PII y la regla de no tocar datos reales.** Cuatro ejemplos que
son la frontera:

| Prueba | Lo que se demuestra | Lo que NUNCA se hace |
|---|---|---|
| IDOR (T1) | Código, **claves** del JSON y **longitud** comparados entre dos cuentas de prueba | Enumerar `{id+1}`, `{id+2}`; listar el directorio de pacientes; **contar** cuántos hay; transcribir el registro. Contar pacientes también es tocar datos de pacientes |
| SQLi (T2) | Una pareja de peticiones booleanas comparativas, con diferencia consistente | `UNION SELECT`, consultas apiladas (`;`), extraer o contar filas, técnica de tiempo (`SLEEP`) |
| XSS (T3) | Un marcador de texto inocuo (`XSS-AUDIT-F2-03`) reflejado sin codificar en la cuenta propia | `script`, `img`, `onerror`, beacon, `document.cookie`, XSS almacenado, o probarlo contra la cuenta de otro |
| Credencial expuesta (T6) | **Una** llamada de lectura al endpoint que el cliente designó por escrito; se registran los **nombres de campo** | Enumerar, filtrar, paginar, descargar, escribir, iniciar sesión, o usarla fuera de la ventana |

**Entregable de M4.** Un `registro-de-acciones-fase-2.csv` completo (con las
técnicas **refutadas** y **no ejecutadas** también, que es donde se ve el
rigor) y una ficha de anexo con el apartado obligatorio **«Lo que NO se hizo»**,
la §5 de datos reales expuestos (**SI/NO + categoría, nunca el valor**), la
declaración de limpieza y el índice de evidencia.

**Remisión.** [`../00-metodologia/fase-2-explotacion-autorizada.md`](../00-metodologia/fase-2-explotacion-autorizada.md) §1, §3, §5 ·
[`../05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md`](../05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md) ·
[`../05-plantillas-de-trabajo/registro-de-acciones-fase-2.csv`](../05-plantillas-de-trabajo/registro-de-acciones-fase-2.csv) ·
[`../02-plantillas/informe-completo/anexo-explotacion-limitada.md`](../02-plantillas/informe-completo/anexo-explotacion-limitada.md).

### 2.6 M5 — Reporte y venta

**Objetivo.** Que el resultado sea **decisiones ejecutables**, no una lista de
hallazgos, y que llegue a las tres audiencias con el grado de detalle
correcto.

**Las tres capas de entregables.**

| Capa | Para quién | Nivel técnico | Qué contiene | Qué **nunca** contiene |
|---|---|---|---|---|
| **1 — Teaser** (PDF) | El dueño, primer contacto | **Cero** | Cifras legales exactas, costo del negocio del riesgo, resumen por categoría, distribución por severidad, **«lo que ya está bien»**, la oferta, la convocatoria | Identificadores de vulnerabilidad, severidad estándar, versiones, rutas, comandos, salidas de herramientas, emails, teléfonos, nombres de herramientas, la lista completa de hallazgos |
| **2 — Informe técnico** (Markdown, §0–§11) | Técnico del cliente, hosting, agencia | Máximo | Mapeo OWASP/WSTG con razonamiento (y **qué filas están forzadas**), contraste de CVE contra fuente primaria, mapeo legal con cita, registro de riesgo puntuado, hoja de ruta por olas, **borradores de ticket** | — (va marcado **CONFIDENCIAL. No enviar al dueño final ni a terceros**) |
| **3 — Brief de lenguaje llano** (2–3 págs) | El dueño no técnico | Cero | Cada afirmación traducida: «esto es lo que significa para ti», nunca «esto es lo que hace la herramienta» | Jerga sin traducir |

**La matriz de severidad** tiene cinco niveles —CRÍTICO, ALTO, MEDIO, BAJO,
INFO— y se calcula sobre **tres ejes, en este orden**: exposición (qué necesita
el atacante para llegar) × severidad del efecto (qué pasa si se explota) ×
contexto y datos (qué hay detrás). Tres reglas de calibración que no se
negocian:

1. **Nunca infles.** Un hallazgo honesto de BAJO genera más confianza que uno
   inflado.
2. **Mira el contenido antes de calibrar.** `/wp-json/wp/v2/media` con 66
   ficheros de plantilla es BAJO; con radiografías de pacientes sería CRÍTICO.
   **La severidad viene de lo que hay detrás, no del tipo de endpoint.**
3. **Si no lo puedes verificar, es INFO** — con el comando de 60 segundos para
   que lo cierre el cliente.

**ICE, no RICE.** `rr_por_hora = riesgo_puntual / effort_hrs`. RICE necesita
*reach* e *impact*, métricas de producto que una auditoría **no tiene y no
puede inventar**: inventar un *reach* es peor que no usar RICE, porque produce
una priorización que parece cuantitativa y es arbitraria con dos decimales.
El resultado operativo de ordenar por ICE: en el caso de referencia, **cinco de
los primeros once ítems de la cola costaban menos de una hora** y detenían un
daño en curso. Ese es el hallazgo real de muchos sitios: no ataques
sofisticados, sino omisiones pequeñas, baratas y acumuladas.

**«Lo que ya está bien» es obligatorio.** No es cortesía: es requisito
metodológico, por tres razones —credibilidad, calibración (sin un positivo, los
negativos no tienen referencia) y no-diseño-del-miedo. Y cada positivo se dice
**con la misma precisión que un negativo**: «el cifrado es fuerte porque sólo
acepta ECDHE/DHE+AES-GCM y ningún CBC ni RSA estático», no «el cifrado está
bien».

**Cómo se habla con el dueño no técnico.** Tres reglas:

| Regla | Ejemplo |
|---|---|
| Traduce la consecuencia, no la técnica | «Alguien puede hacerse pasar por nosotros en un correo» — no «no hay DMARC» |
| Da el coste en tiempo y dinero, no en riesgo abstracto | «Esta semana: 5 correcciones de menos de una hora cada una» |
| Separa lo que puede arreglar él de lo que no | «12 de los hallazgos más graves los tiene que arreglar tu hosting o tu agencia, no tú. Te dejo los textos listos para enviarles» |

Esa última frase es uno de los servicios de más valor que puedes dar: **dirige
la energía del dueño**, que es un recurso escaso.

**Entregable de M5.** Los tres documentos de un objetivo de laboratorio,
revisados, con la hoja de ruta en tres olas ordenada por `rr_por_hora`, los
borradores de ticket y el bloque «lo que ya está bien» con la misma precisión
que los negativos.

**Remisión.** [`../00-metodologia/como-presentar-resultados.md`](../00-metodologia/como-presentar-resultados.md) ·
[`../02-plantillas/teaser-report/README.md`](../02-plantillas/teaser-report/README.md) ·
[`../02-plantillas/informe-completo/README.md`](../02-plantillas/informe-completo/README.md) ·
[`../05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv`](../05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv).

### 2.7 Lo que la formación NO cubre

| Fuera | Por qué |
|---|---|
| Penetración de redes, movimiento lateral, escalada de privilegios | Fuera del modelo de servicio. La Fase 2 es *explotación limitada*, no un pentest |
| Ingeniería social y phishing simulado | Prohibido explícitamente (RoE §4, «Social engineering al personal del cliente») |
| Revisión de código fuente de la aplicación | Fuera de alcance salvo que el cliente lo comparta |
| Pruebas de carga, disponibilidad y denegación de servicio | Prohibido absoluto, sin excepción (Fase 2 §3, prohibiciones 1) |
| Auditoría de cumplimiento normativo formal | El playbook entrega el **mapeo con cita**; el dictamen es del abogado |
| pentest de banco o infraestructura crítica | El modelo es SMB de salud (un sitio, un dueño que decide, datos sensibles) |

---

## 3. El decálogo de reglas innegociables

Diez reglas. No son consejos: son las condiciones de posibilidad del trabajo.
Cada una dice **qué hacer**, **por qué** y **dónde está el respaldo**.

| # | Regla (en imperativo) | Por qué | Remisión |
|:-:|---|---|---|
| **1** | **No hagas ninguna petición al objetivo antes de que el RoE esté firmado.** | Sin RoE firmado, el auditor está exactamente en la misma posición jurídica que sin él, y además pierde el activo probatorio. Una autorización escrita es **un permiso con forma**: identifica sistemas exactos, técnicas enumeradas, ventana y contacto | RoE §1, §4 y §5 · [`../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md`](../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md) |
| **2** | **Usa sólo `GET` y `HEAD`, a ≥ 1 s de espaciado, con User-Agent honesto y contactable.** | Un POST escribe, y su daño se materializa en la bandeja del cliente. Un UA que suplanta a Chrome es suplantación. El ritmo lento es cortesía con el servidor ajeno y con el cliente | RoE §1.1 y §2 · `scope_guard.py` (recorte a `GET`/`HEAD`, suelo de 1 s, rechazo de UA suplantado) |
| **3** | **Reporta la capacidad, no ejecutes la explotación.** | La capacidad es el hallazgo; el resultado de la capacidad es sólo daño. Un informe que dice «pueden obtener tus emails» ya permite al cliente actuar; uno que además incluye tu lista de emails **crea un archivo de datos personales que no tenías derecho a tener** | RoE §1.3 · Fase 2 §1.1 y §4 |
| **4** | **No toques datos de terceros: ni de pacientes, ni de personal, ni de otros inquilinos del hosting.** | Tu autorización es del dominio del cliente, no de las personas ni de los vecinos. En un hosting compartido, «el vecino» son veinte consultas más que no te autorizaron. **Contar cuántos hay también está prohibido** | RoE §1.2, §1.4 y §1.5 · Fase 2 §3.3 y §5.2 |
| **5** | **Contradice al escáner con la fuente primaria, y si no llegas a ella, marca NO VERIFICADO.** | Las herramientas de identificación prueban **pertenencia a un rango**, no **alcanzabilidad**. Gana la fuente primaria y se documenta la discrepancia | Ciclo Fases 5–6, lección (a) · `exposicion-de-secretos.md` §3 |
| **6** | **No escribas un hallazgo sin un fichero de evidencia y un comando reproducible.** | Si no hay archivo, no hay hallazgo. Si no hay severidad, no hay nada. Un hallazgo sin comando reproducible es una opinión, y las opiniones no se venden como auditorías | Ciclo «Regla de oro» · `como-presentar-resultados.md` §5 |
| **7** | **Redacta antes de compartir, y redacta a mano lo que el script no detecta.** | El script garantiza las categorías; los ojos garantizan el resto. `pii_redact.py` no tiene NER y su catálogo de claves es una lista cerrada. Un informe con un `.env` crudo es **un segundo `.env` publicado** | `exposicion-de-secretos.md` §9.1–§9.4 · §6.4 |
| **8** | **Escribe «NO VERIFICADO» cuando no se comprobó, con el requisito que falta y el comando de 60 segundos para cerrarlo.** | «No verificado» no es «bajo»: es un riesgo **sin medir**. Un informe que confunde «no medido» con «no hay problema» es exactamente el informe que el cliente no vuelve a contratar | `exposicion-de-secretos.md` §7.5 · `como-presentar-resultados.md` §1 regla 3 |
| **9** | **Escribe «lo que ya está bien» con la misma precisión que los negativos, y escríbelo siempre.** | Sin positivos, los negativos no tienen referencia y el informe se lee como marketing. Un control de acceso que funciona también es un hallazgo | `como-presentar-resultados.md` §4 · Ciclo Fase 11 |
| **10** | **Si tienes duda de si algo está permitido, no lo hagas y pregunta.** | Una pregunta al cliente cuesta un correo. Un hallazgo de más cuesta cero. Un problema legal cuesta el contrato | RoE §5 principio 8 · `01-tooling/scripts/README.md` (aviso legal) |

---

## 4. Errores que un junior comete

Todos estos errores se cometieron —o casi se cometen— en el caso de referencia.
La columna de la derecha es la que te salva: cada fila tiene un artefacto que
detecta el error si lo miras.

| # | Error | Qué pasa en realidad | Cómo se previene | Con qué artefacto lo detecta |
|:-:|---|---|---|---|
| 1 | **Confundir `curl --tlsv1.0` con «TLS 1.0 exacto»** | `--tlsv1.0` fija la versión **mínima** negociable. El servidor negocia TLS 1.3 y devuelve `200`: el test no probó nada sobre 1.0. Y `ssl_verify_result=0` significa «verificación correcta», no «se usó TLS» | Fijar el máximo (`--tlsv1.0 --tls-max 1.0`), forzar `-provider legacy -provider default` si OpenSSL 3.x no tiene el protocolo, y **leer la versión realmente negociada** | El `%{ssl_version}` de la propia respuesta (`version=TLSv1.3`) y la línea `New, TLSv1.x` de `s_client`. Ejercicio **E6** |
| 2 | **Reportar `X-Powered-By: PHP/8.1.29` como «el sitio corre PHP 8.1.29»** | Es una **pista**, no un hecho: la cabecera la pone el servidor, pero el HTML que se sirve puede venir de una caché con otra versión. En el caso de referencia la caché servía seis valores distintos de `generator` | Escribir «la cabecera expone la versión 8.1.29»; contrastar contra la fuente primaria del proyecto antes de asociar un CVE; y purgar caché si el dato se contradice con el runtime | `header_tls_report.py` marca la fuga de información; `Vary`, `Age` y `X-Cache` en las cabeceras. Ejercicio **E1** |
| 3 | **Confiar en el string del escáner** | Que «6.8.1 cae en el rango 6.8.0–6.8.9» no dice que el código vulnerable sea alcanzable ni que sus precondiciones se cumplan. En el caso de referencia, `retire.js` marcó una versión de jQuery **ya corregida** como vulnerable | Contrastar **toda** versión y **todo** CVE contra la fuente primaria (API de versiones, aviso oficial). Si no se llega: **NO VERIFICADO** | La tabla oficial del proyecto, la API de versiones y el aviso del proveedor. `secrets_scan.py` puntúa antigüedad, **no** CVE: la etiqueta del propio script lo dice |
| 4 | **Declarar «no vulnerable» / «no pasa nada» porque no se probó** | «No lo probé» se convierte en «no hay problema», que es una afirmación que **nunca** hiciste. En el caso de referencia, la corrección de TLS se rotuló explícitamente como *CORRECTION to prior pass*, no como «siempre estuvo bien» | Escribir **NO VERIFICADO** + el requisito que falta + el comando de 60 segundos para cerrarlo + la severidad **si** se confirma | El bloque «pruebas no ejecutables sin cuentas de prueba» del informe (`exposicion-de-secretos.md` §10) y la columna `estado` del registro |
| 5 | **Tratar un soft-404 como exposición** | El servidor devuelve `200` con la página de error para cualquier ruta (*catch-all*). Sin la comparación de `sha256`, el informe se llena de rutas fantasma: `/admin/`, `/phpmyadmin/`, `/administrator/` | Leer la columna `soft_404` y la columna `verdict`. `verdict=soft_404` **no cuenta como exposición** | `probe_exposure.py` (columna `soft_404` y `verdict` del TSV). Ejercicio **E2** |
| 6 | **Creer que no hay `.env` porque el 404 «es correcto»** | En un *catch-all*, `/.env` devuelve `200` con la página de error. Y al revés: un `404` con `Content-Type: text/html` y cuerpo de plantilla no prueba nada sobre un fichero que debería ser `text/plain` | Comprobar **código + `Content-Type` + `sha256`**, no el código solo. Un `.env` real devuelve `200 text/plain` con contenido que **no** es la plantilla de error | `probe_exposure.py` (columnas `content_type` y `sha256`) y `secrets_scan.py` sobre lo descargado. Ejercicio **E2** |
| 7 | **Confundir enumeración de emails con de-anonimización** | Son cosas distintas: *describir* que un hash MD5 de Gravatar es un oráculo reversible offline **es el hallazgo**; *probar* emails candidatos para obtener la lista **es el delito**. Lo primero se documenta, lo segundo no se ejecuta | Escribir la cadena completa y marcarla **MEDIO**, con la no-recomendación explícita en el informe, y **no** ejecutar ninguna parte de la cadena | RoE §1.3 · la sección «Lo que NO se hizo» del informe · el registro de acciones |
| 8 | **Entregar evidencia sin redactar** | Un `.env` crudo que viaja al hosting, a la agencia y al cliente **es un segundo `.env` publicado**, con más audiencia que el original. Cada salto por correo, ticket o chat es una copia más de la credencial | Todo lo que sale del escritorio pasa por `pii_redact.py`; el original se queda cifrado con retención definida en el RoE; y **revisión manual** de los extractos de texto libre | `pii_redact.py` + el informe de conteos + los `grep` de control de calidad de `exposicion-de-secretos.md` §9.4. Ejercicio **E4** |
| 9 | **Confundir la Fase 1 del ciclo con la Fase 2 (explotación) y ejecutar sin addendum** | «Fase 2» son dos cosas distintas: la fase 2 del **ciclo** es reconocimiento pasivo; la Fase 2 de la **escalera de vulnerabilidad** es explotación autorizada. Confundirlas lleva a hacer una prueba activa sin la ventana, sin el cliente presente y sin el "go" por prueba | Escribir siempre el descriptor entre paréntesis («Fase 2 (explotación)», «fase 6 del ciclo»). La Fase 2 exige **tres firmas** | `fase-2-explotacion-autorizada.md` §2.6 (tabla de colisión de nomenclatura) · el addendum firmado |
| 10 | **Confiar en el cliente para confirmar que las cuentas de prueba son sintéticas** | «Las cuentas son de prueba» dicho por correo no es una garantía: si la cuenta A contiene un expediente real, la prueba de IDOR **ha tocado datos de un paciente** y es un incidente, no una demostración | El cliente **crea** las cuentas con **datos sintéticos hechos por él**, y el auditor **recibe** los identificadores: no los elige ni los deduce. Contrato escrito de que esos registros no contienen datos de pacientes reales | Fase 2 §3.3.1 (el auditor no elige el identificador, lo recibe) · la columna `datos_tocados = ninguno` del registro de acciones · el addendum §5 de minimización |
| 11 | **Pegar el valor completo de un secreto en el informe** | El valor completo de una credencial no sale nunca del proceso que lo leyó: ni al informe, ni a la evidencia, ni al chat, ni al ticket, ni a una nota interna | Sólo dos artefactos: la máscara `abcd******yz` y la huella `sha256[:12]`, que permite correlacionar dos apariciones del mismo secreto sin revelarlo | `secrets_scan.py` (no escribe el valor) · el `grep` de secretos del control de calidad |
| 12 | **Reportar como «dato robado» lo que sólo es una capacidad** | El hash MD5 que WordPress sirve en cada respuesta **no es un email robado**: es un oráculo. Reportarlo como dato expuesto infla la severidad y quita credibilidad al resto | Calibrar **por contenido**: qué hay realmente detrás del hallazgo, no el tipo de vector | La matriz de severidad de `como-presentar-resultados.md` §1, regla 2 |
| 13 | **Pegar la salida del escáner como informe** | Una tabla de 200 líneas sin criterio no es una auditoría: es ruido con formato. El lector no sabe qué hacer con ella | Cada hallazgo con: evidencia, comando reproducible, severidad calibrada, dueño, horas | `como-presentar-resultados.md` §6 (anti-patrones) y el registro `registro-de-acciones.EXAMPLE.csv` |

---

## 5. Ejercicios de Joanne

**Joanne** es el nombre del auditor en formación que aparece en los ejercicios.
No es una persona real: es un personaje de ejemplo, como `clinica-ejemplo.mx`.
Todos los datos de estos ejercicios son **100 % ficticios** y están preparados para
que puedas razonar sin red y sin riesgo.

Cada ejercicio tiene: **enunciado**, **datos** (inline, sin dependencias
externas) y **solución** en un bloque plegable. Resuélvelos **antes** de la
segunda auditoría: un ejercicio sin resolver es una deuda que se paga en el
cliente.

| # | Título | Dificultad | Qué entrena | Módulo |
|:-:|---|:-:|---|:-:|
| **E1** | Leer un volcado de cabeceras | Fácil | Interpretar evidencia cruda; detectar controles ausentes y fugas | M3 |
| **E2** | Separar hallazgos de falsos positivos en un TSV | Fácil | Soft-404, veredictos y calibración de severidad | M2, M3 |
| **E3** | Reconocer seis secretos falsos | Media | Taxonomía de secretos y tratamiento en Fase 1 vs. Fase 2 | M2, M4 |
| **E4** | Redactar un JSON de paciente ficticio | Media | Minimización de datos y límites del script | M3 |
| **E5** | Responder a una petición fuera de alcance | Media | Deontología, negativa documentada y escalado | M0 |
| **E6** | Concluir sobre versiones de TLS | Media | Lección (b): `--tlsv1.0` es un mínimo | M1, M3 |
| **E7** | Calcular el índice de exposición a mano | Media | Leer el score y saber qué dice y qué no dice | M2, M5 |
| **E8** | Reescribir una afirmación que promete de más | Difícil | Honestidad del informe y calibración de severidad | M5 |

---

### E1 — Interpretar un volcado de cabeceras

**Enunciado.** Este es el volcado de la respuesta de `https://www.clinica-ejemplo.mx/`
guardado como `evidencia/headers_https.txt`. **¿Qué controles de seguridad
faltan?** Enuméralos y di, para cada uno, qué riesgo concreto mitiga en un
portal de pacientes. Añade, además, todo lo que veas que **no** sea un control
ausente.

**Datos** (`evidencia/headers_https.txt`):

```text
HTTP/1.1 200 OK
Date: Mon, 17 Nov 2026 09:14:22 GMT
Server: Apache
X-Powered-By: PHP/8.1.29
Content-Type: text/html; charset=UTF-8
Content-Length: 48213
Cache-Control: no-cache, no-store, must-revalidate
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Vary: Accept-Encoding, User-Agent
Set-Cookie: PHPSESSID=7f3c9ab21d5e4f6a8b0c2d9e1f4a5b6c; path=/; HttpOnly
```

<details>
<summary><b>Solución E1</b></summary>

**Los 8 controles base ausentes.** Son exactamente los ocho que
`attack_surface_report.py` toma como «cabeceras completas» (`CORE_HEADERS`):

| # | Control ausente | Riesgo concreto en un portal de pacientes |
|:-:|---|---|
| 1 | **Content-Security-Policy** | Sin CSP, un XSS inyectado se ejecuta libremente en el navegador del paciente. La CSP es el límite de contención |
| 2 | **Strict-Transport-Security** | Sin HSTS, la primera visita puede ir en HTTP: el paciente teclea el datos y el identificador de sesión viaja en claro |
| 3 | **X-Content-Type-Options** | Sin `nosniff`, el navegador puede interpretar un fichero como otro tipo y ejecutar contenido que el servidor no pretendía servir |
| 4 | **X-Frame-Options** | Sin él, el sitio se puede incrustar en un marco de otro dominio: phishing con la apariencia exacta de la clínica |
| 5 | **Referrer-Policy** | Sin ella, la URL de una página de paciente puede viajar en la cabecera `Referer` a un tercero |
| 6 | **Permissions-Policy** | El sitio no declara qué capacidades del navegador puede usar un tercero que lo incruste (cámara, micrófono, geolocalización) |
| 7 | **Cross-Origin-Opener-Policy** | Sin ella, la ventana del paciente queda en el mismo grupo de contextos que las que abren terceros |
| 8 | **Cross-Origin-Resource-Policy** | Sin ella, un recurso con datos puede ser leído por otro origen |

> **Un noveno condicional.** `header_tls_report.py` también marca ausente
> **Cross-Origin-Embedder-Policy**. No cuenta entre los 8 base porque sólo
> importa si el sitio usa `SharedArrayBuffer` o Web Workers. Menciónalo si el
> caso lo requiere; no lo infles.

**Lo que también ves y no es «un control ausente»:**

| Observación | Lectura correcta | Severidad |
|---|---|---|
| Cookie `PHPSESSID` con `HttpOnly` pero **sin `Secure` ni `SameSite`**, y sin prefijo `__Host-` | `HttpOnly` está bien (el JS no la lee). `Secure` ausente = la cookie puede viajar en HTTP. `SameSite` ausente = la cookie se envía en peticiones iniciadas por terceros (riesgo de CSRF) | MEDIO |
| `Server: Apache` | Fuga de información del servidor. No es «la» vulnerabilidad, pero acota el trabajo de quien te ataque | BAJO |
| `X-Powered-By: PHP/8.1.29` | Fuga de información. **Ojo:** es una *pista*, no el hecho de que el servidor corra esa versión. Se escribe «la cabecera expone la versión 8.1.29», no «el sitio corre PHP 8.1.29» | BAJO |
| `Vary: Accept-Encoding, User-Agent` | **Aviso de la falsificación nº 3.** Cada User-Agent distinto genera una variante de caché. Es el mecanismo por el que la caché del caso de referencia llegó a servir seis valores distintos de `generator`. Se reporta como observación de caché, **no** como «el sitio corre seis versiones» | INFO/MEDIO |
| `Cache-Control: no-cache, no-store, must-revalidate` + `Expires` en el pasado | **Esto está bien.** Para páginas con datos de pacientes, no cachear es lo correcto. Va al bloque «lo que ya está bien» | INFO (positivo) |
| Sin `Access-Control-Allow-Origin` | **No hay CORS permisivo.** Sin CORS declarado, un frontend de otro origen no puede leer las respuestas. Correcto si la API no la consume otro origen | INFO (positivo) |

**Lo que este volcado NO te dice** (y hay que escribir): si la redirección de
`http://` a `https://` está activa, si hay stapling OCSP, si el cipher suite es
fuerte, y **cuál es la versión real de PHP**. Eso requiere otras pruebas.

**Comprobación.** `python3 header_tls_report.py evidencia/headers_https.txt --out
evidencia/header_tls.md` produce las mismas ausencias en tabla
`check | valor | severidad | remediación`. La herramienta te da la lista; el
**porqué de cada una** es tuyo, y eso es lo que se lee en el informe.

</details>

---

### E2 — Hallazgos reales y falsos positivos en un TSV de sonda

**Enunciado.** Este es el fichero `evidencia/probe_exposure.tsv` que dejó
`probe_exposure.py` contra `www.clinica-ejemplo.mx`. **¿Qué filas son hallazgos
reales y cuáles son falsos positivos?** Para cada fila, explica en una frase el
motivo. Y contesta: ¿de las que son hallazgo, cuál **no** es todavía un
hallazgo, sino un candidato?

**Datos** (`evidencia/probe_exposure.tsv`; la cabecera es
`host path code content_type length sha256 soft_404 verdict severity`):

```tsv
www.clinica-ejemplo.mx	/.env	200	text/plain	1843	3f9c1a7be204	no	expuesto	critico
www.clinica-ejemplo.mx	/.git/HEAD	200	text/plain	23	8a41d0c7f915	no	expuesto	critico
www.clinica-ejemplo.mx	/backup.zip	200	application/zip	1000000	b7e4a9c02f18	no	expuesto	critico
www.clinica-ejemplo.mx	/config.json	200	application/json	612	4be0f7c31a9d	no	expuesto	alto
www.clinica-ejemplo.mx	/swagger.json	200	application/json	28344	51cc9a0e2f73	no	expuesto	medio
www.clinica-ejemplo.mx	/api/v1/	200	application/json	412	9d02e5b7c148	no	expuesto	bajo
www.clinica-ejemplo.mx	/.well-known/security.txt	200	text/plain	612	8d11a6f0c93b	no	expuesto	bajo
www.clinica-ejemplo.mx	/administrator/	200	text/html	15204	7c2e91ab34d0	yes	soft_404	info
www.clinica-ejemplo.mx	/phpmyadmin/	200	text/html	15204	7c2e91ab34d0	yes	soft_404	info
www.clinica-ejemplo.mx	/wp-admin/	301	text/html	0	4c0a1f8b93d7	no	redireccion	info
www.clinica-ejemplo.mx	/phpinfo.php	404	text/html	15204	7c2e91ab34d0	no	no_encontrado	info
www.clinica-ejemplo.mx	/actuator/env	403	text/html	312	4be0f7c31a9d	no	protegido	info
```

<details>
<summary><b>Solución E2</b></summary>

**Falsos positivos (4 filas).** Ninguna es un hallazgo:

| Fila | Por qué no es un hallazgo |
|---|---|
| `/administrator/` | `soft_404=yes` y `sha256` **idéntico al de la referencia 404** (`7c2e91ab34d0`). El servidor devuelve `200` con su página de error para cualquier ruta. No existe un panel ahí |
| `/phpmyadmin/` | Igual que la anterior: mismo `sha256` de la referencia. No hay panel de base de datos |
| `/wp-admin/` | `verdict=redireccion`, `301`. No hay contenido expuesto. Se puede informar como «existe un panel que redirige a `/wp-login.php`» → **INFO/BAJO**, que es información de superficie, no una exposición |
| `/phpinfo.php` | `404` real: la ruta no existe. Cierre |

> **La lección:** sin la comparación de `sha256` con la referencia 404, estas
> cuatro filas habrían entrado en el informe como cuatro hallazgos. En muchos
> sitios el `catch-all` convierte las 53 rutas de la lista en 53 falsos
> positivos. Por eso la columna `soft_404` existe.

**Hallazgos reales (6) + un matiz (1).**

| Fila | Veredicto | Por qué |
|---|---|---|
| `/.env` → `200 text/plain 1843 B` | **CRÍTICO** | Fichero de entorno publicado: por definición contiene credenciales de base de datos y, en una clínica, es la credencial del almacén de expedientes. **No se descarga el cuerpo**: la evidencia es ruta + código + `Content-Type` + tamaño. La severidad es CRÍTICO **esté viva o no**: la rotación es la misma |
| `/.git/HEAD` → `200 text/plain 23 B` | **CRÍTICO** | El repositorio es descargable: eso es el código fuente, la configuración y el historial. Con el SHA del `HEAD` se puede pedir **cualquier** objeto del repositorio |
| `/backup.zip` → `200 application/zip` | **CRÍTICO** | ⚠️ **Ojo al `length`: es `1000000`, que es el tope de `max_bytes` (1 MB) del guard, NO el tamaño real del fichero.** El `sha256` es el del primer megabyte. El tamaño real está en el `Content-Length` de la cabecera: hay que registrarlo con `curl -r 0-1023 -D -`. **Jamás** se descarga el fichero entero |
| `/config.json` → `200 application/json 612 B` | **ALTO por la ruta… y todavía no es un hallazgo** | La severidad del TSV es la severidad *a priori* de la familia de ruta. El contenido decide: si contiene credenciales → CRÍTICO; si son preferencias públicas → BAJO. **Hay que mirarlo sin pegarlo** (o leerlo con `Range`) |
| `/swagger.json` → `200 application/json 28344 B` | **MEDIO** | Superficie de API documentada: rutas, parámetros y esquemas de respuesta. Es el mapa de la API del cliente, que es un activo. No es una vulnerabilidad por sí misma |
| `/api/v1/` → `200 application/json 412 B` | **BAJO… y calibrable** | La ruta responde sin autenticación. **La severidad la pone el contenido**: si devuelve `[]` es un fallo menor; si devuelve fichas de pacientes, es CRÍTICO. El proxy de severidad es «código + claves + longitud», nunca el dato |
| `/.well-known/security.txt` → `200 text/plain 612 B` | **Hallazgo POSITIVO** | El cliente tiene canal público para reportar incidentes de seguridad, con fecha de expiración y contacto. Eso va al bloque **«lo que ya está bien»**, con la misma precisión que los negativos |
| `/actuator/env` → `403` | **MEDIO, no `INFO`** | `verdict=protegido`: la ruta **existe** y está protegida. El inventario de rutas de la aplicación es un activo (revela el stack y los módulos). **No se intenta autenticar** |

**Las dos trampas del ejercicio, que son las dos lessons del playbook:**

1. **La columna `severity` es *a priori*.** `probe_exposure.py` asigna
   `severity = profile.severity if verdict == "expuesto" else "info"`: la
   severidad de la **familia de ruta**, no la del hallazgo. El auditor recalibra
   después, mirando el contenido.
2. **`length` es el número de bytes leídos, no el tamaño del recurso.** Con
   `max_bytes = 1_000_000` por defecto, cualquier recurso mayor se reporta como
   `1000000`. Si escribes «backup de 1 MB» en el informe, estás describiendo tu
   propio límite de lectura.

</details>

---

### E3 — Reconocer seis secretos falsos y decidir qué hacer con cada uno

**Enunciado.** Joanne descarga el bundle de la home de `clinica-ejemplo.mx` y
encuentra este fichero. **¿Qué tipos de secreto son los seis? ¿Qué haría con
cada uno en Fase 1 y qué en Fase 2?** No pruebes ninguno: los valores son
ficticios y, en un caso real, probarlos es una prohibición.

**Datos** (`evidencia/js/app.ejemplo.js`):

```javascript
// app.ejemplo.js — CONTENIDO 100% FICTICIO para el ejercicio E3.
// Ninguno de estos valores existe en ningún proveedor real.
const CONFIG = {
  pagos:    "sk_live_EJEMPLO000000000000000000",
  mapas:    "AIzaSyEJEMPLO00000000000000000000000000",
  nube:     "AKIAEJEMPLO000000000",
  chat:     "https://hooks.slack.com/services/TEJEMPLO1/BEJEMPLO2/EJEMPLO3",
  sesion:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJleGFtcGxvIn0.EJEMPLOFIRMA0000",
  Basedatos:"postgresql://usuario_ejemplo:clave_ejemplo@db.ejemplo-interno.mx:5432/clinica_ejemplo"
};
```

<details>
<summary><b>Solución E3</b></summary>

Los seis los detecta `secrets_scan.py` (verificado sobre este fichero: **6
hallazgos, 3 `critico` y 3 `alto`**). El tipo, la severidad y la máscara que
produce son:

| # | Clave | Tipo | Severidad | Enmascarado | Fase 1 (sin addendum) | Fase 2 (con addendum, T6) |
|:-:|---|---|:-:|---|---|---|
| 1 | `pagos` | `stripe_secret_key` | **crítico** | `sk_l******00` | Se documenta la existencia, la ubicación y la huella `sha256[:12]`. **No se usa.** El alcance se pide al cliente (captura de permisos del panel) | **T6**: **una** llamada de lectura al endpoint que el cliente designe por escrito. Se registra el código, los **nombres de campo**, el prefijo enmascarado y la huella. **Nunca** se enumera, ni se filtra, ni se pagina |
| 2 | `mapas` | `google_api_key` | **alto** | `AIza******00` | Se documenta. **Pregunta clave:** ¿esta clave está pensada para ir en el navegador de cada visitante? Si es una clave de cliente restringida por origen, por sí sola **no es un hallazgo**: es INFO | Sólo T6 si el cliente designa por escrito el endpoint. Sin esa autorización escrita, la columna «¿vive?» dice **«no probado»**, no «no» |
| 3 | `nube` | `aws_access_key_id` | **crítico** | `AKIA******00` | Se documenta. Un *access key id* **sin** el *secret* no sirve para nada: es el identificador, no el secreto. Se busca en el mismo repo el `aws_secret_access_key` | Nunca contra AWS: T6 cubre la API del proveedor que el cliente designe. **Nunca** se intenta firmar peticiones con AWS ni se abre una sesión en la consola |
| 4 | `chat` | `slack_webhook` | **alto** | `http******O3` | Se documenta. **No se envía ningún mensaje de prueba**: escribir en un canal del cliente es escribir en un tercero | No hay técnica habilitada para webhooks. Se queda en Fase 1 como «credencial de escritura publicada» |
| 5 | `sesion` | `jwt` | **alto** | `eyJh******00` | **Análisis local y offline**: se decodifica cabecera y carga útil en base64url **sin verificar la firma**, y se leen `alg`, `exp`, `nbf`, `iss`, `aud` y los claims de rol. Si `exp` está vencido, se documenta «expirado» — y sigue siendo PII, así que se redacta | Verificar la **aceptación** por el servidor requiere T1/T4 con la cuenta propia del auditor y el addendum firmado. **Verificar la firma** es una operación criptográfica offline y sólo tiene sentido con la clave |
| 6 | `Basedatos` | `connection_uri_credentials` | **crítico** | `post******mx` | Se documenta: motor (por el **esquema** de la URI), si el host es interno o externo (por el texto), y **el nombre de las variables**, nunca los valores. **No se abre ninguna conexión**: ni TCP, ni `psql`, ni `mysql`, ni `mongosh` | **Nunca.** Conectar a la base de datos es movimiento lateral y requiere una autorización distinta. Y no hace falta: la credencial expuesta es crítica **esté viva o no**; la acción es **rotar**, en los tres casos |

**Lo que la tabla enseña (y es lo que se evalúa):**

| Principio | Aplicación concreta aquí |
|---|---|
| **La forma no basta** | `mapas` y `nube` tienen forma de credencial y **no son** necesariamente un hallazgo. Hay que preguntar para qué se usan |
| **El valor completo no sale nunca** | En el informe: `sk_l******00` + `sha256[:12]`. Nunca `sk_live_EJEMPLO…` |
| **Contar, no recolectar** | El alcance se describe por **categoría** («acceso a la cuenta de cobro»), no por inventario («puede cobrar a estos 4 281 pacientes») |
| **La rotación la hace el cliente** | El auditor no rota, no revoca y no regenera nada en el panel del cliente, ni aunque le lo pidan |
| **Un resultado honesto es un resultado** | Si la fase 2 no autorizó T6, la columna dice **«no probado»**. No dice «muerta» |

**Comprobación.**
`python3 secrets_scan.py ./evidencia --json --out evidencia/secrets.json` sobre
este fichero devuelve 6 hallazgos, 3 críticos y 3 altos, sin escribir ningún
valor completo.

</details>

---

### E4 — Qué redactar (y qué no) en un JSON de paciente ficticio

**Enunciado.** Esta es la respuesta que devolvió un endpoint del cliente en la
Fase 0. **¿Qué campos habría que redactar y qué NO?** Justifica cada decisión,
incluidas las que no son obvias.

**Datos** (`evidencia/cruda/respuesta.json`):

```json
{
  "codigo_http": 200,
  "tabla": "pacientes",
  "registro": {
    "id_expediente": "EXP-2026-00417",
    "nombre": "Ana Ejemplo Ruiz",
    "apellido": "Ejemplo Pardo",
    "fecha_nacimiento": "1984-07-19",
    "curp": "PEAPB840719HDFRX01",
    "rfc": "PEAPB840719HDF",
    "telefono": "+52 55 1234 5678",
    "email": "paciente.ejemplo@correo-ejemplo.mx",
    "direccion": "Calle Ejemplo 123, Col. Centro, 06000 Ciudad de Mexico",
    "diagnostico": "Caries en molar inferior derecho",
    "tratamiento": "Resina y pulpotomia",
    "alergias": "Penicilina",
    "grupo_sanguino": "O+",
    "seguro": "Poliza 88213-447",
    "num_tarjeta": "4111111111111111",
    "cvv": "123",
    "ultima_cita": "2026-10-02"
  }
}
```

<details>
<summary><b>Solución E4</b></summary>

Ejecutando `python3 pii_redact.py evidencia/cruda/ --out-dir evidencia-sanitizada
--report evidencia/redaccion.json` sobre este fichero, **13 de las 19 claves
quedan redactadas** y **6 pasan intactas**. Y aquí está el ejercicio de verdad:
**3 de esas 6 no deberían pasar intactas**, y ninguna de las 3 se arregla
sustituyendo el script por otro script.

**Grupo A — Se redactan automáticamente (13).** Correcto, y son las categorías
del script:

| Clave | Categoría con la que se redacta | Por qué |
|---|---|---|
| `nombre`, `apellido` | `dato_personal_json` | Identifican a la persona |
| `direccion` | `dato_personal_json` | Identifica y además es dato de domicilio |
| `diagnostico` | `dato_personal_json` | **Dato de salud**: la categoría más sensible de todas |
| `tratamiento`, `alergias` | `dato_personal_json` | Datos de salud |
| `seguro` | `dato_personal_json` | Póliza: dato personal y financiero |
| `fecha_nacimiento` | `fecha_nacimiento` | Dato personal y de salud |
| `curp`, `rfc` | `rfc_nif_dni_cuit` | Identificadores nacionales: permiten reconstruir a la persona |
| `telefono` | `telefono` | Dato personal |
| `email` | `email` | Dato personal |
| `cvv` | `tarjeta` | Clave de verificación: sin ella, la tarjeta no sirve |

**Grupo B — NO se redactan y NO deben redactarse (2).** Redactarlos **destruye
la evidencia**:

| Clave | Por qué se conserva |
|---|---|
| `codigo_http` (`200`) | Es **metadato de la respuesta**, no dato de la persona. Sin él, la evidencia deja de poder interpretarse: el lector no sabe si el endpoint devolvió un registro o un error |
| `tabla` (`pacientes`) | Igual: dice **de qué** es el registro. Sin el nombre de la tabla, nadie puede valorar la gravedad. **El nombre de una tabla no es dato personal** |

> Esta es la prueba de que el objetivo de la redacción **no** es «quitar
> todo lo que parezca un dato». Es «que no salga nada que identifique a una
> persona, y que siga saliendo todo lo que hace la evidencia interpretable».

**Grupo C — NO se redactan y SÍ deberían (3).** Aquí el script tiene un
límite, y el límite es su catálogo de claves, que es **una lista cerrada**:

| Clave | Por qué no la coge el script | Remedio exacto |
|---|---|---|
| `id_expediente` | El catálogo trae `expediente` y `num_expediente`, pero **no** `id_expediente` | `--extra-key "id_expediente"` |
| `num_tarjeta` | El catálogo trae `numero_tarjeta`, pero **no** `num_tarjeta` | `--extra-key "num_tarjeta"` |
| `grupo_sanguino` | El catálogo trae `grupo_sanguineo` (con una `e` de más), así que la clave bien escrita no casa | `--extra-key "grupo_sanguino"` |

Comprobado: con las tres banderas, las tres claves pasan a
`[REDACTADO:dato_personal_json]`.

**Grupo D — Criterio humano (1).**

| Clave | Decisión |
|---|---|
| `ultima_cita` (`2026-10-02`) | **Una fecha de cita, por sí sola, no identifica a una persona.** Se conserva si el resto del registro va redactado (así, el lector ve que el endpoint devuelve un registro con una fecha). Se redacta si el mismo fichero se entrega junto a un identificador. **Esta decisión no la toma el script: la tomas tú, y la dejas escrita** |

**Los dos avisos que el ejercicio debe dejar:**

1. **El script no tiene NER.** No encuentra nombres de personas en texto
   libre. En un volcado de texto («La paciente Ana Ejemplo Ruiz fue atendida
   el…») no tocaría nada. Por eso **la revisión manual es obligatoria**: el
   script garantiza las categorías; los ojos garantizan el resto.
2. **El informe de redacción cuenta coincidencias, no redacciones
   efectivas.** En este fichero el informe dice `tarjeta: 2`, pero sólo una
   clave quedó redactada con esa categoría: el número de tarjeta **pasó el
   filtro de Luhn**, pero la regla de contexto decidió no tocarlo (sin
   separadores y sin contexto explícito —«tarjeta», «visa», «cc»…— en la
   ventana de 60 caracteres). El contador es de **patrones encontrados**, no
   de **valores tapados**. Por eso el informe de redacción es un indicador, no
   una garantía: **el control de calidad final es leer el fichero**.

**Qué se entrega.** `evidencia-sanitizada/respuesta.json` (el JSON sigue siendo
válido y parseable) + `evidencia/redaccion.json` (conteos por categoría, nunca
valores) + la nota en el registro de acciones: *«campos añadidos al catálogo
con `--extra-key`: `id_expediente`, `num_tarjeta`, `grupo_sanguino`; campo
`ultima_cita` conservado por decisión del auditor: una fecha de cita aislada no
identifica a una persona»*.

</details>

---

### E5 — Una petición del cliente que no se puede atender

**Enunciado.** Al final de la reunión de alcance, el dueño de la clínica dice:
*«Mira, el otro médico de la clínica está conmigo. Entra al panel y revisa si su
contraseña está bien puesta, que yo no me acuerdo de cuál es.»* **¿Qué
respondes?** Escribe la respuesta profesional al cliente, el escalado interno y
la documentación que dejas.

<details>
<summary><b>Solución E5</b></summary>

**Por qué no se puede hacer. Tres razones, y todas son duras:**

| Razón | Remisión |
|---|---|
| **Es autenticación, y el RoE la prohíbe sin excepción.** «Entrar al panel» implica usar credenciales y abrir una sesión. El RoE prohíbe login, credenciales y formularios, y sólo permite `GET`/`HEAD` — y eso vale aunque la cuenta sea del propio cliente, porque la prohibición es sobre el **método**, no sobre la titularidad | RoE §1.1 y §4 (prohibido: «Login, credenciales, formularios, autenticación») |
| **Es la cuenta y los datos de una persona concreta.** Tu autorización es sobre el **dominio del cliente**, no sobre las cuentas de las personas que lo usan. Manejar las credenciales de otro médico es manejar un dato personal que nadie te ha entregado, aunque trabaje en la misma sede | RoE §1.2 |
| **Probarla sería de-anonimización.** Si además se comprobaran contraseñas candidatas contra esa cuenta, estarías ejecutando una capacidad ofensiva. Prohibida sin excepción | RoE §1.3 |

Y una razón práctica, que además es la que hace que esto sea rentable en vez
de un no: **aunque el otro médico fuera el propietario del panel**, seguirías
necesitando su autorización por escrito y el mismo soporte de evidencia. El
esfuerzo de hacerlo bien no es menor: es otro RoE.

**La respuesta al cliente (modelo).**

> «Con gusto, pero no puedo entrar a una cuenta que no sea de prueba, y te
> explico por qué, porque es la diferencia entre una revisión de seguridad y
> un problema legal.
>
> Mi autorización es sobre **tu** sitio, no sobre las cuentas de las personas
> que usan el sitio. Y además, mi RoE —que es el documento que firmaste— dice
> explícitamente que no hay login ni credenciales. Entrar al panel es
> justamente lo que no puedo hacer, aunque me lo pidas tú y aunque el médico
> esté de acuerdo: la protección de ese punto no depende de la confianza
> entre nosotros, depende de que el procedimiento sea el mismo siempre.
>
> **Lo que sí puedo hacer, hoy mismo:**
>
> 1. **Revisar la configuración del panel sin entrar**, desde fuera: si expone
>    versiones, si el directorio está abierto, si hay recuperación de contraseña
>    abierta, si el cifrado de la sesión está bien configurado. Eso lo hago con
>    la Fase 0 que ya contrataste y no necesita ninguna cuenta.
> 2. **Pedirte que él cree una cuenta de prueba**, con datos que no sean de
>    pacientes, y que me la dé por escrito junto con la de otro usuario de
>    prueba. Con eso, y sólo con eso, puedo probar el control de acceso por
>    objeto —que es lo que de verdad importa: si un usuario puede ver lo de
>    otro— en la Fase 2, con ventana y con un "go" tuyo en cada prueba. El
>    resultado es un hallazgo con evidencia que tu equipo puede reproducir.
> 3. **Daros una lista de comprobación para la contraseña**, escrita para que la
>    aplique el propio médico: longitud, unicidad respecto a otros servicios,
>    gestor de contraseñas, segundo factor. Eso lo hace él en diez minutos y
>    no necesita que nadie entre a su cuenta.
>
> Lo que **no** voy a hacer, y no por desconfianza sino por procedimiento, es
> entrar a una cuenta real. Si el problema es que no saben cuál es la
> contraseña, eso tiene una solución administrativa que no pasa por mí.»

**El escalado interno.** Si el cliente insiste, o si el otro médico es
co-propietario del negocio:

| Paso | Acción |
|:-:|---|
| 1 | **No acceder.** La negativa no es negociable ni por autoridad del cliente: es una prohibición dura del RoE |
| 2 | **Registrar la petición** antes de contestar, en el registro de acciones: fecha, canal, quién pidió, qué pidió literalmente, qué se respondió |
| 3 | **Escalar al firmante del RoE.** Si quien pidió tiene facultad para ampliar el alcance (es decir, si es el titular o un representante con facultades), el camino es **modificar el RoE y firmarlo**, no hacerlo «esta vez porque es el director». La ampliación se firma **con fecha y con técnicas enumeradas**, y en un RoE aparte si es Fase 2 |
| 4 | **Documentar la negativa** con los cuatro campos del módulo M0: qué se pidió, por qué no se hace, qué se ofrece en su lugar, quién decide |

**La documentación que queda (misma estructura que la del módulo M0).**

| Campo | Contenido |
|---|---|
| Qué se pidió | «Entrar al panel del usuario del segundo médico y comprobar su contraseña», 2026-11-17, reunión de alcance, en persona |
| Por qué no se hace | RoE §1.2 (datos de terceros), §1.1 (prohibido autenticación y login), §1.3 (de-anonimización) |
| Qué se ofrece en su lugar | Revisión externa de la configuración del panel; cuentas de prueba del cliente para la Fase 2; lista de comprobación de contraseña para el propio médico |
| Quién decide | El firmante del RoE, si decide ampliar el alcance, mediante RoE modificado y firmado |

**La lección de fondo.** La negativa documentada **no es un problema
comercial**: es la prueba de que el procedimiento es creíble. La confianza de
un tercero no se gana con un «sí» conveniente, se gana con un «no» que se
sostuvo cuando le convenía decir que sí.

</details>

---

### E6 — Concluir correctamente sobre las versiones de TLS

**Enunciado.** En la primera pasada, Joanne guardó esto como
`evidencia/tls_floor.txt` y escribió en su borrador: *«el servidor acepta
TLS 1.0»*. **¿Es cierto? ¿Qué hay que volver a hacer y qué se escribe en el
informe?**

**Datos** (`evidencia/tls_floor.txt`):

```text
$ curl -sS --tlsv1.0 https://www.clinica-ejemplo.mx/ -o /dev/null \
      -w 'code=%{http_code} ssl_verify=%{ssl_verify_result} version=%{ssl_version}\n'
code=200 ssl_verify=0 version=TLSv1.3

$ openssl s_client -connect www.clinica-ejemplo.mx:443 -tls1
no protocols available
```

<details>
<summary><b>Solución E6</b></summary>

**No, no es cierto. Es un falso positivo, y lo es por dos razones
independientes que se refuerzan.**

**Razón 1 — `--tlsv1.0` es un MÍNIMO, no un valor exacto.** En `curl`,
`--tlsv1.x` fija la versión *mínima* negociable; no restringe a esa versión.
El servidor negocia **TLS 1.3** y devuelve `200`. La prueba no dice absolutamente
nada sobre TLS 1.0.

> **Y la prueba se delata sola en su propia salida:** `version=TLSv1.3`. Ese
> campo es exactamente el que faltaba leer en el caso de referencia.
> `ssl_verify=0` significa «verificación SSL correcta», **no** «se usó SSL»: la
> señal de que la conexión no fue TLS era que no aparecía el indicador
> correspondiente, y se ignoró.

**Razón 2 — el error de OpenSSL era local, no del servidor.** `no protocols
available` es la **política local** de OpenSSL 3.x (nivel de seguridad, y el
provider `legacy` deshabilitado por defecto). No dice nada del servidor. Sin
forzar `-provider legacy -provider default`, ese error no es evidencia de nada.

**Qué hay que volver a hacer: fijar el máximo y forzar el provider.**

```text
$ curl -sS --tlsv1.0 --tls-max 1.0 https://www.clinica-ejemplo.mx/ -o /dev/null \
      -w 'code=%{http_code} version=%{ssl_version}\n'
curl: (35) error:0A000410:SSL routines::sslv3 alert protocol version
code=000 version=(none)
```

> El texto literal del error varía según la versión de `curl`/`OpenSSL`. Lo que
> **no** varía es `version=(none)` y el **alert 70** (`protocol version`):
> el servidor **rechaza** la versión.

Y para las versiones que sí deben estar soportadas, la versión **realmente
negociada**:

```text
$ openssl s_client -connect www.clinica-ejemplo.mx:443 -tls1_2 < /dev/null | grep -E '^New,|^Protocol'
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Protocol  : TLSv1.2

$ openssl s_client -connect www.clinica-ejemplo.mx:443 -tls1_3 < /dev/null | grep -E '^New,|^Protocol'
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol  : TLSv1.3
```

**La conclusión correcta, y cómo se escribe:**

> **TLS 1.0 y TLS 1.1 son rechazados correctamente por el servidor (alert
> `protocol version`). TLS 1.2 y TLS 1.3 están soportados.** Severidad:
> **INFO** — es un hallazgo **positivo**, no una vulnerabilidad. Poner TLS 1.3
> en marcha es una de las medidas con mejor coste/beneficio de la lista.

**Y el hallazgo original se corrige, no se borra.** En la primera pasada, el
mismo sitio se reportó como vulnerable a TLS 1.0. La corrección se escribe
explícitamente en el informe, rotulada como corrección, y el fichero con el
falso positivo **se conserva**:

| Artefacto | Estado |
|---|---|
| `evidencia/tls_floor.txt` | **Se conserva.** Contiene la evidencia del error. Un directorio donde todo salió bien a la primera es sospechoso |
| `evidencia/tls_versions.txt` | La evidencia buena, con la línea `New, TLSv1.x` explícita en cada versión |
| Fila en el registro de acciones | «CORRECTION to prior pass»: qué se dijo, por qué estaba mal, cuál es la afirmación correcta |
| Fila del registro de riesgo | Severidad **INFO**, con la nota de que corrige un hallazgo anterior |

**La regla que sale de aquí, y que es la lección (b) del ciclo:**

> **Nunca afirmes qué versiones TLS acepta un servidor a partir de un cliente
> que puede tenerlas deshabilitadas, ni a partir de un flag que significa
> «mínimo».** Para cada versión: fija el máximo, fuerza el provider legacy si
> el error es local, y lee qué versión se negoció realmente.
> **Si el cliente no puede ni intentar la versión, el resultado es
> *inconcluyente*, no negativo ni positivo.**

> **La lección mayor no es sobre TLS.** Es que **un resultado que no se puede
> distinguir de un error del propio cliente nunca debe convertirse en un
> hallazgo.** Cuando dudes, es `INFO`, no `MEDIO`.

</details>

---

### E7 — Calcular el índice de exposición a mano

**Enunciado.** El `attack_surface_report.py` no ha podido ejecutarse (no hay
fichero de DNS). **Calcula a mano el índice** con los cuatro componentes que sí
tienen evidencia, di la banda y explica qué parte del cálculo **no** puedes
hacer y qué significa eso.

**Datos** (resumen de la evidencia local):

| Componente | Tipo | Máximo | Puntos | Por qué |
|---|---|---:|---:|---|
| `secretos_expuestos` | riesgo | 18 | 10.0 | 1 hallazgo `critico` (6.0) + 1 `alto` (4.0), según `SECRET_WEIGHT` |
| `ficheros_expuestos` | riesgo | 16 | 11.0 | 1 ruta `critico` (5.0) + 1 `alto` (4.0) + 1 `medio` (2.0), según `PATH_WEIGHT`, **sólo** las filas con `verdict=expuesto` |
| `ausencia_dmarc` | riesgo | 6 | 6.0 | La sección DMARC está en `dns_mailsec.txt` pero **no** contiene ningún registro `v=DMARC1` |
| `tls_fuerte` | bonificación | 6 | −6.0 | TLS 1.3 disponible y **sin** versiones legacy en `tls_versions.txt` |

<details>
<summary><b>Solución E7</b></summary>

**La fórmula** (del propio script, no de memoria):

```
total = min(100, max(0,  Σ riesgo − Σ bonificación))
```

con la bonificación **acotada** a 30 puntos (`MAX_BONUS`) y las bandas:

| Índice | Banda |
|---|---|
| 0 – 19.9 | Bajo |
| 20 – 39.9 | Moderado |
| 40 – 59.9 | Alto |
| 60 – 79.9 | Crítico |
| 80 – 100 | Severo |

**El cálculo:**

```
riesgo      = 10.0 + 11.0 + 6.0 = 27.0
bonificación= 6.0
total       = min(100, max(0, 27.0 − 6.0)) = 21.0
banda       = Moderado   (20 – 39.9)
```

**Índice: 21.0/100 — banda Moderado.**

**Lo que NO puedes calcular, y qué significa (esto es lo importante):**

| Componente que falta | Qué hace el script sin datos | Consecuencia para el índice |
|---|---|---|
| Los 11 componentes de riesgo restantes y los 5 de bonificación | Valen **0** y se marcan **«sin datos»**. Cada línea del informe lleva su fuente (`evidencia: <fichero>` o `sin datos`) | El índice de 21.0 **subestima** el riesgo real. Los 21.0 miden **lo que se midió**, no lo que hay |
| `ausencia_dmarc` sin evidencia de DNS | No se puntúa (0) y el script dice «Sin sección DMARC en la evidencia: **no se puede afirmar su ausencia**» | Un componente que vale 0 por falta de datos **no es un componente que vale 0 por estar bien** |

**Por qué esto importa en el informe.** Un 21/100 sin decir «esto cubre cuatro
componentes de trece y el resto está sin datos» es **una afirmación falsa**:
lee como «este sitio está casi bien» cuando lo que se sabe es «aquello que
miramos está moderadamente mal». La línea que hay que escribir al lado del
índice es, literalmente, la que ya usa el script:

> **Índice de exposición: 21.0/100 (banda Moderado). Calculado sobre 4 de 19
> componentes con evidencia; los restantes se puntúan 0 por ausencia de datos.
> *Sin datos no es «sin riesgo».***

Y una segunda regla, más fina: `ausencia_dmarc` puntúa 6.0 **cuando** la
sección DMARC está en el fichero y **no** hay registro `v=DMARC1` (o sea: está
publicado y vacío o mal formado). Si el fichero no tiene sección DMARC, el
componente vale 0 y dice «no se puede afirmar su ausencia». **Ausencia de
evidencia y evidencia de ausencia son cosas distintas**, y el índice las
distingue porque el texto de cada línea lo dice.

**Comprobación.** Con `attack_surface_report.py` y `--dns-mailsec` ausente, el
componente `ausencia_dmarc` aparece con 0 puntos y detalle «Sin sección DMARC
en la evidencia…». Con el fichero presente, 6.0.

</details>

---

### E8 — Reescribir una afirmación que promete de más

**Enunciado.** Joanne escribió esto en el informe técnico: *«Los datos de sus
pacientes son accesibles a través de un endpoint público.»* **Reescríbelo** en
un párrafo que sea honesto, no destructivo y accionable. ¿Qué información se
puede decir y cuál no?

<details>
<summary><b>Solución E8</b></summary>

**Por qué el párrafo original es un problema.** Cuatro fallos en una frase:

| Fallo | Por qué |
|---|---|
| «los datos de sus pacientes **son accesibles**» | Afirma un hecho que **no se comprobó**. No se abrió ninguna conexión, no se obtuvo ninguna ficha y no se listó nada. Lo que se observó es una **capacidad**, no un acceso |
| «sus pacientes» | Confunde el sujeto: el endpoint devolvió una respuesta; quién es el paciente de esa respuesta no se sabe, y el contexto del cliente hace **presumir** datos de pacientes sin **demostrarlo** |
| Sin evidencia | No hay código de respuesta, ni ruta, ni cuenta, ni tamaño, ni comando reproducible. Violación de la regla de oro: sin fichero de evidencia, no hay hallazgo |
| Sin acción | No dice qué hacer, ni quién, ni cuándo |

**El párrafo honesto (modelo):**

> **F-07 — Endpoint de fichas de paciente sin control de acceso observado.**
> **Severidad: ALTO** (calibrada por el tipo de dato que el endpoint parece
> servir y por el contexto de datos de salud; **no** verificada por lectura de
> contenido real).
>
> `GET https://api.ejemplo.mx/api/v1/pacientes/{id}` respondió **HTTP 200**
> `application/json` **sin credenciales** en la petición, con un cuerpo JSON
> cuyas **claves** son `id`, `nombre`, `apellido`, `fecha_nacimiento`,
> `diagnostico` y `expediente`, y una **longitud** de 412 bytes.
> **Evidencia:** `evidencia/probe_exposure.tsv` (fila `/api/v1/`) y
> `evidencia/cruda/api_v1_200.json` (redactada con `pii_redact.py`; ver
> `evidencia/redaccion.json`). **Comando de reproducción:**
> `curl -sS -D - -A "$UA" https://api.ejemplo.mx/api/v1/pacientes/1 -o /dev/null`
> (`{id}` de ejemplo; **no** se enumeraron identificadores).
>
> **Lo que NO se hizo:** no se enumeraron identificadores, no se listó el
> directorio de pacientes, no se leyó ni se transcribió ninguna ficha, no se
> contó cuántos registros existen y no se intentó autenticación. **El
> contenido de la respuesta no se conserva ni se entrega.**
>
> **Qué hay que hacer:** (1) el equipo de sistemas debe confirmar en el código
> que el endpoint exige sesión y comprobación de propiedad del registro;
> (2) si el control existe pero no se aplica a este endpoint, corregirlo y
> verificarlo con la cuenta de prueba del cliente; (3) hasta entonces, tratar
> el endpoint como si devolviera datos de salud y **restringirlo** por firewall
> o por sesión obligatoria.
> **Dueño:** equipo de sistemas / proveedor de la API. **Esfuerzo estimado:**
> 4 h. **Evidencia de cierre:** la misma petición con la cuenta de prueba
> devuelve `401`/`403`.

**Qué se puede decir y qué no, en general:**

| Se puede decir | No se puede decir |
|---|---|
| «El endpoint respondió `200` **sin credenciales**» | «Los datos de sus pacientes son accesibles» |
| «Las claves del JSON son `nombre`, `apellido`, `diagnostico`…» | Los valores de esas claves, ni un ejemplo |
| «El cuerpo tenía 412 bytes» | Cuántos registros hay, ni cuántos pacientes |
| «El control de acceso por objeto **no se observó** en esta prueba» | «El control de acceso por objeto **no existe**» (eso requiere las dos cuentas de prueba) |
| «Severidad ALTO, **no verificada**» | «Severidad CRÍTICO» sin haber visto un dato de salud |
| «No enumeré identificadores ni leí fichas» | Nada que sugiera que sí lo hiciste |

**Y el remate honesto, que es el que más cuesta escribir:** si el control de
acceso por objeto no se ha probado —porque no había dos cuentas de prueba—,
el informe dice, con este formato exacto:

> **NO VERIFICADO — IDOR / BOLA en `/api/v1/pacientes/{id}`**: requiere **dos
> cuentas de prueba con datos sintéticos**.
> **No se ejecutó porque:** el cliente no entregó las cuentas.
> **No se ejecutó porque habría supuesto:** leer registros que no son del
> auditor, o tocar fichas de pacientes reales.
> **Cómo cerrarlo (el cliente, en 60 segundos):** crear dos cuentas de prueba y
> repetir la petición con cada una.
> **Severidad si se confirma:** CRÍTICO — **no es un riesgo bajo; es un riesgo
> sin medir.**

**Por qué esto importa más de lo que parece.** Un párrafo como el original
destruye la confianza en el resto del informe. Y hay un motivo práctico: si el
cliente descubre que el auditor afirmó algo que no comprobó, **todas** las
afirmaciones del informe pasan a estar bajo sospecha, incluidas las que eran
correctas. Un párrafo honesto y acotado cuesta tres líneas; un párrafo
exagerado cuesta el contrato.

</details>

---

## 6. Rúbrica de evaluación del auditor

Tres niveles. El **nivel 1 (aprendiz)** es el de la auditoría 1 y 2; el **nivel 2
(autónomo)** es con el que se firma un RoE como auditor principal; el **nivel 3
(supervisor)** es el que permite revisar el trabajo de otro.

**Cómo se usa.** En la auditoría 3 y en la 4, el mentor evalúa cada competencia
y escribe **una evidencia concreta**, no una impresión. Una competencia sin
evidencia no está evaluada. En la auditoría 1 y 2, la autoevaluación usa la
misma tabla: el aprendiz marca su nivel y anota la evidencia que lo sostiene.

**Escala:** 🔵 1 · 🟡 2 · 🟢 3. Por debajo de 1 se considera «no evaluado».

| # | Competencia | 🔵 Nivel 1 — aprendiz | 🟡 Nivel 2 — autónomo | 🟢 Nivel 3 — supervisor | Cómo se evalúa | Evidencia que lo demuestra |
|:-:|---|---|---|---|---|---|
| 1 | **Marco deontológico y RoE** | Reconoce las 5 prohibiciones y las recite; necesita que le recuerden el ritmo y el UA | Opera dentro del RoE sin recordatorios; sabe decir por qué cada prohibición existe; redacta la negativa documentada con las 4 campos | Diseña la cláusula de negativa para un cliente nuevo; revisa el RoE de otro auditor y detecta la técnica que no debería estar | Revisión del RoE antes de cada auditoría; **preguntas trampa** en la reunión de alcance («¿necesita que entremos a ver la contraseña del socio?») | RoE firmado con las prohibiciones marcadas · una negativa documentada en el registro de acciones |
| 2 | **Recon pasivo y fuentes de terceros** | Consulta crt.sh y Wayback cuando se le dice; no sabe decir de dónde salió un dato | Monta la Fase 0 completa, distingue «lo que sé» de «lo que supongo» y **cita la fuente de cada línea** de su inventario | Enseña el método a otro, sabe qué se sacrifica al no escanear, y reconoce cuándo una fuente de terceros está sesgada | Comparar el inventario de superficie con el del mentor sobre el mismo objetivo | Bitácora de Fase 0 con la columna «fuente» rellena · el inventario coincide con el del mentor en ≥ 80 % de las líneas |
| 3 | **Lectura de evidencia (TSV, JSON, cabeceras)** | Distingue un código 200 de un 404; le cuesta leer un TSV de 53 filas | Distingue `verdict=soft_404` de `expuesto`, y `401/403` de `404`; usa `content_type` y `sha256` como evidencia, no sólo el código | Sabe cuándo el `sha256` de la referencia 404 **no es concluyente** (páginas de error dinámicas) y cuándo hace falta una comprobación manual | Ejercicio E2 + revisión del TSV de una auditoría real | TSV propio con la columna `verdict` bien leída · cero filas soft-404 reportadas como hallazgos |
| 4 | **Verificación contra fuente primaria (lección a)** | Repite lo que dice el escáner | Contrasta cada versión y cada CVE contra la API de versiones o el aviso oficial; marca **NO VERIFICADO** cuando no llega | Decide cuándo una discrepancia entre herramienta y fuente primaria **cambia la severidad**, y lo documenta | Auditoría 3: el mentor pide la URL de la fuente de cada CVE del informe | En el informe, cada afirmación de versión con su URL de fuente primaria, y cada CVE sin fuente con la marca NO VERIFICADO |
| 5 | **Correctitud en el transporte (lección b)** | Repite el resultado de `curl --tlsv1.0` | Aplica `--tls-max`, fuerza el provider legacy y **lee la versión negociada**; sabe que `ssl_verify_result=0` no significa «se usó TLS» | Detecta un falso positivo de TLS en la evidencia de otro y escribe la corrección sin destruir el fichero original | Ejercicio E6 + auditoría 4 | `tls_versions.txt` con la línea `New, TLSv1.x` en cada versión · cero afirmaciones de versión TLS derivadas de un flag de mínimo |
| 6 | **Disciplina de alcance con la toolchain** | Usa los scripts con la plantilla de ejemplo | Ejecuta `--dry-run` **siempre** antes de la sonda; sabe que el guard recorta los métodos a GET/HEAD y que `max_bytes` limita la lectura; sabe que `authorization.json` sin firma aborta con código 2 | Diseña el `authorization.json` de un cliente nuevo, con comodines y lista de hosts correctos, y sabe por qué el comodín `*.ejemplo.mx` **no** cubre el apex | Auditoría 3: el mentor revisa el `--dry-run` antes de la primera petición | El plan de sondeo revisado antes de ejecutarse · cero peticiones fuera del allowlist · cero `POST` en el registro |
| 7 | **Redacción y minimización de datos** | Usa `pii_redact.py` porque se lo han dicho | Sabe qué redacta y qué **no**; añade `--extra-key` cuando el catálogo no cubre la clave; **lee a mano** los extractos de texto libre | Escribe la política de minimización de un encargo con datos clínicos, y sabe cuándo un dato debe **contarse** en vez de **copiarse** | Ejercicio E4 + control de calidad del entregable (los `grep` de la §9.4 del módulo de secretos) | `evidencia/redaccion.json` con conteos y sin valores · el informe de redacción no contiene ni un valor |
| 8 | **Rigor de la evidencia** | Cada hallazgo lleva su fichero de evidencia | Cada hallazgo lleva evidencia **y** comando reproducible; cada «no comprobado» lleva NO VERIFICADO + requisito + comando de 60 segundos | Audita la evidencia de otro y encuentra la afirmación que no está respaldada por ningún fichero | Auditoría 3: el mentor toma 5 filas al azar del registro y pide el fichero y el comando | `registro-de-acciones` con `evidencia` y `comando_reproduccion` rellenos en el 100 % de las filas |
| 9 | **Calibración de severidad** | Usa la severidad que trae la herramienta | Recalibra por **contenido**, mira qué hay detrás del hallazgo y nunca infla; escribe «no verificado» con la severidad **si** se confirma | Sostiene una severidad ALTA frente a un cliente que pide que la bajes, y la sostiene con evidencia | Auditoría 4: el mentor pide justificar cada CRÍTICO y cada ALTO | La matriz de severidad con las tres preguntas contestadas por hallazgo; el informe no contiene ningún «crítico (probable)» |
| 10 | **Reporte en tres capas** | Escribe un informe técnico correcto | Escribe las tres capas, con el teaser **cero técnico** y el informe técnico **confidencial**; incorpora «lo que ya está bien» | Redacta el brief de lenguaje llano para un dueño que no va a leer nada técnico, y los borradores de ticket para hosting y agencia | Auditoría 4: el mentor verifica el teaser con `verify.py` y revisa la separación de audiencias | Los tres documentos + el log del `verify.py` · la sección «lo que ya está bien» con la misma precisión que los negativos |
| 11 | **Fase 2: protocolo de prueba sin daño** | Entiende que hay que pedir el «go» | Ejecuta una técnica con "go" por prueba, respeta los criterios de abort y rellena el registro de acciones | Conduce la ventana, decide el abort y redacta la declaración de limpieza firmada | Auditoría 4: el mentor está al teléfono y da el "go"; el registro se revisa fila por fila | `registro-de-acciones-fase-2.csv` con las técnicas **refutadas** y **no ejecutadas** también · anexo con el apartado «Lo que NO se hizo» |
| 12 | **Trabajo en equipo y revisión del propio trabajo** | Escribe su bitácora cuando se le pide | Documenta sus decisiones para que otro las entienda; pide revisión antes de enviar | Revisa el trabajo de otro auditor, encuentra los errores y los explica sin humillar | Revisión cruzada en la auditoría 4: cada auditor revisa el informe del otro | Notas de revisión cruzada · bitácora de decisiones de la auditoría 4 |

**Regla de promoción.** Se pasa de 🔵 a 🟡 en una competencia cuando hay
**al menos dos auditorías** con 🔵 y la siguiente con 🟡, **y** la evidencia
está en disco. No se pasa por «buena impresión en la reunión»: la evidencia es
el criterio.

**Regla de bloqueo.** Si en la auditoría 3 o 4 aparece una **violación de una
prohibición dura** (un POST, una lectura de datos de terceros, un uso de la
credencial encontrada, una prueba sin "go"), el proceso se detiene y se repasa
M0 **completo** antes de continuar. No es una sanción: es que el primer
incidente de una auditoría es el más barato.

---

## 7. Plan de sombra y mentoría

Cuatro auditorías. La primera es **de observación**: el aprendiz no toca nada.
Las duraciones son **orientativas** y dependen del tamaño del cliente.

### 7.1 Auditoría 1 — Modo sombra (observa)

| | |
|---|---|
| **Qué hace el aprendiz** | Acompaña al mentor. No ejecuta peticiones, no escribe en la evidencia. Toma notas y hace preguntas. Escribe su **bitácora de observación** al final |
| **Qué hace el mentor** | Ejecuta y **narra en voz alta**: «esto lo hago así porque…», «aquí podría haber un soft-404, ¿lo ves?», «esto ya es un hallazgo y esto no, ¿por qué?» |
| **Duración orientativa** | 5–8 h de observación + 3 h de bitácora |
| **Qué aprende** | El orden real de las decisiones: qué se mira primero, qué se descarta y por qué, cuándo se pide permiso |
| **Bitácora de observación (entregable)** | Diez preguntas del mentor con tu respuesta y con lo que **creías** que había pasado. El mentor marca las que estaban mal. Es el primer termómetro |

### 7.2 Auditoría 2 — Fase 0 con revisión

| | |
|---|---|
| **Qué hace el aprendiz** | Ejecuta la Fase 0 (recon pasivo) completo: las 11 fases del ciclo, en especial las 2–7. Toma todas las decisiones él mismo |
| **Qué hace el mentor** | Revisa **cada artefacto** antes de que salga del escritorio: la bitácora de superficie línea por línea, y el origen de cada dato. No corrige: pregunta («¿de dónde sale esto?», «¿qué harías si esto fuera un soft-404?») |
| **Duración orientativa** | Fase 0 completa (10–18 h de carga) con revisión |
| **Lo que se valida** | El módulo M0 (RoE) y el M1 (recon pasivo) |
| **La regla del mentor** | Se permite que el aprendiz se equivoque en la **recolección**. No se permite que se equivoque en el **alcance**. Cualquier petición fuera del RoE se para en el acto, sin discusión |

### 7.3 Auditoría 3 — Fase 1 con revisión

| | |
|---|---|
| **Qué hace el aprendiz** | Ejecuta la Fase 1 (validación activa): la sonda GET/HEAD sobre la lista fija de rutas, el escaneo local de secretos, el informe de cabeceras, el score, y **redacta las tres capas** del informe |
| **Qué hace el mentor** | Revisa el `--dry-run` **antes** de la primera petición. Revisa el TSV, el `secrets.json` y el registro de acciones antes de la redacción. Y hace la revisión final del informe |
| **Duración orientativa** | Fase 1 completa (20–35 h de carga) con revisión |
| **Lo que se valida** | Los módulos M2 (toolchain), M3 (evidencia y redacción) y M5 (reporte) |
| **El hito** | El mentor firma el **primer informe** del aprendiz. Hasta ese momento, todo lo que ha salido lo ha revisado alguien |

### 7.4 Auditoría 4 — Fase 2 como segundo, con el senior al teléfono

| | |
|---|---|
| **Qué hace el aprendiz** | Es el **segundo** en la ventana: el mentor ejecuta y el aprendiz lleva el registro de acciones, la evidencia y las notas. En las técnicas de menor impacto (T1-A, T3, T4) puede ejecutar él, con el mentor al teléfono |
| **Qué hace el mentor** | Está **al teléfono** durante toda la ventana, es quien pide el «go» al cliente y quien puede parar la ejecución en cualquier momento |
| **Duración orientativa** | Una ventana de 3 h + preparación y redacción (16–28 h de carga) |
| **Lo que se valida** | El módulo M4 (Fase 2) y el cierre del ciclo |
| **Condición para que ocurra** | RoE base firmado **y** addendum de Fase 2 firmado por las tres partes. Sin las dos firmas, la auditoría 4 se hace **en papel**: se redacta el addendum y el anexo con un caso simulado |

### 7.5 El mapa de responsabilidades

| Hito | Quién decide | Quién ejecuta | Quién revisa | Quién firma |
|---|---|---|---|---|
| RoE | Cliente y auditor | Aprendiz | Mentor | Cliente + auditor |
| Addendum de Fase 2 | Las tres partes | — | Mentor | Cliente + responsable técnico + auditor |
| Evidencia de Fase 0/1 | — | Aprendiz | Mentor (antes de que salga) | — |
| "Go" por prueba | Responsable técnico del cliente | Aprendiz (o mentor) | Mentor al teléfono | — |
| Informe técnico | — | Aprendiz | Mentor | Auditor |
| Entrega de las tres capas | — | Aprendiz | Mentor | Auditor |

### 7.6 Qué hace el mentor cuando hay un error

No lo corrige en el entregable. Hace tres cosas, en este orden:

1. **Deja que el error llegue al entregable** (si es recuperable). Un error
   detectado por el mentor y corregido en silencio no enseña nada; el mismo
   error detectado por el cliente sí.
2. **Escribe la corrección con su nombre.** Un informe con la corrección
   visible es mejor que un informe sin errores: es la metodología funcionando.
3. **Añade el error a la lista de reincidencias** (§4 de esta guía). Si un error
   aparece tres veces, es un hueco de formación: se arregla en el módulo
   correspondiente, no con una nota en el informe.

---

## 8. Glosario

Términos que aparecen en el playbook y en los informes. Definición de una
línea, en español, sin jerga innecesaria.

| # | Término | Definición |
|:-:|---|---|
| 1 | **Superficie de ataque** | El conjunto de todo lo que un atacante puede alcanzar en un sistema: rutas, ficheros, dominios, puertos, APIs y controles de acceso |
| 2 | **Superficie de exposición** | La parte de la superficie de ataque que es alcanzable **sin autenticación** y sin ninguna condición previa |
| 3 | **Indicador de compromiso (IoC)** | Una señal observable de que un activo ya fue tocado o usado por un tercero: un subdominio nuevo, un certificado emitido, un registro en los logs |
| 4 | **Volumen de ataque** | El número de intentos hostiles contra un sitio. **No es medible desde fuera**: vive en los logs del cliente, no en ningún índice público |
| 5 | **Blast radius** | El radio de impacto: a quién y a qué alcanza un problema cuando se explota. Un backup expuesto en un hosting compartido tiene un blast radius mayor de lo que parece |
| 6 | **Footprint (huella)** | Rastro que deja una acción: una entrada en el log del servidor, un intento de login, una entrada en el log de acceso de un proveedor |
| 7 | **Soft-404** | Un servidor que responde `200` con la página de error para cualquier ruta. Hace que rutas inexistentes parezcan expuestos |
| 8 | **RoE (Rules of Engagement)** | El documento firmado que define qué se puede tocar, cómo, cuándo y qué está prohibido. Sin RoE firmado no empieza la auditoría |
| 9 | **Addendum** | Documento firmado que amplía el RoE en un punto concreto (por ejemplo, la Fase 2). No sustituye al RoE: lo amplía y deja el resto intacto |
| 10 | **DPA / contrato de tratamiento de datos** | El acuerdo entre el cliente y quien trata sus datos por encargo del cliente (hosting, proveedor de formularios, SaaS). El playbook no lo redacta: señala qué debe obtener el cliente |
| 11 | **Dato sensible** | Dato personal que requiere un nivel de protección reforzado. Los **datos de salud** (diagnóstico, tratamiento, receta, alergias, grupo sanguíneo, historial de citas) son la categoría más sensible de todas |
| 12 | **Minimización de datos** | Guardar y entregar sólo lo necesario para sostener el hallazgo. Se opone a la «recolección»: se demuestra **contando**, no copiando |
| 13 | **IDOR / BOLA** | Referencia directa a un objeto no autorizada: un usuario autenticado que lee un registro que pertenece a otra cuenta. Se demuestra con dos cuentas de prueba, comparando código, claves y longitud |
| 14 | **Mass assignment** | Sobreescritura de campos: enviar al servidor un campo de control (`role`, `precio`, `estatus`) que el cliente no debería poder fijar |
| 15 | **SSRF** | Que el servidor, al procesar una petición, haga peticiones a donde le digan. Puede usarse para alcanzar la red interna del cliente |
| 16 | **XSS** | Que se ejecute código en el navegador de otra persona. En Fase 2 se demuestra con un **marcador de texto**, sin `script`, sin `onerror`, sin beacon |
| 17 | **SQLi** | Que un parámetro entre en una consulta SQL y acepte una condición. En Fase 2 sólo booleana, sin `UNION`, sin `;`, sin extraer filas, sin técnica de tiempo |
| 18 | **CSP (Content-Security-Policy)** | Cabecera que dice al navegador qué scripts y recursos puede cargar. Es el límite de contención de un XSS |
| 19 | **HSTS (Strict-Transport-Security)** | Cabecera que obliga al navegador a usar HTTPS en las visitas siguientes, evitando el descenso a HTTP |
| 20 | **DMARC** | Registro DNS que dice qué hacer con los correos que dicen venir de tu dominio. Sin DMARC, el dominio es falsificable |
| 21 | **SPF** | Registro DNS que enumera los servidores autorizados a enviar correo del dominio. Terminar en `~all` es *softfail*: muchos receptores lo entregan igual |
| 22 | **DKIM** | Firma criptográfica que el receptor comprueba para saber que el correo no fue alterado. Un solo selector impide rotar sin añadir registros |
| 23 | **CAA** | Registro DNS que restringe quéAutoridades de Certificación pueden emitir certificados para el dominio. Su ausencia deja la puerta abierta a cualquier CA pública |
| 24 | **SRI (Subresource Integrity)** | Atributo `integrity` en un `<script>`: el navegador sólo lo ejecuta si el fichero tiene el hash esperado. Evita que un CDN comprometido inyecte código |
| 25 | **JWKS** | El conjunto de claves públicas con las que un servicio verifica sus tokens. Es público por diseño; el error típico es usarlo como secreto en un algoritmo HMAC |
| 26 | **Token de servicio** | Credencial que autentica a un proceso, no a una persona: una *service account*, un bot, unas credenciales de CI/CD. No tiene dueño humano ni expira solo |
| 27 | **Prefijo de JWT (`eyJ`)** | Los tres primeros caracteres de la cabecera de un JWT en base64url. Sirve para **reconocer** un token en un fichero, no para validar nada |
| 28 | **CORS** | El mecanismo del navegador que decide si una página de otro origen puede leer una respuesta. `Access-Control-Allow-Origin: *` combinado con credenciales es insostenible |
| 29 | **Lockfile** | Fichero que fija las versiones exactas de las dependencias (`package-lock.json`, `composer.lock`, `yarn.lock`). Es la fuente más fiable de la versión real de una librería |
| 30 | **Source map** | Fichero `.map` que el navegador usa para reconstruir el JavaScript original. Si está publicado, expone el código fuente, las rutas y a veces constantes |
| 31 | **Punta de iceberg** | Hallazgo visible que apunta a un problema mayor debajo. Un backup expuesto puede contener la base de datos; una versión vieja puede apuntar a una cadena de servidores obsoletos |
| 32 | **Rotar vs. revocar** | **Rotar** es emitir una credencial nueva y dejar de usar la vieja. **Revocar** es anular la vieja sin emitir otra. Ante una credencial expuesta, el cliente rota; el auditor no |
| 33 | **Safe harbor** | Cláusula por la que el cliente declara ser titular de los sistemas o tener autorización de sus titulares. No es un seguro: es la prueba de que no actuaste sin autorización |
| 34 | **NO VERIFICADO** | Marca obligatoria de un hallazgo que no se comprobó, con el requisito que falta y el comando para cerrarlo. **No verificado no es «bajo»**: es un riesgo sin medir |
| 35 | **Falso positivo** | Afirmación que la evidencia no sostiene. Se corrige **explícitamente** y se conserva el fichero que la contiene: el playbook guarda los falsos positivos a propósito |
| 36 | **Calibración de severidad** | El ejercicio de ajustar la severidad al **contenido** real del hallazgo, y no al tipo de vector. Mirar qué hay detrás antes de puntuar |
| 37 | **ICE / `rr_por_hora`** | Método de priorización: reducción de riesgo por hora de trabajo. Ordena la cola de arreglos por cuánto riesgo quita cada hora que invierte el cliente |
| 38 | **Escalación** | Avisar a quien tiene la autoridad para decidir: el firmante del RoE, el responsable técnico del cliente o el contacto de emergencia |
| 39 | **Redacción (redact)** | Sustituir un dato personal por una marca que conserve el formato pero quite el valor (`[REDACTADO:email]`, `abcd******yz`), de modo que la evidencia siga siendo interpretable |
| 40 | **Pasa-mustras de redacción** | La comprobación manual obligatoria del texto libre antes de entregarlo, porque el script garantiza las categorías pero no encuentra nombres de personas en prosa |

---

## 9. Checklist — «listo para firmar su primer RoE»

Para el **auditor**, el día antes de firmar su primer RoE como parte del
engaño. Cada punto es **verificable**: o puedes señalar el fichero que lo
demuestra, o no puedes firmarlo. Se relee también al final de cada auditoría.

| # | Punto | Cómo se verifica | Estado |
|:-:|---|---|:-:|
| 1 | **El RoE que voy a firmar lo he leído entero y sé qué prohíbe** — las cinco prohibiciones duras, palabra por palabra | Tienes el RoE delante y puedes señalar cada prohibición sin buscar | ☐ |
| 2 | **Sé qué NO es un permiso genérico**: un correo de «haz lo que necesites» no autoriza nada, porque no identifica sistemas, técnicas ni ventana | Sabes enumerar las seis condiciones de un RoE con forma | ☐ |
| 3 | **Tengo claro el ritmo**: ≥ 1 s entre peticiones, `GET`/`HEAD` solamente, UA honesto y contactable, cargas pesadas fuera de horario comercial | Lo tienes escrito en tus notas, no sólo en la memoria | ☐ |
| 4 | **Sé qué hago cuando el cliente pide algo que el RoE prohíbe** — y sé que la respuesta es «no, esto no, y esto sí» | Tienes escrita la respuesta (ejercicio E5) | ☐ |
| 5 | **Sé documentar una negativa con los cuatro campos**: qué se pidió, por qué no, qué ofrezco, quién decide | Tienes la plantilla rellenada de un caso de ejemplo | ☐ |
| 6 | **La toolchain pasa el selftest** | `python3 tests/selftest.py` → **19/19 checks PASS**, y el check de sockets incluido | ☐ |
| 7 | **Sé que el guard recorta los métodos a `GET`/`HEAD` aunque la autorización diga otra cosa**, y que `max_bytes` limita la lectura | Puedes explicar qué hace el guard con un `authorization.json` que liste `POST` | ☐ |
| 8 | **Entiendo el ciclo de las 11 fases** y sé en qué fase estoy en cada momento | Sabes numerarlas de memoria y decir qué evidencia produce cada una | ☐ |
| 9 | **Sé lo que es un soft-404 y cómo se detecta** — y sé que la severidad del TSV es *a priori* | Puedes explicar por qué `verdict=soft_404` no es un hallazgo (ejercicio E2) | ☐ |
| 10 | **Sé aplicar la regla de `--tls-max`** y sé leer la versión realmente negociada | Puedes explicar por qué `curl --tlsv1.0` no prueba nada sobre TLS 1.0 (ejercicio E6) | ☐ |
| 11 | **Sé contrastar contra la fuente primaria** y sé escribir «NO VERIFICADO» con el requisito que falta y el comando de 60 segundos | Tienes al menos un ejemplo real de las dos cosas | ☐ |
| 12 | **Sé que la evidencia no sale sin pasar por `pii_redact.py`**, y sé que el script no tiene NER y su catálogo de claves es una lista cerrada | Sabes qué campos de tu último JSON pasaron intactos y por qué (ejercicio E4) | ☐ |
| 13 | **Sé que el valor completo de un secreto no sale nunca**, ni al informe, ni al ticket, ni al chat | Tienes las dos formas: máscara `abcd******yz` y huella `sha256[:12]` | ☐ |
| 14 | **Sé redactar las tres capas** y sé a quién va cada una — y sé que el informe técnico **no** va al dueño | Tienes claro qué documento va al dueño, cuál a su hosting y cuál al público | ☐ |
| 15 | **Sé escribir «lo que ya está bien»**, y sé que es un requisito metodológico, no una cortesía | Tienes al menos un positivo escrito con la misma precisión que un negativo | ☐ |

> Las líneas 1–5 son **deontológicas** y bloquean. Las líneas 6–13 son
> **técnicas** y bloquean. La línea 14 es de **entrega** y bloquea. Si una sola
> línea está sin marcar, el RoE no se firma.

---

## Apéndice A — Índice de referencias

**Doctrina (la referencia operativa):**

- [`../00-metodologia/reglas-de-autorizacion-y-roe.md`](../00-metodologia/reglas-de-autorizacion-y-roe.md) — las 5 prohibiciones duras, el ritmo, la regla de terceros, la plantilla de RoE
- [`../00-metodologia/ciclo-de-auditoria.md`](../00-metodologia/ciclo-de-auditoria.md) — las 11 fases, la regla de oro, las lecciones (a) y (b)
- [`../00-metodologia/fase-2-explotacion-autorizada.md`](../00-metodologia/fase-2-explotacion-autorizada.md) — el protocolo de prueba sin daño, la matriz de destructividad, las prohibiciones absolutas
- [`../00-metodologia/exposicion-de-secretos.md`](../00-metodologia/exposicion-de-secretos.md) — taxonomía de secretos, niveles de verificación, reglas de redacción, control de calidad
- [`../00-metodologia/exposicion-a-ataques.md`](../00-metodologia/exposicion-a-ataques.md) — qué se puede decir sobre ataques y qué no
- [`../00-metodologia/como-presentar-resultados.md`](../00-metodologia/como-presentar-resultados.md) — severidad, ICE, las tres capas, «lo que ya está bien», anti-patrones
- [`../00-metodologia/modelo-de-servicio-y-escalabilidad.md`](../00-metodologia/modelo-de-servicio-y-escalabilidad.md) — los paquetes, el marco legal y contractual (§4), la escalabilidad

**Toolchain:**

- [`../01-tooling/scripts/README.md`](../01-tooling/scripts/README.md) — los 7 scripts, el flujo de autorización, las limitaciones conocidas
- [`../01-tooling/scripts/authorization.example.json`](../01-tooling/scripts/authorization.example.json) — la plantilla de autorización firmada
- [`../01-tooling/scripts/tests/selftest.py`](../01-tooling/scripts/tests/selftest.py) — el selftest de 19 checks
- [`../01-tooling/manifiesto-de-herramientas.md`](../01-tooling/manifiesto-de-herramientas.md) — el catálogo de herramientas de terceros con licencias y modo

**Formatos de trabajo:**

- [`../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md`](../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md) — RoE relleno
- [`../05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md`](../05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md) — el addendum con T1–T6
- [`../05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv`](../05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv) — el registro maestro
- [`../05-plantillas-de-trabajo/registro-de-acciones-fase-2.csv`](../05-plantillas-de-trabajo/registro-de-acciones-fase-2.csv) — el registro de la ventana

**Entregables:**

- [`../02-plantillas/teaser-report/README.md`](../02-plantillas/teaser-report/README.md) — la capa 1 y su `verify.py`
- [`../02-plantillas/informe-completo/README.md`](../02-plantillas/informe-completo/README.md) — la capa 2, §0–§11
- [`../02-plantillas/informe-completo/anexo-explotacion-limitada.md`](../02-plantillas/informe-completo/anexo-explotacion-limitada.md) — el anexo de Fase 2
- [`../02-plantillas/propuesta-comercial/README.md`](../02-plantillas/propuesta-comercial/README.md) — la propuesta que precede al RoE

**Formación complementaria:**

- [`01-lab-seguro.md`](01-lab-seguro.md) — el laboratorio, donde se practica todo lo que aquí se enseña
- [`02-herramientas-y-python.md`](02-herramientas-y-python.md) — el inventario de herramientas con la línea de autorización de cada una
- [`03-modelo-de-negocio-y-legal-mx.md`](03-modelo-de-negocio-y-legal-mx.md) — el marco legal y de negocio de México

---

*Esta guía es el libro de formación del playbook. La referencia operativa sigue
siendo [`../00-metodologia/`](../00-metodologia/): cuando esta guía y la
referencia discrepen, **manda la referencia**.*


