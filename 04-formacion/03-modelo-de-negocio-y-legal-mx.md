# 03 — Modelo de negocio y marco legal (México)

Cómo se estructura un encargo de seguridad web, dónde está la línea legal en
México, cómo se cobra y por dónde se aprende. Para el consultor independiente
que ya hizo un encargo real y quiere cobrarlo como negocio.

Doctrina: [`../00-metodologia/reglas-de-autorizacion-y-roe.md`](../00-metodologia/reglas-de-autorizacion-y-roe.md) ·
[`../00-metodologia/como-presentar-resultados.md`](../00-metodologia/como-presentar-resultados.md) ·
comercial: [`../02-plantillas/propuesta-comercial/README.md`](../02-plantillas/propuesta-comercial/README.md)

> Artículos legales y cifras de mercado son *referencias de trabajo*, no
> dictámenes: antes de citar una ley en un informe, descarga el texto vigente y
> anota la fecha de la última reforma (principio 7 del README).

---

## 1. Cómo es una evaluación de verdad

### 1.1 Ciclo de 8 fases y qué produce cada una

| Fase | Qué haces | Entregable |
|---|---|---|
| **Pre-encuentro** | Recon pasivo: DNS, CT, cachés, stack | Notas de superficie + hipótesis de riesgo |
| **Alcance** | Qué entra, qué sale, qué modalidad | RoE **borrador** + lista de activos |
| **RoE** | Reglas de juego: qué, con qué ritmo, hasta cuándo | **RoE firmado** — sin esto no hay encargo, hay delito potencial |
| **Pruebas** | Sólo GET/HEAD salvo autorización expresa; ≥1 s, UA honesto | Evidencia cruda indexada |
| **Evidencia** | Cada afirmación apunta a un archivo; los falsos positivos se conservan | `evidencia/` + `registro-de-acciones.csv` |
| **Informe** | Tres capas (resumen, técnico, remediación) | Borrador + revisión de precisión técnica y legal |
| **Remediación** | Tickets para hosting/agencia, no para el dueño | Tickets con responsable y esfuerzo |
| **Retest** | Verificar el arreglo (se cobra aparte) | Nota de cierre + pendientes abiertos |

### 1.2 El RoE: la línea entre profesional y amateur

Lo que separa una auditoría de un incidente que tú causaste. Plantilla completa:
[`../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md`](../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md).

| Bloque | Contenido mínimo |
|---|---|
| Alcance | Hosts dentro (FQDN exactos, no «su empresa»); terceros fuera |
| Modalidad | Pasiva / activa de baja tasa / activa controlada, cada una con sus técnicas |
| Permitido | Técnicas enumeradas una por una (verbos HTTP, escaneo o no escaneo) |
| Prohibido | Lo que nunca se hace, sin excepción, aunque el cliente lo pida |
| Rate limits | Requests/segundo, horas, ventana por día |
| Ventanas | Fecha/hora de las pruebas activas; quién está avisado y presente |
| Contactos | 24/7 del auditor y del cliente; criterio de abort (p. ej. +5 % de 5xx) |
| Datos encontrados | Credenciales y datos de pacientes: minimización, cifrado, retención, destrucción |
| Autorización | Quién firma, con qué facultad, y evidencia de esa facultad (poderes, contrato) |
| Responsabilidad | Límite de responsabilidad, exclusión de lucro cesante, indemnización |
| Safe harbor | El cliente declara ser titular o tener autorización de los titulares |
| Vigencia y firmas | Fechas y firmas de ambas partes |

**Safe harbor (esquema):** «El Cliente declara ser titular de los sistemas en
alcance o tener autorización de sus titulares; autoriza expresamente las técnicas
enumeradas y no interferirá con la auditoría.» No es un seguro: es la prueba de
que no actuaste sin autorización.

### 1.3 Los 4 tipos de encargo

| Tipo | Alcance | Lo pide… | Riesgo |
|---|---|---|---|
| **Vulnerability Assessment** | Amplio y superficial: superficie, versiones, config, CVEs **sin explotar** | «Quiero saber si estoy expuesto» | Bajo |
| **Penetration Test** | Profundo, orientado a objetivo, con explotación controlada | «Quiero saber si alguien podría entrar» | Medio: RoE + seguro |
| **Red Team** | El objetivo es el negocio: fraude, phishing, OSINT, acceso físico | Bancos, e-commerce grande | Alto: toca personas |
| **Auditoría de cumplimiento** | Contraste técnico y documental contra un marco (LFPDPPP/LGS/NOM, ISO 27001) | Salud, sector regulado | Bajo |

**Para una clínica pequeña:** assessment + auditoría de cumplimiento. **El único
tipo vendible sin pentest es el assessment**: su rasgo definitorio es *no*
explotar, y eso permite venderlo con RoE pasivo o activo de baja tasa, sin seguro
de pentest. Nunca vendas «pentest» si harás un assessment: la expectativa
equivocada trae complainta.

### 1.4 Frameworks: qué te da cada uno

| Framework | Te da | Cuándo |
|---|---|---|
| **PTES** | Metodología por fases con checklist | Narrar en qué fase estás |
| **NIST SP 800-115** | Planeación, ejecución, análisis, informe | Tu índice y tu ciclo de informe |
| **OWASP WSTG v4.2** | Catálogo de casos de prueba web | El «qué se prueba» de una web app |
| **OWASP ASVS** | Requisitos de verificación por nivel (L1–L3) | Custom features sin referencia pública |
| **NIST CSF 2.0** | Govern/Identify/Protect/Detect/Respond/Recover | Traducir a lenguaje de negocio |
| **CIS Controls v8** (IG1/IG2) | Backlog de remediación priorizado | Plan de arreglo para quien no tiene equipo |
| **MITRE ATT&CK** | Comportamiento de adversario | Narrar una cadena de acceso |
| **CVSS v4.0** | Vector y severidad objetiva | Comparar tu informe con el de otros |

### 1.5 El informe

Tres capas: **resumen ejecutivo** (1–2 págs. para el dueño), **informe técnico**
(hosting/agencia: reproducción, evidencia, CWE, CVSS, responsable) y **anexo de
remediación** (ticket, esfuerzo, prioridad). Un hallazgo para un dueño no técnico
dice *qué puede pasar*, *cuánto cuesta*, *quién lo arregla* y *en cuánto tiempo*;
no dice `CVE-2024-XXXX`.

---

## 2. Marco legal en México

### 2.1 Ley Federal de Penalizaciones en Materia de Cibernética

Nombre oficial: **Ley Federal de Penalizaciones en Materia de Cibernética**
(«Ley de Ciberdelitos» es el apodo). Publicada en el DOF el **3 de diciembre de
2012**, en vigor desde el 3 de enero de 2013; reformada varias veces (2014, 2016,
2018, 2021 y posteriores): **descarga el texto vigente antes de citar
artículos.** Qué tipifica:

- **Art. 6 — Acceso a sistemas de información:** accesar sin autorización del
  propietario o usuario legítimo, incluida la pena por obtener, copiar o
  introducir código. Es el que te interesa: «sin autorización» es lo que el RoE
  documenta.
- **Art. 7 — Daño a sistemas:** borrar, alterar, degradar o bloquear un sistema
  o red; destruir o alterar datos.
- **Art. 8 — Intercepción de comunicaciones:** capturar o interceptar
  comunicaciones y señales de transmital, y los dispositivos para ello.
- **Art. 9 — Uso malicioso de sistemas de información:** obtener, transferir o
  usar ilícitamente credenciales y datos de tarjetas.
- **Art. 10 — Manipulación o introducción de código malicioso** (añadido por
  reforma posterior).
- **Art. 11 — Suplantación de identidad** (añadido por reforma posterior).

Complementario del Código Penal Federal: **fraude por medios electrónicos**
(art. 388 Bis), **violación a la correspondencia** (art. 173), **hurto** y **daño**
(arts. 365 y 367). En datos de salud aplican la **LFPDPPP** (los datos de salud
son datos sensibles: art. 9), la **Ley General de Salud** y la
**NOM-004-SSA3-2012** para expediente clínico. Ojo: la LFPDPPP fue sustituida por
un ordenamiento publicado en el DOF en 2025 y cambió la autoridad fiscalizadora:
**verifica cuál está vigente** antes de mapear un hallazgo a ese marco.

> Consistencia interna: `02-herramientas-y-python.md` cita «arts. 218 y 220 del
> Código Penal Federal»; no pude confirmar esa numeración — verifícala o
> cámbiala por el art. 388 Bis.

### 2.2 CFAA (EE.UU.) y por qué te importa extraterritorialmente

Si un cliente es de EE.UU. o maneja datos de EE.UU., el **Computer Fraud and
Abuse Act, 18 U.S.C. § 1030** te aplica: (a)(2) acceso sin autorización o por
encima de la autorización; (a)(5) daño; (a)(7) extorsión. Lo grave no es el
penal: es el **civil**, § 1030(g) — daños y honorarios, con jurisdicción sobre
computadoras en comercio interestatal, casi cualquier servidor en Internet aunque
esté en México.

- **Van Buren v. United States (2021)** limitó «exceeds authorized access» en
  (a)(2) a *acceder a archivos o carpetas prohibidos al actor*; **no** reformuló
  «without authorization», que sigue aplicando al acceso que burla una barrera
  técnica (autenticación).
- **DMCA § 1201** puede convertir saltar un login en un problema de derechos de
  autor.
- Reglas prácticas: RoE en inglés, ley de EE.UU. citada, garantía de autoridad
  del cliente con indemnización. Un cliente estadounidense con seguro cyber te
  pediría el RoE firmado.

### 2.3 Qué es «autorización escrita» exigible en México

No es «me lo pidió por WhatsApp». Es exigible si: por escrito, con firma
autógrafa o electrónica avanzada, del **titular o de quien tenga facultad
expresa** (representante legal, administrador, socio con poderes); identifica
sistemas exactos, objetivo, técnicas permitidas y prohibidas, ventana de
ejecución y nombre del auditor. Guarda el RoE firmado con la evidencia: es tu
primera línea de defensa y lo que la aseguradora te pedirá. Si el alcance cambia,
**se modifica y se firma**; un «sí, sigue» por correo vale si queda registro.

### 2.4 Responsabilidad civil y seguros

Si te equivocas y generas daño (caída del sitio, datos alterados, correo
masivo), aplica la responsabilidad contractual del Código Civil Federal
(responsabilidad civil y por servicios profesionales) y la teoría del daño: tu
error, tu obligación de resarcir. Contratar no te exime, reparte el riesgo.

- **Responsabilidad civil profesional (E&O):** la realmente útil al inicio. Prima
  anual aproximada **MXN 8,000–35,000** para un consultorio individual con
  límites de MXN 1–5 millones. Ramo disponible en GNP, AXA, Chubb, Zurich, HDI.
- **Cyber / RC por incidentes cibernéticos:** prima aproximada **MXN
  25,000–120,000+**, límites de USD 1–10 millones. Más caro y con exclusiones:
  muchas pólizas excluyen *pentest* o Healthcare/medical. Pide que describan tu
  actividad como «consultoría de seguridad de la información / revisión
  autorizada» y **declara el RoE**.

Cotiza con un corredor que entienda E&O tecnológico y ten a la mano RoE
firmado, contrato, CV y política de datos.

### 2.5 Marcos éticos

- **«Hacking is not a crime»**: el manifiesto del activismo
  (`hacktivismo.net/manifesto/`), el «Hacker Ethic» de Steve Levy (1984) y el
  «Hacker Manifesto» de Loyd Blankenship (1971). No son ley: son el marco moral
  de la línea entre *leer* y *romper*.
- **ISACA Code of Ethics** (`isaca.org/resources/cisa-code-of-ethics`):
  interesarse en el interés ajeno, proteger los activos, mantener competencia, no
  participar en ataques ilegales.
- **(ISC)² Code of Ethics** (`isc2.org/about-us/governance/ethics`): cuatro
  cláusulas (protección de la sociedad, integridad, competencia, confidencialidad)
  y postura explícita sobre *ethical hackers*.
- **Vulnerability Disclosure Policy (VDP)**: guía de FIRST (`first.org/vdp/`) y
  plantilla de CISA. Aplica aunque el encargo sea pagado: **tú lo encontraste →
  se lo dices a él primero, en privado, con plazo.** El RoE debe incluir: nada
  se publica sin autorización escrita del cliente; el cliente se notifica antes
  de coordinar con terceros; el plazo de disclosure (90 días, estándar de facto)
  corre desde la notificación.

### 2.6 Hallazgos de terceros: reglas concretas

Caso real: en la auditoría de `dentaleasy.mx` el certificado compartido del
hosting exponía los SANs de **~21 marcas cliente de la agencia web** (16
consultorios), con un CN de un inquilino no relacionado: el certificado del
cliente filtraba la cartera de su agencia.

1. **Congela.** Cero pruebas nuevas sobre el tercero. Lo pasivo ya recogido (el
   certificado que el propio cliente le sirve) es evidencia legítima.
2. **Notifica primero al tercero** (la agencia), por escrito y directo, con
   evidencia mínima. Sin su autorización no hay pentest: hay VDP. Ahí tu deber es
   divulgar, no auditar.
3. **Al cliente, en abstracto:** «existe un riesgo de terceros que no es tuyo y
   que no puedo detallar sin autorización de la otra parte». Eso es un hallazgo
   (relación compartida, blast radius) y va en su informe.
4. **Lo que NO se le entrega al cliente:** la lista de clientes de la agencia, los
   nombres de marcas hermanas, los hallazgos de otros inquilinos. Entregarle «la
   cartera de su agencia» es difundir información confidencial de un tercero que
   no autorizó nada: te expone y daña al cliente que confió. **Informar que
   existe un riesgo que no es suyo, sí; entregar los datos de otro, no.**
5. **Si parece grave** (credenciales o PII explotables): escalamiento al
   tercero en <24 h, evidencia mínima, sin publicar; recomienda al cliente que
   ejecute sus derechos contractuales; documenta con timestamps; si el tercero no
   responde, su VDP o la del hosting es tu canal y avisas al cliente.
6. **En el informe:** sección «Riesgos de terceros» con la relación y la
   recomendación; la evidencia cruda va en anexo redactado. El RoE §7 y el
   contrato deben decir que el auditor notifica hallazgos de terceros a los
   terceros y que el cliente lo aprueba.

Regla general: **tu autorización es el dominio del cliente y lo que el cliente
controla**. Los terceros se describen, no se atacan.

---

## 3. Modelo comercial

### 3.1 Precios por profundidad (MXN; tipo de cambio aproximado 17–18 MXN/USD)

| Servicio | Freelancer | Boutique (2–5) | Big four / grande |
|---|---|---|---|
| Escaneo + revisión superficial (TLS, cabeceras, plugins) | MXN 4,000–12,000 | MXN 15,000–40,000 | MXN 120,000–300,000 |
| **Assessment completo** (3 capas + roadmap + tickets) | MXN 12,000–35,000 | MXN 40,000–120,000 | MXN 150,000–600,000+ |
| Assessment + remediación + retest | MXN 25,000–60,000 | MXN 90,000–250,000 | MXN 300,000–900,000+ |
| Pentest real (con explotación, credenciales provistas) | USD 5,000–15,000 | USD 12,000–40,000 | USD 60,000–200,000+ |
| Auditoría de cumplimiento (LFPDPPP/LGS/NOM) | MXN 20,000–60,000 | MXN 60,000–150,000 | MXN 200,000–600,000+ |

**Qué paga realmente el SMB mexicano:** el punto dulce es **MXN 12,000–30,000**
por assessment completo de un sitio WordPress con hosting compartido; nadie paga
150,000 sin relación previa. Las agencias pagan más (MXN 25,000–80,000) porque lo
re-cobran: **son tu mejor cliente recurrente**. Cobra por entregables y
superficie, nunca por horas. El re-test se cobra aparte: prueba que el arreglo
funcionó y es el mejor gancho de renovación.

### 3.2 Qué hace que un assessment valga su precio a un cliente no técnico

Traducir hallazgo → dinero. Tu caso real ya lo hace bien:

- «El formulario de cita manda el expediente del paciente a un endpoint público
  que nadie controla» → **datos sensibles bajo la LFPDPPP y una queja que te
  cuesta la licencia del consultorio.**
- «El panel de WordPress tiene una sola contraseña de administrador» → **tomar el
  sitio entero: desfigurar la web, mandar phishing a tus pacientes con tu
  nombre, aparecer en Google como tú.**
- «Tu hosting comparte IP y certificado con 21 marcas» → **la analogía del
  edificio con una sola llave: un inquilino comprometido expone a todos,
  incluido tú.** Esa es la frase que el dueño entiende.

Apóyate en benchmarks públicos (IBM *Cost of a Data Breach*: salud, orden de USD
7–10 millones por incidente) y cierra con la consecuencia para su negocio, no con
el CVE.

### 3.3 Retainer vs proyecto único

| | Proyecto único | Retainer mensual |
|---|---|---|
| Precio | MXN 12,000–35,000 | MXN 4,000–12,000/mes (ligero: 3,500–6,000) |
| Incluye | Assessment + informe + tickets | Recaneo trimestral, vigilancia de exposición (DNS, TLS, certificados, subdominios, plugins), canal prioritario 24 h, 1 assessment al año, re-test de lo corregido, 2 h de consulta, resumen de 1 página al mes |
| Qué NO es | — | No es «pentest mensual»: vendelo como **vigilancia de exposición** |

**Valor mensual con KPI, no adjetivos:** exposición media a críticos (días),
tiempo de remediación (MTTR), hallazgos cerrados, activos nuevos, cambios de
configuración no autorizados, certificados por expirar (oro con hosting
compartido). Quien ve «1 activo nuevo detectado, 0 días de exposición a crítico»
renueva; quien recibe «hicimos un escaneo» no.

### 3.4 El RoE y la autorización como activo de venta

Manda el RoE **antes** de la propuesta, como anexo: distingue «consultor» de
«cuñado con un escáner», le quita miedo al cliente y le da material para su
aseguradora, su hosting o su junta directiva. Además fija el límite de tu
responsabilidad desde el minuto uno: **el alcance lo define el cliente y lo
firmas tú.**

Cuando un hallazgo caiga en infraestructura de un tercero (hosting compartido,
panel de la agencia, API externa), no lo vendas como «fallo del cliente»: entrégalo
como **riesgo de terceros** con la acción concreta que el cliente debe exigir a su
proveedor, y aplica las reglas de §2.6 antes de tocar nada.

### 3.5 Certificaciones: cuál vale y cuál es desperdicio

| Certificación | Costo aprox. (USD) | Tiempo | Veredicto |
|---|---|---|---|
| **HTB CPTS** | ~$400–500 (voucher + examen) | 3–6 meses | **La más rentable en la práctica.** Examen práctico con cadena real (Active Directory + web app): te obliga a ejecutar y documentar. |
| **eJPT** | ~$250–300 | 1–2 meses | Barata y fácil: primera insignia y CV, señal débil. No la vendas. |
| **PNPT (TCM)** | ~$400 | 2–3 meses | Similar a CPTS, menor costo y menos reconocimiento. |
| **OSCP** | ~$2,000 | 4–8 meses | Cara; su ROI es empleo y profundidad, no venta SMB. Sólo para pentest profundo o empleo. |
| **GPEN (SANS)** | ~$2,500–3,000 | 4–8 meses | Muy buena metodología, desproporcionada para este negocio. |
| **CEH** | ~$2,200–3,000 | 2–3 meses | **Desperdicio para ti.** Examen de conocimiento, no de habilidad; el cliente no compra sellos. |
| **ISC² CC / Security+** | ~$750–1,000 / ~$400–600 | 2–4 meses | Vocabulario y marca; sólo si una propuesta exige «certificación reconocida». |

**Orden:** CPTS (o eJPT con presupuesto mínimo) → después, **nada** por 12 meses.
Práctica y un caso público de portafolio valen más que tres sellos. Ninguna
certificación sustituye un informe que un dueño pueda ejecutar.

### 3.6 Segmentación de clientes

| Cliente | Atractivo | Por qué |
|---|---|---|
| **Agencias de marketing/webs** | Muy alto | Pagan bien, re-cobran a su cliente, necesitan informe técnico **con marca blanca**. Primer cliente ideal. |
| **Clínicas dentales, consulorios, estética, psicología** | Alto | Dato sensible + urgencia legal + **decide una persona** + el sitio es su canal de pacientes: caído = dinero. |
| **Abogados y despachos** | Medio-alto | Reputación y confidencialidad; poco presupuesto, mucho miedo. |
| **Inmobiliarias y constructoras** | Medio | Fraude y SEO; venta por jefe. |
| **E-commerce pequeño** | Medio-alto | Volumen, pero exige pentest y garantía: cuidado. |

**Por qué las clínicas son buenos clientes:** decisión de una persona y rápida;
datos sensibles = urgencia + marco legal; su web *es* su negocio; se recomiendan
entre colegas; y casi nunca comparan tres cotizaciones de big four: comparan con
«el que me arregla la web», así que gana quien explica.

**Guion de primera llamada:** «No hago pentest; hago una revisión autorizada de tu
sitio. Te entrego tres documentos: un resumen para ti, un informe técnico para tu
hosting o agencia y un plan de arreglo. Primero te mando el documento de reglas —
qué reviso y qué no— y lo firmas antes de que toque nada. Necesito 30 minutos de
tu hosting; sin acceso al panel igual puedo trabajar con lo público.»

---

## 4. Ruta de aprendizaje ordenada

De «ya sé usar `curl` y leer un `dig`» a «puedo entregar una evaluación
defendible».

| Fase | Duración | Costo | Resultado |
|---|---|---|---|
| **0 — Fundamentos de red/HTTP/TLS/DNS** | Semanas 1–2 | ~$0 | Entiendes Host, cookie, SAN, CAA y por qué `curl --tlsv1.2` no prueba nada |
| **1 — Web Security Academy + labs** | Meses 1–2 | ~$0 | Terminas las ~16 áreas de PortSwigger y montas Juice Shop, DVWA y Metasploitable |
| **2 — Laboratorio de WordPress** | Meses 2–4 | $0–30 (VPS) | Superficie real: REST API, `xmlrpc.php`, enumeración de usuarios, plugins/temas, subida de ficheros, backups, multisite |
| **3 — Tus propias herramientas** | Meses 4–6 | ~$0 | Escribes en Python lo que repites (recon, posture HTTP/TLS, secretos en JS): el capítulo 7 de `02-herramientas-y-python.md` es tu hoja de ruta |
| **4 — Certificación + primeros encargos pagados** | Meses 6–9 | $250–500 | CPTS o eJPT, y **2–3 encargos reales de bajo riesgo, cobrados** |
| **5 — Especialización** | Meses 9–12 | ~$0 | WordPress + hosting (cPanel/Plesk, FTP, correo, DNS, certificados) + privacidad para salud y dental (LFPDPPP, LGS, NOM-004-SSA3-2012). **Aquí está tu nicho.** |

**Libros que sí valen:** *Web Security for Developers* (McDonald); *HTTP: The
Definitive Guide* (Gourley); *The Web Application Hacker’s Handbook* 2ª ed.;
*Bulletproof SSL and TLS* (Ristic) para TLS; *The Practice of Network Security
Monitoring* (Bejtlich) para pensar el retainer; *The Blue Team Handbook* para el
lenguaje defensivo. **Pérdida de tiempo:** *Hacking Exposed* (envejece rápido);
*Hacking: The Art of Exploitation* (no es tu dominio); *exam dumps* de
CEH/CompTIA (memorizar no es aprender); los libros de «red team» de usar y tirar.
**Cursos:** no compres ninguno hasta que le des vueltas a un lab de HTB — HTB,
PortSwigger y un VPS de $5 dan más que cualquier curso de $300.

**Gratis:** PortSwigger Web Security Academy (`portswigger.net/web-security`),
los frameworks de §1.4 con sus PDFs (`owasp.org`, `csrc.nist.gov`,
`first.org/cvss/v4.0`), OWASP Cheat Sheets, HackTricks (`hacktricks.xyz`), Linux
Journey, picoCTF, OverTheWire (`overthewire.org/wargames`), Juice Shop, DVWA,
Metasploitable, `testssl.sh`, `sslscan`, `nuclei`, WPScan (documenta licencias
antes de redistribuir: ver el manifiesto de herramientas). **De pago:** HTB
(~$49/mes), CPTS/eJPT y Burp Suite Pro ($475/año) sólo cuando el trabajo activo
lo justifique — la Community cubre el 90 % de lo que harás.

**Newsletters:** Pentester Land (gratis), The Responder (John Hammond), Krebs on
Security, Google Project Zero y, para tu nicho, el blog de Wordfence y los avisos
de seguridad de wordpress.org. **Podcasts:** Darknet Diaries, Security Now,
Unlimited Hangout (OSINT). **YouTube serio:** HTB Academy, John Hammond, IppSec
(walkthroughs de máquinas HTB, oro para CPTS), NetworkChuck, Kevin Stratvert.
**Evita** los canales de «hackear una WiFi en 60 segundos», los rankings de
herramientas y los que reutilizan material filtrado. **Para el formato del
informe:** plantillas públicas de Orange Tsai
(`github.com/Orange-Cyberdefense/PublicPentesting`) e informes de Project
Zero.

---

## 5. Las 3 cosas de esta semana

1. **Convierte tu RoE real en producto.** Toma el RoE del caso dental, sepáralo
   en dos variantes («revisión pasiva/activa de baja tasa» y «assessment con
   pruebas controladas»), añade los bloques legales de §1.2 (autorización con
   facultad, responsabilidad, safe harbor) y crea
   `05-plantillas-de-trabajo/roe-modelo.md` más una versión de una página para el
   dueño. Mándalo en la primera llamada.
2. **Arma el paquete de venta con un ejemplo, no con texto.** Con las tres
   plantillas de `../02-plantillas/`, produce **un hallazgo real tuyo reescrito en
   tres versiones**: (a) frase de una línea para el dueño con su consecuencia en
   dinero, (b) entrada técnica con evidencia y CVSS, (c) ticket para el hosting.
   Eso es tu teaser.
3. **Arranca la fase 1 y hazla visible.** Regístrate en PortSwigger Academy y
   métete a HTB (gratis). Compromiso: **dos módulos por semana durante 4
   semanas** y, al terminar, un informe de 5 hallazgos sobre Juice Shop con el
   formato de tres capas que usarás con clientes: tu primer entregable
   defendible.
