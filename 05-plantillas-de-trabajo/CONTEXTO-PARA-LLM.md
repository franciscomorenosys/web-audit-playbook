# Contexto para revisión por LLM — pegar PRIMERO

> Este archivo es el "código de contexto". Pégalo como **primer mensaje** en cualquier
> LLM antes de subir los artefactos. Sin esto, un LLM te va a hacer una revisión
> genérica y vas a perder la hora.
>
> **Orden de operaciones:** (1) pegas este contexto → (2) subes los artefactos →
> (3) pegas `PREGUNTAS-PARA-REVISION.md` → (4) formulas preguntas de seguimiento.

---

## 1. Qué es esto y de dónde viene

Realicé una auditoría de seguridad digital y una auditoría SEO sobre el sitio web de
una clínica dental en México (una sola sede en la Ciudad de México). Es un encargo real de
un cliente real con el que tengo relación comercial. Este es el material que produje
y necesito una lectura crítica antes de enviarlo.

**Stack del objetivo:** WordPress 7.1.3 + Divi 4.27.4/4.27.7, jQuery 3.7.1, GSAP 3.7.1,
FontAwesome 5.15.4/6.5.1, en hosting compartido (nginx 1.29.8 front, Apache origin,
capa de caché de página completa), PHP y Versión de MySQL no observables desde afuera.

**Superficie pública:** 17 URLs. Cero analítica instalada (sin GA4, GTM, Clarity,
Hotjar, pixel). Cero meta descriptions. Cero JSON-LD. Sin canonical en el home.
Blog inexistente. Sin página de equipo, sin hub de servicios, sin FAQ.

---

## 2. Qué entrego y qué NO entrego — y por qué

Esto es deliberado y quiero que lo evalúes como decisión comercial, no como error.

Entrego **dos documentos con propósitos distintos**:

| Documento | Audience | Contenido |
|---|---|---|
| **Teaser (13 págs, PDF)** | El dueño de la clínica, no técnico | 39 hallazgos contados por categoría y severidad; exposición legal en pesos; costo de brecha con fuente; 6 dominios calificados; qué está bien; tres niveles de servicio con precios; invitación a reunión |
| **Informe técnico (1,546 líneas, .md)** | Interno / sysadmin | Cada hallazgo con: evidencia literal, comando de reproducción, owner, score, owner de remediación, roadmap en 3 olas, 3 tickets de escalamiento redactados |

**El teaser NO incluye:** identificadores de CVE, números de versión, rutas de archivo,
endpoints, comandos de reproducción, nombres de usuario, teléfonos, correos, ni el
nombre de la agencia web ni el de sus otros clientes. Verifiqué esto con grep sobre
texto extraído, bytes crudos, metadatos y HTML fuente.

**El razonamiento:** el informe técnico es el producto que se entrega y se cobra. Un
teaser que regala el detalle técnico es un teaser que no se compra. Es práctica
estándar en consultoría de seguridad (*teaser report* / *advance audit*).

**Lo que sí me preocupa y quiero que ataquen:**
1. ¿El teaser es demasiado *thin* y se lee como anzuelo en vez de como informe real?
2. ¿El balance "suficiente sustancia para ser creíble" vs. "reserva el detalle
   suficiente para justificar la reunión" está bien calibrado, o me pasé?
3. ¿La lógica de precios (tres niveles, el más bajo acreditable contra los otros dos)
   se sostiene, o se ve como una escalera de都由 embudo?

---

## 3. Marco legal — todo verificado contra fuente primaria

El marco正确的是 **LFPDPPP nueva** (DOF 20-mar-2025, vigente 21-mar-2025, última
reforma 14-nov-2025, abrogó la de 2010). **El INAI ya no existe** — la autoridad es la
Secretaría Anticorrupción y Buen Gobierno. Multa máxima: 320,000 UMA × $117.31 (INEGI,
DOF 09-ene-2026) = **$37,539,200 MXN** (art. 59 fr. III; se duplica para datos
sensibles fr. IV). Sin aviso de privacidad → infracción art. 58 fr. V. Transferencia
internacional sin cláusula → art. 35 + art. 58 fr. X. Notificación de brecha: art. 19
obliga a notificar **a los pacientes afectados de inmediato** (la obligación de
notificar a la autoridad con plazo de 30 días de la ley de 2010 ya no existe en el
texto vigente). ARCO: art. 22, 20 días hábiles. Ley General de Salud art. 83: la
cédula profesional debe aparecer **en la publicidad** — el sitio web es publicidad.
Reglamento LGS en Materia de Publicidad art. 18 (eficacia no comprobada científicamente)
y art. 6 fr. I (cualidades terapéuticas no correspondientes).

**Costos de brecha:** IBM Security & Ponemon Institute, *Cost of a Data Breach Report
2026* — global USD 4.99 M; América Latina (muestra que incluye México) USD 4.65 M;
sector salud USD 6.64 M (más caro por 13º año); USD 192 por registro de PII (52 % de
las brechas); 247 días promedio de detección+contención. **No hay desglose por México
ni por pyme** — el documento lo declara explícitamente.

---

## 4. Doctrina metodológica — las reglas que me impuse

Todo fue **pasivo y no intrusivo**. GET/HEAD únicamente, ≥1 s de espaciado, ~330
requests a lo largo de dos pasadas. Cero POST/PUT/PATCH/DELETE, cero login, cero
fuerza bruta, cero nuclei/nikto/nmap/sqlmap, cero wordlists grandes.

Prohibiciones explícitas que respeté y que quiero que audites:
- **Cero requests** al endpoint de Google Apps Script que recibe los datos de los
  pacientes. Mirarlo ya sería un incidente.
- **Nunca revertí el hash MD5 del gravatar.** Lo reporté como oráculo de riesgo.
  De-anonimizar a una persona no es mi trabajo.
- **Cero requests** a hosts de la agencia web ni a sus staging. Solo leí índices
  públicos (crt.sh, Wayback CDX).
- **Cero sondeo activo** de los vecinos de la IP compartida. Solo InternetDB/ipinfo/DNS.
- **Nunca hice submission a urlscan.io** (causa una visita activa). Solo la API de lectura.

**Errores propios que ya detecté y corregí (wanté que los valides):**
1. Reporté "TLS 1.0/1.1 → HTTP 200" en la primera pasada. **Era falso positivo** por
   semántica de curl: `--tlsv1.0` fija un *mínimo*, no un máximo, así que se negoció
   TLS 1.3. Re-verificado con OpenSSL legacy: el servidor rechaza correctamente
   (alert 70). Retirado.
2. Reporté "38 hallazgos, 4 críticos" en el teaser. Los números no tenían fuente.
   El registro canónico tiene **39 filas** y separa *score de riesgo* (L×I) de
   *severidad*. Lo corregí derivando severidad de la columna **Impacto**
   (I=5→Crítico, I=4→Alto, I=3→Medio, I≤2→Bajo), lo que da **11 / 16 / 10 / 2**.
   También detecté que el `§5.6` del informe decía "38 filas" y "1,029 puntos
   agregados" cuando son 39 y 624 — corregido.
3. Los precios de los tres niveles **no tienen respaldo de datos duros**. Son
   estimación de convención de mercado. El benchmark que sí usé está en el playbook.

---

## 5. Lo que necesito de ti

**No me valides. Busca dónde está mal.**

Si todo está bien, dilo — pero si no encuentras nada que corregir, es que no leíste
con suficiente profundidad o que no te estoy dando el ángulo correcto.

Prioriza, en este orden:
1. **Errores factuales** — algo que afirmo que es falso, o un dato mal citado
2. **Defectos de método** — una conclusión que no se sostiene con la evidencia
3. **Juicios débiles** — una afirmación presentada con más confianza de la que
   merece, o un riesgo sobre/subdimensionado
4. **Decisiones comerciales** — pricing, alcance, framing, estructura del entregable
5. **Ecosistema** — lo que el marco legal mexicano no cubre y yo no vi

**Reglas de formato:**
- Cita la ubicación exacta (sección, ID de hallazgo, línea) para cada observación.
- Separa lo que es **error mío** de lo que es **diferencia de criterio**.
- Si no puedes verificar algo desde los artefactos, dilo explícitamente en vez de
  suponerlo. "No lo puedo verificar con lo que me diste" es una respuesta válida.
- No propongas reescribir el documento entero. Quiero observaciones accionables.
- Si algo que afirmo es correcto, no lo elabores: dilo en una línea y pasa al siguiente.
