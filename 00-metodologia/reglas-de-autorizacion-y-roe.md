# Reglas de autorización y RoE (Rules of Engagement)

La doctrina de seguridad que gobierna este playbook. **Se aplica antes de tocar
nada**, no después. Este documento existe porque una auditoría pasiva mal
planteada puede causar un daño real a un cliente que confió en el auditor.

Si alguna vez tienes que elegir entre «encontrar un hallazgo más» y «no causar
daño», **la segunda gana siempre** — y el hallazgo que no pudiste buscar se
reporta como *no verificado*. Perder un hallazgo es un costo comercial. Causar
daño a un paciente o a un tercero es un costo legal y reputacional.

---

## 1. Las cinco prohibiciones duras

Estas no son recomendaciones. Son líneas que no se cruzan **aunque estén en
alcance**, **aunque el cliente lo pida** y **aunque «solo sea una prueba»**.

### 1.1 Nunca hagas POST (ni ningún método con cuerpo)

**Regla.** Sólo `GET` y `HEAD`. Nunca `POST`, `PUT`, `PATCH`, `DELETE`, ni
`OPTIONS` que envíe datos. Nunca auto-formularios ni login.

**Por qué.** En `dentaleasy.mx` hay un endpoint público de Google Apps Script que
recibe el expediente del paciente (F25). Un `POST` de prueba ahí habría escrito
dato de paciente en un despliegue público, o —peor— lo habría hecho visible a
cualquiera. Un `POST` a un `wp-login.php` o a un endpoint de reserva puede
disparar correos,SMS o reservas **reales** que el cliente tiene que responder.
**El daño de un POST no es hipotético: se materializa en la bandeja del cliente.**

**Qué se hizo en su lugar.** Diseño revisado leyendo el JavaScript público:
`fetch('https://script.google.com/macros/s/AKfy.../exec?action=...')`,
`API.post()` con `method:'POST'`, y el placeholder
`this.WHATSAPP_NUMBER = '521234567890'` sin reemplazar. **Eso basta para
reportar el riesgo sin tocar nada.** Similarly, la lista de métodos de
`xmlrpc.php` (incluida `pingback.ping`) **no se enumeró** porque requiere POST:
se reportó como «fuera de alcance» (F15), con la evidencia que sí se pudo
obtener por GET (`?rsd`, 405 en GET).

**Excepción.** Sólo con RoE específico por escrito que la nombre, más ventana
de tiempo y contacto de emergencia. Nunca por interpreting el «haz lo que
necesites» del contrato.

### 1.2 Nunca toques endpoints que sostienen datos de terceros

**Regla.** Si un endpoint expone datos que pertenecen a *otra persona* (pacientes,
usuarios, clientes de un tercero), **no lo solicites**. Se reporta la existencia
de la ruta y se detiene ahí.

**Por qué.** `/wp-json/wp/v2/media` se pudo listar (66 ítems) porque son
ficheros de plantilla del tema. Si hubieran sido radiografías con nombre de
paciente, **declararlo sigue siendo correcto; descargar el contenido para
«confirmar» no lo es.** Tu autorización es del sitio, no de los pacientes que
hay dentro. Ejerces una Excerpta.

### 1.3 Nunca des-anonimices: reporta el riesgo, no ejecutes la capacidad

**Regla.** Cuando encuentres una capacidad ofensiva (enumeración de emails,
cracking de hashes, fuerza bruta, credential stuffing), **documenta la capacidad
y la cadena completa. No la ejecutes.** Jamás.

**El caso del hash de Gravatar (F08).** La cadena encontrada fue:
`?author=1` → slug `easy2025dental` → `/wp-json/wp/v2/users` confirma el slug →
`avatar_urls` incluye el MD5 del email del admin. Ese MD5 es una **función
determinista y reversible offline** del identificador. Como el slug sigue un
patrón obvio (`easy2025` + dental), una lista corta de emails candidatos
puede probarse **offline, a escala, sin rate-limit y sin tocar el servidor**,
para obtener una lista de usernames de alta confianza.

> **🚫 Lo que NO se hizo y NO se debe hacer:**
> - No se rompió el hash de Gravatar.
> - No se probaron emails candidatos.
> - No se ejecutó recuperación de contraseña.
> - No seintentó login.
>
> **Lo que SÍ se hizo:** describir la cadena, marcarla MEDIUM, y **escribir
> explícitamente la no-recomendación** en el informe:
>
> > *«No recomiendo, y este informe no debe leerse como recomendando, que
> > nadie ejecute recuperación de contraseña contra esta cuenta ni rompa el
> > hash. Ninguna de esas acciones es necesaria, apropiada o autorizada. La
> > postura correcta es puramente defensiva: cambiar la contraseña ahora,
> > deshabilitar archivos de autor, deshabilitar la ruta REST de usuarios,
> > renombrar el admin si es práctico, activar MFA, y tratar el hash como
> > **ya público** — cualquier contraseña débil, reutilizada o vieja debe
> > considerarse filtrada. No existe un estado «aún no la han roto» del que
> > uno pueda depender.»*
>
> **Por qué es correcto:** la **capacidad** es el hallazgo; el **resultado** de
> la capacidad sólo es daño. Un informe que dice «pueden obtener tus emails»
> ya permite al cliente actuar. Un informe que además incluye tu lista de emails
> **crea un archivo de datos personales que no tenías derecho a tener**.

### 1.4 Nunca sondees la infraestructura de terceros que descubriste

**Regla.** Un tercero descubierto en recon (una agencia, un hosting, un
proveedor, otro cliente del hosting) **se reporta, no se toca**. Ni un GET a su
panel, ni un chequeo de puertos, ni un escaneo de su TLS.

**El caso de la agencia y el certificado compartido (F31/F32/F33).** Durante la
fase 3 se descubrió que `dentaleasy.mx` resuelve a `162.241.62.126`, un host
compartido que sirve **la agencia FJ Gráfico + ~21 marcas cliente**, de las
cuales ~16 son prácticas médicas/psicológicas con datos de pacientes. El
certificado de producción tenía **24 SANs** que incluían `pruebas.fjgrafico.com`,
`aurapediatrica.com` y `ortopedista-trauma.com.mx` — y su CN era
`mail.ortopedista-trauma.com.mx`, **un inquilino no relacionado**.

Es tentador «echar un vistazo» al panel de la agencia o a otro inquilino del
host. **No se hizo y no se debe.** Tu autorización es de *un* cliente del host,
no de la agencia ni de los otros 20 inquilinos. Un dato de otro inquilino que
termines filtrando —incluso sin querer— **es una violación de confianza que
cuesta el contrato entero**, no un hallazgo.

**Qué se hizo en su lugar:** pasivo puro — el certificado que el *propio
dentaleasy.mx* ya servía (`openssl s_client ... -showcerts | x509 -ext
subjectAltName` no golpea a nadie más que al cliente), crt.sh, y DNS del
dominio del cliente. **La información ya estaba ahí, en la respuesta que el
cliente le devuelve al propio cliente.** Ese es el límite: *sólo respuestas
dirigidas a tu cliente.*

### 1.5 Nunca escaneas una IP compartida

**Regla.** Si la IP del cliente es compartida (hosting multi-tenant), **no hagas
escaneo activo de puertos.** Un escaneo de puertos de `162.241.62.126` golpea
los 20 otros inquilinos, que no te han autorizado nada.

**Qué se hizo.** Las fuentes de puertos abiertos vinieron de **Shodan
InternetDB**, que ya tenía ese dato indexado de su propio escaneo — **consulta
pasiva a un tercero, cero peticiones tuyas al host compartido**. Esa es la
diferencia entre «informarse de lo que ya es público» y «explorar la máquina».

---

## 2. Ritmo y cortesía

- **≥ 1 segundo entre peticiones** al objetivo. En la práctica, `probe.sh`
  lleva `sleep 1` literal y `water.py` lleva `sleep 0.6`→1. **No aceleres esto.**
  Un respetable crawler puede rastrear tu User-Agent; no quieres ser uno.
- **User-Agent honesto y contactable**:
  `Mozilla/5.0 (compatible; ClientSecurityAudit/1.0)`. **Nunca** suplantar
  Chrome/Safari para hidingarte. Si el servidor te bloquea, es señal de que la
  auditoría pasiva no es apropiada para ese cliente — dilo y escala la decisión,
  no lo esquives.
- **Fuera de horario comercial** para cualquier carga más pesada que un GET.
- **No dejes cargas massiveas.** Nada de Nuclei, dirsearch, ni ffuf. Nada de
  fuerza bruta de rutas, de enumerar IDs masivamente, ni de escanear subdominios
  por fuerza bruta.
- **No toques formularios, no uses credenciales**, no intentes autenticarte.

---

## 3. La regla de decisión para hallazgos de terceros

Cuando en una auditoría de cliente aparece algo que pertenece a un tercero, ¿qué
hago? Esta es la tabla:

| Situación | Acción | Razón |
|---|---|---|
| El tercero **es infraestructura del cliente** (hosting, CDN, proveedor de correo del cliente) | ✅ **Reportar como hallazgo del cliente** con la remediación dirigida al proveedor. Escribe el borrador de ticket. | El cliente lo puede corregir; le afecta. ElRoE cubre lo que pide su proveedor. |
| El tercero es **un cliente del mismo hosting/agencia** (los otros 20 inquilinos) | 🔒 **Reportar como hallazgo de blast radius**, sin detalles de *su* posición. Nombra la **relación** (comparten IP/cert), **no** sus vulnerabilidades. | Le afecta al cliente (su nombre está en el mismo cert), pero no te corresponde auditar a ellos. |
| El tercero es **un proveedor externo** (Google Apps Script, un CDN de terceros, una API de reservationes) | 🔒 **Reportar como riesgo de cumplimiento / datos.** «El cliente manda datos de pacientes a un endpoint público que el cliente no controla.» Señala **qué debe obtener el cliente** del proveedor (due diligence), no lo hagas tú. | El cliente tiene que exigir un compromiso de tratamiento de datos al proveedor. Eso es un contrato, no un pentest. |
| El tercero **no tiene relación con el cliente** (ej. un banner de un portal que enlazan, o una vulnerabilidad en un ad-server) | 🔒 **Mentionarlo una vez, genérico**, si es relevante al riesgo del cliente. Sin detalle técnico, sin reproducción. | Ruido. No es tu trabajo yrilsa de pronto da señal. |

**El principio detrás de los cuatro:** el alcance de tu autorización es el
**dominio del cliente y lo que el cliente controla**. Los terceros se
**describen**, no se **atacan**. Y en el informe se distingue siempre entre
«esto lo arregla el cliente», «esto se lo pide el cliente a su proveedor» y
«esto lo arregla un tercero que no es del cliente» — porque el dueño tiene
energía limitada y necesita saber a dónde va dirigida.

---

## 4. Plantilla de RoE (documento a firmar)

> Copia esta sección, rellénala y **hazla firmar antes de empezar**. Guarda la
> copia firmada junto a la evidencia del caso. Ejemplo relleno en
> `05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md`.

```markdown
# RoE — Reglas de enfrentamiento (Rules of Engagement) — [Nombre del cliente]

Fecha:       [AAAA-MM-DD]
Validez:     [AAAA-MM-DD] a [AAAA-MM-DD]
Auditor:     [Nombre / empresa]
Contacto de emergencia 24/7 del auditor: [teléfono]
Contacto de emergencia del cliente:        [teléfono]

## 1. Alcance autorizado
Dominios y hosts EN alcance:
  - [host]
  - [host]
Hosts explícitamente FUERA de alcance:
  - [host de terceros, panel de hosting, API de terceros]

## 2. Modalidad
[ ] Pasiva — sólo fuentes de terceros y lo ya público
[ ] Activa de baja tasa — GET/HEAD, ≥1s entre peticiones, UA contactable
[ ] Activa controlada — requiere sección 5 firmada

## 3. Permitido
  - GET / HEAD a los hosts en alcance, espaciados ≥1s
  - Descarga de HTML/JS público para análisis offline
  - Consulta a crt.sh, Wayback, Common Crawl, InternetDB, ipinfo, etc.

## 4. Prohibido (sin excepción, salvo sección 5)
  - POST/PUT/PATCH/DELETE o cualquier método con cuerpo
  - Login, credenciales, formularios, autenticación
  - Escaneo de puertos / red, fuzzing de rutas, fuerza bruta
  - Cargar, DoS, o stressing el objetivo
  - De-anonimizar: no romper hashes, no probar emails, no verificar credenciales
  - Tocar endpoints con datos de terceros (pacientes, usuarios ajenos)
  - Sondear infraestructura de terceros (agencia, hosting, otros inquilinos)
  - Instalar herramientas o ejecutar exploits en el objetivo
  - Social engineering al personal del cliente

## 5. Pruebas activas controladas (opcional, requiere firma explícita)
Autorizadas: [enumerar una por una]
Ventana:      [fecha/hora]
Presentes en la llamada: [nombre]
Rollback/abort: [criterio de parada inmediata]

## 6. Manejo de datos y confidencialidad
  - Toda la evidencia es CONFIDENCIAL. El informe técnico NO se envía al
    cliente final ni a terceros: va a su equipo técnico / hosting / agencia.
  - Los datos personales descubiertos se reportan por separado y se minimizan.
  - Retención de evidencia: [N] meses tras la entrega.

## 7. Cláusula de hallazgos de terceros
  - Los hallazgos que pertenecen a terceros se reportan como relación/riesgo,
    sin ejecutar ni detallar la ofensa contra el tercero.
  - El auditor no ejecutará ninguna capacidad ofensiva descubierta.

## 8. Firmas
Cliente:  [nombre, cargo, fecha, firma]
Auditor:  [nombre, fecha, firma]
```

---

## 5. Principios generales, resumidos

1. **Autorización primero, siempre por escrito.** Sin RoE firmado, no empieza.
2. **Pasiva por defecto.** El activo es una decisión del cliente, no tuya.
3. **El daño > el hallazgo.** Perder información es un costo. Causarla es otro.
4. **Reporta la capacidad, no la explotación.**
5. **Describe terceros, no los ataques.**
6. **Ritmo lento y UA honesto.**
7. **Confidencialidad sin excepciones.** El informe técnico es del cliente
   *técnico*, no del dueño ni del público.
8. **Si tienes duda de si algo está permitido: no lo hagas y pregunta.** Una
   pregunta al cliente cuesta un email. Un hallazgo de más cuesta cero. Un
   problema legal cuesta el contrato.