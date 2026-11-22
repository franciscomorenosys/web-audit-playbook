# Ejemplo relleno — Alcance y RoE

> **Ejemplo** para un cliente **hipotético siguiente** (una clínica de
> psicología, `saludviva.mx`). **No es un RoE real firmado** — es la plantilla
> de `00-metodologia/reglas-de-autorizacion-y-roe.md` rellenada con datos
> inventados, para que veas el nivel de detalle esperado.
>
> **Cómo usar esto en un cliente real:** copia la sección 4 de
> `reglas-de-autorizacion-y-roe.md`, rellénala con los datos reales, **hazla
> firmar antes de empezar**, y guarda la copia firmada junto a la evidencia del
> caso (`03-casos/<cliente>/evidencia/roe-firmado.md`).

---

# RoE — Reglas de enfrentamiento (Rules of Engagement) — Salud Viva

| Campo | Valor |
|---|---|
| **Cliente** | Salud Viva — Clínica de Psicología (`saludviva.mx`) |
| **Fecha de emisión** | 2026-11-15 |
| **Validez** | 2026-11-15 a 2026-12-15 |
| **Modalidad** | **Pasiva**, más Activa de baja tasa (GET/HEAD) |
| **Auditor** | [Nombre del auditor / empresa de consultoría] |
| **Contacto de emergencia 24/7 del auditor** | +52 XXX-XXX-XXXX |
| **Contacto de emergencia del cliente** | [nombre del admin de sistemas] — +52 XXX-XXX-XXXX |

---

## 1. Alcance autorizado

**Hosts EN alcance:**

| Host | Rol | Comentario |
|---|---|---|
| `saludviva.mx` | sitio principal | En alcance |
| `www.saludviva.mx` | sitio principal | En alcance |
| `citas.saludviva.mx` | subdomain de reservas (proPIO del cliente) | En alcance |
| `*.saludviva.mx` | wildcard | Solo pasivo (CT/Wayback). No se resolverán ni sondearán subdominios por fuerza. |

**Hosts explícitamente FUERA de alcance (y de quién son):**

| Host | Dueño | Razón de la exclusión |
|---|---|---|
| `panel.hosting-proveedor.com` | Proveedor de hosting | No es del cliente. Requiere autorización del hosting por separado. |
| `api.reservas-tercero.com` | Proveedor de SaaS de reservas | Activo del proveedor, no del cliente. Sólo se describirá. |
| Cualquier IP compartida del hosting | Multi-tenant | Incluye clientes ajenos del mismo servidor. **No se escanea.** |
| Cuentas de correo / Gmail del personal | Terceros | No se hace login ni social engineering al personal. |

> **Nota de propiedad (importante en psicología):** `citas.saludviva.mx` se
> incluye porque la clínica lo controla, pero **el contenido del subdomain de
> citas puede incluir información clínica protegida (motivo de consulta)**. Al
> reportarlo se sigue la regla de minimización: **no se descarga ni se reproduce
> contenido de paciente; sólo se describe la existencia y el riesgo de la ruta.**

## 2. Modalidad

- [x] **Pasiva** — sólo fuentes de terceros y lo ya público (crt.sh, Wayback, Common Crawl, InternetDB, ipinfo, Mozilla Observatory, internet.nl, urlscan.io **solo búsqueda**).
- [x] **Activa de baja tasa** — `GET`/`HEAD` a los hosts en alcance, **≥1 s entre peticiones**, User-Agent contactable.
- [ ] Activa controlada — **no autorizada** en este RoE. Requiere sección 5 firmada por separado.

## 3. Permitido

- Peticiones `GET`/`HEAD` a los hosts en alcance, **espaciadas ≥1 s**, con UA
  `Mozilla/5.0 (compatible; ClientSecurityAudit/1.0)`.
- Descarga de HTML/JS/imágenes públicos **para análisis offline**.
- Consultas DNS (`dig`) a `_dmarc`, `_domainkey`, CAA, MX, NS, A, AAAA, CNAME.
- Consulta a servicios de terceros: crt.sh, Wayback CDX, Common Crawl, Shodan
  InternetDB, ipinfo.io, Mozilla Observatory, SSL Labs API, internet.nl,
  urlscan.io (solo búsqueda).
- Análisis offline de lo descargado (versiones, on-page, secretos en JS).
- Revisión de logs de servidor **sólo si el cliente los comparte voluntariamente**
  (GoAccess). No se solicitan credenciales de acceso.

## 4. Prohibido (sin excepción — la sección 5 no está firmada)

- **POST / PUT / PATCH / DELETE** o cualquier método con cuerpo. **Ningún
  auto-formulario, ningún login.** Incluido el endpoint de citas/reservas.
- **Login, credenciales, formularios, autenticación, recuperación de contraseña.**
- **Escaneo de puertos o de red, fuzzing de rutas, fuerza bruta** — ninguna
  herramienta de tipo Nuclei/dirsearch/ffuf se ejecutará.
- **Cargar, DoS, o estresar el objetivo** bajo ninguna circunstancia.
- **De-anonimizar:** no romper hashes (p. ej. Gravatar MD5), no probar emails
  candidatos contra un hash, no verificar credenciales filtradas contra buzones,
  no enumerar cuentas más allá de lo que el propio sitio ya expone en sus
  respuestas públicas.
- **Tocar endpoints que sostienen datos de terceros** (pacientes, usuarios).
  Si un endpoint de la clínica expone historiales o mensajes de pacientes,
  **se reporta la existencia de la ruta pero NO se solicita su contenido.**
- **Sondear infraestructura de terceros** (proveedor de hosting, agencia web,
  otros inquilinos del servidor). Los hallazgos de terceros se reportan como
  **relación/riesgo**, sin detalles de su posición.
- **Ejecutar la capacidad ofensiva descubierta.** Si se encuentra una cadena de
  enumeración o un hash reversible, se **documenta y no se ejecuta**.
- **Social engineering** al personal de la clínica.
- **Instalar herramientas o ejecutar exploits** en el objetivo.

## 5. Pruebas activas controladas

**NO AUTORIZADAS en este RoE.** Si la clínica posteriormente contrata pruebas
activas, se emite un **anexo de RoE aparte**, firmado, que enumere una por una
las pruebas autorizadas, la ventana horaria y el criterio de parada inmediata.

## 6. Manejo de datos y confidencialidad

- **Toda la evidencia y los informes son CONFIDENCIALES.**
- El **informe técnico completo NO se envía** a la propietaria ni a terceros: va
  al equipo técnico / hosting / proveedor que puede actuar sobre él.
- **Minimización de datos personales:** cualquier dato de paciente descubierto
  se reporta por separado y **de forma agregada/anonimizada**; no se incluyen
  nombres, telefonos, correos ni contenido clínico de pacientes en los informes,
  por muy accesibles que sean.
- **Retención de evidencia:** 12 meses tras la entrega, después se destruye (o se
  anonimiza).
- Los hallazgos legales se redactan como **observaciones a verificar con un
  abogado**, no como asesoría legal.

## 7. Cláusula de hallazgos de terceros

- Los hallazgos que pertenecen a un tercero (hosting, proveedor de reservas,
  otros inquilinos del servidor) se reportan como **relación/riesgo de blast
  radius**, **sin ejecutar ni detallar la ofensa** contra el tercero.
- El auditor **no ejecutará ninguna capacidad ofensiva descubierta** (hash
  cracking, enumeración de usuarios, credential stuffing, etc.), aunque esté
  técnicamente a su alcance y en alcance de URL.
- Si un tercero resulta afectado, el auditor **no se pondrá en contacto con él**
  sin autorización escrita previa del cliente.

## 8. Firmas

| | |
|---|---|
| **Cliente** | [Nombre], [cargo — ej. Dirección General] — fecha ____ — firma ____ |
| **Auditor** | [Nombre], [empresa] — fecha ____ — firma ____ |

---

## 9. Check-list de arranque (antes de la primera petición)

- [ ] RoE firmado por ambas partes y archivado.
- [ ] Contacto de emergencia confirmado y probado por el cliente.
- [ ] ¿Se comparten logs de servidor? (opcional — cambia el alcance de la fase 5)
- [ ] ¿Hay un CMS identificado de antemano? (afecta a la fase 5)
- [ ] ¿Algún host es realmente propiedad de la agencia y no del cliente? (esta
      sección lo declara — si al recon aparece algo que no está listado, **parar
      y preguntar al cliente**, no asumir que está en alcance)
- [ ] User-Agent contactable configurado.
- [ ] ¿El cliente tiene algún requisito de privacidad particular? (p. ej. no
      quiero mi dominio en InternetDB) — registrado por escrito.
- [ ] Confirmar que la clínica entiende que, en una auditoría **pasiva**, hay
      hallazgos que sólo se pueden verificar **desde dentro** (versiones del
      servidor, configuración de plugins) y que se reportarán como «no
      verificado» con su ticket de verificación.