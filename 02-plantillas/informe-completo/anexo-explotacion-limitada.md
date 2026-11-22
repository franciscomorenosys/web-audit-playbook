# Anexo — Explotación limitada (Fase 2)

> **Plantilla.** Este anexo se **añade** al informe técnico completo (§0–§9) como
> sección final, y sólo tiene sentido si hubo una Fase 2 con addendum firmado.
> Sustituye todos los campos entre `[corchetes]`.
>
> **Cómo se usa:** copia el anexo al final del informe técnico del caso, en
> `03-casos/<cliente>/informe-tecnico/`, con el banner de confidencialidad de
> ese documento. **Este anexo es material técnico confidencial**: va al equipo
> técnico / hosting / agencia, **no** al dueño final ni a terceros. El dueño
> recibe la versión en lenguaje llano que se deriva de §2, no este documento.
>
> **El bloque de ejemplo (H-01) usa el cliente ficticio `clinica-ejemplo.mx`**
> y sirve para mostrar el nivel de detalle esperado. No copies sus datos a un
> caso real: sustitúyelos por los del engagement.
>
> **Documentos relacionados:** el addendum firmado
> (`05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md`),
> el registro de acciones (`05-plantillas-de-trabajo/registro-de-acciones-fase-2.csv`)
> y la doctrina de severidad y priorización
> (`00-metodologia/como-presentar-resultados.md`).

---

> ⛔ **CONFIDENCIAL.** Documento técnico. No distribuir fuera del equipo técnico
> del cliente, su hosting y su agencia.

---

# Anexo A — Explotación limitada (Fase 2)

## 1. Ficha del engagement

| Campo | Valor |
|---|---|
| **Cliente** | [Nombre legal del cliente] |
| **Dominio / activo** | [dominio principal] |
| **Engagement** | [código del engagement] |
| **RoE base** | [identificador del RoE], firmado el [AAAA-MM-DD], vigencia [AAAA-MM-DD] a [AAAA-MM-DD] |
| **Addendum de Fase 2** | [identificador del addendum], firmado el [AAAA-MM-DD] por [cliente / responsable técnico / auditor] |
| **Ventana de ejecución** | [AAAA-MM-DD] de [HH:MM] a [HH:MM] ([huso]) — [ventana de respaldo, si se usó] |
| **Modalidad** | Activa controlada, limitada a las seis técnicas del addendum |
| **Participantes del cliente** | [nombre, cargo, rol en la fase] · [nombre, cargo, rol] |
| **Participantes del auditor** | [nombre, rol] · [nombre, rol] |
| **Técnicas autorizadas / ejecutadas** | [N] autorizadas · [N] ejecutadas · [N] refutadas · [N] no ejecutadas |
| **Peticiones totales** | [N] ([N] GET/HEAD · [N] POST autorizadas) |
| **Huella total dejada por el auditor** | [N] artefacto(s) propio(s) creado(s) y eliminado(s) · [N] residuo(s) declarado(s) |
| **Estado de la limpieza** | [Cero / Con residuos declarados — ver §8] |

---

## 2. Resumen ejecutivo del anexo

**Para el dueño, en tres líneas:**

> [Línea 1 — qué se comprobó y qué salió, con un número.]
> [Línea 2 — el impacto real demostrado, sin tecnicismos.]
> [Línea 3 — la acción que se le pide y el plazo.]

**Para el equipo técnico (opcional, 3–6 viñetas):**

- [Viñeta 1: hallazgos de Fase 1 confirmados / refutados, con cifras.]
- [Viñeta 2: impacto máximo demostrado y por qué no se llegó más lejos.]
- [Viñeta 3: qué queda pendiente de corregir y quién lo tiene.]
- [Viñeta 4: qué datos reales son alcanzables y cuáles no se tocaron.]

**Cifras de control (las mismas que §3 y §4):**

| Métrica | Valor |
|---|---|
| Hallazgos de Fase 1 arrastrados a Fase 2 | [N] |
| **Confirmados** (la PoC se ejecutó y el fallo se demostró) | [N] |
| **Refutados** (la PoC se ejecutó y el control funcionó) | [N] |
| **No ejecutados** (sin "go", sin entorno, o fuera de ventana) | [N] |
| **No reproducibles** (el resultado fue inconcluyente) | [N] |
| Datos reales de pacientes alcanzados | **No** / Sí — [categoría, nunca el valor] |

---

## 3. Tabla de hallazgos explotados

| Id | Severidad | Vector | Activo | Impacto demostrado | Prueba ejecutada | Datos reales expuestos | Huella | Limpieza | Estado |
|---|---|---|---|---|---|---|---|---|---|
| H-01 | [ALTA] | [IDOR/BOLA] | [endpoint y tipo de activo] | [qué se demostró] | [T1 variante A/B — referencia a §4] | **NO** — sólo cuentas de prueba | [huella] | [hecha] | [ABIERTO] |
| H-02 | [ALTA] | [SQLi] | [endpoint] | [qué se demostró] | [T2 — comparación booleana] | **NO** — no se extrajeron filas | [huella] | [hecha] | [ABIERTO] |
| H-03 | [MEDIA] | [XSS reflejado] | [parámetro] | [qué se demostró] | [T3 — marcador inocuo] | **NO** — sólo cuenta propia | [huella] | [hecha] | [ABIERTO] |
| H-04 | [ALTO] | [Credencial expuesta] | [proveedor] | [qué se demostró] | [T6 — una llamada de lectura] | **NO** — [categoría] | [huella] | [pendiente del cliente] | [ABIERTO] |
| H-05 | [ALTO] | [Configuración insegura] | [fichero de backup] | [qué se demostró] | [T5 — Range 0-1023] | **NO** — no se leyó el contenido | [huella] | [pendiente del cliente] | [ABIERTO] |
| H-0X | [INFO] | [Bypass admin] | [endpoint] | [control de acceso funcionando] | [T4 — 403 con cuenta de paciente] | **NO** | ninguna | n/a | **CERRADO-OK** |

> **Convención de la columna «Datos reales expuestos»:** se escribe **SI** o
> **NO**, y cuando es SI se anota **la categoría** (datos de paciente,
> credenciales, PII de personal, información financiera) — **nunca el valor**.
> Un "SI" sin categoría no es un dato utilizable; es una afirmación.

---

## 4. Fichas de hallazgo

> **Una ficha por hallazgo.** El orden es por severidad, no por id.
> Cada ficha tiene seis apartados obligatorios. El quinto —**«Lo que NO se
> hizo»**— es el que da credibilidad a los otros cinco: **documenta la
> capacidad que el auditor tenía y decidió no ejercer**. Sin ese apartado, el
> lector tiene que suponer que el alcance fue limitado por falta de
> capacidad, y eso es peor que la verdad.

### 4.1 [H-01] — [Título del hallazgo]

| | |
|---|---|
| **Severidad** | [ALTA / MEDIA / BAJA / INFO] |
| **Vector** | [IDOR/BOLA] |
| **Activo** | [host + endpoint + tipo de dato que guarda] |
| **Técnica autorizada** | [T1 — variante A] |
| **Fecha y hora de la prueba** | [AAAA-MM-DD HH:MM:SS, huso] |
| **Cuenta utilizada** | [cuenta de prueba, de quién es] |
| **Estado** | [ABIERTO / CERRADO-OK / NO EJECUTADO] |

**Descripción.**
[Qué es, en dos o tres frases. Qué control falta o está mal implementado, y
por qué Fase 1 lo marcó como candidato.]

**Evidencia.**
[Referencia al archivo: `evidencia/fase2/<archivo>`. Descripción de lo que se
ve. **El valor va enmascarado**: la credencial se escribe como `abcd…wxyz`,
el token como `xxxx…yy`, y los identificadores de personas se sustituyen por
marcadores estables. Si un valor no se puede enmascarar sin perder el
significado, no se incluye y se dice por qué.]

**Pasos exactos.**
```
1. [Petición con la cuenta A]  →  [código y tamaño de la respuesta]
2. [Petición con la cuenta B]  →  [código y tamaño de la respuesta]
3. [Comparación]  →  [qué se observa]
```
[Cada paso es reproducible por el equipo del cliente sin el auditor. Si un
paso no es reproducible, el hallazgo no está probado.]

**Impacto real demostrado.**
[Qué se demostró, con la evidencia. No qué podría pasar: qué pasó.]

**Impacto máximo teórico.**
[Qué haría un atacante con este fallo, y qué queda fuera de lo demostrado.
Separado explícitamente del impacto real, porque confundirlos es la forma
normal de que un informe se lea como alarmista.]

**Lo que NO se hizo.**
- [Capacidad que el auditor tenía y no ejerció, con el motivo.]
- [Dato que no se tocó y por qué.]
- [Prueba que se declara no ejecutada y por qué.]

**Referencias.**
- Addendum de Fase 2, §2, técnica [T1].
- Registro de acciones: fila [F2-01] de `registro-de-acciones-fase-2.csv`.
- Informe de Fase 1: hallazgo [F-xx], sección [§x].

---

### 4.2 [H-0X] — [Resto de hallazgos: repetir la ficha]

> **Ejemplo — ficha completa de H-01 (IDOR/BOLA), con `clinica-ejemplo.mx`.**
> Sustituye los valores por los del engagement real.

#### [H-01] — Control de acceso por objeto ausente en el histórico de pacientes

| | |
|---|---|
| **Severidad** | ALTA |
| **Vector** | IDOR / BOLA (referencia directa a objeto no autorizada) |
| **Activo** | `clinica-ejemplo.mx` — `GET /api/v1/pacientes/{id}` — historial de pacientes |
| **Técnica autorizada** | T1, variantes A y B |
| **Fecha y hora de la prueba** | 2026-11-25 20:06 −06:00 |
| **Cuenta utilizada** | `paciente.pruebaB@clinica-ejemplo.mx` — cuenta de prueba del cliente |
| **Estado** | ABIERTO |

**Descripción.**
El endpoint de histórico de pacientes devuelve el registro completo solicitado
por identificador sin comprobar que el registro pertenezca a la cuenta
autenticada. Fase 1 lo marcó como candidato por la ausencia de un parámetro de
propiedad del objeto en la ruta; la Fase 2 lo confirma con dos cuentas de
prueba del propio cliente.

**Evidencia.**
`evidencia/fase2/idor_pacientes_1042.txt` — petición con la cuenta B contra
el identificador que pertenece a la cuenta A: la respuesta llega con código
`200` y la misma estructura de claves JSON que devuelve la cuenta A a su
propio identificador. **No se transcribe ni se guarda el contenido del
registro**: la comparación se hizo sobre código, claves y longitud. Los dos
registros son **sintéticos**, generados por el cliente para esta fase; no
corresponden a pacientes reales.

**Pasos exactos.**
```
1. GET /api/v1/pacientes/1042   (Cookie: sesión de la cuenta de prueba A)  →  200, N bytes, claves {id, ...}
2. GET /api/v1/pacientes/1042   (Cookie: sesión de la cuenta de prueba B)  →  200, N bytes, claves {id, ...}
3. Comparación de ambos códigos, claves y longitudes  →  idénticos salvo el identificador
```
Reproducible por el equipo del cliente con las dos cuentas de prueba, sin el
auditor.

**Impacto real demostrado.**
Una cuenta autenticada de bajo privilegio obtiene el registro de otro
identificador. Con las dos cuentas de prueba se demuestra la ausencia del
control de propiedad del objeto.

**Impacto máximo teórico.**
Si el endpoint no distingue entre registros de prueba y registros reales —lo
que no se comprobó, por estar prohibido extraer datos de pacientes— el
alcance sería la lectura del **histórico de pacientes completo** por parte de
cualquier cuenta con sesión iniciada, y por extensión los datos clínicos que
ese histórico contenga. **No se midió ese alcance**: el volumen lo calcula el
cliente desde sus logs.

**Lo que NO se hizo.**
- **No se enumeraron identificadores.** No se probó `1043`, `1044` ni ninguna
  secuencia. La prueba se limitó al par de identificadores que el cliente
  designó para la prueba.
- **No se leyó ningún registro de paciente real.** Las dos cuentas y sus
  registros son sintéticos. No se comprobó si el endpoint expone también
  registros reales, ni se comprobó cuántos hay.
- **No se probó la variante destructiva del fallo.** No se intentó modificar,
  eliminar ni reasignar un registro ajeno: es una escritura sobre datos de
  terceros y está prohibido sin excepción.
- **No se exportó ninguna copia de los datos.** La evidencia es la
  diferencia de comportamiento entre dos peticiones, no el contenido.
- **No se probó el mismo vector en otros endpoints** del mismo patrón (por
  ejemplo, `expedientes`), porque no estaban en la lista de técnicas
  autorizadas: se reportan como candidatos para una fase posterior.

**Referencias.**
- Addendum de Fase 2 `ADD-CJE-2026-02`, §2, técnica T1.
- Registro de acciones: fila `F2-01`.
- Informe de Fase 1: hallazgo F-xx (§x), tabla de candidatos a validación.

---

## 5. Datos reales expuestos

**Qué categoría de dato es alcanzable con el fallo demostrado, y qué no se
accedió.**

| Categoría | ¿Alcanzable con el fallo? | ¿Accedido por el auditor? | Detalle |
|---|---|---|---|
| **Datos de paciente** (historial clínico, diagnóstico, receta, motivo de consulta) | [Sí / No / No determinable sin revisar los registros] | **No** | [El auditor no abre ni guarda ningún expediente. La determinación de qué campos concretos contiene cada registro la hace el cliente desde su base de datos.] |
| **PII de personal** (nombre, correo, teléfono, RFC, currículum) | [Sí / No] | **No** | [..] |
| **Credenciales** (API keys, tokens, contraseñas en texto plano o hasheado) | [Sí / No] | **No** | [Una credencial se validó en modo lectura (§H-04); su valor se entrega enmascarado y sigue sin rotar.] |
| **Información financiera o administrativa** | [Sí / No] | **No** | [..] |
| **Datos de terceros ajenos al cliente** (proveedores, pacientes de otros centros) | [Sí / No] | **No** | [..] |

**Lo que se declara explícitamente:**
- **No se accedió a ningún registro de paciente.** Ningún expediente, historial
  clínico, documento de imagen o archivo de paciente fue abierto, copiado,
  transcrito, resumido ni contado durante la Fase 2.
- **No se transmitió** ningún dato a terceros, ni se usó ninguna capacidad
  ofensiva descubierta.
- **La cuantificación del volumen expuesto la hace el cliente**, no el
  auditor. Se entrega una **consulta de solo lectura redactada por el auditor**
  para que el cliente la ejecute desde su servidor, sin que el auditor la
  ejecute nunca.

> **Si durante la Fase 2 se hubiera detectado exposición real de PII ajena**
> (datos de pacientes o de personas que no son cuentas de prueba), se habría
> escalado de inmediato por el contacto de emergencia y se habría notificado
> por escrito al responsable técnico en el plazo de una hora, sin esperar al
> cierre de la fase. **No se habría publicado, comunicado ni utilizado esa
> exposición**, y la decisión sobre la notificación a los titulares y a la
> autoridad es del cliente con su asesoría legal. [Si no hubo exposición
> ajena: *«En esta fase no se detectó exposición de PII de terceros fuera de
  las cuentas de prueba. Las respuestas que contenían datos de personas se
  descartaron sin conservarse y se anotaron en el registro de acciones.»*]

---

## 6. Limitaciones de la fase y lo que queda fuera de alcance

**Limitaciones de la Fase 2 (alcanzables y reales):**

1. **La ventana es corta y las técnicas están acotadas.** El tiempo total de
   ejecución activa autorizado fue de [145 min / N min] frente a una ventana
   de [3 h / N h]. Ninguna técnica se repitió para obtener una segunda
   muestra.
2. **El "go" por prueba limita el ritmo.** Cada técnica esperó la
   autorización individual del responsable técnico. Las técnicas que no
   recibieron "go" están como **no ejecutadas**, no como **no encontradas**.
3. **Sin pruebas de carga.** No se midió el comportamiento del servicio bajo
   carga, ni la resistencia a denegación de servicio, ni el rendimiento de
   las consultas: todo ello está prohibido sin excepción.
4. **Sin pruebas de la cadena de autenticación.** No se evaluaron la
   resistencia de la contraseña, la política de bloqueo, la gestión de
   sesiones ni la implementación de MFA: están fuera de las técnicas
   autorizadas.
5. **Una sola instancia por técnica.** Los resultados son de una ejecución en
   un momento concreto. No hay estadística de tasa de éxito, ni repetibilidad,
   ni análisis de variantes.

**Fuera de alcance (y no se hizo, no se cotizó, no se contrató):**

| Fuera de alcance | Por qué |
|---|---|
| Red interna, puertos y hosts vecinos | Fuera del alcance del RoE base |
| Infraestructura de terceros (hosting, agencia, SaaS de reservas) | Se describe, no se ataca |
| Aplicaciones móviles y APIs de terceros | No son del cliente |
| Datos de pacientes | Fuera de alcance por definición de la fase |
| Cloud, AWS, GCP, Azure y sus configuraciones | No se auditó ningún tenant |
| Redes sociales y correo corporativo del cliente | No se auditó la exposición en esos canales |
| Pentest completo, red team o simulación de phishing | Servicios distintos, con RoE y seguro propios |
| Auditoría de cumplimiento (LFPDPPP, LGS, LFPC) | Es la Fase 1, no la Fase 2 |
| Aplicaciones móviles del cliente | Fuera de alcance |

---

## 7. Plan de remediación y re-test

| Id | Acción | Owner | Esfuerzo | Prioridad ICE | Fecha objetivo |
|---|---|---|---|---|---|
| H-01 | [Corregir el control de propiedad del objeto: validar que el registro pertenece a la cuenta autenticada en la capa de aplicación, no sólo en la ruta. Prueba de regresión con las dos cuentas de prueba.] | [Cliente / equipo de sistemas] | [8 h] | [10.0] | [AAAA-MM-DD] |
| H-02 | [Parametrizar la consulta; revisar el uso de concatenación en el módulo de búsqueda.] | [Cliente / agencia] | [6 h] | [12.0] | [AAAA-MM-DD] |
| H-03 | [Codificar la salida en el contexto afectado; aplicar una política de CSP.] | [Cliente] | [3 h] | [6.0] | [AAAA-MM-DD] |
| H-04 | [Rotar la credencial expuesta y eliminarla del código; limitar el alcance de la nueva al origen que la usa; revocar la anterior.] | [Cliente / responsable del proveedor] | [2 h] | [20.0] | [AAAA-MM-DD — **antes de que el anexo se entregue**] |
| H-05 | [Eliminar el fichero de backup del directorio público; revisar el cron que lo genera; impedir que se sirva desde la web.] | [Cliente / hosting] | [1 h] | [15.0] | [AAAA-MM-DD] |
| H-0X | [Cerrado. Sin acción.] | — | 0 h | — | — |
| — | **[Re-test]** Re-ejecución de las técnicas corregidas, con el mismo addendum y ventana de 2 h. | [Auditor] | [4 h] | — | [AAAA-MM-DD] |

> **Prioridad ICE, no RICE.** La priorización es **riesgo removido ÷ horas de
> esfuerzo**, no RICE: una auditoría de seguridad no tiene «reach» ni
> «impact» de producto, y meter métricas inventadas es peor que no priorizar.
> Ver `00-metodologia/como-presentar-resultados.md` §2.

**El re-test se cotiza aparte.** No está incluido en el precio de la Fase 2 y
se agenda con un addendum nuevo (o con el mismo, si sigue vigente).

---

## 8. Declaración de limpieza (footprint cero)

> **Qué se declara.** El auditor ejecutó la Fase 2 bajo la obligación de dejar
> el sistema en el estado en que lo encontró, y de declarar cualquier residuo
> que no pueda limpiar.

| Artefacto | Origen | Responsable de retirarlo | Retirado | Verificado |
|---|---|---|---|---|
| [Documento de prueba `id 88312`] | [F2-01, variante B] | [Auditor] | [2026-11-25 22:14 −06:00] | [Sí — 404 en la lectura de comprobación] |
| [Entrada en el log de actividad de la cuenta del auditor] | [F2-01] | [Auditor] | [2026-11-25 22:14 −06:00] | [Sí] |
| [Entrada en el log del servidor web] | [Todas las técnicas] | [Cliente / hosting] | [No aplica] | [No es limpiable por el auditor: es registro del sistema] |
| [Fichero de backup `backup-2026-10-14.sql`] | [F2-05 — **no lo creó el auditor**] | [Cliente] | [Pendiente] | [Acción de remediación H-05] |
| [Entrada en el log de acceso del proveedor] | [F2-06] | [Proveedor] | [Pendiente] | [No es limpiable por el auditor] |
| [Credencial expuesta] | [F2-06 — **no la creó el auditor**] | [Cliente] | [Pendiente de rotación] | [Acción de remediación H-04] |

**Declaración:**

> **El auditor declara que ha retirado la totalidad de los artefactos que creó
> durante la Fase 2 y que ha verificado su retirada.** Los residuos que
> subsisten en el log del servidor web y en el log de acceso del proveedor son
> **registros de actividad de sistemas que el auditor no controla y a los que
> no tiene acceso de escritura**, y así se declaran. Los dos elementos que
> **el auditor no creó y que siguen vigentes** —el fichero de backup expuesto y
> la credencial expuesta— **son acciones de remediación del cliente**
> (H-05 y H-04) y se declara de forma expresa su estado al momento del cierre
> de esta fase.

| | |
|---|---|
| **Responsable del equipo de auditoría** | [Nombre], [cargo] — fecha ____ — firma ____ |
| **Contraparte del cliente** | [Nombre], [cargo] — fecha ____ — firma ____ |

---

## 9. Anexo de evidencia — índice

> **Se entrega el índice, no el contenido.** Cada archivo se describe por lo
> que **es**, no por la herramienta que lo produjo, y **no se transcribe aquí
> ningún valor sensible**. Los archivos con valores completos se archivan con
> el auditor bajo el plazo de retención del addendum (§5.3) y se entregan al
> cliente **enmascarados** si el cliente los necesita.

| # | Archivo | Qué contiene | Contiene valores sensibles | Retención |
|---|---|---|---|---|
| 1 | `evidencia/fase2/idor_pacientes_1042.txt` | Petición y respuesta sanitizadas de la prueba IDOR, con código, claves y longitudes | No — contenido del registro no transcrito | 30 días |
| 2 | `evidencia/fase2/sqli_boolean_comparativa.txt` | Las dos respuestas comparadas de la prueba SQLi (código y longitud) | No — sin filas extraídas | 30 días |
| 3 | `evidencia/fase2/xss_reflejado_marcador.txt` | Petición con el marcador y respuesta renderizada con el marcador sin codificar | No — marcador inocuo | 30 días |
| 4 | `evidencia/fase2/admin_acceso_403_cuenta_paciente.txt` | Respuesta 403 del endpoint admin con la cuenta de paciente | No | 30 días |
| 5 | `evidencia/fase2/backup_exposto_head.txt` | Código, `Content-Type`, `Content-Length` y los primeros 1 024 bytes del fichero de backup | **Sí — puede contener material sensible; se entrega enmascarado** | 30 días |
| 6 | `evidencia/fase2/api_proveedor_lectura.txt` | Código de respuesta y nombres de campo de la llamada de lectura al proveedor | **Sí — prefijo de la credencial; se entrega enmascarado** | 30 días |
| 7 | `registro-de-acciones-fase-2.csv` | Registro completo de las seis técnicas autorizadas, con hora, cuenta, huella y rollback | No | 30 días |
| 8 | `addendum-fase2-firmado.md` | Copia firmada del addendum de Fase 2 | No | Con el expediente del engagement |

**Verificación de la minimización (check-list de cierre):**

- [ ] Ningún archivo de evidencia contiene un valor de paciente, un nombre, un
      teléfono o un correo de una persona real.
- [ ] Los secretos aparecen sólo como `prefijo…sufijo`.
- [ ] Las cookies de sesión y los tokens de autorización no aparecen en
      ningún archivo.
- [ ] Las capturas de pantalla están recortadas a la zona relevante.
- [ ] Los falsos positivos y los refutados **se conservan** (filas `F2-04` y
      `no ejecutada`): un directorio donde todo salió bien a la primera es
      sospechoso.
- [ ] El plan de destrucción de la evidencia está escrito y notificado al
      cliente.

---

*Anexo A. Confidencial. Distribución: equipo técnico del cliente, hosting y
agencia. No enviar al dueño final ni a terceros.*
