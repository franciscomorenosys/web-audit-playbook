# Ejemplo relleno — Addendum de autorización de Fase 2 (Explotación Limitada)

> **Ejemplo** para un cliente **hipotético** (`clinica-ejemplo.mx`). **No es un
> addendum real firmado** — es la plantilla del addendum de Fase 2 rellenada con
> datos inventados, para que veas el nivel de detalle esperado antes de
> mandarla a un cliente.
>
> **Cómo usar esto en un cliente real:** copia el documento, sustituye todos los
> campos entre `[corchetes]`, **hazlo firmar por las tres partes antes de la
> ventana**, y guarda la copia firmada junto a la evidencia del caso
> (`03-casos/<cliente>/evidencia/addendum-fase2-firmado.md`).
>
> **Documentos relacionados:**
> - `alcance-y-roe.EJEMPLO.md` — el RoE base que este addendum modifica.
> - `00-metodologia/reglas-de-autorizacion-y-roe.md` — la doctrina y las 5
>   prohibiciones duras.
> - `registro-de-acciones-fase-2.csv` — el registro de ejecución que se llena
>   durante la ventana.
> - `../02-plantillas/informe-completo/anexo-explotacion-limitada.md` — el anexo
>   que se entrega al final de la fase.

---

# Addendum de autorización — Fase 2: Explotación Limitada — Clínica Ejemplo

| Campo | Valor |
|---|---|
| **Cliente** | Clínica Ejemplo — Centro de atención médica, una sede (`clinica-ejemplo.mx`) |
| **RoE base que este documento modifica** | `RoE-CJE-2026-07`, emitido 2026-11-05 |
| **Fase que origina este addendum** | Fase 1 — Validación (ejecutada 2026-11-09 a 2026-11-13) |
| **Fecha de emisión del addendum** | 2026-11-20 |
| **Vigencia de la autorización de explotación** | 2026-11-23 a 2026-12-19 (27 días naturales) |
| **Modalidad que se autoriza aquí** | **Activa controlada** — la única modalidad que este playbook no permite sin un RoE específico por escrito |
| **Auditor** | [Nombre del auditor / empresa de consultoría] |
| **Contacto de emergencia 24/7 del auditor** | +52 XXX-XXX-XXXX (disponible durante toda la ventana) |
| **Contacto de emergencia del cliente** | [Nombre del responsable de sistemas] — +52 XXX-XXX-XXXX |

---

## 1. Referencia al RoE base

Este addendum **no sustituye** al RoE base: lo amplía en un punto concreto y
deja todo lo demás intacto.

| Documento | Identificador | Fecha | Qué gobierna |
|---|---|---|---|
| RoE base | `RoE-CJE-2026-07` | 2026-11-05 | Alcance, hosts en/fuera de alcance, modalidad pasiva + activa de baja tasa, prohibiciones, manejo de datos, firmas |
| Addendum de Fase 2 | `ADD-CJE-2026-02` | 2026-11-20 | **Únicamente** las seis técnicas de explotación listadas en §2, su ventana, su evidencia y su limpieza |

**Estado del RoE base al firmarse este addendum.** El RoE `RoE-CJE-2026-07`
sigue vigente y sus prohibiciones se mantienen íntegras. Este documento:

1. **Autoriza** seis técnicas concretas y delimitadas (§2), que de otro modo
   estarían prohibidas por el RoE base.
2. **Mantiene** la prohibición de POST y de toda prueba con cuerpo **salvo en
   el único caso expresamente nomeclado en §2 (T1, variante B)**, que ocurre
   exclusivamente en el entorno de pruebas que el cliente designe.
3. **No amplía el alcance de hosts**: se ejecutan únicamente los hosts
   listados como en alcance en el RoE base.
4. **Añade** las reglas de §3 (prohibiciones que no se levantan), §5
   (minimización de datos) y §6 (no divulgación) que son **más estrictas**
   que las del RoE base, y que prevalecen sobre él en caso de conflicto.

> **Alcance de la autorización.** La autorización es para **demostrar el
> impacto de hallazgos ya identificados en Fase 1**, sobre activos ya
> existentes, usando cuentas de prueba del propio cliente. **No es una
> autorización para buscar vulnerabilidades nuevas**, ni para explorar la red
> del cliente más allá de los hosts declarados, ni para tocar sistemas de
> terceros.

---

## 2. Qué se autoriza exactamente

**Las seis técnicas siguientes son las únicas autorizadas.** Cualquier otra
técnica, sobre cualquier otro endpoint, con cualquier otro método, está
prohibida. La columna «condición de ejecución» es acumulativa: si no se
cumple, la técnica no se ejecuta.

| # | Técnica | Objetivo / endpoint | Método HTTP | Condición de ejecución | Requisito previo | Evidencia a recoger | Huella (footprint) a dejar | Tiempo máximo |
|:-:|---|---|---|---|---|---|---|---|
| **T1** | **IDOR / BOLA** — referencia directa a objeto no autorizada | `/api/v1/pacientes/{id}` y `/api/v1/expedientes/{id}` (los dos endpoints que Fase 1 marcó como candidatos) | `GET` (variante A, por defecto)<br>`POST` sólo en la variante B | (a) ≥1 s entre peticiones;<br>(b) User-Agent honesto (§4);<br>(c) "go" explícito del responsable técnico **por prueba**;<br>(d) **variante B**: sólo en el entorno de pruebas que el cliente designe por escrito, y únicamente con la cuenta del auditor | Dos cuentas de prueba del cliente (paciente A y paciente B) con **datos sintéticos** y contrato de que sus registros no contienen información de pacientes reales | Petición y respuesta sanitizadas (código, tamaño, claves del JSON), captura recortada, par de identificadores usado | **Variante A: ninguna.**<br>**Variante B: 1** registro creado por el auditor + su entrada en el log de actividad. **Limpieza obligatoria antes de cerrar** | 30 min |
| **T2** | **SQLi no destructivo** — confirmación por respuesta booleana | El parámetro que Fase 1 marcó como entrada de consulta (`/api/v1/buscar?q=` o el parámetro que se defina en el RoE) | `GET` | (a) ≥1 s entre peticiones;<br>(b) una sola pareja de peticiones comparativas (condición verdadera / falsa);<br>(c) **prohibido** `UNION`, **prohibido** apilar consultas (`;`), **prohibido** cualquier extracción de filas;<br>(d) si la respuesta difiere en tamaño o contenido más allá de la longitud esperada, la prueba se detiene ahí | Endpoint identificado en Fase 1 y una cuenta de prueba que devuelva un conjunto de resultados vacío o mínimo | Código y longitud de las dos respuestas, diferencia observada, parámetro exacto usado | Ninguna (no hay escritura). Queda la entrada en el log del servidor web, que el auditor **no puede** limpiar | 20 min |
| **T3** | **XSS con payload inocuo** | Parámetro de entrada reflejado (*reflected*) que Fase 1 marcó (campo de búsqueda o de mensaje) | `GET` | (a) payload **sin carga externa**: un marcador de texto único, sin beacon, sin imagen, sin script, sin acceso a `document.cookie`;<br>(b) **exclusivamente** contra la cuenta propia del auditor;<br>(c) **prohibido** XSS almacenado (no se inyecta nada en el contenido de otra cuenta);<br>(d) ≥1 s entre peticiones | Cuenta de prueba del auditor, con permiso del cliente para escribir en su propio perfil | Petición con el marcador, respuesta con el marcador visible sin codificar, captura recortada | Ninguna (no se toca contenido de terceros). Si el marcador llegara a almacenarse, se borra antes de cerrar y se registra en el log de acciones | 20 min |
| **T4** | **Bypass de control de acceso administrativo** | Endpoints admin que Fase 1 listó (panel y API de administración) | `GET` (y `HEAD` como comprobación) | (a) se ejecutan **las dos** comprobaciones: con la cuenta admin de prueba y con la cuenta de paciente de prueba;<br>(b) sólo lectura de metadatos de la cuenta propia (rol, permisos) — **no** se listan usuarios ni expedientes reales;<br>(c) ≥1 s entre peticiones | Cuenta de prueba **admin** creada y entregada por el cliente, y cuenta de prueba de paciente | Código de respuesta de cada comprobación, cabecera `Location` de las redirecciones, rol efectivo de cada cuenta | Ninguna. Queda el registro de acceso en el log del servidor web | 45 min |
| **T5** | **Configuración insegura — fichero de backup expuesto** | Ruta exacta que Fase 1 encontró (ej. `/wp-content/backups/…`). **Ninguna otra ruta se prueba** | `GET` con cabecera `Range: bytes=0-1023` | (a) **una sola** petición por ruta;<br>(b) se lee como máximo el **primer kilobyte** para confirmar el tipo de contenido;<br>(c) **prohibido** descargar el fichero completo, descomprimirlo o extraer de él credenciales, hashes o datos;<br>(d) ≥1 s entre peticiones | Ruta registrada en el informe de Fase 1 con su evidencia | Código de respuesta, `Content-Type`, `Content-Length`, los primeros bytes del fichero | Ninguna en el servidor. Queda el acceso en el log del servidor web. **El fichero no se elimina: su eliminación la decide el cliente** | 15 min |
| **T6** | **Validación de credencial expuesta mediante la API del proveedor (modo lectura)** | Endpoint de solo lectura del proveedor que el cliente use (ej. `GET /v1/cuentas` o equivalente que el propio cliente indique por escrito) | `GET` | (a) **una sola** llamada de lectura, sin paginación ni filtros que amplíen el resultado;<br>(b) el auditor **no** enumera, **no** descarga y **no** transcribe ningún recurso devuelto: sólo comprueba que la credencial es válida y qué **categorías** de recurso expone;<br>(c) la credencial **no se usa** para nada más, ni en pruebas, ni en el informe, ni fuera de la ventana;<br>(d) ≥1 s entre peticiones | **El cliente indica por escrito** el endpoint de lectura autorizado **y** el proveedor real de la credencial | Código de respuesta, los **nombres de campo** de la respuesta, el prefijo enmascarado de la credencial | **1** entrada en el log de acceso del proveedor (IP, hora, prefijo de clave) + la credencial expuesta, que **sigue viva hasta que el cliente la rote**. Limpieza a cargo del cliente | 15 min |

**Total de tiempo de ejecución activa autorizado: 145 minutos** (2 h 25 min).
La ventana de §4 tiene 3 horas por sesión, de modo que el margen para
coordinación, pausas y abort es real, no teórico.

### 2.1 Notas de ejecución por técnica

**T1 — IDOR / BOLA.** La demostración que se busca es una **diferencia de
respuesta** entre `GET /api/v1/pacientes/{id-A}` con la cuenta A y con la
cuenta B: si la cuenta B obtiene el registro de A, el control de acceso no
está aplicando la propiedad del objeto. Se comparan **códigos de respuesta,
claves del JSON y longitudes**; no se transcribe ni se guarda el contenido de
ningún expediente, aunque los registros de prueba sean sintéticos. La
**variante B** (un único artefacto de prueba creado por el auditor) existe
únicamente para poder demostrar un fallo de control de acceso en la ruta de
**escritura**: sin crear un objeto propio no hay forma de demostrar que el
sistema permite leer el objeto de otro. Esa variante está limitada a un (1)
recurso, en el entorno de pruebas, con contenido vacío y nombre fijo, y su
limpieza es condición de cierre de la fase.

**T2 — SQLi no destructivo.** La única prueba admisible es la **comparación
booleana**: una petición con la condición verdadera y otra con la falsa, y
comprobar si el resultado (código, número de resultados, orden) cambia de
manera consistente. Si la diferencia observada es una **fila o más** de
contenido que el auditor no puede atribuir al parámetro, la prueba se detiene
y ese contenido se descarta. **No se enumeran, no se cuentan y no se copian
filas.** El objetivo es confirmar la **capacidad**, no cuantificar el
volumen de datos expuestos: esa cifra la da el cliente desde sus logs, con
una consulta que el auditor redacta pero **no ejecuta**.

**T3 — XSS con payload inocuo.** El payload es una cadena de texto sin
significado, del tipo `XSS-AUDIT-<id-de-prueba>`, que no invoca ninguna URL
ni carga ningún recurso externo. No se usa `alert`, ni `document.cookie`, ni
un `<img onerror>`, ni nada que contacte un servidor externo. La prueba
termina cuando el marcador aparece sin codificar en la respuesta renderizada
de la **cuenta del propio auditor**. No se intenta XSS almacenado: inyectar un
payload en el contenido de la cuenta de otro usuario es una escritura sobre
datos de un tercero, y está prohibido sin excepción.

**T4 — Bypass de control de acceso administrativo.** La hipótesis a probar es
concreta: «un endpoint administrativo se comporta de forma distinta según la
cuenta, o no comprueba el rol en absoluto». Se hace en las dos direcciones
(cuenta admin y cuenta de paciente) porque un control de acceso que sólo
comprueba «¿hay sesión?» en lugar de «¿qué rol tiene?» es indistinguible de
uno que no comprueba nada. Se comprueban el rol y los permisos **de la propia
cuenta**, nunca el listado de usuarios reales ni ningún expediente.

**T5 — Fichero de backup expuesto.** La prueba es de **existencia**, no de
contenido. Con `Range: bytes=0-1023` se confirma que el fichero existe, de
qué tipo es y cuánto mide, leyendo 1 KB. **No se descarga, no se descomprime y
no se buscan credenciales dentro.** Si el auditor llega a ver un hash o una
contraseña en esos primeros 1 024 bytes, **no lo transcribe**: anota «se
observa material sensible en las primeras líneas» y entrega la evidencia
enmascarada. La eliminación del fichero la decide el cliente, no el auditor.

**T6 — Validación de credencial expuesta vía API del proveedor.** Esta es la
**única excepción** a la prohibición de de-anonimizar del RoE base (regla
1.3), y está acotada a una sola llamada de lectura sobre un endpoint que el
propio cliente indique por escrito. Lo que se busca responder es: «¿esta
credencial está viva y qué categoría de recursos expone?». Lo que **no** se
hace: enumerar recursos, descargar registros de pacientes, usar la credencial
para escribir, o reutilizarla fuera de la ventana. La credencial se entrega al
cliente **enmascarada** y la recomendación es rotarla.

---

## 3. Lo que sigue prohibido, sin excepción

Estas prohibiciones **no se levantan con este addendum**. No hay «excepción
por urgencia», no hay «excepción por autorización del dueño» y no hay
«excepción por tamaño del cliente». Si una prueba requiere alguna de ellas,
**la prueba no se hace y se reporta como no verificada**.

1. **Denegación de servicio, estrés y carga.** Nada de pruebas de
   disponibilidad, de ancho de banda, de concurrencia, de `time-based` para
   medir capacidad, de inundar un endpoint, ni de repetir peticiones para
   «medir el límite». Ninguna herramienta de carga se ejecuta contra el
   objetivo.
2. **Escritura, modificación o borrado de datos de producción.** Ninguna
   creación, edición o eliminación de registros de producción. La única
   escritura autorizada es el artefacto único de T1-B, en el entorno de
   pruebas que el cliente designe, con limpieza obligatoria.
3. **Acceso a cuentas de terceros.** Sólo se usan las cuentas de prueba
   entregadas por el cliente y la cuenta propia del auditor. Ninguna cuenta
   real de personal, de pacientes, de proveedores o de terceros, ni siquiera
   para confirmar que existe.
4. **Extracción de datos personales o clínicos.** No se descarga, copia,
   transcribe, resume, cuenta ni almacena ningún dato de paciente, registro
   clínico, expediente, archivo o historial. **Contar cuántos hay también está
   prohibido.**
5. **Persistencia.** Sin webshells, sin shells inversas, sin backdoors, sin
   tareas programadas, sin claves SSH, sin usuarios creados, sin tokens de
   larga vida, sin ficheros subidos fuera del artefacto de T1-B. Si una
   técnica de explotación deja algo detrás, **se limpia y se reporta**; si no
   se puede limpiar, se reporta como residual y **no se repite**.
6. **Movimiento lateral fuera del alcance.** No se explora la red interna, no
   se escanean puertos, no se testean otros hosts del cliente que no estén
   listados en el RoE base, ni se toca la infraestructura de terceros
   (hosting, agencia, SaaS de terceros, API de terceros).
7. **Cracking de hashes.** No se rompen hashes, no se comparan contra
   diccionarios, no se prueban candidatos offline ni online, no se ejecutan
   listas de contraseñas.
8. **Bypass de MFA.** No se intenta superar un segundo factor por ninguna
   vía, ni se capturan ni se interceptan códigos de un factor, ni se modifica
   la configuración de MFA del cliente.
9. **Ingeniería social al personal.** No se llama, no se escribe, no se
   visita, no se pide ayuda a un empleado del cliente con pretextos, no se
   suplanta a un proveedor para obtener información. El único contacto con el
   cliente es el autorizado en §4.
10. **Uso del secreto encontrado más allá de la validación de lectura
    autorizada.** La credencial expuesta se usa **una vez**, en modo lectura,
    sobre el endpoint que el cliente indique por escrito. No se usa para
    escribir, no se usa para acceder a más recursos, no se usa para iniciar
    sesión en ningún servicio del cliente, no se usa para probar si funciona
    en otro sitio, y no se reutiliza fuera de la ventana.
11. **Comunicación a terceros.** No se contacta al proveedor de la credencial,
    ni al hosting, ni a la agencia web, ni a ningún otro tercero sin
    autorización escrita previa del cliente. Los terceros se describen, no se
    contactan.

---

## 4. Ventana y modo de ejecución

### 4.1 Ventana

| Concepto | Valor |
|---|---|
| **Ventana principal** | 2026-11-25, **20:00 a 23:00** (America/Mexico_City, UTC−6) |
| **Ventana de respaldo** | 2026-11-27, 20:00 a 23:00 (America/Mexico_City, UTC−6) — sólo si la principal se cancela, no se acumula |
| **Horas prohibidas** | Cualquiera fuera de las ventanas anteriores. Las peticiones de Fase 2 **no** se hacen fuera de la ventana, aunque la Fase 1 siga vigente |
| **Días no laborables** | Se acordan con el cliente. Por defecto, la ventana no se usa en domingo ni en el periodo vacacional que el cliente declare |

### 4.2 Participantes

| Parte | Nombre | Rol en la fase | Presencia |
|---|---|---|---|
| **Cliente — decide** | [Nombre] — Dirección General | Aprueba o rechaza técnicas (casilla de §7) | No presente; disponible por teléfono en la ventana |
| **Cliente — da el "go"** | [Nombre] — Responsable de Sistemas | Autoriza cada prueba individualmente; puede detener la fase en cualquier momento | **Presente en la llamada** durante toda la ventana |
| **Cliente — observa** | [Nombre] — [Coordinación de citas] | Presencia su propio panel y logs para confirmar el estado del servicio | En línea, a demanda |
| **Auditor — ejecuta** | [Nombre] — Auditor principal | Ejecuta las pruebas y lleva el registro de acciones | En línea durante toda la ventana |
| **Auditor — apoya** | [Nombre] — Analista | Prepara evidencia, registra, redacta notas | En línea durante toda la ventana |

### 4.3 Comunicación y emergencias

| Canal | Uso |
|---|---|
| **Canal de ejecución (chat + llamada de voz)** | Canal único y exclusivo de la ventana. El "go" de cada prueba se pide y se confirma **por escrito** en el chat, con la hora. |
| **Correo** | Sólo para el envío del addendum firmado y para la entrega final del anexo. **No se usa para dar el "go".** |
| **Emergencia 24/7 del auditor** | +52 XXX-XXX-XXXX — disponible durante toda la ventana y **también fuera de ella** si hay un efecto residual que reportar |
| **Emergencia 24/7 del cliente** | [Nombre del responsable de sistemas] — +52 XXX-XXX-XXXX |

### 4.4 Quién da el "go" y cómo se registra

- **Ninguna prueba empieza sin el "go" explícito del responsable técnico del
  cliente**, dado prueba por prueba, en el canal de ejecución, con la hora. El
  "go" se registra en el log de acciones como parte de la fila de la prueba.
- **El "go" es específico de una prueba.** Un "go" para T1 no habilita T2.
- **El silencio no es un "go".** Si el responsable técnico no contesta en 10
  minutos, la prueba no se ejecuta y se anota como *no ejecutada — sin go*.
- **El auditor puede parar cualquier prueba por iniciativa propia**, sin
  necesidad de pedir permiso, en cuanto se cumple cualquiera de los criterios
  de §4.5.

### 4.5 Criterio de abort inmediato

La ejecución se detiene **de inmediato**, sin esperar confirmación, en cuanto
ocurra cualquiera de estos tres hechos:

1. **Aparece un dato de paciente o de un tercero en una respuesta.** Cualquier
   identificador clínico, nombre, expediente, teléfono, correo o registro de
   una persona que no sea una cuenta de prueba → la respuesta se descarta, no
   se guarda, no se transcribe, se anota el incidente en el log de acciones y
   se avisa al responsable técnico en el canal de ejecución.
2. **Se produce un efecto no previsto y no destructivo pero real.** Un registro
   creado, un correo enviado, un SMS, una notificación, una reserva, un cambio
   de estado, un error 500 reproducible, una entrada en cola de trabajo → la
   prueba se detiene y se revisa con el cliente antes de continuar.
3. **Aparece cualquier señal de degradación o de alarma.** Latencia anormal,
   errores del servicio, alerta del hosting, del panel del cliente o de
   cualquier monitor → se detiene todo, se entrega el registro de acciones
   hasta ese momento y se espera la decisión del cliente.

---

## 5. Reglas de manejo de datos

### 5.1 Minimización — qué se guarda y qué se redacta

| Categoría | Qué se guarda | Qué se redacta o no se guarda |
|---|---|---|
| Peticiones y respuestas | Código de estado, tamaño, claves del JSON, cabeceras relevantes (`Content-Type`, `Location`, `Set-Cookie` **no**) | El cuerpo completo de respuestas que contengan datos de cualquier persona |
| Secretos | Prefijo y sufijo de la credencial (`abcd…wxyz`) | **Nunca** el valor completo, ni en capturas, ni en logs, ni en notas |
| Cookies y tokens | Que existían o no (booleano) | El valor de la cookie de sesión, del `Authorization`, del JWT |
| Identificadores de personas | Que el identificador existe y a qué cuenta pertenece | El nombre, el teléfono, el correo y cualquier dato clínico |
| Capturas de pantalla | Recorte a la zona relevante | Capturas de pantalla completa con datos de pacientes visibles, archivos de historial o listados de usuarios |

### 5.2 Prohibición de registrar PII de pacientes

**Ninguna respuesta que contenga datos de pacientes se transcribe, se guarda,
se cita ni se cuenta.** Si por error una respuesta trae un dato de paciente:

1. Se elimina el archivo que lo contiene, sin excepción y sin conservar copia.
2. Se anota en el log de acciones: *«respuesta con dato de paciente
   descartada; no conservada»*, con la hora y el endpoint.
3. Se avisa al responsable técnico del cliente en el canal de ejecución.

### 5.3 Retención y destrucción

| Concepto | Regla |
|---|---|
| **Retención de la evidencia de Fase 2** | **30 días naturales** contados desde la entrega del anexo |
| **Destrucción** | Al cumplirse el plazo, la evidencia se destruye o se anonimiza de forma verificable, y se confirma por escrito al cliente |
| **Excepciones** | Sólo se conserva, con el mismo plazo, lo que el cliente pida expresamente conservar para su propio expediente (p. ej. la copia enmascarada de la credencial expuesta) |
| **Entrega al cliente** | El cliente recibe la **evidencia enmascarada** y el registro de acciones. Las capturas originales con valores completos **no se entregan**: se archivan con el auditor hasta el final del plazo de retención |

### 5.4 Qué se le entrega al cliente al final

- El **anexo de explotación limitada** (`02-plantillas/informe-completo/anexo-explotacion-limitada.md`).
- El **registro de acciones de Fase 2** completo, con las seis técnicas
  autorizadas, incluidas las que se refutaron y las que no se ejecutaron.
- La **declaración de limpieza** firmada, con el detalle de la huella dejada y
  de quién la retiró.
- **Valores enmascarados, nunca completos**: la credencial expuesta, los
  tokens, las cookies y cualquier identificador sensible.

---

## 6. Compromiso de no divulgación

1. **Sin difusión en redes, foros, wikis, grupos de mensajes ni
   presentaciones.** Ninguna captura que contenga un secreto —ni siquiera
   parcial— se publica, se pega en un ticket abierto, ni se usa como ejemplo
   en una publicación. Las imágenes de la Fase 2 no se comparten fuera de la
   relación profesional.
2. **El auditor no expone los hallazgos a terceros.** No hay comunicación con
   proveedores, hosting, agencia web, certificadoras o auditorías ajenas,
   salvo autorización escrita previa del cliente. Los terceros se describen,
   no se contactan.
3. **Si se detecta exposición real de PII ajena** —es decir, datos de
   pacientes o de personas que no son cuentas de prueba y que un atacante
   podría leer—:
   - **Escalada inmediata**: llamada al contacto de emergencia del cliente en
     el momento en que se detecta, antes de continuar cualquier prueba.
   - **Notificación por escrito** al responsable técnico del cliente en el
     plazo de 1 hora, con el mínimo de detalle técnico necesario.
   - **Se documenta** con hora, endpoint y tipo de dato, en el log de
     acciones.
   - **Y lo que el auditor NO hace**: no difunde la exposición, no la publica,
     no la usa para acceder a más datos, no la usa como palanca comercial, no
     contacta a los afectados, no contacta a la autoridad por su cuenta, y no
     abandona el encargo sin avisar al cliente. La decisión sobre la
     notificación a los titulares y a la autoridad la toma el cliente con su
     asesoría legal, con la información que el auditor le entrega.
4. **La confidencialidad sobrevive a la finalización.** El auditor no reutiliza
   material del cliente en otro encargo, en material comercial ni en
   formación, salvo que el cliente lo autorice por escrito.

---

## 7. Firmas

### 7.1 Rechazo explícito de alguna técnica

El cliente puede rechazar, antes de firmar, cualquiera de las seis técnicas.
**Las técnicas rechazadas no se ejecutan** y se reportan como
*no ejecutada — rechazada por el cliente*, no como *no encontrada*.

| Técnica | Autorizada | Rechazada por el cliente | Motivo (opcional, para el registro) |
|---|---|---|---|
| T1 — IDOR / BOLA | [ ] | [ ] | |
| T2 — SQLi no destructivo | [ ] | [ ] | |
| T3 — XSS con payload inocuo | [ ] | [ ] | |
| T4 — Bypass de control de acceso admin | [ ] | [ ] | |
| T5 — Fichero de backup expuesto | [ ] | [ ] | |
| T6 — Validación de credencial expuesta (API del proveedor, lectura) | [ ] | [ ] | |

> **Al firmar este documento, el cliente autoriza las técnicas marcadas como
> «Autorizada» y rechaza las marcadas como «Rechazada». Las técnicas
> autorizadas se ejecutan únicamente dentro de la ventana de §4 y con el "go"
> del responsable técnico del cliente.**
>
> **El auditor acepta el alcance de §2 y se compromete a respetar §3, §5 y §6
> sin excepción.**

### 7.2 Firmas

| | |
|---|---|
| **Cliente** | [Nombre completo], [cargo — ej. Dirección General] — fecha ____ — firma ____ |
| **Responsable técnico del cliente** | [Nombre completo], [cargo — ej. Responsable de Sistemas] — fecha ____ — firma ____ |
| **Auditor** | [Nombre completo], [empresa de consultoría] — fecha ____ — firma ____ |

---

## 8. Check-list de arranque (antes de la primera prueba)

- [ ] RoE base `RoE-CJE-2026-07` firmado y archivado.
- [ ] Este addendum firmado **por las tres partes** y archivado.
- [ ] Técnicas marcadas como autorizadas en §7.1 (las rechazadas, excluidas).
- [ ] Cuentas de prueba entregadas por el cliente y **verificadas** por el
      auditor como sintéticas (sin datos de pacientes reales): paciente A,
      paciente B, admin de prueba, cuenta propia del auditor.
- [ ] Confirmado por escrito por el cliente qué cuenta corresponde a qué rol.
- [ ] Entorno de pruebas designado por escrito (sólo si se aprueba T1-B).
- [ ] Endpoint de lectura del proveedor identificado **por escrito** (sólo si
      se aprueba T6).
- [ ] Contacto de emergencia del cliente probado (llamada de prueba o
      confirmación en la ventana).
- [ ] User-Agent honesto configurado:
      `Mozilla/5.0 (compatible; ClientSecurityAudit/2.0; +52-XXX-XXX-XXXX)`.
- [ ] Ritmo configurado: ≥1 s entre peticiones, sin concurrencia, sin
      reintentos automáticos.
- [ ] Registro de acciones de Fase 2 abierto y con la hora de la ventana
      escrita.
- [ ] Evidencia en la carpeta de la fase, con nombres por contenido y valores
      sensibles enmascarados desde el momento en que se guardan.
- [ ] El responsable técnico del cliente sabe que puede detener la fase con un
      mensaje y que el auditor para de inmediato.

---

*Documento confidencial. Forma parte del expediente del engagement
`CJE-2026-01`. No distribuir fuera de las partes firmantes.*
