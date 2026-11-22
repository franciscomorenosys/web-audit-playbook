# Paquetes comerciales por fase — Auditoría de seguridad web

> **Nota interna para el consultor (eliminar este bloque antes de enviar el
> documento al cliente).** Los precios de este documento salen de la tabla de
> precios por profundidad del playbook (`04-formacion/03-modelo-de-negocio-y-legal-mx.md`
> §3.1 y §3.3), no de `research/07-paquete-comercial-mx.md` ni de
> `research/03-buo-y-precios.md`: **esos dos documentos son de otra línea de
> producto** (SaaS de assessments de personalidad para selección de personal)
> y sus cifras —planes anuales por número de evaluaciones, no honorarios de
> consultoría— **no son comparables ni trasladables a esta auditoría**. Si en
> algún momento hay que comparar este precio con el de otro proveedor, la
> comparación es contra la tabla del playbook, no contra la de `research/`.
>
> **Estructura de este documento:** los tres paquetes en orden de ejecución
> (0 → 1 → 2), una tabla comparativa y el camino recomendado. Los bloques
> `[…]` son los datos que hay que rellenar por cliente.

---

# Auditoría de seguridad web — Paquetes por fase

**Para:** [Nombre del cliente] · [Dominio]
**De:** [Nombre del consultor / empresa]
**Fecha:** [AAAA-MM-DD]
**Vigencia de la propuesta:** [AAAA-MM-DD] a [AAAA-MM-DD]

---

## 0. Cómo leer este documento

Una auditoría de seguridad web se compra en **tres momentos distintos**, no
en un solo paquete. Cada fase responde a una pregunta y produce una decisión:

| Fase | La pregunta que responde | Qué decide |
|---|---|---|
| **0 — Recon & Superficie** | ¿Qué está expuesto y qué hay que arreglar primero? | Si hace falta una auditoría más profunda, y en qué |
| **1 — Validación** | ¿Qué está realmente mal y qué dice la ley al respecto? | Qué se arregla, en qué orden y quién lo arregla |
| **2 — Explotación Limitada** | ¿Cuál es el impacto real, demostrado y medido? | Qué se arregla primero, con evidencia para terceros |

**Las tres son por separado y se pueden contratar por separado.** No hace falta
contratar las tres, y no se vende la Fase 2 a quien no la necesita.

> **Precios en pesos mexicanos (MXN), antes de impuestos.** El tipo de cambio
> de referencia usado en la elaboración de esta tabla es de aproximadamente
> 17–18 MXN por dólar (octubre de 2026). **No hay cargos por volumen de
> peticiones, por número de hosts adicionales o por "descubrir más cosas":
> el alcance de cada fase está definido por escrito, y si el trabajo
> excede ese alcance, se avisa antes de ejecutarlo.

---

## Paquete 0 — Recon & Superficie

### Para quién es

Para el dueño de una clínica, consultorio o centro de atención que **aún no
tiene un diagnóstico**. También es el paquete que compra una **agencia web**
que necesita un mapa de la superficie de su cliente antes de cotizar el
mantenimiento.

### Cuándo contratarlo (la señal)

- «Recibimos el sitio hace poco y nadie lo ha revisado desde que se puso en
  marcha.»
- «Cambiamos de agencia / de hosting / de plantilla hace menos de un año.»
- «El sitio se rehizo y no sabemos qué quedó expuesto por el camino.»
- La agencia quiere un **mapa de superficie con hallazgos priorizados** que
  pueda usar como base de su cotización y como argumento de su venta.

**Señal de que NO lo necesita:** si ya tienes una auditoría de Fase 1
entregada, esta fase ya está hecha. Pasa directo a donde te falte.

### Objetivo

Construir el **inventario de lo que existe y está expuesto**, y entregar una
**cola de trabajo priorizada** de lo que hay que arreglar, sin tocar nada que
pueda tener consecuencias.

### Qué incluye

- **Inventario de superficie:** hosts y subdominios del cliente (descubrimiento
  pasivo: certificados públicos, historiales de archivo, DNS), URLs indexadas,
  endpoints, formularios, integraciones de terceros y sus destinos.
- **Huella de plataforma:** gestor de contenidos, temas, plugins, versiones
  detectadas y **contraste de cada versión contra la fuente primaria** (no
  contra la tabla de un escáner).
- **Postura de transporte y DNS:** versiones de TLS negociadas realmente
  (fijando el máximo, no el mínimo), suite de cifrados, redirección a HTTPS,
  HSTS, cabeceras de seguridad, SPF/DKIM/DMARC/CAA/BIMI.
- **Verificaciones de configuración de bajo riesgo:** ficheros de respaldo
  expuestos, ficheros de configuración accesibles, listados de directorio
  abiertos, superficies de autenticación, endpoints de administración
  expuestos, metadatos en los ficheros subidos.
- **Barrido de secretos** en el HTML y el JavaScript ya descargados, con
  **valores enmascarados** en el informe.
- **Mapa de riesgo priorizado** con severidad, dueño y horas estimadas, y
  **el plan de remediación de la primera ola** (lo que para daño en curso o
  retira una obligación legal clara).

### Qué NO incluye

- **No hay login, no hay credenciales, no hay formularios, no hay
  autenticación.** Nada de eso.
- **No hay POST ni ningún método con cuerpo.** Sólo peticiones de lectura.
- **No hay explotación, no hay pentest, no hay prueba de concept.** Esta fase
  **encuentra y prioriza**; no demuestra que un fallo sea explotable.
- **No hay escaneo de puertos, ni de red, ni de la infraestructura del
  hosting, ni de los servidores de la agencia.**
- **No hay análisis del código fuente, ni de la aplicación, ni del panel**,
  salvo que el cliente los comparta voluntariamente.
- **No hay auditoría de cumplimiento** (la norma que aplica a cada
  hallazgo) ni redacción de borradores de ticket: eso es la Fase 1.
- **No hay medición de rendimiento, ni de SEO, ni de accesibilidad.**

### Entregables

1. **Mapa de superficie** (documento + CSV de activos).
2. **Informe de hallazgos priorizado**, con evidencia por archivo y comando
   reproducible por su equipo.
3. **Plan de remediación de la primera ola**, con horas y dueño.
4. **Sesión de entrega de 60 minutos** con su equipo técnico.

### Duración y modalidad

- **Duración:** 5 a 8 días hábiles.
- **Modalidad:** pasiva + activa de baja tasa. Peticiones de lectura
  (GET/HEAD), **≥1 segundo entre peticiones**, User-Agent honesto y
  contactable. Nada que pueda tener efecto sobre el servicio.

### Precio

**MXN 12,000** (precio de lista; rango de MXN 9,000 a 15,000 según el número
de hosts y la complejidad de la plataforma).

*Fundamento:* en el mercado mexicano, una revisión de superficie de un sitio
de hosting compartido se cotiza en el tramo bajo. Esta fase se sitúa en el
**extremo superior** de esa banda y en el **extremo inferior** de la banda de
"revisión completa": incluye mapa de superficie, plan de remediación y sesión
de entrega, pero **no** incluye explotación ni tickets de escalación, que son
lo que hace subir el precio. Si el cliente tiene varios dominios o una
plataforma compleja, se ajusta dentro del rango.

### Precondiciones

- **Autorización escrita** (RoE) antes de la primera petición. Se envía como
  anexo a esta propuesta, para que la firme antes de empezar.
- Un **contacto técnico** del cliente que pueda escalar en el momento.
- Opcional: logs de acceso del servidor. Si se comparten, el informe mejora;
  si no, el trabajo se hace igual con lo público.

### Preguntas frecuentes

**¿Esto es una prueba de penetración?**
No. Y la diferencia importa: aquí **no se intenta romper nada**. Se levanta un
inventario de lo que está expuesto y se prioriza. Un pentest que no ha
sido autorizado es una prueba de侵入ión; esto es una revisión con
autorización escrita, y el documento que lo autoriza dice exactamente qué se
va a tocar.

**¿Necesito dar acceso al panel de WordPress o al hosting?**
No, y es una ventaja: la Fase 0 se hace sobre lo que ya es público. El
panel sólo hace falta más adelante, para las Fases 1 y 2, y sólo para
ciertas pruebas que se acuerdan una por una.

**¿Van a tocar mi base de datos?**
No. En esta fase no se envía ni una sola petición con contenido. Se leen
páginas y ficheros públicos. La base de datos no aparece en el alcance.

**Mi sitio está en un hosting compartido con otras clínicas.**
Se trabaja exactamente por eso: **no se escanean los puertos ni se toca la
máquina compartida**, porque eso alcanzaría a los demás inquilinos que no
nos han autorizado nada. Se reporta la relación como riesgo y se le indica a
su hosting qué debe corregir.

**¿Cuánto tarda y qué necesito de mí?**
Entre 5 y 8 días hábiles. De su lado: un correo para autorizar y un
responsable técnico disponible una hora para la sesión de entrega.

---

## Paquete 1 — Validación

### Para quién es

Para el responsable técnico, el hosting y la agencia que **ya saben qué hay
que arreglar y necesitan saber exactamente qué, con qué evidencia, en qué orden
y con qué base legal**. También para el dueño que necesita un documento
formal para su aseguradora, su banco o su junta directiva.

### Cuándo contratarlo (la señal)

- Ya pasó la Fase 0 **y** hay hallazgos abiertos que no se han corregido.
- «Necesito un informe que pueda mandar a mi hosting y a la agencia, no un
  PDF que me dé vergüenza enseñar.»
- «Quiero saber si esto me expone a una sanción o a una reclamación de un
  paciente.»
- «Vamos a cambiar de plataforma y quiero saber qué problemas trae el
  nuevo sitio antes de migrar.»

### Objetivo

Convertir **"hay algo sospechoso"** en **"esto está confirmado, esto es lo
que cuesta arreglarlo, esto es lo que dice la norma aplicable y estos son los
comandos para reproducirlo"**.

### Qué incluye

- **Verificación activa de baja tasa** de los candidatos de la Fase 0:
  peticiones de lectura, ≥1 s entre peticiones, UA honesto, **sin ninguna
  acción que pueda tener efecto sobre el servicio**.
- **Investigación contra fuente primaria** de cada componente detectado: la
  tabla oficial de avisos del proyecto, no la tabla de un escáner. Cada
  afirmación lleva su fuente enlazada, y lo que no se puede verificar se
  marca **«no verificado»** con el ticket de 60 segundos para cerrarlo.
- **Mapeo a cumplimiento** (marco mexicano de protección de datos y de
  publicidad sanitaria) con **cita y enlace a la fuente primaria**, y
  **refutaciones explícitas** donde la obligación no existe.
- **Fichas de hallazgo completas:** evidencia literal, comando de
  reproducción, severidad calibrada por contenido, dueño y horas.
- **Registro de riesgos puntuado**, con separación explícita entre lo que
  arregla el cliente, lo que hay que exigir al hosting y lo que hay que exigir
  a la agencia.
- **Hoja de ruta en tres olas** (hoy / este mes / este trimestre) ordenada
  por **ICE** (riesgo removido por hora de esfuerzo), no por lo que suena más
  grave.
- **Borradores de ticket listos para enviar** al hosting y a la agencia: usted
  no tiene que redactar nada.
- **Entrega en tres capas** (ver abajo).

### Qué NO incluye

- **No hay explotación, no hay PoC, no hay bypass de control de acceso.** Esta
  fase **confirma y prioriza**; no demuestra el impacto.
- **No hay POST, ni login, ni credenciales, ni formularios.**
- **No hay pruebas de carga, ni de denegación de servicio, ni de
  disponibilidad.**
- **No hay escaneo de puertos, ni fuzzing de rutas, ni fuerza bruta.**
- **No hay acceso a la red interna, ni al panel del hosting, ni al servidor.**
- **No hay análisis de código fuente ni de repositorios** del cliente, salvo
  que los comparta voluntariamente.
- **No hay opinión legal ni asesoría jurídica**: lo que se entrega es un
  mapeo de observaciones verificables con su fuente, y eso lo revisa un
  abogado.
- **No hay pentest, ni red team, ni simulación de phishing.**

### Entregables (tres capas, tres audiencias)

| # | Documento | Para quién | Qué lleva |
|---|---|---|---|
| 1 | **Resumen ejecutivo** (PDF) | El dueño | Cifras, categorías de riesgo, exposición legal, **lo que ya está bien**, oferta. Cero detalle técnico. |
| 2 | **Informe técnico completo** (Markdown) | Equipo técnico, hosting, agencia | Las secciones §0–§9 con evidencia, comandos, severidad, dueño, hoja de ruta, tickets y refutaciones legales. **Confidencial: no se envía al dueño ni a terceros.** |
| 3 | **Brief en lenguaje llano** (2–3 páginas) | El dueño | Sin jerga: qué significa cada problema en dinero y en riesgo, y qué se le pide hacer hoy, este mes y este trimestre. |

### Duración y modalidad

- **Duración:** 10 a 15 días hábiles, contando el tiempo de revisión legal
  del cliente (el informe se entrega con los huecos legal marcados).
- **Modalidad:** activa de baja tasa. Sólo peticiones de lectura, ≥1 s entre
  peticiones, UA honesto, ritmo lento y nunca masivo.

### Precio

**MXN 28,000** (precio de lista; rango de MXN 22,000 a 35,000 según la
complejidad de la plataforma y el número de hallazgos a verificar).

*Fundamento:* es el precio de una revisión completa con tres capas, hoja de
ruta y tickets, en el tramo que paga el cliente pequeño y mediano mexicano
para este tipo de encargo. Contratar la Fase 0 y la Fase 1 juntas cuesta
MXN 40,000, que es el piso de la banda de la "revisión completa" para una
boutique.

### Precondiciones

- **Autorización escrita (RoE) firmada** antes de la primera petición.
- **Un responsable técnico identificado** que reciba las escalaciones.
- **El RoE define qué es "fuera de alcance"**: si durante el trabajo aparece
  un host de un tercero (hosting, agencia, SaaS), se describe, no se ataca.
  Si ese host no está listado en el RoE, se para y se pregunta.
- **Opcional pero recomendado:** logs de acceso y el contacto del hosting,
  para que las escalaciones se puedan enviar el mismo día.

### Preguntas frecuentes

**¿Qué diferencia hay entre esto y un análisis de vulnerabilidades con un escáner?**
El escáner **propone**; la fuente primaria **dispone**. Este paquete
contrasta cada versión y cada aviso contra la fuente oficial del proyecto y
distingue siempre dos cosas que los escáneres confunden: que un número de
versión *pertenezca* a un rango vulnerable, y que ese fallo sea *alcanzable*
desde internet. La mitad de los "críticos" que reportan los escáneres
gratuitos no son ni lo uno ni lo otro.

**¿Van a hacer pruebas que puedan afectar mi sitio?**
No. Se hacen peticiones de lectura, espaciadas al menos un segundo, con un
User-Agent que se identifica. En esta fase **no se envía ni una sola
petición con contenido**, no hay login y no hay carga. Si el servidor
bloquea al auditor, eso se reporta como señal y se escala la decisión: no se
esquiva.

**Si aparece algo grave, ¿qué pasa?**
Se le avisa el mismo día por el canal que elija, antes de terminar la fase.
Ese es el motivo por el que la Fase 1 empieza con una hoja de ruta de "hoy":
en la mayoría de los sitios, los primeros problemas son pequeños y baratos y
están esperando a que alguien los escriba.

**¿El informe se lo puedo mandar a mi agencia o a mi hosting?**
Sí, y es el destinatario principal del informe técnico. Por eso lleva los
**borradores de ticket redactados**: usted no sabe escribir un ticket técnico
y perderá el impulso si tiene que redactarlo usted. La versión para el dueño
y el resumen ejecutivo no se envían a terceros.

**¿La parte legal es una asesoría?**
No. Es un **mapeo a la normatividad aplicable, con cita y enlace a la fuente
oficial**, y una lista explícita de lo que **no** es obligación (verificarlo y
refutarlo es tan importante como encontrarlo). La interpretación y la
estrategia legal las revisa su abogado con ese insumo.

---

## Paquete 2 — Explotación Limitada

### Para quién es

Para el cliente que **ya tiene su informe de Fase 1** y necesita **demostrar
el impacto real** de los hallazgos confirmados: para priorizar internamente,
para justificar una inversión ante la junta, para una póliza de seguro
cibernético o para una revisión de un tercero.

### Cuándo contratarlo (la señal)

- «Hay hallazgos ALTO o CRÍTICO confirmados y no sé por dónde empezar a
  arreglarlos.»
- «Mi aseguradora me pide evidencia de que el riesgo es real, no una
  lista de recomendaciones.»
- «El equipo no me cree cuando digo que el sitio tiene un problema de
  control de acceso. Necesito una demostración reproducible.»
- «Vamos a una auditoría externa y necesito saber qué van a encontrar.»

**Señal de que NO lo necesita:** si la Fase 1 no encontró ningún hallazgo
confirmado de severidad alta, o si ya corregiste todo. En ese caso, lo que
conviene es un **re-test** o un **retainer de vigilancia**, no esta fase.

### Objetivo

**Demostrar el impacto real** de los hallazgos ya confirmados, con
ejecuciones acotadas, sin tocar un solo dato de paciente y dejando el sistema
exactamente como estaba.

### Qué incluye

- **Seis técnicas acotadas**, ejecutadas una por una, sólo sobre hallazgos
  ya identificados en Fase 1:
  1. **IDOR / BOLA** con cuentas de prueba del cliente (lectura; y, sólo si el
     cliente designa un entorno de pruebas por escrito, un único recurso
     propio para demostrar el fallo en la ruta de escritura).
  2. **SQLi no destructivo**, por comparación booleana. **Sin** `UNION`, sin
     consultas apiladas, sin extraer filas, sin contar registros.
  3. **XSS con payload inocuo**, sólo contra la cuenta propia del auditor:
     un marcador de texto, sin beacon, sin acceso a cookies.
  4. **Bypass de control de acceso administrativo**, con la cuenta de prueba
     de administrador que entrega el cliente y con una cuenta de paciente.
  5. **Configuración insegura**: confirmar la existencia de un fichero de
     respaldo expuesto leyendo **1 KB**, sin descargar el fichero completo.
  6. **Validación de una credencial expuesta**, mediante **una sola** llamada
     de lectura a la API del proveedor que el cliente indique por escrito.
- **Ejecución bajo "go" por prueba:** el responsable técnico del cliente
  autoriza cada técnica individualmente, en el canal de la ventana.
- **Ventana horaria acordada** (típicamente fuera de horario comercial), con
  contacto de emergencia disponible en ambos lados.
- **Registro de acciones completo**, con hora, cuenta, huella y rollback.
- **Anexo de explotación limitada** añadido al informe técnico, con una
  ficha por hallazgo que incluye **«Lo que NO se hizo»**: qué tenía
  capacidad el auditor de hacer y deliberadamente no hizo.
- **Declaración de limpieza** firmada, con el detalle de la huella dejada y
  de quién la retiró.

### Qué NO incluye

- **No hay denegación de servicio, ni estrés, ni pruebas de carga.**
- **No hay escritura, modificación ni borrado de datos de producción.** La
  única escritura posible es un (1) artefacto de prueba propio, en el
  entorno de pruebas que el cliente designe por escrito.
- **No hay acceso a cuentas de terceros**: ni personal, ni pacientes, ni
  proveedores.
- **No hay extracción de datos personales ni clínicos.** Ni una fila, ni un
  conteo.
- **No hay persistencia**: sin webshells, sin tareas programadas, sin usuarios
  creados, sin claves nuevas.
- **No hay movimiento lateral** fuera de los hosts autorizados, ni sondeo de
  la infraestructura de terceros.
- **No hay cracking de hashes, ni bypass de MFA, ni ingeniería social al
  personal.**
- **No se usa el secreto encontrado más allá de la validación de lectura
  autorizada**, ni se comunica a ningún tercero.
- **No es un pentest completo ni una simulación de intrusión.** No hay
  instalación de exploits, ni persistencia, ni red team.

### Entregables

1. **Anexo de explotación limitada** (sección nueva del informe técnico):
   tabla de hallazgos explotados, ficha por hallazgo con evidencia
   enmascarada, impacto real vs. impacto máximo teórico, **«Lo que NO se
   hizo»**, datos reales expuestos (SI/NO + categoría, nunca el valor),
   limitaciones, plan de remediación con prioridad ICE y re-test.
2. **Registro de acciones de Fase 2** (CSV): las seis técnicas, incluidas las
   refutadas y las no ejecutadas.
3. **Declaración de limpieza** firmada.
4. **Sesión de cierre de 60 minutos** para acordar prioridades de arreglo.

### Duración y modalidad

- **Duración:** 5 a 8 días hábiles de calendario; **la ejecución técnica
  ocurre en una ventana de 3 horas** (típicamente de noche o en fin de
  semana), con una ventana de respaldo acordada.
- **Modalidad:** **activa controlada**, la única que este tipo de trabajo
  admite. Requiere un **addendum de RoE específico, firmado por las tres
  partes**, que enumera una por una las técnicas autorizadas, la ventana, los
  participantes y el criterio de abort inmediato.

### Precio

**MXN 60,000** (precio de lista; rango de MXN 50,000 a 85,000 según el
número de hallazgos a demostrar y el número de entornos).

*Fundamento:* una prueba de penetración con explotación y credenciales
provistas por el cliente se cotiza en un rango de USD 5,000 a 15,000 en
consultoría independiente. **Esta fase se cotiza por debajo de ese rango a
propósito**, y la razón es el alcance: seis técnicas acotadas, sin carga, sin
extracción de datos, sin persistencia y con una ventana de tres horas. No es
un pentest, y no se factura como un pentest.

### Precondiciones

**Todas son obligatorias. Si falta una, la fase no se ejecuta.**

1. **RoE base firmado y vigente.**
2. **Addendum de Fase 2 firmado por las tres partes** (cliente, responsable
   técnico y auditor), con las técnicas marcadas una por una como
   **autorizadas o rechazadas**. El cliente puede rechazar técnicas: las
   rechazadas se reportan como *no ejecutadas*, nunca como *no encontradas*.
3. **Cuentas de prueba del cliente**, verificadas como sintéticas: al menos
   dos cuentas de paciente, una de administrador y una del auditor.
4. **Ventana horaria acordada** y **contacto de emergencia probado** en
   ambos lados.
5. **Para la validación de la credencial:** el endpoint de lectura
   autorizado, **indicado por escrito** por el cliente.
6. **Para el artefacto de escritura (variante B de IDOR):** entorno de
   pruebas designado por escrito. Si no se designa, esa variante no se
   ejecuta y se reporta como no ejecutada.
7. **Continuidad del responsable técnico durante la ventana**: sin "go", no
   hay prueba.

### Preguntas frecuentes

**¿Van a ver datos de mis pacientes?**
No. Está prohibido por escrito en el addendum, y es la primera pregunta que
debe poder hacerse. En la fase de ejecución no se abre, copia, transcribe,
resume ni **cuenta** ningún expediente, historial clínico o archivo de
paciente. Las pruebas se hacen contra cuentas de prueba con datos sintéticos
que usted mismo proporciona. Si una respuesta trajera un dato de una persona
por error, se descarta sin conservarse y se le avisa el mismo día.

**¿Y si encontramos algo que no está previsto?**
Se para. El addendum define tres criterios de **abort inmediato** por
adelantado: que aparezca un dato de paciente o de un tercero en una
respuesta; que se produzca un efecto no previsto (un registro creado, un
correo enviado, un error 500 reproducible); o que aparezca cualquier señal de
degradación del servicio. En cualquiera de los tres casos el auditor detiene
el trabajo de inmediato, sin esperar confirmación, y le entrega el registro de
lo hecho hasta ese momento.

**¿Quién es responsable si algo sale mal?**
El alcance está cerrado por escrito antes de empezar: qué se hace, qué no se
hace, en qué ventana, con qué cuentas y con qué criterio de parada. Además,
la evidencia de Fase 2 se entrega con el valor enmascarado y con la
declaración de limpieza, de modo que el expediente del engagement demuestra
exactamente qué se tocó. La ejecución técnica se hace con el personal del
cliente en línea y con su "go" por prueba, lo que además reduce el riesgo
operativo a un mínimo razonable.

**¿Puedo rechazar alguna técnica?**
Sí, y es una casilla expresa en el addendum. Si rechaza el bypass de control
de acceso administrativo, no se ejecuta y se reporta como *no ejecutada —
rechazada por el cliente*. Lo que no se puede hacer es rechazar la
autorización y después exigir el resultado.

**¿Y si no quiero esta fase?**
Puede no contratarla y queda con la Fase 1, que ya le da el mapa priorizado.
Lo que cambia sin la Fase 2 es la naturaleza de la evidencia: la Fase 1 le
dice **qué** está mal; la Fase 2 le dice **cuánto** le cuesta.

---

## Tabla comparativa

| | **Fase 0 — Recon & Superficie** | **Fase 1 — Validación** | **Fase 2 — Explotación Limitada** |
|---|---|---|---|
| **La pregunta** | ¿Qué está expuesto? | ¿Qué está mal y qué dice la norma? | ¿Cuál es el impacto real? |
| **Método** | Pasivo + lectura | Activo de baja tasa (lectura) | **Activa controlada** (6 técnicas acotadas) |
| **Métodos HTTP** | GET / HEAD | GET / HEAD | GET / HEAD (+ 1 POST acotado y opcional) |
| **Autenticación** | No | No | Sí, con cuentas de prueba del cliente |
| **Abre datos de pacientes** | No | No | **No, prohibido por escrito** |
| **Duración** | 5–8 días hábiles | 10–15 días hábiles | 5–8 días, con ventana de 3 h de ejecución |
| **Entregables** | Mapa de superficie, hallazgos priorizados, ola 1 | 3 capas (resumen, informe técnico, brief) + tickets | Anexo de explotación + registro de acciones + limpieza |
| **Auditoría legal (fuente primaria)** | No | Sí | No (remite a Fase 1) |
| **Requiere RoE firmado** | Sí | Sí | **Sí + addendum de Fase 2 firmado** |
| **Requiere cuentas de prueba** | No | No | **Sí** |
| **Requiere ventana y contacto de emergencia** | No | No | **Sí** |
| **Riesgo de causar daño** | Nulo | Nulo | **Controlado y acotado** |
| **Precio (MXN)** | **12,000** | **28,000** | **60,000** |
| **Precio de la ruta completa** | — | — | **MXN 100,000** (MXN 90,000 con descuento de ruta) |

---

## Camino recomendado: 0 → 1 → 2

**La secuencia natural es esa, y la razón es de eficiencia, no de venta:**

```
   Fase 0                      Fase 1                       Fase 2
   MXN 12,000                 MXN 28,000                   MXN 60,000
       │                          │                            │
       ▼                          ▼                            ▼
  Qué existe y              Qué está mal,                Cuánto cuesta
  qué está expuesto    →    con evidencia y           →   de verdad y qué
                               con la norma                    se arregla primero
```

1. **Fase 0 → Fase 1.** La Fase 0 es barata y rápido: produce el inventario
   y la cola de trabajo. Sin ella, la Fase 1 empieza desde cero y cobra por
   el mismo recon otra vez. **Contratarlas juntas cuesta MXN 40,000.**
2. **Fase 1 → Fase 2.** La Fase 2 sólo tiene sentido sobre hallazgos
   **confirmados** de Fase 1: se demuestra el impacto de lo que ya se sabe
   que está mal, no se buscan cosas nuevas. **Si la Fase 1 no dejó ningún
   hallazgo alto abierto, la Fase 2 no aporta** y lo que conviene es un
   re-test o un retainer.
3. **Cerrar el ciclo con el re-test.** Una vez corregido, se re-ejecutan las
   técnicas afectadas para demostrar que el arreglo funcionó. **El re-test se
   cotiza aparte** (MXN 12,000) y es el mejor gancho de renovación: es la
   prueba de que el dinero gastado funcionó.

**Descuento de ruta:** contratar las tres fases en un mismo encargo da un
**10 % sobre el total** (MXN 90,000 en lugar de MXN 100,000). El descuento
aplica al total del encargo, no a cada fase por separado.

**Alternativas y cuándo tienen sentido:**

| Situación | Qué contratar |
|---|---|
| "No me han revisado nunca la web" | **Fase 0**. Y con lo que salga, se decide si hace falta Fase 1. |
| "Ya tengo el diagnóstico y necesito el documento formal" | **Fase 1**. |
| "Tengo hallazgos altos confirmados y necesito demostrar el impacto" | **Fase 2** (tras el addendum firmado). |
| "Ya lo arreglé todo y quiero comprobarlo" | **Re-test** de los hallazgos cerrados (cotizado aparte). |
| "Quiero que me vigilen todo el año" | **Retainer** de vigilancia de exposición (MXN 4,000 a 12,000 al mes): recaneo trimestral, vigilancia de DNS/TLS/certificados/subdominios, canal prioritario y seguimiento de los arreglos. **No es un pentest mensual** y no se vende como tal. |
| "Somos una agencia y queremos marca blanca" | **Fase 1** con informe en marca blanca y re-cobro al cliente final. Es el mejor cliente recurrente. |

---

*Documento comercial. Vigencia [AAAA-MM-DD] a [AAAA-MM-DD]. Los precios no
incluyen impuestos. Cualquier trabajo fuera del alcance escrito de la fase
contratada se cotiza por separado y se acuerda antes de ejecutarlo.*
