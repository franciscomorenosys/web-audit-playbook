# Fase 2 — Explotación autorizada y limitada

> **Principio gobernante.**
> **Demostrar, no dañar. Probar la frontera, no el daño.**
> La **capacidad** es el hallazgo; la **explotación controlada** genera la evidencia que hace vendible la remediación.

> **Qué es este documento.**
> La metodología de la **segunda etapa** de una auditoría web: la fase en la que, con autorización escrita adicional, se **demuestra** el impacto de un hallazgo ya identificado en la fase anterior, de forma controlada, acotada y no destructiva.
>
> **Qué NO es.**
> No es una guía de pentest, no es una guía de escalada de privilegios y no es una licencia para buscar vulnerabilidades nuevas.
> Es el procedimiento de ejecución de **seis técnicas nombradas una por una** en un addendum firmado.

> **Documentos relacionados:**
> - `00-metodologia/reglas-de-autorizacion-y-roe.md` — la doctrina y las **cinco prohibiciones duras**. Este documento no la sustituye: la ejecuta.
> - `00-metodologia/ciclo-de-auditoria.md` — las 11 fases del ciclo. Define la Fase 0 y la Fase 1 de la escalera de este documento.
> - `05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md` — **la plantilla del addendum**. Es la fuente de verdad de qué se puede hacer.
> - `02-plantillas/informe-completo/anexo-explotacion-limitada.md` — **la plantilla del anexo** que este documento alimenta.
> - `05-plantillas-de-trabajo/registro-de-acciones-fase-2.csv` — el formato de captura durante la ventana.
> - `01-tooling/scripts/README.md` — el toolkit propio (`scope_guard.py`, `probe_exposure.py`, `secrets_scan.py`, `js_intel.py`, `header_tls_report.py`, `pii_redact.py`, `attack_surface_report.py`).
> - Módulos hermanos (en redacción paralela, **no** se duplica su contenido aquí): `exposicion-de-secretos.md` (superficie de secretos y su tratamiento), `exposicion-a-ataques.md` (superficie expuesta a terceros), `modelo-de-servicio-y-escalabilidad.md` (superficie de subdominios y superficie de servicio).

---

## 1. Qué cambia y qué no

### 1.1 El principio que cambia de estatus

En la Fase 0 y en la Fase 1, la doctrina es: **reporta la capacidad, no ejecutes la explotación**.
Esa regla no se deroga: se **acota y se especializa**.

| | Fase 0 / Fase 1 | Fase 2 (este documento) |
|---|---|---|
| **Unión de los hallazgos** | Capacidad descrita, no ejecutada | Capacidad **demostrada** en un caso concreto y controlado |
| **Método** | Lectura del código, del JavaScript público, de las cabeceras, de los índices de terceros | Una **acción controlada** sobre un endpoint identificado |
| **Efecto sobre el sistema** | Cero | **Huella mínima y declarada**, limpiada antes de cerrar |
| **Qué prueba al cliente** | Que el fallo *podría* ocurrir | Que el fallo **ocurre**, con evidencia reproducible por su equipo |
| **Quién debe estar presente** | Nadie (trabajo autónomo) | El **responsable técnico del cliente, en la llamada**, con capacidad de parar |

> **La frase que hay que interiorizar:** *el daño > el hallazgo* no significa «no busques hallazgos».
> Significa que **un hallazgo que no puedes probar sin causar daño se reporta como capacidad y no como explotación**, y que **probar un hallazgo no autoriza crear el daño que el hallazgo describe**.

### 1.2 Lo que el addendum habilita

El addendum **no es una autorización general**.
Es una lista cerrada de seis técnicas, cada una con: endpoint, método HTTP, condición de ejecución, requisito previo, evidencia a recoger, huella a dejar, tiempo máximo y tiempo total.
Si una técnica, un endpoint o un método no aparece en §2 del addendum firmado, **no existe**.

| # | Técnica habilitada | Núcleo de lo que se demuestra | Naturaleza del impacto permitido |
|:-:|---|---|---|
| **T1** | IDOR / BOLA | Una cuenta autenticada lee un registro que pertenece a otra cuenta | Lectura, con dos cuentas de prueba sintéticas |
| **T2** | SQLi no destructivo | Un parámetro entra en una consulta y acepta una condición booleana | Comparación de respuestas, sin extraer filas |
| **T3** | XSS con payload inocuo | Un parámetro se refleja sin codificar en la respuesta | Reflejo de un texto marcador, en la cuenta propia |
| **T4** | Bypass de control de acceso administrativo | Un endpoint administrativo no comprueba el rol, o lo comprueba mal | Lectura de metadatos de la propia cuenta |
| **T5** | Fichero de backup/configuración expuesto | Existe un fichero fuera del directorio público que no debería estarlo | 1 KB de lectura con `Range`, sin descargar |
| **T6** | Validación de credencial expuesta vía API del proveedor | La credencial expuesta está **viva** y expone una categoría de recursos | **Una** llamada de lectura, sobre un endpoint designado por escrito |

> **Límite del alcance del addendum, textual:** la autorización es para *demostrar el impacto de hallazgos ya identificados en Fase 1*, sobre activos ya existentes, usando cuentas de prueba del propio cliente.
> **No es una autorización para buscar vulnerabilidades nuevas**, ni para explorar la red del cliente más allá de los hosts declarados, ni para tocar sistemas de terceros.
> En la práctica, esto significa que la Fase 2 **no puede crecer**.
> Si durante la ventana aparece un vector nuevo, se anota como *candidato a una ventana posterior* y se sigue sin tocarlo.
> Un hallazgo extra no vale una ampliación de alcance.

### 1.3 Las cinco prohibiciones duras: qué se relaja y qué no

Las prohibiciones de `reglas-de-autorizacion-y-roe.md` §1 siguen vigentes.
La tabla dice exactamente cómo se aplica cada una.

| # | Prohibición dura | ¿Se relaja en Fase 2? | Condición exacta de la relajación | Por qué |
|:-:|---|---|---|---|
| **1.1** | Nunca hacer POST ni ningún método con cuerpo | **Sí, de forma excepcional y delimitada** | Únicamente en la **variante B de T1**: un (1) artefacto de prueba propio, **en el entorno de pruebas que el cliente designe por escrito**, con la cuenta del auditor, contenido vacío y nombre fijo, con limpieza obligatoria antes de cerrar. **Ninguna otra técnica escribe.** | Sin crear un objeto propio no hay forma de demostrar un fallo de control de acceso en la **ruta de escritura**. Un solo artefacto, en un entorno que no contiene datos reales, es el mínimo demostrativo. |
| **1.2** | Nunca tocar endpoints que sostienen datos de terceros | **No, en su núcleo.** Lo que se relaja es *qué* se toca: el registro de la cuenta de prueba B (que es del cliente, no de un tercero), no el de un paciente | La prueba usa **exclusivamente cuentas de prueba del cliente con datos sintéticos**. Ningún registro de paciente, de personal o de un tercero se solicita, ni para confirmar que existe | Tocar un registro real de paciente no es «una prueba más»: es la propia brecha que el informe va a describir |
| **1.3** | Nunca des-anonimizar: reporta el riesgo, no ejecutes la capacidad | **Sí, de forma delimitada** | Únicamente **T6**: una (1) llamada de **solo lectura** al endpoint que el cliente indique **por escrito**, para comprobar si la credencial está viva y qué **categorías** de recurso expone. No se enumera, no se descarga, no se transcribe, no se usa para nada más | Es la **única** forma de pasar de «hay una cadena que parece una clave» a «esta clave está viva y abre esta categoría de recursos», que es la diferencia entre un hallazgo vendible y uno decorativo |
| **1.4** | Nunca sondear la infraestructura de terceros que descubriste | **No. Nunca.** | — | T6 es una excepción a 1.3, **no** a 1.4: validar una credencial contra la API del proveedor no autoriza tocar el panel del hosting, la agencia web ni ningún otro inquilino | Un solo host de un tercero tocado destruye la confianza de los 20 demás |
| **1.5** | Nunca escanear una IP compartida | **No. Nunca.** | — | El escaneo de puertos golpea a los demás inquilinos del host | Ninguna técnica de las seis requiere tocar puertos |

> **La asimetría importante:** de las cinco prohibiciones, **tres no se relajan nunca** (1.2 en su núcleo, 1.4 y 1.5) y **dos se relajan de forma nominal** y delimitada (1.1 y 1.3).
> Y en los dos casos de relajación, **el daño sigue prohibiéndose por otra vía**: la escritura de T1-B está confinada a un entorno de pruebas sin datos reales; el uso de T6 está confinado a una llamada de lectura que no puede enumerar ni escribir.
> **No hay «excepción por urgencia», ni «excepción por autorización del dueño», ni «excepción por tamaño del cliente».** Si una prueba requiere alguna de ellas, la prueba **no se hace** y se reporta como *no verificada*.

### 1.4 Lo que el addendum además endurece

El addendum no sólo amplía: **añade reglas más estrictas que las del RoE base**, que prevalecen sobre él en caso de conflicto.
Esto es lo que convierte la Fase 2 en algo defendible ante un cliente que maneja datos clínicos.

| Regla añadida | Por qué endurece |
|---|---|
| El **"go" es por prueba**, no por fase | Nadie puede decir «te di permiso para todo». Cada fila del registro tiene su "go" con hora |
| **El silencio no es un "go"** | Si el responsable técnico no contesta en 10 minutos, la prueba no se ejecuta y se anota *no ejecutada — sin go* |
| **Criterios de abort automático** (3) | El auditor para sin pedir permiso, y el cliente puede parar con un mensaje |
| **Minimización de datos** (§5 del addendum) | Lo que se guarda, lo que se redacta y lo que se destruye, por escrito |
| **Retención de 30 días naturales** y destrucción verificable | La evidencia de una fase que toca datos de pacientes no es un archivo que se guarda para siempre |
| **Compromiso de no divulgación** | Sin redes, sin foros, sin tickets abiertos, sin reutilización en otros encargos |
| **Declaración de limpieza firmada** | El cliente sabe qué quedó, quién lo retira y qué no es retirable por el auditor |
| **Escalación inmediata** ante PII ajena real | Con llamada de emergencia en el momento y notificación escrita en ≤1 h |

> **La ventana de ejecución es de 145 minutos de tiempo activo** para las seis técnicas, dentro de una ventana de 3 horas.
> El margen no es teórico: existe para la coordinación, las pausas y el abort.
> Si una técnica se pasa de su tiempo máximo, **se interrumpe** y se anota como incompleta.

---

## 2. Las tres fases de vulnerabilidad

### 2.1 El modelo: una escalera, no un checklist

El playbook organiza el trabajo en **11 fases de un ciclo**.
Este documento organiza **el tratamiento de una vulnerabilidad** en **tres fases**.
Son dos ejes distintos y no se deben confundir.

```
   Fase 0                    Fase 1                        Fase 2
   Recon pasivo             Validación activa              Explotación autorizada
   ─────────────             ─────────────                  ─────────────────────
   Sin tocar el              GET/HEAD, superficie            Ventana, cliente presente,
   objetivo.                 conocida, no destructivo        prueba sin daño
   ──────────────────────────────────────────────────────────────────────────────
   Capacidad descrita        Capacidad acotada              Capacidad probada
   "esto podría pasar"       "esto pasa en estos             "esto pasó, y esto es
                              endpoints, en este              el impacto medido"
                              estado"
   ──────────────────────────────────────────────────────────────────────────────
   Riesgo: bajo               Riesgo: medio                   Riesgo: acotado por
                                                            diseño (matriz de
                                                            destructividad)
```

> **La escalera no es una escalera de valor.** Fase 2 **no** produce un hallazgo mejor que Fase 1: produce un hallazgo **demostrado**.
> La diferencia es de clase probatoria, no de magnitud.
> Un hallazgo de Fase 1 bien escrito, con su cadena completa y su evidencia, es vendible.
> Un hallazgo de Fase 2 sin el cuidado de esta metodología es un incidente con respaldo documental.

> **Nombramiento interno, sin estándar externo.** La escalera *Fase 0 / Fase 1 / Fase 2* es una convención de este playbook para clasificar **el tratamiento de una vulnerabilidad**.
> No es un marco de referencia publicado ni una taxonomía de OWASP, WSTG o NIST.
> No se cita como si lo fuera, y no se afirma que exista un estándar externo que obligue a esta división.

### 2.2 Fase 0 — Reconocimiento pasivo

| | |
|---|---|
| **Objetivo** | Mapear la superficie sin tocar el objetivo. Saber qué hay antes de decidir qué se va a probar. |
| **Permitido** | Consultas a terceros (crt.sh, Wayback CDX, Common Crawl, InternetDB, ipinfo), descarga de HTML y JS **públicos** para análisis **offline**, DNS del dominio del cliente, certificado del propio cliente. |
| **Prohibido** | Cualquier petición que no sea GET/HEAD al activo; login; formularios; escaneo de puertos; fuerza bruta; enumeración masiva; cualquier lectura de contenido que pertenezca a una persona. |
| **Evidencia** | `crtsh_*.json`, `cdx*.json`, `pages/`, `js/`, `dns_*.txt`, `tls_cert.txt`, `secret_scan.txt`. |
| **Entregable** | Un inventario de superficie **candidatos**, con la evidencia que justifica cada candidato. Nada más. |
| **Quién** | El auditor, de forma autónoma. No requiere presencia del cliente. |
| **Habilidades** | OSINT aplicado; lectura de JavaScript y de cabeceras; disciplina para no «comprobar» nada que ya está documentado como capacidad. |
| **Módulo** | `00-metodologia/ciclo-de-auditoria.md` (Fases 2–7 del ciclo) y `01-tooling/manifiesto-de-herramientas.md`. |

> **La salida de la Fase 0 es una lista, no un veredicto.** Un candidato es «aquí puede haber un problema».
> Su calificación llega después.

### 2.3 Fase 1 — Validación activa controlada

| | |
|---|---|
| **Objetivo** | Acotar la superficie y reducir el conjunto de candidatos a un número pequeño, con evidencia propia y con bajo riesgo. |
| **Permitido** | GET/HEAD espaciados ≥1 s; User-Agent honesto; rutas fijas y **cortas** (`probe_exposure.py` recorre 53 rutas conocidas, no un diccionario); volcado de cabeceras; escaneo local de secretos en lo ya descargado; análisis local de JS/HTML. |
| **Prohibido** | POST o cualquier método con cuerpo; login; credenciales; fuzzing de rutas; escaneo de puertos; carga; escaneo masivo de subdominios; `nuclei`, `sqlmap`, `nikto`, `ffuf`, `dirsearch` sin autorización expresa. |
| **Evidencia** | `probe_exposure.tsv` / `.json` con marca de `soft_404`, `headers.txt`, `secrets.json`, `js_intel.json`, `header_tls.md`. |
| **Entregable** | El **registro de candidatos a Fase 2**: cada hallazgo con (a) el endpoint exacto, (b) el método y los parámetros implicados, (c) la hipótesis falsable, (d) la evidencia que lo sostiene, (e) el riesgo de la prueba si se confirma. |
| **Quién** | El auditor, con el RoE base firmado. Sin presencia del cliente, pero **sin salir del allowlist de hosts**. |
| **Habilidades** | Lectura de TSV/JSON y detección de `soft_404`; criterio para no inflar severidad; redacción de hipótesis falsables. |
| **Módulo** | `00-metodologia/ciclo-de-auditoria.md` (Fases 5–6 del ciclo) y `01-tooling/scripts/`. |

> **El filtro de entrada a la Fase 2 se llama en el addendum.** El §2 del addendum no dice «demuestra lo que encontraste»: dice «demuestra **esto**», con endpoint y método.
> La Fase 1 es la que produce esa lista.
> Sin lista, no hay addendum posible.

### 2.4 Fase 2 — Explotación autorizada y limitada (este documento)

| | |
|---|---|
| **Objetivo** | Convertir un candidato en un hallazgo **demostrado**, con una prueba mínima que no produce daño y una huella declarada y limpiada. |
| **Permitido** | Exactamente las seis técnicas T1–T6 del addendum, en sus endpoints, con sus métodos, con sus condiciones y dentro de su tiempo máximo. Una acción por prueba. |
| **Prohibido** | Las 11 prohibiciones del §3 del addendum (denegación de servicio, escritura/borrado en producción, cuentas de terceros, extracción de PII, persistencia, movimiento lateral, cracking de hashes, bypass de MFA, ingeniería social, uso del secreto más allá de la validación, comunicación a terceros). |
| **Evidencia** | `evidencia/fase2/*.txt` sanitizados; `registro-de-acciones-fase-2.csv`; la **declaración de limpieza** firmada. |
| **Entregable** | El **Anexo — Explotación limitada** con: tabla de hallazgos explotados, una ficha por hallazgo con el apartado obligatorio **«Lo que NO se hizo»**, §5 de datos reales expuestos, §8 de declaración de limpieza, §9 de índice de evidencia. |
| **Quién** | El auditor, **con el cliente presente en la llamada** y con el **"go" por prueba** del responsable técnico del cliente. |
| **Habilidades** | Además de las de Fase 1: lectura de HTTP (códigos, cabeceras, cuerpos, diferencias de longitud); **disciplina de contención** (pararse a media prueba); redacción de evidencia sin datos; lectura de logs del cliente en vivo; calibración de severidad con el impacto demostrado, no con el teórico. |
| **Módulo** | Este documento. |

### 2.5 Comparativa de las tres fases

| Dimensión | Fase 0 | Fase 1 | Fase 2 |
|---|---|---|---|
| **Contacto con el objetivo** | Cero | GET/HEAD | GET/HEAD + 1 escritura acotada (T1-B) + 1 llamada a API de tercero (T6) |
| **Riesgo para el cliente** | Nulo | Bajo | Acotado por diseño, y **declarado** |
| **Presencia del cliente** | No | No | **Sí, en la llamada** |
| **Ritmo** | Sin límite (son consultas a terceros) | ≥1 s | ≥1 s, sin concurrencia, sin reintentos automáticos |
| **Herramientas propias** | `secrets_scan.py`, `js_intel.py` sobre material descargado | `scope_guard.py`, `probe_exposure.py`, `header_tls_report.py` | Las mismas + `pii_redact.py` + `attack_surface_report.py` |
| **Qué produce** | Candidatos | Candidatos calificados | **Hallazgos demostrados** + declaración de limpieza |
| **Firma requerida** | RoE base | RoE base | RoE base + **addendum de Fase 2** |

### 2.6 Colisión de nomenclatura con el ciclo de 11 fases

Riesgo real de lectura: el ciclo de `ciclo-de-auditoria.md` ya usa «Fase 2» para el **Reconocimiento pasivo**, y este documento usa «Fase 2» para la **Explotación autorizada y limitada**.
Mismo número, cosas distintas.

| Ciclo de 11 fases (`ciclo-de-auditoria.md`) | Escalera de vulnerabilidad (este documento) |
|---|---|
| Fase 1 — Alcance y autorización | Fase 0 — Recon pasivo |
| Fase 2 — Reconocimiento pasivo | Fase 1 — Validación activa controlada |
| Fase 3 — Infraestructura y DNS | **Fase 2 — Explotación autorizada y limitada** |
| Fase 4 — Transporte y TLS | |
| Fase 5 — Análisis de plataforma web | |
| Fase 6 — Divulgación de información | |
| Fase 7 — Postura de email y phishing | |
| Fase 8 — Mapeo a cumplimiento | |
| Fase 9 — Registro de riesgos | |
| Fase 10 — Hoja de ruta | |
| Fase 11 — Reporte | |

> **Regla de escritura, desde ya.** En metodología y en el addendum, la escalera se escribe **«Fase 0 / Fase 1 / Fase 2 de vulnerabilidad»** o **«Fase 2 (explotación limitada)»** con el descriptor entre paréntesis.
> En el informe y en el anexo: **«Fase 0 (recon)», «Fase 1 (validación)», «Fase 2 (explotación)»**.
> El ciclo de 11 fases se cita **«fase 5 del ciclo»**, **«fase 7 del ciclo»**, nunca «fase 5» a secas.
> Sin esta convención, un ticket que dice «la fase 6» es ambiguo, y en una ventana con reloj la ambigüedad se paga cara.

### 2.7 Módulos hermanos

Este documento **no** duplica su contenido; los enlaza:

| Módulo | Qué cubre | Relación con la Fase 2 |
|---|---|---|
| `exposicion-de-secretos.md` | Superficie de credenciales expuestas: dónde se publican, qué tipos, qué significa cada una, qué se puede verificar sin usarse | La Fase 2 añade **el protocolo de verificación de un secreto concreto** (§4 de este documento). El catálogo y la taxonomía de secretos viven en el módulo hermano. |
| `exposicion-a-ataques.md` | Superficie expuesta a terceros: CDN, analítica, endpoints de terceros, formularios que envían datos fuera | La Fase 2 **no los toca**: un tercero se describe, no se ataca (RoE 1.4). El módulo hermano define cómo se reportan. |
| `modelo-de-servicio-y-escalabilidad.md` | Subdominios, superficie de servicio, qué parte del estate es realmente del cliente | Define qué entra en el allowlist de `scope_guard.py` y, por tanto, qué puede ser objetivo de una técnica T1–T6. |

---

## 3. La regla de oro: prueba sin daño

### 3.1 Qué significa «probar sin daño»

Demostrar una vulnerabilidad es producir **una diferencia de comportamiento observable** entre dos peticiones.
El daño no es necesario para esa diferencia: es un subproducto opcional que casi nunca hace falta y que en un sitio con datos clínicos es un incidente.

| Propiedad de una PoC | Qué significa en la práctica | Cómo se verifica en el registro |
|---|---|---|
| **Mínima** | El menor conjunto de peticiones que hace aparecer la diferencia | La columna `peticiones` de la ficha: si son más de las que la técnica declara, hay que justificarlo |
| **No destructiva** | No escribe, no borra, no modifica, no altera el estado observable del sistema | `datos_tocados` = `ninguno` en el CSV |
| **Una sola acción** | Una prueba = un par de peticiones comparables. No se repite para «confirmar» ni para «obtener una segunda muestra» | Una fila por acción en `registro-de-acciones-fase-2.csv` |
| **Sin persistencia** | No queda nada detrás: ni artefacto, ni usuario, ni tarea, ni token de larga vida | `footprint` = `ninguno` o el residual declarado en §8 del anexo |
| **Sin exfiltración** | No se copia, transcribe ni cuenta ningún dato de ninguna persona | `datos_tocados` = `ninguno`; el cuerpo de la respuesta no aparece en la evidencia |
| **Con criterio de abort** | Hay una condición, escrita de antemano, que detiene la prueba sin consultar a nadie | §6.4 de este documento |

### 3.2 El criterio de abort, en una línea

> **Si la respuesta contiene algo que no esperabas, el tamaño de la respuesta no cuadra con lo previsto, o el servicio se mueve, se detiene todo.** No se interpreta, no se «ajusta» el payload, no se repite.
> Se registra y se pregunta.

### 3.3 «No tocar datos reales»: cuatro ejemplos concretos

Este es el punto donde una Fase 2 se convierte en un incidente.
La regla es absoluta y no admite «sólo para ver».

#### 3.3.1 IDOR / BOLA (T1)

**Qué hay que demostrar:** el endpoint `/api/v1/pacientes/{id}` devuelve el registro pedido por identificador sin comprobar la propiedad del objeto.

**Cómo se demuestra sin tocar datos reales:**

1. El cliente crea **dos cuentas de prueba** —`paciente.pruebaA@clinica-ejemplo.mx` y `paciente.pruebaB@clinica-ejemplo.mx`— con **datos sintéticos** hechos por el cliente, no por el auditor. El contrato es explícito: «los registros asociados a estas cuentas no contienen información de pacientes reales».
2. Cada cuenta tiene su propio registro. **El auditor no elige el identificador: lo recibe del cliente.**
3. Dos peticiones al **mismo** identificador (el de A): una con la sesión de A y otra con la sesión de B.
4. Se comparan **tres cosas**: código de respuesta, **claves** del JSON y **longitud** del cuerpo. Nada más.
5. El **contenido del registro no se transcribe, no se guarda y no se cuenta.** La evidencia es: «la cuenta B obtuvo un 200 con las mismas claves y una longitud equivalente sobre un identificador que no es suyo».

| No se hace, aunque el sistema lo permita | Por qué |
|---|---|
| Probar `{id-A+1}`, `{id-A+2}`, … | Eso es enumeración. Y si `{id-A+1}` es un paciente real, la petición **lo ha tocado**. |
| Listar `GET /api/v1/pacientes` para «ver cuántos hay» | Contar pacientes también es tocar datos de pacientes. |
| Modificar o borrar el registro de A | Escritura sobre datos de una cuenta que no es del auditor. Prohibido sin excepción. |
| Probar el mismo vector en `/api/v1/expedientes/{id}` | No está en la lista de técnicas autorizadas. Se reporta como candidato. |
| Usar una cuenta real de un empleado del cliente | «Solo para ver si funciona con datos reales». Prohibido. |

**La variante B (la única escritura):** para demostrar el fallo en la **ruta de escritura** el auditor crea **un** recurso propio —contenido vacío, nombre fijo— **sólo en el entorno de pruebas que el cliente designe por escrito**, y lo elimina al final.
Su borrado y su verificación (404) son **condición de cierre de la fase**, no una buena práctica.

#### 3.3.2 SQLi (T2)

**Qué hay que demostrar:** un parámetro de consulta se concatena en una sentencia SQL y acepta una condición booleana.

1. El parámetro se identifica en Fase 1. El auditor **no lo deduce probando**.
2. **Una pareja de peticiones comparativas:** condición verdadera y condición falsa, del mismo parámetro.
3. Se comparan código, número de resultados y orden. La diferencia consistente es la demostración.

| Prohibido | Por qué |
|---|---|
| `UNION SELECT` | Es el camino corto a extraer filas, y «sólo una fila» es una promesa que la herramienta no cumple. |
| Consultas apiladas (`;`) | Convierte una lectura en una escritura (`; DROP`, `; UPDATE`) o en una extracción masiva. |
| Extraer o contar filas | El objetivo es confirmar la **capacidad**, no cuantificar el volumen. **El volumen lo da el cliente desde sus logs**, con una consulta que el auditor **redacta pero no ejecuta**. |

**Por qué no se usa la técnica de tiempo (time-based):** un `SLEEP` o un `pg_sleep` **consume recursos del servidor de producción**.
En una clínica con un único servidor compartido y una agenda activa, cinco llamadas con retardo artificial son la diferencia entre un servicio estable y una queja.
Está en las prohibiciones absolutas del addendum.
**Consecuencia honesta:** la Fase 2 puede confirmar una inyección booleana, pero **no puede descartar** la existencia de variantes ciegas o basadas en tiempo.
Eso se declara como limitación en §6 del anexo, no se oculta.

**Criterio de parada específico:** si la respuesta difiere en contenido más allá de la longitud esperada —o si aparece algo que no se puede atribuir al parámetro—, la prueba **se detiene ahí** y ese contenido **se descarta**.
No se copia, no se lee, no se resume.

#### 3.3.3 XSS (T3)

**Qué hay que demostrar:** un parámetro se refleja en la respuesta sin codificación en el contexto afectado.

1. El payload es un **marcador de texto único** (por ejemplo `XSS-AUDIT-F2-03`): sin `script`, sin `img`, sin `onerror`, sin beacon, sin ninguna URL, sin acceso a `document.cookie`. **Un texto que no puede hacer nada.**
2. La prueba se ejecuta **exclusivamente contra la cuenta propia del auditor**, que el cliente ha autorizado para escribir en su propio perfil.
3. La evidencia es: la petición con el marcador y la respuesta renderizada con el marcador **visible sin codificar**.

| Prohibido | Por qué |
|---|---|
| XSS **almacenado** | Inyectar el payload en el contenido de otra cuenta es una **escritura sobre datos de un tercero**. Prohibido sin excepción. |
| Probar contra la cuenta de paciente B | Aunque sea una cuenta de prueba, no es la del auditor. La prueba se hace sobre lo propio. |
| Beacon o `document.cookie` | Robar la cookie de sesión propia no es una demostración: es un exfiltrado. |
| Persistir el marcador en el perfil | Si llega a almacenarse, **se borra antes de cerrar** y **se registra** en el log de acciones. |

#### 3.3.4 Bypass de control de acceso administrativo (T4)

**Qué hay que demostrar:** un endpoint administrativo se comporta igual con una cuenta sin privilegios.

1. El cliente aporta una **cuenta admin de prueba** (`admin.prueba@clinica-ejemplo.mx`), creada y entregada por él. No es la cuenta real de nadie.
2. Se hacen **las dos comprobaciones**: con la cuenta admin de prueba y con la cuenta de paciente de prueba.
3. Se compara: código de respuesta, cabecera `Location` y **el rol efectivo de la propia cuenta**.

| Lo que se lee | Lo que NO se lee |
|---|---|
| El código y la cabecera `Location` | El listado de usuarios reales |
| El rol y los permisos **de la cuenta propia** | Cualquier expediente |
| Los metadatos de la cuenta de prueba | El directorio de personal |

> **Por qué hacen falta las dos comprobaciones.** Un control de acceso que sólo comprueba «¿hay sesión?» en lugar de «¿qué rol tiene?» es indistinguible de uno que no comprueba nada.
> Con una sola dirección, el resultado es inconcluyente y no hay hallazgo.

**El caso bueno también se reporta.** Si el endpoint devuelve **403** con la cuenta de paciente y **200** sólo con la admin, el control funciona: eso es una fila **INFO / CERRADO-OK** en la tabla de hallazgos explotados, con la evidencia de los dos 403. **«Lo que ya está bien» es obligatorio**, y un control de acceso que funciona es exactamente lo que hay que documentar.

### 3.4 Tabla de decisión: PoC aceptable / PoC prohibida

| Tipo de hallazgo | PoC **aceptable** (produce el mismo hallazgo) | PoC **prohibida** (produce el mismo hallazgo pero con daño) | Señal de abort |
|---|---|---|---|
| **IDOR / BOLA** | 2 GET con 2 cuentas de prueba; comparar código, claves y longitud | Enumerar identificadores; listar el directorio de pacientes; leer el registro de un paciente | La respuesta trae un dato de paciente → descartar, no conservar, escalar |
| **SQLi** | 1 pareja de peticiones booleanas comparativas | `UNION`, `;`, `time-based`, extracción de filas, conteo de registros | La respuesta trae contenido no atribuible al parámetro → descartar |
| **XSS reflejado** | Marcador de texto en la cuenta propia | Beacon, `onerror`, `document.cookie`, XSS almacenado, payload contra otra cuenta | El marcador queda almacenado → borrar y registrar |
| **Bypass admin** | 2 GET (admin de prueba / paciente de prueba); leer el rol propio | Listar usuarios, enumerar roles, leer expedientes, crear un admin | Cualquier contenido de terceros en la respuesta |
| **Backup expuesto** | 1 GET con `Range: bytes=0-1023` | Descargar el fichero, descomprimirlo, buscar credenciales o hashes dentro | El servidor ignora el `Range` y sirve el fichero completo → abort y declarar |
| **Credencial expuesta** | 1 GET de lectura en el endpoint designado; leer **nombres de campo** | Enumerar, filtrar, paginar, descargar, escribir, iniciar sesión en otro servicio | La respuesta trae registros de pacientes → descartar y escalar |

### 3.5 Cómo se redacta una PoC en el informe

> **Regla de las tres líneas.** Una PoC en el informe cabe en tres líneas: la petición (método, ruta, parámetro, cuenta), el resultado (código, tamaño, claves) y la diferencia observada.
> Si no cabe en tres líneas, es que o estás guardando datos que no deberías, o estás describiendo una acción que fue más allá de una prueba.

Si el equipo del cliente no puede **reproducir los tres pasos con sus propias cuentas**, el hallazgo no está probado y no se publica como probado.
La reproducibilidad por el cliente es el criterio de aceptación de la Fase 2.

---

## 4. Verificación de secretos: probar sin usar

### 4.1 El problema

Un secreto expuesto en el JavaScript del sitio es, por definición, **público**.
Que siga vivo o no cambia el riesgo radicalmente:
«hay una cadena con forma de clave de producción en el código fuente» y «esa clave abre hoy la API de facturación con acceso a 40 cuentas» no son el mismo hallazgo.
El primero se reporta en un informe pasivo.
El segundo se vende.

Y aquí está la trampa: la forma obvia de averiguarlo es **usar la clave**.
Eso es exactamente lo que la RoE 1.3 prohíbe, y por razones que no son de estilo.

> **Por qué no se usa el secreto, aunque el cliente lo autorice:**
> 1. **Un uso no autorizado no es un uso autorizado.** En el momento en que la clave sale del entorno del cliente, el derecho de uso es del titular de la clave, y el titular es el cliente. Autorizar «una prueba» no transfiere la titularidad de la credencial.
> 2. **La validación consume el uso.** Una llamada de lectura deja rastro en el log de acceso del proveedor. Esa entrada no se puede borrar.
> 3. **El hallazgo se endurece con cada uso.** Cuantas más llamadas, más probable es que una de ellas devuelva algo que no debía.
> 4. **Existe una ruta que no usa la clave.** Y es la que se usa aquí.

### 4.2 El protocolo escalonado de cuatro niveles

La verificación de un secreto expuesto es **una escalera**, y se sube **un escalón cada vez**, con una condición de entrada en cada uno.

| Nivel | Pregunta | Cómo se responde | Daño | Requisito |
|:-:|---|---|---|---|
| **1 — Existe** | ¿Hay algo en el repositorio o en el JS que tiene la forma de un secreto de este tipo? | Análisis **local** del material ya descargado, con `secrets_scan.py`. Sin red. | Cero | Ninguno. Es Fase 1. |
| **2 — Plausible** | ¿El valor es **coherente** con el tipo de secreto? (formato, prefijo de proveedor, entropía, contexto de uso) | Reglas del escáner + revisión humana del contexto. **El umbral de entropía es configurable** (`--min-entropy`). | Cero | Ninguno. Es Fase 1. |
| **3 — Vivo** | ¿La credencial sigue siendo aceptada por el sistema que dice aceptarla? | **Una** llamada de lectura, sobre un endpoint **que el cliente designe por escrito**, en la ventana, con el cliente presente. | Mínimo y declarado | Addendum firmado (T6) + "go" + cliente presente |
| **4 — Alcance** | ¿Qué **categoría** de recursos expone? | La **misma** llamada de lectura: se observan los **nombres de campo** de la respuesta. **No** se enumeran, no se filtran, no se descargan, no se transcriben. | Mínimo y declarado | Igual que nivel 3, en la **misma** llamada |

> **Los niveles 3 y 4 son la misma petición.** No se hace una llamada para el nivel 3 y otra para el nivel 4.
> Una sola llamada de lectura responde a las dos preguntas: el código de respuesta dice si la credencial es aceptada, y los nombres de campo de la respuesta dicen qué categoría de recurso expone.
> **El nivel 4 tiene un techo duro:** se responde «qué **categoría**», no «qué hay».
> La diferencia entre «expone recursos de facturación» y «estas son las 40 cuentas con sus correos y sus números de cuenta» es exactamente la línea entre una demostración y una exfiltración.

### 4.3 El nivel 3 en detalle: una única request de lectura

**Condiciones acumulativas (todas):** (1) addendum firmado con **T6 marcada como autorizada** en §7.1;
(2) el cliente ha indicado **por escrito** el endpoint de lectura autorizado y el **proveedor real** de la credencial (no se deduce: se pregunta);
(3) el **"go"** del responsable técnico para esa prueba concreta, por escrito en el canal de ejecución, con hora;
(4) el cliente presente en la llamada;
(5) la ventana abierta;
(6) **una sola llamada**, sin paginación, sin filtros, sin parámetros que amplíen el resultado.

**Request de ejemplo (genérico, con valores enmascarados):**

```http
GET /v1/cuentas HTTP/1.1
Host: api.proveedor-ejemplo.com
Authorization: Bearer sk_live_…a1b2
Accept: application/json
User-Agent: Mozilla/5.0 (compatible; ClientSecurityAudit/2.0; +52-XXX-XXX-XXXX)
```

**Qué se registra y qué no:**

| Se registra | No se registra |
|---|---|
| Código de respuesta | El cuerpo de la respuesta |
| Los **nombres de campo** de la respuesta | Los **valores** de esos campos |
| La **categoría** de recurso expuesto | El número de registros |
| El prefijo enmascarado (`sk_live_…a1b2`) | El valor completo, en ninguna parte |
| El `sha256[:12]` de la credencial | La cookie de sesión o el `Authorization` literal |
| La hora y el footprint (1 entrada en el log del proveedor) | Cualquier dato de la respuesta que no sea un nombre de campo |

**Qué NO se hace después, aunque la respuesta invite a ello:** no se pide la página siguiente; no se pide un recurso concreto; no se filtra para acotar; no se usa la credencial para escribir; no se inicia sesión en ningún servicio del cliente con ella; no se prueba si funciona en otro sitio; no se reutiliza fuera de la ventana.

### 4.4 Enmascaramiento y fingerprint

> **El valor completo de una credencial no consta nunca**: ni en el informe, ni en la evidencia, ni en el registro de acciones, ni en el chat de ejecución, ni en un mensaje al cliente, ni en una nota de Debian.

| Elemento | Formato | Ejemplo |
|---|---|---|
| Credencial expuesta | prefijo + `…` + sufijo | `sk_live_…a1b2` |
| Fingerprint de correlación | `sha256` del valor, **primeros 12 hex** | `sha256[:12] = 9f2b7c41a0de` |
| Token / cookie de sesión | `xxxx…yy` | `xxxx…yy` |
| Identificador de persona | marcador estable | `PACIENTE-PRUEBA-A` |

**Por qué el fingerprint y no sólo el enmascaramiento:** con el prefijo y el sufijo, dos hallazgos que apuntan al mismo secreto son reconocibles a simple vista; pero **el cliente necesita** una forma de confirmar que «la credencial que usted rotó» es «la credencial que nosotros encontramos», y ese papel lo juega el `sha256[:12]`.
Es la misma cifra que ya emite `secrets_scan.py` por defecto, con lo que la correlación entre el escaneo de Fase 1 y la validación de Fase 2 es **directa y verificable**.

**Por qué no se registra el valor completo «por si acaso»:** porque el informe técnico se archiva, se comparte con el hosting, a veces se pega en un ticket y a veces termina en un correo.
Un valor completo en ese recorrido es un valor completo filtrado.
El enmascaramiento no es una cortesía: es el control.

> **NO VERIFICADO — requiere comprobación contra fuente primaria.** Que un par «prefijo/sufijo enmascarado + `sha256[:12]`» sea **suficiente para que el cliente identifique y rote esa credencial concreta** ante su proveedor depende del proceso de soporte de cada proveedor (algunos piden el ID de la clave, otros el prefijo, otros el hash de la clave).
> **Antes de entregar el anexo hay que confirmar con el cliente que ese par le basta.** Si no basta, el valor completo se entrega además por un canal seguro y separado, nunca dentro del informe ni del anexo.

### 4.5 La rotación la hace el cliente

La credencial expuesta **sigue viva después de la Fase 2**.
El auditor no la rota: no tiene por qué, y rotarla por su cuenta sería una escritura fuera de alcance.

| Quién | Qué hace | Cuándo |
|---|---|---|
| **El cliente** | Rota la credencial expuesta, revoca la anterior y emite una nueva con alcance limitado al origen que la usa | **Antes de que el anexo se entregue.** Es la acción de remediación de mayor prioridad del anexo (H-04 en la plantilla). |
| **El cliente** | Elimina el secreto del código y del repositorio, y rota **todas** las credenciales que compartían el mismo origen | Antes del cierre |
| **El auditor** | Declara en el anexo que la credencial **no ha sido rotada** al momento del cierre, y que sigue expuesta | En §8 del anexo, en la tabla de residuos |
| **El auditor** | No reutiliza la credencial en ningún momento posterior, ni la registra en otro sistema, ni la incluye en material comercial o de formación | Deuda permanente del encargo |

> **Una credencial expuesta que se valida y no se rota es un hallazgo que empeora con el tiempo.** La evidencia de Fase 2 deja de ser «había una cadena» y pasa a ser «esta cadena funcionaba el día de la validación».
> Por eso el anexo marca la rotación con fecha objetivo **anterior a la entrega**.

### 4.6 Decisión por tipo de secreto

| Tipo de secreto | ¿Se valida contra el sistema? | Vía de validación | Nota |
|---|---|---|---|
| **Clave de API de un proveedor** (pagos, mapas, analítica, mensajería) | Sí, en nivel 3/4, si T6 está autorizada | Una GET de lectura sobre el endpoint que el cliente designe | Es el caso canónico de T6 |
| **Token de acceso a un bucket / almacenamiento** | No, salvo que el cliente designe por escrito un endpoint de lectura | — | Puede listar datos de pacientes. La validación en producción es demasiado peligrosa |
| **Credencial de base de datos** | **No. Nunca.** | — | Conectar a la BD del cliente es un movimiento lateral (§3.6 del addendum) y requiere una autorización distinta |
| **Secreto de firma de cookie / sesión** | No, por el método de T6 | — | Fabricar una cookie firmada es una **escritura implícita** en el sistema de sesiones. Se reporta como capacidad; no se fabrica |
| **JWT expuesto** | Solo **análisis local** (offline) | Decodificar la carga útil **sin verificar la firma** | Verificar la firma es una operación criptográfica **offline**, no de red. Es el único caso de «prueba» de un token que no toca el sistema |
| **Contraseña en texto plano** | **No. Nunca.** | — | Probar una contraseña es autenticación. Prohibido por 1.3 y por el §3 del addendum |
| **Hash de contraseña** | **No. Nunca. Ni offline.** | — | Romper hashes está prohibido sin excepción (§3.7 del addendum) |
| **Credencial de un tercero (no del cliente)** | No | — | Se describe la relación, no se ataca. RoE 1.4 |
| **Secretos de terceros incrustados en el sitio del cliente** (p. ej. la clave de un servicio de mapas) | Solo con autorización escrita del cliente **y** del tercero | — | Es el §3.11 del addendum: los terceros no se contactan |

> **Detalle técnico sobre JWT que conviene tener claro:** un JWT tiene tres partes separadas por puntos.
> Decodificar la carga útil (`base64url`) es **operación local y sin red**.
> **Verificar la firma** de un JWT firmado con HMAC requiere la **clave**; con RSA/ECDSA requiere la clave pública, que es pública — y entonces el punto cambia por completo: **la firma no se puede verificar sin la clave, y el token no se puede usar para verificar la clave**.
> Es un problema de asimetría posterior.
> Lo que sí se puede afirmar, y es verificable en local, es: **¿qué campos contiene la carga útil, qué permisos declara y qué antigüedad tiene?** Eso es un hallazgo de Fase 1 (`secrets_scan.py` y `js_intel.py` lo detectan).
> Si además el `exp` está vencido, el token **no sirve** — y eso se demuestra sin tocar el sistema.
> **NO VERIFICADO — requiere comprobación contra fuente primaria** si el algoritmo concreto del token (HS* frente a RS*/ES*) permite esa conclusión sin tener la clave: hay que leer el encabezado `alg` del propio token y contrastarlo con la especificación vigente del JWT (RFC 7519 y la RFC correspondiente de JWS) antes de afirmarlo.

### 4.7 Remisión

El **catálogo** de secretos (qué tipos existen, dónde se publican, qué implican, cómo se reportan en Fase 1) está en **`exposicion-de-secretos.md`**.
Este documento no lo duplica.
Aquí sólo se fija el **protocolo de validación de Fase 2**, que es el único punto donde un secreto se prueba contra un sistema.

---

## 5. Matriz de destructividad

### 5.1 La matriz

La matriz es la herramienta de decisión central.
Antes de cada prueba, la fila correspondiente dice cuál es el impacto máximo tolerado, qué hay que cumplir, qué evidencia mínima hay que dejar, quién tiene que estar presente, qué huella se permite y cómo se revierte.

| Tipo de prueba | Impacto máximo permitido | Condiciones | Evidencia mínima | Quién debe estar presente | Footprint | Rollback |
|---|---|---|---|---|---|---|
| **Lectura con cuenta de prueba propia** (T3) | Ninguno | ≥1 s; payload inocuo; sólo cuenta propia | Petición con marcador + respuesta con marcador sin codificar | Responsable técnico (o en línea) | Ninguno | Si el marcador queda almacenado: borrado + registro |
| **Lectura con dos cuentas de prueba** (T1-A) | Ninguno | ≥1 s; cuentas sintéticas del cliente; un solo par de identificadores | Código, claves JSON y longitudes comparados; par de identificadores usado | Responsable técnico + quien observa el panel | Ninguno | No aplica |
| **Escritura única en entorno de pruebas** (T1-B) | **1 registro** | Entorno designado **por escrito**; cuenta del auditor; contenido vacío; nombre fijo | Artefacto creado + petición + confirmación de borrado | Responsable técnico | 1 registro + 1 entrada en log de actividad + 1 entrada en log del servidor | **Borrado por el auditor + verificación (404)** antes de cerrar |
| **Comparación booleana SQL** (T2) | Ninguno | ≥1 s; una sola pareja; sin `UNION`, sin `;`, sin extracción | Código y longitud de las dos respuestas | Responsable técnico | Entrada en log del servidor (no limpiable) | No aplica |
| **Comprobación de rol** (T4) | Ninguno | ≥1 s; dos cuentas; sólo metadatos propios | Código y `Location` de las dos respuestas; rol efectivo de cada cuenta | Responsable técnico | Entrada en log del servidor | No aplica |
| **Lectura parcial de fichero expuesto** (T5) | Ninguno | Una sola petición; `Range: bytes=0-1023`; no descomprimir; no leer credenciales dentro | Código, `Content-Type`, `Content-Length`, primeros 1024 bytes (enmascarados) | Responsable técnico | Entrada en log del servidor; **el fichero no se elimina** (decisión del cliente) | No aplica — la eliminación del fichero es remediación del cliente (H-05) |
| **Validación de credencial** (T6) | Mínimo y declarado | Addendum firmado; endpoint designado **por escrito**; una sola llamada de lectura; cliente presente | Código, **nombres de campo**, prefijo enmascarado, `sha256[:12]` | Responsable técnico + contacto de emergencia disponible | 1 entrada en el log de acceso del proveedor; **la credencial sigue viva** | **Rotación por el cliente** antes de la entrega (H-04) |
| **Enumeración de identificadores** | — | — | — | — | — | **PROHIBIDA** |
| **Extracción de filas de datos** | — | — | — | — | — | **PROHIBIDA** |
| **Prueba de carga / disponibilidad** | — | — | — | — | — | **PROHIBIDA** |

### 5.2 Las prohibiciones absolutas de Fase 2

Estas no se levantan.
No hay excepción por urgencia, ni por autorización del dueño, ni por tamaño del cliente.
Si una técnica las requiere, **la técnica no se hace y se reporta como no verificada**.

| # | Prohibición | Por qué no se levanta, nunca |
|:-:|---|---|
| 1 | **Denegación de servicio, estrés y carga** | Nada de pruebas de disponibilidad, ancho de banda, concurrencia, `time-based` para medir capacidad, inundación de endpoints ni repetición para «medir el límite». Ninguna herramienta de carga se ejecuta contra el objetivo. | Un fallo de disponibilidad en una clínica es un daño al paciente: citas perdidas, triaje detenido. |
| 2 | **Escritura, modificación o borrado de datos de producción** | La única escritura autorizada es el artefacto único de T1-B, en el entorno de pruebas designado, con limpieza obligatoria. | Un dato clínico modificado o borrado no se «restaura»: la historia clínica es un registro legal. |
| 3 | **Acceso a cuentas de terceros** | Sólo las cuentas de prueba entregadas por el cliente y la cuenta propia del auditor. Ninguna cuenta real de personal, pacientes, proveedores o terceros, **ni siquiera para confirmar que existe**. | «Sólo compruebo que existe» ya es un acceso. |
| 4 | **Extracción de datos personales o clínicos** | No se descarga, copia, transcribe, resume, cuenta ni almacena ningún dato de paciente, registro clínico, expediente, archivo o historial. **Contar cuántos hay también está prohibido.** | Contar ya es una extracción comprimida. Y el conteo es la operación que más veces se filtra en informes ajenos. |
| 5 | **Persistencia** | Sin webshells, sin shells inversas, sin backdoors, sin tareas programadas, sin claves SSH, sin usuarios creados, sin tokens de larga vida, sin ficheros subidos fuera del artefacto de T1-B. Si una técnica deja algo detrás, se limpia y se reporta; si no se puede limpiar, se reporta como residual y **no se repite**. | La persistencia es la línea entre una auditoría y una intrusión. |
| 6 | **Movimiento lateral fuera del alcance** | No se explora la red interna, no se escanean puertos, no se testean otros hosts del cliente que no estén en el RoE base, no se toca la infraestructura de terceros (hosting, agencia, SaaS, APIs de terceros). | Tu autorización es del cliente, no de sus vecinos — y en un hosting compartido, «el vecino» son veinte consultas más que no te autorizaron. |
| 7 | **Cracking de hashes** | No se rompen hashes, no se comparan contra diccionarios, no se prueban candidatos offline ni online, no se ejecutan listas de contraseñas. | El cracking de un hash de un backup de producción es una extracción de credenciales con pasos extra. |
| 8 | **Bypass de MFA** | No se intenta superar un segundo factor por ninguna vía, no se capturan ni interceptan códigos de un factor, no se modifica la configuración de MFA del cliente. | El MFA es el control que protege al paciente de la credencial filtrada. Saltárselo para «probar» elimina la única protección que queda. |
| 9 | **Ingeniería social al personal** | No se llama, no se escribe, no se visita, no se pide ayuda a un empleado del cliente con pretextos, no se suplanta a un proveedor. | El único contacto con el cliente es el autorizado en §4 del addendum. |
| 10 | **Uso del secreto encontrado más allá de la validación de lectura autorizada** | Una vez, en modo lectura, sobre el endpoint que el cliente indique por escrito. No para escribir, no para acceder a más recursos, no para iniciar sesión en ningún servicio del cliente, no para probar si funciona en otro sitio, no fuera de la ventana. | El valor de un hallazgo de credencial es la prueba. Reutilizar la credencial convierte la prueba en un incidente. |
| 11 | **Comunicación a terceros** | No se contacta al proveedor de la credencial, ni al hosting, ni a la agencia web, ni a ningún otro tercero sin autorización escrita previa del cliente. Los terceros se describen, no se contactan. | La confidencialidad sobrevive al encargo. |

### 5.3 Tabla de decisión rápida: «¿puedo hacer esto?»

| Situación en la ventana | Respuesta |
|---|---|
| El "go" cubría una técnica y estoy a punto de ejecutar otra | **No.** El "go" es específico de una prueba. Pide el "go" nuevo. |
| El "go" es para T1 y el endpoint que veo ahora es `/expedientes/{id}` | **No.** Sólo está autorizado el endpoint del addendum. Se anota como candidato. |
| El responsable técnico no contesta en 10 minutos | **No.** El silencio no es un "go". Se anota *no ejecutada — sin go*. |
| La primera pareja de peticiones SQLi difiere y quiero una tercera para «confirmar» | **No.** Una acción por prueba. Lo que se observe es el hallazgo. |
| El endpoint devuelve un 500 y no sé por qué | **No** se reintenta. Se anota el efecto no previsto y se para (§6.4). |
| Vi un dato de paciente en la respuesta | **Abort.** Se descarta sin conservar, se registra y se escala (§7.3). |
| El sistema pide iniciar sesión y tengo credenciales de la cuenta de prueba | Sólo con las cuentas entregadas por el cliente, y **no** con una credencial encontrada en el código (prohibición 10). |
| El cliente pide «ya que estás ahí, prueba también…» | Se responde: lo que no está en el addendum firmado no se prueba en esta ventana. Se anota como candidato a una ventana posterior. |

---

## 6. Ventana, observabilidad y rollback

### 6.1 La ventana

| Concepto | Regla |
|---|---|
| **Horario** | Sólo dentro de las ventanas declaradas en §4 del addendum. **Las peticiones de Fase 2 no se hacen fuera de la ventana**, aunque el RoE base siga vigente. |
| **Zona horaria** | Se declara explícitamente (ej. `America/Mexico_City`, UTC−6). El registro de acciones usa timestamp con offset: `2026-11-25T20:06:12-06:00`. |
| **Presencia del cliente** | El **responsable técnico** está **en la llamada** durante toda la ventana. Es quien da el "go" y quien puede parar la fase con un mensaje. |
| **Contacto de emergencia** | Del auditor y del cliente, con teléfono, probados antes de empezar. |
| **Canal de ejecución** | Chat + llamada de voz, **exclusivos** de la ventana. El "go" se pide y se confirma **por escrito** en el chat, con hora. **El correo no se usa para dar el "go".** |
| **Ritmo** | ≥1 s entre peticiones. Sin concurrencia. **Sin reintentos automáticos.** |
| **User-Agent** | Honesto y contactable: `Mozilla/5.0 (compatible; ClientSecurityAudit/2.0; +52-XXX-XXX-XXXX)`. Nunca se suplanta un navegador. |
| **Días no laborables** | La ventana no se usa en domingo ni en el periodo vacacional que el cliente declare, salvo acuerdo explícito. |

> **La ventana no es una cortesía, es un mecanismo de control.** Fuera de la ventana, el `scope_guard.py` **rechaza la petición**: su lógica comprueba `valid_from` / `valid_to` del fichero de autorización antes de tocar la red.
> La ventana está impuesta por la herramienta, no por la disciplina del auditor.
> Cuando el reloj pasa de la hora de fin, la herramienta deja de funcionar.
> Eso es intencional.

### 6.2 El registro de acciones

**Formato de captura:** `05-plantillas-de-trabajo/registro-de-acciones-fase-2.csv`.

**Columnas** (id, fecha_hora, host, endpoint, tecnica, metodo_http, cuenta_usada, tipo_cuenta, datos_tocados, resultado, evidencia_archivo, footprint, rollback_hecho, severidad, estado, notas).

**Reglas de llenado durante la ventana:**

| Regla | Detalle |
|---|---|
| **Una fila por acción de prueba** | No una fila por técnica: una fila por **petición comparativa** agrupada, de modo que la fila contenga el par. |
| **La hora es del envío real**, con offset, no la hora en que se anotó. | `2026-11-25T20:06:12-06:00` |
| **`datos_tocados`** | `ninguno` en todo caso salvo que se diga otra cosa. Si aparece otra cosa, es que hubo un incidente: se añade una fila de incidente. |
| **`footprint`** | Qué queda detrás. `none` no es lo mismo que `no aplica`: `none` significa «nada quedó»; `no aplica` significa «lo que queda no es del auditor». La distinción importa en §8 del anexo. |
| **`rollback_hecho`** | Qué se retiró y cuándo, con la hora. Si no se retiró nada, `no aplica` con el motivo. |
| **`resultado`** | `CONFIRMADO` / `REFUTADO` / `NO EJECUTADO` / `NO REPRODUCIBLE`. **Un refutado se registra igual que un confirmado.** Un directorio donde todo salió bien a la primera es sospechoso. |
| **`notas`** | El detalle que hace falta para reproducir. Es la columna más importante y la que más se descuida. |
| **El "go" va en `notas`** | Con hora y con quién se confirmó. |

> **El registro de acciones no es un archivo interno del auditor: es entregable.** §5.4 del addendum lo pone en la lista de lo que recibe el cliente, junto con el anexo y la declaración de limpieza.
> Se entrega **completo**, incluidas las técnicas refutadas y las no ejecutadas.
> Un registro sin las refutaciones no es un registro: es un éxito comercial.

### 6.3 Qué es un footprint y cómo se limpia

**Definición operativa:** el **footprint** es todo estado observable que la Fase 2 deja en un sistema y que no estaba antes.

| Tipo de footprint | Ejemplo | ¿Quién lo limpia? | ¿Es limpiable? |
|---|---|---|---|
| **Objeto creado por el auditor** | El artefacto único de T1-B | El auditor | **Sí, y es condición de cierre.** Se borra y se verifica (404 en lectura de comprobación) |
| **Registro de actividad de una cuenta** | La entrada que genera la creación del artefacto | El auditor, si la cuenta es suya | Sólo si el cliente lo habilita; si no, se declara como residual |
| **Entrada en el log del servidor web** | Una línea de acceso por cada petición | **Nadie** | **No.** El auditor no controla ese log y no tiene acceso de escritura. Se **declara** |
| **Entrada en el log de acceso del proveedor** | La llamada de T6 | El proveedor | **No.** Se declara |
| **Secreto que el auditor no creó** | La credencial expuesta; el fichero de backup | El cliente | No aplica: es remediación (H-04, H-05), no limpieza |
| **Cambio de estado en una cola** | Una reserva, un correo, una notificación | Nadie (ocurre en el sistema del cliente) | **No.** Se declara como efecto no previsto y activa el criterio de abort |

**Protocolo de limpieza de lo que sí es limpiable:**

1. **Eliminar** el artefacto con la misma cuenta que lo creó.
2. **Verificar** la eliminación con una lectura de comprobación (`GET` → 404).
3. **Registrar** en el log de acciones: qué se eliminó, cuándo y cómo se verificó.
4. **Declarar** en §8 del anexo: qué se eliminó, qué queda y por qué no se puede eliminar.

> **Un residuo no declarado es el peor resultado posible de una Fase 2.** Un residuo **declarado** es un resultado aceptable: el sistema del cliente registra actividad, y eso es normal.
> Lo inaceptable es que el auditor deje algo detrás y no lo diga, o que lo diga a medias.

### 6.4 Criterios de abort inmediato

La ejecución se detiene **de inmediato, sin esperar confirmación**, en cuanto ocurra cualquiera de estos hechos:

| # | Criterio | Qué se hace en el acto |
|:-:|---|---|
| **1** | **Aparece un dato de paciente o de un tercero en una respuesta.** Cualquier identificador clínico, nombre, expediente, teléfono, correo o registro de una persona que no sea una cuenta de prueba | La respuesta **se descarta**, no se guarda, no se transcribe. Se anota el incidente en el log de acciones y se avisa al responsable técnico en el canal de ejecución |
| **2** | **Se produce un efecto no previsto y real.** Un registro creado, un correo enviado, un SMS, una notificación, una reserva, un cambio de estado, un error 500 reproducible, una entrada en cola de trabajo | La prueba se detiene y se revisa con el cliente antes de continuar |
| **3** | **Aparece cualquier señal de degradación o de alarma.** Latencia anormal, errores del servicio, alerta del hosting, del panel del cliente o de cualquier monitor | **Se detiene todo**, se entrega el registro de acciones hasta ese momento y se espera la decisión del cliente |

**Criterio adicional del auditor (no espera a nadie):** el auditor puede parar cualquier prueba por iniciativa propia en cuanto dude.
La duda **no** se resuelve probando.

> **Un criterio de abort que no se ha ensayado no existe.** En la Fase 0 y en la Fase 1 abortar es una decisión interna.
> En la Fase 2 abortar significa que hay que interrumpir una sesión con un cliente en la línea, y eso hay que saber hacerlo **antes** de que ocurra.
> Practica el guion con un colega: qué decir, a quién avisar primero, y qué se entrega si se corta la sesión.

### 6.5 Rollback

El rollback es **la última fila del plan**, no un afterthought.

| Elemento | Regla |
|---|---|
| **Orden** | Primero se limpia lo que el auditor creó, **antes** de redactar el informe. La declaración de limpieza se firma con la huella ya verificada, no con la intención de limpiarla. |
| **Verificación** | Cada retirada se **verifica** con una lectura de comprobación. «Ya lo borré» no es evidencia; un 404 sí. |
| **Cierre de fase** | La fase **no se cierra** con residuo propio sin limpiar. Si un residuo no se puede limpiar (log de un tercero, entrada en una cola), se **declara** y se justifica. |
| **Reversión de cambios del cliente** | Si la Fase 2 motive un cambio de configuración en el cliente (por ejemplo, activar un registro adicional), ese cambio también entra en la tabla de residuos, con su responsable y su estado. |
| **Fuera de la ventana** | Si la limpieza cae fuera de la ventana, **no se queda pendiente**: se acuerda con el cliente una acción de limpieza con plazo, y se anota como compromiso con fecha. La limpieza del artefacto de T1-B es la excepción: se hace dentro de la ventana, siempre. |

### 6.6 Observabilidad del cliente

El cliente **observa** durante la ventana.
Esto no es un detalle: es el mecanismo que convierte la Fase 2 de «algo que le hice al cliente» en «algo que hicimos juntos».

| Observador | Qué observa | Para qué |
|---|---|---|
| **Responsable técnico** | El panel, los logs del servidor, la cola de mensajes | Detectar de inmediato un efecto no previsto |
| **Coordinación de citas** | Su propio panel de citas, en línea y a demanda | Confirmar que **no** hay citas fantasma ni correos a pacientes |

> **El abort por efecto no previsto sólo funciona si alguien mira.** Un cliente que se desconecta durante la fase pierde el control de la ventana.
> Si la conexión se cae, **se para la ejecución** hasta que vuelva: seguir sin observador es exactamente el escenario en el que se dispara un correo a un paciente.

---

## 7. Manejo de datos en Fase 2

### 7.1 Minimización: qué se guarda, qué se redacta

| Categoría | Qué se guarda | Qué se redacta o no se guarda |
|---|---|---|
| **Peticiones y respuestas** | Código de estado, tamaño, claves del JSON, cabeceras relevantes (`Content-Type`, `Location`; `Set-Cookie` **no**) | El cuerpo completo de respuestas que contengan datos de cualquier persona |
| **Secretos** | Prefijo y sufijo (`sk_live_…a1b2`) + `sha256[:12]` | **Nunca** el valor completo, ni en capturas, ni en logs, ni en notas |
| **Cookies y tokens** | Que existían o no (booleano) | El valor de la cookie de sesión, del `Authorization`, del JWT |
| **Identificadores de personas** | Que el identificador existe y a qué cuenta de prueba pertenece | El nombre, el teléfono, el correo y cualquier dato clínico |
| **Capturas de pantalla** | Recorte a la zona relevante | Capturas de pantalla completa con datos de pacientes visibles, archivos de historial, listados de usuarios |
| **Cuentas de prueba** | El identificador estable (`PACIENTE-PRUEBA-A`) y el rol | El correo real de la cuenta, si no es necesario — el alias estable basta para el informe |

### 7.2 Por qué tocar un registro real **es** la brecha

Esta es la idea central de la Fase 2 en un sitio con datos de pacientes, y conviene enunciarla con precisión.

> **Tocar un registro real no es «un dato más en la evidencia». Es el incidente que el informe describe.**

La razón es de tres capas:

**Capa 1 — El daño al paciente.** Un expediente que se abre, se copia o se cuenta es un dato clínico que sale del control del responsable.
Con las obligaciones de datos sensibles en México, ese hecho no lo arregla el informe: lo agrava.
El dato ya no está sólo en el servidor del responsable: está en el escritorio del auditor, en su disco, en una copia de seguridad, en un servicio de mensajería.

**Capa 2 — El daño al cliente.** El hallazgo que se entrega dice «con una cuenta autenticada, un atacante puede leer los historiales de pacientes».
Si el auditor ya leyó un historial para demostrarlo, el cliente tiene ahora **dos** problemas: la vulnerabilidad y un manejo de datos fuera de política por parte de quien lo audita.
La segunda resta más confianza que la primera.

**Capa 3 — El daño a la metodología.** Un informe de Fase 2 que dice «no tocamos datos reales» y cuyo anexo lo demuestra es un informe que **se puede entregar al equipo técnico sin miedo**.
Uno que dice «tocamos un registro para confirmar» es un informe que el director de un hospital **no va a poder circular**, porque contiene la prueba de que un tercero ajeno a la relación médico-paciente accedió a un registro clínico.
En un cliente de salud, eso no es un detalle de confianza: es una razón para no contratar.

> **La regla operativa que sale de las tres capas:** *la demostración se hace con datos que el propio cliente fabrique para el efecto*.
> No porque sea más cómodo.
> Porque es la única forma de que el resultado del informe sea utilizable.

### 7.3 Escalación ante exposición real de PII ajena

**Qué es «exposición real de PII ajena»:** datos de pacientes o de personas que no son cuentas de prueba, y que un atacante podría leer a través del fallo demostrado.
Ejemplos: un endpoint que devuelve historiales reales a cualquier sesión; un backup público con la base de datos completa; una credencial expuesta que da acceso a un almacén con expedientes.

**Qué se hace, en este orden:**

| # | Acción | Plazo | Quién |
|:-:|---|---|---|
| 1 | **Escalada inmediata** por el contacto de emergencia del cliente, en el momento en que se detecta, **antes de continuar cualquier prueba** | Inmediato | Auditor → contacto de emergencia |
| 2 | **Notificación por escrito** al responsable técnico del cliente, con el **mínimo detalle técnico necesario**: hora, endpoint, categoría de dato. No con capturas, no con valores | **≤ 1 hora** | Auditor → responsable técnico |
| 3 | **Documentación** en el log de acciones: hora, endpoint, tipo de dato, qué se hizo con la respuesta (descartada) | En el momento | Auditor |
| 4 | **Cierre de la fase** en lo que reste, salvo que el cliente decida continuar | — | Cliente decide |

**Qué NO hace el auditor, en ningún caso:**

- No difunde la exposición (ni en redes, ni en foros, ni en grupos, ni en una presentación).
- No la publica, ni siquiera como ejemplo anónimo.
- No la usa para acceder a más datos.
- No la usa como palanca comercial ni como argumento de venta.
- No contacta a los afectados.
- No contacta a la autoridad por su cuenta.
- No abandona el encargo sin avisar al cliente.

> **La decisión sobre la notificación a los titulares y a la autoridad la toma el cliente, con su asesoría legal.** El auditor entrega la información mínima necesaria para que esa decisión se pueda tomar a tiempo.
> Esa es la frontera entre el deber de informar y la asunción de una responsabilidad que no le corresponde.
> **NO VERIFICADO — requiere comprobación contra fuente primaria.** Si el auditor llega a conocer, por su propia actividad, una exposición real de datos personales sensibles ajenos, la pregunta «¿qué obligaciones tiene el auditor, y cuáles el cliente, y cuáles el responsable de la relación médico-paciente?» **no se responde desde este playbook**.
> Hay que leer la LFPDPPP vigente (incluidas sus reformas) en el texto oficial, contrastar el régimen de obligaciones de los **encargados** y **terceros** — que es la posición del auditor —, y **validarlo con asesoría legal del cliente antes de la ventana**.
> No se cita ninguna ley de memoria.
> Lo que este playbook fija es el **comportamiento operativo**: escalar, documentar, no difundir y no abandonar el encargo.

### 7.4 Retención y destrucción

| Concepto | Regla |
|---|---|
| **Retención de la evidencia de Fase 2** | **30 días naturales** contados desde la entrega del anexo |
| **Destrucción** | Al cumplirse el plazo, la evidencia se destruye o se anonimiza de forma verificable, y **se confirma por escrito al cliente** |
| **Excepciones** | Sólo se conserva, con el mismo plazo, lo que el cliente pida expresamente conservar para su propio expediente (p. ej. la copia enmascarada de la credencial expuesta) |
| **Los originales con valores completos** | **No se entregan.** Se archivan con el auditor hasta el final del plazo |
| **El anexo y el registro de acciones** | Se entregan al cliente y los conserva él: son documentos del cliente, no del auditor |

> **Este plazo es un compromiso contractual del auditor, no un requisito legal.** Si el cliente pide un plazo distinto, se pacta por escrito en el addendum.
> Lo que **no** es negociable es que exista un plazo, que se cumpla, y que se confirme por escrito: una evidencia de Fase 2 sin fecha de destrucción es un archivo de datos de pacientes que nadie va a borrar nunca.
> **NO VERIFICADO — requiere comprobación contra fuente primaria.** Si la evidencia de Fase 2 contiene datos personales sensibles **de forma accidental** —un cuerpo de respuesta que se guardó sin pasar por el redactor—, la obligación de conservación y de comunicación de esa evidencia **no está determinada en este playbook**.
> Hay que revisarlo con la asesoría legal del cliente **antes** de que ocurra, no después.

### 7.5 Qué recibe el cliente al final

| # | Documento | Contenido | Enmascarado |
|:-:|---|---|---|
| 1 | **Anexo — Explotación limitada** (`02-plantillas/informe-completo/anexo-explotacion-limitada.md`) | Hallazgos explotados, fichas con «Lo que NO se hizo», datos reales expuestos, remediación, re-test, declaración de limpieza, índice de evidencia | Sí |
| 2 | **Registro de acciones de Fase 2** completo | Las seis técnicas autorizadas, incluidas las refutadas y las no ejecutadas | Sí |
| 3 | **Declaración de limpieza firmada** | Detalle de la huella dejada y de quién la retiró | Sí |
| 4 | **Valores enmascarados** | Credencial expuesta, tokens, cookies, identificadores sensibles | **Siempre** |
| 5 | **Consulta de cuantificación redactada pero no ejecutada** | Para que el cliente mida el volumen expuesto desde su servidor | N/A |

**Canal de entrega:** el anexo y el registro van al **equipo técnico** del cliente, a su hosting y a su agencia.
**No** van al dueño final, no van a terceros, no van a un ticket abierto.
El material que contiene valores completos, si el cliente lo pide, va por un **canal seguro y separado**, con confirmación de recepción, y **no** dentro del informe ni del anexo.

### 7.6 El redactor obligatorio: `pii_redact.py`

**Ninguna evidencia se comparte sin pasar por el redactor.** Es el paso 7 del flujo de `01-tooling/scripts/README.md`, y en Fase 2 es **obligatorio**, no recomendado.

```bash
python3 pii_redact.py evidencia-cruda/ \
    --out-dir evidencia-sanitizada \
    --report evidencia/redaccion.json
```

**Qué hace y qué garantiza:**

| propiedad | Detalle |
|---|---|
| **Redacta** | Emails, teléfonos (MX/ES/US), RFC/NIF/DNI/NIE/CUIT, IPs (con `--keep-ips` para no tocarlas), tarjetas **validadas con Luhn**, fechas de nacimiento, códigos postales, URLs con credenciales |
| **Redacta claves de dato clínico** | `nombre`, `apellido`, `nombre_paciente`, `telefono`, `email`, `direccion`, `diagnostico`, `expediente`, `fecha_nacimiento`, `curp`, `rfc`, `nss`, `paciente`, `patient`, `dob`, `ssn`, `address`, `phone` |
| **Preserva el formato** | Un JSON redactado sigue siendo JSON válido y parseable; el HTML sigue siendo HTML. El informe sólo contiene **conteos por categoría**, nunca valores |
| **Se completa** | `--extra-key` para claves propias del cliente que el redactor no conoce |

**Complemento obligatorio:** `secrets_scan.py` sobre la evidencia de Fase 2, para volver a enmascarar cualquier secreto que haya quedado en un cuerpo o en una captura:

```bash
python3 secrets_scan.py ./evidencia-sanitizada \
    --json --out evidencia/secrets_fase2.json
```

**Limitaciones que hay que conocer (del README del propio script):**

- **Sin NER.** `pii_redact.py` no detecta nombres de personas en texto libre. Los nombres sólo se redactan cuando van en una clave JSON con nombre típico o cuando el patrón es inequívoco (RFC, CURP, email, teléfono, tarjeta). **Un nombre de paciente escrito en prosa dentro de una nota se escapa.**
- **Teléfonos sin separadores.** Un número en formato E.164 sin guiones (`5215555555555`) es indistinguible de otro identificador: no se redacta en texto libre.
- **Sobre-redacción preferible.** Se prefiere redactar de más: el coste de un dato de más es menor que el de un dato de paciente en la evidencia.

> **Por qué la limitación de NER importa en Fase 2 y no en Fase 1:** en Fase 1 las respuestas son HTML público y no contienen nombres de pacientes.
> En Fase 2 las respuestas **sí** pueden contenerlos, y por eso la revisión del redactor **no es automática**: hay que **leer** el informe de redaction (`redaccion.json`, que da conteos por categoría) y **mirar** cada evidencia saneada antes de entregarla.
> Un `pii_redact.py` ejecutado no es una garantía: es una ayuda.
> La garantía es la lectura.

---

## 8. Procedimiento operativo paso a paso

Quince pasos.
Cada uno con **entrada**, **acción**, **salida**, **artefacto de evidencia** y **condición de parada**.

Los comandos son de la toolchain propia, en `01-tooling/scripts/`.
Todos los paths son relativos a la raíz del caso: `03-casos/<cliente>/`.

---

### Paso 1 — Verificar la cadena de autorización

| Entrada | RoE base firmado; addendum de Fase 2 firmado; `05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md` como plantilla |
|---|---|
| **Acción** | Comprobar que existen: (a) el RoE base, firmado y vigente; (b) el addendum, firmado **por las tres partes** (cliente, responsable técnico, auditor); (c) la tabla §7.1 del addendum con las técnicas **marcadas** como autorizadas o rechazadas; (d) las técnicas rechazadas quedan **excluidas**, no «pendientes» |
| **Salida** | Confirmación de que hay ventana, de qué técnicas y de qué firman |
| **Artefacto** | `evidencia/fase2/addendum-fase2-firmado.md` (copia del firmado), `evidencia/fase2/arranque-checklist.md` |
| **Parada** | Si falta una firma, si el RoE está vencido, o si una técnica no está marcada: **no hay ventana**. No se empieza. |

> **Un addendum sin las tres firmas no es un addendum.** La firma del auditor acepta el alcance y se compromete a §3, §5 y §6; la del responsable técnico es la que da el "go" durante la ventana; la del cliente aprueba el alcance.
> Un addendum firmado sólo por el auditor es un documento interno.

---

### Paso 2 — Autotest del toolkit

| Entrada | `01-tooling/scripts/` |
|---|---|
| **Acción** | `python3 tests/selftest.py` — 19 checks, **sin ninguna llamada de red** (uno bloquea `socket` para comprobarlo) |
| **Salida** | `PASS` en los 19 checks, salida 0 |
| **Artefacto** | `evidencia/fase2/selftest_toolkit.txt` |
| **Parada** | Si algún test falla, **no se abre la ventana**. Un toolkit que no sabe rechazarse no sirve para una fase con datos de pacientes. |

Los checks que importan aquí: *«scope_guard descarta POST aunque esté en allowed_methods»*, *«host no autorizado rechazado»*, *«autorización sin firma rechazada»* y *«detección de secretos sin filtrar valores»*.

---

### Paso 3 — Construir y validar el fichero de autorización de Fase 2

| Entrada | `01-tooling/scripts/authorization.example.json`; datos del RoE y del addendum |
|---|---|
| **Acción** | Copiar la plantilla y ajustar: `authorization_ref` = identificador del addendum; `signed_by` = las tres firmas; `valid_from` / `valid_to` = **la ventana**; `hosts` = los hosts del RoE base; `user_agent` = UA honesto con teléfono; `min_interval_s` = 1.0; `max_bytes` = 1048576 |
| **Salida** | `authorization-fase2.json` |
| **Artefacto** | `evidencia/fase2/authorization-fase2.json` |
| **Parada** | Si `scope_guard.py` devuelve **código 2** (fichero ausente, inválido o **sin firma**), no se hace ninguna petición. Es el comportamiento correcto, no un error. |

```bash
python3 scope_guard.py \
    --authorization evidencia/fase2/authorization-fase2.json \
    --list-hosts --json
```

> **Dos propiedades que se obtienen gratis con este fichero:** (1) **la ventana pasa a estar impuesta por la herramienta**, porque `scope_guard.py` comprueba `valid_from` / `valid_to` antes de tocar la red —fuera de la ventana, la petición no sale—;
> (2) **el addendum por sí solo no abre la red**: la autoridad real la tiene el fichero de autorización, y su constructor es quien lo firma.
> **Limitación real y verificable de la toolchain:** `scope_guard.py` **recorta los métodos a `GET`/`HEAD` aunque el fichero liste otros** (RoE 1.1), de modo que **la variante B de T1 (el único POST autorizado) no puede ejecutarse a través de `scope_guard.py`**.
> Esa escritura se hace con otra herramienta, de forma manual, en el entorno de pruebas designado, y **se registra en el log de acciones con el mismo rigor que las demás** (hora, petición, resultado, huella, rollback).
> No es una excepción al control: es la excepción **nombrada** en el addendum, y por eso se escribe en el registro con más detalle, no con menos.

---

### Paso 4 — Validar el alcance de los endpoints candidatos

| Entrada | La lista de endpoints del §2 del addendum (los de T1–T6) |
|---|---|
| **Acción** | Validar **cada** URL contra la autorización **sin** hacer la petición: `python3 scope_guard.py --authorization ... --check URL`. Para los endpoints de terceros (T6), validar además que el host está autorizado por escrito en el addendum |
| **Salida** | Tabla de endpoints validados / rechazados, con el motivo del rechazo |
| **Artefacto** | `evidencia/fase2/alcance-validado.json` |
| **Parada** | Un endpoint que no valida **no se toca**. Se anota como *fuera de alcance* y el hallazgo queda como *no verificado*. |

```bash
for u in "https://clinica-ejemplo.mx/api/v1/pacientes/1042" \
         "https://clinica-ejemplo.mx/api/v1/buscar?q=x"; do
  python3 scope_guard.py --authorization evidencia/fase2/authorization-fase2.json \
      --check "$u"
done
```

---

### Paso 5 — Confirmar cuentas de prueba y entorno designado

| Entrada | Cuentas entregadas por el cliente; entorno de pruebas designado por escrito (si T1-B está aprobada); endpoint de lectura del proveedor designado por escrito (si T6 está aprobada) |
|---|---|
| **Acción** | En la llamada, con el cliente: (a) confirmar **por escrito** qué cuenta corresponde a qué rol; (b) confirmar **por escrito** que los registros asociados a las cuentas de prueba son sintéticos y no contienen datos de pacientes reales; (c) confirmar el entorno de pruebas y el endpoint de lectura |
| **Salida** | Cuentas confirmadas con su alias estable (`PACIENTE-PRUEBA-A`, `PACIENTE-PRUEBA-B`, `ADMIN-PRUEBA`, `AUDITOR-PRUEBA`) y su tipo |
| **Artefacto** | `evidencia/fase2/cuentas-prueba-confirmadas.md` |
| **Parada** | Si el cliente **no puede garantizar** que una cuenta es sintética, **esa cuenta no se usa**. La técnica se anota *no ejecutada — cuenta no verificable*. Un hallazgo de IDOR sin cuentas sintéticas confirmadas es un hallazgo de Fase 1, no de Fase 2. |

---

### Paso 6 — Abrir el registro de acciones y fijar la lista de pruebas

| Entrada | `05-plantillas-de-trabajo/registro-de-acciones-fase-2.csv`; §7.1 del addendum |
|---|---|
| **Acción** | Copiar el CSV con sus cabeceras; **preparar una fila por técnica autorizada** con `estado` = `pendiente-de-go`; registrar en `notas` el "go" cuando llegue, con hora y con quién se confirmó |
| **Salida** | Registro abierto, con la lista de lo que se va a hacer y lo que **no** se va a hacer |
| **Artefacto** | `03-casos/<cliente>/registro-de-acciones-fase-2.csv` |
| **Parada** | Sin registro abierto, no se hace la primera petición. Una ejecución sin registro no es una ejecución auditable. |

> **Una fila por técnica no es suficiente para T1:** T1 tiene dos peticiones comparativas y, en la variante B, una creación y un borrado.
> Se registra **una fila por acción**, no una fila por técnica, para que la huella sea contable.

---

### Paso 7 — T1: IDOR / BOLA

| Entrada | Cuentas de prueba A y B; el par de identificadores que entrega el cliente; el endpoint del addendum |
|---|---|
| **Acción** | Dos `GET` sobre el **mismo** identificador (el de A), uno con la sesión de A y otro con la sesión de B. Comparar **código, claves del JSON y longitud**. En la variante B y **sólo** en el entorno designado: crear **un** artefacto propio, contenido vacío, nombre fijo |
| **Salida** | La diferencia de comportamiento (o la ausencia de diferencia → refutado) |
| **Artefacto** | `evidencia/fase2/idor_<recurso>_<id>.txt` — petición y respuesta **sanitizadas**: código, tamaño, claves. **El contenido del registro no se transcribe.** En variante B: `evidencia/fase2/idor_variante_b_creacion.txt` |
| **Parada** | La respuesta trae un dato de paciente → **abort**, descartar, no conservar, escalar (§7.3). Variante B: se ejecuta **una sola vez** |

```bash
# Dos peticiones comparativas, separadas por el intervalo mínimo:
# una con la cookie de la cuenta B y otra con la cookie de la cuenta A.
python3 scope_guard.py --authorization evidencia/fase2/authorization-fase2.json \
    --probe "https://clinica-ejemplo.mx/api/v1/pacientes/1042"
```

> **Lo que se registra:** `CONFIRMADO` si la cuenta B obtiene una respuesta equivalente a la de A sobre un identificador ajeno; `REFUTADO` si B recibe 403/404.
> **Un refutado se registra y se entrega.**

---

### Paso 8 — T2: SQLi no destructivo

| Entrada | El parámetro identificado en Fase 1; una cuenta o consulta que devuelva un conjunto mínimo |
|---|---|
| **Acción** | **Una** pareja de peticiones comparativas: condición verdadera y condición falsa. Sin `UNION`, sin `;`, sin extracción, sin `time-based`. Comparar código, número de resultados y orden |
| **Salida** | La diferencia consistente (o la ausencia de diferencia) |
| **Artefacto** | `evidencia/fase2/sqli_boolean_comparativa.txt` — código y longitud de las dos respuestas. **Sin filas extraídas** |
| **Parada** | Si la respuesta difiere en contenido más allá de la longitud esperada → la prueba **se detiene ahí** y ese contenido **se descarta** |

```bash
python3 scope_guard.py --authorization evidencia/fase2/authorization-fase2.json \
    --probe "https://clinica-ejemplo.mx/api/v1/buscar?q=cafe%27%20AND%20%271%27=%271"
# y la condición falsa equivalente
```

> **La comparación booleana es la única prueba admisible.** Si la diferencia no aparece, el hallazgo es «no reproducible», no «no vulnerable»:
> T2 **no descarta** una variante ciega o basada en tiempo (§3.3.2).
> Esa limitación se declara en §6 del anexo.

---

### Paso 9 — T3: XSS con payload inocuo

| Entrada | El parámetro reflejado que marcó Fase 1; la cuenta propia del auditor |
|---|---|
| **Acción** | Un `GET` con el marcador `XSS-AUDIT-F2-03` (texto plano, sin beacon, sin script, sin acceso a cookies) contra la **cuenta propia**. Verificar que el marcador aparece **sin codificar** en la respuesta renderizada |
| **Salida** | El marcador visible sin codificar, o la ausencia de él (refutado) |
| **Artefacto** | `evidencia/fase2/xss_reflejado_marcador.txt` |
| **Parada** | Si el marcador **queda almacenado** → se borra antes de cerrar y **se registra** en el log. XSS almacenado: no se intenta |

---

### Paso 10 — T4: Bypass de control de acceso administrativo

| Entrada | Los endpoints admin del addendum; la cuenta admin de prueba y la cuenta de paciente de prueba |
|---|---|
| **Acción** | Las **dos** comprobaciones: con la cuenta admin de prueba y con la cuenta de paciente de prueba. Comparar código, cabecera `Location` y el **rol efectivo de la propia cuenta**. Nada más |
| **Salida** | Comportamiento del endpoint según el rol (o el `403` que demuestra que el control funciona) |
| **Artefacto** | `evidencia/fase2/admin_acceso_<codigo>_cuenta_paciente.txt` y `evidencia/fase2/admin_acceso_<codigo>_cuenta_admin.txt` |
| **Parada** | Cualquier contenido de terceros en la respuesta → abort. No se listan usuarios reales |

> **Si el control funciona, es un hallazgo `INFO / CERRADO-OK`.** Y va en la tabla de hallazgos explotados.
> Un control de acceso que funciona es «lo que ya está bien», y hay que decirlo con la misma precisión con la que se dice lo que no funciona.

---

### Paso 11 — T5: Fichero de backup expuesto

| Entrada | La ruta exacta registrada en el informe de Fase 1 |
|---|---|
| **Acción** | **Una sola** petición con `Range: bytes=0-1023`. Se lee como máximo el primer kilobyte para confirmar el tipo y el tamaño. **No** se descarga, **no** se descomprime, **no** se buscan credenciales dentro |
| **Salida** | Código, `Content-Type`, `Content-Length` y los primeros bytes |
| **Artefacto** | `evidencia/fase2/backup_exposto_head.txt` |
| **Parada** | Si el servidor **ignora el `Range`** y sirve el fichero completo → abort y se declara. Si en los primeros 1 024 bytes hay un hash o una contraseña, **no se transcribe**: se anota «se observa material sensible en las primeras líneas» y la evidencia se entrega enmascarada |

```bash
# La URL se valida primero (sin red); el Range lo añade curl, porque el CLI
# de scope_guard.py no expone cabeceras adicionales.
python3 scope_guard.py --authorization evidencia/fase2/authorization-fase2.json \
    --check "https://clinica-ejemplo.mx/wp-content/backups/backup-2026-10-14.sql"

curl -sS -D evidencia/fase2/backup_exposto_head.txt -o /dev/null \
    -A "Mozilla/5.0 (compatible; ClientSecurityAudit/2.0; +52-XXX-XXX-XXXX)" \
    -H "Range: bytes=0-1023" \
    "https://clinica-ejemplo.mx/wp-content/backups/backup-2026-10-14.sql"
```

> **Por qué `curl` y no `scope_guard.py --probe`:** el CLI de `scope_guard.py` no admite cabeceras adicionales y `Range` es imprescindible aquí.
> La secuencia correcta es **validar con `--check` primero** (que aplica el allowlist, la ventana y el UA) y **después** hacer la única petición con `curl`, con el UA honesto y respetando el intervalo ≥1 s respecto de la petición anterior.
> **NO VERIFICADO — requiere comprobación contra fuente primaria.** El comportamiento de `Range` depende de la configuración del servidor (algunos lo respetan, otros lo ignoran y sirven el fichero entero).
> **Antes de ejecutar este paso hay que confirmar con el cliente que su servidor respeta rangos**, o ejecutar un `HEAD` previo para ver `Accept-Ranges`.
> Si no los respeta, la lectura de 1 KB no se puede garantizar y T5 **no se ejecuta** tal como está escrita: se declara *no ejecutada — el servidor no admite rangos*, y el fichero se reporta con la evidencia de Fase 1.

---

### Paso 12 — T6: Validación de credencial expuesta

| Entrada | El secreto detectado en Fase 1 (enmascarado en la evidencia); el endpoint de lectura **designado por escrito** por el cliente; el proveedor real |
|---|---|
| **Acción** | **Una** llamada `GET` de lectura. Se registra el código de respuesta y los **nombres de campo**. **No** se enumera, **no** se descarga, **no** se transcribe ningún recurso |
| **Salida** | Si la credencial es aceptada y qué **categoría** de recurso expone |
| **Artefacto** | `evidencia/fase2/api_proveedor_lectura.txt` — código, nombres de campo, prefijo enmascarado y `sha256[:12]` |
| **Parada** | Si la respuesta trae registros de pacientes → descartar y **escalar**. Si la credencial es rechazada (401/403) → el hallazgo es «exposición de un valor que ya no es válido», que se reporta como tal, con su severidad recalibrada |

```bash
python3 scope_guard.py --authorization evidencia/fase2/authorization-fase2.json \
    --check "https://api.proveedor-ejemplo.com/v1/cuentas"
# y la única llamada, con la cabecera Authorization, usando el valor en
# memoria y sin volcarlo a disco en ningún momento
```

> **El valor de la credencial no se escribe en ningún fichero durante este paso.** Se recupera del material original **en memoria**, en la sesión de ejecución, y no se persiste.
> Si el material de origen no está disponible de forma segura en el momento de la ventana, la técnica **no se ejecuta**: se anota *no ejecutada — valor completo no disponible en condiciones controladas*.

---

### Paso 13 — Limpieza del footprint y verificación

| Entrada | Artefactos creados por el auditor (T1-B); tabla de residuos del addendum §5.4 |
|---|---|
| **Acción** | Eliminar cada artefacto con la misma cuenta que lo creó; **verificar** con una lectura de comprobación (`GET` → 404); registrar hora, responsable y método de verificación; enumerar los residuos no limpiables |
| **Salida** | Huella propia = cero (o la lista de lo que no se pudo limpiar, con su motivo) |
| **Artefacto** | `evidencia/fase2/declaracion-limpieza.md` (borrador para firma) y las filas `rollback_hecho` del CSV |
| **Parada** | Si un artefacto propio **no se puede** limpiar, no se repite la técnica y el residuo se declara en §8 del anexo. **No se cierra la fase con residuo propio sin limpiar y sin declarar.** |

---

### Paso 14 — Redacción y minimización de la evidencia

| Entrada | `evidencia-cruda/` (todo lo generado en la fase, incluido lo que se descartó) |
|---|---|
| **Acción** | (a) `pii_redact.py` sobre el directorio completo; (b) `secrets_scan.py` sobre la copia saneada; (c) **lectura manual** del informe de redaction (`redaccion.json`, que da conteos por categoría) y de cada evidencia saneada; (d) comprobación de que ningún fichero contiene cookies, tokens ni valores completos |
| **Salida** | `evidencia-sanitizada/` apta para entregar + `redaccion.json` + `secrets_fase2.json` |
| **Artefacto** | `evidencia/redaccion.json`, `evidencia/secrets_fase2.json` |
| **Parada** | Si aparece un dato personal **no redactado**, se elimina el fichero que lo contiene, sin copia, y se anota en el log de acciones. **No se entrega hasta que la revisión manual esté hecha.** |

```bash
python3 pii_redact.py evidencia-cruda/ \
    --out-dir evidencia-sanitizada \
    --report evidencia/redaccion.json

python3 secrets_scan.py ./evidencia-sanitizada \
    --json --out evidencia/secrets_fase2.json
```

> **El paso (c) no es opcional.** `pii_redact.py` no tiene NER: los nombres de personas en texto libre no se redactan (§7.6), y en Fase 2 las respuestas sí pueden contener nombres.
> **La revisión manual garantiza la minimización; el script sólo la facilita.**

---

### Paso 15 — Informe, anexo, declaración de limpieza y entrega

| Entrada | Evidencia saneada; CSV del registro de acciones; hallazgos de Fase 1; `02-plantillas/informe-completo/anexo-explotacion-limitada.md` |
|---|---|
| **Acción** | (a) Recalcular el score con la evidencia de Fase 2; (b) redactar el anexo: tabla de hallazgos explotados, una ficha por hallazgo con **«Lo que NO se hizo»**, §5 de datos reales expuestos, §6 de limitaciones, §7 de remediación y re-test, §8 de declaración de limpieza firmada, §9 de índice de evidencia; (c) re-verificar cada afirmación contra su fichero; (d) verificar que el informe no lleva datos de paciente ni valores completos; (e) debrief con el cliente; (f) entregar por el canal correcto |
| **Salida** | Anexo, registro de acciones y declaración de limpieza, más la hoja de re-test agendada |
| **Artefacto** | `03-casos/<cliente>/informe-tecnico/anexo-explotacion-limitada.md` · `informe/attack_surface_report.md` · `evidencia/fase2/declaracion-limpieza.md` (firmada) |
| **Parada** | Si alguna afirmación del anexo no se puede trazar a un fichero de evidencia, **no se publica**. Y si falta la revisión manual de la redacción, no se entrega |

```bash
python3 attack_surface_report.py \
    --probe-tsv evidencia/probe_exposure.tsv \
    --secrets-json evidencia/secrets.json \
    --headers evidencia/headers.txt \
    --js-intel evidencia/js_intel.json \
    --out informe/
```

> **El score se recalcula con la evidencia de Fase 2, pero no se reescribe el informe de Fase 1.** Se añade el anexo.
> Un informe con dos versiones incompatibles es un problema de trazabilidad.

---

## 9. Errores que matan este tipo de fase

Nueve trampas reales.
Cada una con su escenario, por qué duele y qué la neutraliza.
Las nueve se han visto en alguna fase de este tipo; ninguna es exótica.

### 9.1 El PoC de SQLi «no destructivo» que en realidad extrae

| | |
|---|---|
| **Escenario** | El auditor quiere una comparación limpia y usa `UNION SELECT NULL,NULL` para alinear columnas. La respuesta vuelve con más campos de los esperados; el auditor «sólo mira la estructura» y sigue. En la tercera petición —con `UNION SELECT id,nombre,apellido FROM pacientes LIMIT 5`— ya está en territorio de extracción, y con un `--batch` o un `--dump` por delante la cosa se sale de control. |
| **Por qué duele** | El agravante no es la extracción: es que **fue incremental y no hubo un momento identificable en el que se cruzó la línea**. Cuando se revise el incidente, nadie sabrá qué petición fue la culpable. Y un archivo de Fase 2 con nombres de paciente en el disco del auditor es un archivo que hay que destruir y del que hay que hablar con el responsable de datos del cliente. |
| **Mitigación** | (1) T2 **sólo** admite la comparación booleana: `UNION` y `;` están prohibidos por el addendum, no por criterio. (2) **Se escribe el límite antes de empezar**, en el registro de acciones: la petición exacta que se va a hacer, con su parámetro. La diferencia entre la petición escrita y la ejecutada es el control. (3) `scope_guard.py` impone `max_bytes`: la página entera no entra en la evidencia. (4) Criterio de parada: contenido no atribuible al parámetro → la prueba se detiene **y ese contenido se descarta**. |

### 9.2 El PoC que crea un usuario administrador y nadie lo borra

| | |
|---|---|
| **Escenario** | Para demostrar el bypass de control de acceso, el auditor crea un usuario con rol admin. El cliente tenía «otro entorno» para pruebas, pero el auditor, por prisa, lo hizo en el que había datos de demostración con nombres reales. Nadie recuerda el usuario. Semanas después aparece un incidente de autenticación y nadie sabe de dónde salió. |
| **Por qué duele** | Un usuario creado por el auditor es un artefacto con **acceso persistente**, no una entrada de log: no se limpia sola. Y la credencial usada para crearlo puede haber quedado en un historial de shell, en un archivo de `~/.bash_history` o en una captura de pantalla. |
| **Mitigación** | (1) La variante B es **un** artefacto, con **contenido vacío** y **nombre fijo**. (2) **Entorno designado por escrito**: sin entorno designado, la variante B no se ejecuta y T1 se queda en la variante A, que es sólo lectura. (3) **El borrado y su verificación (404) son condición de cierre de la fase**, no una buena práctica: si no están en la tabla §8 del anexo, la fase no se cierra. (4) Se revisa y limpia el historial de credenciales del shell antes de cerrar la sesión. (5) **Regla general:** si una técnica deja algo detrás, se limpia **y se reporta**; si no se puede limpiar, se declara como residual y **no se repite**. |

### 9.3 El exploit que dispara un correo real al paciente

| | |
|---|---|
| **Escenario** | La técnica de demostración toca un endpoint que, además de responder, envía un correo de confirmación o un SMS. El correo sale a un paciente que acaba de darse de alta, o a un contacto de la agenda. El paciente recibe un mensaje de un dominio que no reconoce, con datos que no pidió. |
| **Por qué duele** | El daño no es técnico: es de **confianza y de cumplimiento**. El cliente tiene que responder a un paciente que pregunta por qué recibió ese mensaje. Y el auditor ha hecho, sin autorización, algo que la RoE base prohíbe por partida doble: un POST (§1.1) y un efecto sobre terceros (§1.2). |
| **Mitigación** | (1) En Fase 0 y Fase 1, la lectura del JavaScript público **revela** qué endpoints disparan efectos (`fetch(..., {method:'POST'})`, webhooks, pasarelas de SMS). Ese análisis previo es el que evita el disparo: **el efecto se conoce antes de tocar.** (2) En Fase 2, cada técnica nombra su **endpoint**, y los efectos prohibidos están enumerados. Un endpoint que envía correo **no entra** en la lista. (3) El cliente observa en la ventana: quien ve las citas y los correos detecta el disparo en segundos. (4) Criterio de abort 2: «un correo enviado, un SMS, una notificación, una reserva» → parada inmediata y revisión con el cliente. |

### 9.4 El timing-based que degrada el servicio

| | |
|---|---|
| **Escenario** | El auditor usa `SLEEP(5)` para confirmar una inyección ciega. Lo hace tres veces. El servidor de la clínica —compartido, con una agenda activa y un cron que corre cada hora— se ralentiza. Un paciente que estaba cargando el formulario de cita lo abandona. Nadie sabe por qué: la latencia «se normaliza» sola. |
| **Por qué duele** | El auditor nunca ve el error de negocio. Lo ve el paciente, que no le dice al cliente que dejó de agendar porque la web tardaba. Y el cliente, que tampoco lo sabe, **no puede explicar** por qué su rendimiento bajó ese martes. |
| **Mitigación** | (1) `time-based` está en la **prohibición absoluta 1**: nada de pruebas de disponibilidad, ancho de banda, concurrencia, ni `time-based` para medir capacidad. (2) La confirmación booleana (T2) es **una pareja de peticiones**: no hay repetición para «confirmar». (3) Si la base de datos del cliente es compartida, el impacto de un `SLEEP` no se limita al endpoint: afecta a **todas** las consultas del servidor. (4) **Limitación declarada, no escondida:** la Fase 2 no descarta las variantes ciegas o basadas en tiempo, y eso se dice en §6 del anexo. |

### 9.5 El auditor que interpreta «haz lo que necesites» como autorización total

| | |
|---|---|
| **Escenario** | El contrato dice «el auditor hará lo que sea necesario para evaluar la seguridad». El auditor lee eso como permiso para probar endpoints que no están en el addendum, con técnicas que nadie ha nombrado, «porque es lo que hace falta». |
| **Por qué duele** | Porque en el momento en que esto ocurre, **no hay ninguna forma de demostrar que la prueba estaba autorizada**. La autorización no es una frase de contrato: es una **lista de técnicas, con endpoints y métodos**, firmada por tres partes. Un «haz lo que necesites» es exactamente la frase que la RoE base cita como ejemplo de lo que **no** autoriza. |
| **Mitigación** | (1) El addendum es una lista **cerrada**: seis técnicas, con endpoint, método, condición, requisito previo, evidencia, huella y tiempo máximo. (2) Lo que no está en la lista **no se ejecuta**, aunque el técnico del cliente lo pida en el chat: «esto necesita un addendum nuevo; lo anoto como candidato». (3) El **"go" es por prueba**, no por fase: un "go" para T1 no habilita T2. (4) Cambiar modalidad o alcance requiere **firma nueva**, no una decisión a mitad de camino. (5) **Precedente interno:** el RoE es lo que define qué puedes decir «no probé»; un addendum sin el RoE base firmado no se ejecuta. |

### 9.6 El cliente que pide extender la ventana a las 2 a. m.

| | |
|---|---|
| **Escenario** | La ventana era de 20:00 a 23:00. A las 22:40 queda un hallazgo a medio probar y alguien pide «terminemos mañana a las dos». El cliente insiste: «es de madrugada, no hay pacientes, no pasa nada». |
| **Por qué duele** | Por cuatro razones, y ninguna es «la auditoría se hace de noche». (a) **El soporte del hosting y el de la agencia no están**: sin nadie que mire el panel, el criterio de abort pierde su mecanismo. (b) **La autorización estaba escrita para una ventana concreta**: cambiarla es modificar el alcance, y eso requiere firma. (c) **A las 2 a. m. pueden correr los procesos nocturnos** del cliente —backups, purgas, sincronizaciones, tareas no documentadas— y una prueba que coincide con un backup produce efectos que nadie sabe atribuir. (d) El cambio de hora no está en el RoE, y `scope_guard.py` **rechazaría** las peticiones fuera de `valid_from`/`valid_to`: la ventana está impuesta por la herramienta. |
| **Mitigación** | (1) La ventana del addendum es un **rango cerrado** y las peticiones fuera de él **no se hacen**, aunque el RoE base siga vigente. (2) Si hace falta más tiempo, se acuerda **antes**, por escrito, y se amplían `valid_to` y el §4 del addendum, con firma. Nunca «un rato más» sin firma. (3) Si lo que hace falta es más tiempo, la respuesta es **otra ventana**, no alargar la actual a costa de la observabilidad. (4) El abort se puede provocar desde el propio cliente en cualquier momento, y esa posibilidad **debe** existir en cualquier ventana. |

### 9.7 El hallazgo confirmado con una cuenta que en realidad es de un paciente

| | |
|---|---|
| **Escenario** | El cliente manda «estas son las cuentas de prueba»: una de prueba y otra que era la cuenta real de una recepcionista que se jubiló hace un año, o una cuenta de prueba que en realidad es la de un familiar del dueño que «la usa para probar». El auditor no verifica y la usa. El registro que devuelve contiene el historial de una paciente real. |
| **Por qué duele** | Porque **quien piensa que el dato es de prueba es el auditor**, y el auditor no es quien sabe. Y cuando el registro contiene datos clínicos, el problema deja de ser «un dato de más en la evidencia»: es **acceso no autorizado a un expediente**, con todas las consecuencias que eso tiene para el cliente. |
| **Mitigación** | (1) **Confirmación escrita, técnica y específica**: qué cuenta es, qué rol tiene y **qué garantía da el cliente** de que su registro no contiene datos de pacientes reales. Se anota en `evidencia/fase2/cuentas-prueba-confirmadas.md`. (2) Si la garantía no es explícita, **la cuenta no se usa** y la técnica se anota *no ejecutada — cuenta no verificable*. (3) **Prueba de contenido antes de la prueba de vulnerabilidad**: el auditor **mira el registro de la cuenta de prueba** antes de usarla como referencia; si ve algo que no debería estar ahí, para (y si lo ve, eso también es un hallazgo, y se escala). (4) Criterio de abort 1: **aparece un dato de paciente en una respuesta** → se descarta sin conservar, se registra y se escala. |

### 9.8 El «go» verbal que nadie documenta

| | |
|---|---|
| **Escenario** | El responsable técnico dice «dale, sigue». El auditor ejecuta cuatro técnicas en veinte minutos. En el informe hay resultados que no se pueden re-ejecutar porque nadie sabe con qué autorización se hicieron, ni quién las autorizó, ni a qué hora. |
| **Por qué duele** | La Fase 2 produce un anexo que dice «cada paso es reproducible por el equipo del cliente». Si la autorización no está documentada, el hallazgo se cae en la revisión legal. Y si la auditoría se discutió, no hay nada que enseñar. |
| **Mitigación** | (1) El "go" se pide **por escrito en el canal de ejecución, con la hora**, y se anota en la fila correspondiente del registro de acciones. (2) **El silencio no es un "go"**: sin respuesta en 10 minutos, la prueba no se ejecuta y se anota *no ejecutada — sin go*. (3) El **correo no se usa** para dar el "go": sólo lleva el addendum firmado y la entrega final. (4) El registro de acciones se entrega **completo** al cliente: es el documento que prueba que la ejecución fue autorizada prueba por prueba. |

### 9.9 El hallazgo que se agranda porque «ya que estamos dentro»

| | |
|---|---|
| **Escenario** | T1 funcionó con `/api/v1/pacientes/{id}`. El auditor tiene la sesión, la técnica ha funcionado y la tentación es probar `/api/v1/expedientes/{id}`, `/api/v1/consultas/{id}`, `/api/v1/facturas/{id}`. El addendum sólo nombraba el primero. |
| **Por qué duele** | Porque es la forma más natural de **crecer el alcance sin decidirlo**: cada endpoint nuevo es «una petición más», y al final hay quince peticiones que nadie autorizó. Y cada endpoint nuevo es un endpoint nuevo donde puede aparecer un dato real. |
| **Mitigación** | (1) **La lista de endpoints es cerrada** y está en el addendum: un endpoint que no aparece ahí no se toca, ni «una vez», ni «sólo para ver». (2) Lo que se descubre en el camino se **anota como candidato** para una fase posterior, con su hipótesis y su endpoint: es un entregable de la Fase 2, la **hoja de ruta de la siguiente ventana**. (3) El mismo principio aplica a las técnicas: T1 no habilita T2, y una técnica que funciona no habilita «variantes» de esa misma técnica. |

## 10. Checklist de salida de Fase 2

Lista verificable de cierre.
**Todas** las casillas se marcan.
Una casilla sin marcar se escribe como pendiente, con responsable y fecha; no se borra.

### 10.1 Autorización y ejecución

- [ ] RoE base firmado, archivado en la evidencia del caso.
- [ ] Addendum de Fase 2 firmado **por las tres partes**, archivado.
- [ ] Técnicas **autorizadas** en §7.1 ejecutadas; técnicas **rechazadas** excluidas y reportadas como *no ejecutada — rechazada por el cliente*.
- [ ] Registro de acciones con una fila por acción, con el "go" anotado con hora y responsable.
- [ ] Ninguna petición fuera de la ventana. Verificable contra las marcas de tiempo del registro y contra `valid_from`/`valid_to`.
- [ ] User-Agent honesto en **todas** las peticiones.
- [ ] Intervalo ≥1 s respetado entre peticiones. Sin concurrencia, sin reintentos automáticos.

### 10.2 Huella (footprint)

- [ ] **Huella propia = cero**: cada artefacto creado por el auditor está eliminado **y verificado** (lectura de comprobación → 404).
- [ ] Entradas de log propias (log de actividad de la cuenta) retiradas o declaradas como no retirables.
- [ ] Residuos no limpiables **declarados explícitamente** en §8 del anexo: log del servidor web, log de acceso del proveedor, y cualquier otro.
- [ ] Ningún artefacto propio sin limpiar **sin declarar**.
- [ ] **Declaración de limpieza firmada por ambas partes.**

### 10.3 Datos

- [ ] Evidencia pasada por `pii_redact.py` **y revisada a mano**.
- [ ] `secrets_scan.py` ejecutado sobre la copia saneada, sin valores completos.
- [ ] Ningún fichero de evidencia contiene nombre, teléfono, correo, expediente ni dato clínico de una persona real.
- [ ] Ningún fichero contiene cookies de sesión, cabeceras `Authorization` ni tokens completos.
- [ ] Los secretos aparecen **sólo** como `prefijo…sufijo` + `sha256[:12]`.
- [ ] Capturas de pantalla recortadas a la zona relevante.
- [ ] Respuestas que trajeron datos de terceros: **descartadas, no conservadas**, y anotadas en el log de acciones.
- [ ] Los **falsos positivos y los refutados se conservan** (filas `REFUTADO` y `NO EJECUTADO`). Un directorio donde todo salió bien a la primera es sospechoso.

### 10.4 Contenido del informe

- [ ] Anexo redactado desde la plantilla, con las 9 secciones.
- [ ] Una ficha por hallazgo, con los seis apartados, **incluido «Lo que NO se hizo»**.
- [ ] Impacto **real demostrado** separado del impacto **máximo teórico**.
- [ ] §5 de datos reales expuestos completo, con la categoría de dato y **nunca el valor**.
- [ ] §6 con las limitaciones de la fase declaradas (variante ciega no descartada, una sola instancia por técnica, sin pruebas de carga).
- [ ] **«Lo que ya está bien»** presente: controles que funcionaron, refutados que confirman el diseño correcto, buenas decisiones del cliente.
- [ ] Toda afirmación del informe trazable a un fichero de evidencia.
- [ ] Verificado que el anexo **no** contiene datos de paciente ni valores completos.

### 10.5 Cierre

- [ ] **Debrief con el cliente** realizado, con el responsable técnico presente, y con el contenido del debrief registrado.
- [ ] **Rotación de credenciales por el cliente confirmada** (H-04). Si no está confirmada, **no se entrega el anexo** y el residuo se declara como vigente.
- [ ] Plan de remediación con owner, esfuerzo y fecha; re-test **agendado** con su addendum y su ventana.
- [ ] Plan de destrucción de la evidencia **escrito y notificado** al cliente (30 días naturales).
- [ ] Entrega por el canal correcto: anexo + registro + declaración de limpieza al **equipo técnico**; **nada** al dueño final ni a terceros.
- [ ] Nada de la Fase 2 se ha reutilizado en material comercial, en formación o en otro encargo.
- [ ] El caso queda archivado en `03-casos/<cliente>/` con su evidencia, y las herramientas nuevas, si las hubo, anotadas en el manifiesto.

---

## 11. Errores frecuentes de alcance (qué hacer si...)

| Situación | Respuesta correcta |
|---|---|
| **El cliente te pide que metas un keylogger.** | **No.** El keylogger es persistencia (prohibición 5), es vigilancia sobre el personal (prohibición 9) y es una forma de intrusión, no de auditoría. **Se responde con la alternativa:** «Lo que puedo hacer es demostrar, con una cuenta de prueba, si un tercero con acceso al servidor puede leer un expediente que no le corresponde — con el mismo impacto para el negocio y sin dejar nada instalado.» Si el cliente insiste, se anota que la petición queda fuera de alcance y se ofrece una fase de revisión de configuración. |
| **Te piden tocar la base de datos.** | **No.** Conectar a la base de datos es movimiento lateral (§3.6) y requiere una autorización distinta, con su propio RoE y su propia ventana. **Se responde con la alternativa:** «No toco la base de datos. Lo que sí puedo hacer es demostrar el impacto desde la capa web — con dos cuentas de prueba, sin extraer filas y sin tocar datos reales — y redactarle la consulta de solo lectura para que usted mida el volumen expuesto desde su servidor.» |
| **El hospital dice que su director lo autoriza pero no hay nada escrito.** | **No se empieza.** La autorización «de palabra» o por un correo suelto no es autorización: es una versión de «haz lo que necesites». **Se responde:** «Con la confirmación verbal puedo escribir el addendum; necesito la firma antes de la ventana.» Si el director no puede firmar, se propone que firme quien técnica y legalmente pueda, y se documenta la estructura de firma. **Sin firma, la ventana no existe** — ni para una sola petición. |
| **El desarrollador del cliente te pide velocidad.** | **Se mantiene el ritmo.** El ritmo ≥1 s, sin concurrencia y sin reintentos automáticos no son lentitud: son la garantía de que no se rompe nada. **Se responde:** «Voy al ritmo que pedimos para que no haya riesgo de caída, y eso no cambia por urgencia. Lo que sí puedo hacer es priorizar: si me dice qué dos hallazgos le urgen más, ejecuto esos primero.» |
| **El cliente pide que pruebes «un caso más» que no está en el addendum.** | **No en esta ventana.** Se anota como **candidato** con su endpoint, su hipótesis y su técnica propuesta, y se ofrece una **ventana posterior con addendum**. El argumento: cada técnica necesita su condición, su evidencia y su tiempo máximo, y eso se escribe, no se improvisa. |
| **El cliente te pide el valor completo de la credencial expuesta para poder rotarla.** | **Se entrega enmascarado y con el `sha256[:12]`.** El valor completo, si el cliente lo necesita, se entrega **por un canal seguro y separado**, con confirmación de recepción, y **nunca** dentro del informe ni del anexo. Y se comprueba de antemano si el par enmascarado + fingerprint le basta para rotarla (§4.4). |
| **Aparece un dato de paciente real en una respuesta.** | **Se descarta la respuesta sin conservar copia**, se anota en el log de acciones con hora y endpoint, y **se escala de inmediato** al responsable técnico y, si el caso lo amerita, al contacto de emergencia. **No se sigue probando** hasta resolverlo. El hallazgo, si lo hay, se escribe **sin el dato**. |
| **El hosting del cliente llama y dice que detectaron "un ataque".** | **No se confirma nada por teléfono.** Se verifica internamente contra el registro de acciones y los logs que el cliente tiene a la vista, y se responde por escrito. **No se contacta al hosting sin autorización escrita del cliente** (prohibición 11). La comunicación la hace el cliente: es su infraestructura y su relación. |
| **La clínica te pide que revises también el sistema de gestión de pacientes que no es web.** | **No en este encargo.** Es un sistema distinto, con su RoE, su metodología y su alcance. **Se responde con una derivación comercial honesta:** «eso necesita su propia revisión, con su propio RoE y su propia ventana; puedo cotizarla aparte.» Lo que sí se puede hacer es **dejar constancia del hallazgo** — que la web manda datos a un sistema que nadie ha revisado — como riesgo de cumplimiento. |
| **El cliente quiere que el anexo incluya capturas con datos visibles.** | **No.** Las capturas se recortan a la zona relevante y los valores sensibles van enmascarados. **Se explica por qué:** el anexo va al hosting, a la agencia, a veces a un ticket, y a veces termina en un correo. Una captura con datos clínicos en ese recorrido es una fuga de datos provocada por el informe. **Si el cliente necesita el material original**, se le entrega por canal seguro y separado, con confirmación de recepción y con el plazo de retención acordado. |
| **El equipo del cliente quiere que el re-test lo hagan ellos.** | **Se acepta y se documenta.** Se entrega la guía de re-test: los tres pasos exactos de cada ficha, el endpoint, los parámetros y las dos cuentas de prueba. El re-test del cliente **no es un re-test**: no hay evidencia revisable ni cadena de custodia. **Se ofrece una re-ejecución acotada** con su addendum y su ventana, cotizada aparte. |
| **Alguien pide acceso al material de otro cliente como «referencia».** | **No.** La confidencialidad de la Fase 2 sobrevive a la finalización del encargo. El material de otro cliente no se usa como ejemplo, ni en formación, ni en material comercial, salvo autorización escrita del cliente concernido. Y si un hallazgo se vio en otro cliente, **no se escribe con el nombre del otro cliente** — se escribe genérico, o no se escribe. |

---

## Nota de cierre

La Fase 2 es la fase en la que el auditor deja de mirar desde fuera y empieza a tocar.
Por eso es la fase donde la metodología se nota: no en lo que encuentra, sino en lo que **no** rompe y en lo que **no** deja atrás.

Tres frases para tener presentes:

> **Demostrar, no dañar.** Un hallazgo probado sin daño es vendible.
> Un hallazgo probado con daño es un incidente con documentación.
> **La capacidad es el hallazgo; la explotación genera la evidencia que hace vendible la remediación.** No al revés: la explotación no es el objetivo, es el instrumento.
> **El daño > el hallazgo.** Si una prueba no se puede hacer sin riesgo para el paciente, el cliente o el servicio, **no se hace**.
> Se reporta como *no verificado*, con la comprobación pendiente, con el responsable y con el plazo.
> Un hallazgo que no se pudo probar no es un hallazgo perdido: es una hipótesis bien escrita, y las hipótesis bien escritas se cierran en el siguiente encargo.

---

*Metodología del playbook de auditoría web.
Confidencial.
Parte del expediente del engagement.
No distribuir fuera de las partes firmantes.*
