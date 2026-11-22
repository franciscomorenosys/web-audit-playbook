# Plantilla — Informe técnico completo

Aquí va la **capa 2** del modelo de tres capas definido en
`00-metodologia/como-presentar-resultados.md`: el documento técnico en detalle
que va al equipo del cliente, al hosting y a la agencia.

> **Estado:** marcador de posición. La estructura está especificada abajo; el
> documento plantilla rellenable se construye a partir del
> `03-casos/clinica-dental-easy/informe-tecnico/`, que **es** un ejemplo real
> y completo de esta plantilla en producción. Cópialo y adapta.

---

## Qué documento va aquí

El entregable largo, con tabla de contenidos por secciones, donde cada hallazgo
tiene evidencia, comando de reproducción, dueño y horas. **Es el documento con
marcaje CONFIDENCIAL: no se envía al dueño no técnico ni a terceros** — va a
quien puede actuar sobre él.

## Estructura esperada

| § | Sección | Qué contiene |
|:-:|---|---|
| **0** | Resumen ejecutivo | Las tres cosas que más importan. Nada más. Un dueño debe poder leer sólo esto y saber si hay que actuar. |
| **1** | Mapeo OWASP/WSTG | Tabla finding → OWASP Top 10 2021 → WSTG v4.2. **Incluye explícitamente qué filas son forzadas y por qué**, y una sección de hallazgos que OWASP **no** cubre con su marco alternativo (NIST/CIS/ATT&CK). |
| **2** | Investigación de CVE | El corazón técnico. Por cada componente: versión detectada, fuente de la versión, tabla de CVE **de la fuente primaria**, y la conclusión. Distingue siempre *pertenencia al rango* de *alcanzabilidad*. |
| **3** | Modelado de phishing / ingeniería social | Cadena de reconocimiento desde datos públicos, mecánica de DMARC, vishing, enumeración. **Incluye las no-recomendaciones explícitas** (ej. el caso Gravatar). |
| **4** | Mapeo de cumplimiento (ley mexicana) | LFPDPPP, LGS + Reglamento de Publicidad, LFPC. Con **cita de artículo y enlace a fuente primaria**. Incluye los refutes explícitos. |
| **5** | Registro de riesgos | Tabla completa con severidad, exposición, dueño. Subsección de **blast radius** y de **lo que el cliente no puede arreglar solo**. |
| **6** | Hoja de ruta de remediación | Tres olas (HOY / ESTE MES / ESTE TRIMESTRE), ordenadas por `rr_por_hora`, con horas y dueño. |
| **7** | Borradores de ticket | Tickets **listos para enviar** al hosting y a la agencia, con pasos y evidencia de reproducción. El dueño no sabe escribirlos. |
| **8** | Brief en lenguaje llano | La **capa 3**, incrustada al final para que el documento sea autocontenido. Sin jerga. |
| **9** | Resumen honesto | Qué se encontró, qué no, qué queda sin verificar, y qué se necesitaría para cerrarlo. |

## Reglas de la plantilla

1. **Cada hallazgo lleva evidencia + comando reproducible.** Lo que no se puede
   reproducir no se afirma.
2. **Contrastar contra fuente primaria** toda versión y todo CVE. Un escáner
   propone; la fuente primaria dispone.
3. **Marcar «no verificado»** lo que requiere acceso interno, y **dar el
   comando/ticket de 60 segundos** para verificarlo.
4. **Incluir la sección «Lo que ya está bien»** — ver
   `00-metodologia/como-presentar-resultados.md` §4.
5. **Separar explícitamente** lo que arregla el cliente / lo que escala al
   hosting / lo que escala a la agencia.
6. **Banner CONFIDENCIAL** arriba, con instrucción de no distribuir.
7. **No inflar severidad.** Si un hallazgo es LOW, es LOW.

## Ejemplo real de referencia

`../../03-casos/clinica-dental-easy/informe-tecnico/` — 11 secciones, 38
filas de riesgo, 3 olas, 3 tickets de escalación y el brief de lenguaje llano.