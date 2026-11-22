# Plantilla — Propuesta comercial

Aquí va el **material de venta**: la propuesta que se envía a un cliente nuevo
para contratar la auditoría, y la narrativa que sostiene la oferta del teaser.

> **Estado:** marcador de posición. La estructura está especificada abajo.

---

## Qué va aquí

La propuesta que precede a la auditoría y que la cierra en un contrato
siguiente. Nota la distinción importante:

- El **teaser** (`../teaser-report/`) es *resultado de una auditoría ya hecha*,
  usado como demostración de capacidad en una venta nueva.
- La **propuesta** es lo que envías *antes* de auditar, para que te contraten.

## Estructura esperada

| Bloque | Contenido |
|---|---|
| **1. Portada** | Cliente, fecha, confidencialidad, nombre del consultor. |
| **2. El problema, en lenguaje del cliente** | Qué pasa cuando un sitio de clínica/consultorio está mal: pérdida de confianza, riesgo legal, brecha de datos. **Sin jerga, sin CVEs, sin fear.** Engancha con el costo del negocio, no con el pentest. |
| **3. Qué es una revisión pasiva de seguridad** | Qué incluye y —crítico— **qué NO incluye** (no es pentest; no tocamos sistemas; todo GET/HEAD con autorización). **Ser explícito aquí genera confianza y evita sorpresas.** |
| **4. Metodología (resumen)** | Las fases, en lenguaje llano. Muestra rigor sin jerga. |
| **5. Entregables** | Lista de los tres documentos que recibirá (teaser, informe técnico para su equipo, brief de lenguaje llano). |
| **6. Plazos y esfuerzo** | Duración, hitos, qué se necesita del cliente. |
| **7. Inversión** | Precio. Si aplica, escalonado (básico / completo + re-test). |
| **8. Qué necesita el cliente de nosotros** | El RoE firmado, un contacto técnico, y acceso a lo que corresponda. |
| **9. Confidencialidad** | Cómo se maneja la evidencia y los datos encontrados. |

## Reglas de la propuesta

1. **Vende el riesgo de negocio y el cumplimiento, no los scary CVEs.** El
   dueño de una clínica no quiere oír de CVE-2026-87902; quiere oír que sus
   datos de pacientes están expuestos y que una frase de su web puede_costarle
   una multa.
2. **Sé explícito sobre los límites desde el principio.** Una propuesta que
   promete una «prueba de penetración» cuando ofreces una revisión pasiva es un
   problema legal esperando.
3. **Separa lo que arregla el cliente de lo que escala a terceros.** Una buena
   propuesta lo dice antes de cobrar, no después.
4. **La misma severidad/método que en el informe** — ver
   `00-metodologia/como-presentar-resultados.md`.
5. **Cierra con una reunión, no con un contrato.** Invita a una llamada de 30
   minutos para revisar el teaser y decidir.

## Referencias

- Marco de resultados y precios de referencia: `../../03-casos/clinica-dental-easy/`.
- Doctrina de severidad y las tres capas: `../../00-metodologia/como-presentar-resultados.md`.
- RoE que se firma antes de empezar: `../../05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md`.