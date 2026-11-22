# Loop de corrección — cómo la segunda mirada alimenta la propuesta

Este documento convierte la revisión externa en un proceso **mecánico**, no en
una lectura parcial. La idea: cada tipo de observación que devuelve el revisor
tiene un destino exacto en el material de entrega. Sin este mapa, la revisión se
queda en sugerencias y no cambia nada.

---

## 1. El principio

> **La segunda mirada no se exhibe en la propuesta. Se aplica a la propuesta.**

El cliente no necesita saber que hubo un borrador. Necesita un documento
correcto. La única excepción donde la revisión sí se menciona es cuando produce
un **hallazgo nuevo y sustentado** o un **cambio de calibración** — porque eso
mejora lo que el cliente recibe, y en ese caso se comunica como parte del
trabajo, no como proceso.

Esto es lo contrario de "revisión por pares certificada", que es lo que hacen las
firmas grandes. Ellos pueden pagarlo porque su cliente es corporativo y exige
trazabilidad. **Tú no puedes:** un dueño de clínica no sabe lo que es un peer
review, y si lo nombras como IA se lee como "un robot lo escribió". Se queda
como calidad interna.

**Excepción preparada:** el bloque `Verificación independiente del diagnóstico`
ya está insertado en el HTML del teaser, en la sección 9, **desactivado**
(`display:none`). Ver §4.

---

## 2. Mapa: tipo de observación → destino exacto

| Tipo de observación del revisor | A dónde va | Cómo |
|---|---|---|
| **"Este dato es incorrecto"** (versión, CVE, artículo de ley, cifra de IBM) | Informe técnico **y** teaser, si aparece | Corregir en `INFORME-TECNICO-SANITIZADO.md` → propagar al original → si la cifra está en el teaser, corregir también en `teaser-dental-easy.html` → `build.py` → `verify.py` |
| **"Esta conclusión no se sostiene con la evidencia"** | Informe técnico | Reescribir el hallazgo o añadir la evidencia que falta (un comando más, una observación adicional). Si no se puede sostener, **bajar de severidad o retirar** |
| **"El impacto está mal calibrado"** | Registro de riesgos → **y el teaser, porque de ahí sale el gráfico** | Recalcular el bucket de severidad (derivado del Impacto, I=5→Crítico) → `make-charts.py` → `build.py`. **El gráfico del teaser se desincroniza solo si no lo regeneras** |
| **"Falta una superficie que auditaste"** | Metodología y registro | Auditar esa superficie **antes** de que el cliente la mentionte. Una revisión que encuentra un agujero real es oro: lo cierras antes de la reunión |
| **"La redacción del teaser es engañosa"** | Teaser §5 y §8 | Ajustar el lenguaje. **Ojo:** el teaser está diseñado para withhold detail. Si la crítica es "es*vago*", la respuesta correcta es Usually **no** cambiar — pero **sí** cambiar si la criticism es "promete más de lo que entrega" |
| **"El pricing está mal"** | Teaser §7 | Decisión comercial tuya. El benchmark ya está en el playbook. Si decides subir $8,000 → $12,000, es un cambio de un número + rebuild |
| **"Falta un ángulo legal mexicano"** | Informe §4 + teaser §4 | Verificar contra fuente primaria antes de meterlo. Si es un ángulo nuevo y sólido, **súbelo a Crítico** en el registro y súmelo al teaser §4 |
| **"Hay un riesgo que no registraste"** | Registro de riesgos | Agregar fila con L, I, owner, effort. Si el owner es 🔒, va también al ticket de escalamiento |

---

## 3. El ciclo, paso a paso

```
1. Chat nuevo → pegar 00-CONTEXTO.md
2. Subir 01-INFORME / 02-TEASER / 03-METODOLOGIA
3. Pegar 04-PREGUNTAS → Bloque A (factual). Si no sale limpio, parar.
4. Bloques B (coherencia), C (riesgo), D (evidencia), E (comercial), F (lo que falta)
5. Follow-ups: "los 3 cambios antes de enviar", "qué te haría desconfiar",
   "qué le preguntarías al cliente que no está en mis documentos"
6. ↓ CONSOLIDAR en una tabla: observación → tipo (mapa §2) → destino
7. Corregir el INFORME (canónico) primero, siempre
8. Propagar al teaser SOLO lo que cambió de número o de afirmación
9. make-charts.py → build.py → verify.py
10. Releer el PDF entero una vez. Si algo no se sostiene al releer, se corta.
```

**Paso 6 es el que importa.** Sin la tabla de consolidación, la revisión se
desvanece. Con ella, son 15–25 ediciones mecánicas.

---

## 4. Sobre exhibir la revisión (decisión tuya)

El bloque está en `teaser-dental-easy.html`, sección 9, antes de la nota final.
Para habilitarlo: cambia `style="display:none"` por `style="display:block"` y
completa el texto entre corchetes.

**Argumento a favor:** en un mercado donde casi todos envían un PDF de checklist,
que alguien audite tu trabajo es un diferenciador real, y lo puedes cobrar en el
Nivel 3 (Continuidad).

**Argumento en contra:** si nombras a quién revisó y fue una IA, un cliente técnico
va a descubrir rápido que "revisión por un tercero" era un modelo de lenguaje. Y un
dueño de clínica no entiende el concepto. **El riesgo reputacional de que te
des覆露 es mayor que el beneficio de comercial.**

**Mi recomendación: no lo actives.** Aplícalo, y en su lugar sube la **calidad
del contenido**. Ese es el retorno real de la segunda mirada.

---

## 5. Cuándo repetir este loop

El loop está diseñado para correr **una vez por cliente nuevo**, en la fase de
"borrador interno", antes de generar el teaser.

Si en 6 meses ya hiciste 5 auditorías, el retorno se invierte: para entonces lo
que necesitas no es una segunda mirada, es **automatizar** (el `ciclo-de-auditoria.md`
tiene las 11 fases ya descompuestas para eso).

Una sugerencia de cadencia: **repite el loop completo con 1 de cada 3 clientes.**
Con los otros 2, aplica solo el bloque A (factual) — que es el que atrapa errores
que te habrían costado credibilidad frente al cliente.
