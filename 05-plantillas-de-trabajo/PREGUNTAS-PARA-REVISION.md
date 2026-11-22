# Preguntas para la revisión — pegar DESPUÉS de subir los artefactos

> Orden: (1) `CONTEXTO-PARA-LLM.md` → (2) subir artefactos → (3) esto.
>
> Cada bloque es una pregunta independiente. Pégalos **uno por uno** en mensajes
> separados si quieres respuestas limpias; si los pegas todos juntos, el modelo
> suele repartirse la atención y las respuestas se vuelven superficiales.

---

## Bloque A — Auditoría factual (el más importante)

> Revisa el **informe técnico sanitizado** y el **teaser PDF** que subí. Necesito
> una lista de todo lo que afirmo que es un hecho y no se sostiene con la evidencia
> que presento.
>
> Para cada punto: (a) qué afirmo, (b) por qué crees que no se sostiene,
> (c) qué evidencia mínima lo resolvería.
>
> Prioriza verificar específicamente:
> 1. Las versiones de software que detecté y si mi razonamiento sobre CVE-2026-87902
>    (que 5 de 6 versiones cacheadas caen en rango) es correcto. ¿Confirmas el
>    rango de versiones afectadas contra la fuente oficial? ¿Qué se me está
>    escapando sobre el *precondition* que el advisory menciona?
> 2. Que CVE-2026-109618/-109619 (PHP, publicados 2026-10-21) sean los mismos que
>    la prensa llama "PHP2Shell". ¿Encuentras alguna discrepancia entre lo que dice
>    el advisory de php.net y lo que reportan los medios?
> 3. Mi cadena de DMARC: SPF `~all` + DKIM en un solo selector + sin registro DMARC
>    → ¿es correcto que un atacante pueda enviar correo con el `From:` visible de la
>    clínica y que los receptores no tengan instrucción alguna de actuar? ¿Hay algún
>    matiz sobre el alineamiento (relaxed vs strict) o sobre el comportamiento de
>    Gmail/Outlook que esté simplificando de más?
> 4. La composición de 320,000 UMA × $117.31 = $37,539,200 (art. 59 fr. III), y que
>    se duplica para datos sensibles (fr. IV). ¿El doble aplica al mismo supuesto de
>    hecho o son infractions distintas? ¿Estoy mezclando dos$(\$)$~\frac{}{}$~fracciones en una sola fila de tabla?
> 5. Que el art. 19 de la LFPDPPP 2025 obligue a notificar **a los pacientes** de
>    inmediato, y que la obligación de notificar a la autoridad con plazo de 30 días
>    de la ley de 2010 ya no exista. ¿Confirmas? ¿Qué pasa con el Reglamento, que
>    sigue pendiente y podría reintroducirla?
> 6. Que la LGS art. 83 aplique a un sitio web por ser "publicidad". Ese es el
>    argumento más importante de la sección legal y necesito saber si es sólido o si
>    estoy estirando la norma.
>
> Sé escéptico con las cifras de la IBM: cito la regional de América Latina como si
> fuera México. ¿Es eso defendible en una reunión con un cliente, o debería quitarlo?

---

## Bloque B — Coherencia entre los dos documentos

> Tengo dos documentos con propósitos distintos y necesito que verifiques que **no se
> contradigan**. El teaser es lo que ve el cliente; el informe técnico es lo que me
> sirvo para la reunión.
>
> Revisa: ¿algún número del teaser no cuadra con el informe? ¿afirmo en el teaser
> algo que el informe no sostenga? ¿hay una categoría de riesgo que aparece en uno y
> no en el otro? ¿el veredicto por dominio (3 CRÍTICO / 3 ATENCIÓN) se deriva de algo
> o es arbitrario?
>
> Y al revés: ¿el informe técnico tiene hallazgos que **nunca se mencionan** en el
> teaser y que deberían? Dímelo, porque si el cliente siente que le escondimos
> material, la reunión se cae.

---

## Bloque C — Juicios de riesgo (donde más me interesa tu opinión)

> El registro de riesgos usa **Score = Likelihood × Impact** (1–5 cada uno) y lo
> presento con una escala de reducción-de-riesgo-por-hora (RR/hr = Score ÷ horas de
> remediación). Elegí ICE en vez de RICE porque **no hay analítica instalada**, así que
> "Reach" no es calculable y RICE forzaría a inventarlo.
>
> Evalúa:
> 1. ¿Es la elección correcta? ¿O hay un framework que funcione mejor cuando no
>    existe línea base de tráfico?
> 2. ¿El score L×I es adecuado? En seguridad, el impacto suele ponderar más que la
>    probabilidad, y L×I da el mismo peso a ambas. ¿Estás de acuerdo con eso?
> 3. ¿La escala de RR/hr no induce a priorizar mal? Un fix trivial con score bajo
>    puede terminar en la cima de la cola. ¿Cómo lo corregirías?
> 4. ¿Los 12 ítems marcados como 🔒 (escalación: hosting o agencia, no el cliente)
>    son realmente no accionables por el cliente, o estoy leyendo mal la frontera?
> 5. ¿Hay riesgos **que no registré**? En particular: exposure a través del CRM/third
>    parties, riesgo de suplantación de la clínica en Google Business Profile, riesgo
>    de ingeniería social contra el personal, y compromiso del sitio de la agencia web
>    como vía indirecta.

---

## Bloque D — Calidad de la evidencia

> ¿La evidencia que presento es **suficiente** para sostener lo que afirmo, o estoy
> saltando conclusiones? En particular:
>
> 1. Afirmo que el sitio no tiene redirect HTTP→HTTPS. ¿Qué más haría falta para
>    estar seguro, y es mi evidencia suficiente?
> 2. Afirmo que la capa de caché sirve 404 como 200 (soft-404 poisoning). ¿Mi prueba
>    es concluyente o necesito otra observación para que un sysadmin la confirme?
> 3. Afirmo que el sitio tiene **cero** rastreadores y **cero** cookies de terceros.
>    Es una buena noticia (no trackean a los pacientes) pero también significa que
>    **no hay medición de ningún tipo**. ¿Estoysqpresentando esa ausencia como
>    hallazgo y a la vez assertion de "no perdemos nada por no medir"? ¿Hay una
>    inconsistencia ahí?
> 4. Mi §"Lo que ya está bien" lista cinco fortalezas reales. ¿Son verificables por
>    el cliente con las herramientas públicas que menciona, o son afirmaciones que
>    no puede comprobar?

---

## Bloque E — Estructura del teaser y comercial (esta es la que más me cuesta)

> El teaser tiene 13 páginas: portada con 4 cifras ancla → alcance → veredicto por
> dominio + distribución de severidad → costo de brecha → exposición legal → 6 áreas
> de riesgo en lenguaje llano → lo que ya está bien → 3 niveles de servicio con
> precios → invitación a reunión → fuentes y metodología.
>
> 1. **¿Es esto convincente para un dueño de clínica que no es técnico?** ¿Dónde
>    perdería interés o se sentiría engañado?
> 2. La §"Exposición legal inmediata" es la sección más fuerte (multas de $37.5 M
>    verificables). ¿Estoy arriesgando que el cliente piense "me están
>    asustando para vender"?
> 3. ¿Debería el **costo de brecha de la IBM** estar en el documento? Es de
>    organizaciones enterprise y no hay desglose por pyme ni por México. ¿Se sostiene
>    o se ve como número inflado?
> 4. Los tres niveles están a $8,000 / $45,000–85,000 / desde $12,000 al mes, con el
>    primero acreditable al 100% contra los otros dos. ¿La estructura de precios se
>    entiende en 10 segundos? ¿Hay riesgo de que el cliente solo quiera el nivel 1
>    barato y se lleve el detalle técnico por $8,000?
> 5. **¿Debería subir el Diagnóstico a $12,000?** Mi benchmark dice que el "punto
>    dulce" del SMB mexicano para un assessment completo es $12,000–30,000, y que yo
>    estoy 33–60% abajo. MiFear es dos cosas: (a) que a $8,000 me subestime, (b)
>    que la clínica no lo alcance. ¿Qué harías?

---

## Bloque F — Lo que NO sé

> Termina con lo que **crees que me falta ver** en este trabajo.
>
> - ¿Qué superficie técnica no audité y debería? (Enumeré: superficie REST
>   alternativa, rutas sensibles, enumeración de usuarios, posture de correo,
>   infraestructura pasiva, historial, transporte.)
> - ¿Qué marco de referencia me estoy perdiendo? (Revisé OWASP Top 10 2021, WSTG
>   v4.2, y para lo que OWASP no cubre: NIST SP 800-52r2, SP 800-177, CIS Controls v8,
>   MITRE ATT&CK. ¿Falta algo? ¿OWASP ASVS, PTES, NIST SP 800-115?)
> - ¿Hay un ángulo legal mexicano que no toqué? (LFPDPPP 2025, LGS art. 83,
>   Reglamento de Publicidad, LFPC art. 50, y el marco de cibercrimen.)
> - ¿Qué le harías a esta línea base para convertirla en un **sistema repetible** que
>   me permita auditar un cliente nuevo en un día en vez de en cinco?

---

## Follow-ups que siempre funcionan

Después de las respuestas, estas preguntas de seguimiento renden mucho:

- *"De todo lo que dijiste, ¿cuáles son los **tres** cambios que harías antes de
  enviarle esto al cliente? Ordénalos por daño que evitan."*
- *"¿Hay algo que hice **demasiado bien** y que debería simplificar? Estoy pagando
  el costo de un proceso que unConsultor independiente no necesitaría."*
- *"¿Qué le preguntarías al cliente en la reunión que no aparece en ninguno de mis
  documentos?"*
- *"Si fueras el cliente y recibieras esto, ¿qué te haría desconfiar?"*
