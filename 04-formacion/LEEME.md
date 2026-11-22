# Formación

Esta carpeta es la **formación del auditor**: el material para formar a un
auditor nuevo o para revisar el método antes de una auditoría.

- **[`guia-de-formacion-auditor.md`](guia-de-formacion-auditor.md)** — la guía
  de formación: perfil de entrada, los 6 módulos (M0–M5), el decálogo de reglas
  innegociables, los errores típicos de un junior, 8 ejercicios con soluciones,
  la rúbrica de evaluación, el plan de sombra y mentoría, el glosario y la
  checklist «listo para firmar su primer RoE». **Se lee en orden.**
- [`01-lab-seguro.md`](01-lab-seguro.md) — el laboratorio: dónde se practica
  todo lo que la guía enseña, sin tocar objetivos ajenos.
- [`02-herramientas-y-python.md`](02-herramientas-y-python.md) — inventario de
  herramientas con la línea de autorización de cada una.
- [`03-modelo-de-negocio-y-legal-mx.md`](03-modelo-de-negocio-y-legal-mx.md) —
  el marco legal y de negocio de México.

## Qué debe contener la guía (alcance previsto)

Contratarse con `00-metodologia/ciclo-de-auditoria.md`, pero en formato
lineal-lectura, no de referencia:

1. **El mindset pasivo-primero** — por qué se empieza por fuentes de terceros
   y no por el objetivo, y qué se gana y qué se pierde con cada modalidad.
2. **Un ejemplo trabajado de las 11 fases** usando el caso `dentaleasy.mx` como
   hilo conductor: qué se hizo, qué salió, qué se corrigió.
3. **Las dos lecciones duras**, en formato de checklist para no reincidir:
   - **(a)** verificar versión/CVE contra **fuente primaria**, no contra el
     string de un escáner (lección de pertenencia vs. alcanzabilidad).
   - **(b)** la semántica de `curl --tlsv1.x` (es un **mínimo**, no exacto) y el
     error de OpenSSL por provider legacy deshabilitado (lección de falso
     positivo TLS).
4. **Calibración de severidad** — los tres ejes (exposición / efecto /
   contexto) y los anti-patrones (no inflar, no calibrar sin mirar el contenido).
5. **RoE y prohibiciones** — un resumen ejecutivo de `reglas-de-autorizacion-y-roe.md`
   y de cuándo escalar.
6. **Cómo escribir el reporte** — las tres capas, ICE vs. RICE, «lo que ya está
   bien» obligatorio.

## Nota

La guía no debe duplicar el contenido de `00-metodologia/`: es el **libro de
formación**, mientras que `00-metodologia/` es la **referencia operativa**.
La guía enlaza en vez de repetir.

> **Estado:** la guía ya está escrita —
> [`guia-de-formacion-auditor.md`](guia-de-formacion-auditor.md). Cubre el
> alcance previsto arriba y añade lo que el playbook tenía pendiente: los
> ejercicios con soluciones, la rúbrica de evaluación y el plan de sombra y
> mentoría. Los seis puntos del «alcance previsto» de arriba siguen siendo la
> referencia de alcance de la guía.