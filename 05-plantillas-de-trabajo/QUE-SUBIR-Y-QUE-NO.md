# Qué subir y qué NO subir a un LLM externo

> Regla general: **no saques nada de este proyecto a un servicio de terceros sin
> revisar la lista.** Un LLM externo es un procesador de datos. Subir el expediente
> equivocado es un incidente de datos, no un error de tool.

---

## 🚫 NO SUBIR NUNCA

| Carpeta / archivo | Por qué |
|---|---|
| `03-casos/clinica-dental-easy/evidencia/` (**los 99 archivos**) | **71 de 99 contienen identificadores sensibles.** HTML descargados con el `From:` del spammer, su email y URL; `users.json` con el slug de usuario y el hash gravatar; `author2.html` con el segundo usuario; `adm.html` y `wp-login.html`; dumps de DNS con los NS del hosting; las páginas con los números de WhatsApp; `findings2.tsv` con los usernames |
| `03-casos/.../informe-tecnico/dentaleasy-mx-security-risk-report-2026-10-22.md` (**el original**) | Tiene nombre del cliente, dominio, IP, correos, teléfonos, URL del Apps Script, nombre de la agencia **y los 20 dominios de los demás clientes de la agencia** que se destinationaron durante el recon |
| `05-plantillas-de-trabajo/MAPA-DE-REDACCION.md` | Es la **clave inversa** del sanitizado. Si subes el sanitizado y el mapa juntos, la redacción no sirve de nada |
| `03-casos/clinica-dental-easy/README.md` | Identifica al cliente |
| `evidence/audit2/crtsh_fjgrafico.json`, `cdx_fj.json` | Listados completos de la cartera de la agencia |

**El error de fondo que estás evitando:** los 20 dominios de otros clientes de la
agencia **no son del cliente que te contrató.** Subirlos a un LLM externo es
disclosure de información de terceros que no autorizó nadie. Y también es un
problema comercial: si uno de esos 20 clientes se entera de que su nombre circula
en tu proyecto, la relación con la agencia se complica.

---

## ✅ SÍ PUEDES SUBIR

| Archivo | Por qué es seguro |
|---|---|
| `02-plantillas/teaser-report/Evaluacion-Seguridad-Clinica-Dental-Easy.pdf` | Ya está sanitizado por diseño. Verificado con grep en 4 superficies: texto extraído, bytes crudos, metadatos y HTML fuente — 0 coincidencias de CVEs, versiones, rutas, comandos, herramientas, teléfonos, correos, nombres de agencia o endpoint |
| `03-casos/.../informe-tecnico/INFORME-TECNICO-SANITIZADO.md` | Sustituye a los identificadores por placeholders estables. Verificado: **77/77 objetivos literales en 0 coincidencias**, y conserva el 100% del sustancia técnica (122/122 tokens confirmados: CVEs, CVSS, OWASP, WSTG, artículos de ley, UMA, los IDs del registro, los tickets, las 3 olas) |
| `00-metodologia/*.md` (3 docs) | Metodología propia. Sin datos del cliente |
| `01-tooling/manifiesto-de-herramientas.md` | Catálogo de herramientas públicas. Sin datos del cliente |
| `02-plantillas/teaser-report/teaser-dental-easy.html` | El HTML fuente del PDF. Contiene los mismos números, sin identificadores. **Revísalo si prefieres no compartir el fuente** |
| `04-formacion/*.md` (3 docs) | Formación y modelo de negocio. Sin datos del cliente |
| `05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv` | Tiene IDs de hallazgo y comandos de reproducción del caso real. **Revísalo** — si los comandos contienen rutas o versiones, es material técnico del cliente |
| `05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md` | Plantilla de ejemplo |

---

## ⚠️ REVISAR ANTES (contienen datos del caso real)

| Archivo | El riesgo |
|---|---|
| `05-plantillas-de-trabajo/registro-de-acciones.EXAMPLE.csv` | Sus 5 filas son hallazgos reales (F01/F25/F32/F08/F24) con comandos de reproducción contra el sitio del cliente. **No lo subas sin editarlo**, o edítalo a genérico |
| `05-plantillas-de-trabajo/MAPA-DE-REDACCION.md` | Clave inversa. **Nunca** |

---

## Configuración recomendada en ChatGPT

**Opción A — Projects (recomendada, gratis en Plus):**
1. Crea un Project: "Consultoría · Auditorías web"
2. Sube los archivos sanitizados como **Knowledge del proyecto** (quedan disponibles en todas las conversaciones)
3. En `CONTEXTO-PARA-LLM.md` **pon las instrucciones del proyecto** en el campo de instrucciones personalizadas — así se aplican siempre
4. En cada revisión nueva, solo subes lo que cambió y pegas las preguntas

**Opción B — Custom GPT (si repites esto seguido):**
1. Crea un GPT con las instrucciones = el bloque 1 + 4 de `CONTEXTO-PARA-LLM.md`
2. Sube como Knowledge: el informe sanitizado + el ciclo de auditoría + el manifiesto de herramientas
3. Queda como un "revisor de auditoría" que puedes consultar para cada cliente nuevo, cambiando solo el sanitizado del caso

**Opción C — sin cuenta premium:**
Sube los archivos uno por uno en un chat nuevo, pega el contexto primero, y
pregunta por bloque. Funciona, solo que no hay memoria entre sesiones.

---

## Secuencia recomendada

```
1.  Chat nuevo
2.  Pega CONTEXTO-PARA-LLM.md          ← SIEMPRE primero
3.  Sube: INFORME-TECNICO-SANITIZADO.md
4.  Sube: Evaluacion-Seguridad-Clinica-Dental-Easy.pdf
5.  Sube: ciclo-de-auditoria.md
6.  Pega PREGUNTAS-PARA-REVISION.md, Bloque A
7.  Espera la respuesta. Sigue con Bloques B…F en mensajes separados.
8.  Follow-ups: los 4 del final de PREGUNTAS-PARA-REVISION.md
```

**Sube máximo 4–5 archivos por revisión.** Con más, el modelo diluye la atención y
las respuestas se vuelven genéricas — que es exactamente el resultado que no quieres.

---

## Checklist antes de cada revisión

- [ ] ¿Subí solo archivos de la lista **✅**?
- [ ] ¿Revisé el CSV de acciones y lo edité si venía en el paquete?
- [ ] ¿**NO** subí `MAPA-DE-REDACCION.md`?
- [ ] ¿**NO** subí la carpeta `evidencia/`?
- [ ] ¿El contexto va primero?
- [ ] Voy a hacer las preguntas por bloques, no todas de golpe
