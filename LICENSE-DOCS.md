# Licencia de la documentación — CC BY-NC-ND 4.0

> **Texto canónico:** <https://creativecommons.org/licenses/by-nc-nd/4.0/deed.es>
> **Jurisdicción:** internacional.
> **Copyright:** © 2026 Francisco Moreno.

Esta nota aplica a la **documentación, la metodología y las plantillas** de este
repositorio. El **código** tiene otra licencia: ver [LICENSE](LICENSE) (MIT).

---

## 1. Qué queda cubierto por CC BY-NC-ND 4.0

| Ruta | Contenido |
|---|---|
| `00-metodologia/` | El método: ciclo de auditoría de 11 fases, RoE, exposición de secretos y a ataques, modelo de servicio. |
| `01-tooling/manifiesto-de-herramientas.md` | El catálogo de herramientas (pasiva/activa, licencias, fases). |
| `02-plantillas/` | Las tres capas de entregable: teaser, informe técnico y propuesta comercial. |
| `04-formacion/` | Formación del auditor: laboratorio seguro, toolkit de terceros, marco legal y de negocio en México. |
| `05-plantillas-de-trabajo/` | Formatos de captura rellenables: RoE, addendum de Fase 2, registros de acciones. |
| `README.md`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` | Documentación del proyecto. |

**Excluido de esta licencia:** el código fuente (`01-tooling/scripts/**/*.py`,
`02-plantillas/teaser-report/*.py`, `.github/workflows/**`), que se licencia bajo
**MIT** según el fichero [LICENSE](LICENSE).

---

## 2. Resumen de la licencia (texto no normativo)

> El resumen siguiente **no sustituye** al texto legal. La versión que obliga
> es la que se publica en creativecommons.org, enlazada arriba.

**CC BY-NC-ND 4.0 = atribución + no comercial + sin derivados.**

### 2.1 Puedes

- **Copiar** el material en cualquier medio y formato.
- **Redistribuirlo** (compartirlo, publicarlo, incluirlo en una publicación).
- **Adaptarlo** a tu contexto **siempre que lo publiques bajo esta misma
  licencia** y sin añadir restricciones adicionales (la variante «SA» de CC no
  aplica aquí: no puedes «cerrar» el material).

### 2.2 Debes (condiciones)

- **Atribución (BY):** dar crédito al autor, indicar que hubo modificación si la
  hubo, y enlazar a la licencia. La forma recomendada es:

  > «Metodología de auditoría web derivada de *Web Audit Playbook* de
  > Francisco Moreno, bajo CC BY-NC-ND 4.0.»

- **No comercial (NC):** **no** puedes usar el material, ni su adaptación, para
  fines comerciales. Esto incluye **vender el servicio de auditoría de
  seguridad web a partir de este material**, cobrar por un informe producido con
  esta metodología o ofrecerla como parte de una consultoría de pago.

  Uso no comercial típico: formación interna, autopromoción de un profesional
  independiente, uso académico, mejora de la seguridad de un sitio propio, o
  entregarla al cliente de una auditoría que ya estás PAGANDO (la entrega del
  resultado al cliente es el servicio que el cliente ya contrató; lo que no
  puede hacer es revender la metodología).

- **Sin derivados (ND):** **no** puedes publicar material modificado o
  adaptaciones. Puedes usar el material   internamente y compartirlo **sin
  modificar**. Si necesitas modificarlo (traducirlo, actualizarlo, hacerlo
  encajar con tu propio proceso), no puedes publicar esa versión derivada.

### 2.3 No puedes

- Publicar el material (ni una adaptación) **con fines comerciales**.
- Publicar **obras derivadas** (adaptaciones, traducciones modificadas,
  versiones "actualizadas").
- Aplicar restricciones adicionales sobre el material.
- Usar marcas, logotipos o la identidad del autor de forma que sugiera
  respaldo o afiliación no existente.

---

## 3. Por qué dos licencias

El objetivo de este repositorio es que **el método circule**:

- Un profesional que quiera auditar con RoE firmado, minimized data y
  reporte en tres capas debe poder leerlo, copiarlo y usarlo.
- Un cliente debe poder leer la metodología que le aplicaron.
- Un proveedor que quiera **vender** este servicio **no** debe poder tomar la
  metodología, cambiarla un 5 % y venderla como suya.

De ahí el reparto: **MIT para el código** (máxima libertad de uso, incluidos
los usos comerciales: el código es una herramienta, no el método), y
**CC BY-NC-ND 4.0 para la metodología** (libertad de circulación sin
apropiación comercial).

> **Nota sobre la tensión con MIT.** El fichero `LICENSE` (MIT) describe el
> alcance del código en su nota inicial. Si en algún momento un fichero de
> código y un documento quedaran bajo la misma regla, prevalece la licencia
> específica del documento (CC BY-NC-ND 4.0) para el contenido del documento y
> MIT para el código.

---

## 4. Aviso legal (el que aplica a todo el repositorio)

Este material se publica **sin garantía de ningún tipo**. Los scripts son
herramientas de apoyo y **no** sustituyen el criterio profesional ni la
autorización escrita del propietario del sistema auditado.

**No auditamos, pentesteamos ni exploramos sistemas de información sin
autorización escrita del propietario.** Ver [SECURITY.md](SECURITY.md) para la
política completa y el flujo de reporte responsable.

---

## 5. Contacto

Para consultas sobre la licencia o para pedir una autorización concreta
(escrita): abre un issue en <https://github.com/franciscomorenosys/web-audit-playbook/issues>
o escribe al autor. No se responden consultas de auditoría por issue: un
issue no es un encargo.
