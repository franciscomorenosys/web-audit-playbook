/**
 * Vista EXPOSICIÓN A ATAQUES.
 *
 * Tres bloques: el checklist de 18 IoC con su estado, la tabla «afirmación vs.
 * lo que la evidencia sostiene» y la sección «LO QUE NO PUEDO VER».
 * La honestidad epistémica es parte del producto: la sección no verificable
 * no es una nota al pie, es un bloque de primer nivel.
 */

import { api } from "../data.js";
import { el, panel, seccion, vacio } from "./comunes.js";

/** Color y clase según el estado del IoC. */
function estiloEstado(estado) {
  const e = String(estado || "").toLowerCase();
  if (e === "confirmado") return { texto: "CONFIRMADO", clase: "critico" };
  if (e === "indicador pendiente") return { texto: "INDICADOR PENDIENTE", clase: "medio" };
  if (e === "sin indicador") return { texto: "SIN INDICADOR", clase: "ok" };
  if (e === "no evaluable") return { texto: "NO EVALUABLE", clase: "info" };
  return { texto: String(estado || "—").toUpperCase(), clase: "info" };
}

/** Renderiza la vista. */
export async function render(contenedor) {
  const datos = await api("/api/iocs");
  const items = datos.items || [];

  const confirmados = items.filter((i) => i.estado === "confirmado").length;
  const pendientes = items.filter((i) => i.estado === "indicador pendiente").length;
  const sinIndicador = items.filter((i) => i.estado === "sin indicador").length;
  const noEvaluables = items.filter((i) => i.estado === "no evaluable").length;

  const resumen = el("div", { className: "mosaico", estilo: "margin-bottom:var(--s-3)" });
  resumen.append(
    el(
      "div",
      { className: "metrica metrica--rojo" },
      el("div", { className: "metrica__valor", texto: String(confirmados) }),
      el("div", { className: "metrica__etiqueta", texto: "confirmados" }),
    ),
    el(
      "div",
      { className: "metrica metrica--ambar" },
      el("div", { className: "metrica__valor", texto: String(pendientes) }),
      el("div", { className: "metrica__etiqueta", texto: "pendientes" }),
    ),
    el(
      "div",
      { className: "metrica metrica--verde" },
      el("div", { className: "metrica__valor", texto: String(sinIndicador) }),
      el("div", { className: "metrica__etiqueta", texto: "sin indicador" }),
    ),
    el(
      "div",
      { className: "metrica" },
      el("div", { className: "metrica__valor", texto: String(noEvaluables) }),
      el("div", { className: "metrica__etiqueta", texto: "no evaluables" }),
    ),
  );

  // -- checklist ------------------------------------------------------------- //
  const lista = el("div", { className: "checklist" });
  for (const item of items) {
    const info = estiloEstado(item.estado);
    lista.append(
      el(
        "div",
        { className: "check" },
        el("div", { className: "check__num", texto: String(item.numero).padStart(2, "0") }),
        el(
          "div",
          { className: "check__cuerpo" },
          // El estado va en la misma línea que el indicador: en una columna
          // fija a la derecha quedaba a ~950 px de su propio texto, y a
          // 390 px el chip se salía de la celda y lo recortaba el panel.
          el(
            "div",
            { className: "check__cabecera" },
            el("div", { className: "check__titulo", texto: item.indicador }),
            el(
              "div",
              { className: "check__estado" },
              el("span", { className: `etiqueta etiqueta--${info.clase}`, texto: info.texto }),
            ),
          ),
          el("div", { className: "check__detalle", texto: `Dónde se busca: ${item.donde}` }),
          el("div", { className: "check__detalle", texto: `Severidad si se confirma: ${item.severidad}` }),
        ),
      ),
    );
  }

  const nota = el(
    "p",
    { className: "tenue", estilo: "font-size:var(--fs-micro);margin:var(--s-2) 0 0" },
    datos.mensaje || "",
  );

  const panelChecklist = panel(
    "Checklist de indicadores de compromiso",
    "18 indicadores · módulo de exposición a ataques",
    el("div", {}, items.length ? lista : vacio("Sin checklist", "No hay IoC que mostrar."), nota),
    { sinCuerpo: items.length > 0 },
  );

  // -- afirmaciones ---------------------------------------------------------- //
  const afirmaciones = el("div", { className: "afirmaciones" });
  afirmaciones.append(
    el("div", { className: "afirmaciones__cabecera", texto: "Afirmación que NO se sostiene" }),
    el("div", { className: "afirmaciones__cabecera", texto: "Lo que la evidencia sí sostiene" }),
    el("div", { className: "afirmaciones__cabecera", texto: "Fuente mínima" }),
  );
  for (const fila of datos.afirmaciones || []) {
    afirmaciones.append(
      el("div", { className: "afirmaciones__no", texto: fila[0] }),
      el("div", { className: "afirmaciones__si", texto: fila[1] }),
      el("div", { className: "afirmaciones__fuente", texto: fila[2] }),
    );
  }

  const panelAfirmaciones = panel(
    "Afirmación vs. lo que la evidencia sostiene",
    "la redacción correcta",
    afirmaciones,
    { sinCuerpo: true },
  );

  // -- lo que no se puede ver -------------------------------------------------- //
  const noVerificable = el("div", { className: "componentes" });
  for (const fila of datos.no_verificable || []) {
    noVerificable.append(
      el(
        "div",
        { className: "componente", estilo: "grid-template-columns:220px minmax(0,1fr)" },
        el(
          "div",
          {},
          el("div", { className: "componente__nombre", texto: fila[0] }),
        ),
        el(
          "div",
          { className: "componente__detalle", estilo: "font-size:var(--fs-small)" },
          fila[1],
        ),
        el("div", {}),
      ),
    );
  }

  const panelNoVerificable = panel(
    "LO QUE NO PUEDO VER",
    "lo que ningún auditor externo sabe",
    el(
      "div",
      {},
      el(
        "p",
        { className: "tenue", estilo: "font-size:var(--fs-small)" },
        "Cinco razones por las que el número de ataques NO se puede contar desde fuera. " +
          "No son excusas: son la frontera de lo que la evidencia puede sostener.",
      ),
      noVerificable,
    ),
  );

  // -- frase de cierre --------------------------------------------------------- //
  const panelCierre = panel(
    "Frase de cierre de la sección",
    "obligatoria en el informe",
    el("blockquote", { className: "u-bloque" }, datos.frase_cierre || ""),
  );

  contenedor.append(
    el("div", { className: "revelar" }, resumen),
    seccion("Indicadores de compromiso", panelChecklist),
    seccion("Redacción", panelAfirmaciones),
    seccion("Límites de la observación", panelNoVerificable, panelCierre),
  );
}
