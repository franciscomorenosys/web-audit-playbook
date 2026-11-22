/**
 * Vista REGISTRO DE ACCIONES: el CSV de Fase 2 como flujo de terminal.
 *
 * Las filas con `datos_tocados != ninguno` se resaltan: son las únicas que
 * dejaron huella en el sistema del cliente.
 */

import { api } from "../data.js";
import { marcaTiempo } from "../format.js";
import { el, etiqueta, panel, vacio } from "./comunes.js";

/** Renderiza la vista. */
export async function render(contenedor) {
  const datos = await api("/api/actions");
  const items = datos.items || [];

  const conDatos = items.filter((i) => {
    const valor = String(i.datos_tocados || "").trim().toLowerCase();
    return valor && valor !== "ninguno" && valor !== "none";
  }).length;

  const mosaico = el("div", { className: "mosaico", estilo: "margin-bottom:var(--s-3)" });
  mosaico.append(
    el(
      "div",
      { className: "metrica metrica--ambar" },
      el("div", { className: "metrica__valor", texto: String(items.length) }),
      el("div", { className: "metrica__etiqueta", texto: "acciones" }),
    ),
    el(
      "div",
      { className: "metrica metrica--rojo" },
      el("div", { className: "metrica__valor", texto: String(conDatos) }),
      el("div", { className: "metrica__etiqueta", texto: "tocaron datos" }),
    ),
    el(
      "div",
      { className: "metrica metrica--verde" },
      el("div", {
        className: "metrica__valor",
        texto: String(items.filter((i) => i.rollback_hecho).length),
      }),
      el("div", { className: "metrica__etiqueta", texto: "con rollback" }),
    ),
  );

  if (!items.length) {
    contenedor.append(
      el("div", { className: "revelar" }, mosaico),
      panel(
        "Registro de acciones",
        datos.fuente || "sin CSV",
        vacio("Sin registro de acciones", datos.mensaje || "No hay registro-de-acciones-fase-2.csv."),
      ),
    );
    return;
  }

  const flujo = el("div", { className: "flujo" });
  for (const fila of items) {
    const datosTocados = String(fila.datos_tocados || "").trim().toLowerCase();
    const tocados = Boolean(datosTocados) && datosTocados !== "ninguno" && datosTocados !== "none";

    flujo.append(
      el(
        "div",
        { className: "flujo__evento", attrs: { "data-tocado": String(tocados) } },
        el(
          "div",
          { className: "flujo__cabecera" },
          el("span", { className: "flujo__hora", texto: marcaTiempo(fila.fecha_hora) }),
          el("span", { className: "flujo__id", texto: fila.id || "" }),
          el("span", { className: "flujo__titulo", texto: fila.tecnica || "sin técnica" }),
          etiqueta(String(fila.resultado || ""), resultadoClase(fila.resultado)),
          etiqueta(String(fila.severidad || ""), severidadClase(fila.severidad)),
          etiqueta(String(fila.estado || ""), "info"),
        ),
        linea("Host", fila.host),
        linea("Endpoint", fila.endpoint),
        linea("Método", fila.metodo_http),
        linea("Cuenta", `${fila.cuenta_usada || "—"} (${fila.tipo_cuenta || "—"})`),
        linea("Datos tocados", fila.datos_tocados, tocados),
        linea("Footprint", fila.footprint),
        linea("Rollback", fila.rollback_hecho),
        linea("Evidencia", fila.evidencia_archivo),
        fila.notas ? linea("Notas", fila.notas) : null,
      ),
    );
  }

  const panelFlujo = panel(
    "Acciones de Fase 2",
    `${datos.fuente || "registro-de-acciones-fase-2.csv"} · sha256[:12] ${datos.hash_archivo || "—"}`,
    el("div", { className: "panel__cuerpo" }, flujo),
  );

  contenedor.append(
    el(
      "div",
      { className: "revelar" },
      mosaico,
      el(
        "p",
        { className: "tenue", estilo: "font-size:var(--fs-micro)" },
        "Las líneas con borde ámbar tocaron datos. El registro es la prueba de que la " +
          "auditoría se mantuvo dentro de la escalera de la doctrina: prueba sin daño, " +
          "con footprint declarado y rollback cuando procede.",
      ),
    ),
    panelFlujo,
  );
}

/** Línea clave/valor del flujo. */
function linea(clave, valor, destacado = false) {
  return el(
    "div",
    { className: "flujo__linea" },
    el("b", { texto: clave }),
    el("span", {
      className: destacado ? "ambar" : "",
      texto: valor === null || valor === undefined || valor === "" ? "—" : String(valor),
    }),
  );
}

/** Clase de etiqueta según el resultado de la acción. */
function resultadoClase(valor) {
  const v = String(valor || "").toUpperCase();
  if (v === "CONFIRMADO") return "critico";
  if (v === "REFUTADO") return "ok";
  return "info";
}

/** Clase de etiqueta según la severidad de la acción. */
function severidadClase(valor) {
  const v = String(valor || "").toLowerCase();
  if (v === "alta" || v === "critica" || v === "crítica") return "alto";
  if (v === "media" || v === "media") return "medio";
  return "info";
}
