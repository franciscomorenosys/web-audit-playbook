/**
 * Vista API SURFACE: endpoints descubiertos en el material del cliente.
 *
 * La columna «PII» es una **clasificación por la ruta**, no una prueba de que
 * el endpoint devuelva datos personales: eso requiere probarlo, y probarlo
 * está fuera del RoE por defecto.
 */

import { api } from "../data.js";
import { compacto } from "../format.js";
import { el, etiqueta, panel, tabla, vacio } from "./comunes.js";

/** Renderiza la vista. */
export async function render(contenedor) {
  const datos = await api("/api/api-surface");
  const items = datos.items || [];

  const conPii = items.filter((e) => e.pii).length;
  const resumen = el("div", { className: "mosaico", estilo: "margin-bottom:var(--s-3)" });
  resumen.append(
    el(
      "div",
      { className: "metrica metrica--ambar" },
      el("div", { className: "metrica__valor", texto: String(items.length) }),
      el("div", { className: "metrica__etiqueta", texto: "endpoints" }),
    ),
    el(
      "div",
      { className: "metrica metrica--rojo" },
      el("div", { className: "metrica__valor", texto: String(conPii) }),
      el("div", { className: "metrica__etiqueta", texto: "posible PII" }),
    ),
    el(
      "div",
      { className: "metrica" },
      el(
        "div",
        { className: "metrica__valor", texto: String(items.filter((e) => e.sensible).length) },
      ),
      el("div", { className: "metrica__etiqueta", texto: "rutas sensibles" }),
    ),
    el(
      "div",
      { className: "metrica" },
      el(
        "div",
        {
          className: "metrica__valor",
          texto: String(items.filter((e) => e.host && e.host !== "propio").length),
        },
      ),
      el("div", { className: "metrica__etiqueta", texto: "en terceros" }),
    ),
  );

  if (!items.length) {
    contenedor.append(
      el("div", { className: "revelar" }, resumen),
      panel(
        "Superficie de API",
        datos.fuente || "sin js_intel.json",
        vacio("Sin endpoints", datos.mensaje || "No hay js_intel.json en la evidencia."),
      ),
    );
    return;
  }

  const columnas = [
    {
      clave: "metodo",
      titulo: "Método",
      render: (e) => etiqueta(e.metodo, "dato"),
    },
    {
      clave: "ruta",
      titulo: "Ruta",
      render: (e) =>
        el(
          "div",
          {},
          el("code", { texto: e.ruta }),
          e.host && e.host !== "propio"
            ? el("div", { className: "tenuisimo", texto: `host: ${e.host}` })
            : null,
        ),
    },
    {
      clave: "auth",
      titulo: "Auth",
      render: (e) =>
        el("span", {
          className: e.auth === "no" ? "" : "tenue",
          texto: e.auth,
        }),
    },
    {
      clave: "pii",
      titulo: "PII",
      render: (e) => etiqueta(e.pii ? "SÍ" : "no", e.pii ? "critico" : "info"),
    },
    {
      clave: "severidad",
      titulo: "Severidad",
      render: (e) => {
        const v = String(e.severidad || "info").toLowerCase();
        return etiqueta(
          v.toUpperCase(),
          v === "critico" ? "critico" : v === "alto" ? "alto" : v === "medio" ? "medio" : "info",
        );
      },
    },
    {
      clave: "origen",
      titulo: "Origen",
      render: (e) =>
        el(
          "div",
          { className: "celda-truncar mono", estilo: "font-size:var(--fs-micro)" },
          e.origen,
        ),
    },
  ];

  const cuerpo = el("div", {});
  const contador = el("span", { className: "panel__nota" });

  const soloPii = document.createElement("input");
  soloPii.type = "checkbox";
  soloPii.id = "filtro-pii";
  soloPii.addEventListener("change", pintar);

  const barra = el(
    "div",
    { className: "barra-filtros" },
    el(
      "label",
      { className: "campo", attrs: { for: "filtro-pii" } },
      soloPii,
      "devuelve PII",
    ),
    contador,
  );

  function pintar() {
    const visibles = soloPii.checked ? items.filter((e) => e.pii) : items;
    contador.textContent = `${visibles.length} de ${items.length} endpoints`;
    cuerpo.innerHTML = "";
    if (!visibles.length) {
      cuerpo.append(
        vacio(
          "Ningún endpoint con ese filtro",
          "No hay endpoints cuya ruta sugiera datos personales o clínicos.",
        ),
      );
      return;
    }
    cuerpo.append(
      tabla(columnas, visibles, {
        tarjetas: true,
        caption:
          "Endpoints detectados en el material descargado. La columna PII clasifica la ruta, no el contenido.",
      }),
    );
  }

  contenedor.append(
    el(
      "div",
      { className: "revelar" },
      resumen,
      el("p", {
        className: "tenue",
        estilo: "font-size:var(--fs-micro);margin:0 0 var(--s-3)",
        texto:
          "«PII: SÍ» significa que la ruta sugiere datos de pacientes. No significa que se " +
          "hayan descargado datos: no se ha hecho ninguna petición a estos endpoints.",
      }),
    ),
    panel(
      "Superficie de API",
      datos.fuente || "sin js_intel.json",
      el("div", {}, barra, cuerpo),
      { sinCuerpo: true },
    ),
  );

  pintar();
}
