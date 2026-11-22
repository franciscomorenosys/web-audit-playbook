/**
 * Vista EVIDENCIA: índice del directorio de evidencia.
 *
 * Regla de seguridad, no preferencia: un artefacto sin estado de redacción
 * verificable se marca **SIN REDACTAR** y se **oculta por defecto**. Sólo el
 * auditor puede revelarlo, y queda constancia de que lo hizo.
 */

import { api } from "../data.js";
import { bytes, estadoRedaccion, fecha } from "../format.js";
import { el, panel, tabla, vacio } from "./comunes.js";

/** Estado de la vista (persiste entre recargas de la misma sesión). */
const estado = {
  revelar: false,
  texto: "",
};

/** Renderiza la vista. */
export async function render(contenedor) {
  const datos = await api("/api/evidence");
  const artefactos = datos.artefactos || [];
  const resumen = datos.resumen_redaccion || {};

  const banner = el(
    "div",
    { className: "aviso-critico", attrs: { role: "alert" } },
  );
  const sinRedactar = (datos.sin_redactar || []).length;

  if (sinRedactar > 0) {
    banner.append(
      el(
        "div",
        {},
        el("strong", { texto: `${sinRedactar} artefacto(s) SIN REDACTAR` }),
        el("span", {
          texto:
            "No tienen estado de redacción verificable, así que están ocultos por defecto. " +
            "La consola sólo muestra evidencia redactada.",
        }),
      ),
    );
  } else {
    banner.dataset.nivel = "ok";
    banner.style.background = "var(--verde-tenue)";
    banner.style.borderBottomColor = "rgba(63,185,80,0.45)";
    banner.append(
      el(
        "div",
        {},
        el("strong", { texto: "Cobertura de redacción completa" }),
        el("span", { texto: "Todos los artefactos tienen estado de redacción verificable." }),
      ),
    );
  }

  const mosaico = el("div", { className: "mosaico", estilo: "margin-bottom:var(--s-3)" });
  mosaico.append(
    el(
      "div",
      { className: "metrica" },
      el("div", { className: "metrica__valor", texto: String(resumen.total || 0) }),
      el("div", { className: "metrica__etiqueta", texto: "artefactos" }),
    ),
    el(
      "div",
      { className: "metrica metrica--verde" },
      el("div", { className: "metrica__valor", texto: String(resumen.redactados || 0) }),
      el("div", { className: "metrica__etiqueta", texto: "redactados" }),
    ),
    el(
      "div",
      { className: "metrica metrica--rojo" },
      el("div", { className: "metrica__valor", texto: String(resumen.sin_verificar || 0) }),
      el("div", { className: "metrica__etiqueta", texto: "sin verificar" }),
    ),
    el(
      "div",
      { className: "metrica" },
      el("div", { className: "metrica__valor", texto: `${resumen.cobertura_pct ?? 0}%` }),
      el("div", { className: "metrica__etiqueta", texto: "cobertura" }),
    ),
  );

  // -- controles -------------------------------------------------------------- //
  const buscador = document.createElement("input");
  buscador.type = "search";
  buscador.placeholder = "Filtrar por ruta…";
  buscador.value = estado.texto;
  buscador.setAttribute("aria-label", "Filtrar artefactos por ruta");

  const botonRevelar = document.createElement("button");
  botonRevelar.type = "button";
  botonRevelar.className = "boton boton--peligro";
  botonRevelar.textContent = estado.revelar ? "Ocultar sin redactar" : "Revelar sin redactar";
  botonRevelar.setAttribute("aria-pressed", String(estado.revelar));
  botonRevelar.setAttribute("aria-label", "Mostrar u ocultar los artefactos sin redactar");

  const contador = el("span", { className: "panel__nota" });

  const cuerpo = el("div", {});

  const columnas = [
    {
      clave: "ruta",
      titulo: "Ruta",
      render: (a) =>
        el(
          "div",
          { className: "mono", estilo: "font-size:var(--fs-micro);word-break:break-all" },
          a.ruta,
        ),
    },
    {
      clave: "tamano",
      titulo: "Tamaño",
      render: (a) => el("span", { className: "mono", texto: bytes(a.tamano) }),
    },
    {
      clave: "sha256",
      titulo: "sha256[:12]",
      render: (a) =>
        el("span", {
          className: "mono",
          texto: a.hash_corto || "—",
        }),
    },
    {
      clave: "mtime",
      titulo: "Modificado",
      render: (a) => el("span", { className: "mono", texto: fecha(a.mtime_iso) }),
    },
    {
      clave: "redaccion",
      titulo: "Redacción",
      render: (a) => {
        const info = estadoRedaccion(a.redaccion);
        const chip = el("span", { className: `etiqueta etiqueta--${info.clase}`, texto: info.texto });
        if (a.redaccion_motivo) chip.setAttribute("title", a.redaccion_motivo);
        return chip;
      },
    },
    {
      clave: "motivo",
      titulo: "Motivo",
      render: (a) =>
        el(
          "div",
          { className: "celda-truncar tenue", estilo: "font-size:var(--fs-micro)" },
          a.redaccion_motivo,
        ),
    },
  ];

  function pintar() {
    let visibles = artefactos;
    if (!estado.revelar) visibles = visibles.filter((a) => !a.sin_redactar);
    if (estado.texto) {
      const aguja = estado.texto.toLowerCase();
      visibles = visibles.filter((a) => a.ruta.toLowerCase().includes(aguja));
    }
    contador.textContent = `${visibles.length} visibles de ${artefactos.length}`;
    cuerpo.innerHTML = "";
    if (!visibles.length) {
      cuerpo.append(
        vacio(
          "Nada que mostrar",
          estado.revelar
            ? "Ningún artefacto coincide con el filtro."
            : "No hay artefactos redactados que mostrar. Los que no tienen estado de redacción verificable están ocultos.",
        ),
      );
      return;
    }
    cuerpo.append(
      tabla(columnas, visibles, {
        tarjetas: true,
        caption: "Índice del directorio de evidencia.",
      }),
    );
  }

  botonRevelar.addEventListener("click", () => {
    estado.revelar = !estado.revelar;
    botonRevelar.textContent = estado.revelar ? "Ocultar sin redactar" : "Revelar sin redactar";
    botonRevelar.setAttribute("aria-pressed", String(estado.revelar));
    pintar();
  });
  buscador.addEventListener("input", () => {
    estado.texto = buscador.value;
    pintar();
  });

  const barra = el(
    "div",
    { className: "barra-filtros" },
    el("label", { className: "campo" }, buscador),
    botonRevelar,
    contador,
  );

  // -- ficheros esperados ------------------------------------------------------- //
  const resumenEsperados = await api("/api/summary");
  const esperados = resumenEsperados.ficheros_esperados || [];
  const panelEsperados = panel(
    "Ficheros que espera la consola",
    `${esperados.filter((f) => f.presente).length} de ${esperados.length} presentes`,
    el(
      "div",
      { className: "componentes" },
      ...esperados.map((f) =>
        el(
          "div",
          { className: "componente", estilo: "grid-template-columns:230px minmax(0,1fr) 96px" },
          el(
            "div",
            {},
            el("div", { className: "componente__nombre", texto: f.nombre }),
            el("div", { className: "componente__detalle", texto: f.descripcion }),
          ),
          el(
            "div",
            { className: "componente__detalle mono", estilo: "font-size:var(--fs-micro)" },
            f.presente ? f.ruta : "no encontrado",
          ),
          el(
            "div",
            { className: "check__estado" },
            el("span", {
              className: `etiqueta etiqueta--${f.presente ? "ok" : "info"}`,
              texto: f.presente ? "PRESENTE" : "AUSENTE",
            }),
          ),
        ),
      ),
    ),
  );

  contenedor.append(
    banner,
    el("div", { className: "revelar", estilo: "margin-top:var(--s-3)" }, mosaico),
    panel(
      "Artefactos",
      "ruta · tamaño · sha256 · mtime · estado de redacción",
      el("div", {}, barra, cuerpo),
      { sinCuerpo: true },
    ),
    el("div", { estilo: "margin-top:var(--s-3)" }, panelEsperados),
  );

  pintar();
}
