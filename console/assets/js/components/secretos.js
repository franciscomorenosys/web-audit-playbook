/**
 * Vista SECRET REGISTER: la tabla de 12 columnas del módulo de secretos.
 *
 * Regla inviolable: **nunca** el valor completo. Sólo la máscara que produce
 * `secrets_scan.py` (`4 + 6 + 2`) y el `sha256[:12]` como fingerprint.
 */

import { api } from "../data.js";
import { compacto, vivo } from "../format.js";
import { el, etiqueta, panel, tabla, vacio } from "./comunes.js";

/** Renderiza la vista. */
export async function render(contenedor) {
  const datos = await api("/api/secrets");
  const items = datos.items || [];

  const resumen = el("div", { className: "mosaico", estilo: "margin-bottom:var(--s-3)" });
  const conteo = { si: 0, no: 0, "no probado": 0, "no aplica": 0 };
  for (const item of items) {
    const clave = String(item.vive || "no probado").toLowerCase();
    if (conteo[clave] === undefined) conteo[clave] = 0;
    conteo[clave] += 1;
  }
  resumen.append(
    el(
      "div",
      { className: "metrica metrica--ambar" },
      el("div", { className: "metrica__valor", texto: String(items.length) }),
      el("div", { className: "metrica__etiqueta", texto: "secretos" }),
    ),
    el(
      "div",
      { className: "metrica metrica--rojo" },
      el("div", { className: "metrica__valor", texto: String(conteo.si || 0) }),
      el("div", { className: "metrica__etiqueta", texto: "probablemente vivos" }),
    ),
    el(
      "div",
      { className: "metrica metrica--verde" },
      el("div", { className: "metrica__valor", texto: String(conteo.no || 0) }),
      el("div", { className: "metrica__etiqueta", texto: "confirmados muertos" }),
    ),
    el(
      "div",
      { className: "metrica" },
      el("div", { className: "metrica__valor", texto: String(conteo["no probado"] || 0) }),
      el("div", { className: "metrica__etiqueta", texto: "nunca probados" }),
    ),
  );

  const advertencia = el(
    "p",
    {
      className: "tenue",
      estilo: "font-size:var(--fs-micro);margin:0 0 var(--s-3)",
    },
    "Nunca se muestra el valor completo: sólo la máscara y el fingerprint sha256[:12]. " +
      "«Nunca probado» es el estado honesto por defecto: usar una credencial sin " +
      "autorización escrita que la nombre va contra el RoE.",
  );

  if (!items.length) {
    contenedor.append(
      el("div", { className: "revelar" }, resumen, advertencia),
      panel(
        "Secret Register",
        datos.fuente || "sin secrets.json",
        vacio("Sin registro de secretos", datos.mensaje || "No hay secrets.json en la evidencia."),
      ),
    );
    return;
  }

  const columnas = [
    { clave: "id", titulo: "ID", render: (s) => el("span", { className: "mono", texto: s.id }) },
    { clave: "tipo", titulo: "Tipo", render: (s) => el("span", { className: "mono", texto: s.tipo }) },
    { clave: "vector", titulo: "Vector", render: (s) => compacto(s.vector) },
    {
      clave: "ubicacion",
      titulo: "Ubicación",
      render: (s) =>
        el(
          "div",
          { className: "celda-truncar", attrs: { title: s.ubicacion } },
          s.ubicacion,
        ),
    },
    {
      clave: "masked",
      titulo: "Masked",
      render: (s) => el("code", { texto: s.masked || "—" }),
    },
    {
      clave: "fingerprint",
      titulo: "Fingerprint",
      render: (s) => el("span", { className: "mono", texto: s.fingerprint || "—" }),
    },
    {
      clave: "vive",
      titulo: "¿Vive?",
      render: (s) => {
        const info = vivo(s.vive);
        const chip = etiqueta(info.texto, info.clase);
        if (s.vive_detalle) chip.setAttribute("title", s.vive_detalle);
        return chip;
      },
    },
    {
      clave: "alcance_real",
      titulo: "Alcance real",
      render: (s) =>
        el(
          "div",
          { className: "celda-truncar", attrs: { title: s.alcance_real } },
          s.alcance_real,
        ),
    },
    {
      clave: "criticidad",
      titulo: "Criticidad",
      render: (s) => {
        const v = String(s.criticidad || "").toLowerCase();
        const clase =
          v === "critico" ? "critico" : v === "alto" ? "alto" : v === "medio" ? "medio" : "info";
        return etiqueta(String(s.criticidad || "INFO"), clase);
      },
    },
    {
      clave: "rotacion_urgente",
      titulo: "Rotación urgente",
      render: (s) => {
        const urgente = String(s.rotacion_urgente || "").toLowerCase().startsWith("sí");
        return etiqueta(s.rotacion_urgente || "—", urgente ? "critico" : "info");
      },
    },
    { clave: "owner", titulo: "Owner", render: (s) => compacto(s.owner) },
    {
      clave: "evidencia",
      titulo: "Evidencia",
      render: (s) => {
        const primero = (s.evidencia || [])[0];
        if (!primero) return "—";
        return el(
          "div",
          { className: "mono", estilo: "font-size:var(--fs-micro)" },
          el("code", { texto: primero.fichero }),
          el("div", { className: "tenuisimo", texto: primero.hash ? `sha256[:12] ${primero.hash}` : "" }),
        );
      },
    },
  ];

  const cuerpo = el("div", {});
  const contador = el("span", { className: "panel__nota" });

  const filtro = document.createElement("select");
  filtro.setAttribute("aria-label", "Filtrar por estado de verificación");
  const opciones = [
    ["", "Verificación: todas"],
    ["sí", "Probablemente vivos"],
    ["no", "Confirmados muertos"],
    ["no probado", "Nunca probados"],
  ];
  for (const [valor, texto] of opciones) {
    const o = document.createElement("option");
    o.value = valor;
    o.textContent = texto;
    filtro.append(o);
  }

  function pintar() {
    const visibles = filtro.value
      ? items.filter((s) => String(s.vive || "").toLowerCase() === filtro.value)
      : items;
    contador.textContent = `${visibles.length} de ${items.length}`;
    cuerpo.innerHTML = "";
    if (!visibles.length) {
      cuerpo.append(vacio("Sin secretos en ese estado", "Cambia el filtro para ver el resto."));
      return;
    }
    cuerpo.append(
      tabla(columnas, visibles, {
        tarjetas: true,
        caption: `Secret Register de ${datos.fuente || "la evidencia"}.`,
      }),
    );
  }

  filtro.addEventListener("change", pintar);

  const barra = el(
    "div",
    { className: "barra-filtros" },
    el("label", { className: "campo" }, filtro),
    contador,
  );

  contenedor.append(
    el("div", { className: "revelar" }, resumen, advertencia),
    panel(
      "Secret Register",
      datos.fuente || "sin secrets.json",
      el("div", {}, barra, cuerpo),
      { sinCuerpo: true },
    ),
  );

  pintar();
}
