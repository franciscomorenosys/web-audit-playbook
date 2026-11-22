/**
 * Vista AUTORIZACIÓN: el panel del RoE.
 *
 * Recordatorio visual de la doctrina: sin RoE firmado no se empieza, y la
 * Fase 2 (explotación) está bloqueada mientras no exista un addendum firmado.
 */

import { api } from "../data.js";
import { duracion } from "../format.js";
import { el, panel } from "./comunes.js";

/** Temporizador de la cuenta atrás (uno solo: se limpia al cambiar de vista). */
let temporizador = null;

/** Renderiza la vista. */
export async function render(contenedor) {
  if (temporizador) window.clearInterval(temporizador);
  temporizador = null;

  const roe = await api("/api/authorization");

  // -- estado de fase 2 -------------------------------------------------------- //
  const bloqueFase2 = el(
    "div",
    { className: "fase2", attrs: { "data-bloqueada": String(Boolean(roe.fase2_bloqueada)) } },
    el("span", { className: "punto punto--latido", attrs: { "aria-hidden": "true" } }),
    el("span", { className: "fase2__texto", texto: roe.estado_fase2 || "FASE 2 BLOQUEADA" }),
    el("span", {
      className: "tenue",
      texto: roe.fase2_bloqueada
        ? "Sin addendum firmado: sólo se permite Fase 1 (GET/HEAD). El RoE no se amplía solo."
        : `Addendum firmado: ${roe.fase2_addendum}`,
    }),
  );

  // -- cuenta atrás ------------------------------------------------------------- //
  const valorCuenta = el("span", { className: "cuenta__valor", texto: "—" });
  const cuenta = el(
    "div",
    { className: "cuenta" },
    valorCuenta,
    el("span", { className: "cuenta__unidad", texto: "restantes en la ventana" }),
  );

  let segundoActual = roe.segundos_restantes;
  const pintarCuenta = () => {
    if (segundoActual === null || segundoActual === undefined) {
      valorCuenta.textContent = "—";
      return;
    }
    valorCuenta.textContent = duracion(segundoActual);
    valorCuenta.dataset.critico = String(segundoActual < 86400);
    segundoActual -= 1;
  };
  pintarCuenta();
  temporizador = window.setInterval(pintarCuenta, 1000);

  // -- ficha del RoE ------------------------------------------------------------- //
  const ficha = el(
    "div",
    { className: "mosaico", estilo: "margin-bottom:var(--s-3)" },
    el(
      "div",
      { className: "metrica" },
      el("div", { className: "metrica__valor", texto: roe.authorization_ref || "—" }),
      el("div", { className: "metrica__etiqueta", texto: "referencia" }),
    ),
    el(
      "div",
      { className: "metrica metrica--ambar" },
      el("div", { className: "metrica__valor", texto: roe.client || "—" }),
      el("div", { className: "metrica__etiqueta", texto: "cliente" }),
    ),
    el(
      "div",
      { className: "metrica" },
      el("div", { className: "metrica__valor", texto: String((roe.hosts || []).length) }),
      el("div", { className: "metrica__etiqueta", texto: "hosts permitidos" }),
    ),
    el(
      "div",
      { className: "metrica metrica--verde" },
      el("div", { className: "metrica__valor", texto: (roe.metodos_efectivos || []).join(" ") }),
      el("div", { className: "metrica__etiqueta", texto: "métodos efectivos" }),
    ),
  );

  const panelVentana = panel(
    "Ventana de validez",
    roe.en_ventana ? "en ventana" : roe.disponible ? "FUERA de ventana" : "sin autorización",
    el(
      "div",
      {},
      cuenta,
      el(
        "div",
        { className: "componentes", estilo: "margin-top:var(--s-3)" },
        fila("Desde", roe.valid_from || "—"),
        fila("Hasta", roe.valid_to || "—"),
        fila("Firmado por", roe.signed_by || "—"),
        fila("Firmado el", roe.signed_at || "—"),
        fila("User-Agent", roe.user_agent || "—"),
        fila("Intervalo mínimo", `${roe.min_interval_s ?? "—"} s`),
        fila("Máx. bytes", String(roe.max_bytes ?? "—")),
      ),
    ),
  );

  // -- hosts permitidos ------------------------------------------------------------ //
  const listaHosts = el("div", { className: "componentes" });
  const permitidos = new Set(roe.hosts || []);
  const observados = new Set(roe.hosts_observados || []);
  const todos = [...new Set([...permitidos, ...observados])].sort();
  for (const host of todos) {
    const permitido =
      permitidos.has(host) ||
      [...permitidos].some((p) => (p.startsWith("*.") ? host.endsWith(p.slice(1)) : p === host));
    const visto = observados.has(host);
    listaHosts.append(
      el(
        "div",
        { className: "componente", estilo: "grid-template-columns:minmax(0,1fr) 120px" },
        el(
          "div",
          {},
          el("div", {
            className: `componente__nombre${permitido ? "" : " ambar"}`,
            texto: host,
          }),
          el("div", {
            className: "componente__detalle",
            texto: !permitido
              ? "FUERA DEL ALLOWLIST: cualquier petición a este host aborta la sonda"
              : visto
                ? "Host permitido por el RoE y sondeado en esta auditoría."
                : "Host permitido por el RoE (no sondeado en esta auditoría).",
          }),
        ),
        el(
          "div",
          { className: "check__estado" },
          el("span", {
            className: `etiqueta etiqueta--${permitido ? "ok" : "critico"}`,
            texto: permitido ? "PERMITIDO" : "PROHIBIDO",
          }),
        ),
      ),
    );
  }

  const panelHosts = panel(
    "Hosts permitidos",
    `${permitidos.size} en el RoE`,
    el("div", {}, listaHosts),
    { sinCuerpo: true },
  );

  // -- métodos y doctrina ---------------------------------------------------------- //
  const metodos = el("div", { className: "componentes" });
  for (const metodo of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]) {
    const permitido = (roe.metodos_efectivos || []).includes(metodo);
    metodos.append(
      el(
        "div",
        { className: "componente", estilo: "grid-template-columns:120px minmax(0,1fr) 100px" },
        el("div", { className: "componente__nombre mono", texto: metodo }),
        el("div", {
          className: "componente__detalle",
          texto: permitido
            ? "Permitido por el RoE."
            : "NUNCA. Los métodos con cuerpo se descartan aunque el fichero los liste (RoE 1.1).",
        }),
        el(
          "div",
          { className: "check__estado" },
          el("span", {
            className: `etiqueta etiqueta--${permitido ? "ok" : "critico"}`,
            texto: permitido ? "PERMITIDO" : "DESCARTADO",
          }),
        ),
      ),
    );
  }

  const panelMetodos = panel(
    "Métodos",
    "recorte fijo de la doctrina",
    el("div", {}, metodos),
    { sinCuerpo: true },
  );

  const panelDoctrina = panel(
    "Doctrina vigente",
    "reglas de autorización y RoE",
    el(
      "ul",
      { estilo: "margin:0;padding-left:var(--s-4);font-size:var(--fs-small);color:var(--texto-medio)" },
      ...(roe.doctrina || []).map((linea) => el("li", { texto: linea, estilo: "margin-bottom:var(--s-1)" })),
    ),
  );

  const panelNotas = panel(
    "Notas del RoE",
    roe.fuente || "sin authorization.json",
    el("p", { className: "tenue", texto: roe.notes || "Sin notas en el fichero de autorización." }),
  );

  contenedor.append(
    el(
      "div",
      { className: "revelar" },
      bloqueFase2,
      el("div", { estilo: "margin-top:var(--s-3)" }, ficha),
    ),
    el(
      "div",
      { className: "rejilla rejilla--principal", estilo: "margin-top:var(--s-3)" },
      el("div", { className: "revelar" }, panelVentana, panelHosts),
      el("div", { className: "revelar" }, panelMetodos, panelDoctrina, panelNotas),
    ),
  );
}

/** Fila clave/valor del panel de RoE. */
function fila(clave, valor) {
  return el(
    "div",
    { className: "componente", estilo: "grid-template-columns:150px minmax(0,1fr)" },
    el("div", { className: "componente__nombre", texto: clave }),
    el("div", { className: "componente__detalle mono", texto: valor }),
    el("div", {}),
  );
}
