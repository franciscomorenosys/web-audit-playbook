/**
 * Vista SUPERFICIE: el Attack Exposure Score como instrumento.
 *
 * Muestra el dial, el desglose de componentes con su peso y su fuente, y la
 * bonificación por lo que ya está bien (requisito metodológico, no cortesía).
 */

import { api } from "../data.js";
import { banda as colorBanda } from "../format.js";
import { crearDial } from "./dial.js";
import { crearHexGrid } from "./hexgrid.js";
import { el, metrica, panel, seccion, vacio } from "./comunes.js";

/** Fila de un componente del score, con su barra y su fuente. */
function filaComponente(componente) {
  const max = Number(componente.max_points) || 0;
  const puntos = Number(componente.points) || 0;
  const proporcion = max > 0 ? Math.min(1, Math.abs(puntos) / max) : 0;
  const esBoni = componente.kind === "bonificacion";
  const sinDatos = componente.source === "sin datos";

  const barra = el(
    "div",
    {
      className: `componente__barra${esBoni ? " componente__barra--bonif" : ""}${
        sinDatos ? " componente__barra--vacia" : ""
      }`,
      attrs: {
        role: "img",
        "aria-label": `${componente.name}: ${puntos} de ${max} puntos`,
      },
    },
    el("span", { estilo: `width:${(proporcion * 100).toFixed(1)}%` }),
  );

  return el(
    "div",
    { className: `componente${esBoni ? " componente--bonif" : ""}` },
    el(
      "div",
      {},
      el("div", { className: "componente__nombre", texto: componente.name }),
      componente.detail
        ? el("div", { className: "componente__detalle", texto: componente.detail })
        : null,
      el("div", {
        className: "componente__fuente",
        texto: `evidencia: ${componente.source || "sin datos"}`,
      }),
    ),
    barra,
    el(
      "div",
      { className: "componente__puntos" },
      el("b", { texto: puntos.toFixed(1) }),
      " / ",
      String(max),
    ),
  );
}

/**
 * Encaja el hex-grid al dibujo real.
 *
 * El `viewBox` del hex-grid reserva un margen de 38 unidades por encima de
 * la primera fila de celdas y termina antes que la última: el panel queda
 * con una franja de aire muerto sobre el grid y con la última fila de
 * hexágonos cortada por el borde. Recortar el `viewBox` al contenido
 * dibujado deja el grid centrado en su panel, sin aire muerto arriba y sin
 * celdas cortadas.
 *
 * @param {Element} panel Panel del hex-grid, ya montado en el documento:
 *   `getBBox()` necesita que el SVG esté renderizado para medir el dibujo.
 */
function encajarHexGrid(panel) {
  const svg = panel.querySelector(".hexpanel__svg");
  if (!svg || typeof svg.getBBox !== "function") return;
  const caja = svg.getBBox();
  if (!caja || !caja.width || !caja.height) return;

  const holgura = 8; // unidades del viewBox: aire mínimo alrededor del dibujo
  const vista = svg.getAttribute("viewBox").split(/\s+/).map(Number);
  const y = caja.y - holgura;
  const fondo = caja.y + caja.height + holgura;
  // El eje horizontal se conserva: recortar la caja no debe cambiar la
  // escala del dibujo (ni el tamaño de los rótulos de cada celda).
  svg.setAttribute(
    "viewBox",
    `${vista[0]} ${y.toFixed(2)} ${vista[2]} ${(fondo - y).toFixed(2)}`,
  );
}

/** Renderiza la vista. */
export async function render(contenedor) {
  const [score, resumen] = await Promise.all([api("/api/score"), api("/api/summary")]);

  const disponible = score.disponible && score.valor !== null;
  const evaluable = Boolean(score.evaluable);
  // -- dial ---------------------------------------------------------------- //
  const dial = crearDial({
    valor: disponible ? score.valor : null,
    banda: score.banda,
    evaluable: disponible && evaluable,
  });

  const panelDial = panel(
    "Attack Exposure Score",
    disponible ? "bandas del script" : "sin datos",
    dial,
  );

  // -- fórmula ------------------------------------------------------------- //
  const formula = score.formula || {};
  const bloqueFormula = el(
    "pre",
    { className: "mono u-pre" },
    formula.expression ||
      "sin score: ejecuta attack_surface_report.py sobre la evidencia o deja su JSON en el directorio.",
  );

  const mosaico = el(
    "div",
    { className: "mosaico", estilo: "margin-bottom:var(--s-3)" },
    metrica(
      formula.risk_points !== undefined ? formula.risk_points.toFixed(1) : "—",
      "puntos de riesgo",
      "ambar",
    ),
    metrica(
      formula.bonus_points !== undefined ? `−${formula.bonus_points.toFixed(1)}` : "—",
      "bonificación",
      "verde",
    ),
    metrica(
      formula.risk_max !== undefined ? String(formula.risk_max) : "—",
      "máximo de riesgo",
    ),
    metrica(String(formula.bonus_max ?? 30), "tope de bonificación"),
  );

  const cobertura = score.cobertura || {};
  const filasCobertura = Object.entries(cobertura).map(([clave, rutas]) =>
    el(
      "div",
      { className: "flujo__linea" },
      el("b", { texto: clave.replace(/_/g, " ") }),
      el(
        "span",
        {
          className: "mono",
          texto:
            Array.isArray(rutas) && rutas.length
              ? rutas.join(", ")
              : "sin datos",
        },
      ),
    ),
  );

  const panelFormula = panel(
    "Fórmula y cobertura",
    score.fuente || "sin fuente",
    el(
      "div",
      {},
      mosaico,
      score.evaluable
        ? null
        : el("p", {
            className: "tenue",
            estilo: "font-size:var(--fs-micro);margin:0 0 var(--s-2)",
            texto:
              "El script devuelve 0 porque no hay nada que puntuar. No es un 0 de " +
              "seguridad: es una ausencia de evidencia.",
          }),
      bloqueFormula,
      el(
        "div",
        { className: "flujo", estilo: "margin-top:var(--s-3);border-left:none;padding-left:0" },
        ...filasCobertura,
      ),
    ),
  );

  // -- hex-grid ------------------------------------------------------------ //
  const panelHex = panel(
    "Superficie de subdominios",
    `${(score.subdominios || []).length} nombres en Certificate Transparency`,
    crearHexGrid(score.subdominios || []),
    { sinCuerpo: true, clase: "panel--hex" },
  );

  // -- componentes ---------------------------------------------------------- //
  const riesgo = score.riesgo || [];
  const bonificacion = score.bonificacion || [];

  const panelRiesgo = panel(
    "Componentes de riesgo",
    `${riesgo.length} con peso`,
    riesgo.length
      ? el("div", { className: "componentes" }, ...riesgo.map(filaComponente))
      : vacio("Sin componentes de riesgo", "El script no ha emitido ningún componente de riesgo."),
  );

  const panelBoni = panel(
    "Lo que ya está bien",
    "bonificación · requisito metodológico",
    bonificacion.length
      ? el("div", { className: "componentes" }, ...bonificacion.map(filaComponente))
      : vacio(
          "Sin bonificación",
          "Ningún componente de bonificación ha sido concedible: o no hay evidencia que lo respalde, o el script no lo ha emitido.",
        ),
  );

  // -- avisos -------------------------------------------------------------- //
  const avisos = [];
  if (!score.disponible) {
    avisos.push(
      el(
        "div",
        { className: "fase2", attrs: { "data-bloqueada": "true" } },
        el("span", { className: "fase2__texto", texto: "Sin score" }),
        el("span", { className: "tenue", texto: score.mensaje || "" }),
      ),
    );
  } else if (!evaluable) {
    avisos.push(
      el(
        "div",
        { className: "fase2", attrs: { "data-bloqueada": "true" } },
        el("span", { className: "fase2__texto", texto: "No evaluable" }),
        el("span", { className: "tenue", texto: score.mensaje || "" }),
      ),
    );
  }
  if ((score.duplicados || []).length) {
    avisos.push(
      el(
        "p",
        { className: "tenuisimo", estilo: "font-size:var(--fs-micro);margin-top:var(--s-2)" },
        `El script repitió el componente «${score.duplicados.join(", ")}»; la consola lo muestra una sola vez. Los puntos no cambian.`,
      ),
    );
  }

  const cabecera = el(
    "div",
    { className: "revelar" },
    el(
      "div",
      { className: "mosaico", estilo: "margin-bottom:var(--s-3)" },
      metrica(
        score.valor !== null && score.valor !== undefined ? score.valor.toFixed(1) : "—",
        "índice de exposición",
        "ambar",
      ),
      metrica(score.banda, "banda", "ambar"),
      metrica(String(resumen.recuento.hallazgos), "hallazgos"),
      metrica(String(resumen.recuento.secretos), "secretos"),
      metrica(String(resumen.recuento.endpoints), "endpoints"),
    ),
    ...avisos,
  );

  contenedor.append(
    cabecera,
    el(
      "div",
      { className: "rejilla rejilla--dial" },
      el("div", { className: "revelar columna-fija" }, panelDial, panelFormula),
      el(
        "div",
        { className: "revelar" },
        panelHex,
        seccion("Puntuación", panelRiesgo, panelBoni),
      ),
    ),
  );

  // El hex-grid se encaja cuando ya está en el documento: `getBBox()`
  // necesita el SVG renderizado para medir el dibujo real.
  encajarHexGrid(panelHex);
}
