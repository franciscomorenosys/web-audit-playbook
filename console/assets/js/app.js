/**
 * Consola de Operaciones de Seguridad — arranque.
 *
 * Monta el marco (barra de estado, avisos, navegación), registra las ocho
 * vistas y las enruta por hash. No hay build step: es JavaScript de módulos
 * nativos servido tal cual.
 */

import { api, limpiarCache } from "./data.js";
import { crearRouter } from "./router.js";
import { banda as colorBanda } from "./format.js";
import { el, etiqueta } from "./components/comunes.js";

import * as superficie from "./components/superficie.js";
import * as hallazgos from "./components/hallazgos.js";
import * as secretos from "./components/secretos.js";
import * as apisurface from "./components/apisurface.js";
import * as exposicion from "./components/exposicion.js";
import * as evidencia from "./components/evidencia.js";
import * as autorizacion from "./components/autorizacion.js";
import * as acciones from "./components/acciones.js";

/** Las ocho vistas, en el orden en que se usan durante una auditoría. */
const VISTAS = [
  { clave: "superficie", titulo: "Superficie", idx: "01", render: superficie.render },
  { clave: "hallazgos", titulo: "Hallazgos", idx: "02", render: hallazgos.render },
  { clave: "secretos", titulo: "Secret Register", idx: "03", render: secretos.render },
  { clave: "api-surface", titulo: "API Surface", idx: "04", render: apisurface.render },
  { clave: "exposicion", titulo: "Exposición", idx: "05", render: exposicion.render },
  { clave: "evidencia", titulo: "Evidencia", idx: "06", render: evidencia.render },
  { clave: "autorizacion", titulo: "Autorización", idx: "07", render: autorizacion.render },
  { clave: "acciones", titulo: "Acciones", idx: "08", render: acciones.render },
];

/** Pinta la barra de estado superior. */
function pintarBarra(resumen) {
  const destino = document.getElementById("barra-estado");
  destino.innerHTML = "";

  const score = resumen.score || {};
  const valor = score.valor !== null && score.valor !== undefined ? Number(score.valor).toFixed(1) : "—";
  const bandaInfo = colorBanda(score.banda);

  destino.append(
    el(
      "span",
      { className: "etiqueta", attrs: { title: "Attack Exposure Score" } },
      el("span", { className: "punto", estilo: `color:${bandaInfo.color}` }),
      `SCORE ${valor} · ${score.banda || "No evaluable"}`,
    ),
  );

  const sinRedactar = resumen.redaccion?.sin_verificar || 0;
  destino.append(
    el(
      "span",
      { className: `etiqueta${sinRedactar ? " etiqueta--critico" : " etiqueta--ok"}` },
      sinRedactar
        ? `${sinRedactar} SIN REDACTAR`
        : `REDACCIÓN OK · ${resumen.redaccion?.cobertura_pct ?? 0}%`,
    ),
  );

  const roe = resumen.alertas?.some((a) => a.titulo.includes("FASE 2")) || false;
  destino.append(
    el(
      "span",
      { className: `etiqueta${roe ? " etiqueta--bloqueo" : ""}` },
      roe ? "FASE 2 BLOQUEADA" : "FASE 1",
    ),
  );
}

/** Pinta los avisos de cabecera. */
function pintarAvisos(resumen) {
  const sintetico = document.getElementById("aviso-sintetico");
  sintetico.hidden = !resumen.sintetico;

  const critico = document.getElementById("aviso-critico");
  const alertas = (resumen.alertas || []).filter((a) => a.nivel === "critico");
  critico.hidden = alertas.length === 0;
  critico.innerHTML = "";
  if (!alertas.length) return;
  critico.append(
    el(
      "ul",
      {},
      ...alertas.map((alerta) =>
        el(
          "li",
          {},
          el("strong", { texto: alerta.titulo }),
          alerta.detalle ? ` — ${alerta.detalle}` : "",
        ),
      ),
    ),
  );
}

/** Construye la navegación. */
function pintarNav(rutas) {
  const nav = document.getElementById("nav");
  nav.innerHTML = "";
  for (const ruta of rutas) {
    const enlace = el(
      "a",
      {
        className: "nav__enlace",
        attrs: { href: `#/${ruta.clave}` },
      },
      el("span", { className: "nav__idx", texto: ruta.idx }),
      ruta.titulo,
    );
    nav.append(enlace);
  }
}

/** Arranque. */
async function arrancar() {
  const nav = document.getElementById("nav");
  const vista = document.getElementById("vista");

  let resumen;
  try {
    resumen = await api("/api/summary");
  } catch (error) {
    vista.innerHTML = "";
    vista.append(
      el(
        "div",
        { className: "vacio" },
        el("strong", { texto: "La consola no puede leer la evidencia" }),
        el("span", { texto: String(error.message || error) }),
      ),
    );
    return;
  }

  document.getElementById("barra-sesion").textContent = resumen.directorio_evidencia || "";
  document.getElementById("pie-meta").textContent = `Sesión ${resumen.generado} · ${
    resumen.modo === "demo" ? "modo demostración" : "modo evidencia"
  } · ${resumen.recuento.artefactos} artefactos`;

  pintarBarra(resumen);
  pintarAvisos(resumen);
  pintarNav(VISTAS);

  const rutas = {};
  for (const vista of VISTAS) {
    rutas[vista.clave] = { titulo: vista.titulo, render: vista.render };
  }

  crearRouter({
    outlet: vista,
    rutas,
    alCambiar: (clave) => {
      for (const enlace of nav.querySelectorAll(".nav__enlace")) {
        if (enlace.getAttribute("href") === `#/${clave}`) {
          enlace.setAttribute("aria-current", "page");
        } else {
          enlace.removeAttribute("aria-current");
        }
      }
      vista.focus({ preventScroll: true });
    },
  });
}

// Refresco manual de la caché: útil si el auditor deja artefactos nuevos
// mientras la consola está abierta.
window.addEventListener("consola:refrescar", () => {
  limpiarCache();
  window.location.reload();
});

arrancar();
