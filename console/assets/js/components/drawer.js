/**
 * Drawer de detalle.
 *
 * Panel lateral con foco atrapado, cierre con Escape y retorno del foco al
 * elemento que lo abrió. Es la forma que usa la consola para no sacar al
 * auditor de la tabla densa.
 */

/** Selector de los elementos focuses dentro del drawer. */
const FOCALIZABLES =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

let abierto = null;

/**
 * Abre el drawer.
 *
 * @param {object} opciones
 * @param {string} opciones.titulo Título del detalle.
 * @param {Node|Node[]} opciones.contenido Contenido del drawer.
 */
export function abrirDrawer({ titulo, contenido }) {
  cerrarDrawer();

  const origen = document.activeElement;
  const capa = document.createElement("div");
  capa.className = "drawer";
  capa.dataset.abierto = "false";
  capa.setAttribute("role", "dialog");
  capa.setAttribute("aria-modal", "true");
  capa.setAttribute("aria-label", titulo);

  const caja = document.createElement("div");
  caja.className = "drawer__caja";

  const cabecera = document.createElement("div");
  cabecera.className = "drawer__cabecera";

  const encabezado = document.createElement("div");
  const rotulo = document.createElement("h2");
  rotulo.className = "drawer__titulo";
  rotulo.textContent = titulo;
  encabezado.append(rotulo);

  const cerrar = document.createElement("button");
  cerrar.className = "boton boton--fantasma";
  cerrar.type = "button";
  cerrar.textContent = "Cerrar";
  cerrar.setAttribute("aria-label", "Cerrar el detalle");
  cerrar.addEventListener("click", () => cerrarDrawer());

  cabecera.append(encabezado, cerrar);

  const cuerpo = document.createElement("div");
  cuerpo.className = "drawer__cuerpo";
  cuerpo.append(contenido);

  caja.append(cabecera, cuerpo);
  capa.append(caja);
  document.body.append(capa);

  requestAnimationFrame(() => {
    capa.dataset.abierto = "true";
    cerrar.focus();
  });

  capa.addEventListener("click", (evento) => {
    if (evento.target === capa) cerrarDrawer();
  });

  function alPulsarTecla(evento) {
    if (evento.key === "Escape") {
      evento.preventDefault();
      cerrarDrawer();
      return;
    }
    if (evento.key !== "Tab") return;
    const focuses = Array.from(caja.querySelectorAll(FOCALIZABLES)).filter(
      (nodo) => nodo.offsetParent !== null,
    );
    if (focuses.length === 0) return;
    const primero = focuses[0];
    const ultimo = focuses[focuses.length - 1];
    if (evento.shiftKey && document.activeElement === primero) {
      evento.preventDefault();
      ultimo.focus();
    } else if (!evento.shiftKey && document.activeElement === ultimo) {
      evento.preventDefault();
      primero.focus();
    }
  }

  document.addEventListener("keydown", alPulsarTecla);

  abierto = {
    capa,
    origen,
    alPulsarTecla,
  };
}

/** Cierra el drawer y devuelve el foco a donde estaba. */
export function cerrarDrawer() {
  if (!abierto) return;
  const { capa, origen, alPulsarTecla } = abierto;
  abierto = null;
  document.removeEventListener("keydown", alPulsarTecla);
  capa.dataset.abierto = "false";
  window.setTimeout(() => {
    capa.remove();
    if (origen && typeof origen.focus === "function") origen.focus();
  }, 180);
}
