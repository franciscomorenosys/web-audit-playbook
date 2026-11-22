/**
 * Enrutador por hash.
 *
 * Rutas: `#/superficie`, `#/hallazgos`, `#/secretos`, `#/api-surface`,
 * `#/exposicion`, `#/evidencia`, `#/autorizacion`, `#/acciones`.
 */

const PREFIJO = "#/";

/**
 * Crea el enrutador.
 *
 * @param {object} opciones
 * @param {HTMLElement} opciones.outlet Elemento donde se renderiza la vista.
 * @param {Record<string, {titulo: string, render: Function}>} opciones.rutas
 * @param {Function} opciones.alCambiar Aviso de cambio de ruta.
 */
export function crearRouter({ outlet, rutas, alCambiar }) {
  let rutaActual = "";

  /** Resuelve la ruta del hash actual; si no existe, la primera. */
  function resolver() {
    const bruto = window.location.hash.replace(PREFIJO, "").trim();
    const clave = bruto.split("?")[0];
    return rutas[clave] ? clave : Object.keys(rutas)[0];
  }

  /** Cambia el hash sin recargar. */
  function ir(clave) {
    if (rutas[clave]) window.location.hash = `${PREFIJO}${clave}`;
  }

  async function renderizar() {
    const clave = resolver();
    rutaActual = clave;
    const definicion = rutas[clave];
    outlet.innerHTML = "";
    const contenedor = document.createElement("div");
    contenedor.className = "vista__interna";
    outlet.appendChild(contenedor);
    try {
      await definicion.render(contenedor);
    } catch (error) {
      contenedor.innerHTML = "";
      const aviso = document.createElement("div");
      aviso.className = "vacio";
      aviso.innerHTML =
        "<strong>No se pudo cargar la vista</strong>" +
        "<span></span>";
      aviso.querySelector("span").textContent = String(error.message || error);
      contenedor.appendChild(aviso);
    }
    if (alCambiar) alCambiar(clave, definicion);
  }

  window.addEventListener("hashchange", renderizar);
  if (!window.location.hash) window.location.hash = `${PREFIJO}${Object.keys(rutas)[0]}`;
  else renderizar();

  return { ir, renderizar, get ruta() { return rutaActual; } };
}
