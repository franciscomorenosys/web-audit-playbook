/**
 * Cliente de la API local.
 *
 * Regla dura: **sólo rutas relativas** bajo `/api/`. Si alguna vez se
 * intentara una URL absoluta, el cliente la rechazaría antes de salir a la
 * red. La consola no habla con internet.
 */

const CACHE = new Map();

/** Comprueba que la ruta pertenece a la API local. */
function esRutaLocal(ruta) {
  return typeof ruta === "string" && ruta.startsWith("/api/") && !ruta.includes("://");
}

/**
 * Pide un endpoint de la API y lo cachea.
 *
 * @param {string} ruta Ruta relativa bajo `/api/`.
 * @returns {Promise<object>} Datos normalizados.
 */
export async function api(ruta) {
  if (!esRutaLocal(ruta)) {
    throw new Error(`Ruta no permitida (sólo /api/* locales): ${ruta}`);
  }
  if (CACHE.has(ruta)) return CACHE.get(ruta);
  const respuesta = await fetch(ruta, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!respuesta.ok) {
    throw new Error(`${ruta} respondió ${respuesta.status}`);
  }
  const datos = await respuesta.json();
  CACHE.set(ruta, datos);
  return datos;
}

/** Vacía la caché (al recargar la evidencia desde disco). */
export function limpiarCache() {
  CACHE.clear();
}

/** Devuelve todos los endpoints de la API, para las comprobaciones. */
export function endpoints() {
  return [
    "/api/summary",
    "/api/score",
    "/api/findings",
    "/api/secrets",
    "/api/api-surface",
    "/api/iocs",
    "/api/evidence",
    "/api/authorization",
    "/api/actions",
  ];
}
