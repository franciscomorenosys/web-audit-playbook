/**
 * Formateadores compartidos por toda la consola.
 *
 * Todo el texto que llega de la evidencia se trata como **dato no confiable**:
 * aquí sólo se formatea, nunca se interpreta como HTML.
 */

/** Formatea un número de bytes en unidades legibles. */
export function bytes(valor) {
  const n = Number(valor) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

/** Formatea una fecha ISO en formato corto y estable. */
export function fecha(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const mes = [
    "ene", "feb", "mar", "abr", "may", "jun",
    "jul", "ago", "sep", "oct", "nov", "dic",
  ][d.getMonth()];
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${String(d.getDate()).padStart(2, "0")} ${mes} ${d.getFullYear()} ${hh}:${mm}`;
}

/** Formatea una marca temporal ISO con segundos (registro de acciones). */
export function marcaTiempo(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${fecha(iso)} ${hh}:${mm}:${ss}`;
}

/** Etiqueta y clase CSS de una severidad. */
export function severidad(valor) {
  const v = String(valor || "info").toLowerCase();
  const mapa = {
    critico: { texto: "CRÍTICO", clase: "critico" },
    alto: { texto: "ALTO", clase: "alto" },
    medio: { texto: "MEDIO", clase: "medio" },
    bajo: { texto: "BAJO", clase: "bajo" },
    info: { texto: "INFO", clase: "info" },
  };
  return mapa[v] || { texto: v.toUpperCase(), clase: "info" };
}

/** Etiqueta y color de una banda del Attack Exposure Score. */
export function banda(valor) {
  const v = String(valor || "No evaluable");
  const colores = {
    Bajo: "var(--banda-bajo)",
    Moderado: "var(--banda-moderado)",
    Alto: "var(--banda-alto)",
    Crítico: "var(--banda-critico)",
    "Cr\u00edtico": "var(--banda-critico)",
    Severo: "var(--banda-severo)",
    "No evaluable": "var(--texto-tenuisimo)",
  };
  return { texto: v, color: colores[v] || "var(--texto-tenuisimo)" };
}

/** Etiqueta y clase de un estado de hallazgo. */
export function estado(valor) {
  const v = String(valor || "no verificado").toLowerCase();
  const mapa = {
    hallazgo: { texto: "HALLAZGO", clase: "medio" },
    refutado: { texto: "REFUTADO", clase: "ok" },
    "no verificado": { texto: "NO VERIFICADO", clase: "info" },
    "en curso": { texto: "EN CURSO", clase: "dato" },
  };
  return mapa[v] || { texto: v.toUpperCase(), clase: "info" };
}

/** Etiqueta y clase del estado de redacción de un artefacto. */
export function estadoRedaccion(valor) {
  const v = String(valor || "desconocido").toLowerCase();
  if (v === "redactado") return { texto: "REDACTADO", clase: "ok" };
  if (v === "sin_verificar") return { texto: "SIN REDACTAR", clase: "critico" };
  return { texto: "DESCONOCIDO", clase: "info" };
}

/** Traduce la tríada de "¿vive?" a etiqueta y clase. */
export function vivo(valor) {
  const v = String(valor || "").toLowerCase();
  if (v === "sí" || v === "si") return { texto: "PROBABLEMENTE VIVO", clase: "critico" };
  if (v === "no") return { texto: "CONFIRMADO MUERTO", clase: "ok" };
  if (v === "no aplica") return { texto: "NO APLICA", clase: "info" };
  return { texto: "NUNCA PROBADO", clase: "alto" };
}

/** Trunca un texto largo conservando palabras completas. */
export function truncar(texto, maximo = 120) {
  const t = String(texto ?? "");
  if (t.length <= maximo) return t;
  return `${t.slice(0, maximo - 1)}…`;
}

/** Convierte segundos en un texto de cuenta atrás legible. */
export function duracion(segundos) {
  const s = Math.max(0, Math.floor(Number(segundos) || 0));
  const dias = Math.floor(s / 86400);
  const horas = Math.floor((s % 86400) / 3600);
  const minutos = Math.floor((s % 3600) / 60);
  const seg = s % 60;
  if (dias > 0) return `${dias}d ${String(horas).padStart(2, "0")}h ${String(minutos).padStart(2, "0")}m`;
  if (horas > 0) return `${String(horas).padStart(2, "0")}h ${String(minutos).padStart(2, "0")}m ${String(seg).padStart(2, "0")}s`;
  return `${String(minutos).padStart(2, "0")}m ${String(seg).padStart(2, "0")}s`;
}

/** Normaliza un valor a texto compacto para celdas densas. */
export function compacto(valor) {
  if (valor === null || valor === undefined || valor === "") return "—";
  return String(valor);
}
