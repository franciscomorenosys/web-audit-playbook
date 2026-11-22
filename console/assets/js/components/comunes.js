/**
 * Constructores de DOM compartidos.
 *
 * El texto de la evidencia **nunca** se inyecta como HTML: se usa
 * `textContent`. Sólo el marcado literal (SVG de los componentes) se escribe
 * con `innerHTML`.
 */

/**
 * Crea un elemento.
 *
 * @param {string} tag Etiqueta.
 * @param {object} [props] Propiedades: `className`, `texto`, `attrs`, `dataset`, `html`.
 * @param {...(Node|string)} hijos Contenido hijo.
 */
export function el(tag, props = {}, ...hijos) {
  const nodo = document.createElement(tag);
  if (props.className) nodo.className = props.className;
  if (props.texto !== undefined && props.texto !== null) nodo.textContent = String(props.texto);
  if (props.html !== undefined) nodo.innerHTML = props.html;
  // El estilo se aplica por CSSOM (no por atributo `style`): la CSP de la
  // consola prohíbe 'unsafe-inline', y setAttribute('style', …) quedaría
  // bloqueado. El CSSOM sí está permitido.
  if (props.estilo) nodo.style.cssText = props.estilo;
  if (props.attrs) {
    for (const [clave, valor] of Object.entries(props.attrs)) {
      if (valor === null || valor === undefined || valor === false) continue;
      nodo.setAttribute(clave, valor === true ? "" : String(valor));
    }
  }
  if (props.dataset) {
    for (const [clave, valor] of Object.entries(props.dataset)) {
      nodo.dataset[clave] = String(valor);
    }
  }
  if (props.on) {
    for (const [evento, manejador] of Object.entries(props.on)) {
      nodo.addEventListener(evento, manejador);
    }
  }
  for (const hijo of hijos.flat()) {
    if (hijo === null || hijo === undefined || hijo === false) continue;
    nodo.append(hijo instanceof Node ? hijo : document.createTextNode(String(hijo)));
  }
  return nodo;
}

/**
 * Panel con cabecera.
 *
 * @param {string} titulo Título de la sección.
 * @param {string} [nota] Nota de la cabecera.
 * @param {Node|Node[]} cuerpo Contenido.
 * @param {object} [opciones] `clase`, `sinCuerpo`.
 */
export function panel(titulo, nota, cuerpo, opciones = {}) {
  const cabecera = el(
    "div",
    { className: "panel__cabecera" },
    el("h2", { className: "panel__titulo", texto: titulo }),
    nota ? el("span", { className: "panel__nota", texto: nota }) : null,
  );
  const contenido = el(
    "div",
    { className: `panel__cuerpo${opciones.sinCuerpo ? " panel__cuerpo--liso" : ""}` },
    cuerpo,
  );
  return el(
    "section",
    { className: `panel ${opciones.clase || ""}`.trim() },
    cabecera,
    contenido,
  );
}

/**
 * Etiqueta de estado.
 *
 * @param {string} texto Texto.
 * @param {string} [clase] Variante (`critico`, `alto`, `medio`, `ok`…).
 */
export function etiqueta(texto, clase = "") {
  return el("span", { className: `etiqueta${clase ? ` etiqueta--${clase}` : ""}`, texto });
}

/** Bloque vacío con explicación (nunca un 0 disfrazado de dato). */
export function vacio(titulo, detalle) {
  return el(
    "div",
    { className: "vacio" },
    el("strong", { texto: titulo }),
    el("span", { texto: detalle || "" }),
  );
}

/**
 * Tabla densa.
 *
 * @param {Array<{clave: string, titulo: string}>} columnas
 * @param {Array<object>} filas
 * @param {object} [opciones] `caption`, `tarjetas`, `alPulsarFila`, `filaClave`, `clase`.
 */
export function tabla(columnas, filas, opciones = {}) {
  const thead = el("thead");
  const tr = el("tr");
  for (const columna of columnas) {
    tr.append(el("th", { attrs: { scope: "col" }, texto: columna.titulo }));
  }
  thead.append(tr);

  const tbody = el("tbody");
  for (const fila of filas) {
    const trFila = el("tr");
    if (opciones.filaClave) trFila.dataset.clave = opciones.filaClave(fila);
    for (const columna of columnas) {
      const td = el("td", { attrs: { "data-etiqueta": columna.titulo } });
      const contenido = columna.render(fila, td);
      if (contenido !== undefined && contenido !== null) {
        if (contenido instanceof Node) td.append(contenido);
        else td.append(document.createTextNode(String(contenido)));
      }
      trFila.append(td);
    }
    if (opciones.alPulsarFila) {
      trFila.tabIndex = 0;
      trFila.setAttribute(
        "aria-label",
        `Abrir el detalle de ${opciones.etiquetaFila ? opciones.etiquetaFila(fila) : "la fila"}`,
      );
      trFila.addEventListener("click", (evento) => {
        if (evento.target.closest("a, button, select, input")) return;
        opciones.alPulsarFila(fila, trFila);
      });
      trFila.addEventListener("keydown", (evento) => {
        if (evento.key === "Enter" || evento.key === " ") {
          evento.preventDefault();
          opciones.alPulsarFila(fila, trFila);
        }
      });
    }
    tbody.append(trFila);
  }

  const tabla = el(
    "table",
    {
      className: `tabla${opciones.tarjetas ? " tabla--tarjetas" : ""}${
        opciones.clase ? ` ${opciones.clase}` : ""
      }`,
    },
    opciones.caption ? el("caption", { texto: opciones.caption }) : null,
    thead,
    tbody,
  );
  return el("div", { className: "tabla-envoltura" }, tabla);
}

/**
 * Fila de dato (clave/valor) para el drawer.
 *
 * @param {string} clave
 * @param {Node|string} valor
 */
export function dato(clave, valor) {
  const celda = el("div", { className: "dato__valor" });
  if (valor instanceof Node) celda.append(valor);
  else celda.textContent = valor === null || valor === undefined || valor === "" ? "—" : String(valor);
  return el("div", { className: "dato" }, el("div", { className: "dato__clave", texto: clave }), celda);
}

/**
 * Referencia a un fichero de evidencia con su hash corto.
 *
 * @param {string} fichero
 * @param {string} hash
 * @param {string} [referencia]
 */
export function referenciaEvidencia(fichero, hash, referencia) {
  const bloque = el("div", { className: "mono" });
  bloque.append(el("code", { texto: fichero || "—" }));
  if (hash) {
    bloque.append(
      el("span", { className: "tenuisimo", texto: `  sha256[:12] ${hash}` }),
    );
  }
  if (referencia) {
    bloque.append(el("div", { className: "tenuisimo", texto: referencia }));
  }
  return bloque;
}

/** Título de sección con línea divisoria. */
export function seccion(titulo, ...contenido) {
  return el(
    "section",
    { className: "seccion" },
    el("h2", { className: "seccion__titulo", texto: titulo }),
    ...contenido,
  );
}

/** Métrica del mosaico. */
export function metrica(valor, etiquetaTexto, variante = "") {
  return el(
    "div",
    { className: `metrica${variante ? ` metrica--${variante}` : ""}` },
    el("div", { className: "metrica__valor", texto: valor }),
    el("div", { className: "metrica__etiqueta", texto: etiquetaTexto }),
  );
}
