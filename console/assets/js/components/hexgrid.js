/**
 * Hex-grid de superficie.
 *
 * Un campo de celdas hexagonales en proper tiling (tapa plana): cada
 * subdominio conocido ocupa una celda iluminada según su estado de
 * exposición; el resto de celdas es superficie sin exposición conocida. El
 * hexágono **no** es un adorno: cada celda iluminada es un nombre real de la
 * evidencia.
 */

// Espacio de nombres XML de SVG. Se compone en tiempo de ejecución para que
// el rastreo de "recursos externos" sólo encuentre URLs de red: un
// identificador de espacio de nombres no es una petición.
const NS = ["http:", "", "www.w3.org", "2000", "svg"].join("/");

/** Crea un elemento SVG con atributos. */
function svgEl(tag, atributos = {}) {
  const nodo = document.createElementNS(NS, tag);
  for (const [clave, valor] of Object.entries(atributos)) {
    nodo.setAttribute(clave, String(valor));
  }
  return nodo;
}

/** Vértices de un hexágono de tapa plana, centrado en (cx, cy). */
function vertices(cx, cy, radio) {
  const puntos = [];
  for (let i = 0; i < 6; i += 1) {
    const angulo = (Math.PI / 180) * (60 * i);
    puntos.push(
      `${(cx + radio * Math.cos(angulo)).toFixed(2)},${(cy + radio * Math.sin(angulo)).toFixed(2)}`,
    );
  }
  return puntos.join(" ");
}

/** Etiqueta corta de un host: la primera etiqueta, que es la que significa. */
function etiquetaCorta(nombre) {
  const partes = String(nombre).split(".");
  const base = partes[0] || nombre;
  return base.length > 12 ? `${base.slice(0, 11)}…` : base;
}

/** Color de relleno según el nivel del subdominio. */
const COLORES = {
  expuesto: "rgba(229, 72, 77, 0.62)",
  sospechoso: "rgba(255, 166, 48, 0.46)",
  evaluado: "rgba(88, 166, 255, 0.24)",
  autorizado: "rgba(63, 185, 80, 0.28)",
  inventario: "rgba(120, 132, 145, 0.13)",
  inactivo: "rgba(120, 132, 145, 0.04)",
};

/** Colores de la leyenda (se aplican por CSSOM, no por atributo `style`). */
const COLORES_LEYENDA = {
  expuesto: "rgba(229, 72, 77, 0.62)",
  sospechoso: "rgba(255, 166, 48, 0.46)",
  evaluado: "rgba(88, 166, 255, 0.24)",
  inventario: "rgba(120, 132, 145, 0.13)",
};

/**
 * Construye el hex-grid.
 *
 * @param {Array<{nombre: string, nivel: string, severidad: string, evidencia: string}>} subdominios
 */
export function crearHexGrid(subdominios) {
  const raiz = document.createElement("div");
  raiz.className = "hexpanel";

  if (!subdominios || subdominios.length === 0) {
    const aviso = document.createElement("div");
    aviso.className = "vacio u-mt-3";
    const titulo = document.createElement("strong");
    titulo.textContent = "Sin inventario de subdominios";
    aviso.append(titulo);
    const detalle = document.createElement("span");
    detalle.textContent =
      "No hay crt.json en la evidencia: sin Certificate Transparency no se puede " +
      "enumerar la superficie de subdominios.";
    aviso.append(detalle);
    raiz.append(aviso);
    return raiz;
  }

  const radio = 20;
  const pasoX = radio * 1.5; // separación horizontal (tapa plana)
  const pasoY = radio * Math.sqrt(3); // separación vertical
  const margen = radio + 8;

  const columnas = Math.min(8, Math.max(3, Math.ceil(subdominios.length / 2)));
  const filas = Math.max(3, Math.ceil(subdominios.length / columnas));
  const ancho = (columnas - 1) * pasoX + radio * 2 + margen * 2;
  const alto = (filas - 1) * pasoY + radio + margen * 2;

  const svg = svgEl("svg", {
    class: "hexpanel__svg",
    viewBox: `0 0 ${ancho.toFixed(0)} ${alto.toFixed(0)}`,
    role: "img",
  });
  svg.setAttribute(
    "aria-label",
    `Superficie de subdominios: ${subdominios.length} nombres conocidos por Certificate Transparency.`,
  );

  const celdas = columnas * filas;
  for (let indice = 0; indice < celdas; indice += 1) {
    const columna = indice % columnas;
    const fila = Math.floor(indice / columnas);
    const cx = margen + radio + columna * pasoX;
    const cy = margen + radio + fila * pasoY + (columna % 2 ? pasoY / 2 : 0);
    const sub = subdominios[indice];

    const celda = svgEl("polygon", {
      class: "hexpanel__hex",
      points: vertices(cx, cy, radio),
      fill: COLORES[sub ? sub.nivel : "inactivo"],
    });

    if (sub) {
      const titulo = svgEl("title");
      titulo.textContent = `${sub.nombre} · ${sub.nivel}${
        sub.evidencia ? ` · evidencia: ${sub.evidencia}` : ""
      }`;
      celda.append(titulo);
      svg.append(celda);

      const texto = svgEl("text", {
        class: "hexpanel__texto",
        x: cx.toFixed(2),
        y: (cy + 2).toFixed(2),
      });
      texto.textContent = etiquetaCorta(sub.nombre);
      svg.append(texto);
    } else {
      celda.setAttribute("aria-hidden", "true");
      svg.append(celda);
    }
  }

  raiz.append(svg);

  const barrido = document.createElement("div");
  barrido.className = "hexpanel__barrido";
  barrido.setAttribute("aria-hidden", "true");
  raiz.append(barrido);

  const leyenda = document.createElement("div");
  leyenda.className = "hexpanel__leyenda";
  const entradas = [
    ["expuesto", "expuesto (sonda)"],
    ["sospechoso", "sospechoso (pendiente)"],
    ["evaluado", "evaluado, sin exposición"],
    ["inventario", "sólo inventario CT"],
  ];
  for (const [clave, texto] of entradas) {
    const item = document.createElement("span");
    const cuadrado = document.createElement("i");
    cuadrado.style.background = COLORES_LEYENDA[clave];
    item.append(cuadrado);
    item.append(document.createTextNode(texto));
    leyenda.append(item);
  }
  raiz.append(leyenda);

  return raiz;
}
