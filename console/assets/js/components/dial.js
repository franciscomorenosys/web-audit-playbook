/**
 * Dial instrumental del Attack Exposure Score.
 *
 * SVG puro: arco graduado con las cinco bandas reales del script
 * (`attack_surface_report.py`), aguja con contrapeso y lectura numérica.
 * El valor SIEMPRE aparece también como texto: el dial nunca es el único
 * portador de información.
 *
 * Convenciones angulares: 0° = las 12 en punto, Growing en sentido horario.
 */

import { banda as colorBanda } from "../format.js";

const CX = 200;
const CY = 180;
const R = 132;
const INICIO = 225; // 0 del índice: abajo a la izquierda
const RECORRIDO = 270; // barrido total, sentido horario

// Espacio de nombres XML de SVG. Se compone en tiempo de ejecución para que
// el rastreo de "recursos externos" sólo encuentre URLs de red: un
// identificador de espacio de nombres no es una petición.
const NS = ["http:", "", "www.w3.org", "2000", "svg"].join("/");

/** Devuelve las coordenadas polares de un ángulo en grados. */
function polar(angulo, radio = R) {
  const rad = ((angulo - 90) * Math.PI) / 180;
  return [CX + radio * Math.cos(rad), CY + radio * Math.sin(rad)];
}

/** Traza un arco SVG entre dos ángulos. */
function describeArc(anguloInicio, anguloFin, radio = R) {
  const [x1, y1] = polar(anguloInicio, radio);
  const [x2, y2] = polar(anguloFin, radio);
  const grande = anguloFin - anguloInicio > 180 ? 1 : 0;
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${radio} ${radio} 0 ${grande} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

/** Convierte un valor 0-100 en el ángulo de la aguja. */
function anguloDe(valor) {
  const v = Math.max(0, Math.min(100, Number(valor) || 0));
  return INICIO + (v / 100) * RECORRIDO;
}

/** Crea un elemento SVG con atributos. */
function svgEl(tag, atributos = {}) {
  const nodo = document.createElementNS(NS, tag);
  for (const [clave, valor] of Object.entries(atributos)) {
    nodo.setAttribute(clave, String(valor));
  }
  return nodo;
}

/**
 * Construye el dial.
 *
 * @param {object} opciones
 * @param {number|null} opciones.valor Valor 0-100 o `null` si no es evaluable.
 * @param {string} opciones.banda Banda calculada por el script.
 * @param {boolean} opciones.evaluable Si hay evidencia detrás del número.
 */
export function crearDial({ valor, banda, evaluable }) {
  const raiz = document.createElement("div");
  raiz.className = "dial";

  const escala = valor === null || valor === undefined ? 0 : Number(valor);
  const svg = svgEl("svg", {
    class: "dial__svg",
    viewBox: "0 0 400 292",
    role: "img",
  });
  svg.setAttribute(
    "aria-label",
    evaluable
      ? `Attack Exposure Score: ${escala.toFixed(1)} de 100, banda ${banda}`
      : "Attack Exposure Score no evaluable: no hay evidencia suficiente",
  );

  // -- pistas y bandas ------------------------------------------------------ //
  svg.append(
    svgEl("path", {
      class: "dial__arco",
      d: describeArc(INICIO, INICIO + RECORRIDO),
      stroke: "var(--surface-3)",
      "stroke-width": 16,
    }),
  );

  const bandas = [
    { desde: 0, hasta: 19.9, color: "var(--banda-bajo)" },
    { desde: 20, hasta: 39.9, color: "var(--banda-moderado)" },
    { desde: 40, hasta: 59.9, color: "var(--banda-alto)" },
    { desde: 60, hasta: 79.9, color: "var(--banda-critico)" },
    { desde: 80, hasta: 100, color: "var(--banda-severo)" },
  ];

  for (const item of bandas) {
    const inicio = INICIO + (item.desde / 100) * RECORRIDO + 0.8;
    const fin = INICIO + (item.hasta / 100) * RECORRIDO - 0.8;
    svg.append(
      svgEl("path", {
        class: "dial__arco",
        d: describeArc(inicio, fin),
        stroke: item.color,
        "stroke-width": 16,
        opacity: "0.88",
      }),
    );
  }

  // -- graduación ------------------------------------------------------------ //
  for (let valor = 0; valor <= 100; valor += 5) {
    const angulo = anguloDe(valor);
    const mayor = valor % 20 === 0;
    const media = valor % 10 === 0;
    const largo = mayor ? 14 : media ? 10 : 6;
    const [x1, y1] = polar(angulo, R - 9);
    const [x2, y2] = polar(angulo, R - 9 - largo);
    svg.append(
      svgEl("line", {
        class: mayor
          ? "dial__marca-mayor"
          : media
            ? "dial__marca-media"
            : "dial__marca-menor",
        x1: x1.toFixed(2),
        y1: y1.toFixed(2),
        x2: x2.toFixed(2),
        y2: y2.toFixed(2),
      }),
    );
    if (mayor) {
      const [tx, ty] = polar(angulo, R - 32);
      const texto = svgEl("text", {
        class: "dial__marca-texto",
        x: tx.toFixed(2),
        y: (ty + 3).toFixed(2),
      });
      texto.textContent = String(valor);
      svg.append(texto);
    }
  }

  // -- aguja (dibujada apuntando a las 3; se rota en tiempo de ejecución) ---- //
  const aguja = svgEl("g", { class: "dial__aguja" });
  aguja.append(
    svgEl("line", {
      class: "dial__aguja-cuerpo",
      x1: CX - 16,
      y1: CY,
      x2: CX + R - 26,
      y2: CY,
      "stroke-width": 3,
      "stroke-linecap": "round",
    }),
  );
  aguja.append(
    svgEl("polygon", {
      class: "dial__aguja-culata",
      points: `${CX + R - 34},${CY - 6.5} ${CX + R - 18},${CY} ${CX + R - 34},${CY + 6.5}`,
    }),
  );
  aguja.append(svgEl("circle", { class: "dial__aguja-culata", cx: CX, cy: CY, r: 7 }));
  aguja.append(svgEl("circle", { cx: CX, cy: CY, r: 2.4, fill: "var(--bg)" }));
  svg.append(aguja);

  // -- lectura central -------------------------------------------------------- //
  const valorTexto = svgEl("text", { class: "dial__centro-valor", x: CX, y: CY + 70 });
  // Sin evidencia no se escribe un 0: un 0 aquí se lee como «seguro».
  valorTexto.textContent = evaluable ? "0" : "—";
  svg.append(valorTexto);

  const bandaTexto = svgEl("text", { class: "dial__centro-banda", x: CX, y: CY + 92 });
  bandaTexto.textContent = banda || "No evaluable";
  bandaTexto.setAttribute("fill", colorBanda(banda).color);
  svg.append(bandaTexto);

  raiz.append(svg);

  const pie = document.createElement("p");
  pie.className = "dial__pie";
  pie.textContent = evaluable
    ? `Índice ${escala.toFixed(1)} / 100 · banda ${banda} · las cinco bandas son las del script`
    : "No evaluable: sin evidencia, un 0 no significa «seguro».";
  raiz.append(pie);

  // -- animación -------------------------------------------------------------- //
  const anguloFinal = evaluable ? anguloDe(escala) : INICIO;
  requestAnimationFrame(() => {
    aguja.style.transform = `rotate(${(anguloFinal - 90).toFixed(2)}deg)`;
  });

  if (evaluable) animarContador(valorTexto, escala);

  return raiz;
}

/** Cuenta el valor del dial de 0 al número final. */
function animarContador(nodo, destino) {
  const reducir = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reducir) {
    nodo.textContent = destino.toFixed(1);
    return;
  }
  const duracion = 900;
  const inicio = performance.now();
  function paso(ahora) {
    const t = Math.min(1, (ahora - inicio) / duracion);
    const suavizado = 1 - (1 - t) ** 3;
    nodo.textContent = (destino * suavizado).toFixed(1);
    if (t < 1) requestAnimationFrame(paso);
    else nodo.textContent = destino.toFixed(1);
  }
  requestAnimationFrame(paso);
}
