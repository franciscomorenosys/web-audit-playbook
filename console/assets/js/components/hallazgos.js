/**
 * Vista HALLAZGOS: tabla densa y filtrable con drawer de detalle.
 *
 * Estados admitidos: `hallazgo`, `refutado`, `no verificado`, `en curso`.
 * Un hallazgo «no verificado» no es una conclusión: la tabla lo dice.
 */

import { api } from "../data.js";
import { compacto, estado, severidad, truncar } from "../format.js";
import { abrirDrawer } from "./drawer.js";
import { dato, el, etiqueta, panel, referenciaEvidencia, tabla, vacio } from "./comunes.js";

/** Estado interno de los filtros de la vista. */
const filtros = {
  texto: "",
  severidad: "",
  categoria: "",
  estado: "",
  owner: "",
};

/** Aplica los filtros a la lista de hallazgos. */
function filtrar(items) {
  return items.filter((item) => {
    if (filtros.severidad && item.severidad !== filtros.severidad) return false;
    if (filtros.categoria && item.categoria !== filtros.categoria) return false;
    if (filtros.estado && item.estado !== filtros.estado) return false;
    if (filtros.owner && item.owner !== filtros.owner) return false;
    if (filtros.texto) {
      const aguja = filtros.texto.toLowerCase();
      const texto = [
        item.id,
        item.titulo,
        item.descripcion,
        item.owner,
        item.categoria,
        (item.evidencia || []).map((e) => e.fichero).join(" "),
      ]
        .join(" ")
        .toLowerCase();
      if (!texto.includes(aguja)) return false;
    }
    return true;
  });
}

/** Abre el drawer con el detalle completo de un hallazgo. */
function abrirDetalle(hallazgo) {
  const contenido = el("div", {});

  contenido.append(
    el(
      "div",
      { className: "mosaico", estilo: "margin-bottom:var(--s-3)" },
    ),
  );

  const severidadInfo = severidad(hallazgo.severidad);
  const estadoInfo = estado(hallazgo.estado);
  const chips = contenido.querySelector(".mosaico");
  chips.append(
    el("div", { className: "metrica" }, el("div", { className: "metrica__valor", texto: severidadInfo.texto }), el("div", { className: "metrica__etiqueta", texto: "severidad" })),
    el("div", { className: "metrica" }, el("div", { className: "metrica__valor", texto: estadoInfo.texto }), el("div", { className: "metrica__etiqueta", texto: "estado" })),
    el("div", { className: "metrica" }, el("div", { className: "metrica__valor", texto: hallazgo.id }), el("div", { className: "metrica__etiqueta", texto: "identificador" })),
  );

  contenido.append(
    dato("Categoría", hallazgo.categoria),
    dato("Owner", hallazgo.owner),
    dato("Descripción", hallazgo.descripcion || "Sin descripción."),
  );

  const bloqueEvidencia = el("div", { className: "dato" });
  bloqueEvidencia.append(el("div", { className: "dato__clave", texto: "Evidencia" }));
  const valorEvidencia = el("div", { className: "dato__valor" });
  const evidencias = hallazgo.evidencia || [];
  if (evidencias.length === 0) {
    valorEvidencia.append(el("span", { className: "tenuisimo", texto: "Sin fichero de evidencia referenciado." }));
  } else {
    for (const entrada of evidencias) {
      valorEvidencia.append(
        referenciaEvidencia(entrada.fichero, entrada.hash, entrada.referencia),
      );
    }
  }
  bloqueEvidencia.append(valorEvidencia);
  contenido.append(bloqueEvidencia);

  contenido.append(
    dato(
      "Comando de reproducción",
      hallazgo.comando
        ? el("code", { texto: hallazgo.comando })
        : "No hay comando de reproducción registrado.",
    ),
    dato("Footprint", hallazgo.footprint || "No registrado."),
    dato("Estado", estadoInfo.texto),
    dato("Fuente", hallazgo.fuente || "—"),
  );

  abrirDrawer({ titulo: hallazgo.titulo, contenido });
}

/** Renderiza la vista. */
export async function render(contenedor) {
  const datos = await api("/api/findings");
  const todos = datos.items || [];

  const cuerpoTabla = el("div", {});
  const resumen = el("div", { className: "mosaico", estilo: "margin-bottom:var(--s-3)" });

  // -- filtros -------------------------------------------------------------- //
  const opcion = (valor, texto, seleccionado) => {
    const o = document.createElement("option");
    o.value = valor;
    o.textContent = texto;
    if (seleccionado) o.selected = true;
    return o;
  };

  const selSeveridad = document.createElement("select");
  selSeveridad.setAttribute("aria-label", "Filtrar por severidad");
  selSeveridad.append(opcion("", "Severidad: todas", !filtros.severidad));
  for (const valor of ["critico", "alto", "medio", "bajo", "info"]) {
    selSeveridad.append(opcion(valor, severidad(valor).texto, filtros.severidad === valor));
  }

  const selEstado = document.createElement("select");
  selEstado.setAttribute("aria-label", "Filtrar por estado");
  selEstado.append(opcion("", "Estado: todos", !filtros.estado));
  for (const valor of ["hallazgo", "refutado", "no verificado", "en curso"]) {
    selEstado.append(opcion(valor, estado(valor).texto, filtros.estado === valor));
  }

  const selCategoria = document.createElement("select");
  selCategoria.setAttribute("aria-label", "Filtrar por categoría");
  selCategoria.append(opcion("", "Categoría: todas", !filtros.categoria));
  const categorias = [...new Set(todos.map((h) => h.categoria))].sort();
  for (const valor of categorias) {
    selCategoria.append(opcion(valor, valor, filtros.categoria === valor));
  }

  const selOwner = document.createElement("select");
  selOwner.setAttribute("aria-label", "Filtrar por owner");
  selOwner.append(opcion("", "Owner: todos", !filtros.owner));
  const owners = [...new Set(todos.map((h) => h.owner))].sort();
  for (const valor of owners) {
    selOwner.append(opcion(valor, valor, filtros.owner === valor));
  }

  const buscador = document.createElement("input");
  buscador.type = "search";
  // El rótulo anterior ("Buscar en título, descripción, evidencia…") no cabía
  // en el campo y se leía cortado a media palabra.
  buscador.placeholder = "Buscar en título o evidencia…";
  buscador.value = filtros.texto;
  buscador.setAttribute("aria-label", "Buscar hallazgos");

  const contador = el("span", { className: "panel__nota" });

  const barraFiltros = el(
    "div",
    { className: "barra-filtros" },
    el("label", { className: "campo" }, buscador),
    el("label", { className: "campo" }, selSeveridad),
    el("label", { className: "campo" }, selEstado),
    el("label", { className: "campo" }, selCategoria),
    el("label", { className: "campo" }, selOwner),
    contador,
  );

  // -- tabla ---------------------------------------------------------------- //
  const columnas = [
    {
      clave: "id",
      titulo: "ID",
      render: (h) => el("span", { className: "mono", texto: h.id }),
    },
    {
      clave: "severidad",
      titulo: "Severidad",
      render: (h) => etiqueta(severidad(h.severidad).texto, severidad(h.severidad).clase),
    },
    {
      clave: "titulo",
      titulo: "Hallazgo",
      render: (h) =>
        el(
          "div",
          {},
          el("div", { texto: h.titulo }),
          el("div", {
            className: "celda-truncar tenue",
            estilo: "font-size:var(--fs-micro)",
            texto: truncar(h.descripcion, 110),
          }),
        ),
    },
    { clave: "categoria", titulo: "Categoría", render: (h) => compacto(h.categoria) },
    {
      clave: "estado",
      titulo: "Estado",
      render: (h) => etiqueta(estado(h.estado).texto, estado(h.estado).clase),
    },
    { clave: "owner", titulo: "Owner", render: (h) => compacto(h.owner) },
    {
      clave: "evidencia",
      titulo: "Evidencia",
      render: (h) => {
        const primero = (h.evidencia || [])[0];
        if (!primero) return el("span", { className: "tenuisimo", texto: "—" });
        return el(
          "div",
          { className: "mono", estilo: "font-size:var(--fs-micro)" },
          el("code", { texto: primero.fichero }),
          el("div", { className: "tenuisimo", texto: primero.hash ? `sha256[:12] ${primero.hash}` : "" }),
        );
      },
    },
  ];

  function pintar() {
    const visibles = filtrar(todos);
    contador.textContent = `${visibles.length} de ${todos.length} hallazgos`;
    cuerpoTabla.innerHTML = "";
    if (visibles.length === 0) {
      cuerpoTabla.append(
        vacio(
          "Ningún hallazgo con esos filtros",
          todos.length === 0
            ? "No hay hallazgos: la evidencia no ha producido ninguno, o todavía no se ha generado."
            : "Ajusta o limpia los filtros para ver el resto.",
        ),
      );
      return;
    }
    cuerpoTabla.append(
      tabla(columnas, visibles, {
        tarjetas: true,
        caption: "Tabla de hallazgos. Pulsa una fila para abrir su detalle.",
        filaClave: (h) => h.id,
        etiquetaFila: (h) => h.titulo,
        alPulsarFila: (h) => abrirDetalle(h),
      }),
    );
  }

  selSeveridad.addEventListener("change", () => {
    filtros.severidad = selSeveridad.value;
    pintar();
  });
  selEstado.addEventListener("change", () => {
    filtros.estado = selEstado.value;
    pintar();
  });
  selCategoria.addEventListener("change", () => {
    filtros.categoria = selCategoria.value;
    pintar();
  });
  selOwner.addEventListener("change", () => {
    filtros.owner = selOwner.value;
    pintar();
  });
  buscador.addEventListener("input", () => {
    filtros.texto = buscador.value;
    pintar();
  });

  // -- resumen --------------------------------------------------------------- //
  const porEstado = datos.resumen?.por_estado || {};
  for (const clave of ["hallazgo", "refutado", "no verificado", "en curso"]) {
    const info = estado(clave);
    resumen.append(
      el(
        "div",
        { className: `metrica${clave === "hallazgo" ? " metrica--ambar" : ""}` },
        el("div", { className: "metrica__valor", texto: String(porEstado[clave] || 0) }),
        el("div", { className: "metrica__etiqueta", texto: info.texto }),
      ),
    );
  }
  resumen.append(
    el(
      "div",
      { className: "metrica" },
      el("div", { className: "metrica__valor", texto: String(datos.resumen?.total || 0) }),
      el("div", { className: "metrica__etiqueta", texto: "total" }),
    ),
  );

  contenedor.append(
    el("div", { className: "revelar" }, resumen),
    panel(
      "Hallazgos",
      "estados: hallazgo · refutado · no verificado · en curso",
      el("div", {}, barraFiltros, cuerpoTabla),
      { sinCuerpo: true },
    ),
  );

  pintar();
}
