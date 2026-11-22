#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Genera los gráficos del "teaser" de auditoría para Clínica Dental Easy.
Salida: assets/*.png  (300 dpi, fondo blanco, texto vectorial-ish)
Paleta: slate/navy + una sola rampa de riesgo (ámbar -> rojo).
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "assets")
os.makedirs(OUT, exist_ok=True)

# ---------------------------------------------------------------- paleta
NAVY      = "#16232F"
SLATE     = "#33424F"
MUTED     = "#7A8894"
HAIRLINE  = "#DCE2E7"
CRIT      = "#9E1F1F"   # rojo profundo
ALTO      = "#B4551B"   # naranja quemado
MEDIO     = "#B08123"   # ámbar / ocre
BAJO      = "#5C7794"   # azul acero
GREEN     = "#2F6B4F"

plt.rcParams.update({
    "font.family": "sans-serif",
    # matplotlib no puede cargar la variable woff2 de Inter; Helvetica Neue es
    # una grotesca neutra visualmente equivalente a tamaño de etiqueta.
    "font.sans-serif": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
    "text.color": SLATE,
    "axes.labelcolor": SLATE,
    "xtick.color": MUTED,
    "ytick.color": SLATE,
    "axes.edgecolor": HAIRLINE,
    "savefig.facecolor": "white",
    "figure.facecolor": "white",
})

DPI = 300


def strip(ax, keep_left=False):
    for s in ("top", "right", "bottom"):
        ax.spines[s].set_visible(False)
    if keep_left:
        ax.spines["left"].set_color(HAIRLINE)
        ax.spines["left"].set_linewidth(0.8)
    else:
        ax.spines["left"].set_visible(False)
    ax.tick_params(length=0)


# ================================================== 1. severidad (barras)
def chart_severity():
    # Distribución derivada del registro de riesgos canónico (§5.1–5.5 del
    # informe técnico): severidad = columna de Impacto (I), no Score.
    #   I=5 -> Crítico · I=4 -> Alto · I=3 -> Medio · I<=2 -> Bajo
    labels = ["Crítico", "Alto", "Medio", "Bajo"]
    values = [11, 16, 10, 2]
    colors = [CRIT, ALTO, MEDIO, BAJO]
    total = sum(values)

    fig, ax = plt.subplots(figsize=(6.9, 2.55), dpi=DPI)
    y = range(len(labels))
    ax.barh(list(y), values, height=0.52, color=colors, zorder=3)

    for i, v in enumerate(values):
        pct = v / total * 100
        ax.text(v + 0.45, i, f"{v}", va="center", ha="left",
                fontsize=10.5, fontweight="600", color=NAVY)
        ax.text(v + 1.35, i, f"({pct:.0f} %)", va="center", ha="left",
                fontsize=8.6, color=MUTED)

    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=10, fontweight="500")
    ax.set_xlim(0, 21)
    ax.set_xticks([])
    ax.invert_yaxis()
    strip(ax)
    fig.tight_layout(pad=0.2)
    p = os.path.join(OUT, "severity-distribution.png")
    fig.savefig(p, dpi=DPI, bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)
    print("ok", p, "->", dict(zip(labels, values)), "total", total)


# ================================================== 2. costo de brecha
def chart_breach_cost():
    labels = ["Global (promedio mundial)",
              "América Latina\n(muestra que incluye México)",
              "Salud\n(hospitales y clínicas)",
              "Estados Unidos"]
    values = [4.99, 4.65, 6.64, 11.50]
    colors = [HAIRLINE, "#9FB0BF", CRIT, "#C9D3DB"]

    fig, ax = plt.subplots(figsize=(6.9, 3.05), dpi=DPI)
    x = range(len(labels))
    ax.bar(list(x), values, width=0.46, color=colors, zorder=3)

    for i, v in enumerate(values):
        ax.text(i, v + 0.28, f"${v:.2f} M", ha="center", va="bottom",
                fontsize=10.5, fontweight="700", color=NAVY)

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=8.6, color=SLATE, linespacing=1.45)
    ax.set_ylim(0, 13.6)
    ax.set_yticks([])
    strip(ax)
    ax.tick_params(axis="x", pad=7)
    fig.tight_layout(pad=0.2)
    p = os.path.join(OUT, "breach-cost-benchmarks.png")
    fig.savefig(p, dpi=DPI, bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)
    print("ok", p)


# ============================================= 3. tiempo de respuesta
def chart_response_time():
    identify, contain = 183, 64
    total = identify + contain

    fig, ax = plt.subplots(figsize=(6.9, 1.42), dpi=DPI)
    ax.barh([0], [identify], height=0.34, color=NAVY, zorder=3)
    ax.barh([0], [contain], left=[identify], height=0.34, color=CRIT, zorder=3)

    ax.text(identify / 2, 0, f"{identify}", ha="center", va="center",
            fontsize=10, fontweight="700", color="white")
    ax.text(identify + contain / 2, 0, f"{contain}", ha="center", va="center",
            fontsize=10, fontweight="700", color="white")

    ax.annotate("", xy=(0, 0.40), xytext=(total, 0.40),
                arrowprops=dict(arrowstyle="<->", color=MUTED, lw=0.9))
    ax.text(total / 2, 0.50, f"{total} días en promedio",
            ha="center", va="bottom", fontsize=9.6, fontweight="600", color=NAVY)

    ax.text(identify / 2, -0.40, "Detectar", ha="center", va="center",
            fontsize=8.8, color=SLATE)
    ax.text(identify + contain / 2, -0.40, "Contener", ha="center", va="center",
            fontsize=8.8, color=SLATE)

    ax.set_xlim(-6, total + 6)
    ax.set_ylim(-0.72, 0.86)
    ax.axis("off")
    fig.tight_layout(pad=0.15)
    p = os.path.join(OUT, "breach-response-time.png")
    fig.savefig(p, dpi=DPI, bbox_inches="tight", pad_inches=0.05)
    plt.close(fig)
    print("ok", p)


if __name__ == "__main__":
    chart_severity()
    chart_breach_cost()
    chart_response_time()
    print("\nassets/")
    for f in sorted(os.listdir(OUT)):
        if f.endswith(".png"):
            print(f"  {f}  {os.path.getsize(os.path.join(OUT,f))//1024} KB")