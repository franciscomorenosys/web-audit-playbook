#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Renderiza teaser-dental-easy.html -> PDF A4 con Playwright/Chromium,
y luego sanea los metadatos del PDF para que no filtren nombres de
herramientas internas.

Uso:  .venv/bin/python build.py
"""
import os
import sys
import datetime
from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "teaser-dental-easy.html")
RAW = os.path.join(HERE, ".build-raw.pdf")
OUT = os.path.join(HERE, "Evaluacion-Seguridad-Clinica-Dental-Easy.pdf")

FECHA = "22 de octubre de 2026"

META = {
    "/Title":    "Evaluación de Seguridad y Riesgos Digitales — Clínica Dental Easy",
    "/Author":   "Asesoría de Seguridad Digital",
    "/Subject":  "Resumen ejecutivo de la revisión de seguridad y riesgos digitales "
                 "— documento preparatorio, detalle técnico reservado para sesión.",
    "/Keywords": "seguridad digital; cumplimiento; datos personales; clínica dental",
    "/Creator":  "",
    "/Producer": "",
    "/Company":  "",
    "/Manager":  "",
}

FOOTER = f"""
<div style="width:100%;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;
            font-size:7pt;color:#7A8894;padding:0 18mm;
            -webkit-print-color-adjust:exact;display:flex;
            justify-content:space-between;align-items:center;">
  <span>Clínica Dental Easy&nbsp;&nbsp;·&nbsp;&nbsp;Documento confidencial</span>
  <span>{FECHA}</span>
  <span>Página <span class="pageNumber"></span> de <span class="totalPages"></span></span>
</div>
"""


def render():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=[
            "--font-render-hinting=none",
            "--disable-lcd-text",
            "--force-color-profile=srgb",
            "--disable-font-subpixel-positioning",
        ])
        page = browser.new_page()
        page.goto("file://" + SRC, wait_until="networkidle")
        page.evaluate("document.fonts.ready")
        page.emulate_media(media="print")
        page.wait_for_timeout(400)

        page.pdf(
            path=RAW,
            format="A4",
            print_background=True,
            prefer_css_page_size=True,
            display_header_footer=True,
            header_template="<div></div>",
            footer_template=FOOTER,
            margin={"top": "20mm", "bottom": "19mm", "left": "18mm", "right": "18mm"},
        )
        browser.close()


def sanitize():
    from pypdf import PdfReader, PdfWriter

    reader = PdfReader(RAW)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    for k, v in META.items():
        try:
            writer.add_metadata({k: v})
        except Exception:
            pass

    # quita cualquier XMP heredado que pudiera contener nombres de herramienta
    try:
        if "/Metadata" in writer._root_object:
            del writer._root_object["/Metadata"]
    except Exception:
        pass

    with open(OUT, "wb") as fh:
        writer.write(fh)


if __name__ == "__main__":
    render()
    sanitize()
    for f in (RAW,):
        if os.path.exists(f):
            os.remove(f)

    from pypdf import PdfReader
    r = PdfReader(OUT)
    size = os.path.getsize(OUT)
    print(f"PDF      : {OUT}")
    print(f"páginas  : {len(r.pages)}")
    print(f"tamaño   : {size/1024:.0f} KB")
    print("metadatos:")
    for k, v in (r.metadata or {}).items():
        print(f"   {k} = {v!r}")