#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verificación del PDF entregable:
  1. ¿El texto es seleccionable (no rasterizado)?
  2. Metadatos limpios.
  3. Marca de agua en todas las páginas.
  4. Fuentes incrustadas.
  5. Grep de cadenas prohibidas (texto extraído + bytes crudos + metadatos).
"""
import os
import re
import sys
import zlib
from pypdf import PdfReader

HERE = os.path.dirname(os.path.abspath(__file__))
PDF = os.path.join(HERE, "Evaluacion-Seguridad-Clinica-Dental-Easy.pdf")

FORBIDDEN = [
    "CVE-", "CVSS", "7.1.3", "4.27", "3.7.1", "curl", "nmap", "nuclei",
    "/wp-", "wp-json", "Apps Script", "script.google.com", "gravatar",
    "author=", "262.241", "162.241", "zetgifari", "easy2025dental",
    "pruebas", "fjgrafico", "ortopedista", "mysql", "3306", "PHP 8",
    "sha256", "Mozilla Observatory",
]

# tokens internos de la cadena de herramientas que tampoco deben filtrar
TOOLING = ["Skia", "Chromium", "HeadlessChrome", "Matplotlib", "Playwright",
           "pypdf", "WebKit", "AppleWebKit", "selenium"]

fails = []

def normalize(t):
    """Deshace ligaduras tipográficas (ﬁ ﬂ ﬀ) que rompen la búsqueda literal."""
    for a, b in [("\ufb01","fi"),("\ufb02","fl"),("\ufb00","ff"),
                 ("\ufb03","ffi"),("\ufb04","ffl"),("\u00a0"," ")]:
        t = t.replace(a, b)
    return t

# ---------------------------------------------------------------- texto
reader = PdfReader(PDF)
pages_text = [(p.extract_text() or "") for p in reader.pages]
full = "\n".join(pages_text)
full_n = normalize(full)

print("=" * 74)
print("1. TEXTO SELECCIONABLE")
print("=" * 74)
sample = pages_text[1][:220].replace("\n", " ")
print(f"   páginas ............. {len(reader.pages)}")
print(f"   caracteres extraídos {len(full):,}")
print(f"   muestra (pág. 2) .... {sample!r}")
if len(full) < 8000:
    fails.append("el texto parece rasterizado (muy pocos caracteres extraíbles)")
print(f"   -> {'OK, texto vectorial seleccionable' if len(full) > 8000 else 'FALLA'}")

# ------------------------------------------------------------ metadatos
print()
print("=" * 74)
print("2. METADATOS DEL PDF")
print("=" * 74)
for k, v in (reader.metadata or {}).items():
    print(f"   {k:<12} = {v!r}")
meta_blob = " ".join(str(v) for v in (reader.metadata or {}).values())
for t in TOOLING:
    if t.lower() in meta_blob.lower():
        fails.append(f"metadato filtra herramienta: {t}")

# -------------------------------------------------------------- fuentes
print()
print("=" * 74)
print("3. FUENTES INCRUSTADAS")
print("=" * 74)
fonts = set()
for p in reader.pages:
    try:
        res = p.get("/Resources", {})
        for _, fo in res.get("/Font", {}).items():
            fo = fo.get_object()
            fonts.add(str(fo.get("/BaseFont", "?")))
    except Exception:
        pass
for f in sorted(fonts):
    print("   ", f)
print(f"   -> {len(fonts)} familias incrustadas")

# -------------------------------------------------------- marca de agua
print()
print("=" * 74)
print("4. MARCA DE AGUA Y PIE DE PÁGINA")
print("=" * 74)
watermark_pages = [i + 1 for i, t in enumerate(pages_text) if "CONFIDENCIAL" in normalize(t)]
print(f"   páginas con marca 'CONFIDENCIAL': {watermark_pages}")
missing = [i for i in range(1, len(reader.pages) + 1) if i not in watermark_pages]
if missing:
    fails.append(f"páginas sin marca de agua: {missing}")
foot = [i + 1 for i, t in enumerate(pages_text)
        if "Documento confidencial" in normalize(t)]
print(f"   páginas con pie 'Documento confidencial': {len(foot)}/{len(reader.pages)}")
pageno = [i + 1 for i, t in enumerate(pages_text)
          if re.search(r"P.gina \d+ de 13", normalize(t))]
print(f"   páginas con numeración 'Página N de 13': {pageno}")

# -------------------------------------------------- cadenas prohibidas
print()
print("=" * 74)
print("5. GREP DE CADENAS PROHIBIDAS")
print("=" * 74)
print("   a) texto extraído del PDF")
for term in FORBIDDEN:
    n = len(re.findall(re.escape(term), full_n, re.IGNORECASE))
    if n:
        fails.append(f"PROHIBIDO en texto: {term} ({n})")
        print(f"      ENCONTRADO  {term!r} x{n}")
print("      sin coincidencias" if not any(
    t.lower() in full_n.lower() for t in FORBIDDEN) else "")

print("   b) bytes crudos del archivo (incluye flujos comprimidos)")
raw = open(PDF, "rb").read()
decompressed = bytearray(raw)
for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S):
    try:
        decompressed += zlib.decompress(m.group(1))
    except Exception:
        pass
raw_txt = decompressed.decode("latin-1", "ignore")
# los operadores de dibujo llevan operandos numéricos: se eliminan para que
# un decimal como "4.2749939 0 Td" no se confunda con una cadena prohibida.
blob = re.sub(r"\b\d+\.\d+\b", " ", raw_txt)
blob = re.sub(r"\b\d+\b", " ", blob)
blob = re.sub(r"<[0-9A-Fa-f\s]+>", " ", blob)
for term in FORBIDDEN + TOOLING:
    n = len(re.findall(re.escape(term), blob, re.IGNORECASE))
    if n:
        fails.append(f"PROHIBIDO en bytes: {term} ({n})")
        print(f"      ENCONTRADO  {term!r} x{n}")
print("      sin coincidencias" if not any(
    t.lower() in blob.lower() for t in FORBIDDEN + TOOLING) else "")

print("   c) metadatos")
for term in FORBIDDEN + TOOLING:
    if term.lower() in meta_blob.lower():
        fails.append(f"PROHIBIDO en metadatos: {term}")
        print(f"      ENCONTRADO  {term!r}")
print("      sin coincidencias" if not any(
    t.lower() in meta_blob.lower() for t in FORBIDDEN + TOOLING) else "")

print("   d) recursos externos del HTML fuente")
html = open(os.path.join(HERE, "teaser-dental-easy.html"), encoding="utf-8").read()
for term in FORBIDDEN:
    if term.lower() in html.lower():
        fails.append(f"PROHIBIDO en HTML: {term}")
        print(f"      ENCONTRADO  {term!r}")
print("      sin coincidencias" if not any(
    t.lower() in html.lower() for t in FORBIDDEN) else "")

print()
print("=" * 74)
if fails:
    print("RESULTADO: HAY FALLAS")
    for f in fails:
        print("   -", f)
    sys.exit(1)
print("RESULTADO: TODAS LAS VERIFICACIONES PASARON")
print("=" * 74)
print(f"Archivo : {PDF}")
print(f"Tamaño  : {os.path.getsize(PDF)/1024:.0f} KB")
print(f"Páginas : {len(reader.pages)}")