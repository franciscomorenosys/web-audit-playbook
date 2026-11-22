# syntax=docker/dockerfile:1

# =============================================================================
# Consola de Operaciones de Seguridad — imagen de la VPS del auditor
# =============================================================================
#
# QUÉ ES ESTA IMAGEN
# ------------------
# La consola interna (`console/`) empaquetada para correr dentro del stack de
# `deploy/docker-compose.yml`. Python 3.13 de biblioteca estándar: **cero
# dependencias de runtime**, ni en la imagen ni en el navegador.
#
# CONTEXTO DE BUILD: LA RAÍZ DEL REPOSITORIO
# --------------------------------------------
# El contexto NO es `console/`, es la raíz del repo (`.`), y el Dockerfile se
# invoca con `-f console/Dockerfile`. Motivo: la imagen necesita **dos**
# piezas del repositorio:
#
#   console/              → la interfaz y el servidor
#   01-tooling/scripts/   → el toolchain que la consola invoca
#
# El `.dockerignore` de la raíz es una lista blanca: al daemon de Docker sólo
# viajan esas dos rutas. `03-casos/` (evidencia de clientes reales) y el
# resto del repo **nunca entran en el contexto de build**.
#
# LAYOUT DENTRO DE LA IMAGEN
# ---------------------------
#   /app/console/               ← la consola (interfaz + servidor)
#   /app/01-tooling/scripts/    ← el toolchain
#
# Este layout NO es arbitrario: la consola localiza el script del score en
# `Path(__file__).parent.parent / "01-tooling" / "scripts"`
# (`console/api.py`) y el generador de la demo en
# `RAIZ_CONSOLA.parent / "01-tooling" / "scripts"`
# (`console/demo/generar_demo.py`). Con la consola en `/app/console`, ambas
# rutas caen en `/app/01-tooling/scripts`.
#
# CONSTRUIR
# ---------
#   docker build -t web-audit-playbook/console:local -f console/Dockerfile .
#
# o, desde `deploy/`:
#
#   docker compose build console
#
# -----------------------------------------------------------------------------

FROM python:3.13-slim

LABEL org.opencontainers.image.title="web-audit-playbook/console" \
      org.opencontainers.image.description="Consola interna de operaciones de seguridad (Web Audit Playbook)" \
      org.opencontainers.image.source="https://github.com/franciscomorenosys/web-audit-playbook" \
      org.opencontainers.image.licenses="MIT"

# Salida sin buffer (los logs del servidor van a stdout/stderr) y sin
# escribir .pyc en el sistema de ficheros de la imagen.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# -----------------------------------------------------------------------------
# Usuario no-root
# -----------------------------------------------------------------------------
# La consola no escribe nada fuera de sus directorios: no necesita root para
# nada. `console` corre con uid/gid 10001, sin shell y sin home.
# -----------------------------------------------------------------------------
RUN groupadd --gid 10001 console \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin --no-log-init console \
 && mkdir -p /app /data/evidencia \
 && chown -R console:console /app /data

# -----------------------------------------------------------------------------
# Código
# -----------------------------------------------------------------------------
# `console/demo/evidencia/` NO entra en la imagen: es el conjunto de demo
# sintético, se regenera dentro del contenedor (ver console/README.md §Docker).
# -----------------------------------------------------------------------------
COPY --chown=console:console console/ /app/console/
COPY --chown=console:console 01-tooling/scripts/ /app/01-tooling/scripts/

# Directorio de trabajo de la demo: el generador escribe ahí y el usuario
# `console` necesita poder hacerlo.
RUN mkdir -p /app/console/demo/evidencia \
 && chown -R console:console /app/console/demo

# -----------------------------------------------------------------------------
# Puerto y salud
# -----------------------------------------------------------------------------
EXPOSE 8787

# Sonda de vida con la propia stdlib: la imagen no instala `curl` ni `wget`
# (una imagen slim no los trae) y la consola no puede depender de nada
# externo. `/api/summary` responde 200 con cualquier evidencia —incluso
# vacía— y lanza error de HTTP si la consola está rota.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python3", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8787/api/summary')"]

# -----------------------------------------------------------------------------
# Usuario efectivo
# -----------------------------------------------------------------------------
USER console

# -----------------------------------------------------------------------------
# Comando por defecto
# -----------------------------------------------------------------------------
# **Sin modo demo**: la consola arranca leyendo el volumen de evidencia.
# El directorio de evidencia va montado en SOLO LECTURA (ver
# deploy/docker-compose.yml y console/README.md §Docker).
#
# `--no-open` porque en un contenedor no hay navegador que abrir.
# -----------------------------------------------------------------------------
CMD ["python3", "console/server.py", "--evidence", "/data/evidencia", "--host", "0.0.0.0", "--port", "8787", "--no-open"]
