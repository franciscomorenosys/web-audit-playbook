# Despliegue del stack en la VPS

> **Qué es esto.** La guía para levantar la parte del playbook que corre en la
> VPS autoalojada: el runtime de LLM local (Ollama), la consola interna de
> operaciones y el almacén de hallazgos (SQLite).
>
> **La regla que gobierna todo este directorio:** *nada de lo que pertenece al
> cliente sale de esta máquina*. No es una promesa del manual: es una propiedad
> del diseño, y este README dice cómo está construida y cómo se verifica.
>
> **Documentos relacionados:**
> - [`PLAN-MAESTRO.md`](../PLAN-MAESTRO.md) — las decisiones estratégica (§4
>   arquitectura, §5 perímetro, §6 stack, §10 seguridad propia).
> - [`research/06-stack-y-ecosistema.md`](../research/06-stack-y-ecosistema.md) —
>   la investigación que sostiene cada decisión de stack (verificada 2026-11-22).
> - [`hardening.md`](hardening.md) — el checklist de endurecimiento de la VPS.
> - [`../SECURITY.md`](../SECURITY.md) — la política de seguridad del proyecto.
>
> **Este README no es asesoría legal.** Los plazos de retención y las
> condiciones de tratamiento de datos se resuelven con el abogado del cliente
> (ver `PLAN-MAESTRO.md` §9).

---

## 0. Índice

1. [Requisitos](#1-requisitos)
2. [Instalación](#2-instalación)
3. [Primer arranque](#3-primer-arranque)
4. [Descarga de modelos](#4-descarga-de-modelos)
5. [Apuntar la consola a la evidencia](#5-apuntar-la-consola-al-directorio-de-evidencia)
6. [Backup y restauración](#6-backup-y-restauración)
7. [Rotación de secretos](#7-rotación-de-secrets)
8. [Firewall: qué abrir y qué cerrar](#8-firewall-qué-abrir-y-qué-cerrar)
9. [Por qué SQLite y no Postgres](#9-por-qué-sqlite-y-no-postgres)
10. [Modo «todo dentro de las instalaciones»](#10-modo-todo-dentro-de-las-instalaciones)
11. [Diagnóstico](#11-diagnóstico)
12. [Cierre](#12-cierre)

---

## 1. Requisitos

### 1.1 Del host

| Requisito | Mínimo | Recomendado | Nota |
|---|---|---|---|
| SO | Linux con `systemd` (Debian 12, Ubuntu 24.04, RHEL 9) | el mismo | |
| CPU | 2 vCPU | 4 vCPU | Sin GPU, el LLM va a CPU. |
| RAM | 4 GB | **8 GB** | 4 GB sólo con `qwen3.5:4b`; Open WebUI no cabe. |
| Disco | 30 GB | **60 GB** | Modelos (~11 GB con tres) + evidencia + SQLite + logs + swap. |
| Swap | — | **4 GB** | Sin swap, un pico de RAM mata el servicio Ollama y el auditor pierde el contexto. |
| Docker Engine | 24+ | 25+ | |
| Docker Compose | v2.20+ | v2.24+ | Se usa `name:`, `profiles:` y `deploy.resources.limits`. |
| OpenSSL | 3.x | 3.x | Para generar tokens. |

> Fuente de los perfiles: `research/06` §5.5 (verificado 2026-11-22).

### 1.2 De la red

| Requisito | Detalle |
|---|---|
| **Acceso del auditor** | SSH por **clave**, o VPN (WireGuard/Tailscale). |
| **Egreso controlado** | Allow-list: DNS, NTP y el registro de modelos (durante la instalación). Ver §8 y [`hardening.md`](hardening.md). |
| **GPU (opcional)** | NVIDIA Container Toolkit. Se activa con `NVIDIA_VISIBLE_DEVICES` en `.env`. Sin él, el modelo va a CPU. |

### 1.3 Del repo

- El repositorio del playbook (metodología, toolchain y plantillas).
- Python 3.13 para el toolchain (opcional en la VPS: el LLM no lo necesita).

---

## 2. Instalación

### 2.1 Preparar el host

```bash
# --- usuario de servicio (no root) ---
sudo adduser --system --group --home /opt/audit --shell /usr/sbin/nologin audit

# --- directorios ---
sudo mkdir -p /opt/audit/{evidencia,modelos,backups}
sudo chown -R audit:audit /opt/audit
sudo chmod 750 /opt/audit/evidencia

# --- swap de 4 GB (si no lo hay) ---
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# --- actualizaciones de seguridad automáticas ---
sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
```

### 2.2 Instalar Docker

```bash
# Usar el script oficial de Docker, o el repositorio de tu distribución.
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"      # salir de la sesión y volver a entrar

docker --version
docker compose version
```

### 2.3 Traer el playbook

```bash
git clone https://github.com/franciscomorenosys/web-audit-playbook.git
cd web-audit-playbook/deploy
```

> **El repo es la metodología, no el encargo.** En la VPS del cliente se
> despliega **una copia del stack**, no el histórico: `03-casos/` no está y no
> debe estar en la VPS del cliente.

### 2.4 Configurar las variables

```bash
cp .env.example .env
chmod 600 .env
$EDITOR .env
```

**Lo mínimo que hay que cambiar antes de arrancar:**

| Variable | Qué poner | Cómo generarla |
|---|---|---|
| `CONSOLE_TOKEN` | Un token aleatorio | `make token-gen` |
| `WEBUI_SECRET_KEY` | Otro token aleatorio (sólo si usas el perfil `ui`) | `make token-gen` |
| `OLLAMA_IMAGE` | La imagen con **digest fijado** | `docker buildx imagetools inspect ollama/ollama:<tag>` |
| `CONSOLE_IMAGE` | La imagen de la consola con digest fijado (a partir de v0.2) | `docker buildx imagetools inspect <imagen>:<tag>` |
| `EVIDENCE_HOST_DIR` | La ruta **absoluta** donde vive la evidencia | `pwd` |

```bash
make env-check     # aborta si queda algún CAMBIAR_ESTE_VALOR
```

> **Nunca pongas un secreto real en `.env.example`.** Ese fichero se versiona.
> Si algún día un secreto real aparece ahí, es un incidente: revócalo.

---

## 3. Primer arranque

```bash
cd deploy

make up          # ollama + console
make health      # estado y puertos
make logs        # seguir el arranque
```

### 3.1 Qué debería pasar

| Orden | Qué | Cómo se comprueba |
|:-:|---|---|
| 1 | `ollama` arranca y su healthcheck pasa | `docker compose ps` → `healthy` |
| 2 | `console` arranca **después** de que `ollama` esté sano (`depends_on: condition: service_healthy`) | `docker compose ps` |
| 3 | La consola escucha en `127.0.0.1:8787` **dentro del host** | `ss -tlnp \| grep 8787` |

### 3.2 Comprobar el perímetro (esto es lo importante)

```bash
# 1. El puerto de la consola NO está en 0.0.0.0
ss -tlnp | grep 8787
#   DEBE aparecer 127.0.0.1:8787 — NUNDA 0.0.0.0:8787 ni *:8787

# 2. La API de Ollama NO está publicada en el host
ss -tlnp | grep 11434
#   NO debe aparecer. Ollama sólo existe dentro de la red de Docker.

# 3. Desde fuera de la VPS, el puerto está cerrado
#    (pruébalo desde el portátil del auditor)
nc -vz -w 3 <ip-de-la-vps> 8787     # debe fallar (timeout / refused)

# 4. Desde el portátil, por túnel SSH, sí funciona
ssh -N -L 8787:127.0.0.1:8787 usuario@<ip-de-la-vps>
#   y en otra terminal:
curl -s http://127.0.0.1:8787/api/health
```

Si el punto 1 o el 2 fallan, **para el stack y revisa el `docker-compose.yml`**
antes de seguir. Un puerto de administración publicado en `0.0.0.0` rompe el
perímetro entero, y la API de Ollama **no tiene autenticación nativa**: su
único control es el binding.

### 3.3 La consola

Abre `http://127.0.0.1:8787` por el túnel.

> **Sobre la autenticación.** La versión actual de la consola (`console/server.py`)
> **no implementa autenticación propia**: es un servidor HTTP de la stdlib de
> Python que sirve la interfaz y la API de lectura. **Por eso el puerto se
> publica exclusivamente en `127.0.0.1` y el acceso es por túnel SSH o VPN.**
> `CONSOLE_TOKEN` queda preparado en el `.env` para la versión con sesión
> (v0.2). **Nunca expongas la consola en `0.0.0.0` mientras no tenga
> autenticación propia.** Si algún día se publica directamente, tiene que ir
> detrás de un proxy con TLS y autenticación, no con un puerto abierto.

### 3.4 Construir la imagen de la consola

La consola se empaqueta con [`console/Dockerfile`](../console/Dockerfile). El
`docker-compose.yml` la construye con el bloque `build:`; el comando exacto es:

```bash
# Desde la RAÍZ del repositorio
docker build -t web-audit-playbook/console:local -f console/Dockerfile .
```

O, equivalente, `make build-console` (desde `deploy/`).

> **El contexto de build es la RAÍZ del repositorio, no `console/`.** La
> imagen necesita **dos** piezas del repo: `console/` (la interfaz y el
> servidor) y `01-tooling/scripts/` (el toolchain que la consola invoca para
> calcular el score y para generar la demo). Por eso el comando lleva `-f
> console/Dockerfile` y el contexto es `.`.
>
> **Y por eso el `.dockerignore` de la raíz es una lista blanca**: excluye
> todo y re-incluye sólo `console/` y `01-tooling/scripts/`. La consecuencia
> que importa: `03-casos/` —la evidencia de los clientes reales— **nunca
> entra en el contexto de build**, ni siquiera cuando la imagen se construye
> en el portátil del auditor, donde esa carpeta sí existe.

Qué lleva la imagen:

| Pieza | Detalle |
|---|---|
| Base | `python:3.13-slim`. Sin `pip install`: la consola es stdlib puro. |
| Layout | `/app/console/` y `/app/01-tooling/scripts/`. |
| Usuario | `console` (uid 10001). Sin root y sin shell. |
| Puerto | `8787`. |
| Salud | `HEALTHCHECK` con la stdlib: `python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8787/api/summary')"`. La imagen no instala `curl` ni `wget` (una slim no los trae), y la sonda no añade superficie. |
| Comando | `python3 console/server.py --evidence /data/evidencia --host 0.0.0.0 --port 8787 --no-open`. **Nunca en modo demo.** |

> **El `command:` del compose sobrescribe el del `Dockerfile`.** En el stack la
> consola lee `/evidencia` (donde monta el volumen); en un `docker run`
> suelto lee `/data/evidencia`, que es el punto de montaje del ejemplo de
> [`console/README.md` §Docker](../console/README.md#docker). Es el mismo
> parámetro con dos rutas, porque las dos están en solo lectura.

### 3.5 Regenerar la demo dentro del contenedor

El conjunto de demostración **no va en la imagen**: se genera en tiempo de
ejecución con el propio toolchain, que es la copia del repo dentro del
contenedor.

```bash
# Genera la demo sintética (~45 s: la sonda respeta el intervalo de 1 s).
# --no-deps: la demo no necesita el runtime de LLM, así que no se arranca
# ollama para generarla.
docker compose run --rm --no-deps console python3 console/demo/generar_demo.py

# Y ábrela en modo demo, por el túnel SSH como cualquier otra consola
docker compose run --rm --no-deps -p 127.0.0.1:8787:8787 console \
  python3 console/server.py --demo --host 0.0.0.0 --port 8787 --no-open
```

Lo que se escribe se queda **dentro del contenedor**, que es desechable. Para
conservarlo, monta un volumen:

```bash
docker compose run --rm --no-deps \
  -v "$PWD/demo:/app/console/demo/evidencia" \
  console python3 console/demo/generar_demo.py
```

> **La demo es sintética.** La genera el toolchain contra los fixtures del
> repo y un sitio efímero en `127.0.0.1`. Ningún dato de cliente entra en
> ella, y el corpus crudo queda marcado **SIN REDACTAR** a propósito, para
> que se vea la regla de redacción en acción.

---

## 4. Descarga de modelos

```bash
make pull-models
make list-models
```

Qué descarga:

| Modelo | Tamaño del blob | RAM mínima realista | Para qué |
|---|---|---|---|
| `qwen3.5:9b` | 6,6–7,6 GB | ~8–10 GB | **Default de la VPS**: redacción y clasificación de severidad. |
| `granite-code:8b` | 4,6 GB | ~6 GB | Análisis de JavaScript con secretos (para `js_intel.py`). |

> Tamaños verificados contra `ollama.com/library` el 2026-11-22
> (`research/06` §2.2-2.3). El tamaño del blob **no** es la RAM en ejecución:
> hay que sumar el KV cache, el runtime y el resto del stack.

### 4.1 Verificar que corre en CPU (en una VPS sin GPU)

```bash
make list-models
#   La columna PROCESSOR debe decir 100% CPU
```

### 4.2 El modelo por defecto y cómo cambiarlo

En `.env`:

```
LLM_MODEL=qwen3.5:9b
```

Candidatos verificados (`research/06` §2.2): `qwen3.5:4b` (VPS de 4 GB),
`gemma3:4b` (segundo modelo de redacción en español), `phi4-mini:3.8b`
(clasificación rápida), `deepseek-r1:8b` (razonamiento, opcional),
`smollm2:1.7b` (etiquetado ligero, **nunca como control de redacción**).

### 4.3 Integridad de los pesos

Un GGUF troyanizado ejecuta código arbitrario en la VPS del cliente. Por eso:

1. Se descarga **una vez** y se verifica el SHA-256 contra el hash publicado por
   el proveedor.
2. Se anota el **digest del modelo** en el `findings.json` de cada informe: la
   reproducibilidad la da el hash de la evidencia, no el modelo, pero el digest
   deja constancia de con qué se redactó.
3. En el modo «todo dentro de las instalaciones» (§10), los pesos viajan desde
   el portátil del auditor, **verificados**, y la VPS no vuelve a descargar nada.

### 4.4 Actualizar el modelo

Trimestral, y sólo después de pasar la evaluación con casos reales:

```bash
docker compose exec ollama ollama pull qwen3.5:9b
make list-models     # comprobar el digest nuevo
```

> **No se actualiza a ciegas.** Un modelo más nuevo puede cambiar el
> comportamiento del triage. La política es: `pull` → **evaluación con el set de
> 20 casos reales** → promover o descartar. Ver `PLAN-MAESTRO.md` §6 y §13.

---

## 5. Apuntar la consola al directorio de evidencia

### 5.1 La estructura esperada

```
<EVIDENCE_HOST_DIR>/
└── <cliente>/
    ├── roe-firmado.pdf
    ├── authorization.json
    ├── evidencia/                  ← CRUDA. El LLM NUNCA la ve.
    │   ├── probe_exposure.tsv
    │   ├── headers.txt
    │   ├── secrets.json
    │   └── ...
    ├── evidencia-sanitizada/      ← SANEADA. Es lo que lee la consola.
    │   ├── redaccion.json
    │   └── ...
    ├── registro-de-acciones.csv
    └── informe-tecnico/
```

### 5.2 Configurarlo

En `.env`:

```
# Relativa al directorio deploy/ o absoluta. Recomendada: ABSOLUTA.
EVIDENCE_HOST_DIR=/opt/audit/evidencia
EVIDENCE_SANITIZED_SUBDIR=evidencia-sanitizada
```

```bash
make up && make health
```

### 5.3 Las tres reglas que no se negocian aquí

| Regla | Cómo está implementada |
|---|---|
| **La consola no escribe evidencia cruda** | El directorio se monta en **SOLO LECTURA** (`/evidencia:ro`). No es una convención: es el montaje. La propia consola lo documenta: *«Directorio de evidencia leído en modo sólo-lectura. No hace ninguna llamada de red y nunca modifica los artefactos que lee.»* |
| **El LLM sólo ve evidencia saneada** | La consola lee `EVIDENCE_ROOT/EVIDENCE_SANITIZED_SUBDIR` y **sólo** ese subárbol. `pii_redact.py` es la única puerta. |
| **La base guarda el hash, no el contenido** | El almacén SQLite (`/db/hallazgos.db`) guarda la evidencia **saneada** y el `sha256` de la cruda. Ver `PLAN-MAESTRO.md` §15, decisión #7. |

### 5.4 El flujo de redacción antes de subir nada

```bash
# En el portátil del auditor (o en la propia VPS), con el toolchain:
python3 ../01-tooling/scripts/pii_redact.py \
  /opt/audit/evidencia/<cliente>/evidencia/ \
  --out-dir /opt/audit/evidencia/<cliente>/evidencia-sanitizada/ \
  --report /opt/audit/evidencia/<cliente>/evidencia/redaccion.json
```

El informe `redaccion.json` tiene **conteos, nunca valores**. El crudo **no se
sobrescribe ni se envía**: se entrega la copia sanitizada.

### 5.5 Si el cliente exige que nada salga de sus instalaciones

Los pesos y el modelo se descargan **en el portátil**, se verifican por SHA-256
y se transfieren cifrados (`age` o `gpg`). La VPS no vuelve a hacer `pull`.
Ver §10 y `research/06` §5.6.

---

## 6. Backup y restauración

### 6.1 Qué se respalda

| Qué | Dónde | Se puede regenerar |
|---|---|---|
| Base de hallazgos (SQLite) | volumen `wap_db` | **No del todo**: se puede reconstruir desde los CSV del registro de acciones, pero no el historial de estados. **Sí se respalda.** |
| Evidencia saneada | `<EVIDENCE_HOST_DIR>` | **No.** Es el activo. |
| Evidencia cruda | `<EVIDENCE_HOST_DIR>` | **No.** Nunca sale del perímetro y nunca se regenera. |
| Modelos | volumen `ollama_models` | **Sí**: `ollama pull` + verificación de digest. |
| Consola (configuración) | volumen `openwebui_data` (si usas el perfil `ui`) | Parcialmente. |

### 6.2 El principio

> **Un backup que vive en la misma máquina no es un backup.**
>
> `make backup` deja la copia en `BACKUP_DIR` (por defecto `../.backups` en el
> repo, que en la VPS del cliente hay que cambiar a una ruta que se sincronice
> con el portátil del auditor o con el almacenamiento del cliente).

```bash
make backup BACKUP_DIR=/mnt/auditor/wap-backups
```

Qué hace, en orden:

1. `VACUUM INTO` → volcado **consistente** de la base (no es copiar el `.db` en
   caliente: con WAL activo, eso puede dar un fichero inconsistente).
2. `sha256sum` de la copia → el hash va al registro del engagement.
3. Se extrae y **se cifra** (con `age` si está instalado; si no, con
   `openssl` y `BACKUP_PASSPHRASE`; si no hay ninguna de las dos, avisa
   claramente de que la copia queda **sin cifrar**).
4. La copia sale de la VPS.

### 6.3 La prueba de restauración (mensual, no opcional)

```bash
make verify-backup     # comprueba que la última copia se puede LEER
make restore FILE=wap-backup-YYYYMMDDTHHMMSSZ.tar.gz.age
```

**Un job de backup que corre no es un backup.** La prueba es que la copia se
**restaura** y la consola arranca con la base recuperada. Anota la fecha de la
última prueba de restauración en el registro del engagement.

### 6.4 Retención

| Qué | Plazo |
|---|---|
| Evidencia de Fases 0 y 1 | 12 meses desde la entrega |
| Evidencia de Fase 2 | 30 días naturales desde la entrega del anexo |
| Confirmación de destrucción | **Escrita** al cliente |

> **NO VERIFICADO:** los plazos contractuales los fija el abogado del cliente
> (ver `PLAN-MAESTRO.md` §9). Los de arriba son los que el playbook usa como
> referencia; el que manda es el contrato firmado.

---

## 7. Rotación de secretos

### 7.1 Qué hay que rotar y cada cuánto

| Secreto | Dónde vive | Periodicidad | Al cambiarlo |
|---|---|---|---|
| `CONSOLE_TOKEN` | `.env` (0600) | Trimestral y ante sospecha | Reinicia la consola: `make up` |
| `WEBUI_SECRET_KEY` | `.env` (0600) | Trimestral | `make up-ui` (invalida las sesiones) |
| Tokens de API de terceros | `.env` | Trimestral | Lo que corresponda |
| Claves de acceso al modelo (si el proveedor las da) | `.env` | Trimestral | — |
| Clave del backup (`age` / passphrase) | Fuera del repo | Semestral | Re-cifra las copias antiguas |

### 7.2 Cómo rotar sin dejar una ventana abierta

```bash
# 1. Genera el nuevo valor
make token-gen

# 2. Edítalo en .env (sin tocar nada más)
$EDITOR .env
chmod 600 .env

# 3. Aplica
make up

# 4. Verifica
make health
make logs
```

### 7.3 Lo que NO se hace

- **No se rota con el stack arriba y sin verificar.** Primero se comprueba que
  la copia nueva está desplegada y que la antigua ya no sirve.
- **No se guarda un secreto en un gestor que no esté en el perímetro.**
- **No se pone un secreto en el historial de git**, ni siquiera por error. Si
  ocurre: revocar, rotar, y `git filter-repo` + force-push — y avisar al
  equipo, porque un secreto en el historial está en el historial.

---

## 8. Firewall: qué abrir y qué cerrar

> **Por defecto: NADA público salvo el puerto de la consola detrás de VPN o
> túnel SSH.** Y ni siquiera eso en `0.0.0.0`.

### 8.1 Tabla de puertos

| Servicio | Puerto | ¿Se publica? | Quién lo usa |
|---|---|---|---|
| SSH | 22 (o el que elijas) | **Sí, en la IP del auditor** | Sólo el auditor, por clave |
| Consola | 8787 | **Sólo en `127.0.0.1`** | El auditor, por túnel SSH o VPN |
| Open WebUI | 3000 | **Sólo en `127.0.0.1`** | El auditor, por túnel SSH o VPN |
| API de Ollama | 11434 | **Nunca** | Sólo la consola, por la red de Docker |
| SQLite | — | **Nunca** (no hay servidor) | Sólo la consola, por la red de Docker |

### 8.2 Reglas base (ufw)

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow from <IP-DEL-AUDITOR> to any port 22 proto tcp   # SSH, sólo del auditor
sudo ufw enable
sudo ufw status verbose
```

### 8.3 Egreso (allow-list)

El bloqueo del egreso es lo que hace que «nada sale del perímetro» sea una
restricción técnica y no una intención. Ver [`hardening.md`](hardening.md) §3
para las reglas de `nftables`/`ufw` con allow-list de DNS, NTP y el registro
de modelos.

### 8.4 Verificación

```bash
# Desde el portátil del auditor, con la VPS en su IP pública:
nmap -Pn -p 22,3000,8787,11434 <ip-de-la-vps>
#   22   → filtrado o cerrado salvo que la IP del auditor esté permitida
#   3000 → cerrado
#   8787 → cerrado
#   11434→ cerrado
```

---

## 9. Por qué SQLite y no Postgres

**Decisión: SQLite en un volumen con nombre. No hay servidor de base de
datos.**

| Criterio | SQLite (elegido) | Postgres (descartado) |
|---|---|---|
| **Volumen de datos** | Decenas de miles de hallazgos por cliente. Sobra de largo. | Suficiente y de sobra. |
| **Escritura concurrente** | 1 auditor (o 2 en una ventana de Fase 2). SQLite en modo WAL aguanta de sobra. | Un servidor de base de datos para dos autores es un proceso más que mantener. |
| **Superficie de ataque** | **Cero**: no hay daemon, ni puerto, ni protocolo de red, ni credenciales que filtrar. | Un daemon escuchando, con su propio modelo de autenticación, en una máquina que guarda datos de salud. |
| **Copia de seguridad** | Un fichero. `VACUUM INTO` da un volcado consistente. | `pg_dump` + coordinating dump: más piezas, más formas de fallo. |
| **Coste operativo** | Cero procesos extra. | Otro servicio que actualizar, parchear, respaldar y vigilar. |
| **Dependencias** | `sqlite3` de la stdlib de Python: **cero dependencias**. | Imagen de Postgres de cientos de MB, con sus CVEs. |
| **Licencia** | PSF-2.0 (implícito, dominio público) | PostgreSQL License |

**Cuándo se revisaría esta decisión** (y sólo entonces):

1. **Escritura concurrente real** de más de dos autores sobre el mismo
   engagement.
2. **Histórico de varios cientos de miles de hallazgos** en los que el
   análisis analítico (DuckDB, consultas sobre años) justifique un servidor.
3. **Acceso a los hallazgos desde más de una máquina** a la vez — por ejemplo,
   un equipo con dos auditores simultáneos sobre la misma base.

**El plan de migración**, si se llega a ese punto: `sqlite3 .dump` → importar en
Postgres → cambiar `DATABASE_PATH` por `DATABASE_URL` en el `.env` → el resto
del stack no cambia. La capa de acceso a datos de la consola debe quedar
**detrás de un repositorio**, no con SQL suelto en los controladores, para que
ese cambio sea un afternoon y no un trimestre.

> **El `db` del `docker-compose.yml` no es un servidor de base de datos**: es la
> utilidad de operación sobre el volumen SQLite (`sqlite3` para backup,
> restore y verificación), en el perfil `tools` para que no arranque por
> defecto.

---

## 10. Modo «todo dentro de las instalaciones»

Cuando el cliente exige que **nada** salga de sus instalaciones — ni siquiera la
descarga de los pesos:

1. Descarga los GGUF en el **portátil del auditor**.
2. Verifica el **SHA-256** contra el hash publicado por el proveedor.
3. Transfiere cifrado (`age` o `gpg`) al cliente.
4. En la VPS: `OLLAMA_MODELS=/opt/audit/modelos` y el directorio legible por el
   usuario del servicio.
5. Firewall con **egreso bloqueado** por defecto (allow-list sólo para DNS y
   NTP durante la instalación).
6. `llama-server --offline` está diseñado exactamente para esto: *«Offline mode:
   forces use of cache, prevents network access»*.

```bash
# Referencia del comando (llama.cpp, en la VPS, sin red)
llama-server -m /opt/audit/modelos/qwen3.5-9b-Q4_K_M.gguf \
  --host 127.0.0.1 --port 9931 \
  --ctx-size 8192 --api-key "$AUDIT_LLM_KEY" \
  --offline \
  --json-schema-file /opt/audit/esquemas/triage.json
```

> **NO VERIFICADO:** el comportamiento exacto del firewall de egress con
> `ollama pull` bloqueado, y las implicaciones de `--offline` con modelos ya
> cacheados, no se han medido. `research/06` §5.6 recomienda una **prueba de
> aceptación explícita** antes de ofrecer este modo como servicio.

---

## 11. Diagnóstico

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| `console` no arranca | `ollama` no está sano; `depends_on: service_healthy` lo bloquea. O falta la imagen de la consola | `make logs`; `make list-models`; `make build-console` |
| `ollama` se reinicia en bucle | Falta de RAM: el modelo no cabe | `docker stats`; baja `LLM_MODEL` a `qwen3.5:4b` o sube la RAM de la VPS |
| La consola no responde por el túnel | El puerto no está publicado en `127.0.0.1` | `ss -tlnp \| grep 8787` |
| `make up` aborta con `CAMBIAR_ESTE_VALOR` | Falta un secreto en `.env` | `make env-check` y edita `.env` |
| `ollama pull` falla con timeout | Egress bloqueado o DNS | Revisa el allow-list de §8.3 |
| El modelo responde lento | Está en CPU, sin GPU | Normal en una VPS: 4B–9B da ~10–30 tok/s en CPU. **NO VERIFICADO**: no se ha medido en esta infraestructura. |
| `db` no aparece en `docker compose ps` | Está en el perfil `tools` | Es correcto: sólo arranca con `--profile tools` |

### 11.1 Comandos útiles

```bash
make ps                # estado
make logs              # logs en vivo
make shell             # shell en la consola
make db-shell          # sqlite3 sobre la base
docker compose --profile tools run --rm db sh   # shell en el contenedor de operación
docker stats           # consumo de memoria en vivo
```

---

## 12. Cierre

```bash
make down          # para el stack, conserva los volúmenes
make clean-volumes # BORRA la base y los modelos (irreversible)
```

**Antes de dar por terminada una VPS de cliente:**

- [ ] `make backup` ejecutado y **la copia está fuera de la máquina**.
- [ ] `make verify-backup` verde (la copia se lee).
- [ ] La evidencia se ha **entregado saneada** y se ha confirmado por escrito la
      destrucción de la cruda según el plazo del contrato.
- [ ] Los secretos se han **rotado** si la VPS es del cliente y va a seguir viva.
- [ ] Se ha documentado en el expediente: qué se desplegó, con qué digest, y
      qué se dejó montado.

---

*Documento operativo. No es asesoría legal. Las decisiones de stack remiten a
`research/06-stack-y-ecosistema.md` (verificado 2026-11-22) y las decisiones
estratégicas a `PLAN-MAESTRO.md`.*
