# =============================================================================
# Web Audit Playbook — comandos de operación del stack de la VPS
# =============================================================================
#
# Uso:
#   make help
#   make up            # arranca ollama + console
#   make up-ui         # arranca además Open WebUI (perfil `ui`)
#   make down          # para el stack (conserva los volúmenes)
#   make logs          # sigue los logs de todos los servicios
#   make backup        # copia cifrada de la base + evidencia, fuera de la VPS
#   make restore FILE=wap-backup-YYYYMMDDTHHMMSSZ.tar.gz
#   make pull-models   # descarga los modelos fijados
#
# Las variables salen de deploy/.env. Si no existe, `make env-check` lo dice.
# Todas las rutas se citan entre comillas: el repo puede vivir en una ruta con
# espacios.
#
# =============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Directorio del propio Makefile (deploy/) y rutas derivadas.
# Directorio del propio Makefile (deploy/) y rutas derivadas.
#
# OJO: se usa $(CURDIR) y no $(MAKEFILE_LIST) a proposito. Las rutas absolutas
# del repo pueden contener espacios ("Default Project"), y las funciones de
# nombre de fichero de make (abspath, wildcard, dir) dividen su argumento por
# espacios: con $(MAKEFILE_LIST) la ruta se parte en trozos y todo se rompe.
# Por eso los comandos se ejecutan desde deploy/ y todas las rutas se citan
# entre comillas.
DEPLOY_DIR := $(CURDIR)
REPO_DIR   := $(CURDIR)/..
ENV_FILE   := $(CURDIR)/.env

COMPOSE    := docker compose --env-file "$(ENV_FILE)" -f "$(CURDIR)/docker-compose.yml"

# Directorio donde caen las copias de seguridad. FUERA de la VPS: en el
# portátil del auditor o en el almacenamiento del cliente.
BACKUP_DIR    ?= $(REPO_DIR)/.backups
BACKUP_STAMP  ?= $(shell date -u +%Y%m%dT%H%M%SZ)
BACKUP_BASENAME = wap-backup-$(BACKUP_STAMP)

# Modelos que se descargan. Fuente: research/06 §2.3 (verificado 2026-11-22).
MODEL_MAIN  ?= qwen3.5:9b
MODEL_CODE  ?= granite-code:8b

# Puerto local de la consola (para el túnel SSH).
CONSOLE_PORT ?= 8787

.PHONY: help env-check up up-ui down restart ps logs health shell db-shell \
        pull-models models list-models backup restore verify-backup \
        token-gen clean-volumes tunnel build-console

# Guard: este Makefile se ejecuta desde deploy/ (porque las rutas absolutas
# del repo pueden contener espacios y make parte los argumentos por espacios).
ifeq (,$(shell test -f "$(CURDIR)/docker-compose.yml" && echo ok))
$(error No estas en deploy/. Ejecuta:  cd deploy && make <objetivo>)
endif

## ---------------------------------------------------------------------------
## Ayuda
## ---------------------------------------------------------------------------
help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' "$(CURDIR)/Makefile" \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  Ejemplo: make up && make pull-models && make health"

## ---------------------------------------------------------------------------
## Comprobaciones previas
## ---------------------------------------------------------------------------
env-check: ## Comprueba que deploy/.env existe y no tiene valores de fábrica
	@test -f "$(ENV_FILE)" || { \
	  echo "ERROR: no existe '$(ENV_FILE)'."; \
	  echo "       Ejecuta:  cp deploy/.env.example deploy/.env  y edítalo."; exit 1; }
	@if grep -q "CAMBIAR_ESTE_VALOR" "$(ENV_FILE)"; then \
	  echo "ERROR: hay valores CAMBIAR_ESTE_VALOR en '$(ENV_FILE)'."; \
	  echo "       Rellena CONSOLE_TOKEN (y WEBUI_SECRET_KEY si usas el perfil 'ui')."; \
	  exit 1; \
	fi
	@echo "OK: '$(ENV_FILE)' existe y no tiene valores de fábrica."

## ---------------------------------------------------------------------------
## Ciclo de vida
## ---------------------------------------------------------------------------
up: env-check ## Arranca el stack (ollama + console)
	$(COMPOSE) up -d --remove-orphans
	@echo ""
	@echo "Consola: http://127.0.0.1:$(CONSOLE_PORT)  (sólo por túnel SSH o VPN)"
	@echo "Siguiente paso:  make pull-models"

up-ui: env-check ## Arranca el stack con Open WebUI (perfil 'ui')
	$(COMPOSE) --profile ui up -d --remove-orphans

down: ## Para el stack (conserva los volúmenes)
	$(COMPOSE) --profile ui down --remove-orphans

restart: down up ## Reinicia el stack

ps: ## Estado de los contenedores
	$(COMPOSE) ps

health: ## Estado de salud de cada servicio y puertos publicados
	$(COMPOSE) ps --format 'table {{.Service}}\t{{.Status}}\t{{.Ports}}'

logs: ## Sigue los logs de todos los servicios
	$(COMPOSE) --profile ui logs -f --tail=100

## ---------------------------------------------------------------------------
## Acceso
## ---------------------------------------------------------------------------
shell: ## Abre una shell en el contenedor de la consola
	$(COMPOSE) exec console sh

db-shell: ## Abre sqlite3 sobre el volumen de hallazgos
	$(COMPOSE) --profile tools run --rm db sqlite3 /db/hallazgos.db

tunnel: ## Imprime la orden de túnel SSH a la consola
	@echo "En el portátil del auditor:"
	@echo "  ssh -N -L $(CONSOLE_PORT):127.0.0.1:$(CONSOLE_PORT) usuario@<host-de-la-vps>"
	@echo "Y luego abre:  http://127.0.0.1:$(CONSOLE_PORT)"

token-gen: ## Genera un token aleatorio para CONSOLE_TOKEN
	@openssl rand -base64 48

## ---------------------------------------------------------------------------
## Construcción de la consola
## ---------------------------------------------------------------------------
build-console: ## Construye la imagen de la consola desde console/
	@if [ -f "$(REPO_DIR)/console/Dockerfile" ]; then \
	  docker build -t "$${CONSOLE_IMAGE:-web-audit-playbook/console:local}" \
	    -f "$(REPO_DIR)/console/Dockerfile" "$(REPO_DIR)" \
	    && echo "Construida.  make up"; \
	else \
	  echo "AVISO: no existe console/Dockerfile."; \
	  echo "       La consola se despliega con una imagen ya construida:"; \
	  echo "         docker build -t web-audit-playbook/console:local -f console/Dockerfile ."; \
	  echo "       y se pone CONSOLE_IMAGE=web-audit-playbook/console:local en .env"; \
	fi

## ---------------------------------------------------------------------------
## Modelos
## ---------------------------------------------------------------------------
pull-models: ## Descarga los modelos fijados (verificado por digest)
	@echo "Descargando $(MODEL_MAIN) ..."
	$(COMPOSE) exec -T ollama ollama pull $(MODEL_MAIN)
	@echo "Descargando $(MODEL_CODE) ..."
	$(COMPOSE) exec -T ollama ollama pull $(MODEL_CODE)
	@echo "Listo. Verifica con:  make list-models"

models: pull-models ## Alias de pull-models

list-models: ## Lista los modelos descargados y el procesador en uso
	$(COMPOSE) exec -T ollama ollama list
	@echo ""
	@echo "Procesador (debe decir 100% CPU en una VPS sin GPU):"
	$(COMPOSE) exec -T ollama ollama ps

## ---------------------------------------------------------------------------
## Backup y restauración
## ---------------------------------------------------------------------------
# El respaldo sale de la VPS: un backup que vive en la misma máquina no es un
# backup. La copia se cifra; la clave NO va con la copia.
backup: ## Copia cifrada de la base de hallazgos, fuera de la VPS
	@mkdir -p "$(BACKUP_DIR)"
	@chmod 700 "$(BACKUP_DIR)"
	@echo "1/4 volcado consistente de la base (VACUUM INTO):"
	$(COMPOSE) --profile tools run --rm db \
	  sqlite3 /db/hallazgos.db "VACUUM INTO '/db/$(BACKUP_BASENAME).db';"
	@echo "2/4 sha256 de la copia (para el registro del engagement):"
	@$(COMPOSE) --profile tools run --rm db sha256sum "/db/$(BACKUP_BASENAME).db" \
	  | tee "$(BACKUP_DIR)/$(BACKUP_BASENAME).sha256"
	@echo "3/4 extrayendo y cifrando:"
	@$(COMPOSE) --profile tools run --rm -v "$(BACKUP_DIR):/out" db \
	  sh -c 'cp "/db/$(BACKUP_BASENAME).db" /out/ && rm -f "/db/$(BACKUP_BASENAME).db" && echo ok'
	@tar -C "$(BACKUP_DIR)" -czf "$(BACKUP_DIR)/$(BACKUP_BASENAME).tar.gz" \
	  "$(BACKUP_BASENAME).db" "$(BACKUP_BASENAME).sha256"
	@if command -v age >/dev/null 2>&1; then \
	  age --encrypt --output "$(BACKUP_DIR)/$(BACKUP_BASENAME).tar.gz.age" \
	      --recipients "$(BACKUP_AGE_RECIPIENT)" "$(BACKUP_DIR)/$(BACKUP_BASENAME).tar.gz" \
	    && rm -f "$(BACKUP_DIR)/$(BACKUP_BASENAME).tar.gz" \
	    && echo "    cifrado con age (destinatario: $(BACKUP_AGE_RECIPIENT))"; \
	elif [ -n "$$BACKUP_PASSPHRASE" ]; then \
	  openssl enc -aes-256-cbc -pbkdf2 -salt \
	    -in "$(BACKUP_DIR)/$(BACKUP_BASENAME).tar.gz" \
	    -out "$(BACKUP_DIR)/$(BACKUP_BASENAME).tar.gz.enc" \
	    -pass env:BACKUP_PASSPHRASE \
	    && rm -f "$(BACKUP_DIR)/$(BACKUP_BASENAME).tar.gz" \
	    && echo "    cifrado con openssl (passphrase de BACKUP_PASSPHRASE)"; \
	else \
	  echo "    AVISO: sin age ni BACKUP_PASSPHRASE: la copia queda SIN CIFRAR."; \
	  echo "           Exporta BACKUP_PASSPHRASE antes de copiar la a otro sitio."; \
	fi
	@rm -f "$(BACKUP_DIR)/$(BACKUP_BASENAME).db"
	@echo "4/4 resultado:"
	@ls -lh "$(BACKUP_DIR)" | grep "$(BACKUP_BASENAME)" || true
	@echo ""
	@echo "Copia fuera de la VPS: $(BACKUP_DIR)/$(BACKUP_BASENAME).*"
	@echo "Guárdala en el portátil del auditor y anota el sha256 en el expediente."

restore: ## Restaura desde una copia:  make restore FILE=wap-backup-...tar.gz.age
	@test -n "$(FILE)" || { echo "Uso: make restore FILE=<nombre-de-la-copia>"; exit 1; }
	@test -f "$(BACKUP_DIR)/$(FILE)" || { echo "ERROR: no existe '$(BACKUP_DIR)/$(FILE)'"; exit 1; }
	@echo "ATENCIÓN: esto SOBRESCRIBE la base actual."
	@read -p "¿Continuar? (escribe SI) " ok; [ "$$ok" = "SI" ] || { echo "Cancelado."; exit 1; }
	@$(COMPOSE) stop console
	@case "$(FILE)" in \
	  *.age) age --decrypt --output "$(BACKUP_DIR)/restaurado.tar.gz" "$(BACKUP_DIR)/$(FILE)";; \
	  *.enc) openssl enc -d -aes-256-cbc -pbkdf2 -in "$(BACKUP_DIR)/$(FILE)" \
	           -out "$(BACKUP_DIR)/restaurado.tar.gz" -pass env:BACKUP_PASSPHRASE;; \
	  *)      cp "$(BACKUP_DIR)/$(FILE)" "$(BACKUP_DIR)/restaurado.tar.gz";; \
	esac
	@tar -C "$(BACKUP_DIR)" -xzf "$(BACKUP_DIR)/restaurado.tar.gz"
	@$(COMPOSE) --profile tools run --rm -v "$(BACKUP_DIR):/in" db \
	  sh -c 'cp /in/*.db /db/hallazgos.db && chmod 600 /db/hallazgos.db && echo "Base restaurada"'
	@$(COMPOSE) start console
	@echo "Verifica con:  make health"

verify-backup: ## Comprueba que la última copia se puede LEER (prueba de restauración)
	@ls -1t "$(BACKUP_DIR)"/wap-backup-* 2>/dev/null | head -1 | while read -r f; do \
	  echo "Probando: $$f"; \
	  case "$$f" in \
	    *.age) age --decrypt --output /dev/null "$$f" >/dev/null 2>&1 \
	             && echo "  OK: se descifra" || echo "  FALLO: no se descifra";; \
	    *.enc) openssl enc -d -aes-256-cbc -pbkdf2 -in "$$f" -out /dev/null \
	             -pass env:BACKUP_PASSPHRASE >/dev/null 2>&1 \
	             && echo "  OK: se descifra" || echo "  FALLO: no se descifra";; \
	    *)     tar -tzf "$$f" >/dev/null 2>&1 \
	             && echo "  OK: el índice del tar es válido" \
	             || echo "  FALLO: no se puede leer";; \
	  esac; \
	done

## ---------------------------------------------------------------------------
## Mantenimiento
## ---------------------------------------------------------------------------
clean-volumes: ## BORRA los volúmenes (base, modelos, datos de la UI). Irreversible.
	@echo "ATENCIÓN: esto borra la base de hallazgos y los modelos descargados."
	@read -p "¿Continuar? (escribe SI) " ok; [ "$$ok" = "SI" ] || { echo "Cancelado."; exit 1; }
	$(COMPOSE) --profile ui down -v --remove-orphans
