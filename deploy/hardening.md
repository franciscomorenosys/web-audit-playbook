# Endurecimiento de la VPS

> **Para quién es esto.** Para el operador (tú) y para el auditor que va a
> firmar la «declaración de limpieza» de una infraestructura.
>
> **Qué es.** La lista de controles que hay que aplicar a la máquina donde
> corre el stack del playbook, y **cómo se verifica cada uno**. Un control que
> no se verifica es una intención.
>
> **Por qué importa aquí más que en un servidor cualquiera.** Esta máquina
> guarda **evidencia de clientes con datos sensibles de pacientes** y corre un
> **runtime de LLM al que se le mete contenido de sitios controlados por
> terceros**. Es, a la vez, un objetivo y un contenedor de datos confidenciales.
> La regla de `research/06` §1.10 aplica: *todo lo que se autoaloja se audita
> con el mismo rigor que el sitio del cliente*.
>
> **Cómo usar este documento.** Sections 1–7 en orden, en el despliegue.
> Sección 8, mensualmente. Sección 9, en cada cambio.
>
> **Este documento no es asesoría legal.** Los controles que dependan de una
> obligación legal (retención, notificación) están marcados y su fuente
> primaria hay que abrirla; ver `PLAN-MAESTRO.md` §9.

---

## Índice

| # | Bloque | Qué cubre |
|:-:|---|---|
| 1 | [Sistema base](#1-sistema-base) | Actualizaciones, cuentas, permisos, montajes |
| 2 | [SSH](#2-ssh) | Claves, sin contraseña, sin root, sin PuTTY-weak |
| 3 | [Firewall y egress](#3-firewall-y-egress) | Qué entra, qué sale, allow-list |
| 4 | [fail2ban y monitorización](#4-fail2ban-y-monitorización) | Fuerza bruta, logs, alertas |
| 5 | [Docker](#5-docker) | El daemon es root: qué se le deja hacer |
| 6 | [Backups](#6-backups) | Cifrado, prueba de restauración, retención |
| 7 | [El stack de auditoría](#7-el-stack-de-auditoría) | Los controles específicos de este despliegue |
| 8 | [Revisión mensual](#8-revisión-mensual) | La rutina que lo sostiene |
| 9 | [Antes y después de cada cambio](#9-antes-y-después-de-cada-cambio) | Checklist de cambio |
| 10 | [Verificación final](#10-verificación-final) | El resumen que se firma |

---

## 1. Sistema base

| # | Control | Cómo | Verificación |
|:-:|---|---|---|
| 1.1 | **Actualizaciones de seguridad automáticas** | `apt install unattended-upgrades` y `dpkg-reconfigure -plow unattended-upgrades` | `apt-config dump \| grep Unattended-Upgrade` muestra `Automatic: "1"` |
| 1.2 | **Un usuario de servicio, no root** | `adduser --system audit`; Docker corre como root por diseño, pero el resto no | `id audit` → uid < 1000, shell `nologin` |
| 1.3 | **Permisos del directorio de evidencia** | `chmod 750 /opt/audit/evidencia` y `chown audit:audit` | `ls -ld /opt/audit/evidencia` → `drwxr-x--- audit audit` |
| 1.4 | **El `.env` en 0600** | `chmod 600 deploy/.env` | `stat -c '%a' deploy/.env` → `600` |
| 1.5 | **El directorio de backups en 0700** | `chmod 700` (lo hace `make backup`) | `stat -c '%a' .backups` → `700` |
| 1.6 | **Swap de 4 GB** | `fallocate -l 4G /swapfile` + entrada en `/etc/fstab` | `swapon --show` y `grep swapfile /etc/fstab` |
| 1.7 | **Sin servicios innecesarios** | `systemctl list-units --state=running` y deshabilitar lo que no se use | La lista de servicios running es la esperada y ninguna más |
| 1.8 | **Reloj en UTC y sincronizado** | `timedatectl set-timezone UTC` + NTP | `timedatectl show -p NTPSynchronized` → `yes` |
| 1.9 | **Nombres de fichero que no filtran** | Nada de `clinica-dental-easy` en rutas, servicios o contenedores | `ls /opt/audit` y `docker ps --format '{{.Names}}'` → nombres genéricos |
| 1.10 | **`/tmp` y `/var/tmp` con noexec y nodev** | `chmod +t /tmp`, y en `fstab`: `tmpfs /tmp tmpfs noexec,nodev,nosuid,mode=1777 0 0` | `mount \| grep ' /tmp '` |

> **1.9 no es paranoia.** Un nombre de cliente en un nombre de volumen aparece
> en `docker ps`, en los logs del sistema y en cualquier captura de pantalla
> de una sesión de soporte.

---

## 2. SSH

| # | Control | Cómo | Verificación |
|:-:|---|---|---|
| 2.1 | **Sólo autenticación por clave** | `PasswordAuthentication no`, `KbdInteractiveAuthentication no` | `sshd -T \| grep -i passwordauth` → `no` |
| 2.2 | **Sin login de root** | `PermitRootLogin no` | `sshd -T \| grep permitrootlogin` → `no` |
| 2.3 | **Claves Ed25519, con passphrase** | `ssh-keygen -t ed25519 -a 100 -C "wap-auditor"` | `~/.ssh/id_ed25519` existe y `ssh-add -l` la lista cuando está cargada |
| 2.4 | **Una clave por persona, nunca compartida** | Cada auditor tiene su propia | `~/.ssh/authorized_keys` con una línea por persona, comentada con el nombre |
| 2.5 | **Sin claves «de la empresa»** | Si alguien se va, se borra su línea | Revisión trimestral de `authorized_keys` |
| 2.6 | **Puerto no estándar (opcional)** | `Port 2222` | `sshd -T \| grep '^port'` |
| 2.7 | **Allow-list de IPs** (si el auditor tiene IP fija) | `AllowUsers auditor@203.0.113.10` | `sshd -T \| grep allowusers` |
| 2.8 | **Sin forwarding innecesario** | `AllowTcpForwarding no` si no se usa túnel | `sshd -T \| grep allowtcpforwarding` |
| 2.9 | **Timeout de inactividad** | `ClientAliveInterval 300` + `ClientAliveCountMax 2` | `sshd -T \| grep clientalive` |
| 2.10 | **Cambio de clave del host documentado** | `ssh-keygen -R` en el portátil cuando el host se reconfigura | El portátil tiene la huella nueva anotada |

> **2.7 y el túnel SSH se contradicen si no se piensa.** Si el acceso es por
> túnel SSH (`ssh -L`), laAllow-list por IP se aplica igual — el túnel se abre
> **desde** el host permitido. Si la IP del auditor es dinámica, la allow-list
> por IP no sirve y el control pasa a ser: clave con passphrase, sin contraseña,
> sin root, con fail2ban.

```bash
# /etc/ssh/sshd_config — bloque mínimo
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowTcpForwarding yes          # necesario para el túnel a la consola
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
LoginGraceTime 30
```

```bash
sudo sshd -t && sudo systemctl reload ssh
```

---

## 3. Firewall y egress

### 3.1 Entrada

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH — sólo del auditor
sudo ufw allow from 203.0.113.10 to any port 22 proto tcp

sudo ufw enable
sudo ufw status verbose
```

**No hay ninguna regla que abra 8787, 3000 ni 11434.** Esos puertos se
publican **sólo en `127.0.0.1`** (ver `deploy/docker-compose.yml`) y se acceden
por túnel SSH o VPN.

### 3.2 Egreso: el control que hace que «nada sale» sea real

El egreso bloqueado por defecto es lo que convierte el perímetro en una
restricción técnica. Allow-list mínima durante la instalación:

```bash
# DNS
sudo ufw allow out to 1.1.1.1 port 53 proto udp
sudo ufw allow out to 1.1.1.1 port 53 proto tcp
# NTP
sudo ufw allow out to 162.159.200.1 port 123 proto udp
# Registro de modelos (sólo durante la instalación; se retira después)
# sudo ufw allow out to registry.ollama.ai port 443 proto tcp
```

| Control | Cómo | Verificación |
|---|---|---|
| **Egreso bloqueado por defecto** | `ufw` con allow-list, o `nftables` con una policy `drop` de salida | `sudo ufw status verbose` muestra `Default: deny (outgoing)` y las reglas de allow |
| **Sólo el runtime LLM necesita salida** | `ollama` es el único que hace `pull` | `docker exec wap-ollama sh -c 'curl -s -o /dev/null -w "%{http_code}" https://example.com'` → falla; la consola → falla |
| **La consola no tiene salida** | Está en la red `wap_net` y no abre nada | Mismo test contra `wap-console` |
| **Retirar la regla del registro de modelos tras instalar** | Comentar la línea | `sudo ufw status numbered` no la muestra activa |

> **El modo «todo dentro de las instalaciones»** (research/06 §5.6) apaga el
> egreso por completo y usa `llama-server --offline`. En ese modo **no hay
> ninguna regla de salida**, ni DNS.

### 3.3 Exposición de Docker

Docker manipula iptables por su cuenta y **sus reglas pueden abrir puertos
aunque ufw los cierre**. Por eso:

| Control | Cómo | Verificación |
|---|---|---|
| **Los puertos publicados, sólo en loopback** | `ports: - "127.0.0.1:PUERTO:PUERTO"` | `ss -tlnp` — nunca `0.0.0.0` |
| **Nunca `network_mode: host`** | Ningún servicio lo usa | `grep -rn "network_mode" deploy/` → vacío |
| **El daemon de Docker no expone la API de Docker por TCP** | `/etc/docker/daemon.json`: `"hosts": ["unix:///var/run/docker.sock"]` | `ss -tlnp \| grep docker` → no aparece un 2375/2376 |
| **El socket de Docker sólo para `audit` y `root`** | `chown root:docker /var/run/docker.sock` + `chmod 660` | `ls -l /var/run/docker.sock` |

> **El socket de Docker es root.** Cualquiera que esté en el grupo `docker` es
> root en esa máquina. Por eso el grupo `docker` no se da a los auditores: el
> acceso al stack se hace con `sudo` puntual y registrado, o con un usuario de
> servicio propio.

---

## 4. fail2ban y monitorización

| # | Control | Cómo | Verificación |
|:-:|---|---|---|
| 4.1 | **fail2ban para SSH** | `apt install fail2ban`; jail `[sshd]` activo | `sudo fail2ban-client status sshd` lista las IP bloqueadas |
| 4.2 | **Límite de intentos y tiempo de bloqueo** | `maxretry = 5`, `findtime = 10m`, `bantime = 1h` | `sudo fail2ban-client get sshd bantime` |
| 4.3 | **Límite de conexiones simultáneas** | `MaxStartups 10:30:60` en `sshd_config` | `sshd -T \| grep maxstartups` |
| 4.4 | **Los logs del LLM se purgan** | `journalctl --vacuum-time=1d` en el cron diario | `journalctl -u docker --since "2 days ago" \| grep -c "prompt"` → 0 |
| 4.5 | **Nunca `--log-prompts-dir`** | El flag de depuración de llama.cpp queda **prohibido** en producción | `grep -rn "log-prompts-dir" deploy/` → vacío |
| 4.6 | **Rotación de logs de Docker** | Ya está en el `docker-compose.yml` (`max-size: 10m`, `max-file: 3`) | `docker inspect wap-ollama --format '{{.HostConfig.LogConfig.Config}}'` |
| 4.7 | **Alerta de disco** | `df -h` diario; alerta al 80 % | `crontab -l \| grep df` |
| 4.8 | **Alerta de RAM y OOM** | `dmesg \| grep -i "killed process"` en el cron diario | El cron existe y no ha saltado |
| 4.9 | **Un panel mínimo de salud** | `make health` una vez al día, con alerta si algún servicio no está `healthy` | `docker compose ps --format '{{.Service}} {{.Status}}'` |

### 4.1 Snippet de cron diario

```bash
# /etc/cron.d/wap-salud
MAILTO=root@localhost
*/15 * * * * root /usr/bin/docker ps --format '{{.Names}} {{.Status}}' | grep -v healthy && logger -t wap-salud "servicio no healthy"
17 3 * * * root journalctl --vacuum-time=1d
23 3 * * * root df -h / | awk 'NR==2 {if ($5+0 > 80) print "disco " $5}' | logger -t wap-salud
```

---

## 5. Docker

| # | Control | Cómo | Verificación |
|:-:|---|---|---|
| 5.1 | **Imágenes fijadas por digest** | `image: repo@sha256:...` en el compose | `grep -c "sha256:" deploy/.env` > 0; ninguna imagen usa `latest` |
| 5.2 | **`no-new-privileges` en todos los servicios** | `security_opt` en el compose | `docker inspect wap-ollama --format '{{.HostConfig.SecurityOpt}}'` |
| 5.3 | **`cap_drop: ALL` en todos los servicios** | `cap_drop` en el compose | `docker inspect wap-ollama --format '{{.HostConfig.CapDrop}}'` → `ALL` |
| 5.4 | **Límites de memoria** | `deploy.resources.limits.memory` | `docker inspect wap-ollama --format '{{.HostConfig.Memory}}'` > 0 |
| 5.5 | **Registro de Docker sin login anónimo** | `/etc/docker/daemon.json`: `"insecure-registries": []` | `docker info \| grep -i "insecure"` |
| 5.6 | **Escaneo de las imágenes** | `trivy image <imagen>` | Informe sin vulnerabilidades **altas** sin corregir |
| 5.7 | **SBOM de las imágenes** | `syft <imagen> -o spdx-json` | SBOM generado y archivado con el despliegue |
| 5.8 | **Update pinning documentado** | `THIRD_PARTY_LICENSES.md` con SPDX, fecha y digest | El fichero existe y está actualizado |

### 5.1 `/etc/docker/daemon.json` mínimo

```json
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true,
  "no-new-privileges": true,
  "userland-proxy": false
}
```

```bash
sudo systemctl restart docker && docker info | head -20
```

> **`userland-proxy: false`** cierra el proxy de espacio de usuario de Docker, que puede
> eludir reglas de firewall en algunos escenarios. Con `live-restore: true`, los
> contenedores siguen vivos durante una actualización del daemon.

---

## 6. Backups

| # | Control | Cómo | Verificación |
|:-:|---|---|---|
| 6.1 | **El backup sale de la máquina** | `make backup BACKUP_DIR=<ruta sincronizada>` | La copia está en otro dispositivo |
| 6.2 | **Volcado consistente, no copia en caliente** | `VACUUM INTO` | La base restaurada abre sin errores |
| 6.3 | **Cifrado en reposo** | `age` o `openssl enc -aes-256-cbc -pbkdf2` | `make verify-backup` la descifra |
| 6.4 | **La clave NO va con la copia** | La clave vive en el portátil del auditor / en el gestor de secretos del cliente | La copia sin la clave es inservible |
| 6.5 | **SHA-256 registrado** | `make backup` escribe el `.sha256` | El hash está en el expediente del engagement |
| 6.6 | **Prueba de restauración real, mensual** | `make restore FILE=...` en un entorno de prueba | Registro con fecha y resultado |
| 6.7 | **Una copia fuera de línea (regla 3-2-1, adaptada)** | 3 copias · 2 medios · 1 copia offline | El expediente dice dónde está cada una |
| 6.8 | **La evidencia NO se borra hasta el fin del plazo de retención** | Política del contrato (12 meses F0/F1; 30 días F2) | `PLAN-MAESTRO.md` §9.1 |

> **6.6 es el control que importa.** Un job de backup que corre no es un
> backup. Lo que se archiva en el expediente es la **fecha de la última
> restauración probada**, no la fecha del último job.

---

## 7. El stack de auditoría

Controles específicos de este despliegue, que no se aplican a un servidor web
normal.

| # | Control | Cómo | Por qué |
|:-:|---|---|---|
| 7.1 | **El LLM no tiene red hacia el exterior** | Sólo `ollama` puede salir (allow-list del registro de modelos) | Un LLM con red y con contenido de un sitio hostil es un vector de exfiltración |
| 7.2 | **El LLM no tiene herramientas** | Ollama no expone tools; el prompt no pide acciones | Un LLM con `exec_shell_command` en una VPS con datos de pacientes es un RCE esperando |
| 7.3 | **La API de Ollama no se publica nunca** | No hay `ports:` para 11434 | La API de Ollama **no tiene autenticación nativa**: su control es el binding |
| 7.4 | **`OLLAMA_NO_CLOUD=1`** | En el `docker-compose.yml` | Desactiva los modelos cloud de Ollama |
| 7.5 | **La evidencia cruda se monta en solo lectura** | `${EVIDENCE_HOST_DIR}:/evidencia:ro` | La consola no puede escribir ni borrar evidencia cruda ni por bug |
| 7.6 | **La base sólo contiene evidencia saneada** | La consola guarda el `sha256` de la cruda, no su contenido | Es la diferencia entre «guardar PII cifrada» y «no tener PII» |
| 7.7 | **La salida del LLM se re-redacta antes de escribirse** | `LLM_OUTPUT_POLICY=revalidate` | Es un filtro, no una barrera: por eso el auditor lee |
| 7.8 | **El prompt va delimitado y con esquema JSON fijo** | Prompt de sistema + `injection_detected` | Mitiga el prompt injection desde contenido de sitio hostil |
| 7.9 | **El `.env` nunca se versiona** | `.gitignore` excluye `.env`, `.env.*`, `**/.env`, `**/.env.*` | Un secreto en el historial de git está en el historial |
| 7.10 | **gitleaks + Push Protection** | `.gitleaks.toml` y la CI del repo | Detecta secretos antes de que se publiquen |
| 7.11 | **El nombre de los contenedores y volúmenes es genérico** | `wap-ollama`, `wap_db`, `wap_net` | Un nombre de cliente en un `docker ps` es una fuga |
| 7.12 | **`03-casos/` no está en la VPS del cliente** | Se despliega una copia del stack, no del histórico | La evidencia de un cliente no viaja a la máquina de otro cliente |
| 7.13 | **Los logs del LLM no se conservan** | Purga journalctl + nunca `--log-prompts-dir` | Los logs del LLM son evidencia: si el prompt llevaba un dato de paciente, queda persistido |

---

## 8. Revisión mensual

Una rutina de 30 minutos que sostiene todo lo anterior.

| # | Tarea | Comando | Qué hacer si falla |
|:-:|---|---|---|
| 1 | **Prueba de restauración del backup** | `make verify-backup` y, un mes sí, `make restore` en un entorno de prueba | No aceptar el siguiente engagement hasta arreglarlo |
| 2 | **Rotación de secretos** (trimestral, pero revisa que esté al día) | `grep -c CAMBIAR_ESTE_VALOR .env` → 0 | Rotar |
| 3 | **Actualizaciones de seguridad** | `apt list --upgradable` | Aplicar y reiniciar lo que lo necesite |
| 4 | **Escaneo de las imágenes** | `trivy image <imagen>` | Actualizar la imagen, fijar el nuevo digest |
| 5 | **Disco y RAM** | `df -h` · `free -h` · `docker stats --no-stream` | Liberar espacio; bajar `LLM_MODEL` |
| 6 | **Servicios y healthchecks** | `make health` | Reiniciar el servicio afectado |
| 7 | **Puertos publicados** | `ss -tlnp` | Si aparece un `0.0.0.0` no previsto, parar y corregir |
| 8 | **`authorized_keys`** | `cat ~/.ssh/authorized_keys` | Quitar las claves de quien ya no está |
| 9 | **Egress** | `sudo ufw status verbose` | Restablecer la política de `deny outgoing` |
| 10 | **Modelo y digest** | `make list-models` | Actualizar según la política trimestral, con evaluación |

---

## 9. Antes y después de cada cambio

| Antes | Después |
|---|---|
| Snapshot del estado actual (`docker compose ps`, `docker inspect`, `ollama list`) | Reiniciar los servicios afectados y `make health` |
| Copia de la base (`make backup`) | Verificar que la consola lee la base (`make db-shell`) |
| Fijar el digest de la imagen nueva en `.env` | `trivy image` sobre la imagen nueva antes de desplegarla |
| Revisar el diff del `docker-compose.yml` | Comprobar que ningún puerto nuevo se publica en `0.0.0.0` |

> **Regla de una línea para cualquier cambio en este stack:**
> *si el cambio añade un puerto publicado, un volumen con permisos abiertos o
> un servicio con salida a internet, no se.mergea sin la revisión de otra
> persona.*

---

## 10. Verificación final

Resumen que se archiva en el expediente del despliegue.

| # | Control | Estado | Evidencia |
|:-:|---|---|---|
| 1 | Actualizaciones automáticas | ☐ | `apt-config dump \| grep Automatic` |
| 2 | Usuario de servicio sin root | ☐ | `id audit` |
| 3 | `.env` en 0600 | ☐ | `stat -c '%a' .env` |
| 4 | Evidencia en 0750 | ☐ | `ls -ld /opt/audit/evidencia` |
| 5 | SSH sólo por clave, sin root | ☐ | `sshd -T \| grep -E "passwordauth\|permitrootlogin"` |
| 6 | `authorized_keys` con una línea por persona | ☐ | `cat ~/.ssh/authorized_keys` |
| 7 | Firewall: `deny incoming` por defecto | ☐ | `sudo ufw status verbose` |
| 8 | Egreso: `deny outgoing` por defecto + allow-list | ☐ | `sudo ufw status verbose` |
| 9 | fail2ban activo para sshd | ☐ | `sudo fail2ban-client status sshd` |
| 10 | **Ningún puerto de administración en `0.0.0.0`** | ☐ | `ss -tlnp` |
| 11 | **11434 no publicado** | ☐ | `ss -tlnp \| grep 11434` → vacío |
| 12 | La consola responde por túnel SSH | ☐ | `curl -s http://127.0.0.1:8787/api/health` desde el portátil |
| 13 | `no-new-privileges` + `cap_drop: ALL` | ☐ | `docker inspect` |
| 14 | Límites de memoria activos | ☐ | `docker inspect ... {{.HostConfig.Memory}}` |
| 15 | Imágenes fijadas por digest, sin `latest` | ☐ | `grep latest deploy/.env` → vacío |
| 16 | Backup **fuera** de la máquina | ☐ | `ls -l $BACKUP_DIR` |
| 17 | Backup verificado (se puede leer y restaurar) | ☐ | `make verify-backup` |
| 18 | `OLLAMA_NO_CLOUD=1` | ☐ | `docker exec wap-ollama printenv OLLAMA_NO_CLOUD` |
| 19 | El LLM **no** tiene red hacia el exterior | ☐ | test de egreso desde `wap-console` |
| 20 | La evidencia cruda montada en solo lectura | ☐ | `docker inspect wap-console --format '{{json .HostConfig.Binds}}'` |
| 21 | `03-casos/` no está en la VPS | ☐ | `ls /opt/audit` |
| 22 | Los logs del LLM se purgan | ☐ | `journalctl --since "2 days ago" \| grep -c prompt` → 0 |
| 23 | `.env` no está en git | ☐ | `git check-ignore -v deploy/.env` |
| 24 | Nombres de contenedor y volúmenes genéricos | ☐ | `docker ps --format '{{.Names}}'` |

---

## 11. Lo que este documento NO dice

| No | Por qué |
|---|---|
| No dice qué ley aplica a la retención ni a la notificación de incidentes | Esas fechas las fija el abogado del cliente y la fuente primaria (DOF, `diputados.gob.mx/LeyesBiblio`, BOE, EUR-Lex). Ver `PLAN-MAESTRO.md` §9. |
| No da precios de prima de seguro ni límites de indemnización | Son los de la póliza y del corredor. Ver `PLAN-MAESTRO.md` §9.1. |
| No certifica que la máquina sea segura | Un checklist no es una certificación. Esta VPS se audita con el **mismo playbook** que un cliente (research/06 §1.10). |
| No sustituye a la auditoría del propio stack | Revisa la infraestructura. El código, las plantillas y la metodología tienen su propia revisión (CI, `bandit`, `selftest.py`). |

---

*Endurecimiento de la VPS del stack de auditoría. Complementa a
[`deploy/README.md`](README.md) y a [`../PLAN-MAESTRO.md`](../PLAN-MAESTRO.md)
§10. No es asesoría legal.*
