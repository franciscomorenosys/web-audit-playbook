# Laboratorio seguro para auditoría web y WordPress

> **Corte de referencia:** 22 de octubre de 2026. Todo lo que sigue se ejecuta en una máquina o red de laboratorio propia.

## La regla

**Nunca se practica contra un sitio ajeno. Si no hay autorización escrita, no se toca.** El laboratorio es donde se practica todo lo que en un cliente real se hace únicamente con permiso, alcance y RoE firmados. “Es solo una petición”, “es un contenedor vulnerable” o “encontré el dominio en una wordlist” no son autorizaciones.

La separación segura es simple: objetivos con nombre `.test` (reservado por RFC 6761), IPs loopback, contenedores aislados y snapshots. Ante cualquier duda sobre si una petición puede salir del laboratorio, se detiene.

## 1. Apps deliberadamente vulnerables

| App | Comando de una línea | Qué enseña | Dificultad / estado en 2026 |
|---|---|---|---|
| **OWASP Juice Shop** | `docker run --rm -p 3000:3000 bkimminich/juice-shop` | XSS, SQLi, IDOR, JWT y lógica de negocio. | Inicial; **mantenida**, referencia principal. |
| **DVWA** | `docker run --rm -it -p 4280:80 vulnerables/web-dvwa` | SQLi, XSS, LFI, CSRF, credenciales débiles y controles configurables. | Inicial/intermedio; **mantenida**, aunque con cadencia baja. |
| **WebGoat** | `docker run --rm -it -p 8080:8080 -p 9090:9090 webgoat/webgoat` | OWASP Top 10 con lecciones guiadas. | Inicial/intermedio; **mantenida**. |
| **Metasploitable 3** | `docker run --rm --platform linux/amd64 -p 22:22 -p 80:80 -p 443:443 -p 3306:3306 -p 5432:5432 -p 4444:4444 rapid7/metasploitable3:latest` | Explotación de servicios y pivoting. | Avanzado; **existe y es la línea actual**. En Apple Silicon, Docker Desktop emula `amd64`; la OVA oficial en UTM/QEMU suele ser más fiable. |
| **Metasploitable 2** | `docker run --rm --platform linux/amd64 -p 22:22 -p 80:80 -p 443:443 -p 3306:3306 -p 5432:5432 -p 4444:4444 vuln/metasploitable2` | VM clásica de Kali. | Avanzado; **legacy/congelada**. No es un objetivo web. |
| **bWAPP** | `docker run --rm -it -p 80:80 raesene/bwapp` | SQLi, session flaws, file inclusion, XML. | Intermedio; **legacy/abandonada**. |
| **Mutillidae** | `docker run --rm -it -p 8000:80 owasp/mutillidae` | PHP/MySQL mutado, OWASP Top 10. | Intermedio; **mantenida**. |
| **NodeGoat** | `docker run --rm -it -p 9090:9090 nodejsapp/node-goat` | Node/Express, prototype pollution, NoSQL y templado. | Intermedio; **legacy/abandonada**. |
| **Railsgoat** | `git clone https://github.com/RailsGoat/railsgoat.git && cd railsgoat && docker build -t railsgoat . && docker run --rm -it -p 3000:3000 railsgoat` | Rails, mass assignment, SQLi y deserialización. | Avanzado; **abandonada**. |
| **WebGoat.NET** | `docker run --rm -it -p 5000:5000 webgoatdotnet/webgoatdotnet` | ASP.NET/.NET; no es exactamente WordPress. | Avanzado; **abandonada**; la imagen antigua puede fallar. |

Primero se usa Juice Shop para cerrar la metodología; después el WordPress propio, porque representa el 80% del negocio. Antes de confiar en una imagen, se fija versión y digest: `docker image inspect bkimminich/juice-shop --format '{{index .RepoDigests 0}}'`.

En Apple Silicon, `docker buildx imagetools inspect rapid7/metasploitable3:latest` muestra las arquitecturas publicadas: si hay `arm64`, omite `--platform linux/amd64`; si sólo hay `amd64`, Docker Desktop lo emula con QEMU. Para M3, importar la OVA oficial en UTM (QEMU) suele ser más fiable; Lima es útil para una VM Linux arm64 propia, no para acelerar una OVA x86.

Los puertos de la tabla se muestran en su forma literal. En una red no confiable, cambia cada `-p PUERTO:PUERTO` por `-p 127.0.0.1:PUERTO:PUERTO`; así nadie de la LAN alcanza el sandbox. Metasploitable 2 es x86_64 y puede fallar bajo QEMU moderno; en ese caso, importa su VM oficial en UTM/QEMU.

## 2. Tu propio WordPress vulnerable

### Compose mínimo, listo en macOS Apple Silicon

En `~/security-lab/wp-lab`, crea `docker-compose.yml` y el directorio `proxy/`:

```bash
mkdir -p ~/security-lab/wp-lab/proxy
cd ~/security-lab/wp-lab
```

```yaml
name: wp-lab
services:
  db:
    image: mysql:8.0
    environment:
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress
      MYSQL_ROOT_PASSWORD: root-lab-only
    volumes:
      - db_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1"]
      interval: 5s
      timeout: 3s
      retries: 20

  wp:
    image: wordpress:6.8.2-php8.3-apache
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "127.0.0.1:8080:80"   # jamás 0.0.0.0 por defecto
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - ./wordpress:/var/www/html

  proxy:
    image: nginx:1.28-alpine
    depends_on:
      - wp
    ports:
      - "127.0.0.1:8081:80"
    volumes:
      - ./proxy/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - nginx_cache:/var/cache/nginx

volumes:
  db_data:
  nginx_cache:
```

Antes de iniciar, crea `proxy/nginx.conf`:

```nginx
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=page:20m max_size=1g inactive=30d;
server {
    listen 80;
    proxy_cache page;
    proxy_cache_valid 200 365d;
    proxy_cache_key "$scheme$host$request_uri";
    proxy_ignore_headers Cache-Control Set-Cookie Expires;
    add_header X-Cache-Status $upstream_cache_status always;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    resolver 127.0.0.11 valid=10s ipv6=off;
    set $wp_upstream wp:80;
    location / { proxy_pass http://$wp_upstream; }
}
```

```bash
docker compose up -d
docker compose logs wp --tail=50
```

Abre `http://127.0.0.1:8081` —el puerto de nginx—, instala WordPress y fija **Site Address** en `http://127.0.0.1:8081`; así el HTML no redirige y la caché sí queda en el camino. El bind mount deja `wordpress/wp-content/plugins` visible en el host.

### Nombre local sin salir a Internet

Edita `/etc/hosts`:

```text
127.0.0.1 wp.local.test
```

Alternativa con `dnsmasq` para varios nombres:

```bash
brew install dnsmasq
sudo mkdir -p /opt/homebrew/etc/dnsmasq.d /etc/resolver
sudo tee /opt/homebrew/etc/dnsmasq.d/wp-lab.conf >/dev/null <<'EOF'
port=5353
listen-address=127.0.0.1
no-resolv
server=1.1.1.1
address=/wp.local.test/127.0.0.1
EOF
sudo sh -c 'grep -q "^conf-dir=/opt/homebrew/etc/dnsmasq.d" /opt/homebrew/etc/dnsmasq.conf || printf "conf-dir=/opt/homebrew/etc/dnsmasq.d\\n" >> /opt/homebrew/etc/dnsmasq.conf'
sudo tee /etc/resolver/wp.local.test >/dev/null <<'EOF'
nameserver 127.0.0.1
port 5353
EOF
brew services restart dnsmasq
dscacheutil -flushcache
```

Comprueba el destino, no solo el nombre: `dig @127.0.0.1 -p 5353 wp.local.test A` debe devolver `127.0.0.1`.

### Plugin deliberadamente viejo

La API permite ver qué versiones conserva WordPress.org:

```bash
brew install subversion jq
SLUG=elementor
VERSION=3.5.0
curl -fsSL "https://api.wordpress.org/plugins/info/1.0/${SLUG}.json" | jq -r '.versions | keys[]' | sort
```

Patrón exacto para traer un tag histórico del SVN oficial, sin WP-CLI:

```bash
docker compose stop wp
rm -rf "wordpress/wp-content/plugins/${SLUG}"
svn export "https://plugins.svn.wordpress.org/${SLUG}/tags/${VERSION}/" "wordpress/wp-content/plugins/${SLUG}"
docker compose up -d wp
```

Actívalo desde **Plugins** y confirma la versión en el encabezado del plugin; no asumas que la carpeta significa que esté cargado.

Verifica siempre el código instalado y deja evidencia reproducible:

```bash
svn info "https://plugins.svn.wordpress.org/${SLUG}/tags/${VERSION}/" | tee "wordpress/${SLUG}-svn.txt"
find "wordpress/wp-content/plugins/${SLUG}" -type f -exec shasum -a 256 {} \; | sort > "wordpress/${SLUG}-${VERSION}.sha256"
```

La antigüedad sirve para entender el CVE y el impacto, no para «conseguir un exploit».

### Caché que sirve varias versiones

Patología a reproducir: `cliente -> nginx (full-page cache, nunca purga) -> Apache/PHP -> WordPress -> MySQL`. Si el origen cambia de versión o plugin, la caché entrega HTML viejo; rutas cacheadas en épocas distintas muestran WordPress distintos.

Para ensayar el salto sin ensuciar el Compose principal, crea `compose.old.yml`:

```yaml
services:
  wp:
    image: wordpress:6.7.1-php8.2-apache
```

1. Parte de cero, arranca la versión vieja e instala WordPress en `http://127.0.0.1:8081`:

```bash
docker compose down -v
rm -rf ./wordpress
docker compose -f docker-compose.yml -f compose.old.yml up -d
```

2. Siembra la caché y repite la petición: debe aparecer `X-Cache-Status: HIT` en la segunda.

```bash
curl -sS -D - -o /dev/null http://127.0.0.1:8081/
curl -sS -D - -o /dev/null http://127.0.0.1:8081/
```

3. Vuelve a la versión nueva sin purgar DB ni caché: `docker compose stop wp && rm -rf ./wordpress && docker compose up -d --force-recreate wp`. `/` seguirá devolviendo el HTML viejo desde nginx; `/?fresh=1` es otra clave y revela la versión nueva. Compara `curl -sS http://127.0.0.1:8081/ | grep -o 'name="generator" content="[^"]*'` con `curl -sS 'http://127.0.0.1:8081/?fresh=1' | grep -o 'name="generator" content="[^"]*'`.

En un hosting con pool, dos upstreams (`wp-old`, `wp-new`) y afinidad por host/session producen versiones mezcladas. En el lab se mantiene un origen para aislar el efecto de caché. La reproducción exige dos perfiles de nginx y reglas de purga distintas; **nunca se intenta contra un hosting**. `proxy_ignore_headers ... Set-Cookie` permite cachear contenido autenticado: es la patología y el proxy jamás debe publicarse.

### Alternativas locales

- **LocalWP**: mejor experiencia para WordPress y rutas de plugins en Apple Silicon.
- **MAMP**: Apache/MySQL, lo más parecido a shared hosting; licencia paga.
- **Valet**: Nginx/PHP/MySQL, rápido para desarrollo; no reproduce Apache.
- **OrbStack**: mejor runtime Docker para Apple Silicon y Compose; no administra WordPress.

**Elección 2026:** OrbStack + Compose para el laboratorio; LocalWP para trabajar WordPress; MAMP sólo si Apache es parte del experimento.

## 3. Entornos externos legales

| Plataforma | Qué cubre | Costo aproximado | ¿Vale la pena? |
|---|---|---:|---|
| **PortSwigger Web Security Academy** | SQLi, XSS, access control/IDOR, auth, SSRF, XXE, deserialización, SSTI, GraphQL, JWT, path traversal, command injection y lógica. | Gratis | **Sí, el mejor inicio**. |
| **Hack The Box** | Máquinas, Starting Point, AD, web, infra y Academy. | Free limitado; Pro ~US$49/mes. Academy ~US$70/año. | Sí, si ya dominas HTTP y Linux. |
| **HTB Academy / CPTS** | Ruta de pentest hasta la certificación CPTS de HTB. | Academy + voucher CPTS ~US$200: **~MXN 3,400**; 3–4 meses, 8–12 h/semana. | Sí para corrección profesional, no como primer día. |
| **TryHackMe** | Guías, rooms, Paths y blue/red. | Free; Plus ~US$10/mes o US$50/año. | Sí, especialmente Linux/web inicial. |
| **PentesterLab** | PHP, WordPress, Apache, Linux y badges. | Free limitado; PRO ~US$99/año. | Útil si el objetivo es WordPress/PHP. |
| **ProHackMe** | Laboratorios web actuales y sales en español. | Gratis | Sí, excelente para práctica guiada. |
| **picoCTF** | Forense, crypto y web intro. | Gratis | Como warm-up, no como curso principal. |
| **CyberDefenders** | Blue team, Docker y análisis de incidentes. | Gratis/labs free | Sí para roles defensivos. |
| **VulnHub** | VMs descartables para practicar y documentar. | Gratis | Complemento, no fuente principal |

**Distinción HTB:** *Free* limita las máquinas disponibles; *Pro* amplía el catálogo y las instancias. *Academy* es formación guiada y *Pro* acceso a máquinas. *Labs* son máquinas individuales; *Dojo* es un range guiado y colaborativo, con planes y precios propios. La ruta CPTS combina Academy, práctica en máquinas y un voucher de examen.

## 4. Laboratorio de red y TLS

`/etc/hosts` sirve para uno o pocos nombres; `dnsmasq` aporta resolución local dinámica; Caddy/Traefik son **reverse proxies** y no reemplazan DNS: ambos pueden usar nombres `.test` resueltos localmente. Añade `127.0.0.1 local.test` al `/etc/hosts`.

Certificados localmente válidos y confiados por macOS:

```bash
brew install mkcert caddy
mkcert -install
mkdir -p certs
mkcert -cert-file certs/local.test.pem -key-file certs/local.test-key.pem \
  local.test "*.local.test" app.tercero-a.test cdn.tercero-b.test
```

Los SAN “de terceros” usan `.test`; simulan la expansión del certificado sin tocar marcas ni DNS reales. Comprueba SAN y cadena:

```bash
openssl s_client -connect 127.0.0.1:443 -servername local.test </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

En `Caddyfile`:

```caddyfile
http://local.test {
    reverse_proxy 127.0.0.1:8081 {
        header_up Host 127.0.0.1:8081
    }
}
https://local.test {
    tls certs/local.test.pem certs/local.test-key.pem
    reverse_proxy 127.0.0.1:8081 {
        header_up Host 127.0.0.1:8081
    }
    header {
        X-XSS-Protection "1; mode=block"
        X-Frame-Options "SAMEORIGIN"
    }
}
```

Este perfil reproduce a propósito: **HTTP sin redirect** a HTTPS (bloque `http://` explícito), **sin HSTS**, cabeceras modernas ausentes y valores legacy. No se añade `Strict-Transport-Security`, CSP, `Referrer-Policy` ni `Permissions-Policy`. Arranca el proxy con `caddy run --config Caddyfile` y valida por separado:

```bash
curl -I http://local.test
curl -Ik https://local.test
curl -Ik https://local.test | grep -iE 'strict-transport|content-security|x-frame'
```

## 5. Higiene de lab: errores de principiante

- **Escanear la LAN o el router.** Ocurre con `nmap -sn 192.168.0.0/24`, con un rango `/16` equivocado o porque `router.local` resuelve mediante mDNS. Nunca uses un CIDR amplio contra una interfaz real. En macOS, fija el interfaz y un destino: `nmap -e lo -sn 127.0.0.1/32`; en Linux, `nmap --interface lo -sn 127.0.0.1/32`. Para un contenedor de escaneo usa una red Docker interna: `docker network create --internal lab-offline`.
- **La VM “de pruebas” está en tu red de confianza.** UTM/VMware/VirtualBox en NAT todavía puede alcanzar la LAN. **Nunca pongas la VM del lab en una red que te importe.** Usa una VM exclusiva, NAT y egress limitado al rango del laboratorio; jamás la conectes por bridge a la red de casa u oficina.
- **DNS rebinding / TOCTOU.** Un dominio de la wordlist puede resolver a un equipo real y, segundos después, a otra IP. Sólo se usan nombres `.test` controlados; antes de cada lote se verifica `dig` y se fija destino: `curl --resolve wp.local.test:8080:127.0.0.1 http://wp.local.test:8080/`.
- **Reset en diez segundos.** `docker compose down -v && rm -rf ./wordpress && docker compose up -d` borra DB y código bind-mounted. Haz snapshot de la VM antes de una sesión: `VBoxManage snapshot wp-lab take clean`; restaura con `VBoxManage snapshot wp-lab restore clean` o desde UTM.
- **Servicios publicados en todas las interfaces.** En Compose se usa `127.0.0.1:P:80`, no `P:80`. Revisa `docker ps --format 'table {{.Names}}\t{{.Ports}}'`.

## 6. Presupuesto real (MXN)

Referencia: **US$1 ≈ MXN 17**; precios orientativos al 22-10-2026, verificar antes de pagar.

- **MXN 0:** Docker Desktop (si la empresa cumple su licencia gratuita), Juice Shop, DVWA, WebGoat, Mutillidae, WordPress.org, SVN, `mkcert`, PortSwigger Academy, free tier de HTB/THM, ProHackMe, picoCTF, CyberDefenders y VulnHub.
- **MVP:** HTB Pro 1 mes, ~US$49 (**MXN 833**) para más máquinas, o TryHackMe Plus anual, ~US$50 (**MXN 850**). No compres ambos.
- **Ruta CPTS:** Academy ~US$70/año (**MXN 1,190**) + voucher ~US$200 (**MXN 3,400**) + HTB Pro 1 mes (**MXN 833**) = **~MXN 5,423**; sumar 3 meses de Pro eleva el presupuesto a **~MXN 7,089**.
- **WP práctico:** PentesterLab PRO anual, ~US$99 (**MXN 1,683**), sólo si necesitas badges y labs PHP.

## 7. Checklist del primer fin de semana

1. **Crear y arrancar:** `mkdir -p ~/security-lab/wp-lab/proxy && cd ~/security-lab/wp-lab && docker compose up -d`.
2. **Confirmar loopback:** `curl -I http://127.0.0.1:8080 && docker compose ps`.
3. **Instalar WordPress:** `open http://127.0.0.1:8081`; completar el instalador, fijar Site Address a esa URL y crear el admin de pruebas.
4. **Añadir nombre reservado:** `sudo sh -c 'grep -q "wp.local.test" /etc/hosts || printf "127.0.0.1 wp.local.test\\n" >> /etc/hosts'`; luego `curl --resolve wp.local.test:8080:127.0.0.1 http://wp.local.test:8080/`.
5. **Traer plugin viejo:** `SLUG=elementor VERSION=3.5.0; docker compose stop wp; rm -rf "wordpress/wp-content/plugins/${SLUG}"; svn export "https://plugins.svn.wordpress.org/${SLUG}/tags/${VERSION}/" "wordpress/wp-content/plugins/${SLUG}"; docker compose up -d wp; find "wordpress/wp-content/plugins/${SLUG}" -type f -exec shasum -a 256 {} \; | sort > "wordpress/${SLUG}-${VERSION}.sha256"`.
6. **Practicar con el sandbox:** `docker run --rm -p 3000:3000 bkimminich/juice-shop`; resolver una sala y documentar request, impacto y remediación.
7. **Practicar TLS:** `sudo sh -c 'grep -q "local.test" /etc/hosts || printf "127.0.0.1 local.test\\n" >> /etc/hosts' && brew install mkcert caddy && mkcert -install && mkdir -p certs && mkcert -cert-file certs/local.test.pem -key-file certs/local.test-key.pem local.test`; luego `caddy run --config Caddyfile` y `curl -Ik https://local.test`.
8. **Aislar y resetear:** `docker network inspect lab-offline >/dev/null 2>&1 || docker network create --internal lab-offline`; después `docker compose down -v && rm -rf ./wordpress && docker compose up -d`.

## Errores que verás cometidos a otros y no cometas tú

- Confundir “vulnerable” con “sin autorización”.
- Escanear `192.168.0.0/24` desde la laptop.
- Crear nombres reales y confiar en DNS wildcards.
- Publicar puertos Docker en `0.0.0.0`.
- Instalar un plugin viejo sin fijar versión/checksum.
- Usar una imagen o URL real para reproducir caché, HSTS o SAN sprawl.
- Probar sin snapshot, logs ni procedimiento de reset.
- Reportar exploits ejecutados contra terceros como “trabajo legítimo”.
