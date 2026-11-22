# Cómo contribuir

Gracias por querer mejorar este playbook. Este repositorio es la metodología
que un consultor usa para auditar sitios con datos sensibles, así que la
barra de entrada no es «que compile»: es **que no filtre nada**.

---

## 1. Las tres reglas que no se negocian

> **1. Nada de datos de clientes reales.** Ni evidencia, ni informes, ni
> volcados, ni capturas, ni un `curl` contra el sitio de un tercero.
>
> **2. Nada de PII.** Ni de pacientes, ni de empleados, ni de contactos. Ni en
> el texto, ni en el nombre del fichero, ni en la línea de comando que se copia
> al informe.
>
> **3. Nada de secretos reales.** Ni claves, ni tokens, ni contraseñas. En el
> repo sólo hay secretos **sintéticos** (los fixtures de test), y existen
> precisamente para eso.

Si dudas de si algo es un dato de cliente: **no lo subas**. En el peor caso se
borra un PR; en el mejor caso, se publica un expediente.

---

## 2. Flujo de trabajo

```
fork ──► branch ──► commit ──► push ──► pull request ──► revisión ──► merge
```

1. **Fork** del repositorio y clona tu fork.
2. **Branch** con un nombre descriptivo:
   - `feat/<descripcion-corta>` — funcionalidad nueva
   - `fix/<descripcion-corta>` — corrección de un bug
   - `docs/<descripcion-corta>` — sólo documentación
   - `tooling/<descripcion-corta>` — scripts y CI
3. **Commits pequeños y con mensaje útil**. El formato del mensaje:
   ```
   <tipo>: <qué hace>

   <por qué>
   <referencia al issue: #12>
   ```
   Tipos: `feat`, `fix`, `docs`, `refactor`, `test`, `ci`, `chore`.
4. **Push** a tu fork.
5. **Pull request** contra `main`. Rellena la plantilla
   ([.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md)).
6. **La CI tiene que pasar en verde**: compilación de los scripts, `selftest`,
   chequeo de enlaces y `gitleaks`.
7. **Revisión**: el maintainer revisa y responde. Los PRs de documentación se
   revisan por exactitud técnica; los de código, también por seguridad.

**Commits y PRs**: nunca uses `--force` sobre `main` ni reescribas el
historial de una rama compartida.

### 2.1 Qué NO se mergea

- Evidencia de auditorías reales.
- Ficheros `authorization.json` (sólo `authorization.example.json`).
- Secretos reales, ni siquiera «de prueba» sin marcar.
- Dependencias nuevas en el toolkit: los scripts son **Python stdlib, cero
  dependencias**. Esa es una decisión de diseño, no una casualidad.
- Contenido generado que se pueda regenerar (el `.venv/` del teaser son 196 MB).

---

## 3. Convención de la evidencia (por contenido, no por herramienta)

Cuando contributed con material nuevo (casos, plantillas, ejemplos), la
evidencia se nombra **por lo que contiene**, nunca por el comando que la
produjo:

| Bien | Mal |
|---|---|
| `tls_versions.txt` | `openssl.txt` |
| `dns_mailsec.txt` | `dig.txt` |
| `http_check.txt` | `curl.txt` |
| `headers_home.txt` | `header.txt` |
| `users_api.json` | `output.json` |

Reglas adicionales:

- **Un hecho, un fichero.** Si el fichero tiene que explicarse con un
  párrafo, probablemente son dos ficheros.
- **Los falsos positivos se conservan** (ej. `evidencia/tls_floor.txt`). Una
  carpeta donde todo salió bien a la primera es sospechosa: normalmente significa
  que se borró lo incómodo.
- **Cada hallazgo apunta a su evidencia** por ruta y por comando reproducible.
  Si no hay fichero, no hay hallazgo.
- **Mismo nombre, mismo formato.** `*.txt` para texto plano, `*.json` para
  datos estructurados, `*.tsv` para resultados tabulares.

---

## 4. Redacción obligatoria con `pii_redact.py`

> **Todo fichero que salga del escritorio del auditor —al cliente, a hosting, a
> la agencia, a un ticket, a una captura— pasa por `pii_redact.py`.**
> **El crudo no se sobrescribe ni se envía: se entrega la copia sanitizada.**

```bash
# Redactar un fichero suelto
python3 01-tooling/scripts/pii_redact.py evidencia/paciente.json --out-dir ./redactado

# Redactar una carpeta entera y generar el informe de conteos
python3 01-tooling/scripts/pii_redact.py evidencia/ --out-dir ./redactado --report informe.json

# Conservar las IP (cuando son dato público del cliente y no dato de paciente)
python3 01-tooling/scripts/pii_redact.py notas.txt --keep-ips
```

Qué redacta: emails, teléfonos (MX/ES/US), RFC/NIF/DNI/CUIT, IPs, números de
tarjeta (validados con Luhn), fechas de nacimiento, códigos postales, URLs con
credenciales embebidas, y claves JSON cuyo nombre es típico de dato personal o
clínico (`nombre`, `expediente`, `curp`, `diagnostico`, `paciente`, …).

El informe de conteos **sólo contiene categorías y cantidades**: nunca valores.

### 4.1 Reglas de redacción al contribute

| Regla | Detalle |
|---|---|
| **Redacta antes de commitear** | El CI ejecuta `gitleaks` y falla si aparece un secreto. No lo apagues: redáctalo. |
| **No edites el crudo** | Genera una copia sanitizada aparte. El fichero original es evidencia de primera mano y no se toca. |
| **En el nombre del fichero, nada de PII** | `paciente-juan-perez.txt` no existe. Usa `paciente-ejemplo.txt`. |
| **Los marcadores son estables** | `[REDACTADO:email]`, `[DOMINIO-CLIENTE]`, `[EMAIL-CONTACTO]`, `[AGENCIA]`. Los mesmos sitios, los mismos marcadores: eso es lo que permite verificar el sanitizado con un `grep`. |
| **El mapa de redacción no se publica** | Si redactas algo para compartirlo, el fichero que dice «aquí iba X» es tan sensible como el original. No lo subas. |

### 4.2 Qué hacer si te saltan el escáner

1. **No subas el fichero.** Arregla la fuente (plantilla, ejemplo, fixture).
2. Si el valor es **sintético** y es imprescindible (p. ej. el fixture de
   test), márcalo explícitamente en el código con un comentario
   (`// FIXTURE: valor ficticio, no existe en ningún proveedor`) y decláralo en
   la allowlist de `.gitleaks.toml`, que sólo acepta **valores concretos y
   rutas concretas**.
3. Si el valor **es real**, trátalo como una exposición: rota la credencial,
   avisa a quien corresponda y no lo subas ni a un issue.

---

## 5. Antes de abrir el pull request

```bash
# 1. Compila todos los scripts (no debe haber errores de sintaxis)
python3 -m compileall -q 01-tooling/scripts 02-plantillas/teaser-report

# 2. Pasa la auto-prueba (sin red)
python3 01-tooling/scripts/tests/selftest.py

# 3. Comprueba que los enlaces del README resuelven
python3 01-tooling/scripts/tests/check_links.py

# 4. Escanea secretos
python3 01-tooling/scripts/secrets_scan.py . --json --out /tmp/secret_scan.json
```

Si el paso 4 devuelve hallazgos, **revisa cada uno**: o es un secreto sintético
que hay que declarar en la allowlist, o es un secreto real que hay que
**reescribir**. No hay tercera opción.

---

## 6. Estilo

- **Idioma:** la documentación, los mensajes de commit y los entregables al
  cliente van en **español**. Los nombres de fichero, las funciones y los
  comandos técnicos van en inglés o español según el caso.
- **Markdown:** ATX (`#`), una línea por frase, tablas para comparar,
  listas numeradas para procedimientos.
- **Código Python:** stdlib sólo, `from __future__ import annotations`, type
  hints en las funciones públicas, docstring en español con el *qué* y el
  *por qué* (no el *cómo*), y `# `` `` `` como separador de secciones largas.
- **Comentarios:** explican **por qué**, nunca el qué. El código dice el qué.
- **Líneas largas:** 88 caracteres como máximo (Black por defecto).
- **Un script, una responsabilidad.** Si un script hace dos cosas, son dos.

---

## 7. Añadir un script al toolkit

Checklist para un PR que añade `01-tooling/scripts/<nombre>.py`:

- [ ] Es Python 3.11+ **stdlib, cero dependencias**.
- [ ] No hace red sin pasar por `scope_guard.py`.
- [ ] Nunca hace POST ni métodos de escritura.
- [ ] No imprime ni escribe **el valor completo** de un secreto.
- [ ] Tiene `--json` para poder encadenarse con otros scripts.
- [ ] Tiene `--help` con ejemplos reales de uso.
- [ ] Tiene un check en `01-tooling/scripts/tests/selftest.py` que falle si el
      script se rompe.
- [ ] Está documentado en `01-tooling/scripts/README.md` y, si aplica, en
      `01-tooling/manifiesto-de-herramientas.md`.
- [ ] Sus fixtures (si tiene) están en `tests/fixtures/` y son **sintéticos**.

---

## 8. Documentos relacionados

- [`SECURITY.md`](SECURITY.md) — política de seguridad y reporte responsable
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — comportamiento esperado
- [`LICENSE`](LICENSE) — MIT para el código
- [`LICENSE-DOCS.md`](LICENSE-DOCS.md) — CC BY-NC-ND 4.0 para la metodología
- [`05-plantillas-de-trabajo/QUE-SUBIR-Y-QUE-NO.md`](05-plantillas-de-trabajo/QUE-SUBIR-Y-QUE-NO.md) — qué se comparte con un tercero y qué no
- [`00-metodologia/reglas-de-autorizacion-y-roe.md`](00-metodologia/reglas-de-autorizacion-y-roe.md) — la doctrina de autorización
