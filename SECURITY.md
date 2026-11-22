# Política de seguridad y reporte responsable

> **Este repositorio es público. Lee esta página antes de reportar cualquier cosa.**

---

## 1. Declaración de la empresa

<div align="center">

### **No auditamos, pentesteamos ni exploramos sistemas de información sin autorización escrita del propietario. RoE y addendum firmados antes de cualquier prueba.**

</div>

Ésta no es una fórmula retórica: es una condición de trabajo sin excepciones y
sin excepciones «por urgencia». Aplica a:

- auditorías web y de infraestructura,
- pentests y pruebas de explotación,
- reconocimiento y enumeración,
- escaneo de puertos, subdominios y certificados,
- pruebas de application's security sobre sistemas de terceros,
- **y cualquier otra interacción con un sistema de información que no sea tuyo**.

### 1.1 Qué exigimos antes de tocar nada

| # | Requisito | Dónde se documenta |
|:-:|---|---|
| 1 | **Autorización escrita del propietario** del sistema (no de un contacto, no de un employee, no «el cliente dijo que sí por teléfono») | `05-plantillas-de-trabajo/alcance-y-roe.EJEMPLO.md` |
| 2 | **RoE (Rules of Engagement) firmados**: hosts dentro y fuera de alcance, modalidad (pasiva/activa), ventana horaria, métodos permitidos, prohibiciones explícitas, contactos de emergencia | `00-metodologia/reglas-de-autorizacion-y-roe.md` |
| 3 | **Addendum de Fase 2 firmado por las tres partes** (cliente, responsable técnico y auditor) para cualquier prueba de explotación | `05-plantillas-de-trabajo/addendum-fase-2-explotacion-limitada.EJEMPLO.md` |
| 4 | **Verificación técnica del alcance** por parte de la herramienta: `scope_guard.py` aborta la operación si el host no está en el allowlist o si la ventana no está abierta | `01-tooling/scripts/scope_guard.py` |

**Sin los cuatro, no hay trabajo.** Un encargo que empieza por la prueba y
después busca el papel se cancela.

### 1.2 Las 5 prohibiciones duras

Están en `00-metodologia/reglas-de-autorizacion-y-roe.md` y no se levantan en
ninguna fase, ni siquiera con el addendum de explotación firmado:

1. **Nunca POST** ni método de escritura sobre el objetivo.
2. **No tocar datos de terceros** que aparezcan en el alcance (ni de registro,
   ni de lectura, ni de borrado).
3. **No des-anonimizar** a una persona: no se crackean hashes, no se resuelven
   identidades ni se correlacionan datos personales para identificar a un
   individuo.
4. **No sondear terceros**: un subdominio, una IP o un certificado que resulte
   ser de otra persona se **reporta como relación/riesgo**, no se investiga.
5. **No escanear IPs compartidas** (hosting compartido): se mide el ruido del
   neighbours, no el riesgo del cliente.

### 1.3 Qué pasa con los datos personales

- **Minimización:** los datos personales que se descubren se reportan por
  **categoría**, nunca por valor. «Se observó un campo de grupo sanguíneo en la
  respuesta de la API», no el valor.
- **Redacción obligatoria:** todo fichero que sale del escritorio del auditor
  pasa por `01-tooling/scripts/pii_redact.py` antes de compartirse. **El crudo
  no se sobrescribe ni se envía**: se entrega la copia sanitizada.
- **No se verifica ninguna credencial** contra su proveedor (eso ya sería
  des-anonimización). Se documenta la capacidad, no se ejecuta.

---

## 2. Cómo reportar una vulnerabilidad

### 2.1 Qué buscamos (y qué no)

**Sí** — cualquier fallo de este repositorio:

| Tipo | Ejemplo |
|---|---|
| **Vulnerabilidad** | Un script del toolkit permite salir del allowlist o salta la ventana de authorization; `pii_redact.py` deja pasar un dato personal; `secrets_scan.py` imprime el valor completo de un secreto. |
| **Fuga de datos** | Un fichero del repo contiene un secreto real, un dato de paciente o evidencia de un cliente real. |
| **Fallo de seguridad** | El `scope_guard.py` acepta una autorización inválida, expirada o sin firma. |
| **Configuración insegura** | Un workflow de CI publica artefactos con secretos, o el `.gitignore` deja pasar algo que debería excluirse. |

**No** — y no se investigan:

- Vulnerabilidades de **terceros** (aquí se reporta al proveedor, no a nosotros).
- Peticiones de **auditoría, pentest o consultoría** — **un issue no es un
  encargo**. Para eso hay un proceso comercial, con RoE y presupuesto.
- Técnicas de explotación, bypassing de RoE o formas de «auditar sin
  autorización». **No se Responden.**
- Findings sobre sistemas de terceros.

### 2.2 Severidades

| Severidad | Definición | Plazo de respuesta | Plazo de corrección |
|---|---|---|---|
| **Crítica** | El toolkit puede **salir del alcance autorizado**, filtrar un secreto completo, exponer PII de un paciente o aceptar una autorización sin firma/vencida. Impacto directo en la postura de seguridad del cliente. | 48 h | 7 días |
| **Alta** | Bypass de una regla de RoE sin salir del alcance (p. ej. se salta el intervalo mínimo o la validación de Content-Length), o redacción incompleta de PII en un caso concreto. | 7 días | 30 días |
| **Media** | Funcionalidad que degrada la calidad del resultado (p. ej. una cabecera del checklist no se evalúa, un informe no cuenta un tipo de severidad). No hay riesgo de exposición. | 30 días | 60 días |
| **Baja** | Cosmético, typos, documentación poco clara, mejora de ergonomía. | 90 días | Backlog abierto |

### 2.3 Qué incluir en el reporte

1. **Qué** falla y **dónde** (fichero, línea, comando).
2. **Cómo reproducirlo** — pasos mínimos y el comando exacto.
3. **Impacto**: qué dato o control se ve afectado.
4. **Entorno**: versión de Python, sistema operativo, commit (`git rev-parse HEAD`).

**No incluyas en el reporte:**

- Datos reales de pacientes, de clientes o credenciales de terceros.
- Pruebas ejecutadas contra sistemas que no son tuyos.
- Evidencia de un caso real (`03-casos/`) — **no la adjuntes**.

Si tu reporte contiene datos sensibles, **redacta primero** con
`python3 01-tooling/scripts/pii_redact.py <fichero> --out-dir ./redactado` y
adjunta la copia sanitizada.

### 2.4 Dónde reportar

| Canal | Para qué |
|---|---|
| **Issue público** | Bugs de bajo impacto, mejoras, typos, propuestas. Todo lo que no exponga datos. |
| **GitHub Security Advisory** (`Security` → `Report a vulnerability`) | Vulnerabilidades con impacto real, sobre todo si la exploitation es trivial. |
| **Correo directo al autor** | Sólo para vulnerabilidades **críticas** que no pueden esperar a un issue, o cuando el reporte lleva datos sensibles que no debe quedar en un tracker público. |
| **Issue «no auditamos sin autorización»** | Intento de usar este repo para auditar sin RoE. Se responde con la política, sin discusión. |

> **Tiempo de respuesta:** confirmación de recepción en 48 h (laborables). Si en
> 72 h no hay respuesta, reabre el issue citando el número.

### 2.5 Divulgación responsable

- Se confirma la recepción y la severidad provisional **antes** de la
  corrección.
- Se da un plazo de corrección razonable (ver la tabla) **antes** de publicar.
- La divulgación pública se hace **con el autor**, no sin él.
- Se reconoce la contribución en el changelog, salvo que el contributor pida lo
  contrario.

### 2.6 Lo que no vamos a hacer

- No vamos a entregar información sobre terceros.
- No vamos a ejecutar ni reproducir una exploits contra un sistema real.
- No vamos a discutir la validez legal de un RoE por issue: o hay RoE firmado
  y documento de alcance, o no hay trabajo.

---

## 3. Uso responsable del toolkit

Este repositorio incluye scripts que **salen a la red**. Úsalos sólo bajo un
RoE firmado:

```bash
# 1. Copia la plantilla y rellénala con el alcance firmado por el cliente.
cp 01-tooling/scripts/authorization.example.json authorization.json

# 2. Valida el alcance ANTES de cualquier petición (no toca la red).
python3 01-tooling/scripts/scope_guard.py -a authorization.json \
        --check https://objetivo-del-cliente.example.mx/

# 3. Sólo si el paso 2 responde ok, sondea (GET/HEAD, con intervalo mínimo).
python3 01-tooling/scripts/probe_exposure.py -a authorization.json \
        --host objetivo-del-cliente.example.mx --out ./evidencia
```

**Reglas no negociables del toolkit:**

- `scope_guard.py` es **la única puerta a la red**. Si el RoE no cuadra, el
  script aborta. No lo parchees para que pase.
- Ningún script hace POST ni métodos de escritura.
- El User-Agent identifica al auditor honestamente. **No lo falsifiques.**
- `probe_exposure.py` no descarga el cuerpo de las rutas sensibles.
- `js_intel.py` sólo lee JavaScript **público**. No des-anonimizar.
- `secrets_scan.py` **no verifica** ninguna credencial: sólo dice qué se ve.
- `pii_redact.py` es **obligatorio** antes de compartir cualquier evidencia.

---

## 4. Alcance de esta política

Aplica a este repositorio, a sus issues, a sus PRs y a los artefactos
publicados (código, metodología, plantillas). **No** sustituye a los RoE
firmados de cada encargo: aquéllos mandan sobre ésta en lo que se refiera a
un sistema concreto.

**Documentos relacionados:**

- [`00-metodologia/reglas-de-autorizacion-y-roe.md`](00-metodologia/reglas-de-autorizacion-y-roe.md) — la doctrina completa
- [`01-tooling/scripts/scope_guard.py`](01-tooling/scripts/scope_guard.py) — la puerta a la red
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — cómo contribuir sin filtrar datos
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — el comportamiento esperado
