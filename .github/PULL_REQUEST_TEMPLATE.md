<!--
  Plantilla de pull request de Web Audit Playbook.
  Borrar las secciones que no apliquen, pero NO borrar la sección 4
  (redacción) ni la 5 (ausencia de datos de clientes): son la condición
  para que un PR pueda mergearse.
-->

## 1. Qué cambia

<!-- Una o dos frases. Si el PR es grande, resume el objetivo en una frase. -->

-

## 2. Por qué

<!-- El problema concreto que resuelve. Si es un método nuevo: qué paso del
     ciclo de auditoría lo necesitaba y qué se hacía mal antes. -->

-

## 3. Cómo se comprueba

<!-- El comando exacto y la salida esperada. -->

```bash
python3 01-tooling/scripts/tests/selftest.py
python3 01-tooling/scripts/tests/check_links.py
```

<!-- Si el PR cambia un script, añade el check correspondiente a
     `01-tooling/scripts/tests/selftest.py` y dilo aquí. -->

-

## 4. Redacción y datos personales

<!-- IMPORTANTE: marca la casilla que corresponda. -->

- [ ] **No he incluido datos de clientes, de pacientes ni de terceros.**
- [ ] **No he incluido evidencia de auditoría real** (nada de `03-casos/`, ni
      `evidencia/`, ni volcados, ni capturas de sitios reales).
- [ ] **No he incluido secretos reales.** Si hay un valor de ejemplo, es
      sintético y está declarado en la allowlist de `.gitleaks.toml`.
- [ ] **El material que he añadido pasa por `pii_redact.py`** (si contiene PII
      en cualquier forma, por mínima que sea).
- [ ] Los nombres de fichero siguen la convención **por contenido**
      (`tls_versions.txt`, no `openssl.txt`).

## 5. Alcance y autorización

- [ ] Este PR **no** añade ninguna técnica de prueba, explotación o bypass de
      RoE.
- [ ] Este PR **no** permite que ninguna herramienta salga a la red sin pasar
      por `scope_guard.py`.
- [ ] Este PR **no** relaja ninguna de las prohibiciones duras de
      `00-metodologia/reglas-de-autorizacion-y-roe.md`.

## 6. Checklist

- [ ] `python3 -m py_compile` no falla en ningún script.
- [ ] `python3 01-tooling/scripts/tests/selftest.py` pasa (14/14 checks).
- [ ] `python3 01-tooling/scripts/tests/check_links.py` no reporta enlaces rotos.
- [ ] La CI está en verde.
- [ ] Si el PR toca `00-metodologia/`, `02-plantillas/` o `04-formacion/`,
      he tenido en cuenta la licencia **CC BY-NC-ND 4.0** (ver
      [`LICENSE-DOCS.md`](https://github.com/franciscomorenosys/web-audit-playbook/blob/main/LICENSE-DOCS.md)).

## 7. Issues relacionados

<!-- Cierra los que resuelve: Fixes #12 -->

Closes #
