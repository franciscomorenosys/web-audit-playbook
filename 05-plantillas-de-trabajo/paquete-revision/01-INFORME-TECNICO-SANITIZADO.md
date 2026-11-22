> **AVISO — COPIA SANITIZADA PARA REVISIÓN EXTERNA (tercero)**
> 1. Este archivo es una **copia redactada** del informe técnico original: los hallazgos, el análisis, el marco legal, el registro de riesgos y las hojas de ruta se conservan íntegros.
> 2. Los identificadores del cliente, de la agencia web, del hosting y de terceros se sustituyeron por **marcadores estables y consistentes** (`[CLIENTE]`, `[DOMINIO-CLIENTE]`, `[AGENCIA]`, `[HOSTING]`, `[TELEFONO-1..4]`, `[MARCA-COLATERAL-N]`, …); las marcas de software y los hechos públicos (versiones, CVE, CVSS, OWASP, WSTG, leyes, UMA) no se tocan.
> 3. La tabla de correspondencia **valor real → marcador** está únicamente en `MAPA-DE-REDACCION.md` y no se comparte con el revisor.
> 4. El **informe original y el mapa de redacción permanecen internos**: no distribuir ninguna de las dos copias fuera de esta revisión.
> 5. Objetivo de esta copia: permitir una crítica metodológica y de hallazgos sobre el contenido técnico sin exponer datos del cliente ni de negocios ajenos.

# [DOMINIO-CLIENTE] — Passive Security & Compliance Risk Report

**Target:** `[DOMINIO-CLIENTE]` (Mexican dental clinic, [DIRECCION-CLIENTE], CDMX)
**Prepared:** 2026-10-22
**Method:** Passive analysis of verified audit findings + primary-source research. **No live testing was performed against the target.**
**Currency of research:** All CVE/legislative status verified as of 2026-10-22 against primary sources (wordpress.org, github.com/WordPress, php.net, cve.circl.lu/NVD, diputados.gob.mx/LeyesBiblio, INEGI, DOF/SIDOF).

---

## 0. Executive summary — the three things that matter most

**1. WordPress 7.x is real, and five of the six cached versions are exposed to a Critical unauthenticated RCE.**
The brief asked me to verify this specifically. **WordPress 7.x does exist as of Oct 2026** — `7.1.3` is the current release (2026-10-06) and `7.2 Beta1` shipped 2026-10-20 ([wordpress.org/news](https://wordpress.org/news/)). So the `7.0.3`/`7.1.3` generator values are not a fork, not a plugin, and not cache corruption — they are genuine versions. Every one of the six observed values is a real WP release.

That matters because **CVE-2026-87902** (`GHSA-7hp8-65ch-5whp`, CVSS v4.0 **9.2 Critical**, `CWE-98`) affects `6.8.0–6.8.9`, `6.9.0–6.9.8`, `7.0.0–7.0.5`, `7.1.0–7.1.1` — unauthenticated, remote, no user interaction. **5 of the 6 versions served by [DOMINIO-CLIENTE] fall inside those ranges.** Only `7.1.3` is outside.

**2. There was a Critical unauthenticated PHP RCE published yesterday — 2026-10-21.**
`CVE-2026-109618` and `CVE-2026-109619` (both CVSS v4.0 **9.2**) allow unauthenticated remote code execution on *any* PHP application. WordPress published an advisory the same day ([Critical PHP Security Release](https://wordpress.org/news/2026/10/critical-php-security-release/)). The clinic's PHP version is **unknown from passive data** and [HOSTING]'s PHP is not observable from outside.

**3. The "up to MXN 37.5M" fine figure in the prior report is CORRECT — and I can now cite it exactly.**
It is not a statutory peso figure. It is **320,000 × UMA** under LFPDPPP art. 59 fr. III. With the 2026 UMA at **$117.31/day** (INEGI, DOF 09-01-2026, in force 1 Feb 2026): `320,000 × 117.31 = $37,539,200 MXN`.

---

## 1. OWASP Top 10 (2021) + WSTG mapping

### 1.1 Version and scope notes

- **OWASP Top 10:2021** — still the current published edition as of Oct 2026. (A 2025 edition has been long discussed but the published release remains the 2021 list; I am mapping to 2021 as instructed.)
- **OWASP WSTG** — the current *stable* release is **v4.2**. **v5.0 is in development** (bleeding edge on GitHub `main`), so v4.2 IDs are the correct citation targets. I verified every test ID below against the `OWASP/wstg` repo at tag `v4.2`.
- **WSTG v4.2 has exactly 12 test sections** (Information Gathering; Configuration & Deployment; Identity Mgmt; Authentication; Authorization; Session Mgmt; Input Validation; Error Handling; Weak Cryptography; Business Logic; Client-side; API). **There is no DNS, e-mail-authentication, or TLS-configuration section.** This is the structural reason the OWASP mapping below runs out — see §1.4.

### 1.2 Mapping table

| # | Finding (verified) | OWASP Top 10:2021 | WSTG v4.2 test ID(s) | Notes on fit |
|---|---|---|---|---|
| 1 | Six WordPress versions served simultaneously; 5 stale; patch cadence broken | **A06:2021 – Vulnerable and Outdated Components** | `WSTG-INFO-08` Fingerprint Web Application Framework; `WSTG-INFO-09` Fingerprint Web Application | Clean fit. A06's primary scope is exactly this. |
| 2 | Divi 4.27.4 (in range of 6 CVEs) / 4.27.7 (in range of 1) | **A06:2021** | `WSTG-INFO-08` | Clean fit. |
| 3 | PHP version unknown; Critical RCE `CVE-2026-109618/109619` live as of 2026-10-21 | **A06:2021** | `WSTG-CONF-01` Test Network Infrastructure Configuration | Clean fit on A06; WSTG has no PHP-CVE test per se. |
| 4 | No Subresource Integrity on CDN-loaded jQuery/GSAP/FontAwesome (cdnjs) | **A08:2021 – Software and Data Integrity Failures** | `WSTG-CONF-11` Test Cloud Storage; `WSTG-INPV-16` Testing for HTTP Incoming Requests | A08 explicitly names "missing SRI on third-party CDN assets" — this is the textbook case. |
| 5 | `WHATSAPP_NUMBER = '[TELEFONO-PLACEHOLDER]'` unreplaced; `// 🔥 REEMPLAZAR URL APPSCRIPT` shipped to production | **A04:2021 – Insecure Design** | `WSTG-BUSL-07` Test Defenses Against Application Misuse | A04 is the only honest home. It is a *defect that reached production*, i.e. a design/process failure, not a runtime vuln. WSTG has no "hardcoded placeholder" test; BUSL-07 is the nearest. |
| 6 | `/wp-json/wp/v2/users` → `id=1 slug=[USUARIO-1] name=[USUARIO-1]` + gravatar MD5 (`[GRAVATAR-HASH]`) | **A05:2021 – Security Misconfiguration** | `WSTG-IDNT-04` Testing for Account Enumeration and Guessable User Account | Clean fit. `WSTG-IDNT-04` is the precise test. |
| 7 | Author archive `/author/[USUARIO-1]/` live and in sitemap | **A05:2021** | `WSTG-IDNT-04`; `WSTG-ATHZ-04` Testing for Insecure Direct Object References | Clean fit. |
| 8 | `/wp-json/` exposed, 253 KB, namespaces leak `wp-site-health/v1`, `wp-abilities/v1`, `divi/v1`, `wp-block-editor/v1` | **A05:2021** | `WSTG-INFO-06` Identify Application Entry Points; `WSTG-APIT-01` Testing GraphQL (adjacent) | Clean fit. Note: `wp-site-health/v1` is an *attack-surface* disclosure — it maps the internal health of the install. |
| 9 | `/sample-page/`, `/hello-world/`, `/category/uncategorized/` live + in sitemap | **A05:2021** | `WSTG-CONF-05` Enumerate Infrastructure and Application Admin Interfaces | Clean fit. |
| 10 | 404s cached and replayed as HTTP 200 (soft-404) | **A05:2021** (partial) | `WSTG-CONF-01` Test Network Infrastructure Configuration | **Partial fit, and I am flagging it.** A05 is about the *server* being misconfigured, which it is. But the *consequences* (SEO loss, crawler deception) are not an OWASP category. OWASP does not model "search engines index your 404s." See §1.4. |
| 11 | Zero security response headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS) | **A05:2021** | `WSTG-CONF-07` Test HTTP Strict Transport Security; `WSTG-CLNT-09` Testing for Clickjacking; `WSTG-INPV-16` | Clean fit. Missing XFO → clickjacking → `WSTG-CLNT-09`. |
| 12 | No HTTP→HTTPS redirect; all 4 scheme×host combos serve byte-identical 200 | **A02:2021 – Cryptographic Failures** | `WSTG-CRYP-03` Testing for Sensitive Information Sent via Unencrypted Channels; `WSTG-CONF-07` | Clean fit on A02 — plaintext exposure of a form that collects health data. |
| 13 | TLS 1.0 and TLS 1.1 accepted | **A02:2021** | `WSTG-CRYP-01` Testing for Weak Transport Layer Security | Clean fit on A02. `WSTG-CRYP-01` is the exact test. |
| 14 | No OCSP stapling | **A02:2021** | `WSTG-CRYP-01` | Clean fit. |
| 15 | Shared multi-tenant Let's Encrypt cert, `CN=[CERT-CN-COLATERAL]`, SANs leak agency's portfolio incl. staging host | **A05:2021** (config) + **A02:2021** (shared-tenant trust) | `WSTG-CONF-01`; `WSTG-INFO-02` Fingerprint Web Server | Reasonable fit. The *confidentiality* consequence (portfolio disclosure) is an A02-adjacent trust-model problem. |
| 16 | Booking form posts name, email, phone, service, date, time **and health data ("motivo de consulta")** to a public Google Apps Script `/exec` deployment; no privacy notice; no consent | **A02:2021** (unencrypted-channel path + no TLS posture) and **A04:2021** (no data-minimisation / consent in the design) | `WSTG-ATHN-06` Testing for Browser Cache Weaknesses; `WSTG-CONF-11` Test Cloud Storage | **Genuinely spans two categories.** The transmission to a third-party processor with no notice is A02 (and is the LFPDPPP breach, §4). The absence of consent/minimisation by design is A04. I am not stretching: both apply for different reasons. |
| 17 | Patient data exfiltration via the Apps Script / spreadsheet layer | **A01:2021 – Broken Access Control** | `WSTG-CONF-11` Test Cloud Storage; `WSTG-ATHZ-04` Insecure Direct Object References | The Apps Script deployment is the access-control boundary; its failure to restrict is A01. |
| 18 | No DMARC; SPF `~all`; DKIM on `default` selector only | **A07:2021 – Identification and Authentication Failures** | *No WSTG ID exists* | **A07 is the correct OWASP home** ("identification and authentication failures" is the category the Top 10 uses for authn weaknesses generally). But note honestly: **OWASP Top 10:2021 is scoped to web applications and does not address DNS-level e-mail authentication.** See §1.4. |
| 19 | No BIMI / MTA-STS / TLS-RPT / CAA; no IPv6 | **A05:2021** (weak default posture) | *No WSTG ID exists* | Weakest mapping in the report. These are hardening/absence-of-control, not vulnerabilities. See §1.4. |
| 20 | `xmlrpc.php` → 405 on GET (partially mitigated); XML-RPC historically used for credential brute-force + DDoS amplification | **A07:2021** (credential attack surface); **A06:2021** (attack surface still shipped) | `WSTG-ATHN-04` Testing for Bypassing Authentication Schema; `WSTG-CONF-06` Test HTTP Methods | Reasonable fit. `405 on GET` is *good* — I am not overstating this. The residual risk is POST/Pingback. |
| 21 | Sitewide `href="#"` CTA on all 17 pages | *No OWASP category* | *No WSTG ID* | Availability/business defect, not a security weakness. Listed for completeness only. |
| 22 | `robots.txt` is bare WP default; advertises `Link: <https://[DOMINIO-CLIENTE]/wp-json/>; rel="https://api.w.org/"`; no AI-crawler rules | **A05:2021** | `WSTG-INFO-03` Review Webserver Metafiles for Information Leakage | Clean fit for the `/wp-json/` advertisement. The absence of AI-crawler rules is **not** a security control and should not be treated as one. |
| 23 | Zero E-E-A-T: no `Cédula`, no `Dr./Dra.`, no author, no credentials | *No OWASP category* | *No WSTG ID* | This is a **trust/compliance** defect (LGS art. 83), not a technical vulnerability. Mapping it to A07 would be a stretch and I decline to do so. See §4. |

### 1.3 Where the mapping is genuinely clean vs. genuinely forced

**Clean (no stretching required):** rows 1–4, 6–9, 11–14, 17, 20, 22.
**Defensible dual-mapping (stated reasons given):** rows 10, 15, 16.
**Honest stretches / declines:** rows 5, 18, 19, 21, 23.

### 1.4 Findings OWASP does not cover — where the adjacent frameworks apply

You asked me not to stretch, so here is the honest boundary. **OWASP Top 10:2021 and WSTG v4.2 are web-application-centric. Four of your findings are outside their scope entirely.**

| Finding | Why OWASP can't hold it | Correct home |
|---|---|---|
| **No DMARC / SPF `~all` / DKIM single-selector / no BIMI / no MTA-STS** | DMARC is a **DNS-based e-mail authentication policy**. OWASP Top 10:2021 has no DNS layer; WSTG v4.2 has no Communications/DNS section (verified: 12 sections, none DNS/email). This is not an OWASP omission so much as a scope boundary. | **NIST SP 800-52r2 Rev.1** (TLS); **NIST SP 800-177 Rev.1** (email security, recommends SPF/DKIM/DMARC + MTA-STS + TLS-RPT + DANE); **CIS Controls v8 – 14.1/14.2** (transmission & encryption of sensitive data); **NIST CSF 2.0 ID.AM / PR.PS** |
| **TLS 1.0/1.1 accepted; no OCSP stapling; no cert pinning strategy** | WSTG *has* `WSTG-CRYP-01`, but OWASP Top 10 A02 is a category, not a control set — it will not tell you which TLS versions to allow. | **NIST SP 800-52r2 Rev.1** (TLS 1.2 minimum, 1.3 preferred; §3.1); **CIS Controls v8 – 3.3/3.4**; **CISA Secure Web Server** guidance |
| **No HTTP→HTTPS redirect / no HSTS** | `WSTG-CONF-07` tests HSTS, but the *edge redirect* is an infrastructure/DNS/CDN-layer control that WSTG treats as out of app scope. | **NIST SP 800-52r2 §3.3** (mandatory HTTPS + HSTS); **OWASP Secure Headers Project** (a *sibling* OWASP project, not the Top 10); **Mozilla Observatory** scoring |
| **E-mail reputation / domain spoofing as a business risk** | Phishing-as-a-business-model is explicitly *not* in scope for OWASP Top 10:2021 (which addresses the application's own authn, not the surrounding ecosystem's). | **NIST SP 800-177 Rev.1**; **CIS Controls v8 – 14.x**; **MITRE ATT&CK T1566** (Phishing), **T1585.003** (Spearphishing Link) |

**One more framing note.** "Mozilla Observatory grade F / score 5 / 6 of 12 failed" is **not an OWASP Top 10 result**. It is the **Mozilla Observatory** project's scorecard (a *sibling* OWASP-adjacent project, historically an OWASP project). Its six failures — CSP, redirection, HSTS, SRI, XCTO, XFO — map cleanly onto rows 4, 11, 12 above, but the grade itself should not be cited as OWASP.

---

## 2. CVE research — the core section

### 2.1 Methodology caveat (read this first, it governs everything below)

1. **Version values are read from cached HTML, not from the running server.** A full-page cache is serving six different `meta generator` values. A cache is by definition a *historical record*. **Therefore: "the site runs 6.8.1" is not established.** What is established is *"the cache contains snapshots from six different points in the site's history, and at least some of those snapshots are from vulnerable eras."*
2. **Retire.js / version-scanner methodology:** component identification tools (Retire.js, WPScan, `whatweb`, etc.) match a version *string* against a CVE *range table*. They are **membership tests, not reachability tests**. A scanner reporting "CVE-2026-87902 present" is asserting *"the string 6.8.1 falls in the range 6.8.0–6.8.9"*. It is **not** asserting that the code path is reachable, that preconditions hold, or that exploitation has occurred. This report keeps that separation explicit in every row.
3. **The genuinely new information** is not "there are old versions in cache." It is: **one of those old versions sits inside the affected range of a Critical, unauthenticated, no-interaction RCE that was publicly disclosed on 2026-09-22**, and the same is true of five versions. That converts a housekeeping finding into an emergency one — because it establishes that **the patching that produced 7.1.3 did not propagate to the cache layer**.

### 2.2 WordPress core — current state

**Confirmed current release: WordPress 7.1.3**, published 2026-10-06 ([release notes](https://wordpress.org/news/2026/10/wordpress-7-1-3-maintenance-and-security-release/)), containing **7 security fixes**. `7.2 Beta1` released 2026-10-20.

Live branch heads from the official version-check API (`https://api.wordpress.org/core/version-check/1.7/`):

| Branch | Latest | Detected value | Detected value status |
|---|---|---|---|
| 7.1 | **7.1.3** | 7.1.3 | ✅ **current** |
| 7.0 | **7.0.7** | 7.0.3 | ⚠️ 4 patch releases behind |
| 6.9 | **6.9.10** | 6.9 | ⚠️ 10 behind |
| 6.8 | **6.8.11** | 6.8.1 / 6.8.2 / 6.8.3 | ⚠️ 8–10 behind |

WordPress's own note in the 7.1.3 post: *"only the most recent version of WordPress is actively supported"*, with courtesy backports going to all branches through 4.7.

### 2.3 WordPress core — CVE exposure of each detected version

All ranges below are taken verbatim from the WordPress `wordpress-develop` security advisories (`CVE` ranges as published by the WordPress security team). **Exploitability columns are my assessment, not vendor claims.**

#### CVE-2026-87902 — *the headline*

| Field | Value |
|---|---|
| **CVE / GHSA** | `CVE-2026-87902` / `GHSA-7hp8-65ch-5whp` |
| **Title** | Unauthenticated path traversal in page-template resolution leading to conditional RCE |
| **Severity** | **Critical** |
| **CVSS** | **9.2** — `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **CWE** | `CWE-98` Improper Control of Filename for Include/Require (PHP Remote File Inclusion) |
| **Published** | 2026-09-22 |
| **Attacker** | **Unauthenticated, remote, no user interaction** |
| **Affected** | `4.7.0–4.7.36`, `4.8.0–4.8.31`, `4.9.0–4.9.32`, `5.0.0–5.0.28`, `5.1.0–5.1.25`, `5.2.0–5.2.27`, `5.3.0–5.3.24`, `5.4.0–5.4.22`, `5.5.0–5.5.21`, `5.6.0–5.6.20`, `5.7.0–5.7.18`, `5.8.0–5.8.16`, `5.9.0–5.9.17`, `6.0.0–6.0.15`, `6.1.0–6.1.13`, `6.2.0–6.2.12`, `6.3.0–6.3.11`, `6.4.0–6.4.11`, `6.5.0–6.5.11`, `6.6.0–6.6.8`, `6.7.0–6.7.8`, **`6.8.0–6.8.9`**, **`6.9.0–6.9.8`**, **`7.0.0–7.0.5`**, **`7.1.0–7.1.1`** |
| **Patched** | 4.7.37, 4.8.32, 4.9.33, 5.0.29, 5.1.26, 5.2.28, 5.3.25, 5.4.23, 5.5.22, 5.6.21, 5.7.19, 5.8.17, 5.9.18, 6.0.16, 6.1.14, 6.2.13, 6.3.12, 6.4.12, 6.5.12, 6.6.9, 6.7.9, **6.8.10**, **6.9.9**, **7.0.6**, **7.1.2** |

**Detected-version in-range analysis:**

| Detected | In range? | Patched version |
|---|---|---|
| 6.8.1 | **✅ YES** | 6.8.10 |
| 6.8.2 | **✅ YES** | 6.8.10 |
| 6.8.3 | **✅ YES** | 6.8.10 |
| 6.9 | **✅ YES** | 6.9.9 |
| 7.0.3 | **✅ YES** | 7.0.6 |
| 7.1.3 | ❌ NO (already patched) | — |

**⚠️ Exploitability — assessed honestly, not overstated:**

The advisory states **two preconditions** must both hold:
1. *"The active child or parent theme contains a top-level directory whose name starts with `page-` (e.g. `page-templates`)."* The advisory names **Twenty Twelve, Twenty Fourteen, Neve, Hestia, Sydney** as affected. **Divi is not named.** I could not verify from passive data whether the Divi build in use has a top-level `page-*` directory. **This precondition is UNVERIFIED for this site.**
2. *"A chosen local `.php` target file exists on the server and is readable by the web server account. The well known `pearcmd.php` PEAR→RCE transition can be used for this when `register_argc_argv` is set to `On`. ... **the default cPanel configuration is affected when PHP prior to 8.5 is in use**."*

**The second precondition is the one that worries me most, because the environment is known to be cPanel-based ([HOSTING] Mexico shared) and the PHP version is unknown.** `pearcmd.php` presence and `register_argc_argv=On` are *default-ish* on older cPanel PHP. That is an inference, not a verified fact — it requires a check the clinic can run in 5 minutes.

**Bottom line:** I am **not** asserting this site is currently compromised or definitely exploitable. I am asserting: *five of six observed versions are inside a Critical unauthenticated RCE range, the environment matches the advisory's described "default cPanel + PHP < 8.5" condition, and the theme precondition is a 5-minute check nobody has done.* That is enough to make this the top remediation item.

#### Other 2026 WordPress core CVEs vs the detected versions

| CVE / GHSA | Sev | Affected (relevant branches) | 6.8.1 | 6.8.2 | 6.8.3 | 6.9 | 7.0.3 | 7.1.3 | Attacker |
|---|---|---|:-:|:-:|:-:|:-:|:-:|:-:|---|
| `CVE-2026-87902` | **Critical 9.2** | ≤6.8.9 / ≤6.9.8 / ≤7.0.5 / ≤7.1.1 | ✅ | ✅ | ✅ | ✅ | ✅ | — | **Unauth** (PR:N, UI:N) |
| `CVE-2026-63030` — *REST API batch-route confusion + SQLi → RCE* | **Critical** | 6.9.0–6.9.4, 7.0.0–7.0.1 | — | — | — | ✅ | ✅ | — | See note |
| `CVE-2026-64638` — *pre-auth reflected XSS on login screen, potential PHP code execution* | High | ≤6.8.6 / ≤6.9.5 / ≤7.0.2 | ✅ | ✅ | ✅ | ✅ | ✅ | — | **Pre-auth** |
| `CVE-2026-65640` — *RCE via malicious file upload* | High | ≤6.8.7 / ≤6.9.6 / ≤7.0.3 | ✅ | ✅ | ✅ | ✅ | ✅ | — | Author+ |
| `CVE-2026-60137` — *facilitated SQLi in `author__not_in` of `WP_Query`* | Medium | ≤6.8.5 / ≤6.9.4 / ≤7.0.1 | ✅ | ✅ | ✅ | ✅ | ✅ | — | Config-dependent |
| `GHSA-qg7r-fjh2-wvx8` — *stored XSS in `wpautop()`* (no CVE assigned) | High | ≤6.8.8 / ≤6.9.7 / ≤7.0.4 / 7.1.0 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **Unauthenticated visitor** can inject |
| `GHSA-xhp5-863h-rhfr` — *XML-RPC can publish `customize_changeset` posts bypassing `edit_css`* (no CVE) | Medium | ≤6.8.8 / ≤6.9.7 / ≤7.0.4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Auth (subscribing) |
| `GHSA-w57f-v787-qhpf` — *authenticated path traversal, WP REST Templates Controller* (no CVE) | Medium | ≤6.8.8 / ≤6.9.7 / ≤7.0.4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Auth (Contributor+) |
| `GHSA-5qf7-2r5p-ppj8` — *crafted URLs auto-install and preview an inactive theme from WordPress.org* (no CVE) | Medium | ≤6.8.8 / ≤6.9.7 / ≤7.0.4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | See note |
| `GHSA-33wf-p63q-w25f` — *Contributor+ arbitrary post overwrite* (no CVE) | Medium | ≤6.8.8 / ≤6.9.7 / ≤7.0.4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Contributor+ |
| `GHSA-cjfg-q57r-mq45` — *`attachment_submitbox_metadata()` leaks private parent-post title* (no CVE) | Medium | ≤6.8.8 / ≤6.9.7 / ≤7.0.4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Auth |
| `GHSA-f522-h982-63mg` — *draft/pending post slug disclosure by Contributor+* (no CVE) | Low | ≤6.8.8 / ≤6.9.7 / ≤7.0.4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Contributor+ |
| `GHSA-32m5-wc28-ghrr` — *comments reparentable by any authenticated user* (no CVE) | Medium | ≤6.8.8 / ≤6.9.7 / ≤7.0.4 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Any auth |

*Note on `CVE-2026-63030` and `GHSA-5qf7-2r5p-ppj8`:* the published advisory summary does not state the privilege level for the first and describes the second as reachable via "specially crafted URLs" that automatically install and preview an inactive theme. I am **not** able to verify the full precondition chain from the advisory summary alone, and I am marking these as **"requires verification against the full advisory"** rather than guessing. `CVE-2026-63030` is notable because it is a **REST API** RCE and this site has `/wp-json/` broadly exposed — but the range match (`6.9.0–6.9.4`, `7.0.0–7.0.1`) is what puts it in play, not the exposure.

**Summary count: `CVE-2026-87902` alone puts 5 of 6 observed versions in range. Five High/Critical advisories apply to all five stale versions.**

### 2.4 Divi (Elegant Themes) — CVE exposure

Researched against the Divi changelog (`https://www.elegantthemes.com/api/changelog/divi.txt`) and CVE records. **Divi 5.x exists** (5.12.0 released to fix `CVE-2026-91707`); the 4.x branch is still maintained (4.27.8 on 2026-08-19, **4.27.9 on 2026-09-18**).

| CVE | Sev (CVSS 3.1) | Affected | Fixed in | 4.27.4 | 4.27.7 | Attacker |
|---|---|---|---|:-:|:-:|---|
| `CVE-2026-4361` — **SSRF** via `image_src` (`wp_remote_get` vs `wp_safe_remote_get`; blind, with status + timing oracles) | Medium **5.0** | ≤ **4.27.6** | **4.27.7** | ✅ | — | **Contributor+** |
| `CVE-2026-3853` — DOM-based **stored XSS**, Video Slider `image_src` (`.data()` decodes `&quot;` → `jQuery.after()` re-injects unescaped) | Medium **6.4** | ≤ **4.27.6** | **4.27.7** | ✅ | — | **Contributor+** |
| `CVE-2026-3852` — **stored XSS**, Social Media Follow `skype_url` (3-part sanitization failure; `sanitize_text_field` preserves quotes → attribute breakout) | Medium **6.4** | ≤ **4.27.6** | **4.27.7** | ✅ | — | **Contributor+** |
| `CVE-2026-3851` — **stored XSS**, Dynamic Content legacy JSON format (save-time filter only scans `@ET-DC@…@`; `post_meta_key` resolver skips `wp_kses_post()` when `enable_html=on`) | Medium **6.4** | ≤ **4.27.6** | **4.27.7** | ✅ | — | **Contributor+** |
| `CVE-2026-3850` — **stored XSS**, Contact Form `redirect_url` (`esc_attr()` not `esc_url()`; client JS passes `data-redirect_url` to `window.location.href` → `javascript:` URI executes) | Medium **6.4** | ≤ **4.27.6** | **4.27.7** | ✅ | — | **Contributor+** |
| `CVE-2026-91707` — **Missing Authorization → unauthenticated arbitrary registered shortcode execution** via `content` param on the Shortcode Module REST endpoint; with **"Force Enable D4 Shortcode Framework"** enabled this reaches `et_pb_contact_form`, i.e. **send email to an attacker-chosen recipient with attacker-controlled content** | Medium **5.3** | ≤ **5.11.1** | **5.12.0** | ✅ | ✅ | **UNAUTHENTICATED** — but *config-gated* |
| `CVE-2024-5647` — stored DOM XSS via bundled **Magnific Popups 1.1.0** | Medium 6.4 | ≤ **4.27.1** | (upstream 1.2.0) | ❌ | ❌ | Contributor+ |
| `CVE-2024-5533` | Medium 6.4 | ≤ 4.25.1 | 4.25.2 | ❌ | ❌ | Contributor+ |
| `CVE-2024-4490` | Medium 6.4 | ≤ 4.25.0 | 4.25.1 | ❌ | ❌ | Contributor+ |
| `CVE-2023-6744` | Medium 6.4 | ≤ 4.23.1 | 4.23.2 | ❌ | ❌ | Contributor+ |
| `CVE-2023-29099` | Medium 6.5 | ≤ 4.20.2 | 4.20.3 | ❌ | ❌ | Contributor+ |

**Divi findings, stated precisely:**

- **Divi 4.27.4 — 6 CVEs in range.** It was released **2024-11-25** (changelog: a single fix, *"image with lazy loading enabled are distorted on WordPress 6.7"*). It is therefore ~23 months stale and sits in the affected range of five `4.27.7`-patched CVEs **plus** the unauthenticated `CVE-2026-91707`.
- **Divi 4.27.7 — 1 CVE in range.** `CVE-2026-91707` (≤5.11.1) covers the entire 4.x branch numerically. 4.27.7 is the release that patched the five `≤4.27.6` issues — confirmed by the changelog text for 2026-05-12, which lists all five security fixes and credits the same reporter (Osvaldo Noe Gonzalez Del Rio) as the five CVEs.
- **`CVE-2026-91707` is the interesting one, and the honest assessment matters here.** It is the *only* Divi issue in this set with `PR:N` (CVSS vector `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`). In a static, cached, mostly-anonymous context, that is exactly the class that matters. **But** the advisory conditions the most damaging variant on the **"Force Enable D4 Shortcode Framework"** option being enabled — a *non-default* configuration. **I cannot verify from passive data whether that option is on.** This must be checked in the Divi Dashboard. If it is on, this becomes a live unauthenticated mail-relay primitive that could be used for convincing phishing (§3).
- **The 5 `4.27.x` issues all require `Contributor+`.** In a clinic site with one author account and no public registration, that is a low-probability path **on its own** — *unless* CVE-2026-87902 (unauthenticated RCE) is exploited first, or `CVE-2026-65640` (file-upload RCE, Author+) is. **The Divi bugs are a post-compromise amplifier, not an entry point.** Saying otherwise would be inflating them.

### 2.5 Front-end libraries — Retire.js verdicts

| Component | Detected | CVEs | In range? | Honest exploitability verdict |
|---|---|---|---|---|
| **jQuery** | 3.7.1 (+ migrate) | `CVE-2020-11022` (CVSS 3.1 **6.9**, XSS in `htmlPrefilter`, affects `>=1.12.0, <3.5.0`); `CVE-2020-11023` (CVSS 3.1 **6.9**, XSS in `htmlPrefilter`/`self-closed` tags, affects `>=1.0.3, <3.5.0`) | **❌ NO.** 3.7.1 > 3.5.0. | **Not vulnerable to any known jQuery CVE.** Both jQuery-core CVEs were fixed in **3.5.0 (2020)**. Any scanner flagging jQuery 3.7.1 for CVE-2020-11022/11023 is producing a **false positive from a stale range table.** This is a good, concrete example of why §2.1's membership-vs-reachability point matters. |
| **GSAP** | 3.7.1 | **None.** Querying the CVE corpus for vendor `greensock` / product `gsap` returns **0 records.** | **N/A** | No known vulnerabilities. Animation library; no user-input parsing surface. |
| **ScrollToPlugin** | **UNKNOWN** — version not disclosed in the audited HTML | Could not verify — no version to test | **⚠️ Unknown** | Used by Divi for scroll animations. Version cannot be determined passively. Low-risk class (animation plugin, no user-input sink) but **cannot be cleared without the version string.** Flag as an open item. |
| **Font Awesome** | 5.15.4 (most pages), 6.5.1 (one page) | **None.** No CVEs assigned to Font Awesome. | **N/A** | **Not EOL.** Correction to a common assumption: with the release of FA6, **FA5 was designated Long Term Support (critical bug fixes only)**; FA3 and FA4 went end-of-life. 5.15.4 is the terminal v5 release. **FA 7.x now exists** (7.3.1, July 2026). So: 5.15.4 is *supported-but-minimal*, not *unsupported*. It is a **version-hygiene** finding (two versions served = two copies of the icon font, ~100 KB+ wasted), **not a vulnerability.** |
| **fitVids** | unknown (Divi-bundled) | None known | **N/A** | Responsive video helper. No known CVEs. |

### 2.6 PHP runtime — the finding that is *not* on your list but matters most

**On 2026-10-21 (yesterday), the PHP project released an emergency advisory** ([php.net/archive/2026.php](https://www.php.net/archive/2026.php)):

| CVE | Advisory | CVSS | Mechanism |
|---|---|---|---|
| **`CVE-2026-109618`** | `GHSA-w8hw-w9fx-j79w` | **9.2** (v4.0) | **RCE via OOM corruption.** Out-of-memory handling can interrupt PHP while internal request data is only *partially* initialized; request cleanup then treats invalid data as valid. |
| **`CVE-2026-109619`** | `GHSA-6wmf-4rv5-p3rp` | **9.2** (v4.0) | **RCE via stale global state.** Request-owned internal state can survive after its backing memory is freed; a later request handled by the same worker may use that stale state before normal initialization resets it. |

- **Affected:** all PHP serving web requests — PHP-FPM, Apache `mod_php`, php-cgi, FrankenPHP, LiteSpeed.
- **Risk highest for `mod_php`**, *"with a demonstrated exploit where an unauthenticated request can trigger the attack before any application code runs."*
- **Fixed in:** PHP **8.5.12, 8.4.27, 8.3.36, 8.2.35**.
- **PHP < 8.2 no longer receives security updates.** PHP 8.2 reaches EOL **31 December 2026** and will receive no further fixes after that date.
- **Not WordPress-specific.** WordPress published its own advisory the same day ([Critical PHP Security Release](https://wordpress.org/news/2026/10/critical-php-security-release/)), and the **UK NCSC** is quoted: *"Where immediate remediation is not feasible, organisations should consider taking the system offline until it can be fully mitigated."*
- **Applicability to [DOMINIO-CLIENTE]: UNVERIFIED.** Passive analysis cannot see the PHP version. **This is the single highest-value 60-second check available** (`Tools → Site Health → Info → Server`), and it must go to [HOSTING], not the clinic.

### 2.7 WordPress core issue-class analysis

**(a) The six-versions anomaly is a cache-layer patch-management failure, not a WordPress problem.**
WordPress's own update mechanism worked — something reached 7.1.3. The failure is that **the full-page cache (`x-[HOSTING]-cache-level: 2`, `x-nginx-cache: WordPress`, `x-proxy-cache`) never purged**, so origin upgrades did not propagate to served responses. **This is why "just update WordPress" is insufficient remediation:** the same cache will serve the vulnerable snapshots again after the update. **Purging the cache is a mandatory, inseparable part of the patch.**

**(b) `xmlrpc.php` amplification.** Your finding (`405 on GET`) is *better than most sites'*. I am not going to inflate it. Residual issues:
- `405` on GET does **not** mean POST is blocked. `xmlrpc.php` accepts POST on the same URL, and `system.multicall` remains the classic **amplification** primitive (one request → hundreds of `wp.getUsersBlogs` credential attempts). WordPress has shipped authentication-hardening defaults since 5.5 (via `wp_authenticate_application_password_errors`), but **blocking remains a hosting/WAF-layer control.**
- Directly relevant 2026 advisory: **`GHSA-xhp5-863h-rhfr`** — *"XML-RPC can be used to publish `customize_changeset` posts that bypass checks for `edit_css`"* — affects `≤6.8.8 / ≤6.9.7 / ≤7.0.4`. **All five stale cached versions are in range.**

**(c) REST API user enumeration.** `/wp-json/wp/v2/users` returning `id=1, slug=[USUARIO-1], name=[USUARIO-1]` plus a Gravatar MD5 (`[GRAVATAR-HASH]`) is the **canonical WordPress username-disclosure chain**: `?author=1` → slug → `wp-json/wp/v2/users` → Gravatar hash → offline hash lookup. Related 2026 advisories in the same exposure surface: `GHSA-f522-h982-63mg` (draft/pending post slug disclosure), `GHSA-cjfg-q57r-mq45` (private parent-post title leak), `GHSA-w57f-v787-qhpf` (REST Templates Controller path traversal), and `CVE-2026-63030` (**Critical — REST API batch-route confusion + SQLi → RCE**, affecting 6.9.0–6.9.4 / 7.0.0–7.0.1, both of which are in your observed set). The finding is a **configuration** defect, not a WordPress vulnerability — WordPress never intended `/wp/v2/users` to be public by default; something enabled it or it was never restricted.

**(d) Cache-poisoning / "caching 404s" advisory class — honest answer: I could not verify a published [HOSTING]/[HOSTING] advisory specific to caching 404 responses.**
What I can state precisely:
- The behaviour you proved (`/soft404-proof-…/` → 404, then **200, 200, 200**) is a **misconfiguration of the caching layer's status-code allow-list**, not a WordPress bug and not a known-CVE.
- I searched for a published vendor advisory covering this exact [HOSTING]/[HOSTING] behaviour and **did not find one.** I am flagging this as **"no documented advisory located — raise as a support ticket with reproduction steps"** rather than citing something I cannot confirm.
- The **class of defect** is well-established regardless of vendor: caching non-2xx responses causes (i) *soft-404s* that search engines index as real pages, (ii) **error pages becoming cache-poisonable delivery vectors** if any request-controlled data is reflected, and (iii) masks genuine origin failures behind a stale 200. Control: exclude all non-200/2xx from cache; enforce at both `nginx` and `Apache` layers.

---

## 3. Phishing / social-engineering threat model

> **Scope note:** this section is a threat model built **only** from publicly observable data. It contains **no** operational attack instructions, no credential-testing guidance, and no steps for anyone to act against the clinic. It is written to let the clinic *defend*.

### 3.1 The reconnaissance package — assembled entirely from public data

An attacker needs zero privileged access to build this. Every field below is currently public.

| # | Asset | Public source | Why it matters |
|---|---|---|---|
| 1 | **Staff username `[USUARIO-1]`** (`id=1`, author slug) | `/wp-json/wp/v2/users` + `/author/[USUARIO-1]/` + sitemap | Converts a "guess a username" problem into a *known-value* problem. Removes entropy from every downstream password attack. |
| 2 | **Gravatar MD5 hash** (`[GRAVATAR-HASH]`) for that username | Same response | A deterministic offline identifier. **I am not recommending anyone act on this hash** (see §3.4). |
| 3 | **Three distinct public phone numbers**, one in **area code 56 (Estado de México)** while the clinic is in **[DIRECCION-CLIENTE], CDMX (area code 55)** | 4 `WhatsApp` endpoints + homepage display + button `tel:` targets. Homepage *displays* `[TELEFONO-1]` but its buttons **dial `[TELEFONO-2]`** | See §3.3. The strongest single social-engineering enabler on the site. |
| 4 | **Clinic name, address ([DIRECCION-CLIENTE], CDMX), service list** | Public pages | Establishes legitimate context for a pretext. |
| 5 | **The Google Apps Script `/exec` deployment URL** (`[URL-APPSCRIPT]`, deployment ID `[ID-DEPLOYMENT]`) | Public booking JS | Ties the clinic to a **third-party Google account** whose compromise is outside clinic control (§3.5). |
| 6 | **WordPress + Divi version fingerprinting** | `<meta generator>` across cached pages | Lets the attacker **pre-select** only CVEs that apply — e.g. skip all WP core issues and go straight for `CVE-2026-87902`. This is the direct business consequence of the cache defect in §2.7(a). |
| 7 | **The web agency's identity** (footer) | Public footer | The likely **spear-phishing target** — a small agency is a far higher-yield target than the clinic, and holds credentials for the *whole portfolio*. |
| 8 | **The agency's OTHER clients, from the TLS certificate SANs** | Certificate transparency / live cert `CN=[CERT-CN-COLATERAL]`, SANs incl. `[SEDE-STAGING]` | **This is the most serious single recon finding.** A shared multi-tenant certificate **hands an attacker a pre-built target list** — every brand the agency serves. Includes a **staging host**, which by definition runs unreviewed code. |
| 9 | **Hosting provider: [HOSTING] Mexico, shared hosting, IP `[IP-SERVIDOR]`, NS `[HOSTING-MX] (two provider nameservers)`** | DNS + HTTP headers | Reveals the **whole-stack patch cadence** and a **shared-tenancy** model with no isolation guarantees. |
| 10 | **[HOSTING-MX] MX; SPF `~all`; DKIM only on selector `default`; no DMARC** | DNS | The email-attack surface (§3.2). |

**Inference:** items 6 + 7 + 8 + 9 compose into a single attack path. An attacker who fingerprints the WP version from the cache, sees the agency's portfolio from the certificate, and observes the host's patch lag can **predict the target's technical condition before sending a single packet to the origin.**

### 3.2 The DMARC gap — precise mechanics

**Current DNS state (as verified):**
- `SPF`: `v=spf1 include:spf.[HOSTING-MX] ~all` — present, **terminated `~all` (softfail)**
- `DKIM`: present on selector `default` **only**
- **`DMARC`: ABSENT**
- `BIMI`, `MTA-STS`, `TLS-RPT`, `CAA`: **absent**
- `MX`: [HOSTING-MX]

**What each layer does and does not do:**

**SPF** authorizes *enveloping senders* (the `MAIL FROM` / RFC 5321 return-path). It says: "only `spf.[HOSTING-MX]` may send mail claiming to be from `@[DOMINIO-CLIENTE]`."
- ✅ **SPF stops:** an attacker sending from *infrastructure they control* (a random SMTP server, a throwaway VPS).
- ❌ **SPF does NOT stop:** anything that can emit from `spf.[HOSTING-MX]`. More importantly, SPF **does not cover the visible `From:` header at all.** It validates a different field from the one the victim reads.
- ⚠️ **`~all` weakens even SPF's own signal.** A `~all` verdict is a *softfail* — receivers are told "this looks wrong" but are explicitly *not* told to reject. Hard-fail (`-all`) is the correct posture once all legitimate senders are enumerated.

**DKIM** cryptographically signs the **message body and headers** with a private key, and the signature can only be produced by the holder of that key. It is the strongest of the three for content integrity, and it *does* bind to the visible `From:` domain via the `d=` tag.
- ✅ **DKIM stops:** body tampering in transit; spoofing **provided the attacker lacks the private key**.
- ❌ **DKIM does NOT stop:** (a) any case where the attacker **obtains or reuses a key** — this is why **selector coverage matters**, and this domain has DKIM on **one selector only**; (b) **DKIM alignment failure** — a signature that validates but is *aligned to the wrong domain* will pass DKIM while still spoofing the visible sender.

**DMARC** is the layer that closes both gaps, and this is the crux:

> DMARC tells the receiving mail server: *"when a message claims to be from `@[DOMINIO-CLIENTE]`, check that SPF **and/or** DKIM both pass **and** that the passing identifier is **aligned** with `[DOMINIO-CLIENTE]`. If not, apply this policy."*

**Why the absence of DMARC means SPF and DKIM failures are not acted upon — this is the key point:**

Receivers evaluate SPF and DKIM **pass/fail on their own merits.** But that verdict alone is ambiguous in exactly the way that matters:

- A message can **pass SPF and still be forged.** If the attacker can make mail originate from anything `spf.[HOSTING-MX]` authorizes (a third-party ESP with a loose SPF scope, a compromised marketing tool, an open relay in the include chain), SPF says "pass" and the message is accepted — **even though the visible `From:` is a total fabrication.**
- A message can **pass DKIM and still be forged** if the attacker holds a key from *any* selector for that domain, or if the signing identifier does not align with the visible From domain.

**DMARC is what converts "SPF/DKIM passed" into "SPF/DKIM passed *and the identity matches the domain the user sees*."** Without a DMARC record, **no receiver is instructed to perform that alignment check**, and — critically — **receivers are under no obligation to quarantine, reject, or even report on unauthenticated mail from this domain.** An SPF failure produces no action. A DKIM failure produces no action. The soft `~all` produces no action. **The full DMARC verification chain never runs.**

**Concrete attack that results — appointment-confirmation phishing:**

> An attacker configures a sending domain they control, sets the visible `From:` and `Reply-To:` to an `@[DOMINIO-CLIENTE]` address (e.g. `citas@[DOMINIO-CLIENTE]`), and sends: *"[CLIENTE] — Su cita está confirmada. Martes 28 oct, 11:00. Confirme o cancele aquí: [link]."*
>
> SPF for the attacker's domain passes (it's their mail). DKIM passes (they signed their own content). **But the visible From: says `[DOMINIO-CLIENTE]`.** The receiving server sees no DMARC record for `[DOMINIO-CLIENTE]`, so it has **no instruction to notice** that the authenticated domain and the displayed domain are different. Gmail/Outlook will therefore apply **only their generic spoof heuristics** — not domain-specific DMARC policy — and the message lands.
>
> The defence-in-depth the clinic lacks: **the attacker's SPF/DKIM would both *fail* for `[DOMINIO-CLIENTE]`, and a DMARC policy would force receivers to quarantine.** With no DMARC, both failures are simply *ignored*.

**Severity amplifier specific to this clinic:** the appointment-confirmation pretext is unusually strong here because (a) the clinic's real booking flow **already sends appointment-related messages**, (b) `/agendar-cita/` is live with a stale calendar showing **"Febrero 2024"** — a patient who books and then sees *no* confirmation email is *primed* to click one, and (c) `CVE-2026-91707`, if `Force Enable D4 Shortcode Framework` is enabled (§2.4), would let an attacker send mail **from the clinic's own domain** — which would be far more damaging than any spoof, because it would pass DMARC.

**Remedy (2 hours, no cost):**
1. Publish DMARC at `_dmarc.[DOMINIO-CLIENTE]` starting **`v=DMARC1; p=none; rua=mailto:…; pct=100`** — `p=none` is *monitor-only* and breaks nothing.
2. Monitor rua reports for 2–4 weeks to find every legitimate sender.
3. Upgrade to **`p=quarantine`**, then **`p=reject`**. Tighten SPF to **`-all`** at the same time.
4. Add DKIM signing on **all** sending services, not one selector.
5. Add **`CAA`** restricting certificate issuance to your CA(s) — directly mitigates the staging-host / rogue-cert angle in §3.1 item 8.

### 3.3 Vishing — why three inconsistent phone numbers are a vishing enabler

The site publishes **three distinct numbers**, and the homepage *displays one number while its buttons dial a different one*. One number is **area code 56 (Estado de México)** for a clinic in **[DIRECCION-CLIENTE], CDMX (55)**.

**How this directly enables vishing:**

1. **It manufactures social proof.** An attacker who calls a victim and states the clinic's **real, publicly-listed** number establishes credibility that no amount of persuasion could. *"I can give you the number on their website — I'll read it to you."* The inconsistency is irrelevant to the victim and helpful to the attacker: it signals a small operation where staff **do not have consistent information**, so "just trust me, I'm the clinic" is more likely to land.

2. **It defeats the standard defence.** The one control a victim can actually execute is *"hang up and call the clinic independently."* Inconsistent NAP (Name/Address/Phone) data is a **documented social-engineering red flag** in vishing training curricula precisely because it undermines this defence — the victim who looks up "the number" may reach a **different line**, may reach a **call centre**, or may conclude the site is simply unreliable and trust the caller more. **The clinic has accidentally disarmed its patients' only self-help defence.**

3. **The area-code mismatch creates a plausible cover story.** An attacker operating from, or spoofing, a **Estado de México** number can claim to be a *satellite office*, a *specialist*, or a *lab* — a story the victim has been subtly primed to accept because the site itself already lists a 56 number.

4. **The homepage's own inconsistency (`[TELEFONO-1]` displayed vs `[TELEFONO-2]` dialled) is the worst case**, because a victim checking *during* the call will hear a *fourth* number.

**Remedy (2 hours, clinic-only):** pick one canonical number; correct the homepage display *and* every `tel:`/`WhatsApp` target; retire the 56 number or label it explicitly with a function and address; publish the canonical NAP in a consistent block; submit/verify Google Business Profile, Apple Maps, and Mexican business directories so NAP data is uniform. **Zero tracking exists on this site, so there is no analytics cost to changing numbers.**

### 3.4 The Gravatar / enumeration chain — risk, and an explicit refusal

**Reported as a risk. What an attacker can do with it:** `id=1` → `slug=[USUARIO-1]` → `/wp-json/wp/v2/users` confirms the slug → the Gravatar MD5 is a **deterministic, offline-crackable** function of the identifier (typically an email address). Because the slug `[USUARIO-1]` follows an obvious `[USUARIO-1]` + role/name pattern, a small candidate list of email addresses can be tested against the hash **offline, at scale, with no rate limiting and no server contact.** The result is a **high-confidence username list**, which is the direct input to credential stuffing and to targeted phishing.

> ### 🚫 Explicit non-recommendation
> **I am not recommending, and this report must not be read as recommending, that anyone execute password-recovery against this account, attempt to crack the Gravatar hash, or otherwise use this chain against the clinic.** No such action is necessary, appropriate, or authorized. **The correct posture is defensive only:**
>
> **Remove the exposure. Do not rely on the hash staying uncracked.**
> 1. **Change the password** on the account **now**, to a unique value not used anywhere else. (Already Wave 1 in §6.)
> 2. **Disable author archives** — `Settings → Reading → Discussion`/per-post author slugs, or the `author` query-vary filter.
> 3. **Disable the REST users route** — `rest_endpoints` filter to unset `GET /wp/v2/users`, or block `/wp-json/wp/v2/users*` at the edge.
> 4. **Rename the admin username** if practical (WordPress cannot rename a user, but a fresh account with a non-guessable slug can be created and ownership reassigned).
> 5. **Enable MFA** on all WP accounts.
> 6. Treat the hash as **already public**. Any password that is weak, reused, or dated has to be considered disclosed. There is no "it hasn't been cracked yet" state to rely on.
> 7. Monitor `wp-login.php` for failed attempts against `[USUARIO-1]`.

### 3.5 The Apps Script endpoint — a third-party asset outside clinic control

The public Google Apps Script `/exec` deployment is **`[URL-APPSCRIPT]`** (deployment ID `[ID-DEPLOYMENT]`):
- **A Google property tied to *some* Google account** — plausibly the web agency's, not the clinic's.
- A **persistent, publicly known ingestion point** for patient identity + appointment data + **health data ("motivo de consulta")**.
- **Outside the clinic's perimeter.** The clinic cannot apply WAF rules, MFA, IP allowlists, or logging to it. The clinic's compliance posture is bounded by a system whose administrator the clinic has not demonstrated it controls.
- **A single point of failure with no consent record.** No privacy notice, no consent checkbox, no ARCO path (§4).

**Additional risk, stated carefully:** a Google Apps Script web-app deployment, if misconfigured with *"execute as: anyone"*, can be invoked by **anyone on the internet** — including for **reading**, not just writing, depending on the deployment type and script logic. **I have not tested this and must not.** The clinic should treat the deployment as potentially globally invocable and verify its access settings with the account owner.

**Whaling angle:** if that Google account belongs to the agency, then compromising it exposes **the clinic's patient data *and* possibly other clients' data from the same agency's projects.** The agency is the higher-value target and a smaller organization — classic asymmetric-target logic.

**Remedy:** move patient intake onto infrastructure the clinic controls (§6 Wave 2), or at minimum obtain from the account owner a written statement of (a) who owns the Google account, (b) the deployment's access configuration, (c) MFA status, and (d) a data-processing commitment.

### 3.6 Pretexting material — honest assessment

**The claim: "a scammer can quote the clinic's own website back at the victim."** The evidence: the meta description says *"tratamientos sin dolor"* (painless treatments); the homepage says *"resultados visibles desde el primer día"* (visible results from day one). And `/politica-de-cookies` is a **soft-404**, so the site's *only* legal link resolves to a 404 page — meaning the site **looks like it has a privacy policy and does not.**

**Is this a real risk vector? Yes — but not primarily as a *technical* exploit. Here is the honest grading:**

| Claim | As a *security* vector | As a *legal/consumer-protection* vector | As a *social-proof* vector |
|---|---|---|---|
| **"Sin dolor"** | **Weak.** Scam efficacy comes from the *scammer's* claim, not the clinic's. A scammer quoting the clinic's website gains nothing a generic "painless dental implant" script doesn't already have. | **STRONG.** This is the real exposure — see §4.4. It's a probable violation of Reglamento LGS art. 18 fr. II and art. 6 fr. I. | **Moderate.** Lets an attacker say *"even the real clinic advertises painless treatment"* to normalise a fake offer. |
| **"Resultados visibles desde el primer día"** | **Moderate** — this is the one with teeth. It is a **results-guarantee framing**, which is exactly the shape of claim that makes a consumer believe a treatment outcome is assured. It gives a scammer a *plausible-sounding specific* ("you'll see it in one day") that survives more scepticism than a generic claim, and it maps precisely onto consumer-protection doctrine for deceptive advertising (LFPC art. 48–50, §4.5). | **STRONG.** Also engages LGS art. 306 fr. I (claims must be *comprobable* — verifiable). | **Moderate–strong.** A specific, numeric-sounding promise is more persuasive in a vishing script than a vague one. |
| **Broken privacy policy (soft-404)** | **Moderate.** A victim asked to enter health details has been *shown* that this clinic has legal pages and then finds them broken — that is **evidence of neglect**, and neglect is what a scammer needs to make a fake "we need to verify your insurance/records" request sound routine. | **Strong** in its own right (see §4.1). | **Moderate.** |

**My honest verdict:** treat these as **legal and trust risks first, security risks second.** The *security* consequence is real but second-order — the scammer's leverage comes from the claim's existence, not from any technical weakness. **The single highest-value fix here is nearly free: change two sentences on two pages (1 hour).** That simultaneously reduces the LFPDPPP/COFEPRIS exposure, the PROFECO exposure, *and* the pretexting surface. This is the best risk-reduction-per-hour item in the entire report.

---

## 4. Compliance mapping — Mexican law

> **All statutory text below was read directly from the primary source at `diputados.gob.mx/LeyesBiblio/`.** I have flagged every point as **[TEXT]**, **[INTERPRETATION]**, or **[INFERENCE]**.

### 4.1 LFPDPPP (2025) — verified primary source

| Attribute | Verified value |
|---|---|
| Instrument | **Ley Federal de Protección de Datos Personales en Posesión de los Particulares** |
| Published | **DOF 20-mar-2025** |
| In force | **21-mar-2025** (day after publication — Transitorio Primero) |
| Last reform | **DOF 14-nov-2025** (art. 4, parrafo reformado — homologación normativa, CNPCyF; this reform's *content* enters force with the Código Nacional de Procedimientos Civiles y Familiares, **1-abr-2027 at the latest**) |
| Abrogates | The **2010 law** (DOF 5-jul-2010), the LGTPI 2015, the LFTAIP 2016, the LGPDPPSO 2017 (Transitorio Segundo) |
| Enforcement authority | **Secretaría Anticorrupción y Buen Gobierno** — **INAI is gone** |
| Source | `https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf` |

**⚠️ Important on the last reform:** the 14-nov-2025 decree reforms **only art. 4** (supplementary application of the *Código Nacional de Procedimientos Civiles y Familiares* and the *LFPA*). **None of the substantive duties analysed here changed on 2025-11-14.**

#### (a) "Motivo de consulta" is legally **sensitive data**

**[TEXT]** Art. 2, fr. VI:
> *"Datos personales sensibles: Aquellos datos personales que afecten a la esfera más íntima de la persona titular, o cuya utilización indebida pueda dar origen a discriminación o conlleve un riesgo grave para esta. De manera enunciativa más no limitativa se consideran sensibles los datos personales que puedan revelar aspectos como origen racial o étnico, **estado de salud presente o futuro**, información genética, creencias religiosas, filosóficas y morales, opiniones políticas y preferencia sexual"*

**[INTERPRETATION]** A free-text field asking a patient why they are seeking dental care discloses health status and is therefore **sensitive data**. This triggers the **highest** tier of the statute: express **written** consent, no databases without justified purpose, minimized retention, and up to **2× sanctions**.

**[TEXT]** Art. 8 (second paragraph):
> *"No podrán crearse bases de datos que contengan datos personales sensibles, sin que se justifique la creación de las mismas para finalidades legítimas, concretas y acordes con las actividades o fines explícitos que persigue el sujeto regulado."*

**(b) The missing aviso de privacidad — the clearest violation on this site**

**[TEXT]** Art. 14:
> *"El responsable tendrá la obligación de informar a la persona titular, a través del aviso de privacidad, la existencia y características principales del tratamiento al que serán sometidos sus datos personales, a fin de que pueda tomar decisiones informadas al respecto."*

**[TEXT]** Art. 15 — the aviso **must** contain at least:
> *"I. La identidad y domicilio del responsable; II. Los datos personales que serán sometidos a tratamiento, identificando aquéllos que son **sensibles**; III. Las finalidades del tratamiento de datos personales, distinguiendo aquéllas que requieren el consentimiento de la persona titular; IV. Las opciones y medios que el responsable ofrezca a las personas titulares para limitar el uso o divulgación de los datos; V. Los mecanismos, medios y procedimientos para ejercer los derechos ARCO, de conformidad con lo dispuesto en esta Ley, y VI. El procedimiento y medio por el cual el responsable comunicará a las personas titulares de cambios al aviso de privacidad"*

**[TEXT]** Art. 16, fr. II — and this is directly on point for a web form:
> *"Cuando los datos personales sean obtenidos por cualquier medio electrónico, óptico, sonoro, visual, o a través de cualquier otra tecnología, deberá ser proporcionado en su **modalidad simplificada** la que deberá contener al menos la información a que se refieren las fracciones **I a IV** del artículo anterior, y señalar el sitio donde se podrá consultar el aviso de privacidad integral."*

**Assessment of this site: [TEXT + INTERPRETATION]**
- The site collects sensitive data by electronic means (a web form) → **art. 16 fr. II applies.**
- There is **no simplified notice at the point of collection** (no privacy checkbox, no linked text).
- The **only** privacy-related link, `/politica-de-cookies`, is a **soft-404** (returns HTTP 200 with a 404 page title). **There is therefore no aviso de privacidad, simplified or integral, anywhere on the site.**
- **This is a direct, uncontested violation of arts. 14, 15 and 16, and it maps to art. 58 fr. V** (*"Omitir en el aviso de privacidad, alguno o todos los elementos a que se refiere el artículo 15 de esta Ley"*) — an **infracción**.

**(c) Cross-border transfer to Google — arts. 35–36**

**[TEXT]** Art. 35 (final paragraph):
> *"El tratamiento de los datos se hará conforme a lo convenido en el aviso de privacidad, el cual contendrá una cláusula en la que se indique si la persona titular acepta o no la transferencia de sus datos, de igual manera, el tercero receptor, asumirá las mismas obligaciones que correspondan al responsable que transfirió los datos."*

**[TEXT]** Art. 36 — the seven exceptions permitting transfer **without** consent:
> *"Las transferencias nacionales o internacionales de datos podrán llevarse a cabo sin el consentimiento de la persona titular cuando se ubiquen en alguno de los supuestos siguientes: I. La transferencia esté prevista en una Ley o Tratado en los que México sea parte; II. La transferencia sea necesaria para la **prevención o el diagnóstico médico, la prestación de asistencia sanitaria, tratamiento médico o la gestión de servicios sanitarios**; III. …; IV. La transferencia sea necesaria por virtud de un contrato celebrado o por celebrar **en interés de la persona titular**, por el responsable y un tercero; V. …; VI. …; VII. …"*

**[INTERPRETATION — and this is the honest, defensible reading]**
A **booking request** for a dental appointment is plausibly covered by **art. 36 fr. II** (*"prestación de asistencia sanitaria… o la gestión de servicios sanitarios"*). **So the transfer itself is probably lawful** — that is an important, fair point in the clinic's favour, and I am not going to overstate it.
**But the failure is upstream of the transfer:** art. 35 requires a **clause in the aviso de privacidad stating whether the titular accepts the transfer**. There is **no aviso de privacidad at all**. The art. 36 exception excuses *consent*; it **does not excuse the art. 35 disclosure requirement**, nor art. 15's notice content, nor art. 11's purpose-limitation. **The violation is the absence of notice, not the international transfer per se.**
**[INFERENCE]** Transferring sensitive health data to Google infrastructure in the United States without notice also engages arts. 22 fr. XX (**"Transferencia: Toda comunicación de datos personales dentro o fuera del territorio mexicano…"**) and creates LGPD-aligned cross-border exposure — the 2025 LFPDPPP does **not** contain the 2010 law's explicit *cláusula de transferencia* chapter, which is a genuine gap in the new law.

**(d) Retention / minimisation for sensitive data**

**[TEXT]** Art. 12:
> *"El tratamiento de datos personales será el que resulte necesario, adecuado y relevante en relación con las finalidades previstas en el aviso de privacidad, para los datos personales sensibles, el responsable deberá realizar esfuerzos razonables para limitar el periodo de tratamiento de los mismos a efecto de que sea el **mínimo indispensable**."*

**[TEXT]** Art. 10 (final paragraph):
> *"Cuando los datos personales hayan dejado de ser necesarios para el cumplimiento de las finalidades previstas en el aviso de privacidad y que motivaron su tratamiento conforme a las disposiciones legales aplicables, deberán ser suprimidos previo bloqueo…"*

**Assessment: [INTERPRETATION]** The clinic must be able to demonstrate (i) a stated retention period, and (ii) that it actually **deletes** records. **A Google Sheet that has been accumulating "motivo de consulta" entries since the site launched is, on its face, an art. 12 and art. 10 problem.** Nobody can verify current volume from passive data, but the retention question **must be asked and answered in writing.** Note also **[TEXT]** art. 62: *"tres meses a tres años de prisión al que, estando autorizado para tratar datos personales, **con ánimo de lucro**, provoque una vulneración de seguridad a las bases de datos bajo su custodia"* — and **[TEXT]** art. 64: *"Tratándose de datos personales sensibles, las penas … se duplicarán."* **That is the personal exposure for the clinic's principals — separate from and additional to the corporate fine.**

**(e) ARCO rights and the response deadline**

**[TEXT]** Art. 31, first paragraph:
> *"El responsable comunicará a la persona titular, en un plazo máximo de **veinte días**, contados desde la fecha en que se recibió la solicitud para el ejercicio de los derechos ARCO, la determinación adoptada, a efecto de que, si resulta procedente, se haga efectiva la misma dentro de los quince días siguientes a la fecha en que se comunica la respuesta…"*

**[TEXT]** Art. 31, second paragraph:
> *"Los plazos antes referidos podrán ser ampliados una sola vez por un periodo igual, siempre y cuando así lo justifiquen las circunstancias del caso."*

**[TEXT]** Art. 2, fr. VIII — **this is the key to the "hábiles" question and I verified it specifically:**
> *"VIII. **Días: Días hábiles**"*

**Conclusion on the 20-day deadline: [TEXT] The "veinte días hábiles" characterisation in the prior report is CORRECT.** The statute says "veinte días" and then *statutorily defines* "días" as business days. **20 business days, extendable once by an equal period** (→ up to 40 business days in exceptional cases). ARCO rights are at **[TEXT]** art. 22 (Acceso, via the aviso de privacidad), art. 23 (Rectificación), art. 24 (Cancelación — note the *bloqueo* then *supresión* sequence), art. 26 (Oposición).

**[TEXT]** Art. 29 is a concrete operational requirement the clinic currently cannot meet:
> *"Todo responsable fomentará la protección de datos personales al interior de la organización y **designará a una persona, o departamento de datos personales**, quien dará trámite a las solicitudes de las personas titulares…"*

**Assessment: [INTERPRETATION]** There is no evidence of any designated data-protection contact, no ARCO procedure, and no published ARCO mechanism. Art. 58 fr. I (*"No cumplir con la solicitud para el ejercicio de los derechos ARCO de la persona titular, sin razón fundada"*) is an infracción — sanctionable under art. 59 fr. I (*"El apercibimiento"*).

#### (f) ⚠️ SANCTION EXPOSURE — the prior report's "MXN 37.5M" figure: **VERIFIED CORRECT**

You asked me to verify this against primary source and correct it if wrong. **It is correct.** Here is the exact derivation.

**[TEXT]** Art. 58 lists nineteen infractions (fr. I–XIX). The ones this site's facts could plausibly engage:

| Art. 58 fr. | Infraction text (Spanish, verbatim excerpt) | Applies here? |
|---|---|:-:|
| **V** | *"Omitir en el aviso de privacidad, alguno o todos los elementos a que se refiere el artículo 15 de esta Ley"* | **YES — unambiguously** |
| **IV** | *"Dar tratamiento a los datos personales en contravención a los principios establecidos en la presente Ley"* | **YES** |
| **IX** | *"Cambiar sustancialmente la finalidad originaria del tratamiento de los datos, sin observar lo dispuesto por el artículo 11"* | Possible |
| **X** | *"Transferir datos a terceros sin comunicar a estos el aviso de privacidad que contiene las limitaciones a que la persona titular sujetó la divulgación de los mismos"* | **YES — the Google transfer, and art. 35 expressly requires this** |
| **XI** | *"Vulnerar la seguridad de bases de datos, locales, programas o equipos, cuando resulte imputable al responsable"* | Only on a proven breach |
| **XII** | *"Llevar a cabo la transferencia o cesión de los datos personales, fuera de los casos en que esté permitida por la Ley"* | Possible |
| **XIII** | *"Recabar o transferir datos personales sin el consentimiento expreso de la persona titular, en los casos en que éste sea exigible"* | **YES — art. 8 requires express written consent for sensitive data** |
| **XVIII** | *"Crear bases de datos en contravención a lo dispuesto por el artículo 8, segundo párrafo"* | **YES — a growing sheet of health data with no stated justification** |
| **XIX** | *"Cualquier incumplimiento del responsable a las obligaciones establecidas a su cargo…"* | **Catch-all — YES** |

**[TEXT]** Art. 59 — **and here is the answer to your question. The penalties are expressed in UMA multiples, not fixed pesos:**
> *"I. El apercibimiento para que el responsable lleve a cabo los actos solicitados por la persona titular…;*
> *II. Multa de **100 a 160,000** veces la Unidad de Medida y Actualización, en los casos previstos en las fracciones II a VII del artículo anterior;*
> *III. Multa de **200 a 320,000** veces la Unidad de Medida y Actualización, en los casos previstos en las fracciones **VIII a XVIII** del artículo anterior, y*
> *IV. En caso de que de manera reiterada persistan las infracciones citadas en los incisos anteriores, se impondrá una **multa adicional que irá de 100 a 320,000** veces la Unidad de Medida y Actualización. **En tratándose de infracciones cometidas en el tratamiento de datos sensibles, las sanciones podrán incrementarse hasta por dos veces, los montos establecidos.**"*

**[TEXT]** UMA 2026 value — INEGI, Comunicado de Prensa 1/26 (8-ene-2026), published in **DOF 09-01-2026**, in force **1-feb-2026**:
> *"Diario **117.31** pesos mexicanos / Mensual 3 566.22 pesos mexicanos / Anual 42 794.64 pesos mexicanos"*

**The arithmetic:**

| Basis | Calculation | **MXN** |
|---|---|---|
| Art. 59 fr. II max (frs. II–VII) | 160,000 × 117.31 | **$18,769,600** |
| **Art. 59 fr. III max (frs. VIII–XVIII)** ← *the applicable band: V, X, XIII, XVIII all sit here* | **320,000 × 117.31** | **$37,539,200** |
| Art. 59 fr. IV additional (repeat offences) | +100,000–320,000 UMA | **+ $11,731,000 – $37,539,200** |
| Art. 59 fr. IV **sensitive-data doubling** | up to 2× | **up to ~$75,078,400** |
| Theoretical ceiling (art. 59 III max + IV additional max, both doubled) | 1,280,000 UMA × 117.31 | *~$150,156,800* |

> ### ✅ VERIFICATION RESULT
> **The prior report's "up to MXN 37.5M" is CORRECT** — it is `$37,539,200`, being **320,000 × the 2026 UMA of $117.31**, per **art. 59 fr. III**. The prior report's *number* was right even though the *mechanism* (a flat peso statutory cap) is not how the law states it. The correct framing is: **"up to 320,000 UMA under art. 59 fr. III; up to twice that where sensitive data is involved under art. 59 fr. IV."**
>
> **[INTERPRETATION]** Art. 60 requires the Secretaría to consider *"la capacidad económica del responsable"* — so the *actual* fine for a small clinic would realistically be far below the statutory maximum. **But the maximum is the statutory exposure, the maximum is what appears on the face of the law, and the maximum is what a demand letter will quote.** **[INFERENCE]** The realistic risk here is **not** the fine. It is (a) an **order to stop processing immediately** (which would halt patient booking entirely) and (b) the **criminal exposure at art. 62 / art. 64** for whoever is *"autorizado para tratar datos personales, con ánimo de lucro"*.

#### (g) Breach notification — does the 2010 law's 30-day authority notification survive?

**Answer: NO. The 2025 law does not preserve it in the statutory text. It requires notification to the *data subject*, not to an authority.**

**[TEXT]** Art. 19 — the **only** breach provision in the entire law:
> *"Las vulneraciones de seguridad ocurridas en cualquier fase del tratamiento de datos personales que afecten de forma significativa los derechos patrimoniales o morales de las personas titulares **le serán informadas de forma inmediata por el responsable**, a fin de que pueda tomar las medidas correspondientes a la defensa de sus derechos."*

**Three precise findings:**

1. **The 2010 law's regime is gone.** The 2010 LFPDPPP (abrogated, Transitorio Segundo fr. I) required breach notification **to the Secretaría** via its Reglamento (art. 20 of the old law, with a 30-day working-day window implemented through the Reglamento's *procedimiento para brechas de seguridad* — I am stating the *substance*: authority notification within 30 días hábiles). **I searched the full text of the 2025 law for "30", "treinta", "brecha", "incidente", and "notificar" — there is no authority-notification provision.** Words "brecha" and "incidente" appear **zero** times in the entire statute.

2. **What the 2025 law actually requires is *deeper and stricter* for the clinic — but differently shaped.** Art. 19 obliges the clinic to inform **the affected data subjects, immediately**, where the breach *"afecte de forma significativa los derechos patrimoniales o morales"* of the titulars. **[INTERPRETATION]** For sensitive health data, a material breach will almost always meet that threshold. **The practical obligation is therefore: notify affected patients, fast.** This is *harder to execute* than notifying one authority (you must identify and reach affected individuals), and the clinic has **no procedure for it at all** — which is itself the art. 58 fr. XIX breach.

3. **The authority can still self-initiate.** **[TEXT]** Art. 56: *"Si con motivo del desahogo del procedimiento de protección de derechos o del procedimiento de verificación que realice la Secretaría, ésta tuviera conocimiento de un presunto incumplimiento… iniciará el procedimiento de imposición de sanciones."* **[INFERENCE]** Because the 2025 law's verification regime was not fully tested in the 2010-law period, a complaint by **any single patient** exercising ARCO rights could plausibly open a verification proceeding. The clinic currently has **no way to respond to an ARCO request**, which converts one complaint into an art. 58 fr. I + fr. V finding. **This raises the probability of detection, which is why the fine matters less than the *likelihood* it is ever asked about.**

**Recommended posture (documented advice, not legal advice):** prepare a written breach-response procedure now — identify affected titulars, decide the *"afecte de forma significativa"* threshold in advance, prepare a patient notification template, and **keep contemporaneous evidence of every decision.** Under the 2025 law, good-faith documented reasoning is the best available defence, and the Reglamento (which will define "medidas compensatorias" per art. 17) has not yet been issued, so the procedural detail remains genuinely unsettled.

### 4.2 LGS art. 83 — cédula profesional in advertising

**[TEXT]** Verbatim from `https://www.diputados.gob.mx/LeyesBiblio/pdf/LGS.pdf` (LGS, última reforma **DOF 15-01-2026**):
> *"Artículo 83.- Quienes ejerzan las actividades profesionales, técnicas y auxiliares y las especialidades médicas, deberán poner a la vista del público un anuncio que indique la institución que les expidió el Título, Diploma, número de su correspondiente cédula profesional y, en su caso, el Certificado de Especialidad vigente. Iguales menciones deberán consignarse en los documentos y papelería que utilicen en el ejercicio de tales actividades y **en la publicidad que realicen al respecto**."*
> — Última reforma del artículo: **DOF 01-09-2011**

**[TEXT]** Reinforced at the regulatory level by **Reglamento de la LGS en Materia de Publicidad, art. 19** (`https://www.diputados.gob.mx/LeyesBiblio/regley/Reg_LGS_MP.pdf`, última reforma **DOF 08-09-2022**):
> *"ARTÍCULO 19. Quienes ejerzan las actividades profesionales, técnicas y auxiliares y las especialidades a que se refiere el Capítulo I del Título Cuarto de la Ley, deberán expresar **en la publicidad que realicen al respecto, cualquiera que sea el medio publicitario de que se trate**, la institución educativa que les expidió el título, diploma o certificado correspondiente y, en su caso, el número de cédula profesional."*

**Assessment: [TEXT + INTERPRETATION] — this is a live violation, and art. 19 is the tighter of the two because it covers "cualquiera que sea el medio publicitario."**
The audit found **zero** `Cédula`, **zero** `colegiación`, **zero** `Dr./Dra.`, **zero** credentials across all 17 pages. **A website is advertising.** Every service page and the homepage are advertising in the statutory sense.
**What it costs:** fixing this is roughly **3 hours** and is one of the best value-for-effort items in the report — it removes a certain violation, improves the site's E-E-A-T (§5, E6), and supports the "professional legitimacy" half of the §3 pretexting defence at the same time.
**Note the enforcement reality:** enforcement of LGS advertising on small private clinics runs through **COFEPRIS** (state-level) and, in CDMX, the **Secretaría de Salud de la Ciudad de México**. **[INTERPRETATION]** Individual sanction for a small clinic is typically administrative and low; the *practical* risk is that a competitor or a patient complaint triggers a visit, and that the missing credential becomes visible to a regulator. **[INFERENCE]** It also weakens the clinic's position in any professional-conduct dispute — its own failure to display the very credential it would rely on.

### 4.3 Reglamento LGS en Materia de Publicidad art. 6 — prohibited claims (verbatim)

**[TEXT]** `https://www.diputados.gob.mx/LeyesBiblio/regley/Reg_LGS_MP.pdf` (Original DOF 04-05-2000; reformas DOF 06-04-2006, 31-05-2009, 19-01-2012, 14-02-2014, **08-09-2022**):

> *"ARTÍCULO 6. La publicidad será congruente con las características o especificaciones que establezcan las disposiciones aplicables para los productos o servicios objeto de la misma, para lo cual **no deberá:**"*
>
> **I.** *"Atribuirles cualidades **preventivas, terapéuticas, rehabilitatorias, nutritivas, estimulantes o de otra índole**, que no correspondan a su función o uso, de conformidad con lo establecido en las disposiciones aplicables o en la autorización otorgada por la Secretaría;"*
>
> **I Bis.** *"Incluir sellos o leyendas de recomendación o reconocimiento por organizaciones o asociaciones profesionales en aquellos alimentos y bebidas no alcohólicas que, conforme a la norma correspondiente, deban incluir en su etiqueta uno o más sellos de exceso de energía o de nutrimentos críticos."* *(fracción adicionada DOF 08-09-2022)*
>
> **II.** *"Indicar o sugerir que el uso o consumo de un producto o la prestación de un servicio, es un **factor determinante para modificar la conducta de las personas**, o"*
>
> **III.** *"Indicar o inducir a creer explícita o implícitamente que el producto cuenta con los ingredientes o las propiedades de los cuales carezca."*

**[IMPORTANT CLARIFICATION on fr. II — accuracy matters here.]** Fracción II is aimed at **behavioural-modification claims** (the tobacco/alcohol/food pattern). **"Sin dolor" is not a fr. II issue.** Do not misapply it. **The operative fractions for this site's claims are fr. I (and the health-services-specific art. 18 below), not fr. II.** I am flagging this because the prior framing in the brief asked me to "quote I and II" — the honest answer is that **II is the wrong hook and I should say so rather than manufacture a fit.**

**The provision that actually decides this case is [TEXT] art. 18 of the same Reglamento:**
> *"ARTÍCULO 18. **No se autorizará la publicidad de la prestación de servicios de salud cuando:** I. Desvirtúe o contravenga la normatividad aplicable en materia de prevención, tratamiento o rehabilitación de enfermedades; II. **Ofrezca tratamientos preventivos, curativos o rehabilitatorios de naturaleza médica o paramédica cuya eficacia no haya sido comprobada científicamente**, o III. No se acredite que el establecimiento o persona que preste el servicio cuente con el personal capacitado, los recursos técnicos y materiales adecuados, y con los demás elementos que al respecto exijan las disposiciones aplicables."*

**And [TEXT] LGS art. 306, fr. I** (the general veracity rule for advertising under the LGS):
> *"La información contenida en el mensaje sobre calidad, origen, pureza, conservación, propiedades nutritivas y beneficios de empleo deberá ser **comprobable**;"*

#### Assessment of the two specific claims

**Claim A: *"tratamientos sin dolor"* (meta description)**

- **[TEXT]** Art. 6 fr. I prohibits attributing *"cualidades … terapéuticas, rehabilitatorias … que no correspondan a su función o uso."*
- **[INTERPRETATION]** "Sin dolor" is an **absolute therapeutic outcome assertion**. Dental treatment is not, in general, painless; pain is an expected clinical variable (endodontic treatment, extraction, implant surgery, periodontal procedures). An **unqualified absolute** — with no clinical qualification, no "en muchos casos", no clinician attribution — is best read as attributing a therapeutic property that **does not correspond to the service's actual function.**
- **[TEXT]** Art. 18 fr. II reinforces this: it authorises advertising of treatments whose efficacy **has been scientifically verified**. **[INTERPRETATION]** A blanket painless claim is not scientifically verifiable, because its truth is case-dependent. This is the **strongest** hook, and it is *specifically* about **servicios de salud** — which is exactly what this is.
- **[TEXT]** LGS art. 306 fr. I requires claims to be *"comprobable"*. **[INTERPRETATION]** "Sin dolor" is not comprobable.
- **⚠️ Also note the location:** this text is in the **meta description**, i.e. it is *by design* the text served to search engines and rendered in SERP snippets. It is advertising.
- **[INTERPRETATION — verdict: PROBABLE VIOLATION, LOW ENFORCEMENT RISK, HIGH TRUST/REPUTATION RISK.]** Rewrite to something clinically supportable, e.g. *"Tratamientos dentales con opciones de anestesia local y atención reconfortable"* — accurate, still appealing, defensible.

**Claim B: *"resultados visibles desde el primer día"* (homepage)**

- **[TEXT]** Art. 6 fr. I — again, an **outcome** claim (results visible), not a product property claim.
- **[TEXT]** Art. 18 fr. I — *"Desvirtúe o contravenga la normatividad aplicable en materia de prevención, tratamiento o rehabilitación"*. **[INTERPRETATION]** A guaranteed-speed results claim asserts that the treatment achieves its outcome within a fixed, very short period **regardless of the individual patient** — this is the definition of a claim that oversimplifies clinical reality.
- **[TEXT]** Art. 18 fr. II — a "visible results from day one" claim is a **therapeutic efficacy** claim; it is not scientifically verifiable in the general case. **Strongest hook.**
- **[TEXT]** LGS art. 306 fr. I — *"comprobable"*. Not comprobable.
- **[INTERPRETATION — verdict: PROBABLE VIOLATION, and the higher-risk of the two**, because a *timed results guarantee* is closer to a performance promise than a comfort claim. **[INFERENCE]** It also carries LFPC exposure (§4.5) if a patient can be shown it materially shaped their decision and the outcome differed.
- **Recommendation:** delete the timing claim entirely. If a speed message is needed, tie it to *process* not *outcome* — e.g. *"Consulta y plan de tratamiento en la primera cita."* **[INTERPRETATION]** This is both legally safer and, frankly, more credible to patients.

**Time cost: ~1 hour. This is the highest risk-reduction-per-hour item in the report** (§5, L3 = 12 points / 1 hour = **12.0 pts/hr**).

### 4.4 ⚠️ Cookie banner — is one legally required in Mexico?

**Splitting settled law from professional interpretation, as you asked:**

**[TEXT — SETTLED LAW]** I searched the full text of the **2025 LFPDPPP**, the **LGS**, the **LFPC**, and the **Reglamento LGS en Materia de Publicidad** for provisions on cookies, cookie banners, or equivalent consent mechanisms. **The Mexican federal statutes contain no provision equivalent to Article 5(3) of the EU ePrivacy Directive (2002/58/EC) as transposed by the GDPR.** There is **no Mexican federal statute requiring a cookie-consent banner.**

**[INTERPRETATION — this is the operative point, and it is a common misconception worth correcting]** "No cookie-banner law" does **not** mean "no obligation." The obligation exists; it arrives through a **different door**:

1. **[TEXT] LFPDPPP art. 16 fr. II** — where personal data is obtained "por cualquier medio electrónico," a **simplified aviso de privacidad must be provided at the point of collection**, containing at least frs. I–IV of art. 15 (identity/domicile of the responsable; data processed **identifying which are sensitive**; purposes, distinguishing those requiring consent; and **options and means to limit use or disclosure**).
2. **[TEXT] LFPDPPP art. 7** — *"Todo tratamiento de datos personales estará sujeto al consentimiento de la persona titular, salvo las excepciones previstas en la presente Ley."* Express consent is required unless an **art. 9** exception applies.
3. **[INTERPRETATION]** Therefore the accurate Mexican answer is: **a consent-gathering mechanism is required by operation of arts. 7 + 16 (LFPDPPP) — it just isn't called a "cookie banner," and it isn't GDPR-shaped.** Professional practice in Mexico treats a privacy/cookie notice as the mechanism that discharges arts. 7 and 16, with a cookie-consent variant where non-essential cookies are set.
4. **[INFERENCE — how this actually applies to THIS site]** This one is unusually clean, because the audit found **zero analytics, zero pixels, zero tracking of any kind, and zero `Set-Cookie` on `/`, `/contacto/`, `/agendar-cita/`.** So:
   - **The strict GDPR-style cookie problem does not exist here.** With no trackers, there is nothing non-essential to consent to.
   - **But the LFPDPPP problem absolutely does** — and it is *worse* than a cookie problem, because the form collects **sensitive** data (art. 8: express written consent required), for which **no aviso de privacidad exists anywhere on the site**, and the only privacy link is a **soft-404**.
   - **Correct framing for the clinic:** *"We don't need a cookie banner because we run no trackers. We absolutely need an aviso de privacidad plus express written consent for sensitive data, and we currently have neither."* That distinction should be stated plainly in the escalation, so the clinic doesn't buy a cookie-consent plugin that solves the wrong problem.

**Recommendation:** publish the aviso de privacidad (integral + simplified) and add explicit consent to the booking form covering sensitive data and the Google transfer. If trackers are added later, add consent then. **[INTERPRETATION]** Note that the "sin Illegal–privacidad en cookies" reading is settled only in the sense that no *specific* cookie statute exists; **[INFERENCE]** a strict regulator could still characterise undisclosed non-essential cookies as a processing activity without the art. 16 fr. II notice — which is a further, cheaper reason to publish the aviso regardless.

### 4.5 LFPC — advertised prices and offers

**[TEXT]** `https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPC.pdf` (LFPC, última reforma **DOF 12-12-2025**; *"Actualización de montos de operaciones y multas por Acuerdo DOF 23-12-2025"*):

**Art. 46** defines the relevant terms:
> *"Por 'oferta', 'barata', 'descuento', 'remate' o cualquier otra expresión similar se entiende el ofrecimiento al público de productos o servicios de la misma calidad a **precios rebajados o inferiores a los normales del establecimiento**."*

**Art. 48, fr. I** — a condition on any promotion:
> *"En los anuncios respectivos deberán indicarse las condiciones, así como el plazo de duración o el volumen de los bienes o servicios ofrecidos; dicho volumen deberá acreditarse a solicitud de la autoridad. Si no se fija plazo ni volumen, **se presume que son indefinidos** hasta que se haga del conocimiento público la revocación de la promoción o de la oferta…"*

**Art. 48, fr. II** — a hard consumer entitlement:
> *"Todo consumidor que reúna los requisitos respectivos tendrá derecho a la adquisición, durante el plazo previamente determinado o en tanto exista disponibilidad, de los bienes o servicios de que se trate."*

**Art. 49** — anti-inflation on advertised value:
> *"No se podrán realizar promociones en las que se anuncie un valor monetario para el bien, producto o servicio ofrecido, **notoriamente superior al normalmente disponible en el mercado**."*

**Art. 50 — the one you asked about, verbatim:**
> *"ARTÍCULO 50.- Si el autor de la promoción u oferta no cumple su ofrecimiento, el consumidor podrá optar por exigir el cumplimiento, aceptar otro bien o servicio equivalente o la rescisión del contrato y, en todo caso, tendrá derecho al pago de la **diferencia económica entre el precio al que se ofrezca el bien o servicio objeto de la promoción u oferta y su precio normal**, sin perjuicio de la bonificación o compensación a que se refiere el artículo 92 TER de esta ley."*
> — *Artículo reformado DOF 04-02-2004*

**Assessment of the site's actual copy: [INTERPRETATION]**
- The site as observed publishes **no prices at all** ("desde $X" does not appear in the verified findings). So **art. 50 is not currently engaged** — it becomes live **only if the clinic adds a price** (which §4.6 recommends considering for SEO).
- **[INTERPRETATION]** If a "desde $X" offer *is* published, the exposure is concrete and calculable: a patient who is offered the promotional price, is refused it, and is charged more has a statutory entitlement under art. 50 to **the economic difference** — i.e. the clinic would owe the discount *plus* still owe the consumer who took the service.
- **[TEXT] art. 48 fr. I** creates the operational trap: **publishing a price without stating conditions, duration, or volume makes it "indefinido" by presumption** — an unbounded commitment.
- **[TEXT] art. 35 fr. V** confirms PROFECO can apply **cautional measures** (sello de clausura) for *"el incumplimiento de precios o tarifas exhibidos; … el incumplimiento de ofertas y promociones; … por publicidad o información engañosa."*
- **Practical recommendation:** if publishing prices, publish **"precio desde"** (a floor, not a promise), state the conditions and exclusions in the same viewport, state a validity window, and **never** publish a price the front desk would not honour. And note the amusingly convenient **[TEXT]** cross-reference below.

### 4.6 ❓ Explicit confirm/refute #1 — Is there any Mexican legal obligation to publish dental prices?

> ### ❌ REFUTED / NOT FOUND — and I will not fabricate a citation.
>
> **I searched the full text of:** the **LGS** (376 pages, última reforma DOF 15-01-2026), the **LFPC** (119 pages, última reforma DOF 12-12-2025), the **Reglamento de la LGS en Materia de Salud** (n. 98), the **Reglamento de la LGS en Materia de Publicidad** (n. 103), and the **LFPDPPP 2025**.
>
> **Result: I could not find any Mexican federal statute or regulation requiring a private dental clinic to publish prices for its services.**
>
> **The one adjacent provision that points the *other* way — [TEXT], and it is genuinely useful:** **Reglamento de la LGS en Materia de Publicidad, art. 5:**
> > *"No estará sujeta a este Reglamento la publicidad que se realice sobre **ofertas o promociones comerciales relacionados exclusivamente con el precio** de los productos, servicios y actividades, pero cuando se refiera a ellos en forma particular o por sus marcas deberá incluir la leyenda que, en su caso, corresponda."*
>
> **Meaning:** advertising that is **exclusively about price** falls *outside* this health-advertising Reglamento. That is an **exemption from the COFEPRIS advertising regime**, not a mandate to advertise. It does two useful things for the clinic: (a) it confirms **price-only content is not subject to art. 6's prohibited-claim rules** (which is why publishing "desde $1,500 — limpieza dental" is low LGS risk, while publishing "desde $1,500 — resultados visibles desde el primer día" is not, because the second is *not* exclusively about price), and (b) it keeps the clinic inside **LFPC arts. 46–50**, which is the correct and lighter regime for price claims.
>
> **[INTERPRETATION]** There may be **state-level** requirements (some CDMX/other-state consumer or professional bodies have historically issued price-display guidance, and the "Ley Federal de Protección al Consumidor" has *consumer-information* functions under art. 7) that I did not locate in federal sources. **I am not asserting state law is empty — I am asserting I could not find a federal obligation, and I decline to invent one.** If the client wants certainty on state-level rules, that requires a CDMX-specific search by a Mexican-qualified lawyer, which is outside the scope of this passive review.

### 4.7 ❓ Explicit confirm/refute #2 — Is there any Mexican statute prohibiting "antes y después" dental photos?

> ### ❌ REFUTED — no such prohibition found. **But read the caveat — this is the more useful answer.**
>
> **Search performed:** full-text search of the **Reglamento de la LGS en Materia de Publicidad** (the operative instrument for dental advertising) — the string **"antes y después" returns zero (0) matches**. Also searched the LGS and LFPC full texts.
>
> **Conclusion: there is no Mexican federal statute or regulation prohibiting before-and-after dental photographs.**
>
> **⚠️ [INTERPRETATION] — and this is the part that matters more than the absence of a ban:**
> **The real constraints on before/after photography in Mexico are not a prohibition on the photos. They are:**
> 1. **Patient consent to image use.** **[INFERENCE]** Publishing a patient's identifiable dental image engages **LFPDPPP** — a photo of a face is personal data, and using it for marketing requires an **aviso de privacidad** covering that purpose, and (for anything health-related) the art. 8 sensitive-data consent. **[INTERPRETATION]** The widely-used professional practice is a **specific, separate, signed image-release consent**, distinct from treatment consent — a position I did not find written in statute, so I am labelling it professional practice, not law.
> 2. **Art. 6 fr. I of the Reglamento** still applies to the **text and framing** around the photos. The images are permitted; **"results visible from day one" written next to them is not**, and pairing flattering imagery with a speed guarantee makes the fr. I / art. 18 fr. II analysis much stronger (§4.3, Claim B).
> 3. **LFPC art. 46–50** — if the before/after is used to support a promotional claim, the price/offer rules bite normally.
>
> **Recommendation: before/after images are usable.** Pair them with a signed, purpose-specific image release per patient, keep them out of the health-advertising claims analysis (i.e. don't attach speed/guarantee language), and remember each image is now a **personal-data asset requiring its own aviso de privacidad entry**.
>
> **[NOTE]** The current site uses `alt=""` on 100% of images (§5, E4) — so if before/after images *are* being used, they are currently **invisible to Google Images**, which is an SEO loss and, separately, means the alt-text data-processing question hasn't arisen yet. **Adding them properly means adding alt text, which means updating the aviso de privacidad to cover image-processing purposes.**

### 4.8 Other Mexican-law items worth flagging

**[TEXT] LGS art. 316 (first paragraph, reformed DOF 15-01-2026)** — new-ish and directly relevant, since the audit found no `persona responsable sanitaria` disclosure:
> *"Los establecimientos a que se refiere el artículo anteriorPoco contando con una persona responsable sanitaria, de quien deberán dar aviso de su alta, modificación y baja ante la Secretaría de Salud."*

**[INFERENCE]** Confirm with the clinic that the required *aviso de alta* of the responsible sanitary person has been filed with Secretaría de Salud. This is not a website finding and I am not overreaching — but it surfaced during the art. 316 read and is a legitimate operational check. **[INTERPRETATION]** If the aviso is a public-facing duty, a clinic that hasn't filed it may need a site disclosure as well.

**[TEXT] LGS art. 305** — worth noting because it widens the liable party:
> *"Los responsables de la publicidad, anunciantes, **agencias de publicidad** y medios difusores, se ajustarán a las normas de este título."*

**[INTERPRETATION]** The **web agency** is not a bystander to the "sin dolor" / "resultados visibles" claims — it is a named regulated party under art. 305. This is a useful lever: the clinic can make compliance a **contractual obligation of the agency**, which is a far more effective control than asking nicely. **[INFERENCE]** Include claim-submission and approval obligations in the agency contract (§6 Wave 3).

---

## 5. Risk register

**Scoring:** Likelihood (L) 1–5 and Impact (I) 1–5; **Score = L × I**. **RR/hr = Score ÷ Remediation hours** (risk-reduction per hour). Sorted within each group by Score.
**Owner** flags: 🔒 = **not actionable by the clinic** — requires [HOSTING], the web agency, or Elegant Themes. These require written escalation (§7).

### 5.1 Patient-data breach

| ID | Risk statement (plain language) | L | I | Score | OWASP | Owner | Hrs | **RR/hr** |
|---|---|:-:|:-:|:-:|---|---|:-:|:-:|
| **P1** | If a patient books, their name, contact details, appointment and **health complaint** are written into a Google account the clinic may not control, then the clinic cannot say where that data lives, who can read it, or prove it was lawfully obtained — and it has told the patient nothing. | 5 | 5 | **25** | A02 / A04 | Clinic + 🔒 Agency (Google account owner) | 6 | **4.2** |
| **P2** | If a patient asks "what happened to my data?", the clinic has no aviso de privacidad to point at — so the request cannot be answered lawfully, and answering it wrongly is itself a fresh violation. | 4 | 5 | **20** | A02 | **Clinic** | 4 | **5.0** |
| **P3** | If the Apps Script deployment is invocable by anyone on the internet, then patient health data can be read or written by a stranger, and the clinic has no logging to find out. | 3 | 5 | **15** | A01 | Clinic + 🔒 Agency | 4 | **3.8** |
| **P4** | If a security breach exposes the health data, the clinic must tell affected **patients** "de forma inmediata" (LFPDPPP art. 19) and has no procedure, no template and no contact list to do it. | 3 | 5 | **15** | A02 | **Clinic** | 2 | **7.5** |
| **P5** | If a patient demands deletion, the clinic has no ARCO process, no named data-protection contact (art. 29) and no 20-business-day clock — so the statutory deadline is breached by default. | 4 | 4 | **16** | A01 | **Clinic** | 6 | **2.7** |
| **P6** | If sensitive data sits in a growing spreadsheet with no stated purpose or retention period, the clinic breaches the art. 12 minimisation duty and the art. 8(2) "no sensitive databases without justification" rule on its face. | 4 | 4 | **16** | A04 | Clinic + 🔒 Agency | 3 | **5.3** |

### 5.2 Phishing / social engineering

| ID | Risk statement | L | I | Score | OWASP | Owner | Hrs | **RR/hr** |
|---|---|:-:|:-:|:-:|---|---|:-:|:-:|
| **S1** | If there is no DMARC record, then **anyone** can send email that *looks* like it came from the clinic, and no mail server is instructed to check or reject it. Patients receive fake "your appointment is confirmed" links. | 5 | 4 | **20** | A07 | Clinic (DNS) + 🔒 [HOSTING] | 2 | **10.0** |
| **S2** | If the WordPress admin password is weak or reused, an attacker who already knows the username `[USUARIO-1]` (published on the site) logs in and owns the website. | 4 | 5 | **20** | A07 | **Clinic** | 1 | **20.0** |
| **S3** | If the site lists three different phone numbers (one in the wrong state), a scammer can sound legitimate by citing the clinic's own real number — and the victim's one self-help defence ("call them myself") is undermined by the clinic's own inconsistency. | 5 | 4 | **20** | A07 | **Clinic** | 2 | **10.0** |
| **S4** | If the username is published on the site, then password-guessing attacks skip the hardest part and only need to guess the password. | 4 | 4 | **16** | A05 | Clinic + 🔒 Agency | 2 | **8.0** |
| **S5** | If the clinic keeps claiming "painless" and "visible results from day one", then a scammer can quote the clinic's own website back at a victim to make a fake offer sound legitimate. | 3 | 3 | **9** | A07 | **Clinic** | 1 | **9.0** |
| **S6** | If the shared certificate publishes the agency's other client domains, then any phishing campaign against the clinic starts with a free, accurate list of every brand the agency serves. | 4 | 4 | **16** | A02 | 🔒 **[HOSTING] + Agency** | 4 | **4.0** |
| **S7** | If Divi's "Force Enable D4 Shortcode Framework" option is on (unverified), then an unauthenticated attacker can make the site send emails from the clinic's own address — a phishing mail that would pass DMARC. | 2 | 5 | **10** | A07 | 🔒 **Agency (Divi Dashboard)** | 1 | **10.0** |

### 5.3 Website compromise / takedown

| ID | Risk statement | L | I | Score | OWASP | Owner | Hrs | **RR/hr** |
|---|---|:-:|:-:|:-:|---|---|:-:|:-:|
| **W1** | If the site is still running one of the five outdated WordPress versions the cache is serving, an unauthenticated attacker can exploit a **Critical remote-code-execution** flaw (CVE-2026-87902, CVSS 9.2) and take the whole website — plus the clinic's email and the agency's client list. | 4 | 5 | **20** | A06 | 🔒 **Agency** | 2 | **10.0** |
| **W2** | If the server's PHP is not on a patched version, then **any** visitor can potentially execute code on the server — the PHP team released emergency fixes for this **yesterday** and said "update immediately." | 4 | 5 | **20** | A06 | 🔒 **[HOSTING]** | 1 | **20.0** |
| **W3** | If WordPress is patched but the **cache is not purged**, then the site keeps serving the vulnerable old pages to every visitor, and the fix appears not to have worked. | 5 | 4 | **20** | A06 | 🔒 **[HOSTING] + Agency** | 1 | **20.0** |
| **W4** | If the site's WordPress admin login is not protected by MFA, then one stolen or reused password is enough to lose the site permanently. | 4 | 5 | **20** | A07 | **Clinic** | 1 | **20.0** |
| **W5** | If Divi stays on 4.27.4, then the site carries six known Divi security flaws — including one that is **unauthenticated** — that an attacker can use after gaining any foothold. | 3 | 4 | **12** | A06 | 🔒 **Agency** | 1 | **12.0** |
| **W6** | If a placeholder like `WHATSAPP_NUMBER = '[TELEFONO-PLACEHOLDER]'` is live in production, then a customer-facing number could silently send patients' details to a stranger, and nobody notices because it *looks* like it works. | 3 | 4 | **12** | A04 | 🔒 **Agency** | 1 | **12.0** |
| **W7** | If the site runs on **HTTP without redirecting to HTTPS**, then a patient typing the address on a shared or hostile network sends their health details in **plain, readable text**. | 5 | 4 | **20** | A02 | 🔒 **[HOSTING]** | 1 | **20.0** |
| **W8** | If the server accepts **TLS 1.0 and 1.1**, then the connection protecting patient data uses cryptography that is known to be broken and can be decrypted. | 5 | 3 | **15** | A02 | 🔒 **[HOSTING]** | 1 | **15.0** |
| **W9** | If JavaScript libraries are loaded from a third-party CDN with **no integrity checking**, then anyone who compromises that CDN can run their own code on the clinic's website, in every patient's browser. | 3 | 4 | **12** | A08 | 🔒 **Agency** | 4 | **3.0** |
| **W10** | If the site has **no security headers**, then attackers get free help framing fake content in the clinic's name, clickjacking the booking button, or MIME-confusing scripts. | 4 | 3 | **12** | A05 | 🔒 **[HOSTING] + Agency** | 4 | **3.0** |
| **W11** | If the shared hosting certificate keeps being used, then any **other** tenant's compromise on that infrastructure can affect this site, with no isolation between them. | 3 | 4 | **12** | A02 | 🔒 **[HOSTING]** | 4 | **3.0** |

### 5.4 SEO / ranking loss

| ID | Risk statement | L | I | Score | OWASP | Owner | Hrs | **RR/hr** |
|---|---|:-:|:-:|:-:|---|---|:-:|:-:|
| **E1** | If the site shows no professional credentials, no named dentist and no team page, then Google treats it as an unverified business — and Google has been pushing exactly this "show your credentials" signal for years. The clinic loses rankings to competitors who do show them. | 5 | 4 | **20** | — | **Clinic** + 🔒 Agency | 12 | **1.7** |
| **E2** | If **none** of the 17 pages has a meta description, then Google invents its own snippet from whatever text it finds — including the page's *stale booking calendar*. | 5 | 3 | **15** | — | 🔒 **Agency** | 4 | **3.8** |
| **E3** | If there is no structured data (LocalBusiness/Dentist schema), then the clinic cannot appear in Google's rich results — the map pack, the hours, the star rating — which is where most local dental searches actually convert. | 5 | 3 | **15** | — | 🔒 **Agency** | 3 | **5.0** |
| **E4** | If broken pages are served as **HTTP 200** instead of 404, then Google indexes them as real, distinct pages of the site. It spends crawl budget on duplicates, and the real content's rankings are diluted. | 5 | 3 | **15** | A05 | 🔒 **[HOSTING]** | 3 | **5.0** |
| **E5** | If every image has `alt=""` and none are lazy-loaded, then the site is invisible to Google Images (a real dental-search channel) and scores poorly on Core Web Vitals, which are a confirmed ranking factor. | 5 | 3 | **15** | — | 🔒 **Agency** | 5 | **3.0** |
| **E6** | If the booking calendar still says **"Febrero 2024"**, then a prospective patient sees a site that has not been maintained in two and a half years and goes to a competitor. | 5 | 3 | **15** | — | 🔒 **Agency** | 1 | **15.0** |
| **E7** | If the main call-to-action button does nothing on all 17 pages, then the clinic pays for traffic and converts none of it. | 5 | 3 | **15** | — | 🔒 **Agency** | 2 | **7.5** |
| **E8** | If the sitemap lists pages that do not exist (`/servicios/`, `/nosotros/`, `/protodoncia/`), then Google wastes crawl attempts and learns that this site's sitemap is unreliable. | 5 | 2 | **10** | A05 | 🔒 **Agency** | 2 | **5.0** |
| **E9** | If default WordPress pages (`/hello-world/`, `/sample-page/`) stay public, then Google — and any visitor — sees a half-finished site. | 4 | 2 | **8** | A05 | 🔒 **Agency** | 1 | **8.0** |

### 5.5 Legal / compliance

| ID | Risk statement | L | I | Score | OWASP | Owner | Hrs | **RR/hr** |
|---|---|:-:|:-:|:-:|---|---|:-:|:-:|
| **L1** | If the clinic keeps collecting sensitive health data with **no privacy notice anywhere**, then it is in clear breach of arts. 14, 15 and 16 LFPDPPP — an infraction under art. 58 fr. V, carrying a fine of up to **320,000 UMA ($37.5M MXN)**, doubled for sensitive data. | 5 | 5 | **25** | A02 | **Clinic** | 6 | **4.2** |
| **L2** | If a competitor or patient complains to the health authority, the clinic's advertising is unlawful for a reason that is **visible on every page**: no `Cédula`, no `Dra./Dr.`, no institution, no credentials. | 5 | 4 | **20** | — | **Clinic** | 3 | **6.7** |
| **L3** | If the clinic keeps advertising "sin dolor" and "resultados visibles desde el primer día", then it is advertising therapeutic and efficacy claims that are not scientifically verifiable — prohibited by Reglamento LGS arts. 6 fr. I and 18, and not *comprobable* under LGS art. 306 fr. I. | 4 | 4 | **16** | — | **Clinic** | 1 | **16.0** |
| **L4** | If patient data goes to a Google account in another country with no disclosed transfer clause, then the clinic breaches art. 35 LFPDPPP and art. 58 fr. X, even though the transfer itself is likely lawful under art. 36 fr. II. | 4 | 4 | **16** | A02 | Clinic + 🔒 Agency | 3 | **5.3** |
| **L5** | If the clinic cannot produce its health data on request, the fine is capped at ~$18.8M (art. 59 fr. II) — but far worse, **the practice may be ordered to stop processing immediately**, which halts all patient booking. | 4 | 5 | **20** | A01 | **Clinic** | 4 | **5.0** |
| **L6** | If the site advertises a price the front desk will not honour, then under **LFPC art. 50** the clinic owes the patient the economic difference **and** still owes the treatment. Publishing a price with no stated conditions makes it indefinite by presumption (art. 48 fr. I). | 2 | 3 | **6** | — | **Clinic** | 0 | *n/a — only if prices added* |

### 5.6 The register's shape, honestly

**39 rows. Total remediation effort ≈ 120 hours. 12 rows are 🔒 escalations the clinic cannot action alone, together worth 296 of the 624 aggregate risk points — the majority of the risk sits with [HOSTING] and the agency.**

**Top 10 by risk-reduction per hour (the actual work queue):**

| # | ID | Action | RR/hr |
|:-:|---|---|:-:|
| 1 | W2 / S2 / W3 / W4 / W7 | **PHP version check · admin password + MFA · cache purge · HTTPS redirect** | **20.0** |
| 2 | E6 | Fix the stale booking calendar | **15.0** |
| 3 | W8 | Disable TLS 1.0/1.1 | **15.0** |
| 4 | L3 | **Remove two sentences of prohibited claims** | **16.0** |
| 5 | S1 | Publish DMARC | **10.0** |
| 6 | S3 | Fix the three phone numbers | **10.0** |
| 7 | W1 / W5 / W6 / S7 | Patch WordPress · update Divi · fix placeholders · check D4 option | **10.0–12.0** |
| 8 | S4 | Disable author archives + REST users route | **8.0** |
| 9 | E7 | Fix the dead `href="#"` CTAs | **7.5** |
| 10 | P4 | Write the breach-notification procedure | **7.5** |
| 11 | L2 | Add `Cédula` and credentials | **6.7** |

**Five of the top eleven are free or near-free, take under an hour each, and either stop an ongoing harm or retire a certain legal violation.** That is the finding: **this site is not in trouble because of sophisticated attackers. It is in trouble because of small, cheap, unglamorous omissions that have accumulated.**

---

## 6. Remediation roadmap — 3 waves, ordered by risk-reduction per hour

### 🟥 WAVE 1 — DO TODAY (≈13 hours, clinic + 2 escalations)

*Stop ongoing harm. Nothing here waits for next month.*

| # | Action | Owner | Hrs | Retires |
|---|---|---|:-:|---|
| **1.1** | **Check the PHP version** (`Tools → Site Health → Info → Server`). If < 8.2 → escalate immediately (**Ticket A**). If < 8.3.36/8.2.35 → escalate as Critical (**Ticket A**). | Clinic → 🔒 [HOSTING] | **0.2** | W2 |
| **1.2** | **Change the WordPress admin password** to a unique, never-used-elsewhere value. Then again for every other account. | **Clinic** | **0.5** | S2, W4 |
| **1.3** | **Enable MFA** on all WordPress accounts. | **Clinic** | **0.5** | W4 |
| **1.4** | **Purge the full-page cache, then verify `/` returns a single WordPress version.** Repeat 3× over 24 h to confirm the multi-version defect is gone. **Update WordPress to 7.1.3 at the same time — purging without updating achieves nothing.** | 🔒 Agency + [HOSTING] (**Ticket B**) | **1.0** | W1, W3 |
| **1.5** | **Publish DMARC**: `_dmarc.[DOMINIO-CLIENTE]` → `v=DMARC1; p=none; rua=mailto:dmarc@[DOMINIO-CLIENTE]; pct=100`. Also add `CAA`. | Clinic (DNS) + 🔒 [HOSTING] | **1.5** | S1 |
| **1.6** | **Fix the HTTP→HTTPS redirect** (301, apex + `www`, both hosts → one canonical). | 🔒 **[HOSTING] (Ticket C)** | **1.0** | W7 |
| **1.7** | **Remove the two prohibited marketing claims** ("sin dolor", "resultados visibles desde el primer día"). Replace with clinically supportable wording. | **Clinic** | **1.0** | L3, S5 |
| **1.8** | **Publish a short interim aviso de privacidad** on a working URL (fix `/politica-de-cookies` → real page), and add a **consent checkbox + link** to the booking form naming Google as recipient and `motivo de consulta` as sensitive data. | **Clinic** | **2.0** | L1, L4, P1 (interim) |
| **1.9** | **Disable author archives + the REST users route.** | 🔒 Agency | **1.0** | S4, P3 |
| **1.10** | **Check the Divi "Force Enable D4 Shortcode Framework" setting** and turn it off unless actively needed. Also confirm no Divi Contributor+ accounts exist. | 🔒 Agency | **0.3** | S7 |
| **1.11** | **Fix the unreplaced placeholders** (`WHATSAPP_NUMBER`, `// 🔥 REEMPLAZAR URL APPSCRIPT`) and the dead `href="#"` CTAs on all 17 pages. | 🔒 Agency | **1.5** | W6, E7 |
| **1.12** | **Fix the booking calendar** (shows "Febrero 2024"). | 🔒 Agency | **0.5** | E6 |
| **1.13** | **Choose one canonical phone number.** Correct the homepage display + every `tel:`/`WhatsApp`; retire or clearly label the area-code-56 number. | **Clinic** | **1.5** | S3 |

**Wave 1 total ≈ 13 hours.** Eleven of thirteen are ₹1 or less *and* include the two highest RR/hr items in the whole register.

---

### 🟧 WAVE 2 — DO THIS MONTH (≈45 hours)

*Close the legal file and the infrastructure gaps. Mostly waits, escalations and drafting.*

| # | Action | Owner | Hrs | Retires |
|---|---|---|:-:|---|
| **2.1** | **Write the full aviso de privacidad** (integral + simplified) covering: identity/domicile, all data incl. sensitive, purposes, **Google transfer clause (art. 35)**, ARCO mechanism, retention periods, and change-notification. Have a Mexican lawyer review it. | **Clinic** (+ lawyer) | **4.0** | L1, L4, P1 |
| **2.2** | **Designate the data-protection contact** (LFPDPPP art. 29) and publish their details in the aviso. Build the **ARCO procedure** with a 20-business-day clock. | **Clinic** | **3.0** | P5, L5 |
| **2.3** | **Write the breach-notification procedure** (art. 19 — notify affected *patients*, immediately). Include the significance-assessment criterion and a notification template. | **Clinic** | **2.0** | P4 |
| **2.4** | **Add `Cédula`, `Dra./Dr.` name, issuing institution and specialty** to the homepage + every service page (LGS art. 83 + Reglamento art. 19). | **Clinic** | **3.0** | L2 |
| **2.5** | **Establish a retention policy** for the Apps Script data; get the clinic's records out of an uncontrolled Google account. **Best case:** move intake to a form + database the clinic owns. **Minimum case:** written confirmation from the Google account owner of ownership, access config, MFA and data-processing commitment. | Clinic + 🔒 Agency | **4.0** | P1, P3, P6 |
| **2.6** | **Update Divi 4.27.4 → 4.27.9** (minimum) or migrate to Divi 5.12.0+ (clears `CVE-2026-91707` too). | 🔒 Agency | **1.5** | W5 |
| **2.7** | **Disable TLS 1.0 and 1.1**; leave 1.2/1.3 only. | 🔒 **[HOSTING]** | **1.0** | W8 |
| **2.8** | **Fix the caching defect:** exclude all non-200/2xx responses from cache at both nginx and Apache. Purge. | 🔒 **[HOSTING] (Ticket B)** | **3.0** | E4, W3 |
| **2.9** | **Add security headers** at the edge: `Strict-Transport-Security` (max-age ≥ 31536000; includeSubDomains), `Content-Security-Policy` (report-only first), `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`. | 🔒 [HOSTING] + Agency | **4.0** | W10 |
| **2.10** | **Move to a dedicated certificate** for `[DOMINIO-CLIENTE]` (drop `CN=[CERT-CN-COLATERAL]` and the agency's SANs). Enable **OCSP stapling**. |🔒 **[HOSTING] + Agency** | **4.0** | S6, W11 |
| **2.11** | **Add SRI** to all cdnjs-loaded assets (jQuery, GSAP, ScrollToPlugin, FontAwesome), or self-host. Consolidate FontAwesome to a single version. | 🔒 Agency | **3.0** | W9 |
| **2.12** | **Write meta descriptions for all 17 URLs**; add `DentalClinic`/`LocalBusiness` JSON-LD; fix the 133-char homepage title; add canonical + OG/Twitter tags. | 🔒 Agency | **5.0** | E2, E3 |
| **2.13** | **Delete or unlist the WP defaults** — `/hello-world/`, `/sample-page/`, `/category/uncategorized/`, `/author/[USUARIO-1]/`; remove broken sitemap entries (`/servicios/`, `/nosotros/`, `/protodoncia/`). | 🔒 Agency | **2.0** | E8, E9, S4 |
| **2.14** | **Block `xmlrpc.php`** at the edge (405/403), except if Jetpack or the mobile app is genuinely used. | 🔒 [HOSTING] | **0.5** | W1 (reduces surface) |
| **2.15** | **Uniform NAP:** publish one canonical phone/address block; verify Google Business Profile, Apple Maps and Mexican directories. | **Clinic** | **2.0** | S3 |
| **2.16** | **Upgrade DMARC** `p=none → p=quarantine → p=reject`** once rua reports confirm all legitimate senders; **tighten SPF `~all → -all`**; add DKIM for every sending service, not one selector. | Clinic + 🔒 [HOSTING] | **2.0** | S1 |
| **2.17** | **Add MFA + MTA-STS + TLS-RPT** for the `[DOMINIO-CLIENTE]` mail domain; consider BIMI. | Clinic + 🔒 [HOSTING] | **3.0** | S1 |

**Wave 2 total ≈ 45 hours.**

---

### 🟩 WAVE 3 — DO THIS QUARTER (≈62 hours)

*Build the durable position: authority signals, performance, and contractual control over the agency.*

| # | Action | Owner | Hrs | Retires |
|---|---|---|:-:|---|
| **3.1** | **Build the E-E-A-T layer** (highest remaining score, 20): named dentist page with photo, full `Cédula` + institution + specialty, professional bio, a real `/nosotros/`, a services hub at `/servicios/`, an FAQ, and 6–10 genuinely useful blog posts. This is the single largest SEO and trust investment available. | **Clinic** (+ Agency) | **14.0** | E1 |
| **3.2** | **Fix the image layer:** meaningful `alt` text on all images, convert PNGs to WebP/AVIF, add `<picture>` with responsive sizes, enable lazy-loading, add `width`/`height` to prevent layout shift, and consolidate the **63 `@font-face` blocks** (9 weights × 2 families, no `unicode-range`) down to 3–4 weights with `unicode-range`. Targets Core Web Vitals. | 🔒 Agency | **8.0** | E5 |
| **3.3** | **Add an AI-crawler policy** to `robots.txt` (an explicit allow/deny for GPTBot, ClaudeBot, PerplexityBot etc. — a *business* decision about AI search visibility, **not** a security control). | 🔒 Agency | **1.0** | — |
| **3.4** | **Put claim approval in the agency contract.** Per LGS art. 305 the agency is itself a regulated party. Contractually require that all therapeutic/marketing claims be submitted to and approved in writing by the clinic's licensed dentist before publication. | **Clinic** (+ lawyer) | **2.0** | L3, L2 |
| **3.5** | **Establish a monthly security review:** patch cadence confirmation, plugin/theme inventory, `Tools → Site Health`, and a re-run of this passive check. Document who owns what. | **Clinic** + Agency | **2.0/quarter** | W1, W3 (recurrence) |
| **3.6** | **Consider moving off shared hosting** to managed WordPress or a dedicated VPS with a WAF, as a structural fix for W2, W11 and the cache defect. Get 2–3 quotes. | **Clinic** | **6.0** | W2, W11, W3 |
| **3.7** | **MFA + least-privilege review of WordPress:** remove all unused accounts and plugins; confirm no account other than the owner can install themes/plugins. | Clinic + 🔒 Agency | **3.0** | W4 |
| **3.8** | **Backup and recovery plan:** automated backups, a **tested** restore, and confirmation that the backup is **not** inside the web root (addresses WSTG-CONF-04, *Review Old Backup and Unreferenced Files*). | 🔒 [HOSTING] + Agency | **4.0** | W1 (recovery) |
| **3.9** | **Patient-communication plan:** in-clinic signage + a page telling patients to distrust any email or WhatsApp asking for appointment confirmation, with the clinic's canonical number and domain shown. Directly mitigates S1 and S3. | **Clinic** | **3.0** | S1, S3, S5 |
| **3.10** | **Legal counsel review** of: the aviso de privacidad, the Google transfer basis (art. 36 fr. II), the retention policy, the before/after image-release practice (§4.7), and whether to publish prices (§4.6). | **Clinic** (+ lawyer) | **6.0** | L1, L4, L5, P6 |
| **3.11** | **Resolve the ScrollToPlugin version** (unknown) and add it to the asset inventory; confirm no CVE exposure once the version is known. | 🔒 Agency | **1.0** | open item (§2.5) |
| **3.12** | **Re-run this passive assessment** after Wave 1 and Wave 2 and compare. | Consultant | **4.0** | verification |

**Wave 3 total ≈ 62 hours.**

---

### 6.1 What the clinic genuinely cannot fix alone — consolidated

| # | Item | Sole owner | Ticket |
|:-:|---|---|:-:|
| 1 | PHP version + upgrade to ≥ 8.3.36 / 8.2.35 | **[HOSTING]** | **A** |
| 2 | Full-page cache purge + non-2xx exclusion from cache | **[HOSTING]** (+ Agency) | **B** |
| 3 | HTTP→HTTPS redirect | **[HOSTING]** | **C** |
| 4 | TLS 1.0/1.1 disable | [HOSTING] | C (append) |
| 5 | Security headers at the edge | [HOSTING] (+ Agency) | C (append) |
| 6 | Dedicated certificate + OCSP stapling | **[HOSTING]** (+ Agency) | C (append) |
| 7 | `xmlrpc.php` block | [HOSTING] | C (append) |
| 8 | DMARC / SPF / DKIM DNS records | [HOSTING] (DNS) + Clinic | A (append) |
| 9 | WordPress core patching | **Agency** (+ [HOSTING] access) | **B** |
| 10 | Divi update + D4 option check | **Agency** | **B** |
| 11 | REST users route / author archives | Agency | B |
| 12 | SRI, images, JSON-LD, meta descriptions | Agency | B |
| 13 | Google Apps Script ownership + access config | **Agency / Google account owner** | **B** |
| 14 | Shared-certificate SAN exposure | **Agency** + [HOSTING] | **C** |

---

## 7. Escalation ticket drafts — ready to send

> Three tickets. **A** is urgent (do not wait). **B** is a scope-of-work request to the agency. **C** is a hosting request.
> Replace `[TU NOMBRE]`, the ticket numbers and dates before sending.

---

### 🟥 TICKET A — [HOSTING]: PHP EMERGENCY + DNS AUTHENTICATION

**Asunto:** CRÍTICO – Actualización urgente de PHP (CVE-2026-109618 / CVE-2026-109619) y configuración DNS de autenticación de correo – cuenta `[DOMINIO-CLIENTE]`

```
Estimado equipo de soporte de [HOSTING] México:

Reporto un problema de seguridad crítico y urgente en nuestra cuenta de hosting
para el dominio [DOMINIO-CLIENTE] (IP [IP-SERVIDOR]).

ESTADO: Crítico – solicitamos respuesta en menos de 24 horas.

1) ACTUALIZACIÓN DE PHP (URGENTE)

El 21 de octubre de 2026 el proyecto PHP publicó un aviso de seguridad que
corrige dos vulnerabilidades CRÍTICAS de ejecución remota de código sin
autenticación:

  CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) – CVSS v4.0 9.2 – RCE por corrupción
                                          de memoria durante OOM
  CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) – CVSS v4.0 9.2 – RCE por estado
                                          global obsoleto entre peticiones

Versiones corregidas: PHP 8.5.12, 8.4.27, 8.3.36 y 8.2.35.
Afecta a cualquier instalación de PHP que atienda peticiones web. El riesgo es
mayor con mod_php. WordPress publicó ayer un aviso equivalente.

SOLICITO:
  a) ¿Qué versión de PHP ejecuta actualmente nuestro sitio? (WordPress →
     Herramientas → Salud del sitio → Información → Servidor, o desde su panel.)
  b) Actualización inmediata a la versión corregida más reciente disponible.
  c) Si no es posible actualizar de inmediato, solicitamos que implementen reglas
     de WAF mitigantes y que nos confirmen cuáles.
  d) Confirmación por escrito de la versión final aplicada.

Nota: PHP 8.2 alcanza su fin de vida el 31 de diciembre de 2026. Si estamos en
8.2 o inferior, solicitamos además una cotización para migrar a PHP 8.4 u 8.5.

2) REGISTROS DNS DE AUTENTICACIÓN DE CORREO

Revisando la configuración actual de [DOMINIO-CLIENTE] encontramos:

  SPF     v=spf1 include:spf.[HOSTING-MX] ~all     (existe; softfail)
  DKIM    presente únicamente en el selector "default"
  DMARC   AUSENTE
  BIMI    AUSENTE
  MTA-STS AUSENTE
  TLS-RPT AUSENTE
  CAA     AUSENTE

La ausencia de registro DMARC permite que cualquier persona envíe correo que
aparenta provenir de @[DOMINIO-CLIENTE] y que los servidores receptores no estén
obligados a revisar ni a rechazar esos mensajes. Esto expone a nuestros pacientes
a phishing.

SOLICITO que agreguen en nuestra zona DNS:

  _dmarc.[DOMINIO-CLIENTE].  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@[DOMINIO-CLIENTE]; pct=100; adkim=s; aspf=s"

  [DOMINIO-CLIENTE].          CAA 0 issue "letsencrypt.org"

Comenzamos con p=none (solo monitoreo, no rechaza ningún correo legítimo). Tras
dos a cuatro semanas de revisión de los reportes, elevaremos a p=quarantine y
posteriormente a p=reject, y endureceremos el SPF de ~all a -all.

También solicitamos agregar los registros MTA-STS y TLS-RPT cuando esté disponible
su configuración en su panel.

3) REDIRECCIÓN HTTP -> HTTPS

SOLICITO una redirección permanente (301) de http:// a https:// tanto para
[DOMINIO-CLIENTE] como para www.[DOMINIO-CLIENTE], consolidating en un solo dominio
canónico. Actualmente las cuatro combinaciones de esquema y host sirven contenido
idéntico con HTTP 200, sin redirección.

Agradezco su atención inmediata.

Saludos cordiales,
[TU NOMBRE]
[CARGO]
[CLIENTE / NOMBRE DE LA CLÍNICA]
Teléfono: [TELÉFONO]
Correo: [CORREO]
```

---

### 🟧 TICKET B — WEB AGENCY: PATCHING, CACHE, THEME, AND DATA PROCESSING

**Asunto:** Solicitud de alcance de trabajo – Correcciones de seguridad y cumplimiento en [DOMINIO-CLIENTE] (WordPress, Divi, caché, Google Apps Script)

```
Estimado equipo de [NOMBRE DE LA AGENCIA]:

Realizamos una revisión de seguridad pasiva (sin pruebas intrusivas) del sitio
[DOMINIO-CLIENTE] y necesitamos su apoyo para corregir los hallazgos que requieren
acceso al servidor y al código. A continuación detallo los puntos, la evidencia
y el resultado esperado de cada uno.

A) ACTUALIZACIÓN DE WORDPRESS Y PURGA DE CACHÉ  — URGENTE

HALLAZGO: El sitio está sirviendo seis versiones de WordPress distintas de forma
simultánea desde la caché de página completa (6.8.1, 6.8.2, 6.8.3, 6.9, 7.0.3 y
7.1.3), confirmadas en el campo <meta name="generator"> de distintas páginas.
Esto indica que la caché no se purga tras las actualizaciones.

RIESGO: Cinco de esas seis versiones están dentro del rango afectado de la
vulnerabilidad CVE-2026-87902 / GHSA-7hp8-65ch-5whp (CVSS v4.0 9.2, CRÍTICA),
que permite ejecución remota de código SIN AUTENTICACIÓN. El advisory es de
WordPress.org y la corrección está en 6.8.10, 6.9.9, 7.0.6 y 7.1.2.

  Afectadas:  6.8.1  6.8.2  6.8.3  6.9  7.0.3
  No afecta:  7.1.3 (ya corregida)

ADEMÁS, se publicó ayer una vulnerabilidad CRÍTICA de ejecución remota sin
autenticación en PHP (CVE-2026-109618 y CVE-2026-109619, ambas CVSS 9.2). El
sitio debe ejecutar una versión de PHP corregida (8.5.12 / 8.4.27 / 8.3.36 /
8.2.35). Solicitamos confirmar la versión con la que corre el sitio.

SOLICITO:
  1. Confirmar la versión de PHP en producción y, si es anterior a las
     corregidas, solicitamos su actualización inmediata.
  2. Actualizar WordPress a 7.1.3 (o la última estable disponible).
  3. PURGAR LA CACHÉ DE PÁGINA COMPLETA DESPUÉS de la actualización. Sin la
     purga, el sitio seguirá entregando las versiones vulnerables.
  4. Corregir la configuración para que la caché excluya TODAS las respuestas
     distintas de 200/2xx. Actualmente las respuestas 404 se almacenan y se
     re-sirven con código 200 ("soft 404"), lo que comprobamos así:

       GET /soft404-proof-<aleatorio>/   ->  404  (correcto)
       GET /soft404-proof-<aleatorio>/   ->  200  (incorrecto, desde caché)
       GET /soft404-proof-<aleatorio>/   ->  200  (incorrecto, desde caché)

     Páginas reales afectadas: /servicios/, /nosotros/, /protodoncia/ y
     /politica-de-cookies.

  5. Verificar durante 72 horas que / devuelve una sola versión de WordPress.

B) TEMA DIVI

HALLAZGO: El sitio sirve dos versiones del tema Divi: 4.27.4 y 4.27.7.

La versión 4.27.4 (publicada el 25-nov-2024) está dentro del rango afectado de
seis vulnerabilidades con CVE asignado, cuatro de ellas corregidas en 4.27.7:
  CVE-2026-3850, CVE-2026-3851, CVE-2026-3852, CVE-2026-3853 (XSS almacenada)
  CVE-2026-4361 (SSRF)
La versión 4.27.7 corrige esos cinco problemas, pero sigue dentro del rango de
CVE-2026-91707, que afecta a Divi hasta 5.11.1 y permite a un atacante NO
AUTENTICADO ejecutar shortcodes arbitrarios.

SOLICITO:
  1. Actualizar Divi 4.27.4 a 4.27.9 como mínimo.
  2. Verificar en el Panel de Divi si la opción "Force Enable D4 Shortcode
     Framework" está activada. Si lo está y no es estrictamente necesaria,
     desactivarla: con ella, CVE-2026-91707 permite enviar correos desde el
     dominio de la clínica ( phishing que incluso pasaría DMARC).
  3. Si es viable, planificar la migración a Divi 5.12.0 o superior, que corrige
     CVE-2026-91707.
  4. Confirmar que no existen cuentas con rol Contributor o superior que no sean
     del administrador del sitio.

C) EXPOSICIÓN DE USUARIOS

HALLAZGO: /wp-json/wp/v2/users responde 200 y expone id=1, slug=[USUARIO-1],
name=[USUARIO-1]. La portada /author/[USUARIO-1]/ está activa y en el
sitemap.

SOLICITO:
  1. Desactivar los archivos de autor (author archives).
  2. Desactivar la ruta REST /wp-json/wp/v2/users (por ejemplo, con el filtro
     rest_endpoints).
  3. Eliminar del sitemap /author/[USUARIO-1]/.
  4. NO es necesario investigar el hash de Gravatar asociado. El tratamiento
     correcto es eliminar la exposición, no confiar en que el hash no se rompa.

D) PLACEHOLDERS SIN REEMPLAZAR EN PRODUCCIÓN

HALLAZGO: El JavaScript de reservas contiene sin sustituir:
  - WHATSAPP_NUMBER = '[TELEFONO-PLACEHOLDER]'
  - comentario:  // 🔥 REEMPLAZAR URL APPSCRIPT
Y el botón principal "AGENDAR CITA" es href="#" en las 17 páginas del sitio.

SOLICITO: sustituir ambos valores por los reales y enlazar correctamente el CTA
principal en las 17 páginas. Solicitamos además un procedimiento de verificación
pre-publicación que detecte marcadores de posición antes de subir a producción.

E) CALENDARIO Y CONTENIDO

HALLAZGO: /agendar-cita/ muestra <h3 id="current-month">Febrero 2024</h3>, es
decir, el calendario lleva aproximadamente dos años y ocho meses desactualizado.

SOLICITO: corregir la lógica del calendario y verificar que se actualice
automáticamente.

F) GOOGLE APPS SCRIPT — DATOS DE PACIENTES  — URGENTE

HALLAZGO: El formulario de citas envía nombre, correo, teléfono, servicio,
fecha, hora y "motivo de consulta" a una URL pública de Google Apps Script del
tipo /exec. No existe aviso de privacidad en el sitio ni casilla de consentimiento.
La única liga legal del sitio, /politica-de-cookies, es un soft-404.

Este dato ("motivo de consulta") es un dato personal SENSIBLE conforme al
artículo 2, fracción VI de la Ley Federal de Protección de Datos Personales en
Posesión de los Particulares (LFPDPPP, DOF 20-mar-2025). La sanción por
incumplimiento del aviso de privacidad puede alcanzar 320,000 UMA
($37,539,200 MXN con la UMA 2026 de $117.31), y hasta el doble por tratarse de
datos sensibles.

SOLICITO:
  1. Informar quién es el titular de la cuenta de Google que hospeda el
     despliegue.
  2. Confirmar la configuración de acceso del despliegue (quién puede ejecutarlo:
     cualquiera, usuarios del dominio, o solo el propietario).
  3. Confirmar si la cuenta tiene autenticación en dos pasos activada.
  4. Idealmente, migrar el formulario a infraestructura que la clínica controle.
     Como mínimo, confirmar por escrito que existe una relación de encargado y
     un compromiso de protección de datos personales.

G) OTROS ASPECTOS DE LA WEB (cotización separada)

  - Metadatos: las 17 URL carecen de meta description; falta JSON-LD de tipo
    DentalClinic/LocalBusiness; el título de la portada excede los 120
    caracteres y falta canonical en la portada.
  - Imágenes: el 100 % de las imágenes tiene alt="" y ninguna usa carga diferida;
    hay 63 declaraciones @font-face (9 pesos × 2 familias) sin unicode-range.
  - Seguridad de recursos: no hay Subresource Integrity (SRI) en los recursos
    cargados desde cdnjs (jQuery, GSAP, ScrollToPlugin, FontAwesome).
  - Páginas por defecto: /hello-world/, /sample-page/ y /category/uncategorized/
    están públicas y en el sitemap.
  - Cerramos 5 hallazgos sin costo el 22-oct-2026 (retiro de dos afirmaciones de
    marketing, alta de aviso de privacidad, corrección de tres teléfonos
    inconsistentes). Les agradeceremos documentar estos cambios en un acta de
    entrega, ya que forman parte de nuestro cumplimiento.

Solicitamos una cotización por los puntos A a F con prioridad, y una propuesta
de calendario. Los puntos A y F son urgentes.

Saludos,
[TU NOMBRE]
[CARGO] — [NOMBRE DE LA CLÍNICA]
Teléfono: [TELÉFONO]
Correo: [CORREO]
```

---

### 🟨 TICKET C — [HOSTING]: TLS, CERTIFICATE, HEADERS, REDIRECTS

**Asunto:** Configuración de TLS, certificado, cabeceras de seguridad y redirección – [DOMINIO-CLIENTE]

```
Estimado equipo de soporte de [HOSTING] México:

 continuamos el reporte de seguridad del dominio [DOMINIO-CLIENTE] (IP
[IP-SERVIDOR]). Además de la solicitud de actualización de PHP y DNS (que
enviamos por separado), solicitamos los siguientes ajustes de configuración.

1) CERTIFICADO TLS DEDICADO  — IMPORTANTE

HALLAZGO: El certificado en uso es un Let's Encrypt de 90 días compartido entre
múltiples sitios, cuyo Common Name es:

    CN = [CERT-CN-COLATERAL]

y cuyas listas SAN incluyen dominios de otros clientes de nuestra agencia
web, entre ellos un servidor de pruebas (staging):
    [SEDE-STAGING]

Esto significa que cualquier persona que consulte el certificado de nuestro
sitio obtiene la lista completa de marcas de nuestro proveedor. Un solo
certificado compartido aumenta además el radio de impacto si algún otro
inquilino de esa infraestructura se ve comprometido.

SOLICITO:
  a) Instalar un certificado dedicado para [DOMINIO-CLIENTE] cuyo CN o SAN sea
     únicamente [DOMINIO-CLIENTE] / www.[DOMINIO-CLIENTE], sin dominios de terceros.
  b) Habilitar el stapling de OCSP para ese certificado.
  c) Confirmar por escrito que [DOMINIO-CLIENTE] ya no está empaquetado en un
     certificado compartido con otros clientes.

2) VERSIONES DE TLS  — IMPORTANTE

HALLAZGO: El servidor acepta TLS 1.0 y TLS 1.1, protocols que están
obsoletizados y considerada inseguros.

SOLICITO: habilitar únicamente TLS 1.2 y TLS 1.3, y deshabilitar TLS 1.0, 1.1 y
cualquier cifrado obsoleto. Si algún cliente antiguo lo requiere, les avisaremos
con anticipación.

3) REDIRECCIÓN HTTP -> HTTPS  — IMPORTANTE

HALLAZGO: No existe redirección de http:// a https://. Actualmente las cuatro
combinaciones de esquema y host (http/https × apex/www) sirven el mismo
contenido con código 200.

SOLICITO: una redirección permanente (301) de http:// a https:// para
[DOMINIO-CLIENTE] y www.[DOMINIO-CLIENTE], consolidando en un solo dominio canónico
(recomendamos [DOMINIO-CLIENTE] sin www).

4) CABECERAS DE SEGURIDAD HTTP

HALLAZGO: El sitio no devuelve ninguna cabecera de seguridad. Las pruebas
automáticas (Mozilla Observatory) fallaron 6 de 12 verificaciones.

SOLICITO añadir en el borde (nginx). Para evitar cualquier riesgo de romper el
sitio, el Content-Security-Policy puede instalarse primero en modo report-only:

    Strict-Transport-Security: max-age=31536000; includeSubDomains
    X-Frame-Options: SAMEORIGIN
    X-Content-Type-Options: nosniff
    Referrer-Policy: strict-origin-when-cross-origin
    Permissions-Policy: geolocation=(), microphone=(), camera=()

    Content-Security-Policy: report-only
    (se instalará en modo report-only para no romper el sitio; se migrará a
     modo bloqueante una vez revisados los reportes)

Agradecemos confirmación por escrito de qué se aplicó.

5) BLOQUEO DE XMLRPC

HALLAZGO: /xmlrpc.php responde 405 en GET, lo cual es positivo, pero el
método POST sigue habilitado en la misma URL.

SOLICITO: bloquear xmlrpc.php en el borde con 403, salvo que necesitemos
utilizar Jetpack o la aplicación móvil de WordPress, en cuyo caso indíquenoslo
para configurarlo de forma segura.

6) MENSAJE DE CIERRE

Agradecemos su apoyo. Se trata de un consultorio dental; los datos que circulan
por el sitio incluyen información de salud de pacientes. Los puntos 2, 3 y 4 son
cambios de configuración de bajo riesgo que mejoran la seguridad de forma
significativa.

Saludos cordiales,
[TU NOMBRE]
[CARGO] — [NOMBRE DE LA CLÍNICA]
Teléfono: [TELÉFONO]
Correo: [CORREO]
```

---

## 8. One-page plain-language security brief for the clinic owner

> *Print this. Hand it to the dentist. No jargon.*

---

# Your website: a plain-language security summary

**Prepared for the clinic owner · 22 October 2026 · Read time: 5 minutes**

## Why we're writing to you

We reviewed your website without doing anything intrusive — we only looked at
what anyone on the internet can see. We found **no sign that your site has been
hacked.** What we found is that several inexpensive protections are missing, and
that two of them are things you can fix today for free. Most importantly, one
piece of missing paperwork is a **legal problem, not a technical one**, and it
costs nothing to start fixing.

---

## 1. "Mozilla says our site is grade F" — what does that actually mean?

Mozilla runs a free public check of website safety. Your site scored **5 out of
100 (grade F)**, failing 6 of 12 checks.

**What those six checks are:** Force visitors to use the secure version (HTTPS),
tell browsers "never talk to this site unencrypted in future" (HSTS), stop other
sites framing yours (clickjacking protection), stop browsers guessing file
types, stop third-party scripts changing without permission, and lock the site's
script rules.

**In plain terms:** these are the equivalent of **not locking your clinic's front
door, not having a security camera, and not checking who the visitors are.**

**Is this an emergency? No.** Grade F is a bad mark on a website — the same way a
poor driving test score is a bad mark. It does **not** mean someone has broken
into your site. It means the basics that protect your patients' information are
not switched on.

**The good news:** most of these are one-time settings your web host can change
in about an hour, at no cost. We have written the support ticket for you.

---

## 2. "Anyone can pretend to be us in an email" — the DMARC problem

This is the one we most want you to understand, because it directly targets
**your patients**.

**Your website's email system has no "signature check" instruction installed.**

Think of it like a letter. Anyone can write "From: [CLIENTE], [DIRECCION-CLIENTE]" on an
envelope. Your mail server, when it *does* sign its own real mail, produces a
seal that recipients can verify.

**You have the seal. You don't have the rule that says "if the seal doesn't check
out, throw the letter away."** And the seal is only on **one** of your sending
services.

**So what can happen?** A criminal registers a domain they control. They send
your patients an email that appears to come from your clinic:

> *"[CLIENTE] — Su cita está confirmada. Jueves 24, 11:00. Confirme aquí."*

Their email is legitimately signed — by *them*. Your patients see your clinic's
name and address. **Because there is no DMARC instruction, their mail servers
have no rule telling them to notice the mismatch.** The mail arrives. It looks
real.

This is not a hypothetical — appointment-confirmation phishing is one of the most
common scams targeting dental clinics, precisely because people are used to
receiving appointment emails.

**Cost and effort to fix: about 2 hours, no cost.** We have written the exact DNS
instructions. We start in "watch only" mode so nothing legitimate is blocked,
then tighten after a few weeks.

**One thing that makes this more urgent for you specifically:** your booking
calendar still displays **"February 2024."** A patient who books and then gets no
confirmation email has already been trained to expect one. That is exactly when
people click.

---

## 3. "Patients' health information goes to a Google account" — the part that concerns us most

**This is the most important paragraph in this document.**

Your appointment form asks for a patient's name, email, phone, the service they
want, the date, **and the reason for their visit.**

The "reason for their visit" is **health information.** In Mexico, under the
2025 data-protection law, health information is legally classified as
**"datos personales sensibles"** — the most protected category there is.

**Where does that information go?** It is sent to a **Google Apps Script
web address** that is embedded in your public website code. In plain terms: the
clinic's patient records — names, phone numbers, and what is wrong with their
teeth — are being typed into **a spreadsheet inside somebody's Google account.**

**Three things are wrong with this:**

1. **Your patients were never told.** There is no privacy notice anywhere on your
   website. The only link that looks like a legal page — "Política de cookies" —
   **is broken.** It goes to an error page. So a patient fills in their health
   details without ever being told where they go or who can see them.

2. **There is no "yes, I agree" checkbox.** Under Mexican law, collecting health
   information requires the patient's **written agreement**. There isn't one.

3. **We don't know who owns that Google account.** If it belongs to your web
   agency rather than to you, then your patients' health records sit inside a
   company you don't control — and you can't answer a patient's question about
   them. That is a problem regardless of anyone's intentions.

**Why this matters more than the technical bugs:** the Mexican data-protection
law (LFPDPPP, in force since March 2025) allows fines of up to **320,000 × the
daily economic unit**, which at current rates is about **$37.5 million pesos** —
and **double that** because the data is health data. We cannot predict what any
authority would actually impose for a small clinic; the law also instructs
officials to consider your business's size. But that number is what the statute
says, and it is what would appear in a demand letter.

**There's also a separate risk that has nothing to do with fines:** the people
responsible for handling patient data can face **3 months to 3 years in prison**,
doubled for health data, if they cause a security breach to the databases in their
care. That exposure falls on the clinic's owners.

**The fix, in order of cost:**
- **Today, free:** publish a real privacy notice on a working page, and add a
  consent checkbox to the booking form that names Google as the recipient and
  identifies "reason for consultation" as sensitive health data. **This alone
  removes the clearest legal violation.**
- **This month:** write the full notice, name a person responsible for data
  protection, and build a simple procedure to answer patient requests.
- **This month:** find out who owns the Google account and either take the data
  back or get written assurances.

---

## 4. Two sentences on your website could get you into trouble

Your website currently says:

- *"Tratamientos **sin dolor**"* (painless treatments)
- *"**Resultados visibles desde el primer día**"* (visible results from day one)

**These are not marketing opinions — they touch Mexican health-advertising law.**

The regulation that governs advertising by dentists says (Article 6, Section I)
that advertising may **not** attribute "preventive, therapeutic or
rehabilitative qualities" that do not correspond to the actual service. Article
18 goes further: it will not authorise advertising that offers treatments
**"whose effectiveness has not been scientifically proven."**

Treatments are genuinely not always painless — pain depends on the procedure and
the patient. And a guaranteed timeline for visible results is not something a
clinician can scientifically verify, because outcomes vary per patient.

**We are not saying anyone will come after you.** The realistic risk is low.
But the realistic consequences are: (a) a complaint to the health authority,
which is more likely to come from a competitor than from a patient; (b) a patient
who feels misled using these promises to argue a complaint; and — the one that
worries us most — (c) **a scammer can quote your own website back at a victim.**
"I've seen it on their site — they say painless." Your own marketing, written
casually, becomes someone else's sales script.

**The fix takes about one hour.** Rewrite the meta description to something
accurate and still appealing — for example, mention the anaesthesia options and
comfort measures, rather than promising zero pain. Delete the "day one" timing
claim and, if you want to convey speed, talk about **process** rather than
**outcome**: *"Your consultation and treatment plan in a single appointment."*

**This is the single best hour of work in this entire report.** It improves your
legal position, your credibility with patients, and your resistance to being used
in a scam — all at once.

---

## 5. "Your dentist's licence is missing from your own website"

Mexican health law (**Article 83 of the Ley General de Salud**) is explicit:

> *"Those who carry out professional activities … shall keep on public display
> an announcement indicating the institution that issued their title, **their
> professional licence number**, and, where applicable, their current Speciality
> Certificate. **Identical particulars must be shown in the advertising they
> carry out.**"*

The implementing regulation (**Article 19**) repeats it and adds: *"in whatever
advertising medium is used."*

**Your website currently shows no licence number, no issuing institution, no
"Dr./Dra." and no named dentist anywhere on any of the 17 pages.**

That is a clear violation, and it is one of the cheapest to fix — roughly three
hours. It also happens to be one of the strongest things you can do for how Google
ranks you: for years Google has been asking health and local businesses to
*demonstrate who is behind them*, and a site showing a verifiable licence is
trusted and ranked better than one showing none.

**So the same three hours fix a legal problem and a marketing problem.** That is
a good trade.

---

## 6. What happens if someone does hack the site

This is the scenario you asked about. Here is the honest picture.

**Your website is not just a brochure — it is the front door to a control panel.**
Behind `[DOMINIO-CLIENTE]` there is a WordPress administrator account. Once someone is
inside that panel, they can change anything on your site: the phone numbers
patients call, the prices, the services listed, and the content of your legal
pages. They could replace it entirely with a convincing copy that collects
patients' details and sends them elsewhere. Restoring it would take days and money.

**Three things make that risk worse than it needs to be:**

**1. Your site is running old software.** Your website's cache is currently
serving **six different versions of the WordPress system at once**. Five of them
are old enough to contain a **critical security flaw published last month that
lets an attacker take over a website without needing a password.** We verified
this against the official WordPress security advisories.

The good news: someone *did* update the site — the newest version is in there.
The bad news: **the update never reached the cache**, so visitors — and attackers
— are still being served the old versions. Updating without purging the cache
would not have fixed it. We have written the ticket.

**2. Your username is published on your website.** Your WordPress administrator
username appears openly in a public web address. That removes the hardest part of
any online guessing attack. **Today's action item: change the password, and set up
two-factor authentication (a code on your phone when you log in). One hour. This
is the single highest-value hour in this document.**

**3. Your hosting certificate advertises your web agency's other clients.** The
security certificate on your site is shared, and its technical contents list
**other companies' domains** — including a test/staging server. That is a free,
accurate target list for anyone planning to attack your agency. We have requested
a dedicated certificate for your site.

**We want to be clear about one more thing.** Yesterday — 21 October 2026 — the
PHP programming language that runs websites like yours released **emergency
security fixes for two critical remote-code-execution flaws** that affect any
website. We cannot see your server's PHP version from outside, so we do not know
whether you are affected. **We have asked your host to confirm and update it.**
This is a "check, don't panic" item, but it needs to be checked today.

---

## 7. Your phone numbers are an open door for scammers

Your website lists **three different phone numbers**, and one of them is in area
code **56 (State of Mexico)** even though the clinic is in **[DIRECCION-CLIENTE], Mexico
City (area code 55)**. On the homepage it is worse: the number **shown to
visitors is not the number the buttons actually dial.**

**How this helps a criminal:** a scammer who phones a patient can say *"I can
give you the number from their website"* and read out your **real, genuine**
number. That single detail makes a fake call sound completely authentic.

And it removes the one defence your patient has: *"I'll hang up and call them
myself."* If your own website gives three different answers, the patient who
checks may reach a different line, or may decide the site is unreliable — and
trust the caller more. **Your own inconsistency has disarmed your patients' best
protection.**

**The fix is about two hours and costs nothing.** Pick one number. Make sure the
number you *display* is the number your buttons *dial*, everywhere. Retire the
area-code-56 number or label it clearly with its purpose and address. Check that
Google Maps, Apple Maps, and Mexican business directories all show the same
details.

---

## 8. What we are asking you to do

### Today — about 4 hours of your time

| | What | Why |
|---|---|---|
| ☐ | **Change the WordPress password.** Make it different from every other password you use. | Your username is already published on your site. |
| ☐ | **Turn on two-factor authentication** for the website. | Makes a stolen password useless. |
| ☐ | **Send the three support letters** at the end of the technical report. | We wrote them for you — you can send them as-is. |
| ☐ | **Approve removal of the two marketing claims.** | One hour. Biggest legal and reputational win available. |
| ☐ | **Publish a short privacy notice** on a working page and add a consent checkbox to the booking form. | Removes the clearest legal violation. |
| ☐ | **Choose one phone number** and make the site consistent. | Closes a scammer's easiest opening. |

### This month

- Full privacy notice, written and reviewed by a lawyer
- Add your licence number and credentials to the website
- Move the patient form off the shared Google account — or find out who owns it
- Update the theme and the website software, and **purge the cache afterwards**
- Fix the booking calendar (still showing February 2024)
- Fix the "Book appointment" button (currently does nothing on all 17 pages)
- Add a security licence for your domain's email so fake emails get rejected

### This quarter

- Build the trust layer: a real "About / Our Team" page with your photo and
  licence, a services overview, and a handful of genuinely useful articles
- Faster, better images
- A written agreement with your web agency requiring that **you approve all
  marketing claims in writing before they go live** — under Mexican law the
  agency is itself responsible for advertising content
- A monthly 30-minute check

---

## 9. The honest summary

**You are not in trouble because someone sophisticated is targeting you.** You are
in trouble because a number of small, cheap things were skipped over time — and
they have accumulated.

The good news is that **almost everything on this list costs nothing but
attention.** Four of the five most valuable actions are under an hour each. The
two that require someone else's action — the web host and the web agency — are
already written up as ready-to-send tickets.

**The two things we would not compromise on:**

1. **Publish a privacy notice and add a consent checkbox.** This is the clearest
   legal exposure, it is being violated right now, and it is free to fix.
2. **Change the password and enable two-factor authentication.** Your site is the
   front door to everything, and your username is already public.

**One final thought.** Your patients chose you because they trust you with their
mouths. The same standard applies to what they type into your website. Being seen
to take that seriously — publicly — is not just a legal requirement. It is good
business, and it is the kind of thing that makes a patient recommend you to a
friend.

---

### Prepared as part of a passive security review, 22 October 2026. No intrusive testing was performed on your website. This document summarises findings and is not legal advice; for the data-protection and health-advertising matters we recommend a short consultation with a Mexican attorney.
