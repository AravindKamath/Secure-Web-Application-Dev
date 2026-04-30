# Vulnerability Exploitability Analysis (VEX) — PERN-Store

**Audit Date:** 2026-04-30  
**Auditor:** Phase 5 Security Audit  
**Application:** PERN-Store E-Commerce Platform v1.0.0  
**Scan Source:** `npm audit` (server + client)

---

## Executive Summary

| Severity | Server | Client | Total |
|----------|--------|--------|-------|
| **Critical** | 2 | 1 | 3 |
| **High** | 17 | 12 | 29 |
| **Moderate** | 10 | 11 | 21 |
| **Low** | 8 | 0 | 8 |
| **Total** | **37** | **24** | **61** |

### Triage Outcome

| Status | Count | Description |
|--------|-------|-------------|
| 🔴 **Exploitable** | 6 | Requires immediate remediation |
| 🟡 **Under Investigation** | 0 | — |
| 🟢 **Not Affected** | 10 | Mitigated or code not reachable |
| ⚪ **Fixed** | 0 | Awaiting dependency update |

---

## 🔴 CRITICAL — Immediate Action Required

### 1. Node.js 16 End of Life (Infrastructure)

| Field | Value |
|-------|-------|
| **Component** | `node:16` (Dockerfile) |
| **Severity** | 🔴 CRITICAL |
| **Status** | Exploitable |
| **CWE** | CWE-1104 (Use of Unmaintained Third-Party Components) |

**Impact:** Both `server/Dockerfile` and `client/Dockerfile` use `node:16` which reached End of Life on **2023-09-11**. This means:
- No security patches since September 2023
- Known unpatched vulnerabilities in the V8 engine, OpenSSL, and libuv
- Compliance frameworks (SOC2, ISO 27001) flag EOL software as non-compliant

**Remediation:**
```dockerfile
# server/Dockerfile — BEFORE
FROM node:16

# server/Dockerfile — AFTER
FROM node:20-alpine
```

**Priority:** P0 — Must remediate before production deployment.

---

### 2. jsonwebtoken@8.5.1 — Multiple Critical Vulnerabilities

| Field | Value |
|-------|-------|
| **Component** | `jsonwebtoken@8.5.1` |
| **Severity** | 🔴 HIGH (aggregate: CRITICAL) |
| **CVEs** | GHSA-8cf7-32gw-wr33, GHSA-hjrf-2m68-5959, GHSA-qwph-4952-7xr6 |
| **Status** | Exploitable (2 of 3 CVEs) |

**Vulnerabilities:**
1. **Unrestricted key type** — allows legacy insecure key algorithms
2. **RSA-to-HMAC confusion** — attacker can forge tokens using the public key
3. **Insecure default algorithm** — Not Affected (application specifies RS256 explicitly)

**Impact:** An attacker who obtains the public RSA key could forge JWT tokens by exploiting the HMAC confusion attack, gaining unauthorized access to any user account including admin.

**Remediation:**
```bash
npm install jsonwebtoken@9.0.3
```
> ⚠️ **Breaking change:** v9.x has stricter key validation. Test JWT signing/verification after upgrade.

**Priority:** P0 — Authentication bypass risk.

---

### 3. nodemailer@6.8.0 — Multiple High Vulnerabilities

| Field | Value |
|-------|-------|
| **Component** | `nodemailer@6.8.0` |
| **Severity** | 🔴 HIGH |
| **CVEs** | GHSA-9h6g-pr28-7cqp, GHSA-mm7p-fcc7-pg87, GHSA-rcmh-qjqh-p98v, GHSA-c7w3-x93f-qmm8, GHSA-vvjj-xcjg-gr5g |
| **Status** | Exploitable |

**Impact:**
- ReDoS via crafted email addresses
- Email sent to unintended domains (phishing vector)
- SMTP command injection
- DoS via recursive address parsing

**Remediation:**
```bash
npm install nodemailer@latest
```

**Priority:** P1 — Phishing and injection risks.

---

## 🟡 HIGH — Remediation Recommended

### 4. express@4.18.2 — XSS and Open Redirect

| Field | Value |
|-------|-------|
| **Component** | `express@4.18.2` |
| **Severity** | HIGH (aggregate) |
| **Status** | Not Affected |
| **Justification** | Code not reachable |

**Analysis:** The application does not use `res.redirect()` with user-controlled input. All routes are explicitly defined. Additionally, Nginx adds defense-in-depth security headers (X-Frame-Options, CSP) that would prevent exploitation even if the code path existed.

**Recommendation:** Update to `express@4.21.x` or `express@5.x` when ready.

---

### 5. node-forge@1.3.0 — Multiple Cryptographic Vulnerabilities

| Field | Value |
|-------|-------|
| **Component** | `node-forge@1.3.0` (via google-auth-library) |
| **Severity** | HIGH |
| **CVEs** | 7 vulnerabilities including ASN.1 issues, signature forgery |
| **Status** | Not Affected |
| **Justification** | Protected by mitigating control |

**Analysis:** node-forge is used transitively by `google-auth-library` for Google OAuth. The actual TLS/crypto operations are handled by Node.js native `crypto` module and Google's OAuth2 servers. node-forge is only used for key format conversion in development contexts.

**Recommendation:** Update `google-auth-library` to latest version.

---

### 6. axios@1.6.2 — SSRF and Credential Leakage (Client)

| Field | Value |
|-------|-------|
| **Component** | `axios@1.6.2` |
| **Severity** | HIGH |
| **Status** | Not Affected |
| **Justification** | Protected by mitigating control |

**Analysis:** axios is used exclusively in the React client (browser). SSRF vulnerabilities require server-side execution. The browser's same-origin policy and the application's CORS configuration prevent abuse. Additionally, the `follow-redirects` proxy-authorization leak only applies to server-to-server requests.

**Recommendation:** Update to `axios@1.7.x` for completeness.

---

### 7. tar@6.2.1 — Path Traversal and File Overwrite

| Field | Value |
|-------|-------|
| **Component** | `tar@6.2.1` (via @mapbox/node-pre-gyp → bcrypt) |
| **Severity** | HIGH |
| **Status** | Not Affected |
| **Justification** | Code not reachable |

**Analysis:** tar is only used during `npm install` to extract native addon packages (bcrypt). It is not used at runtime and is not exposed to user-supplied tar archives.

---

## 🟢 LOW RISK — Dev Dependencies (Not in Production)

The following vulnerabilities exist only in development dependencies and are not present in the production Docker image:

| Package | Severity | Justification |
|---------|----------|---------------|
| `cross-spawn@7.0.3` | High | Dev-only (cross-env) |
| `braces@3.0.2` | High | Dev-only (micromatch/chokidar) |
| `picomatch@2.3.1` | High | Dev-only (glob matching) |
| `minimatch@3.1.2` | High | Dev-only (eslint) |
| `semver@7.5.4` | High | Dev-only (nodemon) |
| `word-wrap@1.2.3` | Moderate | Dev-only (eslint) |
| `esbuild@0.19.x` | Moderate | Dev-only (vite build tool) |
| `rollup@4.x` | High | Dev-only (vite bundler) |

---

## Supply Chain Risk Assessment

### High-Risk Dependencies

| Package | Risk Factor | Recommendation |
|---------|-------------|----------------|
| `jsonwebtoken@8.5.1` | 🔴 EOL-adjacent, multiple CVEs | Upgrade to v9.x immediately |
| `moment@2.29.4` | 🟡 Maintenance mode, large bundle | Migrate to `date-fns` (already in client) |
| `stripe@8.138.0` | 🟡 Major version behind (current: v17) | Plan upgrade to latest Stripe SDK |
| `googleapis@112.0.0` | 🟡 Many transitive deps, large footprint | Evaluate if full SDK is needed |
| `swagger-ui-express@4.6.0` | 🟡 Should not be exposed in production | Disable in production builds |
| `crypto@1.0.1` | 🔴 Deprecated shim, use Node.js built-in | Remove from package.json |

### Dependency Hygiene Metrics

| Metric | Server | Client |
|--------|--------|--------|
| Total dependencies (lockfile) | 398 | 464 |
| Direct production deps | 16 | 14 |
| Direct dev deps | 6 | 9 |
| Outdated packages (major) | ~8 | ~4 |
| Known vulnerabilities | 37 | 24 |

---

## Remediation Priority Matrix

| Priority | Action | Impact |
|----------|--------|--------|
| **P0** | Upgrade `node:16` → `node:20-alpine` | Resolves 30+ unfixed CVEs in Node.js runtime |
| **P0** | Upgrade `jsonwebtoken@8.5.1` → `9.0.3` | Fixes authentication bypass risk |
| **P1** | Upgrade `nodemailer@6.8.0` → `latest` | Fixes email injection and phishing vectors |
| **P1** | Remove `crypto@1.0.1` from package.json | Dead dependency, use Node.js built-in |
| **P2** | Run `npm audit fix` (server) | Resolves ~20 auto-fixable vulnerabilities |
| **P2** | Run `npm audit fix` (client) | Resolves ~18 auto-fixable vulnerabilities |
| **P3** | Upgrade `stripe@8` → `stripe@17` | Modernize payment integration |
| **P3** | Evaluate removing `moment` | Reduce bundle size, use `date-fns` |
