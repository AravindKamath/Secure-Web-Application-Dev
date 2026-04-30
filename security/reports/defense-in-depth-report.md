# Defense-in-Depth Report — PERN-Store E-Commerce Platform

**Document Version:** 1.0  
**Date:** 2026-04-30  
**Classification:** Internal — Security  
**Application:** PERN-Store E-Commerce Platform v1.0.0  
**Architecture:** PERN Stack (PostgreSQL, Express, React, Node.js)  
**Deployment:** Docker Compose with three-zone network segmentation

---

## Executive Summary

The PERN-Store application implements a comprehensive **Defense-in-Depth** security architecture across five distinct layers. Each layer provides independent security controls that collectively ensure no single point of failure can compromise the entire system. This document summarizes all controls implemented across Phases 1 through 5 of the security hardening lifecycle.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INTERNET                                    │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   UFW Firewall   │  ← Phase 3: Host Firewall
                    │  (80, 443 only)  │     Default deny inbound
                    └────────┬────────┘
                             │
        ╔════════════════════▼═══════════════════════════════════╗
        ║              PHASE 4: NETWORK SEGMENTATION             ║
        ╠════════════════════════════════════════════════════════╣
        ║                                                        ║
        ║   ┌─────────────────────────────────────┐              ║
        ║   │         DMZ (Web Zone)               │              ║
        ║   │     ┌───────────────────┐           │              ║
        ║   │     │  Nginx 1.25       │           │              ║
        ║   │     │  • Reverse proxy  │           │              ║
        ║   │     │  • Rate limiting  │           │              ║
        ║   │     │  • Security hdrs  │           │              ║
        ║   │     │  • Static files   │           │              ║
        ║   │     │  • Read-only FS   │           │              ║
        ║   │     └───────┬───────────┘           │              ║
        ║   └─────────────┼───────────────────────┘              ║
        ║                 │ frontend-net (bridge)                ║
        ║   ┌─────────────┼───────────────────────┐              ║
        ║   │         App Zone                     │              ║
        ║   │     ┌───────▼───────────┐           │              ║
        ║   │     │  Node.js API      │           │              ║
        ║   │     │  • Helmet v7      │           │              ║
        ║   │     │  • CORS           │           │              ║
        ║   │     │  • Rate limiting  │           │              ║
        ║   │     │  • JWT HttpOnly   │           │              ║
        ║   │     │  • Input valid.   │           │              ║
        ║   │     │  • Winston logs   │           │              ║
        ║   │     └───────┬───────────┘           │              ║
        ║   └─────────────┼───────────────────────┘              ║
        ║                 │ backend-net (internal: true)         ║
        ║   ┌─────────────┼───────────────────────┐              ║
        ║   │         Data Zone                    │              ║
        ║   │     ┌───────▼───────────┐           │              ║
        ║   │     │  PostgreSQL 16    │           │              ║
        ║   │     │  • No host ports  │           │              ║
        ║   │     │  • Internal net   │           │              ║
        ║   │     │  • Conn. limits   │           │              ║
        ║   │     │  • DDL logging    │           │              ║
        ║   │     └───────────────────┘           │              ║
        ║   └─────────────────────────────────────┘              ║
        ╚════════════════════════════════════════════════════════╝
```

---

## Phase 1 — Application Security

**Objective:** Secure the application layer against OWASP Top 10 vulnerabilities.

### Controls Implemented

| Control | Implementation | Protection |
|---------|---------------|------------|
| **Security Headers** | Helmet v7 with strict CSP | XSS, clickjacking, MIME sniffing, protocol downgrade |
| **CORS** | Whitelist-based origin validation | Cross-origin request forgery |
| **Rate Limiting** | `express-rate-limit` — 100 req/15 min global | DoS, brute force |
| **Auth Rate Limiting** | Nginx zone — 2 req/s on `/api/login`, `/api/signup` | Credential stuffing |
| **Authentication** | JWT with RS256 (asymmetric signing) | Token forgery |
| **Session Security** | HttpOnly, Secure, SameSite=Strict cookies | XSS token theft, CSRF |
| **Password Hashing** | bcrypt with auto-generated salt rounds | Rainbow table attacks, credential theft |
| **Input Validation** | Joi schema validation on all endpoints | SQL injection, XSS, parameter tampering |
| **Error Handling** | `express-async-errors` with sanitized responses | Information disclosure |
| **Payload Limits** | `express.json({ limit: '10kb' })` | Request smuggling, DoS |
| **Compression** | gzip via `compression` middleware | N/A (performance) |
| **RBAC** | `verifyAdmin` middleware for admin routes | Privilege escalation |
| **Proxy Trust** | `trust proxy: 1` for accurate client IP | Rate limiter bypass |

### Key Configuration Files

| File | Purpose |
|------|---------|
| `server/app.js` | Express middleware chain |
| `server/middleware/rateLimiter.js` | Rate limiting configuration |
| `server/middleware/verifyToken.js` | JWT verification |
| `server/middleware/verifyAdmin.js` | Admin RBAC |
| `server/middleware/validate.js` | Joi request validation |
| `server/helpers/error.js` | Centralized error handling |

---

## Phase 2 — Secret Management & Credential Rotation

**Objective:** Eliminate hardcoded secrets, rotate compromised credentials, and implement secure key management.

### Controls Implemented

| Control | Implementation | Protection |
|---------|---------------|------------|
| **Environment Isolation** | `.env.production.local` (gitignored) | Secret exposure in VCS |
| **Git History Purging** | BFG Repo-Cleaner on `.env` files | Historical credential leakage |
| **RSA Key Management** | Auto-generated 2048-bit RSA keys for JWT | Key compromise |
| **File Permissions** | `chmod 0600` on `private.pem` | Unauthorized key access |
| **Secret Injection** | Docker `env_file` directive | Hardcoded secrets in compose |
| **Example Templates** | `.env.example` with placeholder values | Onboarding without exposing secrets |

### Key Configuration Files

| File | Purpose |
|------|---------|
| `server/.env.production.local` | Production secrets (gitignored) |
| `server/.env.example` | Template with placeholder values |
| `server/keys/private.pem` | RSA private key (auto-generated, 0600) |
| `pgadmin.env` | PgAdmin credentials (if used) |

---

## Phase 3 — Host Hardening

**Objective:** Secure the Linux host operating system and system services.

### Controls Implemented

| Control | Implementation | Protection |
|---------|---------------|------------|
| **SSH Hardening** | Key-only auth, root login disabled, port change | Brute force, unauthorized access |
| **Firewall** | UFW: default deny, allow 22/80/443 only | Network-level attack surface reduction |
| **Intrusion Prevention** | Fail2Ban: 5 attempts → 1hr ban (SSH + Nginx) | Automated brute force |
| **Auto-Patching** | `unattended-upgrades` for security updates | Known vulnerability exploitation |
| **Service Sandboxing** | systemd unit with `NoNewPrivileges`, `ProtectSystem` | Privilege escalation |
| **Non-root Service** | Dedicated `pernstore` system user | Lateral movement |
| **Nginx Hardening** | `server_tokens off`, rate limit zones, hidden files blocked | Information disclosure, path traversal |

### Key Configuration Files

| File | Purpose |
|------|---------|
| `Deployment/scripts/harden-host.sh` | Master hardening orchestrator |
| `Deployment/scripts/harden-ssh.sh` | SSH configuration |
| `Deployment/scripts/setup-ufw.sh` | Firewall rules |
| `Deployment/scripts/setup-fail2ban.sh` | Intrusion prevention |
| `Deployment/scripts/setup-unattended-upgrades.sh` | Auto-patching |
| `Deployment/configs/nginx-pern-store.conf` | Host Nginx configuration |
| `Deployment/configs/pern-store.service` | systemd service unit |

---

## Phase 4 — Network Segmentation

**Objective:** Implement zone-based network isolation to prevent lateral movement between application tiers.

### Three-Zone Architecture

| Zone | Service | Network | External Access |
|------|---------|---------|-----------------|
| **DMZ (Web)** | Nginx | `frontend-net` | ✅ Ports 80, 443 |
| **App** | Node.js API | `frontend-net` + `backend-net` | ❌ No host ports |
| **Data** | PostgreSQL | `backend-net` (`internal: true`) | ❌ No host ports, no external routing |

### Isolation Guarantees

| Path | Allowed | Mechanism |
|------|---------|-----------|
| Internet → Nginx | ✅ | Port 80/443 mapping |
| Nginx → API | ✅ | `frontend-net` bridge |
| API → PostgreSQL | ✅ | `backend-net` bridge |
| Nginx → PostgreSQL | ❌ **BLOCKED** | No shared network |
| PostgreSQL → Internet | ❌ **BLOCKED** | `internal: true` flag |
| Host → PostgreSQL | ❌ **BLOCKED** | No host port mapping |
| Host → API | ❌ **BLOCKED** | No host port mapping |

### Container Security Hardening

| Control | Nginx | API | PostgreSQL |
|---------|-------|-----|------------|
| `no-new-privileges` | ✅ | ✅ | ✅ |
| `read_only` filesystem | ✅ | — | — |
| `tmpfs` for writable paths | ✅ | — | — |
| Healthcheck defined | ✅ | ✅ | ✅ |
| JSON logging with size limits | ✅ | ✅ | ✅ |
| Restart policy | ✅ | ✅ | ✅ |
| Persistent volume | — | — | ✅ (`pgdata`) |

### Key Configuration File

| File | Purpose |
|------|---------|
| `docker-compose.prod.yml` | Production orchestration with zone model |
| `server/config/nginx.conf` | Container Nginx with rate limiting + security headers |

---

## Phase 5 — Audit & Compliance

**Objective:** Generate compliance artifacts, verify security posture, and establish continuous monitoring.

### Deliverables

| Deliverable | File | Format | Purpose |
|-------------|------|--------|---------|
| **Server SBOM** | `security/sbom/sbom-server.cdx.json` | CycloneDX 1.5 | 398 components inventoried |
| **Client SBOM** | `security/sbom/sbom-client.cdx.json` | CycloneDX 1.5 | 464 components inventoried |
| **Docker SBOM** | `security/sbom/sbom-docker.cdx.json` | CycloneDX 1.5 | 4 container images + 2 base OS |
| **VEX Report** | `security/vex/vex-report.cdx.json` | CycloneDX VEX | 16 triaged vulnerabilities |
| **VEX Analysis** | `security/vex/vex-analysis.md` | Markdown | Human-readable triage |
| **Vuln Scan** | `security/vex/vulnerability-scan.txt` | Text | Raw `npm audit` output |
| **AIDE Config** | `security/monitoring/aide.conf` | AIDE | File integrity monitoring |
| **Audit Rules** | `security/monitoring/audit.rules` | auditd | Syscall and file monitoring |
| **Pentest Script** | `security/scripts/audit-verify.sh` | Bash | Automated verification |
| **This Report** | `security/reports/defense-in-depth-report.md` | Markdown | Phase 1–5 summary |

### Vulnerability Triage Summary

| Priority | Finding | Status |
|----------|---------|--------|
| **P0** | Node.js 16 EOL (Dockerfiles) | 🔴 Remediate immediately |
| **P0** | jsonwebtoken@8.5.1 (3 CVEs) | 🔴 Upgrade to v9.x |
| **P1** | nodemailer@6.8.0 (5 CVEs) | 🔴 Upgrade to latest |
| **P1** | `crypto@1.0.1` deprecated shim | 🟡 Remove from dependencies |
| **P2** | 20+ auto-fixable vulnerabilities | 🟡 Run `npm audit fix` |
| **P3** | stripe@8.x, moment@2.x outdated | ⚪ Plan major upgrades |

### Monitoring Coverage

| Monitor | Data Zone | App Zone | DMZ | Host |
|---------|-----------|----------|-----|------|
| **AIDE** (file integrity) | ✅ pg_data, pg_hba.conf | ✅ source, .env, keys | ✅ nginx.conf, static | ✅ binaries, SSH, PAM |
| **auditd** (syscall) | ✅ pgdata writes, config | ✅ env access, key access | ✅ nginx config, TLS | ✅ Docker, iptables, cron |
| **Winston** (app logs) | — | ✅ HTTP requests, errors | — | — |
| **Morgan** (access logs) | — | ✅ Combined format | — | — |
| **Docker** (container logs) | ✅ JSON, 10m/3 files | ✅ JSON, 10m/5 files | ✅ JSON, 10m/3 files | — |

---

## Security Control Matrix

This matrix maps each security control to the threat category it mitigates:

| Threat Category | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 |
|----------------|---------|---------|---------|---------|---------|
| **SQL Injection** | Joi validation, parameterized queries | — | — | — | SBOM tracking |
| **XSS** | Helmet CSP, X-XSS-Protection | — | — | — | nikto/ZAP scan |
| **CSRF** | SameSite cookies, CORS | — | — | — | Header validation |
| **Brute Force** | Rate limiting, bcrypt | — | Fail2Ban | — | nmap/nikto |
| **Credential Theft** | HttpOnly cookies, RS256 JWT | .env isolation, key perms | — | — | VEX report |
| **Secret Exposure** | — | Git purge, env_file | — | — | Config audit |
| **Privilege Escalation** | RBAC middleware | — | NoNewPrivileges, nologin | no-new-privileges | auditd monitoring |
| **Lateral Movement** | — | — | — | Zone isolation, internal net | Network isolation test |
| **Data Breach** | — | Encrypted keys | — | backend-net internal | AIDE integrity |
| **DoS/DDoS** | Payload limits, rate limit | — | UFW, Fail2Ban | — | nmap port scan |
| **Supply Chain** | — | — | unattended-upgrades | — | SBOM, VEX, npm audit |
| **Container Escape** | — | — | — | read_only, no-new-privileges | Docker socket audit |
| **Forensics Evasion** | — | — | — | — | auditd, AIDE, immutable rules |

---

## Compliance Alignment

| Framework | Relevant Controls |
|-----------|-------------------|
| **OWASP Top 10** | All Phase 1 controls directly address OWASP categories |
| **CIS Docker Benchmark** | Phase 4 implements CIS 5.x container security controls |
| **NIST 800-53** | Phases 3–5 cover AC, AU, CM, IA, SC, SI control families |
| **SOC 2 Type II** | SBOM/VEX for CC7.1, monitoring for CC7.2, access controls for CC6.1 |
| **PCI DSS v4.0** | Network segmentation (Req 1), access control (Req 7), monitoring (Req 10) |

---

## Recommendations for Phase 6 (Future)

| Area | Recommendation | Priority |
|------|---------------|----------|
| **TLS** | Enable HTTPS with Let's Encrypt (nginx.conf has commented config ready) | P0 |
| **CI/CD** | Integrate SBOM generation and `npm audit` into Jenkins pipeline | P1 |
| **SIEM** | Forward Winston/auditd logs to ELK or Grafana Loki | P1 |
| **WAF** | Add ModSecurity or Cloudflare WAF in front of Nginx | P2 |
| **Secrets Vault** | Migrate from `.env` files to HashiCorp Vault or AWS Secrets Manager | P2 |
| **Container Registry** | Use private registry with image signing (Cosign/Notary) | P2 |
| **Runtime Protection** | Deploy Falco for runtime container security monitoring | P3 |
| **Backup & DR** | Implement automated PostgreSQL backup with pg_dump + encryption | P1 |
