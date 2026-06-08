# Security Automation — Phase 2: Vulnerability Scanning

This directory contains security automation scripts, configuration, and reports for the PERN-Store project.

## Overview

The security automation is being implemented in phases:

- **Phase 1**: SBOM generation using Syft
- **Phase 2** (Current): Vulnerability scanning with Grype
- **Phase 3** (Future): Report retention and historical tracking
- **Phases 4-5**: Additional security hardening and compliance automation

## Directory Structure

```
security/
├── README.md                 # This file
├── monitoring/               # System monitoring configurations
│   ├── aide.conf            # File integrity monitoring rules
│   └── audit.rules          # Linux audit rules
├── reports/                  # Generated security reports
│   ├── defense-in-depth-report.md  # Architecture & threat model
│   ├── sbom/                # Software Bill of Materials
│   │   ├── nginx-1.25-alpine-2026-06-08.cdx.json
│   │   ├── nginx-1.25-alpine-2026-06-08.md
│   │   └── ...
│   └── vulnerabilities/      # Vulnerability scan reports
│       ├── nginx-1.25-alpine-2026-06-08.json
│       ├── nginx-1.25-alpine-2026-06-08.md
│       └── ...
├── scripts/                  # Security automation scripts
│   ├── generate-sbom.sh     # Generate SBOMs for containers
│   └── vulnerability-scan.sh  # Scan SBOMs for vulnerabilities
└── legacy/                   # Archived/superseded files
    ├── generate-sbom.py     # Previous SBOM generation approach
    ├── sbom/                # Previous SBOM artifacts
    └── vex/                 # Previous vulnerability analysis
```

---

## Phase 1: SBOM Generation

### Purpose

Generate **Software Bill of Materials (SBOM)** for all containerized components of the PERN-Store application. This provides a comprehensive inventory of all software dependencies, versions, and package types across:

- Frontend container (nginx)
- Backend API container (Node.js server)
- Database container (PostgreSQL)

### Requirements

#### Syft

Syft is a CLI tool that generates Software Bill of Materials (SBOM) from container images and filesystems.

**Homepage:** https://github.com/anchore/syft

**Installation:**

The `generate-sbom.sh` script will **automatically install Syft** if it's not already present.

To manually install:

**Linux (Debian/Ubuntu):**
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

**Linux (RHEL/CentOS):**
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

**macOS (Homebrew):**
```bash
brew install syft
```

**Docker (Alternative):**
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/syft:latest <image>
```

#### Additional Tools

- **Docker**: For container access and image inspection
- **jq**: For JSON parsing (usually pre-installed on Linux systems)
  ```bash
  # Install jq if needed
  apt-get install jq  # Debian/Ubuntu
  brew install jq     # macOS
  ```

#### Docker Access

Ensure your user is in the `docker` group to run Docker commands without `sudo`:

```bash
sudo usermod -aG docker $USER
# Log out and back in for group membership to take effect
```

### Usage

Generate SBOMs for all running containers:

```bash
# From project root
bash ./security/scripts/generate-sbom.sh
```

The script will:

1. **Verify** Syft and jq are installed (auto-install Syft if needed)
2. **Discover** all running Docker containers via `docker ps`
3. **Normalize** container image names to short service names (nginx, server, postgres)
4. **Generate** CycloneDX JSON SBOM for each container image using Syft
5. **Parse** the JSON and generate human-readable Markdown summaries
6. **Save** both formats to `security/reports/sbom/`

### Output

For each running container, the script generates two files:

**CycloneDX JSON Format** (Machine-readable):
```
security/reports/sbom/nginx-2026-06-08.cdx.json
security/reports/sbom/server-2026-06-08.cdx.json
security/reports/sbom/postgres-2026-06-08.cdx.json
```

**Markdown Summary** (Human-readable):
```
security/reports/sbom/nginx-2026-06-08.md
security/reports/sbom/server-2026-06-08.md
security/reports/sbom/postgres-2026-06-08.md
```

#### Markdown Report Example

```markdown
# SBOM Report: nginx

**Generated:** 2026-06-08T15:30:45Z

**Container Image:** `nginx:1.25-alpine`

**CycloneDX Spec Version:** 1.5

**Total Packages:** 47

## Packages

| Package Name | Version | Type |
|--------------|---------|------|
| `alpine-base` | 2.12.10 | library |
| `curl` | 8.2.1 | library |
| `openssl` | 3.1.2 | library |
| ... | ... | ... |
```

### SBOM Format: CycloneDX

The JSON output adheres to the [CycloneDX Specification](https://cyclonedx.org/), a lightweight BOM standard for identifying components and their vulnerabilities.

**Key fields in generated JSON:**
- `specVersion`: CycloneDX specification version (typically 1.5)
- `components`: Array of discovered packages
  - `name`: Package name
  - `version`: Package version
  - `type`: Package type (library, framework, application, etc.)
  - `purl`: Package URL (standardized identifier)
  - `licenses`: License information
  - `hashes`: Cryptographic hashes (SHA-256, etc.)

### Example: Running the Script

```bash
$ cd /home/kamath/e-commerce/PERN-Store
$ bash ./security/scripts/generate-sbom.sh

╔════════════════════════════════════════════════════════════════════╗
║                 SBOM Generation Workflow - Phase 1                  ║
╚════════════════════════════════════════════════════════════════════╝

ℹ️  Verifying prerequisites...
✓ Syft is installed
✓ Output directory ready: /home/kamath/e-commerce/PERN-Store/security/reports/sbom
ℹ️  Discovering running containers...
✓ Found 3 running container(s)

ℹ️  Scanning: nginx:1.25-alpine → nginx
✓ Generated SBOM JSON: /home/kamath/e-commerce/PERN-Store/security/reports/sbom/nginx-2026-06-08.cdx.json
✓ Generated Markdown report: /home/kamath/e-commerce/PERN-Store/security/reports/sbom/nginx-2026-06-08.md

ℹ️  Scanning: pern-prod-api → server
✓ Generated SBOM JSON: /home/kamath/e-commerce/PERN-Store/security/reports/sbom/server-2026-06-08.cdx.json
✓ Generated Markdown report: /home/kamath/e-commerce/PERN-Store/security/reports/sbom/server-2026-06-08.md

ℹ️  Scanning: postgres:15-alpine → postgres
✓ Generated SBOM JSON: /home/kamath/e-commerce/PERN-Store/security/reports/sbom/postgres-2026-06-08.cdx.json
✓ Generated Markdown report: /home/kamath/e-commerce/PERN-Store/security/reports/sbom/postgres-2026-06-08.md

╔════════════════════════════════════════════════════════════════════╗
║                              Summary                               ║
╚════════════════════════════════════════════════════════════════════╝

✓ Generated SBOMs: 3
ℹ️  Output directory: /home/kamath/e-commerce/PERN-Store/security/reports/sbom

Generated files:
  • nginx-2026-06-08.cdx.json
  • nginx-2026-06-08.md
  • postgres-2026-06-08.cdx.json
  • postgres-2026-06-08.md
  • server-2026-06-08.cdx.json
  • server-2026-06-08.md
```

---

## Monitoring (aide.conf, audit.rules)

The `monitoring/` directory contains system-level monitoring configurations:

- **aide.conf**: Advanced Intrusion Detection Environment rules for file integrity monitoring
- **audit.rules**: Linux auditd rules for real-time system change detection

These configurations are stable and actively used by the deployed system. They are not modified during Phase 1 refactoring.

---

## Legacy Files

The `legacy/` directory contains previous implementations that have been superseded:

- **generate-sbom.py**: Previous Python-based SBOM generation from npm lockfiles
- **sbom/**: Previous SBOM artifacts generated from package-lock.json
- **vex/**: Previous vulnerability analysis using npm audit

These are preserved for audit trail purposes and comparison with new Syft-based approach.

---

## Phase 2: Vulnerability Scanning with Grype

### Purpose

Scan generated SBOMs for known vulnerabilities using Grype, a vulnerability scanner for container images and filesystems. This phase consumes the CycloneDX SBOMs from Phase 1 and produces vulnerability reports.

### Requirements

#### Grype

Grype is a CLI tool that scans SBOMs and container images for vulnerabilities.

**Homepage:** https://github.com/anchore/grype

**Installation:**

The `vulnerability-scan.sh` script will **automatically install Grype** if it's not already present.

To manually install:

**Linux:**
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/.local/bin
```

**macOS (Homebrew):**
```bash
brew install grype
```

**Docker (Alternative):**
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/grype:latest sbom:<sbom-file>
```

### Usage

Run vulnerability scanning on generated SBOMs:

```bash
# From project root
bash ./security/scripts/vulnerability-scan.sh
```

The script will:

1. **Verify** Grype and jq are installed (auto-install Grype if needed)
2. **Discover** all `.cdx.json` SBOM files in `security/reports/sbom/`
3. **Scan** each SBOM using `grype sbom:<file>` for vulnerabilities
4. **Generate** JSON vulnerability report and Markdown summary for each SBOM
5. **Save** outputs to `security/reports/vulnerabilities/`

### Output

For each SBOM, the script generates two files:

**JSON Vulnerability Report** (Machine-readable):
```
security/reports/vulnerabilities/nginx-1.25-alpine-2026-06-08.json
```

**Markdown Summary** (Human-readable):
```
security/reports/vulnerabilities/nginx-1.25-alpine-2026-06-08.md
```

#### Markdown Report Example

```markdown
# Vulnerability Report

Generated: 2026-06-08T12:00:00Z

Source SBOM:
nginx-1.25-alpine-2026-06-08.cdx.json

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 5 |
| Medium | 12 |
| Low | 8 |
| Negligible | 3 |

## Vulnerabilities

| Package | Installed Version | Severity | CVE |
|---------|-----------------|----------|-----|
| `openssl` | 3.1.2 | Critical | CVE-2024-12345 |
| `curl` | 8.2.1 | High | CVE-2024-54321 |
| ... | ... | ... | ... |
```

### Workflow

The complete workflow requires running scripts sequentially:

```bash
# Step 1: Generate SBOMs from Docker images
./security/scripts/generate-sbom.sh

# Step 2: Scan SBOMs for vulnerabilities
./security/scripts/vulnerability-scan.sh
```

### JSON vs Markdown Reports

- **JSON Reports**: Raw Grype output for programmatic processing, integration with other tools, or CI/CD pipelines
- **Markdown Reports**: Human-readable summaries with severity counts and vulnerability tables for review

---

## Security Constraints

⚠️ **The following are NOT modified during Phase 1 refactoring:**

- Application source code (server/, client/)
- Dockerfiles (frontend, backend, database)
- docker-compose configurations
- nginx configuration (server/config/nginx.conf)
- Database schema and migrations
- CI/CD pipelines
- System monitoring rules (aide.conf, audit.rules)

---

## Support & Documentation

- **Syft Docs**: https://github.com/anchore/syft
- **CycloneDX Spec**: https://cyclonedx.org/
- **Anchore Resources**: https://anchore.com/sbom
- **Project Defense-in-Depth Report**: See `security/reports/defense-in-depth-report.md`

---

**Last Updated:** 2026-06-08  
**Phase:** 2 (Vulnerability Scanning)  
**Status:** Active Development
