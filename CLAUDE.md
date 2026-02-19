# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ReNgGinaNg** is a hardened fork of reNgine 2.2.0 — a self-hosted security reconnaissance and threat intelligence platform. It orchestrates 20+ scanning tools and provides dashboard, scan management, vulnerability tracking, and a custom Threat Intelligence (TI) module.

## Common Commands

All operations are via Docker Compose, wrapped in a Makefile:

```bash
make build          # Build all Docker services
make up             # Build and start everything
make stop           # Stop services
make restart        # Restart services
make down           # Stop and remove containers
make prune          # Remove containers AND delete volumes (destructive)

make certs          # Generate self-signed SSL certificates (required before first run)
make migrate        # Run Django migrations inside web container
make username       # Create Django superuser
make logs           # Tail all container logs
make test           # Run test_scan.py in Celery container
```

**Direct container access:**
```bash
docker compose exec web python3 manage.py <command>
docker compose logs -f celery
docker compose logs -f web
```

**First-time setup:**
```bash
cp .env.example .env
# Edit .env: set DOMAIN_NAME, passwords, API keys
make certs && make build && make up
```

## Architecture

### Service Topology

```
Browser → Nginx (443) → Django (8000) → PostgreSQL
                                      → Redis → Celery Workers (10–80 auto-scale)
                                                → Celery Beat (scheduler)
                                      → Ollama (LLM, :11434)
```

- **Web container**: Django app + Gunicorn served via Nginx reverse proxy with self-signed TLS
- **Celery workers**: Auto-scale between `MIN_CONCURRENCY` and `MAX_CONCURRENCY` (default 10–80)
- **Redis**: Both cache backend and Celery message broker
- Configuration via `.env` file (never committed); see `.env.example`

### Django Apps

The entire Django project lives in `web/`:

| App | Purpose |
|-----|---------|
| `ReNgGinaNg/` | Project settings, root URLs, Celery config, shared utilities |
| `dashboard/` | Main dashboard, API key management, project workspace |
| `targetApp/` | Domain/organization/target management |
| `scanEngine/` | Scan engine YAML configurations |
| `startScan/` | Scan execution, vulnerability/subdomain/endpoint models and views |
| `api/` | REST API (DRF) — `views.py` is ~94K lines |
| `threatIntel/` | Threat Intelligence module (OTX, LeakCheck, WPScan, PDF reports) |
| `recon_note/` | Recon notes per target |

### Key Files

- `web/ReNgGinaNg/tasks.py` — All Celery task definitions (~5K lines); this is where scanning pipelines are implemented
- `web/ReNgGinaNg/common_func.py` — Shared utilities used across apps (~1.7K lines)
- `web/ReNgGinaNg/settings.py` — Django + Celery + database configuration
- `web/startScan/models.py` — Core data models: `ScanHistory`, `Vulnerability`, `Subdomain`, `Endpoint`, DNS records
- `web/threatIntel/views.py` — TI dashboard, async refresh logic, PDF report generation

### Threat Intelligence Module

`threatIntel/` is a custom app added on top of the reNgine fork:

- **Models**: `OTXThreatData`, `LeakCheckData`, `ManualIndicator`, `ThreatIntelScanStatus`, `ThreatIntelReportSetting`
- **Data sources**: OTX AlienVault API, LeakCheck API, WPScan API
- **Flow**: User triggers refresh → Celery tasks fetch each API → results stored in DB → frontend polls `scan_status` endpoint → PDF generated with WeasyPrint
- **Reports**: Bilingual (EN/ID), configurable logo/colors/company info
- **Endpoints**: `/<project_slug>/threat-intel/` with sub-routes for refresh, status polling, domain detail, manual indicators, PDF generate/download

### Unified Risk Score Formula

`calculate_risk_score()` is called consistently from dashboard, TI page, and PDF reports:

**With VA data (5 components, max 100)**:
- Vulnerability Assessment: 40 — weighted density + severity multiplier
- Credential Exposure: 30 — unchecked leaked credentials (LeakCheck)
- Threat Exposure: 12 — OTX AlienVault pulse mentions
- OTX Reputation: 10 — direct OTX reputation score
- Malware Association: 8 — feed-based malware references

**Without VA data (redistributed, same total)**:
- Credential Exposure: 45, Threat Exposure: 25, OTX Reputation: 20, Malware: 10

### URL Routing Pattern

Root `urls.py` routes to project-scoped URLs like `/<slug>/`. Each app registers its own `urls.py`. The TI module uses the prefix `/<slug>/threat-intel/`.

### PDF Reports

WeasyPrint renders HTML templates to PDF. Templates live in:
- `web/templates/report/` — Shared report base
- `web/threatIntel/templates/` — TI-specific report templates

Report settings (logo, language, brand colors) are stored per-project in `ThreatIntelReportSetting` model.

## Environment Variables

Key `.env` variables:
- `DOMAIN_NAME` — FQDN for Nginx/TLS
- `POSTGRES_PASSWORD`, `POSTGRES_USER`, `POSTGRES_DB`
- `DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_PASSWORD`
- `MAX_CONCURRENCY`, `MIN_CONCURRENCY` — Celery worker scaling
- `OTX_API_KEY`, `LEAKCHECK_API_KEY`, `WPSCAN_API_KEY` — TI API keys
- `OPENAI_API_KEY` — Optional LLM integration
