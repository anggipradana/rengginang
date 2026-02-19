<p align="center">
  <img src="docs/images/logo.png" alt="ReNgGinaNg" width="400">
</p>

<h3 align="center">Recon Engine for Global Guarding & Network Attack Intelligence</h3>

<p align="center">
  <strong>v1.0</strong> — A hardened, feature-enhanced fork of reNgine 2.2.0
</p>

<p align="center">
  <a href="#whats-new">What's New</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#installation">Installation</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#api-reference">API</a> &bull;
  <a href="#license">License</a>
</p>

---

## About

**ReNgGinaNg** is the next evolution of automated reconnaissance — built on top of [reNgine 2.2.0](https://github.com/yogeshojha/rengine) and redesigned for professional red team and blue team operations.

This release delivers a **Threat Intelligence module**, **bilingual PDF reporting (EN/ID)**, **dark web breach monitoring**, and a fully rebranded experience.

### Key Highlights

- Fully self-hosted
- Threat Intel dashboard with OTX AlienVault & LeakCheck integration
- Bilingual vulnerability assessment PDF reports (English / Bahasa Indonesia)
- WPScan API integration for WordPress vulnerability scanning
- IoC, CVE, and credential leak analytics with charts
- Enhanced dashboard with threat intelligence overview
- Manual threat indicator management
- Configurable report settings (company logo, document number, executive summary)

---

## What's New

### vs reNgine 2.2.0

| Feature                    | reNgine 2.2.0 | ReNgGinaNg 1.0                         |
| -------------------------- | ------------- | -------------------------------------- |
| Threat Intelligence Page   | -             | OTX AlienVault + LeakCheck             |
| Dark Web Breach Monitoring | -             | Per-domain credential leak scanning    |
| IoC / CVE Analytics        | -             | Tables + Donut/Bar charts              |
| Bilingual PDF Reports      | English only  | English + Bahasa Indonesia             |
| Report Customization       | Basic         | Company logo, doc number, exec summary |
| WPScan Integration         | -             | WordPress vulnerability scanning       |
| Manual Threat Indicators   | -             | Add/manage indicators manually         |
| Dashboard TI Overview      | -             | Pulse count, leak count, risk cards    |
| Google Chat Notifications  | -             | Webhook integration for Google Chat    |
| Branding                   | reNgine       | ReNgGinaNg (fully independent)         |

### Risk Score Calculation

The unified Risk Score (0–100) is calculated across Dashboard, Threat Intel page, and PDF reports using **five weighted components** that combine Threat Intelligence data with Vulnerability Assessment results.

#### With VA Data (5 components)

| Component                    | Max    | Source         | Description                                                                                                                                                                             |
| ---------------------------- | ------ | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Vulnerability Assessment** | **40** | VA Scan        | Weighted vulnerability density per domain + severity bonus. Uses `(critical×4 + high×3 + medium×2 + low×1) / domains` as base, with avg severity² as multiplier. **Largest component.** |
| **Credential Exposure**      | **30** | LeakCheck      | Based on **unchecked** (unreviewed) leaked credentials per domain. Reviewing credentials actively reduces the score.                                                                    |
| Threat Exposure              | 12     | OTX AlienVault | Ratio of monitored domains appearing in threat intelligence feeds                                                                                                                       |
| OTX Reputation               | 10     | OTX AlienVault | Direct reputation assessment of the domain by OTX                                                                                                                                       |
| Malware Association          | 8      | OTX AlienVault | Feed-based malware references (not actual malware in your environment)                                                                                                                  |

#### Without VA Data (4 components)

When no vulnerability scan data is available, the weights are redistributed:

| Component               | Max    | Source                                              |
| ----------------------- | ------ | --------------------------------------------------- |
| **Credential Exposure** | **45** | LeakCheck — unchecked leaked credentials per domain |
| Threat Exposure         | 25     | OTX AlienVault                                      |
| OTX Reputation          | 20     | OTX AlienVault                                      |
| Malware Association     | 10     | OTX AlienVault                                      |

#### Credential Exposure Detail

The leak component uses **unchecked credentials** (not yet reviewed) as the primary risk driver:

- Unchecked credentials count at **full weight**
- Credentials marked as reviewed (checked) **actively reduce** the risk score
- This incentivizes teams to review and triage leaked credentials
- Score decreases proportionally as more credentials are reviewed

#### Vulnerability Assessment Detail

The VA component uses **weighted vulnerability density per domain** to naturally combine severity and volume:

```text
weighted_density = (critical×4 + high×3 + medium×2 + low×1) / total_domains
```

- **Base score** (70% of max): mapped from weighted density thresholds
- **Severity bonus** (30% of max): `(avg_severity / 4.0)²` — high avg severity gets exponentially more impact

Example scenarios (4 domains):

| Scenario                                | Avg Severity | Vuln Score /40 |
| --------------------------------------- | ------------ | -------------- |
| 10 Critical + 20 High                   | 3.33         | 36             |
| 3 Critical + 10 High + 2 Medium + 4 Low | 2.63         | 24             |
| 50 Medium                               | 2.00         | 31             |
| 100 Low                                 | 1.00         | 29             |
| 1 Critical only                         | 4.00         | 16             |

#### Color Indicators

- **Green** (0–30): Low risk
- **Yellow** (31–70): Medium risk
- **Red** (71–100): High risk

> **Design decisions:**
>
> - **VA is the largest component (40)** because actual vulnerability findings from scanning are the most actionable security data.
> - **Credential Exposure is second (30)** because leaked credentials represent confirmed breaches affecting users.
> - **Malware association is intentionally low (8)** because OTX data reflects feed-based references, not actual malware in the domain's infrastructure.
> - The formula is **consistent** across the main Dashboard, Threat Intel page, and PDF reports — all call the same `calculate_risk_score()` function.

### New API Endpoints

| Endpoint                                      | Method   | Description                                 |
| --------------------------------------------- | -------- | ------------------------------------------- |
| `/<slug>/threat-intel/`                       | GET      | Threat intelligence dashboard               |
| `/<slug>/threat-intel/refresh_all`            | POST     | Refresh all domains from OTX + LeakCheck    |
| `/<slug>/threat-intel/refresh_domain/<id>`    | POST     | Refresh single domain                       |
| `/<slug>/threat-intel/scan_status`            | GET      | Polling endpoint for scan progress          |
| `/<slug>/threat-intel/domain_detail/<id>`     | GET      | Full threat data for a domain               |
| `/<slug>/threat-intel/toggle_checked/<id>`    | POST     | Mark/unmark a leaked credential as reviewed |
| `/<slug>/threat-intel/add_indicator`          | POST     | Add a manual threat indicator               |
| `/<slug>/threat-intel/delete_indicator/<id>`  | POST     | Delete a manual indicator                   |
| `/<slug>/threat-intel/refresh_indicator/<id>` | POST     | Re-fetch threat data for a manual indicator |
| `/<slug>/threat-intel/indicator_detail/<id>`  | GET      | Full detail for a manual indicator          |
| `/<slug>/threat-intel/generate_report`        | GET      | Generate TI PDF report                      |
| `/<slug>/threat-intel/report_settings`        | GET/POST | Configure report settings                   |

---

## Architecture

### System Overview

```mermaid
graph TB
    Browser["Web Browser"] -->|HTTPS| Nginx["Nginx :443"]
    Nginx -->|HTTP| Django["Django :8000"]
    Django --> Postgres[("PostgreSQL")]
    Django -->|Tasks| Redis[("Redis")]
    Redis -->|Queue| Celery["Celery Workers"]
    Beat["Celery Beat"] -->|Scheduled| Redis
    Celery --> Postgres
    Celery --> Tools["Subfinder / Nuclei / Nmap / 50+ Tools"]
    Celery --> Ollama["Ollama LLM"]
    Django --> OTX["OTX AlienVault"]
    Django --> LC["LeakCheck API"]
    Django --> WPS["WPScan API"]
```

### Docker Infrastructure

```mermaid
graph LR
    proxy["nginx :443"] --> web["web :8000"]
    web --> db[("PostgreSQL :5432")]
    web --> redis[("Redis :6379")]
    celery["celery workers"] --> db
    celery --> redis
    celery --> ollama["Ollama :11434"]
    beat["celery-beat"] --> redis
```

### Threat Intelligence Data Flow

```mermaid
sequenceDiagram
    actor U as User
    participant W as Web App
    participant OTX as OTX AlienVault
    participant LC as LeakCheck
    U->>W: Click Refresh All
    W->>W: Get all project domains
    loop For each domain
        W->>OTX: GET general indicators
        OTX-->>W: Pulses, reputation, malware
        W->>OTX: GET passive DNS
        OTX-->>W: DNS records
        W->>LC: GET domain query
        LC-->>W: Leaked credentials
        W->>W: Cache results in DB
    end
    W-->>U: Update progress bar
    U->>W: View domain detail
    W-->>U: Show threat data in modal
```

### PDF Report Generation Flow

```mermaid
flowchart TD
    A["Generate Report"] --> B{"Settings"}
    B --> C["Language EN/ID"]
    B --> D["Company Logo"]
    B --> E["Doc Number"]
    B --> F["Exec Summary"]
    C --> G["Render Template"]
    D --> G
    E --> G
    F --> G
    G --> H["WeasyPrint to PDF"]
    H --> O["Download PDF"]
```

---

## Installation

### Prerequisites

- Linux server (Ubuntu 20.04+ / Debian 11+)
- Docker & Docker Compose v2
- Minimum 4 GB RAM, 2 CPU cores
- Open ports: 443 (HTTPS), 8082 (optional)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/anggipradana/ReNgGinaNg.git
cd ReNgGinaNg

# Create environment file
cp .env.example .env

# Edit .env — CHANGE ALL PASSWORDS!
nano .env

# Run installation
sudo ./install.sh
```

### Manual Install (Step by Step)

#### 1. Clone & Configure

```bash
git clone https://github.com/anggipradana/ReNgGinaNg.git
cd ReNgGinaNg
cp .env.example .env
```

#### 2. Edit Environment Variables

```bash
nano .env
```

**Important**: Change these values:

- `AUTHORITY_PASSWORD` — SSL certificate password
- `POSTGRES_PASSWORD` — Database password (use a strong one)
- `DJANGO_SUPERUSER_USERNAME` — Admin username
- `DJANGO_SUPERUSER_PASSWORD` — Admin password (use a strong one)

#### 3. Generate SSL Certificates

```bash
make certs
```

#### 4. Build & Start

```bash
# Build Docker images
make build

# Start all services
make up
```

#### 5. Access the Application

Open your browser and navigate to:

```text
https://your-server-ip
```

Login with the credentials from your `.env` file.

#### 6. Configure API Keys (Optional but Recommended)

Navigate to **Settings > API Vault** and add:

| API             | Purpose                          | Get Key                                          |
| --------------- | -------------------------------- | ------------------------------------------------ |
| OTX AlienVault  | Threat intelligence data         | [otx.alienvault.com](https://otx.alienvault.com) |
| LeakCheck       | Dark web breach data             | [leakcheck.io](https://leakcheck.io)             |
| WPScan          | WordPress vulnerability scanning | [wpscan.com](https://wpscan.com)                 |
| OpenAI / Ollama | LLM-powered analysis             | Local Ollama or OpenAI API                       |

### Docker Compose Commands

```bash
# Start services
make up

# Stop services
make stop

# View logs
make logs

# Rebuild after updates
make build && make up

# Run database migrations
docker compose exec web python3 manage.py migrate

# Create superuser manually
docker compose exec web python3 manage.py createsuperuser
```

---

## Usage

### Workflow Overview

```mermaid
flowchart LR
    A[Add Target] --> B[Create Scan Engine]
    B --> C[Start Scan]
    C --> D[View Results]
    D --> E[Threat Intel]
    E --> F[Generate Report]

    style A fill:#4CAF50,color:#fff
    style F fill:#2196F3,color:#fff
```

### 1. Adding Targets

1. Click **Targets** in the navigation
2. Click **Add Target**
3. Enter the domain (e.g., `example.com`)
4. Optionally add description and organization
5. Click **Save**

### 2. Configuring Scan Engines

ReNgGinaNg comes with pre-configured scan engines:

| Engine                     | Description                          |
| -------------------------- | ------------------------------------ |
| **ReNgGinaNg Recommended** | Full reconnaissance pipeline         |
| **Full Scan**              | All tools enabled, thorough scanning |
| **Subdomain Discovery**    | Subdomain enumeration only           |
| **OSINT**                  | Open-source intelligence gathering   |
| **Vulnerability Scan**     | Nuclei-based vulnerability scanning  |

Custom engines can be created via **Scan Engine > Add Engine** using YAML configuration.

### 3. Running Scans

1. Go to **Dashboard**
2. Select a target domain
3. Choose a scan engine
4. Click **Start Scan**
5. Monitor progress in real-time

### 4. Threat Intelligence

1. Navigate to **Threat Intel** from the top menu
2. Ensure API keys are configured (Settings > API Vault)
3. Click **Refresh All** to scan all domains
4. View summary cards: Risk Score, Pulses, Malware, Leaks
5. Click the eye icon on any domain for detailed threat data
6. Add manual indicators via the **Manual Indicators** section

### 5. Generating Reports

#### Vulnerability Assessment Report

1. Go to **Dashboard**
2. Click **Generate VA Report**
3. Select language (English / Bahasa Indonesia)
4. Download PDF

#### Threat Intelligence Report

1. Go to **Threat Intel**
2. Configure report settings (logo, document number, executive summary)
3. Click **Generate Report**
4. Download PDF

---

## API Reference

### Authentication

All API endpoints require session authentication. Login via the web interface first.

### Endpoints Overview

```mermaid
graph LR
    API["ReNgGinaNg API"] --> Scan["Scan: start, stop, status"]
    API --> Target["Target: list, add, subdomains"]
    API --> Recon["Recon: vulns, endpoints, techs"]
    API --> TI["Threat Intel: refresh, detail, report"]
```

### Scan Operations

| Method | Endpoint                       | Description           |
| ------ | ------------------------------ | --------------------- |
| POST   | `/api/scan/start/<target_id>/` | Start a new scan      |
| GET    | `/api/scan/status/<scan_id>/`  | Get scan status       |
| POST   | `/api/scan/stop/<scan_id>/`    | Stop running scan     |
| GET    | `/api/listScanHistory/`        | List all scan history |

### Reconnaissance Data

| Method | Endpoint                     | Description                  |
| ------ | ---------------------------- | ---------------------------- |
| GET    | `/api/querySubdomains/`      | Query discovered subdomains  |
| GET    | `/api/queryEndpoints/`       | Query discovered endpoints   |
| GET    | `/api/queryVulnerabilities/` | Query found vulnerabilities  |
| GET    | `/api/listTechnologies/`     | List detected technologies   |
| GET    | `/api/listPorts/`            | List discovered ports        |
| GET    | `/api/listIPs/`              | List discovered IP addresses |

### Threat Intelligence

| Method   | Endpoint                                      | Description                                 |
| -------- | --------------------------------------------- | ------------------------------------------- |
| POST     | `/<slug>/threat-intel/refresh_all`            | Refresh all domain threat data              |
| POST     | `/<slug>/threat-intel/refresh_domain/<id>`    | Refresh single domain                       |
| GET      | `/<slug>/threat-intel/scan_status`            | Get refresh progress                        |
| GET      | `/<slug>/threat-intel/domain_detail/<id>`     | Get full threat detail                      |
| POST     | `/<slug>/threat-intel/toggle_checked/<id>`    | Mark/unmark a leaked credential as reviewed |
| POST     | `/<slug>/threat-intel/add_indicator`          | Add a manual threat indicator               |
| POST     | `/<slug>/threat-intel/delete_indicator/<id>`  | Delete a manual indicator                   |
| POST     | `/<slug>/threat-intel/refresh_indicator/<id>` | Re-fetch threat data for a manual indicator |
| GET      | `/<slug>/threat-intel/indicator_detail/<id>`  | Full detail for a manual indicator          |
| GET      | `/<slug>/threat-intel/generate_report`        | Generate TI report                          |
| GET/POST | `/<slug>/threat-intel/report_settings`        | Configure report settings                   |

---

## Project Structure

```text
ReNgGinaNg/
├── config/
│   └── nginx/              # Nginx reverse proxy config
├── docs/
│   └── images/             # Logo and documentation images
├── scripts/                # Utility scripts
├── web/
│   ├── ReNgGinaNg/         # Django project (settings, celery, tasks)
│   ├── api/                # REST API views and serializers
│   ├── dashboard/          # Main dashboard app
│   ├── scanEngine/         # Scan engine configuration
│   ├── startScan/          # Scan execution and history
│   ├── targetApp/          # Target management
│   ├── threatIntel/        # Threat Intelligence module (NEW)
│   ├── static/             # CSS, JS, images
│   ├── templates/          # Shared templates, reports
│   └── fixtures/           # Default scan engines, tools
├── docker-compose.yml
├── Makefile
├── install.sh
└── .env.example
```

---

## Troubleshooting

### Common Issues

**Cannot access the web interface**

```bash
# Check if all containers are running
docker compose ps

# Check web container logs
docker compose logs web

# Restart all services
make stop && make up
```

**Database migration errors**

```bash
docker compose exec web python3 manage.py migrate
```

**Static files not loading**

```bash
docker compose exec web python3 manage.py collectstatic --noinput
```

**Celery workers not processing tasks**

```bash
# Check celery logs
docker compose logs celery

# Restart celery
docker compose restart celery
```

---

## Credits

ReNgGinaNg is built upon the excellent foundation of [reNgine](https://github.com/yogeshojha/rengine) by Yogesh Ojha. We extend our gratitude to the original author and all contributors.

This fork includes significant enhancements for professional security operations while maintaining full compatibility with the original reconnaissance engine.

---

## License

Distributed under the GNU General Public License v3.0. See `LICENSE` for more information.
