# GrooveStrike

> **Autonomous Penetration Testing Framework**
>
> The first MCP-native pentest tool that closes the loop from **find → exploit → report → defend → revalidate**.

---

## Why GrooveStrike?

Enterprise pentest tools cost **$50,000+/year** (Pentera, NodeZero). Autonomous tools like Pentagi require **Docker battleships** with 3 databases. Bug bounty hunters and small security teams are left with manual tool chaining.

GrooveStrike is **pip-installable**, runs natively on Windows/macOS/Linux, and integrates with your existing GrooveGuard static analysis to auto-validate findings, chain attack paths, generate professional reports, and export defensive Sigma rules.

| Competitor | Price | Infra | Our Edge |
|-----------|-------|-------|----------|
| Pentagi | Free (LLM costs) | Docker + 3 DBs | Native Python, no containers |
| Pentera | ~$50k/yr | Cloud-only | Open source, static→dynamic bridge |
| NodeZero | ~$50k/yr | SaaS | Continuous revalidation + defense generation |
| PentestGPT | Free | Assistant only | Fully autonomous with MCP |

---

## Quick Start

```bash
pip install groovestrike

# Create engagement
groovestrike engage "Web App Pentest" \
  -t url:https://example.com \
  -t ip:10.0.0.1

# Run reconnaissance
groovestrike recon 1

# Discover vulnerabilities
groovestrike scan 1

# Build attack paths
groovestrike plan 1

# Validate with safe PoCs
groovestrike validate 1

# Generate professional report
groovestrike report 1 --format markdown

# Export to Sigma + Atomic tests
groovestrike export 1
```

---

## Architecture

```
Engagement → Recon → Discovery → Planning → Validation → Reporting → Export
    │           │          │           │           │           │         │
    ▼           ▼          ▼           ▼           ▼           ▼         ▼
 Scope      Port      Static      Attack      Safe PoC    Executive   Sigma
 Mgmt       Scan      + Dynamic   Paths       Engine      + Technical Rules
```

---

## Features

### Engagement Management
- Named engagements with scope definitions (IPs, domains, URLs, CIDR blocks, repos)
- Exclusion lists and status tracking
- SQLite storage (PostgreSQL optional)

### Reconnaissance Engine
- Multi-threaded TCP port scanning (top 1000 ports)
- Subdomain enumeration via crt.sh
- Technology fingerprinting (WordPress, Django, Next.js, nginx, etc.)
- API endpoint discovery
- Service banner grabbing

### Vulnerability Discovery
- **Static**: GrooveGuard integration for code analysis
- **Dynamic**: Safe probes for SSRF, command injection, path traversal, SQL injection
- **Network**: Service version detection

### Attack Path Planner
- Graph-based vulnerability chaining
- MITRE ATT&CK technique mapping
- Path scoring (likelihood × impact)
- Multi-hop exploit chains

### Safe Exploit Validation
- **Benign PoCs only** — no actual harm
- SSRF probes internal endpoints
- Command injection runs `whoami`, `hostname`
- Path traversal checks for `/etc/passwd` patterns
- SQL injection uses time-based detection

### Professional Reporting
- Executive summary with risk score
- Technical findings with CVSS scores
- Attack path visualizations
- Remediation advice per finding
- Formats: Markdown, HTML, JSON

### PurpleForge Bridge
- Auto-export Sigma detection rules
- Generate atomic test scripts
- GrooveHub-compatible export format

---

## API

GrooveStrike exposes a FastAPI REST API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/engagements` | Create engagement |
| `GET`  | `/engagements` | List engagements |
| `GET`  | `/engagements/{id}` | Get engagement |
| `DELETE`| `/engagements/{id}` | Delete engagement |
| `GET`  | `/engagements/{id}/findings` | List findings |
| `GET`  | `/engagements/{id}/paths` | List attack paths |
| `GET`  | `/engagements/{id}/report` | Get report |
| `POST` | `/export/sigma` | Export Sigma rules |
| `POST` | `/export/atomic` | Export atomic tests |

```bash
groovestrike serve  # Starts on http://127.0.0.1:8001
```

---

## Development

```bash
git clone https://github.com/GrooveXlabs/groovestrike.git
cd groovestrike
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -v
```

---

## Ecosystem

| Project | Role |
|---------|------|
| [grooveguard](https://github.com/GrooveXlabs/grooveguard) | Static security scanner |
| [groovehub](https://github.com/GrooveXlabs/groovehub) | MCP server registry with scoring |
| **groovestrike** | Autonomous pentest framework |

---

## License

MIT — GrooveXlabs
