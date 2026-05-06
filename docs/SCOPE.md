# GrooveStrike — Scope Definition

## MVP v0.1.0 (Build Now)

### In Scope

| Module | Features | Files |
|--------|----------|-------|
| **Engagement** | Create, list, delete engagements; scope definition (IPs, domains, URLs); status tracking | `engine.py`, `models.py` |
| **Reconnaissance** | Port scanner (TCP, top 1000), banner grabber, subdomain enum (crt.sh), tech fingerprinting, API discovery | `recon.py` |
| **Vulnerability Discovery** | GrooveGuard static integration, dynamic safe probes (SSRF, CMDi, path traversal), service version checks | `discovery.py` |
| **Attack Path Planner** | Graph-based chaining, MITRE mapping, path scoring | `planner.py` |
| **Safe Validator** | Benign PoC engine for 6 finding types; no actual exploitation | `validator.py` |
| **Report Generator** | Executive summary, technical findings with CVSS, attack paths, appendices; PDF + Markdown output | `reporter.py` |
| **CLI** | `groovestrike engage`, `groovestrike recon`, `groovestrike scan`, `groovestrike report`, `groovestrike validate` | `cli.py` |
| **API** | FastAPI server mode for remote operation | `api.py` |
| **PurpleForge Bridge** | Auto-export findings to Sigma + atomic test format | `bridge.py` |
| **Tests** | 30+ unit tests covering all modules | `tests/` |

### Out of Scope (v1.0+)
- AI-powered reasoning (LLM agent orchestration)
- Web application scanner (Burp/ZAP integration)
- Active Directory pentesting
- Wireless/network protocol testing
- Dashboard UI (React/Vue)
- Compliance mapping (SOC2, PCI-DSS)
- Multi-user RBAC
- CI/CD plugins

---

## v1.0 Scope (Next Phase)

- AI attack path reasoning with local LLM support
- Web app scanner (form fuzzing, auth bypass detection)
- Credential stuffing / brute force modules
- Cloud-specific tests (AWS/Azure/GCP metadata services)
- Jenkins/GitHub Actions plugin
- HTML dashboard (Streamlit)

---

## v2.0 Scope (Enterprise)

- Multi-agent orchestration (like Pentagi but lighter)
- Real-time collaboration (multiple pentesters)
- Custom exploit module system
- Compliance report templates
- SSO/SAML integration
- Enterprise support tier
