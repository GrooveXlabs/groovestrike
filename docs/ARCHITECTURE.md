# GrooveStrike — System Architecture

## High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERFACE                                  │
│  ┌──────────┐  ┌──────────┐                                                │
│  │   CLI    │  │   API    │  (FastAPI)                                    │
│  │ (Click)  │  │ (Server) │                                                │
│  └────┬─────┘  └────┬─────┘                                                │
│       └─────────────┘                                                        │
│              │                                                               │
└──────────────┼───────────────────────────────────────────────────────────────┘
               │
┌──────────────▼───────────────────────────────────────────────────────────────┐
│                           ORCHESTRATION ENGINE                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │  Engagement Manager  →  Scope Parser  →  Phase Controller               │ │
│  │  (create/manage)      (IPs/domains)     (recon→discover→exploit→report)│ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└──────────────┬───────────────────────────────────────────────────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌──────────────┐ ┌──────────────┐
│  RECON       │ │  DISCOVERY   │
│  ENGINE      │ │  ENGINE      │
│  ─────────── │ │  ─────────── │
│  • Port Scan │ │  • Static    │
│  • Subdomain │ │    (GrooveG) │
│  • Tech Fp   │ │  • Dynamic   │
│  • API Disc  │ │  • Service   │
│  • Screenshot│ │  • Version   │
└──────┬───────┘ └──────┬───────┘
       │                │
       └───────┬────────┘
               ▼
┌──────────────────────────────────┐
│     ATTACK PATH PLANNER          │
│  ┌────────────┐  ┌────────────┐  │
│  │   Graph    │  │   MITRE    │  │
│  │  Builder   │  │   Mapper   │  │
│  └────────────┘  └────────────┘  │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│      SAFE VALIDATOR              │
│  • Benign PoC execution          │
│  • Sandbox verification          │
│  • Impact scoring                │
└──────────────┬───────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌──────────────┐ ┌──────────────┐
│   REPORTER   │ │   BRIDGE     │
│  ─────────── │ │  ─────────── │
│  • Executive │ │  • Sigma     │
│  • Technical │ │  • Atomic    │
│  • PDF/MD    │ │  • GrooveHub │
└──────────────┘ └──────────────┘
```

---

## Component Breakdown

### 1. Engine (`engine.py`)
**Responsibility**: Central orchestrator that manages engagement lifecycle.

```python
class EngagementEngine:
    def create_engagement(name: str, scope: Scope) -> Engagement
    def run_phase(engagement_id: int, phase: Phase) -> Result
    def generate_report(engagement_id: int, format: Format) -> Path
    def revalidate(engagement_id: int) -> DiffReport
```

### 2. Models (`models.py`)
**Responsibility**: SQLAlchemy ORM for engagement data.

**Entities**:
- `Engagement` — Top-level pentest container
- `Target` — Individual scope item (IP, domain, URL)
- `Finding` — Discovered vulnerability
- `AttackPath` — Chained exploitation sequence
- `Report` — Generated report metadata
- `Validation` — PoC execution result

### 3. Reconnaissance (`recon.py`)
**Responsibility**: Information gathering without exploitation.

```python
class ReconEngine:
    def port_scan(targets: list[str], ports: list[int]) -> list[PortResult]
    def subdomain_enum(domain: str) -> list[str]
    def fingerprint(url: str) -> TechStack
    def discover_api(base_url: str) -> list[Endpoint]
    def screenshot(url: str) -> Path
```

### 4. Discovery (`discovery.py`)
**Responsibility**: Vulnerability identification.

```python
class DiscoveryEngine:
    def static_scan(repo_path: Path) -> list[Finding]  # GrooveGuard integration
    def dynamic_probe(target: Target) -> list[Finding]
    def check_service_versions(services: list[Service]) -> list[Finding]
```

### 5. Planner (`planner.py`)
**Responsibility**: Build attack graphs from findings.

```python
class AttackPlanner:
    def build_graph(findings: list[Finding]) -> AttackGraph
    def find_paths(graph: AttackGraph, entry: Node, goal: Node) -> list[Path]
    def score_path(path: Path) -> float  # likelihood * impact
    def map_mitre(findings: list[Finding]) -> list[MitreMapping]
```

### 6. Validator (`validator.py`)
**Responsibility**: Safe proof-of-concept execution.

```python
class SafeValidator:
    def validate_ssrf(target: str, payload: str) -> ValidationResult
    def validate_cmd_injection(target: str, payload: str) -> ValidationResult
    def validate_path_traversal(target: str, payload: str) -> ValidationResult
    def validate_sqli(target: str, payload: str) -> ValidationResult
```

### 7. Reporter (`reporter.py`)
**Responsibility**: Professional report generation.

```python
class ReportGenerator:
    def generate_executive(engagement: Engagement) -> str
    def generate_technical(findings: list[Finding]) -> str
    def generate_attack_paths(paths: list[AttackPath]) -> str
    def to_pdf(content: str, output: Path) -> Path
    def to_markdown(content: str, output: Path) -> Path
```

### 8. Bridge (`bridge.py`)
**Responsibility**: Export to defensive tools.

```python
class PurpleForgeBridge:
    def export_sigma(findings: list[Finding]) -> list[SigmaRule]
    def export_atomic(findings: list[Finding]) -> list[AtomicTest]
    def export_to_groovehub(engagement: Engagement) -> dict
```

---

## Data Flow

### Engagement Lifecycle

```
1. CREATE: User defines scope → Engine creates Engagement + Targets
2. RECON:  Engine triggers ReconEngine → stores PortResults, Services
3. DISCOVER: Engine triggers DiscoveryEngine → stores Findings
4. PLAN:    Engine triggers AttackPlanner → stores AttackPaths
5. VALIDATE: Engine triggers SafeValidator → stores Validations
6. REPORT:  Engine triggers ReportGenerator → stores Report file
7. BRIDGE:  Engine triggers PurpleForgeBridge → exports Sigma + Atomic
```

### Revalidation Flow

```
1. LOAD:   Engine loads previous Engagement baseline
2. RE-RUN: Steps 2-6 on same scope
3. DIFF:   Engine compares findings (fixed / new / persistent)
4. REPORT: Generate trend report with delta visualization
```

---

## Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Language | Python 3.10+ | Ecosystem, GrooveGuard compatibility |
| CLI | Click + Rich | Industry standard, beautiful output |
| API | FastAPI | Async, auto-docs, GrooveHub-compatible |
| DB | SQLite (default), PostgreSQL (optional) | Lightweight MVP, enterprise upgrade path |
| ORM | SQLAlchemy 2.0 | Familiar, robust |
| PDF | fpdf2 | Pure Python, no external deps |
| Web | Playwright (optional) | Screenshot, browser-based recon |
| Network | Python sockets + threading | No nmap dependency |
| Static | GrooveGuard (optional) | Existing ecosystem integration |

---

## Database Schema

```sql
engagements
├── id (PK)
├── name
├── description
├── status (created|recon|discovery|exploitation|reporting|completed)
├── created_at
└── updated_at

targets
├── id (PK)
├── engagement_id (FK)
├── type (ip|domain|url|cidr|repo)
├── value
├── excluded (bool)
└── metadata (JSON)

findings
├── id (PK)
├── engagement_id (FK)
├── target_id (FK)
├── title
├── severity (critical|high|medium|low|info)
├── category (ssrf|cmdi|pathtraversal|sqli|secret|cve|misconfig)
├── description
├── evidence
├── cvss_score
├── cvss_vector
├── validated (bool)
└── created_at

attack_paths
├── id (PK)
├── engagement_id (FK)
├── name
├── steps (JSON array of finding IDs)
├── mitre_techniques (JSON)
├── likelihood_score
├── impact_score
└── overall_score

validations
├── id (PK)
├── finding_id (FK)
├── status (success|failed|error|skipped)
├── poc_command
├── poc_output
├── safe (bool)
└── executed_at

reports
├── id (PK)
├── engagement_id (FK)
├── format (pdf|markdown|json)
├── file_path
├── generated_at
```

---

## API Design

### REST Endpoints

```
POST   /engagements              → Create engagement
GET    /engagements              → List engagements
GET    /engagements/{id}         → Get engagement details
DELETE /engagements/{id}         → Delete engagement

POST   /engagements/{id}/recon   → Start reconnaissance
POST   /engagements/{id}/discover → Start discovery
POST   /engagements/{id}/plan    → Build attack paths
POST   /engagements/{id}/validate → Run safe validations
POST   /engagements/{id}/report  → Generate report
POST   /engagements/{id}/revalidate → Compare with baseline

GET    /engagements/{id}/findings → List findings
GET    /engagements/{id}/paths    → List attack paths
GET    /engagements/{id}/report   → Download latest report

POST   /export/sigma             → Export Sigma rules
POST   /export/atomic            → Export atomic tests
```

---

## Security Considerations

1. **Safe-Only Validation**: All PoCs use benign commands. No reverse shells, no data exfiltration.
2. **Scope Enforcement**: Engine validates all targets against scope before any operation.
3. **Audit Logging**: Every command executed is logged with timestamp, target, and output.
4. **Rate Limiting**: Built-in delays between requests to avoid being disruptive.
5. **No Privilege Escalation**: Tool runs as current user only.
