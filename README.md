# SIH26160: AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

> Smart India Hackathon 2026 | PS ID: **26160** | Theme: **Blockchain & Cybersecurity** | Category: **Software**

Team Alchemist's solution provides a passive, evidence-based way to inspect IPsec VPN packet captures. It extracts observable IKE/ESP protocol facts, assesses the security posture of the VPN configuration, classifies encrypted traffic from flow metadata, and produces dashboard and PDF reports. The system does **not** decrypt ESP payloads.

## Problem Statement

Reviewing the security posture of an IPsec VPN can require packet-level expertise and time-consuming manual inspection. Security teams need a clear way to analyse captured VPN traffic, identify protocol or configuration weaknesses, understand the associated evidence, and prepare reports without exposing encrypted payload contents.

## Proposed Solution

The application accepts a classic PCAP capture and runs a passive analysis workflow. The Go backend extracts IPsec/IKE evidence and calculates security findings; a Python ML worker optionally classifies observable encrypted-flow metadata; and a Next.js dashboard presents the results and generates an executive PDF report.

## Key Features

- Upload and analyse classic `.pcap` and `.cap` files
- Passive IKE, ESP, NAT-T, SA, cipher-suite, DH-group, PFS, and metadata assessment
- Evidence-backed security posture and risk findings
- Optional ML classification of observable flow metadata with confidence and `UNKNOWN` abstention
- Fusion of protocol, security, and ML conclusions
- Interactive dashboard, analysis history, and downloadable PDF reports
- Optional live-capture and XFRM/VICI assessment for authorised Linux/StrongSwan labs

## Technology Stack

| Layer | Technologies |
| --- | --- |
| Frontend | Next.js, TypeScript, React, CSS |
| Core backend | Go, HTTP API, gRPC, Protocol Buffers |
| ML service | Python 3.11+, scikit-learn, NumPy, gRPC |
| Deployment | Azure Container Apps, managed HTTPS ingress, Azure Files; Docker Compose for local development |
| Report assistant | Qwen LLM deployment for plain-language explanations of saved report snapshots |
| Input | PCAP packet captures; optional StrongSwan/Linux lab telemetry |

## Architecture

See [docs/architecture.md](docs/architecture.md) for the detailed architecture.

```text
Security Analyst / Authorised Browser
                  |
                HTTPS
                  v
Azure Container Apps — managed HTTPS ingress / TLS
                  |
      ┌───────────┴──────────────────────────┐
      v                                      v
Next.js Dashboard + BFF              Qwen LLM Report Assistant
upload, orchestration, results       plain-language report explanations
      |
      | HTTP proxy
      v
Go Core — Trusted Analysis Plane
  ├── PCAP ingest and protocol sensor (IKE, ESP, AH, NAT-T)
  ├── Flow metadata windows
  ├── Security & risk assessment
  ├── Evidence fusion
  └── Report engine (dashboard + PDF)
      | private gRPC                   |
      v                                v
Python ML worker                  Azure Files
metadata-only classification      persistent generated PDF reports
confidence and UNKNOWN
```

## Repository Structure

```text
SIH26160/
├── README.md
├── SUBMISSION_GUIDE.md
├── compose.yaml
├── Makefile
├── frontend/                     # Next.js dashboard (kept in its original folder)
├── backend/                      # Go API, protocol/security logic, and ML service
│   └── ml-service/               # Python gRPC ML worker
├── docs/
│   └── architecture.md
├── assets/
│   ├── alchemist-ipsec-analysis-report.pdf
│   └── screenshots/              # Product screenshots
└── submission/
    ├── DEMO.md
    └── SIH26160-Team-Alchemist.pdf
```

## Submission Material

- [Demo video](submission/DEMO.md)
- [Landing page screenshot](assets/screenshots/landing_page.png)
- [PCAP upload screenshot](assets/screenshots/pcap_upload.png)
- [Analysis dashboard screenshot](assets/screenshots/analysis_dashboard.png)
- [Traffic classifier screenshot](assets/screenshots/traffic_classifier.png)
- [Sample generated analysis report](assets/alchemist-ipsec-analysis-report.pdf)

## Installation and Run

### Prerequisites

- Docker Engine/Desktop with Docker Compose (recommended)
- Node.js 20+ with Corepack, Go 1.22+, and Python 3.11+ for local development

### Recommended: run the backend services with Docker

```bash
git clone <YOUR_REPOSITORY_URL>
cd SIH26160
cp .env.example .env
make up
```

Verify that the Core API is ready:

```bash
curl http://127.0.0.1:8080/health
```

Start the frontend in another terminal:

```bash
cd frontend
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

Open `http://localhost:3000`. Stop backend services with `make down`; use `make logs` to inspect service logs.

### Local development without Docker

Run these in separate terminals:

```bash
# Terminal 1 — ML worker
cd backend/ml-service
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-runtime.txt
python -m src.grpc_server
```

```bash
# Terminal 2 — Go Core API
cd backend
go run ./src/cmd/server
```

```bash
# Terminal 3 — Dashboard
cd frontend
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

The API listens on `http://127.0.0.1:8080`; the ML worker defaults to `127.0.0.1:50051`. If Core is remote, set `CORE_HTTP_URL` before starting the frontend.

## Usage

1. Open the dashboard and upload a classic `.pcap` or `.cap` file.
2. Start analysis; enable ML classification when the worker is available.
3. Review protocol evidence, security findings, risk information, and ML output.
4. Generate and download the executive PDF report.

PCAPNG is not accepted by the browser workflow. Convert it first:

```bash
editcap -F libpcap input.pcapng output.pcap
```

## Limitations and Responsible Use

- The system analyses metadata and observable protocol facts only; it does not decrypt ESP payloads.
- `UNKNOWN` is a low-confidence ML abstention, not an error or security finding.
- ML traffic labels describe candidate traffic classes from flow metadata and are not proof of a user's activity.
- Live capture and VICI/XFRM assessment require an authorised Linux/StrongSwan lab and appropriate host permissions.

## Future Scope

- Add more independently collected IPsec traffic captures and continuous model validation.
- Support secure role-based analyst collaboration and managed report retention.
- Extend authorised lab integrations for real-time, multi-gateway monitoring.
- Add configurable organisation-specific security policies and compliance mappings.
- Improve explainability and trend analysis across historical assessments.

## Security Notice

Do not commit passwords, API keys, access tokens, private captures, `.env` files containing secrets, or other confidential information. Use the provided `.env.example` files as templates only.
