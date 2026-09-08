# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

Project for Smart India Hackathon 2026 — Problem Statement 26160 (NTRO,
Blockchain & Cybersecurity).

The application analyzes IPsec VPN packet captures, extracts protocol and
security evidence, scores security posture, classifies encrypted-flow metadata
when the ML worker is available, and produces dashboard and PDF reports. It
does not decrypt ESP payloads.

## Quick start

### Requirements

- Docker Desktop / Docker Engine with Docker Compose
- Node.js 20+ and Corepack (for the frontend)
- `curl` (optional, for the health check and demo)

### 1. Configure and start backend services

From the repository root:

```bash
cp .env.example .env
make up
```

This builds and starts the Go Core API and Python ML worker. The frontend is
deployed separately on Vercel.
Wait a moment, then verify Core:

```bash
curl http://127.0.0.1:8080/health
```

For Azure VM setup, public-repository clone, and `.pem` SSH commands, see
[the backend VM runbook](docs/AZURE_VM_BACKEND_DEPLOYMENT.md).

### 2. Try the included demo (optional)

From the repository root, while the backend services are running:

```bash
make demo
```

The script uploads the included sample capture and waits for an ML-enabled
analysis to finish.

### Stop the backend services

```bash
make down
```

Use `make logs` to follow their logs. The Azure VM runbook deploys the API on
port 8080 and uses the Vercel server-side proxy, so no frontend container or
HTTPS gateway is required.

## Local development without Docker

Install Go 1.22+ and Python 3.11+, then run the services in separate terminals.

```bash
# Terminal 1
cd backend/ml-service
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-runtime.txt
python -m src.grpc_server
```

```bash
# Terminal 2
cd backend
go run ./src/cmd/server
```

```bash
# Terminal 3
cd frontend
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

Go Core listens on `127.0.0.1:8080`; its default ML-worker address is
`127.0.0.1:50051`. Set `CORE_HTTP_URL` before running the frontend only when
Core is hosted elsewhere:

```bash
CORE_HTTP_URL=http://host.docker.internal:8080 pnpm dev
```

## Repository layout

```text
.
├── backend/        Go Core API, analysis and security services
│   └── ml-service/ Python metadata-classification gRPC worker
├── frontend/       Next.js dashboard
├── ipsec_esp/      Sample/legacy PCAP fixtures (not ML training data)
├── scripts/        End-to-end demonstration script
└── compose.yaml    Backend + ML worker Docker setup
```

## Key details

- Use classic PCAP (`.pcap` or `.cap`) files. Convert PCAPNG first with
  `editcap -F libpcap input.pcapng output.pcap`.
- ML predictions classify observable flow metadata, not encrypted payload
  contents. `UNKNOWN` is a low-confidence abstention, not an error.
- The normal MVP workflow is offline PCAP analysis. Live capture and VICI/XFRM
  assessment require an authorised Linux/StrongSwan lab and host permissions.

## Documentation

- [Backend setup and API](backend/README.md)
- [ML worker](backend/ml-service/README.md)
- [Frontend dashboard](frontend/README.md)
- [Submission guide](docs/SUBMISSION_GUIDE.md)
- [ML validation protocol](docs/MODEL_VALIDATION.md)
- [Deep Assessment lab validation](docs/DEEP_ASSESSMENT_LAB.md)
- [Azure Container Apps deployment](docs/AZURE_DEPLOYMENT.md)

## Team

- Daksh Pathak
- Naman Jain
- Anvay
- Riya Shukla
- Yatika Goel
- Shubh
