# Backend

The backend consists of two services:

- **Go Core** — HTTP workflow API, trusted gRPC API, PCAP analysis, Fusion,
  security scoring, and PDF reports.
- **Python ML worker** — internal gRPC inference for encrypted-flow metadata
  classification. It is optional for an analysis, but included in the standard
  setup.

The browser does not connect to either gRPC service directly. The Next.js
frontend calls Go Core through its server-side API route.

## Prerequisites

For local development, install:

- Go 1.22+
- Python 3.11+
- Docker and Docker Compose (recommended, to run both services together)

The repository includes the selected ML model and metadata required for the ML
container image. No database or `.env` file is required for the offline PCAP
workflow.

## Start with Docker (recommended)

From the repository root, build and start both backend services:

```bash
docker compose up --build --detach
```

Or use the root Makefile:

```bash
make up
```

Check that Go Core is available:

```bash
curl http://127.0.0.1:8080/health
```

`status: ready` means the offline PCAP workflow is ready. The response also
reports whether the optional ML worker is available. View logs or stop the
stack with:

```bash
make logs
make down
```

Run the included end-to-end PCAP demonstration after the services are up:

```bash
make demo
```

## Start locally without Docker

Run the ML worker and Go Core in separate terminals. From `backend/ml-service`:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-runtime.txt
python -m src.grpc_server
```

Then, from `backend`, start Go Core. The default ML address already points to
the worker above (`127.0.0.1:50051`):

```bash
go run ./src/cmd/server
```

Verify the service:

```bash
curl http://127.0.0.1:8080/live
curl http://127.0.0.1:8080/health
```

To run Go Core without ML classification, it can still start with an
unavailable `ML_GRPC_ADDRESS`; create analyses with ML disabled in the UI.

## Connect the frontend

With Go Core running, start the dashboard from a third terminal:

```bash
cd frontend
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

Open <http://localhost:3000>. If Core runs on a different host or port, set
`CORE_HTTP_URL` before starting Next.js:

```bash
CORE_HTTP_URL=http://127.0.0.1:8080 pnpm dev
```

## Addresses and configuration

| Service | Default address | Environment variable |
| --- | --- | --- |
| Go Core HTTP API | `127.0.0.1:8080` | `CORE_HTTP_ADDRESS` |
| Go Core trusted gRPC API | `127.0.0.1:50052` | `CORE_GRPC_ADDRESS` |
| Python ML gRPC worker | `127.0.0.1:50051` | `ML_GRPC_ADDRESS` (used by Go Core) |
| Temporary PDF report directory | system temporary directory | `REPORT_TEMP_DIRECTORY` |

Docker Compose exposes ports `8080` and `50052` from Go Core and connects Core
to the ML worker over the private Compose network. It sets the Core listener
addresses to `0.0.0.0` inside the container.

## API workflow

The dashboard uses these HTTP endpoints:

1. `POST /api/v1/pcap` — upload a classic `.pcap` or `.cap` file.
2. `POST /api/v1/analyses` — start analysis for the returned source ID.
3. `GET /api/v1/analyses/{analysisID}` — poll for completion.
4. `POST /api/v1/analyses/{analysisID}/report` — generate a report.
5. `GET /api/v1/reports/{reportID}/download` — download the PDF.

PCAPNG is not accepted by the browser workflow. Convert it first:

```bash
editcap -F libpcap input.pcapng output.pcap
```

Uploaded captures are analyzed passively; the system does not decrypt ESP
payloads. Live capture and VICI/XFRM deep assessment need an authorised
Linux/StrongSwan environment and any required host permissions.

## Development checks

From `backend`:

```bash
go vet ./...
go test ./...
go build ./...
```

The backend Makefile also provides `make fmt`, `make test`, `make vet`, and
`make build`. To run all repository checks, use `make check` from the root.

For ML model training, evaluation, and ML-worker-specific commands, see the
[ML service README](ml-service/README.md).
