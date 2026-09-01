                 INPUT
          ┌────────┴────────┐
          │                 │
     Upload PCAP       Live VPN Traffic
          │                 │
          └────────┬────────┘
                   ▼
              ONE GO SERVER
                   │
                   ▼
          Go Sensor Module
          Protocol Analysis
          IKE / ESP / AH / NAT-T
          SPI / SA Tracking
          Flow Feature Windows
                   │
          ┌────────┴────────┐
          │                 │ gRPC process boundary
          ▼                 ▼
 Protocol / Gateway   PYTHON ML WORKER
 Evidence             Selected Tree Classifier
                      Confidence + SHAP
          │                 │
          └────────┬────────┘
                   ▼
          Evidence Fusion Engine
          Confidence / Provenance
          Conflict Resolution
          Fused Conclusions
                   │
                   ▼
          Security Engine
          Rules / Risk Score
          Threat Matrix
          Recommendations
          Reports
                   │
                   ▼
       NEXT.JS FRONTEND
       Browser HTTP via Next.js server route
             │
       ┌─────┼───────────┐
       ▼     ▼           ▼
 Dashboard Live View   Reports

The Go Sensor, Go Core Backend / Security Engine, and Evidence Fusion
Engine are logical modules in the same Go process. They communicate through
Go interfaces, function calls, channels, shared domain models, and controlled
in-memory state. Do not introduce gRPC between these Go modules in v1.

The only v1 process-boundary gRPC contracts are:

- trusted/native client to Go Core; browser requests use a Next.js server adapter
- Go Server to the Python ML Worker

Only Core services are registered on the external Go gRPC server. Sensor and
Fusion remain internal Go packages. See
[`src/internal/docs/ARCHITECTURE_MVP.md`](src/internal/docs/ARCHITECTURE_MVP.md).

## Containers

The backend owns both server-side containers, but each has an isolated build
context and runtime:

```bash
# From the repository root: Go API only
docker build -t sih-backend:local ./backend

# Python inference worker only
docker build -t sih-ml-service:local ./backend/ml-service
```

The Go image is defined by this directory's `Dockerfile`; its `.dockerignore`
excludes `ml-service/`. The worker's image and runtime configuration live under
[`ml-service/`](ml-service/). The root `compose.yaml` connects the two services
and sets `ML_GRPC_ADDRESS=ml:50051` for the Go API. Use
`docker compose up --build --detach` to run both backend services. The frontend
is intentionally not containerized.
