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
 Evidence             XGBoost / Sequence Models
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
       gRPC-Web / Connect
             │
       ┌─────┼───────────┐
       ▼     ▼           ▼
 Dashboard Live View   Reports

The Go Sensor, Go Core Backend / Security Engine, and Evidence Fusion
Engine are logical modules in the same Go process. They communicate through
Go interfaces, function calls, channels, shared domain models, and controlled
in-memory state. Do not introduce gRPC between these Go modules in v1.

The only v1 process-boundary gRPC contracts are:

- Next.js / external client to the one Go Server
- Go Server to the Python ML Worker
