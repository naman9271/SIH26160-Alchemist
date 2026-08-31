# IPsec Security Analyzer — Backend File Structure v1

> **Status:** Roadmap layout. The current normative MVP contract is
> [`ARCHITECTURE_MVP.md`](ARCHITECTURE_MVP.md). Directories shown below are
> created only when their implementation is started; the tree is not a claim
> that every module already exists.

This document defines the target backend layout for implementing the final API
contracts:

- `go_sensor_api_spec_v1.md`
- `go_core_backend_api_spec_v1.md`
- `fusion_engine_api_spec_v1.md`

The v1 backend is one Go server / one Go process. The Go Sensor, Go Core
Backend / Security Engine, and Evidence Fusion Engine are logical modules
inside that process. Do not add gRPC between those Go modules.

The only v1 process-boundary gRPC contracts are:

- trusted/native client to the Go Core gRPC server; browser traffic goes
  through a Next.js server route/BFF
- Go server to the Python ML Worker

---

# 1. Top-level project layout

The Python ML Worker is owned by the backend and lives under `backend/`, while
remaining a separate Python process and Docker image. It shares a gRPC `.proto`
contract with the Go server because gRPC is language-neutral.

```text
SIH26160/
├── backend/
│   ├── README.md
│   ├── Dockerfile
│   ├── Makefile
│   ├── go.mod
│   ├── go.sum
│   ├── ml-service/
│   │   ├── Dockerfile
│   │   ├── README.md
│   │   ├── requirements.txt
│   │   ├── proto/
│   │   ├── src/
│   │   └── tests/
│   ├── api/
│   │   └── proto/
│   │       ├── core/v1/
│   │       │   ├── core_system.proto
│   │       │   ├── workspace.proto
│   │       │   ├── local_sensor_status.proto
│   │       │   ├── input.proto
│   │       │   ├── analysis.proto
│   │       │   ├── protocol_read.proto
│   │       │   ├── security_assessment.proto
│   │       │   ├── risk.proto
│   │       │   ├── policy.proto
│   │       │   ├── ml_orchestration.proto
│   │       │   ├── fusion_orchestration.proto
│   │       │   ├── reports.proto
│   │       │   ├── events.proto
│   │       │   ├── runtime_config.proto
│   │       │   ├── artifacts.proto
│   │       │   └── types.proto
│   │       └── common/v1/
│   │           ├── ids.proto
│   │           ├── evidence.proto
│   │           ├── errors.proto
│   │           ├── pagination.proto
│   │           └── time.proto
│   ├── gen/
│   │   └── go/
│   │       └── api/
│   │           └── proto/
│   ├── src/
│   │   ├── cmd/
│   │   │   └── server/
│   │   │       └── main.go
│   │   └── internal/
│   │       ├── app/
│   │       ├── transport/
│   │       ├── core/
│   │       ├── sensor/
│   │       ├── fusion/
│   │       ├── mlclient/
│   │       ├── state/
│   │       ├── domain/
│   │       ├── policy/
│   │       ├── config/
│   │       ├── artifacts/
│   │       ├── observability/
│   │       └── docs/
│   └── tests/
└── frontend/
    └── app/
```

`backend/api/proto/core/v1` is the external Go server API consumed by Next.js.
`backend/ml-service/proto/ml/v1/traffic_classifier.proto` is the shared process-boundary
contract. It is outside the three Go blocks and generates:

- a Go client in `backend/gen/go/ml/v1`
- Python server/message stubs in `backend/ml-service/proto`

This is required because the Python ML Worker is a real separate process.
`.proto` files describe the wire contract; they do not mean the worker is
implemented in Go.

Sensor and Fusion do not need external proto folders in v1 because they are
internal Go module contracts. Their contract docs still use protobuf-style
service blocks so the domain can be extracted later without redesign.

---

# 2. Process and module map

```text
Browser -> Next.js server route / trusted client
        |
        | browser HTTP adapter / native gRPC
        v
src/cmd/server
        |
        v
src/internal/app
        |
        +--> src/internal/core      external RPC handlers and orchestration
        +--> src/internal/sensor    packet, PCAP, VICI, XFRM, flow features
        +--> src/internal/fusion    evidence fusion and provenance
        +--> src/internal/mlclient  gRPC client for Python ML Worker
        +--> src/internal/state     synchronized in-memory workspace owner
        +--> src/internal/domain    shared domain models
        |
        | gRPC
        v
Python ML Worker
```

Internal Go modules communicate through interfaces, function calls, channels,
shared domain models, and controlled in-memory state. No package should own a
private mutable copy of global workspace state.

---

# 3. Core external API implementation layout

```text
src/internal/core/
├── system/
│   ├── service.go
│   ├── handler.go
│   └── mapper.go
├── workspace/
│   ├── service.go
│   ├── handler.go
│   └── lifecycle.go
├── localsensor/
│   ├── service.go
│   ├── handler.go
│   └── readiness.go
├── input/
│   ├── service.go
│   ├── handler.go
│   ├── live.go
│   ├── pcap_upload.go
│   └── source.go
├── analysis/
│   ├── service.go
│   ├── handler.go
│   ├── pipeline.go
│   ├── progress.go
│   └── cancellation.go
├── protocolread/
│   ├── service.go
│   ├── handler.go
│   └── views.go
├── security/
│   ├── service.go
│   ├── handler.go
│   ├── rules/
│   ├── findings.go
│   ├── compliance.go
│   ├── metadata_exposure.go
│   ├── threat_matrix.go
│   └── recommendations.go
├── risk/
│   ├── service.go
│   ├── handler.go
│   ├── scoring.go
│   ├── breakdown.go
│   └── overrides.go
├── policy/
│   ├── service.go
│   ├── handler.go
│   ├── loader.go
│   └── validate.go
├── ml/
│   ├── service.go
│   ├── handler.go
│   ├── inference.go
│   ├── prediction_store.go
│   └── shap.go
├── fusionview/
│   ├── service.go
│   ├── handler.go
│   └── views.go
├── reports/
│   ├── service.go
│   ├── handler.go
│   ├── executive.go
│   ├── technical.go
│   └── json_export.go
├── events/
│   ├── service.go
│   ├── handler.go
│   ├── broker.go
│   └── buffer.go
├── runtimeconfig/
│   ├── service.go
│   ├── handler.go
│   └── validate.go
└── artifacts/
    ├── service.go
    ├── handler.go
    └── cleanup.go
```

Core owns only the external gRPC service handlers. Business logic should sit in
service files and call internal Sensor/Fusion interfaces, the ML client, and
the state owner.

## Core service mapping

| External service | Package |
|---|---|
| `CoreSystemService` | `core/system` |
| `WorkspaceService` | `core/workspace` |
| `LocalSensorStatusService` | `core/localsensor` |
| `InputService` | `core/input` |
| `AnalysisService` | `core/analysis` |
| `ProtocolReadService` | `core/protocolread` |
| `SecurityAssessmentService` | `core/security` |
| `RiskService` | `core/risk` |
| `PolicyService` | `core/policy` |
| `MLOrchestrationService` | `core/ml` |
| `FusionOrchestrationService` | `core/fusionview` |
| `ReportService` | `core/reports` |
| `EventService` | `core/events` |
| `RuntimeConfigService` | `core/runtimeconfig` |
| `ArtifactService` | `core/artifacts` |

---

# 4. Sensor internal module layout

```text
src/internal/sensor/
├── contract/
│   ├── system.go
│   ├── session.go
│   ├── network.go
│   ├── capture.go
│   ├── pcap.go
│   ├── protocol.go
│   ├── flow.go
│   ├── vici.go
│   ├── xfrm.go
│   └── telemetry.go
├── system/
├── session/
├── network/
├── capture/
│   ├── live/
│   ├── offline/
│   ├── filters/
│   └── stats/
├── pcap/
│   ├── upload/
│   ├── validate/
│   ├── process/
│   └── cleanup/
├── protocol/
│   ├── ike/
│   ├── esp/
│   ├── ah/
│   ├── natt/
│   ├── spi/
│   ├── sessions/
│   └── timeline/
├── flow/
│   ├── tracker/
│   ├── stats/
│   ├── windows/
│   ├── sequence/
│   └── eviction/
├── deep/
│   ├── vici/
│   └── xfrm/
├── telemetry/
│   ├── snapshot.go
│   ├── observations.go
│   ├── feature_stream.go
│   └── checkpoint.go
├── store/
├── events/
└── tempstorage/
```

## Sensor contract mapping

| Internal service | Package |
|---|---|
| `SensorSystemService` | `sensor/system` |
| `SensorSessionService` | `sensor/session` |
| `NetworkInterfaceService` | `sensor/network` |
| `PassiveCaptureService` | `sensor/capture` |
| `PcapIngestService` | `sensor/pcap` |
| `ProtocolObservationService` | `sensor/protocol` |
| `FlowTelemetryService` | `sensor/flow` |
| `StrongSwanViciService` | `sensor/deep/vici` |
| `KernelXfrmService` | `sensor/deep/xfrm` |
| `SensorTelemetryService` | `sensor/telemetry` |

The `contract` package should contain Go interfaces matching the Sensor spec.
Core depends on those interfaces, not on transport code.

---

# 5. Fusion internal module layout

```text
src/internal/fusion/
├── contract/
│   ├── system.go
│   ├── session.go
│   ├── ingest.go
│   ├── query.go
│   ├── correlation.go
│   ├── conflict.go
│   ├── confidence.go
│   ├── fusion.go
│   ├── provenance.go
│   ├── policy.go
│   └── events.go
├── model/
│   ├── evidence.go
│   ├── conclusion.go
│   ├── conflict.go
│   ├── correlation.go
│   └── provenance.go
├── session/
├── ingest/
├── store/
├── query/
├── correlation/
├── conflict/
├── confidence/
├── policy/
├── engine/
├── provenance/
└── events/
```

## Fusion contract mapping

| Internal service | Package |
|---|---|
| `FusionSystemService` | `fusion/system` |
| `FusionSessionService` | `fusion/session` |
| `EvidenceIngestService` | `fusion/ingest` |
| `EvidenceQueryService` | `fusion/query` |
| `CorrelationService` | `fusion/correlation` |
| `ConflictResolutionService` | `fusion/conflict` |
| `ConfidenceService` | `fusion/confidence` |
| `FusionService` | `fusion/engine` |
| `ProvenanceService` | `fusion/provenance` |
| `FusionPolicyService` | `fusion/policy` |
| `FusionEventService` | `fusion/events` |

Fusion consumes evidence and produces conclusions. It does not score security,
create remediation, change IPsec state, or call an LLM.

---

# 6. ML client and Python worker boundary

```text
src/internal/mlclient/
├── client.go
├── health.go
├── model_info.go
├── schema.go
├── inference.go
├── sequence.go
├── shap.go
├── retry.go
└── errors.go
```

`mlclient` is the only Go package that should call the Python ML Worker gRPC
API directly. It owns:

- worker health checks
- model metadata retrieval
- feature-schema compatibility checks
- tabular batch inference
- optional sequence-model inference
- SHAP explanation requests
- timeouts, retries, and graceful ML failure mapping

The Core ML orchestration package uses `mlclient` and writes ML results into
Core state and Fusion evidence.

---

# 7. Shared domain and state layout

```text
src/internal/domain/
├── ids.go
├── time.go
├── evidence.go
├── source.go
├── ipsec/
│   ├── protocol.go
│   ├── ike.go
│   ├── esp.go
│   ├── ah.go
│   ├── natt.go
│   ├── sa.go
│   ├── spi.go
│   └── replay.go
├── flow/
│   ├── flow.go
│   ├── stats.go
│   ├── feature_window.go
│   └── sequence.go
├── ml/
│   ├── prediction.go
│   ├── model.go
│   └── explanation.go
├── security/
│   ├── finding.go
│   ├── severity.go
│   ├── recommendation.go
│   ├── threat_matrix.go
│   └── compliance.go
└── reports/
    ├── report.go
    └── artifact.go
```

```text
src/internal/state/
├── owner.go
├── workspace.go
├── snapshots.go
├── transactions.go
├── subscriptions.go
└── reset.go
```

The state owner is the only package allowed to mutate workspace-wide state.
Other packages request changes through methods or command messages.

---

# 8. Transport layout

```text
src/internal/transport/
├── grpc/
│   ├── server.go
│   ├── register.go
│   ├── interceptors.go
│   ├── errors.go
│   └── stream.go
└── connect/
    ├── server.go
    └── cors.go
```

Transport packages should only:

- register external Core services
- translate protobuf messages to domain types
- map domain errors to gRPC status codes
- handle streaming cancellation and deadlines

They should not parse packets, run security rules, perform fusion, or call VICI
/ XFRM directly.

---

# 9. Policy, config, artifacts, and observability

```text
src/internal/policy/
├── security/
│   ├── ietf_recommended_v1.yaml
│   ├── strict_v1.yaml
│   └── loader.go
└── fusion/
    ├── default_v1.yaml
    ├── gateway_preferred_v1.yaml
    └── loader.go
```

```text
src/internal/config/
├── config.go
├── defaults.go
├── env.go
└── validate.go
```

```text
src/internal/artifacts/
├── manager.go
├── tempfiles.go
├── reports.go
├── pcap.go
└── cleanup.go
```

```text
src/internal/observability/
├── logging.go
├── metrics.go
├── runtime.go
└── health.go
```

---

# 10. Tests layout

```text
tests/
├── contract/
│   ├── core_api_test.go
│   ├── sensor_contract_test.go
│   ├── fusion_contract_test.go
│   └── ml_worker_contract_test.go
├── sensor/
│   ├── pcap_ingest_test.go
│   ├── ike_parse_test.go
│   ├── esp_spi_test.go
│   ├── natt_test.go
│   ├── flow_windows_test.go
│   └── deep_sources_test.go
├── fusion/
│   ├── correlation_test.go
│   ├── conflict_test.go
│   ├── confidence_test.go
│   ├── provenance_test.go
│   └── incremental_test.go
├── security/
│   ├── crypto_rules_test.go
│   ├── replay_rules_test.go
│   ├── lifetime_rules_test.go
│   ├── risk_score_test.go
│   └── unknown_evidence_test.go
├── integration/
│   ├── passive_pcap_pipeline_test.go
│   ├── passive_live_pipeline_test.go
│   ├── deep_assessment_pipeline_test.go
│   ├── ml_failure_degradation_test.go
│   └── report_generation_test.go
└── fixtures/
    ├── pcaps/
    ├── vici/
    ├── xfrm/
    └── ml/
```

---

# 11. Implementation order

1. Shared domain models and state owner.
2. External Core system/workspace/runtime services.
3. Sensor session, interface discovery, PCAP ingest, and live capture skeletons.
4. Passive protocol detection for IKEv1, IKEv2, ESP, AH, NAT-T, SPI tracking.
5. Flow tracking, feature windows, sequence sketches, eviction and backpressure.
6. Core input and analysis lifecycle using local Sensor interfaces.
7. Fusion evidence store, source coverage, correlation, and basic conclusions.
8. Security rules, findings, compliance, recommendations, and risk score.
9. Python ML Worker gRPC client, schema checks, batch inference, SHAP handling.
10. Incremental Fusion recomputation after ML and Deep Assessment evidence.
11. Event streaming to frontend.
12. Executive, technical, and JSON reports.
13. Artifact cleanup, cancellation, readiness, and graceful degradation tests.

---

# 12. Final API coverage check

The three API specs cover the required product surface:

| Requirement area | Owning contract |
|---|---|
| Interface discovery, live capture, stop/status | Sensor + Core Input |
| PCAP/PCAPNG upload, validation, processing, cleanup | Sensor + Core Input/Artifacts |
| IKEv1/IKEv2, ESP, AH, NAT-T, SPI, sessions, timeline | Sensor Protocol + Core ProtocolRead |
| StrongSwan VICI IKE/CHILD SA state, config, counters, cert metadata | Sensor Deep VICI |
| Linux XFRM states, policies, replay window | Sensor Deep XFRM |
| Flow windows, direction, sizes, timing, burst/idle, schema version | Sensor Flow |
| Python ML health, model info, schema compatibility, inference, SHAP | Core ML + ML Worker gRPC |
| Evidence normalization, confidence, provenance, conflicts, source coverage | Fusion |
| Crypto/compliance findings, remediation, threat matrix | Core Security |
| Security score, risk level, breakdown, score caps, unknown evidence | Core Risk |
| Executive, technical, JSON reports | Core Reports |
| Live dashboard events and progress | Core Events + Analysis |
| Cancellation, bounded queues, cleanup, readiness, graceful degradation | Core/Sensor/Fusion system concerns |

No additional service is required for v1 after this audit. New functionality
should be added only when it has a distinct consumer and cannot fit cleanly
inside one of the existing services.
