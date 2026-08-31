# Backend capability and frontend feature map

## Purpose and scope

This is a code-reviewed inventory of the current Go Core backend and the
Python ML integration. It is intended to answer two practical questions:

1. What can the application already do?
2. What should the Next.js frontend expose next, and what HTTP adapter work is
   needed first?

It describes the implemented MVP, not a promise of production readiness. The
source of truth is the Go implementation and protobuf contracts under
`backend/`; some older architecture documents describe a broader roadmap.

## System at a glance

```text
Browser
  -> Next.js BFF routes (/api/core/*)
  -> Go Core HTTP workflow API (today) or Go Core gRPC (available to trusted clients)
  -> in-process Sensor: PCAP/live capture, protocol observations, flow windows
  -> in-process Fusion: evidence correlation, conflicts, provenance, confidence
  -> in-process Security/Risk/Reports
  -> Python ML worker over gRPC for optional encrypted-flow classification
```

The browser must never call the Python worker directly. It also must not expose
native Go gRPC directly to a public browser client; add an authenticated
Next.js route or a Go HTTP adapter instead.

## What works in the current browser workflow

The existing dashboard uses these HTTP endpoints through
`frontend/app/api/core/[...path]/route.ts`.

| User action | Current endpoint | What the backend does |
|---|---|---|
| Health display | `GET /live`, `GET /health` | Reports Core liveness/readiness plus memory, temporary storage, Sensor, ML, and Fusion dependency states. |
| Upload classic PCAP | `POST /api/v1/pcap` multipart field `pcap` | Enforces a 4 GiB limit, stores the upload temporarily, SHA-256 hashes it, parses it with the Sensor pipeline, and returns packet/IPsec counters. |
| Run offline analysis | `POST /api/v1/analyses` | Starts passive-PCAP processing with Fusion, security, metadata-exposure analysis, and optionally ML. |
| Poll progress/result | `GET /api/v1/analyses/{analysisID}` | Returns lifecycle state, current pipeline stage, counters, a compact protocol/ML/security summary, and a failure reason if needed. |
| Open analyst pages | `GET /api/v1/analyses/{analysisID}/insights` | Browser-safe, read-only bundle of real protocol, flow/ML, Fusion, security, risk, evidence, and availability data for the multi-page dashboard. |
| Create executive PDF | `POST /api/v1/analyses/{analysisID}/report` | Asynchronously creates an executive PDF with timeline, threat matrix, and evidence chain options enabled. |
| Poll/download report | `GET /api/v1/reports/{reportID}` and `/download` | Returns report state, then streams the ready PDF. Reports expire after 24 hours. |

The current UI already implements this baseline workflow: upload, ML toggle,
analysis polling, summary cards, and PDF download.

## End-to-end analysis pipeline

For an offline PCAP, analysis executes the following stages:

1. **PCAP validation and observation** — accepts classic PCAP (`.pcap`/`.cap`),
   not PCAPNG; counts traffic and records payload-free metadata.
2. **Protocol processing** — recognizes IKEv1/v2, ESP, AH, NAT-T, NAT
   keepalives, SPIs, IKE exchange headers, and clear-text IKE proposals.
3. **Flow aggregation** — groups bidirectional outer traffic into flows and
   produces bounded ten-second feature windows. ESP payloads are never
   decrypted or inspected.
4. **Optional ML inference** — sends only flow metadata to Python. Each final
   window with enough packets can return class probabilities, confidence,
   UNKNOWN status, model version, latency, and optional SHAP attributions.
5. **Evidence Fusion** — normalizes passive, ML, VICI, and XFRM evidence;
   correlates it; records source coverage; resolves or records conflicts; and
   emits a winning conclusion with confidence and provenance.
6. **Security assessment and risk** — applies deterministic rules to fused
   facts, produces findings/recommendations/threat counts, and calculates a
   score/risk level/breakdown.
7. **Report generation** — renders a temporary PDF or, through gRPC, JSON and
   technical report variants.

Missing optional dependencies do not make passive PCAP analysis fail. ML,
VICI, XFRM, and SHAP are represented as unavailable/unknown source coverage,
not silently treated as a successful finding.

## Implemented backend capabilities

### 1. Input and packet/Sensor capabilities

- Classic offline PCAP parsing with the same packet-observer pipeline used by
  live capture.
- Live passive capture orchestration: interface selection, IPsec-only,
  all-traffic, or custom BPF filters; promiscuous mode; duration/byte limits;
  optional PCAP saving; capture stats; and safe stop operations.
- Host interface discovery and capture capability reporting.
- IKEv1/IKEv2 header identification: initiator/responder SPI, version,
  exchange type, message ID, and flags.
- IKE clear-text payload extraction only: proposals for encryption, integrity,
  PRF, DH group, authentication method, certificate type, and traffic
  selectors. Encrypted IKE bodies are explicitly marked and not parsed.
- ESP, AH, UDP-encapsulated ESP/NAT-T, and NAT keepalive identification;
  directional SPI metadata is retained.
- IPv4 and IPv6 IPsec filter support.
- Metadata-only flow telemetry: packet/byte counts, rates, packet-size
  distribution, directionality, inter-arrival times, burst behavior, and idle
  ratio. The `flow.v2` schema contains 23 features.
- Sequence sketches (up to 256 signed packet sizes/timing deltas) are exposed
  to trusted gRPC clients, although the current ML worker deliberately does
  not support sequence-model inference.

## Original feature vision: delivery and feasibility review

The following table reconciles the original project feature list with the code
that exists now. It should be used in presentations and frontend copy: do not
describe a partial capability as fully automated.

| # | Original feature | Current delivery status | Accurate statement today | Recommended next decision |
|---:|---|---|---|---|
| 1 | Automated IPsec VPN Testbed | **Lab asset / not part of the deployable app** | The repository documents a strongSwan/Linux deep-assessment lab and can read VICI/XFRM facts from an authorised host. The dashboard does not create VPNs, switch ciphers, or provision test machines. | Do not make full automatic provisioning the main product feature; it needs privileged hosts, isolation, cleanup, and extensive platform work. A small scenario-config generator is feasible later. |
| 2 | Traffic Generator | **Not implemented in the application** | The ML project has training/evaluation material and traffic classes, but the analyzer does not generate web/video/VoIP/email/chat traffic itself. | Keep generation as a separate reproducible lab script, not a dashboard feature. A “scenario recipe” with manual run instructions is feasible; automatic traffic emulation is not a high-value first UI task. |
| 3 | Traffic Capture Engine | **Substantially implemented** | Accepts classic PCAP upload and can orchestrate local passive `tcpdump` capture with IPsec/all/custom BPF filters, limits, and statistics. | Finish the frontend adapter for existing PCAP results first. Add live capture UI only on an authorised local/Linux deployment. Do not claim Wireshark/dumpcap integration unless it is added. |
| 4 | IPsec Protocol Analyzer | **Substantially implemented, evidence-dependent** | Detects IKEv1/v2, ESP, AH, NAT-T, keepalives, SPIs, IKE headers, and clear-text IKE proposals; creates flow evidence. VICI/XFRM can add verified SA/mode/algorithm facts. | Expose protocol/session/SA/evidence pages. Show “unknown” for encrypted or unavailable facts rather than claiming full session reconstruction from every PCAP. |
| 5 | Cryptographic Security Engine | **MVP implemented** | Eight deterministic checks cover IKEv1, weak cipher, weak integrity, weak DH, PFS, replay, long lifetime, and metadata exposure. | Add rule packs and evidence-backed checks incrementally. Do not claim full NIST/IETF compliance until a reviewed policy mapping and test corpus exist. |
| 6 | Security and Risk Scoring Engine | **Implemented** | Deterministic 0–100 score, grade, risk level, confidence penalty for unknown evidence, category breakdown, and critical overrides. | Build the score-breakdown UI and show both score and confidence. |
| 7 | Threat Matrix Engine | **Implemented at MVP level** | Findings carry severity, explanation, recommendation, rule ID, and evidence properties; the backend groups them into a threat matrix. | Build the findings table, severity chart, remediation list, and evidence links. “Impact” is not yet a separately modelled field. |
| 8 | Encrypted Traffic AI Classifier | **Implemented, bounded ML capability** | Classifies metadata-only flow windows into supported traffic classes or `UNKNOWN`; it never decrypts ESP and cannot guarantee the inner payload or separate mixed applications in one opaque tunnel. | Show per-flow predictions, probabilities, UNKNOWN state, model version, and limitation text. Avoid a single global label being presented as ground truth. |
| 9 | Explainable AI Engine | **Implemented behind an option, not in the UI** | The worker and Go bridge can return top SHAP-style feature attributions when explanation support is enabled and requested. | Add a prediction-details drawer/chart after the prediction list. This is feasible because the data path already exists. |
| 10 | Metadata Exposure Analyzer | **Basic MVP implemented** | Current logic records that outer endpoints, timing, direction, and volume remain observable; it creates a low-severity finding. It does not yet calculate a detailed exposure measurement. | This is the best distinctive, low-complexity enhancement: add a deterministic exposure profile/score based on already-collected flow metrics. |
| 11 | Dashboard and Report Generator | **Baseline dashboard and executive PDF implemented** | The UI supports offline PCAP workflow, health, compact results, and executive PDF download. Native Core supports richer report types, but the browser cannot access them yet. | Prioritise detailed result pages and browser adapters for existing data before building unrelated dashboard widgets. |
| 12 | Local LLM + RAG | **Not implemented; optional** | No LLM is required by the current system, and no LLM decides protocol facts, findings, or severity. | Do not prioritise it. Consider it only as a later read-only “ask this completed report” helper with citations to existing evidence; it must never invent findings or change the deterministic score. |

### Recommended unique-but-feasible scope

The most compelling next features are the ones that reuse the current pipeline
and make its evidence visible. They are more defensible than adding a large
new dependency such as automated VPN infrastructure or an LLM.

1. **Evidence-backed IPsec posture explorer** — a protocol/SA page where every
   reported IKE version, algorithm, SPI, mode, and finding opens the evidence
   chain that produced it. Fusion provenance already exists; the main work is
   a read-only HTTP adapter and UI. This makes the project noticeably more
   credible than a generic score dashboard.
2. **Metadata exposure profile** — calculate and display a transparent
   `LOW`/`MEDIUM`/`HIGH` exposure profile from existing packet count, byte
   volume, direction balance, burstiness, idle ratio, and time-span metrics.
   Explain that it measures *observable metadata*, not the decrypted content
   or a probability of attack. This directly extends feature 10 without a new
   model or data pipeline.
3. **Per-flow ML explanation** — display class probabilities, UNKNOWN,
   confidence, and top contributing flow features for each eligible flow.
   The backend already carries predictions and optional SHAP explanations, so
   this is contained frontend/API work and avoids overstating ML certainty.
4. **Risk-to-remediation view** — clicking a score category reveals the
   deterministic rule, affected evidence, severity, and exact recommendation.
   This uses the current risk breakdown, threat matrix, recommendations, and
   evidence-chain APIs; it is high presentation value with low algorithmic
   complexity.
5. **Rekey/lifetime and replay health panel (deep mode)** — visualise existing
   VICI/XFRM lifetime, rekey, replay-window, sequence, and SA counter data
   when available. This is a strong cyber-security differentiator, but gate it
   behind deep-assessment availability and build it after the passive-PCAP UI.

### Features deliberately not prioritised

- **Fully automated VPN creation** is difficult to make safe and portable. It
  needs root/container privileges, keys/certificates, network namespaces or
  VMs, reliable cleanup, and platform-specific debugging.
- **Automated realistic traffic generation** is similarly environment-heavy
  and risks becoming a test-lab project instead of an analyzer. Keep it as a
  reproducible separate lab asset.
- **Local LLM/RAG** is not required for the core security value. It adds model
  distribution, hardware, retrieval, prompt-injection, and factuality work.
  It is less unique than showing verifiable evidence already present in this
  system.

### 2. Optional deep assessment

When running on an authorised Linux/strongSwan host, the backend can collect
read-only gateway/kernel facts in addition to packet evidence:

- **strongSwan VICI:** daemon health/capabilities, IKE SAs, CHILD SAs,
  connections, selectors, negotiated algorithms, lifetimes/rekeying,
  counters, certificates, authorities, and events.
- **Linux XFRM:** state/policy snapshots, mode, SPI, algorithms, replay window,
  sequence information, extended sequence numbers, and traffic limits.
- Readiness APIs report whether VICI/XFRM are available before the user starts
  a deep assessment. Fixture paths make this demonstrable without a live
  gateway.

This is not exposed by the current REST workflow yet. It also requires local
system privileges and should be presented in the UI as a lab/admin feature,
not as browser-only functionality.

### 3. ML orchestration

- Health and model-readiness checks with measured round-trip latency.
- Flow-by-flow inference through the Python gRPC worker, with bounded
  concurrent processing.
- Classes: `WEB`, `VIDEO`, `VOIP`, `EMAIL`, `FILE_TRANSFER`, `MESSAGING`,
  `ICMP`, and `UNKNOWN`.
- Calibrated UNKNOWN is an abstention, not an error and not itself a security
  finding.
- Per prediction: flow ID, predicted class, confidence, class probabilities,
  model/version/schema metadata, inference time, and UNKNOWN flag.
- Optional SHAP-style top feature attributions when requested and supported by
  the worker.
- If ML is disabled or unavailable, deterministic protocol/Fusion/security
  analysis still completes.

### 4. Evidence Fusion and explainability

- Evidence statuses distinguish `OBSERVED`, `DERIVED`, `INFERRED`,
  `VERIFIED_GATEWAY`, and `UNKNOWN`.
- Per-property precedence, source trust, freshness windows, minimum confidence,
  status precedence, and correlation thresholds are defined by a versioned
  Fusion policy.
- VICI/XFRM verified facts can supersede lower-trust passive observations;
  conflicting values are retained rather than hidden.
- Fused conclusions include property/value/resource, confidence, status,
  winning source(s), conflict ID, rationale code, and computed time.
- Evidence-chain reads expose winning, supporting, and conflicting evidence.
- Fusion supports status/summary reads and selective recomputation by property.

### 5. Deterministic security and risk assessment

The current security engine evaluates eight auditable rules. It does not use
ML or an LLM to decide severity:

| Rule | Trigger | Severity |
|---|---|---|
| `IPSEC_IKE_001` | IKEv1 observed | Medium |
| `IPSEC_CIPHER_001` | DES, 3DES, or NULL encryption | High |
| `IPSEC_INTEGRITY_001` | MD5 or SHA-1 integrity | High |
| `IPSEC_DH_001` | Weak MODP/group 1, 2, or 5 family | High |
| `IPSEC_PFS_001` | Verified PFS disabled | Medium |
| `IPSEC_REPLAY_001` | Verified anti-replay disabled | High |
| `IPSEC_LIFETIME_001` | SA lifetime over 24 hours | Medium |
| `IPSEC_METADATA_001` | Observable endpoint/timing/direction/volume metadata | Low |

- Findings include title, severity, category, explanation, remediation, rule
  ID, and evidence-property references.
- Score starts at 100 and deducts 25/15/8/3 for
  critical/high/medium/low findings, with grade `A`–`F`.
- Risk levels are `LOW` (90+), `MODERATE` (70–89), `HIGH` (50–69), and
  `CRITICAL` (<50).
- Risk breakdown partitions the score into cryptography, authentication, key
  exchange, PFS, replay, lifecycle, and metadata categories.
- Unknown evidence reduces risk-score confidence (floor 0.5); it does not
  create a fabricated pass/fail result.
- Threat matrix, priority-sorted recommendations, compliance counters, and a
  metadata-exposure explanation are available in the Core API.

### 6. Workspace, lifecycle, observability, and reports

- In-memory singleton workspace associates source, analysis, Fusion run,
  assessment, and report. Reset is supported through gRPC.
- Analyses are asynchronous and support progress, get, cancel, and retry
  through the gRPC API.
- Progress states cover acquisition, protocol work, sessions/flows/features,
  ML, Fusion, security, finalisation, failure, and cancellation.
- A Core event stream can publish analysis, capture, ML, Fusion, VICI/XFRM,
  finding, score, and report lifecycle events.
- System APIs provide health, readiness, version, capabilities, and runtime
  statistics.
- Reports are asynchronous, streamable, temporary artifacts. The existing
  REST path exposes an executive PDF. Native gRPC additionally declares
  technical-PDF and JSON exports plus report deletion/listing.

## Important frontend integration gap

The Go server listens on native gRPC port `50052`, but the dashboard cannot
use it directly. The browser-ready Core endpoints are the health endpoints,
the workflow endpoints above, and the read-only `insights` composition route.

The `insights` route exposes the high-value analysis results for the current
dashboard. Less common operational/admin gRPC methods remain trusted-client
only. Add narrow Go HTTP routes (or a Next.js server-side gRPC client) for
future browser needs; do not ship a generic public gRPC proxy.

## Frontend roadmap

### Phase 1 — expose existing offline-PCAP results (highest value)

Add read-only REST/BFF endpoints for the existing analysis ID, then build:

| Screen/component | Backend data to expose | Why it matters |
|---|---|---|
| Analysis overview | full analysis progress/summary, dependency/source availability | Make stages, unavailable ML/VICI/XFRM, counts, and failure states understandable. |
| Protocol details | protocol summary, sessions, IKE exchanges, SAs, crypto properties, NAT-T summary | Converts the current three summary values into analyst-usable IPsec evidence. |
| Traffic/flow explorer | flows, feature-window summaries, ML predictions | Shows what was classified and prevents a single top prediction being mistaken for all traffic. |
| Security findings | assessment, severity-filtered findings, recommendations, compliance, metadata exposure | Gives actionable remediation instead of only score/risk. |
| Risk dashboard | score, confidence, unknown-evidence count, category breakdown, critical overrides | Explains how the score was calculated. |
| Fusion/evidence explorer | conclusions, conflicts, evidence chains, source availability | Supports the project's explainability claim. |
| Report centre | report status/download, then technical/JSON choices | Keeps a history within the current in-memory session and makes options explicit. |

Suggested REST shape (all scoped by `analysisID`):

```text
GET /api/v1/analyses/{id}/protocol
GET /api/v1/analyses/{id}/sessions
GET /api/v1/analyses/{id}/flows
GET /api/v1/analyses/{id}/ml/predictions
GET /api/v1/analyses/{id}/security
GET /api/v1/analyses/{id}/risk
GET /api/v1/analyses/{id}/fusion/conclusions
GET /api/v1/analyses/{id}/fusion/conclusions/{conclusionID}/evidence
```

Keep responses paginated for sessions, flows, predictions, conclusions, and
evidence. Preserve the backend's evidence status and unavailable reason in the
view model; do not replace unknown with an empty string or a green checkmark.

### Phase 2 — quality of use

- Replace short-interval polling with a server-side adapter for Core event
  streaming (SSE is a good browser transport) while retaining polling fallback.
- Add query state in the URL: analysis ID, selected session/flow, severity
  filter, and active result tab.
- Add client-side tables with pagination/search/filtering for flows, SAs,
  findings, and evidence.
- Visualize timeline events, threat-matrix severity counts, risk category
  breakdown, confidence bands, and per-flow traffic-class distribution.
- Provide clear states for “not requested,” “unavailable,” “unknown,”
  “no data observed,” and “analysis failed.” They are meaningfully different.
- Make report generation choices visible: executive/technical/JSON and whether
  to include timeline, threat matrix, evidence chains, and SHAP.

### Phase 3 — live and deep-assessment UI

- Interface picker and capability check before live capture.
- Capture controls: IPsec-only/default filter, custom BPF validation,
  promiscuous mode, duration/size guardrails, start/stop, counters, and live
  flow/capture charts.
- Explicit Deep Assessment consent/gating, VICI/XFRM availability, socket
  configuration, and a clear passive-only fallback.
- Gateway pages for IKE/CHILD SAs, XFRM states/policies, replay protection,
  lifetimes, certificates, and connection selectors.

These should follow after Phase 1 because live capture and gateway telemetry
need host permissions, secure deployment design, and the missing browser API
adapter.

## Recommended backend work after the frontend adapter

1. **Persist workspaces, analyses, reports, and artifacts.** Current state is
   in memory and reports/uploads use temporary storage, so a restart loses the
   analyst session.
2. **Add authentication, authorization, tenancy, and audit logs** before any
   remote/shared deployment or remote gateway integration.
3. **Add a real HTTP/BFF contract with OpenAPI or generated TypeScript types.**
   Avoid duplicating ad-hoc interfaces in `page.tsx`.
4. **Add retention/quota controls and background cleanup** for large captures
   and generated report artifacts.
5. **Harden PCAP ingestion** with file-type validation, resource limits,
   cancellation/progress handling, and malware-safe storage operations.
6. **Turn policy management into a safely authorised admin workflow** with
   validation, version history, and change audit rather than exposing a raw
   runtime-config editor.
7. **Extend deterministic parsing/rules carefully.** Examples include richer
   IKE proposal/name mapping, certificate-chain/time validation, rekey/lifetime
   evidence, traffic-selector mismatches, SA churn, and replay/sequence
   exhaustion alerts. Every new rule needs a traceable evidence source.
8. **Productionise ML only after external validation.** Show model version,
   UNKNOWN rate, and known limitations. Do not claim decryption or certainty
   for mixed traffic inside one opaque tunnel.
9. **Add end-to-end API/UI tests** using the checked-in PCAP fixture plus
   failure cases for ML unavailable, malformed PCAP, cancelled analysis, and
   unavailable VICI/XFRM.

## Product and safety limits to keep visible in the UI

- The application analyses outer IPsec metadata; it does not decrypt ESP.
- Only classic PCAP is supported by the browser workflow. Users must convert
  PCAPNG before upload.
- Passive capture cannot reliably expose all negotiated properties after IKE
  messages become encrypted. Those values should remain unknown unless
  captured in clear text or verified through VICI/XFRM.
- ML is traffic-type inference from metadata. `UNKNOWN` means abstention, and
  a predicted label is not evidence of payload content or a security finding.
- Deep assessment is a read-only, authorised Linux/strongSwan lab feature; it
  is not automatically available in Docker or a user browser.
- The current rule set is an MVP baseline of eight deterministic checks, not a
  complete compliance certification.

## Useful implementation locations

| Area | Main code/contract |
|---|---|
| Browser REST workflow | `backend/src/cmd/server/http_api.go` |
| Server composition and health | `backend/src/cmd/server/main.go` |
| Analysis coordinator/pipeline | `backend/src/internal/core/analysis/` |
| PCAP/live input | `backend/src/internal/core/input/`, `backend/src/internal/sensor/capture/` |
| Flow features | `backend/src/internal/sensor/flow/service.go` |
| ML bridge | `backend/src/internal/core/ml/service.go`, `ml-service/proto/ml/v1/traffic_classifier.proto` |
| Fusion | `backend/src/internal/fusion/`, `backend/src/internal/core/fusion/` |
| Security and score | `backend/src/internal/security/assessment.go`, `backend/src/internal/core/security/`, `backend/src/internal/core/risk/` |
| Report rendering | `backend/src/internal/core/report/` |
| Full trusted-client API | `backend/api/proto/core/v1/` |
