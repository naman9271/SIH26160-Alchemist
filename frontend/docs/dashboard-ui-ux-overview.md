# Dashboard UI/UX Overview

This document defines the approved dashboard plan for the SIH 2026 IPsec Sentinel Twin frontend. It is a UI/UX planning document only. It does not define implemented React components, routes, API handlers, backend logic, or styling.

The dashboard must communicate evidence honestly. It must separate packet observations, deterministic derivations, ML inference, authorized gateway verification, unknown values, unavailable sources, security findings, and deterministic risk scoring.

The Next.js frontend communicates only with the Go Server through a Connect or gRPC-Web-compatible API. It never calls the Python ML Worker directly.

## Dashboard Purpose

The dashboard is for security analysts, SIH jury evaluators, and technical operators reviewing IPsec VPN traffic captures or authorized live/deep assessments.

It solves the problem of making IPsec evidence understandable without requiring the user to manually inspect every packet or gateway state source. The user should see what was observed, what was derived, what ML inferred, what was verified from the gateway, what remains unknown, what evidence source is unavailable, and what deterministic security assessment concluded.

Within the first 10 seconds, the user should understand:

- Whether an analysis workspace exists.
- Whether the system is healthy enough to run analysis.
- Whether IPsec evidence was found.
- Which evidence sources are available.
- Whether ML classification is available, unknown, or unavailable.
- Whether Deep Assessment gateway verification is available.
- Whether deterministic findings and risk score are available.

The dashboard story is:

```text
OBSERVE -> DERIVE -> INFER -> VERIFY -> ASSESS
Packets    Facts     ML       Gateway   Findings/Risk
```

Each stage must be visually distinct. ML inference must never be presented as protocol truth. Gateway verification must only appear when authorized Deep Assessment data is available.

## Full Screen and Page Structure

| Page / View | Page Purpose | Main User Actions | Required Data | Required Components | Empty State | Loading State | Error or Unavailable State | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Overview Dashboard | Summarize workspace, evidence coverage, analysis status, ML, gateway availability, findings, and risk | Select workspace, inspect summary, jump to evidence/findings/report | Workspace state, Core health, evidence summary, ML status, gateway status, findings, risk | Workspace card, risk card, evidence coverage, protocol overview, traffic classification summary, top findings, gateway status, event timeline | No workspace or no analysis yet | Loading workspace and summary | Go Server unavailable, ML unavailable, gateway unavailable | Planned |
| PCAP Upload and Analysis Setup | Configure passive PCAP analysis | Create workspace, upload PCAP/PCAPNG, validate source, start analysis | Workspace, accepted file metadata, input mode support | PCAP upload dropzone, validation checklist, mode selector, start analysis button | No file selected | Uploading or validating PCAP | Invalid PCAP, upload failure, input API unavailable | Planned |
| Live Capture View | Configure authorized passive live capture | Select interface, start/stop capture, monitor packet counters | Interface list, capture capability, capture status | Interface selector, live capture control panel, packet counters, filter controls | No interface selected | Probing interfaces or starting capture | Permission denied, interface unavailable, capture unavailable | Planned |
| Analysis Progress View | Explain pipeline execution across observe, derive, infer, verify, assess | Start, observe progress, cancel, retry | Analysis lifecycle, stage events, workspace state | Progress tracker, event stream, stage detail panel, cancel/retry controls | No active analysis | Analysis running | Analysis failed, cancelled, or dependency unavailable | Planned |
| VPN Session Explorer | Inspect IKE, ESP, AH, NAT-T, SPI, and SA evidence | Filter sessions, open details, review timeline | Protocol/session/SA evidence from Go Server | Session table, SPI badges, SA detail card, protocol timeline | No IPsec sessions found | Fetching sessions | Protocol read API unavailable or partial evidence | Planned |
| Flow Explorer | Inspect metadata-only ESP flow windows | Filter flows, open feature window, compare upload/download | Flow records, 10-second feature windows, aggregate statistics | Flow table, feature window panel, traffic metrics, directionality chart | No flows found | Fetching flow data | Flow telemetry unavailable | Planned |
| Traffic Classification Details | Show ML-inferred traffic class and confidence | Inspect predicted class, top candidates, model version, optional explanations | Go-owned ML result fields, model version, confidence, UNKNOWN flag | Traffic classification card, UNKNOWN state card, top prediction list, SHAP explanation panel | No classified flows | Inference pending | ML worker unavailable, low-confidence UNKNOWN, SHAP unavailable | Planned |
| Evidence and Provenance View | Show source, status, confidence, and provenance for facts | Filter by source/status/property, inspect conflicts | Evidence items, fused conclusions, source coverage | Evidence table, provenance drawer, evidence timeline, conflict indicator, source coverage panel | No evidence recorded | Loading evidence | Source unavailable, conflict unresolved, fusion unavailable | Planned |
| Security Findings | Present deterministic security findings | Filter by severity/category, inspect remediation | Security finding records from deterministic Go engine | Security finding cards, remediation panel, severity filters | No findings or assessment not run | Assessment running | Security engine unavailable or policy unavailable | Planned |
| Risk Score and Threat Matrix | Explain deterministic score and score drivers | Inspect score, breakdown, matrix, coverage impact | Risk score, risk level, deterministic breakdown, threat matrix | Risk score card, score breakdown, threat matrix, coverage notices | Risk not calculated | Risk calculation pending | Risk engine unavailable or insufficient evidence | Planned |
| Deep Assessment / Gateway Verification | Show authorized VICI/XFRM availability and verified gateway facts | Probe Deep Assessment readiness, inspect gateway evidence | Local Sensor status, VICI availability, XFRM availability, gateway snapshots | Gateway verification card, VICI/XFRM status, verified evidence table | Deep Assessment not selected | Probing local dependencies | VICI unavailable, XFRM unavailable, unauthorized mode | In Progress |
| Reports and Exports | Generate executive, technical, and JSON exports | Generate report, preview sections, export | Completed assessment, evidence, findings, risk, ML summary | Report generation panel, report preview, export controls | No completed analysis | Report generating | Report generation unavailable or failed | Planned |
| System Health / ML Worker Status | Show Go Server, Sensor, Fusion, ML, and runtime status | Refresh health, inspect capabilities | Core health/readiness, local sensor status, ML readiness | System health indicator, ML worker health indicator, capability table | No health response yet | Refreshing status | Degraded, unavailable, dependency failure | In Progress |

Status definitions:

- **Implemented** means backed by checked-in, working code and a frontend surface.
- **In Progress** means backend or contract foundations exist, but the dashboard surface is not complete.
- **Specified** means documented in architecture/API contracts but not implemented as a frontend feature.
- **Planned** means needed for the dashboard experience but not yet backed by a complete checked-in frontend implementation.

The current checked-in frontend is a starter Next.js scaffold, so the dashboard screens above are not marked **Implemented**.

## Global Application Layout

The desktop dashboard should use a fixed left sidebar, a top header, and a wide main content area.

Left sidebar navigation appears on the far left:

```text
Overview
Upload / Live Capture
Analysis Progress
VPN Sessions
Flows
Traffic Classification
Evidence & Provenance
Security Findings
Risk Matrix
Gateway Verification
Reports
System Health
```

Top header appears above the main content and contains:

- Product name: IPsec Sentinel Twin.
- Current workspace selector.
- Analysis mode badge: Passive PCAP, Passive Live, or Deep Assessment.
- Live connection indicator.
- Go Server health indicator.
- ML worker health indicator.
- Notification or event drawer entry point.

Main content area contains the active page. Data-heavy pages should include global filters below the header:

- Time range.
- Evidence status.
- Evidence source.
- Protocol.
- Session or flow.
- Severity.

The status legend should be visible in the sidebar footer or as a compact header legend:

```text
OBSERVED
DERIVED
INFERRED
VERIFIED_GATEWAY
UNKNOWN
UNAVAILABLE
```

## Required UI Components

| Component | Purpose | Data Source | Evidence Rules | Important States |
| --- | --- | --- | --- | --- |
| Analysis workspace card | Shows current workspace, mode, source, and lifecycle | Go Server workspace API | Do not imply analysis exists before a workspace/source/analysis exists | Empty, active, completed, reset |
| PCAP upload dropzone | Accepts PCAP/PCAPNG source files | Go Server input API | Uploaded file is a source, not evidence, until analyzed | Empty, dragging, validating, rejected, accepted |
| Live capture control panel | Starts and stops authorized passive capture | Go Server capture orchestration | Passive capture observes packet metadata only | Idle, starting, running, stopping, unavailable |
| System health indicator | Shows Go Server readiness | Go Server health/readiness | Degraded dependencies must be shown explicitly | Healthy, degraded, unavailable |
| ML worker health indicator | Shows ML availability through Go Server | Go Server ML orchestration/health | Frontend never calls Python directly | Serving, unavailable, model not loaded |
| Analysis progress tracker | Shows OBSERVE, DERIVE, INFER, VERIFY, ASSESS stages | Go Server analysis/event API | Do not collapse ML and deterministic stages | Pending, running, skipped, failed, complete |
| Risk score card | Shows deterministic risk score | Go Security/Risk Engine via Go Server | Risk score is not ML confidence | Not calculated, sample, low, medium, high, critical |
| Evidence-status badge | Labels evidence values | Evidence status from Go Server | Every security-relevant value needs a status | OBSERVED, DERIVED, INFERRED, VERIFIED_GATEWAY, UNKNOWN, UNAVAILABLE |
| VPN session table | Lists IKE/IPsec sessions and SAs | Go Server protocol views | ML must not populate protocol fields | Empty, partial, populated |
| SPI / Security Association detail card | Shows SPI, mode, counters, algorithms, lifetimes | Packet evidence and authorized gateway evidence | Packet SPI is OBSERVED; gateway state is VERIFIED_GATEWAY only in Deep Assessment | Observed, verified, unknown, conflict |
| Flow table | Lists metadata-only flows | Go Server flow telemetry | Never expose or imply decrypted ESP payload | Empty, active, complete |
| Traffic classification card | Shows traffic class prediction | Go-owned ML result | Must be labelled INFERRED | Known class, UNKNOWN, unavailable |
| UNKNOWN state card | Explains low confidence or no supported conclusion | ML result or evidence model | UNKNOWN is not an error, vulnerability, pass, or low severity | Unknown, insufficient data, low confidence |
| Top prediction list | Shows ranked ML candidates | Go-owned ML result | Candidates are context only when final class is UNKNOWN | Ranked, low confidence |
| SHAP explanation panel | Shows compact model explanation | Go-owned ML result when enabled | Explanation is not protocol evidence or a security finding | Disabled, loading, available, unavailable |
| Security finding card | Shows deterministic finding | Go Security Engine | Findings are created by deterministic rules, not ML | Info, low, medium, high, critical, coverage notice |
| Threat matrix | Shows impact/likelihood view | Go Risk/Security Engine | Deterministic matrix, not generated by ML | Empty, sample, populated |
| Remediation panel | Shows recommended action for findings | Go Security Engine/policy | Must link to deterministic finding, not inferred class | Available, not applicable, unavailable |
| Gateway verification card | Shows VICI/XFRM availability and verified facts | Go Server local sensor/deep assessment | VERIFIED_GATEWAY only during authorized Deep Assessment | Passive unavailable, authorized, verified, unavailable |
| Source coverage panel | Shows evidence source coverage | Go Server/fusion source coverage | Missing sources are UNAVAILABLE, not passing results | Complete, partial, unavailable |
| Evidence timeline | Shows ordered evidence and assessment events | Go Server event/provenance API | Preserve original evidence status | Empty, streaming, complete |
| Conflict-resolution indicator | Shows contradictory evidence | Fusion/provenance data via Go Server | Do not hide source conflict | No conflict, conflict, unresolved |
| Report generation panel | Generates exports | Go Server report API | Reports must preserve evidence labels | Not ready, generating, complete, failed |
| Empty/loading/error/unavailable state components | Standardize page feedback | All Go Server APIs | UNKNOWN and UNAVAILABLE are not security severities | Empty, loading, error, unavailable |

## Evidence Status Design System

Use these evidence states exactly:

```text
OBSERVED
DERIVED
INFERRED
VERIFIED_GATEWAY
UNKNOWN
UNAVAILABLE
```

| Status | User-Facing Label | Suggested Colour Family | Icon Style | Tooltip Text | Correct Usage | Incorrect Usage |
| --- | --- | --- | --- | --- | --- | --- |
| `OBSERVED` | Observed | Blue | Eye or packet icon | Directly present in captured traffic. | ESP SPI parsed from a packet; IKE version observed in packet headers | ML traffic class, security severity, gateway-only facts |
| `DERIVED` | Derived | Teal | Calculator or branch icon | Deterministically computed from observations. | Flow statistics, packet timing aggregates, directional byte ratios | Guessed cipher suite, guessed DH group, ML result |
| `INFERRED` | ML Inferred | Amber | Probability or spark icon | Probabilistic output from aggregate flow metadata. | ML traffic classification, confidence, top predictions | IKE version, cipher suite, DH group, PFS, SPI, security finding |
| `VERIFIED_GATEWAY` | Gateway Verified | Green | Shield-check icon | Read from authorized VICI/XFRM gateway state in Deep Assessment mode. | StrongSwan/XFRM facts during authorized Deep Assessment | Passive PCAP facts, ML facts, unsupported gateway assumptions |
| `UNKNOWN` | Unknown | Neutral gray | Question-circle icon | No supported conclusion or low-confidence ML abstention. | Low-confidence ML result, unavailable PFS fact, unsupported conclusion | Vulnerability, passing result, low-severity finding |
| `UNAVAILABLE` | Unavailable | Muted slate | Plug-off icon | Evidence source or optional feature is not available. | ML worker unavailable, SHAP disabled, VICI/XFRM unavailable | Vulnerability, passing result, low-severity finding |

`INFERRED` must never look equivalent to `VERIFIED_GATEWAY`. Use amber outline badges for inferred values and stronger green shield treatment for verified gateway facts.

`UNKNOWN` is not an error. `UNAVAILABLE` is not a passing security result. Neither should appear as a vulnerability, a passing result, or a low-severity security finding.

Gateway verification must always say that it is available only in authorized Deep Assessment mode.

## Typography and Font System

Recommended font system:

- Primary dashboard font: Geist Sans or Inter.
- Monospace font: Geist Mono or JetBrains Mono.
- Monospace usage: SPI values, workspace IDs, flow IDs, ports, packet counts, timestamps, protocol fields, model versions, and evidence IDs.

Recommended sizing:

- Page heading: 24-28px, weight 650-700.
- Section heading: 16-18px, weight 600.
- Body text: 14-15px, weight 400.
- Table text: 13-14px, weight 400-500.
- Metric labels: 12-13px, weight 500.
- Badge and metadata text: 11-12px, weight 600.
- Primary risk metric: 40-56px, weight 700.
- Secondary metrics: 20-28px, weight 650.

The style should be professional, modern, security-focused, readable, and suitable for a SIH jury demonstration. Avoid oversized landing-page typography inside operational dashboard panels.

## Colours and Visual Style

Recommended visual style: clean cybersecurity command centre, dark-first, readable, and not overly futuristic.

Base palette:

- App background: `#080B12`
- Sidebar background: `#0D1320`
- Main card background: `#111827`
- Secondary panel background: `#162033`
- Border colour: `#263244`
- Primary accent: `#38BDF8`
- Text primary: `#F8FAFC`
- Text secondary: `#CBD5E1`
- Text muted: `#64748B`

Risk severity colours:

- Info: blue.
- Low: green.
- Medium: amber.
- High: orange.
- Critical: red.

Evidence-status colours:

- `OBSERVED`: blue.
- `DERIVED`: teal.
- `INFERRED`: amber.
- `VERIFIED_GATEWAY`: green.
- `UNKNOWN`: neutral gray.
- `UNAVAILABLE`: muted slate.

Dark mode should be the default recommendation for the SIH jury demo. A future light mode may be added, but the primary design should prioritize contrast, dense scanning, and evidence provenance.

## Sample Dashboard Wireframe

All risk scores, findings, model confidence, packet values, and counts shown below are **sample data**.

```text
+------------------------------------------------------------------------------+
| IPsec Sentinel Twin        Workspace: NTRO Demo Capture v     Go Server: OK   |
| Mode: Passive PCAP         Analysis: Sample Completed         ML Worker: WARN |
+---------------+--------------------------------------------------------------+
| Overview      | Overall Risk - SAMPLE DATA                                  |
| Upload/Live   | +--------------------+ +----------------------------------+ |
| Progress      | | 72 / 100           | | Analysis Status - SAMPLE DATA    | |
| Sessions      | | HIGH RISK          | | OBSERVE done  DERIVE done        | |
| Flows         | | deterministic      | | INFER partial VERIFY unavailable | |
| ML Details    | +--------------------+ | ASSESS done                      | |
| Evidence      |                        +----------------------------------+ |
| Findings      |                                                              |
| Risk Matrix   | Evidence Coverage - SAMPLE DATA                              |
| Gateway       | +----------+----------+----------+----------+------------+ |
| Reports       | | Observed | Derived  | Inferred | Verified | Unknown    | |
| Health        | | 184      | 42       | 17       | 0        | 6          | |
|               | +----------+----------+----------+----------+------------+ |
| Legend        |                                                              |
| OBSERVED      | Protocol Overview - SAMPLE DATA                              |
| DERIVED       | +----------------------------------------------------------+ |
| INFERRED      | | IPsec detected: Yes                                      | |
| VERIFIED      | | ESP packets: 12,430 [OBSERVED]                           | |
| UNKNOWN       | | IKE version: IKEv2 [OBSERVED]                            | |
| UNAVAILABLE   | | NAT-T: detected [OBSERVED]                               | |
|               | | SPI count: 4 [OBSERVED]                                  | |
|               | | Cipher suite: UNKNOWN                                    | |
|               | +----------------------------------------------------------+ |
|               |                                                              |
|               | Traffic Classification - SAMPLE DATA                         |
|               | +----------------------------------------------------------+ |
|               | | Dominant class: video [INFERRED]                         | |
|               | | Model confidence: 84% [INFERRED]                         | |
|               | | Top candidates: video 84%, web 10%, voip 6%              | |
|               | | Model version: traffic-classifier-sample                 | |
|               | +----------------------------------------------------------+ |
|               |                                                              |
|               | Assessment Coverage Notice - SAMPLE DATA                     |
|               | +----------------------------------------------------------+ |
|               | | Cipher suite: UNKNOWN                                    | |
|               | | Gateway verification: UNAVAILABLE in Passive PCAP mode   | |
|               | | Deep Assessment is required for verified gateway         | |
|               | | configuration facts.                                     | |
|               | +----------------------------------------------------------+ |
|               |                                                              |
|               | Gateway Verification - SAMPLE DATA                           |
|               | +----------------------------------------------------------+ |
|               | | VICI: UNAVAILABLE   XFRM: UNAVAILABLE                    | |
|               | | VERIFIED_GATEWAY requires authorized Deep Assessment.    | |
|               | +----------------------------------------------------------+ |
|               |                                                              |
|               | Recent Activity - SAMPLE DATA                                |
|               | 14:02:11 ESP SPI observed [OBSERVED]                        |
|               | 14:02:13 Flow window computed [DERIVED]                     |
|               | 14:02:15 Traffic class predicted [INFERRED]                 |
|               | 14:02:16 Deterministic risk assessed                        |
+---------------+--------------------------------------------------------------+
```

## Recommended Dashboard User Flow

Normal flow:

```text
Create Workspace
-> Upload PCAP or Start Authorized Live Capture
-> Start Analysis
-> Observe Progress
-> Review Protocol Evidence
-> Review ML Traffic Classification
-> Review Evidence Fusion
-> Review Security Findings and Risk
-> Generate Report
```

When ML Worker is unavailable:

- Continue deterministic passive analysis where possible.
- Show traffic classification as `UNAVAILABLE`.
- Do not block observed packet evidence.
- Do not reinterpret ML unavailability as a security finding.

When ML returns `UNKNOWN`:

- Show final traffic classification as `UNKNOWN`.
- Show top known-class candidates only as context.
- Do not promote the highest candidate to the final class.
- Do not show `UNKNOWN` as a vulnerability, passing result, or low-severity finding.

When Deep Assessment is unavailable:

- Continue Passive PCAP or Passive Live analysis where possible.
- Show VICI/XFRM evidence as `UNAVAILABLE`.
- Do not show any gateway fact as `VERIFIED_GATEWAY`.
- Explain that authorized Deep Assessment is required for verified gateway configuration facts.

When a PCAP contains no IPsec traffic:

- Show an empty protocol/session state.
- Explain that no IKE, ESP, AH, or NAT-T traffic was observed.
- Avoid generating security conclusions that require IPsec evidence.

When analysis fails or is cancelled:

- Preserve partial evidence with its evidence labels.
- Show the failed or cancelled stage.
- Allow retry/reset.
- Do not show a final deterministic risk score unless the Go Security/Risk Engine completed.

## Strict Accuracy Rules

- The Next.js frontend communicates only with the Go Server through a Connect or gRPC-Web-compatible API. It never calls the Python ML Worker directly.
- The system never decrypts ESP payloads.
- ML classifies only aggregate flow metadata.
- ML does not determine IKE version, cipher suite, DH group, PFS, SPI, or security findings.
- ML results must be labelled `INFERRED`.
- Gateway facts can be labelled `VERIFIED_GATEWAY` only during authorized Deep Assessment.
- The deterministic Go Security/Risk Engine owns findings, severity, and risk scores.
- Risk score is not ML confidence.
- Packet values, flow values, and model confidence values in mockups must be labelled as sample data until backed by real analysis output.
- `UNKNOWN` must not be shown as a vulnerability, passing result, or low-severity security finding.
- `UNAVAILABLE` must not be shown as a vulnerability, passing result, or low-severity security finding.
- Missing ML, SHAP, VICI, XFRM, or gateway access must be shown as source coverage status, not as pass/fail posture.
- ESP payload decryption must never be claimed or implied.
- A feature may be marked **Implemented** only when backed by checked-in, working code. Otherwise use **In Progress**, **Planned**, or **Specified**.
