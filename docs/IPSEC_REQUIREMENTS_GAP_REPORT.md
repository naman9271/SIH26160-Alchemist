# IPsec Analyzer Requirement Gap Report

**Audit date:** 17 September 2026  
**Scope:** Current repository implementation, not marketing claims or screenshots.  
**Purpose:** Compare the Smart India Hackathon requirement with the working code and identify what must be retained, fixed, added, deferred, or removed from the frontend.

## Bottom line

This is a **partially working passive IPsec PCAP-analysis prototype**, not yet the complete end-to-end solution described in the problem statement.

It already has a sound foundation: a Go PCAP parser, protocol/flow services, a metadata-only Python ML service, evidence fusion, deterministic findings, a Next.js dashboard, PDF generation, and optional `tcpdump`/StrongSwan VICI/Linux XFRM integrations. It deliberately does not decrypt ESP, which is correct.

The largest missing deliverable is a reproducible **VPN testbed generator**. The largest analytical gap is that ordinary PCAP processing does not reliably produce the required Child-SA mode, negotiated ESP cipher/integrity, PFS, replay, or lifetime facts. Those facts currently depend on the optional Deep Assessment path (VICI/XFRM), which is not packaged as a deployable lab environment. The dashboard also exposes implementation-oriented screens that are not needed by an analyst and does not present results through the task's requested workflow.

Do not claim that the current product automatically identifies all listed IPsec settings from every PCAP. In IKEv2, much Child-SA information is inside encrypted `IKE_AUTH`/`CREATE_CHILD_SA` messages; a passive capture cannot honestly recover it unless it observes the relevant cleartext negotiation or is correlated with authorized gateway state. IKEv2 itself specifies that later messages are protected after the initial exchange. [RFC 7296](https://www.rfc-editor.org/rfc/rfc7296.html)

## Evidence examined

- `backend/src/internal/sensor/capture/tcpdump.go`: classic-PCAP reader; IPv4/IPv6, IKE, ESP, AH and NAT-T packet metadata decoder; IKE proposal parsing.
- `backend/src/internal/core/analysis/pipeline.go`: analysis orchestration and optional VICI/XFRM/ML stages.
- `backend/src/internal/core/analysis/telemetry.go`: gateway-derived Child-SA, mode, cipher, lifetime, PFS and replay evidence.
- `backend/src/internal/core/security/service.go` and `backend/src/internal/security/assessment.go`: rule facts and eight scoring rules.
- `backend/ml-service/src/features.py`, configuration, tests and artifacts: encrypted-flow metadata classification pipeline.
- `frontend/app/workspace/page.tsx`, `frontend/components/dashboard/dashboard-shell.tsx`, and `live-analysis-panel.tsx`: current operator workflow and dashboard navigation.
- README, Compose files, testbed/dataset snapshot, report generator, and automated tests.

## Requirement coverage matrix

Status definitions: **Implemented** means available in the shipped code path; **Partial** means limited, optional, or not sufficient for the requirement; **Missing** means no usable implementation is included.

| Requirement | Status | What exists | Gap / correction needed |
| --- | --- | --- | --- |
| Reproducible VPN testbed generation | **Missing** | The ML dataset snapshot refers to a separate `ipsec-pcap-lab` repo and its StrongSwan lab. | This repository has no `docker-compose`/network-namespace profiles, StrongSwan configs, traffic generators, capture scripts, or orchestration command to generate the required matrix. Bring the lab into this repo or vendor it as a pinned submodule with one command and documented prerequisites. |
| Tunnel and transport mode generation | **Missing** | Mode is represented in VICI/XFRM telemetry schemas. | No generator creates or validates both modes. Passive packet parsing never emits `child.mode`; therefore normal PCAP analysis cannot show a mode result. |
| AES-128, AES-256, AES-GCM, AES-CBC+HMAC variants | **Partial** | Parser reads IKE transform IDs; gateway telemetry carries Child-SA cipher and integrity strings. | Transform IDs are rendered as generic strings such as `ENCR_…`, rather than IANA names/key lengths. No testbed profile establishes each requested ESP suite, and passive analysis does not reliably identify negotiated Child-SA transforms. |
| Different DH groups / PFS on and off | **Partial** | IKE transform IDs and VICI PFS data can be recorded; scoring has DH/PFS rules. | No configuration matrix or proof captures. The parser uses generic DH labels and PFS is only established through VICI connection evidence. Make PFS `Unknown` for passive-only input, not implicitly safe. |
| IPv4 and IPv6 communication | **Partial** | Decoder supports Ethernet, VLAN, IPv4, IPv6, extension headers, ESP/AH and UDP encapsulation. | No IPv4/IPv6 testbed profiles, fixtures, end-to-end tests, or UI display of address family/inner traffic family. |
| VoIP, WhatsApp/messaging, email, web, ICMP, video traffic | **Partial** | ML class vocabulary includes `web`, `video`, `voip`, `email`, `file_transfer`, `messaging`, `icmp`, and `UNKNOWN`. Dataset documents label mappings. | No current traffic-generation scripts or manifest proving the required labelled combinations. “WhatsApp” should be reported as **messaging-like**, never as proof of a specific app. Classifier feature extraction in `features.py` is metadata-only, which is appropriate but must be accompanied by calibrated per-class evaluation. |
| Capture IKE negotiation, ESP, AH, normal traffic | **Partial** | IKE/ESP/AH/NAT-T detection and `tcpdump` live capture exist. | Default live BPF filters only IPsec (`udp 500`, `udp 4500`, ESP, AH), so normal underlay/application traffic is deliberately excluded. No Wireshark integration or custom capture utility beyond `tcpdump`. Add dual capture points/profiles and state exactly which normal traffic is captured. |
| PCAP/PCAPNG support | **Partial** | Browser/API accepts classic `.pcap`/`.cap`; Python ML tooling can read PCAP/PCAPNG. | Go analysis rejects PCAPNG, requiring manual `editcap` conversion. Add safe PCAPNG ingestion in Go or server-side conversion with size/time limits and provenance. |
| Identify IPsec, IKE version, ESP/AH/NAT-T | **Implemented / Partial** | IP protocol 50/51 and UDP 500/4500 are detected; IKE major/minor version and SPI metadata are parsed. | Add malformed/fragmented/tunneled capture fixtures and confidence/coverage reasons. “IPsec detected” should remain `Unknown` when the relevant packets are absent, not be interpreted as no IPsec. |
| Identify tunnel vs transport mode | **Partial** | Deep VICI/XFRM path emits `child.mode`. | No passive derivation is implemented despite Fusion policy examples. Clearly label passive mode as `Unknown` except where a defensible heuristic is explicitly tagged `Derived`; use gateway verification for conclusive output. |
| Identify encryption/authentication/key exchange | **Partial** | Clear IKE proposals yield transforms; VICI/XFRM may provide Child-SA cipher/integrity; IKE auth fields and DH transform IDs are recorded. | Current proposal parsing does not correlate initiator offer and responder selection, distinguish IKE-SA from Child-SA suite, decode official transform names/key lengths, or reliably recover encrypted Child-SA negotiation. Build an IKE state machine and a transform registry from IANA. |
| Security Association characteristics | **Partial** | SPIs, flows, IKE SA identifiers, Child-SA gateway fields and XFRM state are modelled. | Offline PCAP pipeline treats a flow as sufficient to publish `SA_DISCOVERED`; it does not correlate bidirectional SPIs, rekeys, selectors, SA lifecycle, installation/removal, or multiple SAs robustly. |
| Predict traffic inside ESP | **Partial** | ML uses packet-size, timing, direction, burst and volume features; has confidence, explanation and `UNKNOWN` paths. | Go live/offline flow records are not visibly converted into the full ML feature contract in the audited pipeline; validate this in an end-to-end PCAP test. Publish held-out, group-aware metrics, confusion matrix, calibration, OOD/unknown performance, dataset version and limitations. |
| Cryptographic strength / cipher-suite assessment | **Partial** | Rules flag 3DES/DES/NULL, MD5/SHA-1, weak DH groups; risk breakdown exists. | Rules are only eight simple checks. They do not recognize AES key length, AEAD nonce/tag requirements, modern DH/ECP recommendations, algorithm availability/deprecation policy, ESP versus IKE strength, or compliance profile selection. Align policy with current IETF algorithm guidance such as [RFC 8221](https://www.rfc-editor.org/rfc/rfc8221.html) and [RFC 8247](https://www.rfc-editor.org/rfc/rfc8247.html). |
| Configuration compliance | **Partial** | A policy/fusion model and deterministic assessment service exist. | There is no user-visible compliance baseline (for example, “SIH baseline”, organization baseline, or profile version), no per-control pass/fail/not-evaluated outcome, and no policy editor/import. |
| SA lifetime, replay protection, PFS | **Partial** | VICI provides Child-SA life/rekey values; XFRM provides replay window/ESN; rules exist. | Passive PCAP cannot prove configured lifetime/replay policy. Current score can still be high when these facts are unknown. Introduce `Not evaluated` controls and a coverage-adjusted posture. |
| Metadata exposure | **Implemented, but shallow** | ESP packet evidence states outer endpoints, timing, direction and volume are exposed. | Replace the fixed statement with measured exposure: endpoint pairs, ports/NAT-T, byte/packet/timing summaries, traffic-selector exposure, identifier/certificate exposure, and a privacy-safe redaction mode. |
| Security score, risk score, threat matrix, AI confidence | **Partial** | Score/grade, findings, threat matrix, risk breakdown and ML confidence are generated. | Separate security score, evidence coverage score, and ML confidence. Do not call the rule score “comprehensive” until unknown controls affect its presentation. Explain scoring weights/version and use `N/A` rather than silent omission. |
| Executive + technical reports | **Partial** | PDF report and markdown report model exist; dashboard has a single “Generate Executive PDF” action. | No explicit report-type choice, no full technical evidence appendix workflow in the UI, no report provenance (policy/model/dataset versions), no signed/tamper-evident artifact, and no downloadable structured JSON/CSV evidence bundle. |
| Interactive dashboard | **Implemented, needs redesign** | Upload/workspace, results, history/compare, health, chat and detail screens exist. | Navigation is too implementation-centric and several tabs are thin generic JSON-like views rather than analyst tasks. See dashboard section below. |
| Demo, documentation, dataset | **Partial** | README, architecture docs, demo link, screenshots, submission PDF and dataset snapshot exist. | Missing a reproducible lab runbook, requirements-to-demo traceability, full dataset release or exact retrieval/rebuild instructions, acceptance captures, and a video script that demonstrates every required configuration. |

## Critical correctness issues to fix before claiming compliance

1. **Separate offers from negotiated parameters.** The parser appends transforms from clear IKE SA payloads. It does not track proposal number, protocol ID, initiator/responder direction, response acceptance, or Child-SA selection. An offered `AES` suite is not proof that it was negotiated. Preserve each proposal and label it `offered`, `selected`, or `unknown`.

2. **Decode transforms with a versioned registry.** `transformName()` currently produces `ENCR_<number>`, `PRF_<number>`, `INTEG_<number>`, and `DH_<number>`. A user cannot act on those. Implement IANA transform-ID mapping, key-length attributes, aliases, unknown-ID handling, and unit fixtures for AES-CBC, AES-GCM, HMAC-SHA2, MODP and ECP groups.

3. **Do not infer unavailable facts from a PCAP.** Mode, PFS, lifetime, anti-replay window, ESN, and installed Child-SA suite require gateway/kernel state in many IKEv2 captures. The current pipeline correctly has VICI/XFRM hooks; make the UI explicitly say “Verified gateway”, “Observed passive”, “Derived”, or “Not evaluated.”

4. **Fix evidence-property consistency.** Fusion policy examples mention `child.esp_encryption` and `child.integrity`, while the assessment consumes `child.encryption_algorithm` and `child.integrity_algorithm`. Normalize all property keys in a single schema and add a contract test covering parser → fusion → assessment → report.

5. **Measure, calibrate and disclose ML limits.** Existing artifacts indicate excellent small internal results but also show skipped cross-dataset testing when only one source is usable. Do not present a model confidence as an accuracy guarantee. Require locked, profile-stratified test captures and report macro-F1, per-class precision/recall, calibration error, unknown false-accept rate, and sample counts.

6. **Make “normal traffic” capture explicit.** The current default BPF is IPsec-only. For testbed ground truth, capture at both the protected-side interface (pre-encryption) and the underlay interface (IKE/ESP/AH), associate them with a run ID, and never send inner payload to the production passive analyzer.

## Missing VPN testbed: required design

Create `lab/` as a first-class, reproducible deliverable. Use containers or Linux network namespaces with StrongSwan and a small controller. A minimal topology is:

```text
traffic-client -- protected LAN -- ipsec-left ==== underlay ==== ipsec-right -- protected LAN -- traffic-server
                                      |              |
                               outer PCAP       outer PCAP
                     (optional privileged VICI/XFRM snapshots)
```

Add these components:

- `lab/compose.yaml` or `lab/scripts/up.sh`: starts left/right StrongSwan gateways, client/server namespaces, and a controller; uses pinned image versions.
- `lab/profiles/`: one declarative YAML file per test case. Required axes: IKEv1/IKEv2 where supported; tunnel/transport; IPv4/IPv6; AES-128-CBC+HMAC-SHA2; AES-256-CBC+HMAC-SHA2; AES-128/256-GCM; DH groups; PFS on/off; NAT-T on/off; AH optional.
- `lab/traffic/`: deterministic, legal traffic generators: `ping`, HTTP download/browse replay, SMTP test sink, SIP/RTP synthetic VoIP, messaging-like request/response, and video-like `iperf`/HLS fixture. Do not automate WhatsApp itself; name the label `messaging`.
- `lab/capture/`: captures outer IPsec and labelled protected-side ground truth separately. Use `tcpdump -w` with loss counters; record capture points, interface, BPF, clock, hashes and packet counts.
- `lab/manifest/`: immutable row per run containing profile ID, exact StrongSwan version/config hash, traffic class, duration, seed, IPv4/IPv6, suite, DH group, PFS, NAT-T, expected mode, capture SHA-256, and ground-truth source.
- `lab/verify/`: asserts that `swanctl --list-sas`/VICI/XFRM matches the requested profile before traffic capture; rejects failed or fallback negotiation.
- `lab/tests/`: at least one acceptance PCAP per axis and automated analysis assertions for expected protocol facts and control outcomes.

### Minimum acceptance matrix

Do not attempt every Cartesian product first. Start with a controlled, balanced matrix:

| Priority | Profiles to prove | Acceptance result |
| --- | --- | --- |
| P0 | IKEv2 tunnel IPv4: AES-128-CBC+HMAC-SHA2 and AES-256-GCM; PFS on/off; DH 14 and 19 | Parser/gateway records, score controls, report provenance all match the manifest. |
| P0 | IKEv2 transport IPv4: AES-256-CBC+HMAC-SHA2 and AES-128-GCM | Mode is verified, not guessed. |
| P0 | IPv6 tunnel and transport equivalents | Outer/inner address family and extension-header handling verified. |
| P1 | NAT-T ESP, AH, rekey/lifetime, replay/ESN scenarios | Correct protocol counter and gateway-state/control evidence. |
| P1 | Seven traffic labels in at least two modes and two cipher families | Group-separated training/test evidence; UNKNOWN cases included. |
| P2 | IKEv1 legacy and intentionally weak suites | Detection only in an isolated lab, never as a recommended configuration. |

## Security-assessment redesign

Implement a versioned policy engine with these control states: `PASS`, `FAIL`, `NOT_EVALUATED`, `CONFLICTING_EVIDENCE`, and `NOT_APPLICABLE`. Each must display evidence source, timestamp, capture/gateway provenance, confidence, and a remediation.

Minimum controls:

- IKE version; IKE and ESP/Child-SA encryption, integrity/AEAD, PRF and key length.
- DH/PFS group strength and whether PFS applies to the Child SA.
- Peer authentication method and certificate/identity visibility (without storing secrets).
- Tunnel/transport mode and traffic selectors.
- Lifetime/rekey time plus byte/packet limits.
- Anti-replay enabled, replay-window size, and ESN where gateway state is available.
- NAT-T, fragmentation, AH, IPComp and traffic-flow metadata exposure.
- Algorithm policy status: approved, legacy, prohibited, unknown; use policy version and source links.

Score design: show **Posture score** only over evaluated controls; show **Coverage score** independently; show **Risk level** based on failed control severity plus uncertainty. A 97/100 configuration with six unavailable controls must not visually look equivalent to a fully verified 97/100 configuration.

## Frontend audit: keep, change, remove

The sidebar currently contains: Overview, New capture, Progress flow, VPN sessions, Flows, Traffic classifier, Evidence, Security findings, Risk & fixes, Report assistant, History, Compare analyses, and System health. The items are not useless in isolation, but the total list is too large and several are infrastructure/debug views rather than primary analyst activities.

### Keep as primary navigation

- **Dashboard** (rename Overview): security posture, coverage, top risks, protocol summary, and recent analysis.
- **Analyze Capture** (rename New capture): PCAP upload, live capture and clearly marked authorized Deep Assessment.
- **Results**: a single analysis page with tabs/anchors for Protocol & SAs, Traffic inference, Findings, Evidence, and Reports.
- **History / Compare**: keep only after persistence is implemented. Browser-only history must be clearly labelled local and non-durable.

### Move into the selected analysis, not the global sidebar

- **Progress flow**: a small status panel during execution; hide after completion.
- **VPN sessions**, **Flows**, **Traffic classifier**, **Evidence**, **Security findings**, and **Risk & fixes**: these are all facets of one analysis and should be tabs in Results. This removes six sidebar entries without removing capability.
- **Report assistant**: place inside a completed report/analysis. It should never imply that chat alters evidence or findings.

### Hide behind “Administration / Diagnostics” or remove from the demo UI

- **System health**: valuable for operators, not analysts. Move to an admin menu and expose no internal service terminology in normal results.
- **Gateway/deep availability**: it exists as a code view but is not in the main navigation. Put it in the capture-mode preflight and deep-analysis evidence panel rather than a standalone destination.

### Add missing user-facing panels

- **Testbed & Dataset**: profile catalog, generated PCAP manifests, capture quality/loss, label/ground-truth status, model/dataset version, and train/test split coverage.
- **Protocol confidence and provenance**: one concise matrix showing which result is Passive Observed, Gateway Verified, Derived, ML Inferred or Not Evaluated.
- **Compliance profile**: selected baseline, policy version, control-by-control result, and export.
- **Reports**: Executive PDF, Technical PDF, JSON evidence bundle, CSV findings/flows, generation time and artifact hash.
- **Analysis limitations**: always-visible note that ESP is not decrypted and application labels are probabilistic metadata inference.

### UI quality fixes

- Replace generic collapsible raw-object cards in `LiveAnalysisPanel` with purpose-built tables: IKE exchanges, Child SAs, algorithms, findings, and prediction windows.
- Show exact algorithm names, key lengths, mode, source and confidence rather than `ENCR_#` codes.
- Rename “LIVE GO SERVER DATA” to analyst language such as “Analysis data”; backend implementation should not be a user-facing concept.
- Provide empty states that say what evidence is required and how to collect it, not merely that records are absent.
- Use plain language for a high score with low coverage: “Configuration could not be fully verified.”

## Delivery plan

### Phase 0 — truthfulness and contracts

1. Update README/UI claims to the actual passive/deep capabilities.
2. Define a single evidence schema and source-status taxonomy.
3. Add golden PCAP and gateway-fixture tests for every existing parser/control path.
4. Split score from coverage and ensure unknown facts never render as a pass.

### Phase 1 — lab and dataset foundation 

1. Add the reproducible StrongSwan testbed and test-profile manifest.
2. Add deterministic traffic generators and dual capture points.
3. Commit small sanitized fixtures; publish large PCAPs with hashes and retrieval instructions.
4. Implement testbed verification against VICI/XFRM before each run.

### Phase 2 — protocol truth 

1. Implement a versioned IKE transform registry and proposal/selection correlation.
2. Build SA correlation/rekey tracking and add mode handling with honest provenance.
3. Add PCAPNG support, capture quality metrics, IPv4/IPv6 and NAT-T tests.
4. Make deep evidence optional but easy to configure and visibly verified.

### Phase 3 — assessment and ML evidence

1. Implement versioned compliance controls and risk/coverage scoring.
2. Re-train/evaluate with group-aware, profile-stratified locked tests.
3. Add calibration/OOD acceptance gates and model card in the dashboard/report.
4. Add structured exports and full technical report appendix.

### Phase 4 — analyst workflow and demonstration

1. Consolidate the sidebar into Dashboard, Analyze, Results, History/Compare and Admin.
2. Create the requested executive and technical report flows.
3. Record a demo that runs two contrasting profiles (modern good / legacy weak), one deep verification, one UNKNOWN ML example, and a report export.

## Test and acceptance checklist

- A fresh machine can run `make lab-up`, `make lab-run PROFILE=<id>`, and `make lab-verify PROFILE=<id>` without manual StrongSwan configuration.
- Every generated PCAP has a manifest hash and expected protocol/configuration ground truth.
- At least one automated end-to-end test proves each requested mode, suite family, IPv4/IPv6, PFS state, DH group class, ESP/AH/NAT-T condition, and traffic label.
- Parser tests cover IKEv1/v2, valid/malformed proposals, AES-GCM/CBC/HMAC, unknown transforms, fragmentation, IPv6 extensions, NAT-T and AH.
- A report never labels an offered suite as negotiated, a passive-only fact as gateway verified, or an ML prediction as an observed application.
- Security controls display `Not evaluated` for unavailable lifetime/replay/PFS evidence.
- ML release requires locked-test metrics, class support, calibration, UNKNOWN/OOD results, model checksum and dataset manifest version.
- UI test verifies that primary analyst navigation contains no implementation/debug labels.

## Verification performed during this audit

- `pnpm lint` in `frontend/`: **passed**.
- Focused Go test suite: core, fusion, ML client and most sensor/security packages **passed**.
- Host-dependent capture/network integration tests **failed in this restricted environment** because netlink/interface discovery is not permitted (`operation not permitted` / host interfaces unavailable). This does not establish a code defect, but it proves that live-capture validation needs a privileged CI/lab job.

## Recommended immediate next action

Build the **P0 testbed plus evidence-status/coverage redesign first**. Without the lab, the team cannot demonstrate the requested configuration matrix or obtain trustworthy training/testing data. Without provenance-aware presentation, the UI risks overstating what a passive capture can prove.
