# Final submission handoff

## Demonstrable now

- Classic PCAP upload, passive IPsec/flow analysis, Fusion, security/risk, PDF
  generation, and the browser dashboard.
- Optional Python ML classification over flow metadata, including explicit
  `UNKNOWN` handling.
- Fixture-backed VICI/XFRM evidence paths and deterministic end-to-end tests.
- Docker Compose startup, CI verification, and a scriptable PCAP demo.

## Work that requires team/lab ownership

- **Dataset/ML:** validate against independently collected labelled IPsec
  captures, OOD traffic, and documented provenance. Follow
  [docs/MODEL_VALIDATION.md](docs/MODEL_VALIDATION.md).
- **Linux/StrongSwan:** run and record authorised VICI/XFRM Deep Assessment
  validation. Follow [docs/DEEP_ASSESSMENT_LAB.md](docs/DEEP_ASSESSMENT_LAB.md).
- **Presentation:** record the browser workflow, include the architecture and
  limitations, and attach real test output.

## Honest submission framing

Present the system as an explainable **offline IPsec PCAP analysis MVP** with
optional gateway/kernel telemetry. It does not decrypt ESP packets, it does
not contain an LLM, and `UNKNOWN` ML output is an abstention rather than a
security finding.
