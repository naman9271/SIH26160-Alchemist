# Submission and demonstration guide

## What the submitted system demonstrates

The supported end-to-end workflow is:

```text
classic PCAP upload -> passive IPsec/flow evidence -> optional ML evidence
-> Fusion -> security score and findings -> PDF report
```

The browser never talks directly to native gRPC services. It uses the Next.js
server adapter, which calls the Go Core HTTP workflow API. The Go Core calls
the Python classifier over gRPC.

## Reproducible demo

The Docker prerequisites are Docker Engine and Docker Compose v2. From the
repository root:

```bash
make up
open http://localhost:3000
make demo
```

`make demo` uploads the checked-in safe sample PCAP, enables ML, waits for a
completed analysis, and prints the real summary JSON. Use `make down` to stop
the stack. The UI and HTTP API accept **classic PCAP** only. Convert PCAPNG
before upload:

```bash
editcap -F libpcap input.pcapng output.pcap
```

The Python offline research utility can read PCAPNG, but that does not make
PCAPNG an accepted Go Core upload format.

## Claims that are safe to make

- The system passively identifies observable IKE, ESP, AH, and NAT-T facts.
- It never decrypts ESP payloads or invents unavailable protocol facts.
- Fusion keeps source provenance and feeds fused conclusions to security/risk.
- ML classifies flow-level metadata only. `UNKNOWN` is a deliberate low-
  confidence outcome, not an error or a threat verdict.
- The report reflects the analysis evidence available for that run.

Do **not** claim an LLM, payload decryption, production-generalized ML
accuracy, or guaranteed identification of multiple inner applications in one
opaque tunnel. This project contains a conventional tree-based ML classifier,
not an LLM.

## Submission evidence checklist

- [ ] A 2–3 minute screen recording: upload -> completed result -> PDF.
- [ ] The architecture diagram below in the presentation.
- [ ] At least two authorised PCAP examples, with their provenance and expected
      observable protocol facts.
- [ ] Model-evaluation table and dataset provenance from
      [MODEL_VALIDATION.md](MODEL_VALIDATION.md).
- [ ] A completed Linux Deep Assessment validation record, or an explicit
      statement that the submission demonstrates offline PCAP mode only.
- [ ] Output of `go vet`, Go tests, ML pytest, and frontend lint/build.

```text
PCAP ------> Passive evidence --+
VICI ------> Gateway evidence --+--> Fusion --> Security/Risk --> PDF
XFRM ------> Kernel evidence ---+
ML --------> Flow metadata -----+
```

## Final pre-submission commands

```bash
cd backend && go vet ./... && go test -race ./...
cd ../ml-service && python3 -m pytest
cd ../frontend && npm ci && npm run lint && npm run build
docker compose config
make up && make demo && make down
```
