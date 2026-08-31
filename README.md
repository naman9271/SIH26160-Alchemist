# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

Project for Smart India Hackathon 2026

## Problem Statement

**Problem Statement ID:** 26160  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software  
**Theme:** Blockchain & Cybersecurity

IPsec VPN deployments are widely used in enterprise, government, military, and cloud environments, but their security depends heavily on cryptographic choices, protocol modes, key exchange settings, and operational configuration. Manual packet inspection is slow and requires expert knowledge.

This project aims to build an AI-driven framework that can analyze IPsec traffic, infer protocol characteristics, detect security risks, and generate automated security assessment reports.

## Team

- Daksh Pathak
- Naman Jain
- Anvay
- Riya Shukla
- Yatika Goel
- Shubh

## Objectives

The proposed system is designed to:

- Identify IPsec traffic from captured packets or live streams
- Deterministically observe or verify IKE version, mode, cipher suite, DH group, PFS, SPI, and SA characteristics
- Use ML only to classify the likely dominant traffic type from encrypted-flow metadata
- Evaluate cryptographic strength and configuration compliance
- Generate a security score, threat matrix, and actionable recommendations
- Present results in an interactive dashboard with executive and technical reports

## Planned Capabilities

### VPN Testbed Generation

Support for IPsec VPN test cases with variations such as:

- Tunnel mode and transport mode
- AES-128, AES-256, AES-GCM, AES-CBC + HMAC
- Different Diffie-Hellman groups
- Perfect Forward Secrecy enabled or disabled
- IPv4 and IPv6 traffic
- Application traffic such as VoIP, WhatsApp, e-mail, web browsing, ICMP, and video streaming

### Traffic Capture

Dataset collection using tools such as Wireshark, tcpdump, and custom packet capture utilities, including:

- IKE negotiation packets
- ESP packets
- AH packets, if enabled
- Normal communication traffic

### Hybrid Protocol and Traffic Identification

Deterministic packet/gateway analysis identifies protocol and security facts.
The ML component is limited to encrypted application-traffic classification
and experimental anomaly detection.

- IPsec protocol usage
- IKE version
- Tunnel mode or transport mode
- Encryption algorithm
- Authentication algorithm
- Key exchange method
- Security association characteristics
- Likely traffic type inside ESP payloads

### Security Assessment

Automatic evaluation of:

- Cryptographic strength
- Configuration compliance
- SA parameters
- Key lifetime
- Replay protection
- Forward secrecy posture
- Cipher suite strength
- Metadata exposure

## Expected Output

- Comprehensive security score
- Traffic analysis summary
- Metadata inference
- Executive report
- Technical report
- Threat matrix
- AI confidence score

## Repository Structure

```text
.
├── backend/        # Go-based API, services, and analysis logic
├── frontend/       # Next.js dashboard and user interface
├── ml-service/     # Python traffic classifier, UNKNOWN, SHAP and anomaly experiment
├── ipsec_esp/      # Legacy insecure parser fixtures; never ML training data
└── README.md       # Project overview and documentation
```

## Tech Stack

- Frontend: Next.js, React, TypeScript
- Backend: Go
- Packet analysis: Wireshark, tcpdump, custom capture utilities
- AI/ML: encrypted traffic classification from metadata; deterministic Go security scoring
- Visualization: dashboard for reports, scores, and packet insights

## Getting Started

For the reproducible submission demo, use Docker Compose:

```bash
make up
# Open http://localhost:3000 in a browser.
make demo
make down
```

The demo uploads the checked-in classic PCAP sample, runs passive/Fusion/
security/ML analysis, and verifies completion through the Go Core HTTP API.

### Manual development

This repository is organized as a full-stack project with separate frontend,
backend, and ML applications. Use Python 3.11+ for the ML worker.

```bash
cd backend
ML_GRPC_ADDRESS=127.0.0.1:50051 go run ./src/cmd/server
```

In another terminal:

```bash
cd ml-service
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-runtime.txt
python -m src.grpc_server
```

Then run `npm ci && npm run dev` in `frontend/`. The browser UI accepts classic
PCAP (`.pcap`/`.cap`) uploads. Convert PCAPNG before uploading:

```bash
editcap -F libpcap input.pcapng output.pcap
```

## Project Vision

The long-term goal is to provide a practical assistant for security analysts that reduces manual packet inspection effort and produces fast, explainable assessments of IPsec VPN deployments.

## Documentation

- [Backend README](backend/README.md)
- [Frontend README](frontend/README.md)
- [Submission guide](docs/SUBMISSION_GUIDE.md)
- [ML validation protocol](docs/MODEL_VALIDATION.md)
- [Linux Deep Assessment validation](docs/DEEP_ASSESSMENT_LAB.md)

## Status

The offline PCAP workflow is implemented and demonstrable: passive protocol
facts, optional ML flow classification, Fusion, security/risk, and PDF reports.
It is an MVP, not a production security appliance. Live capture requires host
permissions; VICI/XFRM Deep Assessment requires an authorised Linux/StrongSwan
lab; and ML accuracy claims require the independent validation described above.

This project uses conventional tree-based ML for flow metadata classification.
It does not include an LLM and never decrypts ESP payloads.
