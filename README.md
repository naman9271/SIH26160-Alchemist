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
- Detect IKE version, tunnel/transport mode, cipher suite, DH group, and SA characteristics
- Infer the type of traffic encapsulated inside ESP tunnels
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

### AI-Based Protocol Identification

An AI engine for automatically identifying:

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
└── README.md       # Project overview and documentation
```

## Tech Stack

- Frontend: Next.js, React, TypeScript
- Backend: Go
- Packet analysis: Wireshark, tcpdump, custom capture utilities
- AI/ML: protocol classification and risk assessment models
- Visualization: dashboard for reports, scores, and packet insights

## Getting Started

This repository is organized as a full-stack project with separate frontend and backend applications.

### Backend

```bash
cd backend
go run ./src/cmd/server
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend development server typically runs at `http://localhost:3000`.

## Project Vision

The long-term goal is to provide a practical assistant for security analysts that reduces manual packet inspection effort and produces fast, explainable assessments of IPsec VPN deployments.

## Documentation

- [Backend README](backend/README.md)
- [Frontend README](frontend/README.md)

## Status

This project README documents the initial SIH 2026 concept and repository structure. Implementation details can be expanded as the prototype evolves.
