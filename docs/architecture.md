# Deployment Architecture

## Overview

The production architecture is a single secure multi-container deployment on **Azure Container Apps**. Managed HTTPS ingress is the only public entry point. The Next.js dashboard and BFF, Go Core analysis plane, Python ML worker, and report-assistant integration communicate within the trusted deployment boundary. Generated PDF reports are stored on Azure Files through a private volume mount.

![alt text](assets/screenshots/architecture.png)

## Request and Analysis Flow

1. An authorised analyst uploads a PCAP through the HTTPS dashboard.
2. Azure Container Apps ingress routes the request to the Next.js dashboard/BFF.
3. The BFF sends the workflow request to Go Core over the internal HTTP proxy.
4. Go Core passively ingests the capture and extracts observable protocol evidence, including IKE, ESP, AH, NAT-T, security associations, and flow metadata.
5. Go Core performs security and risk assessment, then combines facts and provenance in the evidence-fusion layer.
6. For ML-enabled analysis, Go Core sends only derived flow metadata to the Python worker over private gRPC. The worker returns a traffic class, confidence, and `UNKNOWN` decision; it never receives decrypted payload content.
7. The report engine returns the dashboard result and writes generated PDF reports to Azure Files.
8. The report assistant receives a saved report snapshot and the analyst's question, then returns a plain-language explanation. It does not modify the analysis result.

## Trust Boundaries

| Boundary | Control |
| --- | --- |
| Public access | Azure Container Apps managed HTTPS ingress and TLS are the only public entry point. |
| Dashboard to Core | Same-origin BFF and internal HTTP proxy; the browser does not contact internal services directly. |
| Core to ML worker | Private gRPC inside the deployment. Only metadata features are sent for classification. |
| Report storage | Azure Files is mounted privately for generated PDF-report persistence. |
| LLM assistant | The assistant receives a compact saved-report snapshot for explanation only; it cannot decrypt data, alter findings, or operate the VPN. |

## Security Principles

- The platform is passive and read-only: it does not alter the inspected VPN.
- ESP payload decryption is not performed.
- The ML component classifies observable metadata; `UNKNOWN` represents a low-confidence abstention.
- Secrets, Azure credentials, and LLM provider keys are supplied through managed configuration and are never committed to the repository.
- The Qwen assistant deployment should be configured as a server-side integration; no provider key is exposed to browser code.
