# SIH 26160 requirement mapping

Status describes the checked-in implementation. A capability marked "requires evidence" needs a fresh privileged lab run before it should be shown as demonstrated.

| Requirement | Status | Implementation and proof |
| --- | --- | --- |
| Tunnel and transport modes | Implemented; new profiles require evidence | `backend/lab/configs/p1.conf` through `p8.conf`; installed-SA verifier |
| AES-128/256, GCM, CBC with HMAC | Implemented | Strict StrongSwan proposals and semantic installed-SA checks |
| Multiple DH groups and PFS on/off | Implemented; rekey requires evidence | MODP2048/3072, ECP256/384; P08 short-lifetime rekey profile |
| IPv4 and IPv6 | Implemented | Tunnel and transport profiles for both address families |
| Web, video, VoIP, email, messaging, file transfer, ICMP | Implemented as controlled generators | `backend/lab/generators` and capture scripts; messaging does not claim WhatsApp identity |
| IKE, ESP, NAT-T, AH parsing | Implemented | Go capture sensor and tests; AH is optional in the problem statement |
| PCAP, PCAPNG, and live capture | Implemented | Offline reader and authorized Linux capture service |
| IKE version and observable proposals | Implemented | IKEv1/v2 parser with proposal/selection representation |
| Installed mode, cipher, lifetime, replay, PFS | Endpoint-assisted | VICI/XFRM evidence; passive-only absence returns Not evaluated |
| Traffic prediction inside ESP | Prototype implemented | Seven-class metadata model, confidence, UNKNOWN, model card |
| Security score and coverage | Implemented | Versioned rule engine; posture and coverage remain separate |
| Threat matrix and remediation | Implemented | Assessment findings and report document |
| Executive, technical, and JSON reports | Implemented | Report API and dashboard actions |
| Interactive dashboard | Implemented | Next.js workspace, results, history, compare, and labs pages |
| Dataset and documentation | Implemented | Frozen manifest, dataset card, model card, managed-lab guide |

Fresh evidence still required before final submission:

- Run and archive P06, P07, and P08 protocol-validation captures.
- Regenerate the model and metrics using the independent calibration split.
- Collect a new post-threshold locked test set in a separate environment.
- Record actual NAT evidence before claiming NAT traversal rather than forced UDP encapsulation.
- Collect authorized application-specific traffic before using a WhatsApp label.
