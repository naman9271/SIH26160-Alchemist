# Evidence schema v1

Alchemist keeps protocol facts, endpoint verification, and ML inference separate.

| Status | Meaning | Example |
| --- | --- | --- |
| Observed | Directly parsed from the capture | IKEv2 header, ESP SPI, packet timestamp |
| Verified | Reported by an authorized gateway or kernel source | Installed CHILD cipher, replay window, tunnel mode |
| Derived | Deterministic conclusion from identified evidence | NAT-T present because UDP/4500 ESP encapsulation was observed |
| Inferred | Statistical estimate with confidence | Dominant traffic class in an ESP flow window |
| Conflicting | Two eligible sources disagree | Capture-derived endpoint mapping differs from gateway state |
| Unknown | Required evidence is unavailable or insufficient | PFS state in an ESP-only passive capture |

Security controls return `PASS`, `FAIL`, `NOT_EVALUATED`, `CONFLICTING_EVIDENCE`, or `NOT_APPLICABLE`. A control with unknown evidence never becomes a pass.

The posture score covers evaluated controls only. Evidence coverage states how much of the weighted policy could be evaluated. Risk level reflects supported failed controls and unresolved evidence. ML confidence applies only to a traffic prediction and is not a security score or measured accuracy.

Every report records the analysis identifier, input summary, policy identifier, evidence source where available, and model version for ML conclusions. ESP payloads are never decrypted.
