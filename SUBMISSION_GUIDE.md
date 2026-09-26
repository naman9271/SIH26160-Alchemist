# Evaluator walkthrough

## Five-minute path

1. Open the live dashboard or start the services using the README.
2. Upload one bundled IPsec capture and start passive analysis.
3. Open Protocol & SAs to inspect IKE/ESP observations and their provenance.
4. Open Findings to inspect evidence, policy status, and remediation.
5. Review traffic inference with confidence and UNKNOWN behavior.
6. Generate the executive report, technical report, and JSON evidence bundle.

## Testbed demonstration

Use an authorized Linux Docker host and set the same strong random `LAB_API_TOKEN` on Core and the frontend server.

```bash
make lab-up
make lab-run PROFILES=1,6,7,8 LABELS=icmp,web REPETITIONS=1
make lab-verify
make lab-down
```

P01 demonstrates IKEv2 IPv4 tunnel mode. P06 and P07 cover IKEv2 transport mode over IPv4 and IPv6. P08 configures a short CHILD lifetime for rekey evidence. Do not describe P08 as a successful rekey until the generated capture and endpoint status show the event.

## Claims to use

- The analyzer parses explicit protocol fields deterministically.
- It predicts a dominant traffic category from encrypted-flow metadata and can abstain as UNKNOWN.
- It verifies hidden CHILD-SA settings only with authorized gateway or kernel evidence.
- It keeps posture score, evidence coverage, and AI confidence separate.

## Claims to avoid

- Passive decryption or recovery of ESP payloads.
- WhatsApp identification from the synthetic messaging generator.
- Real NAT traversal from forced UDP/4500 alone.
- Final real-world accuracy from the current 35-capture internal locked test.
- NTRO or SIH certification of the project-defined compliance baseline.
