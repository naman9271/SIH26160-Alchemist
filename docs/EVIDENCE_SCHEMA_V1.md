# Evidence schema v1

This is the canonical evidence contract for Phase 0. Every value shown in an
analysis, report, or security assessment has a source and an evidence status.
ESP is never decrypted.

## Source-status taxonomy

| Status | Meaning | Allowed source |
| --- | --- | --- |
| `OBSERVED` | Packet/header fact directly present in an authorised capture. | Packet parser |
| `DERIVED` | Deterministic calculation from observed metadata. | Packet parser or flow analyser |
| `INFERRED` | Probabilistic ML metadata classification; never an observed application fact. | ML / SHAP |
| `VERIFIED_GATEWAY` | Read-only StrongSwan VICI or Linux XFRM state. | VICI or XFRM |
| `UNKNOWN` | The collection path did not establish the fact. It is **not** a pass, an absence, or a safe default. | Any source |

Passive input may establish IKE header/proposal metadata, ESP/AH/NAT-T, SPIs,
and traffic-flow metadata. Child-SA mode, installed ESP suite, PFS, lifetime,
replay window, and ESN are `UNKNOWN` unless trusted gateway/kernel evidence
verifies them. Clear IKE offers are not recorded as negotiated Child-SA facts.

## Canonical properties

Configuration coverage is calculated from exactly these six properties:

- `ike.version`
- `child.encryption_algorithm`
- `child.integrity_algorithm` (an AEAD child encryption suite satisfies this)
- `ike.dh_group`
- `child.pfs`
- `replay.enabled`

Other canonical assessment properties are `ike.encryption`, `ike.integrity`,
`ike.prf`, `child.mode`, `child.lifetime_seconds`, and `metadata.exposure`.
The older aliases `child.esp_encryption` and `child.integrity` are invalid and
must not be emitted or consumed.

## Score interpretation

The posture score is calculated from deterministic findings for controls that
have evidence. Coverage is independently reported as evaluated configuration
facts divided by six. A score with incomplete coverage is labelled partial; at
zero coverage the UI displays **Not verified**, rather than `100/100`.

Evidence schema version: `fusion-evidence.v1`.
