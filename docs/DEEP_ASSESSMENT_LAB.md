# Linux Deep Assessment validation

Deep Assessment is an optional authorised laboratory mode. It supplements
passive observation with read-only StrongSwan VICI and Linux XFRM telemetry;
it does not alter IPsec state and it must not be represented as available on
macOS or in an unprivileged container.

## Preconditions

- A Linux host with a working StrongSwan deployment and `charon.vici` socket.
- Permission for the account running Go Core to read the VICI socket and query
  XFRM Netlink state.
- Capture permission for the selected network interface if testing live mode.
- A non-production lab VPN and no production credentials in fixtures or logs.

## Run

Use the default VICI socket unless the deployment differs:

```bash
cd backend
VICI_SOCKET_URI=unix:///var/run/charon.vici \
ML_GRPC_ADDRESS=127.0.0.1:50051 \
go run ./src/cmd/server
```

Run the ML worker separately with Python 3.11, then query Core readiness and
capabilities. Start an authorised Deep Assessment session only after the VICI
and XFRM probes are available. Fixture providers remain appropriate for tests:
`VICI_FIXTURE_PATH` and `XFRM_FIXTURE_PATH` must reference schema-validated
fixtures.

## Evidence required for sign-off

- VICI availability, IKE/CHILD SA IDs, algorithms, identities, endpoints, and
  lifetime/rekey data observed from the lab gateway.
- XFRM state/policy, SPI, mode, selectors, replay/lifetime, and counters.
- Fusion output showing the gateway/kernel evidence provenance.
- A matching passive PCAP run, security result, and generated report.
- Platform, kernel, StrongSwan version, configuration hash, test timestamp,
  and any unavailable capability.

If this record is not completed, present the project as an **offline PCAP
analysis MVP**. That is valid; it is more credible than claiming unverified
live or gateway telemetry.
