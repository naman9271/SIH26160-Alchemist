# SIH IPsec Analyzer — Team Handoff

This checklist separates repository engineering from work that requires real
lab access, labelled traffic, security-policy approval, or frontend ownership.

## Dataset and VPN-lab teammate

- Add dominant-traffic captures for `voip`, `email`, and `messaging`. The
  current project lab covers only web, video, file transfer and ICMP.
- Produce at least several independent captures per class and configuration;
  do not create many windows from one capture and count them as independent
  experiments.
- Add held-out unknown/OOD traffic that is never assigned to a supported
  class, for example DNS-heavy traffic, remote desktop, database traffic,
  gaming or another unsupported application.
- Add labelled suspicious/abnormal scenarios separately for anomaly
  evaluation. UNKNOWN labels and anomaly labels are not interchangeable.
- Fix NAT-T experiments so `actual_nat_present=yes` is verified in the PCAP.
  Merely forcing UDP/4500 while both peers are directly reachable is not NAT.
- Preserve `metadata.csv`, capture SHA-256, traffic generator, exact StrongSwan
  configuration, start/end time and tool versions for every capture.
- Supply reproducible StrongSwan/topology/traffic-generation scripts in the
  dataset repository for tunnel/transport, IKEv1/v2, AES variants, DH/PFS,
  IPv4/IPv6 and NAT-T.
- Confirm dataset licences and provenance. Do not add private payloads,
  credentials or reusable production keys.

## ML teammate

- Preprocess each supported public dataset independently and rerun feature
  validation. No feature is currently approved across multiple public sources.
- Review whether public non-IPsec captures transfer to opaque ESP metadata;
  report domain shift rather than assuming compatibility.
- Collect enough independent groups for train/validation/test coverage of all
  seven classes. The current 64 windows across four classes are insufficient
  for a production classifier.
- Build the grouped training dataset, run leakage/source-holdout audits, train
  both models and choose primarily by macro F1.
- Calibrate UNKNOWN using held-out known groups and genuine OOD groups. Commit
  the selected model, metadata, evaluation, leakage audit and non-null
  threshold only after review.
- Train anomaly detection only on reviewed normal traffic and evaluate against
  separately labelled suspicious scenarios.

## Go/backend teammate

- Implement offline PCAP/PCAPNG ingestion through the same packet decoder used
  for live traffic.
- Extend deterministic IKE parsing from the current header facts to proposal,
  transform, exchange and SA reconstruction. Never infer hidden algorithms
  from opaque ESP packets.
- Implement the real read-only StrongSwan VICI decoder and Linux XFRM provider,
  then enable Deep Assessment only when either source passes readiness probes.
- Add the minimal Core input, analysis, protocol-read, security/risk and report
  APIs around the existing internal Sensor, Fusion, security and report
  packages. Do not expose Sensor gRPC externally.
- Have a security/domain reviewer approve scoring weights, weak-algorithm
  policy, compliance profiles and recommendation language.

## Frontend teammate

- Implement a Next.js server-side adapter/BFF for Core. Browser code must not
  call native Go gRPC or the Python ML service directly.
- Build the primary classification/UNKNOWN UI, flow details, evidence status,
  security score, threat matrix and executive/technical report views from the
  documented contracts.
- Display missing/unavailable evidence honestly. Keep ML confidence distinct
  from security score and UNKNOWN distinct from anomaly status.

## Integration/DevOps teammate

- Run Go and Python services together using configurable loopback addresses,
  then add project-wide orchestration only after the direct commands work.
- Build the inference image only after reviewed model artifacts exist. Public
  datasets and training captures must remain outside the image.
- Add CI for protobuf regeneration checks, `go test`, `go vet`, race-sensitive
  backend tests, Python 3.11 pytest and frontend lint/build.
- Decide how the large dataset is distributed (dataset repository, release
  assets or Git LFS). Avoid repeatedly cloning multi-gigabyte captures in the
  application repository.
