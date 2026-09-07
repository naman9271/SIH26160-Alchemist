# Ubuntu capture and dashboard

Start the local deployment with:

```sh
docker compose -f compose.yaml -f compose.ubuntu.yaml up -d --build
```

This override uses the Ubuntu host network, grants NET_RAW/NET_ADMIN to the Core container, binds Core to localhost and mounts the existing `/var/run/charon.vici` socket. It is intended for this local Linux machine. The base Compose file remains suitable for offline PCAP operation. Restarting Core clears server-side analyses and temporary PDFs.

In Workspace, choose Passive Live or Deep Assessment, select the Wi-Fi adapter (currently `wlp8s0`), confirm consent, and use Stop & Analyse. Captures are bounded to five minutes / 64 MiB. Deep mode reads existing StrongSwan and kernel IPsec facts. An available collector does not imply an active VPN tunnel; no VPN traffic means no ESP classifications. No gateway configuration or VPN connections are created by this setup.

History stores up to 20 completed result snapshots in this browser's localStorage, including time, summary, findings, flow and prediction data. Snapshots remain readable and comparable after a backend restart. A server PDF must be downloaded while its analysis/artifact exists. Clearing browser storage removes history. A storage-quota error is shown rather than silently discarding results.

Risk views include the engine's findings, severity, description and recommendation. Security scores are higher-is-better; compare capture mode and evidence coverage before interpreting score differences.

## Report assistant

Configure the Next.js server in `frontend/.env.local`:

```dotenv
GROQ_API_KEY=your-key
GROQ_MODEL=llama-3.3-70b-versatile
```

Restart Next.js after configuring these values. The key is never sent to the browser. The assistant defaults to the newest saved analysis, supports choosing another report and follow-up questions. Sending a question sends that report snapshot to Groq. It cannot execute commands or change a gateway. Groq API documentation: https://console.groq.com/docs/openai

## Verification

`node scripts/ubuntu-workflow-smoke.mjs wlp8s0` runs two short captures (live and authorized deep), waits for analysis, then verifies PDF bytes for both analyses, including the older analysis after the second runs. Run only on an interface you authorize for capture.
