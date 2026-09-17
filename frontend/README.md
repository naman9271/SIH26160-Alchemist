# IPsec PCAP Analyzer dashboard

The Next.js dashboard is a browser client for the Go Core HTTP workflow API.
It never connects directly to Go gRPC or the Python ML gRPC worker.

## Run locally

Start Go Core on port 8080, then:

```bash
pnpm install --frozen-lockfile
pnpm dev
```

Open `http://localhost:3000`. Set `CORE_HTTP_URL` only when Core is not on
`http://127.0.0.1:8080`.

Copy `.env.example` to `.env.local` for local overrides. `CORE_HTTP_URL` and
`APP_PUBLIC_URL` are server-side runtime values; secrets must never use the
`NEXT_PUBLIC_` prefix. Production Docker and Azure instructions are in
[`../docs/AZURE_DEPLOYMENT.md`](../docs/AZURE_DEPLOYMENT.md).

## Supported workflow

1. Upload a `.pcap`, `.cap`, or `.pcapng` capture file.
2. Optionally enable ML classification when the worker reports `READY`.
3. Inspect passive protocol facts, Fusion/security results, and the ML output.
4. Generate and download the executive PDF after completion.

PCAPNG support covers Ethernet and raw-IP interface blocks and the common
enhanced and simple packet blocks. Use a standard PCAP conversion tool for
unusual link-layer formats that the decoder does not support.

`UNKNOWN` ML output is a low-confidence abstention, not a failed analysis or
a security finding. A high security score and a low risk level are compatible:
the score measures security posture, while the risk level summarizes exposure.
