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

## Supported workflow

1. Upload a classic `.pcap`/`.cap` file.
2. Optionally enable ML classification when the worker reports `READY`.
3. Inspect passive protocol facts, Fusion/security results, and the ML output.
4. Generate and download the executive PDF after completion.

The browser workflow deliberately rejects PCAPNG. Convert it first:

```bash
editcap -F libpcap input.pcapng output.pcap
```

`UNKNOWN` ML output is a low-confidence abstention, not a failed analysis or
a security finding. A high security score and a low risk level are compatible:
the score measures security posture, while the risk level summarizes exposure.
