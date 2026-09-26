import { NextResponse } from "next/server";
import { hasAllowedBrowserOrigin } from "@/lib/request-origin";

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

async function forward(request: Request, { params }: RouteContext) {
  if (!hasAllowedBrowserOrigin(request)) {
    return NextResponse.json({ error: "Origin rejected" }, { status: 403 });
  }
  const { path } = await params;
  const baseUrl = (process.env.CORE_HTTP_URL ?? "http://127.0.0.1:8080").replace(/\/$/, "");
  const target = new URL(`${baseUrl}/${path.join("/")}`);
  target.search = new URL(request.url).search;

  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("connection");
  headers.delete("x-alchemist-lab-token");
  if (path[0] === "api" && path[1] === "v1" && path[2] === "labs") {
    const labToken = process.env.LAB_API_TOKEN?.trim();
    if (!labToken) {
      return NextResponse.json({ error: "Lab controls are disabled." }, { status: 503 });
    }
    headers.set("x-alchemist-lab-token", labToken);
  }

  try {
    const response = await fetch(target, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      cache: "no-store",
      // Node requires this when forwarding the streamed PCAP upload body.
      duplex: "half",
    } as RequestInit);
    const responseHeaders = new Headers();
    for (const name of ["content-type", "content-disposition"]) {
      const value = response.headers.get(name);
      if (value) responseHeaders.set(name, value);
    }
    return new Response(response.body, { status: response.status, headers: responseHeaders });
  } catch {
    return NextResponse.json(
      { error: "Go Server is unavailable. Start Core or set CORE_HTTP_URL." },
      { status: 503 },
    );
  }
}

export const GET = forward;
export const POST = forward;
