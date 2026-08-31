import type { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

const baseURL = (process.env.CORE_HTTP_URL ?? "http://127.0.0.1:8080").replace(/\/$/, "");

async function forward(request: NextRequest, context: RouteContext<"/api/core/[...path]">) {
  const { path } = await context.params;
  const url = `${baseURL}/api/${path.join("/")}${request.nextUrl.search}`;
  const headers = new Headers();
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const init: RequestInit & { duplex?: "half" } = { method: request.method, headers, cache: "no-store" };
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = request.body;
    init.duplex = "half";
  }
  try {
    const response = await fetch(url, init);
    const responseHeaders = new Headers();
    for (const name of ["content-type", "content-disposition"]) {
      const value = response.headers.get(name);
      if (value) responseHeaders.set(name, value);
    }
    return new Response(response.body, { status: response.status, headers: responseHeaders });
  } catch {
    return Response.json({ error: "The Go Core HTTP API is unavailable." }, { status: 503 });
  }
}

export const GET = forward;
export const POST = forward;
