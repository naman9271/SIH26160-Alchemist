export const dynamic = "force-dynamic";

type HealthResponse = { status?: string; ready?: boolean; dependencies?: Record<string, string> };

const baseURL = (process.env.CORE_HTTP_URL ?? "http://127.0.0.1:8080").replace(/\/$/, "");

export async function GET() {
  const started = performance.now();
  try {
    const [live, health] = await Promise.all([
      fetch(`${baseURL}/live`, { cache: "no-store", signal: AbortSignal.timeout(2500) }),
      fetch(`${baseURL}/health`, { cache: "no-store", signal: AbortSignal.timeout(2500) }),
    ]);
    const body = await health.json() as HealthResponse;
    return Response.json({ checkedAt: new Date().toISOString(), latencyMs: Math.round(performance.now() - started), live: live.ok, ready: health.ok && body.ready === true, status: body.status ?? (health.ok ? "ready" : "degraded"), dependencies: body.dependencies ?? {} }, { status: live.ok ? 200 : 503 });
  } catch (error) {
    return Response.json({ checkedAt: new Date().toISOString(), latencyMs: Math.round(performance.now() - started), live: false, ready: false, status: "offline", dependencies: {}, error: error instanceof Error ? error.message : "Backend status request failed" }, { status: 503 });
  }
}
