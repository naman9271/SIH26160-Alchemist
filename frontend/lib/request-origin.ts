export function hasAllowedBrowserOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;

  const configured = process.env.APP_PUBLIC_URL?.trim();
  try {
    const expectedOrigin = configured
      ? new URL(configured).origin
      : new URL(request.url).origin;
    return new URL(origin).origin === expectedOrigin;
  } catch {
    return false;
  }
}
