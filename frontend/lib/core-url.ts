/**
 * Uses the public API directly when Vercel supplies NEXT_PUBLIC_CORE_HTTP_URL.
 * This avoids routing large PCAP uploads through a Vercel function. Local
 * development continues to use the same-origin Next.js proxy by default.
 */
export function coreURL(path: string): string {
  const publicBaseURL = process.env.NEXT_PUBLIC_CORE_HTTP_URL?.replace(/\/$/, "");
  return publicBaseURL ? `${publicBaseURL}${path}` : `/api/core${path}`;
}
