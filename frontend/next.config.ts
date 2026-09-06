import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  experimental: {
    // TypeScript 5.9 can exit before its piped --showConfig output is flushed.
    // Use Next's in-process TypeScript API during production builds instead.
    useTypeScriptCli: false,
  },
};

export default nextConfig;
