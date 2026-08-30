import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "IPsec VPN Analyzer",
  description: "IPsec traffic and security assessment figures.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return <html lang="en"><body>{children}</body></html>;
}
