import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Alchemist · IPsec Evidence Workspace",
  description: "Evidence-led IPsec traffic analysis and security assessment.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return <html lang="en"><body>{children}</body></html>;
}
