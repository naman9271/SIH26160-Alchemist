import type { Metadata } from "next";
import { LandingNavigation } from "@/components/ui/site-chrome";
import "./globals.css";

export const metadata: Metadata = {
  title: "Alchemist · IPsec Evidence Workspace",
  description: "Evidence-led IPsec traffic analysis and security assessment.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return <html lang="en"><body><LandingNavigation />{children}</body></html>;
}
