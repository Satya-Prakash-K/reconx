import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ReconX — AI-Powered Bug Bounty Reconnaissance",
  description: "Enterprise-grade autonomous reconnaissance platform for authorized security testing and responsible disclosure programs.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="animated-gradient min-h-screen">{children}</body>
    </html>
  );
}
