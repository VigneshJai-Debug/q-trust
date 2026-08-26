/**
 * Root layout for the Q-Trust frontend.
 */
import type { Metadata } from "next";
import { ErrorBoundary } from "@/components/error-boundary";
import { Providers } from "@/components/providers";
import "@rainbow-me/rainbowkit/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "Q-Trust — PQC Migration Coordinator",
    template: "%s · Q-Trust",
  },
  description:
    "Cross-organizational protocol that coordinates the migration from classical to post-quantum cryptography, on Base L2. Scan → score → plan → attest on Base.",
  metadataBase: new URL("https://humoge7502.github.io/q-trust"),
  icons: {
    icon: [{ url: "/favicon.ico" }, { url: "/favicon.svg", type: "image/svg+xml" }],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180" }],
  },
  openGraph: {
    title: "Q-Trust — PQC Migration Coordinator",
    description: "Scan your estate, score it against NIST and CNSA 2.0 timelines, rank migration with a GNN planner, and anchor evidence on Base L2.",
    url: "https://humoge7502.github.io/q-trust",
    siteName: "Q-Trust",
    images: [{ url: "/assets/dashboard.png", width: 1200, height: 630, alt: "Q-Trust dashboard — risk gauge, compliance panel and provenance graph" }],
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Q-Trust — PQC Migration Coordinator",
    description: "PQC migration protocol for real cryptography estates — scan, score, plan, attest on Base L2.",
    images: ["/assets/dashboard.png"],
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
        {/* X-Frame-Options is set as an HTTP header in next.config.mjs — it
            cannot be set via <meta> (browsers ignore and warn on it). */}
        <meta name="referrer" content="strict-origin-when-cross-origin" />
      </head>
      <body className="min-h-screen bg-slate-50 text-slate-900 antialiased">
        <ErrorBoundary>
          <Providers>{children}</Providers>
        </ErrorBoundary>
      </body>
    </html>
  );
}
