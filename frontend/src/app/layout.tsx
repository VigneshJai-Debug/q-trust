/**
 * Root layout for the Q-Trust frontend.
 */
import type { Metadata } from "next";
import { ErrorBoundary } from "@/components/error-boundary";
import { Providers } from "@/components/providers";
import "@rainbow-me/rainbowkit/styles.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "Q-Trust — PQC Migration Coordinator",
  description:
    "Cross-organizational protocol that coordinates the migration from classical to post-quantum cryptography, on Base L2.",
  icons: { icon: "/favicon.ico" },
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
