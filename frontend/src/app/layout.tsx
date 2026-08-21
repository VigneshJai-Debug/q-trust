/**
 * Root layout for the Q-Trust frontend.
 */
import type { Metadata } from "next";
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
      <body className="min-h-screen bg-slate-50 text-slate-900 antialiased">
        {children}
      </body>
    </html>
  );
}
