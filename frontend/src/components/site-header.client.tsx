"use client";

import Link from "next/link";
import * as Dialog from "@radix-ui/react-dialog";
import { CHAIN } from "@/lib/config";
import { API_BASE_URL } from "@/lib/api";
import { ArrowTopRightOnSquareIcon } from "@/app/icons";
import { useState } from "react";

function MenuIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" {...props}>
      <path d="M4 6h16M4 12h16M4 18h16" />
    </svg>
  );
}

function CloseIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" {...props}>
      <path d="M6 6l12 12M6 18L18 6" />
    </svg>
  );
}

export function SiteHeader() {
  const [open, setOpen] = useState(false);
  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200/70 bg-white/80 backdrop-blur supports-[backdrop-filter]:bg-white/60">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
        <Link href="/" className="flex items-center gap-2.5 rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600 focus-visible:ring-offset-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-qtrust-600 text-[11px] font-bold tracking-widest text-white" aria-hidden="true">
            QT
          </span>
          <span className="text-sm font-semibold tracking-tight text-slate-900">Q-Trust</span>
          <span className="hidden rounded-full bg-slate-900 px-2 py-0.5 text-[10px] font-medium tracking-wide text-white sm:inline-flex">Base L2</span>
        </Link>

        <nav aria-label="Primary" className="hidden items-center gap-1 md:flex">
          <Link href="/dashboard" className="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
            Dashboard
          </Link>
          <Link href="/vendors" className="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
            Vendors
          </Link>
          <Link href="/v" className="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600">
            Verify
          </Link>
          <a
            href={`${API_BASE_URL.replace(/\/$/, "")}/docs`}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 transition hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
          >
            API docs
            <ArrowTopRightOnSquareIcon className="h-3 w-3" aria-hidden="true" />
            <span className="sr-only">(opens in new tab)</span>
          </a>
        </nav>

        <div className="flex items-center gap-2">
          <span className="hidden items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700 sm:inline-flex" aria-label="Network status: live">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 motion-reduce:hidden" aria-hidden="true" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
            </span>
            {CHAIN.name}
          </span>
          <Link
            href="/dashboard"
            className="hidden items-center justify-center rounded-lg bg-qtrust-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-qtrust-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600 focus-visible:ring-offset-2 sm:inline-flex"
          >
            Launch app
          </Link>

          {/* Mobile hamburger */}
          <Dialog.Root open={open} onOpenChange={setOpen}>
            <Dialog.Trigger asChild>
              <button
                type="button"
                aria-label="Open menu"
                aria-expanded={open}
                className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-700 shadow-sm transition hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600 focus-visible:ring-offset-2 md:hidden"
              >
                <MenuIcon className="h-4 w-4" aria-hidden="true" />
              </button>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 z-50 bg-slate-900/30 backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0" />
              <Dialog.Content
                aria-label="Mobile navigation"
                className="fixed inset-y-0 right-0 z-50 flex h-full w-[84%] max-w-sm flex-col border-l border-slate-200 bg-white p-6 shadow-xl data-[state=closed]:slide-out-to-right data-[state=open]:slide-in-from-right data-[state=open]:animate-in data-[state=closed]:animate-out"
              >
                <div className="flex items-center justify-between">
                  <Link href="/" onClick={() => setOpen(false)} className="flex items-center gap-2">
                    <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-qtrust-600 text-[11px] font-bold tracking-widest text-white">QT</span>
                    <span className="text-sm font-semibold text-slate-900">Q-Trust</span>
                  </Link>
                  <Dialog.Close asChild>
                    <button
                      type="button"
                      aria-label="Close menu"
                      className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-600 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
                    >
                      <CloseIcon className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </Dialog.Close>
                </div>

                <Dialog.Title className="sr-only">Navigation menu</Dialog.Title>
                <Dialog.Description className="sr-only">Primary navigation for mobile</Dialog.Description>

                <nav aria-label="Mobile" className="mt-6 flex flex-col gap-1">
                  <Link
                    href="/dashboard"
                    onClick={() => setOpen(false)}
                    className="rounded-lg px-3 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
                  >
                    Dashboard
                  </Link>
                  <Link
                    href="/vendors"
                    onClick={() => setOpen(false)}
                    className="rounded-lg px-3 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
                  >
                    Vendors
                  </Link>
                  <Link
                    href="/v"
                    onClick={() => setOpen(false)}
                    className="rounded-lg px-3 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
                  >
                    Verify
                  </Link>
                  <a
                    href={`${API_BASE_URL.replace(/\/$/, "")}/docs`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-600 hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
                  >
                    API docs
                    <ArrowTopRightOnSquareIcon className="h-3 w-3" aria-hidden="true" />
                  </a>
                </nav>

                <div className="mt-auto flex flex-col gap-3 border-t border-slate-200 pt-6">
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700">
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500 motion-reduce:animate-none" aria-hidden="true" />
                    {CHAIN.name} · Live
                  </span>
                  <Link
                    href="/dashboard"
                    onClick={() => setOpen(false)}
                    className="inline-flex items-center justify-center rounded-lg bg-qtrust-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-qtrust-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600 focus-visible:ring-offset-2"
                  >
                    Launch app
                  </Link>
                </div>
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>
        </div>
      </div>
    </header>
  );
}
