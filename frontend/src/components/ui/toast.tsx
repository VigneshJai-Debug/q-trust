"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { XCircleIcon, ShieldCheckIcon } from "@/app/icons";

export interface ToastProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "success" | "destructive";
  title?: string;
  description?: string;
  onClose?: () => void;
}

const variantStyles: Record<string, string> = {
  default: "border-slate-200 bg-white text-slate-900",
  success: "border-emerald-200 bg-emerald-50 text-emerald-900",
  destructive: "border-rose-200 bg-rose-50 text-rose-900",
};

export function Toast({
  className,
  variant = "default",
  title,
  description,
  children,
  onClose,
  ...props
}: ToastProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "pointer-events-auto flex w-full max-w-sm items-start gap-3 rounded-xl border p-4 shadow-lg backdrop-blur supports-[backdrop-filter]:bg-white/90",
        variantStyles[variant],
        className,
      )}
      {...props}
    >
      <span className="mt-0.5 shrink-0" aria-hidden="true">
        {variant === "success" ? (
          <ShieldCheckIcon className="h-4 w-4 text-emerald-600" />
        ) : variant === "destructive" ? (
          <XCircleIcon className="h-4 w-4 text-rose-600" />
        ) : null}
      </span>
      <div className="min-w-0 flex-1">
        {title ? <div className="text-sm font-semibold">{title}</div> : null}
        {description ? <div className="mt-1 text-xs leading-5 opacity-90">{description}</div> : null}
        {children ? <div className="mt-1 text-xs">{children}</div> : null}
      </div>
      {onClose ? (
        <button
          type="button"
          onClick={onClose}
          aria-label="Dismiss"
          className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-qtrust-600"
        >
          <span aria-hidden="true">×</span>
        </button>
      ) : null}
    </div>
  );
}

export function ToastViewport({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "fixed bottom-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2 pointer-events-none",
        className,
      )}
      {...props}
    />
  );
}
