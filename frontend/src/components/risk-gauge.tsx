"use client";

import { useEffect, useRef } from "react";

interface RiskGaugeProps {
  score: number;
  level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  label?: string;
}

const LEVEL_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
  NONE: "#6b7280",
};

const LEVEL_BG: Record<string, string> = {
  CRITICAL: "bg-red-500/10",
  HIGH: "bg-orange-500/10",
  MEDIUM: "bg-yellow-500/10",
  LOW: "bg-green-500/10",
  NONE: "bg-gray-500/10",
};

const LEVEL_TEXT: Record<string, string> = {
  CRITICAL: "text-red-500",
  HIGH: "text-orange-500",
  MEDIUM: "text-yellow-500",
  LOW: "text-green-500",
  NONE: "text-gray-500",
};

export default function RiskGauge({ score, level, label }: RiskGaugeProps) {
  const circleRef = useRef<SVGCircleElement>(null);
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const color = LEVEL_COLORS[level] || LEVEL_COLORS.NONE;

  useEffect(() => {
    const circle = circleRef.current;
    if (!circle) return;
    const offset = circumference - (score / 100) * circumference;
    circle.style.strokeDashoffset = String(offset);
  }, [score, circumference]);

  return (
    <div className="flex flex-col items-center gap-2">
      <div
        className={`relative flex items-center justify-center rounded-full p-2 ${LEVEL_BG[level]}`}
      >
        <svg width="140" height="140" viewBox="0 0 120 120">
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth="10"
            className="text-muted"
            strokeDasharray={circumference}
            strokeDashoffset={0}
            strokeLinecap="round"
            style={{ transform: "rotate(-90deg)", transformOrigin: "50% 50%" }}
          />
          <circle
            ref={circleRef}
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={circumference}
            strokeLinecap="round"
            className="transition-[stroke-dashoffset] duration-1000 ease-out"
            style={{ transform: "rotate(-90deg)", transformOrigin: "50% 50%" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold ${LEVEL_TEXT[level]}`}>
            {score}
          </span>
        </div>
      </div>
      {label && (
        <span className="text-sm font-medium text-muted-foreground">
          {label}
        </span>
      )}
      <span className={`text-xs font-semibold uppercase ${LEVEL_TEXT[level]}`}>
        {level}
      </span>
    </div>
  );
}
