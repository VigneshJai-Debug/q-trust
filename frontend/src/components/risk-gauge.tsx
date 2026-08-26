"use client";

interface RiskGaugeProps {
  score: number;
  level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  label?: string;
}

const LEVEL_STYLES = {
  CRITICAL: "text-risk-critical bg-risk-critical/10",
  HIGH: "text-risk-high bg-risk-high/10",
  MEDIUM: "text-risk-medium bg-risk-medium/10",
  LOW: "text-risk-low bg-risk-low/10",
  NONE: "text-risk-none bg-risk-none/10",
} as const;

const LEVEL_STROKE = {
  CRITICAL: "var(--color-risk-critical)",
  HIGH: "var(--color-risk-high)",
  MEDIUM: "var(--color-risk-medium)",
  LOW: "var(--color-risk-low)",
  NONE: "var(--color-risk-none)",
} as const;

export default function RiskGauge({ score, level, label }: RiskGaugeProps) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const offset = c - (score / 100) * c; // pure render — no effect

  return (
    <div className="flex flex-col items-center gap-2">
      <div
        className={`relative flex items-center justify-center rounded-full p-2 ${LEVEL_STYLES[level] ?? LEVEL_STYLES.NONE}`}
      >
        <svg width="140" height="140" viewBox="0 0 120 120" role="img" aria-label={`Risk score ${score} of 100 — ${level}`}>
          <circle
            cx="60"
            cy="60"
            r={r}
            fill="none"
            stroke="currentColor"
            strokeWidth="10"
            className="text-muted"
            strokeDasharray={c}
            strokeDashoffset={0}
            strokeLinecap="round"
            style={{ transform: "rotate(-90deg)", transformOrigin: "50% 50%" }}
          />
          <circle
            cx="60"
            cy="60"
            r={r}
            fill="none"
            stroke={LEVEL_STROKE[level] ?? LEVEL_STROKE.NONE}
            strokeWidth="10"
            strokeDasharray={c}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-[stroke-dashoffset] duration-1000 ease-out"
            style={{ transform: "rotate(-90deg)", transformOrigin: "50% 50%" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold ${LEVEL_STYLES[level] ?? LEVEL_STYLES.NONE}`}>{score}</span>
        </div>
      </div>
      {label && <span className="text-sm font-medium text-muted-foreground">{label}</span>}
      <span className={`text-xs font-semibold uppercase ${LEVEL_STYLES[level] ?? LEVEL_STYLES.NONE}`}>{level}</span>
    </div>
  );
}
