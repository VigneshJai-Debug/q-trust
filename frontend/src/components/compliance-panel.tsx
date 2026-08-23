"use client";

import { useState } from "react";

interface Rule {
  ruleId: string;
  ruleName: string;
  status: "COMPLIANT" | "NON_COMPLIANT" | "PARTIAL" | "NOT_APPLICABLE";
  evidence: string;
  recommendation: string;
}

interface CompliancePanelProps {
  framework: string;
  score: number;
  totalRules: number;
  compliantCount: number;
  nonCompliantCount: number;
  partialCount: number;
  rules: Rule[];
}

const STATUS_CONFIG: Record<
  string,
  { bg: string; text: string; label: string }
> = {
  COMPLIANT: { bg: "bg-green-500/15", text: "text-green-600", label: "Compliant" },
  NON_COMPLIANT: { bg: "bg-red-500/15", text: "text-red-600", label: "Non-Compliant" },
  PARTIAL: { bg: "bg-amber-500/15", text: "text-amber-600", label: "Partial" },
  NOT_APPLICABLE: {
    bg: "bg-gray-500/15",
    text: "text-gray-500",
    label: "N/A",
  },
};

function ScoreBar({
  compliant,
  partial,
  nonCompliant,
  total,
}: {
  compliant: number;
  partial: number;
  nonCompliant: number;
  total: number;
}) {
  if (total === 0) return null;
  const cPct = (compliant / total) * 100;
  const pPct = (partial / total) * 100;
  const nPct = (nonCompliant / total) * 100;

  return (
    <div className="flex h-3 w-full overflow-hidden rounded-full bg-muted">
      {cPct > 0 && (
        <div
          className="bg-green-500 transition-all duration-500"
          style={{ width: `${cPct}%` }}
        />
      )}
      {pPct > 0 && (
        <div
          className="bg-amber-500 transition-all duration-500"
          style={{ width: `${pPct}%` }}
        />
      )}
      {nPct > 0 && (
        <div
          className="bg-red-500 transition-all duration-500"
          style={{ width: `${nPct}%` }}
        />
      )}
    </div>
  );
}

export default function CompliancePanel({
  framework,
  score,
  totalRules,
  compliantCount,
  nonCompliantCount,
  partialCount,
  rules,
}: CompliancePanelProps) {
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);

  const toggle = (id: string) =>
    setExpandedRuleId((prev) => (prev === id ? null : id));

  const scoreColor =
    score >= 80
      ? "text-green-600"
      : score >= 50
        ? "text-amber-600"
        : "text-red-600";

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-foreground">{framework}</h3>
          <span className={`text-2xl font-bold ${scoreColor}`}>{score}%</span>
        </div>
        <ScoreBar
          compliant={compliantCount}
          partial={partialCount}
          nonCompliant={nonCompliantCount}
          total={totalRules}
        />
        <div className="mt-2 flex gap-4 text-xs text-muted-foreground">
          <span>
            {compliantCount}/{totalRules} compliant
          </span>
          <span>{partialCount} partial</span>
          <span>{nonCompliantCount} non-compliant</span>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-muted-foreground">
              <th className="px-4 py-3 font-medium">Rule ID</th>
              <th className="px-4 py-3 font-medium">Name</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Details</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => {
              const cfg = STATUS_CONFIG[rule.status] || STATUS_CONFIG.NOT_APPLICABLE;
              const isExpanded = expandedRuleId === rule.ruleId;
              return (
                <tr
                  key={rule.ruleId}
                  className="border-b border-border last:border-0"
                >
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                    {rule.ruleId}
                  </td>
                  <td className="px-4 py-3 text-foreground">{rule.ruleName}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ${cfg.bg} ${cfg.text}`}
                    >
                      {cfg.label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggle(rule.ruleId)}
                      className="text-xs text-primary underline-offset-2 hover:underline"
                    >
                      {isExpanded ? "Hide" : "Show"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {rules.map((rule) => {
          if (expandedRuleId !== rule.ruleId) return null;
          const cfg = STATUS_CONFIG[rule.status] || STATUS_CONFIG.NOT_APPLICABLE;
          return (
            <div
              key={`detail-${rule.ruleId}`}
              className="border-t border-border bg-muted/30 px-4 py-3"
            >
              <div className="mb-2 flex items-center gap-2">
                <span className="font-mono text-xs text-muted-foreground">
                  {rule.ruleId}
                </span>
                <span
                  className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${cfg.bg} ${cfg.text}`}
                >
                  {cfg.label}
                </span>
              </div>
              <div className="grid gap-3 text-sm md:grid-cols-2">
                <div>
                  <span className="mb-1 block text-xs font-medium uppercase text-muted-foreground">
                    Evidence
                  </span>
                  <p className="text-foreground">{rule.evidence || "—"}</p>
                </div>
                <div>
                  <span className="mb-1 block text-xs font-medium uppercase text-muted-foreground">
                    Recommendation
                  </span>
                  <p className="text-foreground">
                    {rule.recommendation || "—"}
                  </p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
