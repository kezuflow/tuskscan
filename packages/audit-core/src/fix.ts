import type { AuditFinding } from "@repo/shared";

export function runFixAgent(findings: AuditFinding[]): AuditFinding[] {
  return findings.map((finding) => ({
    ...finding,
    recommendation:
      finding.recommendation ||
      "Review this deterministic finding manually and add an explicit authorization or invariant check before deployment.",
  }));
}
