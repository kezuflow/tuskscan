import type { AuditFinding } from "@repo/shared";

export function extractMemoryLessons(findings: AuditFinding[]) {
  return findings
    .filter((finding) => finding.severity !== "info")
    .map(
      (finding) =>
        `${finding.ruleId}: ${finding.title} in ${finding.evidence
          .map((item) => `${item.moduleName}${item.functionName ? `::${item.functionName}` : ""}`)
          .join(", ")}`,
    );
}
