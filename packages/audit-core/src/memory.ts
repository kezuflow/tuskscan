import type { AuditFinding, MemoryPlaybook } from "@repo/shared";

export function extractMemoryLessons(findings: AuditFinding[]) {
  const lessons = findings
    .filter((finding) => finding.severity !== "info")
    .map(
      (finding) =>
        `${finding.ruleId}: ${finding.title} in ${finding.evidence
          .map((item) => `${item.moduleName}${item.functionName ? `::${item.functionName}` : ""}`)
          .join(", ")}`,
    );
  return [...lessons, ...extractMemoryPlaybooks(findings).map((playbook) => playbook.summary)];
}

export function extractMemoryPlaybooks(findings: AuditFinding[]): MemoryPlaybook[] {
  return findings
    .filter((finding) => finding.severity !== "info")
    .slice(0, 20)
    .map((finding): MemoryPlaybook => {
      const target = finding.evidence[0];
      const query = [
        finding.ruleId,
        finding.category,
        finding.title,
        target?.moduleName,
        target?.functionName,
      ]
        .filter(Boolean)
        .join(" ");
      return {
        findingId: finding.id,
        id: `playbook:${finding.ruleId}:${target?.moduleName ?? "package"}:${target?.functionName ?? "scope"}`.toLowerCase(),
        query,
        summary: [
          `PLAYBOOK ${finding.ruleId}: ${finding.title}.`,
          finding.impact ? `Impact: ${finding.impact}` : undefined,
          finding.exploitPath?.length ? `Exploit path: ${finding.exploitPath.join(" -> ")}` : undefined,
          finding.patchSuggestion ? `Patch: ${finding.patchSuggestion}` : undefined,
        ]
          .filter(Boolean)
          .join(" "),
      };
    });
}
