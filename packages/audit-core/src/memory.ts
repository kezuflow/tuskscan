import type {
  AuditFinding,
  AuditObservationMemory,
  MemoryPlaybook,
  NormalizedPackageSnapshot,
  VulnerabilityPatternMemory,
} from "@repo/shared";

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

export function extractMemoryWriteBundle(
  findings: AuditFinding[],
  snapshot: NormalizedPackageSnapshot,
) {
  return {
    lessons: extractMemoryLessons(findings),
    observations: extractAuditObservations(findings, snapshot),
    patterns: extractVulnerabilityPatternMemories(findings),
  };
}

export function extractVulnerabilityPatternMemories(
  findings: AuditFinding[],
): VulnerabilityPatternMemory[] {
  const patterns = new Map<string, VulnerabilityPatternMemory>();
  for (const finding of findings.filter((item) => item.severity !== "info")) {
    const id = `pattern:sui:move:${finding.ruleId.toLowerCase()}`;
    if (patterns.has(id)) continue;
    const evidence = finding.evidence[0];
    patterns.set(id, {
      category: finding.category ?? "uncategorized",
      chain: "sui",
      exampleEvidence: evidence
        ? {
            filePath: evidence.filePath,
            functionName: evidence.functionName,
            moduleName: evidence.moduleName,
            severity: finding.severity,
          }
        : undefined,
      exploitModel: normalizeSteps(finding.exploitPath, finding.impact ?? finding.description),
      falsePositiveChecks: falsePositiveChecksFor(finding),
      fixPattern: normalizeSteps(
        finding.remediationSteps,
        finding.patchSuggestion ?? finding.recommendation,
      ),
      id,
      kind: "vulnerability_pattern",
      language: "move",
      pattern: `${finding.title}: ${finding.description}`,
      ruleId: finding.ruleId,
      severity: finding.severity,
      signals: signalsFor(finding),
      updatedAt: new Date().toISOString(),
    });
  }
  return [...patterns.values()].slice(0, 20);
}

export function extractAuditObservations(
  findings: AuditFinding[],
  snapshot: NormalizedPackageSnapshot,
): AuditObservationMemory[] {
  return findings
    .filter((finding) => finding.severity !== "info")
    .slice(0, 40)
    .map((finding): AuditObservationMemory => ({
      chain: "sui",
      confirmed: false,
      findingId: finding.id,
      kind: "audit_observation",
      language: "move",
      observedAt: new Date().toISOString(),
      packageId: snapshot.packageId,
      patternId: `pattern:sui:move:${finding.ruleId.toLowerCase()}`,
      severity: finding.severity,
      sourceModules: Array.from(
        new Set(finding.evidence.map((item) => item.moduleName)),
      ),
    }));
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

function signalsFor(finding: AuditFinding) {
  return [
    finding.ruleId,
    finding.category,
    finding.title,
    ...finding.evidence.map((item) =>
      [
        item.moduleName,
        item.functionName,
        item.detail,
        item.filePath ? `source:${item.filePath}` : undefined,
      ]
        .filter(Boolean)
        .join(" "),
    ),
    ...(finding.attackPrerequisites ?? []),
    ...(finding.testSuggestions ?? []),
  ]
    .filter((item): item is string => Boolean(item))
    .slice(0, 12);
}

function falsePositiveChecksFor(finding: AuditFinding) {
  const checks = [
    "Verify whether the function is intentionally permissionless.",
    "Search helper calls for capability, owner, sender, or witness checks before confirming.",
    "Check whether object access is constrained by dynamic fields or package-private constructors.",
  ];
  if (finding.ruleId.includes("MISSING_CAPABILITY") || finding.ruleId.includes("ADMIN")) {
    checks.push("Do not flag if an AdminCap/OwnerCap or equivalent authority is required upstream.");
  }
  if (finding.ruleId.includes("TRANSFER") || finding.ruleId.includes("VALUE")) {
    checks.push("Do not flag if recipient and amount are derived from verified entitlement state.");
  }
  if (finding.ruleId.includes("REPLAY") || finding.ruleId.includes("CLAIM")) {
    checks.push("Do not flag if a claimed marker or nonce is written before value movement.");
  }
  return checks;
}

function normalizeSteps(steps: string[] | undefined, fallback: string) {
  return steps?.length ? steps.slice(0, 8) : [fallback];
}
