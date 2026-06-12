import {
  AI_PRE_AUDIT_DISCLAIMER,
  type AuditFinding,
  type AuditReport,
  type FindingSeverity,
  type NormalizedPackageSnapshot,
  type PackageSummary,
  type SourceContext,
  type SourceSummary,
} from "@repo/shared";

import { extractMemoryLessons } from "./memory.js";
import { extractMoveFunctions } from "./source-parser.js";
import type { AuditEngineResult, ExploitMemory } from "./types.js";

export function createAuditReport(options: {
  findings: AuditFinding[];
  memories: ExploitMemory[];
  packageSummary: PackageSummary;
  sourceContext?: SourceContext;
  sourceSummary?: SourceSummary;
  snapshot: NormalizedPackageSnapshot;
}): AuditEngineResult {
  const riskScore = calculateRiskScore(options.findings);
  const severityBreakdown = countSeverities(options.findings);
  const topRisks = options.findings
    .filter((finding) => finding.severity === "critical" || finding.severity === "high")
    .slice(0, 5)
    .map((finding) => finding.title);
  const summary =
    options.findings.length === 0
      ? options.sourceSummary
        ? "No high-signal issues were detected across normalized metadata and provided Move source."
        : "No deterministic high-signal issues were detected in the normalized module surface."
      : `Detected ${options.findings.length} review items across ${options.sourceSummary ? "normalized metadata and provided Move source" : "the deployed package surface"}, including ${severityBreakdown.critical} critical and ${severityBreakdown.high} high severity items.`;
  const learned = extractMemoryLessons(options.findings);
  const report: AuditReport = {
    actionPlan: createActionPlan(options.findings),
    artifacts: {},
    coverage: calculateCoverage(options.snapshot, options.sourceContext),
    createdAt: new Date().toISOString(),
    disclaimer: AI_PRE_AUDIT_DISCLAIMER,
    findings: options.findings,
    packageSummary: options.packageSummary,
    riskScore,
    severityBreakdown,
    sourceSummary: options.sourceSummary,
    status: "completed",
    summary,
    topRisks,
    visibility: "public_summary_private_details",
  };

  return {
    findings: options.findings,
    memoryDiff: { learned, recalled: options.memories },
    privateReportMarkdown: renderMarkdownReport(report, true),
    publicReportMarkdown: renderMarkdownReport(report, false),
    report,
  };
}

export function calculateRiskScore(findings: AuditFinding[]) {
  const weights: Record<FindingSeverity, number> = {
    critical: 35,
    high: 24,
    info: 2,
    low: 6,
    medium: 12,
  };
  return Math.min(
    100,
    findings.reduce((sum, finding) => sum + weights[finding.severity], 0),
  );
}

function countSeverities(findings: AuditFinding[]): Record<FindingSeverity, number> {
  return {
    critical: findings.filter((finding) => finding.severity === "critical").length,
    high: findings.filter((finding) => finding.severity === "high").length,
    info: findings.filter((finding) => finding.severity === "info").length,
    low: findings.filter((finding) => finding.severity === "low").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
  };
}

function calculateCoverage(
  snapshot: NormalizedPackageSnapshot,
  sourceContext: SourceContext | undefined,
): NonNullable<AuditReport["coverage"]> {
  const sourceFunctions = sourceContext?.files.flatMap((file) => extractMoveFunctions(file)) ?? [];
  return {
    checkedModules: snapshot.modules.length,
    checkedMoveFiles: sourceContext?.files.length ?? 0,
    checkedPublicEntryFunctions: snapshot.modules.reduce(
      (count, module) =>
        count + module.functions.filter((fn) => fn.visibility === "public" && fn.isEntry).length,
      0,
    ),
    checkedSourceFunctions: sourceFunctions.length,
  };
}

function createActionPlan(findings: AuditFinding[]) {
  const urgentFindings = findings.filter(
    (finding) => finding.severity === "critical" || finding.severity === "high",
  );
  if (urgentFindings.length === 0) {
    return [
      "Review informational object lifecycle notes before deployment.",
      "Add regression tests around all public entry functions that move value or mutate shared objects.",
      "Run a human review for business-logic invariants that cannot be proven from metadata alone.",
    ];
  }
  return [
    "Fix critical authorization, minting, and value-movement findings before mainnet use.",
    "Add negative Move tests for every critical/high finding using an unauthorized wallet.",
    "Re-run TuskScan with the same source URL and compare the Walrus artifact hashes after remediation.",
    ...urgentFindings.slice(0, 3).map((finding) => `Prioritize: ${finding.title}.`),
  ];
}

function renderMarkdownReport(report: AuditReport, includeDetails: boolean) {
  const lines = [
    "# TuskScan AI Pre-Audit Report",
    "",
    report.disclaimer,
    "",
    `Package: \`${report.packageSummary.packageId}\``,
    `Network: \`${report.packageSummary.network}\``,
    `Risk score: **${report.riskScore}/100**`,
    report.sourceSummary
      ? `Source: \`${report.sourceSummary.url}\` (${report.sourceSummary.moveFileCount} Move files)`
      : "Source: `not provided`",
    report.coverage
      ? `Coverage: ${report.coverage.checkedModules} modules, ${report.coverage.checkedPublicEntryFunctions} public entry functions, ${report.coverage.checkedMoveFiles} Move source files, ${report.coverage.checkedSourceFunctions} source functions`
      : "Coverage: unavailable",
    "",
    "## Summary",
    "",
    report.summary,
    "",
    "## Severity Breakdown",
    "",
    `- Critical: ${report.severityBreakdown?.critical ?? 0}`,
    `- High: ${report.severityBreakdown?.high ?? 0}`,
    `- Medium: ${report.severityBreakdown?.medium ?? 0}`,
    `- Low: ${report.severityBreakdown?.low ?? 0}`,
    `- Info: ${report.severityBreakdown?.info ?? 0}`,
    "",
    "## Action Plan",
    "",
    ...(report.actionPlan?.map((item, index) => `${index + 1}. ${item}`) ?? []),
    "",
    "## Findings",
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("No findings detected by deterministic v1 rules.");
  }

  for (const finding of report.findings) {
    const findingHeader = [
      `### ${finding.severity.toUpperCase()}: ${finding.title}`,
      "",
      `Rule: \`${finding.ruleId}\``,
      finding.category ? `Category: \`${finding.category}\`` : undefined,
      `Confidence: \`${finding.confidence}\``,
      finding.likelihood ? `Likelihood: \`${finding.likelihood}\`` : undefined,
      `Memory assisted: \`${finding.memoryAssisted ? "yes" : "no"}\``,
      "",
      finding.description,
      "",
    ].filter((line): line is string => typeof line === "string");
    lines.push(...findingHeader);
    if (includeDetails) {
      if (finding.impact) {
        lines.push("Impact:", "", finding.impact, "");
      }
      if (finding.attackPrerequisites?.length) {
        lines.push("Attack prerequisites:", "");
        for (const prerequisite of finding.attackPrerequisites) {
          lines.push(`- ${prerequisite}`);
        }
        lines.push("");
      }
      lines.push("Evidence:", "");
      for (const evidence of finding.evidence) {
        const location = evidence.filePath
          ? ` (${evidence.filePath}${evidence.lineStart ? `:${evidence.lineStart}` : ""})`
          : "";
        lines.push(`- ${evidence.detail}${location}`);
        if (evidence.codeSnippet) {
          lines.push("", "```move", evidence.codeSnippet, "```", "");
        }
      }
      if (finding.exploitPath?.length) {
        lines.push("", "Exploit path:", "");
        for (const [index, step] of finding.exploitPath.entries()) {
          lines.push(`${index + 1}. ${step}`);
        }
      }
      lines.push("", "Recommendation:", "", finding.recommendation, "");
      if (finding.remediationSteps?.length) {
        lines.push("Remediation steps:", "");
        for (const [index, step] of finding.remediationSteps.entries()) {
          lines.push(`${index + 1}. ${step}`);
        }
        lines.push("");
      }
      if (finding.patchSuggestion) {
        lines.push("Patch sketch:", "", finding.patchSuggestion, "");
      }
      if (finding.testSuggestions?.length) {
        lines.push("Suggested tests:", "");
        for (const test of finding.testSuggestions) {
          lines.push(`- ${test}`);
        }
        lines.push("");
      }
    }
  }

  return `${lines.join("\n")}\n`;
}
