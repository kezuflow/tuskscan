import {
  AI_PRE_AUDIT_DISCLAIMER,
  type AgentReview,
  type AuditFinding,
  type AuditReport,
  type ExploitTestDraft,
  type FindingSeverity,
  type NormalizedPackageSnapshot,
  type PackageSummary,
  type SourceConsistency,
  type SourceContext,
  type SourceSummary,
} from "@repo/shared";

import { extractMemoryLessons, extractMemoryPlaybooks } from "./memory.js";
import { extractMoveFunctions, extractSourceModuleNames } from "./source-parser.js";
import type { AuditEngineResult, CriticDecision, ExploitMemory } from "./types.js";

export function createAuditReport(options: {
  criticDecisions?: CriticDecision[];
  findings: AuditFinding[];
  memories: ExploitMemory[];
  packageSummary: PackageSummary;
  sourceContext?: SourceContext;
  sourceSummary?: SourceSummary;
  snapshot: NormalizedPackageSnapshot;
}): AuditEngineResult {
  const playbooks = extractMemoryPlaybooks(options.findings);
  const calibratedFindings = calibrateFindings(options.findings, playbooks);
  const riskScore = calculateRiskScore(calibratedFindings);
  const severityBreakdown = countSeverities(calibratedFindings);
  const topRisks = calibratedFindings
    .filter((finding) => finding.severity === "critical" || finding.severity === "high")
    .slice(0, 5)
    .map((finding) => finding.title);
  const summary =
    calibratedFindings.length === 0
      ? options.sourceSummary
        ? "No high-signal issues were detected across normalized metadata and provided Move source."
        : "No deterministic high-signal issues were detected in the normalized module surface."
      : `Detected ${calibratedFindings.length} review items across ${options.sourceSummary ? "normalized metadata and provided Move source" : "the deployed package surface"}, including ${severityBreakdown.critical} critical and ${severityBreakdown.high} high severity items.`;
  const learned = extractMemoryLessons(calibratedFindings);
  const report: AuditReport = {
    actionPlan: createActionPlan(calibratedFindings),
    agentReviews: createAgentReviews(calibratedFindings, options.criticDecisions ?? []),
    artifacts: {},
    calibration: {
      memoryMatchedFindings: calibratedFindings.filter((finding) => finding.memoryAssisted).length,
      memoryRecordsLearned: learned.length,
      memoriesRecalled: options.memories.length,
      note:
        "Confidence is calibrated from severity, deterministic/source evidence, and historical MemWal playbook matches. It is not formal proof.",
    },
    coverage: calculateCoverage(options.snapshot, options.sourceContext),
    createdAt: new Date().toISOString(),
    disclaimer: AI_PRE_AUDIT_DISCLAIMER,
    findings: calibratedFindings,
    generatedExploitTests: generateExploitTestDrafts(calibratedFindings),
    memoryPlaybooks: playbooks,
    packageSummary: options.packageSummary,
    riskScore,
    severityBreakdown,
    sourceConsistency: analyzeSourceConsistency(options.snapshot, options.sourceContext),
    sourceSummary: options.sourceSummary,
    status: "completed",
    summary,
    topRisks,
    visibility: "public_summary_private_details",
  };

  return {
    findings: calibratedFindings,
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

function calibrateFindings(
  findings: AuditFinding[],
  playbooks: ReturnType<typeof extractMemoryPlaybooks>,
): AuditFinding[] {
  return findings.map((finding) => {
    const playbookIds = playbooks
      .filter((playbook) => playbook.findingId === finding.id)
      .map((playbook) => playbook.id);
    const hasStrongEvidence = finding.evidence.some(
      (item) => item.filePath || item.codeSnippet || item.functionName,
    );
    const calibratedConfidence =
      finding.memoryAssisted || hasStrongEvidence || finding.severity === "critical"
        ? "high"
        : finding.confidence;
    return {
      ...finding,
      calibratedConfidence,
      memoryPlaybookIds: playbookIds.length ? playbookIds : undefined,
    };
  });
}

function analyzeSourceConsistency(
  snapshot: NormalizedPackageSnapshot,
  sourceContext: SourceContext | undefined,
): SourceConsistency {
  const deployedModules = snapshot.modules.map((module) => module.name).sort();
  if (!sourceContext) {
    return {
      deployedModules,
      level: "not_provided",
      matchedModules: [],
      missingInSource: deployedModules,
      note: "No source repository was supplied. TuskScan could only inspect normalized deployed package metadata.",
      sourceModules: [],
    };
  }
  const sourceModules = Array.from(
    new Set(
      sourceContext.files.flatMap((file) => extractSourceModuleNames(file.content)),
    ),
  ).sort();
  const sourceSet = new Set(sourceModules);
  const matchedModules = deployedModules.filter((moduleName) => sourceSet.has(moduleName));
  const missingInSource = deployedModules.filter((moduleName) => !sourceSet.has(moduleName));
  return {
    deployedModules,
    level: missingInSource.length === 0 ? "module_name_match" : "module_name_mismatch",
    matchedModules,
    missingInSource,
    note:
      "Source/deploy consistency is checked by module names only. Bytecode/source-map equivalence is not proven yet.",
    sourceModules,
  };
}

function generateExploitTestDrafts(findings: AuditFinding[]): ExploitTestDraft[] {
  return findings
    .filter((finding) => finding.severity === "critical" || finding.severity === "high")
    .slice(0, 8)
    .map((finding): ExploitTestDraft => {
      const evidence = finding.evidence[0];
      const name = `tuskscan_${slug(finding.ruleId)}_${slug(evidence?.functionName ?? evidence?.moduleName ?? "finding")}`;
      return {
        command: `sui move test --filter ${name}`,
        findingId: finding.id,
        kind: "move_unit_test_draft",
        name,
        notes: [
          "Draft generated from deployed metadata/source evidence. Bind package-specific object constructors before running.",
          "The test should fail before remediation and pass after the recommended guard is added.",
          ...(finding.testSuggestions ?? []),
        ],
        source: renderMoveTestDraft(name, finding),
        status: "draft_needs_project_binding",
        target: evidence
          ? {
              filePath: evidence.filePath,
              functionName: evidence.functionName,
              moduleName: evidence.moduleName,
            }
          : undefined,
      };
    });
}

function renderMoveTestDraft(name: string, finding: AuditFinding) {
  const evidence = finding.evidence[0];
  const target = `${evidence?.moduleName ?? "target"}${evidence?.functionName ? `::${evidence.functionName}` : ""}`;
  return [
    "#[test]",
    `fun ${name}() {`,
    "    // TuskScan generated exploit regression draft.",
    `    // Finding: ${finding.ruleId} - ${finding.title}`,
    `    // Target: ${target}`,
    "    // TODO: create required package objects/capabilities using project fixtures.",
    "    // TODO: execute the unauthorized or replay call described below.",
    ...((finding.exploitPath ?? []).map((step) => `    // - ${step}`)),
    "    // Expected: transaction aborts before value movement or unauthorized mutation.",
    "}",
  ].join("\n");
}

function createAgentReviews(
  findings: AuditFinding[],
  criticDecisions: CriticDecision[],
): AgentReview[] {
  const highSignal = findings.filter(
    (finding) => finding.severity === "critical" || finding.severity === "high",
  );
  return [
    {
      agent: "scanner",
      findingsReviewed: findings.length,
      output: [
        "Deterministic metadata and source rules produced the base finding set.",
        `${highSignal.length} critical/high findings require immediate manual review.`,
      ],
      status: "completed",
    },
    {
      agent: "researcher",
      findingsReviewed: findings.length,
      output: [
        "Research pass groups findings by access control, value movement, object lifecycle, replay, and state integrity.",
      ],
      status: "completed",
    },
    {
      agent: "exploit_writer",
      findingsReviewed: highSignal.length,
      output: [
        "Generated Move unit test drafts for critical/high findings where evidence identifies a module/function target.",
      ],
      status: "completed",
    },
    {
      agent: "patch_reviewer",
      findingsReviewed: findings.length,
      output: [
        "Patch sketches and remediation steps are attached to findings; generated tests should be added before remediation.",
      ],
      status: "completed",
    },
    {
      agent: "false_positive_critic",
      findingsReviewed: criticDecisions.length || findings.length,
      output: criticDecisions.length
        ? criticDecisions.slice(0, 5).map((decision) => `${decision.action}: ${decision.reason}`)
        : ["No external critic agent configured; deterministic findings were retained."],
      status: criticDecisions.length ? "completed" : "not_configured",
    },
  ];
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 48);
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
    report.sourceConsistency
      ? `Source consistency: \`${report.sourceConsistency.level}\` (${report.sourceConsistency.matchedModules.length}/${report.sourceConsistency.deployedModules.length} deployed modules matched by name)`
      : "Source consistency: unavailable",
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
    "## Agent Review",
    "",
    ...(report.agentReviews?.flatMap((review) => [
      `- ${review.agent}: ${review.status}, reviewed ${review.findingsReviewed} findings.`,
      ...review.output.map((item) => `  - ${item}`),
    ]) ?? []),
    "",
    "## Generated Exploit Test Drafts",
    "",
    ...(report.generatedExploitTests?.length
      ? report.generatedExploitTests.map(
          (test) => `- \`${test.name}\`: ${test.command} (${test.status})`,
        )
      : ["No critical/high exploit test drafts generated."]),
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
      finding.calibratedConfidence
        ? `Calibrated confidence: \`${finding.calibratedConfidence}\``
        : undefined,
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
