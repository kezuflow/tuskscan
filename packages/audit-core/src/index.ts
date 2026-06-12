import {
  AI_PRE_AUDIT_DISCLAIMER,
  type AuditFinding,
  type AuditReport,
  type FindingSeverity,
  type MemoryReference,
  type NormalizedFunction,
  type NormalizedPackageSnapshot,
  type PackageSummary,
  type SourceContext,
  type SourceFile,
  type SourceSummary,
} from "@repo/shared";

export type ExploitMemory = MemoryReference & {
  query: string;
};

export type AuditEngineResult = {
  findings: AuditFinding[];
  memoryDiff: {
    learned: string[];
    recalled: ExploitMemory[];
  };
  publicReportMarkdown: string;
  privateReportMarkdown: string;
  report: AuditReport;
};

export type ExploitMemoryAgent = {
  recall(snapshot: NormalizedPackageSnapshot): Promise<ExploitMemory[]> | ExploitMemory[];
  writeLessons?(
    lessons: string[],
    snapshot: NormalizedPackageSnapshot,
  ): Promise<void> | void;
};

export type FindingAgentInput = {
  deterministicFindings: AuditFinding[];
  memories: ExploitMemory[];
  packageSummary: PackageSummary;
  sourceContext?: SourceContext;
  snapshot: NormalizedPackageSnapshot;
};

export type AuditFindingAgent = {
  analyze(input: FindingAgentInput): Promise<AuditFinding[]> | AuditFinding[];
};

export type CriticAgentInput = FindingAgentInput & {
  findings: AuditFinding[];
};

export type AuditCriticAgent = {
  critique(input: CriticAgentInput): Promise<CriticDecision[]> | CriticDecision[];
};

export type CriticDecision = {
  action: "keep" | "downgrade" | "drop";
  findingId: string;
  reason: string;
  severity?: FindingSeverity;
};

export type AuditWorkflowResult = AuditEngineResult & {
  criticDecisions: CriticDecision[];
};

const DETERMINISTIC_CRITIC_REASON =
  "Kept because the finding is backed by deterministic normalized Move metadata.";

export function runDeterministicAudit(
  snapshot: NormalizedPackageSnapshot,
  memories: ExploitMemory[] = [],
  sourceContext?: SourceContext,
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const module of snapshot.modules) {
    for (const fn of module.functions) {
      const lowered = fn.name.toLowerCase();
      const evidence = {
        detail: `Function ${module.name}::${fn.name} is ${fn.visibility}${fn.isEntry ? " entry" : ""} with parameters ${fn.parameters.map((param) => param.raw).join(", ") || "none"}.`,
        functionName: fn.name,
        moduleName: module.name,
      };

      if (isPublicEntry(fn) && hasPrivilegedName(lowered)) {
        findings.push(
          createFinding({
            description:
              "A public entry function has an admin-like name. Review whether it is gated by an explicit capability object or trusted admin parameter.",
            evidence: [evidence],
            fn,
            memoryReferences: matchMemories(memories, "admin capability"),
            moduleName: module.name,
            recommendation:
              "Require a dedicated AdminCap/OwnerCap parameter and assert ownership before executing privileged state changes.",
            ruleId: "MOVE_PUBLIC_ADMIN_ENTRY",
            severity: "high",
            title: "Public admin-like entry function",
          }),
        );
      }

      if (isPublicEntry(fn) && hasPrivilegedName(lowered) && !hasCapabilityParam(fn)) {
        findings.push(
          createFinding({
            description:
              "A privileged-looking entry point does not expose an obvious capability/admin parameter in the normalized signature.",
            evidence: [evidence],
            fn,
            memoryReferences: matchMemories(memories, "missing capability"),
            moduleName: module.name,
            recommendation:
              "Add a capability parameter such as AdminCap or enforce an explicit signer/object ownership check.",
            ruleId: "MOVE_MISSING_CAPABILITY_PARAM",
            severity: "critical",
            title: "Privileged function may lack capability gate",
          }),
        );
      }

      if (isPublicEntry(fn) && fn.parameters.some((param) => param.isMutableReference)) {
        findings.push(
          createFinding({
            description:
              "A public entry function accepts mutable references. This is often correct, but privileged shared-object mutation should be reviewed carefully.",
            evidence: [evidence],
            fn,
            memoryReferences: matchMemories(memories, "shared object mutation"),
            moduleName: module.name,
            recommendation:
              "Confirm the mutable object path is gated by ownership, capability checks, or invariant-preserving assertions.",
            ruleId: "MOVE_PUBLIC_MUTABLE_ENTRY",
            severity: hasPrivilegedName(lowered) ? "high" : "medium",
            title: "Public mutable entry surface",
          }),
        );
      }

      if (isPublicEntry(fn) && hasTransferLikeName(lowered)) {
        findings.push(
          createFinding({
            description:
              "A public entry function appears to transfer, withdraw, sweep, or claim value. Value-moving paths deserve explicit authorization review.",
            evidence: [evidence],
            fn,
            memoryReferences: matchMemories(memories, "withdraw transfer claim"),
            moduleName: module.name,
            recommendation:
              "Check sender authority, recipient restrictions, balance accounting, and replay/claim guards.",
            ruleId: "MOVE_VALUE_MOVING_ENTRY",
            severity: "medium",
            title: "Public value-moving entry function",
          }),
        );
      }
    }

    for (const struct of module.structs) {
      if (struct.abilities.includes("key") && struct.abilities.includes("store")) {
        findings.push({
          confidence: "medium",
          description:
            "A key+store object type can become a persistent onchain asset. Review all public functions that create, mutate, transfer, or destroy it.",
          evidence: [
            {
              detail: `Struct ${module.name}::${struct.name} has abilities ${struct.abilities.join(", ")}.`,
              moduleName: module.name,
              structName: struct.name,
            },
          ],
          id: findingId("MOVE_KEY_STORE_OBJECT", module.name, struct.name),
          memoryAssisted: false,
          memoryReferences: [],
          recommendation:
            "Trace object lifecycle functions and ensure ownership/capability checks protect privileged transitions.",
          ruleId: "MOVE_KEY_STORE_OBJECT",
          severity: "info",
          title: "Persistent object lifecycle review",
        });
      }
    }
  }

  return dedupeFindings([...findings, ...runSourceAwareAudit(sourceContext, memories)]);
}

export async function runAuditWorkflow(options: {
  criticAgent?: AuditCriticAgent;
  findingAgent?: AuditFindingAgent;
  memoryAgent?: ExploitMemoryAgent;
  packageSummary: PackageSummary;
  sourceContext?: SourceContext;
  snapshot: NormalizedPackageSnapshot;
}): Promise<AuditWorkflowResult> {
  const recalledMemories =
    (await options.memoryAgent?.recall(options.snapshot)) ?? [];
  const deterministicFindings = runScannerAgent(
    options.snapshot,
    recalledMemories,
    options.sourceContext,
  );
  const agentFindings = await runFindingAgent({
    deterministicFindings,
    findingAgent: options.findingAgent,
    memories: recalledMemories,
    packageSummary: options.packageSummary,
    sourceContext: options.sourceContext,
    snapshot: options.snapshot,
  });
  const scannerFindings = dedupeFindings([...deterministicFindings, ...agentFindings]);
  const criticResult = await runCriticAgent(scannerFindings, {
    criticAgent: options.criticAgent,
    deterministicFindings,
    memories: recalledMemories,
    packageSummary: options.packageSummary,
    sourceContext: options.sourceContext,
    snapshot: options.snapshot,
  });
  const remediatedFindings = runFixAgent(criticResult.findings);
  const reportResult = createAuditReport({
    findings: remediatedFindings,
    memories: recalledMemories,
    packageSummary: options.packageSummary,
    sourceSummary: options.sourceContext
      ? summarizeSourceContext(options.sourceContext)
      : undefined,
  });
  const lessons = extractMemoryLessons(remediatedFindings);

  await options.memoryAgent?.writeLessons?.(lessons, options.snapshot);

  return {
    ...reportResult,
    criticDecisions: criticResult.decisions,
    memoryDiff: {
      learned: lessons,
      recalled: recalledMemories,
    },
  };
}

export function runScannerAgent(
  snapshot: NormalizedPackageSnapshot,
  memories: ExploitMemory[] = [],
  sourceContext?: SourceContext,
) {
  return runDeterministicAudit(snapshot, memories, sourceContext);
}

async function runFindingAgent(options: FindingAgentInput & {
  findingAgent?: AuditFindingAgent;
}) {
  if (!options.findingAgent) return [];
  try {
    return dedupeFindings(await options.findingAgent.analyze(options));
  } catch {
    return [];
  }
}

export async function runCriticAgent(findings: AuditFinding[], options?: FindingAgentInput & {
  criticAgent?: AuditCriticAgent;
}): Promise<{
  decisions: CriticDecision[];
  findings: AuditFinding[];
}> {
  const deterministicDecisions = findings.map((finding) => ({
      action: "keep",
      findingId: finding.id,
      reason: DETERMINISTIC_CRITIC_REASON,
    }) satisfies CriticDecision);

  if (!options?.criticAgent) {
    return { decisions: deterministicDecisions, findings };
  }

  try {
    const agentDecisions = await options.criticAgent.critique({
      deterministicFindings: options.deterministicFindings,
      findings,
      memories: options.memories,
      packageSummary: options.packageSummary,
      sourceContext: options.sourceContext,
      snapshot: options.snapshot,
    });
    return applyCriticDecisions(findings, deterministicDecisions, agentDecisions);
  } catch {
    return { decisions: deterministicDecisions, findings };
  }
}

export function runFixAgent(findings: AuditFinding[]): AuditFinding[] {
  return findings.map((finding) => ({
    ...finding,
    recommendation:
      finding.recommendation ||
      "Review this deterministic finding manually and add an explicit authorization or invariant check before deployment.",
  }));
}

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

export function createAuditReport(options: {
  findings: AuditFinding[];
  memories: ExploitMemory[];
  packageSummary: PackageSummary;
  sourceSummary?: SourceSummary;
}): AuditEngineResult {
  const riskScore = calculateRiskScore(options.findings);
  const summary =
    options.findings.length === 0
      ? options.sourceSummary
        ? "No high-signal issues were detected across normalized metadata and provided Move source."
        : "No deterministic high-signal issues were detected in the normalized module surface."
      : `Detected ${options.findings.length} review items across ${options.sourceSummary ? "normalized metadata and provided Move source" : "the deployed package surface"}.`;
  const learned = extractMemoryLessons(options.findings);
  const report: AuditReport = {
    artifacts: {},
    createdAt: new Date().toISOString(),
    disclaimer: AI_PRE_AUDIT_DISCLAIMER,
    findings: options.findings,
    packageSummary: options.packageSummary,
    riskScore,
    sourceSummary: options.sourceSummary,
    status: "completed",
    summary,
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

function createFinding(options: {
  description: string;
  evidence: AuditFinding["evidence"];
  fn: NormalizedFunction;
  memoryReferences: MemoryReference[];
  moduleName: string;
  recommendation: string;
  ruleId: string;
  severity: FindingSeverity;
  title: string;
}): AuditFinding {
  return {
    confidence:
      options.severity === "critical" || options.severity === "high"
        ? "high"
        : "medium",
    description: options.description,
    evidence: options.evidence,
    id: findingId(options.ruleId, options.moduleName, options.fn.name),
    memoryAssisted: options.memoryReferences.length > 0,
    memoryReferences: options.memoryReferences,
    recommendation: options.recommendation,
    ruleId: options.ruleId,
    severity: options.severity,
    title: options.title,
  };
}

function runSourceAwareAudit(
  sourceContext: SourceContext | undefined,
  memories: ExploitMemory[],
): AuditFinding[] {
  if (!sourceContext) return [];
  const findings: AuditFinding[] = [];

  for (const file of sourceContext.files) {
    for (const fn of extractMoveFunctions(file)) {
      const loweredName = fn.name.toLowerCase();
      const loweredBody = fn.body.toLowerCase();
      const evidence = sourceEvidence(file, fn);
      const hasAuthSignal = hasSourceAuthSignal(fn.body);
      const hasCapParam = /(cap|admin|owner|authority|witness|treasurycap)/i.test(
        fn.signature,
      );

      if (
        fn.isPublicEntry &&
        /transfer::public_transfer|coin::into_balance|balance::withdraw|coin::take/i.test(
          fn.body,
        ) &&
        !hasAuthSignal &&
        !hasCapParam
      ) {
        findings.push({
          confidence: "high",
          description:
            "Source analysis found a public entry value/object transfer path without an obvious capability, sender, or ownership authorization guard in the function body.",
          evidence: [evidence],
          exploitPath: [
            "Attacker calls the public entry function directly.",
            "Attacker supplies or targets the mutable/value-carrying object accepted by the function.",
            "Function reaches a transfer/withdraw path before an obvious authorization guard is enforced.",
          ],
          id: sourceFindingId("SRC_PUBLIC_TRANSFER_WITHOUT_AUTH", file.path, fn.name),
          memoryAssisted: matchMemories(memories, "withdraw transfer claim").length > 0,
          memoryReferences: matchMemories(memories, "withdraw transfer claim"),
          patchSuggestion:
            "Require an AdminCap/OwnerCap or assert tx_context::sender(ctx) owns the affected object before executing the transfer.",
          recommendation:
            "Add an explicit authority check before value/object transfer and add a Move test proving unauthorized callers abort.",
          ruleId: "SRC_PUBLIC_TRANSFER_WITHOUT_AUTH",
          severity: "critical",
          title: "Public transfer path may lack authorization",
        });
      }

      if (
        fn.isPublicEntry &&
        /dynamic_field|dynamic_object_field|table::|object_table::/i.test(fn.body) &&
        /add|remove|borrow_mut|insert/i.test(loweredBody) &&
        !hasAuthSignal &&
        !hasCapParam
      ) {
        findings.push({
          confidence: "medium",
          description:
            "Source analysis found public mutation of dynamic storage without an obvious authority guard. Dynamic field/table paths often control claims, ownership registries, or accounting state.",
          evidence: [evidence],
          exploitPath: [
            "Attacker calls the public entry function with chosen key/object inputs.",
            "Function mutates dynamic storage through add/remove/borrow_mut/insert.",
            "Without a guard, attacker may overwrite, replay, or remove state tied to another actor.",
          ],
          id: sourceFindingId("SRC_DYNAMIC_STORAGE_MUTATION", file.path, fn.name),
          memoryAssisted: matchMemories(memories, "shared object mutation").length > 0,
          memoryReferences: matchMemories(memories, "shared object mutation"),
          patchSuggestion:
            "Bind dynamic storage keys to tx_context::sender(ctx), object ownership, or a capability-controlled namespace.",
          recommendation:
            "Review dynamic storage key derivation and add tests for unauthorized key insertion, removal, and replay.",
          ruleId: "SRC_DYNAMIC_STORAGE_MUTATION",
          severity: "high",
          title: "Dynamic storage mutation needs authority review",
        });
      }

      if (
        fn.isPublicEntry &&
        /(claim|reward|redeem|withdraw|airdrop)/.test(loweredName) &&
        !/(claimed|receipt|nonce|used|has_claimed|contains|exists)/i.test(fn.body)
      ) {
        findings.push({
          confidence: "medium",
          description:
            "A public claim/reward-style function does not show an obvious replay guard such as a receipt, nonce, claimed set, or contains/exists check.",
          evidence: [evidence],
          exploitPath: [
            "Attacker calls the claim/reward function once.",
            "Attacker repeats the same call or changes only recipient-controlled inputs.",
            "Without a durable replay marker, rewards or withdrawals may be claimed multiple times.",
          ],
          id: sourceFindingId("SRC_CLAIM_REPLAY_REVIEW", file.path, fn.name),
          memoryAssisted: matchMemories(memories, "claim replay").length > 0,
          memoryReferences: matchMemories(memories, "claim replay"),
          patchSuggestion:
            "Store a claimed marker keyed by wallet/object/nonce before transferring value, and assert it does not already exist.",
          recommendation:
            "Add a negative Move test proving the second claim attempt aborts.",
          ruleId: "SRC_CLAIM_REPLAY_REVIEW",
          severity: "high",
          title: "Claim path may need replay protection",
        });
      }
    }

    const todo = findSourceMarker(file, /(TODO|FIXME|HACK|SECURITY|AUDIT)/);
    if (todo) {
      findings.push({
        confidence: "low",
        description:
          "Source contains an audit-relevant marker. This may be harmless, but unresolved security notes should not ship without review.",
        evidence: [todo],
        id: sourceFindingId("SRC_SECURITY_MARKER", file.path, String(todo.lineStart)),
        memoryAssisted: false,
        memoryReferences: [],
        recommendation:
          "Resolve or document the marker before deployment, especially if it touches authorization, accounting, or object lifecycle code.",
        ruleId: "SRC_SECURITY_MARKER",
        severity: "low",
        title: "Source contains security review marker",
      });
    }
  }

  return dedupeFindings(findings);
}

function extractMoveFunctions(file: SourceFile) {
  const lines = file.content.split(/\r?\n/);
  const functions: Array<{
    body: string;
    isPublicEntry: boolean;
    name: string;
    signature: string;
    startLine: number;
    endLine: number;
  }> = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const match = line.match(/\b(public\s+)?(entry\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)/);
    if (!match) continue;

    const startLine = index + 1;
    let braceDepth = 0;
    let seenBrace = false;
    const bodyLines: string[] = [];
    for (let cursor = index; cursor < lines.length; cursor += 1) {
      const current = lines[cursor] ?? "";
      bodyLines.push(current);
      for (const char of current) {
        if (char === "{") {
          braceDepth += 1;
          seenBrace = true;
        } else if (char === "}") {
          braceDepth -= 1;
        }
      }
      if (seenBrace && braceDepth <= 0) {
        functions.push({
          body: bodyLines.join("\n"),
          endLine: cursor + 1,
          isPublicEntry: Boolean(match[1]) && Boolean(match[2]),
          name: match[3] ?? "unknown",
          signature: bodyLines.join("\n").split("{")[0] ?? line,
          startLine,
        });
        index = cursor;
        break;
      }
    }
  }

  return functions;
}

function hasSourceAuthSignal(body: string) {
  return /assert!|tx_context::sender|ctx\.sender|sender\(|object::owner|owner|has_owner|address_of|borrow_global|exists</i.test(
    body,
  );
}

function sourceEvidence(
  file: SourceFile,
  fn: { body: string; endLine: number; name: string; startLine: number },
) {
  return {
    detail: `Source function ${fn.name} spans ${file.path}:${fn.startLine}-${fn.endLine}.`,
    filePath: file.path,
    functionName: fn.name,
    lineEnd: fn.endLine,
    lineStart: fn.startLine,
    moduleName: moduleNameFromPath(file.path),
  };
}

function findSourceMarker(file: SourceFile, pattern: RegExp) {
  const lines = file.content.split(/\r?\n/);
  const index = lines.findIndex((line) => pattern.test(line));
  if (index === -1) return undefined;
  return {
    detail: `${file.path}:${index + 1} contains "${lines[index]?.trim()}".`,
    filePath: file.path,
    lineStart: index + 1,
    moduleName: moduleNameFromPath(file.path),
  };
}

function moduleNameFromPath(path: string) {
  return path.split(/[\\/]/).pop()?.replace(/\.move$/i, "") ?? "source";
}

function sourceFindingId(ruleId: string, path: string, name: string) {
  return findingId(ruleId, path, name);
}

function summarizeSourceContext(sourceContext: SourceContext): SourceSummary {
  return {
    digest: sourceContext.digest,
    fileCount: sourceContext.files.length,
    moveFileCount: sourceContext.moveFileCount,
    url: sourceContext.url,
  };
}

function isPublicEntry(fn: NormalizedFunction) {
  return fn.visibility === "public" && fn.isEntry;
}

function hasPrivilegedName(name: string) {
  return /(admin|owner|config|upgrade|pause|unpause|set_|initialize|init|mint|burn|sweep)/.test(
    name,
  );
}

function hasTransferLikeName(name: string) {
  return /(transfer|withdraw|claim|sweep|payout|settle|redeem)/.test(name);
}

function hasCapabilityParam(fn: NormalizedFunction) {
  return fn.parameters.some((param) =>
    /(cap|admin|owner|authority|witness|treasurycap)/i.test(param.raw),
  );
}

function matchMemories(memories: ExploitMemory[], query: string): MemoryReference[] {
  return memories
    .filter((memory) =>
      `${memory.query} ${memory.summary}`.toLowerCase().includes(query.toLowerCase()),
    )
    .map(({ id, summary }) => ({ id, summary }))
    .slice(0, 3);
}

function dedupeFindings(findings: AuditFinding[]) {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    if (seen.has(finding.id)) return false;
    seen.add(finding.id);
    return true;
  });
}

function applyCriticDecisions(
  findings: AuditFinding[],
  fallbackDecisions: CriticDecision[],
  agentDecisions: CriticDecision[],
) {
  const decisionsById = new Map<string, CriticDecision>();
  for (const decision of [...fallbackDecisions, ...agentDecisions]) {
    if (decision.action === "downgrade" && !decision.severity) continue;
    decisionsById.set(decision.findingId, decision);
  }

  return {
    decisions: Array.from(decisionsById.values()),
    findings: findings
      .map((finding) => {
        const decision = decisionsById.get(finding.id);
        if (!decision || decision.action === "keep") return finding;
        if (decision.action === "drop") return undefined;
        return { ...finding, severity: decision.severity ?? finding.severity };
      })
      .filter((finding): finding is AuditFinding => Boolean(finding)),
  };
}

function findingId(...parts: string[]) {
  return parts.join(":").toLowerCase().replace(/[^a-z0-9:]+/g, "-");
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
    "",
    "## Summary",
    "",
    report.summary,
    "",
    "## Findings",
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("No findings detected by deterministic v1 rules.");
  }

  for (const finding of report.findings) {
    lines.push(
      `### ${finding.severity.toUpperCase()}: ${finding.title}`,
      "",
      `Rule: \`${finding.ruleId}\``,
      `Confidence: \`${finding.confidence}\``,
      `Memory assisted: \`${finding.memoryAssisted ? "yes" : "no"}\``,
      "",
      finding.description,
      "",
    );
    if (includeDetails) {
      lines.push("Evidence:", "");
      for (const evidence of finding.evidence) {
        const location = evidence.filePath
          ? ` (${evidence.filePath}${evidence.lineStart ? `:${evidence.lineStart}` : ""})`
          : "";
        lines.push(`- ${evidence.detail}${location}`);
      }
      if (finding.exploitPath?.length) {
        lines.push("", "Exploit path:", "");
        for (const [index, step] of finding.exploitPath.entries()) {
          lines.push(`${index + 1}. ${step}`);
        }
      }
      lines.push("", "Recommendation:", "", finding.recommendation, "");
      if (finding.patchSuggestion) {
        lines.push("Patch sketch:", "", finding.patchSuggestion, "");
      }
    }
  }

  return `${lines.join("\n")}\n`;
}
