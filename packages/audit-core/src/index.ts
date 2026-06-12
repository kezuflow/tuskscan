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
            category: "Access control",
            description:
              "A public entry function has an admin-like name. Review whether it is gated by an explicit capability object or trusted admin parameter.",
            evidence: [evidence],
            impact:
              "An exposed admin path can let any caller mutate protocol configuration, pause/unpause flows, mint, burn, or sweep assets if authorization is missing in source.",
            fn,
            memoryReferences: matchMemories(memories, "admin capability"),
            moduleName: module.name,
            recommendation:
              "Require a dedicated AdminCap/OwnerCap parameter and assert ownership before executing privileged state changes.",
            remediationSteps: [
              "Require a capability object for this entry point.",
              "Assert the capability owner or expected admin address before mutation.",
              "Add a negative Move test for an unauthorized caller.",
            ],
            ruleId: "MOVE_PUBLIC_ADMIN_ENTRY",
            severity: "high",
            testSuggestions: [
              "Call the entry function from a non-admin test account and assert it aborts.",
            ],
            title: "Public admin-like entry function",
          }),
        );
      }

      if (isPublicEntry(fn) && hasPrivilegedName(lowered) && !hasCapabilityParam(fn)) {
        findings.push(
          createFinding({
            category: "Access control",
            description:
              "A privileged-looking entry point does not expose an obvious capability/admin parameter in the normalized signature.",
            evidence: [evidence],
            impact:
              "If the source body also lacks sender or ownership checks, this can become a direct privileged action for arbitrary callers.",
            fn,
            memoryReferences: matchMemories(memories, "missing capability"),
            moduleName: module.name,
            recommendation:
              "Add a capability parameter such as AdminCap or enforce an explicit signer/object ownership check.",
            remediationSteps: [
              "Add an AdminCap/OwnerCap parameter or equivalent ownership proof.",
              "Check the caller with tx_context::sender(ctx) before state change.",
              "Document the expected privileged caller model.",
            ],
            ruleId: "MOVE_MISSING_CAPABILITY_PARAM",
            severity: "critical",
            testSuggestions: [
              "Prove unauthorized callers cannot execute the function.",
              "Prove the authorized owner/capability path still succeeds.",
            ],
            title: "Privileged function may lack capability gate",
          }),
        );
      }

      if (isPublicEntry(fn) && fn.parameters.some((param) => param.isMutableReference)) {
        findings.push(
          createFinding({
            category: "Shared object mutation",
            description:
              "A public entry function accepts mutable references. This is often correct, but privileged shared-object mutation should be reviewed carefully.",
            evidence: [evidence],
            impact:
              "Mutable public entry points are the primary Sui attack surface for shared-object state corruption, unauthorized accounting changes, or invariant bypasses.",
            fn,
            memoryReferences: matchMemories(memories, "shared object mutation"),
            moduleName: module.name,
            recommendation:
              "Confirm the mutable object path is gated by ownership, capability checks, or invariant-preserving assertions.",
            remediationSteps: [
              "Identify each mutable object accepted by the function.",
              "Bind mutation rights to owner/capability/derived key checks.",
              "Add invariant tests around the object before and after mutation.",
            ],
            ruleId: "MOVE_PUBLIC_MUTABLE_ENTRY",
            severity: hasPrivilegedName(lowered) ? "high" : "medium",
            testSuggestions: [
              "Use a second wallet in tests to attempt mutation of another user's object.",
            ],
            title: "Public mutable entry surface",
          }),
        );
      }

      if (isPublicEntry(fn) && hasTransferLikeName(lowered)) {
        findings.push(
          createFinding({
            category: "Value movement",
            description:
              "A public entry function appears to transfer, withdraw, sweep, or claim value. Value-moving paths deserve explicit authorization review.",
            evidence: [evidence],
            impact:
              "Value-moving public entry points can drain funds, duplicate claims, or redirect payouts when authorization and replay protections are incomplete.",
            fn,
            memoryReferences: matchMemories(memories, "withdraw transfer claim"),
            moduleName: module.name,
            recommendation:
              "Check sender authority, recipient restrictions, balance accounting, and replay/claim guards.",
            remediationSteps: [
              "Require authorization before value leaves protocol custody.",
              "Bind recipients to the caller or a verified entitlement.",
              "Persist a receipt/nonce for one-time claims.",
            ],
            ruleId: "MOVE_VALUE_MOVING_ENTRY",
            severity: "medium",
            testSuggestions: [
              "Attempt repeated claims and unauthorized withdrawals in Move unit tests.",
            ],
            title: "Public value-moving entry function",
          }),
        );
      }
    }

    for (const struct of module.structs) {
      if (struct.abilities.includes("key") && struct.abilities.includes("store")) {
        findings.push({
          confidence: "medium",
          category: "Object lifecycle",
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
          impact:
            "Persistent key+store objects often define custody, ownership, or protocol state; unsafe lifecycle functions can strand, duplicate, or transfer critical assets.",
          likelihood: "medium",
          memoryAssisted: false,
          memoryReferences: [],
          recommendation:
            "Trace object lifecycle functions and ensure ownership/capability checks protect privileged transitions.",
          remediationSteps: [
            "Map create, mutate, transfer, freeze, and delete paths for this object.",
            "Verify each lifecycle transition has an owner/capability guard.",
          ],
          ruleId: "MOVE_KEY_STORE_OBJECT",
          severity: "info",
          testSuggestions: [
            "Add lifecycle tests that cover create, transfer, mutation, and deletion paths.",
          ],
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
    sourceContext: options.sourceContext,
    sourceSummary: options.sourceContext
      ? summarizeSourceContext(options.sourceContext)
      : undefined,
    snapshot: options.snapshot,
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

function createFinding(options: {
  category?: string;
  description: string;
  evidence: AuditFinding["evidence"];
  fn: NormalizedFunction;
  impact?: string;
  likelihood?: AuditFinding["likelihood"];
  memoryReferences: MemoryReference[];
  moduleName: string;
  recommendation: string;
  remediationSteps?: string[];
  ruleId: string;
  severity: FindingSeverity;
  testSuggestions?: string[];
  title: string;
}): AuditFinding {
  return {
    category: options.category,
    confidence:
      options.severity === "critical" || options.severity === "high"
        ? "high"
        : "medium",
    description: options.description,
    evidence: options.evidence,
    id: findingId(options.ruleId, options.moduleName, options.fn.name),
    impact: options.impact,
    likelihood: options.likelihood ?? "medium",
    memoryAssisted: options.memoryReferences.length > 0,
    memoryReferences: options.memoryReferences,
    recommendation: options.recommendation,
    remediationSteps: options.remediationSteps,
    ruleId: options.ruleId,
    severity: options.severity,
    testSuggestions: options.testSuggestions,
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
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The target function is callable as a public entry function.",
              "The attacker can obtain or influence the mutable/value-carrying input object.",
            ],
            category: "Value movement",
            confidence: "high",
            description:
              "Source analysis found a public entry value/object transfer path without an obvious capability, sender, or ownership authorization guard in the function body.",
            evidence,
            exploitPath: [
              "Attacker calls the public entry function directly.",
              "Attacker supplies or targets the mutable/value-carrying object accepted by the function.",
              "Function reaches a transfer/withdraw path before an obvious authorization guard is enforced.",
            ],
            impact:
              "Assets or owned objects may be transferred out of protocol custody by an unauthorized caller.",
            likelihood: "high",
            memories,
            memoryQuery: "withdraw transfer claim",
            patchSuggestion:
              "Require an AdminCap/OwnerCap or assert tx_context::sender(ctx) owns the affected object before executing the transfer.",
            recommendation:
              "Add an explicit authority check before value/object transfer and add a Move test proving unauthorized callers abort.",
            remediationSteps: [
              "Identify the authority expected to move this value.",
              "Assert that tx_context::sender(ctx), an owner field, or a capability authorizes the movement.",
              "Abort before any balance/object transfer when authorization fails.",
            ],
            ruleId: "SRC_PUBLIC_TRANSFER_WITHOUT_AUTH",
            severity: "critical",
            testSuggestions: [
              "A non-owner wallet calls the entry function and must abort.",
              "The owner/capability holder calls the entry function and succeeds.",
            ],
            title: "Public transfer path may lack authorization",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /transfer::public_transfer|transfer::transfer|coin::take|balance::withdraw/i.test(
          fn.body,
        ) &&
        /\b(recipient|receiver|to|dst|destination)\s*:\s*address/i.test(fn.signature) &&
        !hasSenderRecipientBinding(fn.body)
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The function accepts a caller-controlled recipient address.",
              "The function transfers a coin/object before binding the recipient to an entitlement.",
            ],
            category: "Value redirection",
            confidence: "medium",
            description:
              "A public value-moving function appears to accept an arbitrary recipient address without binding that recipient to tx_context::sender(ctx), ownership, or a claimed entitlement.",
            evidence,
            exploitPath: [
              "Attacker calls the public entry function with their own recipient address.",
              "The function performs transfer/withdraw logic using the supplied recipient.",
              "If entitlement checks are missing elsewhere, payout can be redirected.",
            ],
            impact:
              "Rewards, withdrawals, or transferred objects may be redirected to a caller-chosen address.",
            likelihood: "medium",
            memories,
            memoryQuery: "recipient withdraw transfer",
            patchSuggestion:
              "Derive the recipient from tx_context::sender(ctx) or from a verified onchain entitlement instead of trusting a free address parameter.",
            recommendation:
              "Bind recipient selection to sender authority or entitlement state before moving value.",
            remediationSteps: [
              "Replace arbitrary recipient parameters with tx_context::sender(ctx) when appropriate.",
              "If third-party payout is required, verify a signed/onchain entitlement for that recipient.",
            ],
            ruleId: "SRC_ARBITRARY_RECIPIENT_TRANSFER",
            severity: "high",
            testSuggestions: [
              "Attempt to claim or withdraw to an unrelated wallet and assert it aborts.",
            ],
            title: "Caller-controlled recipient on value transfer path",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /dynamic_field|dynamic_object_field|table::|object_table::/i.test(fn.body) &&
        /add|remove|borrow_mut|insert/i.test(loweredBody) &&
        !hasAuthSignal &&
        !hasCapParam
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The attacker can call the public entry function.",
              "The attacker can influence a dynamic storage key, object, or table mutation input.",
            ],
            category: "State integrity",
            confidence: "medium",
            description:
              "Source analysis found public mutation of dynamic storage without an obvious authority guard. Dynamic field/table paths often control claims, ownership registries, or accounting state.",
            evidence,
            exploitPath: [
              "Attacker calls the public entry function with chosen key/object inputs.",
              "Function mutates dynamic storage through add/remove/borrow_mut/insert.",
              "Without a guard, attacker may overwrite, replay, or remove state tied to another actor.",
            ],
            impact:
              "A caller may corrupt claim records, ownership registries, accounting state, or other dynamic storage namespaces.",
            likelihood: "medium",
            memories,
            memoryQuery: "shared object mutation",
            patchSuggestion:
              "Bind dynamic storage keys to tx_context::sender(ctx), object ownership, or a capability-controlled namespace.",
            recommendation:
              "Review dynamic storage key derivation and add tests for unauthorized key insertion, removal, and replay.",
            remediationSteps: [
              "Document the namespace owner for each dynamic key.",
              "Assert caller ownership/capability before add/remove/borrow_mut/insert.",
              "Abort when a key is already used or belongs to another wallet/object.",
            ],
            ruleId: "SRC_DYNAMIC_STORAGE_MUTATION",
            severity: "high",
            testSuggestions: [
              "Second wallet attempts to insert/remove another user's dynamic key and must abort.",
            ],
            title: "Dynamic storage mutation needs authority review",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /(claim|reward|redeem|withdraw|airdrop)/.test(loweredName) &&
        !/(claimed|receipt|nonce|used|has_claimed|contains|exists)/i.test(fn.body)
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The target function dispenses value or entitlement.",
              "The caller can repeat the same call or vary recipient-controlled inputs.",
            ],
            category: "Replay protection",
            confidence: "medium",
            description:
              "A public claim/reward-style function does not show an obvious replay guard such as a receipt, nonce, claimed set, or contains/exists check.",
            evidence,
            exploitPath: [
              "Attacker calls the claim/reward function once.",
              "Attacker repeats the same call or changes only recipient-controlled inputs.",
              "Without a durable replay marker, rewards or withdrawals may be claimed multiple times.",
            ],
            impact:
              "One-time rewards, withdrawals, or allocations may be drained repeatedly.",
            likelihood: "medium",
            memories,
            memoryQuery: "claim replay",
            patchSuggestion:
              "Store a claimed marker keyed by wallet/object/nonce before transferring value, and assert it does not already exist.",
            recommendation:
              "Add a negative Move test proving the second claim attempt aborts.",
            remediationSteps: [
              "Write a replay marker before or atomically with the value transfer.",
              "Key the marker by wallet/object/nonce depending on entitlement semantics.",
              "Abort when the marker already exists.",
            ],
            ruleId: "SRC_CLAIM_REPLAY_REVIEW",
            severity: "high",
            testSuggestions: [
              "Call the claim path twice with the same entitlement and assert the second call aborts.",
            ],
            title: "Claim path may need replay protection",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /(init|initialize|setup|create_config|configure)/.test(loweredName) &&
        /object::new|table::new|dynamic_field::add|config|admin/i.test(fn.body) &&
        !/(exists|is_one_time_witness|one_time_witness|initialized|already|has_key|contains)/i.test(
          fn.body,
        ) &&
        !hasCapParam
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The initializer is callable after deployment.",
              "The function creates or mutates global/config-like state.",
            ],
            category: "Initialization",
            confidence: "medium",
            description:
              "A public initializer/configuration path does not show an obvious one-time witness, initialized flag, exists check, or admin capability guard.",
            evidence,
            exploitPath: [
              "Attacker calls the initializer after deployment.",
              "Initializer creates or overwrites config/admin-like state.",
              "Protocol authority or core configuration may be reset to attacker-controlled values.",
            ],
            impact:
              "Protocol config or admin authority may be reinitialized after deployment.",
            likelihood: "medium",
            memories,
            memoryQuery: "initialize admin config",
            patchSuggestion:
              "Gate initialization with a one-time witness or an explicit initialized/exists check that aborts after first setup.",
            recommendation:
              "Make initializer one-time and add reinitialization tests.",
            remediationSteps: [
              "Require a one-time witness for package initialization where possible.",
              "Persist an initialized marker and abort on subsequent calls.",
              "Avoid accepting arbitrary admin/config values after deployment setup.",
            ],
            ruleId: "SRC_REINITIALIZATION_RISK",
            severity: "high",
            testSuggestions: [
              "Call the initializer twice and assert the second call aborts.",
            ],
            title: "Initializer may be callable more than once",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /coin::mint|balance::increase_supply|supply::increase|treasurycap/i.test(fn.body) &&
        !hasAuthSignal &&
        !hasCapParam
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The mint/supply path is exposed as a public entry function.",
              "The function can reach TreasuryCap or supply-increase logic without a guard.",
            ],
            category: "Token supply",
            confidence: "high",
            description:
              "A public entry function appears to reach minting or supply-increase logic without an obvious capability or sender/owner authorization guard.",
            evidence,
            exploitPath: [
              "Attacker calls the mint/supply function directly.",
              "Function reaches mint or supply-increase code.",
              "Attacker mints or increases supply beyond intended policy.",
            ],
            impact:
              "Token supply can be inflated or treasury-controlled assets can be created by unauthorized callers.",
            likelihood: "high",
            memories,
            memoryQuery: "mint treasurycap supply",
            patchSuggestion:
              "Require TreasuryCap/AdminCap ownership and assert the caller is authorized before any mint/supply operation.",
            recommendation:
              "Treat all TreasuryCap and supply operations as critical privileged code.",
            remediationSteps: [
              "Store TreasuryCap under capability-controlled custody.",
              "Require the capability in every mint/supply path.",
              "Add max-supply or policy assertions where applicable.",
            ],
            ruleId: "SRC_TREASURY_CAP_EXPOSURE",
            severity: "critical",
            testSuggestions: [
              "A non-admin wallet attempts minting and must abort.",
              "Supply cannot exceed configured limits.",
            ],
            title: "Mint or TreasuryCap path may be exposed",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /object::delete|id\.delete|delete\(/i.test(fn.body) &&
        !hasAuthSignal &&
        !hasCapParam
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The attacker can call a public object deletion path.",
              "The attacker can supply or reference the object being deleted.",
            ],
            category: "Object lifecycle",
            confidence: "medium",
            description:
              "A public entry function appears to delete an object without an obvious owner/capability authorization guard.",
            evidence,
            exploitPath: [
              "Attacker calls the deletion function with a target object.",
              "Function reaches object delete logic.",
              "Important state or custody records may be destroyed.",
            ],
            impact:
              "Protocol state, receipts, or ownership records may be deleted by unauthorized callers.",
            likelihood: "medium",
            memories,
            memoryQuery: "object delete ownership",
            patchSuggestion:
              "Assert tx_context::sender(ctx) owns the object or require a destroy-specific capability before deletion.",
            recommendation:
              "Protect object destruction paths as privileged lifecycle transitions.",
            remediationSteps: [
              "Require owner/capability authorization before object deletion.",
              "Emit an event or write an audit trail for critical deletions.",
            ],
            ruleId: "SRC_OBJECT_DELETE_WITHOUT_AUTH",
            severity: "high",
            testSuggestions: [
              "Second wallet attempts to delete another user's object and must abort.",
            ],
            title: "Object deletion path may lack authorization",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /(random|lottery|raffle|winner|roll|draw|select)/.test(loweredName) &&
        /(clock::timestamp|epoch|tx_context::digest|ctx\.epoch|%)/i.test(fn.body)
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "Outcome selection uses predictable public chain data.",
              "A caller can influence timing, inputs, or repeated attempts.",
            ],
            category: "Randomness",
            confidence: "medium",
            description:
              "A public randomness-like function appears to use predictable timestamp, epoch, digest, or modulo logic as entropy.",
            evidence,
            exploitPath: [
              "Attacker observes or predicts public entropy inputs.",
              "Attacker times or repeats calls until the outcome is favorable.",
              "Function selects a winner/reward based on predictable data.",
            ],
            impact:
              "Lottery, reward, or selection outcomes may be biased by callers.",
            likelihood: "medium",
            memories,
            memoryQuery: "predictable randomness lottery",
            patchSuggestion:
              "Use a verifiable randomness source or commit-reveal flow instead of timestamp/epoch/modulo-derived entropy.",
            recommendation:
              "Replace predictable entropy with a bias-resistant randomness design.",
            remediationSteps: [
              "Separate commitment and reveal phases if no randomness primitive is available.",
              "Prevent callers from choosing entropy after observing state.",
            ],
            ruleId: "SRC_PREDICTABLE_RANDOMNESS",
            severity: "medium",
            testSuggestions: [
              "Show that repeated calls cannot bias winner selection.",
            ],
            title: "Predictable randomness source",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /(vector::borrow|vector::remove|vector::swap_remove|\[[^\]]+\])/i.test(fn.body) &&
        !/(vector::length|\.length\(|is_empty|assert!\s*\([^)]*(len|length|is_empty))/i.test(
          fn.body,
        )
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The caller can influence an index or collection size.",
              "The function borrows/removes vector elements without a nearby bound check.",
            ],
            category: "Input validation",
            confidence: "medium",
            description:
              "A public entry function performs vector indexing/removal without an obvious length or emptiness check.",
            evidence,
            exploitPath: [
              "Attacker supplies an out-of-range index or an empty collection state.",
              "Function borrows/removes an element without checking length.",
              "Transaction aborts, potentially causing denial of service or blocking expected execution paths.",
            ],
            impact:
              "Caller-controlled aborts may create denial-of-service conditions or griefing vectors around shared-object workflows.",
            likelihood: "medium",
            memories,
            memoryQuery: "vector bounds abort",
            patchSuggestion:
              "Assert index < vector::length(&items) and handle empty vectors before borrow/remove/swap_remove.",
            recommendation:
              "Add explicit bounds checks and tests for empty/out-of-range inputs.",
            remediationSteps: [
              "Validate index and collection length before vector access.",
              "Return/abort with a documented error code for invalid inputs.",
            ],
            ruleId: "SRC_UNCHECKED_VECTOR_ACCESS",
            severity: "medium",
            testSuggestions: [
              "Call with an empty vector or out-of-range index and assert a controlled abort code.",
            ],
            title: "Unchecked vector access in public entry path",
          }),
        );
      }
    }

    const todo = findSourceMarker(file, /(TODO|FIXME|HACK|SECURITY|AUDIT)/);
    if (todo) {
      findings.push({
        category: "Review marker",
        confidence: "low",
        description:
          "Source contains an audit-relevant marker. This may be harmless, but unresolved security notes should not ship without review.",
        evidence: [todo],
        id: sourceFindingId("SRC_SECURITY_MARKER", file.path, String(todo.lineStart)),
        impact:
          "Security-relevant TODO/FIXME markers can indicate intentionally deferred review around authorization, accounting, or lifecycle behavior.",
        likelihood: "low",
        memoryAssisted: false,
        memoryReferences: [],
        recommendation:
          "Resolve or document the marker before deployment, especially if it touches authorization, accounting, or object lifecycle code.",
        remediationSteps: [
          "Resolve the marker or link it to a reviewed issue.",
          "Add tests if the marker references security-sensitive behavior.",
        ],
        ruleId: "SRC_SECURITY_MARKER",
        severity: "low",
        testSuggestions: [
          "Add a regression test for the behavior described by the marker.",
        ],
        title: "Source contains security review marker",
      });
    }
  }

  return dedupeFindings(findings);
}

function createSourceFinding(options: {
  attackPrerequisites: string[];
  category: string;
  confidence: AuditFinding["confidence"];
  description: string;
  evidence: AuditFinding["evidence"][number];
  exploitPath: string[];
  impact: string;
  likelihood: AuditFinding["likelihood"];
  memories: ExploitMemory[];
  memoryQuery: string;
  patchSuggestion: string;
  recommendation: string;
  remediationSteps: string[];
  ruleId: string;
  severity: FindingSeverity;
  testSuggestions: string[];
  title: string;
}): AuditFinding {
  const memoryReferences = matchMemories(options.memories, options.memoryQuery);
  return {
    attackPrerequisites: options.attackPrerequisites,
    category: options.category,
    confidence: options.confidence,
    description: options.description,
    evidence: [options.evidence],
    exploitPath: options.exploitPath,
    id: sourceFindingId(
      options.ruleId,
      options.evidence.filePath ?? options.evidence.moduleName,
      options.evidence.functionName ?? options.title,
    ),
    impact: options.impact,
    likelihood: options.likelihood,
    memoryAssisted: memoryReferences.length > 0,
    memoryReferences,
    patchSuggestion: options.patchSuggestion,
    recommendation: options.recommendation,
    remediationSteps: options.remediationSteps,
    ruleId: options.ruleId,
    severity: options.severity,
    testSuggestions: options.testSuggestions,
    title: options.title,
  };
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
    const match = line.match(
      /\b((?:(?:public(?:\([^)]+\))?|entry|native)\s+)*)fun\s+([A-Za-z_][A-Za-z0-9_]*)/,
    );
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
          isPublicEntry: /\bpublic\b/.test(match[1] ?? "") && /\bentry\b/.test(match[1] ?? ""),
          name: match[2] ?? "unknown",
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

function hasSenderRecipientBinding(body: string) {
  return /(recipient|receiver|to|dst|destination)\s*==\s*(sender|tx_context::sender|ctx\.sender)|assert!\s*\([^)]*(recipient|receiver|to|dst|destination)[^)]*(sender|tx_context::sender|ctx\.sender)|owner|beneficiary|entitlement|allowlist|whitelist/i.test(
    body,
  );
}

function sourceEvidence(
  file: SourceFile,
  fn: { body: string; endLine: number; name: string; startLine: number },
) {
  return {
    codeSnippet: sourceSnippet(file, fn.startLine, fn.endLine),
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
    codeSnippet: sourceSnippet(file, index + 1, index + 1),
    detail: `${file.path}:${index + 1} contains "${lines[index]?.trim()}".`,
    filePath: file.path,
    lineStart: index + 1,
    moduleName: moduleNameFromPath(file.path),
  };
}

function sourceSnippet(file: SourceFile, startLine: number, endLine: number) {
  const lines = file.content.split(/\r?\n/);
  const start = Math.max(1, startLine - 2);
  const end = Math.min(lines.length, endLine + 2);
  return lines
    .slice(start - 1, end)
    .map((line, index) => `${String(start + index).padStart(4, " ")} | ${line}`)
    .join("\n");
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
