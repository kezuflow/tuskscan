import type { NormalizedPackageSnapshot, PackageSummary, SourceContext } from "@repo/shared";

import { runCriticAgent } from "./critic.js";
import { runFixAgent } from "./fix.js";
import { extractMemoryLessons } from "./memory.js";
import { createAuditReport } from "./report.js";
import { runScannerAgent } from "./scanner.js";
import { summarizeSourceContext } from "./source-context.js";
import type {
  AuditCriticAgent,
  AuditFindingAgent,
  AuditWorkflowResult,
  ExploitMemoryAgent,
  FindingAgentInput,
} from "./types.js";
import { dedupeFindings } from "./utils.js";

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
    criticDecisions: criticResult.decisions,
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
