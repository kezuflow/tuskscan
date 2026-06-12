import type { AuditFinding } from "@repo/shared";

import type {
  AuditCriticAgent,
  CriticDecision,
  FindingAgentInput,
} from "./types.js";

const DETERMINISTIC_CRITIC_REASON =
  "Kept because the finding is backed by deterministic normalized Move metadata.";

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
