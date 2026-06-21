import type {
  AuditFinding,
  MemoryReference,
  NormalizedFunction,
} from "@repo/shared";

import type { ExploitMemory } from "./types.js";

export function isPublicEntry(fn: NormalizedFunction) {
  return fn.visibility === "public" && fn.isEntry;
}

export function hasPrivilegedName(name: string) {
  return /(admin|owner|config|upgrade|pause|unpause|set_|initialize|init|mint|burn|sweep)/.test(
    name,
  );
}

export function hasTransferLikeName(name: string) {
  return /(transfer|withdraw|claim|sweep|payout|settle|redeem)/.test(name);
}

export function hasCapabilityParam(fn: NormalizedFunction) {
  return fn.parameters.some((param) =>
    /(cap|admin|owner|authority|witness|treasurycap)/i.test(param.raw),
  );
}

export function matchMemories(
  memories: ExploitMemory[],
  query: string,
  ruleId?: string,
): MemoryReference[] {
  const queryTerms = normalizedTerms(query);
  if (queryTerms.length === 0) return [];
  const exactRuleMatches = ruleId
    ? memories.filter((memory) =>
        memoryMatchesRuleId(`${memory.query} ${memory.summary}`, ruleId),
      )
    : [];
  const candidates = exactRuleMatches.length > 0 ? exactRuleMatches : memories;

  return candidates
    .map((memory) => ({
      memory,
      score: scoreMemoryMatch(`${memory.query} ${memory.summary}`, queryTerms),
    }))
    .filter(({ score }) => score > 0)
    .sort((left, right) => right.score - left.score)
    .map(({ memory }) => memory)
    .map(({ id, summary }) => ({ id, summary }))
    .slice(0, 3);
}

function memoryMatchesRuleId(value: string, ruleId: string) {
  const normalizedRuleId = normalizeMemoryText(ruleId).trim();
  return normalizedRuleId.length > 0 && normalizeMemoryText(value).includes(normalizedRuleId);
}

function normalizedTerms(value: string) {
  return normalizeMemoryText(value)
    .split(/\s+/)
    .filter((term) => term.length > 2);
}

function scoreMemoryMatch(value: string, queryTerms: string[]) {
  const memoryText = normalizeMemoryText(value);
  const matchedTerms = queryTerms.filter((term) => memoryText.includes(term));
  if (matchedTerms.length === queryTerms.length) return matchedTerms.length;
  return matchedTerms.length >= Math.min(2, queryTerms.length) ? matchedTerms.length : 0;
}

function normalizeMemoryText(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ");
}

export function dedupeFindings(findings: AuditFinding[]) {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    if (seen.has(finding.id)) return false;
    seen.add(finding.id);
    return true;
  });
}

export function findingId(...parts: string[]) {
  return parts.join(":").toLowerCase().replace(/[^a-z0-9:]+/g, "-");
}
