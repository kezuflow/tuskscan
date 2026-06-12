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

export function matchMemories(memories: ExploitMemory[], query: string): MemoryReference[] {
  return memories
    .filter((memory) =>
      `${memory.query} ${memory.summary}`.toLowerCase().includes(query.toLowerCase()),
    )
    .map(({ id, summary }) => ({ id, summary }))
    .slice(0, 3);
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
