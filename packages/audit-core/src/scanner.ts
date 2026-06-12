import type {
  NormalizedPackageSnapshot,
  SourceContext,
} from "@repo/shared";

import { runDeterministicAudit } from "./metadata-rules.js";
import type { ExploitMemory } from "./types.js";

export function runScannerAgent(
  snapshot: NormalizedPackageSnapshot,
  memories: ExploitMemory[] = [],
  sourceContext?: SourceContext,
) {
  return runDeterministicAudit(snapshot, memories, sourceContext);
}
