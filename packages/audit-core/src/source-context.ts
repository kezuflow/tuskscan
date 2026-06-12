import type { SourceContext, SourceSummary } from "@repo/shared";

export function summarizeSourceContext(sourceContext: SourceContext): SourceSummary {
  return {
    digest: sourceContext.digest,
    fileCount: sourceContext.files.length,
    moveFileCount: sourceContext.moveFileCount,
    url: sourceContext.url,
  };
}
