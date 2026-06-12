import type { SourceContext, SourceSummary } from "@repo/shared";

export function summarizeSourceContext(sourceContext: SourceContext): SourceSummary {
  return {
    branch: sourceContext.branch,
    digest: sourceContext.digest,
    fileCount: sourceContext.files.length,
    moveFileCount: sourceContext.moveFileCount,
    omittedMoveFileCount: sourceContext.omittedMoveFileCount,
    packageRoots: sourceContext.packageRoots,
    pathPrefix: sourceContext.pathPrefix,
    selectedRoot: sourceContext.selectedRoot,
    totalMoveFileCount: sourceContext.totalMoveFileCount,
    url: sourceContext.url,
  };
}
