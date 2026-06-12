import type {
  AuditFinding,
  AuditReport,
  AuditObservationMemory,
  FindingSeverity,
  MemoryReference,
  NormalizedPackageSnapshot,
  PackageSummary,
  SourceContext,
  VulnerabilityPatternMemory,
} from "@repo/shared";

export type ExploitMemory = MemoryReference & {
  query: string;
};

export type AuditEngineResult = {
  findings: AuditFinding[];
  memoryDiff: {
    learned: string[];
    observations?: AuditObservationMemory[];
    patterns?: VulnerabilityPatternMemory[];
    recalled: ExploitMemory[];
  };
  publicReportMarkdown: string;
  privateReportMarkdown: string;
  report: AuditReport;
};

export type ExploitMemoryAgent = {
  recall(snapshot: NormalizedPackageSnapshot): Promise<ExploitMemory[]> | ExploitMemory[];
  writeMemories?(
    memories: AuditMemoryWrite,
    snapshot: NormalizedPackageSnapshot,
  ): Promise<void> | void;
  writeLessons?(
    lessons: string[],
    snapshot: NormalizedPackageSnapshot,
  ): Promise<void> | void;
};

export type AuditMemoryWrite = {
  lessons: string[];
  observations: AuditObservationMemory[];
  patterns: VulnerabilityPatternMemory[];
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
