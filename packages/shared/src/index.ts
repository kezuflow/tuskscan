export type Network = "testnet" | "mainnet";

export type AuditStatus =
  | "prepared"
  | "paid"
  | "queued"
  | "running"
  | "completed"
  | "failed";

export type FindingSeverity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type FindingConfidence = "low" | "medium" | "high";

export type Visibility = "public_summary_private_details" | "public" | "private";

export type PackageSummary = {
  fetchedAt: string;
  functionCount: number;
  moduleCount: number;
  network: Network;
  packageDigest: string;
  packageId: string;
  structCount: number;
};

export type NormalizedParameter = {
  isMutableReference: boolean;
  isSharedObjectLike: boolean;
  raw: string;
};

export type NormalizedFunction = {
  isEntry: boolean;
  name: string;
  parameters: NormalizedParameter[];
  returns: string[];
  visibility: "private" | "public" | "friend";
};

export type NormalizedStruct = {
  abilities: string[];
  fields: Array<{ name: string; type: string }>;
  name: string;
};

export type NormalizedModule = {
  functions: NormalizedFunction[];
  name: string;
  structs: NormalizedStruct[];
};

export type NormalizedPackageSnapshot = {
  fetchedAt: string;
  modules: NormalizedModule[];
  network: Network;
  packageDigest: string;
  packageId: string;
  source: "github-move-source" | "sui-normalized-modules";
};

export type SourceFile = {
  content: string;
  path: string;
  sizeBytes: number;
};

export type SourceContext = {
  branch?: string;
  digest: string;
  fetchedAt: string;
  files: SourceFile[];
  moveFileCount: number;
  omittedMoveFileCount?: number;
  packageRoots?: string[];
  pathPrefix?: string;
  publishedPackageId?: string;
  resolvedRef?: string;
  selectedRoot?: string;
  source: "github";
  totalMoveFileCount?: number;
  url: string;
};

export type SourceSummary = {
  branch?: string;
  digest: string;
  fileCount: number;
  moveFileCount: number;
  omittedMoveFileCount?: number;
  packageRoots?: string[];
  pathPrefix?: string;
  publishedPackageId?: string;
  resolvedRef?: string;
  selectedRoot?: string;
  totalMoveFileCount?: number;
  url: string;
};

export type FindingEvidence = {
  codeSnippet?: string;
  detail: string;
  filePath?: string;
  functionName?: string;
  lineEnd?: number;
  lineStart?: number;
  moduleName: string;
  structName?: string;
};

export type MemoryReference = {
  id: string;
  summary: string;
};

export type AuditFinding = {
  attackPrerequisites?: string[];
  calibratedConfidence?: FindingConfidence;
  category?: string;
  confidence: FindingConfidence;
  description: string;
  evidence: FindingEvidence[];
  exploitPath?: string[];
  id: string;
  impact?: string;
  likelihood?: FindingConfidence;
  memoryAssisted: boolean;
  memoryPlaybookIds?: string[];
  memoryReferences: MemoryReference[];
  patchSuggestion?: string;
  recommendation: string;
  remediationSteps?: string[];
  ruleId: string;
  severity: FindingSeverity;
  testSuggestions?: string[];
  title: string;
};

export type ExploitTestDraft = {
  command: string;
  findingId: string;
  kind: "move_unit_test_draft";
  name: string;
  notes: string[];
  source?: string;
  status:
    | "draft_needs_project_binding"
    | "executed_compile_only"
    | "execution_failed"
    | "skipped";
  target?: {
    filePath?: string;
    functionName?: string;
    moduleName: string;
  };
};

export type SandboxCommandResult = {
  command: string;
  durationMs: number;
  exitCode: number | null;
  stderrTail?: string;
  stdoutTail?: string;
};

export type SandboxTestRun = {
  baseline?: SandboxCommandResult;
  generated?: SandboxCommandResult;
  generatedTestFile?: string;
  note: string;
  packagePath?: string;
  status:
    | "disabled"
    | "source_unavailable"
    | "sui_cli_missing"
    | "baseline_failed"
    | "generated_failed"
    | "completed";
  testsAttempted: number;
};

export type AgentReview = {
  agent: "scanner" | "researcher" | "exploit_writer" | "patch_reviewer" | "false_positive_critic";
  findingsReviewed: number;
  output: string[];
  status: "completed" | "not_configured";
};

export type SourceConsistency = {
  deployedModules: string[];
  level: "not_provided" | "module_name_match" | "module_name_mismatch";
  matchedModules: string[];
  missingInSource: string[];
  note: string;
  sourceModules: string[];
};

export type MemoryPlaybook = {
  findingId: string;
  id: string;
  query: string;
  summary: string;
};

export type VulnerabilityPatternMemory = {
  category: string;
  chain: "sui";
  exampleEvidence?: {
    filePath?: string;
    functionName?: string;
    moduleName: string;
    severity: FindingSeverity;
  };
  exploitModel: string[];
  falsePositiveChecks: string[];
  fixPattern: string[];
  id: string;
  kind: "vulnerability_pattern";
  language: "move";
  pattern: string;
  ruleId: string;
  severity: FindingSeverity;
  signals: string[];
  updatedAt: string;
};

export type AuditObservationMemory = {
  chain: "sui";
  confirmed: boolean;
  findingId: string;
  kind: "audit_observation";
  language: "move";
  observedAt: string;
  packageId: string;
  patternId: string;
  severity: FindingSeverity;
  sourceModules: string[];
};

export type AuditReportArtifacts = {
  auditRunLog?: ArtifactPointer;
  findings?: ArtifactPointer;
  memoryDiff?: ArtifactPointer;
  packageSnapshot?: ArtifactPointer;
  privateReport?: ArtifactPointer;
  publicReport?: ArtifactPointer;
  sourceContext?: ArtifactPointer;
};

export type ArtifactPointer = {
  blobId: string;
  contentHash: string;
  contentType: string;
  name: string;
  storageBlobId?: string;
};

export type AuditReport = {
  actionPlan?: string[];
  agentReviews?: AgentReview[];
  artifacts: AuditReportArtifacts;
  calibration?: {
    memoryMatchedFindings: number;
    memoryRecordsLearned?: number;
    memoriesRecalled?: number;
    note: string;
  };
  coverage?: {
    checkedModules: number;
    checkedMoveFiles: number;
    checkedPublicEntryFunctions: number;
    checkedSourceFunctions: number;
  };
  createdAt: string;
  disclaimer: string;
  findings: AuditFinding[];
  generatedExploitTests?: ExploitTestDraft[];
  memoryPlaybooks?: MemoryPlaybook[];
  packageSummary: PackageSummary;
  riskScore: number;
  severityBreakdown?: Record<FindingSeverity, number>;
  sourceConsistency?: SourceConsistency;
  sourceSummary?: SourceSummary;
  sandboxTestRun?: SandboxTestRun;
  status: AuditStatus;
  summary: string;
  topRisks?: string[];
  visibility: Visibility;
};

export const AI_PRE_AUDIT_DISCLAIMER =
  "TuskScan is AI pre-audit assistance for developer review. It is not a professional security audit and must not be treated as a deployment approval.";

export const DEFAULT_NETWORK: Network = "mainnet";
