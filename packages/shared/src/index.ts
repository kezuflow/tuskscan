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
  source: "sui-normalized-modules";
};

export type SourceFile = {
  content: string;
  path: string;
  sizeBytes: number;
};

export type SourceContext = {
  digest: string;
  fetchedAt: string;
  files: SourceFile[];
  moveFileCount: number;
  source: "github";
  url: string;
};

export type SourceSummary = {
  digest: string;
  fileCount: number;
  moveFileCount: number;
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
  category?: string;
  confidence: FindingConfidence;
  description: string;
  evidence: FindingEvidence[];
  exploitPath?: string[];
  id: string;
  impact?: string;
  likelihood?: FindingConfidence;
  memoryAssisted: boolean;
  memoryReferences: MemoryReference[];
  patchSuggestion?: string;
  recommendation: string;
  remediationSteps?: string[];
  ruleId: string;
  severity: FindingSeverity;
  testSuggestions?: string[];
  title: string;
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
};

export type AuditReport = {
  actionPlan?: string[];
  artifacts: AuditReportArtifacts;
  coverage?: {
    checkedModules: number;
    checkedMoveFiles: number;
    checkedPublicEntryFunctions: number;
    checkedSourceFunctions: number;
  };
  createdAt: string;
  disclaimer: string;
  findings: AuditFinding[];
  packageSummary: PackageSummary;
  riskScore: number;
  severityBreakdown?: Record<FindingSeverity, number>;
  sourceSummary?: SourceSummary;
  status: AuditStatus;
  summary: string;
  topRisks?: string[];
  visibility: Visibility;
};

export const AI_PRE_AUDIT_DISCLAIMER =
  "TuskScan is AI pre-audit assistance for developer review. It is not a professional security audit and must not be treated as a deployment approval.";

export const DEFAULT_NETWORK: Network = "mainnet";
