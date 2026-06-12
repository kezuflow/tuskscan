import { pathToFileURL } from "node:url";

import { runAuditWorkflow, type ExploitMemory } from "@repo/audit-core";
import { DEFAULT_NETWORK, type AuditReportArtifacts, type Network } from "@repo/shared";
import {
  InMemoryExploitMemoryStore,
  InMemoryWalrusStore,
  recallExploitMemories,
  storeAuditArtifacts,
  writeAuditMemoryRecords,
  writeExploitLessons,
  type MemoryStore,
  type WalrusStore,
} from "@repo/storage";
import {
  fetchNormalizedPackage,
  hashSnapshot,
  summarizePackage,
} from "@repo/sui-integration";

export type PaidAuditJob = {
  attempts?: number;
  id: string;
  maxAttempts?: number;
  network: Network;
  packageId: string;
  snapshotHash: string;
  suiJobObjectId: string;
};

export type CompletedAuditJob = PaidAuditJob & {
  artifacts: Required<AuditReportArtifacts>;
  finalizedDigest: string;
  reportHash: string;
  riskScore: number;
  runLog: WorkerRunLogEntry[];
  status: "completed";
};

export type FailedAuditJob = PaidAuditJob & {
  error: string;
  runLog: WorkerRunLogEntry[];
  status: "dead-letter" | "failed";
};

export type WorkerRunLogEntry = {
  at: string;
  detail?: string;
  step: string;
  status: "ok" | "failed";
};

export type SuiReportFinalizer = {
  finalizeReport(input: {
    artifacts: Required<AuditReportArtifacts>;
    findingsHash: string;
    jobObjectId: string;
    packageSnapshotHash: string;
    reportHash: string;
    riskScore: number;
  }): Promise<{ digest: string }>;
};

export type WorkerDependencies = {
  fetchPackage?: typeof fetchNormalizedPackage;
  finalizer?: SuiReportFinalizer;
  memory?: MemoryStore;
  walrus?: WalrusStore;
};

export async function processPaidAuditJob(
  job: PaidAuditJob,
  dependencies: WorkerDependencies = {},
): Promise<CompletedAuditJob | FailedAuditJob> {
  const runLog: WorkerRunLogEntry[] = [];
  const attempts = (job.attempts ?? 0) + 1;
  const maxAttempts = job.maxAttempts ?? 3;
  const walrus = dependencies.walrus ?? new InMemoryWalrusStore();
  const memory = dependencies.memory ?? new InMemoryExploitMemoryStore();
  const fetchPackage = dependencies.fetchPackage ?? fetchNormalizedPackage;
  const finalizer = dependencies.finalizer;

  try {
    log(runLog, "fetch-package", "ok");
    const snapshot = await fetchPackage({
      network: job.network,
      packageId: job.packageId,
    });
    const actualSnapshotHash = await hashSnapshot(snapshot);
    if (actualSnapshotHash !== job.snapshotHash) {
      throw new Error("Fetched package snapshot hash does not match prepared hash.");
    }

    log(runLog, "run-audit-workflow", "ok");
    const audit = await runAuditWorkflow({
      memoryAgent: {
        recall: async () => {
          const recalled = await recallExploitMemories({
            context: `${job.packageId} admin capability shared object mutation withdraw transfer`,
            store: memory,
          });
          return recalled.map((item): ExploitMemory => ({
            ...item,
            query: item.summary,
          }));
        },
        writeLessons: async (lessons) => {
          await writeExploitLessons({
            lessons,
            metadata: { packageId: job.packageId },
            store: memory,
          });
        },
        writeMemories: async (memories) => {
          await writeAuditMemoryRecords({
            observations: memories.observations,
            patterns: memories.patterns,
            store: memory,
          });
        },
      },
      packageSummary: summarizePackage(snapshot),
      snapshot,
    });

    log(runLog, "store-walrus-artifacts", "ok");
    const stored = await storeAuditArtifacts({
      contents: {
        auditRunLog: runLog,
        findings: audit.findings,
        memoryDiff: audit.memoryDiff,
        packageSnapshot: snapshot,
        privateReportMarkdown: audit.privateReportMarkdown,
        publicReportMarkdown: audit.publicReportMarkdown,
        sourceContext: { source: "none" },
      },
      store: walrus,
    });

    log(runLog, "finalize-sui-report", "ok");
    if (!finalizer) {
      throw new Error("A real Sui report finalizer is required.");
    }
    const finalized = await finalizer.finalizeReport({
      artifacts: stored.artifacts,
      findingsHash: stored.artifacts.findings.contentHash,
      jobObjectId: job.suiJobObjectId,
      packageSnapshotHash: stored.artifacts.packageSnapshot.contentHash,
      reportHash: stored.artifacts.privateReport.contentHash,
      riskScore: audit.report.riskScore,
    });

    return {
      ...job,
      attempts,
      artifacts: stored.artifacts,
      finalizedDigest: finalized.digest,
      reportHash: stored.artifacts.privateReport.contentHash,
      riskScore: audit.report.riskScore,
      runLog,
      status: "completed",
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected worker error.";
    log(runLog, "worker-error", "failed", message);
    return {
      ...job,
      attempts,
      error: message,
      runLog,
      status: attempts >= maxAttempts ? "dead-letter" : "failed",
    };
  }
}

function log(
  runLog: WorkerRunLogEntry[],
  step: string,
  status: WorkerRunLogEntry["status"],
  detail?: string,
) {
  runLog.push({ at: new Date().toISOString(), detail, status, step });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const packageId = process.env.TUSKSCAN_DEMO_PACKAGE_ID;
  const snapshotHash = process.env.TUSKSCAN_DEMO_SNAPSHOT_HASH;
  const suiJobObjectId = process.env.TUSKSCAN_DEMO_JOB_OBJECT_ID ?? "0x1";

  if (!packageId || !snapshotHash) {
    console.log(
      "TuskScan worker ready. Set TUSKSCAN_DEMO_PACKAGE_ID and TUSKSCAN_DEMO_SNAPSHOT_HASH to process one paid job.",
    );
  } else {
    const result = await processPaidAuditJob({
      id: "demo",
      network: parseNetwork(process.env.SUI_NETWORK),
      packageId,
      snapshotHash,
      suiJobObjectId,
    });
    console.log(JSON.stringify(result, null, 2));
  }
}

function parseNetwork(value: string | undefined): Network {
  return value === "testnet" || value === "mainnet" ? value : DEFAULT_NETWORK;
}
