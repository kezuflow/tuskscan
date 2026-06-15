import assert from "node:assert/strict";
import test from "node:test";

import {
  InMemoryExploitMemoryStore,
  InMemoryWalrusStore,
  recallExploitMemories,
  storeAuditArtifacts,
  verifyArtifact,
  writeAuditMemoryRecords,
  writeExploitLessons,
} from "../src/index.ts";

test("stores and verifies all audit artifacts idempotently", async () => {
  const store = new InMemoryWalrusStore();
  const contents = {
    auditRunLog: [{ step: "scan", status: "ok" }],
    findings: [{ ruleId: "MOVE_MISSING_CAPABILITY_PARAM" }],
    memoryDiff: { learned: ["lesson"], recalled: [] },
    packageSnapshot: { packageId: "0x1" },
    privateReportMarkdown: "# Private\n",
    publicReportMarkdown: "# Public\n",
    sourceContext: { source: "none" },
  };

  const first = await storeAuditArtifacts({ contents, store });
  const second = await storeAuditArtifacts({ contents, store });

  assert.deepEqual(first.artifacts, second.artifacts);
  assert.equal(first.artifacts.sourceContext.name, "source-context.json");
  assert.equal(
    Object.values(first.verification).every((result) => result.ok),
    true,
  );

  const publicReportVerification = await verifyArtifact({
    blobId: first.artifacts.publicReport.blobId,
    expectedHash: first.artifacts.publicReport.contentHash,
    store,
  });

  assert.equal(publicReportVerification.ok, true);
});

test("stores independent audit artifacts through a single batch writer when available", async () => {
  class BatchedWalrusStore extends InMemoryWalrusStore {
    batchCalls = 0;
    singleCalls = 0;

    async writeArtifact(input: Parameters<InMemoryWalrusStore["writeArtifact"]>[0]) {
      this.singleCalls += 1;
      await new Promise((resolve) => setTimeout(resolve, 50));
      return super.writeArtifact(input);
    }

    async writeArtifacts(inputs: Record<string, Parameters<InMemoryWalrusStore["writeArtifact"]>[0]>) {
      this.batchCalls += 1;
      await new Promise((resolve) => setTimeout(resolve, 50));
      const entries = await Promise.all(
        Object.entries(inputs).map(async ([name, input]) => [
          name,
          { ...(await super.writeArtifact(input)), storageBlobId: "quilt-root-blob" },
        ] as const),
      );
      return Object.fromEntries(entries);
    }
  }

  const store = new BatchedWalrusStore();
  const startedAt = Date.now();

  const result = await storeAuditArtifacts({
    contents: {
      auditRunLog: [{ step: "scan", status: "ok" }],
      findings: [{ ruleId: "MOVE_MISSING_CAPABILITY_PARAM" }],
      memoryDiff: { learned: ["lesson"], recalled: [] },
      packageSnapshot: { packageId: "0x1" },
      privateReportMarkdown: "# Private\n",
      publicReportMarkdown: "# Public\n",
      sourceContext: { source: "none" },
    },
    store,
  });

  assert.equal(Date.now() - startedAt < 250, true);
  assert.equal(store.batchCalls, 1);
  assert.equal(store.singleCalls, 0);
  assert.equal(result.artifacts.publicReport.storageBlobId, "quilt-root-blob");
});

test("recalls and writes exploit memories through the memory store interface", async () => {
  const store = new InMemoryExploitMemoryStore();

  const written = await writeExploitLessons({
    lessons: ["MOVE_MISSING_CAPABILITY_PARAM: admin sweep missing AdminCap"],
    metadata: { packageId: "0x1" },
    store,
  });
  const recalled = await recallExploitMemories({
    context: "admin capability",
    store,
  });

  assert.equal(written.length, 1);
  assert.equal(recalled[0]?.id, written[0]?.id);
});

test("writes reusable vulnerability patterns and audit observations", async () => {
  const store = new InMemoryExploitMemoryStore();

  const written = await writeAuditMemoryRecords({
    observations: [
      {
        chain: "sui",
        confirmed: false,
        findingId: "finding-1",
        kind: "audit_observation",
        language: "move",
        observedAt: "2026-06-13T00:00:00.000Z",
        packageId: "0x1",
        patternId: "pattern:sui:move:move_missing_capability_param",
        severity: "critical",
        sourceModules: ["vault"],
      },
    ],
    patterns: [
      {
        category: "access_control",
        chain: "sui",
        exploitModel: ["Attacker calls public entry directly."],
        falsePositiveChecks: ["Check helper authorization."],
        fixPattern: ["Require AdminCap."],
        id: "pattern:sui:move:move_missing_capability_param",
        kind: "vulnerability_pattern",
        language: "move",
        pattern: "Public entry mutates privileged state without capability.",
        ruleId: "MOVE_MISSING_CAPABILITY_PARAM",
        severity: "critical",
        signals: ["public entry", "no capability"],
        updatedAt: "2026-06-13T00:00:00.000Z",
      },
    ],
    store,
  });
  const recalled = await recallExploitMemories({
    context: "vulnerability_pattern missing capability",
    store,
  });

  assert.equal(written.length, 2);
  assert.equal(
    recalled.some((memory) => memory.summary.includes("\"kind\":\"vulnerability_pattern\"")),
    true,
  );
});
