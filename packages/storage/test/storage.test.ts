import assert from "node:assert/strict";
import test from "node:test";

import {
  InMemoryExploitMemoryStore,
  InMemoryWalrusStore,
  recallExploitMemories,
  storeAuditArtifacts,
  verifyArtifact,
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
