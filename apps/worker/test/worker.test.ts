import assert from "node:assert/strict";
import test from "node:test";

import type { NormalizedPackageSnapshot } from "@repo/shared";
import { hashSnapshot } from "@repo/sui-integration";

import { processPaidAuditJob } from "../src/index.ts";

const snapshot: NormalizedPackageSnapshot = {
  fetchedAt: "2026-06-12T00:00:00.000Z",
  modules: [
    {
      functions: [
        {
          isEntry: true,
          name: "admin_sweep",
          parameters: [
            {
              isMutableReference: true,
              isSharedObjectLike: true,
              raw: "&mut Treasury",
            },
          ],
          returns: [],
          visibility: "public",
        },
      ],
      name: "vault",
      structs: [
        {
          abilities: ["key", "store"],
          fields: [{ name: "id", type: "UID" }],
          name: "Treasury",
        },
      ],
    },
  ],
  network: "testnet",
  packageDigest: "fixture-digest",
  packageId: "0x1234",
  source: "sui-normalized-modules",
};

test("processes paid audit job through artifacts and Sui finalizer", async () => {
  const result = await processPaidAuditJob(
    {
      id: "job-1",
      network: "testnet",
      packageId: snapshot.packageId,
      snapshotHash: await hashSnapshot(snapshot),
      suiJobObjectId: "0xbeef",
    },
    {
      fetchPackage: async () => snapshot,
      finalizer: {
        finalizeReport: async () => ({ digest: "tx-finalized" }),
      },
    },
  );

  assert.equal(result.status, "completed");
  assert.equal(result.finalizedDigest, "tx-finalized");
  assert.equal(result.artifacts.publicReport.name, "public-report.md");
});

test("snapshot mismatch fails first and dead-letters after max attempts", async () => {
  const result = await processPaidAuditJob(
    {
      attempts: 2,
      id: "job-2",
      maxAttempts: 3,
      network: "testnet",
      packageId: snapshot.packageId,
      snapshotHash: "0xwrong",
      suiJobObjectId: "0xbeef",
    },
    {
      fetchPackage: async () => snapshot,
    },
  );

  assert.equal(result.status, "dead-letter");
  assert.match(result.error, /snapshot hash/);
});
