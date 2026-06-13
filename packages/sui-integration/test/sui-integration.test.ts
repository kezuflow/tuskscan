import assert from "node:assert/strict";
import test from "node:test";

import type { NormalizedPackageSnapshot } from "@repo/shared";

import {
  fetchNormalizedPackage,
  hashSnapshot,
  isValidSuiObjectId,
  normalizeSuiObjectId,
  SuiAuditVerificationError,
  stableJson,
  summarizePackage,
  verifyAuditJobPayment,
} from "../src/index.ts";

const fixtureSnapshot: NormalizedPackageSnapshot = {
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
      structs: [{ abilities: ["key", "store"], fields: [], name: "Treasury" }],
    },
  ],
  network: "testnet",
  packageDigest: "fixture",
  packageId: "0x1",
  source: "sui-normalized-modules",
};

test("validates and normalizes Sui object IDs", () => {
  assert.equal(isValidSuiObjectId("0x2"), true);
  assert.equal(isValidSuiObjectId("https://github.com/example/repo"), false);
  assert.equal(
    normalizeSuiObjectId("0x2"),
    "0x0000000000000000000000000000000000000000000000000000000000000002",
  );
});

test("stable JSON and snapshot hash are deterministic", async () => {
  const left = { b: 2, a: { d: 4, c: 3 } };
  const right = { a: { c: 3, d: 4 }, b: 2 };

  assert.equal(stableJson(left), stableJson(right));
  assert.equal(await hashSnapshot(fixtureSnapshot), await hashSnapshot(fixtureSnapshot));
  assert.equal(
    await hashSnapshot({
      ...fixtureSnapshot,
      fetchedAt: "2026-06-13T00:00:00.000Z",
    }),
    await hashSnapshot(fixtureSnapshot),
  );
});

test("summarizes normalized package fixtures", () => {
  const summary = summarizePackage(fixtureSnapshot);

  assert.equal(summary.moduleCount, 1);
  assert.equal(summary.functionCount, 1);
  assert.equal(summary.structCount, 1);
});

test("verifies paid audit jobs against Sui transaction and object data", async () => {
  const restoreFetch = mockSuiPaymentRpc({ operatorWasPaid: true });
  try {
    await verifyAuditJobPayment({
      contractPackageId: "0x7",
      digest: "payment-digest",
      jobObjectId: "0xbeef",
      network: "testnet",
      operatorAddress: "0x9",
      packageDigest: "snapshot-hash",
      packageId: "github:example/repo/move/package#0xabc",
      payer: "0x8",
      priceMist: "1000000",
      rpcUrl: "http://127.0.0.1:1",
    });
  } finally {
    restoreFetch();
  }
});

test("rejects paid audit jobs that did not credit the configured operator", async () => {
  const restoreFetch = mockSuiPaymentRpc({ operatorWasPaid: false });
  try {
    await assert.rejects(
      () =>
        verifyAuditJobPayment({
          contractPackageId: "0x7",
          digest: "payment-digest",
          jobObjectId: "0xbeef",
          network: "testnet",
          operatorAddress: "0x9",
          packageDigest: "snapshot-hash",
          packageId: "github:example/repo/move/package#0xabc",
          payer: "0x8",
          priceMist: "1000000",
          rpcUrl: "http://127.0.0.1:1",
        }),
      SuiAuditVerificationError,
    );
  } finally {
    restoreFetch();
  }
});

test("optionally fetches a known Sui testnet package", async (context) => {
  if (!process.env.TUSKSCAN_RUN_NETWORK_TESTS) {
    context.skip("Set TUSKSCAN_RUN_NETWORK_TESTS=1 to hit Sui testnet.");
    return;
  }

  const snapshot = await fetchNormalizedPackage({
    network: "testnet",
    packageId: "0x2",
  });

  assert.equal(snapshot.network, "testnet");
  assert.equal(snapshot.modules.length > 0, true);
});

function mockSuiPaymentRpc(options: { operatorWasPaid: boolean }) {
  const previousFetch = globalThis.fetch;
  const contractPackageId = normalizeSuiObjectId("0x7");
  const jobObjectId = normalizeSuiObjectId("0xbeef");
  const operatorAddress = normalizeSuiObjectId("0x9");
  const packageId = "github:example/repo/move/package#0xabc";
  const payer = normalizeSuiObjectId("0x8");

  globalThis.fetch = (async (_url, init) => {
    const request = JSON.parse(String(init?.body)) as { method: string };
    if (request.method === "sui_getTransactionBlock") {
      return jsonResponse({
        balanceChanges: options.operatorWasPaid
          ? [
              {
                amount: "1000000",
                coinType: "0x2::sui::SUI",
                owner: { AddressOwner: operatorAddress },
              },
            ]
          : [],
        effects: { status: { status: "success" } },
        objectChanges: [
          {
            objectId: jobObjectId,
            objectType: `${contractPackageId}::audit::AuditJob`,
            type: "created",
          },
        ],
        transaction: { data: { sender: payer } },
      });
    }
    if (request.method === "sui_getObject") {
      return jsonResponse({
        data: {
          content: {
            fields: {
              package_digest: "snapshot-hash",
              package_id: packageId,
              price_paid: "1000000",
              status: 1,
            },
            type: `${contractPackageId}::audit::AuditJob`,
          },
          objectId: jobObjectId,
          owner: { AddressOwner: payer },
        },
      });
    }
    throw new Error(`Unexpected RPC method: ${request.method}`);
  }) as typeof fetch;

  return () => {
    globalThis.fetch = previousFetch;
  };
}

function jsonResponse(result: unknown) {
  return {
    json: async () => ({ result }),
    ok: true,
  } as Response;
}
