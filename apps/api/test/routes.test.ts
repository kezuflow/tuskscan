import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import test from "node:test";

import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import type { NormalizedPackageSnapshot, SourceContext } from "@repo/shared";
import { InMemoryExploitMemoryStore, InMemoryWalrusStore } from "@repo/storage";

import { InMemoryAuditJobStore, createTuskscanApiServer } from "../src/index.ts";

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

test("prepare resolves a repository URL with published package metadata", async () => {
  const { baseUrl, close } = await startTestServer({
    sourceContext: {
      branch: "main",
      digest: "source-digest",
      fetchedAt: "2026-06-12T00:00:00.000Z",
      files: [],
      moveFileCount: 1,
      packageRoots: ["move/demo-package-a"],
      pathPrefix: "move/demo-package-a",
      publishedPackageId: "0x5678",
      selectedRoot: "move/demo-package-a",
      source: "github",
      totalMoveFileCount: 1,
      url: "https://github.com/example/repo/tree/main/move/demo-package-a",
    },
  });
  try {
    const response = await postJson(`${baseUrl}/api/audits/prepare`, {
      sourceUrl: "https://github.com/example/repo/tree/main/move/demo-package-a",
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.match(body.packageSummary.packageId, /^github:example\/repo\/move\/demo-package-a@main#/);
    assert.equal(body.sourceSummary.publishedPackageId, "0x5678");
  } finally {
    await close();
  }
});

test("prepare accepts repository URLs without published package metadata", async () => {
  const { baseUrl, close } = await startTestServer({
    sourceContext: {
      branch: "main",
      digest: "0xabcdef1234567890",
      fetchedAt: "2026-06-12T00:00:00.000Z",
      files: [
        {
          content: "module demo::vault { public entry fun withdraw_all(treasury: &mut Treasury) {} struct Treasury has key, store { id: UID } }",
          path: "move/demo-package-a/sources/vault.move",
          sizeBytes: 118,
        },
      ],
      moveFileCount: 1,
      packageRoots: ["move/demo-package-a"],
      pathPrefix: "move/demo-package-a",
      selectedRoot: "move/demo-package-a",
      source: "github",
      totalMoveFileCount: 1,
      url: "https://github.com/example/repo/tree/main/move/demo-package-a",
    },
  });
  try {
    const response = await postJson(`${baseUrl}/api/audits/prepare`, {
      sourceUrl: "https://github.com/example/repo/tree/main/move/demo-package-a",
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.match(body.packageSummary.packageId, /^github:example\/repo\/move\/demo-package-a@main#/);
    assert.equal(body.packageSummary.moduleCount, 1);
    assert.equal(body.sourceSummary.publishedPackageId, undefined);
  } finally {
    await close();
  }
});

test("prepare rejects unsupported source URLs", async () => {
  const { baseUrl, close } = await startTestServer();
  try {
    const response = await postJson(`${baseUrl}/api/audits/prepare`, {
      packageId: "0x1234",
      sourceUrl: "https://gitlab.com/example/repo",
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.match(body.error, /GitHub repository URL/);
  } finally {
    await close();
  }
});

test("audit lifecycle creates, reads, reports, and verifies artifacts", async () => {
  const keypair = Ed25519Keypair.generate();
  const payer = keypair.toSuiAddress();
  const { baseUrl, close } = await startTestServer();
  try {
    const prepare = await postJson(`${baseUrl}/api/audits/prepare`, {
      packageId: "0x1234",
    });
    const prepared = await prepare.json();
    assert.equal(prepare.status, 200);
    assert.equal(prepared.packageSummary.moduleCount, 1);

    const create = await postJson(`${baseUrl}/api/audits`, {
      packageId: "0x1234",
      payer,
      suiJobObjectId: "0xbeef",
      suiTransactionDigest: "verified-digest",
    });
    const created = await create.json();
    assert.equal(create.status, 202);
    assert.equal(created.status, "completed");

    const audit = await (await fetch(`${baseUrl}/api/audits/${created.auditId}`)).json();
    assert.equal(audit.report, undefined);
    assert.equal(audit.publicReport.findingCount > 0, true);

    const publicReport = await (
      await fetch(`${baseUrl}/api/audits/${created.auditId}/report`)
    ).json();
    assert.equal(publicReport.private, false);
    assert.equal(publicReport.report.findings.length <= 3, true);

    const challenge = await (
      await postJson(`${baseUrl}/api/auth/challenge`, { address: payer })
    ).json();
    const signed = await keypair.signPersonalMessage(
      new TextEncoder().encode(challenge.message),
    );
    const session = await (
      await postJson(`${baseUrl}/api/auth/session`, {
        address: payer,
        message: challenge.message,
        signature: signed.signature,
      })
    ).json();
    const privateReport = await (
      await fetch(`${baseUrl}/api/audits/${created.auditId}/report`, {
        headers: { authorization: `Bearer ${session.token}` },
      })
    ).json();
    assert.equal(privateReport.private, true);

    const walletAudits = await (
      await fetch(`${baseUrl}/api/audits?wallet=${payer}`, {
        headers: { authorization: `Bearer ${session.token}` },
      })
    ).json();
    assert.equal(walletAudits.audits.length, 1);
    assert.equal(walletAudits.audits[0].id, created.auditId);

    const verification = await (
      await postJson(`${baseUrl}/api/audits/${created.auditId}/verify`, {})
    ).json();
    assert.equal(
      Object.values(verification.verification).every(
        (result) => (result as { ok: boolean }).ok,
      ),
      true,
    );
  } finally {
    await close();
  }
});

test("audit job claims are exclusive per worker", async () => {
  const store = new InMemoryAuditJobStore();
  await store.save({
    createdAt: "2026-06-12T00:00:00.000Z",
    id: "audit-claim",
    network: "testnet",
    packageId: "0x1234",
    packageSummary: {
      fetchedAt: "2026-06-12T00:00:00.000Z",
      functionCount: 1,
      moduleCount: 1,
      network: "testnet",
      packageDigest: "fixture-digest",
      packageId: "0x1234",
      structCount: 1,
    },
    payer: "0x8",
    snapshotHash: "snapshot-hash",
    status: "queued",
    suiJobObjectId: "0xbeef",
    suiTransactionDigest: "verified-digest",
  });

  const first = await store.claimJob("audit-claim", "worker-a", 60_000);
  const second = await store.claimJob("audit-claim", "worker-b", 60_000);

  assert.equal(first?.lockedBy, "worker-a");
  assert.equal(second, undefined);
});

test("expired audit job locks can be reclaimed", async () => {
  const store = new InMemoryAuditJobStore();
  await store.save({
    createdAt: "2026-06-12T00:00:00.000Z",
    id: "audit-reclaim",
    lockExpiresAt: "2020-01-01T00:00:00.000Z",
    lockedBy: "worker-a",
    network: "testnet",
    packageId: "0x1234",
    packageSummary: {
      fetchedAt: "2026-06-12T00:00:00.000Z",
      functionCount: 1,
      moduleCount: 1,
      network: "testnet",
      packageDigest: "fixture-digest",
      packageId: "0x1234",
      structCount: 1,
    },
    payer: "0x8",
    snapshotHash: "snapshot-hash",
    status: "running",
    suiJobObjectId: "0xbeef",
    suiTransactionDigest: "verified-digest",
  });

  const claimed = await store.claimJob("audit-reclaim", "worker-b", 60_000);

  assert.equal(claimed?.lockedBy, "worker-b");
});

async function startTestServer(options: { sourceContext?: SourceContext } = {}) {
  const server = createTuskscanApiServer({
    config: {
      environment: "localhost",
      network: "testnet",
      priceMist: "1000000",
      tuskscanPackageId:
        "0x0000000000000000000000000000000000000000000000000000000000000009",
    },
    auditStore: new InMemoryAuditJobStore(),
    fetchPackage: async ({ network, packageId }) => ({
      ...fixtureSnapshot,
      network,
      packageId,
    }),
    fetchSourceContext: async (sourceUrl) =>
      sourceUrl && options.sourceContext
        ? { ...options.sourceContext, url: sourceUrl }
        : undefined,
    finalizer: async () => ({
      digest: "finalize-digest",
      reportObjectId: "0xcafe",
    }),
    memory: new InMemoryExploitMemoryStore(),
    paymentVerifier: async (input) => {
      if (input.digest !== "verified-digest") {
        throw new Error("unverified payment");
      }
    },
    processJobsInline: true,
    walrus: new InMemoryWalrusStore(),
  });
  server.listen(0);
  await once(server, "listening");
  const address = server.address();
  assert.equal(typeof address, "object");
  assert.notEqual(address, null);

  return {
    baseUrl: `http://127.0.0.1:${address?.port}`,
    close: () => closeServer(server),
  };
}

async function closeServer(server: Server) {
  server.close();
  await once(server, "close");
}

function postJson(url: string, body: unknown) {
  return fetch(url, {
    body: JSON.stringify(body),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
}
