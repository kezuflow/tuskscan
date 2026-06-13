import type {
  ArtifactPointer,
  AuditObservationMemory,
  AuditReportArtifacts,
  Network,
  MemoryReference,
  VulnerabilityPatternMemory,
} from "@repo/shared";
import { sha256Hex, stableJson } from "@repo/sui-integration";
import { MemWal } from "@mysten-incubation/memwal";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import {
  RetryableWalrusClientError,
  WalrusClient,
  type WalrusClientConfig,
} from "@mysten/walrus";

export type ArtifactInput = {
  content: string;
  contentType: string;
  name: string;
};

export type WalrusStore = {
  readArtifact(blobId: string): Promise<string | undefined>;
  writeArtifact(input: ArtifactInput): Promise<ArtifactPointer>;
};

export type WalrusHttpStoreOptions = {
  aggregatorUrl: string;
  publisherUrl: string;
};

export type WalrusSdkStoreOptions = {
  deletable?: boolean;
  epochs?: number;
  key: string;
  network: Extract<Network, "mainnet" | "testnet">;
  rpcUrl: string;
};

type WalrusStoreResponse = {
  newlyCreated?: { blobObject?: { blobId?: string }; blobId?: string };
  alreadyCertified?: { blobId?: string };
  blobId?: string;
};

export class HttpWalrusStore implements WalrusStore {
  constructor(private readonly options: WalrusHttpStoreOptions) {}

  async readArtifact(blobId: string) {
    const response = await fetch(
      `${this.options.aggregatorUrl.replace(/\/$/, "")}/v1/blobs/${blobId}`,
    );
    if (response.status === 404) return undefined;
    if (!response.ok) {
      throw new Error(`Walrus aggregator returned HTTP ${response.status}.`);
    }
    return response.text();
  }

  async writeArtifact(input: ArtifactInput): Promise<ArtifactPointer> {
    const contentHash = await sha256Hex(input.content);
    const response = await fetch(
      `${this.options.publisherUrl.replace(/\/$/, "")}/v1/blobs`,
      {
        body: input.content,
        headers: { "content-type": input.contentType },
        method: "PUT",
      },
    );
    if (!response.ok) {
      throw new Error(`Walrus publisher returned HTTP ${response.status}.`);
    }

    const payload = (await response.json()) as WalrusStoreResponse;
    const blobId =
      payload.blobId ??
      payload.newlyCreated?.blobId ??
      payload.newlyCreated?.blobObject?.blobId ??
      payload.alreadyCertified?.blobId;

    if (!blobId) {
      throw new Error("Walrus publisher response did not include a blob ID.");
    }

    return {
      blobId,
      contentHash,
      contentType: input.contentType,
      name: input.name,
    };
  }
}

export class SdkWalrusStore implements WalrusStore {
  private readonly client: WalrusClient;
  private readonly deletable: boolean;
  private readonly epochs: number;
  private readonly signer: Ed25519Keypair;

  constructor(options: WalrusSdkStoreOptions) {
    const suiClient = new SuiGrpcClient({
      baseUrl: options.rpcUrl,
      network: options.network,
    });
    this.client = new WalrusClient({
      network: options.network,
      storageNodeClientOptions: {
        timeout: 60_000,
      },
      suiClient,
    } satisfies WalrusClientConfig);
    this.deletable = options.deletable ?? false;
    this.epochs = options.epochs ?? 3;
    this.signer = Ed25519Keypair.fromSecretKey(options.key);
  }

  async readArtifact(blobId: string) {
    const bytes = await this.readBlobWithRetry(blobId);
    return new TextDecoder().decode(bytes);
  }

  async writeArtifact(input: ArtifactInput): Promise<ArtifactPointer> {
    const contentHash = await sha256Hex(input.content);
    const blob = new TextEncoder().encode(input.content);
    const { blobId } = await this.writeBlobWithRetry(blob);
    return {
      blobId,
      contentHash,
      contentType: input.contentType,
      name: input.name,
    };
  }

  private async writeBlobWithRetry(blob: Uint8Array) {
    try {
      return await this.client.writeBlob({
        blob,
        deletable: this.deletable,
        epochs: this.epochs,
        signer: this.signer,
      });
    } catch (error) {
      if (!(error instanceof RetryableWalrusClientError)) throw error;
      this.client.reset();
      return this.client.writeBlob({
        blob,
        deletable: this.deletable,
        epochs: this.epochs,
        signer: this.signer,
      });
    }
  }

  private async readBlobWithRetry(blobId: string) {
    try {
      return await this.client.readBlob({ blobId });
    } catch (error) {
      if (!(error instanceof RetryableWalrusClientError)) throw error;
      this.client.reset();
      return this.client.readBlob({ blobId });
    }
  }
}

export class InMemoryWalrusStore implements WalrusStore {
  private readonly blobs = new Map<string, string>();

  async readArtifact(blobId: string) {
    return this.blobs.get(blobId);
  }

  async writeArtifact(input: ArtifactInput): Promise<ArtifactPointer> {
    const contentHash = await sha256Hex(input.content);
    const blobId = `local-walrus-${contentHash.slice(2, 18)}-${slug(input.name)}`;
    this.blobs.set(blobId, input.content);
    return {
      blobId,
      contentHash,
      contentType: input.contentType,
      name: input.name,
    };
  }
}

export type AuditArtifactContents = {
  auditRunLog: unknown;
  findings: unknown;
  memoryDiff: unknown;
  packageSnapshot: unknown;
  privateReportMarkdown: string;
  publicReportMarkdown: string;
  sourceContext: unknown;
};

export type ArtifactVerification = {
  actualHash?: string;
  expectedHash: string;
  ok: boolean;
};

export async function storeAuditArtifacts(options: {
  contents: AuditArtifactContents;
  store: WalrusStore;
}): Promise<{
  artifacts: Required<AuditReportArtifacts>;
  verification: Record<keyof Required<AuditReportArtifacts>, ArtifactVerification>;
}> {
  const inputs = {
    auditRunLog: jsonArtifact("audit-run-log.json", options.contents.auditRunLog),
    findings: jsonArtifact("findings.json", options.contents.findings),
    memoryDiff: jsonArtifact("memory-diff.json", options.contents.memoryDiff),
    packageSnapshot: jsonArtifact(
      "package-snapshot.json",
      options.contents.packageSnapshot,
    ),
    privateReport: {
      content: options.contents.privateReportMarkdown,
      contentType: "text/markdown",
      name: "private-report.md",
    },
    publicReport: {
      content: options.contents.publicReportMarkdown,
      contentType: "text/markdown",
      name: "public-report.md",
    },
    sourceContext: jsonArtifact("source-context.json", options.contents.sourceContext),
  } satisfies Record<keyof Required<AuditReportArtifacts>, ArtifactInput>;

  const artifactEntries: Array<
    readonly [
      keyof Required<AuditReportArtifacts>,
      ArtifactPointer,
      ArtifactVerification & { expectedHash: string },
    ]
  > = [];
  for (const [name, input] of Object.entries(inputs) as Array<
    [keyof Required<AuditReportArtifacts>, ArtifactInput]
  >) {
    const pointer = await options.store.writeArtifact(input);
    const verification = await verifyArtifact({
      blobId: pointer.blobId,
      expectedHash: pointer.contentHash,
      store: options.store,
    });
    artifactEntries.push([
      name,
      pointer,
      { expectedHash: pointer.contentHash, ...verification },
    ] as const);
  }

  return {
    artifacts: Object.fromEntries(
      artifactEntries.map(([name, pointer]) => [name, pointer]),
    ) as Required<AuditReportArtifacts>,
    verification: Object.fromEntries(
      artifactEntries.map(([name, , verification]) => [name, verification]),
    ) as Record<keyof Required<AuditReportArtifacts>, ArtifactVerification>,
  };
}

export type MemoryInput = {
  content: string;
  metadata?: Record<string, string>;
};

export type MemoryStore = {
  recall(query: string, limit?: number): Promise<MemoryReference[]>;
  remember(input: MemoryInput): Promise<MemoryReference>;
};

export class InMemoryExploitMemoryStore implements MemoryStore {
  private readonly memories: MemoryReference[] = [];

  async recall(query: string, limit = 5) {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    return this.memories
      .map((memory) => ({
        memory,
        score: terms.filter((term) => memory.summary.toLowerCase().includes(term))
          .length,
      }))
      .filter(({ score }) => score > 0)
      .sort((left, right) => right.score - left.score)
      .map(({ memory }) => memory)
      .slice(0, limit);
  }

  async remember(input: MemoryInput) {
    const id = `memory-${(await sha256Hex(stableJson(input))).slice(2, 14)}`;
    const memory = { id, summary: input.content };
    if (!this.memories.some((existing) => existing.id === id)) {
      this.memories.push(memory);
    }
    return memory;
  }
}

export type MemWalMemoryStoreOptions = {
  accountId: string;
  key: string;
  namespace?: string;
  serverUrl?: string;
  waitForRemember?: boolean;
};

export class MemWalMemoryStore implements MemoryStore {
  private readonly client: MemWal;
  private readonly namespace?: string;
  private readonly waitForRemember: boolean;

  constructor(options: MemWalMemoryStoreOptions) {
    this.client = MemWal.create({
      accountId: options.accountId,
      key: options.key,
      namespace: options.namespace,
      serverUrl: options.serverUrl,
    });
    this.namespace = options.namespace;
    this.waitForRemember = options.waitForRemember ?? false;
  }

  async recall(query: string, limit = 5): Promise<MemoryReference[]> {
    const result = await this.client.recall({
      limit,
      namespace: this.namespace,
      query,
    });

    return result.results.map((memory) => ({
      id: memory.blob_id,
      summary: memory.text,
    }));
  }

  async remember(input: MemoryInput): Promise<MemoryReference> {
    const accepted = await this.client.remember(input.content, this.namespace);
    if (this.waitForRemember) {
      const result = await this.client.waitForRememberJob(accepted.job_id);
      return {
        id: result.blob_id,
        summary: input.content,
      };
    }

    return {
      id: accepted.job_id,
      summary: input.content,
    };
  }
}

export async function recallExploitMemories(options: {
  context: string;
  limit?: number;
  store: MemoryStore;
}) {
  return options.store.recall(options.context, options.limit);
}

export async function writeExploitLessons(options: {
  lessons: string[];
  metadata?: Record<string, string>;
  store: MemoryStore;
}) {
  return Promise.all(
    options.lessons.map((lesson) =>
      options.store.remember({ content: lesson, metadata: options.metadata }),
    ),
  );
}

export async function writeAuditMemoryRecords(options: {
  observations: AuditObservationMemory[];
  patterns: VulnerabilityPatternMemory[];
  store: MemoryStore;
}) {
  const records = [
    ...options.patterns.map((pattern) => ({
      content: stableJson(pattern),
      metadata: {
        category: pattern.category,
        kind: pattern.kind,
        patternId: pattern.id,
        ruleId: pattern.ruleId,
        severity: pattern.severity,
      },
    })),
    ...options.observations.map((observation) => ({
      content: stableJson(observation),
      metadata: {
        findingId: observation.findingId,
        kind: observation.kind,
        packageId: observation.packageId,
        patternId: observation.patternId,
        severity: observation.severity,
      },
    })),
  ];

  return Promise.all(records.map((record) => options.store.remember(record)));
}

export async function verifyArtifact(options: {
  blobId: string;
  expectedHash: string;
  store: WalrusStore;
}) {
  const content = await options.store.readArtifact(options.blobId);
  if (content === undefined) {
    return { actualHash: undefined, ok: false };
  }
  const actualHash = await sha256Hex(content);
  return {
    actualHash,
    ok: actualHash === options.expectedHash,
  };
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

function jsonArtifact(name: string, value: unknown): ArtifactInput {
  return {
    content: stableJson(value),
    contentType: "application/json",
    name,
  };
}
