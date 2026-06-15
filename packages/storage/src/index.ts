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
  WalrusFile,
  type WalrusClientConfig,
} from "@mysten/walrus";

export type ArtifactInput = {
  content: string;
  contentType: string;
  name: string;
};

export type WalrusStore = {
  readArtifact(blobId: string): Promise<string | undefined>;
  writeArtifacts?(inputs: Record<string, ArtifactInput>): Promise<Record<string, ArtifactPointer>>;
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
  writeTimeoutMs?: number;
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
  private readonly writeTimeoutMs: number;

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
    this.writeTimeoutMs = options.writeTimeoutMs ?? 120_000;
  }

  async readArtifact(blobId: string) {
    const file = await this.readFileWithRetry(blobId);
    if (file) return file.text();
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

  async writeArtifacts(inputs: Record<string, ArtifactInput>) {
    const entries = Object.entries(inputs);
    const contentHashes = await Promise.all(
      entries.map(([, input]) => sha256Hex(input.content)),
    );
    const files = entries.map(([artifact, input]) =>
      WalrusFile.from({
        contents: new TextEncoder().encode(input.content),
        identifier: input.name,
        tags: {
          "content-type": input.contentType,
          "tuskscan-artifact": artifact,
        },
      }),
    );

    const refs = await this.writeFilesWithRetry(files);
    return Object.fromEntries(
      refs.map((ref, index) => {
        const [, input] = entries[index]!;
        return [
          entries[index]![0],
          {
            blobId: ref.id,
            contentHash: contentHashes[index]!,
            contentType: input.contentType,
            name: input.name,
            storageBlobId: ref.blobId,
          },
        ];
      }),
    );
  }

  private async writeBlobWithRetry(blob: Uint8Array) {
    try {
      return await this.withWriteTimeout(this.writeBlob(blob));
    } catch (error) {
      if (!(error instanceof RetryableWalrusClientError)) throw error;
      this.client.reset();
      return this.withWriteTimeout(this.writeBlob(blob));
    }
  }

  private writeBlob(blob: Uint8Array) {
    return this.client.writeBlob({
      blob,
      deletable: this.deletable,
      epochs: this.epochs,
      signer: this.signer,
    });
  }

  private async writeFilesWithRetry(files: WalrusFile[]) {
    try {
      return await this.withWriteTimeout(this.writeFiles(files));
    } catch (error) {
      if (!(error instanceof RetryableWalrusClientError)) throw error;
      this.client.reset();
      return this.withWriteTimeout(this.writeFiles(files));
    }
  }

  private writeFiles(files: WalrusFile[]) {
    return this.client.writeFiles({
      deletable: this.deletable,
      epochs: this.epochs,
      files,
      signer: this.signer,
    });
  }

  private async withWriteTimeout<T>(operation: Promise<T>) {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        operation,
        new Promise<never>((_, reject) => {
          timeout = setTimeout(() => {
            reject(
              new Error(
                `Walrus SDK write timed out after ${this.writeTimeoutMs}ms.`,
              ),
            );
          }, this.writeTimeoutMs);
        }),
      ]);
    } finally {
      if (timeout) clearTimeout(timeout);
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

  private async readFileWithRetry(id: string) {
    try {
      return (await this.client.getFiles({ ids: [id] }))[0];
    } catch (error) {
      if (!(error instanceof RetryableWalrusClientError)) return undefined;
      this.client.reset();
      return (await this.client.getFiles({ ids: [id] }))[0];
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
  onProgress?: (event: {
    artifact: keyof Required<AuditReportArtifacts>;
    blobId?: string;
    contentLength?: number;
    phase: "write-start" | "write-finished" | "verify-start" | "verify-finished";
  }) => void;
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

  const inputEntries = Object.entries(inputs) as Array<
    [keyof Required<AuditReportArtifacts>, ArtifactInput]
  >;
  const writeArtifacts = options.store.writeArtifacts?.bind(options.store);
  const artifactPointers = writeArtifacts
    ? await writeArtifactsBatch({
        inputs,
        onProgress: options.onProgress,
        writeArtifacts,
      })
    : await writeArtifactsSequentially({
        entries: inputEntries,
        onProgress: options.onProgress,
        store: options.store,
      });

  const artifactEntries = [];
  for (const [name] of inputEntries) {
    const pointer = artifactPointers[name];
    if (!pointer) {
      throw new Error(`Walrus store did not return artifact pointer for ${name}.`);
    }
    options.onProgress?.({
      artifact: name,
      blobId: pointer.blobId,
      phase: "verify-start",
    });
    const verification = await verifyArtifact({
      blobId: pointer.blobId,
      expectedHash: pointer.contentHash,
      store: options.store,
    });
    options.onProgress?.({
      artifact: name,
      blobId: pointer.blobId,
      phase: "verify-finished",
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

async function writeArtifactsBatch(options: {
  inputs: Record<keyof Required<AuditReportArtifacts>, ArtifactInput>;
  onProgress?: (event: {
    artifact: keyof Required<AuditReportArtifacts>;
    blobId?: string;
    contentLength?: number;
    phase: "write-start" | "write-finished" | "verify-start" | "verify-finished";
  }) => void;
  writeArtifacts(inputs: Record<string, ArtifactInput>): Promise<Record<string, ArtifactPointer>>;
}) {
  for (const [name, input] of Object.entries(options.inputs) as Array<
    [keyof Required<AuditReportArtifacts>, ArtifactInput]
  >) {
    options.onProgress?.({
      artifact: name,
      contentLength: input.content.length,
      phase: "write-start",
    });
  }
  const pointers = await options.writeArtifacts(options.inputs);
  for (const [name, pointer] of Object.entries(pointers) as Array<
    [keyof Required<AuditReportArtifacts>, ArtifactPointer]
  >) {
    options.onProgress?.({
      artifact: name,
      blobId: pointer.blobId,
      phase: "write-finished",
    });
  }
  return pointers as Record<keyof Required<AuditReportArtifacts>, ArtifactPointer>;
}

async function writeArtifactsSequentially(options: {
  entries: Array<[keyof Required<AuditReportArtifacts>, ArtifactInput]>;
  onProgress?: (event: {
    artifact: keyof Required<AuditReportArtifacts>;
    blobId?: string;
    contentLength?: number;
    phase: "write-start" | "write-finished" | "verify-start" | "verify-finished";
  }) => void;
  store: WalrusStore;
}) {
  const pointers: Partial<Record<keyof Required<AuditReportArtifacts>, ArtifactPointer>> = {};
  for (const [name, input] of options.entries) {
    options.onProgress?.({
      artifact: name,
      contentLength: input.content.length,
      phase: "write-start",
    });
    const pointer = await options.store.writeArtifact(input);
    options.onProgress?.({
      artifact: name,
      blobId: pointer.blobId,
      phase: "write-finished",
    });
    pointers[name] = pointer;
  }
  return pointers as Record<keyof Required<AuditReportArtifacts>, ArtifactPointer>;
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
  timeoutMs?: number;
  waitForRemember?: boolean;
};

export class MemWalMemoryStore implements MemoryStore {
  private readonly client: MemWal;
  private readonly namespace?: string;
  private readonly timeoutMs: number;
  private readonly waitForRemember: boolean;

  constructor(options: MemWalMemoryStoreOptions) {
    this.client = MemWal.create({
      accountId: options.accountId,
      key: options.key,
      namespace: options.namespace,
      serverUrl: options.serverUrl,
    });
    this.namespace = options.namespace;
    this.timeoutMs = options.timeoutMs ?? 120_000;
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
      const result = await this.client.waitForRememberJob(accepted.job_id, {
        timeoutMs: this.timeoutMs,
      });
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
      content: formatPatternMemory(pattern),
      metadata: {
        category: pattern.category,
        kind: pattern.kind,
        patternId: pattern.id,
        ruleId: pattern.ruleId,
        severity: pattern.severity,
      },
    })),
    ...options.observations.map((observation) => ({
      content: formatObservationMemory(observation),
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

function formatPatternMemory(pattern: VulnerabilityPatternMemory) {
  return [
    `${pattern.kind} ${pattern.ruleId} ${pattern.category} ${pattern.severity}`,
    pattern.pattern,
    `signals: ${pattern.signals.join(", ")}`,
    `exploit model: ${pattern.exploitModel.join(" ")}`,
    `fix pattern: ${pattern.fixPattern.join(" ")}`,
    stableJson(pattern),
  ].join("\n");
}

function formatObservationMemory(observation: AuditObservationMemory) {
  return [
    `${observation.kind} ${observation.patternId} ${observation.severity}`,
    `package: ${observation.packageId}`,
    `finding: ${observation.findingId}`,
    `modules: ${observation.sourceModules.join(", ")}`,
    stableJson(observation),
  ].join("\n");
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
