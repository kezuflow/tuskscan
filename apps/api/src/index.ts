import { randomBytes, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import { Transaction } from "@mysten/sui/transactions";
import { SuiJsonRpcClient, getJsonRpcFullnodeUrl } from "@mysten/sui/jsonRpc";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { verifyPersonalMessageSignature } from "@mysten/sui/verify";
import {
  extractMoveFunctions,
  extractSourceModuleNames,
  moduleNameFromPath,
  runAuditWorkflow,
  type AuditCriticAgent,
  type AuditFindingAgent,
  type CriticDecision,
  type ExploitMemory,
} from "@repo/audit-core";
import { Pool } from "pg";
import {
  AI_PRE_AUDIT_DISCLAIMER,
  DEFAULT_NETWORK,
  type AuditFinding,
  type AuditReport,
  type AuditStatus,
  type FindingConfidence,
  type FindingSeverity,
  type Network,
  type NormalizedFunction,
  type NormalizedModule,
  type NormalizedParameter,
  type NormalizedStruct,
  type NormalizedPackageSnapshot,
  type PackageSummary,
  type SandboxCommandResult,
  type SandboxTestRun,
  type SourceContext,
  type SourceSummary,
} from "@repo/shared";
import {
  HttpWalrusStore,
  InMemoryWalrusStore,
  MemWalMemoryStore,
  recallExploitMemories,
  storeAuditArtifacts,
  verifyArtifact,
  writeAuditMemoryRecords,
  writeExploitLessons,
  type MemoryStore,
  type WalrusStore,
} from "@repo/storage";
import {
  fetchNormalizedPackage,
  hashSnapshot,
  isValidSuiObjectId,
  normalizeSuiObjectId,
  sha256Hex,
  stableJson,
  verifyAuditJobPayment,
} from "@repo/sui-integration";
import { summarizePackage } from "@repo/sui-integration";

type RuntimeConfig = {
  databaseUrl?: string;
  environment: "localhost" | "production";
  llmApiKey?: string;
  llmBaseUrl?: string;
  llmModel?: string;
  memwalAccountId?: string;
  memwalNamespace?: string;
  memwalPrivateKey?: string;
  memwalServerUrl?: string;
  operatorAddress?: string;
  network: Network;
  operatorCapId?: string;
  operatorPrivateKey?: string;
  priceMist: string;
  runMoveTests: boolean;
  sandboxTimeoutMs: number;
  suiCliPath?: string;
  suiRpcUrl?: string;
  tuskscanConfigId?: string;
  tuskscanPackageId?: string;
  walrusAggregatorUrl?: string;
  walrusPublisherUrl?: string;
};

type ApiDependencies = {
  auditStore?: AuditJobStore;
  auditProcessor?: AuditJobProcessor;
  config?: RuntimeConfig;
  fetchPackage?: typeof fetchNormalizedPackage;
  fetchSourceContext?: typeof fetchSourceContext;
  finalizer?: AuditReportFinalizer;
  findingAgent?: AuditFindingAgent;
  criticAgent?: AuditCriticAgent;
  memory?: MemoryStore;
  paymentVerifier?: PaymentVerifier;
  processJobsInline?: boolean;
  walrus?: WalrusStore;
};

type PaymentVerifier = (input: {
  digest: string;
  jobObjectId: string;
  network: Network;
  packageDigest: string;
  packageId: string;
  payer: string;
  priceMist: string;
}) => Promise<void>;

type AuditReportFinalizer = (input: {
  artifacts: Required<NonNullable<AuditReport["artifacts"]>>;
  findingsHash: string;
  jobObjectId: string;
  packageSnapshotHash: string;
  reportHash: string;
  riskScore: number;
}) => Promise<{ digest: string; reportObjectId: string }>;

type PreparedAuditRequest = {
  network?: Network;
  packageId?: string;
  sourceUrl?: string;
};

type CreateAuditRequest = PreparedAuditRequest & {
  payer?: string;
  suiJobObjectId?: string;
  suiTransactionDigest?: string;
};

type AuthChallengeRequest = {
  address?: string;
};

type AuthSessionRequest = {
  address?: string;
  message?: string;
  signature?: string;
};

type LocalAuditJob = {
  artifacts?: AuditReport["artifacts"];
  attempts?: number;
  completedAt?: string;
  createdAt: string;
  finalizedDigest?: string;
  id: string;
  lastError?: string;
  lockedAt?: string;
  lockedBy?: string;
  lockExpiresAt?: string;
  maxAttempts?: number;
  network: Network;
  packageId: string;
  packageSummary: PackageSummary;
  payer: string;
  privateReportMarkdown?: string;
  publicReportMarkdown?: string;
  report?: AuditReport;
  reportObjectId?: string;
  snapshotHash: string;
  sourceContext?: SourceContext;
  sourceUrl?: string;
  startedAt?: string;
  status: AuditStatus;
  suiJobObjectId: string;
  suiTransactionDigest: string;
  verification?: unknown;
};

type AuditJobStore = {
  claimJob(id: string, workerId: string, lockMs: number): Promise<LocalAuditJob | undefined>;
  completeJob(job: LocalAuditJob, workerId: string): Promise<void>;
  failJob(job: LocalAuditJob, workerId: string, error: unknown): Promise<void>;
  get(id: string): Promise<LocalAuditJob | undefined>;
  listByPayer(payer: string): Promise<LocalAuditJob[]>;
  save(job: LocalAuditJob): Promise<void>;
};

type AuditJobProcessor = (jobId: string) => Promise<void>;

const DEFAULT_PRICE_MIST = "100000000";
const JOB_LOCK_MS = 10 * 60 * 1000;
const SESSION_TTL_MS = 15 * 60 * 1000;
const execFileAsync = promisify(execFile);

loadLocalEnvFiles();

export function loadRuntimeConfig(env = process.env): RuntimeConfig {
  return {
    databaseUrl: env.DATABASE_URL ?? env.SUPABASE_DATABASE_URL,
    environment: parseRuntimeEnvironment(env.TUSKSCAN_ENV),
    llmApiKey: env.LLM_API_KEY ?? env.OPENAI_API_KEY,
    llmBaseUrl: env.LLM_BASE_URL ?? env.OPENAI_BASE_URL,
    llmModel: env.LLM_MODEL ?? env.OPENAI_MODEL,
    memwalAccountId: env.MEMWAL_ACCOUNT_ID,
    memwalNamespace: env.MEMWAL_NAMESPACE ?? "tuskscan",
    memwalPrivateKey: env.MEMWAL_PRIVATE_KEY,
    memwalServerUrl: env.MEMWAL_SERVER_URL,
    network: (env.SUI_NETWORK as Network | undefined) ?? DEFAULT_NETWORK,
    operatorAddress: env.TUSKSCAN_OPERATOR_ADDRESS,
    operatorCapId: env.TUSKSCAN_OPERATOR_CAP_ID,
    operatorPrivateKey: env.TUSKSCAN_OPERATOR_PRIVATE_KEY,
    priceMist: parsePriceMist(env.TUSKSCAN_PRICE_MIST),
    runMoveTests: parseBoolean(env.TUSKSCAN_RUN_MOVE_TESTS),
    sandboxTimeoutMs: parsePositiveInteger(env.TUSKSCAN_SANDBOX_TIMEOUT_MS, 120_000),
    suiCliPath: env.TUSKSCAN_SUI_BIN,
    suiRpcUrl: env.SUI_RPC_URL,
    tuskscanConfigId: env.TUSKSCAN_CONFIG_ID,
    tuskscanPackageId: env.TUSKSCAN_PACKAGE_ID,
    walrusAggregatorUrl: env.WALRUS_AGGREGATOR_URL,
    walrusPublisherUrl: env.WALRUS_PUBLISHER_URL,
  };
}

function parseBoolean(value: string | undefined) {
  return value === "1" || value?.toLowerCase() === "true";
}

function parsePositiveInteger(value: string | undefined, fallback: number) {
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function parseRuntimeEnvironment(value: string | undefined): RuntimeConfig["environment"] {
  if (value === "localhost") return "localhost";
  return "production";
}

function parsePriceMist(value: string | undefined) {
  if (!value) return DEFAULT_PRICE_MIST;
  if (!/^\d+$/.test(value) || BigInt(value) <= 0n) {
    throw new Error("TUSKSCAN_PRICE_MIST must be a positive integer string.");
  }
  return value;
}

function loadLocalEnvFiles() {
  const protectedKeys = new Set(Object.keys(process.env));
  for (const file of [".env", ".env.local"]) {
    const path = resolve(process.cwd(), file);
    if (!existsSync(path)) continue;
    for (const [key, value] of Object.entries(
      parseEnvFile(readFileSync(path, "utf8")),
    )) {
      if (!protectedKeys.has(key)) {
        process.env[key] = value;
      }
    }
  }
}

function parseEnvFile(contents: string) {
  const values: Record<string, string> = {};
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;
    values[match[1]!] = normalizeEnvValue(match[2] ?? "");
  }
  return values;
}

function normalizeEnvValue(raw: string) {
  const value = raw.trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1).replaceAll("\\n", "\n");
  }
  const commentStart = value.indexOf(" #");
  return commentStart === -1 ? value : value.slice(0, commentStart).trim();
}

export function validateRuntimeConfig(config: RuntimeConfig) {
  return {
    database: config.databaseUrl ? "production" : "missing",
    environment: config.environment,
    memwal: config.memwalPrivateKey && config.memwalAccountId
      ? "production"
      : "missing",
    network: config.network,
    llmAgents: config.llmApiKey ? "production" : "disabled",
    moveTestSandbox: config.runMoveTests ? "enabled" : "disabled",
    auditConfig: config.tuskscanConfigId ? "production" : "missing",
    operatorFinalizer:
      config.tuskscanPackageId &&
        config.operatorCapId &&
        config.operatorPrivateKey
        ? "production"
        : "missing",
    paymentVerifier: config.tuskscanPackageId && config.operatorAddress
      ? "production"
      : "missing",
    suiRpc: getRpcUrl(config),
    walrus: isLocalhost(config)
        ? "localhost"
        : config.walrusAggregatorUrl && config.walrusPublisherUrl
          ? "production"
          : "missing",
  };
}

export function createTuskscanApiServer(dependencies: ApiDependencies = {}) {
  const config = dependencies.config ?? loadRuntimeConfig();
  if (!dependencies.config) {
    assertRuntimeRequirements(config);
  }
  const auditStore = dependencies.auditStore ?? createAuditJobStore(config);
  const fetchPackage = dependencies.fetchPackage ?? fetchNormalizedPackage;
  const auditProcessor =
    dependencies.auditProcessor ??
    createAuditJobProcessor({
      auditStore,
      config,
      criticAgent: dependencies.criticAgent,
      fetchPackage,
      finalizer: dependencies.finalizer,
      findingAgent: dependencies.findingAgent,
      memory: dependencies.memory,
      walrus: dependencies.walrus,
    });
  const challenges = new Map<string, { address: string; expiresAt: number; message: string }>();
  const sessions = new Map<string, { address: string; expiresAt: number }>();

  return createServer(async (request, response) => {
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-methods", "GET,POST,OPTIONS");
    response.setHeader(
      "access-control-allow-headers",
      "authorization,content-type",
    );

    if (request.method === "OPTIONS") {
      response.writeHead(204);
      response.end();
      return;
    }

    try {
      const url = new URL(request.url ?? "/", "http://localhost");

      if (request.method === "GET" && url.pathname === "/health") {
        sendJson(response, 200, {
          config: validateRuntimeConfig(config),
          ok: true,
          service: "tuskscan-api",
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/auth/challenge") {
        const body = await readJson<AuthChallengeRequest>(request);
        if (!body.address || !isValidSuiObjectId(body.address)) {
          sendJson(response, 400, { error: "Missing or invalid wallet address." });
          return;
        }
        const address = normalizeSuiObjectId(body.address);
        const nonce = randomUUID();
        const message = `TuskScan private report access\naddress=${address}\nnonce=${nonce}`;
        challenges.set(nonce, {
          address,
          expiresAt: Date.now() + 5 * 60 * 1000,
          message,
        });
        sendJson(response, 200, { message, nonce });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/auth/session") {
        const body = await readJson<AuthSessionRequest>(request);
        if (!body.address || !body.message || !body.signature) {
          sendJson(response, 400, { error: "Missing auth session fields." });
          return;
        }
        const address = normalizeSuiObjectId(body.address);
        const nonce = body.message.match(/^nonce=(.+)$/m)?.[1];
        const challenge = nonce ? challenges.get(nonce) : undefined;
        if (
          !nonce ||
          !challenge ||
          challenge.expiresAt < Date.now() ||
          challenge.address !== address ||
          challenge.message !== body.message
        ) {
          sendJson(response, 401, { error: "Invalid or expired auth challenge." });
          return;
        }
        await verifyPersonalMessageSignature(new TextEncoder().encode(body.message), body.signature, {
          address,
        });
        challenges.delete(nonce);
        const token = randomBytes(32).toString("hex");
        sessions.set(token, { address, expiresAt: Date.now() + SESSION_TTL_MS });
        sendJson(response, 200, { token });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/audits/prepare") {
        const body = await readJson<PreparedAuditRequest>(request);
        const validation = validatePrepareRequest(body);
        if (!validation.ok) {
          sendJson(response, 400, { error: validation.error });
          return;
        }

        const sourceContext =
          (dependencies.fetchSourceContext ?? fetchSourceContext)(
            validation.sourceUrl,
            validation.network,
          );
        const resolvedSourceContext = await sourceContext;
        if (!validation.packageId && !resolvedSourceContext) {
          sendJson(response, 400, {
            error: "Paste a GitHub repository URL or a deployed Sui package address.",
          });
          return;
        }

        const snapshot = resolvedSourceContext
          ? await createSourcePackageSnapshot(resolvedSourceContext, validation.network)
          : await fetchPackage({
              network: validation.network,
              packageId: validation.packageId!,
              rpcUrl: getRpcUrl(config),
            });
        const packageSummary = summarizePackage(snapshot);
        sendJson(response, 200, {
          disclaimer: AI_PRE_AUDIT_DISCLAIMER,
          packageSummary,
          priceMist: config.priceMist,
          sourceSummary: resolvedSourceContext ? summarizeSourceContext(resolvedSourceContext) : undefined,
          snapshotHash: await hashSnapshot(snapshot),
          warnings: [],
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/audits") {
        const body = await readJson<CreateAuditRequest>(request);
        const validation = validateCreateAuditRequest(body);
        if (!validation.ok) {
          sendJson(response, 400, { error: validation.error });
          return;
        }

        const sourceContext = await (dependencies.fetchSourceContext ?? fetchSourceContext)(
          validation.sourceUrl,
          validation.network,
        );
        const snapshot = sourceContext
          ? await createSourcePackageSnapshot(sourceContext, validation.network, validation.packageId)
          : await fetchPackage({
              network: validation.network,
              packageId: validation.packageId,
              rpcUrl: getRpcUrl(config),
            });
        const snapshotHash = await hashSnapshot(snapshot);

        const paymentVerifier =
          dependencies.paymentVerifier ?? createPaymentVerifier(config);
        await paymentVerifier({
          digest: validation.suiTransactionDigest,
          jobObjectId: validation.suiJobObjectId,
          network: validation.network,
          packageDigest: snapshotHash,
          packageId: snapshot.packageId,
          payer: validation.payer,
          priceMist: config.priceMist,
        });

        const packageSummary = summarizePackage(snapshot);
        const job: LocalAuditJob = {
          createdAt: new Date().toISOString(),
          id: await createAuditId(validation.suiTransactionDigest, snapshotHash),
          network: validation.network,
          packageId: snapshot.packageId,
          packageSummary,
          payer: normalizeSuiObjectId(validation.payer),
          snapshotHash,
          sourceContext,
          sourceUrl: validation.sourceUrl,
          status: "queued",
          suiJobObjectId: normalizeSuiObjectId(validation.suiJobObjectId),
          suiTransactionDigest: validation.suiTransactionDigest,
        };
        await auditStore.save(job);

        const processing = auditProcessor(job.id);
        if (dependencies.processJobsInline) {
          await processing;
        } else {
          processing.catch((error: unknown) => {
            console.error(
              `Failed to process audit job ${job.id}:`,
              error instanceof Error ? error.message : error,
            );
          });
        }
        const currentJob = (await auditStore.get(job.id)) ?? job;

        sendJson(response, 202, {
          auditId: currentJob.id,
          reportObjectId: currentJob.reportObjectId,
          status: currentJob.status,
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/audits") {
        const wallet = url.searchParams.get("wallet");
        if (!wallet || !isValidSuiObjectId(wallet)) {
          sendJson(response, 400, { error: "Missing or invalid wallet address." });
          return;
        }
        const address = normalizeSuiObjectId(wallet);
        const session = readSession(request, sessions);
        if (!session || session.address.toLowerCase() !== address.toLowerCase()) {
          sendJson(response, 401, { error: "Wallet session required." });
          return;
        }
        const audits = await auditStore.listByPayer(address);
        sendJson(response, 200, { audits: audits.map(publicJob) });
        return;
      }

      const auditMatch = url.pathname.match(/^\/api\/audits\/([^/]+)$/);
      if (request.method === "GET" && auditMatch) {
        const job = await auditStore.get(auditMatch[1] ?? "");
        if (!job) {
          sendJson(response, 404, { error: "Audit not found." });
          return;
        }
        sendJson(response, 200, publicJob(job));
        return;
      }

      const reportMatch = url.pathname.match(/^\/api\/audits\/([^/]+)\/report$/);
      if (request.method === "GET" && reportMatch) {
        const job = await auditStore.get(reportMatch[1] ?? "");
        if (!job?.report) {
          sendJson(response, 404, { error: "Report not found." });
          return;
        }

        const session = readSession(request, sessions);
        const includePrivate =
          Boolean(session) && session?.address.toLowerCase() === job.payer.toLowerCase();

        sendJson(response, 200, {
          markdown: includePrivate
            ? job.privateReportMarkdown
            : job.publicReportMarkdown,
          private: includePrivate,
          report: includePrivate
            ? job.report
            : { ...job.report, findings: job.report.findings.slice(0, 3) },
        });
        return;
      }

      const verifyMatch = url.pathname.match(/^\/api\/audits\/([^/]+)\/verify$/);
      if (request.method === "POST" && verifyMatch) {
        const job = await auditStore.get(verifyMatch[1] ?? "");
        if (!job?.artifacts) {
          sendJson(response, 404, { error: "Artifacts not found." });
          return;
        }

        const walrus = dependencies.walrus ?? createWalrusStore(config);
        const verification = Object.fromEntries(
          await Promise.all(
            Object.entries(job.artifacts).map(async ([name, pointer]) => [
              name,
              await verifyArtifact({
                blobId: pointer.blobId,
                expectedHash: pointer.contentHash,
                store: walrus,
              }),
            ]),
          ),
        );
        sendJson(response, 200, {
          reportObjectId: job.reportObjectId,
          suiFinalizationDigest: job.finalizedDigest,
          verification,
        });
        return;
      }

      sendJson(response, 404, { error: "Not found." });
    } catch (error) {
      sendJson(response, 500, {
        error: error instanceof Error ? error.message : "Unexpected error.",
      });
    }
  });
}

function assertRuntimeRequirements(config: RuntimeConfig) {
  const missing: string[] = [];
  if (config.network !== "mainnet") {
    missing.push("SUI_NETWORK=mainnet");
  }
  if (!config.databaseUrl) {
    missing.push("DATABASE_URL");
  }
  if (!config.memwalAccountId) {
    missing.push("MEMWAL_ACCOUNT_ID");
  }
  if (!config.memwalPrivateKey) {
    missing.push("MEMWAL_PRIVATE_KEY");
  }
  if (!config.tuskscanPackageId) {
    missing.push("TUSKSCAN_PACKAGE_ID");
  }
  if (!config.tuskscanConfigId) {
    missing.push("TUSKSCAN_CONFIG_ID");
  }
  if (!config.operatorAddress) {
    missing.push("TUSKSCAN_OPERATOR_ADDRESS");
  }
  if (!config.operatorCapId) {
    missing.push("TUSKSCAN_OPERATOR_CAP_ID");
  }
  if (!config.operatorPrivateKey) {
    missing.push("TUSKSCAN_OPERATOR_PRIVATE_KEY");
  }
  if (missing.length > 0) {
    throw new Error(`Missing required TuskScan runtime config: ${missing.join(", ")}`);
  }
}

function createWalrusStore(config: RuntimeConfig): WalrusStore {
  if (isLocalhost(config)) {
    return new InMemoryWalrusStore();
  }
  if (config.walrusAggregatorUrl && config.walrusPublisherUrl) {
    return new HttpWalrusStore({
      aggregatorUrl: config.walrusAggregatorUrl,
      publisherUrl: config.walrusPublisherUrl,
    });
  }
  throw new Error("Production Walrus publisher/aggregator env vars are required.");
}

function createMemoryStore(config: RuntimeConfig): MemoryStore {
  if (config.memwalPrivateKey && config.memwalAccountId) {
    return new MemWalMemoryStore({
      accountId: config.memwalAccountId,
      key: config.memwalPrivateKey,
      namespace: config.memwalNamespace,
      serverUrl: config.memwalServerUrl,
    });
  }
  throw new Error("MemWal account/delegate key env vars are required.");
}

function createAuditJobProcessor(options: {
  auditStore: AuditJobStore;
  config: RuntimeConfig;
  criticAgent?: AuditCriticAgent;
  fetchPackage: typeof fetchNormalizedPackage;
  finalizer?: AuditReportFinalizer;
  findingAgent?: AuditFindingAgent;
  memory?: MemoryStore;
  walrus?: WalrusStore;
}): AuditJobProcessor {
  const agents = createLlmAuditAgents(options.config);
  const workerId = `api-${process.pid}-${randomUUID()}`;
  return async (jobId) => {
    const job = await options.auditStore.claimJob(jobId, workerId, JOB_LOCK_MS);
    if (!job) return;

    try {
      const snapshot = await options.fetchPackage({
        network: job.network,
        packageId: job.packageId,
        rpcUrl: getRpcUrl(options.config),
      });
      const snapshotHash = await hashSnapshot(snapshot);
      if (snapshotHash !== job.snapshotHash) {
        throw new Error("Fetched package snapshot hash does not match paid audit job.");
      }

      await runStoreAndFinalizeAudit({
        config: options.config,
        criticAgent: options.criticAgent ?? agents?.criticAgent,
        finalizer: options.finalizer ?? createAuditReportFinalizer(options.config),
        findingAgent: options.findingAgent ?? agents?.findingAgent,
        job,
        memory: options.memory ?? createMemoryStore(options.config),
        snapshot,
        walrus: options.walrus ?? createWalrusStore(options.config),
      });
      await options.auditStore.completeJob(job, workerId);
    } catch (error) {
      await options.auditStore.failJob(job, workerId, error);
      throw error;
    }
  };
}

function isLocalhost(config: RuntimeConfig) {
  return config.environment === "localhost";
}

function createAuditJobStore(config: RuntimeConfig): AuditJobStore {
  if (config.databaseUrl) {
    return new PostgresAuditJobStore(config.databaseUrl);
  }
  throw new Error("DATABASE_URL is required for the TuskScan audit job store.");
}

export class InMemoryAuditJobStore implements AuditJobStore {
  private readonly jobs = new Map<string, LocalAuditJob>();

  async claimJob(id: string, workerId: string, lockMs: number) {
    const job = this.jobs.get(id);
    if (!job || !canClaimJob(job)) return undefined;
    const now = new Date();
    const claimed = {
      ...job,
      attempts: (job.attempts ?? 0) + 1,
      lastError: undefined,
      lockedAt: now.toISOString(),
      lockedBy: workerId,
      lockExpiresAt: new Date(now.getTime() + lockMs).toISOString(),
      startedAt: job.startedAt ?? now.toISOString(),
      status: "running" as const,
    };
    this.jobs.set(id, claimed);
    return claimed;
  }

  async completeJob(job: LocalAuditJob, workerId: string) {
    const current = this.jobs.get(job.id);
    if (current?.lockedBy && current.lockedBy !== workerId) {
      throw new Error("Audit job lock is owned by another worker.");
    }
    const now = new Date().toISOString();
    this.jobs.set(job.id, {
      ...current,
      ...job,
      completedAt: now,
      lastError: undefined,
      lockedAt: undefined,
      lockedBy: undefined,
      lockExpiresAt: undefined,
      status: "completed",
    });
  }

  async failJob(job: LocalAuditJob, workerId: string, error: unknown) {
    const current = this.jobs.get(job.id);
    if (current?.lockedBy && current.lockedBy !== workerId) {
      throw new Error("Audit job lock is owned by another worker.");
    }
    const attempts = current?.attempts ?? job.attempts ?? 1;
    this.jobs.set(job.id, {
      ...current,
      ...job,
      lastError: error instanceof Error ? error.message : "Unexpected audit worker error.",
      lockedAt: undefined,
      lockedBy: undefined,
      lockExpiresAt: undefined,
      status: attempts >= (job.maxAttempts ?? current?.maxAttempts ?? 3) ? "failed" : "queued",
    });
  }

  async get(id: string) {
    return this.jobs.get(id);
  }

  async listByPayer(payer: string) {
    const normalized = normalizeSuiObjectId(payer).toLowerCase();
    return Array.from(this.jobs.values())
      .filter((job) => job.payer.toLowerCase() === normalized)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  async save(job: LocalAuditJob) {
    this.jobs.set(job.id, { attempts: 0, maxAttempts: 3, ...job });
  }
}

class PostgresAuditJobStore implements AuditJobStore {
  private readonly pool: Pool;
  private schemaReady?: Promise<void>;

  constructor(databaseUrl: string) {
    this.pool = new Pool({
      connectionString: databaseUrl,
      ssl: shouldUseDatabaseSsl(databaseUrl)
        ? { rejectUnauthorized: false }
        : undefined,
    });
  }

  async claimJob(id: string, workerId: string, lockMs: number) {
    await this.ensureSchema();
    const result = await this.pool.query(
      `with candidate as (
        select id
        from audit_jobs
        where id = $1
          and (
            status = 'queued'
            or (status = 'running' and lock_expires_at < now())
            or (status = 'failed' and attempts < max_attempts)
          )
        for update skip locked
      )
      update audit_jobs
      set attempts = attempts + 1,
        last_error = null,
        locked_at = now(),
        locked_by = $2,
        lock_expires_at = now() + ($3::text || ' milliseconds')::interval,
        started_at = coalesce(started_at, now()),
        status = 'running',
        updated_at = now()
      where id in (select id from candidate)
      returning *`,
      [id, workerId, lockMs],
    );
    return result.rows[0] ? rowToAuditJob(result.rows[0] as AuditJobRow) : undefined;
  }

  async completeJob(job: LocalAuditJob, workerId: string) {
    await this.ensureSchema();
    const result = await this.pool.query(
      `update audit_jobs
      set artifacts = $3,
        completed_at = now(),
        finalized_digest = $4,
        last_error = null,
        locked_at = null,
        locked_by = null,
        lock_expires_at = null,
        private_report_markdown = $5,
        public_report_markdown = $6,
        report = $7,
        report_object_id = $8,
        status = 'completed',
        verification = $9,
        updated_at = now()
      where id = $1 and locked_by = $2 and status = 'running'`,
      [
        job.id,
        workerId,
        job.artifacts ?? null,
        job.finalizedDigest ?? null,
        job.privateReportMarkdown ?? null,
        job.publicReportMarkdown ?? null,
        job.report ?? null,
        job.reportObjectId ?? null,
        job.verification ?? null,
      ],
    );
    if (result.rowCount !== 1) {
      throw new Error("Audit job could not be completed because the lock was lost.");
    }
  }

  async failJob(job: LocalAuditJob, workerId: string, error: unknown) {
    await this.ensureSchema();
    const message = error instanceof Error ? error.message : "Unexpected audit worker error.";
    const result = await this.pool.query(
      `update audit_jobs
      set last_error = $3,
        locked_at = null,
        locked_by = null,
        lock_expires_at = null,
        status = case when attempts >= max_attempts then 'failed' else 'queued' end,
        updated_at = now()
      where id = $1 and locked_by = $2 and status = 'running'`,
      [job.id, workerId, message],
    );
    if (result.rowCount !== 1) {
      throw new Error("Audit job could not be failed because the lock was lost.");
    }
  }

  async get(id: string) {
    await this.ensureSchema();
    const result = await this.pool.query("select * from audit_jobs where id = $1", [
      id,
    ]);
    return result.rows[0] ? rowToAuditJob(result.rows[0] as AuditJobRow) : undefined;
  }

  async listByPayer(payer: string) {
    await this.ensureSchema();
    const result = await this.pool.query(
      "select * from audit_jobs where payer = $1 order by created_at desc",
      [normalizeSuiObjectId(payer)],
    );
    return result.rows.map((row) => rowToAuditJob(row as AuditJobRow));
  }

  async save(job: LocalAuditJob) {
    await this.ensureSchema();
    await this.pool.query(
      `insert into audit_jobs (
        id,
        artifacts,
        attempts,
        completed_at,
        created_at,
        finalized_digest,
        last_error,
        locked_at,
        locked_by,
        lock_expires_at,
        max_attempts,
        network,
        package_id,
        package_summary,
        payer,
        private_report_markdown,
        public_report_markdown,
        report,
        report_object_id,
        snapshot_hash,
        source_context,
        source_url,
        started_at,
        status,
        sui_job_object_id,
        sui_transaction_digest,
        verification,
        updated_at
      ) values (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
        $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, now()
      )
      on conflict (id) do update set
        artifacts = excluded.artifacts,
        attempts = excluded.attempts,
        completed_at = excluded.completed_at,
        finalized_digest = excluded.finalized_digest,
        last_error = excluded.last_error,
        locked_at = excluded.locked_at,
        locked_by = excluded.locked_by,
        lock_expires_at = excluded.lock_expires_at,
        max_attempts = excluded.max_attempts,
        network = excluded.network,
        package_id = excluded.package_id,
        package_summary = excluded.package_summary,
        payer = excluded.payer,
        private_report_markdown = excluded.private_report_markdown,
        public_report_markdown = excluded.public_report_markdown,
        report = excluded.report,
        report_object_id = excluded.report_object_id,
        snapshot_hash = excluded.snapshot_hash,
        source_context = excluded.source_context,
        source_url = excluded.source_url,
        started_at = excluded.started_at,
        status = excluded.status,
        sui_job_object_id = excluded.sui_job_object_id,
        sui_transaction_digest = excluded.sui_transaction_digest,
        verification = excluded.verification,
        updated_at = now()`,
      [
        job.id,
        job.artifacts ?? null,
        job.attempts ?? 0,
        job.completedAt ?? null,
        job.createdAt,
        job.finalizedDigest ?? null,
        job.lastError ?? null,
        job.lockedAt ?? null,
        job.lockedBy ?? null,
        job.lockExpiresAt ?? null,
        job.maxAttempts ?? 3,
        job.network,
        job.packageId,
        job.packageSummary,
        job.payer,
        job.privateReportMarkdown ?? null,
        job.publicReportMarkdown ?? null,
        job.report ?? null,
        job.reportObjectId ?? null,
        job.snapshotHash,
        job.sourceContext ?? null,
        job.sourceUrl ?? null,
        job.startedAt ?? null,
        job.status,
        job.suiJobObjectId,
        job.suiTransactionDigest,
        job.verification ?? null,
      ],
    );
  }

  private ensureSchema() {
    this.schemaReady ??= this.pool.query(AUDIT_JOBS_SCHEMA_SQL).then(() => undefined);
    return this.schemaReady;
  }
}

type AuditJobRow = {
  artifacts: AuditReport["artifacts"] | null;
  attempts: number;
  completed_at: Date | string | null;
  created_at: Date | string;
  finalized_digest: string | null;
  id: string;
  last_error: string | null;
  locked_at: Date | string | null;
  locked_by: string | null;
  lock_expires_at: Date | string | null;
  max_attempts: number;
  network: Network;
  package_id: string;
  package_summary: PackageSummary;
  payer: string;
  private_report_markdown: string | null;
  public_report_markdown: string | null;
  report: AuditReport | null;
  report_object_id: string | null;
  snapshot_hash: string;
  source_context: SourceContext | null;
  source_url: string | null;
  started_at: Date | string | null;
  status: AuditStatus;
  sui_job_object_id: string;
  sui_transaction_digest: string;
  verification: unknown;
};

const AUDIT_JOBS_SCHEMA_SQL = `
create table if not exists audit_jobs (
  id text primary key,
  payer text not null,
  network text not null check (network in ('mainnet', 'testnet')),
  package_id text not null,
  package_summary jsonb not null,
  snapshot_hash text not null,
  status text not null check (status in ('prepared', 'paid', 'queued', 'running', 'completed', 'failed')),
  sui_job_object_id text not null,
  sui_transaction_digest text not null,
  report_object_id text,
  finalized_digest text,
  artifacts jsonb,
  report jsonb,
  public_report_markdown text,
  private_report_markdown text,
  verification jsonb,
  source_context jsonb,
  source_url text,
  attempts integer not null default 0,
  max_attempts integer not null default 3,
  locked_by text,
  locked_at timestamptz,
  lock_expires_at timestamptz,
  last_error text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null,
  updated_at timestamptz not null default now()
);

alter table audit_jobs add column if not exists source_context jsonb;
alter table audit_jobs add column if not exists source_url text;

create index if not exists audit_jobs_payer_created_at_idx
  on audit_jobs (payer, created_at desc);

create unique index if not exists audit_jobs_sui_job_object_id_idx
  on audit_jobs (sui_job_object_id);

create index if not exists audit_jobs_queue_claim_idx
  on audit_jobs (status, lock_expires_at, created_at);
`;

function rowToAuditJob(row: AuditJobRow): LocalAuditJob {
  return {
    artifacts: row.artifacts ?? undefined,
    attempts: row.attempts,
    completedAt: row.completed_at ? new Date(row.completed_at).toISOString() : undefined,
    createdAt: new Date(row.created_at).toISOString(),
    finalizedDigest: row.finalized_digest ?? undefined,
    id: row.id,
    lastError: row.last_error ?? undefined,
    lockedAt: row.locked_at ? new Date(row.locked_at).toISOString() : undefined,
    lockedBy: row.locked_by ?? undefined,
    lockExpiresAt: row.lock_expires_at
      ? new Date(row.lock_expires_at).toISOString()
      : undefined,
    maxAttempts: row.max_attempts,
    network: row.network,
    packageId: row.package_id,
    packageSummary: row.package_summary,
    payer: row.payer,
    privateReportMarkdown: row.private_report_markdown ?? undefined,
    publicReportMarkdown: row.public_report_markdown ?? undefined,
    report: row.report ?? undefined,
    reportObjectId: row.report_object_id ?? undefined,
    snapshotHash: row.snapshot_hash,
    sourceContext: row.source_context ?? undefined,
    sourceUrl: row.source_url ?? undefined,
    startedAt: row.started_at ? new Date(row.started_at).toISOString() : undefined,
    status: row.status,
    suiJobObjectId: row.sui_job_object_id,
    suiTransactionDigest: row.sui_transaction_digest,
    verification: row.verification ?? undefined,
  };
}

function shouldUseDatabaseSsl(databaseUrl: string) {
  try {
    const parsed = new URL(databaseUrl);
    return parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1";
  } catch {
    return true;
  }
}

function canClaimJob(job: LocalAuditJob) {
  if (job.status === "queued") return true;
  if (job.status === "failed" && (job.attempts ?? 0) < (job.maxAttempts ?? 3)) {
    return true;
  }
  if (job.status !== "running" || !job.lockExpiresAt) return false;
  return new Date(job.lockExpiresAt).getTime() < Date.now();
}

async function fetchSourceContext(
  sourceUrl: string | undefined,
  network: Network = DEFAULT_NETWORK,
): Promise<SourceContext | undefined> {
  if (!sourceUrl) return undefined;
  const parsed = parseGithubSourceUrl(sourceUrl);
  if (!parsed) {
    throw new Error("Source URL must be a public GitHub repository URL.");
  }

  const branch = parsed.branch ?? (await fetchGithubDefaultBranch(parsed));
  const tree = await fetchGithubTree({ ...parsed, branch });
  const packageRoots = discoverMovePackageRoots(tree.map((item) => item.path));
  const selectedRoot = selectMovePackageRoot(packageRoots, parsed.pathPrefix);
  const publishedPackageId = await resolvePublishedPackageId({
    branch,
    network,
    parsed,
    selectedRoot,
    tree,
  });
  const movePaths = tree
    .filter(
      (item) =>
        item.type === "blob" &&
        item.path.endsWith(".move") &&
        pathIsUnderSelectedScope(item.path, selectedRoot, parsed.pathPrefix),
    )
    .map((item) => item.path)
    .sort();

  const files = (
    await Promise.all(
      movePaths.slice(0, 80).map(async (path) => {
        const content = await fetchGithubRaw({ ...parsed, branch, path });
        if (content.length > 250_000) return undefined;
        return { content, path, sizeBytes: Buffer.byteLength(content, "utf8") };
      }),
    )
  ).filter((file): file is SourceContext["files"][number] => Boolean(file));

  const limitedFiles = limitSourceBytes(files, 1_500_000);
  const unsignedContext = {
    branch,
    fetchedAt: new Date().toISOString(),
    files: limitedFiles,
    moveFileCount: limitedFiles.length,
    omittedMoveFileCount: Math.max(0, movePaths.length - limitedFiles.length),
    packageRoots,
    pathPrefix: parsed.pathPrefix,
    publishedPackageId,
    selectedRoot,
    source: "github" as const,
    totalMoveFileCount: movePaths.length,
    url: sourceUrl,
  };

  return {
    ...unsignedContext,
    digest: await sha256Hex(stableJson(unsignedContext)),
  };
}

function discoverMovePackageRoots(paths: string[]) {
  return paths
    .filter((path) => path.endsWith("Move.toml"))
    .map((path) => path.replace(/\/?Move\.toml$/, ""))
    .map((path) => path || ".")
    .sort((left, right) => left.localeCompare(right));
}

function selectMovePackageRoot(packageRoots: string[], pathPrefix: string | undefined) {
  if (pathPrefix) {
    const normalizedPrefix = pathPrefix.replace(/\/$/, "");
    const exact = packageRoots.find((root) => root === normalizedPrefix);
    if (exact) return exact;
    const nested = packageRoots.find((root) => root.startsWith(`${normalizedPrefix}/`));
    if (nested) return nested;
    return normalizedPrefix;
  }
  if (packageRoots.length === 1) return packageRoots[0];
  const preferred = packageRoots.find((root) =>
    /^(move|contracts|contract|sources|sui|packages\/move|apps\/move)$/i.test(root),
  );
  return preferred ?? packageRoots[0];
}

function pathIsUnderSelectedScope(
  path: string,
  selectedRoot: string | undefined,
  pathPrefix: string | undefined,
) {
  const scope = selectedRoot ?? pathPrefix;
  if (!scope || scope === ".") return true;
  return path === scope || path.startsWith(`${scope}/`);
}

async function resolvePublishedPackageId(input: {
  branch: string;
  network: Network;
  parsed: ParsedGithubSourceUrl;
  selectedRoot: string | undefined;
  tree: Array<{ path: string; type: string }>;
}) {
  const selectedRoot = input.selectedRoot && input.selectedRoot !== "." ? input.selectedRoot : "";
  const candidates = [
    selectedRoot ? `${selectedRoot}/Published.toml` : "Published.toml",
    selectedRoot ? `${selectedRoot}/Move.lock` : "Move.lock",
  ];
  const existingPaths = new Set(
    input.tree.filter((item) => item.type === "blob").map((item) => item.path),
  );

  for (const path of candidates) {
    if (!existingPaths.has(path)) continue;
    const content = await fetchGithubRaw({ ...input.parsed, branch: input.branch, path });
    const packageId =
      path.endsWith("Published.toml")
        ? parsePublishedTomlPackageId(content, input.network)
        : parseMoveLockPackageId(content, input.network);
    if (packageId) return packageId;
  }

  return undefined;
}

function parsePublishedTomlPackageId(content: string, network: Network) {
  const section = content.match(
    new RegExp(`\\[published\\.${escapeRegExp(network)}\\]([\\s\\S]*?)(?:\\n\\[|$)`, "i"),
  )?.[1];
  const packageId = section?.match(/published-at\s*=\s*"([^"]+)"/i)?.[1];
  return packageId && isValidSuiObjectId(packageId) ? packageId : undefined;
}

function parseMoveLockPackageId(content: string, network: Network) {
  const section = content.match(
    new RegExp(`\\[env\\.${escapeRegExp(network)}\\]([\\s\\S]*?)(?:\\n\\[|$)`, "i"),
  )?.[1];
  const packageId =
    section?.match(/published-at\s*=\s*"([^"]+)"/i)?.[1] ??
    section?.match(/original-id\s*=\s*"([^"]+)"/i)?.[1];
  return packageId && isValidSuiObjectId(packageId) ? packageId : undefined;
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isGithubUrl(value: string) {
  return Boolean(parseGithubSourceUrl(value));
}

type ParsedGithubSourceUrl = {
  branch?: string;
  owner: string;
  pathPrefix?: string;
  repo: string;
};

function parseGithubSourceUrl(value: string): ParsedGithubSourceUrl | undefined {
  try {
    const url = new URL(value.trim());
    if (url.hostname !== "github.com") return undefined;
    const parts = url.pathname.split("/").filter(Boolean);
    const [owner, repo, marker, branch, ...pathParts] = parts;
    if (!owner || !repo) return undefined;
    if (marker && marker !== "tree") return undefined;
    return {
      branch,
      owner,
      pathPrefix: pathParts.length ? pathParts.join("/") : undefined,
      repo: repo.replace(/\.git$/i, ""),
    };
  } catch {
    return undefined;
  }
}

async function fetchGithubDefaultBranch(input: ParsedGithubSourceUrl) {
  const payload = await githubJson<{ default_branch?: string }>(
    `https://api.github.com/repos/${input.owner}/${input.repo}`,
  );
  return payload.default_branch ?? "main";
}

async function fetchGithubTree(input: ParsedGithubSourceUrl & { branch: string }) {
  const payload = await githubJson<{
    tree?: Array<{ path: string; type: string }>;
  }>(
    `https://api.github.com/repos/${input.owner}/${input.repo}/git/trees/${encodeURIComponent(input.branch)}?recursive=1`,
  );
  return payload.tree ?? [];
}

async function fetchGithubRaw(
  input: ParsedGithubSourceUrl & { branch: string; path: string },
) {
  const response = await fetch(
    `https://raw.githubusercontent.com/${input.owner}/${input.repo}/${encodeURIComponent(input.branch)}/${input.path}`,
    { headers: githubHeaders() },
  );
  if (!response.ok) {
    throw new Error(`GitHub raw source fetch failed with HTTP ${response.status}.`);
  }
  return response.text();
}

async function githubJson<T>(url: string): Promise<T> {
  const response = await fetch(url, { headers: githubHeaders() });
  if (!response.ok) {
    throw new Error(`GitHub source fetch failed with HTTP ${response.status}.`);
  }
  return response.json() as Promise<T>;
}

function githubHeaders() {
  return {
    accept: "application/vnd.github+json",
    ...(process.env.GITHUB_TOKEN
      ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
      : {}),
  };
}

function limitSourceBytes(files: SourceContext["files"], maxBytes: number) {
  const selected: SourceContext["files"] = [];
  let total = 0;
  for (const file of files) {
    if (total + file.sizeBytes > maxBytes) break;
    selected.push(file);
    total += file.sizeBytes;
  }
  return selected;
}

function summarizeSourceContext(sourceContext: SourceContext): SourceSummary {
  return {
    branch: sourceContext.branch,
    digest: sourceContext.digest,
    fileCount: sourceContext.files.length,
    moveFileCount: sourceContext.moveFileCount,
    omittedMoveFileCount: sourceContext.omittedMoveFileCount,
    packageRoots: sourceContext.packageRoots,
    pathPrefix: sourceContext.pathPrefix,
    publishedPackageId: sourceContext.publishedPackageId,
    selectedRoot: sourceContext.selectedRoot,
    totalMoveFileCount: sourceContext.totalMoveFileCount,
    url: sourceContext.url,
  };
}

async function createSourcePackageSnapshot(
  sourceContext: SourceContext,
  network: Network,
  preparedTargetId?: string,
): Promise<NormalizedPackageSnapshot> {
  const modules = normalizeSourceModules(sourceContext);
  const packageId = preparedTargetId?.trim() || sourceTargetId(sourceContext);
  const unsignedSnapshot = {
    fetchedAt: sourceContext.fetchedAt,
    modules,
    network,
    packageId,
    source: "github-move-source" as const,
  };

  return {
    ...unsignedSnapshot,
    packageDigest: await sha256Hex(
      stableJson({
        modules,
        packageId,
        sourceDigest: sourceContext.digest,
        sourceUrl: sourceContext.url,
      }),
    ),
  };
}

function normalizeSourceModules(sourceContext: SourceContext): NormalizedModule[] {
  const modules = new Map<string, NormalizedModule>();

  for (const file of sourceContext.files) {
    const moduleName = extractSourceModuleNames(file.content)[0] ?? moduleNameFromPath(file.path);
    const existing = modules.get(moduleName) ?? {
      functions: [],
      name: moduleName,
      structs: [],
    };
    existing.functions.push(...extractMoveFunctions(file).map(normalizeSourceFunction));
    existing.structs.push(...extractSourceStructs(file.content));
    modules.set(moduleName, existing);
  }

  return Array.from(modules.values())
    .map((module) => ({
      functions: dedupeByName(module.functions).sort((left, right) =>
        left.name.localeCompare(right.name),
      ),
      name: module.name,
      structs: dedupeByName(module.structs).sort((left, right) =>
        left.name.localeCompare(right.name),
      ),
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

function normalizeSourceFunction(fn: {
  isPublicEntry: boolean;
  name: string;
  signature: string;
}): NormalizedFunction {
  return {
    isEntry: /\bentry\b/.test(fn.signature),
    name: fn.name,
    parameters: parseSourceParameters(fn.signature),
    returns: [],
    visibility: /\bpublic\b/.test(fn.signature) ? "public" : "private",
  };
}

function parseSourceParameters(signature: string): NormalizedParameter[] {
  const parameterBlock = signature.match(/\(([\s\S]*)\)/)?.[1] ?? "";
  return splitTopLevel(parameterBlock)
    .map((raw) => raw.trim())
    .filter(Boolean)
    .map((raw) => ({
      isMutableReference: /&\s*mut\b/i.test(raw),
      isSharedObjectLike: /&\s*mut\b|UID|Receiving|object::|has\s+key/i.test(raw),
      raw,
    }));
}

function extractSourceStructs(content: string): NormalizedStruct[] {
  return Array.from(
    content.matchAll(
      /\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:has\s+([^{]+))?\{/g,
    ),
  ).map((match) => ({
    abilities: (match[2] ?? "")
      .split(",")
      .map((ability) => ability.trim())
      .filter(Boolean)
      .sort(),
    fields: [],
    name: match[1] ?? "Struct",
  }));
}

function splitTopLevel(value: string) {
  const parts: string[] = [];
  let current = "";
  let depth = 0;
  for (const char of value) {
    if (char === "<" || char === "(") depth += 1;
    if (char === ">" || char === ")") depth = Math.max(0, depth - 1);
    if (char === "," && depth === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  if (current.trim()) parts.push(current);
  return parts;
}

function dedupeByName<T extends { name: string }>(items: T[]) {
  return Array.from(new Map(items.map((item) => [item.name, item])).values());
}

function sourceTargetId(sourceContext: SourceContext) {
  try {
    const url = new URL(sourceContext.url);
    const [owner, repo] = url.pathname.split("/").filter(Boolean);
    const root = sourceContext.selectedRoot && sourceContext.selectedRoot !== "."
      ? `/${sourceContext.selectedRoot}`
      : "";
    const branch = sourceContext.branch ? `@${sourceContext.branch}` : "";
    return `github:${owner ?? "repo"}/${repo ?? "source"}${root}${branch}#${sourceContext.digest.slice(2, 14)}`;
  } catch {
    return `github:move-source#${sourceContext.digest.slice(2, 14)}`;
  }
}

function createPaymentVerifier(config: RuntimeConfig): PaymentVerifier {
  if (!config.tuskscanPackageId || !config.operatorAddress) {
    throw new Error(
      "TUSKSCAN_PACKAGE_ID and TUSKSCAN_OPERATOR_ADDRESS are required for payment verification.",
    );
  }
  return async (input) => {
    await verifyAuditJobPayment({
      contractPackageId: config.tuskscanPackageId!,
      digest: input.digest,
      jobObjectId: input.jobObjectId,
      network: input.network,
      operatorAddress: config.operatorAddress!,
      packageDigest: input.packageDigest,
      packageId: input.packageId,
      payer: input.payer,
      priceMist: input.priceMist,
      rpcUrl: getRpcUrl(config),
    });
  };
}

function createAuditReportFinalizer(config: RuntimeConfig): AuditReportFinalizer {
  if (!config.tuskscanPackageId || !config.operatorCapId || !config.operatorPrivateKey) {
    throw new Error(
      "TUSKSCAN_PACKAGE_ID, TUSKSCAN_OPERATOR_CAP_ID, and TUSKSCAN_OPERATOR_PRIVATE_KEY are required for report finalization.",
    );
  }
  const client = new SuiJsonRpcClient({
    network: config.network,
    url: getRpcUrl(config),
  });
  const keypair = Ed25519Keypair.fromSecretKey(config.operatorPrivateKey);

  return async (input) => {
    const tx = new Transaction();
    tx.moveCall({
      arguments: [
        tx.object(config.operatorCapId!),
        tx.object(input.jobObjectId),
        vectorBytes(tx, input.artifacts.packageSnapshot.blobId),
        vectorBytes(tx, input.packageSnapshotHash),
        vectorBytes(tx, input.artifacts.privateReport.blobId),
        vectorBytes(tx, input.reportHash),
        vectorBytes(tx, input.findingsHash),
        tx.pure.u64(input.riskScore),
        tx.pure.u8(1),
        tx.object("0x6"),
      ],
      target: `${normalizeSuiObjectId(config.tuskscanPackageId!)}::audit::finalize_report`,
    });
    const executed = await keypair.signAndExecuteTransaction({ client, transaction: tx });
    const digest = readExecutedDigest(executed);
    const finalized = await client.waitForTransaction({
      digest,
      options: { showObjectChanges: true },
    });
    const reportObject = finalized.objectChanges?.find(
      (change) =>
        change.type === "created" &&
        "objectType" in change &&
        change.objectType === `${normalizeSuiObjectId(config.tuskscanPackageId!)}::audit::AuditReport`,
    );
    if (!reportObject || !("objectId" in reportObject)) {
      throw new Error("Report finalization succeeded but no AuditReport object was found.");
    }
    return {
      digest,
      reportObjectId: reportObject.objectId,
    };
  };
}

async function runStoreAndFinalizeAudit(options: {
  config: RuntimeConfig;
  criticAgent?: AuditCriticAgent;
  finalizer: AuditReportFinalizer;
  findingAgent?: AuditFindingAgent;
  job: LocalAuditJob;
  memory: MemoryStore;
  snapshot: NormalizedPackageSnapshot;
  walrus: WalrusStore;
}) {
  try {
    const audit = await runAuditWorkflow({
      criticAgent: options.criticAgent,
      findingAgent: options.findingAgent,
      memoryAgent: {
        recall: async (snapshot) => {
          const recalled = await recallExploitMemories({
            context: buildMemoryRecallContext(snapshot),
            store: options.memory,
          });
          return recalled.map((item): ExploitMemory => ({
            ...item,
            query: item.summary,
          }));
        },
        writeLessons: async (lessons, snapshot) => {
          await writeExploitLessons({
            lessons,
            metadata: { packageId: snapshot.packageId },
            store: options.memory,
          });
        },
        writeMemories: async (memories) => {
          await writeAuditMemoryRecords({
            observations: memories.observations,
            patterns: memories.patterns,
            store: options.memory,
          });
        },
      },
      packageSummary: options.job.packageSummary,
      sourceContext: options.job.sourceContext,
      snapshot: options.snapshot,
    });
    const sandbox = await runSandboxMoveTests({
      config: options.config,
      report: audit.report,
      sourceContext: options.job.sourceContext,
    });
    audit.report = {
      ...audit.report,
      generatedExploitTests: sandbox.generatedTests,
      sandboxTestRun: sandbox.run,
    };
    audit.privateReportMarkdown = appendSandboxMarkdown(
      audit.privateReportMarkdown,
      audit.report,
    );
    audit.publicReportMarkdown = appendSandboxMarkdown(
      audit.publicReportMarkdown,
      audit.report,
    );

    const stored = await storeAuditArtifacts({
      contents: {
        auditRunLog: [
          { at: options.job.createdAt, step: "created", status: "paid" },
          { at: new Date().toISOString(), step: "completed", status: "ok" },
        ],
        findings: audit.findings,
        memoryDiff: audit.memoryDiff,
        packageSnapshot: options.snapshot,
        privateReportMarkdown: audit.privateReportMarkdown,
        publicReportMarkdown: audit.publicReportMarkdown,
        sourceContext: options.job.sourceContext ?? { source: "none" },
      },
      store: options.walrus,
    });
    const finalized = await options.finalizer({
      artifacts: stored.artifacts,
      findingsHash: stored.artifacts.findings.contentHash,
      jobObjectId: options.job.suiJobObjectId,
      packageSnapshotHash: stored.artifacts.packageSnapshot.contentHash,
      reportHash: stored.artifacts.privateReport.contentHash,
      riskScore: audit.report.riskScore,
    });

    options.job.artifacts = stored.artifacts;
    options.job.finalizedDigest = finalized.digest;
    options.job.privateReportMarkdown = audit.privateReportMarkdown;
    options.job.publicReportMarkdown = audit.publicReportMarkdown;
    options.job.report = { ...audit.report, artifacts: stored.artifacts };
    options.job.reportObjectId = finalized.reportObjectId;
    options.job.status = "completed";
    options.job.verification = stored.verification;
  } catch (error) {
    options.job.status = "failed";
    throw error;
  }
}

function buildMemoryRecallContext(snapshot: NormalizedPackageSnapshot) {
  const moduleNames = snapshot.modules.map((module) => module.name);
  const functionNames = snapshot.modules.flatMap((module) =>
    module.functions
      .filter((fn) => fn.isEntry || fn.visibility === "public")
      .map((fn) => `${module.name}::${fn.name}`),
  );
  const structNames = snapshot.modules.flatMap((module) =>
    module.structs.map((struct) => `${module.name}::${struct.name}`),
  );
  return [
    snapshot.packageId,
    "sui move vulnerability_pattern audit_observation",
    "admin owner capability shared object withdraw transfer claim mint burn treasury replay dynamic field vector delete randomness initialize",
    ...moduleNames,
    ...functionNames,
    ...structNames,
  ]
    .join(" ")
    .slice(0, 4_000);
}

async function runSandboxMoveTests(options: {
  config: RuntimeConfig;
  report: AuditReport;
  sourceContext?: SourceContext;
}): Promise<{
  generatedTests: NonNullable<AuditReport["generatedExploitTests"]>;
  run: SandboxTestRun;
}> {
  const generatedTests = options.report.generatedExploitTests ?? [];
  if (!options.config.runMoveTests) {
    return {
      generatedTests: generatedTests.map((test) => ({ ...test, status: "skipped" })),
      run: {
        note: "Sandbox Move test execution is disabled. Set TUSKSCAN_RUN_MOVE_TESTS=1 to enable repo checkout and sui move test execution.",
        status: "disabled",
        testsAttempted: 0,
      },
    };
  }
  if (!options.sourceContext?.url) {
    return {
      generatedTests: generatedTests.map((test) => ({ ...test, status: "skipped" })),
      run: {
        note: "No source repository was available for sandbox test execution.",
        status: "source_unavailable",
        testsAttempted: 0,
      },
    };
  }

  const parsed = parseGithubSourceUrl(options.sourceContext.url);
  if (!parsed) {
    return {
      generatedTests: generatedTests.map((test) => ({ ...test, status: "skipped" })),
      run: {
        note: "Source URL could not be parsed as a GitHub repository for sandbox execution.",
        status: "source_unavailable",
        testsAttempted: 0,
      },
    };
  }

  const sandboxRoot = await mkdtemp(join(tmpdir(), "tuskscan-"));
  const clonePath = join(sandboxRoot, "repo");
  const branch = options.sourceContext.branch ?? parsed.branch;
  try {
    const cloneArgs = ["clone", "--depth", "1"];
    if (branch) cloneArgs.push("--branch", branch);
    cloneArgs.push(`https://github.com/${parsed.owner}/${parsed.repo}.git`, clonePath);
    const cloneResult = await runSandboxCommand("git", cloneArgs, sandboxRoot, options.config);
    if (cloneResult.exitCode !== 0) {
      return {
        generatedTests: generatedTests.map((test) => ({ ...test, status: "skipped" })),
        run: {
          baseline: cloneResult,
          note: "GitHub checkout failed before Sui Move tests could run.",
          status: "source_unavailable",
          testsAttempted: 0,
        },
      };
    }

    const packagePath = join(
      clonePath,
      normalizePackageRoot(options.sourceContext.selectedRoot ?? parsed.pathPrefix),
    );
    const baseline = await runSandboxCommand(
      options.config.suiCliPath ?? "sui",
      ["move", "test"],
      packagePath,
      options.config,
    );
    if (isMissingExecutable(baseline)) {
      return {
        generatedTests: generatedTests.map((test) => ({ ...test, status: "skipped" })),
        run: {
          baseline,
          note: "Sui CLI was not available to execute Move tests.",
          packagePath: relativeSandboxPath(packagePath, sandboxRoot),
          status: "sui_cli_missing",
          testsAttempted: 0,
        },
      };
    }
    if (baseline.exitCode !== 0) {
      return {
        generatedTests: generatedTests.map((test) => ({ ...test, status: "skipped" })),
        run: {
          baseline,
          note: "Baseline package tests failed; generated exploit tests were not injected.",
          packagePath: relativeSandboxPath(packagePath, sandboxRoot),
          status: "baseline_failed",
          testsAttempted: 0,
        },
      };
    }

    if (generatedTests.length === 0) {
      return {
        generatedTests,
        run: {
          baseline,
          note: "Baseline package tests passed; no critical/high generated exploit tests were available.",
          packagePath: relativeSandboxPath(packagePath, sandboxRoot),
          status: "completed",
          testsAttempted: 0,
        },
      };
    }

    const testsDirectory = join(packagePath, "tests");
    await mkdir(testsDirectory, { recursive: true });
    const generatedTestFile = join(testsDirectory, "tuskscan_generated_tests.move");
    await writeFile(
      generatedTestFile,
      await renderGeneratedMoveTestModule(packagePath, generatedTests),
      "utf8",
    );
    const generated = await runSandboxCommand(
      options.config.suiCliPath ?? "sui",
      ["move", "test", "tuskscan_"],
      packagePath,
      options.config,
    );
    const generatedStatus = generated.exitCode === 0 ? "executed_compile_only" : "execution_failed";
    return {
      generatedTests: generatedTests.map((test) => ({
        ...test,
        status: generatedStatus,
      })),
      run: {
        baseline,
        generated,
        generatedTestFile: relativeSandboxPath(generatedTestFile, sandboxRoot),
        note:
          generated.exitCode === 0
            ? "Baseline tests passed and generated TuskScan exploit-test skeletons executed as compile-only regression placeholders. Bind project fixtures to turn them into concrete exploit PoCs."
            : "Baseline tests passed, but generated TuskScan test skeletons failed to compile or execute.",
        packagePath: relativeSandboxPath(packagePath, sandboxRoot),
        status: generated.exitCode === 0 ? "completed" : "generated_failed",
        testsAttempted: generatedTests.length,
      },
    };
  } finally {
    await rm(sandboxRoot, { force: true, recursive: true });
  }
}

async function runSandboxCommand(
  command: string,
  args: string[],
  cwd: string,
  config: RuntimeConfig,
): Promise<SandboxCommandResult> {
  const started = Date.now();
  const commandText = [command, ...args].join(" ");
  try {
    const result = await execFileAsync(command, args, {
      cwd,
      timeout: config.sandboxTimeoutMs,
      windowsHide: true,
    });
    return {
      command: commandText,
      durationMs: Date.now() - started,
      exitCode: 0,
      stderrTail: tail(result.stderr),
      stdoutTail: tail(result.stdout),
    };
  } catch (error) {
    const details = error as {
      code?: number | string;
      killed?: boolean;
      stderr?: string;
      stdout?: string;
    };
    return {
      command: commandText,
      durationMs: Date.now() - started,
      exitCode: typeof details.code === "number" ? details.code : null,
      stderrTail: tail(
        details.stderr ??
          (details.code === "ENOENT" ? `${command} executable was not found.` : String(error)),
      ),
      stdoutTail: tail(details.stdout),
    };
  }
}

async function renderGeneratedMoveTestModule(
  packagePath: string,
  tests: NonNullable<AuditReport["generatedExploitTests"]>,
) {
  const addressName = await inferMoveTestAddress(packagePath);
  return [
    "#[test_only]",
    `module ${addressName}::tuskscan_generated_tests {`,
    ...tests.flatMap((test) => [
      "    #[test]",
      `    fun ${sanitizeMoveIdentifier(test.name)}() {`,
      "        // TuskScan generated compile-only exploit regression skeleton.",
      `        // Finding: ${test.findingId}`,
      ...test.notes.map((note) => `        // ${sanitizeMoveComment(note)}`),
      ...(test.source ?? "")
        .split(/\r?\n/)
        .slice(0, 24)
        .map((line) => `        // ${sanitizeMoveComment(line)}`),
      "    }",
      "",
    ]),
    "}",
    "",
  ].join("\n");
}

async function inferMoveTestAddress(packagePath: string) {
  try {
    const manifest = await readFile(join(packagePath, "Move.toml"), "utf8");
    const addresses = manifest.match(/\[addresses\]([\s\S]*?)(?:\n\[|$)/)?.[1] ?? "";
    const firstAddress = addresses.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/m)?.[1];
    if (firstAddress) return firstAddress;
  } catch {
    // Fall through to numeric address for packages without a readable manifest.
  }
  return "0x0";
}

function appendSandboxMarkdown(markdown: string, report: AuditReport) {
  const run = report.sandboxTestRun;
  if (!run) return markdown;
  const lines = [
    "",
    "## Sandbox Move Test Execution",
    "",
    `Status: \`${run.status}\``,
    "",
    run.note,
    "",
    run.packagePath ? `Package path: \`${run.packagePath}\`` : undefined,
    run.baseline ? `Baseline: \`${run.baseline.command}\` -> ${run.baseline.exitCode}` : undefined,
    run.generated ? `Generated: \`${run.generated.command}\` -> ${run.generated.exitCode}` : undefined,
    run.generatedTestFile ? `Generated test file: \`${run.generatedTestFile}\`` : undefined,
    `Tests attempted: ${run.testsAttempted}`,
    "",
  ].filter((line): line is string => typeof line === "string");
  return `${markdown.trimEnd()}\n${lines.join("\n")}\n`;
}

function normalizePackageRoot(root: string | undefined) {
  if (!root || root === ".") return "";
  return root.replace(/^[\\/]+/, "").replace(/[\\/]+$/, "");
}

function relativeSandboxPath(path: string, sandboxRoot: string) {
  return path.startsWith(sandboxRoot) ? path.slice(sandboxRoot.length + 1) : path;
}

function isMissingExecutable(result: SandboxCommandResult) {
  return result.exitCode === null && /not found|ENOENT/i.test(result.stderrTail ?? "");
}

function tail(value: string | undefined, maxLength = 4_000) {
  if (!value) return undefined;
  return value.length <= maxLength ? value : value.slice(-maxLength);
}

function sanitizeMoveIdentifier(value: string) {
  const sanitized = value.toLowerCase().replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
  const identifier = /^[a-z_]/.test(sanitized) ? sanitized : `test_${sanitized}`;
  return `tuskscan_${identifier}`.slice(0, 80);
}

function sanitizeMoveComment(value: string) {
  return value.replace(/\*\//g, "* /").slice(0, 180);
}

type LlmAgentBundle = {
  criticAgent: AuditCriticAgent;
  findingAgent: AuditFindingAgent;
};

type LlmFindingDraft = {
  attackPrerequisites?: unknown;
  category?: unknown;
  confidence?: unknown;
  description?: unknown;
  evidence?: unknown;
  exploitPath?: unknown;
  impact?: unknown;
  likelihood?: unknown;
  patchSuggestion?: unknown;
  recommendation?: unknown;
  remediationSteps?: unknown;
  ruleId?: unknown;
  severity?: unknown;
  testSuggestions?: unknown;
  title?: unknown;
};

type LlmCriticDraft = {
  action?: unknown;
  findingId?: unknown;
  reason?: unknown;
  severity?: unknown;
};

function createLlmAuditAgents(config: RuntimeConfig): LlmAgentBundle | undefined {
  if (!config.llmApiKey) return undefined;
  return {
    criticAgent: {
      critique: async (input) => {
        const payload = await callLlmJson(config, {
          system:
            "You are a conservative Move smart-contract audit critic. Return JSON only. Keep deterministic findings unless they are clearly duplicate or unsupported. Never invent object IDs.",
          user: JSON.stringify({
            expectedShape:
              "{ decisions: [{ findingId, action: 'keep'|'downgrade'|'drop', severity?: 'info'|'low'|'medium'|'high'|'critical', reason }] }",
            findings: input.findings.map((finding) => ({
              confidence: finding.confidence,
              description: finding.description,
              evidence: finding.evidence,
              id: finding.id,
              ruleId: finding.ruleId,
              severity: finding.severity,
              title: finding.title,
            })),
            packageSummary: input.packageSummary,
            sourceSummary: input.sourceContext
              ? summarizeSourceContext(input.sourceContext)
              : undefined,
          }),
        });
        return normalizeCriticDecisions(payload, input.findings);
      },
    },
    findingAgent: {
      analyze: async (input) => {
        const [researcher, exploit] = await Promise.all([
          runLlmFindingAgent(config, "researcher", input),
          runLlmFindingAgent(config, "exploit", input),
        ]);
        return [...researcher, ...exploit];
      },
    },
  };
}

async function runLlmFindingAgent(
  config: RuntimeConfig,
  agent: "exploit" | "researcher",
  input: {
    deterministicFindings: AuditFinding[];
    memories: ExploitMemory[];
    packageSummary: PackageSummary;
    sourceContext?: SourceContext;
    snapshot: NormalizedPackageSnapshot;
  },
) {
  const system =
    agent === "researcher"
      ? "You are a Move security research agent. Look for architectural risk, access-control mistakes, shared-object lifecycle problems, upgrade/admin surfaces, and missing invariants. Return JSON only."
      : "You are an exploit hypothesis agent for Sui Move. Think like an attacker, but only report plausible issues supported by normalized module metadata or provided source snippets. Return JSON only.";
  const payload = await callLlmJson(config, {
    system,
    user: JSON.stringify({
      deterministicFindings: input.deterministicFindings.map((finding) => ({
        evidence: finding.evidence,
        ruleId: finding.ruleId,
        severity: finding.severity,
        title: finding.title,
      })),
      expectedShape:
        "{ findings: [{ title, severity, confidence, likelihood, category, impact, description, recommendation, patchSuggestion, remediationSteps: string[], testSuggestions: string[], exploitPath: string[], ruleId, evidence: [{ moduleName, functionName?, structName?, filePath?, lineStart?, lineEnd?, codeSnippet?, detail }] }] }",
      memories: input.memories.slice(0, 6),
      packageSummary: input.packageSummary,
      source: input.sourceContext
        ? {
            snippets: compactSourceContext(
              input.sourceContext,
              input.deterministicFindings,
            ),
            summary: summarizeSourceContext(input.sourceContext),
          }
        : undefined,
      snapshot: compactSnapshot(input.snapshot),
    }),
  });
  const drafts = readArray(payload, "findings").slice(0, 6);
  return drafts.map((draft, index) =>
    normalizeAgentFinding(agent, index, draft as LlmFindingDraft, input),
  );
}

async function callLlmJson(
  config: RuntimeConfig,
  input: { system: string; user: string },
): Promise<Record<string, unknown>> {
  const baseUrl = (config.llmBaseUrl ?? "https://api.openai.com/v1").replace(/\/$/, "");
  const model = config.llmModel ?? "gpt-4.1-mini";
  const response = await fetch(`${baseUrl}/chat/completions`, {
    body: JSON.stringify({
      messages: [
        { content: input.system, role: "system" },
        { content: input.user, role: "user" },
      ],
      model,
      response_format: { type: "json_object" },
      temperature: 0.1,
    }),
    headers: {
      authorization: `Bearer ${config.llmApiKey}`,
      "content-type": "application/json",
    },
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(`LLM provider returned HTTP ${response.status}.`);
  }
  const payload = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  const content = payload.choices?.[0]?.message?.content;
  if (!content) throw new Error("LLM provider did not return JSON content.");
  return JSON.parse(stripJsonFence(content)) as Record<string, unknown>;
}

function normalizeAgentFinding(
  agent: "exploit" | "researcher",
  index: number,
  draft: LlmFindingDraft,
  input: { memories: ExploitMemory[]; snapshot: NormalizedPackageSnapshot },
): AuditFinding {
  const title = stringOr(draft.title, `${agent} review item`);
  const ruleId = stringOr(draft.ruleId, `AI_${agent.toUpperCase()}_${slug(title)}`).toUpperCase();
  const evidence = normalizeEvidence(draft.evidence, input.snapshot);
  const memoryReferences = input.memories.slice(0, 3).map(({ id, summary }) => ({ id, summary }));
  return {
    attackPrerequisites: stringArrayOr(draft.attackPrerequisites),
    category: optionalString(draft.category),
    confidence: confidenceOr(draft.confidence, "medium"),
    description: stringOr(
      draft.description,
      "An AI agent flagged this area for manual Move security review.",
    ),
    evidence,
    exploitPath: stringArrayOr(draft.exploitPath),
    id: `ai:${agent}:${index}:${slug(title)}`,
    impact: optionalString(draft.impact),
    likelihood: confidenceOr(draft.likelihood, "medium"),
    memoryAssisted: memoryReferences.length > 0,
    memoryReferences,
    patchSuggestion: optionalString(draft.patchSuggestion),
    recommendation: stringOr(
      draft.recommendation,
      "Review the affected module manually and add explicit authorization or invariant checks.",
    ),
    remediationSteps: stringArrayOr(draft.remediationSteps),
    ruleId,
    severity: severityOr(draft.severity, agent === "exploit" ? "high" : "medium") ?? "medium",
    testSuggestions: stringArrayOr(draft.testSuggestions),
    title,
  };
}

function normalizeEvidence(value: unknown, snapshot: NormalizedPackageSnapshot) {
  const fallbackModule = snapshot.modules[0]?.name ?? "package";
  const items = Array.isArray(value) && value.length > 0 ? value : [];
  if (items.length === 0) {
    return [{ detail: "AI agent flagged package-level risk from normalized metadata.", moduleName: fallbackModule }];
  }
  return items.slice(0, 4).map((item) => {
    if (!item || typeof item !== "object") {
      return { detail: String(item), moduleName: fallbackModule };
    }
    const evidence = item as Record<string, unknown>;
    return {
      codeSnippet: optionalString(evidence.codeSnippet),
      detail: stringOr(evidence.detail, "AI agent evidence from normalized metadata."),
      filePath: optionalString(evidence.filePath),
      functionName: optionalString(evidence.functionName),
      lineEnd: optionalNumber(evidence.lineEnd),
      lineStart: optionalNumber(evidence.lineStart),
      moduleName: stringOr(evidence.moduleName, fallbackModule),
      structName: optionalString(evidence.structName),
    };
  });
}

function normalizeCriticDecisions(
  payload: Record<string, unknown>,
  findings: AuditFinding[],
): CriticDecision[] {
  const ids = new Set(findings.map((finding) => finding.id));
  return readArray(payload, "decisions")
    .map((draft): LlmCriticDraft => draft as LlmCriticDraft)
    .filter((draft) => typeof draft.findingId === "string" && ids.has(draft.findingId))
    .map((draft): CriticDecision => {
      const action: CriticDecision["action"] =
        draft.action === "drop" || draft.action === "downgrade"
          ? draft.action
          : "keep";
      return {
        action,
        findingId: String(draft.findingId),
        reason: stringOr(draft.reason, "Reviewed by AI critic agent."),
        severity: severityOr(draft.severity, undefined),
      };
    })
    .filter((decision) => decision.action !== "downgrade" || decision.severity);
}

function compactSnapshot(snapshot: NormalizedPackageSnapshot) {
  return {
    ...snapshot,
    modules: snapshot.modules.slice(0, 20).map((module) => ({
      functions: module.functions.slice(0, 40),
      name: module.name,
      structs: module.structs.slice(0, 30),
    })),
  };
}

function compactSourceContext(
  sourceContext: SourceContext,
  findings: AuditFinding[] = [],
) {
  const evidencePaths = new Set(
    findings.flatMap((finding) =>
      finding.evidence.map((evidence) => evidence.filePath).filter(Boolean),
    ),
  );
  const prioritized = [...sourceContext.files].sort((left, right) => {
    const leftScore = evidencePaths.has(left.path) ? 0 : 1;
    const rightScore = evidencePaths.has(right.path) ? 0 : 1;
    return leftScore - rightScore || left.path.localeCompare(right.path);
  });
  return prioritized.slice(0, 20).map((file) => ({
    content: file.content.split(/\r?\n/).slice(0, 180).join("\n").slice(0, 12_000),
    path: file.path,
    sizeBytes: file.sizeBytes,
  }));
}

function readArray(payload: Record<string, unknown>, key: string) {
  const value = payload[key];
  return Array.isArray(value) ? value : [];
}

function severityOr(value: unknown, fallback: FindingSeverity | undefined) {
  return value === "info" ||
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
    ? value
    : fallback;
}

function confidenceOr(value: unknown, fallback: FindingConfidence) {
  return value === "low" || value === "medium" || value === "high" ? value : fallback;
}

function stringOr(value: unknown, fallback: string) {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function optionalString(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stringArrayOr(value: unknown) {
  return Array.isArray(value)
    ? value.filter(
        (item): item is string => typeof item === "string" && item.trim().length > 0,
      )
    : undefined;
}

function optionalNumber(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
}

function stripJsonFence(value: string) {
  return value.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
}

function publicJob(job: LocalAuditJob) {
  return {
    createdAt: job.createdAt,
    finalizedDigest: job.finalizedDigest,
    id: job.id,
    network: job.network,
    packageId: job.packageId,
    packageSummary: job.packageSummary,
    publicReport: job.report
      ? {
          createdAt: job.report.createdAt,
          findingCount: job.report.findings.length,
          riskScore: job.report.riskScore,
          status: job.report.status,
          summary: job.report.summary,
          visibility: job.report.visibility,
        }
      : undefined,
    reportObjectId: job.reportObjectId,
    snapshotHash: job.snapshotHash,
    sourceSummary: job.report?.sourceSummary,
    sourceUrl: job.sourceUrl,
    status: job.status,
    suiJobObjectId: job.suiJobObjectId,
    suiTransactionDigest: job.suiTransactionDigest,
  };
}

function readSession(
  request: IncomingMessage,
  sessions: Map<string, { address: string; expiresAt: number }>,
) {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return undefined;
  const token = header.slice("Bearer ".length);
  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(token);
    return undefined;
  }
  return session;
}

function validatePrepareRequest(body: PreparedAuditRequest):
  | { network: Network; ok: true; packageId?: string; sourceUrl?: string }
  | { error: string; ok: false } {
  if (body.packageId && !body.sourceUrl && !isValidSuiObjectId(body.packageId)) {
    return { error: "Invalid Sui package ID. Enter a deployed package object ID like 0x....", ok: false };
  }
  if (body.sourceUrl && !isGithubUrl(body.sourceUrl)) {
    return { error: "Source URL must be a public GitHub repository URL.", ok: false };
  }
  if (!body.packageId && !body.sourceUrl) {
    return { error: "Paste a GitHub repository URL or a deployed Sui package address.", ok: false };
  }

  return {
    network: body.network ?? DEFAULT_NETWORK,
    ok: true,
    packageId: body.packageId?.trim(),
    sourceUrl: body.sourceUrl?.trim() || undefined,
  };
}

function validateCreateAuditRequest(body: CreateAuditRequest):
  | {
      network: Network;
      ok: true;
      packageId: string;
      payer: string;
      sourceUrl?: string;
      suiJobObjectId: string;
      suiTransactionDigest: string;
    }
  | { error: string; ok: false } {
  const prepared = validatePrepareRequest(body);
  if (!prepared.ok) return prepared;
  if (!prepared.packageId) {
    return { error: "Missing prepared audit target for paid audit creation.", ok: false };
  }
  if (!body.payer || !isValidSuiObjectId(body.payer)) {
    return { error: "Missing or invalid payer wallet address.", ok: false };
  }
  if (!body.suiJobObjectId || !isValidSuiObjectId(body.suiJobObjectId)) {
    return { error: "Missing or invalid Sui AuditJob object ID.", ok: false };
  }
  if (!body.suiTransactionDigest) {
    return { error: "Missing Sui transaction digest.", ok: false };
  }
  return {
    network: prepared.network,
    ok: true,
    packageId: prepared.packageId,
    payer: body.payer,
    sourceUrl: prepared.sourceUrl,
    suiJobObjectId: body.suiJobObjectId,
    suiTransactionDigest: body.suiTransactionDigest,
  };
}

function getRpcUrl(config: RuntimeConfig) {
  return config.suiRpcUrl ?? getJsonRpcFullnodeUrl(config.network);
}

function vectorBytes(tx: Transaction, value: string) {
  return tx.pure.vector("u8", Array.from(new TextEncoder().encode(value)));
}

function readExecutedDigest(result: unknown) {
  if (
    result &&
    typeof result === "object" &&
    "Transaction" in result &&
    result.Transaction &&
    typeof result.Transaction === "object" &&
    "digest" in result.Transaction &&
    typeof result.Transaction.digest === "string"
  ) {
    return result.Transaction.digest;
  }
  if (
    result &&
    typeof result === "object" &&
    "digest" in result &&
    typeof result.digest === "string"
  ) {
    return result.digest;
  }
  throw new Error("Sui finalization response did not include a digest.");
}

function sendJson(response: ServerResponse, status: number, value: unknown) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

async function readJson<T>(request: IncomingMessage) {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return (raw ? JSON.parse(raw) : {}) as T;
}

async function createAuditId(transactionDigest: string, snapshotHash: string) {
  const { sha256Hex } = await import("@repo/sui-integration");
  return `audit-${(await sha256Hex(`${transactionDigest}:${snapshotHash}`)).slice(2, 14)}`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 8787);
  createTuskscanApiServer().listen(port, () => {
    console.log(`TuskScan API listening on http://localhost:${port}`);
  });
}
