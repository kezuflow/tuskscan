import type {
  Network,
  NormalizedFunction,
  NormalizedModule,
  NormalizedPackageSnapshot,
  NormalizedParameter,
  NormalizedStruct,
  PackageSummary,
} from "@repo/shared";

export class SuiPackageError extends Error {
  constructor(
    public readonly code:
      | "INVALID_PACKAGE_ID"
      | "PACKAGE_NOT_FOUND"
      | "RPC_UNAVAILABLE"
      | "UNEXPECTED_RPC_RESPONSE",
    message: string,
  ) {
    super(message);
    this.name = "SuiPackageError";
  }
}

export class SuiAuditVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SuiAuditVerificationError";
  }
}

const rpcUrls: Record<Network, string> = {
  mainnet: "https://fullnode.mainnet.sui.io:443",
  testnet: "https://fullnode.testnet.sui.io:443",
};

export function getSuiRpcUrl(network: Network, override?: string) {
  return override ?? rpcUrls[network];
}

export function isValidSuiObjectId(value: string) {
  return /^0x[a-fA-F0-9]{1,64}$/.test(value.trim());
}

export function normalizeSuiObjectId(value: string) {
  const trimmed = value.trim();
  if (!isValidSuiObjectId(trimmed)) {
    throw new SuiPackageError(
      "INVALID_PACKAGE_ID",
      "Expected a Sui package object ID like 0x...",
    );
  }

  const hex = trimmed.slice(2).toLowerCase().padStart(64, "0");
  return `0x${hex}`;
}

type JsonRpcResponse<T> = {
  error?: { code: number; message: string };
  result?: T;
};

type RawSuiTransactionBlock = {
  balanceChanges?: Array<{
    amount?: string;
    coinType?: string;
    owner?: unknown;
  }>;
  effects?: {
    status?: { error?: string; status?: string };
  };
  events?: Array<{
    parsedJson?: unknown;
    type?: string;
  }>;
  objectChanges?: Array<Record<string, unknown>>;
  transaction?: {
    data?: {
      sender?: string;
    };
  };
};

type RawSuiObject = {
  data?: {
    content?: {
      dataType?: string;
      fields?: Record<string, unknown>;
      type?: string;
    };
    objectId?: string;
    owner?: unknown;
  };
  error?: unknown;
};

type RawNormalizedModules = Record<
  string,
  {
    exposedFunctions?: Record<
      string,
      {
        isEntry?: boolean;
        parameters?: unknown[];
        return?: unknown[];
        visibility?: string;
      }
    >;
    fileFormatVersion?: number;
    structs?: Record<
      string,
      {
        abilities?: { abilities?: string[] } | string[];
        fields?: Array<{ name?: string; type?: unknown }>;
      }
    >;
  }
>;

export async function fetchNormalizedPackage(options: {
  network: Network;
  packageId: string;
  rpcUrl?: string;
}): Promise<NormalizedPackageSnapshot> {
  const packageId = normalizeSuiObjectId(options.packageId);
  const rpcUrl = getSuiRpcUrl(options.network, options.rpcUrl);
  const response = await fetch(rpcUrl, {
    body: JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method: "sui_getNormalizedMoveModulesByPackage",
      params: [packageId],
    }),
    headers: { "content-type": "application/json" },
    method: "POST",
  }).catch((error: unknown) => {
    throw new SuiPackageError(
      "RPC_UNAVAILABLE",
      error instanceof Error ? error.message : "Sui RPC request failed.",
    );
  });

  if (!response.ok) {
    throw new SuiPackageError(
      "RPC_UNAVAILABLE",
      `Sui RPC returned HTTP ${response.status}.`,
    );
  }

  const payload = (await response.json()) as JsonRpcResponse<RawNormalizedModules>;
  if (payload.error) {
    const isMissing =
      payload.error.message.toLowerCase().includes("not found") ||
      payload.error.message.toLowerCase().includes("object");
    throw new SuiPackageError(
      isMissing ? "PACKAGE_NOT_FOUND" : "UNEXPECTED_RPC_RESPONSE",
      payload.error.message,
    );
  }

  if (!payload.result || typeof payload.result !== "object") {
    throw new SuiPackageError(
      "UNEXPECTED_RPC_RESPONSE",
      "Sui RPC did not return normalized modules.",
    );
  }

  const fetchedAt = new Date().toISOString();
  const modules = Object.entries(payload.result)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, module]) => normalizeModule(name, module));

  return {
    fetchedAt,
    modules,
    network: options.network,
    packageDigest: await sha256Hex(stableJson({ modules, packageId })),
    packageId,
    source: "sui-normalized-modules",
  };
}

export async function verifyAuditJobPayment(options: {
  contractPackageId: string;
  digest: string;
  jobObjectId: string;
  network: Network;
  operatorAddress: string;
  packageDigest: string;
  packageId: string;
  payer: string;
  priceMist: string;
  rpcUrl?: string;
}) {
  const contractPackageId = normalizeSuiObjectId(options.contractPackageId);
  const jobObjectId = normalizeSuiObjectId(options.jobObjectId);
  const operatorAddress = normalizeSuiObjectId(options.operatorAddress);
  const payer = normalizeSuiObjectId(options.payer);
  const packageId = options.packageId.trim();
  const rpcUrl = getSuiRpcUrl(options.network, options.rpcUrl);
  const expectedJobType = `${contractPackageId}::audit::AuditJob`;

  const tx = await suiRpc<RawSuiTransactionBlock>(rpcUrl, "sui_getTransactionBlock", [
    options.digest,
    {
      showEffects: true,
      showEvents: true,
      showInput: true,
      showBalanceChanges: true,
      showObjectChanges: true,
    },
  ]);

  if (tx.effects?.status?.status !== "success") {
    throw new SuiAuditVerificationError(
      `Sui payment transaction did not succeed: ${tx.effects?.status?.error ?? "unknown failure"}`,
    );
  }

  if (normalizeOptionalObjectId(tx.transaction?.data?.sender) !== payer) {
    throw new SuiAuditVerificationError("Sui payment sender does not match payer.");
  }

  const operatorWasPaid = (tx.balanceChanges ?? []).some((change) => {
    const owner = normalizeOptionalObjectId(readOwnerAddress(change.owner));
    const amount = BigInt(String(change.amount ?? "0"));
    return (
      owner === operatorAddress &&
      isSuiCoinType(change.coinType) &&
      amount >= BigInt(options.priceMist)
    );
  });
  if (!operatorWasPaid) {
    throw new SuiAuditVerificationError("Sui payment did not credit the configured operator address.");
  }

  const createdJob = (tx.objectChanges ?? []).find((change) => {
    return (
      change.type === "created" &&
      normalizeOptionalObjectId(String(change.objectId ?? "")) === jobObjectId &&
      change.objectType === expectedJobType
    );
  });
  if (!createdJob) {
    throw new SuiAuditVerificationError("Transaction did not create the expected AuditJob object.");
  }

  const job = await suiRpc<RawSuiObject>(rpcUrl, "sui_getObject", [
    jobObjectId,
    { showContent: true, showOwner: true },
  ]);
  const content = job.data?.content;
  if (content?.type !== expectedJobType) {
    throw new SuiAuditVerificationError("AuditJob object has unexpected type.");
  }
  if (normalizeOptionalObjectId(readOwnerAddress(job.data?.owner)) !== payer) {
    throw new SuiAuditVerificationError("AuditJob object is not owned by payer.");
  }

  const fields = content.fields ?? {};
  if (bytesToString(fields.package_id) !== packageId) {
    throw new SuiAuditVerificationError("AuditJob package ID does not match prepared package.");
  }
  if (bytesToString(fields.package_digest) !== options.packageDigest) {
    throw new SuiAuditVerificationError("AuditJob package digest does not match prepared snapshot hash.");
  }
  if (BigInt(String(fields.price_paid ?? "0")) < BigInt(options.priceMist)) {
    throw new SuiAuditVerificationError("AuditJob payment is below the required price.");
  }
  if (Number(fields.status ?? -1) !== 1) {
    throw new SuiAuditVerificationError("AuditJob is not in paid status.");
  }

  return {
    jobObjectId,
    payer,
    transactionDigest: options.digest,
  };
}

export function summarizePackage(
  snapshot: NormalizedPackageSnapshot,
): PackageSummary {
  return {
    fetchedAt: snapshot.fetchedAt,
    functionCount: snapshot.modules.reduce(
      (sum, module) => sum + module.functions.length,
      0,
    ),
    moduleCount: snapshot.modules.length,
    network: snapshot.network,
    packageDigest: snapshot.packageDigest,
    packageId: snapshot.packageId,
    structCount: snapshot.modules.reduce(
      (sum, module) => sum + module.structs.length,
      0,
    ),
  };
}

export async function hashSnapshot(snapshot: NormalizedPackageSnapshot) {
  return sha256Hex(stableJson(snapshot));
}

export function stableJson(value: unknown): string {
  if (value === undefined) {
    return "null";
  }
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(",")}]`;
  }

  return `{${Object.entries(value)
    .filter(([, nestedValue]) => nestedValue !== undefined)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, nestedValue]) => `${JSON.stringify(key)}:${stableJson(nestedValue)}`)
    .join(",")}}`;
}

export async function sha256Hex(input: string) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return `0x${Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
}

async function suiRpc<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const response = await fetch(rpcUrl, {
    body: JSON.stringify({ id: 1, jsonrpc: "2.0", method, params }),
    headers: { "content-type": "application/json" },
    method: "POST",
  }).catch((error: unknown) => {
    throw new SuiPackageError(
      "RPC_UNAVAILABLE",
      error instanceof Error ? error.message : "Sui RPC request failed.",
    );
  });

  if (!response.ok) {
    throw new SuiPackageError(
      "RPC_UNAVAILABLE",
      `Sui RPC returned HTTP ${response.status}.`,
    );
  }

  const payload = (await response.json()) as JsonRpcResponse<T>;
  if (payload.error) {
    throw new SuiPackageError("UNEXPECTED_RPC_RESPONSE", payload.error.message);
  }
  if (payload.result === undefined) {
    throw new SuiPackageError("UNEXPECTED_RPC_RESPONSE", "Sui RPC returned no result.");
  }
  return payload.result;
}

function normalizeOptionalObjectId(value: string | undefined) {
  if (!value) return undefined;
  return isValidSuiObjectId(value) ? normalizeSuiObjectId(value) : value;
}

function readOwnerAddress(owner: unknown) {
  if (!owner || typeof owner !== "object") return undefined;
  if ("AddressOwner" in owner) {
    return String((owner as { AddressOwner?: unknown }).AddressOwner);
  }
  return undefined;
}

function isSuiCoinType(value: unknown) {
  return typeof value === "string" && value.endsWith("::sui::SUI");
}

function bytesToString(value: unknown) {
  if (!Array.isArray(value)) return String(value ?? "");
  return new TextDecoder().decode(Uint8Array.from(value.map(Number)));
}

function normalizeModule(
  name: string,
  module: RawNormalizedModules[string],
): NormalizedModule {
  const functions = Object.entries(module.exposedFunctions ?? {})
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([functionName, fn]): NormalizedFunction => {
      const parameters = (fn.parameters ?? []).map(normalizeParameter);
      return {
        isEntry: Boolean(fn.isEntry),
        name: functionName,
        parameters,
        returns: (fn.return ?? []).map(typeToString),
        visibility: normalizeVisibility(fn.visibility),
      };
    });

  const structs = Object.entries(module.structs ?? {})
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([structName, struct]): NormalizedStruct => ({
      abilities: normalizeAbilities(struct.abilities),
      fields: (struct.fields ?? []).map((field) => ({
        name: field.name ?? "field",
        type: typeToString(field.type),
      })),
      name: structName,
    }));

  return { functions, name, structs };
}

function normalizeVisibility(value: string | undefined) {
  if (value === "Private") return "private";
  if (value === "Friend") return "friend";
  return "public";
}

function normalizeParameter(value: unknown): NormalizedParameter {
  const raw = typeToString(value);
  return {
    isMutableReference:
      raw.includes("MutableReference") ||
      raw.includes("&mut") ||
      raw.toLowerCase().includes("mutablereference"),
    isSharedObjectLike:
      raw.includes("UID") ||
      raw.includes("Receiving") ||
      raw.includes("sui::object") ||
      raw.toLowerCase().includes("object"),
    raw,
  };
}

function normalizeAbilities(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map(String).sort();
  }
  if (value && typeof value === "object" && "abilities" in value) {
    const abilities = (value as { abilities?: unknown }).abilities;
    return Array.isArray(abilities) ? abilities.map(String).sort() : [];
  }
  return [];
}

function typeToString(value: unknown): string {
  if (typeof value === "string") return value;
  return stableJson(value);
}
