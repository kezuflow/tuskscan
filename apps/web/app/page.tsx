"use client";

import {
  ConnectButton,
  useCurrentAccount,
  useSignPersonalMessage,
  useSignAndExecuteTransaction,
  useSuiClient,
} from "@mysten/dapp-kit";
import { Transaction } from "@mysten/sui/transactions";
import { useMemo, useState } from "react";

import styles from "./page.module.css";

type AuditState = "idle" | "preparing" | "prepared" | "paying" | "running" | "complete" | "failed";

type PackageSummary = {
  functionCount: number;
  moduleCount: number;
  network: "testnet" | "mainnet";
  packageDigest: string;
  packageId: string;
  structCount: number;
};

type PreparedAudit = {
  packageSummary: PackageSummary;
  priceMist: string;
  sourceSummary?: SourceSummary;
  snapshotHash: string;
};

type SourceSummary = {
  branch?: string;
  digest: string;
  fileCount: number;
  moveFileCount: number;
  omittedMoveFileCount?: number;
  packageRoots?: string[];
  pathPrefix?: string;
  selectedRoot?: string;
  totalMoveFileCount?: number;
  url: string;
};

type AuditReport = {
  actionPlan?: string[];
  agentReviews?: Array<{
    agent: string;
    findingsReviewed: number;
    output: string[];
    status: string;
  }>;
  artifacts?: Record<string, { blobId: string; contentHash: string; name: string }>;
  calibration?: {
    memoryMatchedFindings: number;
    note: string;
  };
  coverage?: {
    checkedModules: number;
    checkedMoveFiles: number;
    checkedPublicEntryFunctions: number;
    checkedSourceFunctions: number;
  };
  findings: Array<{
    attackPrerequisites?: string[];
    calibratedConfidence?: string;
    category?: string;
    confidence: string;
    description?: string;
    evidence: Array<{
      codeSnippet?: string;
      detail: string;
      filePath?: string;
      functionName?: string;
      lineEnd?: number;
      lineStart?: number;
      moduleName: string;
    }>;
    exploitPath?: string[];
    impact?: string;
    likelihood?: string;
    memoryAssisted: boolean;
    memoryPlaybookIds?: string[];
    patchSuggestion?: string;
    recommendation: string;
    remediationSteps?: string[];
    ruleId: string;
    severity: string;
    testSuggestions?: string[];
    title: string;
  }>;
  generatedExploitTests?: Array<{
    command: string;
    findingId: string;
    kind: string;
    name: string;
    notes: string[];
    source?: string;
    status: string;
  }>;
  memoryPlaybooks?: Array<{
    findingId: string;
    id: string;
    query: string;
    summary: string;
  }>;
  riskScore: number;
  severityBreakdown?: Record<string, number>;
  sourceConsistency?: {
    deployedModules: string[];
    level: string;
    matchedModules: string[];
    missingInSource: string[];
    note: string;
    sourceModules: string[];
  };
  sourceSummary?: SourceSummary;
  summary: string;
  topRisks?: string[];
};

type AuditJob = {
  createdAt?: string;
  finalizedDigest?: string;
  id: string;
  packageId?: string;
  publicReport?: {
    findingCount: number;
    riskScore: number;
    status: string;
    summary: string;
  };
  report?: AuditReport;
  reportObjectId?: string;
  sourceSummary?: SourceSummary;
  sourceUrl?: string;
  status: string;
  suiJobObjectId: string;
  suiTransactionDigest: string;
};

type ReportResponse = {
  markdown?: string;
  private: boolean;
  report: AuditReport;
};

const apiBase = process.env.NEXT_PUBLIC_TUSKSCAN_API_URL ?? "http://localhost:8787";
const contractPackageId = process.env.NEXT_PUBLIC_TUSKSCAN_PACKAGE_ID;
const configObjectId = process.env.NEXT_PUBLIC_TUSKSCAN_CONFIG_ID;
const network = process.env.NEXT_PUBLIC_TUSKSCAN_NETWORK === "mainnet" ? "mainnet" : "testnet";
const samplePackage =
  "0x0000000000000000000000000000000000000000000000000000000000000002";
const sampleWallet =
  "0xffbed9bd27e8e786764a015b084acf26e27b74e97602034b4765759d26f09729";

export default function Home() {
  const account = useCurrentAccount();
  const suiClient = useSuiClient();
  const signAndExecute = useSignAndExecuteTransaction();
  const signPersonalMessage = useSignPersonalMessage();
  const [audit, setAudit] = useState<AuditJob | null>(null);
  const [error, setError] = useState("");
  const [packageId, setPackageId] = useState(samplePackage);
  const [prepared, setPrepared] = useState<PreparedAudit | null>(null);
  const [privateReport, setPrivateReport] = useState(false);
  const [sourceUrl, setSourceUrl] = useState("");
  const [state, setState] = useState<AuditState>("idle");
  const [walletAudits, setWalletAudits] = useState<AuditJob[]>([]);

  const riskScore = audit?.report?.riskScore ?? 0;
  const findings = audit?.report?.findings ?? [];
  const proofRows = useMemo(() => {
    const artifacts = audit?.report?.artifacts ?? {};
    return Object.entries(artifacts).map(([name, pointer]) => ({
      hash: pointer.contentHash,
      name,
      uri: `walrus://${pointer.blobId}`,
    }));
  }, [audit]);

  async function preparePackage() {
    setError("");
    setState("preparing");
    try {
      const response = await postJson<PreparedAudit>("/api/audits/prepare", {
        network,
        packageId,
        sourceUrl: sourceUrl.trim() || undefined,
      });
      setPrepared(response);
      setAudit(null);
      setState("prepared");
    } catch (caught) {
      setError(errorMessage(caught));
      setState("failed");
    }
  }

  async function runPaidAudit() {
    if (!prepared) return;
    setError("");
    setState("paying");
    if (!account) {
      setError("Connect a Sui wallet before paying.");
      setState("failed");
      return;
    }

    try {
      const payment = await createAuditJobPayment({
        packageId: prepared.packageSummary.packageId,
        priceMist: prepared.priceMist,
        snapshotHash: prepared.snapshotHash,
      });
      setState("running");
      const created = await postJson<{ auditId: string; status: string }>("/api/audits", {
        network,
        packageId: prepared.packageSummary.packageId,
        payer: account.address,
        sourceUrl: sourceUrl.trim() || undefined,
        suiJobObjectId: payment.jobObjectId,
        suiTransactionDigest: payment.digest,
      });
      const job = await waitForAuditCompletion(created.auditId);
      const token = await createPrivateReportSession(account.address);
      const reportPayload = await getJsonWithAuth<ReportResponse>(
        `/api/audits/${created.auditId}/report`,
        token,
      );
      setPrivateReport(reportPayload.private);
      setAudit({ ...job, report: reportPayload.report });
      setState("complete");
    } catch (caught) {
      setError(errorMessage(caught));
      setState("failed");
    }
  }

  async function waitForAuditCompletion(auditId: string) {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const job = await getJson<AuditJob>(`/api/audits/${auditId}`);
      setAudit(job);
      if (job.status === "completed") return job;
      if (job.status === "failed") {
        throw new Error("Audit processing failed after payment.");
      }
      await sleep(2000);
    }
    throw new Error("Audit processing is still running. Load your audits again in a moment.");
  }

  async function loadWalletAudits() {
    setError("");
    if (!account) {
      setError("Connect a Sui wallet before loading audits.");
      return;
    }

    try {
      const token = await createPrivateReportSession(account.address);
      const payload = await getJsonWithAuth<{ audits: AuditJob[] }>(
        `/api/audits?wallet=${encodeURIComponent(account.address)}`,
        token,
      );
      setWalletAudits(payload.audits);
      if (payload.audits[0]) {
        await loadAuditReport(payload.audits[0], token);
      }
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  async function loadAuditReport(job: AuditJob, token?: string) {
    if (!account && !token) {
      setError("Connect a Sui wallet before loading a private report.");
      return;
    }
    const sessionToken = token ?? (await createPrivateReportSession(account!.address));
    const reportPayload = await getJsonWithAuth<ReportResponse>(
      `/api/audits/${job.id}/report`,
      sessionToken,
    );
    setAudit({ ...job, report: reportPayload.report });
    setPackageId(job.packageId ?? packageId);
    setSourceUrl(job.sourceUrl ?? job.report?.sourceSummary?.url ?? sourceUrl);
    setPrivateReport(reportPayload.private);
    setState("complete");
  }

  return (
    <main className={styles.shell}>
      <aside className={styles.sidebar}>
        <div>
          <p className={styles.eyebrow}>Sui Overflow / Walrus Track</p>
          <h1>TuskScan</h1>
          <p className={styles.subtitle}>
            AI pre-audits for deployed Sui Move packages. Exploit memories,
            package snapshots, and reports persist on Walrus.
          </p>
        </div>

        <nav className={styles.nav}>
          <a href="#audit">Audit</a>
          <a href="#findings">Findings</a>
          <a href="#proof">Proof</a>
        </nav>

        <div className={styles.disclaimer}>
          AI pre-audit assistance only. TuskScan is not a professional security
          audit or deployment approval.
        </div>
      </aside>

      <section className={styles.content}>
        <section className={styles.panel} id="audit">
          <div className={styles.panelHeader}>
            <div>
              <p className={styles.eyebrow}>Deployed package audit</p>
              <h2>Scan an onchain Sui package</h2>
            </div>
            <div className={styles.walletBox}>
              <ConnectButton connectText="Connect Sui" />
              <span className={styles.status}>{stateLabel(state)}</span>
            </div>
          </div>

          <div className={styles.formGrid}>
            <label className={styles.field}>
              <span>Package object ID</span>
              <input
                value={packageId}
                onChange={(event) => setPackageId(event.target.value)}
                placeholder="0x..."
              />
            </label>

            <label className={styles.field}>
              <span>GitHub source URL</span>
              <input
                value={sourceUrl}
                onChange={(event) => setSourceUrl(event.target.value)}
                placeholder="https://github.com/org/repo/tree/main/contracts"
              />
            </label>

            <label className={styles.field}>
              <span>Connected wallet</span>
              <input
                value={account?.address ?? ""}
                onChange={() => undefined}
                placeholder={sampleWallet}
                readOnly
              />
            </label>
          </div>

          <div className={styles.actions}>
            <button disabled={state === "preparing"} onClick={preparePackage} type="button">
              Prepare
            </button>
            <button
              disabled={
                !account ||
                !contractPackageId ||
                !configObjectId ||
                !prepared ||
                state === "running" ||
                signAndExecute.isPending ||
                signPersonalMessage.isPending
              }
              onClick={runPaidAudit}
              type="button"
            >
              Pay + Run
            </button>
            <button
              className={styles.secondary}
              disabled={!account || signPersonalMessage.isPending}
              onClick={loadWalletAudits}
              type="button"
            >
              Load my audits
            </button>
            <button
              className={styles.secondary}
              onClick={() => {
                setPackageId(samplePackage);
                setSourceUrl("");
              }}
              type="button"
            >
              Fill demo
            </button>
          </div>

          {error ? <p className={styles.error}>{error}</p> : null}

          <div className={styles.metrics}>
            <div>
              <span>Modules</span>
              <strong>{prepared?.packageSummary.moduleCount ?? "--"}</strong>
            </div>
            <div>
              <span>Functions</span>
              <strong>{prepared?.packageSummary.functionCount ?? "--"}</strong>
            </div>
            <div>
              <span>Source files</span>
              <strong>
                {prepared?.sourceSummary?.moveFileCount ??
                  audit?.report?.sourceSummary?.moveFileCount ??
                  "--"}
              </strong>
            </div>
            <div>
              <span>Risk</span>
              <strong>{audit ? `${riskScore}/100` : "--"}</strong>
            </div>
          </div>

          {walletAudits.length ? (
            <div className={styles.history}>
              {walletAudits.slice(0, 4).map((item) => (
                <button
                  key={item.id}
                  onClick={() => {
                    void loadAuditReport(item);
                  }}
                  type="button"
                >
                  <span>{item.status}</span>
                  <strong>{item.packageId ?? item.id}</strong>
                </button>
              ))}
            </div>
          ) : null}
        </section>

        <section className={styles.grid}>
          <div className={styles.panel}>
            <div className={styles.panelHeader}>
              <h2>Workflow timeline</h2>
            </div>
            <ol className={styles.timeline}>
              {timeline(state).map((item) => (
                <li className={item.done ? styles.done : ""} key={item.label}>
                  <span>{item.step}</span>
                  {item.label}
                </li>
              ))}
            </ol>
          </div>

          <div className={styles.panel} id="proof">
            <div className={styles.panelHeader}>
              <h2>Walrus + Sui proof</h2>
            </div>
            <dl className={styles.proofList}>
              <div>
                <dt>Sui report job</dt>
                <dd>{audit?.suiJobObjectId ?? `pending ${network} payment`}</dd>
              </div>
              <div>
                <dt>Transaction</dt>
                <dd>{audit?.suiTransactionDigest ?? "pending"}</dd>
              </div>
              {proofRows.slice(0, 4).map((row) => (
                <div key={row.name}>
                  <dt>{row.name}</dt>
                  <dd>{row.uri}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>

        <section className={styles.panel} id="findings">
          <div className={styles.panelHeader}>
            <div>
              <p className={styles.eyebrow}>Memory-assisted results</p>
              <h2>Findings</h2>
            </div>
            <span className={styles.status}>
              {privateReport ? "Private report unlocked" : "Public summary"}
            </span>
          </div>

          {audit?.report ? (
            <div className={styles.reportSummary}>
              <div>
                <span>Top risks</span>
                <ul>
                  {(audit.report.topRisks?.length
                    ? audit.report.topRisks
                    : ["No critical or high severity risks detected."]
                  ).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </div>
              <div>
                <span>Action plan</span>
                <ol>
                  {(audit.report.actionPlan ?? []).slice(0, 4).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ol>
              </div>
              {audit.report.coverage ? (
                <div>
                  <span>Coverage</span>
                  <p>
                    {audit.report.coverage.checkedPublicEntryFunctions} public entries,
                    {" "}
                    {audit.report.coverage.checkedSourceFunctions} source functions,
                    {" "}
                    {audit.report.coverage.checkedMoveFiles} Move files.
                  </p>
                </div>
              ) : null}
              <div>
                <span>Source match</span>
                <p>
                  {audit.report.sourceConsistency
                    ? `${audit.report.sourceConsistency.level}: ${audit.report.sourceConsistency.matchedModules.length}/${audit.report.sourceConsistency.deployedModules.length} modules`
                    : "No source consistency check."}
                </p>
                {audit.report.sourceSummary?.selectedRoot ? (
                  <small>{audit.report.sourceSummary.selectedRoot}</small>
                ) : null}
              </div>
              <div>
                <span>Generated tests</span>
                <p>
                  {audit.report.generatedExploitTests?.length ?? 0} exploit drafts
                </p>
                {audit.report.generatedExploitTests?.[0] ? (
                  <small>{audit.report.generatedExploitTests[0].command}</small>
                ) : null}
              </div>
              <div>
                <span>Agent review</span>
                <p>
                  {audit.report.agentReviews?.filter((review) => review.status === "completed").length ?? 0}
                  {" "}completed stages
                </p>
                <small>
                  {audit.report.calibration?.memoryMatchedFindings ?? 0} MemWal matched findings
                </small>
              </div>
              <div>
                <span>Playbooks</span>
                <p>{audit.report.memoryPlaybooks?.length ?? 0} stored patterns</p>
                {audit.report.memoryPlaybooks?.[0] ? (
                  <small>{audit.report.memoryPlaybooks[0].id}</small>
                ) : null}
              </div>
            </div>
          ) : null}

          <div className={styles.table}>
            <div className={styles.tableHead}>
              <span>Severity</span>
              <span>Finding</span>
              <span>Evidence</span>
              <span>Memory</span>
            </div>
            {(findings.length ? findings : emptyFindings).map((finding) => (
              <div className={styles.tableRow} key={`${finding.ruleId}-${finding.title}`}>
                <span className={severityClass(finding.severity, styles)}>
                  {finding.severity}
                </span>
                <span>
                  <strong>{finding.title}</strong>
                  <small>
                    {finding.category ? `${finding.category} / ` : ""}
                    {finding.ruleId}
                  </small>
                </span>
                <span>
                  {formatEvidence(finding.evidence[0])}
                  {finding.impact ? <small>{finding.impact}</small> : null}
                </span>
                <span>
                  {finding.memoryAssisted ? "MemWal match" : "No memory match"}
                  {finding.likelihood ? <small>Likelihood: {finding.likelihood}</small> : null}
                  {finding.calibratedConfidence ? (
                    <small>Calibrated: {finding.calibratedConfidence}</small>
                  ) : null}
                </span>
              </div>
            ))}
          </div>
        </section>
      </section>
    </main>
  );

  async function createAuditJobPayment(input: {
    packageId: string;
    priceMist: string;
    snapshotHash: string;
  }) {
    if (!contractPackageId) {
      throw new Error("NEXT_PUBLIC_TUSKSCAN_PACKAGE_ID must be configured before payment.");
    }
    if (!configObjectId) {
      throw new Error("NEXT_PUBLIC_TUSKSCAN_CONFIG_ID must be configured before payment.");
    }
    if (!account) {
      throw new Error("Connect a Sui wallet before paying.");
    }

    const tx = new Transaction();
    const [paymentCoin] = tx.splitCoins(tx.gas, [input.priceMist]);
    tx.moveCall({
      arguments: [
        tx.object(configObjectId),
        tx.pure.vector("u8", Array.from(new TextEncoder().encode(input.packageId))),
        tx.pure.vector("u8", Array.from(new TextEncoder().encode(input.snapshotHash))),
        paymentCoin,
        tx.object("0x6"),
      ],
      target: `${contractPackageId}::audit::create_audit_job`,
    });

    const result = await signAndExecute.mutateAsync({
      chain: `sui:${network}`,
      transaction: tx,
    });
    const finalized = await suiClient.waitForTransaction({
      digest: result.digest,
      options: { showObjectChanges: true },
    });
    const createdJob = finalized.objectChanges?.find(
      (change) =>
        change.type === "created" &&
        "objectType" in change &&
        change.objectType === `${contractPackageId}::audit::AuditJob`,
    );

    if (!createdJob || !("objectId" in createdJob)) {
      throw new Error("Payment succeeded, but no AuditJob object was found in object changes.");
    }

    return {
      digest: result.digest,
      jobObjectId: createdJob.objectId,
    };
  }

  async function createPrivateReportSession(address: string) {
    const challenge = await postJson<{ message: string; nonce: string }>(
      "/api/auth/challenge",
      { address },
    );
    const signed = await signPersonalMessage.mutateAsync({
      message: new TextEncoder().encode(challenge.message),
    });
    const session = await postJson<{ token: string }>("/api/auth/session", {
      address,
      message: challenge.message,
      signature: signed.signature,
    });
    return session.token;
  }
}

const emptyFindings: AuditReport["findings"] = [
  {
    confidence: "n/a",
    evidence: [],
    memoryAssisted: false,
    recommendation: "",
    ruleId: "pending",
    severity: "Info",
    title: "Prepare and run an audit to load findings",
  },
];

function stateLabel(state: AuditState) {
  if (state === "idle") return "Ready";
  if (state === "preparing") return "Preparing";
  if (state === "prepared") return "Prepared";
  if (state === "paying") return "Payment";
  if (state === "running") return "Running";
  if (state === "failed") return "Failed";
  return "Complete";
}

function timeline(state: AuditState) {
  const completed = state === "complete" ? 7 : state === "running" ? 5 : state === "prepared" ? 1 : 0;
  return [
    `Package normalized from Sui ${network}`,
    "Payment transaction submitted",
    "GitHub Move source fetched when supplied",
    "Exploit memories recalled from MemWal",
    "Deterministic and source-aware rules scanned the package",
    "Report artifacts stored on Walrus",
    "Sui proof object finalized",
  ].map((label, index) => ({ done: index < completed, label, step: index + 1 }));
}

function formatEvidence(evidence: AuditReport["findings"][number]["evidence"][number] | undefined) {
  if (!evidence) return "Run an audit to load evidence.";
  const location = evidence.filePath
    ? ` (${evidence.filePath}${evidence.lineStart ? `:${evidence.lineStart}` : ""})`
    : "";
  return `${evidence.detail}${location}`;
}

function severityClass(severity: string, stylesObject: Record<string, string>) {
  if (severity.toLowerCase() === "critical") return stylesObject.critical;
  if (severity.toLowerCase() === "high") return stylesObject.high;
  if (severity.toLowerCase() === "medium") return stylesObject.medium;
  return stylesObject.info;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    body: JSON.stringify(body),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  if (!response.ok) {
    throw new Error((await response.json()).error ?? `HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${apiBase}${path}`);
  if (!response.ok) {
    throw new Error((await response.json()).error ?? `HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

async function getJsonWithAuth<T>(path: string, token: string): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    headers: { authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error((await response.json()).error ?? `HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function sleep(ms: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Unexpected error.";
}
