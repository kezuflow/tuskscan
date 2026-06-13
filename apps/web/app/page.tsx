"use client";

import {
  ConnectButton,
  useCurrentAccount,
  useSignAndExecuteTransaction,
  useSignPersonalMessage,
  useSuiClient,
} from "@mysten/dapp-kit";
import { Transaction } from "@mysten/sui/transactions";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

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
  sandboxTestRun?: {
    generatedTestFile?: string;
    note: string;
    packagePath?: string;
    status: string;
    testsAttempted: number;
  };
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

type TerminalLog = {
  id: number;
  section: "SYSTEM" | "AUTH" | "SCAN" | "PAYMENT" | "REPORT";
  text: string;
  tone?: "normal" | "success" | "warning" | "error";
};

type ParsedCommand = {
  sourceUrl?: string;
  target?: string;
};

const apiBase = process.env.NEXT_PUBLIC_TUSKSCAN_API_URL ?? "http://localhost:8787";
const contractPackageId = process.env.NEXT_PUBLIC_TUSKSCAN_PACKAGE_ID;
const configObjectId = process.env.NEXT_PUBLIC_TUSKSCAN_CONFIG_ID;
const network = process.env.NEXT_PUBLIC_TUSKSCAN_NETWORK === "mainnet" ? "mainnet" : "testnet";
const samplePackage =
  "0x0000000000000000000000000000000000000000000000000000000000000002";
const bannerText = "TUSKSCAN";

export default function Home() {
  const account = useCurrentAccount();
  const suiClient = useSuiClient();
  const signAndExecute = useSignAndExecuteTransaction();
  const signPersonalMessage = useSignPersonalMessage();
  const [audit, setAudit] = useState<AuditJob | null>(null);
  const [command, setCommand] = useState("");
  const [error, setError] = useState("");
  const [packageId, setPackageId] = useState("");
  const [prepared, setPrepared] = useState<PreparedAudit | null>(null);
  const [privateReport, setPrivateReport] = useState(false);
  const [sourceUrl, setSourceUrl] = useState("");
  const [state, setState] = useState<AuditState>("idle");
  const [terminalLogs, setTerminalLogs] = useState<TerminalLog[]>(initialLogs);
  const [walletAudits, setWalletAudits] = useState<AuditJob[]>([]);
  const logId = useRef(initialLogs.length + 1);
  const previousWallet = useRef<string | null>(null);

  const walletLabel = account ? shorten(account.address) : "[ DISCONNECTED ]";
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

  const appendLogs = useCallback((entries: Omit<TerminalLog, "id">[]) => {
    entries.forEach((entry, index) => {
      window.setTimeout(() => {
        setTerminalLogs((current) => [
          ...current.slice(-90),
          { ...entry, id: logId.current++ },
        ]);
      }, index * 180);
    });
  }, []);

  useEffect(() => {
    if (account?.address && previousWallet.current !== account.address) {
      appendLogs([
        {
          section: "AUTH",
          text: `Wallet authenticated: ${shorten(account.address)}`,
          tone: "success",
        },
        {
          section: "SYSTEM",
          text: "Neural exploit engine access granted. Awaiting scan target.",
        },
      ]);
    }
    if (!account?.address && previousWallet.current) {
      appendLogs([
        {
          section: "AUTH",
          text: "Wallet session disconnected. Payment and private reports locked.",
          tone: "warning",
        },
      ]);
    }
    previousWallet.current = account?.address ?? null;
  }, [account?.address, appendLogs]);

  async function preparePackage(input?: { packageId?: string; sourceUrl?: string }) {
    const targetPackage = (input?.packageId ?? packageId).trim();
    const targetSource = (input?.sourceUrl ?? sourceUrl).trim();

    if (!targetPackage) {
      const message = "No Sui package address supplied. Paste a deployed package address before PREPARE.";
      setError(message);
      appendLogs([{ section: "SCAN", text: message, tone: "error" }]);
      return;
    }

    setError("");
    setPackageId(targetPackage);
    setSourceUrl(targetSource);
    setState("preparing");
    appendLogs([
      { section: "SCAN", text: `Preparing package snapshot: ${shorten(targetPackage)}` },
      {
        section: "SCAN",
        text: targetSource
          ? `Source channel staged: ${targetSource}`
          : "Source channel empty. Proceeding with onchain package metadata.",
      },
    ]);

    try {
      const response = await postJson<PreparedAudit>("/api/audits/prepare", {
        network,
        packageId: targetPackage,
        sourceUrl: targetSource || undefined,
      });
      setPrepared(response);
      setAudit(null);
      setState("prepared");
      appendLogs([
        {
          section: "SCAN",
          text: `Snapshot ready: ${response.packageSummary.moduleCount} modules / ${response.packageSummary.functionCount} functions.`,
          tone: "success",
        },
        {
          section: "PAYMENT",
          text: `Price quote received: ${response.priceMist} MIST. Execute PAY_AND_RUN when ready.`,
        },
      ]);
    } catch (caught) {
      const message = errorMessage(caught);
      setError(message);
      setState("failed");
      appendLogs([{ section: "SCAN", text: message, tone: "error" }]);
    }
  }

  async function runPaidAudit() {
    if (!prepared) {
      appendLogs([
        {
          section: "PAYMENT",
          text: "No prepared package found. Paste a package address or run PREPARE after staging one.",
          tone: "warning",
        },
      ]);
      return;
    }
    setError("");
    setState("paying");
    appendLogs([{ section: "PAYMENT", text: "Payment transaction requested from wallet." }]);

    if (!account) {
      const message = "Connect a Sui wallet before paying.";
      setError(message);
      setState("failed");
      appendLogs([{ section: "AUTH", text: message, tone: "error" }]);
      return;
    }

    try {
      const payment = await createAuditJobPayment({
        packageId: prepared.packageSummary.packageId,
        priceMist: prepared.priceMist,
        snapshotHash: prepared.snapshotHash,
      });
      setState("running");
      appendLogs([
        {
          section: "PAYMENT",
          text: `Transaction sealed: ${shorten(payment.digest)}`,
          tone: "success",
        },
        { section: "SCAN", text: "Audit workers online. Recalling exploit memories." },
      ]);
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
      appendLogs([
        {
          section: "REPORT",
          text: `Report unlocked: risk ${reportPayload.report.riskScore}/100, ${reportPayload.report.findings.length} findings.`,
          tone: "success",
        },
      ]);
    } catch (caught) {
      const message = errorMessage(caught);
      setError(message);
      setState("failed");
      appendLogs([{ section: "PAYMENT", text: message, tone: "error" }]);
    }
  }

  async function waitForAuditCompletion(auditId: string) {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const job = await getJson<AuditJob>(`/api/audits/${auditId}`);
      setAudit(job);
      if (attempt === 0 || attempt % 5 === 0) {
        appendLogs([{ section: "SCAN", text: `Audit job ${auditId} status: ${job.status}` }]);
      }
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
    appendLogs([{ section: "AUTH", text: "Requesting private audit index for wallet." }]);
    if (!account) {
      const message = "Connect a Sui wallet before loading audits.";
      setError(message);
      appendLogs([{ section: "AUTH", text: message, tone: "error" }]);
      return;
    }

    try {
      const token = await createPrivateReportSession(account.address);
      const payload = await getJsonWithAuth<{ audits: AuditJob[] }>(
        `/api/audits?wallet=${encodeURIComponent(account.address)}`,
        token,
      );
      setWalletAudits(payload.audits);
      appendLogs([
        {
          section: "REPORT",
          text: `${payload.audits.length} wallet audit record(s) loaded.`,
          tone: "success",
        },
      ]);
      if (payload.audits[0]) {
        await loadAuditReport(payload.audits[0], token);
      }
    } catch (caught) {
      const message = errorMessage(caught);
      setError(message);
      appendLogs([{ section: "REPORT", text: message, tone: "error" }]);
    }
  }

  async function loadAuditReport(job: AuditJob, token?: string) {
    if (!account && !token) {
      const message = "Connect a Sui wallet before loading a private report.";
      setError(message);
      appendLogs([{ section: "AUTH", text: message, tone: "error" }]);
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
    appendLogs([
      {
        section: "REPORT",
        text: `Loaded report ${shorten(job.id)} with ${reportPayload.report.findings.length} finding(s).`,
        tone: "success",
      },
    ]);
  }

  function handleCommandSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsed = parseCommand(command);
    const trimmed = command.trim();

    if (!trimmed) return;

    appendLogs([{ section: "SYSTEM", text: `tuskscan (~/scan) $ ${trimmed}` }]);
    setCommand("");

    if (parsed.sourceUrl && !parsed.target) {
      setSourceUrl(parsed.sourceUrl);
      appendLogs([
        { section: "SCAN", text: `Source staged: ${parsed.sourceUrl}`, tone: "success" },
        { section: "SCAN", text: "Add a deployed Sui package address to bind source to an onchain scan." },
      ]);
      return;
    }

    if (!parsed.target) {
      appendLogs([
        {
          section: "SCAN",
          text: "Unable to parse input. Paste a GitHub repo URL, a Sui package address, or both.",
          tone: "error",
        },
      ]);
      return;
    }

    void preparePackage({
      packageId: parsed.target,
      sourceUrl: parsed.sourceUrl ?? sourceUrl,
    });
  }

  function fillDemo() {
    setPackageId(samplePackage);
    setSourceUrl("");
    setCommand(samplePackage);
    appendLogs([
      {
        section: "SYSTEM",
        text: `Demo package loaded. Submit command or run PREPARE: ${shorten(samplePackage)}`,
      },
    ]);
  }

  return (
    <main className={styles.shell}>
      <div className={styles.crtOverlay} />
      <header className={styles.topBar}>
        <div>
          <span className={styles.brand}>TUSKSCAN // AI VULNERABILITY CORE</span>
          <span className={styles.topStatus}>SYSTEM STATUS: {stateLabel(state).toUpperCase()}</span>
        </div>
        <div className={styles.walletBox}>
          <ConnectButton connectText="CONNECT_WALLET" />
        </div>
      </header>

      <section className={styles.terminal}>
        <section className={styles.bootPanel} aria-label="TuskScan terminal">
          <div className={styles.arcadeMasthead}>
            <div className={styles.brandPlate}>
              <h1 className={styles.banner}>{bannerText}</h1>
            </div>
          </div>

          <div className={styles.cockpitGrid}>
            <section className={styles.miniPanel}>
              <h2>SYSTEM STATUS</h2>
              <p>- SYSTEM: {stateLabel(state).toUpperCase()}</p>
              <p>- ENGINE: READY</p>
              <p>- MODE  : SCAN</p>
            </section>
            <section className={styles.miniPanel}>
              <h2>WALLET</h2>
              <p>- STATUS: {account ? "CONNECTED" : "DISCONNECTED"}</p>
              <p>- ADDR  : {walletLabel}</p>
              <p>- NET   : SUI_{network.toUpperCase()}</p>
            </section>
          </div>

          <div className={styles.consolePanel}>
            <h2>CONSOLE OUTPUT</h2>
            <div className={styles.logStream} aria-live="polite">
            {terminalLogs.map((line) => (
              <p className={toneClass(line.tone, styles)} key={line.id}>
                <span>[{line.section}]</span> &gt; {line.text}
              </p>
            ))}
            {error ? (
              <p className={styles.errorLine}>
                <span>[ERROR]</span> &gt; {error}
              </p>
            ) : null}
            </div>
          </div>

          <form className={styles.promptForm} onSubmit={handleCommandSubmit}>
            <label htmlFor="scan-command">tuskscan (~/scan) $</label>
            <input
              autoComplete="off"
              id="scan-command"
              onChange={(event) => setCommand(event.target.value)}
              placeholder="github.com/org/repo or Sui package address"
              spellCheck={false}
              value={command}
            />
            <span aria-hidden="true" className={styles.cursor} />
            <button type="submit">EXEC</button>
          </form>
          <p className={styles.hint}>
            paste a GitHub repo, a Sui package address, or both in one line
          </p>

          <div className={styles.actions}>
            <button disabled={state === "preparing"} onClick={() => void preparePackage()} type="button">
              [ PREPARE ]
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
              [ PAY_AND_RUN ]
            </button>
            <button
              disabled={!account || signPersonalMessage.isPending}
              onClick={loadWalletAudits}
              type="button"
            >
              [ LOAD_MY_AUDITS ]
            </button>
            <button onClick={fillDemo} type="button">
              [ FILL_DEMO ]
            </button>
          </div>
        </section>

        {prepared || audit ? (
          <>
            <section className={styles.statusPanel}>
              <div className={styles.metricLine}>
                <span>MODULES</span>
                <strong>{prepared?.packageSummary.moduleCount ?? "--"}</strong>
              </div>
              <div className={styles.metricLine}>
                <span>FUNCTIONS</span>
                <strong>{prepared?.packageSummary.functionCount ?? "--"}</strong>
              </div>
              <div className={styles.metricLine}>
                <span>SOURCE_FILES</span>
                <strong>
                  {prepared?.sourceSummary?.moveFileCount ??
                    audit?.report?.sourceSummary?.moveFileCount ??
                    "--"}
                </strong>
              </div>
              <div className={styles.metricLine}>
                <span>RISK</span>
                <strong>{audit ? `${riskScore}/100` : "--"}</strong>
              </div>
            </section>

            <section className={styles.panelGrid}>
              <section className={styles.terminalPanel}>
                <h2>[ SCAN_TIMELINE ]</h2>
                <ol className={styles.timeline}>
                  {timeline(state).map((item) => (
                    <li className={item.done ? styles.done : ""} key={item.label}>
                      <span>{String(item.step).padStart(2, "0")}</span>
                      {item.label}
                    </li>
                  ))}
                </ol>
              </section>

              <section className={styles.terminalPanel}>
                <h2>[ WALRUS_SUI_PROOF ]</h2>
                <dl className={styles.proofList}>
                  <div>
                    <dt>SUI_REPORT_JOB</dt>
                    <dd>{audit?.suiJobObjectId ?? `pending ${network} payment`}</dd>
                  </div>
                  <div>
                    <dt>TRANSACTION</dt>
                    <dd>{audit?.suiTransactionDigest ?? "pending"}</dd>
                  </div>
                  {proofRows.slice(0, 4).map((row) => (
                    <div key={row.name}>
                      <dt>{row.name.toUpperCase()}</dt>
                      <dd>{row.uri}</dd>
                    </div>
                  ))}
                </dl>
              </section>
            </section>
          </>
        ) : null}

        {walletAudits.length ? (
          <section className={styles.terminalPanel}>
            <h2>[ COMMAND_HISTORY ]</h2>
            <div className={styles.history}>
              {walletAudits.slice(0, 5).map((item) => (
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
          </section>
        ) : null}

        {audit ? (
        <section className={styles.terminalPanel}>
          <div className={styles.panelHeader}>
            <h2>[ REPORT_OUTPUT ]</h2>
            <span>{privateReport ? "PRIVATE_REPORT_UNLOCKED" : "PUBLIC_SUMMARY"}</span>
          </div>

          {audit?.report ? (
            <div className={styles.reportSummary}>
              <div>
                <span>TOP_RISKS</span>
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
                <span>ACTION_PLAN</span>
                <ol>
                  {(audit.report.actionPlan ?? []).slice(0, 4).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ol>
              </div>
              {audit.report.coverage ? (
                <div>
                  <span>COVERAGE</span>
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
                <span>SOURCE_MATCH</span>
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
                <span>GENERATED_TESTS</span>
                <p>{audit.report.generatedExploitTests?.length ?? 0} exploit drafts</p>
                {audit.report.generatedExploitTests?.[0] ? (
                  <small>{audit.report.generatedExploitTests[0].command}</small>
                ) : null}
              </div>
              <div>
                <span>SANDBOX</span>
                <p>{audit.report.sandboxTestRun?.status ?? "disabled"}</p>
                <small>
                  {audit.report.sandboxTestRun
                    ? `${audit.report.sandboxTestRun.testsAttempted} attempted`
                    : "Set TUSKSCAN_RUN_MOVE_TESTS=1"}
                </small>
              </div>
              <div>
                <span>AGENT_REVIEW</span>
                <p>
                  {audit.report.agentReviews?.filter((review) => review.status === "completed").length ?? 0}
                  {" "}completed stages
                </p>
                <small>
                  {audit.report.calibration?.memoryMatchedFindings ?? 0} MemWal matched findings
                </small>
              </div>
              <div>
                <span>PLAYBOOKS</span>
                <p>{audit.report.memoryPlaybooks?.length ?? 0} stored patterns</p>
                {audit.report.memoryPlaybooks?.[0] ? (
                  <small>{audit.report.memoryPlaybooks[0].id}</small>
                ) : null}
              </div>
            </div>
          ) : null}

          <div className={styles.table}>
            <div className={styles.tableHead}>
              <span>SEVERITY</span>
              <span>FINDING</span>
              <span>EVIDENCE</span>
              <span>MEMORY</span>
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
        ) : null}
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

const initialLogs: TerminalLog[] = [
  {
    id: 1,
    section: "SYSTEM",
    text: "System initialized. Awaiting Web3 authentication...",
  },
  {
    id: 2,
    section: "AUTH",
    text: "Please connect your wallet to access the neural exploit engine.",
    tone: "warning",
  },
  {
    id: 3,
    section: "SCAN",
    text: "Paste a GitHub repo, a Sui package address, or both to begin.",
  },
];

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

function parseCommand(input: string): ParsedCommand {
  const trimmed = input.trim();
  const targetMatch = trimmed.match(/--target=(\S+)/i);
  const sourceMatch = trimmed.match(/--source=(\S+)/i);
  const urlMatch = trimmed.match(/https?:\/\/\S+/i);
  const githubMatch = trimmed.match(/(?:https?:\/\/)?github\.com\/[^\s]+/i);
  const packageMatch = trimmed.match(/0x[a-f0-9]{16,}/i);
  const sourceUrl = sourceMatch?.[1] ?? urlMatch?.[0] ?? githubMatch?.[0];

  return {
    sourceUrl: sourceUrl?.startsWith("github.com") ? `https://${sourceUrl}` : sourceUrl,
    target: targetMatch?.[1] ?? packageMatch?.[0],
  };
}

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

function toneClass(tone: TerminalLog["tone"], stylesObject: Record<string, string>) {
  if (tone === "success") return stylesObject.successLine;
  if (tone === "warning") return stylesObject.warningLine;
  if (tone === "error") return stylesObject.errorLine;
  return stylesObject.logLine;
}

function shorten(value: string) {
  if (value.length <= 18) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
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
