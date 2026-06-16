"use client";

import {
  ConnectButton,
  useCurrentAccount,
  useSignAndExecuteTransaction,
  useSignPersonalMessage,
  useSuiClient,
} from "@mysten/dapp-kit";
import { Transaction } from "@mysten/sui/transactions";
import Image from "next/image";
import {
  type FormEvent,
  type MouseEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

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
  publishedPackageId?: string;
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
  artifacts?: Record<
    string,
    { blobId: string; contentHash: string; contentType?: string; name: string; storageBlobId?: string }
  >;
  calibration?: {
    memoryMatchedFindings: number;
    memoryRecordsLearned?: number;
    memoriesRecalled?: number;
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
  attempts?: number;
  createdAt?: string;
  finalizedDigest?: string;
  id: string;
  lastError?: string;
  lockedAt?: string;
  lockedBy?: string;
  lockExpiresAt?: string;
  maxAttempts?: number;
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
  section: "SYSTEM" | "AUTH" | "SCAN" | "PAYMENT" | "AGENT" | "REPORT";
  text: string;
  tone?: "normal" | "success" | "warning" | "error";
};

type ParsedCommand = {
  sourceUrl?: string;
  target?: string;
};

const configuredApiBase = process.env.NEXT_PUBLIC_TUSKSCAN_API_URL ?? "http://localhost:8787";
const productionApiBase = "https://api.tuskscan.xyz";
const localHosts = new Set(["localhost", "127.0.0.1", "::1"]);
const contractPackageId = process.env.NEXT_PUBLIC_TUSKSCAN_PACKAGE_ID;
const configObjectId = process.env.NEXT_PUBLIC_TUSKSCAN_CONFIG_ID;
const network = process.env.NEXT_PUBLIC_TUSKSCAN_NETWORK === "mainnet" ? "mainnet" : "testnet";
const suiExplorerBase =
  network === "mainnet" ? "https://suivision.xyz" : "https://testnet.suivision.xyz";
const zeroSuiAddress = "0x0000000000000000000000000000000000000000000000000000000000000000";
const bannerText = "TUSKSCAN";

function resolveApiBase() {
  if (typeof window === "undefined") return configuredApiBase;
  const currentHost = window.location.hostname;
  const isLocalPage = localHosts.has(currentHost);
  const configuredIsLocal =
    configuredApiBase.includes("localhost") ||
    configuredApiBase.includes("127.0.0.1") ||
    configuredApiBase.includes("[::1]");

  if (!isLocalPage && configuredIsLocal) return productionApiBase;
  return configuredApiBase;
}

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
  const [selectedFindingIndex, setSelectedFindingIndex] = useState(0);
  const [activeSection, setActiveSection] = useState("scan");
  const logId = useRef(initialLogs.length + 1);
  const logStreamRef = useRef<HTMLDivElement | null>(null);
  const privateReportSession = useRef<{ address: string; token: string } | null>(null);
  const terminalRef = useRef<HTMLElement | null>(null);
  const previousWallet = useRef<string | null>(null);

  const walletLabel = account ? shorten(account.address) : "[ DISCONNECTED ]";
  const riskScore = audit?.report?.riskScore ?? 0;
  const findings = audit?.report?.findings ?? [];
  const proofRows = useMemo(() => {
    const artifacts = audit?.report?.artifacts ?? {};
    return Object.entries(artifacts).map(([name, pointer]) => ({
      artifactName: name,
      downloadHref: audit ? artifactDownloadUrl(audit.id, name) : undefined,
      hash: pointer.contentHash,
      name,
      protected: name !== "publicReport",
      storageUri: pointer.storageBlobId ? `walrus://${pointer.storageBlobId}` : undefined,
      uri: `walrus://${pointer.blobId}`,
    }));
  }, [audit]);
  const preparedMoveFileCount = prepared?.sourceSummary?.moveFileCount ?? 0;
  const preparedModuleCount = prepared?.packageSummary.moduleCount ?? 0;
  const paymentDisabledReason = !account
    ? "CONNECT_WALLET_REQUIRED"
    : !contractPackageId
      ? "NEXT_PUBLIC_TUSKSCAN_PACKAGE_ID_MISSING"
      : !configObjectId
        ? "NEXT_PUBLIC_TUSKSCAN_CONFIG_ID_MISSING"
        : !prepared
          ? "LOAD_PACKAGE_REQUIRED"
          : preparedMoveFileCount < 1
            ? "NO_MOVE_SOURCE_FILES_PREPARED"
            : preparedModuleCount < 1
              ? "NO_MODULES_PREPARED"
              : state === "running"
                ? "SCAN_ALREADY_RUNNING"
                : signAndExecute.isPending || signPersonalMessage.isPending
                  ? "WALLET_REQUEST_PENDING"
                  : "";
  const paymentButtonBusy =
    state === "preparing" ||
    state === "paying" ||
    state === "running" ||
    signAndExecute.isPending ||
    signPersonalMessage.isPending;
  const visibleFindings = findings.length ? findings : emptyFindings;
  const selectedFinding =
    visibleFindings[Math.min(selectedFindingIndex, visibleFindings.length - 1)] ?? emptyFindings[0]!;
  const selectedEvidence = selectedFinding.evidence[0];
  const criticalCount = findings.filter((finding) => finding.severity.toLowerCase() === "critical").length;
  const highCount = findings.filter((finding) => finding.severity.toLowerCase() === "high").length;
  const mediumCount = findings.filter((finding) => finding.severity.toLowerCase() === "medium").length;
  const lowCount = findings.filter((finding) => finding.severity.toLowerCase() === "low").length;
  const infoCount = findings.filter((finding) => finding.severity.toLowerCase() === "info").length;
  const memoryMatchCount = findings.filter((finding) => finding.memoryAssisted).length;
  const agentReviewCount =
    audit?.report?.agentReviews?.filter((review) => review.status === "completed").length ?? 0;
  const maxSeverityCount = Math.max(criticalCount, highCount, mediumCount, lowCount, infoCount, 1);
  const severityDistribution = [
    { count: criticalCount, label: "critical" },
    { count: highCount, label: "high" },
    { count: mediumCount, label: "medium" },
    { count: lowCount, label: "low" },
    { count: infoCount, label: "info" },
  ];
  const resolvedSource =
    prepared?.sourceSummary?.url ?? audit?.sourceUrl ?? audit?.report?.sourceSummary?.url ?? sourceUrl;
  const scanProgress =
    state === "complete" ? "100%" : state === "running" ? "68%" : state === "prepared" ? "24%" : "8%";

  useEffect(() => {
    debugE2E("pay-gate", {
      account: account?.address ? shorten(account.address) : null,
      busy: paymentButtonBusy,
      configObjectId: configObjectId ? shorten(configObjectId) : null,
      contractPackageId: contractPackageId ? shorten(contractPackageId) : null,
      prepared: prepared
        ? {
            modules: prepared.packageSummary.moduleCount,
            moveFiles: prepared.sourceSummary?.moveFileCount ?? 0,
            packageId: prepared.packageSummary.packageId,
            priceMist: prepared.priceMist,
            snapshotHash: shorten(prepared.snapshotHash),
          }
        : null,
      reason: paymentDisabledReason || "READY",
      state,
    });
  }, [account?.address, paymentButtonBusy, paymentDisabledReason, prepared, state]);

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
    const logStream = logStreamRef.current;
    if (!logStream) return;
    logStream.scrollTo({ top: logStream.scrollHeight });
  }, [terminalLogs, error]);

  const scrollToSection = useCallback((sectionId: string, behavior: ScrollBehavior = "smooth") => {
    const scroller = terminalRef.current;
    const target = document.getElementById(sectionId);
    if (!scroller || !target) return;

    window.scrollTo(0, 0);
    const scrollerTop = scroller.getBoundingClientRect().top;
    const targetTop = target.getBoundingClientRect().top;
    scroller.scrollTo({
      behavior,
      top: Math.max(targetTop - scrollerTop + scroller.scrollTop, 0),
    });
    setActiveSection(sectionId);
  }, []);

  useEffect(() => {
    function syncHashToTerminal() {
      const sectionId = decodeURIComponent(window.location.hash.replace(/^#/, ""));
      if (!sectionId) return;
      requestAnimationFrame(() => scrollToSection(sectionId, "auto"));
    }

    syncHashToTerminal();
    window.addEventListener("hashchange", syncHashToTerminal);
    return () => window.removeEventListener("hashchange", syncHashToTerminal);
  }, [scrollToSection]);

  useEffect(() => {
    if (account?.address && previousWallet.current !== account.address) {
      privateReportSession.current = null;
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
      privateReportSession.current = null;
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

    if (!targetPackage && !targetSource) {
      const message = "Paste a GitHub repo URL before loading a package.";
      setError(message);
      appendLogs([{ section: "SCAN", text: message, tone: "error" }]);
      return;
    }

    setError("");
    if (targetPackage) setPackageId(targetPackage);
    setSourceUrl(targetSource);
    setState("preparing");
    appendLogs([
      {
        section: "SCAN",
        text: targetPackage
          ? `Preparing audit target: ${shorten(targetPackage)}`
          : "Building Move source snapshot from GitHub.",
      },
      {
        section: "SCAN",
        text: targetSource
          ? `Source channel staged: ${targetSource}`
          : "Source channel empty. Proceeding with onchain package metadata fallback.",
      },
    ]);

    try {
      debugE2E("prepare-request", {
        network,
        packageId: targetPackage || null,
        sourceUrl: targetSource || null,
      });
      const response = await postJson<PreparedAudit>("/api/audits/prepare", {
        network,
        packageId: targetPackage || undefined,
        sourceUrl: targetSource || undefined,
      });
      debugE2E("prepare-response", {
        modules: response.packageSummary.moduleCount,
        moveFiles: response.sourceSummary?.moveFileCount ?? 0,
        packageId: response.packageSummary.packageId,
        priceMist: response.priceMist,
        sourceUrl: response.sourceSummary?.url,
        snapshotHash: response.snapshotHash,
      });
      setPrepared(response);
      setAudit(null);
      setPackageId(response.packageSummary.packageId);
      setState("prepared");
      requestAnimationFrame(() => {
        terminalRef.current?.scrollTo({ top: 0 });
      });
      appendLogs([
        ...(targetPackage
          ? []
          : [
              {
                section: "SCAN" as const,
                text: `Resolved audit target: ${shorten(response.packageSummary.packageId)}`,
                tone: "success" as const,
              },
            ]),
        {
          section: "SCAN",
          text: `Snapshot ready: ${response.packageSummary.moduleCount} modules / ${response.packageSummary.functionCount} functions.`,
          tone: "success",
        },
        {
          section: "PAYMENT",
          text: `Price quote received: ${response.priceMist} MIST. Select RUN when ready.`,
        },
        {
          section: "PAYMENT",
          text: account
            ? "PAY_GATE: READY"
            : "PAY_GATE: CONNECT_WALLET_REQUIRED",
          tone: account ? "success" : "warning",
        },
      ]);
    } catch (caught) {
      const message = errorMessage(caught);
      debugE2E("prepare-error", { message });
      setError(message);
      setState("failed");
      appendLogs([{ section: "SCAN", text: message, tone: "error" }]);
    }
  }

  async function runPaidAudit() {
    debugE2E("pay-click", {
      busy: paymentButtonBusy,
      reason: paymentDisabledReason || "READY",
      state,
    });
    if (paymentDisabledReason) {
      setError(paymentDisabledReason);
      appendLogs([
        {
          section: "PAYMENT",
          text: `PAY_LOCK: ${paymentDisabledReason}`,
          tone: "warning",
        },
      ]);
      return;
    }
    if (!prepared) {
      appendLogs([
        {
          section: "PAYMENT",
          text: "No loaded target found. Paste a GitHub repo URL and load the package first.",
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
      const paidSourceUrl = (prepared.sourceSummary?.url ?? sourceUrl.trim()) || undefined;
      debugE2E("payment-start", {
        packageId: prepared.packageSummary.packageId,
        priceMist: prepared.priceMist,
        snapshotHash: prepared.snapshotHash,
        sourceUrl: paidSourceUrl,
      });
      const token = await getPrivateReportSession(account.address);
      const payment = await createAuditJobPayment({
        packageId: prepared.packageSummary.packageId,
        priceMist: prepared.priceMist,
        snapshotHash: prepared.snapshotHash,
      });
      debugE2E("payment-result", {
        digest: payment.digest,
        jobObjectId: payment.jobObjectId,
      });
      setState("running");
      appendLogs([
        {
          section: "PAYMENT",
          text: `Transaction sealed: ${shorten(payment.digest)}`,
          tone: "success",
        },
        { section: "AGENT", text: "Payment accepted. Agent orchestrator preparing audit job." },
        { section: "SCAN", text: "Registering paid audit with TuskScan API." },
      ]);
      const created = await postJson<{ auditId: string; status: string }>("/api/audits", {
        network,
        packageId: prepared.packageSummary.packageId,
        payer: account.address,
        sourceUrl: paidSourceUrl,
        suiJobObjectId: payment.jobObjectId,
        suiTransactionDigest: payment.digest,
      });
      debugE2E("audit-created", created);
      appendLogs([
        {
          section: "AGENT",
          text: `Job ${shorten(created.auditId)} queued. Waiting for audit worker.`,
        },
      ]);
      const job = await waitForAuditCompletion(created.auditId);
      appendLogs([{ section: "AGENT", text: "Report worker finished. Fetching private report." }]);
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
        ...agentReportLogs(reportPayload.report, job),
      ]);
    } catch (caught) {
      const message = errorMessage(caught);
      debugE2E("pay-error", { message });
      setError(message);
      setState("failed");
      appendLogs([{ section: "PAYMENT", text: message, tone: "error" }]);
    }
  }

  async function waitForAuditCompletion(auditId: string) {
    const loggedPhases = new Set<string>();
    for (let attempt = 0; attempt < 240; attempt += 1) {
      const job = await getJson<AuditJob>(`/api/audits/${auditId}`);
      debugE2E("audit-poll", {
        attempt,
        attempts: job.attempts,
        auditId,
        lastError: job.lastError,
        lockedBy: job.lockedBy,
        lockExpiresAt: job.lockExpiresAt,
        status: job.status,
      });
      setAudit(job);
      if (attempt === 0 || attempt % 5 === 0) {
        appendLogs([{ section: "SCAN", text: `Audit job ${auditId} status: ${job.status}` }]);
      }
      if (job.status === "queued" && !loggedPhases.has("queued")) {
        loggedPhases.add("queued");
        appendLogs([
          {
            section: "AGENT",
            text: "Queue monitor active. Waiting for exclusive worker claim.",
          },
        ]);
      }
      if (job.status === "running" && !loggedPhases.has("running")) {
        loggedPhases.add("running");
        appendLogs([
          {
            section: "AGENT",
            text: "Worker claimed job. Verifying paid package snapshot.",
            tone: "success",
          },
          {
            section: "AGENT",
            text: "MemWal recall agent retrieving prior exploit patterns.",
          },
          {
            section: "AGENT",
            text: "Scanner agent running deterministic Move and source-aware rules.",
          },
          {
            section: "AGENT",
            text: "Researcher/exploit agents reviewing architecture and attack paths when LLM is configured.",
          },
          {
            section: "AGENT",
            text: "Critic and patch agents triaging confidence, false positives, and remediation notes.",
          },
        ]);
      }
      if (job.status === "completed") return job;
      if (job.status === "failed") {
        throw new Error(job.lastError ?? "Audit processing failed after payment.");
      }
      await sleep(2000);
    }
    throw new Error("Audit processing is still running. Load your audits again in a moment.");
  }

  async function openArtifactDownload(row: (typeof proofRows)[number]) {
    if (!row.downloadHref) return;
    const targetWindow = window.open("about:blank", "_blank");
    if (targetWindow) {
      targetWindow.document.title = `TuskScan ${row.name}`;
      targetWindow.document.body.textContent = `Loading ${row.name} from TuskScan API...`;
    }
    try {
      if (row.protected && !account) {
        throw new Error("Connect the payer wallet to open private audit artifacts.");
      }
      const token = row.protected && account
        ? await getPrivateReportSession(account.address)
        : undefined;
      const response = await fetch(row.downloadHref, {
        headers: token ? { authorization: `Bearer ${token}` } : undefined,
      });
      if (!response.ok) {
        throw new Error(`Artifact download returned HTTP ${response.status}: ${await readErrorBody(response)}`);
      }
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      if (targetWindow) {
        targetWindow.location.href = objectUrl;
      } else {
        window.open(objectUrl, "_blank");
      }
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
      appendLogs([
        {
          section: "REPORT",
          text: `Opened readable artifact: ${row.name}`,
          tone: "success",
        },
      ]);
    } catch (caught) {
      targetWindow?.close();
      const message = errorMessage(caught);
      setError(message);
      appendLogs([{ section: "REPORT", text: message, tone: "error" }]);
    }
  }

  function handleCommandSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsed = parseCommand(command);
    const trimmed = command.trim();

    if (!trimmed) return;

    appendLogs([{ section: "SYSTEM", text: `tuskscan (~/scan) $ ${trimmed}` }]);
    setCommand("");

    if (parsed.sourceUrl && !parsed.target) {
      void preparePackage({ sourceUrl: parsed.sourceUrl });
      return;
    }

    if (!parsed.target) {
      appendLogs([
        {
          section: "SCAN",
          text: "Unable to parse input. Paste a GitHub repo URL.",
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

  function handleSectionNav(event: MouseEvent<HTMLAnchorElement>, sectionId: string) {
    event.preventDefault();
    if (window.location.hash !== `#${sectionId}`) {
      window.history.pushState(null, "", `#${sectionId}`);
    }
    scrollToSection(sectionId);
  }

  function navClass(sectionId: string) {
    return activeSection === sectionId ? styles.navActive : undefined;
  }

  return (
    <main className={styles.shell}>
      <div className={styles.crtOverlay} />
      <aside className={styles.sidebar} aria-label="TuskScan navigation">
        <div className={styles.sidebarBrand}>
          <span className={styles.logoMark}>
            <Image alt="" aria-hidden="true" height={21} src="/tusk-logo.webp" width={21} />
          </span>
          <div>
            <strong>&gt; {bannerText}</strong>
            <span>Move audit workbench</span>
          </div>
        </div>
        <nav className={styles.navList} aria-label="Scanner sections">
          <a className={navClass("scan")} href="#scan" onClick={(event) => handleSectionNav(event, "scan")}>Dashboard</a>
          <a className={navClass("findings")} href="#findings" onClick={(event) => handleSectionNav(event, "findings")}>Findings</a>
          <a className={navClass("proof")} href="#proof" onClick={(event) => handleSectionNav(event, "proof")}>Walrus / Sui proof</a>
          <a className={navClass("memwal")} href="#memwal" onClick={(event) => handleSectionNav(event, "memwal")}>MemWal</a>
          <a className={navClass("activity")} href="#activity" onClick={(event) => handleSectionNav(event, "activity")}>Agent session</a>
        </nav>
        <div className={styles.sidebarFooter}>
          <span>[PROJECT]</span>
          <strong>Sui {network} package</strong>
          <small>{account ? "[connected]" : "[wallet disconnected]"}</small>
          <div className={styles.walletBox}>
            <ConnectButton connectText="Connect wallet" />
          </div>
        </div>
      </aside>

      <section className={styles.terminal} ref={terminalRef}>
        <section className={styles.bootPanel} id="scan" aria-label="TuskScan command center">
          <div className={styles.arcadeMasthead}>
            <div className={styles.brandPlate}>
              <h1 className={styles.banner}>{bannerText} Workbench</h1>
            </div>
          </div>

          <div className={styles.commandStack}>
            <div className={styles.cockpitGrid}>
              <section className={styles.miniPanel}>
                <h2>SCAN CONTROL</h2>
                <p>State: {stateLabel(state)}</p>
                <p>Progress: {scanProgress}</p>
                <p>Agentic engine: armed</p>
              </section>
              <section className={styles.miniPanel}>
                <h2>CHAIN SESSION</h2>
                <p>Status: {account ? "Connected" : "Disconnected"}</p>
                <p>Address: {walletLabel}</p>
                <p>Network: Sui {network}</p>
              </section>
            </div>

            <form className={styles.promptForm} onSubmit={handleCommandSubmit}>
              <label htmlFor="scan-command">Source / package target</label>
              <div className={styles.commandInputRow}>
                <input
                  autoComplete="off"
                  id="scan-command"
                  onChange={(event) => setCommand(event.target.value)}
                  placeholder="github.com/org/repo/tree/main/move/package"
                  spellCheck={false}
                  value={command}
                />
                <button disabled={state === "preparing"} type="submit">[load package]</button>
                <button
                  className={styles.runButton}
                  disabled={paymentButtonBusy}
                  onClick={runPaidAudit}
                  title={paymentDisabledReason || "Pay and run audit"}
                  type="button"
                >
                  [run agentic audit]
                </button>
              </div>
              <span aria-hidden="true" className={styles.cursor} />
              <span className={styles.actionHint}>
                {paymentDisabledReason ? `RUN_LOCK: ${paymentDisabledReason}` : prepared ? "RUN_GATE: READY" : ""}
              </span>
            </form>
            <p className={styles.hint}>
              {resolvedSource
                ? `Staged source: ${resolvedSource}`
                : "Paste a GitHub repo URL; TuskScan scopes the scan to Move smart-contract packages."}
            </p>
          </div>

          <div className={styles.consolePanel} id="activity">
            <h2>AGENT SESSION LOG</h2>
            <div className={styles.logStream} ref={logStreamRef} aria-live="polite">
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
        </section>

        {state ? (
          <>
            <section className={styles.statusPanel}>
              <div className={styles.metricLine}>
                <span>MOVE_MODULES</span>
                <strong>{prepared?.packageSummary.moduleCount ?? "--"}</strong>
              </div>
              <div className={styles.metricLine}>
                <span>ENTRY_FUNCTIONS</span>
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
                <span>RISK_SCORE</span>
                <strong>{audit ? `${riskScore}/100` : "--"}</strong>
              </div>
            </section>

            <section className={styles.workbenchGrid} aria-label="Audit workbench status">
              <section className={styles.terminalPanel}>
                <div className={styles.panelHeader}>
                  <h2>[ SEVERITY_DISTRIBUTION ]</h2>
                  <span>{findings.length} findings</span>
                </div>
                <div className={styles.barList}>
                  {severityDistribution.map((item) => (
                    <div className={styles.barRow} key={item.label}>
                      <span className={severityClass(item.label, styles)}>{item.label}</span>
                      <div className={styles.barTrack}>
                        <span style={{ width: `${Math.max((item.count / maxSeverityCount) * 100, item.count ? 8 : 0)}%` }} />
                      </div>
                      <strong>{item.count}</strong>
                    </div>
                  ))}
                </div>
              </section>

              <section className={styles.terminalPanel} id="memwal">
                <div className={styles.panelHeader}>
                  <h2>[ MEMWAL_CALIBRATION ]</h2>
                  <span>{memoryMatchCount} matches</span>
                </div>
                <dl className={styles.systemList}>
                  <div>
                    <dt>memory_playbooks</dt>
                    <dd>{audit?.report?.memoryPlaybooks?.length ?? 0}</dd>
                  </div>
                  <div>
                    <dt>calibrated_findings</dt>
                    <dd>{memoryMatchCount}/{findings.length || 0}</dd>
                  </div>
                  <div>
                    <dt>agent_reviews</dt>
                    <dd>{agentReviewCount} completed</dd>
                  </div>
                  <div>
                    <dt>calibration_note</dt>
                    <dd>{audit?.report?.calibration?.note ?? "waiting for completed audit report"}</dd>
                  </div>
                </dl>
              </section>

              <section className={styles.terminalPanel}>
                <div className={styles.panelHeader}>
                  <h2>[ PROOF_INVENTORY ]</h2>
                  <span>{proofRows.length} artifacts</span>
                </div>
                <dl className={styles.systemList}>
                  <div>
                    <dt>snapshot_hash</dt>
                    <dd>{prepared?.snapshotHash ? shorten(prepared.snapshotHash) : "pending prepare"}</dd>
                  </div>
                  <div>
                    <dt>walrus_blobs</dt>
                    <dd>{proofRows.length}</dd>
                  </div>
                  <div>
                    <dt>sui_job_object</dt>
                    <dd>{audit?.suiJobObjectId ? shorten(audit.suiJobObjectId) : "pending payment"}</dd>
                  </div>
                  <div>
                    <dt>finalized_digest</dt>
                    <dd>{audit?.finalizedDigest ? shorten(audit.finalizedDigest) : "not finalized"}</dd>
                  </div>
                </dl>
              </section>
            </section>

            <section className={styles.panelGrid}>
              <section className={styles.terminalPanel}>
                <h2>[ AGENTIC_SCAN_PIPELINE ]</h2>
                <ol className={styles.timeline}>
                  {timeline(state).map((item) => (
                    <li className={item.done ? styles.done : ""} key={item.label}>
                      <span>{String(item.step).padStart(2, "0")}</span>
                      {item.label}
                    </li>
                  ))}
                </ol>
              </section>

              <section className={styles.terminalPanel} id="proof">
                <h2>[ WALRUS_STORAGE / SUI_PROOF ]</h2>
                <dl className={styles.proofList}>
                  <div>
                    <dt>SUI_REPORT_JOB</dt>
                    <dd>
                      {audit?.suiJobObjectId ? (
                        <a
                          href={suiObjectUrl(audit.suiJobObjectId)}
                          rel="noreferrer"
                          target="_blank"
                          title="Open Sui report job object"
                        >
                          {audit.suiJobObjectId}
                        </a>
                      ) : (
                        `pending ${network} payment`
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>TRANSACTION</dt>
                    <dd>
                      {audit?.suiTransactionDigest ? (
                        <a
                          href={suiTransactionUrl(audit.suiTransactionDigest)}
                          rel="noreferrer"
                          target="_blank"
                          title="Open Sui transaction"
                        >
                          {audit.suiTransactionDigest}
                        </a>
                      ) : (
                        "pending"
                      )}
                    </dd>
                  </div>
                  {proofRows.map((row) => (
                    <div key={row.name}>
                      <dt>{row.name.toUpperCase()}</dt>
                      <dd>
                        {row.downloadHref && !row.protected ? (
                          <a
                            href={row.downloadHref}
                            rel="noreferrer"
                            target="_blank"
                            title={`Open readable ${row.name}`}
                          >
                            {row.downloadHref}
                          </a>
                        ) : row.downloadHref ? (
                          <button
                            className={styles.proofLink}
                            onClick={() => void openArtifactDownload(row)}
                            title={`Open readable ${row.name}`}
                            type="button"
                          >
                            {row.downloadHref}
                          </button>
                        ) : (
                          <span>{row.uri}</span>
                        )}
                        <small>walrus artifact {row.uri}</small>
                        {row.storageUri && row.storageUri !== row.uri ? (
                          <small>stored in {row.storageUri}</small>
                        ) : null}
                      </dd>
                    </div>
                  ))}
                </dl>
              </section>
            </section>
          </>
        ) : null}

        {state ? (
        <section className={styles.terminalPanel} id="findings">
          <div className={styles.panelHeader}>
            <h2>[ FINDINGS / REPORT_OUTPUT ]</h2>
            <span>{privateReport ? "PRIVATE_REPORT_UNLOCKED" : "PUBLIC_SUMMARY"}</span>
          </div>

          {audit?.report ? (
            <div className={styles.reportSummary}>
              <div>
                  <span>TOP_RISKS</span>
                <p className={styles.severityDigest}>
                  {criticalCount} critical / {highCount} high findings
                </p>
                <ul>
                  {(audit.report.topRisks?.length
                    ? audit.report.topRisks
                    : ["No critical or high severity risks detected."]
                  ).map((item, index) => (
                    <li key={listItemKey("risk", item, index)}>{item}</li>
                  ))}
                </ul>
              </div>
              <div>
                <span>ACTION_PLAN</span>
                <ol>
                  {(audit.report.actionPlan ?? []).slice(0, 4).map((item, index) => (
                    <li key={listItemKey("action", item, index)}>{item}</li>
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
                  {audit.report.calibration?.memoriesRecalled ?? 0} recalled /{" "}
                  {audit.report.calibration?.memoryMatchedFindings ?? 0} matched
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
            {visibleFindings.map((finding, index) => (
              <button
                className={`${styles.tableRow} ${index === selectedFindingIndex ? styles.tableRowActive : ""}`}
                key={findingKey(finding, index)}
                onClick={() => setSelectedFindingIndex(index)}
                type="button"
              >
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
              </button>
            ))}
          </div>

          <aside className={styles.findingDetail} aria-label="Selected finding detail">
            <div className={styles.panelHeader}>
              <h2>Resolve insight</h2>
              <span className={severityClass(selectedFinding.severity, styles)}>
                {selectedFinding.severity}
              </span>
            </div>
            <div className={styles.detailStack}>
              <div>
                <span>Finding</span>
                <strong>{selectedFinding.title}</strong>
                <p>{selectedFinding.description ?? selectedFinding.recommendation}</p>
              </div>
              <div>
                <span>Evidence</span>
                <p>{formatEvidence(selectedEvidence)}</p>
                {selectedEvidence?.codeSnippet ? (
                  <pre className={styles.codeBlock}>{selectedEvidence.codeSnippet}</pre>
                ) : null}
              </div>
              <div>
                <span>Recommended action</span>
                <p>{selectedFinding.patchSuggestion ?? selectedFinding.recommendation}</p>
              </div>
              <div>
                <span>Confidence</span>
                <p>{selectedFinding.calibratedConfidence ?? selectedFinding.confidence}</p>
              </div>
            </div>
          </aside>
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

    debugE2E("payment-config-check", {
      configObjectId: shorten(configObjectId),
      expectedPriceMist: input.priceMist,
    });
    await assertLivePaymentConfig({
      configObjectId,
      expectedPriceMist: input.priceMist,
      suiClient,
    });
    debugE2E("payment-config-ok", {
      configObjectId: shorten(configObjectId),
      expectedPriceMist: input.priceMist,
    });

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

    debugE2E("wallet-sign-request", {
      chain: `sui:${network}`,
      packageId: input.packageId,
      priceMist: input.priceMist,
      target: `${shorten(contractPackageId)}::audit::create_audit_job`,
    });
    const result = await signAndExecute.mutateAsync({
      chain: `sui:${network}`,
      transaction: tx,
    });
    debugE2E("wallet-sign-result", { digest: result.digest });
    const finalized = await suiClient.waitForTransaction({
      digest: result.digest,
      options: { showObjectChanges: true },
    });
    debugE2E("wallet-finalized", {
      digest: result.digest,
      objectChangeTypes: finalized.objectChanges?.map((change) => change.type) ?? [],
    });
    const createdJob = finalized.objectChanges?.find(
      (change) =>
        change.type === "created" &&
        "objectType" in change &&
        isMoveType(change.objectType, contractPackageId, "audit", "AuditJob"),
    );

    if (!createdJob || !("objectId" in createdJob)) {
      debugE2E("wallet-finalized-no-job", {
        digest: result.digest,
        objectChanges: finalized.objectChanges,
      });
      throw new Error("Payment succeeded, but no AuditJob object was found in object changes.");
    }
    debugE2E("wallet-created-job", {
      objectId: createdJob.objectId,
      objectType: "objectType" in createdJob ? createdJob.objectType : null,
      owner: "owner" in createdJob ? createdJob.owner : null,
    });

    return {
      digest: result.digest,
      jobObjectId: createdJob.objectId,
    };
  }

  async function assertLivePaymentConfig(input: {
    configObjectId: string;
    expectedPriceMist: string;
    suiClient: ReturnType<typeof useSuiClient>;
  }) {
    const config = await input.suiClient.getObject({
      id: input.configObjectId,
      options: { showContent: true },
    });
    const content = config.data?.content;
    const fields =
      content && "fields" in content ? (content.fields as Record<string, unknown>) : null;
    const operator = typeof fields?.operator === "string" ? fields.operator : "";
    const priceMist = String(fields?.price_mist ?? "");
    debugE2E("live-payment-config", {
      configObjectId: shorten(input.configObjectId),
      expectedPriceMist: input.expectedPriceMist,
      operator: operator ? shorten(operator) : null,
      priceMist,
    });

    if (!operator || isZeroAddress(operator)) {
      throw new Error("Payment halted: onchain AuditConfig operator is the zero address.");
    }
    if (priceMist !== input.expectedPriceMist) {
      throw new Error(
        `Payment halted: stale price quote. Chain expects ${priceMist} MIST, app prepared ${input.expectedPriceMist} MIST. Prepare again after restarting the API.`,
      );
    }
  }

  async function getPrivateReportSession(address: string) {
    const normalizedAddress = address.toLowerCase();
    if (privateReportSession.current?.address === normalizedAddress) {
      debugE2E("auth-session-cache-hit", { address: shorten(address) });
      return privateReportSession.current.token;
    }

    appendLogs([
      {
        section: "AUTH",
        text: "Requesting one wallet signature for private report access.",
      },
    ]);
    const token = await createPrivateReportSession(address);
    privateReportSession.current = { address: normalizedAddress, token };
    appendLogs([
      {
        section: "AUTH",
        text: "Private report session unlocked for this wallet.",
        tone: "success",
      },
    ]);
    return token;
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
    text: "Paste a GitHub repo URL to begin a Move smart-contract audit.",
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
    `Move package normalized from source on Sui ${network}`,
    "Payment transaction submitted",
    "GitHub Move source fetched when supplied",
    "Exploit memories recalled from MemWal",
    "Deterministic and source-aware rules scanned the package",
    "Report artifacts stored on Walrus",
    "Sui proof object finalized",
  ].map((label, index) => ({ done: index < completed, label, step: index + 1 }));
}

function isMoveType(
  value: unknown,
  packageId: string,
  moduleName: string,
  typeName: string,
) {
  return (
    typeof value === "string" &&
    (value === `${packageId}::${moduleName}::${typeName}` ||
      value.endsWith(`::${moduleName}::${typeName}`))
  );
}

function findingKey(finding: AuditReport["findings"][number], index: number) {
  const evidence = finding.evidence[0];
  return [
    "finding",
    index,
    finding.ruleId,
    finding.title,
    evidence?.moduleName,
    evidence?.functionName,
    evidence?.filePath,
    evidence?.lineStart,
    evidence?.lineEnd,
  ]
    .filter((value) => value !== undefined && value !== "")
    .map(String)
    .join(":");
}

function listItemKey(scope: string, item: string, index: number) {
  return `${scope}:${index}:${item}`;
}

function suiObjectUrl(objectId: string) {
  return `${suiExplorerBase}/object/${encodeURIComponent(objectId)}`;
}

function suiTransactionUrl(digest: string) {
  return `${suiExplorerBase}/txblock/${encodeURIComponent(digest)}`;
}

function artifactDownloadUrl(auditId: string, artifactName: string) {
  const apiBase = resolveApiBase();
  return `${apiBase}/api/audits/${encodeURIComponent(auditId)}/artifacts/${encodeURIComponent(artifactName)}`;
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

function agentReportLogs(report: AuditReport, job: AuditJob): Omit<TerminalLog, "id">[] {
  const logs: Omit<TerminalLog, "id">[] = [];
  const memoryMatches = report.calibration?.memoryMatchedFindings ?? 0;
  const memoriesRecalled = report.calibration?.memoriesRecalled ?? 0;
  const playbookCount = report.memoryPlaybooks?.length ?? 0;
  logs.push({
    section: "AGENT",
    text: `MemWal calibration complete: ${memoriesRecalled} recalled memories, ${memoryMatches} matched findings, ${playbookCount} reusable playbooks.`,
    tone: memoryMatches > 0 ? "success" : "normal",
  });

  for (const review of report.agentReviews ?? []) {
    const status = review.status === "completed" ? "completed" : "not configured";
    const output = review.output[0] ? ` ${review.output[0]}` : "";
    logs.push({
      section: "AGENT",
      text: `${formatAgentName(review.agent)} ${status}; reviewed ${review.findingsReviewed} findings.${output}`,
      tone: review.status === "completed" ? "success" : "warning",
    });
  }

  if (report.generatedExploitTests?.length || report.sandboxTestRun) {
    logs.push({
      section: "AGENT",
      text: `Patch/test agent drafted ${report.generatedExploitTests?.length ?? 0} exploit tests; sandbox status ${report.sandboxTestRun?.status ?? "disabled"}.`,
      tone: report.sandboxTestRun?.status === "completed" ? "success" : "normal",
    });
  }

  const artifactCount = Object.keys(report.artifacts ?? {}).length;
  logs.push({
    section: "AGENT",
    text: `Walrus writer stored ${artifactCount} report artifacts; ${job.finalizedDigest ? `Sui proof finalized ${shorten(job.finalizedDigest)}.` : "Sui proof finalization pending."}`,
    tone: job.finalizedDigest ? "success" : "warning",
  });

  return logs;
}

function formatAgentName(agent: string) {
  return agent
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function shorten(value: string) {
  if (value.length <= 18) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

function isZeroAddress(value: string) {
  try {
    return BigInt(value) === 0n || value.toLowerCase() === zeroSuiAddress;
  } catch {
    return value.toLowerCase() === zeroSuiAddress;
  }
}

function debugE2E(event: string, payload?: unknown) {
  if (typeof window === "undefined") return;
  console.info(`[TuskScan:E2E] ${event}`, payload ?? {});
}

function sanitizeApiBody(body: unknown) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return body;
  const sanitized = { ...(body as Record<string, unknown>) };
  if ("signature" in sanitized) sanitized.signature = "[redacted]";
  if ("message" in sanitized && typeof sanitized.message === "string") {
    sanitized.message = "[redacted]";
  }
  return sanitized;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  let response: Response;
  const apiBase = resolveApiBase();
  try {
    debugE2E("api-request", {
      body: sanitizeApiBody(body),
      method: "POST",
      path,
    });
    response = await fetch(`${apiBase}${path}`, {
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
  } catch (error) {
    debugE2E("api-network-error", {
      error: errorMessage(error),
      method: "POST",
      path,
    });
    throw new Error(
      `API request failed for ${path}: ${errorMessage(error)} Check that TuskScan API is running at ${apiBase}.`,
    );
  }
  debugE2E("api-response", {
    method: "POST",
    ok: response.ok,
    path,
    status: response.status,
  });
  if (!response.ok) {
    throw new Error(`API ${path} returned HTTP ${response.status}: ${await readErrorBody(response)}`);
  }
  return response.json() as Promise<T>;
}

async function getJson<T>(path: string): Promise<T> {
  const apiBase = resolveApiBase();
  debugE2E("api-request", { method: "GET", path });
  const response = await fetch(`${apiBase}${path}`);
  debugE2E("api-response", {
    method: "GET",
    ok: response.ok,
    path,
    status: response.status,
  });
  if (!response.ok) {
    throw new Error(`API ${path} returned HTTP ${response.status}: ${await readErrorBody(response)}`);
  }
  return response.json() as Promise<T>;
}

async function getJsonWithAuth<T>(path: string, token: string): Promise<T> {
  const apiBase = resolveApiBase();
  debugE2E("api-request", { auth: "bearer:[redacted]", method: "GET", path });
  const response = await fetch(`${apiBase}${path}`, {
    headers: { authorization: `Bearer ${token}` },
  });
  debugE2E("api-response", {
    method: "GET",
    ok: response.ok,
    path,
    status: response.status,
  });
  if (!response.ok) {
    throw new Error(`API ${path} returned HTTP ${response.status}: ${await readErrorBody(response)}`);
  }
  return response.json() as Promise<T>;
}

async function readErrorBody(response: Response) {
  try {
    const payload = (await response.json()) as { error?: unknown };
    return typeof payload.error === "string" ? payload.error : JSON.stringify(payload);
  } catch {
    return response.statusText || "request failed";
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Unexpected error.";
}
