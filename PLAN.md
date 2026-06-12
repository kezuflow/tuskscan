# TuskScan: Walrus Memory Audits for Deployed Sui Move Packages

## Summary

TuskScan is a web app where a user connects a Sui wallet, pays testnet SUI, submits a deployed Sui package ID, and receives a multi-agent audit report for the actual onchain Move package.

The core Walrus-track claim: the audit workflow improves over time because exploit patterns, reports, logs, normalized package snapshots, and findings are stored as persistent Walrus/MemWal memory and reused by future audits.

MVP defaults:

- Target: deployed Sui Move packages only
- Input: Sui package object ID
- Surface: web app
- Chain: real Sui testnet payment and proof objects
- Reports: public summary, wallet-gated details
- Audit engine: deterministic normalized-module rules plus AI explanations

## Key Architecture

- Frontend: Next.js app for wallet connect, package ID submission, audit progress, report viewer, and proof verification.
- Backend: Node service for Sui package fetch, normalized module parsing, audit orchestration, LLM calls, MemWal/Walrus writes, and Sui transaction coordination.
- Database: Postgres for users, audit jobs, package metadata, findings index, report visibility, and async job state.
- Queue: Redis/BullMQ for long-running audit jobs and artifact uploads.
- Sui Move package: `AuditJob`, `AuditReport`, and payment/ownership objects on testnet.
- Sui RPC/indexer: source of truth for package object metadata and normalized Move modules.
- MemWal: persistent exploit memory and reusable audit lessons.
- Walrus: durable artifacts: normalized package snapshot, findings JSON, report markdown/PDF, run logs, memory diff, and eval summary.

Audit workflow agents:

- Package Inspector Agent: fetches deployed package metadata and normalized modules from Sui.
- Scanner Agent: applies deterministic vulnerability heuristics to normalized module surfaces.
- Exploit Memory Agent: recalls similar vulnerabilities from MemWal.
- Critic Agent: reviews findings and removes weak/duplicate claims.
- Fix Agent: proposes remediation guidance based on available module/function signatures.
- Report Agent: generates final public/private report artifacts.
- Memory Agent: writes new validated exploit lessons back to MemWal.

## Core Flow

1. User connects Sui wallet.
2. User submits a Sui package object ID.
3. App validates the package ID and fetches package metadata/normalized modules from Sui testnet.
4. User pays testnet SUI to create an onchain `AuditJob`.
5. Backend starts audit after observing/confirming the job.
6. Normalized package snapshot is stored on Walrus.
7. Multi-agent workflow scans, recalls exploit memory, critiques, fixes, and reports.
8. Report artifacts are uploaded to Walrus.
9. Backend finalizes onchain `AuditReport` with report blob ID, package snapshot blob ID, content hashes, risk score, and visibility metadata.
10. User sees risk score, findings summary, detailed wallet-gated report, exploit memories used, suggested fixes, Walrus artifact links, and Sui proof object.
11. Memory Agent stores new validated exploit patterns in MemWal.
12. Second demo audit shows memory-assisted findings reused from the prior run.

## Public Interfaces

Web app routes:

- `/` landing and package ID submission
- `/audit/new` create audit
- `/audit/:id` live progress and final report
- `/audit/:id/proof` Walrus/Sui verification view
- `/dashboard` wallet-owned audit history

Backend API:

- `POST /api/audits/prepare` validates package ID, fetches package summary, and estimates audit price
- `POST /api/audits` creates local audit record after Sui job transaction
- `GET /api/audits/:id` returns status, findings summary, artifact metadata
- `GET /api/audits/:id/report` returns wallet-gated private report
- `POST /api/audits/:id/verify` fetches Walrus artifact and verifies hash against Sui report object

Sui objects:

```move
AuditJob {
  payer,
  package_id,
  package_digest,
  price_paid,
  status,
  created_at
}

AuditReport {
  job_id,
  package_id,
  package_snapshot_blob_id,
  package_snapshot_hash,
  report_blob_id,
  report_hash,
  findings_hash,
  risk_score,
  visibility,
  created_at
}
```

Walrus artifacts:

- `package-snapshot.json`
- `findings.json`
- `public-report.md`
- `private-report.md`
- `audit-run-log.json`
- `memory-diff.json`

## Implementation Phases

### 1. Foundation

- Scaffold the TuskScan product inside the existing Turborepo.
- Keep `apps/web` as the main user-facing app.
- Add backend service, Postgres schema, queue worker, and shared audit packages.
- Add Sui wallet connect and package ID submission.
- Fetch deployed package metadata and normalized modules through Sui RPC.

### 2. Sui Payment And Proof

- Implement Move package for audit jobs and reports.
- Add frontend transaction flow for testnet SUI payment.
- Add backend watcher/finalizer for job and report object IDs.
- Store package ID and canonical package digest/hash in every audit proof.

### 3. Audit Engine

- Implement deterministic normalized-module heuristics for v1:
  - public/entry admin-like function surfaces
  - privileged functions without obvious capability/admin parameters
  - shared-object mutation entry points
  - transfer/withdraw-like functions exposed as public entry points
  - structs with risky abilities or public exposure patterns
  - upgrade/admin/config surfaces that deserve manual review
- Add LLM explanation layer for findings and suggested fixes.
- Add Critic Agent pass to reduce false positives.
- Make reports explicit that source comments/original source may be unavailable; findings are based on deployed package structure and normalized module data.

### 4. Walrus And MemWal

- Upload normalized package snapshot and report artifacts to Walrus.
- Store/retrieve exploit memories with MemWal.
- Mark findings as memory-assisted when recalled patterns contributed.
- Store new validated exploit lessons after each audit.

### 5. Dashboard And Demo Polish

- Build audit timeline, package surface view, findings table, report viewer, and proof page.
- Add public summary card with private details gated by connected wallet.
- Deploy two vulnerable demo Sui testnet packages:
  - Package A teaches exploit memory.
  - Package B contains a similar issue and demonstrates recall.

## Test Plan

- Unit test Sui package ID validation and package fetch normalization.
- Unit test deterministic Move vulnerability heuristics with normalized module fixtures.
- Unit test report and package snapshot hash canonicalization.
- Integration test: package ID -> audit job -> findings -> Walrus artifacts -> Sui report.
- Integration test: first audit writes MemWal exploit memory; second audit recalls it.
- Wallet access test: public summary visible to anyone; private report visible only to payer/admin.
- Proof test: fetch Walrus report/snapshot, recompute hashes, compare against Sui `AuditReport`.
- E2E demo test with two deployed testnet packages proving memory-assisted improvement.

## Assumptions

- Use Sui testnet for all payment/proof flows during the hackathon.
- V1 audits deployed package metadata and normalized modules, not GitHub source repositories.
- If verified source is unavailable, reports must avoid source-line claims and instead cite module/function/struct signatures.
- Use redacted and structure-level findings in public summaries.
- Full Seal encryption is a stretch goal; v1 uses wallet-gated dashboard access and public/private artifact separation.
- The audit is positioned as AI pre-audit assistance, not a replacement for a professional security audit.
- The winning narrative is: persistent exploit memory makes future audit agents better, and Walrus makes that memory portable, durable, and verifiable.
