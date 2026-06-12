# TuskScan Implementation Tasklist

This tasklist is written for a coding agent with limited context. Complete tasks in order. Do not skip ahead unless the current section is blocked. Keep changes small and run the listed checks before moving to the next section.

Read first:

- `PLAN.md`
- `AGENTS.md`
- root `package.json`
- `apps/web/package.json`

## 0. Current Repo Baseline

- [x] Confirm the repo is the `tuskscan` pnpm/Turborepo workspace.
- [x] Run `pnpm install` only if dependencies are missing or broken.
- [x] Run `pnpm lint`, `pnpm check-types`, and `pnpm build` to capture the starter baseline.
- [x] Do not change product scope: v1 audits deployed Sui package IDs, not GitHub repositories.

Acceptance:

- Baseline command results are known.
- Any pre-existing failures are noted before feature work begins.

## 1. Workspace Structure

Create these workspace packages/apps:

- [x] `apps/api`: backend API service.
- [x] `apps/worker`: queue worker for long-running audit jobs.
- [x] `packages/audit-core`: scanner rules, normalized package model, scoring.
- [x] `packages/sui-integration`: Sui clients, package fetch, transaction helpers.
- [x] `packages/storage`: Walrus artifact and MemWal memory helpers.
- [x] `packages/shared`: shared types, schemas, constants.
- [x] `move/tuskscan`: Sui Move package for audit job/report objects.

Rules:

- Use TypeScript for all JS packages.
- Export only typed APIs from packages.
- Keep scanner logic out of UI/backend route handlers.

Acceptance:

- `pnpm check-types` sees all new packages.
- Empty packages build without implementation logic.

## 2. Shared Types And Schemas

In `packages/shared`, define the core types:

- [x] `Network = "testnet" | "mainnet"` but default runtime config to `mainnet`.
- [x] `AuditStatus = "prepared" | "paid" | "running" | "completed" | "failed"`.
- [x] `FindingSeverity = "info" | "low" | "medium" | "high" | "critical"`.
- [x] `FindingConfidence = "low" | "medium" | "high"`.
- [x] `PackageSummary` with package ID, network, module count, function count, struct count, fetched checkpoint/version when available.
- [x] `NormalizedPackageSnapshot` for modules, structs, functions, abilities, visibilities, entry flags, parameters, returns.
- [x] `AuditFinding` with rule ID, title, severity, confidence, evidence, module/function/struct references, memory-assisted metadata.
- [x] `AuditReportArtifacts` with Walrus blob IDs and content hashes.

Acceptance:

- Types are usable from `apps/web`, `apps/api`, `apps/worker`, and packages.
- No `any` for core audit data.

## 3. Sui Integration

In `packages/sui-integration`:

- [x] Add Sui JSON-RPC client helper for testnet/mainnet package reads.
- [x] Add package ID validation for Sui object ID format.
- [x] Implement `fetchNormalizedPackage(packageId, network)`.
- [x] Use Sui RPC/SDK methods for normalized Move modules or equivalent package metadata.
- [x] Convert fetched package data into `NormalizedPackageSnapshot`.
- [x] Add deterministic canonical JSON serialization and SHA-256 hash helpers for snapshots.
- [x] Add clear error types: invalid package ID, package not found, package not Move package, RPC unavailable.

Acceptance:

- Unit tests can load a fixture package snapshot.
- Integration test can fetch a known Sui testnet package ID when env enables network tests.
- Snapshot hash is stable across repeated serialization.

## 4. Move Contract

In `move/tuskscan`:

- [x] Create `AuditJob` object with payer, package ID, package digest/hash, price paid, status, created timestamp.
- [x] Create `AuditReport` object linked to an `AuditJob`.
- [x] Add entry function to create paid audit job.
- [x] Add entry/admin function to finalize report with package snapshot blob ID/hash, report blob ID/hash, findings hash, risk score, visibility.
- [x] Add events for job created and report finalized.
- [x] Keep privileged finalization controlled by an operator/admin capability for MVP.

Acceptance:

- `sui move test` passes.
- Contract can be published to Sui Mainnet.
- A frontend PTB can call the create-job entry function.

## 5. Deterministic Audit Rules

In `packages/audit-core`:

- [x] Implement rule engine that consumes `NormalizedPackageSnapshot`.
- [x] Add v1 rules:
  - [x] public/entry admin-like function names
  - [x] privileged-looking functions without obvious capability/admin parameters
  - [x] shared-object mutation entry points
  - [x] transfer/withdraw-like public entry functions
  - [x] risky abilities or public exposure patterns
  - [x] upgrade/admin/config surfaces that require manual review
- [x] Each rule returns structured `AuditFinding` candidates.
- [x] Add risk scoring from structured findings only.
- [x] Add fixture snapshots for safe and intentionally vulnerable packages.

Acceptance:

- Every rule has at least one positive fixture test and one non-triggering fixture test.
- Findings cite module/function/struct identifiers, not source lines.
- No LLM output is required for deterministic findings.

## 6. AI Agent Layer

In `packages/audit-core` or a dedicated agent package:

- [x] Add Scanner Agent wrapper around deterministic rules.
- [x] Add Exploit Memory Agent interface for recall results from MemWal.
- [x] Add Critic Agent pass that can downgrade/drop findings only with structured reason.
- [x] Add Fix Agent pass that adds remediation text.
- [x] Add Report Agent that generates public and private markdown reports.
- [x] Add Memory Agent that extracts validated exploit lessons.

Rules:

- LLM text must never create a finding without deterministic evidence.
- All reports must include the AI pre-audit disclaimer.
- If no LLM API key is configured, produce deterministic reports with placeholder explanation text.

Acceptance:

- Audit can complete without LLM credentials.
- With LLM credentials, explanation text improves but schema remains unchanged.

## 7. Walrus And MemWal Storage

In `packages/storage`:

- [x] Add Walrus client wrapper for writing and reading blobs.
- [x] Store artifacts:
  - [x] `package-snapshot.json`
  - [x] `findings.json`
  - [x] `public-report.md`
  - [x] `private-report.md`
  - [x] `audit-run-log.json`
  - [x] `memory-diff.json`
- [x] Hash every artifact before/after upload.
- [x] Add proof helper to read a Walrus artifact and verify hash.
- [x] Add MemWal helper to recall exploit memories by package/finding context.
- [x] Add MemWal helper to write validated exploit lessons after audit completion.

Acceptance:

- Storage code is idempotent for retrying the same audit job.
- Artifact verification returns pass/fail with expected and actual hashes.
- Memory write and recall can be mocked in tests.

## 8. Backend API

In `apps/api`:

- [x] Add health route.
- [x] Add config validation for Sui RPC, Walrus, MemWal, database, Redis, and operator key.
- [x] Add `POST /api/audits/prepare`.
  - Input: package ID and network.
  - Output: package summary, package snapshot hash, price, warnings.
- [x] Add `POST /api/audits`.
  - Input: package ID, network, Sui job transaction digest/object ID.
  - Output: local audit ID and status.
- [x] Verify the submitted Sui payment transaction before audit work starts.
  - Transaction must succeed and be sent by the claimed payer.
  - Transaction must create the claimed `AuditJob`.
  - `AuditJob` must match the prepared package ID/hash and required price.
  - Balance changes must credit the configured operator address.
- [x] Add `GET /api/audits/:id`.
- [x] Add `GET /api/audits/:id/report`.
- [x] Add `POST /api/audits/:id/verify`.
- [x] Enforce wallet ownership for private report access.

Acceptance:

- Route tests cover success and failure cases.
- API never accepts GitHub repo URLs in v1.
- API rejects packages that cannot be fetched from Sui.

## 9. Worker

In `apps/worker`:

- [x] Poll/consume paid audit jobs.
- [x] Re-fetch package snapshot and verify hash matches prepared snapshot.
- [x] Run audit workflow.
- [x] Upload artifacts to Walrus.
- [x] Write exploit lessons to MemWal.
- [x] Finalize Sui `AuditReport`.
- [x] Mark local job completed or failed.
- [x] Add retry and dead-letter behavior.

Acceptance:

- Worker job is idempotent if restarted.
- A failed Walrus/MemWal/Sui step can be retried without duplicating final reports.
- Run log artifact includes major workflow steps and timings.

## 10. Web App

In `apps/web`:

- [x] Replace starter page with TuskScan product UI.
- [x] Add Sui wallet connect.
- [x] Add package ID input and network indicator.
- [x] Call prepare API and show package summary before payment.
- [x] Build Sui transaction to create `AuditJob`.
- [x] Submit job to backend after wallet transaction succeeds.
- [x] Show audit progress timeline.
- [x] Show report page with risk score, findings, memories used, and suggested fixes.
- [x] Show proof page with Sui object IDs, Walrus blob IDs, and hash verification.
- [x] Gate private report details by connected wallet.

Design rules:

- Build the actual app as the first screen, not a marketing landing page.
- Keep UI dense, clear, and operational.
- Do not use decorative gradients/orbs as primary design.

Acceptance:

- User can complete the demo from package ID input to verified report.
- Public summary is readable without wallet.
- Private report requires the payer/admin wallet.

## 11. Demo Fixtures

Create/demo-deploy two Sui packages:

- [x] Package A: contains a clear privileged public entry/admin-like vulnerability.
- [x] Package B: contains a similar vulnerability with different module/function names.
- [ ] Publish both to Sui Mainnet if using self-owned demo packages. Manual E2E.
- [ ] Record package IDs in `docs/demo-packages.md`. Manual E2E after publish.
- [x] Add normalized snapshots as test fixtures.

Acceptance:

- Audit A writes exploit memory.
- Audit B recalls memory from Audit A.
- UI labels Package B finding as memory-assisted.

## 12. Docs

- [x] Update `README.md` from Turborepo starter to TuskScan overview.
- [x] Add local development setup.
- [x] Add required environment variables.
- [x] Add demo script.
- [x] Add security disclaimer.
- [x] Add architecture diagram in markdown or Mermaid.
- [x] Keep `PLAN.md`, `TASKLIST.md`, and `AGENTS.md` in sync if architecture changes.

Acceptance:

- A new agent/developer can run the app from README.
- Demo script matches the actual UI and package IDs.

## 13. Final Validation

Run:

```sh
pnpm lint
pnpm check-types
pnpm build
sui move test
```

Manual E2E:

- [ ] Open web app.
- [ ] Connect wallet.
- [ ] Prepare Package A.
- [ ] Pay SUI and run audit.
- [ ] Verify report artifacts on Walrus and proof on Sui.
- [ ] Prepare Package B.
- [ ] Run audit.
- [ ] Confirm memory-assisted finding appears.
- [ ] Confirm public summary/private report behavior.

Final acceptance:

- The demo proves: deployed package audit -> Walrus artifacts -> Sui proof -> MemWal exploit memory -> second audit improves through memory recall.
