# AGENTS.md

## Project

TuskScan is a Sui Overflow Walrus-track project for wallet-native AI pre-audits of Sui Move packages.

Users connect a Sui wallet, paste a GitHub Move package URL or deployed package ID, pay into an onchain `AuditJob`, and receive a multi-agent vulnerability report with Walrus artifacts, Sui proof metadata, and MemWal-backed exploit memory.

The core thesis:

> TuskScan audit agents improve over time because reusable exploit patterns and audit observations are persisted through MemWal, while reports, snapshots, run logs, source context, and memory diffs are stored as verifiable Walrus artifacts anchored by Sui proof objects.

Read `PLAN.md` before making product or architecture changes. `README.md` is the operator/demo guide.

## Repository Shape

This repo is a pnpm/Turborepo workspace.

- `apps/web`: main Next.js workbench with Sui Dapp Kit wallet connect, package loading, paid audit flow, findings, MemWal, Walrus, and Sui proof UI.
- `apps/api`: Node HTTP API plus the database queue worker for prepare/create/status/report/artifact/verify routes.
- `apps/docs`: unused starter docs app; do not spend time here for the hackathon demo.
- `packages/audit-core`: deterministic scanner rules, source-aware rules, agent workflow, report rendering, memory extraction.
- `packages/storage`: Walrus artifact storage and MemWal-compatible memory helpers.
- `packages/sui-integration`: Sui RPC helpers, package normalization, payment verification, stable hashing.
- `packages/shared`: shared report, finding, artifact, source, and sandbox types.
- `packages/ui`: starter shared UI package; not central to the TuskScan workbench.
- `move/tuskscan`: Sui Move package for `AuditConfig`, shared `AuditJob`, `AuditReport`, operator finalization, and events.
- `move/demo-package-a`: intentionally unsafe package that teaches memory.
- `move/demo-package-b`: intentionally unsafe package that should recall memory from package A.
- `move/demo-package-c`: intentionally unsafe package for predictable randomness and vector-bound findings.
- `docs/demo-packages.md`: demo package notes and publish commands.

## Product Defaults

- Chain: Sui Mainnet for the hackathon build.
- Input: public GitHub repository/package URL first; deployed package IDs remain supported as a fallback path.
- Source scope: only selected Move package roots and `.move` files, not whole repositories.
- Payment: real Sui transaction that creates a shared onchain `AuditJob`.
- Artifacts: Walrus stores report artifacts and source/package snapshots; the browser opens artifacts through the TuskScan API proxy.
- Memory: MemWal stores reusable vulnerability patterns and audit observations.
- Database: Postgres/Supabase stores hot audit job state and wallet history.
- LLMs: optional OpenRouter/OpenAI-compatible agents improve review text and critique, but deterministic rules remain the source of findings.
- Sandbox: optional `sui move test` execution for GitHub source packages when `TUSKSCAN_RUN_MOVE_TESTS=1`.
- Security framing: AI pre-audit assistance only, not a professional audit or deployment approval.

## Engineering Rules

- Prefer TypeScript throughout app/backend/shared packages.
- Keep deterministic scanners separate from LLM explanation logic.
- LLM output may explain, critique, prioritize, and suggest patches; it must not create unsupported findings.
- Findings must have structured rule IDs, severity, confidence, evidence, and source basis.
- Findings should cite source file/line when GitHub source is available; otherwise cite package/module/function/struct identifiers.
- Never commit secrets, wallet keys, API keys, private env files, or private repository contents.
- Do not ingest an entire GitHub monorepo. Scope to the selected Move package root.
- Keep public summaries redacted and structure-level. Private report details require wallet session auth.
- Do not store every intermediate event on Sui. Sui stores proof metadata; Walrus stores durable artifacts.
- Do not replace Postgres with Walrus. Postgres is for live queue state and dashboard UX.
- Use stable canonical JSON and content hashes before anchoring report or snapshot references on Sui.
- Package fetching, Walrus upload, MemWal writes, and Sui finalization must be retry-safe.
- Every public security claim must include the TuskScan AI pre-audit disclaimer.

## Sui, Walrus, MemWal

- Use Sui Mainnet by default.
- Verify submitted payment transactions on Sui RPC. The transaction must succeed, be sent by the claimed payer, create the claimed `AuditJob`, match the prepared package hash, and credit the configured operator.
- `AuditJob` objects are shared objects; verifier logic should accept upgraded package type IDs when the original type still matches `audit::AuditJob`.
- Store package/source snapshot hashes and private report hashes in the Sui finalization path.
- Walrus artifacts must be hash-verified before presenting them as verified.
- Browser-readable artifact links should go through `/api/audits/:id/artifacts/:artifactName`, not raw `walrus://` identifiers.
- MemWal records should be searchable, compact, and structured. Prefer reusable vulnerability patterns over duplicate raw scan text.
- `MEMWAL_WAIT_FOR_REMEMBER=1` keeps package A -> package B demos deterministic by waiting for indexing before scan completion.

## Audit Correctness

- Deterministic and source-aware rules produce finding candidates.
- The critic can downgrade/drop weak findings only with a structured reason.
- Risk scores derive from structured findings, not free-form LLM text.
- Memory-assisted findings must include recalled memory references.
- Reports should be clear about what was scanned: GitHub Move source, optional Sui package metadata, or metadata-only fallback.
- Sandbox-generated tests are compile-only skeletons unless explicitly bound to project fixtures.

## Validation

Before considering changes ready, run the focused checks for touched packages. For broad changes, run:

```powershell
pnpm lint
pnpm check-types
pnpm build
pnpm --filter api test
pnpm --filter @repo/audit-core test
pnpm --filter @repo/storage test
pnpm --filter @repo/sui-integration test
```

For Move changes, run:

```powershell
sui move test
```

from the relevant `move/*` package.

## Demo Narrative

The hackathon demo should show:

1. Package A GitHub URL loads scoped Move source, runs a paid audit, stores artifacts on Walrus, anchors proof on Sui, and writes reusable exploit memory to MemWal.
2. Package B GitHub URL runs next and recalls the prior pattern, showing memory-assisted findings.
3. Package C shows the scanner catches another bug family, such as predictable randomness or vector-bound issues.

The punchline:

> TuskScan is not just a scanner. It is a wallet-native Sui Move pre-audit workbench whose agents build reusable exploit memory across audits, with Walrus artifacts and Sui proof objects for verification.
