# AGENTS.md

## Project

TuskScan is a Sui Overflow Walrus-track project. It provides paid, wallet-native AI pre-audits for deployed Sui Move packages.

The product goal is not generic static analysis. The core thesis is:

> TuskScan audit agents improve over time because exploit patterns, audit artifacts, normalized package snapshots, run logs, and reports are persisted through Walrus/MemWal and anchored with Sui proofs.

Read `PLAN.md` before making product or architecture changes. Use `TASKLIST.md`
as the ordered implementation checklist.

## Repository Shape

This repo is a pnpm/Turborepo workspace.

- `apps/web`: main Next.js product app with Sui Dapp Kit wallet connect.
- `apps/api`: HTTP API for package prepare, audit creation, reports, and verification.
- `apps/worker`: paid audit worker flow and retry/dead-letter behavior.
- `apps/docs`: docs app, currently starter scaffold.
- `packages/ui`: shared React UI components.
- `packages/eslint-config`: shared ESLint config.
- `packages/typescript-config`: shared TypeScript config.

- `packages/audit-core`: deterministic scanner rules, agent workflow, reports.
- `packages/storage`: Walrus and MemWal-compatible artifact/memory helpers.
- `packages/sui-integration`: Sui package fetch, normalization, stable hashing.
- `move/tuskscan`: Sui Move package for `AuditJob` and `AuditReport`.
- `move/demo-package-a` and `move/demo-package-b`: intentionally unsafe demo packages.

## Build Direction

Prioritize the MVP in this order:

1. Web app with wallet connect and deployed Sui package ID input.
2. Sui RPC package fetch and normalized module extraction.
3. Deterministic normalized-module vulnerability heuristics.
4. Real Sui Mainnet `AuditJob` payment/proof flow.
5. Walrus artifact upload for package snapshots and reports.
6. MemWal exploit memory recall/write.
7. Dashboard report and proof verification.

Do not start with GitHub repo cloning, private source ingestion, generalized smart contract languages, Discord/Telegram, or production billing.

## Product Defaults

- Audit target: deployed Sui Move packages only.
- Input: Sui package object ID only.
- Chain: Sui Mainnet for hackathon unless `PLAN.md` explicitly changes it.
- Payment: real SUI transaction to create audit job.
- Report visibility: public summary, wallet-gated details.
- Audit style: deterministic normalized-module rules plus AI explanation and critique.
- Security framing: AI pre-audit assistance, not a professional audit replacement.
- Use `TUSKSCAN_ENV=localhost` for local development. The hackathon demo must use `TUSKSCAN_ENV=production` with a real Sui `AuditJob`, real operator payment verification, Walrus artifacts, and MemWal memory.

## Engineering Rules

- Prefer TypeScript throughout app/backend/shared packages.
- Keep deterministic scanners separate from LLM explanation logic.
- Treat LLM output as advisory. Findings must have structured rule IDs, evidence, confidence, severity, and source basis.
- Findings must cite package/module/function/struct identifiers. Do not invent source lines when original source is unavailable.
- Never upload secrets, wallet keys, API keys, or private repo contents.
- Do not clone or execute untrusted repositories in v1.
- Keep public summaries redacted and structure-level. Private report access must be wallet-gated.
- Do not store every intermediate event on Sui. Sui stores proof metadata and ownership; Walrus stores durable artifacts.
- Do not replace Postgres with Walrus. Postgres is for hot state and dashboard UX.
- Use stable canonical JSON and hashing before anchoring package snapshot/report hashes on Sui.
- Package fetching, Walrus upload, MemWal writes, and Sui finalization must be idempotent and retry-safe.
- Every public security claim must include the disclaimer that TuskScan is an AI pre-audit, not a professional audit.

## Sui And Walrus Rules

- Use Sui Mainnet by default unless `PLAN.md` explicitly changes it.
- Verify a submitted package ID resolves to a package object before accepting payment.
- Verify submitted payment transactions on Sui RPC. The transaction must succeed, be sent by the claimed payer, create the claimed `AuditJob`, match the prepared package hash, and credit the configured operator address.
- Store the package ID and canonical package snapshot hash in every audit proof.
- Wait for Sui transaction finality before starting paid audit work.
- Walrus artifacts must be content-addressed or hash-verified before displaying "verified" in the UI.
- MemWal memories should store exploit patterns and lessons, not raw private user data.
- If Seal encryption is added, keep encrypted artifact paths separate from public summary artifacts.

## Audit Correctness Rules

- Deterministic rules produce the finding candidates; AI agents explain, critique, prioritize, and propose fixes.
- A finding should be dropped or downgraded if the Critic Agent cannot identify concrete normalized-module evidence.
- Risk scores must be derived from structured findings, not from free-form LLM text alone.
- Memory-assisted findings must list the recalled exploit memory ID or reference.
- Reports based only on normalized modules must say that original source comments and line numbers may be unavailable.

## Validation

Before considering an implementation ready, run the relevant checks:

```sh
pnpm lint
pnpm check-types
pnpm build
```

For feature work, add targeted tests for:

- Sui package ID validation.
- normalized module fetch and canonicalization.
- vulnerability rule fixtures.
- package snapshot and report hash verification.
- access control for private report details.
- first-audit memory write and second-audit memory recall.
- idempotent job retry behavior.

## Demo Narrative

The core hackathon demo should show two deployed Sui package audits:

1. Package A contains a vulnerability. TuskScan finds it from normalized module structure, stores the report on Walrus, anchors a proof on Sui, and writes an exploit lesson to MemWal.
2. Package B contains a similar vulnerability. TuskScan recalls the prior exploit memory and marks the finding as memory-assisted.

The punchline:

> The agent did not just scan code. It learned a reusable exploit pattern, persisted that memory through Walrus/MemWal, and used it to improve a future audit of an actual deployed Sui package.
