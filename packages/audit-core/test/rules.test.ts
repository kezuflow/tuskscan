import assert from "node:assert/strict";
import test from "node:test";

import {
  calculateRiskScore,
  runAuditWorkflow,
  runDeterministicAudit,
} from "../src/index.ts";
import type { SourceContext } from "@repo/shared";
import {
  demoPackageASnapshot,
  demoPackageBSnapshot,
  safePackageSnapshot,
  vulnerablePackageSnapshot,
  vulnerablePackageSummary,
} from "./fixtures.ts";

const expectedRuleIds = [
  "MOVE_PUBLIC_ADMIN_ENTRY",
  "MOVE_MISSING_CAPABILITY_PARAM",
  "MOVE_PUBLIC_MUTABLE_ENTRY",
  "MOVE_VALUE_MOVING_ENTRY",
  "MOVE_KEY_STORE_OBJECT",
];

test("deterministic rules trigger on an intentionally exposed package", () => {
  const findings = runDeterministicAudit(vulnerablePackageSnapshot);
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  for (const ruleId of expectedRuleIds) {
    assert.equal(ruleIds.has(ruleId), true, `${ruleId} should trigger`);
  }

  assert.equal(
    findings.every((finding) =>
      finding.evidence.every((evidence) => evidence.moduleName.length > 0),
    ),
    true,
  );
  assert.equal(calculateRiskScore(findings) > 0, true);
});

test("deterministic rules stay quiet on a non-public safe package", () => {
  const findings = runDeterministicAudit(safePackageSnapshot);
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  for (const ruleId of expectedRuleIds) {
    assert.equal(ruleIds.has(ruleId), false, `${ruleId} should not trigger`);
  }

  assert.equal(calculateRiskScore(findings), 0);
});

test("memory references mark matched findings as memory-assisted", () => {
  const findings = runDeterministicAudit(vulnerablePackageSnapshot, [
    {
      id: "mem-1",
      query: "missing capability",
      summary: "Previous package exposed admin sweep without an AdminCap gate.",
    },
  ]);

  const missingCapFinding = findings.find(
    (finding) => finding.ruleId === "MOVE_MISSING_CAPABILITY_PARAM",
  );

  assert.equal(missingCapFinding?.memoryAssisted, true);
  assert.equal(missingCapFinding?.memoryReferences[0]?.id, "mem-1");
});

test("source-aware rules identify unauthenticated public transfer paths", () => {
  const findings = runDeterministicAudit(
    safePackageSnapshot,
    [],
    sourceContextFromFiles({
      "sources/vault.move": [
        "module demo::vault {",
        "  public entry fun drain(vault: &mut Vault, recipient: address, ctx: &mut TxContext) {",
        "    transfer::public_transfer(vault.coin, recipient);",
        "  }",
        "}",
      ].join("\n"),
    }),
  );

  const sourceFinding = findings.find(
    (finding) => finding.ruleId === "SRC_PUBLIC_TRANSFER_WITHOUT_AUTH",
  );

  assert.equal(sourceFinding?.severity, "critical");
  assert.equal(sourceFinding?.evidence[0]?.filePath, "sources/vault.move");
  assert.equal(sourceFinding?.evidence[0]?.codeSnippet?.includes("public_transfer"), true);
  assert.equal(sourceFinding?.impact?.includes("unauthorized caller"), true);
  assert.equal(sourceFinding?.patchSuggestion?.includes("AdminCap"), true);
});

test("source-aware rules identify advanced Sui Move exploit classes", () => {
  const findings = runDeterministicAudit(
    safePackageSnapshot,
    [],
    sourceContextFromFiles({
      "sources/advanced.move": [
        "module demo::advanced {",
        "  public entry fun initialize(ctx: &mut TxContext) {",
        "    let id = object::new(ctx);",
        "  }",
        "  public entry fun mint_anyone(recipient: address, ctx: &mut TxContext) {",
        "    let coin = coin::mint(100, ctx);",
        "    transfer::public_transfer(coin, recipient);",
        "  }",
        "  public entry fun draw_winner(clock: &Clock) {",
        "    let slot = clock::timestamp_ms(clock) % 10;",
        "  }",
        "  public entry fun pick(items: &mut vector<u64>, index: u64) {",
        "    vector::swap_remove(items, index);",
        "  }",
        "  entry public fun delete_receipt(receipt: Receipt) {",
        "    let Receipt { id } = receipt;",
        "    object::delete(id);",
        "  }",
        "}",
      ].join("\n"),
    }),
  );
  const ruleIds = new Set(findings.map((finding) => finding.ruleId));

  assert.equal(ruleIds.has("SRC_REINITIALIZATION_RISK"), true);
  assert.equal(ruleIds.has("SRC_TREASURY_CAP_EXPOSURE"), true);
  assert.equal(ruleIds.has("SRC_ARBITRARY_RECIPIENT_TRANSFER"), true);
  assert.equal(ruleIds.has("SRC_PREDICTABLE_RANDOMNESS"), true);
  assert.equal(ruleIds.has("SRC_UNCHECKED_VECTOR_ACCESS"), true);
  assert.equal(ruleIds.has("SRC_OBJECT_DELETE_WITHOUT_AUTH"), true);
});

test("agent workflow recalls memory, keeps deterministic findings, and writes lessons", async () => {
  const writtenLessons: string[] = [];
  const result = await runAuditWorkflow({
    memoryAgent: {
      recall: () => [
        {
          id: "mem-1",
          query: "missing capability",
          summary: "Prior audit found an admin sweep without an AdminCap gate.",
        },
      ],
      writeLessons: (lessons) => {
        writtenLessons.push(...lessons);
      },
      writeMemories: (memories) => {
        writtenLessons.push(...memories.patterns.map((pattern) => pattern.pattern));
        writtenLessons.push(...memories.observations.map((observation) => observation.patternId));
      },
    },
    packageSummary: vulnerablePackageSummary,
    sourceContext: sourceContextFromFiles({
      "sources/vault.move": [
        "module demo::vault {",
        "  public entry fun admin_sweep(treasury: &mut Treasury, recipient: address) {",
        "    transfer::public_transfer(treasury.coin, recipient);",
        "  }",
        "}",
      ].join("\n"),
    }),
    snapshot: vulnerablePackageSnapshot,
  });

  assert.equal(result.report.disclaimer.includes("not a professional security audit"), true);
  assert.equal(result.criticDecisions.every((decision) => decision.action === "keep"), true);
  assert.equal(result.report.coverage?.checkedModules, 1);
  assert.equal(result.report.severityBreakdown?.critical > 0, true);
  assert.equal((result.report.actionPlan?.length ?? 0) > 0, true);
  assert.equal((result.report.agentReviews?.length ?? 0) >= 5, true);
  assert.equal((result.report.generatedExploitTests?.length ?? 0) > 0, true);
  assert.equal(result.report.sourceConsistency?.level, "module_name_match");
  assert.equal((result.report.memoryPlaybooks?.length ?? 0) > 0, true);
  assert.equal(result.memoryDiff.recalled.length, 1);
  assert.equal((result.memoryDiff.patterns?.length ?? 0) > 0, true);
  assert.equal((result.memoryDiff.observations?.length ?? 0) > 0, true);
  assert.equal(writtenLessons.some((lesson) => lesson.includes("pattern:sui:move")), true);
});

test("demo package B can be marked memory-assisted after package A teaches a lesson", () => {
  const packageALessons = runDeterministicAudit(demoPackageASnapshot)
    .filter((finding) => finding.severity !== "info")
    .map((finding, index) => ({
      id: `demo-a-${index}`,
      query: "missing capability shared object mutation withdraw transfer claim",
      summary: `${finding.ruleId}: ${finding.title}`,
    }));

  const packageBFindings = runDeterministicAudit(
    demoPackageBSnapshot,
    packageALessons,
  );

  assert.equal(packageALessons.length > 0, true);
  assert.equal(
    packageBFindings.some((finding) => finding.memoryAssisted),
    true,
  );
});

function sourceContextFromFiles(files: Record<string, string>): SourceContext {
  const sourceFiles = Object.entries(files).map(([path, content]) => ({
    content,
    path,
    sizeBytes: Buffer.byteLength(content, "utf8"),
  }));
  return {
    branch: "main",
    digest: "source-digest",
    fetchedAt: "2026-06-12T00:00:00.000Z",
    files: sourceFiles,
    moveFileCount: sourceFiles.length,
    omittedMoveFileCount: 0,
    packageRoots: ["."],
    selectedRoot: ".",
    source: "github",
    totalMoveFileCount: sourceFiles.length,
    url: "https://github.com/example/vault",
  };
}
