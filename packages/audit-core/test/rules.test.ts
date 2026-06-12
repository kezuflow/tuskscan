import assert from "node:assert/strict";
import test from "node:test";

import {
  calculateRiskScore,
  runAuditWorkflow,
  runDeterministicAudit,
} from "../src/index.ts";
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
  const findings = runDeterministicAudit(safePackageSnapshot, [], {
    digest: "source-digest",
    fetchedAt: "2026-06-12T00:00:00.000Z",
    files: [
      {
        content: [
          "module demo::vault {",
          "  public entry fun drain(vault: &mut Vault, recipient: address, ctx: &mut TxContext) {",
          "    transfer::public_transfer(vault.coin, recipient);",
          "  }",
          "}",
        ].join("\n"),
        path: "sources/vault.move",
        sizeBytes: 180,
      },
    ],
    moveFileCount: 1,
    source: "github",
    url: "https://github.com/example/vault",
  });

  const sourceFinding = findings.find(
    (finding) => finding.ruleId === "SRC_PUBLIC_TRANSFER_WITHOUT_AUTH",
  );

  assert.equal(sourceFinding?.severity, "critical");
  assert.equal(sourceFinding?.evidence[0]?.filePath, "sources/vault.move");
  assert.equal(sourceFinding?.patchSuggestion?.includes("AdminCap"), true);
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
    },
    packageSummary: vulnerablePackageSummary,
    snapshot: vulnerablePackageSnapshot,
  });

  assert.equal(result.report.disclaimer.includes("not a professional security audit"), true);
  assert.equal(result.criticDecisions.every((decision) => decision.action === "keep"), true);
  assert.equal(result.memoryDiff.recalled.length, 1);
  assert.equal(writtenLessons.length > 0, true);
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
