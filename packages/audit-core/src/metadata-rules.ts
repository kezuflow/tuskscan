import type {
  AuditFinding,
  FindingSeverity,
  MemoryReference,
  NormalizedFunction,
  NormalizedPackageSnapshot,
  SourceContext,
} from "@repo/shared";

import { runSourceAwareAudit } from "./source-rules.js";
import type { ExploitMemory } from "./types.js";
import {
  dedupeFindings,
  findingId,
  hasCapabilityParam,
  hasPrivilegedName,
  hasTransferLikeName,
  isPublicEntry,
  matchMemories,
} from "./utils.js";

export function runDeterministicAudit(
  snapshot: NormalizedPackageSnapshot,
  memories: ExploitMemory[] = [],
  sourceContext?: SourceContext,
): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const module of snapshot.modules) {
    for (const fn of module.functions) {
      const lowered = fn.name.toLowerCase();
      const evidence = {
        detail: `Function ${module.name}::${fn.name} is ${fn.visibility}${fn.isEntry ? " entry" : ""} with parameters ${fn.parameters.map((param) => param.raw).join(", ") || "none"}.`,
        functionName: fn.name,
        moduleName: module.name,
      };

      if (isPublicEntry(fn) && hasPrivilegedName(lowered)) {
        findings.push(
          createFinding({
            category: "Access control",
            description:
              "A public entry function has an admin-like name. Review whether it is gated by an explicit capability object or trusted admin parameter.",
            evidence: [evidence],
            impact:
              "An exposed admin path can let any caller mutate protocol configuration, pause/unpause flows, mint, burn, or sweep assets if authorization is missing in source.",
            fn,
            memoryReferences: matchMemories(
              memories,
              "admin capability",
              "MOVE_PUBLIC_ADMIN_ENTRY",
            ),
            moduleName: module.name,
            recommendation:
              "Require a dedicated AdminCap/OwnerCap parameter and assert ownership before executing privileged state changes.",
            remediationSteps: [
              "Require a capability object for this entry point.",
              "Assert the capability owner or expected admin address before mutation.",
              "Add a negative Move test for an unauthorized caller.",
            ],
            ruleId: "MOVE_PUBLIC_ADMIN_ENTRY",
            severity: "high",
            testSuggestions: [
              "Call the entry function from a non-admin test account and assert it aborts.",
            ],
            title: "Public admin-like entry function",
          }),
        );
      }

      if (isPublicEntry(fn) && hasPrivilegedName(lowered) && !hasCapabilityParam(fn)) {
        findings.push(
          createFinding({
            category: "Access control",
            description:
              "A privileged-looking entry point does not expose an obvious capability/admin parameter in the normalized signature.",
            evidence: [evidence],
            impact:
              "If the source body also lacks sender or ownership checks, this can become a direct privileged action for arbitrary callers.",
            fn,
            memoryReferences: matchMemories(
              memories,
              "missing capability",
              "MOVE_MISSING_CAPABILITY_PARAM",
            ),
            moduleName: module.name,
            recommendation:
              "Add a capability parameter such as AdminCap or enforce an explicit signer/object ownership check.",
            remediationSteps: [
              "Add an AdminCap/OwnerCap parameter or equivalent ownership proof.",
              "Check the caller with tx_context::sender(ctx) before state change.",
              "Document the expected privileged caller model.",
            ],
            ruleId: "MOVE_MISSING_CAPABILITY_PARAM",
            severity: "critical",
            testSuggestions: [
              "Prove unauthorized callers cannot execute the function.",
              "Prove the authorized owner/capability path still succeeds.",
            ],
            title: "Privileged function may lack capability gate",
          }),
        );
      }

      if (isPublicEntry(fn) && fn.parameters.some((param) => param.isMutableReference)) {
        findings.push(
          createFinding({
            category: "Shared object mutation",
            description:
              "A public entry function accepts mutable references. This is often correct, but privileged shared-object mutation should be reviewed carefully.",
            evidence: [evidence],
            impact:
              "Mutable public entry points are the primary Sui attack surface for shared-object state corruption, unauthorized accounting changes, or invariant bypasses.",
            fn,
            memoryReferences: matchMemories(
              memories,
              "shared object mutation",
              "MOVE_PUBLIC_MUTABLE_ENTRY",
            ),
            moduleName: module.name,
            recommendation:
              "Confirm the mutable object path is gated by ownership, capability checks, or invariant-preserving assertions.",
            remediationSteps: [
              "Identify each mutable object accepted by the function.",
              "Bind mutation rights to owner/capability/derived key checks.",
              "Add invariant tests around the object before and after mutation.",
            ],
            ruleId: "MOVE_PUBLIC_MUTABLE_ENTRY",
            severity: hasPrivilegedName(lowered) ? "high" : "medium",
            testSuggestions: [
              "Use a second wallet in tests to attempt mutation of another user's object.",
            ],
            title: "Public mutable entry surface",
          }),
        );
      }

      if (isPublicEntry(fn) && hasTransferLikeName(lowered)) {
        findings.push(
          createFinding({
            category: "Value movement",
            description:
              "A public entry function appears to transfer, withdraw, sweep, or claim value. Value-moving paths deserve explicit authorization review.",
            evidence: [evidence],
            impact:
              "Value-moving public entry points can drain funds, duplicate claims, or redirect payouts when authorization and replay protections are incomplete.",
            fn,
            memoryReferences: matchMemories(
              memories,
              "withdraw transfer claim",
              "MOVE_VALUE_MOVING_ENTRY",
            ),
            moduleName: module.name,
            recommendation:
              "Check sender authority, recipient restrictions, balance accounting, and replay/claim guards.",
            remediationSteps: [
              "Require authorization before value leaves protocol custody.",
              "Bind recipients to the caller or a verified entitlement.",
              "Persist a receipt/nonce for one-time claims.",
            ],
            ruleId: "MOVE_VALUE_MOVING_ENTRY",
            severity: "medium",
            testSuggestions: [
              "Attempt repeated claims and unauthorized withdrawals in Move unit tests.",
            ],
            title: "Public value-moving entry function",
          }),
        );
      }
    }

    for (const struct of module.structs) {
      if (struct.abilities.includes("key") && struct.abilities.includes("store")) {
        findings.push({
          confidence: "medium",
          category: "Object lifecycle",
          description:
            "A key+store object type can become a persistent onchain asset. Review all public functions that create, mutate, transfer, or destroy it.",
          evidence: [
            {
              detail: `Struct ${module.name}::${struct.name} has abilities ${struct.abilities.join(", ")}.`,
              moduleName: module.name,
              structName: struct.name,
            },
          ],
          id: findingId("MOVE_KEY_STORE_OBJECT", module.name, struct.name),
          impact:
            "Persistent key+store objects often define custody, ownership, or protocol state; unsafe lifecycle functions can strand, duplicate, or transfer critical assets.",
          likelihood: "medium",
          memoryAssisted: false,
          memoryReferences: [],
          recommendation:
            "Trace object lifecycle functions and ensure ownership/capability checks protect privileged transitions.",
          remediationSteps: [
            "Map create, mutate, transfer, freeze, and delete paths for this object.",
            "Verify each lifecycle transition has an owner/capability guard.",
          ],
          ruleId: "MOVE_KEY_STORE_OBJECT",
          severity: "info",
          testSuggestions: [
            "Add lifecycle tests that cover create, transfer, mutation, and deletion paths.",
          ],
          title: "Persistent object lifecycle review",
        });
      }
    }
  }

  return dedupeFindings([...findings, ...runSourceAwareAudit(sourceContext, memories)]);
}

function createFinding(options: {
  category?: string;
  description: string;
  evidence: AuditFinding["evidence"];
  fn: NormalizedFunction;
  impact?: string;
  likelihood?: AuditFinding["likelihood"];
  memoryReferences: MemoryReference[];
  moduleName: string;
  recommendation: string;
  remediationSteps?: string[];
  ruleId: string;
  severity: FindingSeverity;
  testSuggestions?: string[];
  title: string;
}): AuditFinding {
  return {
    category: options.category,
    confidence:
      options.severity === "critical" || options.severity === "high"
        ? "high"
        : "medium",
    description: options.description,
    evidence: options.evidence,
    id: findingId(options.ruleId, options.moduleName, options.fn.name),
    impact: options.impact,
    likelihood: options.likelihood ?? "medium",
    memoryAssisted: options.memoryReferences.length > 0,
    memoryReferences: options.memoryReferences,
    recommendation: options.recommendation,
    remediationSteps: options.remediationSteps,
    ruleId: options.ruleId,
    severity: options.severity,
    testSuggestions: options.testSuggestions,
    title: options.title,
  };
}
