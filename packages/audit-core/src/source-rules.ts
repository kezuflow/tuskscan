import type {
  AuditFinding,
  FindingSeverity,
  SourceContext,
} from "@repo/shared";

import type { ExploitMemory } from "./types.js";
import {
  dedupeFindings,
  findingId,
  matchMemories,
} from "./utils.js";
import {
  extractMoveFunctions,
  findSourceMarker,
  hasSenderRecipientBinding,
  hasSourceAuthSignal,
  sourceEvidence,
} from "./source-parser.js";

export function runSourceAwareAudit(
  sourceContext: SourceContext | undefined,
  memories: ExploitMemory[],
): AuditFinding[] {
  if (!sourceContext) return [];
  const findings: AuditFinding[] = [];

  for (const file of sourceContext.files) {
    for (const fn of extractMoveFunctions(file)) {
      const loweredName = fn.name.toLowerCase();
      const loweredBody = fn.body.toLowerCase();
      const evidence = sourceEvidence(file, fn);
      const hasAuthSignal = hasSourceAuthSignal(fn.body);
      const hasCapParam = /(cap|admin|owner|authority|witness|treasurycap)/i.test(
        fn.signature,
      );

      if (
        fn.isPublicEntry &&
        /transfer::public_transfer|coin::into_balance|balance::withdraw|coin::take/i.test(
          fn.body,
        ) &&
        !hasAuthSignal &&
        !hasCapParam
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The target function is callable as a public entry function.",
              "The attacker can obtain or influence the mutable/value-carrying input object.",
            ],
            category: "Value movement",
            confidence: "high",
            description:
              "Source analysis found a public entry value/object transfer path without an obvious capability, sender, or ownership authorization guard in the function body.",
            evidence,
            exploitPath: [
              "Attacker calls the public entry function directly.",
              "Attacker supplies or targets the mutable/value-carrying object accepted by the function.",
              "Function reaches a transfer/withdraw path before an obvious authorization guard is enforced.",
            ],
            impact:
              "Assets or owned objects may be transferred out of protocol custody by an unauthorized caller.",
            likelihood: "high",
            memories,
            memoryQuery: "withdraw transfer claim",
            patchSuggestion:
              "Require an AdminCap/OwnerCap or assert tx_context::sender(ctx) owns the affected object before executing the transfer.",
            recommendation:
              "Add an explicit authority check before value/object transfer and add a Move test proving unauthorized callers abort.",
            remediationSteps: [
              "Identify the authority expected to move this value.",
              "Assert that tx_context::sender(ctx), an owner field, or a capability authorizes the movement.",
              "Abort before any balance/object transfer when authorization fails.",
            ],
            ruleId: "SRC_PUBLIC_TRANSFER_WITHOUT_AUTH",
            severity: "critical",
            testSuggestions: [
              "A non-owner wallet calls the entry function and must abort.",
              "The owner/capability holder calls the entry function and succeeds.",
            ],
            title: "Public transfer path may lack authorization",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /transfer::public_transfer|transfer::transfer|coin::take|balance::withdraw/i.test(
          fn.body,
        ) &&
        /\b(recipient|receiver|to|dst|destination)\s*:\s*address/i.test(fn.signature) &&
        !hasSenderRecipientBinding(fn.body)
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The function accepts a caller-controlled recipient address.",
              "The function transfers a coin/object before binding the recipient to an entitlement.",
            ],
            category: "Value redirection",
            confidence: "medium",
            description:
              "A public value-moving function appears to accept an arbitrary recipient address without binding that recipient to tx_context::sender(ctx), ownership, or a claimed entitlement.",
            evidence,
            exploitPath: [
              "Attacker calls the public entry function with their own recipient address.",
              "The function performs transfer/withdraw logic using the supplied recipient.",
              "If entitlement checks are missing elsewhere, payout can be redirected.",
            ],
            impact:
              "Rewards, withdrawals, or transferred objects may be redirected to a caller-chosen address.",
            likelihood: "medium",
            memories,
            memoryQuery: "recipient withdraw transfer",
            patchSuggestion:
              "Derive the recipient from tx_context::sender(ctx) or from a verified onchain entitlement instead of trusting a free address parameter.",
            recommendation:
              "Bind recipient selection to sender authority or entitlement state before moving value.",
            remediationSteps: [
              "Replace arbitrary recipient parameters with tx_context::sender(ctx) when appropriate.",
              "If third-party payout is required, verify a signed/onchain entitlement for that recipient.",
            ],
            ruleId: "SRC_ARBITRARY_RECIPIENT_TRANSFER",
            severity: "high",
            testSuggestions: [
              "Attempt to claim or withdraw to an unrelated wallet and assert it aborts.",
            ],
            title: "Caller-controlled recipient on value transfer path",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /dynamic_field|dynamic_object_field|table::|object_table::/i.test(fn.body) &&
        /add|remove|borrow_mut|insert/i.test(loweredBody) &&
        !hasAuthSignal &&
        !hasCapParam
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The attacker can call the public entry function.",
              "The attacker can influence a dynamic storage key, object, or table mutation input.",
            ],
            category: "State integrity",
            confidence: "medium",
            description:
              "Source analysis found public mutation of dynamic storage without an obvious authority guard. Dynamic field/table paths often control claims, ownership registries, or accounting state.",
            evidence,
            exploitPath: [
              "Attacker calls the public entry function with chosen key/object inputs.",
              "Function mutates dynamic storage through add/remove/borrow_mut/insert.",
              "Without a guard, attacker may overwrite, replay, or remove state tied to another actor.",
            ],
            impact:
              "A caller may corrupt claim records, ownership registries, accounting state, or other dynamic storage namespaces.",
            likelihood: "medium",
            memories,
            memoryQuery: "shared object mutation",
            patchSuggestion:
              "Bind dynamic storage keys to tx_context::sender(ctx), object ownership, or a capability-controlled namespace.",
            recommendation:
              "Review dynamic storage key derivation and add tests for unauthorized key insertion, removal, and replay.",
            remediationSteps: [
              "Document the namespace owner for each dynamic key.",
              "Assert caller ownership/capability before add/remove/borrow_mut/insert.",
              "Abort when a key is already used or belongs to another wallet/object.",
            ],
            ruleId: "SRC_DYNAMIC_STORAGE_MUTATION",
            severity: "high",
            testSuggestions: [
              "Second wallet attempts to insert/remove another user's dynamic key and must abort.",
            ],
            title: "Dynamic storage mutation needs authority review",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /(claim|reward|redeem|withdraw|airdrop)/.test(loweredName) &&
        !/(claimed|receipt|nonce|used|has_claimed|contains|exists)/i.test(fn.body)
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The target function dispenses value or entitlement.",
              "The caller can repeat the same call or vary recipient-controlled inputs.",
            ],
            category: "Replay protection",
            confidence: "medium",
            description:
              "A public claim/reward-style function does not show an obvious replay guard such as a receipt, nonce, claimed set, or contains/exists check.",
            evidence,
            exploitPath: [
              "Attacker calls the claim/reward function once.",
              "Attacker repeats the same call or changes only recipient-controlled inputs.",
              "Without a durable replay marker, rewards or withdrawals may be claimed multiple times.",
            ],
            impact:
              "One-time rewards, withdrawals, or allocations may be drained repeatedly.",
            likelihood: "medium",
            memories,
            memoryQuery: "claim replay",
            patchSuggestion:
              "Store a claimed marker keyed by wallet/object/nonce before transferring value, and assert it does not already exist.",
            recommendation:
              "Add a negative Move test proving the second claim attempt aborts.",
            remediationSteps: [
              "Write a replay marker before or atomically with the value transfer.",
              "Key the marker by wallet/object/nonce depending on entitlement semantics.",
              "Abort when the marker already exists.",
            ],
            ruleId: "SRC_CLAIM_REPLAY_REVIEW",
            severity: "high",
            testSuggestions: [
              "Call the claim path twice with the same entitlement and assert the second call aborts.",
            ],
            title: "Claim path may need replay protection",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /(init|initialize|setup|create_config|configure)/.test(loweredName) &&
        /object::new|table::new|dynamic_field::add|config|admin/i.test(fn.body) &&
        !/(exists|is_one_time_witness|one_time_witness|initialized|already|has_key|contains)/i.test(
          fn.body,
        ) &&
        !hasCapParam
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The initializer is callable after deployment.",
              "The function creates or mutates global/config-like state.",
            ],
            category: "Initialization",
            confidence: "medium",
            description:
              "A public initializer/configuration path does not show an obvious one-time witness, initialized flag, exists check, or admin capability guard.",
            evidence,
            exploitPath: [
              "Attacker calls the initializer after deployment.",
              "Initializer creates or overwrites config/admin-like state.",
              "Protocol authority or core configuration may be reset to attacker-controlled values.",
            ],
            impact:
              "Protocol config or admin authority may be reinitialized after deployment.",
            likelihood: "medium",
            memories,
            memoryQuery: "initialize admin config",
            patchSuggestion:
              "Gate initialization with a one-time witness or an explicit initialized/exists check that aborts after first setup.",
            recommendation:
              "Make initializer one-time and add reinitialization tests.",
            remediationSteps: [
              "Require a one-time witness for package initialization where possible.",
              "Persist an initialized marker and abort on subsequent calls.",
              "Avoid accepting arbitrary admin/config values after deployment setup.",
            ],
            ruleId: "SRC_REINITIALIZATION_RISK",
            severity: "high",
            testSuggestions: [
              "Call the initializer twice and assert the second call aborts.",
            ],
            title: "Initializer may be callable more than once",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /coin::mint|balance::increase_supply|supply::increase|treasurycap/i.test(fn.body) &&
        !hasAuthSignal &&
        !hasCapParam
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The mint/supply path is exposed as a public entry function.",
              "The function can reach TreasuryCap or supply-increase logic without a guard.",
            ],
            category: "Token supply",
            confidence: "high",
            description:
              "A public entry function appears to reach minting or supply-increase logic without an obvious capability or sender/owner authorization guard.",
            evidence,
            exploitPath: [
              "Attacker calls the mint/supply function directly.",
              "Function reaches mint or supply-increase code.",
              "Attacker mints or increases supply beyond intended policy.",
            ],
            impact:
              "Token supply can be inflated or treasury-controlled assets can be created by unauthorized callers.",
            likelihood: "high",
            memories,
            memoryQuery: "mint treasurycap supply",
            patchSuggestion:
              "Require TreasuryCap/AdminCap ownership and assert the caller is authorized before any mint/supply operation.",
            recommendation:
              "Treat all TreasuryCap and supply operations as critical privileged code.",
            remediationSteps: [
              "Store TreasuryCap under capability-controlled custody.",
              "Require the capability in every mint/supply path.",
              "Add max-supply or policy assertions where applicable.",
            ],
            ruleId: "SRC_TREASURY_CAP_EXPOSURE",
            severity: "critical",
            testSuggestions: [
              "A non-admin wallet attempts minting and must abort.",
              "Supply cannot exceed configured limits.",
            ],
            title: "Mint or TreasuryCap path may be exposed",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /object::delete|id\.delete|delete\(/i.test(fn.body) &&
        !hasAuthSignal &&
        !hasCapParam
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The attacker can call a public object deletion path.",
              "The attacker can supply or reference the object being deleted.",
            ],
            category: "Object lifecycle",
            confidence: "medium",
            description:
              "A public entry function appears to delete an object without an obvious owner/capability authorization guard.",
            evidence,
            exploitPath: [
              "Attacker calls the deletion function with a target object.",
              "Function reaches object delete logic.",
              "Important state or custody records may be destroyed.",
            ],
            impact:
              "Protocol state, receipts, or ownership records may be deleted by unauthorized callers.",
            likelihood: "medium",
            memories,
            memoryQuery: "object delete ownership",
            patchSuggestion:
              "Assert tx_context::sender(ctx) owns the object or require a destroy-specific capability before deletion.",
            recommendation:
              "Protect object destruction paths as privileged lifecycle transitions.",
            remediationSteps: [
              "Require owner/capability authorization before object deletion.",
              "Emit an event or write an audit trail for critical deletions.",
            ],
            ruleId: "SRC_OBJECT_DELETE_WITHOUT_AUTH",
            severity: "high",
            testSuggestions: [
              "Second wallet attempts to delete another user's object and must abort.",
            ],
            title: "Object deletion path may lack authorization",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /(random|lottery|raffle|winner|roll|draw|select)/.test(loweredName) &&
        /(clock::timestamp|epoch|tx_context::digest|ctx\.epoch|%)/i.test(fn.body)
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "Outcome selection uses predictable public chain data.",
              "A caller can influence timing, inputs, or repeated attempts.",
            ],
            category: "Randomness",
            confidence: "medium",
            description:
              "A public randomness-like function appears to use predictable timestamp, epoch, digest, or modulo logic as entropy.",
            evidence,
            exploitPath: [
              "Attacker observes or predicts public entropy inputs.",
              "Attacker times or repeats calls until the outcome is favorable.",
              "Function selects a winner/reward based on predictable data.",
            ],
            impact:
              "Lottery, reward, or selection outcomes may be biased by callers.",
            likelihood: "medium",
            memories,
            memoryQuery: "predictable randomness lottery",
            patchSuggestion:
              "Use a verifiable randomness source or commit-reveal flow instead of timestamp/epoch/modulo-derived entropy.",
            recommendation:
              "Replace predictable entropy with a bias-resistant randomness design.",
            remediationSteps: [
              "Separate commitment and reveal phases if no randomness primitive is available.",
              "Prevent callers from choosing entropy after observing state.",
            ],
            ruleId: "SRC_PREDICTABLE_RANDOMNESS",
            severity: "medium",
            testSuggestions: [
              "Show that repeated calls cannot bias winner selection.",
            ],
            title: "Predictable randomness source",
          }),
        );
      }

      if (
        fn.isPublicEntry &&
        /(vector::borrow|vector::remove|vector::swap_remove|\[[^\]]+\])/i.test(fn.body) &&
        !/(vector::length|\.length\(|is_empty|assert!\s*\([^)]*(len|length|is_empty))/i.test(
          fn.body,
        )
      ) {
        findings.push(
          createSourceFinding({
            attackPrerequisites: [
              "The caller can influence an index or collection size.",
              "The function borrows/removes vector elements without a nearby bound check.",
            ],
            category: "Input validation",
            confidence: "medium",
            description:
              "A public entry function performs vector indexing/removal without an obvious length or emptiness check.",
            evidence,
            exploitPath: [
              "Attacker supplies an out-of-range index or an empty collection state.",
              "Function borrows/removes an element without checking length.",
              "Transaction aborts, potentially causing denial of service or blocking expected execution paths.",
            ],
            impact:
              "Caller-controlled aborts may create denial-of-service conditions or griefing vectors around shared-object workflows.",
            likelihood: "medium",
            memories,
            memoryQuery: "vector bounds abort",
            patchSuggestion:
              "Assert index < vector::length(&items) and handle empty vectors before borrow/remove/swap_remove.",
            recommendation:
              "Add explicit bounds checks and tests for empty/out-of-range inputs.",
            remediationSteps: [
              "Validate index and collection length before vector access.",
              "Return/abort with a documented error code for invalid inputs.",
            ],
            ruleId: "SRC_UNCHECKED_VECTOR_ACCESS",
            severity: "medium",
            testSuggestions: [
              "Call with an empty vector or out-of-range index and assert a controlled abort code.",
            ],
            title: "Unchecked vector access in public entry path",
          }),
        );
      }
    }

    const todo = findSourceMarker(file, /(TODO|FIXME|HACK|SECURITY|AUDIT)/);
    if (todo) {
      findings.push({
        category: "Review marker",
        confidence: "low",
        description:
          "Source contains an audit-relevant marker. This may be harmless, but unresolved security notes should not ship without review.",
        evidence: [todo],
        id: sourceFindingId("SRC_SECURITY_MARKER", file.path, String(todo.lineStart)),
        impact:
          "Security-relevant TODO/FIXME markers can indicate intentionally deferred review around authorization, accounting, or lifecycle behavior.",
        likelihood: "low",
        memoryAssisted: false,
        memoryReferences: [],
        recommendation:
          "Resolve or document the marker before deployment, especially if it touches authorization, accounting, or object lifecycle code.",
        remediationSteps: [
          "Resolve the marker or link it to a reviewed issue.",
          "Add tests if the marker references security-sensitive behavior.",
        ],
        ruleId: "SRC_SECURITY_MARKER",
        severity: "low",
        testSuggestions: [
          "Add a regression test for the behavior described by the marker.",
        ],
        title: "Source contains security review marker",
      });
    }
  }

  return dedupeFindings(findings);
}

function createSourceFinding(options: {
  attackPrerequisites: string[];
  category: string;
  confidence: AuditFinding["confidence"];
  description: string;
  evidence: AuditFinding["evidence"][number];
  exploitPath: string[];
  impact: string;
  likelihood: AuditFinding["likelihood"];
  memories: ExploitMemory[];
  memoryQuery: string;
  patchSuggestion: string;
  recommendation: string;
  remediationSteps: string[];
  ruleId: string;
  severity: FindingSeverity;
  testSuggestions: string[];
  title: string;
}): AuditFinding {
  const memoryReferences = matchMemories(
    options.memories,
    options.memoryQuery,
    options.ruleId,
  );
  return {
    attackPrerequisites: options.attackPrerequisites,
    category: options.category,
    confidence: options.confidence,
    description: options.description,
    evidence: [options.evidence],
    exploitPath: options.exploitPath,
    id: sourceFindingId(
      options.ruleId,
      options.evidence.filePath ?? options.evidence.moduleName,
      options.evidence.functionName ?? options.title,
    ),
    impact: options.impact,
    likelihood: options.likelihood,
    memoryAssisted: memoryReferences.length > 0,
    memoryReferences,
    patchSuggestion: options.patchSuggestion,
    recommendation: options.recommendation,
    remediationSteps: options.remediationSteps,
    ruleId: options.ruleId,
    severity: options.severity,
    testSuggestions: options.testSuggestions,
    title: options.title,
  };
}

function sourceFindingId(ruleId: string, path: string, name: string) {
  return findingId(ruleId, path, name);
}
