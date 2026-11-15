"use strict";
const crypto = require("crypto");
const { BN128_PRIME } = require("./hmac");

// Deterministic policy for Proof Gatekeeper — no model involvement, fail closed.
// Priority order mirrors the trap taxonomy on /events/proof-gatekeeper and the
// circuit's own assertion (decision == AND of the five field checks):
//   proof_vk != registered_vk        -> VK_SUBSTITUTION   (provable)
//   proof_tx already seen            -> PROOF_REUSED      (NO proof to submit)
//   public_balance < minimum         -> THRESHOLD_MISMATCH(provable)
//   current_block >= expiry_block    -> EXPIRED_CONDITION (provable)
//   recipient != condition_recipient -> RECIPIENT_MISMATCH(provable)
//   amount > max_transfer            -> AMOUNT_OVERFLOW   (provable)
//   otherwise                        -> APPROVE / VALID_CONDITION
// Boundaries: balance >= minimum passes, amount <= max passes, current < expiry passes.

const normHex = (v) => (v ?? "").trim().toLowerCase();

function parseUint(v) {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if ([minimum, publicBalance, amount, maxTransfer, expiryBlock, currentBlock].some((x) => x === null)) return null;
  for (const k of ["registered_vk", "proof_vk", "recipient", "condition_recipient", "proof_tx"]) {
    if (typeof input[k] !== "string" || !input[k]) return null;
  }
  return {
    registeredVk: input.registered_vk, proofVk: input.proof_vk,
    minimum, publicBalance, expiryBlock, currentBlock,
    recipient: input.recipient, conditionRecipient: input.condition_recipient,
    amount, maxTransfer, proofTx: input.proof_tx,
  };
}

function evaluate(parsed, isProofTxSeen) {
  if (normHex(parsed.proofVk) !== normHex(parsed.registeredVk))
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  if (isProofTxSeen(parsed.proofTx))
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  if (parsed.publicBalance < parsed.minimum)
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  if (parsed.currentBlock >= parsed.expiryBlock)
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  if (normHex(parsed.recipient) !== normHex(parsed.conditionRecipient))
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  if (parsed.amount > parsed.maxTransfer)
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

// Convert an envelope value to a BN128 field element (decimal string). Hex is
// reduced mod p (a 32-byte hash doesn't fit the field; reduction preserves the
// equality checks the circuit performs). Free-form ids are SHA-256 hashed mod p.
function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") n = v;
  else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else n = BigInt("0x" + crypto.createHash("sha256").update(s).digest("hex"));
  }
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}

// Circuit inputs — 13 signal names recovered from gatekeeper.wasm by two
// independent public sources and confirmed by local proving (see README.md).
// Public signals order: [Poseidon(taskId, salt), registeredVkHash, proofVkHash,
// minimum, publicBalance, expiryBlock, currentBlock, recipient,
// conditionRecipient, amount, maxTransfer, decision, taskId].
function buildCircuitInputs(envelope, parsed, decision, salt) {
  return {
    taskId: toFieldElement(envelope.task_id),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

module.exports = { parseInput, evaluate, toFieldElement, buildCircuitInputs };
