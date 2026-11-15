"use strict";
const crypto = require("crypto");

// HMAC scheme: primary sources specify only "HMAC over the raw body" vs the
// x-agent-games-signature header (algorithm/encoding undocumented). Convention
// below is the one empirically proven against the live platform preflight by a
// public implementation: HMAC-SHA256, hex when signing; verification accepts
// hex or base64 of the same MAC bytes (optional "sha256=" prefix), constant-time.

function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function decodeCandidate(headerValue) {
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice("sha256=".length).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  } catch { /* fall through */ }
  return null;
}

function verifyBodySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const candidate = decodeCandidate(headerValue);
  if (!candidate) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest();
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Deterministic per-task salt for the circuit's private `salt` input, so an
// idempotent redelivery reproduces identical proof inputs.
function deriveSalt(secret, taskId) {
  const digest = crypto
    .createHmac("sha256", secret || "gatekeeper-local-dev")
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

module.exports = { signBody, verifyBodySignature, deriveSalt, BN128_PRIME };
