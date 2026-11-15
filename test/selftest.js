"use strict";
// Self-test: boots the real server on an ephemeral port and replays signed,
// spec-shaped envelopes for every trap type + valid + protocol edge cases.
// Asserts decision + reason_code, verifies every returned Groth16 proof
// locally against the official verification key, and checks response
// signatures, idempotency, and the PROOF_REUSED no-proof rule.
process.env.AGENT_GAMES_HMAC_SECRET = "selftest-secret-not-a-platform-secret";
process.env.SEEN_STORE_PATH = require("path").join(__dirname, "tmp-seen.json");
process.env.KURIER_API_KEY = ""; // Kurier disabled: inline proof is the scored artifact

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { createAgentServer } = require("../src/server");
const { signBody, verifyBodySignature } = require("../src/hmac");

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
const info = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "circuits", "circuit-info.json"), "utf8"));
const VK_HASH = info.circuits.gatekeeper.vkHash;
const VK_JSON = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "circuits", "verification_key.json"), "utf8"));
const RECIPIENT = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
const OTHER_RECIPIENT = "0x742d35Cc6634C0532925a3b844Bc454e4438f44f";
const tx = (seed) => "0x" + crypto.createHash("sha256").update(seed).digest("hex");

try { fs.unlinkSync(process.env.SEEN_STORE_PATH); } catch {}

let pass = 0, fail = 0;
const results = [];
function check(name, cond, extra = "") {
  if (cond) { pass++; results.push(`PASS  ${name}${extra ? "  (" + extra + ")" : ""}`); }
  else { fail++; results.push(`FAIL  ${name}${extra ? "  (" + extra + ")" : ""}`); }
}

function makeTask(taskId, overrides = {}) {
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "practice",
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + 55_000).toISOString(),
    input: {
      registered_vk: VK_HASH, proof_vk: VK_HASH,
      minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000,
      recipient: RECIPIENT, condition_recipient: RECIPIENT,
      amount: "500", max_transfer: "1000",
      proof_tx: tx("proof-" + taskId),
      ...overrides,
    },
  };
}

let base;
async function post(rawBody, signature) {
  const headers = { "content-type": "application/json" };
  if (signature !== undefined) headers["x-agent-games-signature"] = signature;
  const t0 = Date.now();
  const res = await fetch(`${base}/agent`, { method: "POST", headers, body: rawBody });
  const text = await res.text();
  return { status: res.status, text, json: safeParse(text), sig: res.headers.get("x-agent-games-signature"), ms: Date.now() - t0 };
}
const safeParse = (t) => { try { return JSON.parse(t); } catch { return null; } };
const postSigned = (obj, enc = "hex") => {
  const raw = JSON.stringify(obj);
  let sig = signBody(SECRET, raw);
  if (enc === "base64") sig = Buffer.from(sig, "hex").toString("base64");
  return post(raw, sig);
};

async function expectTask(name, envelope, decision, reason, withProof) {
  const r = await postSigned(envelope);
  let proofOk = null;
  if (withProof && r.json?.proof) {
    proofOk = await snarkjs.groth16.verify(VK_JSON, r.json.public_signals, r.json.proof);
  }
  check(`${name}: HTTP 200`, r.status === 200, `got ${r.status}`);
  check(`${name}: decision=${decision}`, r.json?.decision === decision, `got ${r.json?.decision}`);
  check(`${name}: reason_code=${reason}`, r.json?.reason_code === reason, `got ${r.json?.reason_code}`);
  if (withProof) {
    check(`${name}: proof present, 13 public signals`, !!r.json?.proof && r.json?.public_signals?.length === 13);
    check(`${name}: proof verifies locally`, proofOk === true);
  } else {
    check(`${name}: NO proof attached (documented PROOF_REUSED rule)`, !r.json?.proof);
  }
  check(`${name}: response signature valid`, !!r.sig && verifyBodySignature(SECRET, r.text, r.sig));
  check(`${name}: within 60s deadline`, r.ms < 60_000, `${r.ms} ms`);
  return r;
}

(async () => {
  const server = createAgentServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
  try {
    // Health
    const h = await (await fetch(`${base}/agent`)).json();
    check("health: GET /agent {ok, protocolVersion v1}", h.ok === true && h.protocolVersion === "v1");

    // Preflight
    const pf = await postSigned({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
    check("preflight: HTTP 200 + {ok:true, protocolVersion:v1}", pf.status === 200 && pf.json?.ok === true && pf.json?.protocolVersion === "v1");
    check("preflight: response signature valid", !!pf.sig && verifyBodySignature(SECRET, pf.text, pf.sig));
    const pfBad = await post(JSON.stringify({ type: "agent-games.preflight.v1" }), "0".repeat(64));
    check("preflight: bad signature -> 401", pfBad.status === 401, `got ${pfBad.status}`);

    // Tampered body -> 401
    const rawValid = JSON.stringify(makeTask("gk_t_tamper"));
    const tampered = await post(rawValid.replace("1460", "1461"), signBody(SECRET, rawValid));
    check("tamper: signed-then-modified body -> 401", tampered.status === 401, `got ${tampered.status}`);

    // Scored-shape tasks
    await expectTask("valid", makeTask("gk_t_valid"), "APPROVE", "VALID_CONDITION", true);
    await expectTask("vk-substitution", makeTask("gk_t_vk", { proof_vk: "0x13ab00000000000000000000000000000000000000000000000000000000aa" }), "REJECT", "VK_SUBSTITUTION", true);
    await expectTask("threshold-mismatch", makeTask("gk_t_threshold", { public_balance: "900" }), "REJECT", "THRESHOLD_MISMATCH", true);
    await expectTask("expired", makeTask("gk_t_expired", { current_block: 8430000 }), "REJECT", "EXPIRED_CONDITION", true);
    await expectTask("recipient-mismatch", makeTask("gk_t_recipient", { recipient: OTHER_RECIPIENT }), "REJECT", "RECIPIENT_MISMATCH", true);
    await expectTask("amount-overflow", makeTask("gk_t_amount", { amount: "1500" }), "REJECT", "AMOUNT_OVERFLOW", true);

    // Proof reuse: first use approves, second (new task_id, same proof_tx) rejects with no proof
    const reusedTx = tx("reused-proof");
    await expectTask("reuse-source", makeTask("gk_t_reuse_src", { proof_tx: reusedTx }), "APPROVE", "VALID_CONDITION", true);
    await expectTask("proof-reused", makeTask("gk_t_reuse", { proof_tx: reusedTx }), "REJECT", "PROOF_REUSED", false);

    // Idempotent redelivery: exact same envelope as "valid" -> identical body, still APPROVE
    const again = await postSigned(makeTask("gk_t_valid"));
    check("idempotency: redelivery returns APPROVE (not PROOF_REUSED)", again.json?.decision === "APPROVE" && again.json?.reason_code === "VALID_CONDITION");

    // Base64-encoded signature accepted (same MAC bytes)
    const b64 = await postSigned(makeTask("gk_t_b64"), "base64");
    check("hmac: base64 signature encoding accepted", b64.status === 200 && b64.json?.decision === "APPROVE", `got ${b64.status}/${b64.json?.decision}`);

    // Malformed input fails closed
    const bad = makeTask("gk_t_bad", { minimum: "not-a-number" });
    const badRes = await postSigned(bad);
    check("fail-closed: malformed input -> REJECT/INVALID_TASK", badRes.json?.decision === "REJECT" && badRes.json?.reason_code === "INVALID_TASK");
  } finally {
    server.close();
    try { fs.unlinkSync(process.env.SEEN_STORE_PATH); } catch {}
  }
  console.log(results.join("\n"));
  console.log(`\nSELFTEST: ${pass} passed, ${fail} failed, ${pass + fail} total`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error("SELFTEST ERROR:", e); process.exit(2); });
