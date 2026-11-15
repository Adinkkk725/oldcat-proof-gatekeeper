# Proof Gatekeeper Agent — zkVerify Agent Games

A Node.js agent for the **Proof Gatekeeper** track of the [zkVerify Agent Games](https://agentgames.zkverify.io).
The platform sends this agent signed payment-condition tasks; the agent decides
**APPROVE** or **REJECT**, and backs every provable decision with a **Groth16
zero-knowledge proof generated locally** — so the platform can verify *that the
decision follows the rules* without trusting the agent's word.

- **Deterministic policy** — no language model anywhere near the decision path. The same input always produces the same output.
- **Proof-carrying responses** — every provable task is answered with a Groth16 proof (snarkjs, BN128) plus its 13 public signals.
- **Fail-closed** — malformed input, bad signatures, and proving failures never become unproven approvals.
- **Fast** — measured ~490–680 ms per provable task on a small shared VM (1.5 vCPU), against a 60-second platform deadline.

## How the decision works

Each task describes a payment condition and a proof reference. The agent checks
the fields in a fixed priority order — the first failing check decides:

| # | Check | If it fails | Reason code |
|---|-------|-------------|-------------|
| 1 | Proof's verification key == registered condition VK | REJECT | `VK_SUBSTITUTION` |
| 2 | Proof reference not seen before (local seen-set) | REJECT | `PROOF_REUSED` |
| 3 | Public balance ≥ minimum threshold | REJECT | `THRESHOLD_MISMATCH` |
| 4 | Condition not expired (`current_block < expiry_block`) | REJECT | `EXPIRED_CONDITION` |
| 5 | Recipient == condition recipient | REJECT | `RECIPIENT_MISMATCH` |
| 6 | Amount ≤ single-transfer cap | REJECT | `AMOUNT_OVERFLOW` |
| — | All checks pass | APPROVE | `VALID_CONDITION` |

Boundary semantics are the circuit's own: balance `>=` minimum passes, amount
`<=` cap passes, `current_block < expiry_block` passes.

Two special rules:

- **PROOF_REUSED carries no proof.** The event rules state reused-proof tasks have no proof to submit, so the agent answers with the decision only.
- **Idempotency.** `task_id` is the idempotency key: a platform redelivery returns the cached response and is never misread as proof reuse.

## How the proof works

The decision is proven with the official Gatekeeper circuit
(Groth16 / BN128, compiled with Circom 2.x):

- Artifacts in `circuits/`: `gatekeeper.wasm` (1,755,820 B, sha256 `be00aefe…64f`) and `gatekeeper_final.zkey` (309,750 B, sha256 `adfe95a4…80d`), downloaded from the URLs published by the platform's own `/api/circuit-info`.
- Registered verification-key hash on zkVerify mainnet: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` (see `circuits/circuit-info.json`).
- The circuit takes 13 inputs (12 public + a private per-task salt) and **asserts that the decision equals the AND of the five field checks** (VK equality, balance ≥ minimum, not expired, recipient equality, amount ≤ cap). A wrong decision cannot produce a witness, let alone a proof — this was confirmed experimentally: valid scenarios prove and verify; the same scenarios with a flipped decision fail inside the circuit's assertion.
- Proofs are generated in-process with `snarkjs.groth16.fullProve` and returned inline as `{ decision, reason_code, proof, public_signals }`.
- Optionally, if `KURIER_API_KEY` is set, the proof is also submitted to zkVerify via Kurier and the returned transaction hash is attached as the optional `proof_tx` audit pointer. Scoring does not depend on this.

## Preflight & HMAC

The platform authenticates every delivery, and the agent authenticates every
response, with an HMAC in the `x-agent-games-signature` header, computed over
the **raw body before parsing**:

- The platform issues a 32-byte secret when the agent is registered (dashboard → agent → *Rotate Secret*, shown once). It is supplied to this code only through the `AGENT_GAMES_HMAC_SECRET` environment variable — it is never stored in this repository.
- Incoming signatures are verified in constant time before any JSON parsing; unsigned or tampered bodies get `401`.
- Responses are signed the same way over the exact response bytes.
- A signed preflight (`{ "type": "agent-games.preflight.v1", … }`) is answered with a signed `{ "ok": true, "protocolVersion": "v1" }`; `GET /agent` serves the same payload as the health check.

*Documentation note:* the official build guide specifies "HMAC over the raw body" but does not publish the exact algorithm/encoding. This implementation uses HMAC-SHA256 with hex encoding (accepting hex or base64 inbound), the convention used by agents that pass the platform's live preflight.

## Architecture

```
platform ──signed POST──▶ api/agent.js (Vercel) / src/server.js (long-lived)
                              │
                              ▼
                         src/handler.js     pipeline: verify HMAC → preflight?
                              │             → idempotency cache → deadline check
                              ▼
                         src/decision.js    parse + trap evaluation + circuit inputs
                              │
                              ▼
                         src/prover.js      snarkjs fullProve (circuits/*.wasm/.zkey)
                              │
                              ├─▶ src/kurier.js   optional on-chain submission (proof_tx)
                              ▼
                         signed JSON response
                         src/seenStore.js   proof_tx seen-set + response cache
                         src/hmac.js        sign/verify + per-task salt derivation
                         src/config.js      environment-only configuration
```

## Run locally

Requirements: Node.js ≥ 18.

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<redacted> npm start   # listens on :8787, POST /agent
```

## Test

```bash
npm test
```

The self-test boots the real server on an ephemeral port and replays signed,
spec-shaped envelopes: the valid case, every trap type, preflight, bad/tampered
signatures, idempotent redelivery, and the PROOF_REUSED no-proof rule. Every
returned proof is verified locally against the official verification key.

**Current result: 63 passed, 0 failed** — warm response ~490–680 ms per provable
task, ~5 ms for PROOF_REUSED (measured on a 1.5-vCPU shared VM; first, cold
task ~1.5 s including WASM load).

## Configuration (environment only)

| Variable | Required | Purpose |
|----------|----------|---------|
| `AGENT_GAMES_HMAC_SECRET` | **Yes** (in production) | Platform-issued HMAC secret (dashboard → Rotate Secret). No default exists. |
| `KURIER_API_KEY` | No | Enables optional Kurier submission for the `proof_tx` audit pointer. |
| `KURIER_API_URL` | No | Kurier API base (default: mainnet `https://api.kurier.xyz/api/v1`). |
| `GATEKEEPER_VK_HASH` | No | Overrides the registered circuit VK hash default. |
| `CIRCUITS_DIR` | No | Overrides circuit artifact location (default: this repo's `circuits/`). |
| `SEEN_STORE_PATH` | No | Seen-set file location (default `data/seen.json`; `/tmp` on Vercel). |
| `PORT` | No | Listen port for `npm start` (default 8787). |

See `.env.example` for the full list. **Never commit a real `.env` file** — it is git-ignored by design.

## Deployment notes

- The registered endpoint is the full handler path, e.g. `https://<host>/agent` — public HTTPS, no custom ports (platform rules).
- On **Vercel**, `api/agent.js` is the function entry; `vercel.json` bundles `circuits/**` into that function (`includeFiles`) and allows a 60 s max duration. Framework preset: *Other*; root directory: the repo root; no build command.
- **Seen-set caveat on serverless:** the seen-set file lives in `/tmp` on Vercel and can reset on cold starts, which can weaken PROOF_REUSED detection across instance recycles. The in-memory set covers a warm instance. For maximum reuse-detection reliability, run the same code as a single long-lived process (`npm start`) behind any public HTTPS front.

## Competition facts

- Event: zkVerify Agent Games, Proof Gatekeeper track — 8 daily scored rounds, 13–20 Nov 2026, 8 tasks per agent per round, 60-second response deadline, scores cumulative.
- Scoring: correct decision +12; wrong APPROVE −6; wrong REJECT −3; timeout −2; missing/invalid proof on a provable task −2; reliability bonus +0…+5 per round pro-rated by verified proofs.
- Entry is free; this agent was built and tested locally before registration, and its first scored round is Round 3 (15 Nov 2026).

## License

ISC
