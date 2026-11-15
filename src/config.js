"use strict";
const fs = require("fs");
const path = require("path");

// All configuration from environment. No secret has a default: the HMAC secret
// must come from the platform dashboard ("Rotate Secret").
function defaultCircuitsDir() {
  const candidates = [
    process.env.CIRCUITS_DIR,
    path.resolve(__dirname, "..", "circuits"), // <project>/circuits — the layout this repo ships
    path.resolve(process.cwd(), "circuits"),
    path.resolve(__dirname, "..", "..", "circuits"), // sibling circuits/ dir (monorepo-style layouts)
  ].filter(Boolean);
  for (const c of candidates) if (fs.existsSync(path.join(c, "gatekeeper.wasm"))) return c;
  return candidates[0];
}
function defaultSeenStorePath() {
  if (process.env.VERCEL) return "/tmp/gatekeeper-seen.json";
  return path.resolve(__dirname, "..", "data", "seen.json");
}
function loadConfig(env = process.env) {
  return {
    hmacSecret: env.AGENT_GAMES_HMAC_SECRET ?? "",
    kurierApiKey: env.KURIER_API_KEY ? env.KURIER_API_KEY : null,
    kurierApiUrl: env.KURIER_API_URL ?? "https://api.kurier.xyz/api/v1",
    // Registered gatekeeper vk_hash (zkVerify mainnet) from /api/circuit-info.
    gatekeeperVkHash: env.GATEKEEPER_VK_HASH ??
      "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    circuitsDir: defaultCircuitsDir(),
    seenStorePath: env.SEEN_STORE_PATH ?? defaultSeenStorePath(),
    kurierPollBudgetMs: Number(env.KURIER_POLL_BUDGET_MS ?? 15_000),
    kurierPollIntervalMs: Number(env.KURIER_POLL_INTERVAL_MS ?? 3_000),
    taskSoftDeadlineMs: Number(env.TASK_SOFT_DEADLINE_MS ?? 50_000), // hard platform deadline: 60 s
    port: Number(env.PORT ?? 8787),
  };
}
module.exports = { loadConfig };
