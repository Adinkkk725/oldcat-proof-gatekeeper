"use strict";
const fs = require("fs");
const path = require("path");

// Seen-set for proof_tx references (PROOF_REUSED detection) + task_id ->
// serialized-response cache for idempotent redelivery. In-memory structures
// are authoritative for the life of the process; a JSON file backs them
// across restarts (atomic tmp+rename writes).
// DEPLOYMENT NOTE: on serverless (Vercel) the file lives in /tmp and may
// vanish on cold start — see README.md ("Deployment notes") for the implication.
class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seenProofTx = new Set();
    this.responseByTaskId = new Map();
    try {
      const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
      for (const tx of data.proofTx ?? []) this.seenProofTx.add(normalizeTx(tx));
      for (const [k, v] of Object.entries(data.responses ?? {})) this.responseByTaskId.set(k, v);
    } catch { /* missing/corrupt -> start empty */ }
  }
  persist() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({
        proofTx: [...this.seenProofTx],
        responses: Object.fromEntries(this.responseByTaskId),
      }));
      fs.renameSync(tmp, this.filePath);
    } catch (err) { console.error("[seen-store] persist failed:", err.message); }
  }
  hasProofTx(tx) { return this.seenProofTx.has(normalizeTx(tx)); }
  recordProofTx(tx) {
    const key = normalizeTx(tx);
    if (key && !this.seenProofTx.has(key)) { this.seenProofTx.add(key); this.persist(); }
  }
  getResponse(taskId) { return this.responseByTaskId.get(taskId) ?? null; }
  recordResponse(taskId, body) {
    if (!this.responseByTaskId.has(taskId)) { this.responseByTaskId.set(taskId, body); this.persist(); }
  }
}
const normalizeTx = (tx) => (tx ?? "").trim().toLowerCase();
module.exports = { SeenStore, normalizeTx };
