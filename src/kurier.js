"use strict";

// OPTIONAL Kurier (zkVerify) submission — the scored artifact is the inline
// proof + public_signals; proof_tx is an optional on-chain audit pointer
// (build guide §05). This client is active only when KURIER_API_KEY is set.
// Shape per build guide §03 + docs.zkverify.io; the gatekeeper vk is already
// registered on mainnet (vkRegistered: true, no register-vk call).
// Never throws: any failure returns null and the caller still answers the task.
async function submitProofAndPoll(cfg, proof, publicSignals, budgetMs) {
  if (!cfg.kurierApiKey) return null;
  const key = cfg.kurierApiKey;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const submitRes = await fetch(`${cfg.kurierApiUrl}/submit-proof/${key}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: cfg.gatekeeperVkHash },
      }),
    });
    if (!submitRes.ok) { console.error(`[kurier] submit-proof HTTP ${submitRes.status}`); return null; }
    const job = await submitRes.json();
    if (!job.jobId) return null;
    let status = "Submitted", lastTxHash;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, Math.min(cfg.kurierPollIntervalMs, Math.max(0, deadline - Date.now()))));
      const sRes = await fetch(`${cfg.kurierApiUrl}/job-status/${key}/${job.jobId}`);
      if (!sRes.ok) continue;
      const s = await sRes.json();
      status = s.status ?? status;
      const txHash = s.txHash ?? s.transactionInfo?.txHash;
      if (txHash) lastTxHash = txHash;
      if (status === "Failed") return { jobId: job.jobId, status, txHash, finalized: false };
      if (txHash) return { jobId: job.jobId, status, txHash, finalized: status === "Finalized" };
    }
    return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
  } catch (err) {
    console.error("[kurier] submission error:", err.message);
    return null;
  }
}
module.exports = { submitProofAndPoll };
