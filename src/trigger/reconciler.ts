// Masterkey — unconfirmed-charge reconciler (RUN_RELIABILITY_SPEC 2.5). Resolves `unconfirmed` ledger
// rows (Sponge reported a payment but we couldn't verify a real on-chain settlement at booking time) so
// the ledger converges to on-chain truth GOING FORWARD.
//
// Policy (locked 2026-06-08): CONSERVATIVE — promote a row to `settled` (+count spend) ONLY when we can
// positively confirm a real, successful, unique on-chain USDC settlement of ~the charged amount;
// anything else → `voided` (never counted). Errs toward under-counting; guarantees no over-charge (D2).
// Timing: act on rows older than 3 min; run every 5 min.
//
// Why not Sponge `getTransactionStatus`? It optimistically returns `pending` for a fabricated/non-existent
// hash (verified live 2026-06-08), so it can't distinguish real-from-fake. We decode the on-chain receipt
// (RPC) + match the USDC Transfer amount instead. EVM chains (base/ethereum) are verifiable here; rows on
// chains we can't yet verify are LEFT (logged), never wrongly voided.
//
// Scope v1: reconciles `unconfirmed` rows. Settled rows carry a receipt-derived hash (Phase 1) and are
// trusted; a periodic re-audit of settled rows is a future enhancement.

import { schedules } from "@trigger.dev/sdk";
import {
  findUnconfirmedToReconcile,
  hasOtherSettledTxHash,
  claimedTxHashes,
  resolveUnconfirmedRow,
  settledCostForRun,
  incSpent,
} from "@/lib/spend/ledger";
import { listSettlementCandidates } from "@/lib/wallet";
import { topicToAddress } from "@/lib/spend/settlement-match";
import { patchRun } from "@/lib/chat/db";

const RECONCILE_AFTER_MS = 3 * 60 * 1000; // a real Base tx confirms in seconds; 3 min is ample

/** USDC contract per EVM chain we can verify. Other networks → unverifiable (leave + log). */
const EVM_USDC: Record<string, { usdc: string; rpc: string }> = {
  base: { usdc: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", rpc: process.env.BASE_RPC_URL || "https://mainnet.base.org" },
  ethereum: { usdc: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", rpc: process.env.ETH_RPC_URL || "https://eth.llamarpc.com" },
};
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

type Verdict = "confirmed" | "rejected"; // rejected = failed / missing / wrong-amount → void

/**
 * Verify an EVM settlement via the tx receipt: success (0x1) AND a USDC Transfer of ~costUsd — to the
 * provider's `payTo` when we know it (`topics[2]` is the Transfer recipient).
 *
 * The recipient check is what makes this verification actually bind to THIS charge. Amount-only matching
 * confirms that *a* transfer of the right size happened, not that it paid the right provider — so a row
 * that never settled could be promoted on another provider's genuine transaction. `expectedPayTo` is
 * optional: legacy rows written before it was persisted verify on amount alone, exactly as before.
 * Throws on a transient RPC error so the caller leaves the row for the next pass (no false void).
 */
async function verifyEvmSettlement(
  chain: string,
  txHash: string,
  costUsd: number,
  expectedPayTo?: string,
): Promise<Verdict> {
  const cfg = EVM_USDC[chain];
  const res = await fetch(cfg.rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionReceipt", params: [txHash] }),
  });
  if (!res.ok) throw new Error(`rpc ${res.status}`);
  const json = (await res.json()) as { result?: { status?: string; logs?: { address: string; topics: string[]; data: string }[] } | null; error?: unknown };
  if (json.error) throw new Error(`rpc error`);
  const receipt = json.result;
  if (!receipt) return "rejected"; // not mined after the delay → conservative void
  if (receipt.status !== "0x1") return "rejected"; // reverted/failed
  const tol = Math.max(0.0005, costUsd * 0.02);
  const want = expectedPayTo?.toLowerCase();
  for (const log of receipt.logs ?? []) {
    if (log.address.toLowerCase() !== cfg.usdc || (log.topics[0] ?? "").toLowerCase() !== TRANSFER_TOPIC) continue;
    if (want && topicToAddress(log.topics[2]) !== want) continue; // paid someone else → not this charge
    const value = Number(BigInt(log.data)) / 1e6; // USDC has 6 decimals
    if (Math.abs(value - costUsd) <= tol) return "confirmed";
  }
  return "rejected"; // succeeded but moved no matching USDC to the expected recipient → not our settlement
}

export async function reconcileUnconfirmed(
  olderThanMs = RECONCILE_AFTER_MS,
): Promise<{ candidates: number; promoted: number; voided: number; skipped: number }> {
  const rows = await findUnconfirmedToReconcile(olderThanMs);
  let promoted = 0;
  let voided = 0;
  let skipped = 0;

  for (const row of rows) {
    try {
      let decision: "settled" | "voided" | "skip";
      // The tx hash to verify/record: the row's own (receipt-derived) or one recovered below for a
      // hashless row (provider returned no per-call receipt — e.g. a burst of same-amount search calls).
      let txHash = row.txHash;

      if (!txHash) {
        // BURST-SAFE recovery: claim a recent on-chain SENT tx of this exact amount — and, when the row
        // recorded one, to this provider's `payTo` — that no other ledger row has taken. Serial
        // reconciliation → distinct same-amount rows get distinct txs (vs the synchronous pay-time
        // recovery, which bails on bursts). The payTo filter keeps a burst from crossing providers.
        // Verified on-chain below before counting.
        const cands = await listSettlementCandidates(row.costUsd, row.network, row.payTo, undefined, row.userId);
        if (cands.length) {
          const claimed = await claimedTxHashes(cands);
          txHash = cands.find((h) => !claimed.has(h));
        }
      }

      if (!txHash) {
        decision = "voided"; // no on-chain SENT tx matches → genuinely nothing settled → void
      } else if (await hasOtherSettledTxHash(txHash, row._id)) {
        decision = "voided"; // this tx already settled another charge → promoting double-counts
      } else if (!EVM_USDC[row.network]) {
        decision = "skip"; // chain we can't verify yet → leave it (never wrongly void a real payment)
      } else {
        const verdict = await verifyEvmSettlement(row.network, txHash, row.costUsd, row.payTo); // may throw → retry
        decision = verdict === "confirmed" ? "settled" : "voided";
      }

      if (decision === "skip") {
        skipped++;
        continue;
      }

      // On settle, persist the recovered hash (if the row was hashless) so it's auditable + claimed.
      const did = await resolveUnconfirmedRow(row._id, decision, decision === "settled" ? txHash : undefined);
      if (!did) {
        skipped++; // another pass already resolved it
        continue;
      }
      if (decision === "settled") {
        await incSpent(row.userId, row.costUsd); // now counted (confirmed real spend)
        if (row.runId) await patchRun(row.runId, { providerCostUsd: await settledCostForRun(row.runId) });
        promoted++;
      } else {
        voided++;
      }
    } catch {
      skipped++; // transient (RPC/db) error → leave the row for the next sweep
    }
  }

  return { candidates: rows.length, promoted, voided, skipped };
}

export const ledgerReconciler = schedules.task({
  id: "masterkey-ledger-reconciler",
  cron: "*/5 * * * *", // every 5 minutes
  run: async () => reconcileUnconfirmed(),
});
