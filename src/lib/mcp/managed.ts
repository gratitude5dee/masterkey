// Masterkey — per-user managed values (server-only). A generic create-once store: a user gets ONE of
// a managed value (e.g. an agentmail inbox, or — future — a saved postal address), obtained once and
// reused across runs. Two kinds:
//   • "provisioned" — created via a paid operation under STANDARD spend enforcement (reserve→pay→
//     settle; over-limit → typed reject the caller surfaces as "raise your limit"). agentmail uses this.
//   • "value" — a value the user supplies once, saved so we don't re-ask (no consumer yet; the store
//     + setUserResource are ready, e.g. a future PostalForm postal address).
// Services opt in via the registry `managedResource` flag (src/data/types.ts). Only agentmail today.

import { getDb } from "@/lib/db";
import { COLLECTIONS, type UserResourceDoc, type ManagedResourceKind } from "@/lib/mcp/types";
import { payProvider, PaymentExceededError } from "@/lib/wallet";
import { reserveSpend, settleSpend, releaseReservation, recordRejected, type CallRef } from "@/lib/spend/enforce";
import { findServiceById } from "@/lib/registry";

export type ManagedResult =
  | { ok: true; value: string; key: string; created: boolean; label?: string }
  | { ok: false; code: string; message: string };

function isDupKey(e: unknown): boolean {
  return !!e && typeof e === "object" && (e as { code?: number }).code === 11000;
}

function extractAddress(body: unknown): string | null {
  const tryObj = (o: unknown): string | null => {
    if (o && typeof o === "object") {
      const r = o as Record<string, unknown>;
      const v = r.inbox_id ?? r.email ?? r.address ?? r.id;
      if (typeof v === "string") return v;
    }
    return null;
  };
  let found = tryObj(body);
  if (!found && typeof body === "string") {
    try {
      found = tryObj(JSON.parse(body));
    } catch {
      /* not json */
    }
  }
  if (!found) {
    const m = JSON.stringify(body ?? "").match(/([a-z0-9][a-z0-9._-]*@agentmail\.to)/i);
    found = m ? m[1] : null;
  }
  return found;
}

// --- generic store -----------------------------------------------------------------------------

/** Look up the user's managed value for `key` (no creation, no charge). */
export async function getUserResource(userId: string, key: string): Promise<UserResourceDoc | null> {
  const db = await getDb();
  return db.collection<UserResourceDoc>(COLLECTIONS.userResources).findOne({ _id: `${userId}::${key}` });
}

/** Save a user-supplied value (kind "value") so we don't re-ask (e.g. a postal address). Upsert. */
export async function setUserResource(userId: string, key: string, value: string, kind: ManagedResourceKind = "value", label?: string): Promise<void> {
  const db = await getDb();
  await db.collection<UserResourceDoc>(COLLECTIONS.userResources).updateOne(
    { _id: `${userId}::${key}` },
    { $set: { userId, key, kind, value, ...(label ? { label } : {}), }, $setOnInsert: { createdISO: new Date().toISOString() } },
    { upsert: true },
  );
}

/** Store a freshly-provisioned value, tolerating a concurrent winner (returns whichever persisted). */
async function store(userId: string, key: string, value: string, kind: ManagedResourceKind, label?: string): Promise<{ value: string; created: boolean }> {
  const db = await getDb();
  try {
    await db.collection<UserResourceDoc>(COLLECTIONS.userResources).insertOne({
      _id: `${userId}::${key}`,
      userId,
      key,
      kind,
      value,
      ...(label ? { label } : {}),
      createdISO: new Date().toISOString(),
    });
    return { value, created: true };
  } catch (e) {
    if (isDupKey(e)) {
      const ex = await getUserResource(userId, key);
      if (ex) return { value: ex.value, created: false }; // a concurrent create won
    }
    throw e;
  }
}

/** Return the user's resource for `key`, or run `provision` ONCE (it does its own spend enforcement). */
async function getOrProvision(
  userId: string,
  key: string,
  kind: ManagedResourceKind,
  label: string | undefined,
  provision: () => Promise<{ ok: true; value: string } | { ok: false; code: string; message: string }>,
): Promise<ManagedResult> {
  const existing = await getUserResource(userId, key);
  if (existing) return { ok: true, value: existing.value, key, created: false, label: existing.label };
  const p = await provision();
  if (!p.ok) return p;
  const s = await store(userId, key, p.value, kind, label);
  return { ok: true, value: s.value, key, created: s.created, label };
}

// --- agentmail inbox (the one provisioned consumer today) --------------------------------------

const AGENTMAIL_FALLBACK_URL = "https://x402.api.agentmail.to/v0/inboxes";

/** Provision an agentmail inbox under standard spend enforcement (reserve → pay → settle). */
async function provisionAgentmailInbox(userId: string, connectionId: string): Promise<{ ok: true; value: string } | { ok: false; code: string; message: string }> {
  const svc = findServiceById("agentmail");
  // Match the curated operation name exactly ("Create Inbox"); the ?? fallbacks below keep this
  // working even if the registry entry is renamed.
  const op = svc?.operations.find((o) => o.name === (svc.managedResource?.createOperation ?? "Create Inbox"));
  const url = op?.url ?? AGENTMAIL_FALLBACK_URL;
  const estCost = op?.price?.amount ?? 2;

  const reserve = await reserveSpend({ userId, connectionId, category: "communication", estCostUsd: estCost });
  const ref: CallRef = { userId, connectionId, serviceId: "agentmail", serviceName: "AgentMail inbox (provisioned)", operation: "Create inbox", provider: "AgentMail", backendUrl: url, bucket: reserve.bucket };
  if (!reserve.allow) {
    await recordRejected(ref, reserve.reason);
    return { ok: false, code: reserve.reason, message: `${reserve.message}. Raise your limit in Settings (/dashboard/limits) to continue.` };
  }

  let pay;
  try {
    pay = await payProvider({ url, method: "POST", body: { display_name: "Masterkey" }, maxValueUsd: reserve.maxValueUsd, payerUserId: userId });
  } catch (e) {
    await releaseReservation(ref, { reservedUsd: reserve.reservedUsd, status: "failed" });
    if (e instanceof PaymentExceededError) {
      return { ok: false, code: "price_exceeded", message: `Creating an email inbox costs $${estCost}, which exceeds your per-call limit. Raise it in Settings (/dashboard/limits) to continue.` };
    }
    return { ok: false, code: "payment_failed", message: e instanceof Error ? e.message : String(e) };
  }
  if (!pay.ok && !pay.paid) {
    await releaseReservation(ref, { reservedUsd: reserve.reservedUsd, status: "failed", network: pay.network });
    return { ok: false, code: "provider_error", message: `AgentMail returned ${pay.status} creating the inbox` };
  }

  await settleSpend(ref, { reservedUsd: reserve.reservedUsd, actualCostUsd: pay.costUsd, network: pay.network, confirmed: pay.confirmed, ...(pay.txHash ? { txHash: pay.txHash } : {}) });
  const address = extractAddress(pay.body);
  if (!address) return { ok: false, code: "provider_error", message: "Could not read the inbox address from AgentMail." };
  return { ok: true, value: address };
}

/** The user's managed email inbox (agentmail) — created once under spend enforcement, reused after. */
export async function getOrCreateUserInbox(userId: string, connectionId: string): Promise<ManagedResult> {
  const mr = findServiceById("agentmail")?.managedResource;
  const key = mr?.key ?? "agentmail:inbox";
  const label = mr?.label ?? "Email inbox";
  return getOrProvision(userId, key, "provisioned", label, () => provisionAgentmailInbox(userId, connectionId));
}
