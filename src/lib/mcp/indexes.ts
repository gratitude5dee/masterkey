// Masterkey — MongoDB index setup (server-only). Idempotent; safe to call repeatedly.
// See MCP_SPEC.md §5 + Appendix R (R5 revoke-by-connection / connection dedupe).

import { getDb } from "@/lib/db";
import { COLLECTIONS } from "@/lib/mcp/types";

let _ensured: Promise<void> | undefined;

async function create(): Promise<void> {
  const db = await getDb();
  await Promise.all([
    // users — one per wallet
    db.collection(COLLECTIONS.users).createIndex({ walletAddress: 1 }, { unique: true }),
    // partner identity (airv2 users.id) → one Masterkey user
    db.collection(COLLECTIONS.users).createIndex(
      { "externalIds.airv2": 1 },
      { unique: true, partialFilterExpression: { "externalIds.airv2": { $type: "string" } } },
    ),
    // connections — by user, and dedupe key (client + user) for upsert (R5)
    db.collection(COLLECTIONS.connections).createIndex({ userId: 1 }),
    db.collection(COLLECTIONS.connections).createIndex({ client: 1, userId: 1 }),
    // auth codes — short-lived (TTL on expiresAt)
    db.collection(COLLECTIONS.authCodes).createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    // tokens — TTL, lookup by hash, revoke-by-connection (R5)
    db.collection(COLLECTIONS.tokens).createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection(COLLECTIONS.tokens).createIndex({ hashedToken: 1 }),
    db.collection(COLLECTIONS.tokens).createIndex({ connectionId: 1 }),
    // ledger — per-user, newest first
    db.collection(COLLECTIONS.ledger).createIndex({ userId: 1, createdAt: -1 }),
    // run_idempotency — _id is the unique (userId,key) guard; TTL must exceed max run + retry window.
    db.collection(COLLECTIONS.runIdempotency).createIndex({ createdAt: 1 }, { expireAfterSeconds: 604_800 }), // 7d
    // bundles — slug unique PER OWNER (spec §1.2/§1.8); + per-owner listing newest-first.
    db.collection(COLLECTIONS.bundles).createIndex({ ownerUserId: 1, slug: 1 }, { unique: true }),
    db.collection(COLLECTIONS.bundles).createIndex({ ownerUserId: 1, updatedISO: -1 }),
  ]);
}

/** Ensure all Masterkey indexes exist. Memoized per process so it runs at most once. */
export async function ensureIndexes(): Promise<void> {
  if (!_ensured) _ensured = create();
  return _ensured;
}
