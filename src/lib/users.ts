// Masterkey — user CRUD (server-only). Users are keyed by CDP embedded-wallet address.
// Identity (wallet + email) always comes from the validated CDP token (see src/lib/cdp.ts),
// never from client-sent values (Appendix R R3). See MCP_SPEC.md §5 + M1.

import { randomUUID } from "crypto";
import { getDb } from "@/lib/db";
import { COLLECTIONS, type UserDoc } from "@/lib/mcp/types";
import { ensureIndexes } from "@/lib/mcp/indexes";

function nowISO(): string {
  return new Date().toISOString();
}

/** First day of next month, UTC — the next spend-period reset. */
export function firstOfNextMonthISO(): string {
  const d = new Date();
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1)).toISOString();
}

export function newUserId(): string {
  return `usr_${randomUUID().replace(/-/g, "")}`;
}

/** Default account state for a brand-new user (mirrors seedAccount() minus the hardcoded identity). */
export function seedDefaults(
  email: string | null,
): Pick<UserDoc, "profile" | "billing" | "spend"> {
  const name = email ? email.split("@")[0] : "";
  return {
    profile: { name, org: "Personal", plan: "Pay-as-you-go" },
    billing: {
      card: null,
      spentThisPeriodUsd: 0,
      periodResetsISO: firstOfNextMonthISO(),
      invoices: [],
    },
    spend: {
      monthlyLimitUsd: 50,
      advancedEnabled: false,
      perCallMaxUsd: null,
      rules: [],
      alerts: email
        ? [
            { id: "alert_20", pct: 20, email },
            { id: "alert_100", pct: 100, email },
          ]
        : [],
    },
  };
}

export async function getUser(id: string): Promise<UserDoc | null> {
  const db = await getDb();
  return db.collection<UserDoc>(COLLECTIONS.users).findOne({ _id: id });
}

export async function getUserByWallet(walletAddress: string): Promise<UserDoc | null> {
  const db = await getDb();
  return db
    .collection<UserDoc>(COLLECTIONS.users)
    .findOne({ walletAddress: walletAddress.toLowerCase() });
}

/**
 * Create-or-update a user keyed by wallet address, atomically (race-safe via the
 * unique walletAddress index + upsert). Seed defaults are applied only on insert.
 */
export async function upsertUserByWallet(input: {
  walletAddress: string;
  email: string | null;
  cdpUserId?: string;
  smartAccountAddress?: string | null;
  solanaAddress?: string | null;
}): Promise<UserDoc> {
  await ensureIndexes();
  const db = await getDb();
  const users = db.collection<UserDoc>(COLLECTIONS.users);
  const walletAddress = input.walletAddress.toLowerCase();

  const set: Partial<UserDoc> = { updatedISO: nowISO() };
  if (input.email !== undefined) set.email = input.email;
  if (input.cdpUserId) set.cdpUserId = input.cdpUserId;
  if (input.smartAccountAddress !== undefined)
    set.smartAccountAddress = input.smartAccountAddress;
  if (input.solanaAddress !== undefined) set.solanaAddress = input.solanaAddress;

  const result = await users.findOneAndUpdate(
    { walletAddress },
    {
      $set: set,
      $setOnInsert: {
        _id: newUserId(),
        ...seedDefaults(input.email),
        createdISO: nowISO(),
      },
    },
    { upsert: true, returnDocument: "after" },
  );

  if (!result) {
    // Should not happen with returnDocument:"after" + upsert; refetch defensively.
    const doc = await users.findOne({ walletAddress });
    if (!doc) throw new Error("upsertUserByWallet failed to return a user");
    return doc;
  }
  return result;
}

export async function getSpendSettings(id: string): Promise<UserDoc["spend"] | null> {
  const u = await getUser(id);
  return u ? u.spend : null;
}

export async function updateSpendSettings(
  id: string,
  patch: Partial<UserDoc["spend"]>,
): Promise<void> {
  const db = await getDb();
  const set: Record<string, unknown> = { updatedISO: nowISO() };
  for (const [k, v] of Object.entries(patch)) set[`spend.${k}`] = v;
  await db.collection<UserDoc>(COLLECTIONS.users).updateOne({ _id: id }, { $set: set });
}

/**
 * Record the user's per-user Sponge agent (wallet seam). Only the agent id — never a key.
 * Atomic first-writer-wins claim: only sets when no agent is stored yet, and always returns the
 * agent that ends up on the user, so concurrent provisioners converge on one wallet (funds are
 * only ever sent to the stored agent's address).
 */
export async function claimUserSpongeAgent(id: string, agentId: string): Promise<string> {
  const db = await getDb();
  const users = db.collection<UserDoc>(COLLECTIONS.users);
  const claimed = await users.findOneAndUpdate(
    { _id: id, "sponge.agentId": { $exists: false } },
    { $set: { sponge: { agentId, createdISO: nowISO() }, updatedISO: nowISO() } },
    { returnDocument: "after" },
  );
  if (claimed?.sponge?.agentId) return claimed.sponge.agentId;
  const current = await users.findOne({ _id: id });
  const winner = current?.sponge?.agentId;
  if (!winner) throw new Error(`claimUserSpongeAgent: no stored agent for ${id}`);
  return winner;
}

/**
 * Find-or-create the Masterkey user for an airv2 control-plane user. Keyed by `externalIds.airv2`,
 * always under a synthetic `airv2:<id>` wallet key that no real EOA can collide with — a
 * partner-supplied wallet address must never select (and thereby grant tokens for) an existing
 * wallet-authed account, since the partner cannot prove ownership of that wallet here.
 */
export async function upsertUserByAirv2Id(input: {
  airv2UserId: string;
  email?: string | null;
}): Promise<UserDoc> {
  await ensureIndexes();
  const db = await getDb();
  const users = db.collection<UserDoc>(COLLECTIONS.users);
  const walletAddress = `airv2:${input.airv2UserId}`.toLowerCase();
  const existing = await users.findOne({ "externalIds.airv2": input.airv2UserId });
  if (existing) {
    if (existing.walletAddress === walletAddress) return existing;
    // A link that points at a wallet-authed account (created by the removed wallet_address path) must
    // not keep granting the partner tokens for it — detach it and fall through to the synthetic account.
    await users.updateOne(
      { _id: existing._id, "externalIds.airv2": input.airv2UserId },
      { $unset: { "externalIds.airv2": "" }, $set: { updatedISO: nowISO() } },
    );
  }
  const result = await users.findOneAndUpdate(
    { walletAddress },
    {
      $set: { "externalIds.airv2": input.airv2UserId, updatedISO: nowISO() },
      $setOnInsert: {
        _id: newUserId(),
        email: input.email ?? null,
        ...seedDefaults(input.email ?? null),
        createdISO: nowISO(),
      },
    },
    { upsert: true, returnDocument: "after" },
  );
  if (!result) throw new Error("upsertUserByAirv2Id failed to return a user");
  return result;
}
