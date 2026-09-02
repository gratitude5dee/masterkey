// Masterkey — airv2 partner seam (server-only). The airv2 control plane is a trusted server-side
// caller: it authenticates with a shared secret (AIRV2_PARTNER_SECRET), maps each of its users onto a
// Masterkey user, and receives a short-lived audience-bound MCP access token to attach to /mcp calls
// it proxies for that user's agent. The token and this secret never leave the two control planes —
// airv2 keeps them out of the user's box and browser.
//
// Each airv2 user pays from their OWN per-user Sponge agent wallet (src/lib/wallet.ts); airv2 sends
// the caps it enforces so Masterkey's spend enforcement (M5) mirrors them as a second gate.

import { createHash, timingSafeEqual } from "node:crypto";
import { mintSystemToken, type FirstPartyToken } from "@/lib/agent/first-party-token";
import { upsertUserByAirv2Id, updateSpendSettings } from "@/lib/users";
import { ensureUserWallet, getMasterWallet, type UserWalletInfo } from "@/lib/wallet";
import type { UserDoc } from "@/lib/mcp/types";

export const AIRV2_CLIENT_ID = "airv2";
const AIRV2_TOKEN_TTL_SEC = 60 * 60 * 24; // 24h — airv2 re-mints on expiry

export function verifyPartnerSecret(authorization: string | null): boolean {
  const secret = process.env.AIRV2_PARTNER_SECRET;
  if (!secret || !authorization) return false;
  const m = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!m) return false;
  const a = createHash("sha256").update(m[1]).digest();
  const b = createHash("sha256").update(secret).digest();
  return timingSafeEqual(a, b);
}

export interface Airv2LinkInput {
  airv2UserId: string;
  email?: string | null;
  /** Non-negative; there is no null/unlimited state for the monthly limit. */
  monthlyCapUsd?: number;
  perCallMaxUsd?: number | null;
}

export interface Airv2Link {
  user: UserDoc;
  token: FirstPartyToken;
  wallet: UserWalletInfo | null;
}

/** Find-or-create the Masterkey user for an airv2 user, mirror caps, ensure the wallet, mint a token. */
export async function linkAirv2User(input: Airv2LinkInput): Promise<Airv2Link> {
  const user = await upsertUserByAirv2Id({
    airv2UserId: input.airv2UserId,
    email: input.email,
  });
  const patch: Partial<UserDoc["spend"]> = {};
  if (typeof input.monthlyCapUsd === "number" && input.monthlyCapUsd >= 0) {
    patch.monthlyLimitUsd = input.monthlyCapUsd;
  }
  if (input.perCallMaxUsd !== undefined) {
    // null clears the cap (unlimited); 0 is a real cap that blocks every paid call.
    patch.perCallMaxUsd =
      typeof input.perCallMaxUsd === "number" && input.perCallMaxUsd >= 0 ? input.perCallMaxUsd : null;
  }
  if (Object.keys(patch).length) await updateSpendSettings(user._id, patch);

  let wallet: UserWalletInfo | null = null;
  if (process.env.SPONGE_MASTER_KEY) {
    try {
      wallet = await ensureUserWallet(user._id);
    } catch (e) {
      console.error("[partner/airv2] ensureUserWallet failed", e instanceof Error ? e.message : e);
    }
  }
  const token = await mintSystemToken(user._id, {
    clientId: AIRV2_CLIENT_ID,
    name: "airv2 control plane",
    ttlSec: AIRV2_TOKEN_TTL_SEC,
  });
  return { user, token, wallet };
}

export interface Airv2WalletView {
  agentId: string;
  addresses: Record<string, string>;
  /** chain → token symbol → amount, as reported by Sponge. */
  balances: Record<string, Record<string, string>>;
}

/** Funding address + balances of the airv2 user's per-user wallet (display only). */
export async function airv2WalletView(user: UserDoc): Promise<Airv2WalletView | null> {
  if (!process.env.SPONGE_MASTER_KEY) return null;
  const info = await ensureUserWallet(user._id);
  const wallet = await getMasterWallet(user._id);
  const balances: Airv2WalletView["balances"] = {};
  try {
    const raw = await wallet.getBalances();
    for (const [chain, b] of Object.entries(raw)) balances[chain] = { ...b };
  } catch (e) {
    console.error("[partner/airv2] getBalances failed", e instanceof Error ? e.message : e);
  }
  return { agentId: info.agentId, addresses: info.addresses, balances };
}
