// Masterkey — first-party MCP token for the web brain (server-only). Minted at run start (POST
// /api/runs) and passed into the durable task, which calls our /mcp over HTTP with it as the Bearer
// (one enforcement path — same M5 spend + M7 idempotency as the agent side). Audience-bound to the
// MCP resourceUrl (Appendix W-R / R1) so verifyMcpToken accepts it; bound to a system ConnectionDoc
// (clientId "masterkey-web", one per user) whose `scopes` cap which spend buckets the run may touch.
//
// TTL: the standard OAuth access token is 1h (config), which would expire mid-run — a run can pause on
// an approval waitpoint for up to 24h. So we mint a run-lifetime access token directly (48h) covering
// the waitpoint TTL + execution margin. It's run-scoped + revocable via the connection.

import { randomUUID } from "node:crypto";
import { getDb } from "@/lib/db";
import { COLLECTIONS, type TokenDoc } from "@/lib/mcp/types";
import { hashToken, randomToken } from "@/lib/oauth/crypto";
import { upsertConnection } from "@/lib/oauth/store";
import { MCP_RESOURCE_URL, DEFAULT_SCOPE } from "@/lib/oauth/config";

const WEB_CLIENT_ID = "masterkey-web";
const WEB_TOKEN_TTL_SEC = 60 * 60 * 48; // 48h — covers the 24h approval waitpoint + execution margin

export interface FirstPartyToken {
  token: string;
  connectionId: string;
  expiresInSec: number;
}

/**
 * Ensure the user's system "masterkey-web" connection, then mint a run-lifetime, audience-bound MCP
 * access token. NOTE (W-S minor — least privilege): we default the connection's spend scopes to
 * ["all"]; the W6 default-deny approval gate is the real guard for ecommerce/payments. A future
 * refinement requires explicit opt-in for those buckets.
 */
export async function mintFirstPartyToken(userId: string): Promise<FirstPartyToken> {
  return mintSystemToken(userId, { clientId: WEB_CLIENT_ID, name: "Masterkey Web" });
}

/**
 * Same shape for other trusted server-side callers (e.g. the airv2 control-plane proxy, clientId
 * "airv2"): one system connection per (user, client), a hashed audience-bound access token.
 */
export async function mintSystemToken(
  userId: string,
  opts: { clientId: string; name: string; ttlSec?: number },
): Promise<FirstPartyToken> {
  const ttlSec = opts.ttlSec ?? WEB_TOKEN_TTL_SEC;
  const conn = await upsertConnection({
    userId,
    clientId: opts.clientId,
    name: opts.name,
    scopes: ["all"],
  });

  const accessToken = randomToken(32);
  const db = await getDb();
  await db.collection<TokenDoc>(COLLECTIONS.tokens).insertOne({
    _id: randomUUID(), // jti
    type: "access",
    hashedToken: hashToken(accessToken), // never store raw
    userId,
    clientId: opts.clientId,
    connectionId: conn._id,
    scope: DEFAULT_SCOPE, // "mcp:read mcp:run"
    audience: MCP_RESOURCE_URL, // R1: verifyMcpToken rejects a mismatch
    revoked: false,
    createdISO: new Date().toISOString(),
    expiresAt: new Date(Date.now() + ttlSec * 1000),
  });

  return { token: accessToken, connectionId: conn._id, expiresInSec: ttlSec };
}
