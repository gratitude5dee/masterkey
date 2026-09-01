// Masterkey — POST /api/partner/airv2/token (partner-secret gated; server-to-server only).
// The airv2 control plane exchanges one of its user ids for a Masterkey MCP access token bound to
// that user's own Masterkey account + per-user Sponge wallet. airv2 attaches the token to /mcp
// requests it proxies for the user's agent; the token is never handed to the agent's box.
//
// Body: { external_user_id, wallet_address?, email?, monthly_cap_usd?, per_call_max_usd? }
// 200:  { access_token, token_type: "Bearer", expires_in, connection_id, user_id,
//         wallet: { agent_id, addresses } | null }

import { NextResponse } from "next/server";
import { linkAirv2User, verifyPartnerSecret } from "@/lib/partner/airv2";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function optNumber(v: unknown): number | null | undefined {
  if (v === undefined) return undefined;
  if (v === null) return null;
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

export async function POST(req: Request) {
  if (!verifyPartnerSecret(req.headers.get("authorization"))) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "invalid body" }, { status: 400 });
  }
  const externalUserId = body.external_user_id;
  if (typeof externalUserId !== "string" || !UUID_RE.test(externalUserId)) {
    return NextResponse.json({ error: "external_user_id must be a uuid" }, { status: 400 });
  }
  const walletAddress =
    typeof body.wallet_address === "string" && /^0x[0-9a-f]{40}$/i.test(body.wallet_address)
      ? body.wallet_address
      : null;
  const email = typeof body.email === "string" ? body.email : null;

  const link = await linkAirv2User({
    airv2UserId: externalUserId,
    walletAddress,
    email,
    monthlyCapUsd: optNumber(body.monthly_cap_usd),
    perCallMaxUsd: optNumber(body.per_call_max_usd),
  });
  return NextResponse.json(
    {
      access_token: link.token.token,
      token_type: "Bearer",
      expires_in: link.token.expiresInSec,
      connection_id: link.token.connectionId,
      user_id: link.user._id,
      wallet: link.wallet ? { agent_id: link.wallet.agentId, addresses: link.wallet.addresses } : null,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
