// Masterkey — GET /api/partner/airv2/wallet?external_user_id=… (partner-secret gated).
// Funding address + balances of the airv2 user's per-user Sponge wallet, so the airv2 Store can show
// "fund this address" and the current balance. Read-only; no key material.

import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { COLLECTIONS, type UserDoc } from "@/lib/mcp/types";
import { airv2WalletView, verifyPartnerSecret } from "@/lib/partner/airv2";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  if (!verifyPartnerSecret(req.headers.get("authorization"))) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const externalUserId = new URL(req.url).searchParams.get("external_user_id");
  if (!externalUserId) {
    return NextResponse.json({ error: "external_user_id required" }, { status: 400 });
  }
  const db = await getDb();
  const user = await db
    .collection<UserDoc>(COLLECTIONS.users)
    .findOne({ "externalIds.airv2": externalUserId });
  if (!user) return NextResponse.json({ error: "not linked" }, { status: 404 });
  const view = await airv2WalletView(user);
  return NextResponse.json(
    {
      user_id: user._id,
      wallet: view,
      spend: {
        monthly_limit_usd: user.spend.monthlyLimitUsd,
        per_call_max_usd: user.spend.perCallMaxUsd,
        spent_this_period_usd: user.billing.spentThisPeriodUsd,
        period_resets_iso: user.billing.periodResetsISO,
      },
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
