// Masterkey — master wallet, backed by Sponge (@paysponge/sdk). Pays providers on behalf of users.
//
// We no longer hold a raw private key or hand-roll x402. The master wallet is ONE Sponge wallet
// (funded by us) reached through `getMasterWallet()`. Payment goes through `wallet.paidFetch`, which
// transparently handles x402 (v1 **and** v2) and MPP across Base/Solana/Tempo/Ethereum — this is what
// supersedes the old @x402-v2-Base-only path. See docs/SPONGE_WALLET_SPEC.md (W-S3) + MCP_SPEC.md M4.
//
// `payProvider` keeps the SAME `PayResult` shape so M5 (enforce/ledger) and M7 (`run_service`) are
// unaffected — only the internals changed:
//   1. Pre-flight an UNPAID request to read the x402 402 quote → hard per-call ceiling
//      (paidFetch has no max-amount param, so we gate before paying). A free 2xx → passthrough, cost 0.
//   2. Pay via Sponge `wallet.paidFetch({ url, method, headers, body, chain? })`.
//   3. costUsd = exactly what Sponge debited us (pass-through), captured from the paid/fetch response
//      (`payment_details.amount`), falling back to the pre-flight quote; capture txHash + network too.
//
// S2 boundary: we use the SDK PROGRAMMATICALLY here. We never call `wallet.mcp()` / hand the wallet to
// an agent — enforcement (M5) happens in deterministic server code before this is ever reached.

import { SpongeWallet, SpongePlatform, SpongeApiError } from "@paysponge/sdk";
import * as os from "node:os";
import * as path from "node:path";
import { detectSiwxChallenge, signSiwx, siwxAvailable } from "./siwx";
import { sameAddress, recipientAllows } from "./spend/settlement-match";
import { getUser, setUserSpongeAgent } from "./users";

const USDC_DECIMALS = 6;

// Serverless filesystems (Vercel / AWS Lambda) are READ-ONLY except the temp dir. On connect, the
// Sponge SDK caches credentials to disk (default ~/.spongewallet/credentials.json); the write
// (mkdir + writeFileSync, no internal try/catch) throws EROFS/EACCES there, and connect()'s catch
// mis-reports ANY throw in that block as "Failed to get agent info. The API key may be invalid or
// expired." — so a perfectly valid key looks invalid in prod. Point the cache at the writable temp
// dir. Setting the env default too covers any SDK path that resolves it via SPONGE_CREDENTIALS_PATH
// (e.g. the SPONGE_MASTER_KEY platform path). Verified: read-only HOME → fail; tmp path → connect OK.
const SPONGE_CREDENTIALS_CACHE = path.join(os.tmpdir(), "masterkey-sponge-credentials.json");
process.env.SPONGE_CREDENTIALS_PATH ||= SPONGE_CREDENTIALS_CACHE;

/** Sponge's chain hint for paidFetch (a preference, not a hard requirement). */
type SpongeChain = "base" | "solana" | "tempo" | "ethereum";
/** HTTP methods paidFetch accepts. */
type PayMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
const PAY_METHODS: readonly PayMethod[] = ["GET", "POST", "PUT", "DELETE", "PATCH"];

/** Thrown when the provider's quoted price exceeds the per-call ceiling (nothing was paid). */
export class PaymentExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PaymentExceededError";
  }
}

/** Thrown when Sponge could not settle the payment (e.g. master wallet out of funds, over limit). */
export class WalletPaymentError extends Error {
  code?: string;
  constructor(message: string, code?: string) {
    super(message);
    this.name = "WalletPaymentError";
    this.code = code;
  }
}

export type PayResult = {
  ok: boolean;
  status: number;
  body: unknown;
  costUsd: number; // amount Sponge debited us (pass-through; 0 if nothing was paid)
  paid: boolean;
  // RUN_RELIABILITY_SPEC 1.4: `confirmed` = we have a verifiable settlement (a real per-call tx hash
  // and the receipt did not report failure). When paid && !confirmed, callers book an `unconfirmed`
  // ledger row and do NOT count it in spend (the reconciler resolves it). 1.6 strengthens this with an
  // on-chain getTransactionStatus check.
  confirmed: boolean;
  network: string;
  txHash?: string;
  contentType: string | null;
  // RUN_RELIABILITY_SPEC (async axes 1/4/8): response headers, lowercased. Lets the async engine read a
  // 202 + `Location` poll URL and a `Content-Disposition` result filename that the body can't carry. Optional —
  // absent on paths where headers aren't available; the async logic falls back to body-only behavior.
  headers?: Record<string, string>;
};

/** Response headers → a lowercased plain record (so the async engine can read Location/Content-Disposition). */
export function headerMap(h: Headers | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (h && typeof h.forEach === "function") h.forEach((v, k) => { out[k.toLowerCase()] = v; });
  return out;
}
/** Normalize an unknown header record (e.g. Sponge's response.headers) to a lowercased string map. */
export function normalizeHeaderRecord(h: unknown): Record<string, string> | undefined {
  if (!h || typeof h !== "object") return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h as Record<string, unknown>)) if (typeof v === "string") out[k.toLowerCase()] = v;
  return Object.keys(out).length ? out : undefined;
}

// --- The wallet seam --------------------------------------------------------------------------
// Two payer identities live behind `getMasterWallet(payerUserId?)`:
//   * platform master wallet (no `payerUserId`, or the user has no Sponge agent yet and per-user
//     provisioning is off) — a least-privilege agent key (SPONGE_API_KEY) or ONE master agent resolved
//     from SPONGE_MASTER_KEY.
//   * per-user Sponge agent wallet — one Sponge agent per Masterkey user (`UserDoc.sponge.agentId`),
//     created through `SpongePlatform.createAgent` under SPONGE_MASTER_KEY and connected with
//     `connectAgent`. The user funds it (USDC on Base) from their own wallet; x402 charges for that
//     user's runs are debited from it, so spend enforcement + the ledger (already keyed by userId /
//     connectionId) line up with the wallet that actually paid.
// Agent API keys are only ever held in server memory; nothing wallet-related leaves this module.

const MASTER_AGENT_NAME = "masterkey-master";
let _walletPromise: Promise<SpongeWallet> | undefined;
let _platformPromise: Promise<SpongePlatform> | undefined;
const _userWallets = new Map<string, Promise<SpongeWallet>>();
const USER_WALLET_CACHE_MAX = 256;

/** Per-user agent wallets are provisioned lazily when a master key is present (opt out with "0"). */
function perUserWalletsEnabled(): boolean {
  return !!process.env.SPONGE_MASTER_KEY && process.env.SPONGE_PER_USER_WALLETS !== "0";
}

/**
 * The wallet that pays for `payerUserId` — that user's own Sponge agent when one exists (or can be
 * provisioned), else the platform master wallet. Callers never touch keys.
 */
export function getMasterWallet(payerUserId?: string): Promise<SpongeWallet> {
  if (payerUserId && perUserWalletsEnabled()) return getUserWallet(payerUserId);
  if (!_walletPromise) {
    _walletPromise = connectMasterWallet().catch((e) => {
      _walletPromise = undefined; // don't cache a failed connect — allow retry next call
      throw e;
    });
  }
  return _walletPromise;
}

function getPlatform(): Promise<SpongePlatform> {
  if (!_platformPromise) {
    const masterKey = process.env.SPONGE_MASTER_KEY;
    if (!masterKey) return Promise.reject(new Error("SPONGE_MASTER_KEY not configured"));
    _platformPromise = SpongePlatform.connect({
      apiKey: masterKey,
      baseUrl: process.env.SPONGE_API_URL || undefined,
    }).catch((e) => {
      _platformPromise = undefined;
      throw e;
    });
  }
  return _platformPromise;
}

function userAgentName(userId: string): string {
  return `masterkey-user:${userId}`;
}

export interface UserWalletInfo {
  agentId: string;
  /** Funding address per chain (lowercased EVM / base58 Solana), as reported by Sponge. */
  addresses: Record<string, string>;
}

/**
 * Ensure `userId` has its own Sponge agent wallet; returns its id + funding addresses. Idempotent:
 * reuses `UserDoc.sponge.agentId`, then an existing agent by name, then creates one.
 */
export async function ensureUserWallet(userId: string): Promise<UserWalletInfo> {
  const platform = await getPlatform();
  const user = await getUser(userId);
  if (!user) throw new Error(`ensureUserWallet: unknown user ${userId}`);
  let agentId = user.sponge?.agentId;
  if (!agentId) {
    const name = userAgentName(userId);
    const existing = (await platform.listAgents()).find((a) => a.name === name);
    if (existing) {
      agentId = existing.id;
    } else {
      const created = await platform.createAgent({
        name,
        description: `Masterkey per-user wallet (${userId})`,
      });
      agentId = created.agent.id;
    }
    await setUserSpongeAgent(userId, agentId);
    _userWallets.delete(userId);
  }
  const wallet = await getUserWallet(userId);
  const addresses = await wallet.getAddresses();
  return { agentId, addresses: { ...addresses } };
}

async function getUserWallet(userId: string): Promise<SpongeWallet> {
  let p = _userWallets.get(userId);
  if (!p) {
    if (_userWallets.size >= USER_WALLET_CACHE_MAX) {
      const oldest = _userWallets.keys().next().value;
      if (oldest !== undefined) _userWallets.delete(oldest);
    }
    p = connectUserWallet(userId).catch((e) => {
      _userWallets.delete(userId);
      throw e;
    });
    _userWallets.set(userId, p);
  }
  return p;
}

async function connectUserWallet(userId: string): Promise<SpongeWallet> {
  const user = await getUser(userId);
  if (!user) throw new WalletPaymentError(`unknown payer ${userId}`, "unknown_payer");
  if (!user.sponge?.agentId) {
    // First paid call provisions the agent; the wallet starts empty until the user funds it.
    await ensureUserWallet(userId);
    return getUserWallet(userId);
  }
  const platform = await getPlatform();
  const agentId = user.sponge.agentId;
  const agentKey =
    (await platform.getAgentApiKey(agentId)) ?? (await platform.regenerateAgentApiKey(agentId));
  return platform.connectAgent({ apiKey: agentKey, agentId });
}

async function connectMasterWallet(): Promise<SpongeWallet> {
  const baseUrl = process.env.SPONGE_API_URL || undefined;
  const apiKey = process.env.SPONGE_API_KEY;
  if (apiKey) {
    // Agent-scoped key → direct wallet client. noBrowser: never attempt device-flow on a server.
    // credentialsPath → writable temp dir (serverless read-only-FS fix, see note above). agentId,
    // when set via SPONGE_AGENT_ID, skips connect()'s getCurrent()+credential-write block entirely.
    return SpongeWallet.connect({
      apiKey,
      agentId: process.env.SPONGE_AGENT_ID || undefined,
      baseUrl,
      noBrowser: true,
      credentialsPath: SPONGE_CREDENTIALS_CACHE,
    });
  }

  const masterKey = process.env.SPONGE_MASTER_KEY;
  if (masterKey) {
    const platform = await getPlatform();
    const agents = await platform.listAgents();
    let agent = agents.find((a) => a.name === MASTER_AGENT_NAME) ?? agents[0];
    let agentKey: string | null;
    if (agent) {
      agentKey = (await platform.getAgentApiKey(agent.id)) ?? (await platform.regenerateAgentApiKey(agent.id));
    } else {
      const created = await platform.createAgent({
        name: MASTER_AGENT_NAME,
        description: "Masterkey platform master wallet",
      });
      agent = created.agent;
      agentKey = created.apiKey;
    }
    return platform.connectAgent({ apiKey: agentKey, agentId: agent.id });
  }

  throw new Error("Sponge master wallet not configured: set SPONGE_API_KEY (or SPONGE_MASTER_KEY)");
}

// --- Pay --------------------------------------------------------------------------------------

export async function payProvider(opts: {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: unknown;
  maxValueUsd: number;
  preferredChain?: string;
  /** Registry hint (`authMode`/`usage.auth === "siwx"`). The live challenge is authoritative; this only
   *  nudges us to attempt SIWX when a challenge is ambiguous. */
  siwxHint?: string;
  /** Money-safety gate (default off → production behavior unchanged). When true, only pay if the unpaid
   *  pre-flight presented a real x402 challenge (402) or SIWX or was a free 2xx. If the probe returned
   *  some other non-2xx (e.g. a dead orbis slug that 404s unpaid), DO NOT attempt payment — paying it
   *  just loses money. Used by Registry QA ("confirm 402, then pay"). */
  requireChallenge?: boolean;
  /** Masterkey user whose own Sponge agent wallet pays (see the wallet seam). Omitted → master wallet. */
  payerUserId?: string;
  /** The provider's x402 `payTo` for the chain we expect to pay on (from the registry's
   *  `payment.accepts[]`). Binds a recovered/reported settlement to THIS provider so a charge can never
   *  claim a different provider's same-amount transaction. Optional — omitted = amount+chain matching only. */
  expectedPayTo?: string;
}): Promise<PayResult> {
  const method = (opts.method || "GET").toUpperCase() as PayMethod;
  const safeMethod: PayMethod = PAY_METHODS.includes(method) ? method : "GET";

  const reqHeaders: Record<string, string> = { "Content-Type": "application/json", ...(opts.headers ?? {}) };
  const init: RequestInit = { method: safeMethod, headers: reqHeaders };
  if (opts.body != null && safeMethod !== "GET") {
    init.body = typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body);
  }

  const overCeiling = (q: bigint): boolean => Number(q) / 10 ** USDC_DECIMALS > opts.maxValueUsd;
  const ceilingError = (q: bigint): PaymentExceededError =>
    new PaymentExceededError(
      `provider price ${Number(q) / 10 ** USDC_DECIMALS} USD exceeds per-call ceiling ${opts.maxValueUsd} USD`,
    );

  // 1) Pre-flight (UNPAID). A free 2xx is the real result; a 402 carries the quote for the hard ceiling;
  //    a SIWX challenge (402 carrying a `sign-in-with-x` extension) needs a wallet signature first.
  let pre: Response;
  try {
    pre = await fetch(opts.url, init);
  } catch (e) {
    throw new WalletPaymentError(`provider request failed: ${redact(errMsg(e))}`);
  }
  const preText = await safeText(pre);

  if (pre.ok) {
    return { ...passthrough(preText), status: pre.status, contentType: pre.headers.get("content-type"), headers: headerMap(pre.headers) };
  }

  let payHeaders = opts.headers; // headers sent to paidFetch (SIWX header merged in if we sign)
  let quoteAtomic: bigint | null = null;
  let signedSiwx = false;

  // 1a) SIWX gate. Detect from the challenge (body extension / `payment-required` header / error marker)
  //     or the registry hint, then sign with the master wallet. The SIWX nonce is SINGLE-USE, so we must
  //     present the signature exactly ONCE — never re-probe-then-pay with the same nonce (that 402s with
  //     `siwx_nonce_used`). We decide free-vs-pay from the ORIGINAL challenge's quote:
  //       • no quote (e.g. `accepts:[]`) ⇒ SIWX-only / free identity-gated read → ONE signed fetch, done.
  //       • a real quote ⇒ pay+SIWX → enforce ceiling, then a single paidFetch with the SIWX header.
  //     (In the merit/`stable*` family SIWX reads are free; paid calls are plain x402; pulls are one
  //     signed fetch — see SIWX_SUPPORT_SPEC.md §3. pay+SIWX-same-call is rare and validated in Phase 8.)
  const siwx = detectSiwxChallenge({ status: pre.status, body: parseBody(preText), headers: pre.headers });
  if (siwx.required || opts.siwxHint === "siwx") {
    if (siwx.info) {
      if (!siwxAvailable()) {
        throw new WalletPaymentError("service requires SIWX authentication but SPONGE_API_KEY is not set");
      }
      const auth = await signSiwx(siwx.info);
      if (!auth) throw new WalletPaymentError("SIWX signing failed for this service");

      const siwxQuote = readX402Quote(pre, preText); // non-null ⇒ pay+SIWX; null ⇒ SIWX-only (free)
      if (siwxQuote == null) {
        // SIWX-only: a single signed request IS the result (no payment, nonce used exactly once).
        const init2: RequestInit = { method: safeMethod, headers: { ...reqHeaders, ...auth.headers } };
        if (init.body != null) init2.body = init.body;
        let r: Response;
        try {
          r = await fetch(opts.url, init2);
        } catch (e) {
          throw new WalletPaymentError(`provider request failed (SIWX): ${redact(errMsg(e))}`);
        }
        const t = await safeText(r);
        return {
          ok: r.ok,
          status: r.status,
          body: parseBody(t),
          costUsd: 0,
          paid: false,
          confirmed: false,
          network: "",
          contentType: r.headers.get("content-type"),
          headers: headerMap(r.headers),
        };
      }
      // pay+SIWX: enforce the ceiling, then pay once with the SIWX header attached.
      if (overCeiling(siwxQuote)) throw ceilingError(siwxQuote);
      quoteAtomic = siwxQuote;
      payHeaders = { ...(opts.headers ?? {}), ...auth.headers };
      signedSiwx = true;
    }
    // (marked SIWX but no signable `info`, or hint with no challenge) → fall through to plain pay.
  }

  // 1b) Plain x402 (we did not sign SIWX): read the quote from the original 402 for the ceiling.
  if (!signedSiwx && pre.status === 402) {
    quoteAtomic = readX402Quote(pre, preText);
    if (quoteAtomic != null && overCeiling(quoteAtomic)) throw ceilingError(quoteAtomic);
  }
  // Non-2xx / non-402 with no SIWX: fall through and let Sponge try; it surfaces the provider error in
  // its response, which we map to ok:false below.

  // Money-safety gate (opt-in): when the caller only wants to pay on a real challenge and the unpaid
  // probe showed neither a 402 nor SIWX (and wasn't a free 2xx — that returned earlier), DON'T pay.
  // This stops funds leaking into dead endpoints (e.g. an orbis slug that 404s before any settlement).
  if (opts.requireChallenge && !signedSiwx && pre.status !== 402) {
    return {
      ok: false,
      status: pre.status,
      body: parseBody(preText),
      costUsd: 0,
      paid: false,
      confirmed: false,
      network: "",
      contentType: pre.headers.get("content-type"),
      headers: headerMap(pre.headers),
    };
  }

  // 2) Pay via Sponge (with the SIWX header if we signed one).
  const wallet = await getMasterWallet(opts.payerUserId);
  const chain = toSpongeChain(opts.preferredChain);
  let resp: unknown;
  try {
    resp = await payViaSponge(wallet, {
      url: opts.url,
      method: safeMethod,
      headers: payHeaders,
      body: opts.body,
      ...(chain ? { chain } : {}),
    });
  } catch (e) {
    throw mapSpongeError(e);
  }

  // 3) Map Sponge's paid/fetch response → PayResult (defensive: the SDK types it `unknown`).
  return mapPaidFetchResult(resp, { fallbackChain: chain, wallet, expectedPayTo: opts.expectedPayTo });
}

// --- paidFetch with a money-safe, pre-settlement retry ----------------------------------------

/**
 * A transient, PRE-SETTLEMENT failure of Sponge's x402 proxy that is safe to retry. When the proxy
 * forwards a POST/PUT/PATCH (a request WITH a body) it probes the upstream unpaid to read the 402, then
 * re-issues the SAME request with the X-Payment header — and on a cold path it reuses the already-read
 * body stream, so the upstream runtime (Cloudflare Workers) throws "Body has already been used". This is
 * thrown while CONSTRUCTING the upstream request, BEFORE any x402 payment is signed or settled — verified
 * live (the failing call reports paid:false with $0 debited on-chain). It is therefore safe to retry: a
 * second attempt finds the challenge warm (single fetch, no reuse) and succeeds, and cannot double-charge
 * because no charge occurred. We match ONLY this body-reuse signature — never a real settlement/funds error.
 */
function isPreSettlementBodyReuseError(e: unknown): boolean {
  const msg = errMsg(e).toLowerCase();
  return /body (has )?(already been|already) (used|read)|body is unusable|request with a (get|head)|bodyused/.test(msg);
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Call Sponge's paidFetch, retrying ONLY the pre-settlement body-reuse error above (bounded, with a short
 * backoff). Every other error — including any real payment/settlement failure — propagates on the first
 * throw untouched, so the per-call ceiling and funds checks are never weakened. Bodyless GETs can't hit
 * the reuse path, so they effectively never retry here.
 */
async function payViaSponge(
  wallet: SpongeWallet,
  req: { url: string; method: PayMethod; headers?: Record<string, string>; body?: unknown; chain?: SpongeChain },
): Promise<unknown> {
  const MAX_ATTEMPTS = 3;
  const BACKOFF_MS = [400, 1200];
  let lastErr: unknown;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    try {
      return await wallet.paidFetch(req);
    } catch (e) {
      lastErr = e;
      if (!isPreSettlementBodyReuseError(e) || attempt === MAX_ATTEMPTS - 1) throw e;
      await sleep(BACKOFF_MS[attempt] ?? 1200);
    }
  }
  throw lastErr; // unreachable (loop either returns or throws), kept for type-safety
}

// --- Mapping helpers --------------------------------------------------------------------------

async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

function parseBody(rawText: string): unknown {
  try {
    return JSON.parse(rawText);
  } catch {
    return rawText;
  }
}

function passthrough(rawText: string): Omit<PayResult, "status" | "contentType"> {
  return { ok: true, body: parseBody(rawText), costUsd: 0, paid: false, confirmed: false, network: "" };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function asNum(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}
function asStr(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/** The decoded x402 `X-Payment-Response` settlement receipt (the authoritative per-call proof). */
export type SettlementReceipt = {
  success?: boolean;
  transaction?: string; // the real on-chain tx hash for THIS payment
  payer?: string;
  network?: string;
};

/**
 * Decode the x402 `X-Payment-Response` header Sponge forwards on a settled paidFetch. It is base64 of
 * `{ network, payer, success, transaction }`; `transaction` is the real on-chain tx hash — the ONLY
 * trustworthy hash source (paidFetch's JSON body carries none). Verified live 2026-06-08 — see
 * RUN_RELIABILITY_SPEC §Appendix A. Tolerant: returns undefined on any missing/garbled header.
 */
function decodeSettlementReceipt(headers: Record<string, unknown> | undefined): SettlementReceipt | undefined {
  const raw = asStr(headers?.["x-payment-response"]) ?? asStr(headers?.["X-Payment-Response"]);
  if (!raw) return undefined;
  try {
    const json: unknown = JSON.parse(Buffer.from(raw, "base64").toString("utf8"));
    if (!isRecord(json)) return undefined;
    return {
      success: typeof json.success === "boolean" ? json.success : undefined,
      transaction: asStr(json.transaction),
      payer: asStr(json.payer),
      network: asStr(json.network),
    };
  } catch {
    return undefined;
  }
}

/**
 * Recover the real on-chain tx hash for a settled paidFetch that returned NO `X-Payment-Response`
 * header (some x402 providers/facilitators omit it). CONSTRAINED correlation — NOT the deleted blind
 * limit:1 backfill: it accepts a hash ONLY when exactly ONE recent SENT tx matches this charge's amount
 * (USDC atomic), chain AND — when known — the provider's `payTo` recipient, within a ~3-min window. On 0
 * or ambiguous (>1) matches it returns undefined, so the row stays unconfirmed and the reconciler decides
 * — no risk of stamping an unrelated hash.
 *
 * WHY the recipient check: amount+chain alone cannot tell two providers apart. A charge that never settled
 * could otherwise claim a DIFFERENT provider's genuinely-settled tx of the same amount and be booked
 * `settled` — a phantom charge. That precondition is real, not theoretical: Sponge can report
 * `payment_made:true` with no on-chain settlement (RUN_RELIABILITY_SPEC 0.2, confirmed 2026-07-26).
 * `expectedPayTo` is OPTIONAL — when absent we fall back to the amount+chain+uniqueness rule, so targets
 * with no known payTo behave exactly as before.
 */
async function recoverTxHashFromHistory(
  wallet: SpongeWallet,
  costUsd: number,
  network: string,
  expectedPayTo?: string,
): Promise<string | undefined> {
  const chain = toSpongeChain(network);
  if (!chain || !(costUsd > 0)) return undefined;
  const atomic = String(Math.round(costUsd * 1e6)); // USDC = 6 decimals (the only asset we pay in)
  let rows: unknown;
  try {
    rows = await wallet.getTransactionHistoryDetailed({ limit: 25 });
  } catch {
    return undefined;
  }
  const list: unknown[] = Array.isArray(rows)
    ? rows
    : isRecord(rows)
      ? ((rows.transactions ?? rows.data ?? rows.items) as unknown[]) ?? []
      : [];
  const cutoff = Date.now() - 180_000; // this paidFetch just settled → only consider txs from the last ~3 min
  const matches = list.filter((t) => {
    if (!isRecord(t)) return false;
    const dir = asStr(t.direction) ?? asStr(t.type);
    const val = asStr(t.value) ?? asStr(t.amount);
    const ch = asStr(t.chain);
    const tsRaw = asStr(t.timestamp) ?? asStr(t.createdAt);
    const ts = tsRaw ? Date.parse(tsRaw) : NaN;
    // Recipient gate: only applied when we know who this charge was supposed to pay.
    if (!recipientAllows(t, expectedPayTo)) return false;
    return dir === "sent" && val === atomic && (!ch || ch === chain) && (Number.isNaN(ts) || ts >= cutoff);
  });
  if (matches.length !== 1) return undefined; // 0 or ambiguous → don't guess; reconciler handles it
  const m = matches[0] as Record<string, unknown>;
  return asStr(m.txHash) ?? asStr(m.transactionHash) ?? asStr(m.hash) ?? asStr(m.transaction);
}

/**
 * ALL recent SENT on-chain tx hashes matching an amount + chain — and, when known, the provider's `payTo`
 * recipient (newest-first). The reconciler uses this to settle BURSTS of same-amount calls that returned no
 * per-call receipt: it claims one unclaimed tx per hashless row (recoverTxHashFromHistory above bails on
 * bursts because it requires a UNIQUE match).
 *
 * The `payTo` filter is what keeps a burst from CROSSING providers. Without it, a hashless row for provider
 * B that never settled can claim provider A's real same-amount tx: the amount matches, the RPC receipt is
 * genuine, and it gets promoted to `settled`. Total spend would look right while the charge is attributed
 * to the wrong service and run (and `RunDoc.providerCostUsd` derives from those tags). Optional — omitted
 * `payTo` preserves the previous amount+chain behavior.
 */
export async function listSettlementCandidates(
  costUsd: number,
  network: string,
  expectedPayTo?: string,
  withinMs = 60 * 60_000,
  payerUserId?: string,
): Promise<string[]> {
  if (!(costUsd > 0)) return [];
  const chain = toSpongeChain(network);
  if (!chain) return [];
  let rows: unknown;
  try {
    const wallet = await getMasterWallet(payerUserId);
    rows = await wallet.getTransactionHistoryDetailed({ limit: 50 });
  } catch {
    return [];
  }
  const list: unknown[] = Array.isArray(rows)
    ? rows
    : isRecord(rows)
      ? ((rows.transactions ?? rows.data ?? rows.items) as unknown[]) ?? []
      : [];
  const atomic = String(Math.round(costUsd * 1e6));
  const cutoff = Date.now() - withinMs;
  const out: string[] = [];
  for (const t of list) {
    if (!isRecord(t)) continue;
    const dir = asStr(t.direction) ?? asStr(t.type);
    const val = asStr(t.value) ?? asStr(t.amount);
    const ch = asStr(t.chain);
    const tsRaw = asStr(t.timestamp) ?? asStr(t.createdAt);
    const ts = tsRaw ? Date.parse(tsRaw) : NaN;
    if (dir !== "sent" || val !== atomic) continue;
    if (ch && ch.toLowerCase() !== chain && toSpongeChain(ch) !== chain) continue;
    if (!Number.isNaN(ts) && ts < cutoff) continue;
    if (!recipientAllows(t, expectedPayTo)) continue; // different provider's tx
    const h = asStr(t.txHash) ?? asStr(t.transactionHash) ?? asStr(t.hash) ?? asStr(t.transaction);
    if (h) out.push(h);
  }
  return out;
}

/**
 * Sponge's `/api/paid/fetch` response is `{ ok, status, payment_made, payment_details:{amount,token,
 * chain,to,…}, route:{selected_protocol,selected_chain}, data, … }` (verified against the SDK's CLI
 * renderer). Read it tolerantly so a backend tweak to field names degrades gracefully.
 */
async function mapPaidFetchResult(
  resp: unknown,
  ctx: { fallbackChain?: SpongeChain; wallet: SpongeWallet; expectedPayTo?: string },
): Promise<PayResult> {
  const r = isRecord(resp) ? resp : {};
  const pd = (isRecord(r.payment_details) && r.payment_details) || (isRecord(r.payment) && r.payment) || undefined;
  const route = isRecord(r.route) ? r.route : undefined;
  const headers = isRecord(r.headers) ? r.headers : undefined;

  // Authoritative per-call settlement proof (RUN_RELIABILITY_SPEC §Appendix A): the x402
  // `X-Payment-Response` header carries { success, transaction (real on-chain hash), payer, network }
  // for THIS payment. paidFetch's JSON body carries no hash, so this is the only trustworthy source.
  const receipt = decodeSettlementReceipt(headers);

  // RUN_RELIABILITY_SPEC 1.3: gate "paid" on Sponge's AUTHORITATIVE settlement signal — the
  // `payment_made` boolean or the receipt's `success` — NOT on `payment_details`/`payment` merely being
  // present. The old `|| pd != null` treated the payment *requirement* (quote) as proof of payment,
  // which booked phantom debt. (1.4 downgrades a "paid" call with no confirmed tx to `unconfirmed`.)
  const paid = r.payment_made === true || r.paymentMade === true || receipt?.success === true;

  // Pass-through cost: EXACTLY what Sponge debited (`payment_details.amount`, a real settled amount).
  // RUN_RELIABILITY_SPEC 1.2: the x402 quote is a CEILING, never a cost — do NOT fall back to it. If no
  // settled amount is present, costUsd stays 0 (the gate/`unconfirmed` handling decides what to book).
  let costUsd = 0;
  if (paid) {
    costUsd = asNum(pd?.amount) ?? asNum(pd?.usdValue) ?? asNum(r.amount) ?? 0;
  }

  const network =
    asStr(pd?.chain) ?? asStr(route?.selected_chain) ?? asStr(r.chain) ?? (paid ? ctx.fallbackChain ?? "" : "");

  let txHash =
    asStr(pd?.txHash) ??
    asStr(pd?.transactionHash) ??
    asStr(pd?.transaction) ??
    asStr(pd?.tx_hash) ??
    asStr(pd?.hash) ??
    asStr(r.txHash) ??
    asStr(r.transactionHash) ??
    receipt?.transaction;
  // RUN_RELIABILITY_SPEC 1.1: still NO blind backfill. The DELETED heuristic was
  // getTransactionHistoryDetailed({limit:1}) — it stamped the wallet's most-recent tx onto a charge with
  // NO amount/recipient/time match, so an unrelated 12h-old transfer got recorded as a settlement. The
  // recovery below is the opposite: it only accepts a UNIQUE very-recent SENT tx whose amount+chain match
  // THIS charge (else it gives up, leaving the row unconfirmed for the reconciler). Needed because some
  // x402 providers/facilitators (e.g. StableStudio) settle on-chain but return NO `X-Payment-Response`
  // header, so the charge would otherwise be unconfirmed → falsely voided despite real money leaving.
  if (paid && !txHash && costUsd > 0) {
    txHash = await recoverTxHashFromHistory(ctx.wallet, costUsd, network, ctx.expectedPayTo);
  }

  const ok = typeof r.ok === "boolean" ? r.ok : true;
  const status = asNum(r.status) ?? (ok ? 200 : 502);
  const body = "data" in r ? r.data : "body" in r ? r.body : r;

  const contentType =
    asStr(r.content_type) ??
    asStr(r.contentType) ??
    asStr(headers?.["content-type"]) ??
    (isRecord(body) || Array.isArray(body) ? "application/json" : null);

  // RUN_RELIABILITY_SPEC 1.4: a charge is `confirmed` only with a real per-call tx hash and a receipt
  // that didn't report failure. paid && !confirmed → caller books an `unconfirmed` row (no spend
  // counted) for the reconciler.
  let confirmed = paid && !!txHash && receipt?.success !== false;

  // RUN_RELIABILITY_SPEC 1.6: synchronous on-chain backstop — veto a settlement the chain ALREADY
  // reports as `failed` at booking time. IMPORTANT (verified live 2026-06-08): Sponge's
  // getTransactionStatus optimistically returns `pending` for any not-yet-confirmed hash — INCLUDING a
  // fabricated/non-existent one — and a real just-settled tx is also `pending` for ~2s. So a fresh real
  // tx and a fake one are INDISTINGUISHABLE synchronously; we therefore do NOT veto `pending`/`unknown`
  // here (that would falsely unconfirm every real payment). Fabrication / late-failure is caught by the
  // RECONCILER (2.5), which re-checks after a delay via a reliable method (RPC receipt + amount/recipient
  // match, or poll-until-confirmed). A thrown read error never flips a good receipt.
  if (confirmed && txHash) {
    const chain = toSpongeChain(network);
    if (chain) {
      try {
        const st = await ctx.wallet.getTransactionStatus(txHash, chain);
        if (st?.status === "failed") confirmed = false;
      } catch {
        /* transient status-read failure → trust the receipt; the reconciler verifies later */
      }
    }
  }

  // Recipient cross-check: when the registry tells us WHO this call is supposed to pay, a settlement
  // reported against a different recipient is not this charge. Downgrade to `unconfirmed` and let the
  // reconciler decide from the chain rather than trusting the envelope.
  const reportedTo = asStr(pd?.to) ?? asStr(pd?.payTo) ?? asStr(pd?.recipient);
  const recipientMismatch = !!ctx.expectedPayTo && !!reportedTo && !sameAddress(reportedTo, ctx.expectedPayTo);
  if (recipientMismatch) confirmed = false;

  // RUN_RELIABILITY_SPEC 0.2: capture the settlement envelope whenever a booking is anomalous (paid but
  // unconfirmed, or a recipient mismatch) so these cases are REPLAYABLE. The 2026-06-08 phantom-charge
  // incident stayed INDETERMINATE for weeks purely because this was never captured. Settlement METADATA
  // only — never the response body, which can carry user data.
  if (paid && (!confirmed || recipientMismatch)) {
    console.warn(
      "[settlement] anomalous booking",
      JSON.stringify({
        reason: recipientMismatch ? "recipient_mismatch" : "paid_without_confirmation",
        ok,
        status,
        paymentMade: r.payment_made === true || r.paymentMade === true,
        receiptPresent: !!receipt,
        receiptSuccess: receipt?.success ?? null,
        costUsd,
        network,
        txHash: txHash ?? null,
        expectedPayTo: ctx.expectedPayTo ?? null,
        reportedTo: reportedTo ?? null,
      }),
    );
  }

  return { ok, status, body, costUsd, paid, confirmed, network, txHash, contentType, headers: normalizeHeaderRecord(headers) };
}

// --- x402 quote reader (for the hard per-call ceiling) ----------------------------------------

/**
 * Pull the atomic price from an x402 `402` challenge. Reads both the JSON body
 * (`accepts[].maxAmountRequired` (v1) / `accepts[].amount` (v2), or a top-level `maxAmountRequired`)
 * and the `payment-required` header (base64-or-plain JSON). Returns the MINIMUM quoted amount (the
 * cheapest option Sponge could pick) so the ceiling rejects only when even the cheapest exceeds it.
 * Returns null when no amount is readable (e.g. MPP) → caller relies on the M5 estimate gate instead.
 */
function readX402Quote(res: Response, rawText: string): bigint | null {
  const amounts: bigint[] = [];

  const collect = (obj: unknown): void => {
    if (!isRecord(obj)) return;
    const accepts = Array.isArray(obj.accepts) ? obj.accepts : [];
    for (const a of accepts) {
      if (!isRecord(a)) continue;
      const v = a.maxAmountRequired ?? a.amount;
      const b = toAtomic(v);
      if (b != null) amounts.push(b);
    }
    const top = toAtomic(obj.maxAmountRequired ?? obj.amount);
    if (top != null) amounts.push(top);
  };

  collect(parseBody(rawText));

  const hdr = res.headers.get("payment-required") || res.headers.get("x-payment-required");
  if (hdr) {
    collect(parseBody(hdr));
    try {
      collect(JSON.parse(Buffer.from(hdr, "base64").toString("utf8")));
    } catch {
      /* not base64 */
    }
  }

  if (!amounts.length) return null;
  return amounts.reduce((min, x) => (x < min ? x : min));
}

function toAtomic(v: unknown): bigint | null {
  if (typeof v === "bigint") return v;
  if (typeof v === "number" && Number.isFinite(v)) return BigInt(Math.trunc(v));
  if (typeof v === "string" && /^\d+$/.test(v.trim())) {
    try {
      return BigInt(v.trim());
    } catch {
      return null;
    }
  }
  return null;
}

// --- chain mapping + errors -------------------------------------------------------------------

/** Map our network identifiers (CAIP-2 or canonical) → Sponge's paidFetch chain hint. */
function toSpongeChain(net?: string): SpongeChain | undefined {
  if (!net) return undefined;
  const n = net.toLowerCase();
  const exact: Record<string, SpongeChain> = {
    base: "base",
    "eip155:8453": "base",
    ethereum: "ethereum",
    eth: "ethereum",
    "eip155:1": "ethereum",
    solana: "solana",
    tempo: "tempo",
  };
  if (exact[n]) return exact[n];
  if (n.includes("8453") || n.includes("base")) return "base";
  if (n.includes("solana") || n.startsWith("sol")) return "solana";
  if (n.includes("tempo")) return "tempo";
  if (n.includes("ethereum") || n === "eip155:1") return "ethereum";
  return undefined;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Strip any Sponge API key that might appear in an error string. */
function redact(s: string): string {
  return s.replace(/sponge_(live|master)_[A-Za-z0-9]+/g, "sponge_$1_***");
}

function mapSpongeError(e: unknown): Error {
  if (e instanceof PaymentExceededError) return e;
  const code = e instanceof SpongeApiError ? e.errorCode : undefined;
  const msg = redact(errMsg(e));
  if (code === "insufficient_funds" || /insufficient|not enough|balance|fund/i.test(msg)) {
    return new WalletPaymentError(`master wallet has insufficient funds: ${msg}`, code ?? "insufficient_funds");
  }
  if (/limit|exceed/i.test(msg)) {
    return new WalletPaymentError(`Sponge spending limit reached: ${msg}`, code ?? "over_limit");
  }
  return new WalletPaymentError(`Sponge payment failed: ${msg}`, code);
}
