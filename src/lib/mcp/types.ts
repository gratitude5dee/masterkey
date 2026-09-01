// Masterkey — shared MongoDB document + contract types for the MCP (server-only data shapes).
// Mirrors the Account shape (src/lib/account.tsx) so the M1 dashboard→Mongo migration is ~1:1,
// then adds the OAuth + ledger collections. Incorporates Appendix R corrections.
// See MCP_SPEC.md §5 + Appendix R (R1 audience, R4 operation/network, R5 tokenJti, R6 RunResult).

import type { RuleScope, RulePeriod, BucketKey } from "@/lib/spend-buckets";
import type { AsyncSpec } from "@/data/types";

export type Plan = "Free" | "Pay-as-you-go" | "Team";

export interface SpendRuleDoc {
  id: string;
  scope: RuleScope;
  period: RulePeriod;
  capUsd: number;
  enabled: boolean;
}

export interface SpendAlertDoc {
  id: string;
  pct: number; // threshold of the monthly limit (e.g. 20, 100)
  email: string;
}

// users — one per CDP login. _id is our userId ("usr_…").
export interface UserDoc {
  _id: string;
  walletAddress: string; // CDP EVM EOA address, lowercased — unique index (canonical user key)
  email: string | null;
  cdpUserId?: string; // endUser.userId from validateAccessToken (stable cross-check)
  smartAccountAddress?: string | null; // CDP EVM smart-account address (lowercased), if provisioned — null until smart accounts / EIP-7702 are used
  solanaAddress?: string | null; // CDP Solana account address (base58, case-sensitive), if provisioned
  profile: { name: string; org: string; plan: Plan; avatarUrl?: string };
  billing: {
    card: { brand: string; last4: string; linkedISO: string } | null;
    spentThisPeriodUsd: number; // ledger-driven running spend this period
    periodResetsISO: string;
    invoices: { id: string; dateISO: string; amountUsd: number; status: "paid" }[];
  };
  spend: {
    monthlyLimitUsd: number;
    advancedEnabled: boolean;
    perCallMaxUsd: number | null;
    rules: SpendRuleDoc[];
    alerts: SpendAlertDoc[];
  };
  // Bundle Studio — slugs of bundles (curated or the user's own) this user has favorited (spec §1.7).
  // Stored inline (no extra collection); resolved against both curated + user bundles by slug.
  favoriteBundleSlugs?: string[];
  // Per-user Sponge agent wallet (src/lib/wallet.ts seam). Only the agent id is stored — its API key is
  // resolved from the platform master key at connect time and never persisted here.
  sponge?: { agentId: string; createdISO: string };
  // Partner identities (e.g. the airv2 control plane's users.id) that map onto this user.
  externalIds?: { airv2?: string };
  createdISO: string;
  updatedISO: string;
}

export type ConnectionStatus = "active" | "revoked";

// connections — an authorized agent (1 OAuth grant ↔ 1 connection). Mirrors dashboard Connection.
export interface ConnectionDoc {
  _id: string; // "conn_…"
  userId: string;
  name: string; // "Claude Code"
  client: string; // OAuth client_id / descriptor ("masterkey-web" for the first-party harness)
  scopes: RuleScope[]; // buckets this agent may spend on; ["all"] = everything (M5 reads THIS)
  status: ConnectionStatus;
  firstParty?: boolean; // true for the WEB_SPEC harness system connection (R6)
  createdISO: string;
  lastUsedISO?: string;
}

export type TokenEndpointAuthMethod = "none" | "client_secret_post";

// oauth_clients — DCR-registered MCP clients (RFC 7591).
export interface OAuthClientDoc {
  _id: string; // client_id
  clientSecretHash?: string; // confidential clients only
  clientName?: string;
  redirectUris: string[];
  grantTypes: string[]; // default ["authorization_code","refresh_token"]
  responseTypes: string[]; // default ["code"]
  scope?: string;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  createdISO: string;
}

// oauth_auth_codes — short-lived; PKCE + RFC 8707 resource binding.
export interface AuthCodeDoc {
  _id: string; // the authorization code
  clientId: string;
  userId: string;
  connectionId: string;
  redirectUri: string;
  scope: string;
  audience: string; // RFC 8707 resource (R1) — the MCP resourceUrl
  codeChallenge: string;
  codeChallengeMethod: "S256";
  expiresAt: Date; // TTL ~60s
}

export type TokenType = "access" | "refresh";

// oauth_tokens — opaque access/refresh tokens (hashed at rest).
export interface TokenDoc {
  _id: string; // jti
  type: TokenType;
  hashedToken: string; // never store raw
  userId: string;
  clientId: string;
  connectionId: string;
  scope: string;
  audience: string; // MUST equal the MCP resourceUrl; verifyToken rejects mismatches (R1)
  expiresAt: Date;
  revoked: boolean;
  createdISO: string;
}

// "unconfirmed" = Sponge reported a payment but we have no verifiable on-chain settlement (no tx hash
// / receipt success / on-chain confirm) yet. Such rows are NOT counted in billing.spentThisPeriodUsd.
// The reconciler (RUN_RELIABILITY_SPEC 2.5) later promotes them to "settled" (+incSpent) or, when it
// cannot positively confirm a real on-chain settlement, marks them "voided" (never counted).
export type LedgerStatus = "settled" | "failed" | "rejected" | "unconfirmed" | "voided";

// Typed rejection reason (R6) — the web layer renders copy/links off this enum.
export type RejectReason =
  | "monthly_limit"
  | "per_call_max"
  | "scope"
  | "rule"
  | "unsupported_network";

// ledger — one row per paid call. Source of truth for "what the user owes us".
export interface LedgerDoc {
  _id: string; // "led_…"
  userId: string;
  connectionId?: string;
  tokenJti?: string; // per-session aggregation (R5)
  serviceId: string;
  serviceName: string; // human-readable line item (e.g. "GPT Image 2 via BlockRun") — never the prompt
  operation?: string; // for api-kind services (R4)
  provider: string;
  backendUrl: string;
  bucket: BucketKey | "all"; // derived from service.category
  costUsd: number; // settled amount (from decodeXPaymentResponse); 0 for failed/rejected
  network: string; // canonical network key, e.g. "base" (R4)
  txHash?: string;
  payTo?: string; // the provider's x402 recipient for this call. Lets the reconciler bind a hashless row
  // to a tx that actually paid THIS provider, so a same-amount charge can't claim another's settlement.
  status: LedgerStatus;
  rejectedReason?: RejectReason;
  runId?: string; // web-run association (from the idempotencyKey prefix) — RunDoc.providerCostUsd is
  // derived from the settled rows for this runId (RUN_RELIABILITY_SPEC 2.1). Absent for external agents.
  reconciledAt?: Date; // set when the reconciler (2.5) has resolved an `unconfirmed` row (→ settled/voided)
  createdAt: Date;
}

// --- run_service output envelope (shared contract with WEB_SPEC §10 / R6) ---
export type RunOutputType = "image" | "video" | "audio" | "text" | "json" | "url";

export interface RunOutput {
  type: RunOutputType;
  url?: string;
  data?: string; // base64 (avoid for large media — prefer url)
  mime?: string;
}

export interface RunResult {
  serviceId: string;
  serviceName: string;
  modalityOut: string[]; // canonicalized from service.modality.output
  category: string; // for renderer fallback
  operation?: string;
  outputs: RunOutput[];
  providerCostUsd?: number; // settled cost for this call
  render?: string; // optional explicit renderer hint
  raw?: unknown; // full provider body (elided) — media/file results only; in structuredContent for the agent, never rendered as UI
  notice?: string; // in-context nudge for the AGENT only (e.g. "paid result was EMPTY — broaden/switch, don't repeat"); read from structuredContent, never rendered as UI
}

// jobs — async/long-running provider tasks (slow image, video). The provider charges on submit and
// returns a job to poll; we store it and a `get_result` tool retrieves the media when ready (M7-async).
export type JobStatus = "pending" | "complete" | "failed";

export interface JobDoc {
  _id: string; // "job_…" — the handle returned to the agent
  userId: string;
  connectionId?: string;
  tokenJti?: string;
  serviceId: string;
  serviceName: string;
  provider: string;
  backendUrl: string; // the submit endpoint (origin used to resolve a relative poll_url)
  pollUrl: string; // absolute URL to poll for the result
  providerJobId?: string;
  modalityOut: string[]; // canonical output modality, for result mapping
  bucket: BucketKey | "all";
  costUsd: number; // charged on submit (+ any poll costs added later)
  priceUsd?: number; // the endpoint's KNOWN price (registry price.amount at submit) — the legitimate job cost the
  // poller may authorize. NOT a spend ceiling (that's a runtime/user concern: spend limits + an env safety backstop).
  network: string;
  txHash?: string;
  payTo?: string; // provider's x402 recipient at submit — reused for paid polls so their charges are bound
  // to the same provider (settlement matching + reconciliation), not just to an amount
  runId?: string; // web-run association (from the idempotencyKey prefix); poll ledger rows inherit it
  async?: AsyncSpec; // RUN_RELIABILITY_SPEC 3.2: the backend's async descriptor, so polling reads the right status field/result path
  status: JobStatus;
  pollCount: number;
  result?: unknown; // cached provider body once complete
  error?: string;
  createdAt: Date;
  updatedAt: Date;
}

// run_idempotency — the crash-safe double-charge guard for durable run_service callers (M7 amendment).
// Keyed on (userId, idempotencyKey). The SOLE money-layer guard (Trigger does not memoize inline calls).
// `outcome` stores the RunResultEnvelope so a duplicate key returns the same result without re-charging
// (media is URL-based or <1MB inline, so the doc stays well under Mongo's 16MB cap). See idempotency.ts.
export type RunIdempotencyState = "in_progress" | "settled" | "settled_failure" | "needs_reconcile";

export interface RunIdempotencyDoc {
  _id: string; // `${userId}::${idempotencyKey}`
  userId: string;
  key: string; // the caller's opaque idempotency key (content-hash + durable seq)
  state: RunIdempotencyState;
  leaseUntil: Date; // bounded claim lease; an expired in_progress lease enables recovery
  jobId?: string; // persisted before returning an async job handle → expired-lease recovery re-polls it
  outcome?: unknown; // the stored RunResultEnvelope, returned verbatim on a duplicate settled key
  createdAt: Date; // TTL anchor (≥ max run + retry window)
  settledAt?: Date;
  failedAt?: Date;
}

// user_resources — a generic per-user managed value, obtained ONCE and reused across runs. Two kinds:
//   • "provisioned" — created via a paid operation (e.g. an agentmail inbox; owned by the master
//     wallet, so this mapping is the only per-user identity). Created under standard spend enforcement.
//   • "value" — a value the user supplies once that we save so we don't re-ask (e.g. a postal address
//     for PostalForm). [future — no consumer yet; the store + flag are ready.]
// Keyed on (userId, key) where key is the registry Service's managedResource.key.
export type ManagedResourceKind = "provisioned" | "value";
export interface UserResourceDoc {
  _id: string; // `${userId}::${key}`
  userId: string;
  key: string; // e.g. "agentmail:inbox"
  kind: ManagedResourceKind;
  value: string; // the inbox address, the postal address, etc.
  label?: string;
  createdISO: string;
}

// Collection names — single source of truth for db access.
export const COLLECTIONS = {
  users: "users",
  connections: "connections",
  oauthClients: "oauth_clients",
  authCodes: "oauth_auth_codes",
  tokens: "oauth_tokens",
  ledger: "ledger",
  jobs: "jobs",
  runIdempotency: "run_idempotency",
  // WEB layer (human-facing durable runs) — see WEB_SPEC.md §5.
  runs: "runs",
  runSteps: "run_steps",
  runAssets: "run_assets",
  // Per-user managed values (e.g. an agentmail email inbox, or a saved postal address) — obtained
  // once (provisioned or user-supplied), reused across runs. See src/lib/mcp/managed.ts.
  userResources: "user_resources",
  // Bundle Studio — user-authored saved bundles (graph + compiled recipe). Curated bundles still load
  // from data/bundles/*.json (src/lib/bundles.ts) and are merged in. BundleDoc lives in studio/types.ts.
  bundles: "bundles",
} as const;
