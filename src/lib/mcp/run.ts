// Masterkey — run_service execution pipeline (server-only, M7). The crown jewel: resolve a registry
// service → callable target → enforce spend (M5) → pay via the Sponge master wallet (M4) → record the
// user's debt (ledger) → map the provider result to MCP content + a RunResult envelope (R6).
//
// Order is fixed: ENFORCE (reserve) → PAY → SETTLE/RELEASE → RETURN. Enforcement happens before any
// payment; blocked requests never reach the wallet. SSRF-safe: the URL always comes from the resolved
// registry entry (the agent supplies only serviceId/operation/backendProviderId/input). See Appendix R4/R6.

import { createHash } from "node:crypto";
import { tierOf } from "@/data/team-tiers";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { findServiceById } from "@/lib/registry";
import { callerFromExtra } from "@/lib/mcp/tools";
import { payProvider, PaymentExceededError, WalletPaymentError } from "@/lib/wallet";
import {
  estimateCost,
  reserveSpend,
  settleSpend,
  releaseReservation,
  recordRejected,
  type CallRef,
} from "@/lib/spend/enforce";
import { appendLedger, incSpent } from "@/lib/spend/ledger";
import {
  detectAsyncJob,
  bodyHasPendingStatus,
  createJob,
  getJob,
  pollJobOnce,
  fetchSeparateResult,
  markJobComplete,
  markJobFailed,
  addJobCost,
} from "@/lib/mcp/jobs";
import { claimRun, settleRun, failRun, markRunJob } from "@/lib/mcp/idempotency";
import { getOrCreateUserInbox } from "@/lib/mcp/managed";
import { isMcpAppsEnabled } from "@/lib/mcp/apps/flag";
import { runViewerToolMeta, isClientAppsCapable } from "@/lib/mcp/apps/resource";
import { mirrorOutputToBlob } from "@/lib/mcp/apps/media-mirror";
import { fetchMediaBytes, downscaleImageForInline, isDisplayableImageMime, normalizeToJpeg, extractPdfText } from "@/lib/mcp/perception";
import { getUser } from "@/lib/users";
import type { Service, Price, PaymentOption, AsyncSpec } from "@/data/types";
import { indexForBackendKey } from "@/data/backend-key";
import type { RunResult, RunOutput, RunOutputType, RejectReason } from "@/lib/mcp/types";

// Networks the Sponge wallet can actually pay (paidFetch chain hints). Registry stays x402-only; a
// backend whose only payable network is outside this set is surfaced as unsupported, not failed at pay.
const SUPPORTED_NETWORKS = new Set(["base", "solana", "tempo", "ethereum"]);

// Cap agent-supplied input so a runaway payload can't bloat the request/body (M8 input validation).
const MAX_INPUT_BYTES = 256_000;

/** CAIP-2 / bare network id → canonical key. */
export function canonicalNetwork(net: string): string {
  const n = (net || "").toLowerCase();
  if (n === "base" || n === "eip155:8453") return "base";
  if (n === "ethereum" || n === "eth" || n === "eip155:1") return "ethereum";
  if (n === "solana" || n.startsWith("solana:")) return "solana";
  if (n === "tempo" || n.startsWith("tempo:") || n.startsWith("tempo-")) return "tempo";
  if (n === "eip155:137") return "polygon";
  if (n === "eip155:42161") return "arbitrum";
  if (n === "eip155:43114") return "avalanche";
  return n;
}

type ContentBlock =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string }
  | { type: "audio"; data: string; mimeType: string };

export type RunErrorCode =
  | RejectReason
  | "service_not_found"
  | "no_payable_target"
  | "price_exceeded"
  | "payment_failed"
  | "provider_error"
  | "bad_input"
  | "duplicate_in_progress" // another call with the same idempotency key is in flight (M7)
  | "needs_reconcile"; // a prior paid attempt with this key couldn't be confirmed — not re-charged (M7)

export type RunResultEnvelope =
  | {
      ok: true;
      async?: false;
      content: ContentBlock[];
      structured: RunResult;
      summary: string;
      costUsd: number;
      remainingUsd: number;
      providerOk: boolean;
      providerStatus: number;
    }
  | {
      ok: true;
      async: true;
      jobId: string;
      status: "pending";
      content: ContentBlock[];
      summary: string;
      costUsd: number;
      remainingUsd: number;
    }
  | { ok: false; code: RunErrorCode; message: string };

export type RunArgs = {
  serviceId: string;
  operation?: string;
  backendProviderId?: string;
  model?: string;
  input?: Record<string, unknown>;
  // M7 amendment: durable callers (the WEB harness) pass a stable content-hash + seq key so a crash-retry
  // can't double-charge. Opaque to us; dedupe is keyed on (userId, idempotencyKey). Absent → legacy behavior.
  idempotencyKey?: string;
};
export type RunCaller = { userId: string; connectionId: string; tokenJti?: string };

// A unified callable target abstracted over backends[] (model kind) and operations[] (api kind).
type Target = {
  provider: string;
  providerId: string;
  operationName?: string;
  url: string;
  method: string;
  modelParam?: { name: string; value: string };
  price: Price;
  payment: { protocols: string[]; accepts: PaymentOption[] };
  inputSchema: Record<string, unknown> | null;
  authMode?: string; // registry hint; "siwx" nudges payProvider to attempt SIWX (live challenge is authoritative)
  async?: AsyncSpec; // RUN_RELIABILITY_SPEC 3.2: drives registry-aware async detection/polling
  firstParty?: boolean; // service owner's own endpoint (1P) — preferred by default over aggregator routes
  team?: string; // operating team behind the host (BlockRun/Merit/Sponge/Orthogonal/…) — for trust-based ranking
  hosting?: "custom" | "platform"; // "platform" = no own domain (*.vercel.app etc) = Tier 4, lowest trust
};

/**
 * Provider trust tier for routing (`src/data/team-tiers.ts`, graded in TEAMS_AND_FIRST_PARTY.md).
 * T1 owner's own host · T2 direct-relationship operator · T3 own domain, no relationship · T4 proxy with
 * no own domain. Lower is better, and it is the PRIMARY routing key — trust outranks price.
 */
const tierRank = (t: Target): number => tierOf(t);

function priceFloor(p: Price): number {
  return p.amount ?? p.max ?? Number.POSITIVE_INFINITY;
}

function payableNetworks(t: Target): string[] {
  return (t.payment?.accepts ?? []).map((a) => canonicalNetwork(a.network)).filter((n) => SUPPORTED_NETWORKS.has(n));
}
function isPayable(t: Target): boolean {
  return (t.payment?.protocols ?? []).includes("x402") && payableNetworks(t).length > 0;
}
/** Prefer Base, else the first supported network of the target (drives Sponge's preferredChain). */
function preferredChain(t: Target): string {
  const nets = payableNetworks(t);
  return nets.includes("base") ? "base" : nets[0];
}

/**
 * Agent-facing wording for money. A payment we cannot tie to a verifiable on-chain settlement is booked
 * `unconfirmed` and contributes ZERO to spend (RUN_RELIABILITY_SPEC 1.4); the reconciler later settles or
 * voids it. Asserting "charged $X" for those calls contradicts our own ledger — on 2026-07-26 it made the
 * MCP report two $0.45 "charges" that never touched the chain and were subsequently voided, and the agent
 * relayed that phantom loss to the user. The wording therefore tracks `confirmed`.
 */
function chargeNoun(costUsd: number, confirmed: boolean, digits = 6): string {
  const amt = `$${costUsd.toFixed(digits)}`;
  return confirmed
    ? `a ${amt} charge`
    : `an UNCONFIRMED ${amt} payment attempt (not counted against the budget unless it settles on-chain)`;
}

/**
 * The provider's x402 `payTo` for the chain we're paying on. Threaded into the wallet so a recovered or
 * reported settlement can be bound to THIS provider — without it, amount+chain matching alone can attach
 * another provider's same-amount transaction to this charge. Undefined when the registry has no payTo for
 * the chosen chain (matching then falls back to amount+chain, as before).
 */
function expectedPayTo(t: Target, chain: string): string | undefined {
  return (t.payment?.accepts ?? []).find((a) => canonicalNetwork(a.network) === chain && a.payTo)?.payTo;
}

/** Build the callable targets from a service's backends[] AND operations[] (both can be callable). */
function targetsFor(svc: Service): Target[] {
  const out: Target[] = [];
  for (const b of svc.backends ?? []) {
    if (b.status !== "active") continue;
    out.push({
      provider: b.provider,
      providerId: b.providerId,
      url: b.url,
      method: b.method,
      modelParam: b.modelParam,
      price: b.price,
      payment: b.payment,
      inputSchema: b.inputSchema ?? null,
      authMode: b.authMode,
      async: b.async,
      firstParty: b.firstParty,
      team: b.team,
      hosting: b.hosting,
    });
  }
  for (const o of svc.operations ?? []) {
    if (o.audience === "internal" || o.trivial || o.status === "hidden") continue;
    out.push({
      provider: svc.provider,
      providerId: svc.providerId,
      operationName: o.name,
      url: o.url,
      method: o.method,
      modelParam: o.modelParam,
      price: o.price,
      payment: o.payment,
      inputSchema: o.inputSchema,
      authMode: o.authMode,
      async: o.async,
      team: o.team,
      hosting: (svc.backends ?? []).find((x) => x.url && o.url?.startsWith(new URL(x.url).origin))?.hosting,
    });
  }
  return out;
}

/** Does the call carry an input image? → the user is EDITING an existing image, not generating fresh. */
function inputHasImage(input?: Record<string, unknown>): boolean {
  if (!input) return false;
  for (const [k, v] of Object.entries(input)) {
    if (!/image|img/i.test(k)) continue;
    if (typeof v === "string" && v.trim()) return true;
    if (Array.isArray(v) && v.some((x) => typeof x === "string" && x.trim())) return true;
  }
  return false;
}
/** A backend/operation that EDITS (vs generates) — same provider often ships both (…/edit vs …/generate). */
function isEditTarget(t: Target): boolean {
  return /(?:^|[/_-])edit(?:$|[/_-])/i.test(t.url) || t.operationName?.toLowerCase() === "edit";
}
/** Among candidates, choose by edit-intent first (image present → prefer the edit endpoint; otherwise
 *  prefer generate), then RUN_RELIABILITY_SPEC 4.4 ranking (de-rank per-poll, then cheapest). */
function rankTargets(cands: Target[], wantsEdit: boolean): Target | undefined {
  if (!cands.length) return undefined;
  const editing = cands.filter(isEditTarget);
  const generating = cands.filter((t) => !isEditTarget(t));
  const pool = wantsEdit ? (editing.length ? editing : cands) : generating.length ? generating : cands;
  const isPerPoll = (t: Target): boolean => t.async?.poll?.cost === "per-poll";
  // Selection order (no explicit provider hint):
  //   1. TRUST TIER   T1 owner's own host > T2 direct-relationship operator > T3 own domain > T4 proxy
  //                   with no own domain. Trust is the PRIMARY key: a bare "use Exa" must hit api.exa.ai,
  //                   and a `*.vercel.app` proxy must never win a route just by being $0.001 cheaper.
  //   2. avoid per-poll — per-poll async billing can overshoot a cost cap
  //   3. cheapest, then stable by provider name
  // Full ladder wired 2026-07-29 per TEAMS_AND_FIRST_PARTY.md (was firstParty-only, then T1+T4).
  return [...pool].sort(
    (a, b) =>
      tierRank(a) - tierRank(b) ||
      (isPerPoll(a) ? 1 : 0) - (isPerPoll(b) ? 1 : 0) ||
      priceFloor(a.price) - priceFloor(b.price) ||
      a.provider.localeCompare(b.provider),
  )[0];
}

/** Resolve which target to call from the caller's hints, or pick the best payable one. Edit-aware: a
 *  call carrying an input image routes to the service's EDIT endpoint (when it has a separate one), so
 *  "edit this image" doesn't land on the generate endpoint and regenerate from scratch. */
function pickTarget(svc: Service, args: RunArgs): { target?: Target; anyExist: boolean; anyPayable: boolean } {
  const all = targetsFor(svc);
  const payable = all.filter(isPayable);
  const wantsEdit = inputHasImage(args.input);
  const ret = (target?: Target) => ({ target, anyExist: all.length > 0, anyPayable: payable.length > 0 });

  if (args.operation) {
    return ret(payable.find((x) => x.operationName === args.operation)); // explicit operation wins
  }
  if (args.backendProviderId) {
    const want = args.backendProviderId.toLowerCase();
    // 1) Exact per-endpoint selector key (e.g. "stablestudio:edit") — an explicit per-endpoint pin wins
    //    outright. Computed over svc.backends (the SAME ordered list the catalog UI uses) → payable by url.
    const backends = svc.backends ?? [];
    const ki = indexForBackendKey(backends.map((b) => ({ providerId: b.providerId, url: b.url })), want);
    if (ki >= 0) {
      const keyed = payable.find((x) => x.url === backends[ki].url);
      if (keyed) return ret(keyed);
    }
    // 2) Legacy provider/name match — may hit MULTIPLE backends (e.g. StableStudio generate+edit). The
    //    generic name is ambiguous, so route by edit-intent: with an image → the edit endpoint.
    const cands = payable.filter(
      (x) =>
        x.providerId.toLowerCase() === want ||
        x.provider.toLowerCase() === want ||
        x.operationName?.toLowerCase() === want,
    );
    return ret(rankTargets(cands, wantsEdit));
  }
  // No hint → best payable, edit-aware.
  return ret(rankTargets(payable, wantsEdit));
}

// ---- request building (R4: 7+ inputSchema shapes; query/header/path vs body; modelParam) ---------

type ParamSpec = { name: string; in: string };
function paramSpecs(schema: Record<string, unknown> | null): ParamSpec[] {
  if (!schema) return [];
  const arr = (schema as { parameters?: unknown }).parameters;
  if (!Array.isArray(arr)) return [];
  return arr
    .filter((p): p is { name: string; in?: string } => !!p && typeof p === "object" && typeof (p as { name?: unknown }).name === "string")
    .map((p) => ({ name: p.name, in: p.in ?? "body" }));
}

function buildRequest(
  target: Target,
  input: Record<string, unknown>,
  model?: string,
): { url: string; method: string; headers: Record<string, string>; body: Record<string, unknown> } {
  const specs = paramSpecs(target.inputSchema);
  const where = new Map(specs.map((p) => [p.name, p.in]));
  const query: Record<string, string> = {};
  const headers: Record<string, string> = {};
  const path: Record<string, string> = {};
  const body: Record<string, unknown> = {};

  const method = (target.method || "GET").toUpperCase();
  const noBody = method === "GET" || method === "HEAD"; // these can't carry a body → undeclared fields go to the query

  for (const [k, v] of Object.entries(input ?? {})) {
    if (v === undefined || v === null) continue;
    const loc = where.get(k);
    if (loc === "query") query[k] = String(v);
    else if (loc === "header") headers[k] = String(v);
    else if (loc === "path") path[k] = String(v);
    else if (noBody) query[k] = typeof v === "string" ? v : JSON.stringify(v);
    else body[k] = v;
  }
  // modelParam selects the model on a shared endpoint; backend value wins over the caller's `model`.
  if (target.modelParam) {
    if (method === "GET") query[target.modelParam.name] = target.modelParam.value;
    else body[target.modelParam.name] = target.modelParam.value;
  } else if (model) {
    if (method === "GET") query.model = model;
    else body.model = model;
  }

  let url = target.url;
  // Path templates: support BOTH ":name" and "{name}" styles. A backend URL can carry a template the
  // inputSchema doesn't declare (or there's no schema at all), so also auto-route any input key that
  // matches a template token in the URL into the path (and out of body/query). Without this, a token
  // like "{voice_id}" is sent LITERALLY (POSTed as a stray field, URL left as ".../{voice_id}") and the
  // upstream 400s — which silently broke every templated-URL service (elevenlabs, defillama, ipfs-fetch).
  const tokenNames = new Set<string>();
  for (const m of url.matchAll(/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g)) tokenNames.add(m[1]);
  for (const m of url.matchAll(/:([a-zA-Z_][a-zA-Z0-9_]*)/g)) tokenNames.add(m[1]);
  for (const name of tokenNames) {
    if (path[name] != null) continue;
    const v = (input ?? {})[name];
    if (v !== undefined && v !== null) {
      path[name] = String(v);
      delete body[name];
      delete query[name];
    }
  }
  for (const [k, v] of Object.entries(path)) {
    url = url.split(`:${k}`).join(encodeURIComponent(v)).split(`{${k}}`).join(encodeURIComponent(v));
  }
  const qs = new URLSearchParams(query).toString();
  if (qs) url += (url.includes("?") ? "&" : "?") + qs;

  return { url, method, headers, body };
}

// ---- output mapping (R4: video→text/URL, prefer URL over base64, json/text→text block) -----------

function canonModality(m: string): RunOutputType {
  const s = m.toLowerCase();
  if (s.startsWith("image")) return "image";
  if (s.startsWith("video")) return "video";
  if (s.startsWith("audio") || s === "speech" || s === "voice") return "audio";
  if (s === "text") return "text";
  return "json";
}

/** Resolve a dot-path (supports numeric array indices, e.g. "results.0.url") against a body. */
function getByPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const key of path.split(".")) {
    if (Array.isArray(cur)) {
      const i = Number(key);
      cur = Number.isInteger(i) ? cur[i] : undefined;
    } else if (cur && typeof cur === "object") {
      cur = (cur as Record<string, unknown>)[key];
    } else {
      return undefined;
    }
    if (cur == null) return undefined;
  }
  return cur;
}

/**
 * RUN_RELIABILITY_SPEC 3.4: extract the result media URL from a registry-declared `resultPath` (e.g.
 * `async.poll.resultPath = "results.0.url"`) when present — deterministic, vs the depth-4 `findUrl` guess.
 * The path may point straight at a URL string OR at a sub-tree we then narrow `findUrl` to.
 */
function resolveResultUrl(body: unknown, resultPath?: string): string | undefined {
  if (!resultPath) return undefined;
  const node = getByPath(body, resultPath);
  if (typeof node === "string") return /^https?:\/\/\S+$/.test(node) ? node : undefined;
  return node != null ? findUrl(node) : undefined;
}

function findUrl(body: unknown): string | undefined {
  const seen = new Set<unknown>();
  const visit = (v: unknown, depth: number): string | undefined => {
    if (depth > 4 || v == null || seen.has(v)) return undefined;
    if (typeof v === "string") return /^https?:\/\/\S+$/.test(v) ? v : undefined;
    if (Array.isArray(v)) {
      seen.add(v);
      for (const x of v) {
        const u = visit(x, depth + 1);
        if (u) return u;
      }
      return undefined;
    }
    if (typeof v === "object") {
      seen.add(v);
      const o = v as Record<string, unknown>;
      // prefer obvious media url keys first
      for (const k of ["url", "image_url", "audio_url", "video_url", "output_url", "downloadUrl", "uri"]) {
        if (typeof o[k] === "string" && /^https?:\/\//.test(o[k] as string)) return o[k] as string;
      }
      for (const val of Object.values(o)) {
        const u = visit(val, depth + 1);
        if (u) return u;
      }
    }
    return undefined;
  };
  return visit(body, 0);
}

// Hosts drop an inlined base64 block bigger than ~1 MB (Claude Desktop limit). An image over this is
// downscaled to a JPEG preview the model can still see (perception.ts); audio over it stays URL-only.
const CLAUDE_INLINE_MAX_B64 = 1_000_000;
const IMAGE_B64_KEYS = ["b64_json", "image_data", "imageData", "imageBase64", "image_base64", "b64"];
const AUDIO_B64_KEYS = ["audio_data", "audioData", "audioBase64", "audio_base64", "audio_base_64"];

/** Recursively find the first long string under any of `keys` (handles OpenAI's nested data[].b64_json). */
function deepFindString(obj: unknown, keys: string[], depth = 0): string | undefined {
  if (depth > 6 || obj == null) return undefined;
  if (Array.isArray(obj)) {
    for (const x of obj) {
      const r = deepFindString(x, keys, depth + 1);
      if (r) return r;
    }
    return undefined;
  }
  if (typeof obj === "object") {
    const o = obj as Record<string, unknown>;
    for (const k of keys) if (typeof o[k] === "string" && (o[k] as string).length > 64) return o[k] as string;
    for (const v of Object.values(o)) {
      const r = deepFindString(v, keys, depth + 1);
      if (r) return r;
    }
  }
  return undefined;
}

function parseDataUri(s: string): { data: string; mime: string } | undefined {
  const m = s.match(/^data:([^;,]+);base64,([\s\S]+)$/);
  return m ? { mime: m[1], data: m[2] } : undefined;
}

/** Inline base64 media already present in the body (raw or as a data: URI). */
function inlineBase64(body: unknown, keys: string[], defaultMime: string): { data: string; mime: string } | undefined {
  const raw = deepFindString(body, keys);
  if (!raw) return undefined;
  return parseDataUri(raw) ?? { data: raw, mime: defaultMime };
}

/** Infer a media mime from a URL's file extension (CDNs often serve images as octet-stream). */
function mimeFromExt(url: string, kindPrefix: "image/" | "audio/"): string | undefined {
  const u = url.toLowerCase().split("?")[0].split("#")[0];
  const map: Record<string, string> =
    kindPrefix === "image/"
      ? { ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif" }
      : { ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg", ".m4a": "audio/mp4", ".aac": "audio/aac" };
  for (const [ext, mime] of Object.entries(map)) if (u.endsWith(ext)) return mime;
  return undefined;
}

/** Infer a mime from a URL extension across all output kinds (image/audio/video/doc) — used to set
 * RunOutput.mime on url/video/file outputs (so the link labels + the future web W6 registry can
 * dispatch precisely). Returns undefined when the extension isn't recognized. */
function mimeFromAnyExt(url: string): string | undefined {
  const u = url.toLowerCase().split("?")[0].split("#")[0];
  const map: Record<string, string> = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif", ".svg": "image/svg+xml",
    ".mp3": "audio/mpeg", ".wav": "audio/wav", ".ogg": "audio/ogg", ".m4a": "audio/mp4", ".aac": "audio/aac",
    ".mp4": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime", ".m4v": "video/x-m4v",
    ".pdf": "application/pdf",
    ".csv": "text/csv", ".tsv": "text/tab-separated-values",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xls": "application/vnd.ms-excel",
    ".zip": "application/zip",
    ".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  };
  for (const [ext, mime] of Object.entries(map)) if (u.endsWith(ext)) return mime;
  return undefined;
}

/** Human caption/emoji for a downloadable file artifact, by mime. */
function fileCaption(mime: string | undefined): string {
  const m = mime ?? "";
  if (m === "application/pdf") return "📄 PDF report";
  if (m === "text/csv" || m === "text/tab-separated-values" || m.includes("spreadsheetml") || m === "application/vnd.ms-excel") return "📊 Spreadsheet";
  if (m === "application/zip") return "📦 Archive";
  if (m.includes("wordprocessingml") || m === "application/msword") return "📄 Document";
  return "📎 File";
}

// (Media fetching now goes through perception.ts `fetchMediaBytes` — one generous-cap download per
// output, reused for inline/preview + Blob mirroring. The old per-call `fetchAsBase64` was removed in 2.2.)

/** Collapse long strings (e.g. base64 blobs) so the text block stays readable when a media block exists. */
// For DATA results (search/LLM), keep the ACTUAL content the agent needs — clamp total size but do NOT
// per-field elide (that would gut search snippets). The brain caps the whole tool_result again (~8KB).
// A "paid but empty" result: the provider returned 2xx with a result-collection field that is an empty
// array (people/results/data/items/matches/records/hits) and no other array on the body has any rows.
// Conservative on purpose — only fires when the body clearly carries an empty collection, so we never
// flag a scalar/object result (e.g. an enrichment that returns one object) as "empty".
function isEmptyResultBody(body: unknown): boolean {
  let obj: Record<string, unknown> | undefined;
  if (typeof body === "string") {
    try { obj = JSON.parse(body); } catch { return false; }
  } else if (body && typeof body === "object") {
    obj = body as Record<string, unknown>;
  }
  if (!obj || typeof obj !== "object") return false;
  const COLLECTION_KEYS = ["people", "results", "data", "items", "matches", "records", "hits", "contacts", "profiles", "organizations", "companies"];
  // Look at top-level arrays AND one level into a nested result wrapper (e.g. monid nests people under
  // `output`, some providers under `data`) so a wrapped empty collection is still detected.
  const scopes: Record<string, unknown>[] = [obj];
  for (const wrap of ["output", "data", "result", "response"]) {
    const w = obj[wrap];
    if (w && typeof w === "object" && !Array.isArray(w)) scopes.push(w as Record<string, unknown>);
  }
  const arrays = scopes.flatMap((o) => Object.entries(o).filter(([, v]) => Array.isArray(v))) as [string, unknown[]][];
  if (!arrays.length) return false;
  // If ANY array on the body has rows, it's not empty.
  if (arrays.some(([, v]) => v.length > 0)) return false;
  // All arrays are empty — only call it "empty" if at least one is a recognized result collection.
  return arrays.some(([k]) => COLLECTION_KEYS.includes(k));
}

function clampData(body: unknown, max = 6000): unknown {
  let s: string;
  try {
    s = typeof body === "string" ? body : JSON.stringify(body);
  } catch {
    return undefined;
  }
  if (s.length <= max) return body; // small enough → keep the structured form
  return `${s.slice(0, max)}…[truncated ${s.length - max} chars]`;
}

function elideLong(v: unknown, depth = 0): unknown {
  if (typeof v === "string") return v.length > 256 ? `[${v.length} chars elided]` : v;
  if (Array.isArray(v)) return depth > 6 ? "[…]" : v.map((x) => elideLong(x, depth + 1));
  if (v && typeof v === "object") {
    if (depth > 6) return "{…}";
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) o[k] = elideLong(val, depth + 1);
    return o;
  }
  return v;
}

async function mapOutput(
  body: unknown,
  modalityOut: RunOutputType[],
  resultPath?: string,
): Promise<{ content: ContentBlock[]; outputs: RunOutput[]; isMediaOrFile: boolean }> {
  const content: ContentBlock[] = [];
  const outputs: RunOutput[] = [];
  // 2.2: bytes fetched for inline/preview are kept here so the mirror reuses them (one download per output).
  const fetchedBuffers = new Map<RunOutput, Buffer>();

  // 3.4: prefer the registry-declared result path (deterministic) over the depth-4 heuristic.
  const url = resolveResultUrl(body, resultPath) ?? findUrl(body);
  // Detect media from the RESULT (registry modality is often incomplete): inline base64, or a URL
  // whose extension is a known media type. Fall back to the declared modality.
  const imgB64 = inlineBase64(body, IMAGE_B64_KEYS, "image/png");
  const audB64 = inlineBase64(body, AUDIO_B64_KEYS, "audio/mpeg");
  const urlImg = url ? mimeFromExt(url, "image/") : undefined;
  const urlAud = url ? mimeFromExt(url, "audio/") : undefined;
  const urlVid = url ? /\.(mp4|webm|mov|m4v)$/i.test(url.split("?")[0]) : false;
  // A downloadable FILE artifact (pdf/csv/xlsx/zip/doc) — narrow on purpose so an *incidental* in-body
  // link (e.g. an Exa result's article URL, which `findUrl` would grab) is NOT mistaken for "the result".
  const urlIsFile = url ? /\.(pdf|csv|tsv|xlsx?|zip|docx?)$/i.test(url.split("?")[0].split("#")[0]) : false;

  const isImage = modalityOut.includes("image") || !!imgB64 || !!urlImg;
  const isAudio = !isImage && (modalityOut.includes("audio") || !!audB64 || !!urlAud);
  const isVideo = !isImage && !isAudio && (modalityOut.includes("video") || urlVid);
  const isFile = !isImage && !isAudio && !isVideo && urlIsFile;

  let mediaInlined = false;
  let caption = "";

  if (isImage) {
    // Get the raw bytes ONCE: provider inline base64, or fetch the URL with a generous cap (1.1).
    let rawBuf: Buffer | undefined;
    let rawMime: string | undefined;
    if (imgB64) {
      rawBuf = Buffer.from(imgB64.data, "base64");
      rawMime = imgB64.mime;
    } else if (url) {
      const fetched = await fetchMediaBytes(url);
      if (fetched) {
        rawBuf = fetched.buffer;
        rawMime = fetched.contentType || urlImg || "image/png";
      }
    }

    if (rawBuf) {
      // Normalize formats claude.ai won't display (webp/avif) to JPEG so the image renders everywhere
      // (content block + widget). png/jpeg/gif pass through untouched. If conversion fails, keep original.
      if (!isDisplayableImageMime(rawMime)) {
        const jpeg = await normalizeToJpeg(rawBuf);
        if (jpeg) {
          rawBuf = jpeg;
          rawMime = "image/jpeg";
        }
      }
      const rawB64 = rawBuf.toString("base64");
      // Inline the original when it's a displayable format AND under the host cap; otherwise hand the
      // model a downscaled JPEG preview so it can SEE big images. Full-res stays at url.
      let inline: { data: string; mime: string } | undefined;
      if (rawB64.length <= CLAUDE_INLINE_MAX_B64 && isDisplayableImageMime(rawMime)) {
        inline = { data: rawB64, mime: rawMime as string };
      } else {
        inline = await downscaleImageForInline(rawBuf);
      }
      if (inline) {
        content.push({ type: "image", data: inline.data, mimeType: inline.mime });
        mediaInlined = true;
      }
      // The OUTPUT carries the full-res artifact (the JPEG-normalized bytes for webp/avif, else original).
      const imgOut: RunOutput = { type: "image", url, data: url ? undefined : rawB64, mime: rawMime ?? urlImg };
      outputs.push(imgOut);
      fetchedBuffers.set(imgOut, rawBuf); // 2.2/webp-fix: mirror reuses these (JPEG-normalized) bytes
    } else if (url) {
      outputs.push({ type: "image", url, mime: urlImg });
    }
    caption = "🖼️ Image ready";
  } else if (isAudio) {
    // Fetch the bytes ONCE (1.1/2.2): provider inline base64, or fetch the URL with a generous cap.
    let rawBuf: Buffer | undefined;
    let rawMime: string | undefined;
    if (audB64) {
      rawBuf = Buffer.from(audB64.data, "base64");
      rawMime = audB64.mime;
    } else if (url) {
      const fetched = await fetchMediaBytes(url);
      if (fetched) {
        rawBuf = fetched.buffer;
        rawMime = (fetched.contentType.startsWith("audio/") ? fetched.contentType : urlAud) || "audio/mpeg";
      }
    }
    if (rawBuf) {
      const rawB64 = rawBuf.toString("base64");
      const audioMime = rawMime ?? "audio/mpeg";
      // Inline a native audio block the model can play, when it fits the host cap (no "downscale" for audio).
      if (rawB64.length <= CLAUDE_INLINE_MAX_B64 && audioMime.startsWith("audio/")) {
        content.push({ type: "audio", data: rawB64, mimeType: audioMime });
        mediaInlined = true;
      }
      const audioOut: RunOutput = { type: "audio", url, data: url ? undefined : rawB64, mime: rawMime ?? urlAud };
      outputs.push(audioOut);
      fetchedBuffers.set(audioOut, rawBuf); // 2.2: reuse for mirroring
    } else if (url) {
      outputs.push({ type: "audio", url, mime: urlAud });
    }
    caption = "🔊 Audio ready";
  } else if (isVideo && url) {
    outputs.push({ type: "video", url, mime: mimeFromAnyExt(url) }); // no native MCP video block — URL only
    caption = "🎬 Video ready";
  } else if (isFile && url) {
    const mime = mimeFromAnyExt(url);
    const fileOut: RunOutput = { type: "url", url, mime };
    outputs.push(fileOut);
    caption = fileCaption(mime);
    // Perception (1.4): make the document READABLE by the model — extract text and inline it (the full
    // file stays at the link). PDF → unpdf; plain-text formats → decode. Binary office/zip → link only.
    const ext = url.split("?")[0].split("#")[0].toLowerCase();
    const fetched = await fetchMediaBytes(url);
    if (fetched) {
      fetchedBuffers.set(fileOut, fetched.buffer); // 2.3: mirror the document for a durable link (reuse bytes)
      let docText: string | undefined;
      if (/\.pdf$/.test(ext) || mime === "application/pdf") {
        docText = await extractPdfText(fetched.buffer);
      } else if (/\.(csv|tsv|txt|json|md)$/.test(ext)) {
        const decoded = fetched.buffer.toString("utf8").trim();
        docText = decoded.length > 12_000 ? `${decoded.slice(0, 12_000)}\n…[truncated — full file at the link]` : decoded;
      }
      if (docText) content.push({ type: "text", text: `📄 Document text:\n\n${docText}` });
    }
  }

  // Re-host media to OUR Blob origin so every output has a DURABLE URL (provider URLs expire) — needed
  // for (a) the edit/iterate loop (re-feeding an output's URL into a later call) and (b) the ui:// viewer's
  // single-origin CSP. ALWAYS ON (OUTPUT_AWARENESS_SPEC 2.1) — decoupled from the MCP Apps flag, since
  // durability is a correctness requirement, not experimental UI. Best-effort: failure/oversize keeps the
  // provider URL. Done BEFORE the content link below so the human "[open/download]" link is durable too.
  for (const o of outputs) {
    // image/audio/video media + file artifacts (type "url" = a downloadable file) get a durable Blob link.
    let mtype: "image" | "video" | "audio" | "file" | null = null;
    if (o.type === "image" || o.type === "video" || o.type === "audio") mtype = o.type;
    else if (o.type === "url") mtype = "file";
    if (!mtype) continue;
    if (o.url?.includes(".public.blob.vercel-storage.com")) {
      delete o.data; // already ours → never carry the heavy base64 in the structured payload
      continue;
    }
    // 2.2/2.3: reuse the bytes we already downloaded for the preview/inline/text; only fetch here if we didn't.
    const buf = fetchedBuffers.get(o);
    const base64 = buf ? buf.toString("base64") : o.data;
    if (!o.url && !base64) continue; // nothing to mirror
    // Mirror BOTH url-origin AND base64-origin media (e.g. TTS returns inline base64, no url) so every
    // output has a durable URL.
    const blobUrl = await mirrorOutputToBlob({ type: mtype, url: o.url, base64, mime: o.mime });
    if (blobUrl) o.url = blobUrl;
    // Once we have ANY url, DROP the base64 from the output. Carrying multi-MB base64 (TTS audio, video)
    // in structuredContent bloats the /mcp HTTP response past serverless limits → "HTTP 500" that kills
    // the run before the audio is surfaced. The durable URL is what callers/the widget use. Keep base64
    // only as a last resort when mirroring failed AND there's no provider url.
    if (o.url) delete o.data;
  }

  // A real artifact was produced iff we inlined media or pushed a media/file URL output. (A data result
  // — e.g. search results, an LLM completion — produces neither, so it falls to the data branch.)
  const isMediaOrFile = mediaInlined || outputs.some((o) => !!o.url);

  if (isMediaOrFile) {
    // Clean, human-facing caption + the artifact link. The raw provider JSON is NOT dumped into the
    // human view — it's preserved in structuredContent.raw for the agent (set by the caller).
    const primaryUrl = outputs.find((o) => o.url)?.url;
    const link = primaryUrl ? ` — [open / download](${primaryUrl})` : "";
    content.push({ type: "text", text: `${caption || "✅ Result ready"}${link}` });
  } else {
    // Data result: the body IS the answer. Show it as text. Do NOT surface a body-derived URL as
    // "the result" and do NOT add a url-type output (fixes the stray "🔗 Result: <random link>" wart).
    if (!outputs.length) outputs.push({ type: typeof body === "string" ? "text" : "json" });
    content.push({ type: "text", text: typeof body === "string" ? body : JSON.stringify(body, null, 2) });
  }

  if (!outputs.length) outputs.push({ type: typeof body === "string" ? "text" : "json" });

  return { content, outputs, isMediaOrFile };
}

// ---- the pipeline -------------------------------------------------------------------------------

export async function runService(caller: RunCaller, args: RunArgs): Promise<RunResultEnvelope> {
  // Input-size guard (M8): reject oversized / non-serializable payloads before any work.
  if (args.input !== undefined) {
    let bytes = 0;
    try {
      bytes = JSON.stringify(args.input).length;
    } catch {
      return { ok: false, code: "bad_input", message: "input is not JSON-serializable" };
    }
    if (bytes > MAX_INPUT_BYTES) {
      return { ok: false, code: "bad_input", message: `input too large (${bytes} bytes > ${MAX_INPUT_BYTES})` };
    }
  }

  const svc = findServiceById(args.serviceId);
  if (!svc || svc.status === "hidden") {
    return { ok: false, code: "service_not_found", message: `service not found: ${args.serviceId}` };
  }

  // M7 idempotency: a durable caller passes an idempotencyKey so a crash-retry can't double-charge.
  // Claim the slot or short-circuit on the existing record. No key → unchanged legacy behavior.
  const idemKey = args.idempotencyKey;
  if (idemKey) {
    const claim = await claimRun<RunResultEnvelope>(caller.userId, idemKey);
    if (claim.kind === "settled") return claim.outcome; // exact prior result, no re-charge
    if (claim.kind === "in_progress")
      return { ok: false, code: "duplicate_in_progress", message: "a call with this idempotency key is already in progress; retry shortly" };
    if (claim.kind === "needs_reconcile")
      return { ok: false, code: "needs_reconcile", message: "a prior paid attempt with this key could not be confirmed — not re-charging; this run needs reconciliation/refund review" };
    if (claim.kind === "async_recover") return getJobResult(caller, claim.jobId); // re-poll the existing job (exactly-once)
    // kind === "fresh" → we own the slot; proceed to pay.
  }

  // 1) Resolve a callable, payable target.
  const { target, anyExist, anyPayable } = pickTarget(svc, args);
  if (!target) {
    if (anyExist && !anyPayable) {
      return {
        ok: false,
        code: "unsupported_network",
        message: `'${svc.name}' has no x402 backend on a supported network (${[...SUPPORTED_NETWORKS].join(", ")}).`,
      };
    }
    return { ok: false, code: "no_payable_target", message: `no callable target for '${svc.name}'${args.operation ? ` (operation '${args.operation}')` : ""}.` };
  }

  // 2) Build the request (URL/query/headers/body; modelParam).
  const { url, method, headers, body } = buildRequest(target, args.input ?? {}, args.model);

  // 2a) Guard unfilled path templates: if the caller omitted a required path parameter (e.g. AgentMail's
  // "{inbox_id}"), the URL still carries a literal "{token}" — sending it would 4xx upstream with an opaque
  // error the brain can't act on. Fail FAST (pre-payment, no charge) with an actionable message naming the
  // field, so the brain fixes it on the next try instead of flailing. (Helps every templated-URL service.)
  const unfilled = [...new Set([...url.matchAll(/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g)].map((m) => m[1]))];
  if (unfilled.length) {
    if (idemKey) await failRun(caller.userId, idemKey); // nothing paid → release the claim (retryable)
    return {
      ok: false,
      code: "bad_input",
      message: `Missing required path parameter${unfilled.length > 1 ? "s" : ""} ${unfilled.map((n) => `"${n}"`).join(", ")} — this endpoint's URL has ${unfilled.length > 1 ? "those tokens" : "that token"} in the path (e.g. .../${`{${unfilled[0]}}`}/...). Include ${unfilled.length > 1 ? "them" : "it"} as ${unfilled.length > 1 ? "fields" : "a field"} in the input and retry.`,
    };
  }

  // 3) Enforce spend (reserve-before-pay). estCost = amount → max → ceiling.
  const estCostUsd = estimateCost(target.price, null);
  const reserve = await reserveSpend({ userId: caller.userId, connectionId: caller.connectionId, category: svc.category, estCostUsd });

  // The idempotencyKey is `${runId}:hash:seq` for web runs — tag ledger rows so RunDoc.providerCostUsd
  // can be DERIVED from the run's settled rows (RUN_RELIABILITY_SPEC 2.1). Absent for external agents.
  const webRunId = idemKey && idemKey.startsWith("run_") ? idemKey.split(":")[0] : undefined;

  const ref: CallRef = {
    userId: caller.userId,
    connectionId: caller.connectionId,
    tokenJti: caller.tokenJti,
    serviceId: svc.id,
    serviceName: `${svc.name} via ${target.provider}`,
    operation: target.operationName,
    provider: target.provider,
    backendUrl: target.url,
    bucket: reserve.bucket,
    ...(webRunId ? { runId: webRunId } : {}),
  };

  if (!reserve.allow) {
    await recordRejected(ref, reserve.reason);
    if (idemKey) await failRun(caller.userId, idemKey); // nothing paid → release the claim (retryable)
    return { ok: false, code: reserve.reason, message: reserve.message };
  }

  // 4) Pay via the Sponge master wallet.
  const payChain = preferredChain(target);
  const targetPayTo = expectedPayTo(target, payChain);
  let pay;
  try {
    pay = await payProvider({
      url,
      method,
      headers,
      body,
      maxValueUsd: reserve.maxValueUsd,
      preferredChain: payChain,
      expectedPayTo: targetPayTo,
      siwxHint: target.authMode === "siwx" ? "siwx" : undefined,
      payerUserId: caller.userId,
    });
  } catch (e) {
    await releaseReservation(ref, { reservedUsd: reserve.reservedUsd, status: "failed" });
    if (idemKey) await failRun(caller.userId, idemKey); // pre-flight/quote/pay threw → nothing settled (retryable)
    if (e instanceof PaymentExceededError) return { ok: false, code: "price_exceeded", message: e.message };
    if (e instanceof WalletPaymentError) return { ok: false, code: "payment_failed", message: e.message };
    return { ok: false, code: "payment_failed", message: e instanceof Error ? e.message : String(e) };
  }

  const modalityOut = (svc.modality?.output ?? []).map(canonModality);

  // 5) Record. Charged if a payment was made OR the provider returned 2xx (R2: non-2xx after a payment
  // is still charged). Nothing paid + provider error → release the reservation (cost 0).
  if (pay.ok || pay.paid) {
    await settleSpend(ref, { reservedUsd: reserve.reservedUsd, actualCostUsd: pay.costUsd, network: pay.network, txHash: pay.txHash, confirmed: pay.confirmed, payTo: targetPayTo });
  } else {
    await releaseReservation(ref, { reservedUsd: reserve.reservedUsd, status: "failed", network: pay.network });
    if (idemKey) await failRun(caller.userId, idemKey); // provider error, nothing paid → retryable
    return { ok: false, code: "provider_error", message: `provider returned ${pay.status} and no payment was made` };
  }

  // Fresh remaining budget after settle.
  const fresh = await getUser(caller.userId);
  const remainingUsd = fresh ? Math.max(0, fresh.spend.monthlyLimitUsd - fresh.billing.spentThisPeriodUsd) : 0;

  // R2 charge-then-error: the provider TOOK PAYMENT but returned a non-2xx (e.g. CogVideoX 429 "insufficient
  // balance / no resource package — recharge"; charge-then-validate 400s). Its error body is neither a result
  // nor a pollable job — detectAsyncJob must NOT fabricate a job from it (an error body has no job id, so the
  // poll URL came out as ".../async-result/" with an empty {id} → hundreds of dead "pending" polls). Surface
  // the failure now; the charge is already settled, so settle the idempotency record with the error (a retry
  // returns it, never re-pays).
  if (!pay.ok) {
    const errEnv: RunResultEnvelope = {
      ok: false,
      code: "provider_error",
      message: `${ref.serviceName} returned ${pay.status} after ${chargeNoun(pay.costUsd, pay.confirmed)} — no result or pollable job (likely a provider-side outage). Try another provider.`,
    };
    if (idemKey) await settleRun(caller.userId, idemKey, errEnv);
    return errEnv;
  }

  // 5b) Async job? The provider charged on submit and returned a job to poll (slow image / video).
  // Persist it and hand the agent a job handle to retrieve later via get_result.
  const job = detectAsyncJob(pay.body, target.url, target.async, { status: pay.status, headers: pay.headers });
  if (job) {
    const saved = await createJob({
      userId: caller.userId,
      connectionId: caller.connectionId,
      tokenJti: caller.tokenJti,
      serviceId: svc.id,
      serviceName: ref.serviceName,
      provider: target.provider,
      backendUrl: target.url,
      pollUrl: job.pollUrl,
      providerJobId: job.providerJobId,
      modalityOut,
      bucket: reserve.bucket,
      costUsd: pay.costUsd,
      priceUsd: estCostUsd, // the endpoint's known price (also what we reserved against) — the legit job cost the poller may authorize
      network: pay.network,
      txHash: pay.txHash,
      ...(targetPayTo ? { payTo: targetPayTo } : {}),
      ...(webRunId ? { runId: webRunId } : {}),
      ...(target.async ? { async: target.async } : {}),
    });
    // Messaging is the lever that controls the agent's polling. On a widget-capable host (claude.ai),
    // the run_service result card already shows a LIVE progress view that polls + renders the media on
    // its own — so the agent must NOT poll get_result (each agent poll spawns ANOTHER widget card, and
    // they all render the image → the duplicate-cards problem). Tell it the UI handles display; only pull
    // if IT needs the raw data. On a non-widget host there's no live view, so keep the "pull once" path.
    //
    // ⚠️ Gate on isMcpAppsEnabled() (the env flag = "we attached the ui:// viewer"), NOT on the runtime
    // capability detection (opts.appsCapable / isClientAppsCapable). On the pinned SDK 1.26 that detector
    // returns FALSE for every client (the strict ClientCapabilitiesSchema strips `extensions`), so this
    // branch was DEAD in prod — the agent always got the poll-INVITING message below and busy-spammed
    // get_result (the duplicate-card stack). The flag is the truthful signal: when it's on we DID attach
    // the live viewer, and our prod hosts (claude.ai/ChatGPT) render + self-poll it. (SIWX_SUPPORT_SPEC §14.)
    const jsummary = isMcpAppsEnabled()
      ? `Job started for ${ref.serviceName} (${chargeNoun(pay.costUsd, pay.confirmed)}). A live result view is ALREADY shown to the user above and will render the ${ref.serviceName} output automatically when it's ready — you do NOT need to fetch it for the user to see it. Do NOT call get_result to poll for this job. Only call get_result ONCE if YOU need the raw output (e.g. its URL) to feed into another tool; otherwise just briefly tell the user it's generating and will appear above. Remaining budget: $${remainingUsd.toFixed(2)}.`
      : `Job started for ${ref.serviceName} (${chargeNoun(pay.costUsd, pay.confirmed)}). Call get_result ONCE with jobId="${saved._id}" to retrieve it — that call WAITS for the result (blocks until ready, up to ~45s) and returns the media. Do NOT poll in a tight loop; if it returns still "rendering", call it again after a pause. Remaining budget: $${remainingUsd.toFixed(2)}.`;
    const asyncEnvelope: RunResultEnvelope = {
      ok: true,
      async: true,
      jobId: saved._id,
      status: "pending",
      content: [{ type: "text", text: jsummary }],
      summary: jsummary,
      costUsd: pay.costUsd,
      remainingUsd,
    };
    // Persist the jobId BEFORE returning (so an expired-lease recovery re-polls it, exactly-once), then
    // settle the idempotency record with the job handle.
    if (idemKey) {
      await markRunJob(caller.userId, idemKey, saved._id);
      await settleRun(caller.userId, idemKey, asyncEnvelope, saved._id);
    }
    return asyncEnvelope;
  }

  // 6) Map output + RunResult envelope (R6).
  const { content, outputs, isMediaOrFile } = await mapOutput(pay.body, modalityOut, target.async?.poll?.resultPath);

  // RUN_RELIABILITY_SPEC 3.3 — unfinished-sync guard. If this wasn't recognized as an async job but the
  // "sync" body is explicitly still PROCESSING and produced no media when media was expected, don't
  // present junk JSON as success — return an error so the agent tries another provider. We DID pay
  // (settleSpend ran), so settle the idempotency record with this error (a retry returns it, never
  // re-pays). This is the backstop for pending bodies that detectAsyncJob couldn't turn into a job.
  const mediaExpected = modalityOut.some((m) => m === "image" || m === "video" || m === "audio");
  if (mediaExpected && !isMediaOrFile && bodyHasPendingStatus(pay.body, target.async)) {
    const errEnv: RunResultEnvelope = {
      ok: false,
      code: "provider_error",
      message: `${ref.serviceName} returned a still-processing response with no result and no pollable job — ${chargeNoun(pay.costUsd, pay.confirmed)}, and it produced no output. Try another provider or a backend with a documented async/poll flow.`,
    };
    if (idemKey) await settleRun(caller.userId, idemKey, errEnv);
    return errEnv;
  }

  // A PAID call that returned an empty result set (people/results/data: []) was charged in full but
  // produced nothing — almost always a too-narrow/wrong-shaped query, not missing data. Nudge the AGENT
  // (via structuredContent.notice, the only thing the brain reads) to broaden/re-shape once then switch,
  // rather than firing the same empty-returning shape at the next item and burning money. UI never shows it.
  const emptyNotice = pay.ok && isEmptyResultBody(pay.body)
    ? `This paid call returned an EMPTY result set and incurred ${chargeNoun(pay.costUsd, pay.confirmed, 4)} anyway. This is almost always a too-narrow or wrong-shaped query (e.g. an exact job title instead of a seniority level), NOT missing data. Do NOT repeat this same query shape on other items. Broaden or re-shape the query ONCE (loosen the narrowest filter / use the provider's documented vocabulary), and if it's still empty switch to a different provider for this capability.`
    : undefined;

  const summary = `Charged $${pay.costUsd.toFixed(6)} for ${ref.serviceName}${pay.ok ? "" : ` (provider returned ${pay.status})`}${emptyNotice ? " — EMPTY result (see notice)" : ""}. Remaining budget: $${remainingUsd.toFixed(2)}.`;

  const structured: RunResult = {
    serviceId: svc.id,
    serviceName: svc.name,
    modalityOut,
    category: svc.category,
    operation: target.operationName,
    outputs,
    providerCostUsd: pay.costUsd,
    ...(emptyNotice ? { notice: emptyNotice } : {}),
    // Carry the provider body for the AGENT in structuredContent (the brain reads `structured`, not the
    // human `content`). Media → elide long blobs (base64/urls); DATA results (search, LLM) → keep the
    // actual text (clamped, NOT per-field elided) so the agent can chain output→input. Bug fix: data
    // results used to ship only `outputs:[{type:"json"}]` here, so the brain saw an empty result.
    raw: isMediaOrFile ? elideLong(pay.body) : clampData(pay.body),
  };

  const envelope: RunResultEnvelope = {
    ok: true,
    content: [...content, { type: "text", text: summary }],
    structured,
    summary,
    costUsd: pay.costUsd,
    remainingUsd,
    providerOk: pay.ok,
    providerStatus: pay.status,
  };
  // Settle the idempotency record with the final outcome (paid + mapped) so a duplicate key returns it
  // verbatim without re-charging. If we crash before this lands, recovery → needs_reconcile (at-most-once).
  if (idemKey) await settleRun(caller.userId, idemKey, envelope);
  return envelope;
}

// ---- get_result (async jobs) --------------------------------------------------------------------

// Server-side long-poll budget for get_result: how long a single call blocks while internally polling
// the provider, and the gap between internal polls. Keeps agents from busy-spamming get_result — each
// agent call now absorbs ~LONGPOLL_MS of waiting, so a ~3-min job drops from ~9 "still rendering" cards
// (at 20s) to ~4 (at 45s). Kept under the 300s /mcp maxDuration; 45s is a balance vs the MCP client's
// own tool-call timeout (claude.ai tolerates ≥20s in testing; raise toward ~90s if it tolerates more,
// or lower if calls start timing out). Both env-tunable. The loop ALWAYS returns early on completion.
const LONGPOLL_MS = Number(process.env.GET_RESULT_LONGPOLL_MS) || 45_000;
const LONGPOLL_INTERVAL_MS = Number(process.env.GET_RESULT_POLL_INTERVAL_MS) || 10_000;
// AXIS 6 (stuck-forever guard): a hard cap on total polls so a FREE/SIWX job (which no cost cap bounds) can't
// be polled forever silently. Generous — ~240 polls at the 10s interval ≈ 40 min of real polling, so it only
// trips genuinely-stuck jobs, never slow-but-working ones. Per-poll jobs are also bounded by the cost cap.
const MAX_POLLS_DEFAULT = Number(process.env.MASTERKEY_MAX_POLLS) || 240;

/** Retrieve (or poll for) the result of a previously-submitted async job. */
export async function getJobResult(caller: RunCaller, jobId: string): Promise<RunResultEnvelope> {
  const job = await getJob(jobId, caller.userId);
  if (!job) return { ok: false, code: "service_not_found", message: `job not found: ${jobId}` };
  const modalityOut = job.modalityOut as RunOutputType[];

  const finish = async (body: unknown): Promise<RunResultEnvelope> => {
    const { content, outputs, isMediaOrFile } = await mapOutput(body, modalityOut, job.async?.poll?.resultPath);
    const fresh = await getUser(caller.userId);
    const remainingUsd = fresh ? Math.max(0, fresh.spend.monthlyLimitUsd - fresh.billing.spentThisPeriodUsd) : 0;
    // `job.costUsd` is what the engine METERED for this job (submit + polls); a JobDoc carries no per-charge
    // confirmation flag, and its components may still be `unconfirmed` in the ledger. `remainingUsd` below
    // is derived from settled spend only, so the two are stated as the distinct things they are rather than
    // implying the metered figure was definitely charged.
    const summary = `${job.serviceName} complete (metered cost $${job.costUsd.toFixed(6)} — only on-chain-settled charges count toward the budget). Remaining budget: $${remainingUsd.toFixed(2)}.`;
    const structured: RunResult = {
      serviceId: job.serviceId,
      serviceName: job.serviceName,
      modalityOut,
      category: findServiceById(job.serviceId)?.category ?? "",
      outputs,
      providerCostUsd: job.costUsd,
      raw: isMediaOrFile ? elideLong(body) : clampData(body),
    };
    return { ok: true, content: [...content, { type: "text", text: summary }], structured, summary, costUsd: job.costUsd, remainingUsd, providerOk: true, providerStatus: 200 };
  };

  // DEDUP: the job was already completed + delivered by a PRIOR get_result call. Agents (and multiple
  // result-viewer widgets) often call get_result several more times around completion — if each returned
  // the full media again, claude.ai renders a DUPLICATE image/video card every time (observed: ~5-6
  // identical images). So a re-fetch returns a COMPACT pointer (no media block, empty outputs → the
  // viewer shows a tiny "already delivered" card, never a second image) and tells the agent to stop.
  if (job.status === "complete") {
    const fresh = await getUser(caller.userId);
    const remainingUsd = fresh ? Math.max(0, fresh.spend.monthlyLimitUsd - fresh.billing.spentThisPeriodUsd) : 0;
    const msg = `${job.serviceName} already completed and its result was delivered above. Do not call get_result again for jobId="${jobId}".`;
    const structured: RunResult = {
      serviceId: job.serviceId,
      serviceName: job.serviceName,
      modalityOut,
      category: findServiceById(job.serviceId)?.category ?? "",
      outputs: [],
      providerCostUsd: job.costUsd,
    };
    return { ok: true, content: [{ type: "text", text: msg }], structured, summary: msg, costUsd: job.costUsd, remainingUsd, providerOk: true, providerStatus: 200 };
  }
  if (job.status === "failed") return { ok: false, code: "provider_error", message: `job failed: ${job.error ?? "unknown error"}` };

  // Safety backstop on a runaway paid poller. A paid (`per-poll`) provider settles its job exactly ONCE at
  // the legitimate price — BlockRun, the canonical case, authorizes the full price on each poll but only the
  // COMPLETED poll settles (verified on-chain 2026-06-23), so the real-world job cost is its price, once. The
  // cap is therefore the endpoint's KNOWN PRICE (job.priceUsd, the registry amount we reserved against) with a
  // small margin for dynamic pricing — NOT a per-endpoint registry "ceiling" field (a spend ceiling is a
  // runtime/user policy, not endpoint description). The user's spend limits are the real money guardrail (they
  // already gated this job at reserve time); MASTERKEY_JOB_COST_CAP_USD is just an env backstop when price is
  // unknown. Free/SIWX polls cost $0 and are never blocked.
  const knownPrice = (job.priceUsd ?? 0) > 0 ? (job.priceUsd as number) * 1.5 : null;
  const JOB_COST_CAP = knownPrice ?? (Number(process.env.MASTERKEY_JOB_COST_CAP_USD) || 0.5);
  const pollsCostMoney = job.async?.poll?.cost === "per-poll" || job.async?.poll?.cost == null; // free/siwx = $0
  const estNextPollCost = (): number =>
    pollsCostMoney ? (job.priceUsd ?? job.costUsd / (job.pollCount + 1)) : 0; // known price (a poll may be the settling one), else running avg
  const pendingEnvelope = async (text: string): Promise<RunResultEnvelope> => {
    const u = await getUser(caller.userId);
    const rem = u ? Math.max(0, u.spend.monthlyLimitUsd - u.billing.spentThisPeriodUsd) : 0;
    return { ok: true, async: true, jobId, status: "pending", content: [{ type: "text", text }], summary: text, costUsd: job.costUsd, remainingUsd: rem };
  };
  const costCapMsg = `Job ${jobId} hasn't completed and continuing to poll would cross the $${JOB_COST_CAP.toFixed(2)} safety cap for this job. Not polling further — it may be stuck; consider re-running on a provider with free result polling.`;
  const wouldExceedCap = (): boolean => pollsCostMoney && job.costUsd + estNextPollCost() > JOB_COST_CAP;
  if (wouldExceedCap()) return pendingEnvelope(costCapMsg);

  // Book a poll/result-fetch charge as additional job debt (BlockRun-style paid polls, or a paid AXIS-7
  // result-fetch). RUN_RELIABILITY_SPEC 1.4/1.5: append FIRST (appendLedger downgrades settled→unconfirmed for
  // a missing/duplicate tx hash), then count spend ONLY for the row actually written `settled`. Returns true if
  // money moved. Shared by the poll loop and the separate-result fetch so both are booked identically.
  const bookCost = async (c: { costUsd: number; network?: string; txHash?: string }, label: string): Promise<boolean> => {
    if (!(c.costUsd > 0)) return false;
    const written = await appendLedger({
      userId: job.userId,
      connectionId: job.connectionId,
      tokenJti: job.tokenJti,
      serviceId: job.serviceId,
      serviceName: `${job.serviceName} (${label})`,
      provider: job.provider,
      backendUrl: job.pollUrl,
      bucket: job.bucket,
      costUsd: c.costUsd,
      network: c.network ?? job.network,
      txHash: c.txHash,
      ...(job.payTo ? { payTo: job.payTo } : {}),
      status: "settled",
      ...(job.runId ? { runId: job.runId } : {}),
    });
    if (written === "settled") await incSpent(job.userId, c.costUsd);
    await addJobCost(job._id, c.costUsd);
    job.costUsd += c.costUsd; // keep the in-memory total accurate for finish()/messages
    return true;
  };

  // AXIS 7: when the result lives at a SEPARATE endpoint (resultUrlTemplate), fetch it on completion, book any
  // cost, and map THAT body instead of the (status-only) poll body. The fetch is cost-capped (refuse if it would
  // cross the cap) and at-most-once (it runs in the single completing poll, then job.status=complete dedups).
  const completeWith = async (pollBody: unknown): Promise<RunResultEnvelope> => {
    let resultBody = pollBody;
    if (job.async?.poll?.resultUrlTemplate) {
      const paidResult = (job.async.poll.resultCost ?? "free") === "per-poll";
      if (paidResult && wouldExceedCap()) return pendingEnvelope(costCapMsg); // don't fetch a paid result over the cap
      const rf = await fetchSeparateResult(job);
      if (rf && rf.ok) {
        await bookCost({ costUsd: rf.costUsd, network: rf.network, txHash: rf.txHash }, "result");
        resultBody = rf.body;
      }
    }
    await markJobComplete(job._id, resultBody);
    return finish(resultBody);
  };

  const maxPolls = job.async?.maxPolls ?? MAX_POLLS_DEFAULT;
  if (job.pollCount >= maxPolls) {
    // AXIS 6: a free/SIWX job that has polled past the cap is treated as stuck — fail it terminally so it stops
    // being re-polled forever (per-poll jobs hit the cost cap instead).
    await markJobFailed(job._id, `gave up after ${job.pollCount} polls (maxPolls=${maxPolls})`);
    return { ok: false, code: "provider_error", message: `job ${jobId} did not complete after ${job.pollCount} polls; giving up.` };
  }

  // Long-poll: block server-side and poll the provider for up to LONGPOLL_MS, returning early the moment
  // the job finishes. MCP agents have no real timer and ignore "wait 30s" hints — so without this they
  // busy-spam get_result every few seconds. One call now absorbs ~LONGPOLL_MS of waiting → ~2-4 calls
  // instead of 10+. We ONLY keep looping while polls are FREE; the instant a poll costs money
  // (BlockRun-style per-poll charge) we return after that single poll so long-polling can't multiply
  // per-poll cost. (/mcp maxDuration is 300s, so the ~45s block is safe; LONGPOLL_MS is env-tunable.)
  const deadline = Date.now() + LONGPOLL_MS;
  for (;;) {
    if (wouldExceedCap()) return pendingEnvelope(costCapMsg); // 4.2: refuse the poll BEFORE it can charge
    const outcome = await pollJobOnce(job); // 4.3: atomically claims + advances job.pollCount before paying
    if (outcome.claimSkipped) break; // another worker/replay owns this poll index → stop (return pending)
    const paidThisPoll = await bookCost(outcome, "poll");

    if (outcome.state === "complete") return completeWith(outcome.body); // AXIS 7: may fetch a separate result
    if (outcome.state === "failed") {
      await markJobFailed(job._id, "provider reported failure");
      return { ok: false, code: "provider_error", message: `job ${jobId} failed at the provider` };
    }
    // still pending — decide whether to keep long-polling. (The pre-charge cap guard at the loop top
    // prevents the NEXT poll from overshooting; 4.2.)
    if (paidThisPoll) break; // paid-poll provider → don't loop (would multiply per-poll cost)
    if (job.pollCount >= maxPolls) break; // AXIS 6: hit the poll cap mid-long-poll → stop (re-call will fail it)
    if (Date.now() + LONGPOLL_INTERVAL_MS >= deadline) break; // out of long-poll budget
    await new Promise((r) => setTimeout(r, LONGPOLL_INTERVAL_MS));
  }
  // Same lever as the submit message: when the live viewer is attached (flag on), do NOT invite another
  // poll — the widget above is already polling + will render the media itself. Only the non-widget path
  // tells the agent to call again (it's the only way media surfaces there). SIWX_SUPPORT_SPEC §14.
  const stillRendering = isMcpAppsEnabled()
    ? `${job.serviceName} is still rendering (poll #${job.pollCount}). The live result view shown to the user above will display it automatically the moment it's ready — you do NOT need to call get_result again. Only call it once more if YOU need the raw output URL to feed into a follow-up tool.`
    : `${job.serviceName} is still rendering (poll #${job.pollCount}). Call get_result again with jobId="${jobId}" to keep waiting — it resumes where it left off.`;
  return pendingEnvelope(stillRendering);
}

// ---- MCP tool registration ----------------------------------------------------------------------

// Some MCP clients DROP the human-visible content[] when structuredContent is present (known bugs in
// Claude Code, VS Code, Codex). For those we OMIT structuredContent so the content blocks render.
// Best-effort: only fires when the host reported clientInfo at `initialize`; otherwise we keep
// structuredContent (which now always carries a human-readable `summary` as a last-resort fallback).
// Matched precisely so we NEVER gate Claude Desktop ("claude"/"claude-ai") — only "claude-code".
// NOTE: when the MCP App (ui://) lands, an MCP-Apps-capable client must KEEP structuredContent even if
// it's on this list — gate on app-capability first at that point.
const CONTENT_DROPPING_CLIENT_RE = /(claude-code|visual studio code|vscode|codex)/i;
function clientDropsContent(server: McpServer): boolean {
  try {
    return CONTENT_DROPPING_CLIENT_RE.test(server.server.getClientVersion()?.name ?? "");
  } catch {
    return false; // best-effort — never block a result on detection
  }
}

/**
 * Convert a RunResultEnvelope to an MCP tool result.
 * - `clientDropsContent` → omit structuredContent so the human-visible content[] renders (legacy bug).
 * - `appsCapable` (MCP Apps, §4.4 gate inversion) → KEEP structuredContent even on the drop list, because
 *   the ui:// viewer renders from structuredContent. App-capability WINS over the drop list.
 */
function toToolResult(res: RunResultEnvelope, clientDropsContent = false, appsCapable = false) {
  const drop = clientDropsContent && !appsCapable; // Apps-capable clients must keep structuredContent
  if (!res.ok) {
    const content = [{ type: "text" as const, text: res.message }];
    return drop
      ? { content, isError: true as const }
      : { content, structuredContent: { error: true, code: res.code, message: res.message }, isError: true as const };
  }
  if (res.async) {
    if (drop) return { content: res.content };
    // RUN_RELIABILITY_SPEC 2.2: surface the cost charged so far on async envelopes too (submit + polls),
    // so the agent/transcript see it even before completion. (RunDoc.providerCostUsd is derived from the
    // ledger per 2.1 — this field is informational and is NOT re-accumulated into RunDoc.)
    const j = { kind: "job" as const, jobId: res.jobId, status: res.status, summary: res.summary, providerCostUsd: res.costUsd };
    return { content: res.content, structuredContent: j, _meta: { masterkey: j } };
  }
  if (drop) return { content: res.content };
  // Embed a human-readable `summary` inside structuredContent so even a content-dropping client we
  // failed to detect still shows something useful when it renders the raw structured payload.
  const structured = { ...(res.structured as unknown as Record<string, unknown>), summary: res.summary };
  return { content: res.content, structuredContent: structured, _meta: { masterkey: structured } };
}

/** Register run_service + get_result (both require the mcp:run scope; discovery tools need mcp:read). */
export function registerRunServiceTool(server: McpServer) {
  server.registerTool(
    "run_service",
    {
      title: "Run a service",
      description:
        "Pay for and run a catalog service on the user's behalf, then return the provider's result. " +
        "Masterkey pays the provider from its master wallet and records the cost as the user's debt against their spend limit — " +
        "the agent never holds a wallet or pays directly. Use search_services + get_service first to find the serviceId and input schema. " +
        "Requires the mcp:run scope. Spend limits are enforced BEFORE payment; over-limit calls are rejected with no charge. " +
        "Slow services (some image models, video) return a job handle — call get_result with that jobId to retrieve the media when ready. " +
        "ITERATE ON A RESULT: a previous result's output URL (the `outputs[].url` in the structured result) is durable and can be " +
        "passed straight into a NEW run_service `input` to transform it — e.g. edit/inpaint/upscale/background-remove an image, turn " +
        "an image into a video, or run a vision/'describe' model over it. Call get_service on the target service to see which input " +
        "field takes the image/file (commonly `image`, `image_url`, `init_image`, or `source_image_url`) and pass the prior URL there.",
      inputSchema: {
        serviceId: z.string().describe("The service id (from search_services / get_service)."),
        operation: z.string().describe("Operation name for api-kind services with multiple operations.").optional(),
        backendProviderId: z.string().describe("Pin a specific backend provider (e.g. to force an aggregator route like 'blockrun'). If omitted, the service's first-party provider is used by default, falling back to the cheapest payable one.").optional(),
        model: z.string().describe("Optional model override (ignored when the backend already pins a model).").optional(),
        input: z.record(z.unknown()).describe("Input payload matching the service's input schema.").optional(),
        idempotencyKey: z
          .string()
          .describe(
            "Optional. A stable key for durable callers so a crash-retry of the SAME logical call is not charged twice. " +
              "Reuse the exact same key only for a retry of one call; use a different key for an intentional repeat. Omit for one-shot calls.",
          )
          .optional(),
      },
      // MCP Apps (MCP_APPS_SPEC §4.2 / P0-d): point run_service's result at the ui:// run viewer.
      // Flag-gated — off by default → no `_meta`, byte-identical to today. get_result gets this in P1-d.
      ...(isMcpAppsEnabled() ? { _meta: runViewerToolMeta() } : {}),
    },
    async (args, extra) => {
      const c = callerFromExtra(extra as { authInfo?: AuthInfo });
      if (!c.userId || !c.connectionId) return { content: [{ type: "text" as const, text: "not authenticated" }], isError: true };
      if (!c.scopes.includes("mcp:run")) {
        return { content: [{ type: "text" as const, text: "this connection is not authorized to run services (missing mcp:run scope)" }], structuredContent: { error: true, code: "scope", message: "missing mcp:run scope" }, isError: true };
      }
      const t0 = Date.now();
      const uHash = createHash("sha256").update(c.userId).digest("hex").slice(0, 8);
      let res: RunResultEnvelope;
      try {
        res = await runService({ userId: c.userId, connectionId: c.connectionId }, args);
      } catch (e) {
        const m = e instanceof Error ? e.message : String(e);
        console.log(`[run_service] user=${uHash} service=${args.serviceId} THREW ${m} ms=${Date.now() - t0}`);
        return { content: [{ type: "text" as const, text: `run_service failed: ${m}` }], structuredContent: { error: true, code: "internal", message: m }, isError: true };
      }
      const tail = res.ok ? (res.async ? `ok=true job=${res.jobId}` : `ok=true cost=${res.costUsd} providerStatus=${res.providerStatus}`) : `ok=false code=${res.code}`;
      console.log(`[run_service] user=${uHash} service=${args.serviceId} ${tail} ms=${Date.now() - t0}`);
      return toToolResult(res, clientDropsContent(server), isClientAppsCapable(server));
    },
  );

  server.registerTool(
    "get_result",
    {
      title: "Get an async job result",
      description:
        "Retrieve the RAW result of a slow/async run_service job (slow image, video) by its jobId — use this ONLY " +
        "if you need the output's data/URL yourself (e.g. to feed into another tool). On hosts with a live result " +
        "view, the user ALREADY sees the media render automatically, so you usually do NOT need to call this at all. " +
        "When you do call it: it blocks server-side until ready (up to ~45s) and returns the media; call it at most " +
        "ONCE and NEVER poll in a loop (repeated calls spawn duplicate result cards). Requires mcp:run.",
      inputSchema: { jobId: z.string().describe('The jobId returned by run_service (e.g. "job_…").') },
      // MCP Apps (P1-d): async media arrives here, so get_result also points at the ui:// run viewer.
      // Flag-gated — off by default → no `_meta`, byte-identical to today.
      ...(isMcpAppsEnabled() ? { _meta: runViewerToolMeta() } : {}),
    },
    async ({ jobId }, extra) => {
      const c = callerFromExtra(extra as { authInfo?: AuthInfo });
      if (!c.userId || !c.connectionId) return { content: [{ type: "text" as const, text: "not authenticated" }], isError: true };
      if (!c.scopes.includes("mcp:run")) {
        return { content: [{ type: "text" as const, text: "missing mcp:run scope" }], structuredContent: { error: true, code: "scope", message: "missing mcp:run scope" }, isError: true };
      }
      const t0 = Date.now();
      const uHash = createHash("sha256").update(c.userId).digest("hex").slice(0, 8);
      let res: RunResultEnvelope;
      try {
        res = await getJobResult({ userId: c.userId, connectionId: c.connectionId }, jobId);
      } catch (e) {
        const m = e instanceof Error ? e.message : String(e);
        console.log(`[get_result] user=${uHash} job=${jobId} THREW ${m} ms=${Date.now() - t0}`);
        return { content: [{ type: "text" as const, text: `get_result failed: ${m}` }], structuredContent: { error: true, code: "internal", message: m }, isError: true };
      }
      const tail = res.ok ? (res.async ? "pending" : "complete") : `error=${res.code}`;
      console.log(`[get_result] user=${uHash} job=${jobId} ${tail} ms=${Date.now() - t0}`);
      return toToolResult(res, clientDropsContent(server), isClientAppsCapable(server));
    },
  );

  server.registerTool(
    "get_email_inbox",
    {
      title: "Get your managed email inbox",
      description:
        "Return THIS user's managed email inbox address (e.g. name@agentmail.to), creating it ONCE if they don't have one yet. " +
        "Reused across sessions — call this before sending email and pass the returned address as the inbox to send FROM. " +
        "Do NOT create inboxes yourself (that would recreate a $2 inbox every time). Creating the first inbox costs $2 (one-time, " +
        "charged to the user); returning an existing one is free. Requires mcp:run.",
      inputSchema: {},
    },
    async (_args, extra) => {
      const c = callerFromExtra(extra as { authInfo?: AuthInfo });
      if (!c.userId || !c.connectionId) return { content: [{ type: "text" as const, text: "not authenticated" }], isError: true };
      if (!c.scopes.includes("mcp:run")) {
        return { content: [{ type: "text" as const, text: "missing mcp:run scope" }], structuredContent: { error: true, code: "scope", message: "missing mcp:run scope" }, isError: true };
      }
      const r = await getOrCreateUserInbox(c.userId, c.connectionId);
      if (!r.ok) {
        return { content: [{ type: "text" as const, text: r.message }], structuredContent: { error: true, code: r.code, message: r.message }, isError: true };
      }
      const summary = `Your email inbox is ${r.value}${r.created ? " (just created)" : ""}. Send from it with run_service → an email service's send (inbox_id = this address).`;
      return { content: [{ type: "text" as const, text: summary }], structuredContent: { address: r.value, inboxId: r.value, created: r.created } };
    },
  );
}
