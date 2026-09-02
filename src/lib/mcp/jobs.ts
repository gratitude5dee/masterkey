// Masterkey — async job store + polling (server-only). Some providers (slow image, video) charge on
// submit and return a job to poll. We persist the job and a `get_result` tool retrieves the media when
// ready. Polling handles three provider patterns: free GET, x402-paid poll (via payProvider), and a
// SIWX-gated free poll (via Sponge's /api/siwe/generate + a Sign-In-With-X header). See MCP_SPEC.md M7.

import { randomUUID } from "crypto";
import { signSiwxFromChallenge } from "@/lib/siwx";
import { getDb } from "@/lib/db";
import { payProvider, headerMap, type PayResult } from "@/lib/wallet";
import { COLLECTIONS, type JobDoc, type JobStatus } from "@/lib/mcp/types";
import type { AsyncSpec } from "@/data/types";
import type { BucketKey } from "@/lib/spend-buckets";
// Pure detection/classification core (no wallet/db/network) — split out so it's unit-testable in isolation.
import { classifyJobBody, resolvePollBody, resolvePollHeaders } from "@/lib/mcp/async-detect";
// Re-export the pure public fns so existing importers (run.ts) keep their `from "@/lib/mcp/jobs"` import.
export { detectAsyncJob, bodyHasPendingStatus, classifyJobBody } from "@/lib/mcp/async-detect";

const POLL_MAX_USD = 0.5; // hard ceiling on a single poll's cost (polls are usually free or near-zero)

// ---- storage --------------------------------------------------------------------------------

export async function createJob(input: {
  userId: string;
  connectionId?: string;
  tokenJti?: string;
  serviceId: string;
  serviceName: string;
  provider: string;
  backendUrl: string;
  pollUrl: string;
  providerJobId?: string;
  modalityOut: string[];
  bucket: BucketKey | "all";
  costUsd: number;
  priceUsd?: number;
  network: string;
  txHash?: string;
  payTo?: string; // provider's x402 recipient — reused to bind paid polls to the same provider
  runId?: string;
  async?: AsyncSpec;
}): Promise<JobDoc> {
  const db = await getDb();
  const now = new Date();
  const doc: JobDoc = {
    _id: `job_${randomUUID().replace(/-/g, "")}`,
    ...input,
    status: "pending",
    pollCount: 0,
    createdAt: now,
    updatedAt: now,
  };
  await db.collection<JobDoc>(COLLECTIONS.jobs).insertOne(doc);
  return doc;
}

export async function getJob(jobId: string, userId: string): Promise<JobDoc | null> {
  const db = await getDb();
  return db.collection<JobDoc>(COLLECTIONS.jobs).findOne({ _id: jobId, userId });
}

async function updateJob(jobId: string, set: Partial<JobDoc>): Promise<void> {
  const db = await getDb();
  await db.collection<JobDoc>(COLLECTIONS.jobs).updateOne({ _id: jobId }, { $set: { ...set, updatedAt: new Date() } });
}

// ---- polling --------------------------------------------------------------------------------

/**
 * SIWX-gated free poll: GET the challenge, sign it via the shared SIWX core (`src/lib/siwx.ts`), and
 * retry the poll with the `Sign-In-With-X` header. The core builds the structured base64 payload the
 * merit/`stable*` family expects (NOT the raw `base64SiweMessage`, which servers reject as
 * `siwx_malformed` — the bug this refactor fixes) and lifts the full `info` (domain/uri/nonce/chainId/…)
 * from the challenge. The nonce is single-use, so we present the signature exactly once on the retry.
 */
// A poll's HTTP shape. Most providers poll with GET; some (2Captcha) require POST with a body whose values
// are templated with {id} (the provider job id). method/body/headers come from the registry AsyncSpec.poll.
type PollHttp = { method: "GET" | "POST"; body?: unknown; headers?: Record<string, string> };
function parseBody(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function siweFetch(pollUrl: string, http: PollHttp = { method: "GET" }): Promise<PayResult | undefined> {
  try {
    const jsonHdr = http.body !== undefined ? { "content-type": "application/json" } : undefined;
    const reqInit = (extra?: Record<string, string>): RequestInit => ({
      method: http.method,
      ...(jsonHdr || extra || http.headers ? { headers: { ...jsonHdr, ...http.headers, ...extra } } : {}),
      ...(http.body !== undefined ? { body: JSON.stringify(http.body) } : {}),
    });
    const challengeRes = await fetch(pollUrl, reqInit());
    const challenge = parseBody(await challengeRes.text());

    const auth = await signSiwxFromChallenge({ status: challengeRes.status, body: challenge, headers: challengeRes.headers });
    if (!auth) return undefined; // not a SIWX challenge, or signing unavailable/failed

    const res = await fetch(pollUrl, reqInit(auth.headers));
    const body = parseBody(await res.text());
    return { ok: res.ok, status: res.status, body, costUsd: 0, paid: false, confirmed: false, network: "", contentType: res.headers.get("content-type"), headers: headerMap(res.headers) };
  } catch {
    return undefined;
  }
}

/** Free unauthenticated poll (no payment ever). PayResult-shaped with costUsd 0. */
async function plainGet(pollUrl: string, http: PollHttp = { method: "GET" }): Promise<PayResult | undefined> {
  try {
    const jsonHdr = http.body !== undefined ? { "content-type": "application/json" } : undefined;
    const res = await fetch(pollUrl, {
      method: http.method,
      ...(jsonHdr || http.headers ? { headers: { ...jsonHdr, ...http.headers } } : {}),
      ...(http.body !== undefined ? { body: JSON.stringify(http.body) } : {}),
    });
    const body = parseBody(await res.text());
    return { ok: res.ok, status: res.status, body, costUsd: 0, paid: false, confirmed: false, network: "", contentType: res.headers.get("content-type"), headers: headerMap(res.headers) };
  } catch {
    return undefined;
  }
}

/** Run ONE HTTP poll at the given cost model (shared by pollJobOnce and the separate-result fetch, AXIS 7).
 *  free→plainGet, siwx→siweFetch, per-poll/undefined→paid (bounded by `ceiling`). Never throws. */
type PollCost = "free" | "siwx" | "per-poll" | undefined;
async function runHttpPoll(
  cost: PollCost,
  url: string,
  http: PollHttp,
  ceiling: number,
  payerUserId: string,
  expectedPayTo?: string,
): Promise<PayResult | undefined> {
  if (cost === "free") return plainGet(url, http);
  if (cost === "siwx") return siweFetch(url, http);
  // per-poll OR uncurated (undefined): try paid; uncurated falls back to a SIWX attempt.
  let pay: PayResult | undefined;
  try {
    pay = await payProvider({ url, method: http.method, headers: http.headers, body: http.body, maxValueUsd: ceiling, expectedPayTo, payerUserId });
  } catch {
    pay = undefined;
  }
  if (cost == null && (!pay || (!pay.ok && !pay.paid))) {
    const siwx = await siweFetch(url, http);
    if (siwx) pay = siwx;
  }
  return pay;
}

export type PollOutcome = { state: JobStatus; body?: unknown; costUsd: number; network?: string; txHash?: string; claimSkipped?: boolean; httpStatus?: number; headers?: Record<string, string> };

/** The per-poll ceiling for a job: the endpoint's known price (+margin) or the $0.50 env backstop. */
function pollCeiling(priceUsd?: number): number {
  return Math.max(POLL_MAX_USD, (priceUsd ?? 0) * 1.25);
}

/**
 * AXIS 7 — when complete, fetch the result from a SEPARATE endpoint (async.poll.resultUrlTemplate), e.g.
 * Allium's paid `/query-runs/{id}/results`. Returns a PayResult (with any cost) or undefined. The caller
 * (getJobResult) books the cost + maps the body. resultCost defaults to "free"; the paid case is bounded by
 * the same per-job cost cap as a poll. Never throws.
 */
export async function fetchSeparateResult(job: JobDoc): Promise<PayResult | undefined> {
  const a = job.async;
  const tmpl = a?.poll?.resultUrlTemplate;
  if (!tmpl) return undefined;
  let origin = "";
  try {
    origin = new URL(job.backendUrl).origin;
  } catch {
    /* ignore */
  }
  const url = tmpl.replace(/\{origin\}/g, origin).replace(/\{id\}/g, encodeURIComponent(job.providerJobId ?? ""));
  const resolved = url.startsWith("http") ? url : origin + (url.startsWith("/") ? "" : "/") + url;
  const http: PollHttp = {
    method: a?.poll?.resultMethod === "POST" ? "POST" : "GET",
    body: resolvePollBody(a?.poll?.resultBody, job.providerJobId),
    headers: resolvePollHeaders(a?.poll?.resultHeaders, job.providerJobId),
  };
  const cost: PollCost = a?.poll?.resultCost ?? "free"; // result fetch is FREE unless the registry says otherwise
  return runHttpPoll(cost, resolved, http, pollCeiling(job.priceUsd), job.userId, job.payTo);
}

/**
 * Poll a job once. RUN_RELIABILITY_SPEC 4.1: the poll-payment decision is REGISTRY-DRIVEN — `async.poll.cost`
 * picks the path so a free/SIWX-poll provider is NEVER accidentally charged:
 *   • "free"     → plain GET (no payment)
 *   • "siwx"     → SIWX-signed free GET
 *   • "per-poll" → paid poll via payProvider (bounded by the per-poll ceiling)
 *   • undefined  → legacy heuristic (try paid, then SIWX) for not-yet-curated backends
 * Never throws.
 */
export async function pollJobOnce(job: JobDoc): Promise<PollOutcome> {
  // RUN_RELIABILITY_SPEC 4.3 — claim THIS poll slot atomically BEFORE paying: only the caller that flips
  // pollCount N→N+1 proceeds. A crash-replay or concurrent worker re-entering at the same index loses the
  // race and skips (no second payment for the same poll). At-most-once per poll index; a payment made then
  // lost to a crash before booking is an under-count (refundable), never a double-charge.
  const db = await getDb();
  const claimed = await db
    .collection<JobDoc>(COLLECTIONS.jobs)
    .findOneAndUpdate({ _id: job._id, pollCount: job.pollCount }, { $inc: { pollCount: 1 }, $set: { updatedAt: new Date() } });
  if (!claimed) return { state: "pending", costUsd: 0, claimSkipped: true }; // another worker/replay owns this poll index
  job.pollCount += 1; // reflect the claim in-memory

  const pollCost = job.async?.poll?.cost as PollCost;
  // Poll HTTP shape (registry-driven): default GET; some providers (2Captcha) require POST with a body and/or
  // headers whose {id} is the provider job id (which may live in the BODY/HEADER, not the URL).
  const http: PollHttp = {
    method: job.async?.poll?.method === "POST" ? "POST" : "GET",
    body: resolvePollBody(job.async?.poll?.body, job.providerJobId),
    headers: resolvePollHeaders(job.async?.poll?.headers, job.providerJobId),
  };
  // Per-poll providers like BlockRun authorize the FULL job price on EVERY poll but SETTLE ONCE at completion
  // (verified on-chain 2026-06-23 — in_progress polls move $0; only the completed poll carries an
  // X-Payment-Response receipt → the receipt-only settlement gate books the charge exactly once). The ceiling is
  // sized from job.priceUsd (the registry price at submit — endpoint data, NOT a spend policy); the user's spend
  // limits (checked at reserve time) are the real money guardrail, with POLL_MAX_USD as the env backstop.
  const pay = await runHttpPoll(pollCost, job.pollUrl, http, pollCeiling(job.priceUsd), job.userId, job.payTo);

  if (!pay) return { state: "pending", costUsd: 0 }; // pollCount already advanced by the claim

  // AXIS 6: pass the poll's HTTP status so a `statusFromHttp` provider (no body status field) classifies right.
  const state = classifyJobBody(pay.body, job.async, pay.status);
  return { state, body: pay.body, costUsd: pay.costUsd, network: pay.network, txHash: pay.txHash, httpStatus: pay.status, headers: pay.headers };
}

export async function markJobComplete(jobId: string, result: unknown): Promise<void> {
  await updateJob(jobId, { status: "complete", result });
}
export async function markJobFailed(jobId: string, error: string): Promise<void> {
  await updateJob(jobId, { status: "failed", error });
}
export async function addJobCost(jobId: string, delta: number): Promise<void> {
  if (!delta) return;
  const db = await getDb();
  await db.collection<JobDoc>(COLLECTIONS.jobs).updateOne({ _id: jobId }, { $inc: { costUsd: delta }, $set: { updatedAt: new Date() } });
}
