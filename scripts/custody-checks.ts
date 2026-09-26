/**
 * Custody's newer checks, kept apart from custody.ts's walk over the run
 * (Fable and Codex, 2026-09-26, after reading the custody verdicts of the
 * recorded runs):
 *
 * - every check says what it is: passed, failed, incomplete, not applicable
 *   or unavailable, with why and how much it covered, so an omitted or failed
 *   check can never read as a quiet pass;
 * - the operator's own audit (runs/operator-audit.jsonl) is chained and each
 *   operator line on the trace is matched to it;
 * - the acquisition hashes the operator gave at kickoff are compared with
 *   the evidence as custody re-hashed it;
 * - the verdict can be signed (ssh-keygen -Y, namespace dfirswarm-custody)
 *   and timestamped by an RFC 3161 authority, and a reference clock's offset
 *   can be recorded;
 * - a re-check names the lines written after the verdict's seal (the hub's
 *   custody and clear-up lines and the operator's stop) rather than reading
 *   them as tampering.
 *
 * Nothing here knows a tool or a format of evidence.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";

export type CheckStatus = "passed" | "failed" | "incomplete" | "not_applicable" | "unavailable";
export type Check = { name: string; status: CheckStatus; reason?: string; expected?: number; checked?: number };

const sha256 = (text: string | Buffer) => createHash("sha256").update(text).digest("hex");

// --- the operator's audit ------------------------------------------------------------

export type OperatorAudit = {
  path: string;
  /** Lines in the audit, and whether each names the sha256 of the one before. */
  lines: number;
  intact: boolean;
  detail: string;
  /** Operator lines on the run's trace, and how many the audit carries too. */
  trace_actions: number;
  matched: number;
  /** Trace operator lines with no audit line of the same command and arguments within two minutes. */
  unmatched: Array<{ at: string; command: string; argv: string[] }>;
} | null;

export type TraceAction = { at: string; command: string; argv: string[] };

/**
 * The operator's audit beside the registry: its chain (each line's `prev` the
 * sha256 of the line before, the first null), and each operator line the
 * trace carries matched to an audit line of the same command and arguments,
 * within two minutes. Null when the run has no audit beside it.
 */
export function verifyOperatorAudit(path: string, actions: TraceAction[]): OperatorAudit {
  if (!existsSync(path)) return null;
  let text = "";
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    return { path, lines: 0, intact: false, detail: `unreadable (${(err as NodeJS.ErrnoException).code ?? "error"})`, trace_actions: actions.length, matched: 0, unmatched: actions };
  }
  const lines = text.split("\n").filter((l) => l.length);
  let prev: string | null = null;
  let broken: string | null = null;
  const parsed: Array<{ at: number; command: string; argv: string }> = [];
  lines.forEach((l, i) => {
    let o: { prev?: string | null; at?: string; command?: string; argv?: unknown };
    try {
      o = JSON.parse(l);
    } catch {
      broken ??= `line ${i + 1} is not JSON`;
      return;
    }
    if (!broken && (o.prev ?? null) !== prev) broken = `line ${i + 1}'s prev does not name the line before it`;
    prev = sha256(l);
    parsed.push({ at: Date.parse(String(o.at ?? "")), command: String(o.command ?? ""), argv: JSON.stringify(Array.isArray(o.argv) ? o.argv : []) });
  });
  const unmatched: TraceAction[] = [];
  let matched = 0;
  for (const a of actions) {
    const t = Date.parse(a.at);
    const argv = JSON.stringify(a.argv);
    const hit = parsed.some((p) => p.command === a.command && p.argv === argv && Number.isFinite(t) && Math.abs(p.at - t) <= 120_000);
    if (hit) matched += 1;
    else unmatched.push(a);
  }
  return {
    path,
    lines: lines.length,
    intact: broken === null,
    detail: broken === null ? `${lines.length} lines, chain intact` : `chain broken: ${broken}`,
    trace_actions: actions.length,
    matched,
    unmatched,
  };
}

// --- acquisition hashes ------------------------------------------------------------------

export type AcquisitionEntry = { path: string; algo: "md5" | "sha1" | "sha256"; digest: string };
export type Acquisition = {
  /** The hashes file the operator gave, by name and sha256, as the kickoff recorded it. */
  source: string | null;
  source_sha256: string | null;
  given: number;
  matched: number;
  mismatched: string[];
  /** Given, but custody could not compare it (the file was not re-read, or the digest was not computed). */
  not_compared: string[];
} | null;

const ALGO_BY_LENGTH: Record<number, AcquisitionEntry["algo"]> = { 32: "md5", 40: "sha1", 64: "sha256" };

/**
 * The lines of an imager's hash list, as `<digest> <name>` (md5sum,
 * sha1sum, sha256sum and most imagers' logs), `<name> <digest>`, or
 * `ALGO (name) = digest` (BSD). The algorithm is the digest's length. Names
 * are matched to the inputs by their path under inputs/ or by basename when
 * it is unique. Lines that are none of these are ignored and counted.
 */
export function parseAcquisitionHashes(text: string, inputs: string[]): { entries: AcquisitionEntry[]; unmatched: string[]; ignored: number } {
  const entries: AcquisitionEntry[] = [];
  const unmatched: string[] = [];
  let ignored = 0;
  const byBase = new Map<string, string[]>();
  for (const p of inputs) {
    const b = p.slice(p.lastIndexOf("/") + 1);
    byBase.set(b, [...(byBase.get(b) ?? []), p]);
  }
  const find = (name: string): string | null => {
    const n = name.replace(/^\*/, "").replace(/^\.\//, "").trim();
    const want = n.startsWith("inputs/") ? n : `inputs/${n}`;
    if (inputs.includes(want)) return want;
    const b = n.slice(n.lastIndexOf("/") + 1);
    const hits = byBase.get(b) ?? [];
    return hits.length === 1 ? hits[0] : null;
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    let digest = "";
    let name = "";
    const bsd = /^(MD5|SHA1|SHA256|SHA-1|SHA-256)\s*\((.+)\)\s*=\s*([0-9a-fA-F]+)$/.exec(line);
    const first = /^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\s+(.+)$/.exec(line);
    const last = /^(.+?)\s+([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.exec(line);
    if (bsd) [digest, name] = [bsd[3], bsd[2]];
    else if (first) [digest, name] = [first[1], first[2]];
    else if (last) [digest, name] = [last[2], last[1]];
    else {
      ignored += 1;
      continue;
    }
    const algo = ALGO_BY_LENGTH[digest.length];
    if (!algo) {
      ignored += 1;
      continue;
    }
    const path = find(name);
    if (!path) unmatched.push(name);
    else entries.push({ path, algo, digest: digest.toLowerCase() });
  }
  return { entries, unmatched, ignored };
}

/** Each acquisition digest against the digest custody computed for that file now. */
export function compareAcquisition(
  given: { source?: string; source_sha256?: string; entries?: AcquisitionEntry[] } | undefined,
  actual: Map<string, { sha256?: string; md5?: string; sha1?: string }>,
): Acquisition {
  if (!given?.entries?.length) return null;
  let matched = 0;
  const mismatched: string[] = [];
  const notCompared: string[] = [];
  for (const e of given.entries) {
    const now = actual.get(e.path)?.[e.algo];
    if (!now) notCompared.push(`${e.path} (${e.algo})`);
    else if (now.toLowerCase() === e.digest.toLowerCase()) matched += 1;
    else mismatched.push(`${e.path} (${e.algo})`);
  }
  return { source: given.source ?? null, source_sha256: given.source_sha256 ?? null, given: given.entries.length, matched, mismatched, not_compared: notCompared };
}

// --- each check, said -----------------------------------------------------------------

type CustodyLike = {
  inputs: unknown;
  sessions: { files: Array<{ sha256: string | null }>; not_files: string[] };
  tool_outputs: { referenced: number; verified: number; missing: string[]; mismatched: string[]; refused: string[] };
  trace: { lines: number; intact: boolean; detail: string };
  ledger: { entries: number; intact: boolean; detail: string } | null;
  attestations?: { lines: number; intact: boolean; detail: string } | null;
  model_gateway: { intact: boolean; detail: string; refused?: string } | null;
  vms: Array<{ snapshot: unknown; stopped: boolean; kept: string | null }> | null;
  artifacts: { files: number; skipped: number } | null;
  store: { journal: { intact: boolean; detail: string; anchor: string }; outputs: { files: number; verified: number; mismatched: string[]; missing: string[] }; manifests_missing: string[]; logs?: { checked: number; mismatched: string[] }; catalogue?: { revisions_mismatched: string[]; generations_mismatched: string[] } | null; ledger_unreadable?: string | null; images?: { undeclared: string[]; digests: Record<string, string[]> } } | null;
  operator?: OperatorAudit;
  acquisition?: Acquisition;
  not_reached: string[];
  incomplete: string | null;
};

/**
 * Every part of the verdict as one status: what an examiner reads first, and
 * what a verifier compares. A part that was not reached is incomplete; one
 * that raised is unavailable, with why; one the run did not have is not
 * applicable. Never an empty result that reads as nothing wrong.
 */
export function checksOf(c: CustodyLike, errors: Record<string, string> = {}): Check[] {
  const out: Check[] = [];
  const reached = (part: string) => !c.not_reached.includes(part);
  const add = (name: string, status: CheckStatus, reason?: string, counts: { expected?: number; checked?: number } = {}) => out.push({ name, status, ...(reason ? { reason } : {}), ...counts });
  // The evidence.
  const inputs = c.inputs as null | { unverifiable: string } | { files: number; unchanged: boolean; complete: boolean; changed: string[]; missing: string[]; added: string[]; skipped: string[]; unreadable: string[]; checked?: { files: number } };
  if (!reached("the evidence")) add("evidence", "incomplete", "not reached before custody ended");
  else if (inputs === null) add("evidence", "not_applicable", "the run was given no evidence");
  else if ("unverifiable" in inputs) add("evidence", "failed", inputs.unverifiable);
  else if (inputs.changed.length || inputs.missing.length || inputs.added.length) add("evidence", "failed", `${inputs.changed.length} changed, ${inputs.missing.length} missing, ${inputs.added.length} added`, { expected: inputs.files, checked: inputs.checked?.files });
  else if (!inputs.complete) add("evidence", "incomplete", `${inputs.skipped.length} not re-read, ${inputs.unreadable.length} unreadable`, { expected: inputs.files, checked: inputs.checked?.files });
  else if (!inputs.unchanged) add("evidence", "failed", "the manifest does not match its anchor", { expected: inputs.files });
  else add("evidence", "passed", undefined, { expected: inputs.files, checked: inputs.checked?.files ?? inputs.files });
  // The acquisition hashes, when the operator gave them.
  if (c.acquisition === undefined || c.acquisition === null) add("acquisition hashes", "not_applicable", "none were given at kickoff (--inputs-hashes)");
  else if (c.acquisition.mismatched.length) add("acquisition hashes", "failed", `do not match: ${c.acquisition.mismatched.join(", ")}`, { expected: c.acquisition.given, checked: c.acquisition.matched + c.acquisition.mismatched.length });
  else if (c.acquisition.not_compared.length) add("acquisition hashes", "incomplete", `not compared: ${c.acquisition.not_compared.join(", ")}`, { expected: c.acquisition.given, checked: c.acquisition.matched });
  else add("acquisition hashes", "passed", undefined, { expected: c.acquisition.given, checked: c.acquisition.matched });
  // The sessions.
  if (!reached("the sessions")) add("sessions", "incomplete", "not reached");
  else {
    const unhashed = c.sessions.files.filter((f) => !f.sha256).length;
    if (c.sessions.not_files.length) add("sessions", "failed", `${c.sessions.not_files.length} not a regular file`, { expected: c.sessions.files.length });
    else if (unhashed) add("sessions", "incomplete", `${unhashed} not hashed before the deadline`, { expected: c.sessions.files.length, checked: c.sessions.files.length - unhashed });
    else add("sessions", c.sessions.files.length ? "passed" : "not_applicable", c.sessions.files.length ? undefined : "no session files", { expected: c.sessions.files.length, checked: c.sessions.files.length });
  }
  // The kept outputs.
  if (!reached("the kept outputs")) add("kept outputs", "incomplete", "not reached");
  else {
    const o = c.tool_outputs;
    if (o.missing.length || o.mismatched.length) add("kept outputs", "failed", `${o.missing.length} missing, ${o.mismatched.length} not matching the trace`, { expected: o.referenced, checked: o.verified });
    else if (o.refused.length) add("kept outputs", "incomplete", `${o.refused.length} refused or not reached`, { expected: o.referenced, checked: o.verified });
    else add("kept outputs", o.referenced ? "passed" : "not_applicable", o.referenced ? undefined : "no kept output was referenced on the trace (tool work may still have run as jobs)", { expected: o.referenced, checked: o.verified });
  }
  // The trace.
  if (!reached("the trace")) add("trace", "incomplete", "not reached");
  else if (!c.trace.lines) add("trace", c.trace.detail.startsWith("chain broken") ? "failed" : "unavailable", c.trace.detail);
  else add("trace", c.trace.intact ? "passed" : "failed", c.trace.intact ? undefined : c.trace.detail, { checked: c.trace.lines });
  // The ledger and its attestations.
  if (!reached("the ledger")) add("ledger", "incomplete", "not reached");
  else if (!c.ledger) add("ledger", "not_applicable", "no ledger entries");
  else add("ledger", c.ledger.intact ? "passed" : "failed", c.ledger.intact ? undefined : c.ledger.detail, { checked: c.ledger.entries });
  if (c.attestations) add("ledger attestations", c.attestations.intact ? "passed" : "failed", c.attestations.intact ? undefined : c.attestations.detail, { checked: c.attestations.lines });
  // The model gateway log.
  if (c.model_gateway) add("model gateway log", c.model_gateway.refused ? "unavailable" : c.model_gateway.intact ? "passed" : "failed", c.model_gateway.intact ? undefined : c.model_gateway.detail);
  else add("model gateway log", "not_applicable", "the run's model calls did not go through the host's gateway");
  // The VMs.
  if (!reached("the VMs")) add("VMs", "incomplete", "not reached");
  else if (!c.vms) add("VMs", "not_applicable", "a host run");
  else {
    const snap = (v: { snapshot: unknown }) => v.snapshot as { verified?: boolean; msb_verified?: boolean | null; error?: string } | null;
    const bad = c.vms.filter((v) => snap(v) && (snap(v)?.error || snap(v)?.verified === false || snap(v)?.msb_verified === false));
    const away = c.vms.filter((v) => !v.stopped || v.kept);
    add("VMs", bad.length || away.length ? "failed" : "passed", bad.length || away.length ? `${bad.length} snapshot(s) not verified, ${away.length} not put away` : undefined, { expected: c.vms.length, checked: c.vms.length - bad.length });
  }
  // The work files.
  if (!reached("the artifact index")) add("work files", "incomplete", "not reached");
  else if (errors.artifacts) add("work files", "unavailable", errors.artifacts);
  else if (!c.artifacts) add("work files", "not_applicable", "no work/ directory");
  else add("work files", c.artifacts.skipped ? "incomplete" : "passed", c.artifacts.skipped ? `${c.artifacts.skipped} not hashed (named in artifacts.json)` : undefined, { checked: c.artifacts.files });
  // The store.
  if (!reached("the store")) add("store", "incomplete", "not reached");
  else if (errors.store) add("store", "unavailable", errors.store);
  else if (!c.store) add("store", "not_applicable", "the run had no job service");
  else {
    const s = c.store;
    const problems = [
      ...(s.journal.intact ? [] : [`journal: ${s.journal.detail}`]),
      ...(s.journal.anchor === "off" || s.journal.anchor === "missing" ? [`journal anchor ${s.journal.anchor}`] : []),
      ...(s.outputs.mismatched.length ? [`${s.outputs.mismatched.length} output(s) changed`] : []),
      ...(s.outputs.missing.length ? [`${s.outputs.missing.length} output(s) missing`] : []),
      ...(s.manifests_missing.length ? [`${s.manifests_missing.length} manifest(s) missing`] : []),
      ...(s.logs?.mismatched.length ? [`${s.logs.mismatched.length} job log(s) changed since sealed`] : []),
      ...(s.catalogue && (s.catalogue.revisions_mismatched.length || s.catalogue.generations_mismatched.length) ? ["catalogue records differ from the journal"] : []),
      ...(s.ledger_unreadable ? [`the ledger could not be read for the findings count: ${s.ledger_unreadable}`] : []),
      ...(s.images?.undeclared.length ? [`${s.images.undeclared.length} job(s) in an image the run did not declare`] : []),
      ...(s.images && Object.values(s.images.digests).some((d) => d.length > 1) ? ["an image name booted more than one digest"] : []),
    ];
    const short = s.outputs.verified + s.outputs.mismatched.length + s.outputs.missing.length < s.outputs.files;
    add("store", problems.length ? "failed" : short ? "incomplete" : "passed", problems.length ? problems.join("; ") : short ? "not every output was re-hashed before the deadline" : undefined, { expected: s.outputs.files, checked: s.outputs.verified });
  }
  // The operator's audit.
  if (c.operator === undefined || c.operator === null) add("operator audit", "not_applicable", "no runs/operator-audit.jsonl beside the run");
  else if (!c.operator.intact) add("operator audit", "failed", c.operator.detail);
  else if (c.operator.unmatched.length) add("operator audit", "failed", `${c.operator.unmatched.length} operator line(s) on the trace are not on the audit`, { expected: c.operator.trace_actions, checked: c.operator.matched });
  else add("operator audit", "passed", undefined, { expected: c.operator.trace_actions, checked: c.operator.matched });
  if (c.incomplete) add("custody", "incomplete", c.incomplete);
  return out;
}

/** The words of a list of checks: the ones that did not pass, or that all did. */
export function checksLine(checks: Check[]): string {
  const counts = new Map<CheckStatus, number>();
  for (const c of checks) counts.set(c.status, (counts.get(c.status) ?? 0) + 1);
  const bad = checks.filter((c) => c.status === "failed" || c.status === "incomplete" || c.status === "unavailable");
  const head = `checks: ${counts.get("passed") ?? 0} passed, ${counts.get("failed") ?? 0} failed, ${counts.get("incomplete") ?? 0} incomplete, ${counts.get("unavailable") ?? 0} unavailable, ${counts.get("not_applicable") ?? 0} not applicable`;
  return bad.length ? `${head} (${bad.map((c) => `${c.name} ${c.status.toUpperCase()}${c.reason ? `: ${c.reason}` : ""}`).join("; ")})` : head;
}

// --- signature, trusted time, a reference clock ----------------------------------------

function run(cmd: string, args: string[], input?: Buffer): Promise<{ code: number; out: string; err: string }> {
  return new Promise((done) => {
    const child = execFile(cmd, args, { maxBuffer: 16 * 1024 * 1024 }, (error, stdout, stderr) => {
      done({ code: error ? (typeof (error as NodeJS.ErrnoException & { code?: unknown }).code === "number" ? Number((error as { code?: number }).code) : 1) : 0, out: String(stdout), err: String(stderr) });
    });
    if (input) child.stdin?.end(input);
    else child.stdin?.end();
  });
}

export const SIGN_NAMESPACE = "dfirswarm-custody";

/** Sign a file with an SSH key (ssh-keygen -Y sign): `<file>.sig` beside it. */
export async function signFile(file: string, key: string): Promise<{ ok: true; signature: string; sha256: string; fingerprint: string | null } | { ok: false; why: string }> {
  if (!existsSync(key)) return { ok: false, why: `no key at ${key}` };
  const r = await run("ssh-keygen", ["-Y", "sign", "-f", key, "-n", SIGN_NAMESPACE, file]);
  if (r.code !== 0 || !existsSync(`${file}.sig`)) return { ok: false, why: `ssh-keygen -Y sign failed: ${r.err.trim() || `exit ${r.code}`}` };
  const fp = await run("ssh-keygen", ["-l", "-f", key]);
  return { ok: true, signature: `${file}.sig`, sha256: sha256(readFileSync(`${file}.sig`)), fingerprint: fp.code === 0 ? (fp.out.trim().split(/\s+/)[1] ?? null) : null };
}

/**
 * A signature checked: against an allowed-signers file when one is given
 * (who may sign), otherwise only that it is a valid signature of the file by
 * the key it carries (ssh-keygen -Y check-novalidate).
 */
export async function verifySignature(file: string, sig: string, allowedSigners?: string, identity?: string): Promise<{ ok: boolean; how: string; detail: string }> {
  if (!existsSync(sig)) return { ok: false, how: "none", detail: `no signature at ${sig}` };
  const data = readFileSync(file);
  if (allowedSigners) {
    const r = await run("ssh-keygen", ["-Y", "verify", "-f", allowedSigners, "-I", identity ?? "*", "-n", SIGN_NAMESPACE, "-s", sig], data);
    return { ok: r.code === 0, how: "allowed signers", detail: (r.out + r.err).trim() };
  }
  const r = await run("ssh-keygen", ["-Y", "check-novalidate", "-n", SIGN_NAMESPACE, "-s", sig], data);
  return { ok: r.code === 0, how: "valid signature, signer not checked (no allowed-signers file)", detail: (r.out + r.err).trim() };
}

// DER, the few shapes a TimeStampReq needs.
function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const der = (tag: number, body: Buffer) => Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
const SHA256_OID = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);

/** An RFC 3161 TimeStampReq over a sha256 digest, asking for the authority's certificate. */
export function timestampRequest(digestHex: string, nonce = Buffer.from(createHash("sha256").update(`${digestHex}${Date.now()}`).digest().subarray(0, 8))): Buffer {
  const algo = der(0x30, Buffer.concat([SHA256_OID, Buffer.from([0x05, 0x00])]));
  const imprint = der(0x30, Buffer.concat([algo, der(0x04, Buffer.from(digestHex, "hex"))]));
  const n = nonce[0] & 0x80 ? Buffer.concat([Buffer.from([0]), nonce]) : nonce;
  return der(0x30, Buffer.concat([der(0x02, Buffer.from([1])), imprint, der(0x02, n), Buffer.from([0x01, 0x01, 0xff])]));
}

/**
 * What a timestamp response says, read without a CMS library: the status
 * (granted is 0 or 1), whether it carries the digest it was asked for, and
 * the authority's time (the first GeneralizedTime in the token). Its
 * signature is not checked here: `openssl ts -verify` with the authority's
 * certificate does that, and the verify command says so.
 */
export function readTimestampResponse(resp: Buffer, digestHex: string): { granted: boolean; status: number | null; imprint: boolean; gen_time: string | null } {
  // TimeStampResp ::= SEQUENCE { status PKIStatusInfo (SEQUENCE { status INTEGER ... }), token ... }
  let status: number | null = null;
  const i = resp.indexOf(Buffer.from([0x02, 0x01]));
  if (i >= 0 && i < 16) status = resp[i + 2];
  const imprint = resp.includes(Buffer.from(digestHex, "hex"));
  let gen: string | null = null;
  for (let k = 0; k < resp.length - 2; k += 1) {
    if (resp[k] !== 0x18) continue;
    const len = resp[k + 1];
    if (len < 13 || len > 24 || k + 2 + len > resp.length) continue;
    const text = resp.subarray(k + 2, k + 2 + len).toString("latin1");
    if (/^\d{14}(\.\d+)?Z$/.test(text)) {
      gen = `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}T${text.slice(8, 10)}:${text.slice(10, 12)}:${text.slice(12)}`;
      break;
    }
  }
  return { granted: status === 0 || status === 1, status, imprint, gen_time: gen };
}

function post(url: string, body: Buffer, headers: Record<string, string>, timeoutMs = 20_000): Promise<{ status: number; body: Buffer; headers: Record<string, string | string[] | undefined> }> {
  return new Promise((done, fail) => {
    const u = new URL(url);
    const req = (u.protocol === "http:" ? httpRequest : httpsRequest)(u, { method: body.length ? "POST" : "HEAD", headers: { ...headers, "content-length": String(body.length) }, timeout: timeoutMs }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => done({ status: res.statusCode ?? 0, body: Buffer.concat(chunks), headers: res.headers }));
    });
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", fail);
    req.end(body);
  });
}

/** Ask an RFC 3161 authority to timestamp a file's sha256; the response is kept as `<file>.tsr`. */
export async function timestampFile(file: string, url: string): Promise<{ ok: true; tsr: string; gen_time: string | null; sha256: string } | { ok: false; why: string }> {
  const digest = sha256(readFileSync(file));
  try {
    const res = await post(url, timestampRequest(digest), { "content-type": "application/timestamp-query", accept: "application/timestamp-reply" });
    if (res.status !== 200) return { ok: false, why: `the authority answered HTTP ${res.status}` };
    const read = readTimestampResponse(res.body, digest);
    if (!read.granted) return { ok: false, why: `the authority did not grant it (status ${read.status ?? "unknown"})` };
    if (!read.imprint) return { ok: false, why: "the token does not carry this file's sha256" };
    writeFileSync(`${file}.tsr`, res.body, { mode: 0o444 });
    return { ok: true, tsr: `${file}.tsr`, gen_time: read.gen_time, sha256: sha256(res.body) };
  } catch (err) {
    return { ok: false, why: (err as Error).message };
  }
}

/** A reference clock's offset from this host's, from an https server's Date header (a second's precision). */
export async function referenceOffset(url: string): Promise<{ url: string; at: string; offset_ms: number | null; precision_ms: number; error?: string }> {
  const before = Date.now();
  try {
    const res = await post(url, Buffer.alloc(0), {});
    const after = Date.now();
    const date = Date.parse(String(res.headers.date ?? ""));
    if (!Number.isFinite(date)) return { url, at: new Date(after).toISOString(), offset_ms: null, precision_ms: 1000, error: "no Date header" };
    return { url, at: new Date(after).toISOString(), offset_ms: date - Math.round((before + after) / 2), precision_ms: 1000 + (after - before) };
  } catch (err) {
    return { url, at: new Date().toISOString(), offset_ms: null, precision_ms: 1000, error: (err as Error).message };
  }
}

// --- after the seal ---------------------------------------------------------------------

/** What closes a run after its verdict is written, and is expected there. */
const CLOSURE_TOOLS = new Set(["custody", "hub_clear_up", "operator_action", "vm_finish", "agent_stop"]);

/**
 * The trace lines written after a verdict sealed its first `sealed` lines,
 * by tool, and whether all of them are the run's closing lines.
 */
export function afterSeal(traceText: string, sealed: number): { lines: number; tools: string[]; closure_only: boolean } {
  const rest = traceText.split("\n").filter((l) => l.trim()).slice(sealed);
  const tools = rest.map((l) => {
    try {
      const o = JSON.parse(l) as { tool?: string; args?: { command?: string } };
      return o.tool === "operator_action" ? `operator_action:${o.args?.command ?? "?"}` : String(o.tool ?? "?");
    } catch {
      return "(not json)";
    }
  });
  return { lines: rest.length, tools, closure_only: tools.every((t) => CLOSURE_TOOLS.has(t.split(":")[0])) };
}

// --- the kickoff's side: the acquisition hashes into inputs.json, a reference clock ----

/**
 * The kickoff's step: read the operator's hash list, match it to the
 * inputs, hold each digest to the one the kickoff computed, and write the
 * list into inputs.json (anchored with it) as `acquisition`. Refused, with
 * each name, when a digest does not match, when a name is none of the
 * inputs, or when nothing matched at all.
 */
export async function applyAcquisitionHashes(sandbox: string, hashesFile: string): Promise<{ ok: true; given: number; matched: number } | { ok: false; why: string[] }> {
  const { readFile, writeFile, chmod, lstat, unlink } = await import("node:fs/promises");
  const { join, resolve } = await import("node:path");
  const manifestPath = join(resolve(sandbox), "inputs.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { files?: Array<{ path: string; sha256?: string; md5?: string; sha1?: string }>; acquisition?: unknown };
  const files = manifest.files ?? [];
  const raw = await readFile(hashesFile);
  const parsed = parseAcquisitionHashes(raw.toString("utf8"), files.map((f) => f.path));
  const why: string[] = [];
  for (const n of parsed.unmatched) why.push(`${n} is none of the inputs (or more than one has that name)`);
  const byPath = new Map(files.map((f) => [f.path, f]));
  for (const e of parsed.entries) {
    const have = byPath.get(e.path)?.[e.algo];
    if (!have) why.push(`${e.path}: the kickoff computed no ${e.algo}`);
    else if (have.toLowerCase() !== e.digest) why.push(`${e.path}: ${e.algo} ${e.digest} given, ${have} computed`);
  }
  if (!parsed.entries.length) why.push("no line of the file names an input with a digest");
  if (why.length) return { ok: false, why };
  manifest.acquisition = { source: hashesFile, source_sha256: sha256(raw), entries: parsed.entries, ignored_lines: parsed.ignored };
  // A manifest left read-only is replaced, not written through.
  if (await lstat(manifestPath).then(() => true, () => false)) await unlink(manifestPath);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  await chmod(manifestPath, 0o644);
  return { ok: true, given: parsed.entries.length, matched: parsed.entries.length };
}

if (process.argv[1] && (await import("node:url")).pathToFileURL(process.argv[1]).href === import.meta.url) {
  const [cmd, a, b] = process.argv.slice(2);
  if (cmd === "acquisition" && a && b) {
    const r = await applyAcquisitionHashes(a, b);
    if (r.ok) {
      console.log(JSON.stringify(r));
      process.exit(0);
    }
    for (const w of r.why) console.error(`  ${w}`);
    process.exit(4);
  } else if (cmd === "reference" && a) {
    console.log(JSON.stringify(await referenceOffset(a)));
    process.exit(0);
  } else {
    console.error("usage: custody-checks.ts acquisition <sandbox> <hashes file> | reference <https url>");
    process.exit(2);
  }
}
