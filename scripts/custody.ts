#!/usr/bin/env node
/**
 * What the host can say about a run once nothing is running any more.
 *
 * Every integrity check an agent reports about itself — its `inputs` check,
 * its done line — is the agent's word. This is the harness's, taken after
 * the agents (and, under --isolation microvm, their VMs) are gone, from the
 * host, reading every byte again:
 *
 *   - the evidence: every file inputs.json lists, hashed in full now and
 *     compared with the sha256 recorded when the run started (and with the
 *     md5 and sha1 when the manifest has them); anything missing, changed,
 *     added or unreadable is named. The manifest itself is compared with the
 *     sha256 the kickoff anchored outside the run, so a manifest rewritten
 *     inside the run is caught rather than trusted. Names are compared as
 *     bytes, so a name that is not valid UTF-8 is the same name at both ends;
 *   - the sessions: every file under .pi-sessions/, with its sha256 — the
 *     agents' own transcripts, sealed as they were left;
 *   - the kept outputs: every whole tool output the trace points to
 *     (`tool-output/…` with a sha256), re-hashed against the hash the line
 *     that kept it gave; a file that is gone, no longer matches, or was named
 *     again with another hash is named;
 *   - the trace: the hash chain and its anchor; every line outside the
 *     chain (the spills), parsed and attributed to the seat whose directory
 *     it sits in, and counted for no one else;
 *   - the ledger: its own chain, held to the trace — in a microVM run to the
 *     hub's lines, which no guest writes;
 *   - the VMs: for a microVM run, each VM's image digest and, when its disk
 *     was kept, the snapshot re-hashed against its record and verified by
 *     msb's own integrity record; the kept logs hashed; a VM whose disk was
 *     not kept, whose finish failed, or whose record cannot be read, named.
 *
 * Custody reads what agents wrote, so it trusts none of it: every file it
 * opens is opened as a regular file, never through a link and never waiting
 * on a FIFO or a device (O_NOFOLLOW | O_NONBLOCK, then fstat), every path it
 * takes from a trace line or a VM record must be under the run (or the
 * snapshot directory), the trace and the manifest are streamed whatever
 * their size, and every file is hashed in full — no size is too large to
 * check — against one deadline, checked inside the hashing, past which
 * `custody.json` names what was not checked and says it is incomplete
 * instead of the stop hanging. A second, hard deadline ends the process if
 * anything still holds it, and writes what was checked before it goes.
 *
 * What it writes (`custody.json`, the previous verdict beside it, dated, and
 * `artifacts.json`) goes to a fresh file renamed into place: a link a pane
 * planted at one of those names is replaced, never written through. The
 * previous verdict is moved aside before anything is checked, so the
 * `custody.json` in the run is this custody's or none. Adds the verdict's
 * sha256 to the anchor the kickoff wrote outside the run, and prints its
 * summary line.
 *
 *   node --experimental-strip-types scripts/custody.ts <sandbox> [--timeout SEC] [--run ID] [--quiet]
 */
import { isUtf8 } from "node:buffer";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { lstat, mkdtemp, readdir, readlink, realpath, rename, rm, unlink } from "node:fs/promises";
import { createInterface } from "node:readline";
import { StringDecoder } from "node:string_decoder";
import { basename, dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { eventChainVerifier, specialKind, verifyLedgerChain } from "../extensions/protocol.ts";
import { hashArtifacts } from "./artifacts.ts";
import { checkStore, type StoreCheck } from "./evidence-store.ts";
import {
  hashRegularFile,
  openRegular as openRegularFile,
  readRegularText as readRegularTextFile,
  writeFileNoFollowSync,
  type PathLike,
} from "./regular-file.ts";

export const CUSTODY_REL = "custody.json";
/** A sender clock this far from the collector's is named in the verdict. */
export const CLOCK_FLAG_SEC = 120;
/** A text custody holds whole (a VM record, the ledger): past this it is not one. */
const MAX_TEXT_BYTES = 256 * 1024 * 1024;
/** How far past the deadline the process may run before it ends itself. */
const HARD_GRACE_SEC = 120;
/** The part of inputs.json that is not the file list; past this it is not a manifest. */
const MAX_MANIFEST_META_CHARS = 16 * 1024 * 1024;
const SLASH = Buffer.from("/");
const INPUTS_PREFIX = Buffer.from("inputs/");

/**
 * The kickoff's own record of what the run started with, outside the run.
 * The kickoff names it by the sandbox's real parent (`pwd -P`); a sandbox
 * given through a link (/tmp on macOS) resolves to the same file.
 */
export function custodyAnchorPath(sandbox: string): string {
  return `${resolve(sandbox)}.custody-anchor.json`;
}

async function anchorPathFor(sandbox: string): Promise<string> {
  const parent = await realpath(dirname(resolve(sandbox))).catch(() => dirname(resolve(sandbox)));
  const real = join(parent, basename(resolve(sandbox)));
  return existsSync(`${real}.custody-anchor.json`) ? `${real}.custody-anchor.json` : custodyAnchorPath(sandbox);
}

class Deadline {
  private readonly until: number;
  constructor(seconds: number) {
    this.until = Date.now() + seconds * 1000;
  }
  get over(): boolean {
    return Date.now() > this.until;
  }
  get remainingMs(): number {
    return Math.max(0, this.until - Date.now());
  }
}

/**
 * A file opened the one way custody opens anything: as a regular file, not
 * through a link (O_NOFOLLOW), not waiting on a FIFO or a device someone left
 * in its place (O_NONBLOCK), and checked by fstat after the open, so a file
 * swapped in between is what is judged.
 */
export async function openRegular(path: PathLike) {
  return openRegularFile(path);
}

/** A regular file's text, whole; the reason when it is not one or is too large to hold. */
export async function readRegularText(path: PathLike, maxBytes = MAX_TEXT_BYTES): Promise<{ text: string } | { why: string }> {
  return readRegularTextFile(path, maxBytes);
}

/** A regular file's sha256, read in full with the deadline checked as it goes (null past it). */
async function hashRegular(path: PathLike, deadline: Deadline): Promise<{ sha256: string; size: number } | { why: string } | null> {
  return hashRegularFile(path, { expiry: deadline });
}

/** Each line of a regular file, streamed: a trace of any size is read without holding it. */
async function eachLine(path: string, onLine: (line: string) => void): Promise<{ lines: number } | { why: string }> {
  const opened = await openRegular(path);
  if ("why" in opened) return opened;
  let lines = 0;
  try {
    const rl = createInterface({ input: opened.handle.createReadStream({ autoClose: false, encoding: "utf8" }), crlfDelay: Infinity });
    for await (const line of rl) {
      if (line === "") continue;
      lines += 1;
      onLine(line);
    }
  } finally {
    await opened.handle.close();
  }
  return { lines };
}

/** A regular file, by lstat (a link is not followed), or null with the reason. */
async function regular(path: string): Promise<{ size: number } | { why: string }> {
  const st = await lstat(path).catch(() => null);
  if (!st) return { why: "missing" };
  if (st.isSymbolicLink()) return { why: "a link" };
  if (!st.isFile()) return { why: "not a regular file" };
  return { size: st.size };
}

/**
 * Files under a directory, never through a link; what is not a regular file
 * or a directory (a link, a FIFO, a socket, a device) is listed in `other`
 * so it is named rather than silently passed over. Pushed one by one, never
 * spread: a directory of 150,000 names overflowed the stack as one push.
 */
async function walkAll(dir: string, base = dir, acc: { files: string[]; other: string[] } = { files: [], other: [] }): Promise<{ files: string[]; other: string[] }> {
  for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) await walkAll(abs, base, acc);
    else if (entry.isFile()) acc.files.push(abs);
    else acc.other.push(relative(base, abs));
  }
  if (dir === base) {
    acc.files.sort();
    acc.other.sort();
  }
  return acc;
}

async function walk(dir: string): Promise<string[]> {
  return (await walkAll(dir)).files;
}

/**
 * Names under the evidence, as bytes, the way every walk over it does: a
 * link is a name of its own and is never followed (a loop would never end,
 * and what is under a directory link is another directory's); the top of
 * the evidence may itself be a link (--inputs in place), so the caller gives
 * its real path.
 */
async function walkEvidence(root: Buffer, onName: (abs: Buffer) => void): Promise<void> {
  const stack: Buffer[] = [root];
  while (stack.length) {
    const dir = stack.pop() as Buffer;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true, encoding: "buffer" });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const abs = Buffer.concat([dir, SLASH, entry.name as unknown as Buffer]);
      if (entry.isDirectory()) stack.push(abs);
      else onName(abs); // a file, a link, and anything else (a FIFO, a socket, a device) is a name
    }
  }
}

/**
 * A name's bytes, the way Python's os.fsencode gives them back: the manifest
 * writer walks with surrogateescape, so a byte that is not UTF-8 arrives as a
 * lone surrogate U+DC80–U+DCFF, which stands for that one byte. Encoding such
 * a string as UTF-8 gave U+FFFD instead, and a name that never changed was
 * missing at one end and added at the other.
 */
export function fsEncode(name: string): Buffer {
  const out: number[] = [];
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c >= 0xdc80 && c <= 0xdcff) {
      out.push(c - 0xdc00);
      continue;
    }
    let cp = c;
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < name.length) {
      const d = name.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        cp = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i += 1;
      }
    }
    for (const b of Buffer.from(String.fromCodePoint(cp), "utf8")) out.push(b);
  }
  return Buffer.from(out);
}

/** The display form of a name's bytes: UTF-8 when it is, else Python's surrogateescape, byte for byte. */
export function fsDecode(bytes: Buffer): string {
  if (isUtf8(bytes)) return bytes.toString("utf8");
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i];
    const len = b < 0x80 ? 1 : b >= 0xc2 && b <= 0xdf ? 2 : b >= 0xe0 && b <= 0xef ? 3 : b >= 0xf0 && b <= 0xf4 ? 4 : 0;
    if (len && i + len <= bytes.length && isUtf8(bytes.subarray(i, i + len))) {
      out += bytes.subarray(i, i + len).toString("utf8");
      i += len;
    } else {
      out += String.fromCharCode(0xdc00 + b);
      i += 1;
    }
  }
  return out;
}

/** One entry of inputs.json, as custody compares it: the name and a link's target as bytes. */
type ManifestFile = {
  path: string;
  /** The name under inputs/, as bytes. */
  rel: Buffer;
  /** The size the kickoff recorded; null when it recorded none. */
  bytes: number | null;
  sha256: string;
  md5?: string;
  sha1?: string;
  link?: Buffer;
  special?: string;
};

function manifestFile(raw: unknown): ManifestFile | null {
  const f = raw as Record<string, unknown> | null;
  if (!f || typeof f !== "object" || typeof f.path !== "string" || typeof f.sha256 !== "string") return null;
  // `path_b64` is the name's raw bytes when the kickoff recorded them (a
  // name that is not UTF-8); otherwise the name is re-encoded as Python
  // wrote it.
  const full = typeof f.path_b64 === "string" ? Buffer.from(f.path_b64, "base64") : fsEncode(f.path);
  const rel = full.subarray(0, INPUTS_PREFIX.length).equals(INPUTS_PREFIX) ? full.subarray(INPUTS_PREFIX.length) : full;
  const linkB64 = typeof f.link_b64 === "string" ? f.link_b64 : typeof f.target_b64 === "string" ? f.target_b64 : null;
  const link = linkB64 !== null ? Buffer.from(linkB64, "base64") : typeof f.link === "string" ? fsEncode(f.link) : undefined;
  const hex = (v: unknown, len: number) => (typeof v === "string" && new RegExp(`^[0-9a-fA-F]{${len}}$`).test(v) ? v.toLowerCase() : undefined);
  return {
    path: f.path,
    rel,
    bytes: typeof f.bytes === "number" && Number.isFinite(f.bytes) ? f.bytes : null,
    sha256: f.sha256.toLowerCase(),
    ...(hex(f.md5, 32) ? { md5: hex(f.md5, 32) } : {}),
    ...(hex(f.sha1, 40) ? { sha1: hex(f.sha1, 40) } : {}),
    ...(link ? { link } : {}),
    ...(f.special === "fifo" || f.special === "socket" || f.special === "char" || f.special === "block" ? { special: f.special } : {}),
  };
}

/**
 * inputs.json streamed: its sha256 over the bytes as read, each element of
 * its `files` array handed over as it is parsed, and the rest of the object
 * (the few fields around the list) parsed at the end. A manifest of a
 * million files is 250 MB of JSON: read whole, it hit the text cap and its
 * hash was taken over nothing (a false MANIFEST REWRITTEN), and past 512 MB
 * it did not fit in a string at all. Elements are handed over a chunk at a
 * time, and the next chunk is read when they are done, so what is held is
 * one chunk's worth.
 */
async function streamManifest(
  path: string,
  onFile: (raw: unknown) => Promise<void>,
): Promise<{ sha256: string; meta: Record<string, unknown> } | { why: string; sha256?: string }> {
  const opened = await openRegular(path);
  if ("why" in opened) return opened;
  const hash = createHash("sha256");
  const decoder = new StringDecoder("utf8");
  let depth = 0;
  let inString = false;
  let escape = false;
  let key = "";
  let lastString = "";
  let inFiles = false;
  let sawFiles = false;
  let capture = "";
  let capturing = false;
  let meta = "";
  let tooBig = false;
  const pending: string[] = [];
  const scan = (text: string) => {
    let metaFrom = inFiles ? -1 : 0;
    let capFrom = capturing ? 0 : -1;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if (inString) {
        if (escape) escape = false;
        else if (c === 92) escape = true;
        else if (c === 34) {
          inString = false;
          if (depth === 1) lastString = key;
        } else if (depth === 1) key += text[i];
        continue;
      }
      if (c === 34) {
        inString = true;
        if (depth === 1) key = "";
        continue;
      }
      if (c === 123 || c === 91) {
        depth += 1;
        if (c === 91 && depth === 2 && lastString === "files" && !sawFiles) {
          inFiles = true;
          sawFiles = true;
          meta += text.slice(metaFrom, i + 1);
          metaFrom = -1;
        } else if (inFiles && depth === 3 && c === 123) {
          capturing = true;
          capFrom = i;
        }
        continue;
      }
      if (c === 125 || c === 93) {
        if (inFiles && depth === 3 && c === 125 && capturing) {
          pending.push(capture + text.slice(capFrom, i + 1));
          capture = "";
          capturing = false;
          capFrom = -1;
        } else if (inFiles && depth === 2 && c === 93) {
          inFiles = false;
          metaFrom = i;
        }
        depth -= 1;
      }
    }
    if (capturing && capFrom >= 0) capture += text.slice(capFrom);
    if (metaFrom >= 0) meta += text.slice(metaFrom);
    if (meta.length > MAX_MANIFEST_META_CHARS) tooBig = true;
  };
  const drain = async () => {
    for (const element of pending.splice(0)) {
      let raw: unknown;
      try {
        raw = JSON.parse(element);
      } catch {
        raw = null;
      }
      await onFile(raw);
    }
  };
  try {
    for await (const chunk of opened.handle.createReadStream({ autoClose: false, highWaterMark: 1024 * 1024 })) {
      hash.update(chunk as Buffer);
      if (tooBig) continue;
      scan(decoder.write(chunk as Buffer));
      await drain();
    }
    if (!tooBig) {
      scan(decoder.end());
      await drain();
    }
  } finally {
    await opened.handle.close();
  }
  const sha256 = hash.digest("hex");
  if (tooBig || !sawFiles) return { why: "not a manifest (no file list)", sha256 };
  try {
    const parsed = JSON.parse(meta) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.files)) return { why: "not a manifest (no file list)", sha256 };
    return { sha256, meta: parsed };
  } catch {
    return { why: "not valid JSON", sha256 };
  }
}

/**
 * inputs.json's own fields, without its file list, streamed: what the
 * report and the summary say about how the evidence arrived (`held`,
 * `source_checked`, `digests`) from a manifest of any size. Null when it is
 * missing or not a manifest.
 */
export async function manifestMeta(sandbox: string): Promise<Record<string, unknown> | null> {
  const read = await streamManifest(join(resolve(sandbox), "inputs.json"), async () => undefined);
  return "meta" in read ? read.meta : null;
}

/**
 * Every name inputs.json lists, streamed: the path as the manifest shows it
 * and the name under inputs/ as bytes (`path_b64` honoured). What coverage
 * matches the trace against, for a manifest of any size; `why` when there is
 * no manifest to read.
 */
export async function eachInputsFile(
  sandbox: string,
  onFile: (f: { path: string; rel: Buffer }) => void | Promise<void>,
): Promise<{ ok: true } | { why: string }> {
  const read = await streamManifest(join(resolve(sandbox), "inputs.json"), async (raw) => {
    const f = manifestFile(raw);
    if (f) await onFile({ path: f.path, rel: f.rel });
  });
  return "meta" in read ? { ok: true } : { why: read.why };
}

export type Custody = {
  at: string;
  run: string | null;
  /** How the run held its agents, as the kickoff anchored it outside the run: microvm, host, or null when an older anchor did not say. */
  isolation: string | null;
  /** Where the verdict this one replaces was moved, before anything was checked. */
  previous: string | null;
  inputs:
    | null
    | { unverifiable: string }
    | {
        files: number;
        bytes: number;
        unchanged: boolean;
        /** Every listed file was re-read in full before the deadline, and none was unreadable. */
        complete: boolean;
        changed: string[];
        missing: string[];
        added: string[];
        /** Files not re-read because the deadline passed: the verdict does not cover them. */
        skipped: string[];
        /** Files the host could not read (a permission, an I/O error): not missing, not checked. */
        unreadable: string[];
        /** What was checked how: regular files by their bytes, links by their target, special files by their kind. */
        checked: { files: number; links: number; special: number };
        /** How many files each digest was compared on; md5 and sha1 when the manifest carries them. */
        digests_compared: { sha256: number; md5: number; sha1: number };
        manifest_sha256: string;
        manifest_anchored: boolean | null;
      };
  sessions: { files: Array<{ path: string; bytes: number; sha256: string | null }>; digest: string; not_files: string[] };
  tool_outputs: {
    referenced: number;
    verified: number;
    missing: string[];
    mismatched: string[];
    refused: string[];
    /** Named again later with another hash: checked against the hash of the line that kept it. */
    rereferenced: string[];
    /** Named by a line from an agent whose directory it is not: not taken as a reference. */
    foreign: string[];
  };
  trace: {
    lines: number;
    intact: boolean;
    detail: string;
    /** Lines no pane's token vouched for, operator actions aside. */
    unverified: number;
    /** `operator_action` lines from a shell outside the run (stop, reap, say): the operator's, carried with no pane's token by design; each is also on runs/operator-audit.jsonl. */
    operator_actions: number;
    disputed: number;
    /** `unauthenticated`: a host run's shared spill, which any pane can write and whose lines carry no token (only the collector ever sees one). */
    spilled: Array<{ path: string; lines: number; agent: string | null; bad: number; duplicates: number; refused?: string; unauthenticated?: true }>;
    /** Per sending process, how many of its numbered lines are in neither the chain nor a spill. */
    gaps: Array<{ sid: string; agent: string; missing: number }>;
    /** Per agent, lines whose own clock (`ts`) was more than CLOCK_FLAG_SEC off the collector's (`recv_ts`). */
    clock: Array<{ agent: string; lines: number; max_skew_s: number }>;
    /** Per agent, lines its own process said it could write nowhere. */
    sender_lost: Array<{ agent: string; lines: number }>;
  };
  ledger: {
    entries: number;
    chained: number;
    intact: boolean;
    detail: string;
    /** Entries whose hash the trace carries (the record tool's line, or the hub's) but the ledger does not: deleted. */
    missing_from_ledger: string[];
    /** Chained entries the trace never carried: written into the file without the tool. */
    not_on_trace: number[];
    /** Whether the ledger could be held to the trace at all (a readable trace), and to whose lines. */
    held_to: "the hub's lines" | "the record tool's lines" | "the seats' own lines (the hub logged none)" | "nothing (no readable trace)";
    /** Hashes a seat's own `record` line carried that the hub never logged: a guest's word, not counted against the ledger. */
    claimed_by_seat: string[];
  } | null;
  vms:
    | null
    | Array<{
        agent: string;
        /** The sha256 of the VM's record as custody read it. */
        record_sha256: string;
        image: string | null;
        /** The digest the kickoff resolved for the run; null when it recorded none. */
        expected_image: string | null;
        stopped: boolean;
        kept: string | null;
        snapshot:
          | null
          | {
              path: string;
              sha256: string;
              verified: boolean;
              /** msb's own check: true, false (msb said not verified), null (it did not run; `msb_note` says why). */
              msb_verified: boolean | null;
              msb_note?: string;
              /** Why the snapshot was not read at all: outside the snapshot directory, not a .msb, gone. */
              refused?: string;
            }
          | { error: string };
        logs: Array<{ path: string; sha256: string }>;
        /** Placeholders msb stopped on their way to a host their secret is not bound to (runtime.log). */
        secret_violations: SecretViolation[];
        /** Packages the VM held at stop that its image did not (vm.ts INVENTORY_SCRIPT), or why that is unknown. */
        installed_outside: { apt: string[]; venv: string[]; note: string | null };
        /** msb's version when the VM was made and when it was put away, when they differ. */
        runtime_changed: { from: string; to: string } | null;
        /** What the finish that removed the VM did to msb's database (scrubbed, busy, no sqlite3, no database); null when it was not removed by a finish that said. */
        msb_db: string | null;
      }>;
  /** What the VM records themselves said: records that could not be read, agents with none, a vm/ in a host run. */
  vm_records: { unreadable: string[]; no_record: string[]; ignored: string | null } | null;
  /**
   * What the run produced under work/, every file with its sha256, written
   * beside the verdict (artifacts.json) and its hash anchored with it: the
   * record of the deliverables as the host found them at stop, not only when
   * someone packages the run.
   */
  artifacts: { files: number; bytes: number; skipped: number; index_sha256: string } | null;
  /**
   * The model gateway's call log (traces/model-gateway.jsonl), when the run
   * had one: its lines, whether its chain holds (each line's `prev` the
   * sha256 of the line before, the first null) and its sha256, anchored with
   * the verdict. Null when there is no log.
   */
  model_gateway: { lines: number; intact: boolean; detail: string; sha256: string | null; refused?: string } | null;
  /**
   * The evidence-work store (tool jobs, their sealed outputs, the catalogue
   * they grew): the journal's chain and its anchor beside the run, every
   * committed file hashed again against its manifest, staging left behind.
   * Null when the run had no job service.
   */
  store: StoreCheck | null;
  /** Parts custody never reached, for a verdict written when it was ended. */
  not_reached: string[];
  incomplete: string | null;
  summary: string;
};

/**
 * What custody has found so far. Filled as each part is done, so a verdict
 * can be written from it when custody is ended early — by its hard deadline
 * or by an error — rather than the whole verdict being lost.
 */
export type CustodyState = {
  phase: string;
  sandbox?: string;
  anchorFile?: string;
  run?: string | null;
  isolation?: string | null;
  previous?: string | null;
  inputs?: Custody["inputs"];
  inputsDone?: boolean;
  sessions?: Custody["sessions"];
  tool_outputs?: Custody["tool_outputs"];
  trace?: Custody["trace"];
  traceProblem?: string | null;
  traceAnchored?: boolean;
  ledger?: Custody["ledger"];
  ledgerDone?: boolean;
  vms?: Custody["vms"];
  vm_records?: Custody["vm_records"];
  vmsDone?: boolean;
  artifacts?: Custody["artifacts"];
  artifactsDone?: boolean;
  model_gateway?: Custody["model_gateway"];
  gatewayDone?: boolean;
  store?: Custody["store"];
  storeDone?: boolean;
  incomplete?: string | null;
};

/** The model gateway's call log and totals, beside the trace (scripts/model-gateway.ts). */
export const GATEWAY_LOG = "traces/model-gateway.jsonl";

/**
 * The gateway log's own chain, line by line as written: every line JSON,
 * its `prev` the sha256 of the raw line before it and null on the first.
 */
export function gatewayChainVerifier(): { line: (raw: string) => void; result: () => { lines: number; ok: boolean; broken_at: number | null; reason: string | null } } {
  let lines = 0;
  let last: string | null = null;
  let broken: { at: number; reason: string } | null = null;
  return {
    line(raw: string) {
      lines += 1;
      if (broken) return;
      let rec: { prev?: unknown };
      try {
        rec = JSON.parse(raw) as { prev?: unknown };
      } catch {
        broken = { at: lines, reason: "not json" };
        return;
      }
      if (!rec || typeof rec !== "object" || !("prev" in rec)) broken = { at: lines, reason: "a line without its prev" };
      else if ((rec.prev ?? null) !== last) broken = { at: lines, reason: last === null ? "the first line names a line before it" : "prev does not name the line before it" };
      last = createHash("sha256").update(raw).digest("hex");
    },
    result: () => ({ lines, ok: !broken, broken_at: broken?.at ?? null, reason: broken?.reason ?? null }),
  };
}

/** What a VM's stop-time inventory said: package names, or why there is none. */
function outsideOf(raw: unknown): { apt: string[]; venv: string[]; note: string | null } {
  if (!raw || typeof raw !== "object") return { apt: [], venv: [], note: "no inventory was taken (a VM put away before stop took one)" };
  const r = raw as { error?: string; baseline?: boolean; apt?: Record<string, string>; venv?: Record<string, string> };
  if (r.error) return { apt: [], venv: [], note: `the inventory failed: ${r.error}` };
  const fmt = (m?: Record<string, string>) => Object.entries(m ?? {}).map(([k, v]) => `${k} ${v}`);
  return { apt: fmt(r.apt), venv: fmt(r.venv), note: r.baseline === false ? "the image records no full package list, so apt installs cannot be told apart" : null };
}

export type SecretViolation = {
  at: string;
  env: string;
  host: string;
  method: string;
  path: string;
  action: string;
  /** Where msb found the placeholder (header, query, body) and in what form (raw, percent_decoded). */
  location?: string;
  match_form?: string;
  /**
   * Whether `host` is one the credential is bound to (the VM record's
   * secrets); null when the record does not say. msb 0.7.2 also stops
   * requests to a credential's own host: when the TLS record with the
   * header holds a `%` or `\u` of the body, it reads the header's
   * placeholder as body (run se064eb, 52 stops, all to api.openai.com).
   */
  own_host?: boolean | null;
};

/**
 * msb's record of a placeholder it stopped: a WARN line in the VM's
 * runtime.log (measured, msb 0.7.2, secretViolationAction block-and-log):
 *   <ts>  WARN microsandbox_network::engine::secrets::handler: secret
 *   violation: placeholder detected for disallowed host action=block-and-log
 *   secret_env_var=K placeholder=… sni=… host=… method=GET path=/v1/models …
 * A request to a host outside the policy is not logged at all: its name does
 * not resolve and its address has no route. This is the one refusal msb
 * writes down, and the one that says a credential was aimed somewhere else.
 */
export function secretViolations(runtimeLog: string): SecretViolation[] {
  const out: SecretViolation[] = [];
  for (const line of runtimeLog.split("\n")) {
    const i = line.indexOf("secret violation:");
    if (i < 0) continue;
    const fields: Record<string, string> = {};
    for (const m of line.slice(i).matchAll(/(\w+)=(\S*)/g)) fields[m[1]] = m[2];
    out.push({
      at: line.slice(0, line.indexOf(" ")).trim(),
      env: fields.secret_env_var ?? "",
      host: fields.host || fields.sni || "",
      method: fields.method ?? "",
      path: fields.path ?? "",
      action: fields.action ?? "",
      ...(fields.location ? { location: fields.location } : {}),
      ...(fields.match_form ? { match_form: fields.match_form } : {}),
    });
  }
  return out;
}

/**
 * Each stop marked with whether it was on the credential's own host, from
 * the VM record's secrets: matched by the variable msb holds it under
 * (records since 2026-09-25 name it), else by a pack secret's own name or
 * the provider's DFIRSWARM_<PROVIDER>_CREDENTIAL. Unmatched stays null.
 */
export function markOwnHost(violations: SecretViolation[], secrets: unknown): SecretViolation[] {
  const bound = (Array.isArray(secrets) ? secrets : [])
    .filter((x): x is { name?: unknown; env?: unknown; hosts?: unknown } => !!x && typeof x === "object")
    .map((x) => {
      const name = typeof x.name === "string" ? x.name : "";
      const provider = name.replace(/ \((?:API key|subscription token)\)$/, "");
      const envs = new Set<string>([typeof x.env === "string" ? x.env : "", name, `DFIRSWARM_${provider.replace(/[^A-Za-z0-9]/g, "_").toUpperCase()}_CREDENTIAL`].filter(Boolean));
      const hosts = (Array.isArray(x.hosts) ? x.hosts : []).filter((h): h is string => typeof h === "string").map((h) => h.replace(/:\d+$/, "").toLowerCase());
      return { envs, hosts };
    });
  return violations.map((v) => {
    const s = bound.find((b) => b.envs.has(v.env));
    return { ...v, own_host: s ? s.hosts.includes(v.host.toLowerCase()) : null };
  });
}

/**
 * Every `{path: "tool-output/…", sha256}` a trace line carries, wherever it
 * sits in the line. The first hash named for a path is kept: a later line
 * cannot replace the hash the output was kept under.
 */
export function keptOutputRefs(value: unknown, out: Map<string, string> = new Map()): Map<string, string> {
  if (Array.isArray(value)) {
    for (const v of value) keptOutputRefs(v, out);
  } else if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    if (typeof o.path === "string" && o.path.startsWith("tool-output/") && typeof o.sha256 === "string" && /^[0-9a-f]{64}$/.test(o.sha256)) {
      if (!out.has(o.path)) out.set(o.path, o.sha256);
    }
    for (const v of Object.values(o)) keptOutputRefs(v, out);
  }
  return out;
}

/** A path from a trace line, resolved: a regular file under `tool-output/` of the run, or the reason it is not. */
export async function confinedOutput(sandbox: string, rel: string): Promise<{ abs: string; size: number } | { why: string }> {
  if (!/^tool-output\/[a-z][a-z0-9_-]{0,31}\/[^/\0]+$/.test(rel)) return { why: "not a file directly under tool-output/<agent>/" };
  const root = await realpath(join(sandbox, "tool-output")).catch(() => null);
  if (!root) return { why: "no tool-output/" };
  const abs = join(sandbox, rel);
  const reg = await regular(abs);
  if ("why" in reg) return reg;
  const real = await realpath(abs).catch(() => null);
  if (!real || !real.startsWith(`${root}/`)) return { why: "outside tool-output/" };
  return { abs: real, size: reg.size };
}

/**
 * msb's own integrity check of a kept disk. `msb snapshot verify` reads a
 * snapshot directory, not the `.msb` archive stop keeps (measured: on the
 * archive it answers "snapshot not found: …/snapshot.json: Not a directory",
 * so this check used to fail every time). The archive is loaded into a
 * directory of its own beside it (not the host's /tmp, which may be memory,
 * and which a killed custody would leave an evidence-derived disk in),
 * verified there — msb recomputes its merkle tree over every file — and
 * taken out of msb's index again.
 *
 * `verified` is msb's answer; null when msb never gave one (not installed,
 * the archive would not load, out of time), with the reason. A load that
 * failed is not a disk that failed msb's check.
 */
async function msbSnapshotVerify(file: string, deadline: Deadline): Promise<{ verified: boolean | null; note?: string }> {
  let msb: string;
  try {
    msb = (await import("./vm.ts")).msbBinary();
  } catch (err) {
    return { verified: null, note: `msb could not be located: ${(err as Error).message}` };
  }
  const run = (args: string[]) =>
    new Promise<{ code: number; out: string; missing: boolean; timedOut: boolean }>((done) => {
      const timeout = Math.max(1000, Math.min(10 * 60_000, deadline.remainingMs));
      const child = execFile(msb, args, { timeout, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) =>
        done({
          code: err ? 1 : 0,
          out: `${stdout}${stderr}`,
          missing: (err as NodeJS.ErrnoException | null)?.code === "ENOENT",
          timedOut: Boolean((err as { killed?: boolean } | null)?.killed),
        }),
      );
      child.stdin?.end();
    });
  if (deadline.over) return { verified: null, note: "the deadline passed before msb's check" };
  let dest: string;
  try {
    dest = await mkdtemp(join(dirname(file), ".verify-"));
  } catch (err) {
    return { verified: null, note: `no room to load the snapshot beside it (${(err as NodeJS.ErrnoException).code ?? "error"})` };
  }
  let digest = "";
  try {
    const loaded = await run(["snapshot", "load", "--dest", dest, file]);
    if (loaded.code !== 0) {
      if (loaded.missing) return { verified: null, note: "msb is not installed" };
      if (loaded.timedOut) return { verified: null, note: "msb did not load the snapshot in time" };
      return { verified: null, note: `msb could not load the snapshot: ${loaded.out.trim().split("\n").at(-1) ?? "no answer"}` };
    }
    digest = loaded.out.match(/sha256:[0-9a-f]{64}/)?.[0] ?? "";
    const dir = (await walk(dest)).find((p) => p.endsWith("/snapshot.json"));
    if (!dir) return { verified: null, note: "msb loaded the snapshot but wrote no snapshot.json" };
    const verified = await run(["snapshot", "verify", dirname(dir)]);
    if (verified.timedOut) return { verified: null, note: "msb did not finish its check in time" };
    return { verified: verified.code === 0 && /Verification:\s+verified/.test(verified.out) };
  } catch (err) {
    return { verified: null, note: `msb's check could not run: ${(err as Error).message}` };
  } finally {
    if (digest) await run(["snapshot", "remove", "--force", "--quiet", digest]);
    await rm(dest, { recursive: true, force: true }).catch(() => undefined);
  }
}

const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/**
 * The verdict already in the run goes aside, dated by its own `at`, before
 * anything is checked: the `custody.json` a stop leaves is then its own or
 * none, never an older one standing in for a custody that failed. It is read
 * as a regular file only; a link (or anything else) at that name is removed,
 * never followed, and never copied into the run.
 */
async function setAsidePrevious(sandbox: string): Promise<string | null> {
  const file = join(sandbox, CUSTODY_REL);
  const lst = await lstat(file).catch(() => null);
  if (!lst) return null;
  const stamp = new Date().toISOString().replace(/[^0-9A-Za-z]/g, "");
  if (lst.isDirectory()) {
    await rename(file, join(sandbox, `custody.json.not-a-file-${stamp}`)).catch(() => undefined);
    return `custody.json was a directory; moved to custody.json.not-a-file-${stamp}`;
  }
  const read = lst.isFile() ? await readRegularText(file) : { why: lst.isSymbolicLink() ? "a link" : "not a regular file" };
  if ("why" in read) {
    await unlink(file).catch(() => undefined);
    return `custody.json was ${read.why}; removed, not read`;
  }
  let name = `custody.previous-${stamp}.json`;
  try {
    const at = (JSON.parse(read.text) as { at?: unknown }).at;
    if (typeof at === "string" && ISO_TIME.test(at) && Number.isFinite(Date.parse(at))) name = `custody.${at.replace(/[^0-9A-Za-z]/g, "")}.json`;
  } catch {
    // kept under a name of this custody's own time: it is what was there
  }
  writeFileNoFollowSync(sandbox, name, read.text);
  await unlink(file).catch(() => undefined);
  return name;
}

export async function takeCustody(
  sandboxInput: string,
  options: { timeoutSec?: number; run?: string; progress?: (line: string) => void; state?: CustodyState } = {},
): Promise<Custody> {
  const sandbox = resolve(sandboxInput);
  const state: CustodyState = options.state ?? { phase: "starting" };
  const deadline = new Deadline(options.timeoutSec ?? 4 * 3600);
  state.incomplete = null;
  const tooLate = (what: string) => {
    if (deadline.over && !state.incomplete) state.incomplete = `the deadline passed during ${what}`;
    return deadline.over;
  };
  const say = options.progress ?? (() => undefined);
  let anchor: { inputs_manifest_sha256?: string; run?: string; isolation?: string } | null = null;
  const anchorFile = await anchorPathFor(sandbox);
  try {
    anchor = JSON.parse(await readRegularTextOutside(anchorFile));
  } catch {
    anchor = null;
  }
  const run = options.run ?? anchor?.run ?? null;
  const isolation = typeof anchor?.isolation === "string" ? anchor.isolation : null;
  // Whether the VM records and the hub's lines are this run's: the anchor,
  // outside the run, says so; an older anchor that does not leaves the
  // presence of vm/ to say it.
  const vmRun = isolation ? isolation === "microvm" : existsSync(join(sandbox, "vm"));
  Object.assign(state, { sandbox, anchorFile, run, isolation });
  state.phase = "setting the previous verdict aside";
  state.previous = await setAsidePrevious(sandbox);

  // --- the evidence ---------------------------------------------------------
  state.phase = "the evidence re-hash";
  const manifestPath = join(sandbox, "inputs.json");
  const hasEvidence = existsSync(join(sandbox, "inputs")) || existsSync(join(sandbox, "inputs.device"));
  const manifestLst = await lstat(manifestPath).catch(() => null);
  if (!manifestLst) {
    if (anchor?.inputs_manifest_sha256) state.inputs = { unverifiable: "the kickoff anchored an inputs.json that is gone or unreadable now" };
    else if (hasEvidence) state.inputs = { unverifiable: "the run has evidence but no readable inputs.json to compare it with" };
    else state.inputs = null;
  } else {
    const changed: string[] = [];
    const missing: string[] = [];
    const skipped: string[] = [];
    const unreadable: string[] = [];
    const checked = { files: 0, links: 0, special: 0 };
    const digests = { sha256: 0, md5: 0, sha1: 0 };
    const listed = new Set<string>();
    let total = 0;
    let totalBytes = 0;
    const evidenceRoot = Buffer.from(await realpath(join(sandbox, "inputs")).catch(() => join(sandbox, "inputs")));
    let lastSaid = Date.now();
    const streamed = await streamManifest(manifestPath, async (raw) => {
      const file = manifestFile(raw);
      if (!file) return;
      total += 1;
      totalBytes += file.bytes ?? 0;
      listed.add(file.rel.toString("latin1"));
      if (tooLate("the evidence re-hash")) {
        skipped.push(file.path);
        return;
      }
      const abs = Buffer.concat([evidenceRoot, SLASH, file.rel]);
      let lst;
      try {
        lst = await lstat(abs);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === "ENOENT" || code === "ENOTDIR") missing.push(file.path);
        else unreadable.push(`${file.path} (${code ?? "error"})`);
        return;
      }
      if (file.link) {
        // A link is checked as a link: its target, never followed. A regular
        // file where the link was is a change, not an absence.
        checked.links += 1;
        if (!lst.isSymbolicLink()) {
          changed.push(file.path);
          return;
        }
        const target = await readlink(abs, { encoding: "buffer" }).catch(() => null);
        if (target === null) unreadable.push(`${file.path} (the link could not be read)`);
        else if (!target.equals(file.link)) changed.push(file.path);
        return;
      }
      if (file.special) {
        // A FIFO, socket or device node is checked by its kind, never opened.
        checked.special += 1;
        if (specialKind(lst) !== file.special) changed.push(file.path);
        return;
      }
      if (!lst.isFile()) {
        // A link, a FIFO or a device where a file was: not what was recorded.
        changed.push(file.path);
        return;
      }
      // The size first: a file that grew or shrank has changed, whatever
      // its size, and needs no reading to say so.
      if (file.bytes !== null && lst.size !== file.bytes) {
        changed.push(file.path);
        return;
      }
      if (lst.size > 256 * 1024 * 1024 || Date.now() - lastSaid > 30_000) {
        say(`custody: re-hashing ${file.path} (${total}, ${lst.size} bytes)`);
        lastSaid = Date.now();
      }
      const hashed = await hashRegularFile(abs, {
        expiry: deadline,
        md5: Boolean(file.md5),
        sha1: Boolean(file.sha1),
        progress: (read, size) => say(`custody: ${file.path}: ${(read / 2 ** 30).toFixed(0)} of ${(size / 2 ** 30).toFixed(0)} GiB read`),
      });
      if (hashed === null) {
        tooLate("the evidence re-hash");
        skipped.push(file.path);
        return;
      }
      if ("why" in hashed) {
        if (hashed.why === "missing") missing.push(file.path);
        else if (hashed.why.startsWith("unreadable")) unreadable.push(`${file.path} (${hashed.why})`);
        else changed.push(file.path);
        return;
      }
      checked.files += 1;
      digests.sha256 += 1;
      let same = hashed.sha256 === file.sha256;
      if (file.md5) {
        digests.md5 += 1;
        same &&= hashed.md5 === file.md5;
      }
      if (file.sha1) {
        digests.sha1 += 1;
        same &&= hashed.sha1 === file.sha1;
      }
      if (!same) changed.push(file.path);
    });
    if ("why" in streamed) {
      state.inputs = {
        unverifiable: anchor?.inputs_manifest_sha256 && streamed.why !== "not valid JSON"
          ? `the kickoff anchored an inputs.json that is ${streamed.why} now`
          : `inputs.json is ${streamed.why}`,
      };
    } else {
      const anchored = anchor?.inputs_manifest_sha256 ? anchor.inputs_manifest_sha256 === streamed.sha256 : null;
      const added: string[] = [];
      if (existsSync(join(sandbox, "inputs"))) {
        await walkEvidence(evidenceRoot, (abs) => {
          const rel = abs.subarray(evidenceRoot.length + 1);
          if (!listed.has(rel.toString("latin1"))) added.push(`inputs/${fsDecode(rel)}`);
        });
        added.sort();
      }
      const metaBytes = Number(streamed.meta.bytes);
      state.inputs = {
        files: total,
        bytes: Number.isFinite(metaBytes) && metaBytes > 0 ? metaBytes : totalBytes,
        unchanged: !changed.length && !missing.length && !added.length && !skipped.length && !unreadable.length && anchored !== false,
        complete: !skipped.length && !unreadable.length,
        changed,
        missing,
        added,
        skipped,
        unreadable,
        checked,
        digests_compared: digests,
        manifest_sha256: streamed.sha256,
        manifest_anchored: anchored,
      };
    }
  }
  state.inputsDone = true;

  // --- the sessions ----------------------------------------------------------
  state.phase = "the session seal";
  const sessionFiles: Custody["sessions"]["files"] = [];
  const sessionWalk = await walkAll(join(sandbox, ".pi-sessions"));
  for (const abs of sessionWalk.files) {
    if (tooLate("the session seal")) {
      sessionFiles.push({ path: relative(sandbox, abs), bytes: (await lstat(abs).catch(() => null))?.size ?? 0, sha256: null });
      continue;
    }
    const hashed = await hashRegular(abs, deadline);
    if (hashed === null) tooLate("the session seal");
    sessionFiles.push({ path: relative(sandbox, abs), bytes: hashed && !("why" in hashed) ? hashed.size : 0, sha256: hashed && !("why" in hashed) ? hashed.sha256 : null });
  }
  const sessionsDigest = createHash("sha256").update(sessionFiles.map((f) => `${f.sha256 ?? "unhashed"}  ${f.path}`).join("\n")).digest("hex");
  state.sessions = { files: sessionFiles, digest: sessionsDigest, not_files: sessionWalk.other };

  // --- the trace and the kept outputs -----------------------------------------
  state.phase = "the trace";
  const refs = new Map<string, string>();
  const rereferenced = new Set<string>();
  const foreign = new Set<string>();
  let lines = 0;
  let unverified = 0;
  let operatorActions = 0;
  let disputed = 0;
  // Numbered lines, per sender: (agent, sid) and the seqs seen. Keyed by the
  // agent the line is attributed to as well as its sid, so a seat that
  // writes lines under another's sid cannot fill that sender's gaps.
  const numbered = new Map<string, { agent: string; sid: string; seqs: Set<number> }>();
  const note = (parsed: Record<string, unknown>) => {
    if (typeof parsed.sid !== "string" || typeof parsed.seq !== "number") return false;
    const agent = String(parsed.agent ?? "?");
    const key = `${agent}\u0000${parsed.sid}`;
    const entry = numbered.get(key) ?? { agent, sid: parsed.sid, seqs: new Set<number>() };
    numbered.set(key, entry);
    const had = entry.seqs.has(parsed.seq);
    entry.seqs.add(parsed.seq);
    return had;
  };
  // Every ledger entry's hash the trace carries. In a microVM run that is
  // the hub's line for each record (agent "system"), which no guest can
  // write; the seat's own `record` line is its guest's word, and a hash only
  // it carries is named, not counted against the ledger. In a host run the
  // record tool's own line is the one there is.
  const hubRecordHashes = new Set<string>();
  const seatRecordHashes = new Set<string>();
  // Lines a sender says it could not deliver (logEvent's count, carried on
  // its next line).
  const senderLost = new Map<string, number>();
  const noteLost = (parsed: Record<string, unknown>) => {
    const n = Number((parsed.args as Record<string, unknown> | undefined)?.trace_lines_lost_before ?? 0);
    if (Number.isFinite(n) && n > 0) senderLost.set(String(parsed.agent ?? "?"), (senderLost.get(String(parsed.agent ?? "?")) ?? 0) + n);
  };
  const noteRecord = (parsed: Record<string, unknown>) => {
    const result = parsed.result as Record<string, unknown> | undefined;
    const args = parsed.args as Record<string, unknown> | undefined;
    if (!result || result.ok !== true || typeof result.hash !== "string" || result.merged === true) return;
    if (parsed.tool === "hub_call" && args?.fn === "recordEntry" && parsed.agent === "system") hubRecordHashes.add(result.hash);
    else if (parsed.tool === "record") seatRecordHashes.add(result.hash);
  };
  // The kept outputs a line names. Only its own agent's (or the harness's)
  // are references: a line from one seat cannot vouch for, or cast doubt
  // on, another seat's output. The first hash a path is named with is the
  // one it was kept under; naming it again with another is said.
  const noteRefs = (parsed: Record<string, unknown>) => {
    const who = String(parsed.agent ?? "");
    for (const [path, sha] of keptOutputRefs(parsed)) {
      const owner = path.split("/")[1];
      if (who !== owner && who !== "system") {
        foreign.add(`${path} (named by ${who || "an unnamed line"})`);
        continue;
      }
      const seen = refs.get(path);
      if (seen === undefined) refs.set(path, sha);
      else if (seen !== sha) rereferenced.add(path);
    }
  };
  // A sender's clock against the collector's: in a VM, the guest's against
  // the host's. The record orders by the collector's; a line whose own time
  // is far from it is said, because a reader of `ts` would be misled.
  const skewed = new Map<string, { lines: number; max: number }>();
  const clockOf = (parsed: Record<string, unknown>) => {
    if (typeof parsed.ts !== "string" || typeof parsed.recv_ts !== "string") return;
    const skew = (Date.parse(parsed.ts) - Date.parse(parsed.recv_ts)) / 1000;
    if (!Number.isFinite(skew) || Math.abs(skew) <= CLOCK_FLAG_SEC) return;
    const agent = String(parsed.agent ?? "?");
    const entry = skewed.get(agent) ?? { lines: 0, max: 0 };
    entry.lines += 1;
    if (Math.abs(skew) > Math.abs(entry.max)) entry.max = Math.round(skew);
    skewed.set(agent, entry);
  };
  // The chain is checked on the same pass, a line at a time: a trace of
  // any size is read without holding it whole.
  let traceAnchor = null;
  try {
    traceAnchor = JSON.parse(await readRegularTextOutside(`${sandbox}.trace-anchor.json`));
  } catch {
    traceAnchor = null;
  }
  const chainCheck = eventChainVerifier(traceAnchor);
  const traceRead = await eachLine(join(sandbox, "traces", "events.jsonl"), (line) => {
    chainCheck.push(line);
    if (!line.trim()) return;
    lines += 1;
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      note(parsed);
      clockOf(parsed);
      noteRefs(parsed);
      noteRecord(parsed);
      noteLost(parsed);
      if (parsed.agent_unverified === true) {
        if (parsed.tool === "operator_action") operatorActions += 1;
        else unverified += 1;
      }
      // The collector's word on a line whose sender claimed another seat.
      if (parsed.claimed_agent) disputed += 1;
    } catch {
      // a line that does not parse is the chain check's business
    }
  });
  const traceProblem = "why" in traceRead && traceRead.why !== "missing" ? traceRead.why : null;
  // Lines the collector never took, kept rather than lost: the shared spill
  // on the host, each agent's own in a VM run, and the harness's own.
  const spills: Custody["trace"]["spilled"] = [];
  const spillPaths = ["work/.trace-spill.jsonl", "traces/system-spill.jsonl", "traces/hub-spill.jsonl", ...(await readdir(join(sandbox, "tool-output")).catch(() => [])).map((a) => `tool-output/${a}/trace-spill.jsonl`)];
  for (const rel of spillPaths) {
    // A seat can leave anything at its spill's path: a link to a host file,
    // a FIFO that would hold the read forever. Only a regular file is read.
    const owner = rel.match(/^tool-output\/([^/]+)\//)?.[1] ?? (rel.startsWith("traces/") ? "system" : null);
    // The shared spill on work/ is a host run's: in a microVM run every seat
    // spills into its own directory and the hub into traces/, so lines there
    // are anybody's and are counted for no one. In a host run it is the
    // panes' fallback: a line there counts only for the agent it names
    // (gaps are keyed by agent and sid), carries no token (the token goes to
    // the collector and nowhere else), and is said to be unauthenticated.
    const nobodys = owner === null && vmRun;
    let count = 0;
    let bad = 0;
    let duplicates = 0;
    const read = await eachLine(join(sandbox, rel), (l) => {
      if (!l.trim()) return;
      count += 1;
      try {
        const parsed = JSON.parse(l) as Record<string, unknown>;
        // A spilled line says whose it is; the directory it sits in says
        // whose it can be. One that names somebody else is not counted for
        // them: it cannot fill their gaps, add to their losses, or put a
        // ledger hash on the trace.
        if (nobodys || (owner && owner !== "system" && parsed.agent !== owner)) {
          bad += 1;
          return;
        }
        // Also in the chain: the collector took it after the sender gave up.
        if (note(parsed)) duplicates += 1;
        noteRecord(parsed);
        noteLost(parsed);
      } catch {
        bad += 1;
      }
    });
    if ("why" in read) {
      if (read.why !== "missing") spills.push({ path: rel, lines: 0, agent: owner, bad: 0, duplicates: 0, refused: read.why });
      continue;
    }
    if (!count) continue;
    spills.push({ path: rel, lines: count, agent: owner, bad, duplicates, ...(owner === null && !vmRun ? { unauthenticated: true as const } : {}) });
  }
  // A process's numbered lines run 1..n; a number missing below its highest
  // is a line that reached neither the chain nor a spill.
  const gaps: Custody["trace"]["gaps"] = [];
  for (const entry of numbered.values()) {
    let top = 0;
    for (const n of entry.seqs) if (n > top) top = n;
    const missing = top - entry.seqs.size;
    if (missing > 0) gaps.push({ sid: entry.sid, agent: entry.agent, missing });
  }
  const clock = [...skewed].map(([agent, e]) => ({ agent, lines: e.lines, max_skew_s: e.max }));
  const chain = chainCheck.finish();
  const chained = chain.ok && chain.chained > 0;
  const chainDetail = traceProblem
    ? `the trace is ${traceProblem}`
    : !lines
      ? !chain.ok
        ? `chain broken at line ${chain.broken_at ?? "?"} (${chain.reason ?? "unknown"})`
        : "no trace"
      : chain.ok
        ? chain.chained > 0
          ? `chain intact, ${chain.chained} of ${chain.total} lines chained${traceAnchor ? ", anchor matches" : ", no anchor"}`
          : "unchained: no collector wrote this trace"
        : `chain broken at line ${chain.broken_at ?? "?"} (${chain.reason ?? "unknown"})`;
  state.traceProblem = traceProblem;
  state.traceAnchored = Boolean(traceAnchor);
  state.trace = {
    lines,
    intact: chained,
    detail: chainDetail,
    unverified,
    operator_actions: operatorActions,
    disputed,
    spilled: spills,
    gaps,
    clock,
    sender_lost: [...senderLost].map(([agent, n]) => ({ agent, lines: n })),
  };

  state.phase = "the kept-output check";
  const missingOut: string[] = [];
  const mismatched: string[] = [];
  const refused: string[] = [];
  let verified = 0;
  state.tool_outputs = { referenced: refs.size, verified, missing: missingOut, mismatched, refused, rereferenced: [...rereferenced].sort(), foreign: [...foreign].sort() };
  for (const [path, sha] of refs) {
    if (tooLate("the kept-output check")) break;
    const where = await confinedOutput(sandbox, path);
    if ("why" in where) {
      (where.why === "missing" ? missingOut : refused).push(where.why === "missing" ? path : `${path} (${where.why})`);
      continue;
    }
    const hashed = await hashRegular(where.abs, deadline);
    if (hashed === null) {
      tooLate("the kept-output check");
      refused.push(`${path} (not checked: the deadline passed)`);
      continue;
    }
    if ("why" in hashed) refused.push(`${path} (${hashed.why})`);
    else if (hashed.sha256 !== sha) mismatched.push(path);
    else verified += 1;
    state.tool_outputs.verified = verified;
  }
  state.tool_outputs.verified = verified;

  // --- the ledger --------------------------------------------------------------
  state.phase = "the ledger";
  const ledgerRead = await readRegularText(join(sandbox, "ledger", "entries.jsonl"));
  const ledgerText = "text" in ledgerRead ? ledgerRead.text : "";
  // What the ledger is held to. A microVM run's is the hub's lines; one
  // whose hub logged none (an older run) falls back to the seats' own lines,
  // and says so.
  const traceUsable = !traceProblem && lines > 0;
  const heldTo: NonNullable<Custody["ledger"]>["held_to"] = !traceUsable
    ? "nothing (no readable trace)"
    : !vmRun
      ? "the record tool's lines"
      : hubRecordHashes.size || !seatRecordHashes.size
        ? "the hub's lines"
        : "the seats' own lines (the hub logged none)";
  const recordHashes = heldTo === "the hub's lines" ? hubRecordHashes : heldTo === "nothing (no readable trace)" ? new Set<string>() : seatRecordHashes;
  if ("why" in ledgerRead && ledgerRead.why !== "missing") {
    state.ledger = { entries: 0, chained: 0, intact: false, detail: `the ledger is ${ledgerRead.why}`, missing_from_ledger: [], not_on_trace: [], held_to: heldTo, claimed_by_seat: [] };
  } else if (ledgerText.trim() || recordHashes.size) {
    const v = verifyLedgerChain(ledgerText);
    // The ledger held to the trace: an entry whose hash the trace carries
    // must be in it (a tail deleted from the file is caught here, which the
    // ledger's own chain cannot see), and every chained entry must be on the
    // trace (one written into the file without the tool is). Version 2
    // entries and the record line's hash shipped together, so a version 2
    // entry the trace never carried was not written by the tool; nor was an
    // older-shaped entry after the first version 2 one.
    const inLedger = new Set(v.hashes);
    const missingFromLedger = [...recordHashes].filter((h) => !inLedger.has(h));
    const notOnTrace: number[] = [];
    if (traceUsable) {
      let seenV2 = false;
      for (const line of ledgerText.split("\n")) {
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line) as { v?: number; seq?: number; hash?: string };
          if (e.v === 2) {
            seenV2 = true;
            if (!e.hash || !recordHashes.has(e.hash)) notOnTrace.push(Number(e.seq));
          } else if (seenV2) notOnTrace.push(Number(e.seq));
        } catch {
          // the chain check names it
        }
      }
    }
    const claimedBySeat = heldTo === "the hub's lines" ? [...seatRecordHashes].filter((h) => !hubRecordHashes.has(h)).sort() : [];
    state.ledger = {
      entries: v.total,
      chained: v.chained,
      intact: v.ok && !missingFromLedger.length && !notOnTrace.length,
      detail: v.ok ? `${v.chained} of ${v.total} entries chained` : `broken at entry ${v.broken_at ?? "?"} (${v.reason ?? "unknown"})`,
      missing_from_ledger: missingFromLedger,
      not_on_trace: notOnTrace,
      held_to: heldTo,
      claimed_by_seat: claimedBySeat,
    };
  } else state.ledger = null;
  state.ledgerDone = true;

  // --- the model gateway's log -----------------------------------------------
  // When the run's model calls went through the host's gateway, its log is
  // the record of what each seat spent: the host's own, in traces/, which no
  // VM writes. Its chain is checked and its hash anchored with the verdict.
  state.phase = "the model gateway log";
  state.model_gateway = null;
  const gatewayPath = join(sandbox, GATEWAY_LOG);
  const gatewayThere = await lstat(gatewayPath).then(() => true, () => false);
  if (gatewayThere && !tooLate("the model gateway log")) {
    const reg = await regular(gatewayPath);
    if (!vmRun) {
      // A host run starts no gateway: a file there is not the harness's.
      state.model_gateway = { lines: 0, intact: false, detail: "not read: a host run has no model gateway, so this file is not the harness's", sha256: null, refused: "in a host run" };
    } else if ("why" in reg) {
      state.model_gateway = { lines: 0, intact: false, detail: `not read: it is ${reg.why}`, sha256: null, refused: reg.why };
    } else {
      const verifier = gatewayChainVerifier();
      const read = await eachLine(gatewayPath, (line) => verifier.line(line));
      if ("why" in read) state.model_gateway = { lines: 0, intact: false, detail: `not read: it is ${read.why}`, sha256: null, refused: read.why };
      else {
        const r = verifier.result();
        // The file's own sha256, over its bytes, for the anchor.
        const digest = await hashRegular(gatewayPath, deadline).catch(() => null);
        state.model_gateway = {
          lines: r.lines,
          intact: r.ok,
          detail: r.ok ? `${r.lines} lines, chain intact` : `chain broken at line ${r.broken_at} (${r.reason})`,
          sha256: digest && "sha256" in digest ? digest.sha256 : null,
        };
      }
    }
  }
  state.gatewayDone = true;

  // --- the VMs -----------------------------------------------------------------
  state.phase = "the VM check";
  const vmDir = join(sandbox, "vm");
  state.vms = null;
  state.vm_records = null;
  if (existsSync(vmDir) && !vmRun) {
    // A host run's panes can write vm/: what is there is theirs, not a VM's
    // record, and none of it goes into the host's verdict.
    state.vm_records = { unreadable: [], no_record: [], ignored: "a vm/ directory in a host run (the panes can write it, so nothing in it is a VM's record)" };
  } else if (existsSync(vmDir)) {
    const vms: NonNullable<Custody["vms"]> = [];
    state.vms = vms;
    const unreadableRecords: string[] = [];
    const snapRoot = await realpath(`${sandbox}.vm-snapshots`).catch(() => null);
    // A loaded disk a killed custody left beside the snapshots is removed first.
    if (snapRoot) {
      for (const name of await readdir(snapRoot).catch(() => [])) {
        if (name.startsWith(".verify-")) await rm(join(snapRoot, name), { recursive: true, force: true }).catch(() => undefined);
      }
    }
    const recorded = new Set<string>();
    for (const name of (await readdir(vmDir)).filter((n) => n.endsWith(".json")).sort()) {
      if (tooLate("the VM check")) break;
      let rec: Record<string, unknown>;
      let recordSha = "";
      const recText = await readRegularText(join(vmDir, name));
      if ("why" in recText) {
        unreadableRecords.push(`${name} (${recText.why})`);
        continue;
      }
      try {
        rec = JSON.parse(recText.text);
        recordSha = createHash("sha256").update(recText.text).digest("hex");
      } catch {
        unreadableRecords.push(`${name} (not valid JSON)`);
        continue;
      }
      if (run && rec.run && rec.run !== run) continue; // another run's record in a reused sandbox
      const agentId = String(rec.agent ?? name.replace(/\.json$/, ""));
      recorded.add(agentId);
      const image = ((rec.image as Record<string, unknown> | undefined)?.manifest_digest as string | null) ?? null;
      const expectedImage = ((rec.image as Record<string, unknown> | undefined)?.expected_digest as string | undefined) ?? null;
      const snap = rec.snapshot as { path?: string; sha256?: string; error?: string } | undefined;
      let snapshot: NonNullable<Custody["vms"]>[number]["snapshot"] = null;
      if (snap?.error) snapshot = { error: snap.error };
      else if (snap?.path && snap.sha256) {
        // Only a file in the run's own snapshot directory, and only a regular one.
        const real = await realpath(snap.path).catch(() => null);
        const refusal = !real
          ? "gone"
          : !snapRoot || !real.startsWith(`${snapRoot}/`)
            ? "outside the run's snapshot directory"
            : !basename(real).endsWith(".msb")
              ? "not a .msb file"
              : null;
        if (refusal) snapshot = { path: snap.path, sha256: snap.sha256, verified: false, msb_verified: null, refused: refusal };
        else {
          const hashed = await hashRegular(real as string, deadline);
          if (hashed === null) tooLate("the snapshot check");
          const ok = !!hashed && !("why" in hashed) && hashed.sha256 === snap.sha256;
          const msb = ok ? await msbSnapshotVerify(real as string, deadline) : { verified: null, note: hashed === null ? "the deadline passed before msb's check" : "not asked: the disk does not match its record" };
          snapshot = {
            path: snap.path,
            sha256: snap.sha256,
            verified: ok,
            msb_verified: msb.verified,
            ...(msb.note ? { msb_note: msb.note } : {}),
            ...(hashed && "why" in hashed ? { refused: hashed.why } : {}),
          };
        }
      }
      const logs: Array<{ path: string; sha256: string }> = [];
      let violations: SecretViolation[] = [];
      const logDir = typeof rec.logs === "string" ? await realpath(rec.logs).catch(() => null) : null;
      if (logDir && snapRoot && logDir.startsWith(`${snapRoot}/`)) {
        for (const abs of await walk(logDir)) {
          const hashed = await hashRegular(abs, deadline);
          if (hashed === null) tooLate("the VM log hash");
          logs.push({ path: relative(dirname(snapRoot), abs), sha256: hashed && !("why" in hashed) ? hashed.sha256 : "unhashed" });
          if (basename(abs) === "runtime.log") {
            let text = "";
            await eachLine(abs, (l) => {
              if (l.includes("secret violation:")) text += `${l}\n`;
            });
            violations = violations.concat(secretViolations(text));
          }
        }
      }
      vms.push({
        agent: agentId,
        record_sha256: recordSha,
        image,
        expected_image: expectedImage,
        stopped: typeof rec.stopped_at === "string",
        kept: typeof rec.kept === "string" ? rec.kept : null,
        snapshot,
        logs,
        secret_violations: markOwnHost(violations, rec.secrets),
        installed_outside: outsideOf(rec.installed_outside_image),
        runtime_changed: rec.runtime_changed && typeof rec.runtime_changed === "object" ? (rec.runtime_changed as { from: string; to: string }) : null,
        msb_db: typeof rec.msb_db === "string" ? rec.msb_db : null,
      });
    }
    // Every agent of a microVM run had a VM: one with no record is named.
    let noRecord: string[] = [];
    if (vmRun) {
      const team = await readRegularText(join(sandbox, "team.json"));
      if ("text" in team) {
        try {
          const ids = ((JSON.parse(team.text) as { agents?: Array<{ id?: unknown }> }).agents ?? []).map((a) => String(a.id ?? "")).filter(Boolean);
          noRecord = ids.filter((id) => !recorded.has(id));
        } catch {
          noRecord = [];
        }
      }
    }
    state.vm_records = { unreadable: unreadableRecords, no_record: tooLate("the VM check") ? [] : noRecord, ignored: null };
  }
  state.vmsDone = true;

  // --- what the run produced -------------------------------------------------------
  state.phase = "the artifact index";
  state.artifacts = null;
  if (!tooLate("the artifact index")) {
    try {
      const index = await hashArtifacts(sandbox, { expiry: deadline });
      if (index.skipped.some((s) => s.reason === "not hashed: the deadline passed")) tooLate("the artifact index");
      const text = `${JSON.stringify(index, null, 2)}\n`;
      writeFileNoFollowSync(sandbox, "artifacts.json", text);
      state.artifacts = { files: index.files.length, bytes: index.bytes, skipped: index.skipped.length, index_sha256: createHash("sha256").update(text).digest("hex") };
    } catch {
      state.artifacts = null;
    }
  }
  state.artifactsDone = true;

  // --- the evidence-work store ---------------------------------------------------------
  state.phase = "the store";
  state.store = null;
  if (!tooLate("the store")) {
    try {
      state.store = await checkStore(sandbox, Date.now() + deadline.remainingMs);
      if (state.store && state.store.outputs.verified + state.store.outputs.mismatched.length + state.store.outputs.missing.length < state.store.outputs.files) tooLate("the store");
    } catch {
      state.store = null;
    }
  }
  state.storeDone = true;

  state.phase = "writing the verdict";
  const custody = verdictOf(state, state.incomplete ?? null);
  const written = writeVerdict(sandbox, anchorFile, custody);
  if (!written.anchored) say(`custody: WARN: the verdict could not be added to the anchor outside the run (${written.why}); custody.json cannot be checked against it`);
  return custody;
}

/** A file beside the run (an anchor), read as a regular file: an anchor that is a link is no anchor. */
async function readRegularTextOutside(path: string): Promise<string> {
  const read = await readRegularText(path);
  if ("why" in read) throw new Error(read.why);
  return read.text;
}

/**
 * The verdict from what was found, whole or not. A part custody never
 * reached is named as not reached rather than given an empty result that
 * would read as nothing wrong.
 */
export function verdictOf(state: CustodyState, incomplete: string | null): Custody {
  const notReached: string[] = [];
  if (!state.inputsDone) notReached.push("the evidence");
  if (!state.sessions) notReached.push("the sessions");
  if (!state.trace) notReached.push("the trace");
  if (!state.tool_outputs) notReached.push("the kept outputs");
  if (!state.ledgerDone) notReached.push("the ledger");
  if (!state.vmsDone) notReached.push("the VMs");
  if (!state.artifactsDone) notReached.push("the artifact index");
  if (!state.gatewayDone && state.sandbox && existsSync(join(state.sandbox, GATEWAY_LOG))) notReached.push("the model gateway log");
  if (!state.storeDone && state.sandbox && existsSync(join(state.sandbox, "store", "journal.jsonl"))) notReached.push("the store");
  const inputs = state.inputs ?? null;
  const sessions = state.sessions ?? { files: [], digest: "", not_files: [] };
  const toolOutputs = state.tool_outputs ?? { referenced: 0, verified: 0, missing: [], mismatched: [], refused: [], rereferenced: [], foreign: [] };
  const trace = state.trace ?? { lines: 0, intact: false, detail: "not checked", unverified: 0, operator_actions: 0, disputed: 0, spilled: [], gaps: [], clock: [], sender_lost: [] };
  const c: Omit<Custody, "summary"> = {
    at: new Date().toISOString(),
    run: state.run ?? null,
    isolation: state.isolation ?? null,
    previous: state.previous ?? null,
    inputs,
    sessions,
    tool_outputs: toolOutputs,
    trace,
    ledger: state.ledger ?? null,
    vms: state.vms ?? null,
    vm_records: state.vm_records ?? null,
    artifacts: state.artifacts ?? null,
    model_gateway: state.model_gateway ?? null,
    store: state.store ?? null,
    not_reached: notReached,
    incomplete,
  };
  return { ...c, summary: summaryOf(c, { traceProblem: state.traceProblem ?? null, traceAnchored: state.traceAnchored ?? false }) };
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

function summaryOf(c: Omit<Custody, "summary">, t: { traceProblem: string | null; traceAnchored: boolean }): string {
  const parts: string[] = [];
  const reached = (part: string) => !c.not_reached.includes(part);
  const inputs = c.inputs;
  if (!reached("the evidence")) {
    // said with the rest of what was not reached, below
  } else if (inputs && "unverifiable" in inputs) parts.push(`EVIDENCE UNVERIFIABLE: ${inputs.unverifiable}`);
  else if (inputs) {
    const changedAny = inputs.changed.length || inputs.missing.length || inputs.added.length || inputs.manifest_anchored === false;
    const unreadable = inputs.unreadable ?? [];
    const how = [
      `${plural(inputs.checked?.files ?? inputs.files, "file")} re-hashed in full`,
      ...(inputs.checked?.links ? [`${plural(inputs.checked.links, "link")} checked by target`] : []),
      ...(inputs.checked?.special ? [`${plural(inputs.checked.special, "special file")} checked by kind`] : []),
      ...(inputs.digests_compared?.md5 || inputs.digests_compared?.sha1
        ? [`md5 on ${inputs.digests_compared.md5} and sha1 on ${inputs.digests_compared.sha1} compared too`]
        : []),
    ];
    parts.push(inputs.unchanged
      ? `evidence unchanged (${how.join(", ")}${inputs.manifest_anchored === true ? ", manifest anchored" : inputs.manifest_anchored === null ? ", manifest not anchored" : ""})`
      : changedAny
        ? `EVIDENCE CHANGED: ${inputs.changed.length} changed, ${inputs.missing.length} missing, ${inputs.added.length} added${inputs.manifest_anchored === false ? ", MANIFEST REWRITTEN" : ""}${inputs.skipped.length ? `; ${inputs.skipped.length} NOT RE-READ` : ""}${unreadable.length ? `; ${unreadable.length} UNREADABLE BY THE HOST (${unreadable.join(", ")})` : ""}`
        : `EVIDENCE NOT FULLY RE-HASHED: ${inputs.files - inputs.skipped.length - unreadable.length} of ${inputs.files} checked unchanged${inputs.skipped.length ? `, ${inputs.skipped.length} not re-read before the deadline` : ""}${unreadable.length ? `, ${unreadable.length} unreadable by the host (${unreadable.join(", ")})` : ""}${inputs.manifest_anchored === null ? ", manifest not anchored" : ""}`);
  }
  if (reached("the sessions")) {
    parts.push(`${plural(c.sessions.files.length, "session file")} sealed${c.sessions.not_files.length ? `, ${c.sessions.not_files.length} NOT A FILE (${c.sessions.not_files.join(", ")})` : ""}`);
  }
  if (reached("the kept outputs")) {
    const o = c.tool_outputs;
    parts.push(o.missing.length || o.mismatched.length || o.refused.length
      ? `KEPT OUTPUTS: ${o.verified}/${o.referenced} verified, ${o.missing.length} missing, ${o.mismatched.length} not matching the trace, ${o.refused.length} refused`
      : `${o.verified}/${o.referenced} kept outputs verified`);
    if (o.rereferenced.length) parts.push(`KEPT OUTPUT NAMED AGAIN WITH ANOTHER HASH: ${o.rereferenced.join(", ")} (checked against the hash it was kept under)`);
    if (o.foreign.length) parts.push(`${plural(o.foreign.length, "kept-output reference")} from an agent whose directory it is not, ignored: ${o.foreign.join(", ")}`);
  }
  if (reached("the trace")) {
    const tr = c.trace;
    if (t.traceProblem) parts.push(`TRACE UNREADABLE: ${t.traceProblem}`);
    else if (!tr.lines) parts.push(tr.detail.startsWith("chain broken") ? `NO TRACE, AND THE ANCHOR NAMES ONE: ${tr.detail}` : "NO TRACE");
    else if (tr.intact) parts.push(`trace ${tr.lines} lines, chain intact${t.traceAnchored ? "" : " (no anchor)"}${tr.unverified ? `, ${tr.unverified} unverified` : ""}${tr.operator_actions ? `, ${plural(tr.operator_actions, "operator action")} from a shell outside the run` : ""}${tr.disputed ? `, ${tr.disputed} disputed` : ""}`);
    else if (!tr.detail.startsWith("chain broken")) parts.push(`TRACE UNCHAINED (${tr.lines} lines)`);
    else parts.push("TRACE CHAIN BROKEN");
    const spilled = tr.spilled.reduce((n, s) => n + s.lines, 0);
    const badSpill = tr.spilled.reduce((n, s) => n + s.bad, 0);
    const dupSpill = tr.spilled.reduce((n, s) => n + s.duplicates, 0);
    if (spilled) parts.push(`${plural(spilled, "trace line")} outside the chain (spilled: ${tr.spilled.filter((s) => s.lines).map((s) => (s.unauthenticated ? `${s.path}, which any pane can write` : s.path)).join("; ")})${dupSpill ? `, ${dupSpill} also in the chain` : ""}${badSpill ? `, ${badSpill} NOT ATTRIBUTABLE` : ""}`);
    const refusedSpills = tr.spilled.filter((s) => s.refused);
    if (refusedSpills.length) parts.push(`SPILL NOT READ: ${refusedSpills.map((s) => `${s.path} is ${s.refused}`).join("; ")}`);
    if (tr.clock.length) parts.push(`sent with a clock more than ${CLOCK_FLAG_SEC} s off the host's: ${tr.clock.map((x) => `${x.agent} ${plural(x.lines, "line")} (up to ${x.max_skew_s} s)`).join(", ")}; the record orders by the host's recv_ts`);
    const lost = tr.gaps.reduce((n, g) => n + g.missing, 0);
    if (lost) parts.push(`${lost} TRACE LINE${lost === 1 ? "" : "S"} LOST (numbered but in neither the chain nor a spill: ${tr.gaps.map((g) => `${g.agent} ${g.missing}`).join(", ")})`);
    if (tr.sender_lost.length) parts.push(`TRACE LINES THE SENDER COULD NOT WRITE: ${tr.sender_lost.map((s) => `${s.agent} ${s.lines}`).join(", ")}`);
  }
  if (c.ledger) {
    const l = c.ledger;
    const chainedPart = l.chained === l.entries ? "all chained" : `${l.chained} of ${l.entries} chained`;
    if (l.intact) parts.push(`ledger ${l.entries} entries, ${chainedPart}, chain intact${l.held_to === "nothing (no readable trace)" ? " (not held to the trace: there is no readable trace)" : l.held_to === "the seats' own lines (the hub logged none)" ? " (held to the seats' own lines: the hub logged none)" : ""}`);
    else if (l.missing_from_ledger.length || l.not_on_trace.length) {
      parts.push(`LEDGER DIFFERS FROM THE TRACE: ${l.missing_from_ledger.length} entr${l.missing_from_ledger.length === 1 ? "y" : "ies"} on the trace missing from the ledger, ${l.not_on_trace.length} in the ledger never on the trace${l.not_on_trace.length ? ` (seq ${l.not_on_trace.join(", ")})` : ""}${l.detail.startsWith("broken") ? `; LEDGER CHAIN BROKEN ${l.detail}` : ""}`);
    } else parts.push(`LEDGER CHAIN BROKEN (${l.detail})`);
    if (l.claimed_by_seat.length) parts.push(`${plural(l.claimed_by_seat.length, "ledger hash", "ledger hashes")} a seat's own record line carried and the hub never logged (a guest's word, not counted against the ledger)`);
  }
  if (c.model_gateway) {
    const g = c.model_gateway;
    parts.push(g.refused ? `MODEL GATEWAY LOG NOT READ: ${g.detail.replace(/^not read: /, "")}` : g.intact ? `model gateway log ${plural(g.lines, "line")}, chain intact` : `MODEL GATEWAY LOG CHAIN BROKEN (${g.detail})`);
  }
  if (c.vm_records?.ignored) parts.push(`VM RECORDS NOT READ: ${c.vm_records.ignored}`);
  if (c.vms) {
    const vms = c.vms;
    const snapOf = (v: (typeof vms)[number]) => (v.snapshot && "verified" in v.snapshot ? v.snapshot : null);
    const kept = vms.filter((v) => snapOf(v)?.verified).length;
    const byMsb = vms.filter((v) => snapOf(v)?.msb_verified === true).length;
    const msbFailed = vms.filter((v) => snapOf(v)?.msb_verified === false);
    const msbNotRun = vms.filter((v) => snapOf(v)?.verified && snapOf(v)?.msb_verified === null);
    const mismatch = vms.filter((v) => snapOf(v) && !snapOf(v)?.verified && !snapOf(v)?.refused);
    const refusedSnap = vms.filter((v) => snapOf(v)?.refused);
    const failed = vms.filter((v) => (v.snapshot && "error" in v.snapshot) || v.kept || !v.stopped);
    parts.push(`${plural(vms.length, "VM")}, ${kept} of ${vms.length} snapshots verified against their record, ${byMsb} by msb's own integrity check${msbFailed.length ? `, ${msbFailed.length} FAILED MSB'S CHECK (${msbFailed.map((v) => v.agent).join(", ")})` : ""}${mismatch.length ? `, SNAPSHOT DOES NOT MATCH ITS RECORD (${mismatch.map((v) => v.agent).join(", ")})` : ""}${refusedSnap.length ? `, SNAPSHOT NOT READ (${refusedSnap.map((v) => `${v.agent}: ${snapOf(v)?.refused}`).join("; ")})` : ""}${msbNotRun.length ? `, ${msbNotRun.length} not checked by msb (${msbNotRun.map((v) => `${v.agent}: ${snapOf(v)?.msb_note ?? "no answer"}`).join("; ")})` : ""}${failed.length ? `, ${failed.length} NOT PUT AWAY (${failed.map((v) => v.agent).join(", ")})` : ""}`);
    const offImage = vms.filter((v) => v.expected_image && v.image && v.image !== v.expected_image);
    if (offImage.length) parts.push(`IMAGE DIGEST DIFFERS: ${offImage.map((v) => `${v.agent} booted ${v.image}, not ${v.expected_image}`).join("; ")}`);
    const moved = vms.filter((v) => v.runtime_changed);
    if (moved.length) parts.push(`MSB CHANGED DURING THE RUN: ${moved.map((v) => `${v.agent} ${v.runtime_changed?.from} → ${v.runtime_changed?.to}`).join("; ")}`);
    const outside = vms.filter((v) => v.installed_outside.apt.length || v.installed_outside.venv.length);
    if (outside.length) {
      parts.push(`INSTALLED OUTSIDE THE IMAGE AND THE TOOLCHAIN RECORD: ${outside.map((v) => `${v.agent} ${[...v.installed_outside.apt.map((p) => `apt ${p}`), ...v.installed_outside.venv.map((p) => `venv ${p}`)].join(", ")}`).join("; ")}`);
    }
    // msb keeps a VM's secret values in its database while the VM lives; a
    // finish that removed VMs rewrites it without them. One that could not
    // (another msb held it, no sqlite3) left them there.
    const unscrubbed = vms.filter((v) => v.msb_db && v.msb_db !== "scrubbed" && v.msb_db !== "no database");
    if (unscrubbed.length) parts.push(`MSB'S DATABASE NOT CLEARED after removing ${unscrubbed.map((v) => `${v.agent} (${v.msb_db})`).join(", ")}: a secret's value may remain in msb's database`);
    const line = (agent: string, x: SecretViolation) => `${agent} ${x.env} → ${x.host} ${x.method} ${x.path}${x.location ? ` (${x.location})` : ""}`.trim();
    const sv = vms.flatMap((v) => v.secret_violations.filter((x) => x.own_host !== true).map((x) => line(v.agent, x)));
    if (sv.length) parts.push(`${sv.length} SECRET PLACEHOLDER${sv.length === 1 ? "" : "S"} AIMED AT A HOST NOT ITS OWN, stopped by msb: ${sv.join("; ")}`);
    const own = vms.flatMap((v) => v.secret_violations.filter((x) => x.own_host === true).map((x) => line(v.agent, x)));
    // Not a leak: the host is the one the credential is bound to. msb 0.7.2
    // stops these when it finds the placeholder outside the headers, which
    // it also reported, wrongly, for a body starting with % or \u.
    if (own.length) parts.push(`msb stopped ${own.length} request${own.length === 1 ? "" : "s"} to a credential's own host on a placeholder it found outside the headers (not a leak; each request failed): ${own.join("; ")}`);
  }
  if (c.vm_records?.unreadable.length) parts.push(`VM RECORD UNREADABLE: ${c.vm_records.unreadable.join(", ")}`);
  if (c.vm_records?.no_record.length) parts.push(`NO VM RECORD FOR: ${c.vm_records.no_record.join(", ")}`);
  if (c.artifacts) parts.push(`${plural(c.artifacts.files, "work file")} indexed (artifacts.json)${c.artifacts.skipped ? `, ${c.artifacts.skipped} not hashed (links, special files, or the deadline; named there)` : ""}`);
  if (c.store) {
    const st = c.store;
    const j = st.journal;
    const anchor = j.anchor === "matches" ? "its anchor matches" : j.anchor === "behind" ? "its anchor one step behind (a crash between two writes, recovered)" : j.anchor === "missing" ? "NO JOURNAL ANCHOR" : "JOURNAL ANCHOR OFF THE CHAIN";
    const bits = [`store: ${plural(st.jobs, "job")}, ${st.committed} committed, journal ${plural(j.lines, "line")} ${j.intact ? "chain intact" : `CHAIN BROKEN (${j.detail})`}, ${anchor}`];
    bits.push(`${st.outputs.verified} of ${plural(st.outputs.files, "output file")} verified against their manifests`);
    // A long list is named in part here and whole in custody.json.
    const some = (xs: Array<string | number>, n: number, where: string) => `${xs.slice(0, n).join(", ")}${xs.length > n ? `, … all ${xs.length} in custody.json ${where}` : ""}`;
    if (st.outputs.mismatched.length) bits.push(`${st.outputs.mismatched.length} OUTPUT FILE(S) CHANGED SINCE SEALED (${some(st.outputs.mismatched, 5, "store.outputs.mismatched")})`);
    if (st.outputs.missing.length) bits.push(`${st.outputs.missing.length} OUTPUT FILE(S) MISSING`);
    if (st.manifests_missing.length) bits.push(`${st.manifests_missing.length} MANIFEST(S) MISSING`);
    if (j.repaired || j.anchor_mismatch) bits.push(`the journal recorded ${j.repaired} repair(s) and ${j.anchor_mismatch} anchor mismatch(es)`);
    if (st.staging_left.length) bits.push(`${st.staging_left.length} job staging director${st.staging_left.length === 1 ? "y" : "ies"} left unsealed (${some(st.staging_left, 5, "store.staging_left")})`);
    bits.push(`${plural(st.generations, "catalogue generation")}, ${plural(st.revisions, "revision")}`);
    if (st.findings.total) {
      const f = st.findings;
      const parts = [`${f.structured} with refs${f.refs_invalid.length ? ` (${f.refs_invalid.length} NO LONGER RESOLVE: ledger seq ${some(f.refs_invalid, 20, "store.findings.refs_invalid")})` : ""}${f.unresolved_only.length ? `, ${f.unresolved_only.length} of them saying only why no object can be named` : ""}`];
      if (f.path_only.length) parts.push(`${f.path_only.length} naming a path in prose only`);
      parts.push(f.without_refs.length ? `${f.without_refs.length} citing no object of the run (ledger seq ${some(f.without_refs, 20, "store.findings.without_refs")}): an audit gap` : "none citing nothing");
      bits.push(`${plural(f.total, "standing finding")}: ${parts.join(", ")}`);
    }
    if (st.catalogue) {
      const c = st.catalogue;
      const bad = [...c.revisions_mismatched, ...c.generations_mismatched];
      bits.push(`catalogue: ${plural(c.revisions_verified, "revision")} and ${plural(c.generations_verified, "generation")} held to the journal${bad.length ? `, ${bad.length} NOT MATCHING (${some(bad, 10, "store.catalogue")})` : ""}`);
    }
    if (st.derived && (st.derived.offered || st.derived.skipped)) {
      const d = st.derived;
      bits.push(`derived catalogue: ${d.offered} object(s) offered (${d.skipped} skipped as known), ${d.detected} pair(s) answered (${d.applied} applied), ${d.catalogued} catalogued complete and ${d.partial} in part, ${d.unanswered} unanswered${d.deferred ? `, deferred by its budget ${d.deferred} time(s)` : ""}${d.bounded.length ? `, STOPPED at its ${d.bounded.join(" and ")} ceiling` : ""}`);
    }
    if (st.degraded) bits.push(`the job service told the agents ${st.degraded} time(s) that workers were not running`);
    if (st.notes) bits.push(`${plural(st.notes, "examiner note")} added to the record after the run`);
    parts.push(bits.join(", "));
  }
  if (c.not_reached.length) parts.push(`NOT CHECKED BEFORE CUSTODY ENDED: ${c.not_reached.join(", ")}`);
  if (c.incomplete) parts.push(`CUSTODY INCOMPLETE: ${c.incomplete}`);
  return parts.join(" · ");
}

/**
 * `custody.json` and its hash beside the kickoff's anchor, outside the run.
 * Synchronous, so the hard deadline's timer can write a verdict while every
 * I/O thread is held by a read that never returns.
 */
function writeVerdict(sandbox: string, anchorFile: string, custody: Custody): { anchored: boolean; why?: string } {
  const text = `${JSON.stringify(custody, null, 2)}\n`;
  writeFileNoFollowSync(sandbox, CUSTODY_REL, text);
  // The verdict's hash goes beside the kickoff's anchor, outside the run: a
  // custody.json edited after the stop no longer matches what stop wrote,
  // and the report, the summary and the console say so.
  try {
    anchorVerdict(anchorFile, {
      at: custody.at,
      sha256: createHash("sha256").update(text).digest("hex"),
      summary: custody.summary,
      snapshots: (custody.vms ?? []).flatMap((v) => (v.snapshot && "sha256" in v.snapshot ? [{ agent: v.agent, sha256: v.snapshot.sha256 }] : [])),
      sessions_digest: custody.sessions.digest,
      artifacts_sha256: custody.artifacts?.index_sha256 ?? null,
      ...(custody.model_gateway ? { model_gateway: { sha256: custody.model_gateway.sha256, lines: custody.model_gateway.lines, intact: custody.model_gateway.intact } } : {}),
    });
    return { anchored: true };
  } catch (err) {
    return { anchored: false, why: (err as Error).message };
  }
}

/** Add a verdict to the anchor file outside the run; the kickoff's fields stay as they were. */
function anchorVerdict(anchorFile: string, verdict: Record<string, unknown>): void {
  let anchor: Record<string, unknown> = {};
  try {
    anchor = JSON.parse(readFileSync(anchorFile, "utf8"));
  } catch {
    anchor = {};
  }
  const verdicts = Array.isArray(anchor.custody) ? (anchor.custody as unknown[]) : [];
  verdicts.push(verdict);
  writeFileNoFollowSync(dirname(anchorFile), basename(anchorFile), `${JSON.stringify({ ...anchor, custody: verdicts }, null, 2)}\n`, 0o444);
}

export type VerdictAnchor =
  | { state: "matches"; at: string }
  | { state: "differs"; at: string | null; note: string }
  | { state: "not anchored" }
  | { state: "no verdict" };

/**
 * Whether the `custody.json` in the run is the verdict custody last wrote:
 * its sha256 against the last one added to the anchor outside the run. The
 * report, the summary and the console print custody.json; this is what lets
 * them say it is the host's, and not a file edited after the stop.
 */
export async function verdictAnchorState(sandboxInput: string): Promise<VerdictAnchor> {
  const sandbox = resolve(sandboxInput);
  const hashed = await hashRegularFile(join(sandbox, CUSTODY_REL));
  if (hashed === null || "why" in hashed) return { state: "no verdict" };
  let verdicts: Array<{ at?: unknown; sha256?: unknown }> = [];
  try {
    const anchor = JSON.parse(await readRegularTextOutside(await anchorPathFor(sandbox))) as { custody?: unknown };
    verdicts = Array.isArray(anchor.custody) ? (anchor.custody as Array<{ at?: unknown; sha256?: unknown }>) : [];
  } catch {
    verdicts = [];
  }
  if (!verdicts.length) return { state: "not anchored" };
  const last = verdicts.at(-1) as { at?: unknown; sha256?: unknown };
  if (last.sha256 === hashed.sha256) return { state: "matches", at: String(last.at ?? "") };
  const earlier = [...verdicts].reverse().find((v) => v.sha256 === hashed.sha256);
  return {
    state: "differs",
    at: typeof last.at === "string" ? last.at : null,
    note: earlier
      ? `it is an earlier verdict (${String(earlier.at ?? "?")}), not the last one custody anchored`
      : "it is not a verdict custody anchored: it was changed after custody wrote it",
  };
}

/** The anchor state in words, for a report row or a summary line. */
export function verdictAnchorLine(v: VerdictAnchor): string {
  switch (v.state) {
    case "matches":
      return "matches the verdict anchored outside the run";
    case "differs":
      return `DOES NOT MATCH the verdict anchored outside the run${v.at ? ` at ${v.at}` : ""}: ${v.note}`;
    case "not anchored":
      return "no anchored verdict to check it against";
    default:
      return "";
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const args = process.argv.slice(2);
  const sandbox = args.find((a) => !a.startsWith("--"));
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  if (!sandbox || !existsSync(sandbox)) {
    console.error("usage: custody.ts <sandbox> [--timeout SEC] [--run ID] [--quiet]");
    process.exit(2);
  }
  const timeoutSec = opt("--timeout") ? Number(opt("--timeout")) : 4 * 3600;
  const state: CustodyState = { phase: "starting" };
  // What was found before custody ended, written as its verdict: the part
  // done is not lost with the part that could not be.
  const writePartial = (why: string): string | null => {
    try {
      if (!state.sandbox || !state.anchorFile) return null;
      const c = verdictOf(state, why);
      writeVerdict(state.sandbox, state.anchorFile, c);
      return c.summary;
    } catch (err) {
      console.error(`custody: the partial verdict could not be written: ${(err as Error).message}`);
      return null;
    }
  };
  // The hard deadline: the soft one is checked between and inside reads, and
  // anything that still holds the process past it plus a grace period ends
  // it, so a stop is never held by custody.
  const hard = setTimeout(() => {
    const why = `still running ${HARD_GRACE_SEC} s past its ${timeoutSec} s deadline, during ${state.phase}; ended`;
    console.error(`custody: CUSTODY INCOMPLETE: ${why}`);
    const summary = writePartial(why);
    if (summary) console.log(summary);
    process.exit(3);
  }, (timeoutSec + HARD_GRACE_SEC) * 1000);
  hard.unref();
  // A stop's timeout wrapper, or ^C, ends custody with a signal: what was
  // found by then is written first, not lost with the process.
  for (const [sig, code] of [["SIGTERM", 143], ["SIGINT", 130]] as const) {
    process.once(sig, () => {
      const summary = writePartial(`ended by ${sig} during ${state.phase}`);
      if (summary) console.log(summary);
      process.exit(code);
    });
  }
  takeCustody(sandbox, { timeoutSec, run: opt("--run"), state, progress: args.includes("--quiet") ? undefined : (line) => console.error(line) })
    .then((c) => {
      console.log(c.summary);
      process.exit(c.incomplete ? 3 : 0);
    })
    .catch((err) => {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`custody: ${message}`);
      const summary = writePartial(`custody failed during ${state.phase}: ${message}`);
      if (summary) console.log(summary);
      process.exit(1);
    });
}
