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
 * previous verdict is moved aside before anything is checked, with the
 * index it sealed (`artifacts.<its time>.json`), so the `custody.json` in
 * the run is this custody's or none, and every verdict the anchor names
 * keeps the index it sealed. Adds the verdict's sha256 to the anchor the
 * kickoff wrote outside the run, and prints its summary line.
 *
 *   node --experimental-strip-types scripts/custody.ts <sandbox> [--timeout SEC] [--run ID] [--quiet]
 */
import { isUtf8 } from "node:buffer";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { lstat, mkdtemp, readdir, readlink, realpath, rename, rm, unlink } from "node:fs/promises";
import { createInterface } from "node:readline";
import { StringDecoder } from "node:string_decoder";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { eventChainVerifier, HARNESS_RECORD_TOOL, specialKind, verifyAttestationChain, verifyDisputeChain, verifyLedgerChain } from "../extensions/protocol.ts";
import { verifyLeadChain } from "../extensions/leads.ts";
import { LEDGER_SWEEPS, verifySweepChain } from "../extensions/store-sweep.ts";
import { FINISH_LOG } from "../extensions/finish.ts";
import { checkNetwork, FETCH_LOG, GRANTS_LOG, type NetworkCheck } from "./net-grants.ts";
import { hashArtifacts, type ArtifactIndex } from "./artifacts.ts";
import { checkStore, verifyJournalText, type StoreCheck } from "./evidence-store.ts";
import {
  afterSeal,
  checksLine,
  checksOf,
  compareAcquisition,
  referenceOffset,
  signFile,
  timestampFile,
  verifyOperatorAudit,
  verifyTimestampToken,
  type Acquisition,
  type Check,
  type OperatorAudit,
  type TraceAction,
} from "./custody-checks.ts";
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
 * its real path. So may each of several sets directly under it: `sets` are
 * those names (latin1 keys of their bytes, as the manifest lists them), and
 * a link by one of them at the top is walked through as the set it is.
 */
async function walkEvidence(root: Buffer, onName: (abs: Buffer) => void, sets: Set<string> = new Set()): Promise<void> {
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
      const name = entry.name as unknown as Buffer;
      const abs = Buffer.concat([dir, SLASH, name]);
      if (entry.isDirectory() || (dir === root && entry.isSymbolicLink() && sets.has(name.toString("latin1")))) stack.push(abs);
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

/**
 * The links the evidence is read through, held to what the kickoff
 * recorded: inputs/ itself when the evidence was held in place as one set
 * (`held: "bind"`, or a link where the manifest names one source), or each
 * inputs/<name> of several sets (inputs.json `sets`: name and source). Each
 * must still be a link whose target is the source recorded, and resolve to
 * it. A set that was copied in is a directory of the run's own, with no link
 * to check.
 */
export async function evidenceLinks(sandbox: string, meta: Record<string, unknown>): Promise<{ checked: number; moved: string[] }> {
  const moved: string[] = [];
  let checked = 0;
  const bound = meta.held === "bind" || meta.bound === true;
  const targets: Array<{ rel: string; source: string }> = [];
  const sets = Array.isArray(meta.sets) ? (meta.sets as Array<{ name?: unknown; source?: unknown }>) : [];
  for (const s of sets) {
    if (typeof s?.name === "string" && s.name && !s.name.includes("/") && s.name !== ".." && typeof s.source === "string") targets.push({ rel: `inputs/${s.name}`, source: s.source });
  }
  if (!sets.length && typeof meta.source === "string" && meta.source) {
    const top = await lstat(join(sandbox, "inputs")).catch(() => null);
    if (bound || top?.isSymbolicLink()) targets.push({ rel: "inputs", source: meta.source });
  }
  for (const t of targets) {
    const lst = await lstat(join(sandbox, t.rel)).catch(() => null);
    if (!lst) {
      moved.push(`${t.rel} is gone (it led to ${t.source})`);
      continue;
    }
    if (!lst.isSymbolicLink()) {
      // A set copied in is the run's own directory; held in place, a link was made, and something else is there now.
      if (bound) moved.push(`${t.rel} is no longer the link to ${t.source} the kickoff made: a ${lst.isDirectory() ? "directory" : "file"} is there`);
      continue;
    }
    const target = await readlink(join(sandbox, t.rel)).catch(() => null);
    const real = await realpath(join(sandbox, t.rel)).catch(() => null);
    // The source as recorded, resolved the same way: a recorded path through a link of the system (/var on macOS) is the same place.
    const source = await realpath(t.source).catch(() => t.source);
    if (real === null) moved.push(`${t.rel} leads to ${target ?? "?"}, which is not there now (the kickoff recorded ${t.source})`);
    else if (real !== source) moved.push(`${t.rel} leads to ${real}${target !== real ? ` (through ${target})` : ""}, not ${t.source}, the source the kickoff recorded`);
    else checked += 1;
  }
  return { checked, moved };
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
        /**
         * The evidence held in place: inputs/ (one set) or each
         * inputs/<set> (several) is a link the kickoff made to the source
         * inputs.json records. How many were checked, and each that leads
         * elsewhere now (or nowhere, or is no longer a link). A copy or an
         * attached image has none. Absent from a verdict taken before this
         * was checked.
         */
        links?: { checked: number; moved: string[] };
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
    /** Lines the harness spilled while no collector was up, chained afterwards by `swarm.sh stop` (trace-collector.mjs --gather): each marked `gathered` with its spill and its own sha256. */
    gathered?: number;
    /** `unauthenticated`: a host run's shared spill, which any pane can write and whose lines carry no token (only the collector ever sees one). */
    spilled: Array<{ path: string; lines: number; agent: string | null; bad: number; duplicates: number; refused?: string; unauthenticated?: true; after_close?: number }>;
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
    /** Entries whose hash the trace carries (the record tool's line, the hub's, or the harness's `harness_record` line) but the ledger does not: deleted. */
    missing_from_ledger: string[];
    /** Chained entries the trace never carried: written into the file without the tool, the hub or the harness's own line. */
    not_on_trace: number[];
    /** Whether the ledger could be held to the trace at all (a readable trace), and to whose lines (beside them, always, the harness's `harness_record` lines for the entries it authored). */
    held_to: "the hub's lines" | "the record tool's lines" | "the seats' own lines (the hub logged none)" | "nothing (no readable trace)";
    /** Hashes a seat's own `record` (or `harness_record`) line carried that the hub never logged: a guest's word, not counted against the ledger. */
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
  /**
   * What the verdict sealed: each chain's length and head as custody read it,
   * so a later check knows what was sealed and names what was added after
   * (the hub's own custody and clear-up lines, the operator's stop) instead
   * of reading it as a changed record.
   */
  seal: {
    trace: { lines: number; bytes: number; last_line_sha256: string | null };
    ledger: { entries: number; head: string | null };
    attestations: { lines: number; head: string | null };
    /** The agents' disputes (ledger/disputes.jsonl, ledger version 4): absent from a verdict taken before they were sealed. */
    disputes?: { lines: number; head: string | null };
    /** The lead register (leads/leads.jsonl): absent from a verdict taken before it was sealed. */
    leads?: { lines: number; head: string | null };
    /** The question register (questions/questions.jsonl): absent from a verdict taken before it was sealed. */
    questions?: { lines: number; head: string | null };
    /** The dynamic network's two chains (network/grants.jsonl, network/fetches.jsonl): absent from a verdict taken before they were sealed. */
    network?: { grants: { lines: number; head: string | null }; fetches: { lines: number; head: string | null } };
    /** The operator requests' chain (requests/requests.jsonl, docs/adr/0014): absent from a verdict taken before it was sealed. */
    requests?: { lines: number; head: string | null };
    /** The store sweeps' chain (ledger/sweeps.jsonl, docs/adr/0013): absent from a verdict taken before it was sealed. */
    sweeps?: { lines: number; head: string | null };
    /** The finish register (leads/finish.jsonl, docs/adr/0015): absent from a verdict taken before it was sealed. */
    finish?: { lines: number; head: string | null };
    /** The case policy's record (network/policy.json) by its sha256: absent from a verdict taken before it was sealed. */
    case_policy?: { sha256: string };
    journal: { lines: number; head: string | null } | null;
    model_gateway: { lines: number; sha256: string | null } | null;
  };
  /** The ledger's attestations (a second author of an entry, appended beside it): their own chain. */
  attestations: { lines: number; intact: boolean; detail: string } | null;
  /** The agents' disputes of entries and their withdrawals (ledger/disputes.jsonl): their own chain; null when there are none. */
  disputes?: { lines: number; intact: boolean; detail: string } | null;
  /** The lead register's events (leads/leads.jsonl): their own chain, sealed unsigned; null when the run opened no lead. */
  leads?: { lines: number; intact: boolean; detail: string } | null;
  /** The question register's events (questions/questions.jsonl): their own chain, sealed unsigned (a signed act carries its own signature); null when the run wrote none. */
  questions?: { lines: number; intact: boolean; detail: string } | null;
  /** The dynamic network's records: both chains, and every sealed capture re-hashed; null when the run made no request (docs/adr/0012). */
  network?: NetworkCheck | null;
  /** The operator requests (requests/requests.jsonl): their own chain, sealed unsigned; null when nothing was asked of the operator. */
  requests?: { lines: number; intact: boolean; detail: string } | null;
  /** The store sweeps (ledger/sweeps.jsonl): what the hub found when it searched the run's outputs for a coverage record's strings, a chain of its own; null when no sweep ran. */
  sweeps?: { lines: number; intact: boolean; detail: string } | null;
  /** The finish register (leads/finish.jsonl): the coordinator's lease, readiness, the checks and the report's reviews, a chain of its own; null when the run has none. */
  finish?: { lines: number; intact: boolean; detail: string } | null;
  /**
   * The case policy the kickoff recorded (network/policy.json), by its
   * sha256, against the one the kickoff anchored beside the run: a policy
   * rewritten inside the run is named. Null for a run from before the case
   * policy was recorded.
   */
  case_policy?: { path: string; sha256: string; anchored: boolean | null; policy: string; network: string; more_evidence: string; material_use: Record<string, string> } | { path: string; unreadable: string; anchored: boolean | null } | null;
  /** The operator's audit beside the registry, and each operator line on the trace matched to it. */
  operator: OperatorAudit;
  /** The acquisition hashes given at kickoff (--inputs-hashes), against the evidence as re-hashed now. */
  acquisition: Acquisition;
  /** Each check's status: passed, failed, incomplete, not applicable, unavailable. */
  checks: Check[];
  /** How long each part took, and the evidence read. */
  timing: { phases: Record<string, number>; evidence_bytes: number; evidence_mb_per_s: number | null; total_ms: number };
  /**
   * The models the run's agents were given (team.json), and the model ids the
   * gateway saw answer, when it had one; and whose credential each seat used
   * and under which terms, as the kickoff anchored it outside the run
   * (`credentials`: api_key, oauth with its plan, local, other; the owner the
   * operator named with --key-owner; whether it was a customer's case). Null
   * credentials for a run from before the kickoff anchored them.
   */
  models: { team: Array<{ agent: string; model: string | null }>; gateway_answered: string[] | null; credentials?: AnchoredCredentials | null };
  /** A reference clock's offset from the host's, when the operator named one. */
  time_reference: { url: string; at: string; offset_ms: number | null; precision_ms: number; error?: string } | null;
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
  seal?: Custody["seal"];
  attestations?: Custody["attestations"];
  disputes?: Custody["disputes"];
  leads?: Custody["leads"];
  questions?: Custody["questions"];
  network?: Custody["network"];
  requests?: Custody["requests"];
  sweeps?: Custody["sweeps"];
  finish?: Custody["finish"];
  case_policy?: Custody["case_policy"];
  operator?: Custody["operator"];
  acquisition?: Custody["acquisition"];
  models?: Custody["models"];
  time_reference?: Custody["time_reference"];
  /** Why a part could not be checked at all (an exception): said as unavailable, never as nothing wrong. */
  errors?: Record<string, string>;
  timing?: Custody["timing"];
};

/** Whose credential each seat used, as the kickoff anchored it (swarm.sh credentials_json). */
export type AnchoredCredentials = { customer_case: boolean; seats: Array<{ seat: string; model: string; provider: string; credential: string; owner: string | null; variable?: string; plan?: string }> };

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
 *
 * A read-only check (custody --verify) loads it under `scratch.root`
 * instead, outside the run and its snapshot directory, and says in
 * `scratch.touched` what it wrote there and what it put in msb's index and
 * took out again: a check that writes nothing into the run still uses msb,
 * and says so.
 */
async function msbSnapshotVerify(file: string, deadline: Deadline, scratch?: { root: string; touched: string[] }): Promise<{ verified: boolean | null; note?: string }> {
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
    dest = await mkdtemp(join(scratch?.root ?? dirname(file), ".verify-"));
  } catch (err) {
    return { verified: null, note: `no room to load the snapshot ${scratch ? `in ${scratch.root}` : "beside it"} (${(err as NodeJS.ErrnoException).code ?? "error"})` };
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
    if (digest) {
      const removed = await run(["snapshot", "remove", "--force", "--quiet", digest]);
      scratch?.touched.push(`msb's index: loaded ${basename(file)} as ${digest}, and ${removed.code === 0 ? "removed it again" : "COULD NOT REMOVE IT"}`);
    }
    const gone = await rm(dest, { recursive: true, force: true }).then(() => true, () => false);
    scratch?.touched.push(`made ${dest} to load ${basename(file)} into, and ${gone ? "removed it" : "COULD NOT REMOVE IT"}`);
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
  // The index that verdict sealed goes aside with it (artifacts.<its time>.json):
  // the anchor names its sha256, which stays checkable once a new index replaces it.
  const index = await readRegularText(join(sandbox, "artifacts.json"));
  if ("text" in index) writeFileNoFollowSync(sandbox, name.replace(/^custody\./, "artifacts."), index.text);
  await unlink(file).catch(() => undefined);
  return name;
}

export type CustodyOptions = {
  timeoutSec?: number;
  run?: string;
  progress?: (line: string) => void;
  state?: CustodyState;
  /**
   * Check and return the verdict without writing anything in the run: no
   * verdict, no anchor, no artifacts.json, nothing set aside, nothing a
   * custody that was ended left beside the snapshots removed. A kept disk
   * msb checks is loaded under `scratchDir` (the host's temporary directory
   * by default), and `touched` gets a line for each thing written there or
   * put in msb's index, and for each thing found and left alone.
   */
  readOnly?: boolean;
  scratchDir?: string;
  touched?: string[];
  /** Handed the index of work/ as this custody hashed it, so a verify holds it to the sealed one without hashing work/ twice. */
  onIndex?: (index: ArtifactIndex) => void;
  /** Sign custody.json with this SSH key (ssh-keygen -Y, namespace dfirswarm-custody). */
  signKey?: string;
  /** Ask this RFC 3161 authority to timestamp custody.json's sha256. */
  timestampUrl?: string;
  /** The authority's CA certificates (PEM): the token's signature is checked against them (openssl ts -verify) and the result recorded. */
  timestampCa?: string;
  /** Record this https server's clock offset from the host's (its Date header). */
  timeReference?: string;
  /** Where the operator's audit is: the runs directory beside the run, by default. */
  runsDir?: string;
};

export async function takeCustody(sandboxInput: string, options: CustodyOptions = {}): Promise<Custody> {
  const sandbox = resolve(sandboxInput);
  const state: CustodyState = options.state ?? { phase: "starting" };
  const deadline = new Deadline(options.timeoutSec ?? 4 * 3600);
  state.incomplete = null;
  state.errors = {};
  // How long each part took: custody's cost, said.
  const began = Date.now();
  let phaseAt = began;
  state.timing = { phases: {}, evidence_bytes: 0, evidence_mb_per_s: null, total_ms: 0 };
  const enter = (phase: string) => {
    const now = Date.now();
    if (state.phase && state.phase !== "starting" && state.timing) state.timing.phases[state.phase] = (state.timing.phases[state.phase] ?? 0) + (now - phaseAt);
    phaseAt = now;
    state.phase = phase;
  };
  const tooLate = (what: string) => {
    if (deadline.over && !state.incomplete) state.incomplete = `the deadline passed during ${what}`;
    return deadline.over;
  };
  const say = options.progress ?? (() => undefined);
  let anchor: { inputs_manifest_sha256?: string; case_policy_sha256?: string; run?: string; isolation?: string; credentials?: unknown } | null = null;
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
  enter("setting the previous verdict aside");
  // A read-only check moves nothing: the verdict on disk stays where it is.
  state.previous = options.readOnly ? null : await setAsidePrevious(sandbox);

  // --- the evidence ---------------------------------------------------------
  enter("the evidence re-hash");
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
    // What each file hashed to now: the acquisition hashes are held to it.
    const actual = new Map<string, { sha256?: string; md5?: string; sha1?: string }>();
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
      if (state.timing) state.timing.evidence_bytes += lst.size;
      actual.set(file.path, { sha256: hashed.sha256, ...(hashed.md5 ? { md5: hashed.md5 } : {}), ...(hashed.sha1 ? { sha1: hashed.sha1 } : {}) });
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
        // Several sets, each at inputs/<name>/ (the manifest's `sets`): one
        // held in place is a link there, walked through.
        const sets = new Set(
          (Array.isArray(streamed.meta.sets) ? streamed.meta.sets : [])
            .map((set) => (set && typeof set === "object" && typeof (set as { name?: unknown }).name === "string" ? fsEncode((set as { name: string }).name).toString("latin1") : null))
            .filter((key): key is string => key !== null && key !== "" && !key.includes("/")),
        );
        await walkEvidence(evidenceRoot, (abs) => {
          const rel = abs.subarray(evidenceRoot.length + 1);
          if (!listed.has(rel.toString("latin1"))) added.push(`inputs/${fsDecode(rel)}`);
        }, sets);
        added.sort();
      }
      // Evidence held in place is read through links the kickoff made: one
      // that leads elsewhere now is evidence read from another place,
      // whatever its bytes say.
      const links = await evidenceLinks(sandbox, streamed.meta);
      const metaBytes = Number(streamed.meta.bytes);
      state.inputs = {
        files: total,
        bytes: Number.isFinite(metaBytes) && metaBytes > 0 ? metaBytes : totalBytes,
        unchanged: !changed.length && !missing.length && !added.length && !skipped.length && !unreadable.length && anchored !== false && !links.moved.length,
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
        links,
      };
      // The imager's numbers, when the operator gave them at kickoff (inputs.json, anchored with it).
      state.acquisition = compareAcquisition(streamed.meta.acquisition as Parameters<typeof compareAcquisition>[0], actual);
    }
  }
  state.inputsDone = true;
  if (state.timing) {
    const ms = state.timing.phases["the evidence re-hash"] ?? Date.now() - phaseAt;
    state.timing.evidence_mb_per_s = ms > 0 && state.timing.evidence_bytes ? Math.round((state.timing.evidence_bytes / 2 ** 20 / (ms / 1000)) * 10) / 10 : null;
  }

  // --- the sessions ----------------------------------------------------------
  enter("the session seal");
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
  enter("the trace");
  const refs = new Map<string, string>();
  const rereferenced = new Set<string>();
  const foreign = new Set<string>();
  let lines = 0;
  let unverified = 0;
  let operatorActions = 0;
  let disputed = 0;
  let gathered = 0;
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
  // An entry the harness authored itself (external material, a person's
  // hint as a hypothesis) carries its hash on a `harness_record` line: the
  // harness's own (agent "system", the hub's or the operator's CLI's), or,
  // on the host, the line of the pane whose process wrote the entry. In a
  // microVM run only the harness's own counts, as only the hub's record
  // lines do.
  const harnessRecordHashes = new Set<string>();
  const paneHarnessHashes = new Set<string>();
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
    else if (parsed.tool === HARNESS_RECORD_TOOL) (parsed.agent === "system" && parsed.claimed_agent === undefined ? harnessRecordHashes : paneHarnessHashes).add(result.hash);
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
    // A gathered line's recv_ts is when the stop chained it, not when it was sent.
    if (parsed.gathered) return;
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
  // What the verdict seals: how many lines, how many bytes, and the last line's own hash.
  let traceBytes = 0;
  let lastLine: string | null = null;
  let lastTime = Number.NaN;
  const operatorLines: TraceAction[] = [];
  const traceRead = await eachLine(join(sandbox, "traces", "events.jsonl"), (line) => {
    chainCheck.push(line);
    traceBytes += Buffer.byteLength(line) + 1;
    if (!line.trim()) return;
    lines += 1;
    lastLine = line;
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      const t = Date.parse(String(parsed.recv_ts ?? parsed.ts ?? ""));
      if (Number.isFinite(t)) lastTime = t;
      note(parsed);
      clockOf(parsed);
      noteRefs(parsed);
      noteRecord(parsed);
      noteLost(parsed);
      if (parsed.gathered) gathered += 1;
      if (parsed.tool === "operator_action") {
        const a = (parsed.args ?? {}) as { command?: unknown; argv?: unknown };
        // A gathered line was chained after the fact: its own time is when the command ran.
        operatorLines.push({ at: String((parsed.gathered ? parsed.ts : parsed.recv_ts) ?? parsed.ts ?? ""), command: String(a.command ?? ""), argv: Array.isArray(a.argv) ? a.argv.map(String) : [] });
      }
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
    let afterClose = 0;
    const read = await eachLine(join(sandbox, rel), (l) => {
      if (!l.trim()) return;
      count += 1;
      try {
        const parsed = JSON.parse(l) as Record<string, unknown>;
        // A line dated after the last one the chain took: written once the collector was down (a watchdog's last word after the stop).
        const t = Date.parse(String(parsed.recv_ts ?? parsed.ts ?? ""));
        if (Number.isFinite(t) && Number.isFinite(lastTime) && t > lastTime) afterClose += 1;
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
    spills.push({ path: rel, lines: count, agent: owner, bad, duplicates, ...(afterClose ? { after_close: afterClose } : {}), ...(owner === null && !vmRun ? { unauthenticated: true as const } : {}) });
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
    ...(gathered ? { gathered } : {}),
    spilled: spills,
    gaps,
    clock,
    sender_lost: [...senderLost].map(([agent, n]) => ({ agent, lines: n })),
  };
  state.seal = {
    trace: { lines, bytes: traceBytes, last_line_sha256: lastLine === null ? null : createHash("sha256").update(lastLine).digest("hex") },
    ledger: { entries: 0, head: null },
    attestations: { lines: 0, head: null },
    disputes: { lines: 0, head: null },
    journal: null,
    model_gateway: null,
  };

  enter("the kept-output check");
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
  enter("the ledger");
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
  // The harness's own lines for the entries it authored count beside them
  // (every entry is on the trace by the line of the process that wrote it);
  // on the host a pane's too, as its record lines do.
  const recordHashes =
    heldTo === "nothing (no readable trace)"
      ? new Set<string>()
      : new Set([...(heldTo === "the hub's lines" ? hubRecordHashes : seatRecordHashes), ...harnessRecordHashes, ...(vmRun ? [] : paneHarnessHashes)]);
  if ("why" in ledgerRead && ledgerRead.why !== "missing") {
    state.ledger = { entries: 0, chained: 0, intact: false, detail: `the ledger is ${ledgerRead.why}`, missing_from_ledger: [], not_on_trace: [], held_to: heldTo, claimed_by_seat: [] };
  } else if (ledgerText.trim() || recordHashes.size) {
    const v = verifyLedgerChain(ledgerText);
    // The ledger held to the trace: an entry whose hash the trace carries
    // must be in it (a tail deleted from the file is caught here, which the
    // ledger's own chain cannot see), and every chained entry must be on the
    // trace (one written into the file without the tool is). Version 2
    // entries and the record line's hash shipped together, so a version 2
    // or later entry the trace never carried was not written by the tool;
    // nor was an older-shaped entry after the first of them. (Only version 2
    // was held to it until 2026-09-27, so an all-version-3 ledger, every run
    // since, skipped the check.)
    const inLedger = new Set(v.hashes);
    const missingFromLedger = [...recordHashes].filter((h) => !inLedger.has(h));
    const notOnTrace: number[] = [];
    if (traceUsable) {
      let seenV2 = false;
      for (const line of ledgerText.split("\n")) {
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line) as { v?: number; seq?: number; hash?: string };
          if (typeof e.v === "number" && e.v >= 2) {
            seenV2 = true;
            if (!e.hash || !recordHashes.has(e.hash)) notOnTrace.push(Number(e.seq));
          } else if (seenV2) notOnTrace.push(Number(e.seq));
        } catch {
          // the chain check names it
        }
      }
    }
    if (state.seal) state.seal.ledger = { entries: v.total, head: v.hashes.at(-1) ?? null };
    const claimedBySeat = heldTo === "the hub's lines" ? [...new Set([...seatRecordHashes, ...paneHarnessHashes])].filter((h) => !recordHashes.has(h)).sort() : [];
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
  // A second author of an entry is an attestation beside it: its own chain.
  const attRead = await readRegularText(join(sandbox, "ledger", "attestations.jsonl"));
  if ("text" in attRead && attRead.text.trim()) {
    const a = verifyAttestationChain(attRead.text);
    state.attestations = { lines: a.total, intact: a.ok, detail: a.ok ? `${a.total} lines, chain intact` : `broken at line ${a.broken_at} (${a.reason})` };
    if (state.seal) state.seal.attestations = { lines: a.total, head: a.head };
  } else if ("why" in attRead && attRead.why !== "missing") {
    state.attestations = { lines: 0, intact: false, detail: `the attestations are ${attRead.why}` };
  } else state.attestations = null;
  // A dispute of an entry, and its withdrawal: a chain of its own beside the ledger.
  const dispRead = await readRegularText(join(sandbox, "ledger", "disputes.jsonl"));
  if ("text" in dispRead && dispRead.text.trim()) {
    const d = verifyDisputeChain(dispRead.text);
    state.disputes = { lines: d.total, intact: d.ok, detail: d.ok ? `${d.total} lines, chain intact` : `broken at line ${d.broken_at} (${d.reason})` };
    if (state.seal) state.seal.disputes = { lines: d.total, head: d.head };
  } else if ("why" in dispRead && dispRead.why !== "missing") {
    state.disputes = { lines: 0, intact: false, detail: `the disputes are ${dispRead.why}` };
  } else state.disputes = null;
  // The lead register: the swarm's open work and how each piece ended, a chain of its own beside the ledger.
  const leadsRead = await readRegularText(join(sandbox, "leads", "leads.jsonl"));
  if ("text" in leadsRead && leadsRead.text.trim()) {
    const v = verifyLeadChain(leadsRead.text);
    state.leads = { lines: v.total, intact: v.ok, detail: v.ok ? `${v.total} events, chain intact` : `broken at line ${v.broken_at} (${v.reason})` };
    if (state.seal) state.seal.leads = { lines: v.total, head: v.head };
  } else if ("why" in leadsRead && leadsRead.why !== "missing") {
    state.leads = { lines: 0, intact: false, detail: `the lead register is ${leadsRead.why}` };
  } else state.leads = null;
  // The question register: what the examination was asked and by whom, a chain of its own beside the leads.
  const questionsRead = await readRegularText(join(sandbox, "questions", "questions.jsonl"));
  if ("text" in questionsRead && questionsRead.text.trim()) {
    const v = verifyLeadChain(questionsRead.text);
    state.questions = { lines: v.total, intact: v.ok, detail: v.ok ? `${v.total} events, chain intact` : `broken at line ${v.broken_at} (${v.reason})` };
    if (state.seal) state.seal.questions = { lines: v.total, head: v.head };
  } else if ("why" in questionsRead && questionsRead.why !== "missing") {
    state.questions = { lines: 0, intact: false, detail: `the question register is ${questionsRead.why}` };
  } else state.questions = null;
  // The dynamic network: requests, decisions and grants, and every fetch, each a chain of its own; each capture against its manifest.
  const net = await checkNetwork(sandbox).catch(() => null);
  state.network = net?.check ?? null;
  if (state.seal && net) state.seal.network = net.seal;
  // What was asked of the operator and how each request stood: a chain of its own (the outbox, docs/adr/0014).
  const requestsRead = await readRegularText(join(sandbox, "requests", "requests.jsonl"));
  if ("text" in requestsRead && requestsRead.text.trim()) {
    const v = verifyLeadChain(requestsRead.text);
    state.requests = { lines: v.total, intact: v.ok, detail: v.ok ? `${v.total} events, chain intact` : `broken at line ${v.broken_at} (${v.reason})` };
    if (state.seal) state.seal.requests = { lines: v.total, head: v.head };
  } else if ("why" in requestsRead && requestsRead.why !== "missing") {
    state.requests = { lines: 0, intact: false, detail: `the operator requests are ${requestsRead.why}` };
  } else state.requests = null;
  // What the store sweeps found (the hub's search of the run's outputs for a coverage record's strings): a chain of its own beside the ledger.
  const sweepsRead = await readRegularText(join(sandbox, LEDGER_SWEEPS));
  if ("text" in sweepsRead && sweepsRead.text.trim()) {
    const v = verifySweepChain(sweepsRead.text);
    state.sweeps = { lines: v.total, intact: v.ok, detail: v.ok ? `${v.total} lines, chain intact` : `broken at line ${v.broken_at} (${v.reason})` };
    if (state.seal) state.seal.sweeps = { lines: v.total, head: v.head };
  } else if ("why" in sweepsRead && sweepsRead.why !== "missing") {
    state.sweeps = { lines: 0, intact: false, detail: `the store sweeps are ${sweepsRead.why}` };
  } else state.sweeps = null;
  // The finish register: the coordinator's lease, readiness, the checks, the report's reviews (chained with the lead register's code).
  const finishRead = await readRegularText(join(sandbox, FINISH_LOG));
  if ("text" in finishRead && finishRead.text.trim()) {
    const v = verifyLeadChain(finishRead.text);
    state.finish = { lines: v.total, intact: v.ok, detail: v.ok ? `${v.total} events, chain intact` : `broken at line ${v.broken_at} (${v.reason})` };
    if (state.seal) state.seal.finish = { lines: v.total, head: v.head };
  } else if ("why" in finishRead && finishRead.why !== "missing") {
    state.finish = { lines: 0, intact: false, detail: `the finish register is ${finishRead.why}` };
  } else state.finish = null;
  // The case policy, by its bytes, against the sha256 the kickoff anchored outside the run.
  const policyRead = await readRegularText(join(sandbox, "network", "policy.json"));
  if ("text" in policyRead) {
    const sha = createHash("sha256").update(policyRead.text).digest("hex");
    const anchored = anchor?.case_policy_sha256 ? anchor.case_policy_sha256 === sha : null;
    try {
      const p = JSON.parse(policyRead.text) as { policy?: string; network?: string; more_evidence?: string; material_use?: unknown };
      const mu = p.material_use && typeof p.material_use === "object" ? Object.fromEntries(Object.entries(p.material_use as Record<string, unknown>).map(([k, v]) => [k, String(v)])) : typeof p.material_use === "string" ? { text: p.material_use } : {};
      state.case_policy = { path: "network/policy.json", sha256: sha, anchored, policy: String(p.policy ?? ""), network: String(p.network ?? ""), more_evidence: String(p.more_evidence ?? ""), material_use: mu };
    } catch {
      state.case_policy = { path: "network/policy.json", unreadable: "not JSON", anchored };
    }
    if (state.seal) state.seal.case_policy = { sha256: sha };
  } else if (policyRead.why !== "missing" || anchor?.case_policy_sha256) {
    state.case_policy = { path: "network/policy.json", unreadable: policyRead.why === "missing" ? "gone, though the kickoff anchored it" : policyRead.why, anchored: anchor?.case_policy_sha256 ? false : null };
  } else state.case_policy = null;
  state.ledgerDone = true;

  // --- the model gateway's log -----------------------------------------------
  // When the run's model calls went through the host's gateway, its log is
  // the record of what each seat spent: the host's own, in traces/, which no
  // VM writes. Its chain is checked and its hash anchored with the verdict.
  enter("the model gateway log");
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
  if (state.seal && state.model_gateway) state.seal.model_gateway = { lines: state.model_gateway.lines, sha256: state.model_gateway.sha256 };
  // Which models the agents were given, and which the gateway saw answer.
  const teamModels: Array<{ agent: string; model: string | null }> = [];
  const teamText = await readRegularText(join(sandbox, "team.json"));
  if ("text" in teamText) {
    try {
      for (const a of (JSON.parse(teamText.text) as { agents?: Array<{ id?: unknown; model?: unknown }> }).agents ?? []) teamModels.push({ agent: String(a.id ?? ""), model: typeof a.model === "string" ? a.model : null });
    } catch {
      // an unreadable team is the VM check's to name
    }
  }
  let answered: string[] | null = null;
  if (state.model_gateway && !state.model_gateway.refused) {
    const seen = new Set<string>();
    await eachLine(gatewayPath, (line) => {
      try {
        const m = (JSON.parse(line) as { model?: unknown; response_model?: unknown }).response_model ?? (JSON.parse(line) as { model?: unknown }).model;
        if (typeof m === "string" && m) seen.add(m);
      } catch {
        // the chain check names it
      }
    });
    answered = [...seen].sort();
  }
  state.models = { team: teamModels, gateway_answered: answered, credentials: anchoredCredentials(anchor?.credentials) };

  // --- the operator's audit -------------------------------------------------------
  // Beside the registry, where no pane writes: its chain, and each operator
  // line on the trace matched to a line of it.
  const runsDir = options.runsDir ?? dirname(await realpath(sandbox).catch(() => sandbox));
  state.operator = verifyOperatorAudit(join(runsDir, "operator-audit.jsonl"), operatorLines);

  // --- the VMs -----------------------------------------------------------------
  enter("the VM check");
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
    // A loaded disk a killed custody left beside the snapshots is removed
    // first; a read-only check removes nothing, and names it.
    if (snapRoot) {
      for (const name of await readdir(snapRoot).catch(() => [])) {
        if (!name.startsWith(".verify-")) continue;
        if (options.readOnly) options.touched?.push(`found ${join(snapRoot, name)}, a disk a custody that was ended left loaded; not removed (a read-only check removes nothing)`);
        else await rm(join(snapRoot, name), { recursive: true, force: true }).catch(() => undefined);
      }
    }
    const scratch = options.readOnly ? { root: options.scratchDir ?? process.env.SWARM_VERIFY_SCRATCH ?? tmpdir(), touched: options.touched ?? [] } : undefined;
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
          const msb = ok ? await msbSnapshotVerify(real as string, deadline, scratch) : { verified: null, note: hashed === null ? "the deadline passed before msb's check" : "not asked: the disk does not match its record" };
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
  enter("the artifact index");
  state.artifacts = null;
  if (!tooLate("the artifact index")) {
    try {
      const index = await hashArtifacts(sandbox, { expiry: deadline });
      options.onIndex?.(index);
      if (index.skipped.some((s) => s.reason === "not hashed: the deadline passed")) tooLate("the artifact index");
      const text = `${JSON.stringify(index, null, 2)}\n`;
      if (!options.readOnly) writeFileNoFollowSync(sandbox, "artifacts.json", text);
      state.artifacts = { files: index.files.length, bytes: index.bytes, skipped: index.skipped.length, index_sha256: createHash("sha256").update(text).digest("hex") };
    } catch (err) {
      // Said as unavailable, with why: never an absent part that reads as nothing wrong.
      state.artifacts = null;
      state.errors.artifacts = (err as Error).message;
    }
  }
  state.artifactsDone = true;

  // --- the evidence-work store ---------------------------------------------------------
  enter("the store");
  state.store = null;
  if (!tooLate("the store")) {
    try {
      state.store = await checkStore(sandbox, Date.now() + deadline.remainingMs);
      if (state.store && state.store.outputs.verified + state.store.outputs.mismatched.length + state.store.outputs.missing.length < state.store.outputs.files) tooLate("the store");
    } catch (err) {
      state.store = null;
      state.errors.store = (err as Error).message;
    }
  }
  state.storeDone = true;
  if (state.seal && state.store) state.seal.journal = { lines: state.store.journal.lines, head: state.store.journal.head };
  // A reference clock, when the operator named one.
  const refUrl = options.timeReference ?? process.env.SWARM_TIME_REFERENCE;
  state.time_reference = refUrl ? await referenceOffset(refUrl) : null;

  enter("writing the verdict");
  if (state.timing) state.timing.total_ms = Date.now() - began;
  const custody = verdictOf(state, state.incomplete ?? null);
  if (options.readOnly) return custody;
  const written = writeVerdict(sandbox, anchorFile, custody);
  if (!written.anchored) say(`custody: WARN: the verdict could not be added to the anchor outside the run (${written.why}); custody.json cannot be checked against it`);
  // Signed and timestamped, when the operator set it up: the signature and
  // the authority's token beside custody.json, their hashes in the anchor.
  await sealVerdict(sandbox, anchorFile, { signKey: options.signKey ?? process.env.SWARM_CUSTODY_SIGN_KEY, timestampUrl: options.timestampUrl ?? process.env.SWARM_CUSTODY_TSA_URL, timestampCa: options.timestampCa ?? process.env.SWARM_CUSTODY_TSA_CA }, say);
  return custody;
}

/**
 * Sign custody.json and have it timestamped, as set up; each result added to
 * the last verdict in the anchor. A token is checked for the digest it was
 * asked for; its signature and the authority's certificate only against a
 * CA the operator named (openssl ts -verify), and the anchor says which it
 * was: verified, not verified with why, or imprint only.
 */
export async function sealVerdict(sandbox: string, anchorFile: string, how: { signKey?: string; timestampUrl?: string; timestampCa?: string }, say: (line: string) => void = () => undefined): Promise<{ signature?: Record<string, unknown>; timestamp?: Record<string, unknown> }> {
  const file = join(sandbox, CUSTODY_REL);
  const out: { signature?: Record<string, unknown>; timestamp?: Record<string, unknown> } = {};
  if (how.signKey) {
    const r = await signFile(file, how.signKey);
    out.signature = r.ok ? { file: `${CUSTODY_REL}.sig`, sha256: r.sha256, key: r.fingerprint, namespace: "dfirswarm-custody" } : { error: r.why };
    if (!r.ok) say(`custody: WARN: custody.json was not signed: ${r.why}`);
  }
  if (how.timestampUrl) {
    const r = await timestampFile(file, how.timestampUrl);
    if (r.ok) {
      const checked = how.timestampCa ? await verifyTimestampToken(r.tsr, file, how.timestampCa) : null;
      const caSha = how.timestampCa ? await hashRegularFile(how.timestampCa).then((h) => (h && "sha256" in h ? h.sha256 : null)).catch(() => null) : null;
      const signature = checked
        ? { verified: checked.verified, ca: how.timestampCa, ca_sha256: caSha, detail: checked.detail }
        : { verified: null, ca: null, detail: "imprint only, signature not verified (no CA named: --custody-timestamp-ca)" };
      out.timestamp = { file: `${CUSTODY_REL}.tsr`, sha256: r.sha256, authority: how.timestampUrl, gen_time: r.gen_time, signature };
      if (checked && checked.verified !== true) say(`custody: WARN: the timestamp token ${checked.verified === false ? "DOES NOT VERIFY" : "could not be checked"} against ${how.timestampCa}: ${checked.detail}`);
    } else out.timestamp = { authority: how.timestampUrl, error: r.why };
    if (!r.ok) say(`custody: WARN: custody.json was not timestamped: ${r.why}`);
  }
  if (out.signature || out.timestamp) {
    try {
      const anchor = JSON.parse(readFileSync(anchorFile, "utf8")) as Record<string, unknown>;
      const verdicts = Array.isArray(anchor.custody) ? (anchor.custody as Array<Record<string, unknown>>) : [];
      const last = verdicts.at(-1);
      if (last) Object.assign(last, out);
      writeFileNoFollowSync(dirname(anchorFile), basename(anchorFile), `${JSON.stringify({ ...anchor, custody: verdicts }, null, 2)}\n`, 0o444);
    } catch (err) {
      say(`custody: WARN: the signature and timestamp could not be added to the anchor: ${(err as Error).message}`);
    }
  }
  return out;
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
    seal: state.seal ?? { trace: { lines: 0, bytes: 0, last_line_sha256: null }, ledger: { entries: 0, head: null }, attestations: { lines: 0, head: null }, disputes: { lines: 0, head: null }, journal: null, model_gateway: null },
    attestations: state.attestations ?? null,
    disputes: state.disputes ?? null,
    leads: state.leads ?? null,
    questions: state.questions ?? null,
    network: state.network ?? null,
    requests: state.requests ?? null,
    sweeps: state.sweeps ?? null,
    finish: state.finish ?? null,
    case_policy: state.case_policy ?? null,
    operator: state.operator ?? null,
    acquisition: state.acquisition ?? null,
    checks: [],
    timing: state.timing ?? { phases: {}, evidence_bytes: 0, evidence_mb_per_s: null, total_ms: 0 },
    models: state.models ?? { team: [], gateway_answered: null },
    time_reference: state.time_reference ?? null,
    not_reached: notReached,
    incomplete,
  };
  c.checks = checksOf(c as never, state.errors ?? {});
  return { ...c, summary: summaryOf(c, { traceProblem: state.traceProblem ?? null, traceAnchored: state.traceAnchored ?? false }) };
}

/** The anchor's credentials, read as what they must be, or null. */
export function anchoredCredentials(raw: unknown): AnchoredCredentials | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as { customer_case?: unknown; seats?: unknown };
  if (!Array.isArray(r.seats)) return null;
  const str = (v: unknown) => (typeof v === "string" ? v : "");
  const seats = r.seats
    .filter((x): x is Record<string, unknown> => Boolean(x) && typeof x === "object")
    .map((x) => ({ seat: str(x.seat), model: str(x.model), provider: str(x.provider), credential: str(x.credential) || "other", owner: str(x.owner) || null, ...(str(x.variable) ? { variable: str(x.variable) } : {}), ...(str(x.plan) ? { plan: str(x.plan) } : {}) }));
  return { customer_case: r.customer_case === true, seats };
}

/** Whose credential the seats used, in one line: by provider, kind and owner, with how many seats. */
export function credentialsWords(c: AnchoredCredentials): string {
  const groups = new Map<string, number>();
  for (const s of c.seats) {
    const kind = s.credential === "oauth" ? `subscription (OAuth: ${s.plan ?? "subscription login; not for customer data"})` : s.credential === "api_key" ? "API key" : s.credential === "local" ? "local model, no key" : s.credential === "env" ? `key from ${s.variable ?? "the environment"}` : "key from models.json";
    const key = `${s.provider} ${kind}${s.owner ? `, the key of ${s.owner}` : s.credential === "local" ? "" : ", owner not named"}`;
    groups.set(key, (groups.get(key) ?? 0) + 1);
  }
  return `credentials${c.customer_case ? " (a customer's case: API keys only)" : ""}: ${[...groups].map(([k, n]) => `${k} (${plural(n, "seat")})`).join("; ")}`;
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
    // Unchanged since the kickoff hashed it: that is all a re-hash can say. Against the imager's own numbers only when the operator gave them.
    const acq = c.acquisition;
    const acqText = !acq
      ? "; acquisition hashes not given (--inputs-hashes)"
      : acq.mismatched.length
        ? `; DOES NOT MATCH THE ACQUISITION HASHES GIVEN: ${acq.mismatched.join(", ")}`
        : `; matches the acquisition hashes given (${acq.matched} of ${acq.given}${acq.not_compared.length ? `, ${acq.not_compared.length} NOT COMPARED` : ""})`;
    const movedLinks = inputs.links?.moved ?? [];
    if (movedLinks.length) parts.push(`EVIDENCE READ THROUGH A LINK THAT MOVED: ${movedLinks.join("; ")}`);
    else if (inputs.links?.checked) how.push(`${plural(inputs.links.checked, "link")} to where it was held still leading there`);
    parts.push(inputs.unchanged
      ? `evidence unchanged since the run began (${how.join(", ")}${inputs.manifest_anchored === true ? ", manifest anchored" : inputs.manifest_anchored === null ? ", manifest not anchored" : ""})${acqText}`
      : movedLinks.length && !changedAny && inputs.complete
        ? `the files read through it hash as the kickoff recorded (${how.join(", ")}), which does not make them the source it recorded${acqText}`
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
    else if (tr.intact) {
      const op = c.operator;
      const opText = tr.operator_actions
        ? `, ${plural(tr.operator_actions, "operator action")} from a shell outside the run${op ? (op.unmatched.length ? ` (${op.unmatched.length} NOT ON THE OPERATOR AUDIT)` : `, each on the operator audit`) : ""}`
        : "";
      parts.push(`trace ${tr.lines} lines, chain intact${t.traceAnchored ? "" : " (no anchor)"}, sealed at line ${c.seal.trace.lines}${tr.unverified ? `, ${tr.unverified} unverified` : ""}${opText}${tr.disputed ? `, ${tr.disputed} disputed` : ""}${tr.gathered ? `, ${plural(tr.gathered, "line")} the harness spilled while the collector was down chained by the stop (marked gathered)` : ""}`);
    }
    else if (!tr.detail.startsWith("chain broken")) parts.push(`TRACE UNCHAINED (${tr.lines} lines)`);
    else parts.push("TRACE CHAIN BROKEN");
    const spilled = tr.spilled.reduce((n, s) => n + s.lines, 0);
    const badSpill = tr.spilled.reduce((n, s) => n + s.bad, 0);
    const dupSpill = tr.spilled.reduce((n, s) => n + s.duplicates, 0);
    const afterClose = tr.spilled.reduce((n, s) => n + (s.after_close ?? 0), 0);
    if (spilled) parts.push(`${plural(spilled, "trace line")} outside the chain (spilled: ${tr.spilled.filter((s) => s.lines).map((s) => (s.unauthenticated ? `${s.path}, which any pane can write` : s.path)).join("; ")})${afterClose ? `, ${afterClose === spilled ? "all" : afterClose} dated after the last line the chain took (written once the collector was down)` : ""}${dupSpill ? `, ${dupSpill} also in the chain` : ""}${badSpill ? `, ${badSpill} NOT ATTRIBUTABLE` : ""}`);
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
  if (c.attestations) parts.push(c.attestations.intact ? `${plural(c.attestations.lines, "ledger attestation")}, chain intact` : `LEDGER ATTESTATIONS CHAIN BROKEN (${c.attestations.detail})`);
  if (c.disputes) parts.push(c.disputes.intact ? `${plural(c.disputes.lines, "ledger dispute line")}, chain intact` : `LEDGER DISPUTES CHAIN BROKEN (${c.disputes.detail})`);
  if (c.leads) parts.push(c.leads.intact ? `${plural(c.leads.lines, "lead event")}, chain intact` : `LEAD REGISTER CHAIN BROKEN (${c.leads.detail})`);
  if (c.questions) parts.push(c.questions.intact ? `${plural(c.questions.lines, "question event")}, chain intact` : `QUESTION REGISTER CHAIN BROKEN (${c.questions.detail})`);
  if (c.network) {
    const n = c.network;
    const bad = [...n.captures.mismatched, ...n.captures.missing];
    const open = n.fetches.unresolved ?? [];
    parts.push(n.grants.intact && n.fetches.intact && !bad.length && !open.length ? `network records: ${plural(n.grants.lines, "grant event")}, ${plural(n.fetches.lines, "fetch line")}, ${plural(n.captures.verified, "capture")} verified${n.captures.unpublished ? `, ${plural(n.captures.unpublished, "attempt")} recorded as not published` : ""}` : `NETWORK RECORDS DO NOT HOLD (${[...(n.grants.intact ? [] : [`grants: ${n.grants.detail}`]), ...(n.fetches.intact ? [] : [`fetches: ${n.fetches.detail}`]), ...(open.length ? [`attempts with no outcome: ${open.join(", ")}`] : []), ...(bad.length ? [`captures: ${bad.join(", ")}`] : [])].join("; ")})`);
  }
  if (c.requests) parts.push(c.requests.intact ? `${plural(c.requests.lines, "operator request event")}, chain intact` : `OPERATOR REQUESTS CHAIN BROKEN (${c.requests.detail})`);
  if (c.sweeps) parts.push(c.sweeps.intact ? `${plural(c.sweeps.lines, "store sweep")}, chain intact` : `STORE SWEEPS CHAIN BROKEN (${c.sweeps.detail})`);
  if (c.finish) parts.push(c.finish.intact ? `${plural(c.finish.lines, "finish event")}, chain intact` : `FINISH REGISTER CHAIN BROKEN (${c.finish.detail})`);
  if (c.case_policy) {
    const cp = c.case_policy;
    if ("unreadable" in cp) parts.push(`CASE POLICY UNREADABLE (${cp.path} is ${cp.unreadable})`);
    else if (cp.anchored === false) parts.push(`CASE POLICY REWRITTEN: ${cp.path} is not the policy the kickoff anchored (sha256 ${cp.sha256})`);
    else parts.push(`case policy ${cp.policy}, network ${cp.network}, more evidence ${cp.more_evidence}, sealed${cp.anchored === true ? " and held to the kickoff's anchor" : " (not anchored: a run from before the anchor held it)"}`);
  }
  if (c.operator && !c.operator.intact) parts.push(`OPERATOR AUDIT CHAIN BROKEN (${c.operator.detail})`);
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
    const anchor = j.anchor === "matches" ? "its anchor matches" : j.anchor === "behind" ? "its anchor behind the journal's head, on the chain (a crash between two writes, recovered)" : j.anchor === "missing" ? "NO JOURNAL ANCHOR" : "JOURNAL ANCHOR OFF THE CHAIN";
    const bits = [`store: ${plural(st.jobs, "job")}, ${st.committed} committed, journal ${plural(j.lines, "line")} ${j.intact ? "chain intact" : `CHAIN BROKEN (${j.detail})`}, ${anchor}`];
    bits.push(`${st.outputs.verified} of ${plural(st.outputs.files, "output file")} verified against their manifests`);
    // A long list is named in part here and whole in custody.json.
    const some = (xs: Array<string | number>, n: number, where: string) => `${xs.slice(0, n).join(", ")}${xs.length > n ? `, … all ${xs.length} in custody.json ${where}` : ""}`;
    if (st.outputs.mismatched.length) bits.push(`${st.outputs.mismatched.length} OUTPUT FILE(S) CHANGED SINCE SEALED (${some(st.outputs.mismatched, 5, "store.outputs.mismatched")})`);
    if (st.outputs.missing.length) bits.push(`${st.outputs.missing.length} OUTPUT FILE(S) MISSING`);
    if (st.manifests_missing.length) bits.push(`${st.manifests_missing.length} MANIFEST(S) MISSING`);
    if (j.repaired || j.anchor_mismatch) bits.push(`the journal recorded ${j.repaired} repair(s) and ${j.anchor_mismatch} anchor mismatch(es)`);
    if (st.staging_left.length) {
      const why = st.staging_why ?? {};
      bits.push(`${st.staging_left.length} job staging director${st.staging_left.length === 1 ? "y" : "ies"} left unsealed (${some(st.staging_left.map((n) => (why[n] ? `${n}: ${why[n]}` : `${n}: no account on the journal`)), 5, "store.staging_left")})`);
    }
    bits.push(`${plural(st.generations, "catalogue generation")}, ${plural(st.revisions, "revision")}`);
    if (st.findings.total) {
      const f = st.findings;
      const parts = [`${f.structured} with refs${f.refs_invalid.length ? ` (${f.refs_invalid.length} NO LONGER RESOLVE: ledger seq ${some(f.refs_invalid, 20, "store.findings.refs_invalid")})` : ""}${f.unresolved_only.length ? `, ${f.unresolved_only.length} of them saying only why no object can be named` : ""}`];
      if (f.path_only.length) parts.push(`${f.path_only.length} naming a path in prose only`);
      parts.push(f.without_refs.length ? `${f.without_refs.length} citing no object of the run (ledger seq ${some(f.without_refs, 20, "store.findings.without_refs")}): an audit gap` : "none citing nothing");
      if (f.on_failed_jobs?.length) parts.push(`${f.on_failed_jobs.length} resting on the kept output of a job that did not succeed (ledger seq ${some(f.on_failed_jobs, 20, "store.findings.on_failed_jobs")})`);
      bits.push(`${plural(f.total, "standing finding")}: ${parts.join(", ")}`);
    }
    if (st.findings.contradictions?.length) bits.push(`${plural(st.findings.contradictions.length, "standing contradiction")} (${st.findings.contradictions.map((x) => `#${x.from} contradicts #${x.to}`).join(", ")})`);
    if (st.findings.limitations) bits.push(`${plural(st.findings.limitations, "limitation")} recorded`);
    if (st.findings.sensitive?.length) bits.push(`${plural(st.findings.sensitive.length, "entry", "entries")} marked sensitive (package --redact replaces what they cite)`);
    if (st.logs) bits.push(st.logs.mismatched.length || st.logs.missing.length ? `JOB LOGS: ${st.logs.mismatched.length} CHANGED SINCE SEALED, ${st.logs.missing.length} MISSING` : `${st.logs.checked} job logs verified against their seal`);
    if (st.ledger_unreadable) bits.push(`FINDINGS NOT COUNTED: ${st.ledger_unreadable}`);
    if (st.images) {
      const many = Object.entries(st.images.digests).filter(([, d]) => d.length > 1);
      bits.push(st.images.undeclared.length ? `${st.images.undeclared.length} JOB(S) RAN IN AN IMAGE THE RUN DID NOT DECLARE (${some(st.images.undeclared, 10, "store.images.undeclared")})` : `every job in one of the ${st.images.declared.length} job images the run declared`);
      if (many.length) bits.push(`AN IMAGE NAME BOOTED MORE THAN ONE DIGEST: ${many.map(([k, d]) => `${k} (${d.join(", ")})`).join("; ")}`);
    }
    if (st.access) {
      // Declared: the scope was enforced (a view of what the job named), the reads within it not observed. Else every object was in reach.
      const sc = st.access.scopes;
      const m = st.access.manifests;
      bits.push(
        sc && sc.declared
          ? `${plural(sc.declared, "job")} ran in its declared scope, enforced (reads within it not observed${m?.mismatched.length ? `; ${m.mismatched.length} SCOPE MANIFEST(S) NOT MATCHING THE JOURNAL (${some(m.mismatched, 5, "store.access.manifests")})` : ""}); ${sc.all + sc.default_all} with every object of the run in reach (${sc.default_all} by default, having declared nothing), what they read not observed`
          : `what each job read is not observed by the harness (${st.access.observed_unknown} of ${st.access.jobs} jobs: declared inputs and accessible mounts are recorded)`,
      );
    }
    if (st.imports) bits.push(`${plural(st.imports.sealed, "import")} (brain-side outputs a finding cited, and evidence and material added from outside) sealed, ${st.imports.verified} verified against the journal${st.imports.mismatched.length ? `, ${st.imports.mismatched.length} NOT MATCHING (${some(st.imports.mismatched, 5, "store.imports.mismatched")})` : ""}`);
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
  if (c.time_reference) parts.push(c.time_reference.offset_ms === null ? `REFERENCE CLOCK NOT READ (${c.time_reference.url}: ${c.time_reference.error ?? "no answer"})` : `the host's clock ${c.time_reference.offset_ms >= 0 ? "behind" : "ahead of"} ${c.time_reference.url} by ${Math.abs(c.time_reference.offset_ms)} ms (± ${c.time_reference.precision_ms} ms)`);
  if (c.models?.credentials?.seats.length) parts.push(credentialsWords(c.models.credentials));
  parts.push(checksLine(c.checks));
  // What the anchors are: files of the operator's own account beside the run. They hold the agents to account, not the operator.
  parts.push("anchors are the operator's own files beside the run: they hold the agents to account; a signature and an external timestamp hold the verdict itself");
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
      seal: custody.seal,
      checks: custody.checks.map((x) => `${x.name}: ${x.status}`),
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

/**
 * A resume of the run (scripts/resume.ts), added to the anchor outside the
 * run beside the verdicts: when, by whom, from what, and the chains' heads
 * it found. An earlier verdict and an earlier release are held to the run
 * as prefixes once the anchor names a resume after them.
 */
export function anchorResume(sandboxInput: string, entry: Record<string, unknown>): void {
  const anchorFile = custodyAnchorPath(resolve(sandboxInput));
  let anchor: Record<string, unknown> = {};
  try {
    anchor = JSON.parse(readFileSync(anchorFile, "utf8"));
  } catch {
    throw new Error(`the custody anchor beside the run (${anchorFile}) cannot be read: the resume is not anchored`);
  }
  const resumes = Array.isArray(anchor.resumes) ? (anchor.resumes as unknown[]) : [];
  resumes.push(entry);
  writeFileNoFollowSync(dirname(anchorFile), basename(anchorFile), `${JSON.stringify({ ...anchor, resumes }, null, 2)}\n`, 0o444);
}

/** The resumes the anchor outside the run names, in order. */
export function anchoredResumes(sandboxInput: string, anchorFile?: string | null): Array<{ at: string; by?: string; from?: string; segment?: number }> {
  try {
    const a = JSON.parse(readFileSync(anchorFile ?? custodyAnchorPath(resolve(sandboxInput)), "utf8")) as { resumes?: unknown };
    return Array.isArray(a.resumes) ? (a.resumes as Array<{ at: string; by?: string; from?: string; segment?: number }>).filter((r) => typeof r?.at === "string") : [];
  } catch {
    return [];
  }
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

/** A verdict's checks that did not pass. */
export function adverse(c: Pick<Custody, "checks">): Check[] {
  return c.checks.filter((x) => x.status === "failed" || x.status === "incomplete" || x.status === "unavailable");
}

/**
 * The index custody wrote of work/ at stop (artifacts.json beside the
 * verdict), held to the verdict that names its sha256 and to the anchor
 * outside the run that names it too. `sealed` carries the index itself, for
 * every file to be held to it; `not sealed` is a verdict that indexed
 * nothing (an older custody, or one that never reached the index), said as
 * that; `differs` is an index that is gone or is not the one sealed.
 */
export type SealedIndex =
  | { state: "sealed"; sha256: string; index: ArtifactIndex }
  | { state: "not sealed"; why: string }
  | { state: "differs"; why: string };

export async function sealedIndex(sandboxInput: string, sealed: { artifacts?: { index_sha256?: string } | null } | null, anchored?: string | null): Promise<SealedIndex> {
  const sandbox = resolve(sandboxInput);
  const want = sealed?.artifacts?.index_sha256;
  if (!sealed) return { state: "not sealed", why: "there is no verdict to hold work/ to" };
  if (!want) return { state: "not sealed", why: "the verdict indexed no work files (a custody from before the index was sealed, or one that did not reach it)" };
  if (anchored !== undefined && anchored !== null && anchored !== want) return { state: "differs", why: `the anchor names another index (${anchored}) than the verdict (${want})` };
  const read = await readRegularText(join(sandbox, "artifacts.json"));
  if ("why" in read) return { state: "differs", why: `artifacts.json, the index the verdict sealed (${want}), is ${read.why}` };
  const sha256 = createHash("sha256").update(read.text).digest("hex");
  if (sha256 !== want) return { state: "differs", why: `artifacts.json is not the index the verdict sealed: its sha256 is ${sha256}, the sealed one ${want}` };
  try {
    return { state: "sealed", sha256, index: JSON.parse(read.text) as ArtifactIndex };
  } catch {
    return { state: "differs", why: "artifacts.json has the sealed sha256 and is not JSON" };
  }
}

/** Each work/ file that is not what the sealed index says, by what happened to it. */
export type WorkDrift = {
  /** Sealed paths whose bytes are not the sealed ones now (or that are no longer a regular file). */
  changed: string[];
  /** Sealed paths that are gone. */
  removed: string[];
  /** Files under work/ the index did not have. */
  added: string[];
  /** Files the index named as not hashed at custody (the deadline, a read that failed): there, and never sealed. */
  unsealed: string[];
  /** Files not hashed now before the deadline. */
  not_checked: string[];
};

/**
 * Every file under work/ held to the index custody sealed. The walk is
 * today's (hashArtifacts); a sealed path the walk no longer lists (a rule
 * that now leaves it out) is hashed where the index says it is, so a
 * change in what is indexed is never read as a file removed.
 */
export async function workDrift(sandboxInput: string, index: ArtifactIndex, expiry?: { over: boolean }, walked?: ArtifactIndex | null): Promise<WorkDrift> {
  const sandbox = resolve(sandboxInput);
  const out: WorkDrift = { changed: [], removed: [], added: [], unsealed: [], not_checked: [] };
  const live = walked ?? (await hashArtifacts(sandbox, { expiry }));
  const now = new Map(live.files.map((f) => [f.path, f.sha256]));
  const sealed = new Map((index.files ?? []).map((f) => [f.path, f.sha256]));
  const sealedSkipped = new Set((index.skipped ?? []).map((s) => s.path));
  const liveSkipped = new Map(live.skipped.map((s) => [s.path, s.reason]));
  for (const [path, sha] of sealed) {
    if (!/^work\//.test(path) || path.split("/").includes("..")) {
      out.changed.push(`${path} (not a path under work/)`);
      continue;
    }
    const current = now.get(path);
    if (current !== undefined) {
      if (current !== sha) out.changed.push(path);
      continue;
    }
    if (liveSkipped.get(path) === "not hashed: the deadline passed") {
      out.not_checked.push(path);
      continue;
    }
    const direct = await hashRegularFile(join(sandbox, path), { expiry });
    if (direct === null) out.not_checked.push(path);
    else if ("why" in direct) (direct.why === "missing" ? out.removed : out.changed).push(direct.why === "missing" ? path : `${path} (now ${direct.why})`);
    else if (direct.sha256 !== sha) out.changed.push(path);
  }
  for (const [path] of now) {
    if (sealed.has(path)) continue;
    (sealedSkipped.has(path) ? out.unsealed : out.added).push(path);
  }
  for (const [path, reason] of liveSkipped) {
    if (sealed.has(path) || sealedSkipped.has(path)) continue;
    if (reason === "not hashed: the deadline passed") out.not_checked.push(path);
    else out.added.push(`${path} (${reason})`);
  }
  for (const k of Object.keys(out) as Array<keyof WorkDrift>) out[k].sort();
  return out;
}

/** A drift, in words: nothing when there is none. */
export function workDriftLine(d: WorkDrift): string {
  const parts = [
    ...(d.changed.length ? [`${d.changed.length} CHANGED (${d.changed.join(", ")})`] : []),
    ...(d.removed.length ? [`${d.removed.length} REMOVED (${d.removed.join(", ")})`] : []),
    ...(d.added.length ? [`${d.added.length} ADDED (${d.added.join(", ")})`] : []),
    ...(d.unsealed.length ? [`${d.unsealed.length} never sealed (not hashed at custody: ${d.unsealed.join(", ")})`] : []),
    ...(d.not_checked.length ? [`${d.not_checked.length} NOT CHECKED before the deadline (${d.not_checked.join(", ")})`] : []),
  ];
  return parts.join("; ");
}

type Seal = Custody["seal"];

/**
 * Each chain the verdict sealed, held to what the run holds now: the
 * ledger's entries and head, the attestations' lines and head, the store
 * journal's lines and head (examiner notes after the seal are named, and
 * are the only lines that may follow it), the model gateway log's lines and
 * sha256. A part the verdict did not seal (an older custody) is not held,
 * and is said as not sealed; one that appeared or went since is a drift.
 */
export function sealDrift(sealed: Partial<Seal> | undefined, now: Seal, journal: { hashes: string[]; types: string[] } | null, chains: { requests?: string[] } = {}): { drift: Array<{ what: string; sealed: string; now: string }>; after: string[]; not_sealed: string[] } {
  const drift: Array<{ what: string; sealed: string; now: string }> = [];
  const after: string[] = [];
  const notSealed: string[] = [];
  if (!sealed) return { drift, after, not_sealed: ["the ledger", "the attestations", "the disputes", "the store sweeps", "the lead register", "the finish register", "the question register", "the network records", "the operator requests", "the store journal", "the model gateway log"] };
  const chain = (n: number, head: string | null, unit: string) => `${n} ${unit}, head ${head ?? "none"}`;
  if (!sealed.ledger) notSealed.push("the ledger");
  else if (sealed.ledger.entries !== now.ledger.entries || sealed.ledger.head !== now.ledger.head) {
    drift.push({ what: "ledger", sealed: chain(sealed.ledger.entries, sealed.ledger.head, "entries"), now: chain(now.ledger.entries, now.ledger.head, "entries") });
  }
  if (!sealed.attestations) notSealed.push("the attestations");
  else if (sealed.attestations.lines !== now.attestations.lines || sealed.attestations.head !== now.attestations.head) {
    drift.push({ what: "ledger attestations", sealed: chain(sealed.attestations.lines, sealed.attestations.head, "lines"), now: chain(now.attestations.lines, now.attestations.head, "lines") });
  }
  // A verdict from before the disputes were sealed does not hold them; one that sealed none holds them to none.
  const nowDisputes = now.disputes ?? { lines: 0, head: null };
  if (!sealed.disputes) notSealed.push("the disputes");
  else if (sealed.disputes.lines !== nowDisputes.lines || sealed.disputes.head !== nowDisputes.head) {
    drift.push({ what: "ledger disputes", sealed: chain(sealed.disputes.lines, sealed.disputes.head, "lines"), now: chain(nowDisputes.lines, nowDisputes.head, "lines") });
  }
  // The store sweeps and the finish register, the same way: a verdict from before they were sealed does not hold them.
  for (const [k, what, unit] of [["sweeps", "store sweeps", "lines"], ["finish", "finish register", "events"]] as const) {
    const nowK = now[k] ?? { lines: 0, head: null };
    const sealedK = sealed[k];
    if (!sealedK) {
      if (nowK.lines) notSealed.push(`the ${what}`);
    } else if (sealedK.lines !== nowK.lines || sealedK.head !== nowK.head) drift.push({ what, sealed: chain(sealedK.lines, sealedK.head, unit), now: chain(nowK.lines, nowK.head, unit) });
  }
  // The lead register, the same way: a verdict from before it was sealed does not hold it.
  const nowLeads = now.leads ?? { lines: 0, head: null };
  if (!sealed.leads) {
    if (nowLeads.lines) notSealed.push("the lead register");
  } else if (sealed.leads.lines !== nowLeads.lines || sealed.leads.head !== nowLeads.head) {
    drift.push({ what: "lead register", sealed: chain(sealed.leads.lines, sealed.leads.head, "events"), now: chain(nowLeads.lines, nowLeads.head, "events") });
  }
  // The question register, the same way.
  const nowQuestions = now.questions ?? { lines: 0, head: null };
  if (!sealed.questions) {
    if (nowQuestions.lines) notSealed.push("the question register");
  } else if (sealed.questions.lines !== nowQuestions.lines || sealed.questions.head !== nowQuestions.head) {
    drift.push({ what: "question register", sealed: chain(sealed.questions.lines, sealed.questions.head, "events"), now: chain(nowQuestions.lines, nowQuestions.head, "events") });
  }
  // The network records, the same way (docs/adr/0012).
  const nowNet = now.network ?? { grants: { lines: 0, head: null }, fetches: { lines: 0, head: null } };
  if (!sealed.network) {
    if (nowNet.grants.lines || nowNet.fetches.lines) notSealed.push("the network records");
  } else {
    for (const k of ["grants", "fetches"] as const) {
      if (sealed.network[k].lines !== nowNet[k].lines || sealed.network[k].head !== nowNet[k].head) drift.push({ what: `network ${k}`, sealed: chain(sealed.network[k].lines, sealed.network[k].head, "lines"), now: chain(nowNet[k].lines, nowNet[k].head, "lines") });
    }
  }
  // The operator requests (docs/adr/0014), the same way; what the operator did
  // with them after the stop (acknowledged, answered, declined) follows the
  // sealed line and is named, not a change to it. A sealed line changed or gone is.
  const nowRequests = now.requests ?? { lines: 0, head: null };
  if (!sealed.requests) {
    if (nowRequests.lines) notSealed.push("the operator requests");
  } else if (sealed.requests.lines !== nowRequests.lines || sealed.requests.head !== nowRequests.head) {
    const n = sealed.requests.lines;
    const prefix = chains.requests !== undefined && (n === 0 ? sealed.requests.head === null : chains.requests[n - 1] === sealed.requests.head);
    if (prefix && nowRequests.lines > n) after.push(`operator requests: ${nowRequests.lines - n} event(s) after the seal (the operator's acts on them after the stop)`);
    else drift.push({ what: "operator requests", sealed: chain(n, sealed.requests.head, "events"), now: chain(nowRequests.lines, nowRequests.head, "events") });
  }
  if (sealed.journal === undefined) notSealed.push("the store journal");
  else if (sealed.journal === null && now.journal) drift.push({ what: "store journal", sealed: "none", now: chain(now.journal.lines, now.journal.head, "lines") });
  else if (sealed.journal && !now.journal) drift.push({ what: "store journal", sealed: chain(sealed.journal.lines, sealed.journal.head, "lines"), now: "none (gone, or not readable)" });
  else if (sealed.journal && now.journal && (sealed.journal.lines !== now.journal.lines || sealed.journal.head !== now.journal.head)) {
    // The sealed line is still there, and every line after it is an examiner's note: the record after the run, not a change to it.
    const at = sealed.journal.lines > 0 ? journal?.hashes[sealed.journal.lines - 1] ?? null : null;
    const prefix = sealed.journal.lines === 0 ? sealed.journal.head === null : at === sealed.journal.head;
    const rest = journal ? journal.types.slice(sealed.journal.lines) : [];
    if (prefix && now.journal.lines > sealed.journal.lines && rest.every((t) => t === "note")) after.push(`store journal: ${rest.length} examiner note(s) after the seal`);
    else drift.push({ what: "store journal", sealed: chain(sealed.journal.lines, sealed.journal.head, "lines"), now: `${chain(now.journal.lines, now.journal.head, "lines")}${prefix ? `; after the sealed line: ${[...new Set(rest)].join(", ") || "nothing"}` : "; the sealed line is not there"}` });
  }
  if (sealed.model_gateway === undefined) notSealed.push("the model gateway log");
  else if ((sealed.model_gateway?.lines ?? null) !== (now.model_gateway?.lines ?? null) || (sealed.model_gateway?.sha256 ?? null) !== (now.model_gateway?.sha256 ?? null)) {
    const g = (x: Seal["model_gateway"]) => (x ? `${x.lines} lines, sha256 ${x.sha256 ?? "none"}` : "none");
    drift.push({ what: "model gateway log", sealed: g(sealed.model_gateway), now: g(now.model_gateway) });
  }
  return { drift, after, not_sealed: notSealed };
}

/** An earlier verdict the anchor names, held to the run as a prefix: every chain it sealed still begins with what it sealed. */
export type EarlierSeal = { at: string | null; sha256: string | null; resumed_after: boolean; ok: boolean; held: string[]; broken: string[] };

/** The lines of a JSONL text, and the `hash` each carries. */
function lineHashField(text: string): string[] {
  return text
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => {
      try {
        return String((JSON.parse(l) as { hash?: unknown }).hash ?? "");
      } catch {
        return "";
      }
    });
}

/**
 * Whether every chain a verdict sealed is a prefix of the run now: the line
 * it sealed as the last one is still at its place, with the hash it had,
 * every chain recomputed over its first lines with its own code (the
 * ledger, the attestations, the disputes, the registers, the journal), so a
 * sealed line rewritten with its hash fields kept is broken.
 * What the run appended after it (the continuation of a resumed run, the
 * closing lines of a stop) is allowed; a line it sealed that changed or went
 * is not. Pure over the texts read.
 */
export function sealPrefix(sealed: Partial<Seal> | undefined, now: { trace: string; ledger: string; attestations: string; disputes: string; leads: string; questions: string; grants: string; fetches: string; requests?: string; sweeps?: string; finish?: string; journal: string | null; gateway: string | null }): { ok: boolean; held: string[]; broken: string[] } {
  const held: string[] = [];
  const broken: string[] = [];
  if (!sealed) return { ok: false, held, broken: ["the verdict seals no chain (a custody from before the seal)"] };
  const at = (list: string[], n: number) => (n > 0 ? (list[n - 1] ?? null) : null);
  const check = (what: string, n: number | undefined, head: string | null | undefined, list: string[]) => {
    if (n === undefined) return;
    if (n > list.length) broken.push(`${what}: it sealed ${n} line(s), and ${list.length} are here`);
    else if ((at(list, n) ?? null) !== (head ?? null)) broken.push(`${what}: line ${n} is not the one it sealed`);
    else held.push(`${what} (${n})`);
  };
  // A register chained with the lead register's code (leads, questions, the
  // network chains, the operator requests): the first n events' own chain is
  // recomputed (every event's hash over its content), never read from the
  // hash fields the lines carry, so a changed body with its hash left in
  // place does not pass (docs/adr/0016).
  const checkChain = (what: string, n: number | undefined, head: string | null | undefined, text: string) => {
    if (n === undefined) return;
    const lines = text.split("\n").filter((l) => l.trim());
    if (n > lines.length) {
      broken.push(`${what}: it sealed ${n} event(s), and ${lines.length} are here`);
      return;
    }
    const v = n > 0 ? verifyLeadChain(`${lines.slice(0, n).join("\n")}\n`) : { ok: true, head: null as string | null };
    if (!v.ok) broken.push(`${what}: its first ${n} event(s) do not chain (${(v as { reason?: string }).reason})`);
    else if ((v.head ?? null) !== (head ?? null)) broken.push(`${what}: event ${n} is not the one it sealed`);
    else held.push(`${what} (${n})`);
  };
  const traceLines = now.trace.split("\n").filter((l) => l.trim());
  if (sealed.trace) {
    const n = sealed.trace.lines;
    const line = n > 0 ? traceLines[n - 1] : undefined;
    if (n > traceLines.length) broken.push(`the trace: it sealed ${n} line(s), and ${traceLines.length} are here`);
    else if (n > 0 && createHash("sha256").update(line ?? "").digest("hex") !== sealed.trace.last_line_sha256) broken.push(`the trace: line ${n} is not the one it sealed`);
    else held.push(`the trace (${n})`);
  }
  // The attestations and the disputes the same way, each with its own
  // chain's code: the first n lines recomputed, never their hash fields read.
  const checkActs = (what: string, n: number | undefined, head: string | null | undefined, text: string, verify: (t: string) => { ok: boolean; reason: string | null; head: string | null }) => {
    if (n === undefined) return;
    const lines = text.split("\n").filter((l) => l.trim());
    if (n > lines.length) {
      broken.push(`${what}: it sealed ${n} line(s), and ${lines.length} are here`);
      return;
    }
    const v = n > 0 ? verify(`${lines.slice(0, n).join("\n")}\n`) : { ok: true, reason: null, head: null as string | null };
    if (!v.ok) broken.push(`${what}: its first ${n} line(s) do not chain (${v.reason})`);
    else if ((v.head ?? null) !== (head ?? null)) broken.push(`${what}: line ${n} is not the one it sealed`);
    else held.push(`${what} (${n})`);
  };
  if (sealed.ledger) check("the ledger", sealed.ledger.entries, sealed.ledger.head, verifyLedgerChain(now.ledger).hashes);
  checkActs("the attestations", sealed.attestations?.lines, sealed.attestations?.head, now.attestations, verifyAttestationChain);
  checkActs("the disputes", sealed.disputes?.lines, sealed.disputes?.head, now.disputes, verifyDisputeChain);
  checkChain("the lead register", sealed.leads?.lines, sealed.leads?.head, now.leads);
  checkChain("the question register", sealed.questions?.lines, sealed.questions?.head, now.questions);
  checkChain("the network grants", sealed.network?.grants.lines, sealed.network?.grants.head, now.grants);
  checkChain("the network fetches", sealed.network?.fetches.lines, sealed.network?.fetches.head, now.fetches);
  if (now.requests !== undefined) checkChain("the operator requests", sealed.requests?.lines, sealed.requests?.head, now.requests ?? "");
  if (now.sweeps !== undefined) checkActs("the store sweeps", sealed.sweeps?.lines, sealed.sweeps?.head, now.sweeps, verifySweepChain);
  if (now.finish !== undefined) checkChain("the finish register", sealed.finish?.lines, sealed.finish?.head, now.finish);
  if (sealed.journal) check("the store journal", sealed.journal.lines, sealed.journal.head, now.journal === null ? [] : verifyJournalText(now.journal).hashes);
  if (sealed.model_gateway && now.gateway === null && sealed.model_gateway.lines > 0) {
    broken.push(`the model gateway log it sealed (${sealed.model_gateway.lines} lines) is not here`);
  } else if (sealed.model_gateway && now.gateway !== null) {
    const lines = now.gateway.split("\n").filter((l) => l.trim());
    const first = lines.slice(0, sealed.model_gateway.lines);
    const sha = first.length ? createHash("sha256").update(`${first.join("\n")}\n`).digest("hex") : null;
    if (first.length < sealed.model_gateway.lines) broken.push(`the model gateway log: it sealed ${sealed.model_gateway.lines} line(s), and ${lines.length} are here`);
    else if (sealed.model_gateway.sha256 && sha !== sealed.model_gateway.sha256) broken.push("the model gateway log: its first lines are not the ones it sealed");
    else held.push(`the model gateway log (${sealed.model_gateway.lines})`);
  }
  return { ok: broken.length === 0, held, broken };
}

/**
 * Every verdict the anchor names before the current one, each held to the
 * run as a prefix (sealPrefix), and whether a resume came after it: a run
 * resumed after a seal still verifies against that seal for what it held.
 */
export async function earlierSeals(sandbox: string): Promise<EarlierSeal[]> {
  let anchor: { custody?: Array<{ at?: string; sha256?: string; seal?: Partial<Seal> }>; resumes?: Array<{ at?: string }> } = {};
  try {
    anchor = JSON.parse(await readRegularTextOutside(await anchorPathFor(sandbox)));
  } catch {
    return [];
  }
  const verdicts = Array.isArray(anchor.custody) ? anchor.custody : [];
  const resumes = Array.isArray(anchor.resumes) ? anchor.resumes : [];
  const read = async (rel: string) => {
    const r = await readRegularText(join(sandbox, rel), 1 << 30);
    return "text" in r ? r.text : "";
  };
  const journal = await readRegularText(join(sandbox, "store", "journal.jsonl"), 1 << 30);
  const gateway = await readRegularText(join(sandbox, GATEWAY_LOG), 1 << 30);
  const now = {
    trace: await read(join("traces", "events.jsonl")),
    ledger: await read(join("ledger", "entries.jsonl")),
    attestations: await read(join("ledger", "attestations.jsonl")),
    disputes: await read(join("ledger", "disputes.jsonl")),
    leads: await read(join("leads", "leads.jsonl")),
    questions: await read(join("questions", "questions.jsonl")),
    grants: await read(GRANTS_LOG),
    fetches: await read(FETCH_LOG),
    requests: await read(join("requests", "requests.jsonl")),
    sweeps: await read(LEDGER_SWEEPS),
    finish: await read(FINISH_LOG),
    journal: "text" in journal ? journal.text : null,
    gateway: "text" in gateway ? gateway.text : null,
  };
  return verdicts.slice(0, -1).map((v) => {
    const p = sealPrefix(v.seal, now);
    return { at: v.at ?? null, sha256: v.sha256 ?? null, resumed_after: resumes.some((r) => typeof r.at === "string" && typeof v.at === "string" && r.at > v.at), ok: p.ok, held: p.held, broken: p.broken };
  });
}

export type TimestampCheck = { present: boolean; imprint: boolean | null; gen_time: string | null; signature: { verified: boolean | null; ca: string | null; detail: string } | null; note: string };

export type VerifyReport = {
  sandbox: string;
  verdict: { at: string | null; anchor: string };
  prefix: { sealed_lines: number; intact: boolean; detail: string };
  after_seal: { lines: number; tools: string[]; closure_only: boolean };
  changed: Array<{ check: string; sealed: string | null; now: string }>;
  /** Each sealed chain that is not as sealed; `seal_after` what followed the seal and may (examiner notes); `not_sealed` what the verdict did not seal. */
  seal_drift: Array<{ what: string; sealed: string; now: string }>;
  seal_after: string[];
  not_sealed: string[];
  /** work/ held to the index custody sealed. */
  work: { index: SealedIndex["state"]; detail: string; drift: WorkDrift | null };
  now: Check[];
  signature: { present: boolean; ok: boolean | null; how: string; detail: string };
  timestamp: TimestampCheck;
  /** What the check wrote outside the run, or found and left alone. */
  touched: string[];
  /** Every earlier verdict the anchor names, held to the run as a prefix (a resumed run's first seal among them). */
  earlier: EarlierSeal[];
  ok: boolean;
};

/**
 * What a third party runs: the checks again, writing nothing in the run,
 * against the verdict that was sealed. The sealed prefix of the trace must
 * be the same bytes; lines after it are named (the run's own closing lines
 * are expected); every chain the verdict sealed must have the length and
 * the head it sealed; every file under work/ must be the one the sealed
 * index names, and none added; each check's status then and now; the
 * signature and the timestamp token, when there are any, the token's own
 * signature against the authority's CA when one is given.
 */
export async function verifyCustody(sandboxInput: string, opts: { timeoutSec?: number; allowedSigners?: string; identity?: string; runsDir?: string; tsaCa?: string; scratchDir?: string } = {}): Promise<VerifyReport> {
  const sandbox = resolve(sandboxInput);
  const { verifySignature } = await import("./custody-checks.ts");
  const { readTimestampResponse } = await import("./custody-checks.ts");
  const sealedText = await readRegularText(join(sandbox, CUSTODY_REL));
  const sealed = "text" in sealedText ? (JSON.parse(sealedText.text) as Custody) : null;
  const anchor = await verdictAnchorState(sandbox);
  const lastAnchored = await lastAnchoredVerdict(sandbox);
  const touched: string[] = [];
  const deadline = new Deadline(opts.timeoutSec ?? 4 * 3600);
  let walked: ArtifactIndex | null = null;
  const now = await takeCustody(sandbox, { readOnly: true, timeoutSec: opts.timeoutSec, runsDir: opts.runsDir, scratchDir: opts.scratchDir, touched, onIndex: (i) => (walked = i) });
  const traceText = await readRegularText(join(sandbox, "traces", "events.jsonl"), 1 << 30);
  const text = "text" in traceText ? traceText.text : "";
  const sealedLines = sealed?.seal?.trace?.lines ?? 0;
  const lines = text.split("\n").filter((l) => l.trim());
  const lastSealed = sealedLines > 0 ? lines[sealedLines - 1] : undefined;
  const prefixOk = !sealed?.seal ? false : sealedLines === 0 ? true : lastSealed !== undefined && createHash("sha256").update(lastSealed).digest("hex") === sealed.seal.trace.last_line_sha256;
  const tail = afterSeal(text, sealedLines);
  const before = new Map((sealed?.checks ?? []).map((x) => [x.name, x.status]));
  const changed = now.checks.filter((x) => (before.get(x.name) ?? null) !== x.status).map((x) => ({ check: x.name, sealed: before.get(x.name) ?? null, now: x.status }));
  // Every chain against the head and the length the verdict sealed.
  const journalRead = await readRegularText(join(sandbox, "store", "journal.jsonl"), 1 << 30);
  const journal = "text" in journalRead ? (() => {
    const j = verifyJournalText(journalRead.text);
    return { hashes: j.hashes, types: j.lines.map((l) => String((l as { type?: unknown }).type ?? "")) };
  })() : null;
  const requestsRead = await readRegularText(join(sandbox, "requests", "requests.jsonl"), 1 << 30);
  const seal = sealDrift(sealed?.seal, now.seal, journal, { requests: lineHashField("text" in requestsRead ? requestsRead.text : "") });
  // work/ against the index custody sealed.
  const idx = await sealedIndex(sandbox, sealed, lastAnchored?.artifacts_sha256);
  const drift = idx.state === "sealed" ? await workDrift(sandbox, idx.index, deadline, walked) : null;
  const driftLine = drift ? workDriftLine(drift) : "";
  const work: VerifyReport["work"] = {
    index: idx.state,
    detail: idx.state === "sealed"
      ? driftLine ? `NOT AS SEALED: ${driftLine}` : `every one of the ${idx.index.files?.length ?? 0} files the sealed index names is as sealed, and none was added`
      : idx.state === "differs" ? `THE SEALED INDEX CANNOT BE HELD TO: ${idx.why}` : `not held to an index: ${idx.why}`,
    drift,
  };
  const sigPath = join(sandbox, `${CUSTODY_REL}.sig`);
  const sig = existsSync(sigPath) ? await verifySignature(join(sandbox, CUSTODY_REL), sigPath, opts.allowedSigners, opts.identity) : null;
  const tsrPath = join(sandbox, `${CUSTODY_REL}.tsr`);
  let ts: TimestampCheck = { present: false, imprint: null, gen_time: null, signature: null, note: "no timestamp token" };
  if (existsSync(tsrPath) && "text" in sealedText) {
    const read = readTimestampResponse(readFileSync(tsrPath), createHash("sha256").update(sealedText.text).digest("hex"));
    const recorded = (lastAnchored?.timestamp as { signature?: { verified?: boolean | null; ca?: string; detail?: string } } | undefined)?.signature;
    const ca = opts.tsaCa ?? null;
    const signature = ca
      ? { ...(await verifyTimestampToken(tsrPath, join(sandbox, CUSTODY_REL), ca)), ca }
      : recorded?.verified === false
        ? { verified: false, ca: recorded.ca ?? null, detail: `the token did not verify when custody took it (${recorded.detail ?? "no detail"}), and no CA is given here to check it again` }
        : { verified: null, ca: null, detail: recorded?.verified === true ? `imprint only, signature not verified here (no CA given: --tsa-ca FILE); the anchor says it verified against ${recorded.ca ?? "a CA"} when custody took it` : "imprint only, signature not verified (no CA given: --tsa-ca FILE)" };
    ts = {
      present: true,
      imprint: read.imprint,
      gen_time: read.gen_time,
      signature,
      note: `the token names this verdict's sha256: ${read.imprint ? "yes" : "NO"}; its signature: ${signature.verified === true ? `verified against ${signature.ca}` : signature.verified === false ? `DOES NOT VERIFY (${signature.detail})` : ca ? `NOT CHECKED (${signature.detail})` : signature.detail}`,
    };
  }
  const report: VerifyReport = {
    sandbox,
    verdict: { at: sealed?.at ?? null, anchor: verdictAnchorLine(anchor) || anchor.state },
    prefix: { sealed_lines: sealedLines, intact: prefixOk, detail: !sealed ? "no verdict to hold the run to" : !sealed.seal ? "the verdict predates the seal (no sealed prefix to compare)" : prefixOk ? `the first ${sealedLines} lines are the ones sealed` : `THE SEALED PREFIX CHANGED: line ${sealedLines} is not the line the verdict sealed` },
    after_seal: tail,
    changed,
    seal_drift: seal.drift,
    seal_after: seal.after,
    not_sealed: seal.not_sealed,
    work,
    now: now.checks,
    signature: sig ? { present: true, ok: sig.ok, how: sig.how, detail: sig.detail } : { present: false, ok: null, how: "none", detail: "custody.json is not signed" },
    timestamp: ts,
    touched,
    earlier: await earlierSeals(sandbox),
    ok: false,
  };
  // A token's signature fails the check when it does not verify, and when a CA was given and it could not be checked.
  const tsOk = !ts.present || (ts.imprint === true && ts.signature?.verified !== false && !(opts.tsaCa && ts.signature?.verified !== true));
  report.ok =
    Boolean(sealed) &&
    anchor.state === "matches" &&
    prefixOk &&
    tail.closure_only &&
    !adverse(now).length &&
    !seal.drift.length &&
    work.index !== "differs" &&
    !driftLine &&
    (sig ? sig.ok : true) &&
    tsOk &&
    report.earlier.every((e) => e.ok);
  return report;
}

/** The last verdict the anchor outside the run names, as written there; null when there is none. */
async function lastAnchoredVerdict(sandbox: string): Promise<Record<string, unknown> & { artifacts_sha256?: string | null; timestamp?: unknown } | null> {
  try {
    const anchor = JSON.parse(await readRegularTextOutside(await anchorPathFor(sandbox))) as { custody?: unknown };
    const verdicts = Array.isArray(anchor.custody) ? (anchor.custody as Array<Record<string, unknown>>) : [];
    return (verdicts.at(-1) as (Record<string, unknown> & { artifacts_sha256?: string | null }) | undefined) ?? null;
  } catch {
    return null;
  }
}

/** The run's custody set-up from the registry beside it: sign key, timestamp authority and its CA, reference clock. */
async function registrySeal(sandbox: string, run: string | undefined, runsDirGiven?: string): Promise<{ signKey?: string; timestampUrl?: string; timestampCa?: string; timeReference?: string }> {
  try {
    const runsDir = runsDirGiven ?? dirname(await realpath(sandbox).catch(() => sandbox));
    const reg = JSON.parse(readFileSync(join(runsDir, "registry.json"), "utf8")) as { runs?: Array<Record<string, unknown>> };
    const rec = (reg.runs ?? []).find((r) => (run && r.id === run) || r.sandbox === sandbox) ?? null;
    const seal = (rec?.custody_seal ?? {}) as { sign_key?: string; timestamp_url?: string; timestamp_ca?: string; time_reference?: string };
    return {
      ...(seal.sign_key ? { signKey: seal.sign_key } : {}),
      ...(seal.timestamp_url ? { timestampUrl: seal.timestamp_url } : {}),
      ...(seal.timestamp_ca ? { timestampCa: seal.timestamp_ca } : {}),
      ...(seal.time_reference ? { timeReference: seal.time_reference } : {}),
    };
  } catch {
    return {};
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const args = process.argv.slice(2);
  const sandbox = args.find((a, i) => !a.startsWith("--") && !["--timeout", "--run", "--sign-key", "--timestamp-url", "--timestamp-ca", "--tsa-ca", "--time-reference", "--runs-dir", "--allowed-signers", "--identity", "--scratch"].includes(args[i - 1] ?? ""));
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  if (!sandbox || !existsSync(sandbox)) {
    console.error("usage: custody.ts <sandbox> [--timeout SEC] [--run ID] [--quiet] [--sign-key FILE] [--timestamp-url URL] [--timestamp-ca FILE] [--time-reference URL] [--runs-dir DIR]\n       custody.ts <sandbox> --verify [--allowed-signers FILE --identity NAME] [--tsa-ca FILE] [--scratch DIR] [--json]");
    process.exit(2);
  }
  const timeoutSec = opt("--timeout") ? Number(opt("--timeout")) : 4 * 3600;
  if (args.includes("--verify")) {
    // Exit 0: the run is as the verdict sealed it; 4: something differs or a check does not pass; 1: the verify could not run.
    // The authority's CA: the flag, the environment, or the run's own set-up.
    const fromRegistry = await registrySeal(resolve(sandbox), opt("--run"), opt("--runs-dir"));
    const tsaCa = opt("--tsa-ca") ?? process.env.SWARM_CUSTODY_TSA_CA ?? fromRegistry.timestampCa;
    verifyCustody(sandbox, { timeoutSec, allowedSigners: opt("--allowed-signers"), identity: opt("--identity"), runsDir: opt("--runs-dir"), tsaCa, scratchDir: opt("--scratch") })
      .then((r) => {
        if (args.includes("--json")) console.log(JSON.stringify(r, null, 2));
        else {
          console.log(`Verdict:      ${r.verdict.at ?? "none"} (${r.verdict.anchor})`);
          console.log(`Sealed:       ${r.prefix.detail}`);
          console.log(`After seal:   ${r.after_seal.lines} line(s)${r.after_seal.lines ? `: ${r.after_seal.tools.join(", ")}${r.after_seal.closure_only ? " (the run's own closing lines)" : " (NOT ONLY THE RUN'S CLOSING LINES)"}` : ""}${r.seal_after.length ? `; ${r.seal_after.join("; ")}` : ""}`);
          console.log(`Chains:       ${r.seal_drift.length ? `NOT AS SEALED: ${r.seal_drift.map((d) => `${d.what} sealed ${d.sealed}, now ${d.now}`).join("; ")}` : "each chain has the length and the head the verdict sealed"}${r.not_sealed.length ? ` (not sealed by this verdict: ${r.not_sealed.join(", ")})` : ""}`);
          console.log(`Work files:   ${r.work.detail}`);
          console.log(`Checks now:   ${checksLine(r.now)}`);
          if (r.changed.length) console.log(`Changed:      ${r.changed.map((x) => `${x.check} ${x.sealed ?? "absent"} → ${x.now}`).join("; ")}`);
          console.log(`Signature:    ${r.signature.present ? `${r.signature.ok ? "valid" : "NOT VALID"} (${r.signature.how})` : r.signature.detail}`);
          console.log(`Timestamp:    ${r.timestamp.present ? `${r.timestamp.gen_time ?? "time unread"}; ${r.timestamp.note}` : r.timestamp.note}`);
          if (r.touched.length) console.log(`Outside run:  ${r.touched.join("; ")}`);
          for (const e of r.earlier) console.log(`Earlier seal: ${e.at ?? "?"} (${e.sha256 ?? "?"})${e.resumed_after ? ", before a resume" : ""}: ${e.ok ? `holds as a prefix: ${e.held.join(", ")}` : `DOES NOT HOLD AS A PREFIX: ${e.broken.join("; ")}`}`);
          console.log(r.ok ? `VERIFIED: the run is as the verdict sealed it${r.earlier.length ? `, and ${r.earlier.length === 1 ? "the earlier seal holds" : `each of the ${r.earlier.length} earlier seals holds`} as a prefix` : ""}.` : "NOT VERIFIED: see above.");
        }
        process.exit(r.ok ? 0 : 4);
      })
      .catch((err) => {
        console.error(`custody --verify: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      });
  } else {
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
    const fromRegistry = await registrySeal(resolve(sandbox), opt("--run"));
    takeCustody(sandbox, {
      timeoutSec,
      run: opt("--run"),
      state,
      progress: args.includes("--quiet") ? undefined : (line) => console.error(line),
      signKey: opt("--sign-key") ?? fromRegistry.signKey,
      timestampUrl: opt("--timestamp-url") ?? fromRegistry.timestampUrl,
      timestampCa: opt("--timestamp-ca") ?? fromRegistry.timestampCa,
      timeReference: opt("--time-reference") ?? fromRegistry.timeReference,
      runsDir: opt("--runs-dir"),
    })
      .then((c) => {
        console.log(c.summary);
        // 3: incomplete; 4: complete, and a check did not pass (evidence changed, a chain broken, ...); 0: every check passed or did not apply.
        process.exit(c.incomplete ? 3 : adverse(c).length ? 4 : 0);
      })
      .catch((err) => {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`custody: ${message}`);
        const summary = writePartial(`custody failed during ${state.phase}: ${message}`);
        if (summary) console.log(summary);
        process.exit(1);
      });
  }
}
