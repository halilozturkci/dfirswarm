/**
 * virtualization-backup-forensics: backup_audit_normalise presets (named sets of the declared-mapping parameters, held as reviewed files under
 * tools/backup_audit_normalise/presets/ and checked against a sha256 list in run.py), the JSON array reader (declared_json), and the first preset, the
 * Proxmox Backup client's snapshot listing (`proxmox-backup-client snapshot list --output-format json`).
 *
 * Every fixture is SYNTHETIC. The listing's fields come from the Proxmox Backup source (pbs-api-types, SnapshotListItem: backup-type, backup-id, backup-time,
 * comment, owner, size, files, protected, as served by git.proxmox.com, retrieved 2026-11-03); the values are invented. Nothing was checked against a real export.
 */
import assert from "node:assert/strict";
import { createWriteStream } from "node:fs";
import { cp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { AUDIT, CANARY, asJob, body, json, put, startDetached, tool, withCwd } from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const T0 = 1709604000;
const snap = (i: number, extra: Json = {}): Json => ({ "backup-type": "vm", "backup-id": String(100 + i), "backup-time": T0 + i * 3600, owner: "root@pam", comment: `run ${i}`, size: 1000 + i, files: [{ filename: "a.img.fidx", size: 5 }], protected: false, ...extra });
const PRESET = "proxmox_backup_client";

async function list(cwd: string, name: string, text: string | Buffer, args: Record<string, unknown> = { product: PRESET }) {
  await put(cwd, `in/${name}`, text);
  return tool(AUDIT, cwd, { path: `in/${name}`, ...args });
}

test("the PBS client snapshot list preset: a clean array, each snapshot an event, the answer names preset@revision and its provenance", async () => {
  await withCwd(async (cwd) => {
    const out = body(await list(cwd, "snaps.json", JSON.stringify([snap(0), snap(1, { "backup-type": "ct" }), snap(2, { "backup-type": "host", "backup-id": "srv01" })], null, 1)));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.preset, "proxmox_backup_client_snapshot_list@1");
    assert.equal(out.sources[0].format, "declared_json");
    assert.equal(out.counts.events, 3);
    assert.deepEqual(out.events.map((e: Json) => e.object), ["100", "101", "srv01"]);
    assert.equal(out.events[0].time_utc, "2024-03-05T02:00:00Z");
    assert.equal(out.events[0].category, "backup_end");
    assert.equal(out.events[0].actor, "root@pam");
    assert.equal(out.events[0].result, "unknown");
    const p = out.provenance[0];
    assert.equal(p.schema_basis, "vendor_documentation");
    assert.equal(p.validated_against_real_export, false);
    assert.equal(p.preset, out.preset);
    assert.match(p.documentation, /retrieved 2026-11-03/);
  });
});

test("an unknown extra field is tolerated; a missing time field makes the answer partial; a time that is not epoch seconds is not guessed", async () => {
  await withCwd(async (cwd) => {
    const extra = body(await list(cwd, "a.json", JSON.stringify([snap(0, { surprise: { nested: 1 } })])));
    assert.equal(extra.status, "complete");
    const noTime = snap(1);
    delete noTime["backup-time"];
    const miss = body(await list(cwd, "b.json", JSON.stringify([snap(0), noTime])));
    assert.equal(miss.status, "partial");
    assert.match(miss.partial_reasons.join(" "), /backup-time/);
    assert.equal(miss.events[1].time_utc, null);
    const odd = body(await list(cwd, "c.json", JSON.stringify([snap(0, { "backup-time": "2024-03-05 02:00:00" })])));
    assert.equal(odd.events[0].time_utc, null);
    assert.match(odd.events[0].time_basis, /does not match|not a usable epoch/);
    assert.equal(odd.status, "partial");
  });
});

test("a tampered preset is refused by name: one changed byte, a link in its place, a missing file", async () => {
  await withCwd(async (cwd) => {
    await cp(join(AUDIT, ".."), join(cwd, "tool", "backup_audit_normalise"), { recursive: true });
    const script = join(cwd, "tool", "backup_audit_normalise", "run.py");
    const file = join(cwd, "tool", "backup_audit_normalise", "presets", "proxmox-backup-client-snapshot-list.json");
    await put(cwd, "in/s.json", JSON.stringify([snap(0)]));
    const ok = body(await tool(script, cwd, { path: "in/s.json", product: PRESET }));
    assert.equal(ok.status, "complete");
    const orig = await readFile(file);
    const changed = Buffer.from(orig);
    changed[changed.indexOf(Buffer.from("backup-time"))] ^= 0x01;           // one byte of one field name
    await writeFile(file, changed);
    const bad = json(await tool(script, cwd, { path: "in/s.json", product: PRESET }));
    assert.equal(bad.status, "failed");
    assert.match(JSON.stringify(bad), /proxmox-backup-client-snapshot-list\.json was changed/);
    assert.equal(bad.counts?.events ?? 0, 0);
    await writeFile(file, Buffer.concat([orig, Buffer.from(" ")]));
    assert.match(JSON.stringify(json(await tool(script, cwd, { path: "in/s.json", product: PRESET }))), /was changed/);
    await rm(file);
    await symlink(join(cwd, "in", "s.json"), file);
    assert.match(JSON.stringify(json(await tool(script, cwd, { path: "in/s.json", product: PRESET }))), /cannot be read/);
    await rm(file);
    assert.match(JSON.stringify(json(await tool(script, cwd, { path: "in/s.json", product: PRESET }))), /cannot be read/);
    await writeFile(file, orig);
    assert.equal(body(await tool(script, cwd, { path: "in/s.json", product: PRESET })).status, "complete");
  });
});

test("an unknown product is refused by name as before; a preset is not mixed with a mapping of the caller's own; an unknown preset name is refused", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/s.json", JSON.stringify([snap(0)]));
    const unknown = json(await tool(AUDIT, cwd, { path: "in/s.json", product: "nonesuch" }));
    assert.equal(unknown.status, "failed");
    assert.match(JSON.stringify(unknown), /unsupported/);
    const veeam = json(await tool(AUDIT, cwd, { path: "in/s.json", product: "veeam" }));
    assert.match(JSON.stringify(veeam), /unsupported/);
    const mixed = json(await tool(AUDIT, cwd, { path: "in/s.json", product: PRESET, mapping: { time: "backup-time", action: "backup-type" } }));
    assert.equal(mixed.status, "failed");
    assert.match(JSON.stringify(mixed), /fixes mapping/);
    for (const extra of [{ result_map: { ok: "ok" } }, { time_format: "iso8601" }, { time_zone_offset_minutes: 60 }]) {
      const beside = json(await tool(AUDIT, cwd, { path: "in/s.json", product: PRESET, ...extra }));
      assert.equal(beside.status, "failed", JSON.stringify(extra));
      assert.match(JSON.stringify(beside), /fixes /);
    }
    assert.equal(body(await tool(AUDIT, cwd, { path: "in/s.json", product: PRESET })).events[0].category, "backup_end");
    await put(cwd, "in/u.json", JSON.stringify([snap(0, { "backup-type": "newkind" })]));
    assert.equal(body(await tool(AUDIT, cwd, { path: "in/u.json", product: PRESET })).events[0].category, "other", "a backup type outside vm, ct and host is not labelled backup_end");
    const wrongFormat = json(await tool(AUDIT, cwd, { path: "in/s.json", product: PRESET, format: "declared_csv" }));
    assert.match(JSON.stringify(wrongFormat), /reads format declared_json/);
    const named = json(await tool(AUDIT, cwd, { path: "in/s.json", preset: "not_a_preset" }));
    assert.match(JSON.stringify(named), /none of this tool's presets/);
    const byName = body(await tool(AUDIT, cwd, { path: "in/s.json", preset: "proxmox_backup_client_snapshot_list" }));
    assert.equal(byName.preset, "proxmox_backup_client_snapshot_list@1");
  });
});

test("declared_json with a mapping of the caller's own: an array of records, an element that is not an object is unparsed, provenance says caller_declared_mapping", async () => {
  await withCwd(async (cwd) => {
    const out = body(await list(cwd, "x.json", JSON.stringify([{ t: "2024-03-05T02:00:00Z", a: "Delete", who: "svc" }, 7, { t: "2024-03-05T03:00:00Z", a: "Backup" }]),
      { format: "declared_json", product: "Example", mapping: { time: "t", action: "a", actor: "who" }, category_map: { delete: "retention_remove" } }));
    assert.equal(out.counts.events, 2);
    assert.equal(out.counts.unparsed, 1);
    assert.equal(out.problem_lines[0].record, 2);
    assert.equal(out.events[0].category, "retention_remove");
    assert.equal(out.provenance[0].schema_basis, "caller_declared_mapping");
    assert.equal(out.preset, null);
  });
});

test("the array reader is strict: not an array, a cut file, a syntax error and a trailing comma stop the read at that element and are counted and located", async () => {
  await withCwd(async (cwd) => {
    const args = { format: "declared_json", mapping: { time: "t", action: "a" } };
    const el = (i: number) => `{"t":"2024-03-05T02:00:0${i}Z","a":"x"}`;
    for (const [name, text, events, reason] of [
      ["obj.json", el(1), 0, /begins with \[/],
      ["cut.json", "[" + el(1) + "," + el(2), 2, /no closing \]/],
      ["bad.json", "[" + el(1) + ",{\"t\": nope}," + el(2) + "]", 1, /not valid JSON/],
      ["comma.json", "[" + el(1) + ",]", 1, /after a comma/],
      ["empty.json", "", 0, /empty file/],
      ["glue.json", "[" + el(1) + el(2) + "]", 1, /expected , or \]/],
    ] as const) {
      const out = json(await list(cwd, name, text, args));
      assert.equal(out.counts.events, events, name);
      assert.equal(out.counts.unparsed, 1, name);
      assert.match(out.problem_lines[0].reason, reason, name);
      assert.notEqual(out.status, "complete", name);
    }
    const ok = body(await list(cwd, "ok.json", "﻿ [ " + el(1) + " , " + el(2) + " ] \n", args));
    assert.equal(ok.counts.events, 2);
    assert.equal(ok.status, "complete");
    const empty = body(await list(cwd, "none.json", "[]", args));
    assert.equal(empty.counts.events, 0);
  });
});

test("nesting and size bombs: 500,000 open brackets, a number of 100,000 digits, an element of 10 MB (located, the read ends), NUL bytes and invalid UTF-8", async () => {
  await withCwd(async (cwd) => {
    const args = { format: "declared_json", mapping: { time: "t", action: "a" } };
    const bomb = json(await list(cwd, "bomb.json", "[" + "[".repeat(500000), args));
    assert.equal(bomb.counts.unparsed, 1);
    const num = json(await list(cwd, "num.json", '[{"t":"2024-03-05T02:00:00Z","a":' + "9".repeat(100000) + "}]", args));
    assert.doesNotMatch(JSON.stringify(num), /Traceback/);
    assert.equal(num.counts.events + num.counts.unparsed >= 1, true);
    const big = json(await list(cwd, "big.json", '[{"t":"2024-03-05T02:00:00Z","a":"first"},{"t":"2024-03-05T02:00:00Z","a":"' + "x".repeat(10 << 20) + '"},{"t":"2024-03-05T02:00:00Z","a":"third"}]', args));
    assert.equal(big.counts.events, 1);
    assert.equal(big.counts.over_line_limit, 1);
    assert.equal(big.status, "partial");
    assert.equal(big.problem_lines[0].record, 2);
    const raw = Buffer.concat([Buffer.from('[{"t":"2024-03-05T02:00:00Z","a":"nul \\u0000 and '), Buffer.from([0xff, 0xfe]), Buffer.from(' bytes"},\0{"t":"x"}]')]);
    const odd = await list(cwd, "odd.json", raw, args);
    assert.doesNotMatch(odd.stderr, /Traceback/);
    assert.equal(json(odd).counts.events, 1);
  });
});

async function bigArray(path: string, n: number): Promise<void> {
  const ws = createWriteStream(path);
  const w = (s: string) => new Promise<void>((r) => (ws.write(s) ? r() : ws.once("drain", () => r())));
  await w("[\n");
  let buf: string[] = [];
  for (let i = 0; i < n; i++) {
    buf.push(`{"backup-type":"vm","backup-id":"${i % 5000}","backup-time":${T0 + i},"owner":"root@pam"}${i + 1 < n ? "," : ""}`);
    if (buf.length === 20000) { await w(buf.join("\n") + "\n"); buf = []; }
  }
  await w(buf.join("\n") + "\n]\n");
  await new Promise<void>((r) => ws.end(r));
}

test("an array of a million snapshots is read within max_seconds, the whole list is on disk, the inline list is cut", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/x", "");
    await bigArray(join(cwd, "in/big.json"), 1_000_000);
    const t0 = Date.now();
    const run = await asJob(AUDIT, cwd, { path: "in/big.json", product: PRESET, max_seconds: 30, limit: 100000 });
    assert.ok((Date.now() - t0) / 1000 < 58);
    const out = json(run);
    assert.ok(["complete", "partial"].includes(out.status));
    if (out.status === "complete") assert.equal(out.counts.events, 1_000_000);
    assert.ok(Buffer.byteLength(run.stdout) < 2_000_000);
    assert.ok(out.pages.events.all_results);
  });
});

test("a SIGTERM during a long read ends with one JSON answer, partial, exit 143", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "in/x", "");
    await bigArray(join(cwd, "in/big.json"), 700_000);
    const child = startDetached(AUDIT, cwd, { path: "in/big.json", product: PRESET, max_seconds: 50 }, { JOB_ID: "j000557", OUT: join(cwd, "out") });
    await new Promise((r) => setTimeout(r, 600));
    child.signal("SIGTERM");
    const code = await child.closed;
    const out = JSON.parse(child.stdout());
    if (code === 143) {
      assert.equal(out.status, "partial");
      assert.match(JSON.stringify(out), /SIGTERM/);
    } else {
      assert.equal(code, 0, "the run had already ended");
    }
  });
});

test("canaries in the backup id (a job or machine name), the owner and the comment never reach the answer; the comment goes to the secret-output text file only", async () => {
  await withCwd(async (cwd) => {
    const secrets = [CANARY.github, CANARY.aws, CANARY.hex, CANARY.userinfo];
    const items = [
      snap(0, { "backup-id": CANARY.github }),
      snap(1, { owner: `${CANARY.userinfo}@pbs`, comment: `token=${CANARY.aws} and https://${CANARY.userinfo}@h.example.net` }),
      snap(2, { "backup-id": `vm-${CANARY.hex}`, comment: `password ${CANARY.hex}` }),
    ];
    await put(cwd, "in/s.json", JSON.stringify(items));
    const run = await asJob(AUDIT, cwd, { path: "in/s.json", product: PRESET, write_text: true });
    for (const s of secrets) {
      for (let i = 0; i + 12 <= s.length; i += 3) assert.ok(!run.stdout.includes(s.slice(i, i + 12)), `a window of a canary is in the answer (${s.slice(0, 4)}...)`);
    }
    assert.equal(json(run).counts.events, 3);
  });
});

test("anything after the closing ] is not read and not called complete: a second record, a second array, text; trailing white space is fine", async () => {
  await withCwd(async (cwd) => {
    const args = { format: "declared_json", mapping: { time: "t", action: "a", object: "o" } };
    const r1 = '{"t":"2024-01-01T00:00:00Z","a":"backup","o":"x"}';
    const r2 = '{"t":"2024-01-02T00:00:00Z","a":"delete","o":"y"}';
    for (const [name, text] of [["rec.json", `[${r1}]\n${r2}\n`], ["arr.json", `[${r1}][${r2}]`], ["junk.json", `[${r1}] garbage`], ["emptyarr.json", `[] ${r1}`]] as const) {
      const out = json(await list(cwd, name, text, args));
      assert.equal(out.counts.unparsed, 1, name);
      assert.equal(out.status, "partial", name);
      assert.match(out.problem_lines[0].reason, /content after the closing \] \(at character \d+\)/, name);
      assert.equal(out.counts.events, name === "emptyarr.json" ? 0 : 1, name);
    }
    for (const text of [`[${r1}]`, `[${r1}]\n`, `[${r1}] \t\r\n\n\n`, `[ ]\n`]) {
      const out = body(await list(cwd, "ok.json", text, args));
      assert.equal(out.status, "complete", JSON.stringify(text));
    }
    const at = json(await list(cwd, "at.json", `[${r1}] x`, args));
    assert.match(at.problem_lines[0].reason, new RegExp(`at character ${r1.length + 3}\\)`), "the offset points at the first character after the white space");
  });
});
