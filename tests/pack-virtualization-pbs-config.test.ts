/**
 * virtualization-backup-forensics: backup_audit_normalise reads Proxmox Backup Server configuration files (format pbs_config).
 *
 * Every fixture is SYNTHETIC and written here from the Proxmox Backup documentation page "Configuration Files" (its title read "Proxmox Backup 4.2.8-1
 * documentation", retrieved 2026-11-03): a header `<type>: <id>` at column 0 and the object's properties indented below it, `<name> <value>`. The property
 * names are the ones the page lists; the values are invented. None of this was checked against a real export, and the answer says so.
 */
import assert from "node:assert/strict";
import { createWriteStream } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { AUDIT, CANARY, asJob, body, everythingBut, json, put, startDetached, tool, withCwd } from "./pack-virtualization-harness.ts";
import type { Json } from "./pack-virtualization-harness.ts";

const DATASTORE = [
  "datastore: store1",
  "\tpath /mnt/datastore/store1",
  "\tcomment nightly store",
  "\tgc-schedule sat 04:00",
  "\tprune-schedule daily",
  "\tkeep-last 3",
  "\tkeep-daily 7",
  "\tkeep-weekly 4",
  "\tkeep-monthly 6",
  "\tkeep-yearly 1",
  "\tnotify gc=always,prune=error,sync=never",
  "",
  "datastore: store2",
  "   path /mnt/datastore/store2",
  "   tuning gc-atime-safety-check=1",
  "",
].join("\n");
const PRUNE = ["prune: job-a", "\tschedule daily", "\tstore store1", "\tkeep-hourly 2", "\tkeep-daily 5", "\tmax-depth 3", "\tns team-a", ""].join("\n");
const SYNC = ["sync: pull-1", "\tstore store1", "\tremote-store offsite", "\tremote r1", "\tschedule hourly", "\tremove-vanished true", "\tsync-direction pull", ""].join("\n");
const VERIFY = ["verification: v1", "\tstore store1", "\tschedule weekly", "\toutdated-after 30", "\tignore-verified true", ""].join("\n");
const REMOTE = ["remote: r1", "\thost backup.example.net", "\tauth-id sync@pbs!job", "\tpassword " + Buffer.from("not-a-real-password").toString("base64"), "\tfingerprint aa:bb:cc", "\tport 8007", ""].join("\n");

async function read(cwd: string, name: string, text: string, extra: Record<string, unknown> = {}): Promise<Json> {
  await put(cwd, `etc/${name}`, text);
  return body(await tool(AUDIT, cwd, { path: `etc/${name}`, ...extra }));
}

test("each documented file type, clean: recognised by file name and first section, settings read as records, nothing unparsed", async () => {
  await withCwd(async (cwd) => {
    for (const [name, text, type, count] of [
      ["datastore.cfg", DATASTORE, "datastore", 12],
      ["prune.cfg", PRUNE, "prune", 6],
      ["sync.cfg", SYNC, "sync", 6],
      ["verification.cfg", VERIFY, "verification", 4],
      ["remote.cfg", REMOTE, "remote", 5],
    ] as const) {
      const out = await read(cwd, name, text);
      assert.equal(out.status, "complete", `${name}: ${out.status_basis}`);
      assert.equal(out.sources[0].format, "pbs_config");
      assert.equal(out.counts.unparsed, 0);
      const settings = out.events.filter((e: Json) => e.setting);
      assert.equal(settings.length, count, name);
      assert.ok(settings.every((e: Json) => e.setting.section_type === type));
      const p = out.provenance.find((x: Json) => x.format === "pbs_config");
      assert.equal(p.validated_against_real_export, false);
      assert.equal(p.schema_basis, "vendor_documentation");
    }
  });
});

test("retention settings are read with their values: keep-* as numbers, schedules and notify as written, and flagged as retention", async () => {
  await withCwd(async (cwd) => {
    const out = await read(cwd, "datastore.cfg", DATASTORE);
    const by = (obj: string, prop: string) => out.events.find((e: Json) => e.object === obj && e.setting.property === prop);
    assert.equal(by("store1", "keep-last").setting.value_number, 3);
    assert.equal(by("store1", "keep-yearly").setting.value_number, 1);
    assert.equal(by("store1", "gc-schedule").setting.value, "sat 04:00");
    assert.equal(by("store1", "prune-schedule").setting.value, "daily");
    assert.equal(by("store1", "notify").setting.value, "gc=always,prune=error,sync=never");
    assert.equal(by("store1", "keep-last").retention_setting, true);
    assert.equal(by("store1", "path").retention_setting, false);
    assert.equal(by("store2", "tuning").setting.value, "gc-atime-safety-check=1");
    assert.equal(by("store1", "keep-last").time_utc, null);
    assert.match(by("store1", "keep-last").time_basis, /carries no time/);
    assert.equal(by("store1", "comment").setting.value, null, "a comment is free text and is not printed");
    assert.equal(by("store1", "comment").setting.value_chars, "nightly store".length);
  });
});

test("an unknown section type and an unknown property are counted unparsed and located; the answer is partial; a missing required property is said", async () => {
  await withCwd(async (cwd) => {
    const text = ["datastore: s", "\tpath /p", "\tfrobnicate yes", "\tkeep-last many", "\tnotify gc=sometimes", "", "widget: w", "\tcolour red", "", "prune: j", "\tstore s", ""].join("\n");
    const out = await read(cwd, "datastore.cfg", text);
    assert.equal(out.status, "partial");
    assert.equal(out.counts.unparsed, 5);
    assert.deepEqual(out.problem_lines.map((p: Json) => p.line), [3, 4, 5, 7, 8]);
    assert.match(out.problem_lines[0].reason, /does not list/);
    assert.match(out.partial_reasons.join(" "), /section prune lacks the property the documentation requires: schedule/);
    assert.equal(out.events.length, 2, "path, the prune section's store, and nothing for the lines that were not read");
    const bare = await read(cwd, "x.cfg", "just some text\n", { format: "pbs_config" });
    assert.equal(bare.status, "partial");
    assert.equal(bare.counts.unparsed, 1);
  });
});

test("format auto recognises a configuration file only by its documented name together with a section of its type", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "etc/other.cfg", DATASTORE);
    const wrongName = json(await tool(AUDIT, cwd, { path: "etc/other.cfg" }));
    assert.equal(wrongName.unrecognised.length, 1);
    await put(cwd, "etc/prune.cfg", DATASTORE);
    const wrongType = json(await tool(AUDIT, cwd, { path: "etc/prune.cfg" }));
    assert.equal(wrongType.unrecognised.length, 1);
    const named = await read(cwd, "other.cfg", DATASTORE, { format: "pbs_config" });
    assert.equal(named.sources[0].format, "pbs_config");
  });
});

test("remote.cfg: the password is never printed; it is in the text file of a secret_output job only; every other property of remote.cfg and sync.cfg is sealed", async () => {
  await withCwd(async (cwd) => {
    const pw = CANARY.userinfo.split(":")[1];
    const text = ["remote: r1", "\thost backup.example.net", "\tauth-id sync@pbs!job", "\tpassword " + pw, "\tcomment " + CANARY.aws, ""].join("\n");
    await put(cwd, "etc/remote.cfg", text);
    const plain = await tool(AUDIT, cwd, { path: "etc/remote.cfg" });
    assert.ok(!plain.stdout.includes(pw) && !plain.stdout.includes(CANARY.aws));
    const run = await asJob(AUDIT, cwd, { path: "etc/remote.cfg", write_text: true });
    assert.ok(!run.stdout.includes(pw));
    const everything = await everythingBut(cwd, run.stdout, ["etc/remote.cfg", "out/audit-values.jsonl"]);
    assert.ok(!everything.includes(pw), "not in the answer, a page or any file but the text file");
    // the text file of the job holds it (the values file is skipped by everythingBut; read the tool's own text file)
    const { readdir, readFile } = await import("node:fs/promises");
    const names = (await readdir(join(cwd, "out"))).filter((n) => n.startsWith("audit-values"));
    assert.equal(names.length, 1);
    assert.ok((await readFile(join(cwd, "out", names[0]), "utf8")).includes(pw));
    // a canary in every property of remote.cfg and of sync.cfg
    const remoteAll = ["host", "auth-id", "password", "comment", "fingerprint", "port", "use-node-proxy"];
    const syncAll = ["store", "remote-store", "remote", "schedule", "comment", "owner", "group-filter", "ns", "remote-ns", "active-encryption-key", "associated-key", "transfer-last"];
    for (const [name, type, props] of [["remote.cfg", "remote", remoteAll], ["sync.cfg", "sync", syncAll]] as const) {
      const planted = [`${type}: ${CANARY.hex}`, ...props.map((p, i) => `\t${p} ${[CANARY.github, CANARY.aws, CANARY.hex, `https://${CANARY.userinfo}@h.example.net/x`][i % 4]}`), ""].join("\n");
      await put(cwd, `etc/${name}`, planted);
      const r = await tool(AUDIT, cwd, { path: `etc/${name}`, format: "pbs_config" });
      for (const s of [CANARY.github, CANARY.aws, CANARY.hex, CANARY.userinfo]) {
        for (let i = 0; i + 12 <= s.length; i += 3) assert.ok(!r.stdout.includes(s.slice(i, i + 12)), `${name}: a window of a canary is in the answer (${s.slice(0, 4)}...)`);
      }
      assert.doesNotMatch(r.stderr, /Traceback/);
    }
  });
});

test("NUL bytes and invalid UTF-8 give one JSON answer and no traceback; the odd lines are counted", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "etc/datastore.cfg", Buffer.concat([Buffer.from("datastore: s\n\tpath /a\0b\n\tcomment bad \xff\xfe bytes\n\0\0\n\tkeep-last 2\n")]));
    const run = await tool(AUDIT, cwd, { path: "etc/datastore.cfg" });
    assert.doesNotMatch(run.stderr, /Traceback/);
    const out = json(run);
    assert.equal(out.sources[0].format, "pbs_config");
    assert.equal(out.counts.events, 2);
    assert.equal(out.counts.unparsed, 2, "the NUL line is no header, so the property after it belongs to a section that was not read");
    assert.equal(out.status, "partial");
  });
});

test("a single 10 MB line is located and not read; the sections around it are", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "etc/datastore.cfg", "datastore: s\n\tcomment " + "x".repeat(10 << 20) + "\n\tpath /p\n");
    const out = body(await tool(AUDIT, cwd, { path: "etc/datastore.cfg" }));
    assert.equal(out.counts.over_line_limit, 1);
    assert.equal(out.counts.events, 1);
    assert.equal(out.status, "partial");
    assert.equal(out.problem_lines[0].line, 2);
  });
});

async function bigConfig(path: string, props: number): Promise<void> {
  const ws = createWriteStream(path);
  const w = (s: string) => new Promise<void>((r) => (ws.write(s) ? r() : ws.once("drain", () => r())));
  let buf: string[] = ["datastore: big", "\tpath /p"];
  for (let i = 0; i < props; i++) {
    buf.push(i % 1000 === 0 ? `datastore: s${i}\n\tpath /p${i}` : "\tkeep-last " + (i % 50));
    if (buf.length === 20000) { await w(buf.join("\n") + "\n"); buf = []; }
  }
  await w(buf.join("\n") + "\n");
  await new Promise<void>((r) => ws.end(r));
}

test("a file of a million properties is read within max_seconds, the whole list is on disk, the inline list is cut", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "etc/x", "");
    await bigConfig(join(cwd, "etc/datastore.cfg"), 1_000_000);
    const t0 = Date.now();
    const run = await asJob(AUDIT, cwd, { path: "etc/datastore.cfg", max_seconds: 30, limit: 100000 });
    assert.ok((Date.now() - t0) / 1000 < 58, "inside the manifest's 60 s");
    const out = json(run);
    assert.ok(["complete", "partial"].includes(out.status));
    assert.ok(Buffer.byteLength(run.stdout) < 2_000_000, "the inline list is cut");
    if (out.status === "partial") assert.ok(out.partial_reasons.length > 0 || out.counts.unparsed > 0);
    assert.ok(out.pages.events.all_results);
  });
});

test("a SIGTERM during a long read ends with one JSON answer, partial, exit 143", async () => {
  await withCwd(async (cwd) => {
    await put(cwd, "etc/x", "");
    await bigConfig(join(cwd, "etc/datastore.cfg"), 800_000);
    const child = startDetached(AUDIT, cwd, { path: "etc/datastore.cfg", max_seconds: 50 }, { JOB_ID: "j000556", OUT: join(cwd, "out") });
    await new Promise((r) => setTimeout(r, 700));
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
