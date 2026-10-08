/**
 * network-forensics: the network-capture recipe catalogues a capture with tshark and capinfos.
 *
 * tshark and capinfos are not on every machine these suites run on, so stand-ins play them: `--version` prints a
 * version line, `-G fields` prints the field list in the tab-separated layout the manual gives (F, name, filter
 * name, type, parent protocol ...), a listing (`-T fields`) prints the table prepared for the display filter it was
 * given. That proves the recipe's logic (the receipt from the first moment, per-step status, the deadline, the
 * conditional listings, the IPv6 fields, the truncation count); it proves nothing about a real tshark, which
 * decides whether a field exists and what a listing holds.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { RECIPE, drop, exists, frameTcp4, gone, pcapClassic, pidFile, startDetached, stub, TCP, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const TSHARK = `#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
case "$1" in
  --version) echo 'TShark (Wireshark) 4.2.0 (stand-in)'; exit 0;;
  -G) cat "$STUB_DIR/fields.txt"; [ -f "$STUB_DIR/fields-exit" ] && exit "$(cat "$STUB_DIR/fields-exit")"; exit 0;;
esac
filter=packets
while [ $# -gt 0 ]; do
  case "$1" in -Y) filter="$2"; shift;; esac
  shift
done
if [ -f "$STUB_DIR/sleep-$filter" ]; then echo $$ > "$STUB_DIR/engine-$filter.pid"; sleep 60 & echo $! > "$STUB_DIR/child-$filter.pid"; echo started > "$STUB_DIR/started-$filter"; wait; fi
if [ -f "$STUB_DIR/exit-$filter" ]; then echo "tshark: stand-in failing on request" >&2; exit "$(cat "$STUB_DIR/exit-$filter")"; fi
[ -f "$STUB_DIR/out-$filter.tsv" ] && cat "$STUB_DIR/out-$filter.tsv"
exit 0
`;
const CAPINFOS = `#!/bin/sh
case "$1" in --version) echo 'Capinfos (Wireshark) 4.2.0 (stand-in)'; exit 0;; esac
echo "File name: stand-in"
exit 0
`;

const fieldLine = (name: string): string => `F\tA field\t${name}\tFT_STRING\tproto\t0\t0x0\tdescription`;

type Opts = { fields?: string[]; tables?: Record<string, string>; sleeps?: string[]; exits?: Record<string, number> };

async function stage(cwd: string, bin: string, o: Opts = {}): Promise<string> {
  const dir = join(cwd, "stub");
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  await stub(bin, "tshark", TSHARK);
  await stub(bin, "capinfos", CAPINFOS);
  await writeFile(join(dir, "fields.txt"), (o.fields ?? ["frame.number", "ip.src"]).map(fieldLine).join("\n") + "\n");
  for (const [filter, text] of Object.entries(o.tables ?? {})) await writeFile(join(dir, `out-${filter}.tsv`), text);
  for (const f of o.sleeps ?? []) await writeFile(join(dir, `sleep-${f}`), "1");
  for (const [f, c] of Object.entries(o.exits ?? {})) await writeFile(join(dir, `exit-${f}`), String(c));
  await writeFile(join(cwd, "tshark-calls.txt"), "");
  return dir;
}

const PACKETS = [
  '"frame.number"\t"frame.time_epoch"\t"frame.cap_len"\t"frame.len"\t"_ws.col.Protocol"',
  '"1"\t"1700000000.1"\t"96"\t"1500"\t"TCP"',
  '"2"\t"1700000000.2"\t"60"\t"60"\t"TCP"',
  '"3"\t"1700000000.3"\t"54"\t"54"\t"UDP"',
  '"4"\t"1700000000.4"\t"96"\t"900"\t"TLS"',
].join("\n") + "\n";
const TABLE = (cols: string[], n: number): string => [cols.map((c) => `"${c}"`).join("\t"), ...Array.from({ length: n }, (_, i) => cols.map(() => `"${i}"`).join("\t"))].join("\n") + "\n";

type Run = { code: number | null; stdout: string; stderr: string };

function recipe(cwd: string, bin: string, args: string[], env: Record<string, string> = {}, path?: string): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [RECIPE, ...args], { cwd, env: { ...process.env, PATH: path ?? `${bin}:${process.env.PATH}`, STUB_DIR: join(cwd, "stub"), STUB_LOG: join(cwd, "tshark-calls.txt"), ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }));
  });
}

const target = (p: string): string => JSON.stringify({ paths: [p], name: p });
const env = (cwd: string) => ({ STUB_DIR: join(cwd, "stub"), STUB_LOG: join(cwd, "tshark-calls.txt") });

async function capture(cwd: string): Promise<string> {
  return drop(cwd, "inputs/c.pcap", pcapClassic([{ sec: 1, frame: frameTcp4({ src: "10.0.0.5", dst: "203.0.113.7", sport: 50000, dport: 80, flags: TCP.SYN }) }]));
}

async function coverage(cwd: string, out: string): Promise<Json> {
  return JSON.parse(await readFile(join(cwd, out, "coverage.json"), "utf8"));
}

test("a run lists the selected fields of every packet and of DNS, HTTP and TLS, records the versions, counts truncated packets, and says which table can hold secrets", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { tables: { packets: PACKETS, dns: TABLE(["frame.number"], 2), http: TABLE(["frame.number"], 3), tls: TABLE(["frame.number"], 1) } });
    const result = await recipe(cwd, bin, ["run", "--target", target(await capture(cwd)), "--out", "work/cat"]);
    assert.equal(result.code, 0, result.stderr + result.stdout);
    const c = await coverage(cwd, "work/cat");
    assert.equal(c.status, "complete");
    assert.equal(c.finished, true);
    assert.match(c.tools.tshark.version, /4\.2\.0/);
    assert.match(c.tools.capinfos.version, /4\.2\.0/);
    const steps = Object.fromEntries(c.steps.map((s: Json) => [s.step, s]));
    for (const name of ["capinfos", "packets.tsv", "dns.tsv", "http.tsv", "tls.tsv"]) assert.equal(steps[name].status, "ok", name);
    assert.equal(steps["packets.tsv"].rows, 4);
    assert.equal(steps["http.tsv"].rows, 3);
    assert.equal(c.limits_on_what_the_listings_show.truncated_packets, 2, "two packets were captured shorter than they were on the wire");
    assert.deepEqual(Object.keys(c.secret_bearing), ["http.tsv"]);
    assert.match(c.secret_bearing["http.tsv"], /credentials/);
    assert.equal(steps["http.tsv"].secret_bearing, true);
    assert.match(c.not_covered, /does not show a protocol is absent/);
    const index = (await readFile(join(cwd, "work/cat/index.tsv"), "utf8")).trimEnd().split("\n");
    assert.deepEqual(index.map((l) => l.split("\t")[0]), ["path", "capture.txt", "packets.tsv", "dns.tsv", "http.tsv", "tls.tsv"]);
    // IPv6 endpoints are listed wherever IPv4 ones are.
    const calls = (await readFile(join(cwd, "tshark-calls.txt"), "utf8")).split("\n");
    for (const filter of ["http", "tls", "dns"]) {
      const call = calls.find((l) => l.includes(`-Y ${filter} `));
      assert.ok(call, filter);
      assert.match(call, /-e ipv6\.src/, `${filter} lists ipv6.src`);
    }
    assert.match(calls.find((l) => l.includes("-Y http ")) ?? "", /-e ipv6\.dst/);
    assert.match(calls.find((l) => l.includes("-Y tls ")) ?? "", /-e ipv6\.dst/);
    // The description no longer calls a selected-field projection lossless.
    const meta = JSON.parse(await readFile(RECIPE.replace("run.py", "recipe.json"), "utf8"));
    assert.doesNotMatch(JSON.stringify(meta), /lossless/i);
    assert.match(meta.description, /complete listing of the selected fields/);
  });
});

test("HTTP/2 and QUIC are listed only when the installed tshark lists their fields, and only with the fields it lists", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { tables: { packets: PACKETS, dns: TABLE(["frame.number"], 0), http: TABLE(["frame.number"], 0), tls: TABLE(["frame.number"], 0) } });
    const none = await recipe(cwd, bin, ["run", "--target", target(await capture(cwd)), "--out", "work/a"]);
    assert.equal(none.code, 0);
    const a = await coverage(cwd, "work/a");
    const stepsA = Object.fromEntries(a.steps.map((s: Json) => [s.step, s]));
    assert.equal(stepsA["http2.tsv"].status, "skipped");
    assert.match(stepsA["http2.tsv"].reason, /says nothing about whether the capture holds the protocol/);
    assert.equal(stepsA["quic.tsv"].status, "skipped");
    assert.equal(a.status, "complete", "a skipped optional listing is stated, not an error");
    assert.equal((await readFile(join(cwd, "tshark-calls.txt"), "utf8")).includes("-Y http2"), false, "no listing of fields the build does not have");
    assert.equal(await exists(join(cwd, "work/a/http2.tsv")), false);
    // This build lists the HTTP/2 stream id and header fields but not the type, and the QUIC version and connection ids.
    await stage(cwd, bin, {
      fields: ["http2.streamid", "http2.headers.method", "http2.headers.path", "quic.version", "quic.dcid"],
      tables: { packets: PACKETS, dns: TABLE(["frame.number"], 0), http: TABLE(["frame.number"], 0), tls: TABLE(["frame.number"], 0), http2: TABLE(["frame.number"], 5), quic: TABLE(["frame.number"], 7) },
    });
    const some = await recipe(cwd, bin, ["run", "--target", target(await capture(cwd)), "--out", "work/b"]);
    assert.equal(some.code, 0, some.stderr);
    const b = await coverage(cwd, "work/b");
    const stepsB = Object.fromEntries(b.steps.map((s: Json) => [s.step, s]));
    assert.equal(stepsB["http2.tsv"].status, "ok");
    assert.equal(stepsB["http2.tsv"].rows, 5);
    assert.deepEqual(stepsB["http2.tsv"].fields_missing.sort(), ["http2.headers.authority", "http2.headers.status", "http2.type"]);
    assert.equal(stepsB["http2.tsv"].fields.includes("http2.type"), false);
    assert.equal(stepsB["http2.tsv"].fields.includes("http2.headers.path"), true);
    assert.equal(stepsB["quic.tsv"].rows, 7);
    const call = (await readFile(join(cwd, "tshark-calls.txt"), "utf8")).split("\n").find((l) => l.includes("-Y http2 ")) ?? "";
    assert.doesNotMatch(call, /http2\.type|http2\.headers\.status/);
    assert.match(call, /-e http2\.streamid/);
    assert.equal(b.status, "complete");
  });
});

test("a field list that cannot be read is an error and no conditional listing is made", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stage(cwd, bin, { tables: { packets: PACKETS, dns: TABLE(["frame.number"], 0), http: TABLE(["frame.number"], 0), tls: TABLE(["frame.number"], 0) } });
    await writeFile(join(dir, "fields-exit"), "3");
    const result = await recipe(cwd, bin, ["run", "--target", target(await capture(cwd)), "--out", "work/a"]);
    assert.equal(result.code, 2);
    const c = await coverage(cwd, "work/a");
    assert.equal(c.status, "partial");
    const steps = Object.fromEntries(c.steps.map((s: Json) => [s.step, s]));
    assert.equal(steps["tshark -G fields"].status, "failed");
    assert.equal(steps["http2.tsv"].status, "skipped");
    assert.match(steps["http2.tsv"].reason, /could not be checked/);
    assert.equal(steps["http.tsv"].status, "ok", "the listings that need no check still ran");
  });
});

test("a step that outlives the shared deadline is killed with what it started; the receipt names it and the steps after it", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stage(cwd, bin, { sleeps: ["dns"], tables: { packets: PACKETS } });
    const started = Date.now();
    const result = await recipe(cwd, bin, ["run", "--target", target(await capture(cwd)), "--out", "work/cat"], { NETWORK_CAPTURE_SECONDS: "3" });
    assert.ok(Date.now() - started < 30_000);
    assert.equal(result.code, 2);
    const c = await coverage(cwd, "work/cat");
    assert.equal(c.status, "partial");
    assert.equal(c.finished, true);
    const steps = Object.fromEntries(c.steps.map((s: Json) => [s.step, s]));
    assert.equal(steps["packets.tsv"].status, "ok");
    assert.equal(steps["dns.tsv"].status, "timed_out");
    for (const later of ["http.tsv", "tls.tsv"]) {
      assert.equal(steps[later].status, "not_attempted", later);
      assert.match(steps[later].reason, /shared deadline/);
    }
    assert.match(c.errors.join(" "), /dns\.tsv timed out/);
    const dns = c.files.find((f: Json) => f.path === "dns.tsv");
    assert.match(dns.description, /PARTIAL/);
    const pid = Number((await readFile(join(dir, "child-dns.pid"), "utf8")).trim());
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), /ESRCH/, "what the step started is gone");
  });
});

test("a run killed by its process group (as the harness ends a tool) leaves a receipt that is partial and unfinished, and tshark and what it started die with it", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stage(cwd, bin, { sleeps: ["dns"], tables: { packets: PACKETS } });
    const run = startDetached(RECIPE, cwd, null, env(cwd), bin, ["run", "--target", target(await capture(cwd)), "--out", "work/cat"]);
    let engine = 0, child = 0;
    try {
      engine = await pidFile(join(dir, "engine-dns.pid"));
      child = await pidFile(join(dir, "child-dns.pid"));
      run.killGroup();
      await run.closed;
      assert.equal(await gone(engine), true, "tshark survived the group kill");
      assert.equal(await gone(child), true, "what tshark started survived");
      const c = await coverage(cwd, "work/cat");
      assert.equal(c.status, "partial");
      assert.equal(c.finished, false);
      const steps = Object.fromEntries(c.steps.map((s: Json) => [s.step, s]));
      assert.equal(steps["packets.tsv"].status, "ok");
      assert.equal(steps["packets.tsv"].rows, 4);
      assert.equal(steps["dns.tsv"].status, "running", "a SIGKILL gives no last word: the receipt still says where it was");
      assert.equal(steps["http.tsv"].status, "not_attempted");
      assert.ok((await readFile(join(cwd, "work/cat/index.tsv"), "utf8")).includes("packets.tsv"));
    } finally {
      for (const pid of [engine, child]) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
    }
  });
});

test("SIGTERM, SIGINT and SIGHUP kill the running step and what it started, and the receipt says which step was interrupted", async () => {
  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await stage(cwd, bin, { sleeps: ["dns"], tables: { packets: PACKETS } });
      const run = startDetached(RECIPE, cwd, null, env(cwd), bin, ["run", "--target", target(await capture(cwd)), "--out", "work/cat"]);
      let engine = 0, child = 0;
      try {
        engine = await pidFile(join(dir, "engine-dns.pid"));
        child = await pidFile(join(dir, "child-dns.pid"));
        run.signal(sig);
        await run.closed;
        assert.equal(await gone(engine), true, `${sig}: tshark survived`);
        assert.equal(await gone(child), true, `${sig}: its child survived`);
        const c = await coverage(cwd, "work/cat");
        const steps = Object.fromEntries(c.steps.map((s: Json) => [s.step, s]));
        assert.equal(steps["dns.tsv"].status, "interrupted", sig);
        assert.match(c.errors.join(" "), /stopped by signal/);
        assert.equal(c.finished, false);
      } finally {
        for (const pid of [engine, child]) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
      }
    });
  }
});

test("an output place that cannot be created is a JSON error, and dns.tsv lists the destination too", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { tables: { packets: PACKETS, dns: TABLE(["frame.number"], 1), http: TABLE(["frame.number"], 0), tls: TABLE(["frame.number"], 0) } });
    await writeFile(join(cwd, "work/afile"), "x");
    const blocked = await recipe(cwd, bin, ["run", "--target", target(await capture(cwd)), "--out", "work/afile/sub"]);
    assert.equal(blocked.code, 2);
    assert.doesNotMatch(blocked.stderr, /Traceback/);
    assert.match(JSON.parse(blocked.stdout).error, /could not be created/);
    assert.equal((await recipe(cwd, bin, ["run", "--target", target(await capture(cwd)), "--out", "work/cat"])).code, 0);
    const call = (await readFile(join(cwd, "tshark-calls.txt"), "utf8")).split("\n").find((l) => l.includes("-Y dns ")) ?? "";
    assert.match(call, /-e ip\.dst/);
    assert.match(call, /-e ipv6\.dst/);
  });
});

test("a listing that fails keeps its stderr, the others still run, and the run is partial and exits 2", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { exits: { tls: 2 }, tables: { packets: PACKETS, dns: TABLE(["frame.number"], 1), http: TABLE(["frame.number"], 1), tls: TABLE(["frame.number"], 0) } });
    const result = await recipe(cwd, bin, ["run", "--target", target(await capture(cwd)), "--out", "work/cat"]);
    assert.equal(result.code, 2);
    const c = await coverage(cwd, "work/cat");
    assert.equal(c.status, "partial");
    const steps = Object.fromEntries(c.steps.map((s: Json) => [s.step, s]));
    assert.equal(steps["tls.tsv"].status, "failed");
    assert.equal(steps["tls.tsv"].exit_code, 2);
    assert.equal(steps["http.tsv"].status, "ok");
    assert.match(await readFile(join(cwd, "work/cat/tls.tsv.stderr"), "utf8"), /stand-in failing/);
    assert.ok(c.files.some((f: Json) => f.path === "tls.tsv.stderr"));
    assert.match(c.errors.join(" "), /tls\.tsv \(tshark\) exited 2/);
  });
});

test("detect, a missing program and a target that is not a capture are answered in JSON, never a traceback", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin);
    const good = await capture(cwd);
    const yes = await recipe(cwd, bin, ["detect", "--target", target(good)]);
    assert.equal(yes.code, 0);
    assert.equal(JSON.parse(yes.stdout).applies, true);
    await drop(cwd, "inputs/notes.txt", "plain text");
    const no = await recipe(cwd, bin, ["detect", "--target", target("inputs/notes.txt")]);
    assert.equal(no.code, 1);
    const unsupported = await recipe(cwd, bin, ["run", "--target", target("inputs/notes.txt"), "--out", "work/n"]);
    assert.equal(unsupported.code, 2);
    assert.equal((await coverage(cwd, "work/n")).status, "unsupported");
    const bad = await recipe(cwd, bin, ["detect", "--target", "{not json"]);
    assert.equal(bad.code, 2);
    assert.doesNotMatch(bad.stderr, /Traceback/);
    assert.equal(JSON.parse(bad.stdout).ok, false);
    const noOut = await recipe(cwd, bin, ["run", "--target", target(good)]);
    assert.equal(noOut.code, 2);
    // Without tshark and capinfos on PATH the receipt says failed, and says which are missing.
    const only = join(cwd, "onlypython");
    await mkdir(only, { recursive: true });
    const which = await new Promise<string>((resolve) => { const c = spawn("sh", ["-c", "command -v python3"]); let s = ""; c.stdout.on("data", (d: Buffer) => { s += d; }); c.on("close", () => resolve(s.trim())); });
    await symlink(which, join(only, "python3"));
    const missing = await recipe(cwd, bin, ["run", "--target", target(good), "--out", "work/m"], {}, only);
    assert.equal(missing.code, 2);
    const m = await coverage(cwd, "work/m");
    assert.equal(m.status, "failed");
    assert.equal(m.finished, true);
    assert.match(m.errors[0], /missing program\(s\): tshark, capinfos/);
  });
});
