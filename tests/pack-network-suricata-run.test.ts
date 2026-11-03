/**
 * network-forensics: suricata_run runs local rules over a capture and records what ran.
 *
 * Suricata is not on every machine these suites run on, so a stand-in program plays it. It prints what its
 * documentation says the options print: `--build-info` a version line, `-T` a test of the configuration, a run
 * (`-r`) writing eve.json and its logs into the directory `-l` names. EVE events are written from the layout
 * Suricata's documentation gives (one JSON object per line with `timestamp`, `event_type` and the event's own
 * object), never from this tool's output. The stand-in records every call and the configuration it was given.
 * That proves the wrapper's logic (the configuration it writes and tests, what it records, how it counts); it
 * proves nothing about a real Suricata: whether the installed build accepts the keys the written configuration
 * uses, or produces a JA4 fingerprint, is a thing that build's own output shows.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { SURICATA, asJob, body, exists, filesUnder, gone, pidFile, put, refused, startDetached, stub, tool, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

const STUB = `#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
mode=run; conf=""; logdir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --build-info) [ -f "$STUB_DIR/build-fail" ] && { echo "suricata: build info failed on request" >&2; exit 3; }; printf 'This is Suricata version 7.0.0-stand-in RELEASE\\nFeatures: stand-in\\n'; exit 0;;
    -T) mode=test;;
    -c) conf="$2"; shift;;
    -l) logdir="$2"; shift;;
  esac
  shift
done
[ -n "$conf" ] && cp "$conf" "$STUB_DIR/seen-config-$mode.yaml"
if [ "$mode" = test ]; then
  [ -f "$STUB_DIR/loadline-test" ] && cat "$STUB_DIR/loadline-test" >&2
  if [ -f "$STUB_DIR/test-exit" ]; then echo "stand-in: configuration test failed on request" >&2; exit "$(cat "$STUB_DIR/test-exit")"; fi
  exit 0
fi
[ -f "$STUB_DIR/sleep" ] && { echo $$ > "$STUB_DIR/engine.pid"; sleep 300 & echo $! > "$STUB_DIR/child.pid"; echo started > "$STUB_DIR/started"; wait; }
[ -f "$STUB_DIR/eve.json" ] && cp "$STUB_DIR/eve.json" "$logdir/eve.json"
[ -f "$STUB_DIR/loadline-run" ] && cat "$STUB_DIR/loadline-run" >&2
if [ -f "$STUB_DIR/run-exit" ]; then exit "$(cat "$STUB_DIR/run-exit")"; fi
exit 0
`;

type Opts = { eve?: string; testExit?: number; runExit?: number; loadTest?: string; loadRun?: string; sleep?: boolean; buildFail?: boolean };

async function stage(cwd: string, bin: string, o: Opts = {}): Promise<string> {
  const dir = join(cwd, "stub");
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  await stub(bin, "suricata", STUB);
  if (o.eve !== undefined) await writeFile(join(dir, "eve.json"), o.eve);
  if (o.testExit !== undefined) await writeFile(join(dir, "test-exit"), String(o.testExit));
  if (o.runExit !== undefined) await writeFile(join(dir, "run-exit"), String(o.runExit));
  if (o.loadTest) await writeFile(join(dir, "loadline-test"), o.loadTest);
  if (o.loadRun) await writeFile(join(dir, "loadline-run"), o.loadRun);
  if (o.sleep) await writeFile(join(dir, "sleep"), "1");
  if (o.buildFail) await writeFile(join(dir, "build-fail"), "1");
  await writeFile(join(cwd, "suricata-calls.txt"), "");
  return dir;
}

const env = (cwd: string) => ({ STUB_DIR: join(cwd, "stub"), STUB_LOG: join(cwd, "suricata-calls.txt") });
const RULES = 'alert tcp any any -> any any (msg:"test one"; sid:1000001; rev:1;)\n# a comment\n\nalert udp any any -> any 53 (msg:"test two"; sid:1000002; rev:1;)\n';

async function inputs(cwd: string): Promise<{ path: string; rules: string }> {
  await put(cwd, "work/c.pcap", Buffer.from("not read by the stand-in"));
  await put(cwd, "work/case.rules", RULES);
  return { path: "work/c.pcap", rules: "work/case.rules" };
}

const ev = (o: Json): string => JSON.stringify({ timestamp: "2023-11-14T22:13:20.123456+0000", ...o });
const ALERT = (n: number, sig = "test one") => ev({ event_type: "alert", flow_id: 1000 + n, src_ip: "10.0.0.5", src_port: 50000 + n, dest_ip: "203.0.113.7", dest_port: 443, proto: "TCP", alert: { signature_id: 1000001, signature: sig } });

test("a configuration is written by key, tested with -T before the run, and recorded with the engine's version, the rules' digest and the checksum mode", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: [ALERT(1), ev({ event_type: "flow", proto: "TCP" })].join("\n") + "\n", loadTest: "<Info> - 2 rules successfully loaded, 0 rules failed\n" });
    const { path, rules } = await inputs(cwd);
    const out = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.match(out.suricata_version, /version 7\.0\.0-stand-in/);
    assert.ok(await exists(join(cwd, "work/s/suricata-build-info.txt")));
    const config = await readFile(join(cwd, "work/s/suricata.yaml"), "utf8");
    assert.equal(out.configuration.sha256, sha(config));
    assert.equal(out.configuration.generated_by_this_tool, true);
    // By key, not by list position.
    assert.match(config, /^        - tls:\n            extended: yes$/m);
    assert.match(config, /ja4-fingerprints: yes/);
    assert.equal(/outputs\.\d/.test(config), false);
    const calls = (await readFile(join(cwd, "suricata-calls.txt"), "utf8")).trimEnd().split("\n");
    assert.equal(calls.length, 3, calls.join("\n"));
    assert.match(calls[0], /^--build-info$/);
    assert.match(calls[1], /^-T -c .*work\/s\/suricata\.yaml -S .*work\/case\.rules -l .*work\/s -k none -v$/, "the configuration is tested before the run");
    assert.match(calls[2], /^-r .*work\/c\.pcap -c .*work\/s\/suricata\.yaml -S .*work\/case\.rules -l .*work\/s -k none -v$/);
    assert.equal(calls.some((c) => /--set/.test(c)), false, "no positional --set path");
    assert.equal(out.rules.sha256, sha(RULES));
    assert.equal(out.rules.rule_lines, 2);
    assert.equal(out.rules.bytes, Buffer.byteLength(RULES));
    assert.equal(out.checksum_mode, "none");
    assert.deepEqual(out.rule_load.configuration_test, { loaded: 2, failed: 0, from: "suricata-test.stderr" });
    assert.equal(out.rule_load.run, null, "a number the engine did not print is not a zero");
    assert.equal(out.ok, true);
    // The configuration the engine tested is the one it ran.
    assert.equal(await readFile(join(cwd, "stub/seen-config-run.yaml"), "utf8"), config);
    const all = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s2", checksum_mode: "all" }, env(cwd), bin));
    assert.equal(all.checksum_mode, "all");
    assert.match(await readFile(join(cwd, "suricata-calls.txt"), "utf8"), /-k all/);
  });
});

test("a configuration that fails its test is returned whole and nothing is run over the capture", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { testExit: 1, eve: ALERT(1) + "\n" });
    const { path, rules } = await inputs(cwd);
    const err = refused(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.match(err.error, /configuration test \(suricata -T\) failed with exit code 1, so nothing was run/);
    assert.equal(err.exit_code, 1);
    assert.match(await readFile(join(cwd, err.stderr), "utf8"), /failed on request/);
    assert.equal(err.config_generated, true);
    assert.equal((await readFile(join(cwd, "suricata-calls.txt"), "utf8")).split("\n").some((c) => c.startsWith("-r ")), false, "no run over the capture");
    assert.equal(await exists(join(cwd, "work/s/eve.json")), false);
  });
});

test("fingerprints: what is asked, what traffic could carry one, and what was produced are three numbers", async () => {
  await withCwd(async (cwd, bin) => {
    const tls = (n: number, extra: Json = {}) => ev({ event_type: "tls", src_ip: "10.0.0.5", dest_ip: "203.0.113.7", tls: { sni: `host${n}.example.test`, version: "TLS 1.3", ...extra } });
    await stage(cwd, bin, {
      eve: [tls(1, { ja3: { hash: "a".repeat(32) }, ja4: "t13d1516h2_8daaf6152771_b186095e22b6" }), tls(2, { ja3: { hash: "b".repeat(32) } }), tls(3), ev({ event_type: "alert", alert: { signature: "x" }, tls: { ja3: { hash: "c".repeat(32) } } })].join("\n") + "\n",
    });
    const { path, rules } = await inputs(cwd);
    const out = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin));
    const f = out.tls_fingerprints;
    assert.match(f.ja4_enabled, /^yes \(asked of the engine/);
    assert.equal(f.tls_events, 3, "an alert that carries a tls object is not a TLS event");
    assert.equal(f.tls_with_ja3, 2);
    assert.equal(f.tls_with_ja4, 1);
    assert.match(f.note, /does not show the build lacks the feature/);
    // A TLS event with no ja4 under an enabled setting is not an error and not a claim.
    await stage(cwd, bin, { eve: tls(1) + "\n" });
    const none = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s2" }, env(cwd), bin));
    assert.equal(none.tls_fingerprints.tls_events, 1);
    assert.equal(none.tls_with_ja4, 0);
    assert.match(none.tls_fingerprints.ja4_enabled, /^yes/);
    // And no fact about a Suricata version or default is stated anywhere in what the tool says.
    assert.doesNotMatch(none.note + none.tls_fingerprints.note + none.out_dir_note, /Suricata [0-9]|since version|by default (it|Suricata)/i);
  });
});

test("EVE lines that are not events are counted with their line numbers, and the run is not ok", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: [ALERT(1), "{broken", "[1,2,3]", "7", JSON.stringify({ timestamp: "2023-11-14T22:13:20+0000", note: "no event_type" }), ALERT(2), ""].join("\n") });
    const { path, rules } = await inputs(cwd);
    const result = await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin);
    assert.equal(result.code, 0, "exit 0 means the engine ran; status and ok say whether the run was clean");
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    assert.equal(out.invalid_eve_lines, 1);
    assert.equal(out.eve_lines_not_objects, 2);
    assert.equal(out.events_without_event_type, 1);
    assert.equal(out.event_types.alert, 2);
    assert.equal(out.event_types.no_event_type, 1);
    assert.deepEqual(out.eve_line_problems, [{ line: 2, why: "not valid JSON" }, { line: 3, why: "valid JSON that is not an object" }, { line: 4, why: "valid JSON that is not an object" }, { line: 5, why: "an object with no event_type" }], "the typeless object has its line number too");
    assert.match(out.problems.join(" "), /4 EVE lines were not read as events/);
  });
});

test("rules that fail to load are a failure of the run, read from the engine's own numbers", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ALERT(1) + "\n", loadRun: "<Info> - 1 rule files processed. 3 rules successfully loaded, 1 rules failed, 0 rules skipped\n" });
    const { path, rules } = await inputs(cwd);
    const result = await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin);
    assert.equal(result.code, 0, "exit 0 means the engine ran; status and ok say whether the run was clean");
    const out = JSON.parse(result.stdout);
    assert.deepEqual(out.rule_load.run, { loaded: 3, failed: 1, from: "suricata.stderr" });
    assert.equal(out.ok, false);
    assert.match(out.problems.join(" "), /failed to load/);
  });
});

test("a configuration of the caller's own is used as given and recorded, and one from the evidence is refused", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ALERT(1) + "\n" });
    const { path, rules } = await inputs(cwd);
    const yaml = "%YAML 1.1\n---\noutputs: []\n";
    await put(cwd, "work/mine.yaml", yaml);
    const out = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s", config: "work/mine.yaml" }, env(cwd), bin));
    assert.equal(out.configuration.generated_by_this_tool, false);
    assert.equal(out.configuration.sha256, sha(yaml));
    assert.equal(await exists(join(cwd, "work/s/suricata.yaml")), false, "nothing is written over the caller's choice");
    assert.match(out.tls_fingerprints.ja3_enabled, /^not read/);
    assert.equal(await readFile(join(cwd, "stub/seen-config-run.yaml"), "utf8"), yaml);
    await put(cwd, "inputs/evidence.yaml", yaml);
    const err = refused(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s3", config: "inputs/evidence.yaml" }, env(cwd), bin));
    assert.match(err.error, /from inputs\/ is refused/);
    assert.equal(await exists(join(cwd, "work/s3")), false);
  });
});

test("alerts are bounded inline, every one stays in eve.json, and the counts say how many were left out", async () => {
  await withCwd(async (cwd, bin) => {
    const eve = Array.from({ length: 30 }, (_, i) => ALERT(i, i % 2 ? "test one" : "test two")).join("\n") + "\n";
    await stage(cwd, bin, { eve });
    const { path, rules } = await inputs(cwd);
    const out = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s", return_alerts: 5 }, env(cwd), bin));
    assert.equal(out.alert_count, 30);
    assert.equal(out.alerts_returned, 5);
    assert.equal(out.alerts_omitted, 25);
    assert.deepEqual(out.signatures, { "test two": 15, "test one": 15 });
    assert.equal(out.alerts[0].flow_id, 1000);
    assert.equal((await readFile(join(cwd, "work/s/eve.json"), "utf8")).trimEnd().split("\n").length, 30);
    const zero = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s0", return_alerts: 0 }, env(cwd), bin));
    assert.equal(zero.alerts_returned, 0);
    assert.equal(zero.alert_count, 30);
  });
});

test("the directory is private, in a job it must be under $OUT, a stop leaves nothing running, and no eve.json is an error naming the output", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ALERT(1) + "\n" });
    const { path, rules } = await inputs(cwd);
    const outside = refused(await asJob(SURICATA, cwd, { path, rules, out_dir: "work/elsewhere" }, bin, env(cwd)));
    assert.match(outside.error, /\$OUT/);
    const out = body(await asJob(SURICATA, cwd, { path, rules, out_dir: "out/s" }, bin, env(cwd)));
    assert.equal(out.out_dir_contains_secret_values, true);
    assert.match(out.out_dir_note, /secret_output: true/);
    assert.equal(((await stat(join(cwd, "out/s"))).mode & 0o777).toString(8), "700");
    for (const f of await filesUnder(join(cwd, "out/s"))) assert.equal(((await stat(join(cwd, "out/s", f))).mode & 0o777).toString(8), "600", f);
    const again = refused(await asJob(SURICATA, cwd, { path, rules, out_dir: "out/s" }, bin, env(cwd)));
    assert.match(again.error, /already holds files/);
  });
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, {});
    const { path, rules } = await inputs(cwd);
    const err = refused(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.match(err.error, /wrote no eve\.json/);
    assert.ok(err.stderr && err.stdout);
  });
  await withCwd(async (cwd, bin) => {
    const dir = await stage(cwd, bin, { sleep: true });
    const { path, rules } = await inputs(cwd);
    // 10 seconds is the tool's smallest deadline. The wall bound is far under the stand-in's 300 seconds: what is asked is that
    // the tool ended at its deadline (and said so), and that the sleeper it recorded is gone, not how quickly a loaded machine did it.
    const started = Date.now();
    let pid = 0;
    try {
      const err = refused(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s", timeout_seconds: 10 }, env(cwd), bin));
      assert.ok(Date.now() - started < 120_000, "the tool ended at its deadline, not when the stand-in did");
      assert.match(err.error, /did not finish in time/);
      pid = await pidFile(join(dir, "child.pid"));
      assert.equal(await gone(pid), true, "what Suricata started is gone");
    } finally {
      if (pid > 1) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
    }
  });
});

test("the generated configuration defines the variables rules are written against, from home_net or the private ranges, and says they are assumptions", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ALERT(1) + "\n" });
    const { path, rules } = await inputs(cwd);
    const out = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin));
    const config = await readFile(join(cwd, "work/s/suricata.yaml"), "utf8");
    assert.match(config, /^vars:\n  address-groups:\n    HOME_NET: "\[192\.168\.0\.0\/16,10\.0\.0\.0\/8,172\.16\.0\.0\/12\]"$/m);
    for (const name of ["EXTERNAL_NET", "HTTP_SERVERS", "DNS_SERVERS", "HTTP_PORTS", "SSH_PORTS", "FTP_PORTS"]) assert.match(config, new RegExp(`^    ${name}: `, "m"), name);
    assert.deepEqual(out.configuration.vars.HOME_NET, ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]);
    assert.match(out.configuration.vars.note, /assumptions/);
    const mine = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s2", home_net: ["203.0.113.0/24", "2001:db8::/32"] }, env(cwd), bin));
    assert.deepEqual(mine.configuration.vars.HOME_NET, ["203.0.113.0/24", "2001:db8::/32"]);
    assert.match(await readFile(join(cwd, "work/s2/suricata.yaml"), "utf8"), /HOME_NET: "\[203\.0\.113\.0\/24,2001:db8::\/32\]"/);
    for (const bad of [[], ["not-an-address"], ["10.0.0.0/8; evil"], "10.0.0.0/8", [5]]) {
      const err = refused(await tool(SURICATA, cwd, { path, rules, out_dir: "work/bad", home_net: bad }, env(cwd), bin));
      assert.match(err.error, /home_net/, JSON.stringify(bad));
    }
    assert.equal(await exists(join(cwd, "work/bad")), false);
  });
});

test("a rules file from the evidence is refused as a config is, also through a link; zero rules loaded from a file with rules is a problem; no load line is said, not read as zero", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ALERT(1) + "\n" });
    const { path } = await inputs(cwd);
    await put(cwd, "inputs/evidence.rules", RULES);
    await mkdir(join(cwd, "work/links"), { recursive: true });
    await symlink(join(cwd, "inputs/evidence.rules"), join(cwd, "work/links/mine.rules"));
    for (const rules of ["inputs/evidence.rules", "work/links/mine.rules", "work/../inputs/evidence.rules"]) {
      const err = refused(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s", config: undefined }, env(cwd), bin));
      assert.match(err.error, /rules file from inputs\/ is refused/, rules);
    }
    assert.equal(await exists(join(cwd, "work/s")), false);
    assert.equal((await readFile(join(cwd, "suricata-calls.txt"), "utf8")).includes("-S"), false, "the engine never saw it");
  });
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ALERT(1) + "\n", loadRun: "<Info> - 1 rule files processed. 0 rules successfully loaded, 0 rules failed, 2 rules skipped\n" });
    const { path, rules } = await inputs(cwd);
    const result = await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin);
    assert.equal(result.code, 0, "exit 0 means the engine ran; status and ok say whether the run was clean");
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    assert.match(out.problems.join(" "), /0 rules loaded though the rules file has 2 rule lines/);
    // No sentence at all: the run is not failed on a guess, and the answer says nothing shows a rule loaded.
    await stage(cwd, bin, { eve: ALERT(1) + "\n" });
    const quiet = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/q" }, env(cwd), bin));
    assert.equal(quiet.rule_load.known, false);
    assert.match(quiet.rule_load.note, /nothing here shows that any rule loaded/);
  });
});

test("a failing --build-info is a problem and the version stays unrecorded; a fingerprint found in an event that is not a TLS event is counted apart", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ev({ event_type: "quic", quic: {}, tls: { ja4: "q13d0310h3_55b375c5d22e_cd85d2d88918" } }) + "\n", buildFail: true });
    const { path, rules } = await inputs(cwd);
    const result = await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin);
    assert.equal(result.code, 0, "exit 0 means the engine ran; status and ok say whether the run was clean");
    const out = JSON.parse(result.stdout);
    assert.equal(out.suricata_version, null);
    assert.match(out.problems.join(" "), /--build-info/);
    assert.equal(out.tls_fingerprints.tls_events, 0);
    assert.equal(out.tls_fingerprints.other_events_with_a_fingerprint, 1);
    assert.doesNotMatch(out.tls_fingerprints.note, /traffic that could carry a fingerprint\./);
  });
});

test("timeout_seconds is held under the manifest's limit", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ALERT(1) + "\n" });
    const { path, rules } = await inputs(cwd);
    for (const bad of [1001, 5000, 9]) {
      const err = refused(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s", timeout_seconds: bad }, env(cwd), bin));
      assert.match(err.error, /timeout_seconds must be an integer from 10 to 1000/, String(bad));
    }
    assert.equal(await exists(join(cwd, "work/s")), false);
  });
});

test("the harness ends a tool by killing its process group, and that ends Suricata and what it started; SIGINT and SIGHUP do the same", async () => {
  for (const how of ["group", "SIGINT", "SIGHUP"] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await stage(cwd, bin, { sleep: true });
      const { path, rules } = await inputs(cwd);
      const run = startDetached(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin);
      let engine = 0, child = 0;
      try {
        engine = await pidFile(join(dir, "engine.pid"));
        child = await pidFile(join(dir, "child.pid"));
        if (how === "group") run.killGroup();
        else run.signal(how);
        await run.closed;
        assert.equal(await gone(engine), true, `${how}: Suricata survived`);
        assert.equal(await gone(child), true, `${how}: what Suricata started survived`);
      } finally {
        for (const pid of [engine, child]) try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
      }
    });
  }
});

// --- D-network-F1 ----------------------------------------------------------------------------------------------------------

import { createRng, planted } from "./pack-network-canaries.ts";

test("a line nested 100,000 deep is counted as not read, named with its line, and the other events are still read", async () => {
  await withCwd(async (cwd, bin) => {
    const deep = `{"event_type":"alert","a":${"[".repeat(100_000)}${"]".repeat(100_000)}}`;
    await stage(cwd, bin, { eve: [ALERT(1), deep, ALERT(2), ""].join("\n"), loadTest: "<Info> - 2 rules successfully loaded, 0 rules failed\n" });
    const { path, rules } = await inputs(cwd);
    const result = await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin);
    assert.equal(result.code, 0);
    assert.doesNotMatch(result.stdout + result.stderr, /RecursionError|unexpected failure|Traceback/);
    const out = JSON.parse(result.stdout);
    assert.equal(out.alert_count, 2);
    assert.equal(out.invalid_eve_lines, 1);
    assert.deepEqual(out.eve_line_problems, [{ line: 2, why: "nested deeper than 64 levels: located, not parsed" }]);
    assert.equal(out.ok, false);
    assert.equal(out.status, "partial");
  });
});

test("a line is refused for its nesting at 65 levels and read at 64, whatever the interpreter parses (the same answer on every Python)", async () => {
  await withCwd(async (cwd, bin) => {
    const nested = (levels: number) => `{"event_type":"alert","a":${"[".repeat(levels - 1)}${"]".repeat(levels - 1)}}`;
    await stage(cwd, bin, { eve: [ALERT(1), nested(64), nested(65), nested(2_000), ""].join("\n"), loadTest: "<Info> - 2 rules successfully loaded, 0 rules failed\n" });
    const { path, rules } = await inputs(cwd);
    const out = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.equal(out.alert_count, 2, "the line at 64 levels is an alert");
    assert.deepEqual(out.eve_line_problems, [{ line: 3, why: "nested deeper than 64 levels: located, not parsed" }, { line: 4, why: "nested deeper than 64 levels: located, not parsed" }]);
  });
});

test("every EVE line that was not read as an event is in a file with its line number, however many there are: the answer shows ten and says where the rest are", async () => {
  await withCwd(async (cwd, bin) => {
    const bad = Array.from({ length: 25 }, (_, i) => (i % 2 ? "not json " + i : "[1,2]"));
    await stage(cwd, bin, { eve: [ALERT(1), ...bad, ev({ foo: 1 }), ""].join("\n"), loadTest: "<Info> - 2 rules successfully loaded, 0 rules failed\n" });
    const { path, rules } = await inputs(cwd);
    const out = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.equal(out.eve_line_problems.length, 10);
    assert.equal(out.eve_problem_lines_total, 26);
    const rows = (await readFile(join(cwd, "work/s", out.eve_problems_file), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(rows.length, 26);
    assert.deepEqual(rows.slice(0, 3).map((r: Json) => r.line), [2, 3, 4]);
    assert.equal(((await stat(join(cwd, "work/s", out.eve_problems_file))).mode & 0o777).toString(8), "600");
    // a clean run writes no such file
    await stage(cwd, bin, { eve: ALERT(1) + "\n", loadTest: "<Info> - 2 rules successfully loaded, 0 rules failed\n" });
    const clean = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/c" }, env(cwd), bin));
    assert.equal(clean.eve_problems_file, null);
    assert.equal(clean.status, "complete");
    assert.match(clean.status_basis, /every EVE line was read/);
  });
});

test("the slots of an inline alert are typed: an address is an address, a port or id is a number, and a signature, a protocol, a timestamp and the keys of event_types and signatures go through the block", async () => {
  await withCwd(async (cwd, bin) => {
    const rng = createRng(31337);
    const shapes = ["ghp", "akia", "jwt", "xoxb", "github_pat", "sk"] as const;
    const plant = Object.fromEntries(shapes.map((s) => [s, planted(rng, s)]));
    const events = shapes.map((s, i) => ev({
      event_type: i === 0 ? plant.ghp : "alert", timestamp: i === 1 ? plant.akia : "2023-11-14T22:13:20.123456+0000", flow_id: i === 2 ? plant.jwt : 5000 + i,
      src_ip: i === 3 ? plant.xoxb : "10.0.0.5", src_port: i === 4 ? plant.github_pat : 50000, dest_ip: "203.0.113.7", dest_port: 443, proto: i === 5 ? plant.sk : "TCP",
      alert: { signature_id: i === 0 ? plant.ghp : 1000001, signature: `ET TEST ${plant[s]}` },
    }));
    await stage(cwd, bin, { eve: [...events, ALERT(9999)].join("\n") + "\n", loadTest: "<Info> - 2 rules successfully loaded, 0 rules failed\n" });
    const { path, rules } = await inputs(cwd);
    const result = await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin);
    const out = JSON.parse(result.stdout);
    for (const secret of Object.values(plant)) assert.equal(result.stdout.includes(secret), false, `${secret.slice(0, 10)}... was printed`);
    const first = out.alerts.find((a: Json) => a.flow_id === 10999);
    assert.equal(first.src_ip, "10.0.0.5");
    assert.equal(first.proto, "TCP");
    assert.equal(first.dest_ip, "203.0.113.7");
    assert.equal(first.dest_port, 443);
    assert.equal(first.timestamp, "2023-11-14T22:13:20.123456+0000");
    assert.ok(Object.keys(out.signatures).some((k) => k.startsWith("ET TEST ")), "the readable part of a signature stays");
  });
});

test("a stop signal prints partial JSON with the stage and the files on disk, and kills the engine and what it started (exit 128 + signal)", async () => {
  for (const [sig, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await stage(cwd, bin, { sleep: true, eve: ALERT(1) + "\n" });
      const { path, rules } = await inputs(cwd);
      const run = startDetached(SURICATA, cwd, { path, rules, out_dir: "work/s" }, env(cwd), bin);
      // A state, waited for as long as a loaded runner needs (the signal is meant to land after the stand-in has started its program).
      await untilExists(join(dir, "started"));
      run.signal(sig);
      assert.equal(await run.closed, code, sig);
      const last = JSON.parse(run.stdout());
      assert.equal(last.status, "partial");
      assert.equal(last.interrupted_by_signal, code - 128);
      assert.equal(last.stage, "running Suricata");
      assert.ok(last.files_on_disk.includes("suricata.yaml"));
      const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
      assert.equal(await gone(pid), true, `${sig}: what Suricata started is gone`);
    });
  }
});

/** Waits for a file the stand-in writes once it is in the state a test needs; fails by name after a minute rather than going on without it. */
async function untilExists(path: string, ms = 60_000): Promise<void> {
  const until = Date.now() + ms;
  while (!(await exists(path))) {
    if (Date.now() > until) assert.fail(`${path} was not written within ${ms} ms`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

test("a bad home_net entry is named by its position and length, never echoed", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ALERT(1) + "\n" });
    const { path, rules } = await inputs(cwd);
    const secret = planted(createRng(5), "ghp");
    const err = refused(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s", home_net: ["10.0.0.0/8", secret] }, env(cwd), bin));
    assert.equal(err.home_net_index, 1);
    assert.equal(err.home_net_entry_length, secret.length);
    assert.equal(JSON.stringify(err).includes(secret), false);
    assert.equal(err.status, "failed");
  });
});

test("eve.json is read under the tool's own clock: it is read in part when the clock runs out, and says so (partial, eve_read_to_the_end false), the file whole on disk", async () => {
  await withCwd(async (cwd, bin) => {
    const eve = Array.from({ length: 120_000 }, (_, i) => ALERT(i % 100)).join("\n") + "\n";
    await stage(cwd, bin, { eve, loadTest: "<Info> - 2 rules successfully loaded, 0 rules failed\n", loadRun: "<Info> - 2 rules successfully loaded, 0 rules failed\n" });
    const { path, rules } = await inputs(cwd);
    const cut = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s" }, { ...env(cwd), SURICATA_RUN_READ_SECONDS: "0.05" }, bin));
    assert.equal(cut.status, "partial");
    assert.equal(cut.ok, false);
    assert.equal(cut.eve_read_to_the_end, false);
    assert.ok(cut.eve_reading_cut_by_its_clock.lines_read > 0 && cut.eve_reading_cut_by_its_clock.lines_read < 120_000);
    assert.equal(cut.eve_lines, cut.eve_reading_cut_by_its_clock.lines_read);
    assert.ok(cut.alert_count < 120_000, "the counts are those of the lines read");
    assert.match(cut.status_basis, /eve\.json was read only to line/);
    assert.equal((await readFile(join(cwd, "work/s/eve.json"), "utf8")), eve, "eve.json is whole on disk");
    const whole = body(await tool(SURICATA, cwd, { path, rules, out_dir: "work/s2" }, env(cwd), bin));
    assert.equal(whole.eve_read_to_the_end, true);
    assert.equal(whole.eve_reading_cut_by_its_clock, null);
    assert.equal(whole.alert_count, 120_000);
    assert.equal(whole.status, "complete");
  });
});

test("a stop signal that arrives while the answer is being written adds no second document: the answer is whole and the exit is 128 plus the signal", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { eve: ALERT(1) + "\n", loadTest: "<Info> - 2 rules successfully loaded, 0 rules failed\n", loadRun: "<Info> - 2 rules successfully loaded, 0 rules failed\n" });
    const { path, rules } = await inputs(cwd);
    const code = [
      "import os, signal, sys, runpy",
      "class Out:",
      "    def __init__(self, real): self.real, self.sent = real, False",
      "    def write(self, text):",
      "        n = self.real.write(text)",
      "        if not self.sent and text.startswith('{') and '\"tool\"' in text:",
      "            self.sent = True",
      "            os.kill(os.getpid(), signal.SIGTERM)",
      "        return n",
      "    def __getattr__(self, name): return getattr(self.real, name)",
      "sys.stdout = Out(sys.stdout)",
      "runpy.run_path(sys.argv[1], run_name='__main__')",
    ].join("\n");
    const run = spawnSync("python3", ["-c", code, SURICATA], { cwd, input: JSON.stringify({ path, rules, out_dir: "work/s" }), encoding: "utf8", maxBuffer: 1 << 26,
      env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}`, ...env(cwd) } });
    assert.equal(run.status, 143, run.stderr);
    const answer = JSON.parse(run.stdout);
    assert.equal(answer.tool.name, "suricata_run");
    assert.equal(answer.interrupted_by_signal, undefined, "one document: the answer, not a last word after it");
  });
});

// --- dry_run: the engine receipt without a capture (the stand-in prints what Suricata's documentation says: a version line for --build-info, a
// --- usage text for --help that lists --dump-config on builds that have it, a test (-T) that prints the rule-load line; a run over a capture
// --- (-r) is the thing a dry run must never start) ----------------------------------------------------------------------------------

const DRY_STUB = `#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
for a in "$@"; do
  case "$a" in
    -r) echo "a capture was named" > "$STUB_DIR/capture-read"; exit 9;;
  esac
done
mode=run
while [ $# -gt 0 ]; do
  case "$1" in
    --build-info) printf 'This is Suricata version 7.0.0-stand-in RELEASE\\n'; exit 0;;
    --help)
      printf 'USAGE: suricata [OPTIONS] [BPF FILTER]\\n  -T   test configuration file\\n'
      [ -f "$STUB_DIR/no-dump" ] || printf '  --dump-config   show the running configuration\\n'
      exit 0;;
    --dump-config) [ -f "$STUB_DIR/dump-fail" ] && { echo "dump failed on request" >&2; exit 4; }; printf 'vars.address-groups.HOME_NET = [192.168.0.0/16]\\n'; exit 0;;
    -T) mode=test;;
  esac
  shift
done
if [ -f "$STUB_DIR/sleep" ]; then echo $$ > "$STUB_DIR/engine.pid"; sleep 300 & echo $! > "$STUB_DIR/child.pid"; echo started > "$STUB_DIR/started"; wait; fi
[ -f "$STUB_DIR/test-stderr" ] && cat "$STUB_DIR/test-stderr" >&2
if [ -f "$STUB_DIR/test-exit" ]; then exit "$(cat "$STUB_DIR/test-exit")"; fi
exit 0
`;

type Dry = { noDump?: boolean; dumpFail?: boolean; stderr?: string; testExit?: number; sleep?: boolean };

async function stageDry(cwd: string, bin: string, o: Dry = {}): Promise<string> {
  const dir = join(cwd, "stub");
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  await stub(bin, "suricata", DRY_STUB);
  if (o.noDump) await writeFile(join(dir, "no-dump"), "1");
  if (o.dumpFail) await writeFile(join(dir, "dump-fail"), "1");
  if (o.stderr !== undefined) await writeFile(join(dir, "test-stderr"), o.stderr);
  if (o.testExit !== undefined) await writeFile(join(dir, "test-exit"), String(o.testExit));
  if (o.sleep) await writeFile(join(dir, "sleep"), "1");
  await writeFile(join(cwd, "suricata-calls.txt"), "");
  return dir;
}

const LOADED_LINE = (n: number, failed = 0, skipped = 0): string => `<Info> - ${n} rules successfully loaded, ${failed} rules failed, ${skipped} rules skipped\n`;

// The rules file the receipt is checked against. The expected numbers below are counted by hand from these lines (see the comments), not by the tool.
const DRY_RULES = [
  'alert tcp any any -> any any (msg:"a"; sid:1000001; rev:2;)', //                 1  alert, sid 1000001, rev 2
  'alert udp any any -> any 53 (msg:"b"; sid:1000002; rev:1;)', //                  2  alert, sid 1000002, rev 1
  'drop tcp any any -> any 22 (msg:"c"; sid:1000003; rev:1;)', //                   3  drop, sid 1000003, rev 1
  '# alert tcp any any -> any 80 (msg:"d"; sid:1000004; rev:1;)', //                4  disabled alert, sid 1000004
  '#drop ip any any -> any any (msg:"e"; sid:1000010; rev:3;)', //                  5  disabled drop, sid 1000010
  "# this is prose about alert rules and their sids", //                           6  a comment, not a rule
  'pass tcp any any -> any 443 (msg:"f"; \\', //                                    7  pass, continued on the next line
  "   sid:1000005; rev:1;)", //                                                    8  (sid 1000005, rev 1)
  'alert http any any -> any any (msg:"no rev"; sid:2000001;)', //                  9  alert, sid 2000001, no rev
  'alert tcp any any -> any any (msg:"dup"; sid:1000001; rev:2;)', //               10 alert, a repeated sid
  'reject tcp any any -> any 25 (msg:"g"; sid:2000003; rev:1;)', //                 11 reject, sid 2000003, rev 1
  'alert dns any any -> any any (msg:"no sid"; rev:1;)', //                         12 alert, no sid, rev 1
  "garbage line that is not a rule", //                                            13 active, not a rule
].join("\n") + "\n";

async function dryInputs(cwd: string, rules: string | Buffer = DRY_RULES): Promise<string> {
  await put(cwd, "work/case.rules", rules);
  return "work/case.rules";
}

test("dry_run refuses a path, reads no capture and starts no run over one", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await stageDry(cwd, bin, { stderr: LOADED_LINE(8) });
    const rules = await dryInputs(cwd);
    await put(cwd, "work/c.pcap", Buffer.from("not read"));
    const err = refused(await tool(SURICATA, cwd, { dry_run: true, path: "work/c.pcap", rules, out_dir: "work/s" }, env(cwd), bin));
    assert.equal(err.status, "failed");
    assert.match(err.error, /path is not taken with dry_run/);
    assert.equal(await exists(join(cwd, "work/s")), false, "a refusal wrote nothing");
    assert.equal(await readFile(join(cwd, "suricata-calls.txt"), "utf8"), "", "a refusal started nothing");
    assert.match(refused(await tool(SURICATA, cwd, { dry_run: 1, rules, out_dir: "work/s" }, env(cwd), bin)).error, /dry_run must be true or false/);
    const out = body(await tool(SURICATA, cwd, { dry_run: true, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.equal(out.dry_run, true);
    assert.equal("path" in out, false);
    assert.equal(await exists(join(dir, "capture-read")), false);
    assert.equal(await exists(join(cwd, "work/s/eve.json")), false);
    const calls = (await readFile(join(cwd, "suricata-calls.txt"), "utf8")).trimEnd().split("\n");
    for (const c of calls) assert.doesNotMatch(c, /(^| )-r( |$)/, c);
    // without dry_run the same call (no path) is still the old refusal
    assert.match(refused(await tool(SURICATA, cwd, { rules, out_dir: "work/t" }, env(cwd), bin)).error, /path must name a readable file/);
  });
});

test("dry_run writes only under out_dir and gives each part of the receipt: identities, the effective configuration, the rule-load status, the log outputs and what is not covered", async () => {
  await withCwd(async (cwd, bin) => {
    await stageDry(cwd, bin, { stderr: LOADED_LINE(8) });
    const rules = await dryInputs(cwd);
    const before = await filesUnder(cwd);
    const out = body(await tool(SURICATA, cwd, { dry_run: true, rules, out_dir: "work/s" }, env(cwd), bin));
    const after = await filesUnder(cwd);
    const created = after.filter((f) => !before.includes(f) && !f.startsWith("stub/") && f !== "suricata-calls.txt");
    assert.ok(created.length > 0 && created.every((f) => f.startsWith("work/s/")), `only out_dir: ${created.join(", ")}`);
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.ok, true);

    // identities: the file's digest, size and rule line count (physical lines that are not empty or comments), and by hand the rest
    const id = out.identities.rules;
    assert.equal(id.sha256, sha(DRY_RULES));
    assert.equal(id.bytes, Buffer.byteLength(DRY_RULES));
    assert.equal(id.rule_lines, 10);
    const a = id.analysis;
    assert.equal(a.whole, true);
    assert.equal(a.rules_active, 8);
    assert.deepEqual(a.active_by_action, { alert: 5, drop: 1, pass: 1, reject: 1 });
    assert.equal(a.active_lines_that_are_not_rules, 1);
    assert.equal(a.rules_disabled, 2, "a # line with an action word and a sid is a disabled rule; prose after a # is not");
    assert.deepEqual(a.disabled_by_action, { alert: 1, drop: 1 });
    assert.equal(a.disabled_sid_min, 1000004);
    assert.equal(a.disabled_sid_max, 1000010);
    assert.deepEqual(a.sid.ranges, [[1000001, 1000003], [1000005, 1000005], [2000001, 2000001], [2000003, 2000003]]);
    assert.equal(a.sid.count, 7);
    assert.equal(a.sid.distinct, 6);
    assert.equal(a.sid.duplicates, 1);
    assert.equal(a.sid.min, 1000001);
    assert.equal(a.sid.max, 2000003);
    assert.equal(a.sid.without_sid, 1);
    assert.deepEqual(a.rev.values, { "1": 5, "2": 2 });
    assert.equal(a.rev.without_rev, 1);
    assert.equal(a.sid.ranges_file, null, "four ranges are all inline");
    const config = await readFile(join(cwd, "work/s/suricata.yaml"), "utf8");
    assert.equal(out.identities.configuration.sha256, sha(config));
    assert.match(out.identities.engine.suricata_version, /version 7\.0\.0-stand-in/);

    // the effective configuration: the -T test with its status, and the dump where the build has the command
    const eff = out.effective_configuration;
    assert.equal(eff.test.exit_code, 0);
    assert.match(eff.test.command.join(" "), /-T -c .*suricata\.yaml -S .*case\.rules/);
    assert.equal(eff.dump_config.available, true);
    assert.equal(eff.dump_config.exit_code, 0);
    const dump = await readFile(join(cwd, "work/s/suricata-dump-config.txt"));
    assert.equal(eff.dump_config.sha256, sha(dump));
    assert.equal(eff.dump_config.bytes, dump.length);
    assert.ok(await exists(join(cwd, "work/s/suricata-help.txt")));

    // the rule-load status
    assert.deepEqual(out.rule_load.configuration_test, { loaded: 8, failed: 0, skipped: 0, from: "suricata-test.stderr" });
    assert.equal(out.rule_load.known, true);
    assert.equal(out.rule_load.disabled_in_file, 2);

    // the log outputs are those of the written configuration
    const types = [...config.matchAll(/^        - (\w+):?$/gm)].map((m) => m[1]);
    assert.deepEqual(out.log_outputs.files[0].types, types);
    assert.equal(out.log_outputs.files[0].name, "eve.json");

    // what is not covered
    const gaps = out.not_covered.join("\n");
    assert.match(gaps, /No ruleset ships/);
    assert.match(gaps, /no automatic download and no suricata-update/);
    assert.match(gaps, /No capture was read/);
  });
});

test("dry_run names a build without --dump-config, and a dump that fails makes the receipt partial", async () => {
  await withCwd(async (cwd, bin) => {
    await stageDry(cwd, bin, { noDump: true, stderr: LOADED_LINE(8) });
    const rules = await dryInputs(cwd);
    const out = body(await tool(SURICATA, cwd, { dry_run: true, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.equal(out.effective_configuration.dump_config.available, false);
    assert.match(out.effective_configuration.dump_config.reason, /does not list --dump-config/);
    assert.equal(out.status, "complete", "a command the build lacks is named, not a failure");
    assert.match(out.status_basis, /no --dump-config/);
    assert.equal(await exists(join(cwd, "work/s/suricata-dump-config.txt")), false);
    assert.doesNotMatch(await readFile(join(cwd, "suricata-calls.txt"), "utf8"), /--dump-config -c/);
    await stageDry(cwd, bin, { dumpFail: true, stderr: LOADED_LINE(8) });
    const failed = body(await tool(SURICATA, cwd, { dry_run: true, rules, out_dir: "work/t" }, env(cwd), bin));
    assert.equal(failed.status, "partial");
    assert.match(failed.status_basis, /--dump-config` exited 4/);
    assert.equal(failed.effective_configuration.dump_config.sha256, null);
  });
});

test("dry_run: rules that fail to load make a partial receipt with the engine's first failures, withheld by shape, and the rest in the files", async () => {
  await withCwd(async (cwd, bin) => {
    const canary = "k".repeat(8) + randomBytes(24).toString("hex");
    const stderr = [
      `<Error> - [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "alert tcp any any -> any any (msg:\\"${canary}\\"; sid:3;" from file work/case.rules at line 13`,
      `<Error> - [ERRCODE: SC_ERR_NO_RULES(42)] - failed to load rules`,
      LOADED_LINE(7, 1, 0).trimEnd(),
    ].join("\n") + "\n";
    await stageDry(cwd, bin, { stderr, testExit: 1 });
    const rules = await dryInputs(cwd);
    const out = body(await tool(SURICATA, cwd, { dry_run: true, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.equal(out.status, "partial");
    assert.equal(out.ok, false);
    assert.match(out.status_basis, /configuration test \(suricata -T\) failed with exit code 1/);
    assert.deepEqual(out.rule_load.configuration_test, { loaded: 7, failed: 1, skipped: 0, from: "suricata-test.stderr" });
    assert.equal(out.rule_load.failure_lines_total, 2);
    assert.equal(out.rule_load.first_failures[0].rules_line, 13);
    assert.match(out.rule_load.first_failures[1].text, /failed to load rules/);
    assert.equal(JSON.stringify(out).includes(canary), false, "a token-shaped run in the engine's text is withheld from the answer");
    assert.ok((await readFile(join(cwd, "work/s/suricata-test.stderr"), "utf8")).includes(canary), "the whole stays in the file");
  });
});

test("dry_run: a rule longer than the limit is located and not read, a NUL in a rule is no obstacle, and 5,000 ranges are all in a file the answer names", async () => {
  await withCwd(async (cwd, bin) => {
    await stageDry(cwd, bin, { stderr: LOADED_LINE(1) });
    const huge = Buffer.concat([
      Buffer.from('alert tcp any any -> any any (msg:"'), Buffer.alloc(10 << 20, 0x41), Buffer.from('"; sid:9;)\n'),
      Buffer.from('alert tcp any any -> any any (msg:"a\0b"; sid:7; rev:1;)\n'),
    ]);
    const rules = await dryInputs(cwd, huge);
    const t0 = Date.now();
    const out = body(await tool(SURICATA, cwd, { dry_run: true, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.ok(Date.now() - t0 < 30_000);
    const a = out.identities.rules.analysis;
    assert.deepEqual(a.over_limit_lines, [1]);
    assert.equal(a.over_limit_total, 1);
    assert.equal(a.rules_active, 1, "the rule with a NUL is read; the 10 MB one is in no count");
    assert.deepEqual(a.sid.ranges, [[7, 7]]);
    assert.equal(a.whole, false);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /longer than 1048576 bytes were located by line number/);
    assert.equal(out.identities.rules.bytes, huge.length);
    assert.equal(out.identities.rules.rule_lines, 2);

    // many ranges: the answer holds the first 100, the file holds every one, and the two counts agree
    await stageDry(cwd, bin, { stderr: LOADED_LINE(5000) });
    const many = Array.from({ length: 5000 }, (_, i) => `alert ip any any -> any any (msg:"r"; sid:${2 * i + 1}; rev:1;)`).join("\n") + "\n";
    await put(cwd, "work/many.rules", many);
    const m = body(await tool(SURICATA, cwd, { dry_run: true, rules: "work/many.rules", out_dir: "work/m" }, env(cwd), bin)).identities.rules.analysis;
    assert.equal(m.sid.ranges_total, 5000);
    assert.equal(m.sid.ranges.length, 100);
    assert.equal(m.sid.ranges_in_file, 5000);
    const lines = (await readFile(join(cwd, "work/m/sid-ranges.txt"), "utf8")).trimEnd().split("\n");
    assert.equal(lines.length, 5000);
    assert.equal(lines[0], "1-1");
    assert.equal(lines[4999], "9999-9999");
    assert.equal((await stat(join(cwd, "work/m/sid-ranges.txt"))).mode & 0o777, 0o600);
  });
});

test("dry_run: 200,000 continuation lines of one rule take linear time, and a rule file read past the tool's own clock is a partial receipt", async () => {
  await withCwd(async (cwd, bin) => {
    await stageDry(cwd, bin, { stderr: LOADED_LINE(0) });
    const rules = await dryInputs(cwd, "x\\\n".repeat(200_000) + "y\n");
    const t0 = Date.now();
    const out = body(await tool(SURICATA, cwd, { dry_run: true, rules, out_dir: "work/s" }, env(cwd), bin));
    assert.ok(Date.now() - t0 < 20_000, `took ${Date.now() - t0} ms`);
    assert.equal(out.identities.rules.analysis.active_lines_that_are_not_rules, 1);
    const big = Array.from({ length: 300_000 }, (_, i) => `alert ip any any -> any any (msg:"r"; sid:${i + 1}; rev:1;)`).join("\n") + "\n";
    await put(cwd, "work/big.rules", big);
    const cut = body(await tool(SURICATA, cwd, { dry_run: true, rules: "work/big.rules", out_dir: "work/c" }, { ...env(cwd), SURICATA_RUN_DRY_SECONDS: "0" }, bin));
    assert.equal(cut.status, "partial");
    assert.notEqual(cut.identities.rules.analysis.cut_by_its_clock, null);
    assert.match(cut.status_basis, /clock ran out while the rules file was read/);
  });
});

test("dry_run: a refused write of the sid-range file is named and the file is not left half-written", async () => {
  await withCwd(async (cwd, bin) => {
    await stageDry(cwd, bin, { stderr: LOADED_LINE(5000) });
    const many = Array.from({ length: 5000 }, (_, i) => `alert ip any any -> any any (msg:"r"; sid:${2 * i + 1}; rev:1;)`).join("\n") + "\n";
    await put(cwd, "work/many.rules", many);
    // RLIMIT_FSIZE of 20 KiB (dash counts 512-byte blocks): the 5,000 range lines are about 55 KB, so the write is refused; Python ignores SIGXFSZ, so it is an OSError
    const run = spawnSync("sh", ["-c", "ulimit -f 40 && exec python3 \"$0\"", SURICATA], {
      cwd, input: JSON.stringify({ dry_run: true, rules: "work/many.rules", out_dir: "work/m" }), encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, AGENT_ID: "s1", ...env(cwd) },
    });
    assert.equal(run.status, 0, run.stderr + run.stdout);
    const out = JSON.parse(run.stdout);
    const a = out.identities.rules.analysis;
    assert.equal(out.status, "partial");
    assert.equal(a.sid.ranges_file, null);
    assert.equal(a.sid.ranges.length, 100);
    assert.equal(a.sid.ranges_total, 5000);
    assert.match(a.problems.join(" "), /file of all sid ranges could not be written/);
    assert.equal(await exists(join(cwd, "work/m/sid-ranges.txt")), false, "a file that holds fewer ranges than the answer counts is removed");
  });
});

test("dry_run: a stop signal gives one JSON answer with the stage, exit 128 + signal, and kills the engine and what it started", async () => {
  for (const [sig, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await stageDry(cwd, bin, { sleep: true });
      const rules = await dryInputs(cwd);
      const run = startDetached(SURICATA, cwd, { dry_run: true, rules, out_dir: "work/s" }, env(cwd), bin);
      await untilExists(join(dir, "started"));
      run.signal(sig);
      assert.equal(await run.closed, code, sig);
      const last = JSON.parse(run.stdout());
      assert.equal(last.status, "partial");
      assert.equal(last.interrupted_by_signal, code - 128);
      assert.equal(last.stage, "testing the configuration");
      assert.ok(last.files_on_disk.includes("suricata.yaml"));
      const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
      assert.equal(await gone(pid), true, `${sig}: what Suricata started is gone`);
    });
  }
});
