/**
 * network-forensics: a stop signal that lands the moment the answer has been read does not kill the call by the signal's default action.
 *
 * The interpreter's own teardown resets the signal handlers to their defaults before it frees what the call held; a SIGINT/SIGTERM/SIGHUP that
 * lands there ended the process with no exit code (killed by the signal) with the whole answer already printed (macOS CI: pcap_summary, SIGINT,
 * `null !== 130`). Every tool of the pack now ends with `_leave()` (flush, then os._exit with the code the call had), and the three tools that
 * print one document at the end (pcap_summary, beacon_score, network_log_summary) set a flag the handler reads before the document is
 * written, so that a signal after it writes no second one.
 *
 * Here each tool is run for real (a success where the tool needs no outside program, a refusal otherwise), and the signal is sent as soon as a
 * complete JSON document has been read from its standard output. 0 of N may die by the signal; the answer stays ONE document; the exit status
 * is the call's own (0 or 1) or 128 + the signal.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { AGENT, BEACON, CONNS, EXTRACT, FLOW, LOGS, QUICI, SUMMARY, SURICATA, TLSD, TRANSFORM, ZEEK, drop, frameTcp4, pcapClassic, put, TCP, withCwd } from "./pack-network-harness.ts";
import { PYTHON3 } from "./host-gates.ts";

const SIGNALS = [["SIGTERM", 15], ["SIGINT", 2], ["SIGHUP", 1]] as const;
const ROUNDS = 6;

function whole(text: string): boolean {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

async function runThenSignal(script: string, cwd: string, args: unknown, signal: NodeJS.Signals): Promise<{ code: number | null; by: string | null; stdout: string; stderr: string }> {
  const child = spawn(PYTHON3, [script], { cwd, env: { ...process.env, ...AGENT }, detached: true, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  let sent = false;
  child.stdout.on("data", (b: Buffer) => {
    stdout += b.toString("utf8");
    if (!sent && whole(stdout)) {
      sent = true;
      try {
        child.kill(signal);                      // the moment the answer has been read
      } catch {
        /* gone */
      }
    }
  });
  child.stderr.on("data", (b: Buffer) => { stderr += b.toString("utf8"); });
  child.stdin.on("error", () => undefined);
  child.stdin.end(JSON.stringify(args));
  return new Promise((resolve) => {
    const timer = setTimeout(() => { try { process.kill(-(child.pid as number), "SIGKILL"); } catch { /* gone */ } }, 90_000);
    child.on("close", (code, by) => { clearTimeout(timer); resolve({ code, by, stdout, stderr }); });
  });
}

const frame = frameTcp4({ src: "10.0.0.1", dst: "10.0.0.2", sport: 40000, dport: 443, flags: TCP.SYN, seq: 1 });
const CASES: Array<[string, string, (cwd: string) => Promise<unknown>]> = [
  ["pcap_summary (a summary)", SUMMARY, async (cwd) => ({ path: await drop(cwd, "work/a.pcap", pcapClassic(Array.from({ length: 300 }, (_, i) => ({ sec: 1_700_000_000 + i, frame })))) })],
  ["beacon_score (a score)", BEACON, async () => ({ timestamps: Array.from({ length: 50 }, (_, i) => 1_771_070_000 + i * 10) })],
  ["network_log_summary (a summary)", LOGS, async (cwd) => {
    await put(cwd, "access.log", '203.0.113.9 - - [10/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8"\n');
    return { path: "access.log", out_dir: "work/s1/out" };
  }],
  ["pcap_summary (a refusal)", SUMMARY, async () => ({})],
  ["beacon_score (a refusal)", BEACON, async () => ({})],
  ["network_log_summary (a refusal)", LOGS, async () => ({})],
  ["zeek_run (a refusal)", ZEEK, async () => ({})],
  ["suricata_run (a refusal)", SURICATA, async () => ({})],
  ["pcap_extract (a refusal)", EXTRACT, async () => ({})],
  ["capture_transform (a refusal)", TRANSFORM, async () => ({})],
  ["flow_reader (a refusal)", FLOW, async () => ({})],
  ["tls_decrypt (a refusal)", TLSD, async () => ({})],
  ["quic_inspect (a refusal)", QUICI, async () => ({})],
  ["conn_series (a refusal)", CONNS, async () => ({})],
];

for (const [name, script, args] of CASES) {
  test(`${name}: a stop signal sent the moment the answer was read kills no call by the signal (0 of ${ROUNDS * SIGNALS.length}), and the answer stays one document`, { timeout: 280_000 }, async () => {
    await withCwd(async (cwd) => {
      const arg = await args(cwd);
      for (let round = 0; round < ROUNDS; round++) {
        for (const [signal, number] of SIGNALS) {
          const run = await runThenSignal(script, cwd, arg, signal);
          const where = `${name} ${signal} (round ${round}): exit ${run.code}, killed by ${run.by}`;
          assert.equal(run.by, null, where);
          assert.notEqual(run.code, null, where);
          assert.doesNotMatch(run.stderr, /Traceback/, `${where}: ${run.stderr.slice(0, 300)}`);
          JSON.parse(run.stdout);               // one document: a second one after it would not parse
          assert.ok([0, 1, 128 + number].includes(run.code as number), `${where}: ${run.stdout.slice(0, 200)}`);
        }
      }
    });
  });
}

test("every tool of the pack ends with _leave(): the call does not go through the interpreter's teardown", async () => {
  const scripts = [SUMMARY, BEACON, LOGS, ZEEK, SURICATA, EXTRACT, TRANSFORM, FLOW, TLSD, QUICI, CONNS];
  for (const script of scripts) {
    const text = await readFile(script, "utf8");
    const main = text.slice(text.lastIndexOf('\nif __name__ == "__main__":\n'));     // the script's own, after the shared ENDS block's
    assert.match(main, /\n    _leave\(exit_code\)\n$/, script);
    assert.match(text, /def _leave\(code\):[\s\S]*os\._exit\(code\)/, script);
  }
});