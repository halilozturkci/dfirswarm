/**
 * network-forensics: capture_transform makes derivative captures and accounts for every packet.
 *
 * Wireshark's command-line tools and tcpdump are not on every machine these suites run on, so stand-in programs play them. A stand-in
 * works on a plain-text "capture" (a first line `#STUBCAP pcap` or `#STUBCAP pcapng`, then one packet per line, `<seconds> <payload>`)
 * and does what the program's documentation says of its options: `editcap -c N in out` writes `<out base>_<NNNNN>_<time>.<ext>` parts,
 * `-d`/`-D`/`-w` remove duplicates, `-F` sets the format; `mergecap [-a] [-F type] -w out in...`; `tcpdump -n -r in -w out -- filter`;
 * `text2pcap [options] in out`; `capinfos -M files` prints `File name:`, `File type:`, `File encapsulation:`, `Number of packets:` and,
 * for pcapng, `Number of interfaces in file:` per file. That proves the wrapper's logic: the arguments it builds, the accounting it
 * derives from the counts, what it places and where, and how it stops. It proves nothing about the real programs: a gated test at the
 * end runs them when they are installed and says so when they are not.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, TRANSFORM, asJob, body, exists, filesUnder, frameTcp4, gone, pcapClassic, put, refused, startDetached, stub, TCP, tool, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

const CAPINFOS = `#!/bin/sh
printf '%s\\n' "capinfos $*" >> "$STUB_LOG"
case "$1" in --version) echo 'Capinfos (Wireshark) 4.0.11-stand-in'; exit 0;; esac
[ -f "$STUB_DIR/capinfos-hang" ] && { sleep 300; exit 0; }
rc=0
for f in "$@"; do
  case "$f" in -*) continue;; esac
  head=$(head -n 1 "$f" 2>/dev/null)
  case "$head" in
    "#STUBCAP pcapng") type='Wireshark/... - pcapng'; ifs='Number of interfaces in file: 1';;
    "#STUBCAP pcap") type='Wireshark/tcpdump/... - pcap'; ifs='';;
    *) echo "capinfos: The file \\"$f\\" isn't a capture file in a format Wireshark understands." >&2; rc=2; continue;;
  esac
  n=$(($(wc -l < "$f") - 1))
  printf 'File name:           %s\\nFile type:           %s\\nFile encapsulation:  Ethernet\\nNumber of packets:   %s\\n' "$f" "$type" "$n"
  [ -n "$ifs" ] && echo "$ifs"
  echo
done
exit $rc
`;

const EDITCAP = `#!/bin/sh
printf '%s\\n' "editcap $*" >> "$STUB_LOG"
case "$1" in --version) echo 'Editcap (Wireshark) 4.0.11-stand-in'; exit 0;; esac
[ -f "$STUB_DIR/editcap-fail" ] && { echo "editcap: failed on request" >&2; exit 2; }
if [ -f "$STUB_DIR/editcap-sleep" ]; then echo $$ > "$STUB_DIR/engine.pid"; sleep 300 & echo $! > "$STUB_DIR/child.pid"; echo started > "$STUB_DIR/started"; wait; fi
c=""; i=""; d=""; D=""; w=""; F=""
while [ $# -gt 0 ]; do
  case "$1" in -c) c=$2; shift;; -i) i=$2; shift;; -d) d=5;; -D) D=$2; shift;; -w) w=$2; shift;; -F) F=$2; shift;; -t|-S) echo shifted > "$STUB_DIR/time-shift"; shift;; *) break;; esac
  shift
done
in=$1; out=$2
type=$(head -n 1 "$in" | sed 's/#STUBCAP //'); [ -n "$F" ] && type=$F
lose=0; [ -f "$STUB_DIR/editcap-lose" ] && lose=1
if [ -n "$c" ]; then
  base=\${out%.*}; ext=\${out##*.}
  tail -n +2 "$in" | awk -v c="$c" -v base="$base" -v ext="$ext" -v type="$type" -v lose="$lose" '
    { lines[NR] = $0 } END {
      last = NR; if (lose && last > 0) last--
      prev = ""
      for (k = 1; k <= last; k++) {
        n = int((k - 1) / c) + 1; f = sprintf("%s_%05d_20231114221320.%s", base, n, ext)
        if (f != prev) { if (prev != "") close(prev); print "#STUBCAP " type > f; prev = f }
        print lines[k] > f
      }
      if (prev != "") close(prev)
    }' || exit 2
  exit 0
fi
if [ -n "$d$D$w" ]; then
  window=5; [ -n "$D" ] && window=$D
  { echo "#STUBCAP $type"; tail -n +2 "$in" | awk -v window="$window" '
    { p = $0; sub(/^[^ ]+ /, "", p); dup = 0
      for (k = NR - 1; k >= 1 && k >= NR - window; k--) if (seen[k] == p) dup = 1
      seen[NR] = p; if (!dup) print $0 }'; } > "$out"
  exit 0
fi
{ echo "#STUBCAP $type"; tail -n +2 "$in"; } > "$out"
`;

const MERGECAP = `#!/bin/sh
printf '%s\\n' "mergecap $*" >> "$STUB_LOG"
case "$1" in --version) echo 'Mergecap (Wireshark) 4.0.11-stand-in'; exit 0;; esac
a=""; F=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in -a) a=1;; -F) F=$2; shift;; -w) out=$2; shift;; *) break;; esac
  shift
done
type=$(head -n 1 "$1" | sed 's/#STUBCAP //'); [ -n "$F" ] && type=$F
{ echo "#STUBCAP $type"
  if [ -n "$a" ]; then for f in "$@"; do tail -n +2 "$f"; done; else for f in "$@"; do tail -n +2 "$f"; done | sort -s -k1,1n; fi; } > "$out"
`;

const TCPDUMP = `#!/bin/sh
printf '%s\\n' "tcpdump $*" >> "$STUB_LOG"
case "$1" in --version) echo 'tcpdump version 4.99.3-stand-in' >&2; exit 0;; esac
in=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in -n) ;; -r) in=$2; shift;; -w) out=$2; shift;; --) shift; break;; *) break;; esac
  shift
done
filter="$*"
{ echo "#STUBCAP pcap"; tail -n +2 "$in" | grep -F -- "$filter"; } > "$out"
exit 0
`;

const TEXT2PCAP = `#!/bin/sh
printf '%s\\n' "text2pcap $*" >> "$STUB_LOG"
case "$1" in --version) echo 'Text2pcap (Wireshark) 4.0.11-stand-in'; exit 0;; esac
F=pcapng
while [ $# -gt 0 ]; do
  case "$1" in -l|-e|-i|-u|-T|-t) shift;; -F) F=$2; shift;; *) break;; esac
  shift
done
in=$1; out=$2
{ echo "#STUBCAP $F"; grep -v '^$' "$in" | awk '{ print "0 hex:" $0 }'; } > "$out"
`;

async function programs(cwd: string, bin: string, o: { fail?: boolean; sleep?: boolean; lose?: boolean; capinfosHang?: boolean } = {}): Promise<string> {
  const dir = join(cwd, "stub");
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  for (const [name, script] of Object.entries({ capinfos: CAPINFOS, editcap: EDITCAP, mergecap: MERGECAP, tcpdump: TCPDUMP, text2pcap: TEXT2PCAP })) await stub(bin, name, script);
  if (o.fail) await writeFile(join(dir, "editcap-fail"), "1");
  if (o.sleep) await writeFile(join(dir, "editcap-sleep"), "1");
  if (o.lose) await writeFile(join(dir, "editcap-lose"), "1");
  if (o.capinfosHang) await writeFile(join(dir, "capinfos-hang"), "1");
  await writeFile(join(cwd, "calls.txt"), "");
  return dir;
}

const env = (cwd: string) => ({ STUB_DIR: join(cwd, "stub"), STUB_LOG: join(cwd, "calls.txt") });
const stubCap = (type: "pcap" | "pcapng", packets: Array<[number, string]>): string => `#STUBCAP ${type}\n` + packets.map(([t, p]) => `${t} ${p}`).join("\n") + (packets.length ? "\n" : "");
const SEVEN: Array<[number, string]> = [[1, "a"], [2, "b"], [3, "c"], [4, "d"], [5, "e"], [6, "f"], [7, "g"]];

async function original(cwd: string, name: string, text: string): Promise<{ path: string; text: string }> {
  const path = `inputs/${name}`;
  await put(cwd, path, text);
  return { path, text };
}

/** Every file under the temporary directories a run makes inside out_dir (they must be gone). */
async function leftovers(cwd: string, out: string): Promise<string[]> {
  return (await readdir(join(cwd, out)).catch(() => [])).filter((n) => n.startsWith(".capture_transform-"));
}

test("split: the parts together hold every packet, the original is untouched, and nothing is written outside out_dir and the page directory", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const o = await original(cwd, "a.pcap", stubCap("pcap", SEVEN));
    const before = await filesUnder(cwd);
    const out = body(await tool(TRANSFORM, cwd, { operation: "split", inputs: [o.path], packets: 3, out_dir: "work/t" }, env(cwd), bin));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.operation, "split");
    assert.equal(out.derivatives_total, 3);
    assert.deepEqual(out.derivatives.map((d: Json) => [d.name, d.packets]), [["split-00001.pcap", 3], ["split-00002.pcap", 3], ["split-00003.pcap", 1]]);
    assert.deepEqual(out.accounting, { packets_in: 7, packets_out: 7, dropped: 0, dropped_by: "none by design: split keeps every packet", balanced: true });
    for (const d of out.derivatives) {
      assert.equal(d.label, "derivative, not evidence");
      const bytes = await readFile(join(cwd, d.path));
      assert.equal(d.sha256, sha(bytes));
      assert.equal(d.bytes, bytes.length);
      assert.equal((await stat(join(cwd, d.path))).mode & 0o777, 0o600);
    }
    // The original: same bytes, and the programs were given it to read, never as an output.
    assert.equal(await readFile(join(cwd, o.path), "utf8"), o.text);
    assert.equal(out.inputs[0].sha256, sha(o.text));
    assert.equal(out.inputs[0].packets, 7);
    const calls = (await readFile(join(cwd, "calls.txt"), "utf8")).trimEnd().split("\n");
    const edit = calls.find((c) => /^editcap -c 3 /.test(c));
    assert.ok(edit, calls.join("\n"));
    assert.doesNotMatch(edit, / -t | -S /, "no time shift");
    const created = (await filesUnder(cwd)).filter((f) => !before.includes(f) && !f.startsWith("stub/") && f !== "calls.txt");
    assert.ok(created.every((f) => f.startsWith("work/t/")), created.join(", "));
    assert.deepEqual(await leftovers(cwd, "work/t"), []);
    assert.equal(out.tool_versions.editcap, "Editcap (Wireshark) 4.0.11-stand-in");
    // by seconds instead
    const s = body(await tool(TRANSFORM, cwd, { operation: "split", inputs: [o.path], seconds: 2, out_dir: "work/u" }, env(cwd), bin));
    assert.equal(s.accounting.balanced, true);
    assert.match(await readFile(join(cwd, "calls.txt"), "utf8"), /editcap -i 2 /);
  });
});

test("a time shift is refused, an unknown parameter is named, and each operation refuses what it does not take", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const o = await original(cwd, "a.pcap", stubCap("pcap", SEVEN));
    for (const shift of ["time_shift", "time_adjustment"]) {
      const err = refused(await tool(TRANSFORM, cwd, { operation: "convert", inputs: [o.path], format: "pcap", out_dir: "work/t", [shift]: 3600 }, env(cwd), bin));
      assert.match(err.error, /a time shift is refused/);
      assert.equal(err.parameter, shift);
    }
    assert.match(refused(await tool(TRANSFORM, cwd, { operation: "convert", inputs: [o.path], format: "pcap", out_dir: "work/t", reverse: true }, env(cwd), bin)).error, /unknown parameters: reverse/);
    assert.match(refused(await tool(TRANSFORM, cwd, { operation: "split", inputs: [o.path], out_dir: "work/t" }, env(cwd), bin)).error, /exactly one of packets/);
    assert.match(refused(await tool(TRANSFORM, cwd, { operation: "split", inputs: [o.path], packets: 2, bpf_filter: "tcp", out_dir: "work/t" }, env(cwd), bin)).error, /split does not take bpf_filter/);
    assert.match(refused(await tool(TRANSFORM, cwd, { operation: "merge", inputs: [o.path], out_dir: "work/t" }, env(cwd), bin)).error, /two or more inputs/);
    assert.match(refused(await tool(TRANSFORM, cwd, { operation: "filter", inputs: [o.path], out_dir: "work/t" }, env(cwd), bin)).error, /filter needs bpf_filter/);
    assert.match(refused(await tool(TRANSFORM, cwd, { operation: "hexdump", inputs: [o.path], udp_ports: [1, 2], tcp_ports: [3, 4], out_dir: "work/t" }, env(cwd), bin)).error, /at most one of/);
    assert.match(refused(await tool(TRANSFORM, cwd, { operation: "split", inputs: [o.path], packets: 2, out_dir: "inputs/x" }, env(cwd), bin)).error, /cannot be under inputs/);
    assert.equal(await readFile(join(cwd, "calls.txt"), "utf8"), "", "a refusal started no program");
    assert.equal(await exists(join(cwd, "work/t")), false);
  });
});

test("merge: chronological interleaves, append keeps the order given, and the interface counts of the inputs and the output are read back", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const a = await original(cwd, "a.pcapng", stubCap("pcapng", [[1, "a1"], [5, "a5"]]));
    const b = await original(cwd, "b.pcapng", stubCap("pcapng", [[2, "b2"], [3, "b3"], [9, "b9"]]));
    const chrono = body(await tool(TRANSFORM, cwd, { operation: "merge", inputs: [a.path, b.path], out_dir: "work/t" }, env(cwd), bin));
    assert.equal(chrono.status, "complete", chrono.status_basis);
    assert.deepEqual(chrono.accounting, { packets_in: 5, packets_out: 5, dropped: 0, dropped_by: "none by design: merge keeps every packet", balanced: true });
    assert.deepEqual((await readFile(join(cwd, chrono.derivatives[0].path), "utf8")).split("\n").slice(1, 6).map((l) => l.split(" ")[1]), ["a1", "b2", "b3", "a5", "b9"]);
    assert.equal(chrono.derivatives[0].interfaces, 1);
    assert.equal(chrono.inputs[0].interfaces, 1);
    assert.match(chrono.notes.join(" "), /Chronological/);
    const appended = body(await tool(TRANSFORM, cwd, { operation: "merge", inputs: [a.path, b.path], merge_order: "append", out_dir: "work/u" }, env(cwd), bin));
    assert.deepEqual((await readFile(join(cwd, appended.derivatives[0].path), "utf8")).split("\n").slice(1, 6).map((l) => l.split(" ")[1]), ["a1", "a5", "b2", "b3", "b9"]);
    assert.match(appended.notes.join(" "), /output can run backwards in time/);
    assert.match(await readFile(join(cwd, "calls.txt"), "utf8"), /mergecap -a -w /);
    assert.equal(appended.settings.order, "append");
  });
});

test("filter: the packets the recorded BPF filter dropped are counted with the reason, the derivative says it is not the capture, and a filter that matches nothing is a named zero-packet derivative", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const o = await original(cwd, "a.pcap", stubCap("pcap", [[1, "tcp-a"], [2, "udp-b"], [3, "tcp-c"], [4, "udp-d"], [5, "tcp-e"]]));
    const out = body(await tool(TRANSFORM, cwd, { operation: "filter", inputs: [o.path], bpf_filter: "tcp-", out_dir: "work/t" }, env(cwd), bin));
    assert.equal(out.status, "complete", out.status_basis);
    assert.deepEqual(out.accounting, { packets_in: 5, packets_out: 3, dropped: 2, dropped_by: "dropped by the BPF filter recorded in settings", balanced: true });
    assert.equal(out.settings.bpf_filter, "tcp-");
    assert.match(out.notes.join(" "), /not the capture/);
    assert.match(await readFile(join(cwd, "calls.txt"), "utf8"), /^tcpdump -n -r .*inputs\/a\.pcap -w .*filtered\.pcap -- tcp-$/m);
    const none = body(await tool(TRANSFORM, cwd, { operation: "filter", inputs: [o.path], bpf_filter: "no-such", out_dir: "work/u" }, env(cwd), bin));
    assert.equal(none.accounting.packets_out, 0);
    assert.equal(none.accounting.dropped, 5);
    assert.deepEqual(none.zero_packet_derivatives, ["filtered.pcap"]);
    assert.match(none.notes.join(" "), /hold no packet/);
    // a filter that starts with a dash stays one argument after --
    const dash = body(await tool(TRANSFORM, cwd, { operation: "filter", inputs: [o.path], bpf_filter: "-x", out_dir: "work/v" }, env(cwd), bin));
    assert.equal(dash.settings.bpf_filter, "-x");
  });
});

test("dedup: the three ways to name the window reach editcap, and the removed duplicates are counted", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const o = await original(cwd, "a.pcap", stubCap("pcap", [[1, "x"], [2, "x"], [3, "y"], [4, "x"], [5, "y"]]));
    const plain = body(await tool(TRANSFORM, cwd, { operation: "dedup", inputs: [o.path], out_dir: "work/t" }, env(cwd), bin));
    assert.equal(plain.accounting.packets_out, 2, "the second x, the second y and the third x repeat a payload within five packets");
    assert.equal(plain.accounting.dropped, 3);
    assert.match(plain.accounting.dropped_by, /removed as duplicates by editcap \(its default window\)/);
    const win = body(await tool(TRANSFORM, cwd, { operation: "dedup", inputs: [o.path], dedup_window: 1, out_dir: "work/u" }, env(cwd), bin));
    assert.equal(win.accounting.packets_out, 4);
    assert.match(win.accounting.dropped_by, /a window of 1 packets/);
    const secs = body(await tool(TRANSFORM, cwd, { operation: "dedup", inputs: [o.path], dedup_seconds: 0.5, out_dir: "work/v" }, env(cwd), bin));
    assert.match(secs.accounting.dropped_by, /a window of 0\.5 seconds/);
    const calls = await readFile(join(cwd, "calls.txt"), "utf8");
    assert.match(calls, /editcap -d /);
    assert.match(calls, /editcap -D 1 /);
    assert.match(calls, /editcap -w 0\.5 /);
    assert.match(refused(await tool(TRANSFORM, cwd, { operation: "dedup", inputs: [o.path], dedup_window: 1, dedup_seconds: 1, out_dir: "work/w" }, env(cwd), bin)).error, /at most one/);
  });
});

test("convert: the format reaches editcap, pcapng to pcap names what is lost, and the counts agree", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const o = await original(cwd, "a.pcapng", stubCap("pcapng", SEVEN));
    const out = body(await tool(TRANSFORM, cwd, { operation: "convert", inputs: [o.path], format: "pcap", out_dir: "work/t" }, env(cwd), bin));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.derivatives[0].name, "converted.pcap");
    assert.match(out.derivatives[0].file_type, /pcap$/);
    assert.match(await readFile(join(cwd, "calls.txt"), "utf8"), /editcap -F pcap /);
    assert.match(out.notes.join(" "), /pcapng to pcap loses what the pcap format has no place for: Name Resolution Blocks/);
    assert.match(out.notes.join(" "), /does not read the input's blocks/);
    assert.equal(out.accounting.balanced, true);
  });
});

test("hexdump: the result is labelled synthetic, the text dump is no capture, and options that fabricate headers reach text2pcap", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const dump = await original(cwd, "dump.txt", "0000 de ad be ef\n0004 00 01\n\n0000 ff ff\n");
    const out = body(await tool(TRANSFORM, cwd, { operation: "hexdump", inputs: [dump.path], udp_ports: [53, 5353], out_dir: "work/t" }, env(cwd), bin));
    assert.equal(out.status, "complete", out.status_basis);
    const d = out.derivatives[0];
    assert.equal(d.synthetic, true);
    assert.match(d.label, /synthetic/);
    assert.match(d.label, /shows nothing about traffic that occurred/);
    assert.equal(out.accounting.packets_in, null);
    assert.match(out.accounting.dropped_by, /not applicable: a text dump is not a capture/);
    assert.match(out.notes.join(" "), /timestamps .* are synthetic/);
    assert.match(await readFile(join(cwd, "calls.txt"), "utf8"), /text2pcap -u 53,5353 .*dump\.txt .*text2pcap\.pcapng/);
    assert.equal(out.inputs[0].file_type, "text hex dump (not read as a capture)");
  });
});

test("an input capinfos cannot describe as a capture is refused before any program is run; a FIFO input is refused without waiting", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const text = await original(cwd, "notacapture.pcap", "this is not a capture\n");
    const err = refused(await tool(TRANSFORM, cwd, { operation: "split", inputs: [text.path], packets: 2, out_dir: "work/t" }, env(cwd), bin));
    assert.match(err.error, /capinfos could not describe every input as a capture, so nothing was run/);
    const calls = await readFile(join(cwd, "calls.txt"), "utf8");
    assert.doesNotMatch(calls, /^editcap -c/m, "no derivative of a file that is not read as a capture");
    assert.deepEqual(await leftovers(cwd, "work/t"), []);
    const fifo = spawnSync("mkfifo", [join(cwd, "inputs/fifo.pcap")]);
    assert.equal(fifo.status, 0);
    const t0 = Date.now();
    const f = refused(await tool(TRANSFORM, cwd, { operation: "split", inputs: ["inputs/fifo.pcap"], packets: 2, out_dir: "work/t" }, env(cwd), bin));
    assert.match(f.error, /not a regular file/);
    assert.ok(Date.now() - t0 < 20_000, "the FIFO was never waited on");
  });
});

test("a program that exits nonzero places nothing, keeps its diagnostic, and leaves no temporary directory; the accounting that does not add up makes the answer partial", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin, { fail: true });
    const o = await original(cwd, "a.pcap", stubCap("pcap", SEVEN));
    const err = refused(await tool(TRANSFORM, cwd, { operation: "split", inputs: [o.path], packets: 3, out_dir: "work/t" }, env(cwd), bin));
    assert.match(err.error, /editcap exited 2, so nothing was placed/);
    assert.match(err.diagnostics.lines.join(" "), /failed on request/);
    assert.deepEqual((await readdir(join(cwd, "work/t"))).filter((n) => !n.startsWith(".capture_transform-")), []);
    assert.deepEqual(await leftovers(cwd, "work/t"), []);
    await programs(cwd, bin, { lose: true });
    const lost = body(await tool(TRANSFORM, cwd, { operation: "split", inputs: [o.path], packets: 3, out_dir: "work/u" }, env(cwd), bin));
    assert.equal(lost.status, "partial");
    assert.equal(lost.accounting.balanced, false);
    assert.equal(lost.accounting.dropped, 1);
    assert.match(lost.status_basis, /the packets do not add up: 7 in, 6 out/);
    assert.equal(lost.derivatives_total, 2, "the derivatives are placed whole and the answer says the counts disagree");
  });
});

test("an output never replaces a file that is there: a second run takes -2, a different file keeps its name, a FIFO at the name is not waited on", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const o = await original(cwd, "a.pcap", stubCap("pcap", SEVEN));
    await put(cwd, "work/t/converted.pcap", "an earlier, different result\n");
    const first = body(await tool(TRANSFORM, cwd, { operation: "convert", inputs: [o.path], format: "pcap", out_dir: "work/t" }, env(cwd), bin));
    assert.equal(first.derivatives[0].path, "work/t/converted-2.pcap");
    assert.equal(await readFile(join(cwd, "work/t/converted.pcap"), "utf8"), "an earlier, different result\n");
    // the same bytes again are named again, not copied to -3
    const again = body(await tool(TRANSFORM, cwd, { operation: "convert", inputs: [o.path], format: "pcap", out_dir: "work/t" }, env(cwd), bin));
    assert.equal(again.derivatives[0].path, "work/t/converted-2.pcap");
    assert.deepEqual((await readdir(join(cwd, "work/t"))).filter((n) => n.startsWith("converted")).sort(), ["converted-2.pcap", "converted.pcap"]);
    // a FIFO planted at the name
    spawnSync("mkfifo", [join(cwd, "work/t/filtered.pcap")]);
    const t0 = Date.now();
    const f = body(await tool(TRANSFORM, cwd, { operation: "filter", inputs: [o.path], bpf_filter: "a", out_dir: "work/t" }, env(cwd), bin));
    assert.equal(f.derivatives[0].path, "work/t/filtered-2.pcap");
    assert.ok(Date.now() - t0 < 30_000);
  });
});

test("the answer pages: the first rows inline, the whole list in a file that holds as many rows as the answer counts, and a job keeps everything under $OUT", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const packets: Array<[number, string]> = Array.from({ length: 40 }, (_, i) => [i + 1, `p${i}`]);
    const o = await original(cwd, "a.pcap", stubCap("pcap", packets));
    const out = body(await asJob(TRANSFORM, cwd, { operation: "split", inputs: [o.path], packets: 1, limit: 5, out_dir: "out/parts" }, bin, env(cwd)));
    assert.equal(out.status, "complete", out.status_basis);
    assert.equal(out.derivatives_total, 40);
    assert.equal(out.derivatives.length, 5);
    assert.equal(out.truncated, true);
    const file = join(cwd, out.all_results.replace(/^store\/jobs\/[^/]+\/out\//, "out/"));
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n");
    assert.equal(rows.length, 40, "the file holds every row the answer counts");
    assert.equal(JSON.parse(rows[39]).name, "split-00040.pcap");
    assert.deepEqual(await leftovers(cwd, "out/parts"), []);
    assert.deepEqual((await readdir(join(cwd, "out/tool-output"))).filter((n) => n.startsWith(".")), [], "no hidden file of a page is left");
    // a second run with the same inputs does not replace the page file with another
    const again = body(await asJob(TRANSFORM, cwd, { operation: "split", inputs: [o.path], packets: 1, limit: 5, out_dir: "out/parts" }, bin, env(cwd)));
    assert.equal(again.derivatives_total, 40);
  });
});

test("a refused write of the page file (a file size limit) is this tool's failed answer: the placed derivatives are named, nothing is left hidden", async () => {
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const packets: Array<[number, string]> = Array.from({ length: 200 }, (_, i) => [i + 1, `payload-${i}`.padEnd(40, "x")]);
    const o = await original(cwd, "a.pcap", stubCap("pcap", packets));
    // RLIMIT_FSIZE of 8 KiB (dash counts 512-byte blocks): the 200 rows of the page are about 60 KB, so the write is refused (Python ignores SIGXFSZ: an OSError).
    const run = spawnSync("sh", ["-c", "ulimit -f 16 && exec python3 \"$0\"", TRANSFORM], {
      cwd, input: JSON.stringify({ operation: "split", inputs: [o.path], packets: 1, limit: 2, out_dir: "work/t" }), encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, AGENT_ID: "s1", ...env(cwd) },
    });
    assert.equal(run.status, 1, run.stderr + run.stdout.slice(0, 300));
    const out = JSON.parse(run.stdout);
    assert.equal(out.status, "failed");
    assert.match(out.error, /cannot be written to/);
    assert.ok(Array.isArray(out.derivatives_placed) && out.derivatives_placed.length > 0, "the derivatives placed so far are named");
    for (const p of out.derivatives_placed) assert.ok(await exists(join(cwd, p)), `${p} is a whole file on disk`);
    assert.deepEqual(await leftovers(cwd, "work/t"), []);
    assert.deepEqual((await readdir(join(cwd, "work/s1/tool-output")).catch(() => [])).filter((n) => n.startsWith(".")), [], "the hidden file of the page was removed");
  });
});

test("a full disk under out_dir (a small tmpfs) is the program's failure: nothing is placed, no temporary directory is left, and the answer does not blame the evidence", async (t) => {
  const probe = spawnSync("unshare", ["-rm", "true"]);
  if (probe.status !== 0) return t.skip("unshare -rm is not available on this host, so no tmpfs can be mounted");
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    const packets: Array<[number, string]> = Array.from({ length: 300 }, (_, i) => [i + 1, `payload-${i}`]);
    const o = await original(cwd, "a.pcap", stubCap("pcap", packets));
    await mkdir(join(cwd, "work/t"), { recursive: true });
    const run = spawnSync("unshare", ["-rm", "sh", "-c", `mount -t tmpfs -o size=64k tmpfs work/t && python3 "$0"; echo "EXIT $?"; ls -A work/t`, TRANSFORM], {
      cwd, input: JSON.stringify({ operation: "split", inputs: [o.path], packets: 1, out_dir: "work/t" }), encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, AGENT_ID: "s1", ...env(cwd) },
    });
    assert.equal(run.status, 0, run.stderr);
    const json = run.stdout.slice(0, run.stdout.lastIndexOf("EXIT"));
    const out = JSON.parse(json);
    assert.equal(out.status, "failed");
    assert.match(out.error, /editcap exited 2, so nothing was placed/);
    assert.doesNotMatch(out.error + out.status_basis, /evidence|capture is|packet is/i);
    assert.match(run.stdout, /EXIT 1\n$/, "nothing left in out_dir: the listing after EXIT 1 is empty");
  });
});

test("a stop signal gives one JSON answer with the stage, kills the program and what it started, removes the temporary directory and leaves no part under a final name", async () => {
  for (const [sig, code] of [["SIGTERM", 143], ["SIGINT", 130], ["SIGHUP", 129]] as const) {
    await withCwd(async (cwd, bin) => {
      const dir = await programs(cwd, bin, { sleep: true });
      const o = await original(cwd, "a.pcap", stubCap("pcap", SEVEN));
      const run = startDetached(TRANSFORM, cwd, { operation: "split", inputs: [o.path], packets: 3, out_dir: "work/t" }, env(cwd), bin);
      for (let i = 0; i < 1200 && !(await exists(join(dir, "started"))); i++) await new Promise((r) => setTimeout(r, 50));
      run.signal(sig);
      assert.equal(await run.closed, code, sig);
      const text = run.stdout();
      assert.equal(text.trim().split("\n").length, 1, "one document");
      const last = JSON.parse(text);
      assert.equal(last.status, "partial");
      assert.equal(last.interrupted_by_signal, code - 128);
      assert.equal(last.stage, "running editcap");
      assert.deepEqual(last.derivatives_placed, []);
      const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
      assert.equal(await gone(pid), true, `${sig}: what editcap started is gone`);
      assert.deepEqual(await readdir(join(cwd, "work/t")), [], "no temporary directory and no part is left");
    });
  }
});

test("a program that outlives the tool's own clock is killed with what it started and nothing is placed", async () => {
  await withCwd(async (cwd, bin) => {
    const dir = await programs(cwd, bin, { sleep: true });
    const o = await original(cwd, "a.pcap", stubCap("pcap", SEVEN));
    const t0 = Date.now();
    const err = refused(await tool(TRANSFORM, cwd, { operation: "split", inputs: [o.path], packets: 3, max_seconds: 10, out_dir: "work/t" }, env(cwd), bin));
    assert.ok(Date.now() - t0 < 25_000, `took ${Date.now() - t0} ms`);
    assert.match(err.error, /did not finish before the tool's own clock and was killed with everything it had started; nothing was placed/);
    const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
    assert.equal(await gone(pid), true);
    assert.deepEqual(await readdir(join(cwd, "work/t")), []);
  });
});

test("the manifest names the parameters the script reads, its example runs, its TOOL version is its version, and it declares secret output", async () => {
  const manifest: Json = JSON.parse(await readFile(join(TOOLS, "capture_transform", "manifest.json"), "utf8"));
  const script = await readFile(TRANSFORM, "utf8");
  assert.equal(manifest.sha256, sha(script));
  const tool_ = script.match(/^TOOL = \{"name": "([a-z_]+)", "version": (\d+)\}$/m)!;
  assert.deepEqual([tool_[1], Number(tool_[2])], ["capture_transform", manifest.version]);
  assert.match(script, /^PARSER = "capture_transform\/\d+"$/m);
  const read = new Set<string>();
  const allowed = script.match(/^ALLOWED = \(([\s\S]*?)\)$/m)![1];
  for (const m of allowed.matchAll(/"([a-z_]+)"/g)) read.add(m[1]);
  assert.deepEqual([...read].filter((p) => !(p in manifest.params)).sort(), []);
  assert.deepEqual(Object.keys(manifest.params).filter((p) => !read.has(p)).sort(), []);
  for (const key of Object.keys(JSON.parse(manifest.example))) assert.ok(key in manifest.params, `the example uses ${key}`);
  assert.deepEqual(manifest.requires, ["editcap", "mergecap", "tcpdump", "text2pcap", "capinfos"]);
  assert.equal(manifest.secret_output, "required");
  assert.match(manifest.description, /secret_output: "required"/);
  assert.match(manifest.description, /derivative, not evidence/);
  assert.ok(manifest.timeout_seconds > 1000);
  await withCwd(async (cwd, bin) => {
    await programs(cwd, bin);
    await put(cwd, "inputs/capture.pcap", stubCap("pcap", SEVEN));
    const given = JSON.parse(manifest.example.replaceAll("<your id>", "s1").replaceAll("work/s1/", "out/"));
    const result = await asJob(TRANSFORM, cwd, given, bin, env(cwd));
    const out = JSON.parse(result.stdout);
    assert.equal(out.error, undefined, out.error);
    assert.equal(out.status, "complete");
  });
});

// A gated run against the real programs: it runs when editcap, mergecap, tcpdump, text2pcap and capinfos are installed, and says so when they are not.
test("with the real Wireshark tools and tcpdump: split, merge, filter, dedup and convert of captures built from the pcap format agree with capinfos", async (t) => {
  const need = ["editcap", "mergecap", "tcpdump", "text2pcap", "capinfos"].filter((n) => spawnSync("sh", ["-c", `command -v ${n}`]).status !== 0);
  if (need.length) return t.skip(`not on this host: ${need.join(", ")}; the rebuilt-image proof is required`);
  await withCwd(async (cwd) => {
    const frame = (port: number, seq: number) => frameTcp4({ src: "10.0.0.5", dst: "203.0.113.7", sport: port, dport: 80, flags: TCP.ACK, seq, payload: `p${seq}` });
    const same = frame(50000, 1);
    await put(cwd, "inputs/a.pcap", pcapClassic([1, 2, 3, 4].map((n, i) => ({ sec: 1_700_000_000 + i, frame: n === 3 ? same : frame(50000 + (n % 2), n) })).concat([{ sec: 1_700_000_010, frame: same }])));
    const split = body(await tool(TRANSFORM, cwd, { operation: "split", inputs: ["inputs/a.pcap"], packets: 2, out_dir: "work/s" }));
    assert.equal(split.accounting.balanced, true);
    assert.equal(split.accounting.packets_in, 5);
    const merged = body(await tool(TRANSFORM, cwd, { operation: "merge", inputs: ["inputs/a.pcap", "inputs/a.pcap"], out_dir: "work/m" }));
    assert.equal(merged.accounting.packets_out, 10);
    const filtered = body(await tool(TRANSFORM, cwd, { operation: "filter", inputs: ["inputs/a.pcap"], bpf_filter: "tcp src port 50000", out_dir: "work/f" }));
    assert.equal(filtered.accounting.packets_in - filtered.accounting.packets_out, filtered.accounting.dropped);
    const dedup = body(await tool(TRANSFORM, cwd, { operation: "dedup", inputs: ["inputs/a.pcap"], dedup_window: 10, out_dir: "work/d" }));
    assert.ok(dedup.accounting.dropped >= 1, "the repeated frame within the window is removed");
    const converted = body(await tool(TRANSFORM, cwd, { operation: "convert", inputs: ["inputs/a.pcap"], format: "pcapng", out_dir: "work/c" }));
    assert.equal(converted.accounting.balanced, true);
  });
});
