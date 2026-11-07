/**
 * PKG-P3 (the network-forensics pack in the process sweep). The shared PROCESS block ends what a program leaves behind (settle()); the network tools that run a
 * program and report files that program wrote call process_apply, so that a program that exits 0 and leaves a writer behind, or a host where the absence of one
 * cannot be proven, never answers `complete` over a file the program wrote. Stand-ins only, with real abandoned children:
 *   plain    a child in the tool's group that writes to the file by name a second after the program exited 0
 *   stdout   a child that holds the program's stdout (a file the tool keeps) and writes to it after the exit
 *   setsid   the same writer in a session of its own, with no descriptor open
 *   double   a double fork (the parent of the writer is gone at once)
 *   rewrite  a session of its own that truncates the file and writes it again
 *   periodic a session of its own that appends every 100 ms until it is killed
 * For every tool: the answer is `partial`, says what was ended (program_group.left_behind, a line under problems or errors), every leftover is gone, and
 * nothing under the working directory changed between the answer and 1.6 seconds later. A clean run is still `complete` (left_behind 0, nothing unproven).
 * Where the absence cannot be proven (the host is not Linux, or the kernel refuses PR_SET_CHILD_SUBREAPER: the tool is run with sys.platform patched, or with
 * ctypes.CDLL replaced by a library whose prctl fails) a clean run of a tool that reports a file a program wrote is `partial` and says why. The three tools that
 * report only what tshark printed on a pipe (the pipe cases are in their own test files) are not held to that.
 * The cases that fail on the batch head (before the tools called process_apply) are the ones that expect `partial` and program_group: the answer was `complete`.
 */
import assert from "node:assert/strict";
import { copyFile, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { FLOW, NET, RECIPE, SURICATA, TRANSFORM, ZEEK, EXTRACT, drop, frameTcp4, pcapClassic, put, stub, TCP, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";
import { ROOT } from "./tool-library-harness.ts";

import { VARIANTS, FEW, alive, exec, pids, reap, sh, sleep, snapshot, stubDir } from "./network-process-harness.ts";
import type { Host, Run } from "./network-process-harness.ts";
import { NO_ADOPTION } from "./host-gates.ts";

type Case = {
  name: string;
  /** Stage the stand-ins and run the tool; the printed answer (the first JSON document on stdout) and the files whose bytes the answer names. */
  invoke: (cwd: string, bin: string, left: string | undefined, host: Host) => Promise<{ answer: Json; run: Run }>;
  variants: string[];
  /** False for a tool that reports only what a program printed on a pipe. */
  holdsFiles: boolean;
  /** The status a run that is not clean may keep when the leftover is not what the tool reports (none: always partial). */
  recipe?: boolean;
};
const text = (a: Json): string => JSON.stringify([a.problems, a.errors, a.status_basis, a.program_group]);

async function expectLeft(c: Case, variant: string): Promise<void> {
  await withCwd(async (cwd, bin) => {
    try {
      const { answer } = await c.invoke(cwd, bin, variant, "linux");
      assert.equal(answer.status, "partial", `${c.name} ${variant}: ${answer.status_basis}`);
      if (!c.recipe && "ok" in answer) assert.equal(answer.ok, false, `${c.name} ${variant}`);
      assert.ok(answer.program_group, "the answer carries program_group");
      assert.ok(answer.program_group.left_behind >= 1, `${c.name} ${variant}: ${JSON.stringify(answer.program_group)}`);
      assert.equal(answer.program_group.subreaper, true);
      assert.match(text(answer), /left \d+ process\(es\) running after it ended/, `${c.name} ${variant}: the leftover is named under problems`);
      const left = await pids(cwd);
      assert.ok(left.length >= 1, `${c.name} ${variant}: the stand-in left a process`);
      for (const pid of left) assert.equal(alive(pid), false, `${c.name} ${variant}: leftover ${pid} is gone`);
      const now = await snapshot(cwd);
      await sleep(1600);
      assert.deepEqual(await snapshot(cwd), now, `${c.name} ${variant}: nothing changed after the answer`);
      for (const pid of left) assert.equal(alive(pid), false);
    } finally {
      await reap(cwd);
    }
  });
}

async function expectClean(c: Case): Promise<void> {
  await withCwd(async (cwd, bin) => {
    const { answer } = await c.invoke(cwd, bin, undefined, "linux");
    assert.equal(answer.status, "complete", `${c.name}: ${answer.status_basis}`);
    assert.ok(answer.program_group, "program_group is in a clean answer too");
    assert.equal(answer.program_group.left_behind, 0);
    assert.deepEqual(answer.program_group.unproven, []);
    assert.equal(answer.program_group.subreaper, true);
  });
}

async function expectUnproven(c: Case, host: Host): Promise<void> {
  await withCwd(async (cwd, bin) => {
    const { answer } = await c.invoke(cwd, bin, undefined, host);
    assert.ok(answer.program_group, `${c.name} ${host}: program_group`);
    assert.equal(answer.program_group.subreaper, false);
    assert.ok(answer.program_group.unproven.length >= 1, `${c.name} ${host}: ${JSON.stringify(answer.program_group)}`);
    if (c.holdsFiles) {
      assert.equal(answer.status, "partial", `${c.name} ${host}: ${answer.status_basis}`);
      assert.match(text(answer), /cannot be shown to be final/, `${c.name} ${host}: says why`);
      if (!c.recipe && "ok" in answer) assert.equal(answer.ok, false);
    } else {
      assert.equal(answer.status, "complete", `${c.name} ${host}: a tool that reports only what a program printed is not held: ${answer.status_basis}`);
    }
  });
}

function register(c: Case): void {
  // The first two need a host that adopts the orphans of a program; the darwin and refused cases below run everywhere, with the host patched.
  for (const variant of c.variants) test(`${c.name}: a ${variant} leftover is ended, the answer is partial and the files do not change after it`, { skip: NO_ADOPTION }, () => expectLeft(c, variant));
  test(`${c.name}: a clean run is complete, nothing left, nothing unproven`, { skip: NO_ADOPTION }, () => expectClean(c));
  for (const host of ["darwin", "refused"] as const) test(`${c.name}: where the absence of a leftover cannot be proven (${host}) a clean run is partial and says why`, () => expectUnproven(c, host));
}

// ---- zeek_run ---------------------------------------------------------------------------------------------------------------------------------------

const CONN = [
  "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tconn", "#open\t2023-11-14-22-13-20",
  "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto", "#types\ttime\tstring\taddr\tport\taddr\tport\tenum",
  "1700000000.123456\tCYWJAH2BG8ssSd3Mpk\t10.0.0.5\t50000\t203.0.113.7\t443\ttcp", "#close\t2023-11-14-22-14-00",
].join("\n") + "\n";

const ZEEK_STUB = sh(`case "$*" in *--version*) echo "zeek version 8.0.10-stand-in"; exit 0;; esac
cp "$STUB_DIR/conn.log" conn.log
leave "$PWD/conn.log"
exit 0
`);

const zeek: Case = {
  name: "zeek_run",
  variants: VARIANTS,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "zeek", ZEEK_STUB);
    await writeFile(join(dir, "conn.log"), CONN);
    await put(cwd, "work/c.pcap", Buffer.from("not read by the stand-in"));
    const run = await exec(ZEEK, [], { path: "work/c.pcap", out_dir: "work/z" }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
};
register(zeek);

const ZEEK_DRY_STUB = sh(`for a in "$@"; do
  case "$a" in
    --version) echo "zeek version 8.0.10-stand-in"; exit 0;;
    --help) echo "zeek version 8.0.10-stand-in" >&2; echo "usage: zeek [options] [file ...]" >&2; exit 0;;
  esac
done
printf 'network-forensics-dry-run\\t0\\t/opt/zeek/share/zeek/base/init-bare.zeek\\n'
leave "$PWD/zeek-dry-run.stdout"
exit 0
`);
register({
  name: "zeek_run dry_run",
  variants: FEW,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "zeek", ZEEK_DRY_STUB);
    const run = await exec(ZEEK, [], { dry_run: true, out_dir: "work/z", policies: [] }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
});

// ---- suricata_run -----------------------------------------------------------------------------------------------------------------------------------

const RULES = 'alert tcp any any -> any any (msg:"test one"; sid:1000001; rev:1;)\nalert udp any any -> any 53 (msg:"test two"; sid:1000002; rev:1;)\n';
const SURICATA_STUB = sh(`mode=run; logdir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --build-info) echo 'This is Suricata version 7.0.0-stand-in RELEASE'; exit 0;;
    -T) mode=test;;
    -l) logdir="$2"; shift;;
  esac
  shift
done
if [ "$mode" = test ]; then echo '<Info> - 2 rules successfully loaded, 0 rules failed' >&2; exit 0; fi
echo '{"timestamp":"2023-11-14T22:13:20.123456+0000","event_type":"flow","proto":"TCP"}' > "$logdir/eve.json"
leave "$logdir/eve.json"
exit 0
`);
register({
  name: "suricata_run",
  variants: VARIANTS,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "suricata", SURICATA_STUB);
    await put(cwd, "work/c.pcap", Buffer.from("not read by the stand-in"));
    await put(cwd, "work/case.rules", RULES);
    const run = await exec(SURICATA, [], { path: "work/c.pcap", rules: "work/case.rules", out_dir: "work/s" }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
});

const SURICATA_DRY_STUB = sh(`mode=run
for a in "$@"; do case "$a" in -r) exit 9;; esac; done
while [ $# -gt 0 ]; do
  case "$1" in
    --build-info) echo 'This is Suricata version 7.0.0-stand-in RELEASE'; exit 0;;
    --help) echo 'USAGE: suricata [OPTIONS]'; echo '  -T   test configuration file'; echo '  --dump-config   show the running configuration'; exit 0;;
    --dump-config) echo 'vars.address-groups.HOME_NET = [192.168.0.0/16]'; leave "/proc/$$/fd/1"; exit 0;;
    -T) mode=test;;
  esac
  shift
done
echo '<Info> - 2 rules successfully loaded, 0 rules failed, 0 rules skipped' >&2
exit 0
`);
register({
  name: "suricata_run dry_run",
  variants: ["stdout"],
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "suricata", SURICATA_DRY_STUB);
    await put(cwd, "work/case.rules", RULES);
    const run = await exec(SURICATA, [], { dry_run: true, rules: "work/case.rules", out_dir: "work/s" }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
});

// ---- capture_transform ------------------------------------------------------------------------------------------------------------------------------

const CAPINFOS_STUB = `#!/bin/sh
case "$1" in --version) echo 'Capinfos (Wireshark) 4.0.11-stand-in'; exit 0;; esac
for f in "$@"; do
  case "$f" in -*) continue;; esac
  head=$(head -n 1 "$f" 2>/dev/null)
  case "$head" in
    "#STUBCAP pcap") ;;
    *) echo "capinfos: not a capture" >&2; exit 2;;
  esac
  n=$(($(wc -l < "$f") - 1))
  printf 'File name:           %s\\nFile type:           Wireshark/tcpdump/... - pcap\\nFile encapsulation:  Ethernet\\nNumber of packets:   %s\\n\\n' "$f" "$n"
done
`;
const EDITCAP_STUB = sh(`case "$1" in --version) echo 'Editcap (Wireshark) 4.0.11-stand-in'; exit 0;; esac
for a in "$@"; do last="$a"; done
cp "$(echo "$@" | awk '{ print $(NF-1) }')" "$last"
leave "$last"
exit 0
`);
register({
  name: "capture_transform",
  variants: VARIANTS,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "capinfos", CAPINFOS_STUB);
    await stub(bin, "editcap", EDITCAP_STUB);
    await put(cwd, "inputs/a.pcap", "#STUBCAP pcap\n1 a\n2 b\n3 c\n");
    const run = await exec(TRANSFORM, [], { operation: "convert", inputs: ["inputs/a.pcap"], format: "pcap", out_dir: "work/t" }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
});

// ---- pcap_extract -----------------------------------------------------------------------------------------------------------------------------------

const EXTRACT_STUB = sh(`case " $* " in *" --version "*) echo 'TShark (Wireshark) 4.2.0 (stand-in)'; exit 0;; esac
spec=""
while [ $# -gt 0 ]; do
  case "$1" in --export-objects) spec="$2"; shift;; esac
  shift
done
if [ "$spec" = help ]; then printf 'tshark: The available export object types for the "--export-objects" option are:\\n    tftp\\n' >&2; exit 0; fi
dest=$(echo "$spec" | cut -d, -f2-)
head -c 300 /dev/zero | tr '\\0' 'B' > "$dest/boot.img"
leave "$dest/boot.img"
exit 0
`);
register({
  name: "pcap_extract",
  variants: VARIANTS,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "tshark", EXTRACT_STUB);
    const path = await drop(cwd, "work/c.pcap", pcapClassic([{ sec: 1, frame: frameTcp4({ src: "203.0.113.7", dst: "10.0.0.5", sport: 80, dport: 50000, flags: TCP.ACK }) }]));
    const run = await exec(EXTRACT, [], { path, out_dir: "work/x", protocols: ["tftp"] }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    const answer = JSON.parse(run.stdout);
    // the receipt on disk says the same as the answer
    const receipt = JSON.parse(await readFile(join(cwd, "work/x/receipt.json"), "utf8"));
    assert.equal(receipt.status, answer.status);
    return { answer, run };
  },
});

// ---- flow_reader ------------------------------------------------------------------------------------------------------------------------------------

const FIX = join(ROOT, "tests", "fixtures", "network-flow");
const NFDUMP_PY = `import json, os, sys
d = os.environ["STUB_DIR"]
rec = json.load(open(os.path.join(d, "recorded.json")))
args = sys.argv[1:]
def emit(r, name):
    sys.stdout.write(r["stdout"].replace("@FILE@", name)); sys.stdout.flush()
    sys.stderr.write(r["stderr"].replace("@FILE@", name)); sys.stderr.flush()
    sys.exit(r["exit"])
if args == ["-V"]:
    emit(rec["@version"], "")
if args[0] == "-v": kind, path = "v", args[1]
elif args[:2] == ["-I", "-r"]: kind, path = "I", args[2]
elif args[0] == "-E": kind, path = "E", args[1]
elif args[0] == "-r" and "-o" in args and args[args.index("-o") + 1] == "json": kind, path = "json", args[1]
else:
    sys.stderr.write("stand-in: not a call a reader makes: %r\\n" % args); sys.exit(99)
emit(rec[os.path.basename(path)][kind], path)
`;
const NFDUMP_STUB = sh(`python3 "$STUB_DIR/nfdump.py" "$@"
rc=$?
case "$*" in *"-o json"*) leave "$(readlink /proc/$$/fd/1)";; esac
exit $rc
`);
register({
  name: "flow_reader",
  variants: VARIANTS,
  holdsFiles: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await copyFile(join(FIX, "recorded.json"), join(dir, "recorded.json"));
    await writeFile(join(dir, "nfdump.py"), NFDUMP_PY);
    await stub(bin, "nfdump", NFDUMP_STUB);
    await copyFile(join(FIX, "nfcapd.v5"), join(cwd, "inputs", "nfcapd.v5"));
    const run = await exec(FLOW, [], { inputs: ["inputs/nfcapd.v5"], declared_format: "netflow_v5" }, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    return { answer: JSON.parse(run.stdout), run };
  },
});

// ---- the network-capture recipe -----------------------------------------------------------------------------------------------------------------------

const FIELD_NAMES = ["frame.number", "frame.time_epoch", "frame.cap_len", "frame.len", "_ws.col.protocol", "ip.src", "ipv6.src", "tcp.srcport", "udp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport",
  "dns.id", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.a", "dns.aaaa", "dns.resp.name", "dns.flags.rcode",
  "tcp.stream", "http.request.method", "http.host", "http.request.uri", "http.response.code", "http.content_length", "http.user_agent",
  "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ja3", "x509sat.uTF8String"];
const RECIPE_TSHARK = sh(`case "$1" in
  --version) echo 'TShark (Wireshark) 4.2.0 (stand-in)'; exit 0;;
  -G) cat "$STUB_DIR/fields.txt"; exit 0;;
esac
filter=packets
while [ $# -gt 0 ]; do
  case "$1" in -Y) filter="$2"; shift;; esac
  shift
done
printf '"frame.number"\\t"frame.time_epoch"\\n"1"\\t"1700000000.1"\\n'
case "$filter" in packets) leave "$(readlink /proc/$$/fd/1)";; esac
exit 0
`);
const RECIPE_CAPINFOS = `#!/bin/sh
case "$1" in --version) echo 'Capinfos (Wireshark) 4.2.0 (stand-in)'; exit 0;; esac
echo "File name: stand-in"
exit 0
`;
register({
  name: "network-capture recipe",
  variants: VARIANTS,
  holdsFiles: true,
  recipe: true,
  invoke: async (cwd, bin, left, host) => {
    const dir = await stubDir(cwd);
    await stub(bin, "tshark", RECIPE_TSHARK);
    await stub(bin, "capinfos", RECIPE_CAPINFOS);
    await writeFile(join(dir, "fields.txt"), FIELD_NAMES.map((n) => `F\tA field\t${n}\tFT_STRING\tproto\t0\t0x0\tdescription`).join("\n") + "\n");
    const path = await drop(cwd, "inputs/c.pcap", pcapClassic([{ sec: 1, frame: frameTcp4({ src: "10.0.0.5", dst: "203.0.113.7", sport: 50000, dport: 80, flags: TCP.SYN }) }]));
    const run = await exec(RECIPE, ["run", "--target", JSON.stringify({ paths: [path], name: path }), "--out", "work/cat"], undefined, cwd, bin, { STUB_DIR: dir, ...(left ? { STUB_LEFT: left } : {}) }, host);
    assert.equal(run.code, 0, run.stderr + run.stdout);
    const printed = JSON.parse(run.stdout);
    const coverage = JSON.parse(await readFile(join(cwd, "work/cat/coverage.json"), "utf8"));
    assert.equal(coverage.status, printed.status, "coverage.json and the printed answer agree");
    assert.deepEqual(coverage.program_group, printed.program_group);
    return { answer: { ...coverage, ok: printed.ok }, run };
  },
});

// ---- the tools that run no program ---------------------------------------------------------------------------------------------------------------------

test("pcap_summary, network_log_summary and beacon_score start no program: they carry no process block and are not held to the leftover rule", async () => {
  for (const tool of ["pcap_summary", "network_log_summary", "beacon_score"]) {
    const source = await readFile(join(NET, "tools", tool, "run.py"), "utf8");
    assert.doesNotMatch(source, /BEGIN SHARED PROCESS|subprocess|process_apply|spawn\(/, tool);
  }
});

test("the pipe tools (conn_series, quic_inspect, tls_decrypt) call process_verdict, not process_apply: a host that cannot prove the absence of a leftover does not make them partial", async () => {
  for (const tool of ["conn_series", "quic_inspect", "tls_decrypt"]) {
    const source = await readFile(join(NET, "tools", tool, "run.py"), "utf8");
    assert.match(source, /"program_group": process_verdict\(\)/, tool);
    assert.doesNotMatch(source, /^[ \t]+process_apply\(/m, tool);
  }
  for (const tool of ["zeek_run", "suricata_run", "capture_transform", "pcap_extract", "flow_reader"]) {
    const source = await readFile(join(NET, "tools", tool, "run.py"), "utf8");
    assert.match(source, /\n\s+process_apply\((answer|state|result)\)/, tool);
  }
  assert.match(await readFile(RECIPE, "utf8"), /\n\s+process_apply\(data\)/);
});

