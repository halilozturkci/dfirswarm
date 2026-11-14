/**
 * windows-forensics: a program that closes its output and goes on running does not hold the tool. yara_scan's own pipe reader and
 * registry_recover's count by regfexport waited for the program with no bound once its output had reached its end; a stand-in that closes
 * its standard output and sleeps held each of them past its clock (40 s and 30 s). The wait is now PIPE_GRACE seconds, the program is
 * then ended, and the answer is partial and says why.
 */
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { REGIPY, body, stub, tool } from "./windows-pack-harness.ts";
import { hive } from "./windows-hive.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

// Closes its standard output (and error) and keeps running, in the same process: the pipe reaches its end while the program is alive.
const CLOSE_AND_STAY = "exec >&- 2>&-\nexec sleep 60";

const YARA_PROBES = `case "$1" in\n  --version) echo 4.5.8; exit 0;;\n  --help) printf '%s\\n' '  -s,  --print-strings   print matching strings' '  -L,  --print-string-length   print length of matched strings' '  -N,  --no-follow-symlinks   do not follow symlinks'; exit 0;;\nesac\n`;

test("yara_scan: a yara that closes its output and keeps running is ended after the grace, and the answer is partial with the reason", async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "yara", `${YARA_PROBES}${CLOSE_AND_STAY}`);
    await writeFile(join(cwd, "work", "input.bin"), "stand-in input\n");
    await writeFile(join(cwd, "work", "rules.yar"), "rule r { condition: true }\n");
    const began = Date.now();
    const out = body<Answer>(await tool("yara_scan", cwd, { rules: "work/rules.yar", target: "work/input.bin", timeout_seconds: 40 }, {}, bin));
    const took = Date.now() - began;
    assert.ok(took < 20_000, `answered in ${took} ms: the wait after the end of the output is bounded, not the program's 60 s or the 40 s clock`);
    assert.equal(out.status, "partial");
    assert.equal(out.timed_out, false, "it was not the clock that ended it");
    assert.match(out.status_basis, /yara closed its output and was still running [0-9.]+ s later: it was ended/);
  });
});

test("registry_recover: a regfexport that closes its output and keeps running is ended after the grace, its counts are not compared, and the status is partial", { skip: REGIPY }, async () => {
  await withCwd(async (cwd, bin) => {
    await stub(bin, "regfexport", `printf 'Key path: x\\n'\n${CLOSE_AND_STAY}`);
    const data = hive({ name: "ROOT", children: [{ name: "Software", children: [{ name: "Run", values: [{ name: "App", type: "sz", value: "C:\\app.exe" }] }] }] });
    await writeFile(join(cwd, "work", "h.dat"), data);
    const began = Date.now();
    const out = body<Answer>(await tool("registry_recover", cwd, { hive: "work/h.dat", limit: 5, export: true, max_seconds: 60 }, {}, bin));
    const took = Date.now() - began;
    const reader = out.records.independent_reader.regfexport;
    assert.ok(took < 20_000, `answered in ${took} ms: the wait after the end of the output is bounded`);
    assert.equal(reader.ran, true);
    assert.equal(reader.finished, false);
    assert.equal(reader.agrees, undefined, "an unfinished count is not compared");
    assert.match(reader.why_not_finished, /closed its output and was still running [0-9.]+ s later: it was ended/);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /regfexport closed its output and was still running/);
  });
});
