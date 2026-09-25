/**
 * The fence a job's worker must pass before its output is read: destroyWorker
 * says a worker is gone only when msb's inspect does not know the name AND
 * msb's list does not show it. On Ali Hadi #10 a worker whose boot had failed
 * was "not found" to inspect while its sandbox row was still to appear, and
 * the journal recorded a fence that was not one. A list msb prints that is not
 * understood is no answer, and the process making the worker (an orphan of a
 * hub that died included) is stopped first. A stand-in msb (SWARM_MSB_BIN)
 * plays each case.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { destroyWorker, listedNames, stopMaker } from "../scripts/vm.ts";

// state: one name per line in $D/vms; $D/mode picks the behaviour.
const STANDIN = `#!/bin/bash
D="$(dirname "$0")"
mode="$(cat "$D/mode")"
echo "$*" >> "$D/calls"
case "$1" in
  stop) exit 0 ;;
  rm)
    n=$(( $(cat "$D/rm-count" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$D/rm-count"
    # late: the row stays through the first rm, then goes
    if [[ "$mode" == stuck || ( "$mode" == late && "$n" -lt 2 ) ]]; then echo "removed $2"; exit 0; fi
    grep -vx -- "$2" "$D/vms" > "$D/vms.new"; mv "$D/vms.new" "$D/vms"; echo "removed $2"; exit 0 ;;
  inspect)
    if [[ "$mode" == locked ]]; then echo "error: database is locked" >&2; exit 1; fi
    # stuck and late: inspect does not know the name whatever the list says
    if [[ "$mode" == stuck || "$mode" == late || "$mode" == garbled ]] || ! grep -qx -- "$2" "$D/vms"; then echo "error: sandbox not found" >&2; exit 1; fi
    echo '{"name":"'"$2"'"}'; exit 0 ;;
  list)
    if [[ "$mode" == garbled ]]; then echo '{"oops": 1}'; exit 0; fi
    printf '['; sep=""; while read -r v; do [[ -n "$v" ]] && { printf '%s{"name":"%s","status":"Stopped"}' "$sep" "$v"; sep=","; }; done < "$D/vms"; printf ']\\n'; exit 0 ;;
esac
exit 2
`;

function standIn(mode: string, vms: string[]): string {
  const D = mkdtempSync(join(tmpdir(), "msb-fence-"));
  writeFileSync(join(D, "msb"), STANDIN);
  chmodSync(join(D, "msb"), 0o755);
  writeFileSync(join(D, "mode"), mode);
  writeFileSync(join(D, "vms"), vms.map((v) => `${v}\n`).join(""));
  process.env.SWARM_MSB_BIN = join(D, "msb");
  return D;
}

const NAME = "dfs-s000000-job-j000001-1";

test("a worker msb neither inspects nor lists is gone", async () => {
  standIn("normal", [NAME, "dfs-s000000-s00000000"]);
  assert.deepEqual(await destroyWorker(NAME), { ok: true });
});

test("inspect saying 'not found' while the list still shows the worker is not a fence", async () => {
  const D = standIn("stuck", [NAME]);
  const r = await destroyWorker(NAME);
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /msb lists .* although it says it does not know it/);
  assert.equal(readFileSync(join(D, "calls"), "utf8").split("\n").filter((l) => l.startsWith("rm ")).length, 3, "three attempts at removing it");
});

test("a row that goes on the second attempt is fenced then", async () => {
  standIn("late", [NAME]);
  assert.deepEqual(await destroyWorker(NAME), { ok: true });
});

test("msb that cannot answer is not a fence", async () => {
  standIn("locked", [NAME]);
  const r = await destroyWorker(NAME);
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /could not say whether .* is gone: error: database is locked/);
});

test("a list that is not a list of named VMs is no answer", async () => {
  standIn("garbled", [NAME]);
  const r = await destroyWorker(NAME);
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /msb's list \(\d+ bytes\) was not a list of VMs/);
  assert.deepEqual(listedNames('[{"name":"a"},{"name":"b","status":"Stopped"}]'), ["a", "b"]);
  assert.deepEqual(listedNames('{"sandboxes":[{"name":"a"}]}'), ["a"]);
  assert.deepEqual(listedNames("[]"), []);
  for (const bad of ["", "not json", "{}", '[{"id":1}]', '[{"name":7}]', "[null]", '{"sandboxes":{}}']) assert.equal(listedNames(bad), null, bad);
});

test("the process making a worker is stopped before msb is asked, found by the worker's name", async () => {
  standIn("normal", [NAME]);
  const other = "dfs-s000000-job-j000002-1";
  const maker = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", "worker-once", "--name", NAME], { stdio: "ignore" });
  const bystander = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", "worker-once", "--name", other], { stdio: "ignore" });
  const exited = new Promise((r) => maker.on("exit", r));
  try {
    await new Promise((r) => setTimeout(r, 300));
    assert.deepEqual(await destroyWorker(NAME), { ok: true });
    await exited;
    assert.equal(maker.signalCode, "SIGKILL");
    assert.equal(bystander.exitCode, null, "another worker's maker is left alone");
    assert.equal(bystander.signalCode, null);
    assert.deepEqual(await stopMaker(NAME), { ok: true }, "none left");
  } finally {
    bystander.kill("SIGKILL");
    maker.kill("SIGKILL");
  }
});
