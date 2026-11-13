/**
 * job_run's three forms: what a seat plainly meant is taken, and a mix is
 * refused with the form to send.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { jobRunShape } from "../extensions/agent-swarm.ts";

test("one form is taken as it is; a placeholder command beside a tool call is dropped", () => {
  assert.deepEqual(jobRunShape({ command: "ls inputs" }), { ok: true });
  assert.deepEqual(jobRunShape({ tool: "ad1_extract", args: { image: "x.ad1" } }), { ok: true });
  assert.deepEqual(jobRunShape({ tool: "file_type" }), { ok: true });
  assert.deepEqual(jobRunShape({ import: "work/a/x.bin" }), { ok: true });
  for (const command of ["true", ":", "", "echo run", "# tool job", "ad1_extract", "exit 0"]) {
    assert.deepEqual(jobRunShape({ command, tool: "ad1_extract", args: { image: "x.ad1" } }), command ? { ok: true, dropped: "command" } : { ok: true }, JSON.stringify(command));
  }
});

test("a mix is refused with the call to send (the five runs' 27 'one of them' refusals)", () => {
  const noTool = jobRunShape({ args: { image: "x.ad1", members: [3] } });
  assert.ok(!noTool.ok && /args with no tool: name the tool.*job_run\(tool: "<name>", args: \{\.\.\.\}\)/.test(noTool.reason));
  const cmdArgs = jobRunShape({ command: "python3 x.py", args: { a: 1 } });
  assert.ok(!cmdArgs.ok && /args are a tool's parameters, and this call names no tool/.test(cmdArgs.reason));
  const line = jobRunShape({ command: "ad1_extract --image inputs/x.ad1", tool: "ad1_extract" });
  assert.ok(!line.ok && /ad1_extract is a pack tool: it takes its parameters in args, not on a command line.*tools\(name: "ad1_extract"\)/.test(line.reason));
  const both = jobRunShape({ command: "python3 parse.py out", tool: "regkv", args: { hive: "x" } });
  assert.ok(!both.ok && /a job is one thing: either the tool regkv with its args, or the command/.test(both.reason));
  const withImport = jobRunShape({ command: "ls", import: "work/a/x" });
  assert.ok(!withImport.ok && /gives command and import/.test(withImport.reason));
  const nothing = jobRunShape({});
  assert.ok(!nothing.ok && /nothing to run: send exactly one of command/.test(nothing.reason));
});
