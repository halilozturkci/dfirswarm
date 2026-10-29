// A stand-in for Cursor's `cursor-agent -p --output-format stream-json`, for
// tests/cursor-provider.test.ts. Each run takes the next step of the plan in
// $FAKE_CURSOR_PLAN (a JSON array; the step count is kept beside it), logs what
// it was given to $FAKE_CURSOR_LOG (one JSON line per run), and answers in the
// shape the real CLI was seen to (2026.10.22): an init event, partial assistant
// events with timestamp_ms, the whole reply once more without it, a result.
import { spawn } from "node:child_process";
import { appendFileSync, closeSync, existsSync, openSync, readFileSync } from "node:fs";
import { join } from "node:path";

const plan = JSON.parse(readFileSync(process.env.FAKE_CURSOR_PLAN, "utf8"));
// Runs that start together each take a step of their own: step n is the first `<plan>.n.<n>` this run creates.
let n = 0;
for (;; n++) {
  try {
    closeSync(openSync(`${process.env.FAKE_CURSOR_PLAN}.n.${n}`, "wx"));
    break;
  } catch {
    // taken by an earlier run
  }
}
const step = plan[Math.min(n, plan.length - 1)];

let stdin = "";
for await (const chunk of process.stdin) stdin += chunk;
const perms = join(process.cwd(), ".cursor", "cli.json");
const log = { run: n, args: process.argv.slice(2), cwd: process.cwd(), stdin, permissions: existsSync(perms) ? JSON.parse(readFileSync(perms, "utf8")) : null, env: Object.keys(process.env).sort() };

if (step.linger) {
  // The real CLI leaves a child behind; this one is in the run's process group.
  const left = spawn("sleep", ["300"], { stdio: "ignore" });
  left.unref(); // the CLI itself exits; what it started does not
  log.linger_pid = left.pid;
}
appendFileSync(process.env.FAKE_CURSOR_LOG, `${JSON.stringify(log)}\n`);

if (step.holdStdout) {
  // A process outside the CLI's group that keeps its stdout open; the CLI exits without an answer.
  const holder = spawn("sleep", ["30"], { detached: true, stdio: ["ignore", "inherit", "ignore"] });
  holder.unref();
  appendFileSync(process.env.FAKE_CURSOR_LOG, `${JSON.stringify({ holder_pid: holder.pid })}\n`);
  process.exit(0);
}
if (step.notLoggedIn) {
  process.stderr.write("Error: Not logged in\n");
  process.exit(1);
}
const say = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
const sessionId = step.sessionId ?? `chat-${n}`;
say({ type: "system", subtype: "init", apiKeySource: "login", cwd: step.initCwd ?? process.cwd(), session_id: sessionId, model: "Fake", permissionMode: "default" });
if (step.hang) {
  setInterval(() => {}, 1000);
} else {
  if (step.ownTool || step.ownToolRan) {
    say({ type: "tool_call", subtype: "started", tool_call: { readToolCall: { args: { path: "/etc/hostname" } } }, session_id: sessionId });
    const result = step.ownToolRan ? { success: { content: "a host's file" } } : { error: { errorMessage: "Permission denied" } };
    say({ type: "tool_call", subtype: "completed", tool_call: { readToolCall: { result } }, session_id: sessionId });
  }
  const chunks = step.chunks ?? [step.reply ?? ""];
  for (const text of chunks) say({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text }] }, session_id: sessionId, timestamp_ms: Date.now() });
  if (step.failAfterText) process.exit(3);
  say({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text: step.reply ?? chunks.join("") }] }, session_id: sessionId });
  say({ type: "result", subtype: "success", is_error: false, session_id: sessionId, usage: step.usage ?? { inputTokens: 100, outputTokens: 7, cacheReadTokens: 50, cacheWriteTokens: 0 } });
}
