// A stand-in for Cursor's `cursor-agent -p --output-format stream-json`, for
// tests/cursor-provider.test.ts. Each run takes the next step of the plan in
// $FAKE_CURSOR_PLAN (a JSON array; the step count is kept beside it), logs what
// it was given to $FAKE_CURSOR_LOG (one JSON line per run), and answers in the
// shape the real CLI was seen to (2026.10.22): an init event, partial assistant
// events with timestamp_ms, the whole reply once more without it, a result.
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const plan = JSON.parse(readFileSync(process.env.FAKE_CURSOR_PLAN, "utf8"));
const countFile = `${process.env.FAKE_CURSOR_PLAN}.n`;
const n = existsSync(countFile) ? Number(readFileSync(countFile, "utf8")) : 0;
writeFileSync(countFile, String(n + 1));
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
  if (step.ownTool) {
    say({ type: "tool_call", subtype: "started", tool_call: { readToolCall: { args: { path: "/etc/hostname" } } }, session_id: sessionId });
    say({ type: "tool_call", subtype: "completed", tool_call: { readToolCall: { result: { error: { errorMessage: "Permission denied" } } } }, session_id: sessionId });
  }
  const chunks = step.chunks ?? [step.reply ?? ""];
  for (const text of chunks) say({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text }] }, session_id: sessionId, timestamp_ms: Date.now() });
  say({ type: "assistant", message: { role: "assistant", content: [{ type: "text", text: step.reply ?? chunks.join("") }] }, session_id: sessionId });
  say({ type: "result", subtype: "success", is_error: false, session_id: sessionId, usage: step.usage ?? { inputTokens: 100, outputTokens: 7, cacheReadTokens: 50, cacheWriteTokens: 0 } });
}
