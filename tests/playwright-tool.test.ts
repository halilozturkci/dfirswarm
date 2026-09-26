/**
 * `playwright` tool fixture. No LLM. Needs `npm install` (playwright
 * devDependency) and `npx playwright install chromium`; the browser test
 * skips with a reason when either is missing so the rest of the suite runs.
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Value } from "typebox/value";
import {
  browserRequestAllowed,
  parseActions,
  PLAYWRIGHT_TOOL_PARAMS,
  prepareScreenshotDirectory,
  registerPlaywrightTool,
  resolveTarget,
  runBrowserCheck,
  screenshotDir,
} from "../extensions/playwright-tool.ts";
import { appendEvent, EVENTS_REL, initSandbox } from "../extensions/protocol.ts";

const FIXTURE_HTML = `<!doctype html>
<html><head><title>Slice 2 fixture</title></head>
<body>
  <h1 id="headline">Pelican pending</h1>
  <button id="go" onclick="document.getElementById('headline').textContent='Pelican rendered'">Render</button>
  <a id="download" download="probe.txt" href="data:text/plain,download-probe">Download</a>
  <input id="name" />
  <script>console.error("fixture console error");</script>
</body></html>
`;

const NETWORK_FIXTURE_HTML = `<!doctype html>
<html><head><title>Network policy fixture</title></head>
<body><h1>Offline</h1><script>
fetch("https://example.com/browser-policy-probe").catch(() => {});
const socket = new WebSocket("wss://example.com/browser-policy-socket");
socket.onerror = () => {};
</script></body></html>`;

async function browserAvailable(): Promise<string | null> {
  try {
    const pw = await import("playwright");
    const launchOptions: { headless: true; executablePath?: string; channel?: string } = {
      headless: true,
    };
    if (process.env.BROWSER_CHECK_EXECUTABLE) {
      launchOptions.executablePath = process.env.BROWSER_CHECK_EXECUTABLE;
    } else if (process.env.BROWSER_CHECK_CHANNEL) {
      launchOptions.channel = process.env.BROWSER_CHECK_CHANNEL;
    }
    const browser = await pw.chromium.launch(launchOptions);
    await browser.close();
    return null;
  } catch (err) {
    return (err as Error).message.split("\n")[0];
  }
}

test("resolveTarget: sandbox files become file://, remote http is refused by default", async () => {
  const root = await mkdtemp(join(tmpdir(), "slice2-target-"));
  const outside = await mkdtemp(join(tmpdir(), "slice2-outside-"));
  try {
    await initSandbox(root, { reset: true });
    await writeFile(join(root, "work", "index.html"), FIXTURE_HTML, "utf8");
    assert.match(resolveTarget(root, "work/index.html", false), /^file:\/\/.*\/work\/index\.html$/);
    assert.equal(resolveTarget(root, "http://localhost:4321/", false), "http://localhost:4321/");
    assert.equal(resolveTarget(root, "http://127.0.0.1:4321/x", false), "http://127.0.0.1:4321/x");
    assert.throws(() => resolveTarget(root, "https://example.com/", false), /remote target refused/);
    assert.equal(resolveTarget(root, "https://example.com/", true), "https://example.com/");
    assert.throws(() => resolveTarget(root, "../etc/passwd", false), /escapes sandbox/);
    assert.throws(() => resolveTarget(root, "ftp://host/x", false), /unsupported scheme/);
    assert.throws(() => resolveTarget(root, "   ", false), /target is empty/);
    assert.deepEqual(parseActions(undefined), []);
    assert.throws(() => parseActions([{ type: "eval" }]), /type must be one of/);
    assert.throws(() => parseActions([{ type: "click" }]), /selector must be a non-empty string/);
    assert.throws(() => parseActions([{ type: "goto", value: "" }]), /value must be a non-empty string/);
    assert.throws(() => parseActions([{ type: "wait" }]), /wait needs selector or ms/);
    assert.throws(() => parseActions([{ type: "wait", ms: -1 }]), /non-negative finite number/);
    assert.deepEqual(parseActions([{ type: "fill", selector: "#name", value: "" }]), [{ type: "fill", selector: "#name", value: "" }]);
    assert.equal(Value.Check(PLAYWRIGHT_TOOL_PARAMS, { target: "work/index.html", actions: [{ type: "fill", selector: "#name", value: "" }] }), true);
    assert.equal(Value.Check(PLAYWRIGHT_TOOL_PARAMS, { target: "   " }), false);
    assert.equal(Value.Check(PLAYWRIGHT_TOOL_PARAMS, { target: "work/index.html", actions: [{ type: "click", selector: "   " }] }), false);
    assert.equal(Value.Check(PLAYWRIGHT_TOOL_PARAMS, { target: "work/index.html", actions: [{ type: "wait", ms: Number.POSITIVE_INFINITY }] }), false);

    await symlink("/etc/passwd", join(root, "work", "outside"));
    assert.throws(() => resolveTarget(root, "work/outside", false), /escapes sandbox/);

    const fileTarget = resolveTarget(root, "work/index.html", false);
    assert.equal(browserRequestAllowed(root, new Set([fileTarget]), "https://example.com/x", false), false);
    assert.equal(browserRequestAllowed(root, new Set([fileTarget]), "http://127.0.0.1:4321/x", false), false);
    assert.equal(browserRequestAllowed(root, new Set([fileTarget]), fileTarget, false), true);
    const localTarget = resolveTarget(root, "http://127.0.0.1:4321/", false);
    assert.equal(browserRequestAllowed(root, new Set([localTarget]), "http://127.0.0.1:4321/app.js", false), true);
    assert.equal(browserRequestAllowed(root, new Set([localTarget]), "ws://127.0.0.1:4321/socket", false), true);
    assert.equal(browserRequestAllowed(root, new Set([localTarget]), "http://127.0.0.1:9999/x", false), false);
    assert.equal(browserRequestAllowed(root, new Set([fileTarget]), "https://example.com/x", true), true);
    assert.equal(browserRequestAllowed(root, new Set([fileTarget]), "chrome://resources/a.css", false), true);

    await mkdir(join(root, "work", "agent00"), { recursive: true });
    await symlink("/tmp", join(root, "work", "agent00", ".browser"));
    await assert.rejects(
      () => prepareScreenshotDirectory(root, "agent00"),
      /screenshot directory is not a plain sandbox path/,
    );
    await symlink(outside, join(root, "work", "agent01"));
    await assert.rejects(
      () => prepareScreenshotDirectory(root, "agent01"),
      /screenshot directory is not a plain sandbox path/,
    );
    await assert.rejects(() => stat(join(outside, ".browser")), /ENOENT/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("playwright tool: renders a work/ page, runs actions, captures errors and a screenshot", async (t) => {
  const unavailable = await browserAvailable();
  if (unavailable) {
    // A job that installed the browser (CI's Linux job) says so, and there a
    // missing browser is a failure, not a quiet skip.
    if (process.env.SWARM_REQUIRE_BROWSER === "1") assert.fail(`SWARM_REQUIRE_BROWSER=1 but playwright/chromium is unavailable: ${unavailable}`);
    t.skip(`playwright/chromium unavailable: ${unavailable}`);
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "slice2-browser-"));
  try {
    await initSandbox(root, { reset: true });
    await writeFile(join(root, "work", "index.html"), FIXTURE_HTML, "utf8");
    await writeFile(join(root, "work", "network.html"), NETWORK_FIXTURE_HTML, "utf8");

    const before = await runBrowserCheck({
      sandboxRoot: root,
      agentId: "agent00",
      target: "work/index.html",
      textSelector: "#headline",
    });
    assert.equal(before.title, "Slice 2 fixture");
    assert.equal(before.text, "Pelican pending");
    assert.deepEqual(before.console_errors, ["fixture console error"]);
    assert.equal(before.screenshot, null);

    const after = await runBrowserCheck({
      sandboxRoot: root,
      agentId: "agent00",
      target: "work/index.html",
      actions: [
        { type: "fill", selector: "#name", value: "scout" },
        { type: "click", selector: "#go" },
        { type: "click", selector: "#download" },
        { type: "wait", selector: "#headline" },
      ],
      screenshot: true,
    });
    assert.equal(after.actions_run, 4);
    assert.match(after.text, /Pelican rendered/);
    assert.deepEqual(after.blocked_downloads, ["probe.txt"]);
    assert.ok(after.screenshot?.startsWith(`${screenshotDir("agent00")}/`), "screenshot lives under the agent's work directory");
    assert.match(after.screenshot ?? "", /-agent00\.png$/);
    const shot = await stat(join(root, after.screenshot!));
    assert.ok(shot.size > 0);

    const network = await runBrowserCheck({
      sandboxRoot: root,
      agentId: "agent00",
      target: "work/network.html",
      actions: [{ type: "wait", ms: 100 }],
    });
    assert.ok(network.blocked_requests.includes("https://example.com/browser-policy-probe"));
    assert.ok(network.blocked_requests.includes("wss://example.com/browser-policy-socket"));

    await assert.rejects(
      () => runBrowserCheck({ sandboxRoot: root, agentId: "agent00", target: "https://example.com/" }),
      /remote target refused/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("registerPlaywrightTool: registers `playwright`, logs ok/error events in the harness schema", async (t) => {
  const unavailable = await browserAvailable();
  const root = await mkdtemp(join(tmpdir(), "slice2-register-"));
  try {
    await initSandbox(root, { reset: true });
    await writeFile(join(root, "work", "index.html"), FIXTURE_HTML, "utf8");

    const registered: Array<Record<string, any>> = [];
    const fakePi = { registerTool: (def: Record<string, unknown>) => registered.push(def), on: () => {} };
    registerPlaywrightTool(fakePi as never, {
      getAgentId: () => "agent01",
      logEvent: async (cwd, agent, tool, args, result) => {
        await appendEvent(cwd, { agent, tool, args, result });
      },
    });
    assert.equal(registered.length, 1);
    const tool = registered[0];
    assert.equal(tool.name, "playwright");
    assert.equal(tool.label, "Playwright");

    const ctx = { cwd: root };
    await assert.rejects(
      () => tool.execute("t1", { target: "https://example.com/" }, undefined, undefined, ctx),
      /remote target refused/,
    );
    if (!unavailable) {
      const result = await tool.execute("t2", { target: "work/index.html", screenshot: true, note: "fixture" }, undefined, undefined, ctx);
      assert.equal(result.details.title, "Slice 2 fixture");
      assert.match(result.details.screenshot, /^work\/agent01\/\.browser\/.*-agent01\.png$/);
    } else {
      if (process.env.SWARM_REQUIRE_BROWSER === "1") assert.fail(`SWARM_REQUIRE_BROWSER=1 but playwright/chromium is unavailable: ${unavailable}`);
      t.diagnostic(`browser step skipped: ${unavailable}`);
    }

    const events = (await readFile(join(root, EVENTS_REL), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.ok(events.length >= 1);
    for (const event of events) {
      // sid and seq: the sending process and its count (custody reads them).
      assert.deepEqual(Object.keys(event).sort(), ["agent", "args", "result", "seq", "sid", "tool", "ts"]);
      assert.equal(event.tool, "playwright");
      assert.equal(event.agent, "agent01");
    }
    assert.equal(events[0].result.ok, false);
    assert.match(events[0].result.error, /remote target refused/);
    if (!unavailable) {
      assert.equal(events[1].result.ok, true);
      assert.equal(events[1].args.note, "fixture");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
