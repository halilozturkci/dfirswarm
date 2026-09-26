/**
 * `playwright` tool: real headless Chromium behind the existing `--playwright`
 * kickoff flag. agent-swarm.ts keeps the registration name/activation; this
 * module owns the implementation so the two can evolve separately.
 *
 * Agents use it to verify what they built in a real browser. The signature:
 *
 *   playwright(target, actions?, screenshot?, text_selector?, note?)
 *     -> { ok, url, final_url, title, text, console_errors, page_errors,
 *          screenshot, actions_run }
 *
 * Safety defaults (product decisions):
 *   - `target` is a sandbox-relative file (served as file://) or a URL.
 *     Remote http(s) is refused unless SWARM_BROWSER_REMOTE=1; loopback is
 *     always allowed so a worker can check a dev server it started via bash.
 *   - Screenshots land in `work/<agent>/.browser/<ts>-<agent>.png`: the
 *     agent's writable microVM hole, with unique names and no claim needed.
 *   - A file target may load only sandbox files. Network requests are denied
 *     unless the target is a same-origin loopback page or remote access was
 *     explicitly enabled; downloads are rejected and reported.
 *   - `playwright` (npm) is a devDependency, imported lazily. Missing package
 *     or browser -> the tool throws an install hint; extension load is fine.
 *
 * Official Pi API used here (verified against @earendil-works/pi-coding-agent
 * 0.87.0, the pinned dependency): pi.registerTool({ name, label, description, promptSnippet,
 * promptGuidelines, parameters, execute(toolCallId, params, signal, onUpdate,
 * ctx) }) with ctx.cwd; throw from execute() to report an error to the LLM.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { spawn } from "node:child_process";
import { constants, realpathSync } from "node:fs";
import { mkdir, open, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Type } from "typebox";
import { claimKey, keepToolOutput, toolOutputRel, toolText, type FullOutputRef } from "./protocol.ts";

export type BrowserAction =
  | { type: "click"; selector: string }
  | { type: "fill"; selector: string; value: string }
  | { type: "press"; selector: string; value: string }
  | { type: "wait"; selector?: string; ms?: number }
  | { type: "goto"; value: string };

export type BrowserCheckOptions = {
  sandboxRoot: string;
  agentId: string;
  target: string;
  actions?: BrowserAction[];
  screenshot?: boolean;
  textSelector?: string;
  maxTextChars?: number;
  timeoutMs?: number;
  allowRemote?: boolean;
};

export type BrowserCheckResult = {
  ok: true;
  url: string;
  final_url: string;
  title: string;
  text: string;
  text_truncated: boolean;
  /** The whole page text under tool-output/ when `text` is a prefix of it. */
  full_text?: FullOutputRef;
  console_errors: string[];
  page_errors: string[];
  blocked_requests: string[];
  blocked_downloads: string[];
  screenshot: string | null;
  actions_run: number;
};

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1", "0.0.0.0"]);
const ACTION_TYPES = new Set(["click", "fill", "press", "wait", "goto"]);

function safeAgentId(agentId: string): string {
  return /^[a-z][a-z0-9_-]{0,31}$/.test(agentId) ? agentId : "unknown";
}

export function screenshotDir(agentId: string): string {
  return `work/${safeAgentId(agentId)}/.browser`;
}

type ScreenshotDirectory = { absolute: string; relative: string; root: string; agent: string };
const DIRECTORY_FLAGS = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;

async function openLinuxScreenshotDirectory(root: string, agent: string, create: boolean) {
  const handles: Awaited<ReturnType<typeof open>>[] = [];
  try {
    const rootHandle = await open(root, DIRECTORY_FLAGS);
    handles.push(rootHandle);
    const openChild = async (parent: Awaited<ReturnType<typeof open>>, name: string, mayCreate: boolean) => {
      const child = `/proc/self/fd/${parent.fd}/${name}`;
      if (mayCreate) {
        try {
          await mkdir(child, { mode: 0o700 });
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        }
      }
      const handle = await open(child, DIRECTORY_FLAGS);
      handles.push(handle);
      return handle;
    };
    const workHandle = await openChild(rootHandle, "work", false);
    const agentHandle = await openChild(workHandle, agent, create);
    const browserHandle = await openChild(agentHandle, ".browser", create);
    return {
      browserHandle,
      async closeParents() {
        for (const handle of handles.slice(0, -1).reverse()) await handle.close();
      },
    };
  } catch (err) {
    for (const handle of handles.reverse()) await handle.close().catch(() => undefined);
    throw err;
  }
}

const POSIX_SCREENSHOT_HELPER = String.raw`
import os, sys
mode, root, agent, filename = sys.argv[1:5]
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
fds = []
def child(parent, name, create):
    try:
        fd = os.open(name, flags, dir_fd=parent)
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(name, 0o700, dir_fd=parent)
        fd = os.open(name, flags, dir_fd=parent)
    fds.append(fd)
    return fd
try:
    root_fd = os.open(root, flags); fds.append(root_fd)
    work_fd = child(root_fd, "work", False)
    agent_fd = child(work_fd, agent, True)
    browser_fd = child(agent_fd, ".browser", True)
    if mode == "write":
        out = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=browser_fd)
        try:
            while True:
                block = os.read(0, 65536)
                if not block: break
                view = memoryview(block)
                while view:
                    view = view[os.write(out, view):]
        finally:
            os.close(out)
finally:
    for fd in reversed(fds): os.close(fd)
`;

async function runPosixScreenshotHelper(
  mode: "prepare" | "write",
  root: string,
  agent: string,
  filename = "",
  png?: Buffer,
): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn("python3", ["-c", POSIX_SCREENSHOT_HELPER, mode, root, agent, filename], {
      stdio: ["pipe", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`playwright: safe screenshot path helper failed (${code}): ${stderr.trim()}`));
    });
    child.stdin.end(png);
  });
}

export async function prepareScreenshotDirectory(
  sandboxRoot: string,
  agentId: string,
): Promise<ScreenshotDirectory> {
  const root = realpathSync(sandboxRoot);
  const agent = safeAgentId(agentId);
  const relative = screenshotDir(agentId);
  const absolute = resolve(root, relative);
  claimKey(root, absolute);
  try {
    if (process.platform === "linux") {
      const opened = await openLinuxScreenshotDirectory(root, agent, true);
      await opened.browserHandle.close();
      await opened.closeParents();
    } else {
      await runPosixScreenshotHelper("prepare", root, agent);
    }
  } catch (err) {
    throw new Error(`playwright: screenshot directory is not a plain sandbox path (${relative}): ${(err as Error).message}`);
  }
  return { absolute, relative, root, agent };
}

async function writeScreenshotFile(
  directory: ScreenshotDirectory,
  filename: string,
  png: Buffer,
): Promise<void> {
  if (process.platform !== "linux") {
    await runPosixScreenshotHelper("write", directory.root, directory.agent, filename, png);
    return;
  }
  const opened = await openLinuxScreenshotDirectory(directory.root, directory.agent, false);
  try {
    await writeFile(`/proc/self/fd/${opened.browserHandle.fd}/${filename}`, png, { flag: "wx" });
  } finally {
    await opened.browserHandle.close();
    await opened.closeParents();
  }
}

function sandboxFileUrl(sandboxRoot: string, rawPath: string): string {
  const root = realpathSync(sandboxRoot);
  const lexical = join(root, claimKey(root, rawPath));
  const real = realpathSync(lexical);
  return pathToFileURL(join(root, claimKey(root, real))).toString();
}

export function resolveTarget(sandboxRoot: string, target: string, allowRemote: boolean): string {
  const trimmed = target.trim();
  if (!trimmed) throw new Error("playwright: target is empty");
  if (/^https?:\/\//i.test(trimmed)) {
    const url = new URL(trimmed);
    if (!LOOPBACK.has(url.hostname.toLowerCase()) && !allowRemote) {
      throw new Error(
        `playwright: remote target refused (${url.hostname}). Set SWARM_BROWSER_REMOTE=1 to allow non-loopback http(s).`,
      );
    }
    return url.toString();
  }
  if (/^file:\/\//i.test(trimmed)) {
    return sandboxFileUrl(sandboxRoot, fileURLToPath(trimmed));
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) {
    throw new Error(`playwright: unsupported scheme in ${trimmed}`);
  }
  return sandboxFileUrl(sandboxRoot, trimmed);
}

export function parseActions(raw: unknown): BrowserAction[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) throw new Error("playwright: actions must be an array");
  return raw.map((item, index) => {
    if (!item || typeof item !== "object") throw new Error(`playwright: actions[${index}] is not an object`);
    const action = item as Record<string, unknown>;
    if (typeof action.type !== "string" || !ACTION_TYPES.has(action.type)) {
      throw new Error(`playwright: actions[${index}].type must be one of ${[...ACTION_TYPES].join(", ")}`);
    }
    const needString = (field: "selector" | "value", allowEmpty = false): string => {
      const value = action[field];
      if (typeof value !== "string" || (!allowEmpty && !value.trim())) {
        throw new Error(`playwright: actions[${index}].${field} must be ${allowEmpty ? "a string" : "a non-empty string"} for ${action.type}`);
      }
      return value;
    };
    switch (action.type) {
      case "click":
        return { type: "click", selector: needString("selector") };
      case "fill":
        return { type: "fill", selector: needString("selector"), value: needString("value", true) };
      case "press":
        return { type: "press", selector: needString("selector"), value: needString("value") };
      case "goto":
        return { type: "goto", value: needString("value") };
      case "wait": {
        const selector = action.selector;
        const ms = action.ms;
        if (selector !== undefined && (typeof selector !== "string" || !selector.trim())) {
          throw new Error(`playwright: actions[${index}].selector must be a non-empty string for wait`);
        }
        if (ms !== undefined && (typeof ms !== "number" || !Number.isFinite(ms) || ms < 0)) {
          throw new Error(`playwright: actions[${index}].ms must be a non-negative finite number for wait`);
        }
        if (selector === undefined && ms === undefined) {
          throw new Error(`playwright: actions[${index}] wait needs selector or ms`);
        }
        return { type: "wait", ...(selector !== undefined ? { selector } : {}), ...(ms !== undefined ? { ms } : {}) };
      }
      default:
        throw new Error(`playwright: unknown action ${JSON.stringify(action)}`);
    }
  });
}

function networkOrigin(url: URL): string | null {
  if (url.protocol === "http:" || url.protocol === "https:") return url.origin;
  if (url.protocol === "ws:") return `http://${url.host}`;
  if (url.protocol === "wss:") return `https://${url.host}`;
  return null;
}

/** Browser-wide request policy, including redirects and page-initiated loads. */
export function browserRequestAllowed(
  sandboxRoot: string,
  approvedTargets: ReadonlySet<string>,
  requestUrl: string,
  allowRemote: boolean,
): boolean {
  let requested: URL;
  try {
    requested = new URL(requestUrl);
  } catch {
    return false;
  }
  if (requested.protocol === "file:") {
    try {
      resolveTarget(sandboxRoot, requestUrl, false);
      return true;
    } catch {
      return false;
    }
  }
  if (["about:", "blob:", "data:", "chrome:", "chrome-extension:", "chrome-untrusted:"].includes(requested.protocol)) return true;
  const origin = networkOrigin(requested);
  if (!origin) return false;
  if (allowRemote) return true;
  if (!LOOPBACK.has(requested.hostname.toLowerCase())) return false;
  return [...approvedTargets].some((target) => {
    try {
      return networkOrigin(new URL(target)) === origin;
    } catch {
      return false;
    }
  });
}

type PlaywrightModule = typeof import("playwright");

async function loadPlaywright(): Promise<PlaywrightModule> {
  try {
    return (await import("playwright")) as PlaywrightModule;
  } catch (err) {
    throw new Error(
      `playwright: package not installed (${(err as Error).message}). Run: npm install && npx playwright install chromium`,
    );
  }
}

export async function runBrowserCheck(opts: BrowserCheckOptions): Promise<BrowserCheckResult> {
  const allowRemote = opts.allowRemote ?? process.env.SWARM_BROWSER_REMOTE === "1";
  const url = resolveTarget(opts.sandboxRoot, opts.target, allowRemote);
  const timeout = opts.timeoutMs ?? 15_000;
  const maxChars = opts.maxTextChars ?? 8_000;
  const pw = await loadPlaywright();

  const launchOptions: Record<string, unknown> = { headless: true };
  // Escape hatches for hosts without the Playwright browser download:
  if (process.env.BROWSER_CHECK_EXECUTABLE) launchOptions.executablePath = process.env.BROWSER_CHECK_EXECUTABLE;
  if (process.env.BROWSER_CHECK_CHANNEL) launchOptions.channel = process.env.BROWSER_CHECK_CHANNEL;

  const browser = await pw.chromium.launch(launchOptions);
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const blockedRequests: string[] = [];
  const blockedDownloads: string[] = [];
  const approvedTargets = new Set([url]);
  let actionsRun = 0;
  try {
    const context = await browser.newContext({ acceptDownloads: false, serviceWorkers: "block" });
    await context.route("**/*", async (route) => {
      const requestUrl = route.request().url();
      if (browserRequestAllowed(opts.sandboxRoot, approvedTargets, requestUrl, allowRemote)) {
        await route.continue();
      } else {
        blockedRequests.push(requestUrl);
        await route.abort("blockedbyclient");
      }
    });
    await context.routeWebSocket(/.*/, async (webSocket) => {
      const requestUrl = webSocket.url();
      if (browserRequestAllowed(opts.sandboxRoot, approvedTargets, requestUrl, allowRemote)) {
        webSocket.connectToServer();
      } else {
        blockedRequests.push(requestUrl);
        await webSocket.close({ code: 1008, reason: "Blocked by DFIR Swarm browser policy" });
      }
    });
    const page = await context.newPage();
    page.setDefaultTimeout(timeout);
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => pageErrors.push(err.message));
    page.on("download", (download) => {
      blockedDownloads.push(download.suggestedFilename());
      void download.cancel().catch(() => undefined);
    });

    await page.goto(url, { waitUntil: "load", timeout });

    for (const action of opts.actions ?? []) {
      switch (action.type) {
        case "click":
          await page.click(action.selector);
          break;
        case "fill":
          await page.fill(action.selector, action.value);
          break;
        case "press":
          await page.press(action.selector, action.value);
          break;
        case "wait":
          if (action.selector) await page.waitForSelector(action.selector);
          if (action.ms) await page.waitForTimeout(Math.min(action.ms, timeout));
          break;
        case "goto":
          {
            const next = resolveTarget(opts.sandboxRoot, action.value, allowRemote);
            approvedTargets.add(next);
            await page.goto(next, { waitUntil: "load", timeout });
          }
          break;
        default:
          throw new Error(`playwright: unknown action ${JSON.stringify(action)}`);
      }
      actionsRun += 1;
    }
    // Let navigation/download events caused by the last action reach their
    // handlers before the result is sealed.
    await page.waitForTimeout(50);

    const title = await page.title();
    const rawText = opts.textSelector
      ? await page.locator(opts.textSelector).first().innerText()
      : await page.locator("body").innerText();
    // The model receives the first `maxChars`; the whole text is kept under
    // tool-output/ and named, so nothing a page said is lost to the record.
    const truncated = rawText.length > maxChars;
    const fullText = truncated ? await keepToolOutput(opts.sandboxRoot, toolOutputRel(opts.agentId, "browser_check", "text"), rawText) : undefined;
    const text = truncated ? `${rawText.slice(0, maxChars)}\n\n[Showing the first ${maxChars} of ${rawText.length} characters. Full text: ${fullText?.path}]` : rawText;

    let screenshot: string | null = null;
    if (opts.screenshot) {
      const screenshotDirectory = await prepareScreenshotDirectory(opts.sandboxRoot, opts.agentId);
      const stamp = new Date().toISOString().replace(/[-:.]/g, "");
      const safeAgent = safeAgentId(opts.agentId);
      const filename = `${stamp}-${safeAgent}.png`;
      const rel = `${screenshotDirectory.relative}/${filename}`;
      const png = await page.screenshot({ fullPage: true });
      await writeScreenshotFile(screenshotDirectory, filename, png);
      screenshot = rel;
    }

    return {
      ok: true,
      url,
      final_url: page.url(),
      title,
      text,
      text_truncated: truncated,
      ...(fullText ? { full_text: fullText } : {}),
      console_errors: consoleErrors,
      page_errors: pageErrors,
      blocked_requests: blockedRequests,
      blocked_downloads: blockedDownloads,
      screenshot,
      actions_run: actionsRun,
    };
  } finally {
    await browser.close();
  }
}

const NON_BLANK_STRING = Type.String({ pattern: "\\S" });

export const PLAYWRIGHT_TOOL_PARAMS = Type.Object({
  target: Type.String({
    pattern: "\\S",
    description: "Sandbox-relative file (e.g. work/index.html) or a loopback URL such as http://127.0.0.1:4321/",
  }),
  actions: Type.Optional(
    Type.Array(
      Type.Union([
        Type.Object({ type: Type.Literal("click"), selector: NON_BLANK_STRING }),
        Type.Object({ type: Type.Literal("fill"), selector: NON_BLANK_STRING, value: Type.String() }),
        Type.Object({ type: Type.Literal("press"), selector: NON_BLANK_STRING, value: NON_BLANK_STRING }),
        Type.Object({ type: Type.Literal("wait"), selector: NON_BLANK_STRING, ms: Type.Optional(Type.Number({ minimum: 0 })) }),
        Type.Object({ type: Type.Literal("wait"), selector: Type.Optional(NON_BLANK_STRING), ms: Type.Number({ minimum: 0 }) }),
        Type.Object({ type: Type.Literal("goto"), value: NON_BLANK_STRING }),
      ]),
      { description: "Ordered actions to run after load" },
    ),
  ),
  screenshot: Type.Optional(Type.Boolean({ description: "Save a full-page PNG under work/<agent>/.browser/" })),
  text_selector: Type.Optional(Type.String({ description: "Return innerText of this selector instead of body" })),
  note: Type.Optional(Type.String({ description: "What you wanted to verify (logged only)" })),
});

type ToolCtx = { cwd: string };
type EventLogger = (
  cwd: string,
  agentId: string,
  tool: string,
  args: Record<string, unknown>,
  result: unknown,
) => Promise<void>;

/**
 * Register the `playwright` tool. `getAgentId` is a getter because
 * agent-swarm.ts resolves the id lazily on session_start.
 */
export function registerPlaywrightTool(
  pi: ExtensionAPI,
  deps: { getAgentId: () => string; logEvent: EventLogger },
): void {
  pi.registerTool({
    name: "playwright",
    label: "Playwright",
    description:
      "Headless Chromium check of a work/ HTML file or a loopback URL: optional actions (click, fill, press, wait, goto), then title, visible text, console/page errors, blocked requests/downloads and an optional screenshot path under the agent's work directory. Off unless --playwright was passed at kickoff. Remote traffic is refused unless the spawner sets SWARM_BROWSER_REMOTE=1.",
    promptSnippet: "Render a work/ HTML file or local dev server headlessly and read back text/errors",
    promptGuidelines: [
      "Use playwright to verify a rendered artifact (canvas, SVG, HTML) instead of guessing from source; read console_errors and page_errors before posting a result. Do not use it for the hello-file DoD.",
    ],
    parameters: PLAYWRIGHT_TOOL_PARAMS,
    async execute(_id, params, _signal, _onUpdate, toolCtx: ToolCtx) {
      const agent = deps.getAgentId() || "unknown";
      const logArgs = {
        target: params.target,
        actions: (params.actions ?? []).length,
        screenshot: params.screenshot ?? false,
        text_selector: params.text_selector,
        note: params.note,
      };
      try {
        const result = await runBrowserCheck({
          sandboxRoot: toolCtx.cwd,
          agentId: agent,
          target: params.target,
          actions: parseActions(params.actions),
          screenshot: params.screenshot ?? false,
          textSelector: params.text_selector,
        });
        await deps.logEvent(toolCtx.cwd, agent, "playwright", logArgs, {
          ok: true,
          title: result.title,
          errors: result.console_errors.length + result.page_errors.length,
          blocked_requests: result.blocked_requests.length,
          blocked_downloads: result.blocked_downloads.length,
          screenshot: result.screenshot,
          text_chars: result.text.length,
          ...(result.full_text ? { full_text: result.full_text } : {}),
        });
        return { content: [{ type: "text" as const, text: toolText(result) }], details: result };
      } catch (err) {
        await deps.logEvent(toolCtx.cwd, agent, "playwright", logArgs, {
          ok: false,
          error: (err as Error).message,
        });
        throw err;
      }
    },
  });
}
