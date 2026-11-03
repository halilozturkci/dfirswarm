/**
 * scripts/check-pins.ts: every URL a pack pins is still there, and a URL that
 * names no version still serves the pinned bytes. A local server plays the
 * upstreams: the right bytes, a 404, other bytes at the same address, a 503
 * that goes away, a 503 that does not, and a server that refuses HEAD.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const SCRIPT = join(ROOT, "scripts/check-pins.ts");
const sha = (b: string) => createHash("sha256").update(b).digest("hex");

const GOOD = "the bytes that were pinned";
const OTHER = "other bytes at the same address";

let server: Server;
let base = "";
let tmp = "";
const hits: Record<string, string[]> = {};
let flakyHeads = 0;

before(async () => {
  tmp = mkdtempSync(join(tmpdir(), "check-pins-"));
  server = createServer((req, res) => {
    const url = req.url ?? "";
    (hits[url] ??= []).push(req.method ?? "?");
    if (url === "/rel/tool-1.2.3.zip" || url === "/net/same.zip") {
      res.writeHead(200, { "content-length": String(GOOD.length) });
      res.end(req.method === "HEAD" ? undefined : GOOD);
    } else if (url === "/net/replaced.zip") {
      res.writeHead(200, { "content-length": String(OTHER.length) });
      res.end(req.method === "HEAD" ? undefined : OTHER);
    } else if (url === "/flaky/tool-2.0.deb") {
      if (flakyHeads++ < 1) {
        res.writeHead(503);
        res.end();
      } else {
        res.writeHead(200, { "content-length": "1" });
        res.end(req.method === "HEAD" ? undefined : "x");
      }
    } else if (url === "/big/symbols.zip") {
      // 70 MiB by its header; a fetch of it would hang the test, so none is made.
      res.writeHead(200, { "content-length": String(70 * 1024 * 1024) });
      if (req.method === "HEAD") res.end();
    } else if (url === "/down/tool-3.0.deb") {
      res.writeHead(503);
      res.end();
    } else if (url === "/nohead/tool-4.0.tgz") {
      if (req.method === "HEAD") {
        res.writeHead(405);
        res.end();
      } else {
        res.writeHead(206, { "content-range": "bytes 0-0/9", "content-length": "1" });
        res.end("x");
      }
    } else if (url === "/redir/tool-5.0.zip") {
      res.writeHead(302, { location: "/rel/tool-1.2.3.zip" });
      res.end();
    } else if (url === "/loop/tool-6.0.zip") {
      res.writeHead(302, { location: "/loop/tool-6.0.zip" });
      res.end();
    } else if (url === "/hang/tool-7.0.zip") {
      // Never answers: the socket stays open until the test ends.
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.closeAllConnections();
  server.close();
  rmSync(tmp, { recursive: true, force: true });
});

type Row = { name: string; version: string; path: string; bytes: string; size?: number };

/** A tree of one pack whose host.json pins each row as a download. */
function tree(name: string, rows: Row[]): string {
  const root = join(tmp, name);
  mkdirSync(join(root, "packs/p/requires"), { recursive: true });
  const binaries = rows.map((r) => ({
    name: r.name,
    optional: true,
    install: { download: { version: r.version, amd64: { url: `${base}${r.path}`, sha256: sha(r.bytes), ...(r.size ? { bytes: r.size } : {}) } } },
  }));
  writeFileSync(join(root, "packs/p/requires/host.json"), JSON.stringify({ binaries }));
  return root;
}

/** Async, so this process's server keeps answering while the script runs. */
function exec(args: string[]): Promise<{ code: number | null; out: string }> {
  return new Promise((done) => {
    execFile(process.execPath, ["--experimental-strip-types", SCRIPT, ...args], { encoding: "utf8", timeout: 60_000 }, (err, stdout, stderr) => {
      done({ code: err ? ((err as { code?: number }).code ?? 1) : 0, out: stdout + stderr });
    });
  });
}

function run(root: string, extra: string[] = []) {
  return exec(["--root", root, "--retries", "2", "--retry-delay", "1", ...extra]);
}

test("a pin that answers, with the pinned bytes where the URL names no version, passes", async () => {
  const root = tree("good", [
    { name: "tool", version: "1.2.3", path: "/rel/tool-1.2.3.zip", bytes: GOOD },
    { name: "same", version: "2026.10.2", path: "/net/same.zip", bytes: GOOD },
  ]);
  const { code, out } = await run(root);
  assert.equal(code, 0, out);
  assert.match(out, /^ok\s+p\/tool download amd64 \S+\/rel\/tool-1\.2\.3\.zip/m);
  assert.match(out, /^ok\s+p\/same download amd64 \S+\/net\/same\.zip same bytes/m);
  assert.match(out, /2 pins: 2 ok, 0 rotted, 0 changed, 0 in error, 0 unchecked/);
  // The versioned URL was asked with HEAD alone; the unversioned one was fetched.
  assert.deepEqual(hits["/rel/tool-1.2.3.zip"], ["HEAD"]);
  assert.deepEqual(hits["/net/same.zip"], ["HEAD", "GET"]);
});

test("a 404 is a rotted pin, named, and the run fails", async () => {
  const root = tree("gone", [{ name: "tool", version: "9.9", path: "/rel/tool-9.9.zip", bytes: GOOD }]);
  const { code, out } = await run(root);
  assert.equal(code, 1, out);
  assert.match(out, /^rotted\s+p\/tool download amd64 \S+\/rel\/tool-9\.9\.zip HTTP 404/m);
  assert.match(out, /Pins to look at[\s\S]*- p\/tool \(rotted\): \S+\/rel\/tool-9\.9\.zip/);
});

test("other bytes at an address that names no version are a changed pin; a HEAD alone would have passed it", async () => {
  const root = tree("changed", [{ name: "ez", version: "2026.10.2", path: "/net/replaced.zip", bytes: GOOD }]);
  const { code, out } = await run(root);
  assert.equal(code, 1, out);
  assert.match(out, new RegExp(`^changed\\s+p/ez download amd64 \\S+/net/replaced\\.zip sha256 is now ${sha(OTHER)}, pinned ${sha(GOOD)}`, "m"));
  // --head-only skips the fetch and says so: the pin is unchecked, not ok.
  const headOnly = await run(root, ["--head-only"]);
  assert.equal(headOnly.code, 0, headOnly.out);
  assert.match(headOnly.out, /^unchecked\s+p\/ez/m);
  assert.match(headOnly.out, /1 unchecked/);
});

test("a 503 that goes away is retried and passes; one that stays is an error after the retries", async () => {
  flakyHeads = 0;
  const ok = await run(tree("flaky", [{ name: "flaky", version: "2.0", path: "/flaky/tool-2.0.deb", bytes: GOOD }]));
  assert.equal(ok.code, 0, ok.out);
  assert.match(ok.out, /^ok\s+p\/flaky/m);
  assert.deepEqual(hits["/flaky/tool-2.0.deb"], ["HEAD", "HEAD"]);
  const down = await run(tree("down", [{ name: "down", version: "3.0", path: "/down/tool-3.0.deb", bytes: GOOD }]));
  assert.equal(down.code, 1, down.out);
  assert.match(down.out, /^error\s+p\/down .* HTTP 503/m);
  assert.equal(hits["/down/tool-3.0.deb"]!.length, 3, "one try and two retries");
});

test("a server that refuses HEAD is asked for the first byte instead", async () => {
  const { code, out } = await run(tree("nohead", [{ name: "nohead", version: "4.0", path: "/nohead/tool-4.0.tgz", bytes: GOOD }]));
  assert.equal(code, 0, out);
  assert.match(out, /^ok\s+p\/nohead/m);
});

test("an artefact too large to fetch is checked by the size it answers with", async () => {
  const mk = (size: number) => tree(`big${size}`, [{ name: "syms", version: "2019", path: "/big/symbols.zip", bytes: GOOD, size }]);
  const same = await run(mk(70 * 1024 * 1024));
  assert.equal(same.code, 0, same.out);
  assert.match(same.out, /^ok\s+p\/syms .*too large to fetch/m);
  const other = await run(mk(80 * 1024 * 1024));
  assert.equal(other.code, 1, other.out);
  assert.match(other.out, /^changed\s+p\/syms .*size is now 73400320, pinned 83886080/m);
  assert.ok(!hits["/big/symbols.zip"]!.includes("GET"), "the large file was fetched");
});

test("--list prints every pin and how it would be checked, and asks nothing", async () => {
  const root = tree("list", [
    { name: "tool", version: "1.2.3", path: "/rel/tool-1.2.3.zip", bytes: GOOD },
    { name: "ez", version: "2026.10.2", path: "/net/replaced.zip", bytes: GOOD },
  ]);
  const before = JSON.stringify(hits);
  const { out } = await exec(["--root", root, "--list"]);
  assert.match(out, /^head\s+p\/tool download amd64 /m);
  assert.match(out, /^fetch\s+p\/ez download amd64 /m);
  assert.match(out, /2 pins, 1 of them name no version and are fetched/);
  assert.equal(JSON.stringify(hits), before, "--list made a request");
});

test("the tree itself: every pinned URL of every pack is found, and the unversioned ones are the ones to fetch", async () => {
  const { out } = await exec(["--list"]);
  const pins = out.split("\n").filter((l) => /^(head|fetch)\s/.test(l));
  assert.ok(pins.length >= 30, `only ${pins.length} pins found`);
  assert.match(out, /^fetch\s+windows-forensics\/RECmd download amd64 \S+download\.ericzimmermanstools\.com\/net\/RECmd\.zip/m);
  assert.match(out, /^head\s+memory-forensics\/avml download amd64 \S+github\.com\/microsoft\/avml\/releases\/download\/v0\.20\.0\/avml/m);
});

test("a redirect is followed; a redirect loop is an error, not a hang", async () => {
  const ok = await run(tree("redir", [{ name: "r", version: "5.0", path: "/redir/tool-5.0.zip", bytes: GOOD }]));
  assert.equal(ok.code, 0, ok.out);
  assert.match(ok.out, /^ok\s+p\/r /m);
  const t0 = Date.now();
  const loop = await run(tree("loop", [{ name: "l", version: "6.0", path: "/loop/tool-6.0.zip", bytes: GOOD }]));
  assert.equal(loop.code, 1, loop.out);
  assert.match(loop.out, /^error\s+p\/l /m);
  assert.ok(Date.now() - t0 < 30_000, "the loop was not cut");
});

test("a host that never answers is cut by the run's deadline, whatever the per-request timeout", async () => {
  const root = tree("hang", [
    { name: "h", version: "7.0", path: "/hang/tool-7.0.zip", bytes: GOOD },
    { name: "tool", version: "1.2.3", path: "/rel/tool-1.2.3.zip", bytes: GOOD },
  ]);
  const t0 = Date.now();
  // A per-request timeout of 50 s and three tries would be 150 s without the deadline.
  const { code, out } = await run(root, ["--timeout", "50000", "--retries", "3", "--deadline", "1500"]);
  assert.equal(code, 1, out);
  assert.match(out, /^error\s+p\/h .*deadline/m);
  assert.match(out, /^ok\s+p\/tool /m, "a pin answered before the deadline is still reported");
  assert.match(out, /2 pins: 1 ok, 0 rotted, 0 changed, 1 in error/);
  assert.ok(Date.now() - t0 < 20_000, `took ${Date.now() - t0} ms`);
});

test("Dependabot watches the images' inputs, no entry merges itself, and the weekly workflow reports through the failure reporter", () => {
  const dep = readFileSync(join(ROOT, ".github/dependabot.yml"), "utf8");
  const entries = dep.split(/^ {2}- package-ecosystem: /m).slice(1).map((e) => ({ eco: e.split("\n")[0]!.trim(), dir: /directory: (\S+)/.exec(e)?.[1], interval: /interval: (\S+)/.exec(e)?.[1] }));
  const has = (eco: string, dir: string) => entries.some((e) => e.eco === eco && e.dir === dir && e.interval === "weekly");
  assert.ok(has("npm", "/") && has("github-actions", "/"), "the existing entries are kept");
  for (const [eco, dir] of [["docker", "/images"], ["docker", "/tests/linux"], ["pip", "/images"], ["npm", "/spikes/microvm-smoke"]] as const) assert.ok(has(eco, dir), `${eco} ${dir}`);
  assert.match(dep, /dependency-name: "microsandbox"/, "the microsandbox hold is kept");
  assert.doesNotMatch(dep, /auto-?merge/i);
  const wf = readFileSync(join(ROOT, ".github/workflows/pins.yml"), "utf8");
  assert.match(wf, /schedule:/);
  assert.match(wf, /workflow_dispatch:/);
  assert.match(wf, /report-failure:\s*\n(?:.*\n)*?\s+needs: \[check\]/);
  assert.match(wf, /if: always\(\) && github\.event_name == 'schedule'/);
  assert.match(wf, /issues: write/);
  assert.match(wf, /run: bash scripts\/ci-report-failure\.sh/);
  // The checking job itself keeps read-only rights.
  assert.match(wf, /^permissions:\s*\n\s+contents: read/m);
});
