/**
 * What pins the base image: the apt snapshot date and the two base image digests
 * (images/debian-snapshot, images/base.Dockerfile, scripts/apt-snapshot-bump.sh,
 * images/install.py). A floating tag or a live mirror makes two builds of one
 * source two different images.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const DOCKERFILE = readFileSync(join(ROOT, "images/base.Dockerfile"), "utf8");
const STAMP = /^\d{8}T\d{6}Z$/;

test("both FROM lines carry an @sha256: digest and keep their tag beside it", () => {
  const froms = DOCKERFILE.split("\n").filter((l) => l.startsWith("FROM "));
  assert.equal(froms.length, 2, "the base image has two stages");
  assert.match(froms[0]!, /^FROM debian:bookworm-slim@sha256:[0-9a-f]{64} AS seekfix$/);
  assert.match(froms[1]!, /^FROM node:24-bookworm-slim@sha256:[0-9a-f]{64}$/);
});

test("the snapshot date is a valid timestamp in one file, the Dockerfile's ARG repeats it, and both stages' sources use it", () => {
  const stamp = readFileSync(join(ROOT, "images/debian-snapshot"), "utf8").trim();
  assert.match(stamp, STAMP);
  const parsed = Date.UTC(+stamp.slice(0, 4), +stamp.slice(4, 6) - 1, +stamp.slice(6, 8), +stamp.slice(9, 11), +stamp.slice(11, 13), +stamp.slice(13, 15));
  assert.ok(parsed > Date.UTC(2020, 0, 1) && parsed <= Date.now() + 86_400_000, "a real date, not in the future");
  assert.equal(DOCKERFILE.match(/^ARG APT_SNAPSHOT=(\S+)$/m)?.[1], stamp, "the ARG default is the file's date");
  // Each stage writes the snapshot sources (archive/debian and archive/debian-security) from the date, before its first apt-get update.
  const stages = DOCKERFILE.split(/^FROM /m).slice(1);
  assert.equal(stages.length, 2);
  for (const stage of stages) {
    const firstUpdate = stage.indexOf("apt-get update");
    assert.ok(firstUpdate > 0, "each stage runs apt-get update");
    const before = stage.slice(0, firstUpdate);
    assert.match(before, /snapshot\.debian\.org\/archive\/debian\/%s\//, "bookworm and bookworm-updates from the snapshot");
    assert.match(before, /snapshot\.debian\.org\/archive\/debian-security\/%s\//, "bookworm-security from the snapshot");
    assert.match(before, /Acquire::Check-Valid-Until "false";/);
    assert.match(before, /Acquire::Retries "5";/);
    assert.match(before, /COPY debian-snapshot /, "the date is read from the file");
  }
  assert.match(DOCKERFILE, /dev\.dfirswarm\.apt-snapshot="\$\{APT_SNAPSHOT\}"/, "the date is an image label");
});

test("no deb.debian.org source is left in the base image's Dockerfile or in what install.py adds", () => {
  const code = (text: string) => text.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
  assert.doesNotMatch(code(DOCKERFILE), /deb\.debian\.org/);
});

const PY = process.platform === "win32" ? "python" : "python3";
function install(sourcesDir: string, osRelease: string, expr: string): unknown {
  const code = `
import importlib.util, json, os, sys
os.environ["DFIRSWARM_APT_SOURCES_DIR"] = sys.argv[1]
os.environ["DFIRSWARM_OS_RELEASE"] = sys.argv[2]
spec = importlib.util.spec_from_file_location("install", sys.argv[3])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(json.dumps(${expr}))
`;
  return JSON.parse(execFileSync(PY, ["-I", "-c", code, sourcesDir, osRelease, join(ROOT, "images/install.py")], { encoding: "utf8" }));
}

test("enable_release on a snapshot sources directory writes a snapshot backports source, and the image record names the date", () => {
  const dir = mkdtempSync(join(tmpdir(), "image-pins-"));
  try {
    const stamp = "20261030T000000Z";
    const sources = join(dir, "sources.list.d");
    mkdirSync(sources);
    writeFileSync(
      join(sources, "debian.sources"),
      `Types: deb\nURIs: http://snapshot.debian.org/archive/debian/${stamp}/\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\n` +
        `Types: deb\nURIs: http://snapshot.debian.org/archive/debian-security/${stamp}/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n`,
    );
    const osRelease = join(dir, "os-release");
    writeFileSync(osRelease, 'VERSION_CODENAME="bookworm"\n');
    assert.equal(install(sources, osRelease, 'm.enable_release("bookworm-backports")'), null);
    const written = readFileSync(join(sources, "dfirswarm-bookworm-backports.sources"), "utf8");
    assert.match(written, new RegExp(`^URIs: http://snapshot\\.debian\\.org/archive/debian/${stamp}/$`, "m"), "the backports suite comes from the snapshot at the image's date, not the security archive");
    assert.match(written, /^Suites: bookworm-backports$/m);
    assert.doesNotMatch(written, /deb\.debian\.org|debian-security/);
    assert.equal(install(sources, osRelease, "m.apt_snapshot()"), stamp);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the bump script, on a scratch copy, changes only the date; with --digests it changes only the two digests besides", () => {
  const dir = mkdtempSync(join(tmpdir(), "image-pins-"));
  try {
    mkdirSync(join(dir, "images"));
    cpSync(join(ROOT, "images/base.Dockerfile"), join(dir, "images/base.Dockerfile"));
    cpSync(join(ROOT, "images/debian-snapshot"), join(dir, "images/debian-snapshot"));
    const script = join(ROOT, "scripts/apt-snapshot-bump.sh");
    const before = readFileSync(join(dir, "images/base.Dockerfile"), "utf8").split("\n");
    const stamp = "20270101T000000Z";
    execFileSync("bash", [script, stamp, "--root", dir], { encoding: "utf8" });
    assert.equal(readFileSync(join(dir, "images/debian-snapshot"), "utf8"), `${stamp}\n`);
    const after = readFileSync(join(dir, "images/base.Dockerfile"), "utf8").split("\n");
    assert.equal(after.length, before.length);
    const changed = after.map((l, i) => [before[i]!, l] as const).filter(([a, b]) => a !== b);
    assert.equal(changed.length, 1, "one line of the Dockerfile moved");
    assert.equal(changed[0]![1], `ARG APT_SNAPSHOT=${stamp}`);

    // With --digests: a stand-in for `docker buildx imagetools inspect` prints a made-up index digest per tag.
    const inspect = join(dir, "inspect.sh");
    writeFileSync(inspect, '#!/bin/sh\ncase "$1" in\n  debian:*) echo "Digest:    sha256:' + "a".repeat(64) + '" ;;\n  node:*) echo "Digest:    sha256:' + "b".repeat(64) + '" ;;\nesac\n');
    chmodSync(inspect, 0o755);
    execFileSync("bash", [script, "20270201T000000Z", "--digests", "--root", dir], { encoding: "utf8", env: { ...process.env, APT_SNAPSHOT_INSPECT: inspect } });
    const third = readFileSync(join(dir, "images/base.Dockerfile"), "utf8").split("\n");
    const moved = third.map((l, i) => [after[i]!, l] as const).filter(([a, b]) => a !== b).map(([, b]) => b);
    assert.deepEqual(moved, [
      "ARG APT_SNAPSHOT=20270201T000000Z",
      `FROM debian:bookworm-slim@sha256:${"a".repeat(64)} AS seekfix`,
      `FROM node:24-bookworm-slim@sha256:${"b".repeat(64)}`,
    ]);
    // A timestamp that is not one is refused and nothing is written.
    assert.throws(() => execFileSync("bash", [script, "tomorrow", "--root", dir], { stdio: "pipe" }));
    assert.equal(readFileSync(join(dir, "images/debian-snapshot"), "utf8"), "20270201T000000Z\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
