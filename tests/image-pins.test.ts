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

// --- Pi: one version, a fixed undici ---------------------------------------------------------------------

const PACKAGE = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { devDependencies: Record<string, string> };
const PI_PINNED = PACKAGE.devDependencies["@earendil-works/pi-coding-agent"]!;

test("ARG PI_VERSION in the Dockerfile and cloud-setup.sh's default equal package.json's Pi devDependency", () => {
  assert.match(PI_PINNED, /^\d+\.\d+\.\d+$/, "package.json pins Pi exactly");
  assert.equal(DOCKERFILE.match(/^ARG PI_VERSION=(\S+)$/m)?.[1], PI_PINNED);
  const setup = readFileSync(join(ROOT, "scripts/cloud-setup.sh"), "utf8");
  assert.equal(setup.match(/PI_VERSION_FALLBACK="([^"]+)"/)?.[1], PI_PINNED, "the fallback, used where no checkout is beside the script");
  assert.match(setup, /pi-coding-agent": \*"/, "the default is read from package.json");
});

test("cloud-setup.sh takes Pi's version from package.json when PI_VERSION is unset, and PI_VERSION wins when set", () => {
  const dir = mkdtempSync(join(tmpdir(), "image-pins-"));
  try {
    // Run only the version step: the script's provision phase installs things, so the block is extracted and run alone.
    const setup = readFileSync(join(ROOT, "scripts/cloud-setup.sh"), "utf8");
    const start = setup.indexOf('    if [[ -z "${PI_VERSION:-}" ]]; then');
    const end = setup.indexOf("    fi\n", setup.indexOf('PI_VERSION="${PI_VERSION:-$PI_VERSION_FALLBACK}"')) + "    fi\n".length;
    assert.ok(start > 0 && end > start, "the version step is in cloud-setup.sh");
    mkdirSync(join(dir, "scripts"));
    writeFileSync(join(dir, "package.json"), '{"devDependencies": {"@earendil-works/pi-coding-agent": "9.8.7"}}\n');
    writeFileSync(join(dir, "scripts/step.sh"), `#!/usr/bin/env bash\n${setup.slice(start, end)}\necho "$PI_VERSION"\n`);
    const run = (env: Record<string, string>) => execFileSync("bash", [join(dir, "scripts/step.sh")], { encoding: "utf8", cwd: dir, env: { PATH: process.env.PATH!, ...env } }).trim();
    assert.equal(run({}), "9.8.7");
    assert.equal(run({ PI_VERSION: "1.2.3" }), "1.2.3");
    rmSync(join(dir, "package.json"));
    assert.equal(run({}), PI_PINNED, "without a package.json, the fallback");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the Dockerfile installs Pi as a project with the undici override, and links pi onto PATH", () => {
  assert.match(DOCKERFILE, /"overrides":\{"undici":"\^8\.12\.2"\}/);
  assert.match(DOCKERFILE, /ln -s \/opt\/pi\/node_modules\/\.bin\/pi \/usr\/local\/bin\/pi/);
  assert.doesNotMatch(DOCKERFILE.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n"), /npm install -g[^\n]*pi-coding-agent/);
});

function undiciProblems(piDir: string): string[] {
  const code = `
import importlib.util, json, os, sys
os.environ["DFIRSWARM_PI_DIR"] = sys.argv[1]
spec = importlib.util.spec_from_file_location("install", sys.argv[2])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(json.dumps(m.pi_undici_problems()))
`;
  return JSON.parse(execFileSync(PY, ["-I", "-c", code, piDir, join(ROOT, "images/install.py")], { encoding: "utf8" })) as string[];
}

test("the build's undici check fails a nested undici older than 8.12.2 and passes 8.12.2 and later", () => {
  const dir = mkdtempSync(join(tmpdir(), "image-pins-"));
  try {
    const put = (rel: string, version: string) => {
      mkdirSync(join(dir, "node_modules", rel), { recursive: true });
      writeFileSync(join(dir, "node_modules", rel, "package.json"), JSON.stringify({ name: "undici", version }));
    };
    assert.deepEqual(undiciProblems(dir), [], "nothing installed, nothing to check");
    put("undici", "8.12.2");
    put("@scope/pkg/node_modules/undici", "8.13.0");
    assert.deepEqual(undiciProblems(dir), []);
    put("@scope/other/node_modules/undici", "8.10.2");
    const bad = undiciProblems(dir);
    assert.equal(bad.length, 1);
    assert.match(bad[0]!, /8\.10\.2/);
    put("@scope/old/node_modules/undici", "7.99.0");
    assert.equal(undiciProblems(dir).length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("each BASE_PROGRAMS entry is a package of the Dockerfile's apt list (through a small map where the names differ), or Python or Node", () => {
  const recipe = readFileSync(join(ROOT, "images/recipe.py"), "utf8");
  const programs = [...(recipe.match(/BASE_PROGRAMS = \{([^}]*)\}/)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
  assert.ok(programs.length >= 15, `read ${programs.length} programs`);
  // The final stage's apt install block.
  const from = DOCKERFILE.lastIndexOf("apt-get install");
  const block = DOCKERFILE.slice(from, DOCKERFILE.indexOf("rm -rf /var/lib/apt/lists", from));
  const packages = new Set(block.split(/\s+/).filter((w) => /^[a-z0-9][a-z0-9.+-]+$/.test(w)));
  // Where the program's name is not its package's.
  const packageOf: Record<string, string> = { strings: "binutils", hexdump: "bsdextrautils", "7z": "p7zip-full", rg: "ripgrep", exiftool: "libimage-exiftool-perl", xz: "xz-utils" };
  for (const program of programs) {
    if (program === "node") continue; // the base image's own
    const pkg = packageOf[program] ?? program;
    assert.ok(packages.has(pkg), `${program} -> ${pkg} is not in the Dockerfile's apt list`);
  }
  for (const [program, pkg] of Object.entries(packageOf)) assert.ok(packages.has(pkg), `${program}'s package ${pkg} is in the apt list`);
});
