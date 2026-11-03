/**
 * vss_materialise against stand-ins for vshadowinfo, vshadowmount, fusermount3, fls and icat that follow what those programs print. A
 * "volume" is a JSON file ({"fs": {"Windows": {"System32": {"SYSTEM": "text"}}}}); the stand-in vshadowmount puts one such file per store in
 * the mount directory, fls lists a directory of it in the Sleuth Kit's `r/r <inode>:\t<name>` form and icat writes a file's text. Nothing here
 * mounts anything: a real run needs FUSE and libvshadow, and is not made by these tests.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { chmodSync } from "node:fs";
import { body, failed, tool } from "./windows-pack-harness.ts";
import { assertStopped, runTool, scriptOf, stopAt, withDeadline } from "./windows-tool-contract.ts";

type Answer = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const PY = "#!/usr/bin/env python3\n";
const INFO = `${PY}print("""vshadowinfo 20240101

Volume Shadow Snapshot information:
\\tNumber of stores:\\t2

Store: 1
\\tIdentifier\\t\\t: 11111111-aaaa-bbbb-cccc-000000000001
\\tCreation time\\t\\t: Oct 17, 2023 12:00:00.000000000 UTC
Store: 2
\\tIdentifier\\t\\t: 22222222-aaaa-bbbb-cccc-000000000002
\\tCreation time\\t\\t: Nov 02, 2023 08:30:00.000000000 UTC
""")
`;
const MOUNT = `${PY}import os, shutil, sys
d = os.environ["FAKE_DIR"]
mount = sys.argv[-1]
open(os.path.join(d, "mount.log"), "a").write("mount %s\\n" % mount)
for n in os.environ.get("FAKE_STORES", "1,2").split(","):
    src = os.path.join(d, "store-%s.json" % n)
    if os.environ.get("FAKE_LINK") == n:
        os.symlink("/etc/hostname", os.path.join(mount, "vss%s" % n))
    elif os.path.exists(src):
        shutil.copy(src, os.path.join(mount, "vss%s" % n))
`;
const UMOUNT = `${PY}import glob, os, sys
d = os.environ["FAKE_DIR"]
mount = sys.argv[-1]
for f in glob.glob(os.path.join(mount, "vss*")):
    os.unlink(f)
open(os.path.join(d, "mount.log"), "a").write("unmount %s\\n" % mount)
`;
const FLS = `${PY}import json, sys
a = sys.argv[1:]
if a[:1] == ["-o"]:
    a = a[2:]
vol, rest = a[0], a[1:]
fs = json.load(open(vol))["fs"]
def enc(p): return str(int.from_bytes(p.encode(), "big")) + "-128-1"
def dec(i): n = int(i.split("-")[0]); return n.to_bytes((n.bit_length() + 7) // 8, "big").decode()
path = dec(rest[0]) if rest else ""
node = fs
for part in [p for p in path.split("/") if p]:
    node = node[part]
for name, val in node.items():
    deleted = name.startswith("~")
    nm = name[1:] if deleted else name
    kind = "d/d" if isinstance(val, dict) else "r/r"
    print("%s %s%s:\\t%s" % (kind, "* " if deleted else "", enc((path + "/" + name).lstrip("/")), nm))
`;
const ICAT = `${PY}import json, os, sys, time
a = sys.argv[1:]
if a[:1] == ["-o"]:
    a = a[2:]
vol, inode = a
def dec(i): n = int(i.split("-")[0]); return n.to_bytes((n.bit_length() + 7) // 8, "big").decode()
node = json.load(open(vol))["fs"]
for part in dec(inode).split("/"):
    node = node[part]
pidfile = os.environ.get("FAKE_PIDFILE")
if pidfile and vol.endswith("vss1"):
    open(pidfile, "w").write(str(os.getpid()))
    time.sleep(60)
sys.stdout.write(node * int(os.environ.get("FAKE_REPEAT", "1")))
sys.stdout.flush()
`;

type Volume = Record<string, unknown>;
const volume = (fs: Volume): string => JSON.stringify({ fs });
const sha = (text: string): string => createHash("sha256").update(text).digest("hex");

async function setup(cwd: string, bin: string, stores: Record<string, Volume>, live: Volume): Promise<Record<string, string>> {
  const fake = join(cwd, "fake");
  mkdirSync(fake, { recursive: true });
  for (const [n, fs] of Object.entries(stores)) writeFileSync(join(fake, `store-${n}.json`), volume(fs));
  writeFileSync(join(cwd, "work", "disk.raw"), volume(live));
  writeFileSync(join(cwd, "fuse-device"), "");
  for (const [name, script] of [["vshadowinfo", INFO], ["vshadowmount", MOUNT], ["fusermount3", UMOUNT], ["fls", FLS], ["icat", ICAT]]) {
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, name), script);
    chmodSync(join(bin, name), 0o755);
  }
  return { FAKE_DIR: fake, DFIRSWARM_FUSE_DEVICE: join(cwd, "fuse-device"), FAKE_STORES: Object.keys(stores).join(",") };
}

const SYSTEM = "/Windows/System32/config/SYSTEM";
const ARGS = { image: "work/disk.raw", offset: 1048576, stores: [1, 2], paths: [SYSTEM] };
const log = (env: Record<string, string>): string => (existsSync(join(env.FAKE_DIR, "mount.log")) ? readFileSync(join(env.FAKE_DIR, "mount.log"), "utf8") : "");
const hidden = (dir: string): string[] => {
  const found: string[] = [];
  const walk = (d: string): void => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name.startsWith(".")) found.push(join(d, e.name));
      if (e.isDirectory()) walk(join(d, e.name));
    }
  };
  if (existsSync(dir)) walk(dir);
  return found;
};
const config = (system: string, extra: Volume = {}): Volume => ({ Windows: { System32: { config: { SYSTEM: system, ...extra } } } });

test("without FUSE the answer is blocked: no FUSE as JSON, and nothing is written or run", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, { 1: config("a") }, config("a"));
    const out = failed(await tool("vss_materialise", cwd, ARGS, { ...env, DFIRSWARM_FUSE_DEVICE: join(cwd, "no-such-device") }, bin)) as Answer;
    assert.equal(out.status, "failed");
    assert.equal(out.blocked, "no FUSE");
    assert.equal(out.no_fuse.reason, "no_fuse");
    assert.match(out.no_fuse.blocked_by[0], /is not present/);
    assert.equal(log(env), "", "nothing was mounted");
    assert.deepEqual(readdirSync(join(cwd, "work")), ["disk.raw"], "nothing was written");
  });
});

test("two stores: each path is looked up in each, copied with the store's identity, compared with the live volume, and the mount is gone", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, { 1: config("old system", { SAM: "secret-bytes" }), 2: { Windows: { System32: { config: { SYSTEM: "new system" } } } } }, config("new system"));
    const out = body<Answer>(await tool("vss_materialise", cwd, { ...ARGS, paths: [SYSTEM, "/windows/system32/CONFIG/sam", "/Windows/missing.txt"] }, env, bin));
    assert.equal(out.stores_listed["1"].identifier, "11111111-aaaa-bbbb-cccc-000000000001");
    assert.equal(out.stores_listed["2"].created, "Nov 02, 2023 08:30:00.000000000 UTC");
    const rowOf = (store: number, path: string): Answer => out.rows.find((r: Answer) => r.store === store && r.path === path);
    const s1 = rowOf(1, SYSTEM);
    assert.equal(s1.copy_status, "copied");
    assert.equal(s1.sha256, sha("old system"));
    assert.equal(s1.relation_to_live, "differs");
    assert.equal(s1.store_guid, "11111111-aaaa-bbbb-cccc-000000000001");
    assert.equal(readFileSync(join(cwd, s1.copied_to), "utf8"), "old system", "the copy is the store's file");
    assert.equal(rowOf(2, SYSTEM).relation_to_live, "same");
    assert.equal(rowOf(2, "/Windows/missing.txt").copy_status, "not_in_store");
    assert.deepEqual(out.paths_in_stores[SYSTEM], { "1": true, "2": true });
    assert.deepEqual(out.paths_in_stores["/Windows/missing.txt"], { "1": false, "2": false });
    assert.equal(rowOf(1, "/windows/system32/CONFIG/sam").copy_status, "credential_file_not_copied");
    assert.equal(rowOf(1, "/windows/system32/CONFIG/sam").sha256, null);
    assert.ok(!JSON.stringify(out).includes(sha("secret-bytes")), "no digest of a credential file");
    assert.ok(out.status === "partial" && /credential file/.test(out.status_basis), "a credential file found and not copied is named");
    assert.match(log(env), /^mount .*\nunmount /, "mounted once and unmounted");
    assert.equal(out.mount.unmounted, true);
    assert.equal(out.mount.mount_dir_removed, true);
    assert.deepEqual(hidden(join(cwd, "work")), [], "no hidden file or mount directory is left");
  });
});

test("a path that exists in every store and was copied is complete; a store vshadowinfo does not list is partial and named", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, { 1: config("x"), 2: config("x") }, config("x"));
    const ok = body<Answer>(await tool("vss_materialise", cwd, ARGS, env, bin));
    assert.equal(ok.status, "complete", ok.status_basis);
    const bad = body<Answer>(await tool("vss_materialise", cwd, { ...ARGS, stores: [2, 7] }, env, bin));
    assert.equal(bad.status, "partial");
    assert.deepEqual(bad.stores_not_listed, [7]);
  });
});

test("a link where the store file should be is not followed", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, { 1: config("x") }, config("x"));
    const out = body<Answer>(await tool("vss_materialise", cwd, { ...ARGS, stores: [1] }, { ...env, FAKE_LINK: "1" }, bin));
    assert.equal(out.rows[0].copy_status, "store_not_exposed");
    assert.equal(out.status, "partial");
    assert.match(log(env), /unmount/);
  });
});

test("credential files: refused outside a secret-output job, copied in one with no digest", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, { 1: config("x", { SAM: "secret-bytes" }) }, config("x"));
    const path = "/Windows/System32/config/SAM";
    const refused = failed(await tool("vss_materialise", cwd, { ...ARGS, stores: [1], paths: [path], copy_credentials: true }, env, bin));
    assert.match(refused.error, /copy_credentials is refused/);
    assert.equal(log(env), "", "nothing was mounted");
    const out = join(cwd, "out");
    mkdirSync(out);
    const job = { ...env, JOB_ID: "j000001", OUT: out, SECRET_OUTPUT: "1" };
    const done = body<Answer>(await tool("vss_materialise", cwd, { ...ARGS, stores: [1], paths: [path], copy_credentials: true }, job, bin));
    const row = done.rows[0];
    assert.equal(row.copy_status, "copied");
    assert.equal(row.sha256, null);
    assert.match(row.copied_to, /^store\/jobs\/j000001\/out\//);
    assert.equal(readFileSync(join(out, row.copied_to.replace("store/jobs/j000001/out/", "")), "utf8"), "secret-bytes");
    assert.ok(!JSON.stringify(done).includes(sha("secret-bytes")));
    assert.deepEqual(hidden(out), [], "the job's output holds no mount and no temporary file");
  });
});

test("hostile paths and names: refused before anything is mounted, and a name with odd characters is copied under a safe name", async () => {
  await withCwd(async (cwd, bin) => {
    const odd = "we ird;$(x)\u00e9 `n`.txt";
    const env = await setup(cwd, bin, { 1: { Dir: { [odd]: "t", normal: "n" } } }, { Dir: { [odd]: "t" } });
    for (const p of ["Windows/x", "/a/../b", "/a/./b", "", "/a\u0000b", "/" + "d/".repeat(40) + "f"]) {
      const out = failed(await tool("vss_materialise", cwd, { ...ARGS, stores: [1], paths: [p] }, env, bin));
      assert.match(out.error, /every path must start/);
    }
    assert.equal(log(env), "");
    const out = body<Answer>(await tool("vss_materialise", cwd, { ...ARGS, stores: [1], paths: ["/Dir/" + odd] }, env, bin));
    const row = out.rows[0];
    assert.equal(row.copy_status, "copied");
    assert.match(row.copied_to, /\/0000-we_ird___x____n_\.txt$/);
    assert.equal(row.relation_to_live, "same");
    for (const bad of [{ stores: [] }, { stores: [0] }, { stores: ["1"] }, { paths: "x" }, { image: 1 }, { offset: -1 }, { copy_credentials: "yes" }, { max_copy_bytes: 0 }]) {
      assert.equal(failed(await tool("vss_materialise", cwd, { ...ARGS, ...bad }, env, bin)).status, "failed");
    }
  });
});

test("a FIFO as the image is refused without waiting; a deleted entry is never copied", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, { 1: { a: { "~gone.txt": "deleted text" } } }, { a: {} });
    spawnSync("mkfifo", [join(cwd, "work", "pipe.raw")]);
    const started = Date.now();
    assert.match(failed(await tool("vss_materialise", cwd, { ...ARGS, image: "work/pipe.raw" }, env, bin)).error, /not a regular file or a block device/);
    assert.ok(Date.now() - started < 10_000);
    const out = body<Answer>(await tool("vss_materialise", cwd, { ...ARGS, stores: [1], paths: ["/a/gone.txt"] }, env, bin));
    assert.equal(out.rows[0].copy_status, "not_in_store");
  });
});

test("a file over max_copy_bytes is named and not kept, and the other paths go on", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, { 1: { big: "x".repeat(1000), small: "s" } }, { big: "x" });
    const out = body<Answer>(await tool("vss_materialise", cwd, { ...ARGS, stores: [1], paths: ["/big", "/small"], max_copy_bytes: 100 }, { ...env, FAKE_REPEAT: "1" }, bin));
    assert.equal(out.rows[0].copy_status, "too_large");
    assert.equal(out.rows[1].copy_status, "copied");
    assert.equal(out.status, "partial");
    assert.deepEqual(hidden(join(cwd, "work")), []);
    assert.deepEqual(readdirSync(join(cwd, "work", "s1", "tool-output", readdirSync(join(cwd, "work", "s1", "tool-output")).filter((n) => n.startsWith("vss_materialise-"))[0], "store-1")).length, 1, "only the whole copy is kept");
  });
});

test("a write that is refused (a file size limit) removes the partial copy, names no copy, and still unmounts", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, { 1: config("x".repeat(100)) }, config("x"));
    const done = spawnSync("bash", ["-c", `ulimit -f 8; exec python3 ${scriptOf("vss_materialise")}`], {
      cwd, input: JSON.stringify({ ...ARGS, stores: [1] }), encoding: "utf8", env: { ...process.env, ...env, FAKE_REPEAT: "300", AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}` },
    });
    const out = JSON.parse(done.stdout) as Answer;
    assert.equal(out.rows[0].copy_status, "write_failed", done.stdout.slice(0, 600));
    assert.equal(out.rows[0].copied_to, null);
    assert.equal(out.status, "partial");
    assert.match(log(env), /unmount/);
    assert.deepEqual(hidden(join(cwd, "work")), [], "the partial file is gone");
  });
});

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
  test(`${signal} while a program runs ends it, unmounts, removes the partial copy and answers with JSON`, async () => {
    await withCwd(async (cwd, bin) => {
      const env = await setup(cwd, bin, { 1: config("x") }, config("x"));
      const pidFile = join(cwd, "icat.pid");
      const stopped = await stopAt("vss_materialise", { ...ARGS, stores: [1] }, { ...env, FAKE_PIDFILE: pidFile, PATH: `${bin}:${process.env.PATH}` }, "child", signal, { cwd, pidFile });
      const { answered, answer } = assertStopped(stopped, signal);
      assert.ok(answered);
      assert.equal(answer.interrupted, true);
      assert.match(log(env), /unmount/, "the mount was unmounted by the last word");
      assert.deepEqual(hidden(join(cwd, "work")), []);
    });
  });
}

test("at the tool's deadline the lookups not made are named, the mount is gone and the answer is partial", async () => {
  await withCwd(async (cwd, bin) => {
    const env = await setup(cwd, bin, { 1: config("x") }, config("x"));
    const copy = withDeadline("vss_materialise", 20);
    const done = await runTool(copy, cwd, { ...ARGS, stores: [1] }, { ...env, PATH: `${bin}:${process.env.PATH}` });
    const out = JSON.parse(done.stdout) as Answer;
    assert.equal(out.status, "partial");
    assert.equal(out.counts.not_attempted, 1);
    assert.match(log(env), /unmount/);
  });
});

test("the manifest says what the code does", () => {
  const manifest = JSON.parse(readFileSync(join(scriptOf("vss_materialise"), "..", "manifest.json"), "utf8")) as Answer;
  assert.deepEqual(manifest.needs, ["fuse"]);
  assert.deepEqual(manifest.requires, ["vshadowinfo", "vshadowmount", "fls", "icat"]);
  assert.deepEqual(manifest.secret_output, { when_args: ["copy_credentials"] });
  assert.ok(manifest.timeout_seconds > 270);
  assert.ok(statSync(scriptOf("vss_materialise")).mode & 0o100, "run.py is executable");
});
