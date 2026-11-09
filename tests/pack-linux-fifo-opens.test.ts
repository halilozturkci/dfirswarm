/**
 * The Linux pack, bundle 29's tools: every path a tool opens that comes from the evidence tree or from a parameter is opened without waiting
 * (O_NONBLOCK) and looked at with fstat, so a FIFO there is an error the answer names, never a hang. One case per path. Each case runs the
 * tool with a FIFO at the path under a clock: a tool that opens it plainly waits for a writer that never comes and the case fails by name.
 * Also: what a path that cannot be read does to the status (never complete), and the two view cases of container_layers where a file or a link
 * in an upper layer hides what a lower layer holds under it.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, asJob as plainJob, body, put, rowsOf, startDetached, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const script = (name: string): string => join(TOOLS, name, "run.py");
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

function fifo(path: string): void {
  const r = spawnSync("mkfifo", [path]);
  assert.equal(r.status, 0, String(r.stderr));
}

/** Runs the tool in a job-shaped $OUT and fails by name when it is still running after `ms`. */
async function bounded(name: string, cwd: string, args: unknown, bin?: string, ms = 25_000): Promise<{ out: Json; stdout: string }> {
  const run = startDetached(script(name), cwd, args, { JOB_ID: "j1", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" }, bin);
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<"late">((resolve) => { timer = setTimeout(() => resolve("late"), ms); });
  const result = await Promise.race([run.closed, late]);
  clearTimeout(timer);
  if (result === "late") {
    run.killGroup();
    assert.fail(`${name} was still waiting after ${ms} ms: a path it opened is not opened without waiting`);
  }
  return { out: JSON.parse(run.stdout()), stdout: run.stdout() };
}

test("container_inventory opens layerdb's cache-id and size without waiting, and an unreadable one is a read error that keeps the status from complete", async () => {
  await withCwd(async (cwd) => {
    const base = join(cwd, "work/r/var/lib/docker");
    const diff = "a".repeat(64);
    const chain = diff;
    await mkdir(join(cwd, "out"), { recursive: true });
    await put(base, `image/overlay2/imagedb/content/sha256/${"b".repeat(64)}`, JSON.stringify({ architecture: "amd64", os: "linux", created: "2026-01-01T00:00:00Z", config: {}, rootfs: { type: "layers", diff_ids: ["sha256:" + diff] }, history: [{}] }));
    const layerdir = join(base, "image/overlay2/layerdb/sha256", chain);
    await mkdir(layerdir, { recursive: true });
    fifo(join(layerdir, "cache-id"));
    fifo(join(layerdir, "size"));
    const withFifos = await bounded("container_inventory", cwd, { root: "work/r" });
    assert.notEqual(withFifos.out.status, "complete", "a layerdb file that could not be read makes the answer partial");
    const errors = JSON.stringify(withFifos.out.read_errors);
    assert.ok(errors.includes("cache-id") && errors.includes("/size"), errors.slice(0, 300));
    // a directory where the file should be: the same
    await mkdir(join(cwd, "work/r2/var/lib/docker/image/overlay2/layerdb/sha256", chain, "cache-id"), { recursive: true });
    await put(join(cwd, "work/r2/var/lib/docker"), `image/overlay2/imagedb/content/sha256/${"b".repeat(64)}`, JSON.stringify({ architecture: "amd64", os: "linux", created: "2026-01-01T00:00:00Z", config: {}, rootfs: { type: "layers", diff_ids: ["sha256:" + diff] }, history: [{}] }));
    const dir = await bounded("container_inventory", cwd, { root: "work/r2" });
    assert.notEqual(dir.out.status, "complete");
    assert.ok((dir.out.pages?.read_errors?.matched ?? 0) >= 1);
  });
});

test("container_layers opens overlay2's lower file without waiting, and a lower that cannot be read is a named problem", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work/ov");
    await put(root, `${"1".repeat(64)}/diff/etc/a`, "a\n");
    fifo(join(root, "1".repeat(64), "lower"));
    const r = await bounded("container_layers", cwd, { overlay2_root: "work/ov", start: "1".repeat(64) });
    assert.notEqual(r.out.status, "complete");
    assert.match(r.out.chain_notes.join(" "), /lower file could not be read/);
    // a start or a link that names a place outside the store is not followed
    const dots = await bounded("container_layers", cwd, { overlay2_root: "work/ov", start: ".." });
    assert.equal(dots.out.status, "failed");
    await mkdir(join(root, "l"), { recursive: true });
    await symlink("../../diff", join(root, "l", "AAAAAAAAAAAAAAAAAAAAAAAAAA"));
    await writeFile(join(root, "2".repeat(64) + "-lower"), "");
    await put(root, `${"2".repeat(64)}/diff/x`, "x");
    await put(root, `${"2".repeat(64)}/lower`, "l/AAAAAAAAAAAAAAAAAAAAAAAAAA");
    const esc = await bounded("container_layers", cwd, { overlay2_root: "work/ov", start: "2".repeat(64) });
    assert.notEqual(esc.out.status, "complete");
  });
});

test("container_layers hides what a lower layer holds under a path that a higher layer makes a file or a link, and will not copy it", async () => {
  await withCwd(async (cwd) => {
    for (const kind of ["file", "link"] as const) {
      const l0 = join(cwd, "work", kind, "l0"), l1 = join(cwd, "work", kind, "l1");
      await put(l0, "a/b", "b\n");
      await put(l0, "a/sub/c", "c\n");
      await mkdir(l1, { recursive: true });
      if (kind === "file") await writeFile(join(l1, "a"), "now a file\n");
      else await symlink("/etc", join(l1, "a"));
      const args = { layers: [`work/${kind}/l0`, `work/${kind}/l1`] };
      const out = body(await plainJob(script("container_layers"), cwd, args, undefined, { SECRET_OUTPUT: "1" }, `out-${kind}`));
      const view = Object.fromEntries((await rowsOf(cwd, out, "view", `out-${kind}`)).map((r: Json) => [r.path, r]));
      assert.equal(view["a"].visible, true, kind);
      assert.equal(view["a"].supplied_by, 1, kind);
      for (const p of ["a/b", "a/sub", "a/sub/c"]) {
        assert.equal(view[p].visible, false, `${kind}: ${p} is under a path a higher layer made a ${kind}`);
        assert.ok(view[p].changes.some((c: Json) => c.action === "present_but_hidden"), `${kind}: ${p}`);
      }
      const copied = body(await plainJob(script("container_layers"), cwd, { ...args, copy: true, copy_paths: ["a/b", "a/sub/c"] }, undefined, { SECRET_OUTPUT: "1" }, `outc-${kind}`));
      assert.ok(copied.materialised.every((m: Json) => m.copied === false), `${kind}: nothing hidden is copied`);
    }
  });
});

test("package_verify opens the rpm database's Packages file without waiting, and counts standard error that is not a missing file against the status", async () => {
  await withCwd(async (cwd, bin) => {
    await mkdir(join(cwd, "work/r/var/lib/rpm"), { recursive: true });
    fifo(join(cwd, "work/r/var/lib/rpm/Packages"));
    await put(bin, "rpm", "#!/bin/bash\ncase \"$1\" in --version) echo 'rpm version 9.9.9'; exit 0;; esac\nexit 0\n", 0o755);
    for (const family of ["rpm", "auto"]) {
      const r = await bounded("package_verify", cwd, { root: "work/r", family }, bin);
      assert.ok(["partial", "complete", "failed"].includes(r.out.status), family);
    }
    // standard error that says it could not check something
    await put(join(cwd, "work/d"), "var/lib/dpkg/status", "Package: a\nStatus: install ok installed\n");
    await put(join(cwd, "work/d"), "var/lib/dpkg/info/a.md5sums", "d41d8cd98f00b204e9800998ecf8427e  usr/bin/a\n");
    await put(bin, "debsums", "#!/bin/bash\ncase \"$1\" in --version) echo 'debsums version 9.9.9'; exit 0;; esac\necho '/usr/bin/a                                        OK'\necho \"debsums: can't open /var/lib/dpkg/info/b.md5sums: Input/output error\" >&2\necho 'debsums: package zz is not installed' >&2\nexit 2\n", 0o755);
    const r = await bounded("package_verify", cwd, { root: "work/d", family: "debian" }, bin);
    assert.equal(r.out.status, "partial");
    assert.match(r.out.status_basis, /standard error that are errors, warnings or not understood/);
  });
});

test("audit_events, linux_persistence and utmp_parse open the files they are given without waiting: a FIFO is named, not read", async () => {
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "out"), { recursive: true });
    await put(cwd, "work/audit.log", `type=SYSCALL msg=audit(1700000000.001:5): arch=c000003e syscall=59 success=yes exit=0 pid=1 auid=1000 uid=0\n`);
    fifo(join(cwd, "work/passwd-fifo"));
    fifo(join(cwd, "work/audit-fifo.log"));
    const identity = await bounded("audit_events", cwd, { paths: ["work/audit.log"], identity: ["work/passwd-fifo"] });
    assert.ok(["failed", "partial"].includes(identity.out.status), identity.stdout.slice(0, 200));
    const listed = await bounded("audit_events", cwd, { paths: ["work/audit-fifo.log"] });
    assert.notEqual(listed.out.status, "complete");
    // linux_persistence: a journal records file given as execution_rows
    await put(cwd, "work/root/etc/systemd/system/a.service", "[Service]\nExecStart=/bin/true\n");
    fifo(join(cwd, "work/rows-fifo.jsonl"));
    const rows = await bounded("linux_persistence", cwd, { root: "work/root", execution_rows: ["work/rows-fifo.jsonl"] });
    assert.notEqual(rows.out.status, "complete");
    // utmp_parse: a passwd that is a FIFO, and a path that is one
    await writeFile(join(cwd, "work/lastlog"), Buffer.alloc(292 * 3));
    const passwd = await bounded("utmp_parse", cwd, { path: "work/lastlog", passwd: "work/passwd-fifo", layout: "lastlog-292" });
    assert.equal(passwd.out.status, "failed");
    const path = await bounded("utmp_parse", cwd, { path: "work/passwd-fifo" });
    assert.equal(path.out.status, "failed");
    assert.equal(sha("x").length, 64);
    assert.equal((await readFile(join(cwd, "work/audit.log"), "utf8")).length > 0, true);
  });
});
