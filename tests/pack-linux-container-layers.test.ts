/**
 * The Linux pack: container_layers, against overlay2's on-disk layout (`<id>/diff` holds a layer's files, `<id>/lower` lists the layers below as
 * `l/<short id>` separated by colons, `l/<short id>` is a link to `../<id>/diff`), the OCI image layer rules for deleting (a `.wh.<name>` file) and
 * for an opaque directory (`.wh..wh..opq`) and overlayfs's own whiteout (a character device 0/0). Every fixture is built by the test, never by the tool.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, asJob as plainJob, body, filesUnder, put, refused, rowsOf, startDetached, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const LAYERS = join(TOOLS, "container_layers", "run.py");
const asJob = (cwd: string, args: unknown, env: Record<string, string> = {}, outName = "out"): ReturnType<typeof plainJob> =>
  plainJob(LAYERS, cwd, args, undefined, { SECRET_OUTPUT: "1", ...env }, outName);
const W = "work";

async function view(cwd: string, out: Json): Promise<Record<string, Json>> {
  return Object.fromEntries((await rowsOf(cwd, out, "view")).map((r) => [r.path, r]));
}

/** Three explicit layers (base, middle, writable) built from the image rules. */
async function chain(cwd: string): Promise<{ layers: string[]; upper: string }> {
  const a = join(cwd, W, "a"), b = join(cwd, W, "b"), up = join(cwd, W, "up");
  await put(a, "etc/passwd", "root\n");
  await put(a, "etc/hosts", "old hosts\n");
  await put(a, "var/data/x", "x\n");
  await put(a, "var/data/sub/z", "z\n");
  await put(a, "tmp/keep", "keep\n");
  await put(b, "etc/hosts", "new hosts, longer\n");
  await put(b, "etc/.wh.passwd", "");
  await put(b, "var/data/.wh..wh..opq", "");
  await put(b, "var/data/y", "y\n");
  await put(up, "root/new", "n\n");
  await put(up, "tmp/.wh.keep", "");
  return { layers: [`${W}/a`, `${W}/b`], upper: `${W}/up` };
}

test("container_layers builds the effective view: the layer that supplies each path, and what each layer did to it, OCI whiteouts and opaque directories included", async () => {
  await withCwd(async (cwd) => {
    const { layers, upper } = await chain(cwd);
    const out = body(await tool(LAYERS, cwd, { layers, upper }));
    const v = await view(cwd, out);
    assert.equal(out.status, "complete");
    assert.equal(out.layers_total, 3);
    assert.deepEqual(out.layers.map((l: Json) => [l.layer, l.role]), [[0, "lower"], [1, "lower"], [2, "writable (upper)"]]);
    // replaced in layer 1, supplied by it
    assert.deepEqual([v["etc/hosts"].visible, v["etc/hosts"].supplied_by, v["etc/hosts"].size], [true, 1, 18]);
    assert.deepEqual(v["etc/hosts"].changes.map((c: Json) => [c.layer, c.action]), [[0, "added"], [1, "replaced"]]);
    // deleted by a whiteout in layer 1
    assert.equal(v["etc/passwd"].visible, false);
    assert.equal(v["etc/passwd"].why_not_visible, "deleted by layer 1");
    assert.deepEqual(v["etc/passwd"].changes.map((c: Json) => [c.layer, c.action]), [[0, "added"], [1, "deleted"]]);
    // under an opaque directory of layer 1: the base's files are hidden, layer 1's own are visible
    assert.equal(v["var/data/y"].visible, true);
    assert.equal(v["var/data/x"].visible, false);
    assert.equal(v["var/data/x"].changes.some((c: Json) => c.action === "present_but_hidden"), true);
    assert.equal(v["var/data/sub/z"].visible, false);
    assert.equal(v["var/data"].visible, true, "the opaque directory itself is the base's");
    assert.deepEqual(v["var/data"].changes.map((c: Json) => c.action), ["added", "merged", "made_opaque"], "a directory over a directory is merged, not replaced");
    // deleted by the writable layer
    assert.equal(v["tmp/keep"].visible, false);
    assert.equal(v["tmp/keep"].why_not_visible, "deleted by layer 2");
    assert.equal(v["root/new"].supplied_by, 2);
    assert.equal(out.layers.find((l: Json) => l.layer === 1).oci_whiteouts, 1);
    assert.equal(out.layers.find((l: Json) => l.layer === 1).oci_opaque_dirs, 1);
    assert.match(out.whiteout_kinds.overlayfs_native, /character device 0\/0/);
    // marker files are not paths of the view
    assert.ok(!("etc/.wh.passwd" in v) && !("var/data/.wh..wh..opq" in v));
    // path_prefix keeps one subtree
    const etc = await view(cwd, body(await tool(LAYERS, cwd, { layers, upper, path_prefix: "etc" })));
    assert.deepEqual(Object.keys(etc).sort(), ["etc", "etc/hosts", "etc/passwd"]);
  });
});

test("container_layers resolves overlay2's own chain through the l/ links, and names a lower layer that is missing", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, W, "overlay2");
    const ids = ["1".repeat(64), "2".repeat(64), "3".repeat(64)];
    await put(root, `${ids[0]}/diff/etc/base`, "b\n");
    await put(root, `${ids[1]}/diff/etc/mid`, "m\n");
    await put(root, `${ids[2]}/diff/etc/top`, "t\n");
    await mkdir(join(root, "l"), { recursive: true });
    await symlink(`../${ids[0]}/diff`, join(root, "l", "AAAAAAAAAAAAAAAAAAAAAAAAAA"));
    await symlink(`../${ids[1]}/diff`, join(root, "l", "BBBBBBBBBBBBBBBBBBBBBBBBBB"));
    await put(root, `${ids[1]}/lower`, "l/AAAAAAAAAAAAAAAAAAAAAAAAAA");
    await put(root, `${ids[2]}/lower`, "l/BBBBBBBBBBBBBBBBBBBBBBBBBB:l/AAAAAAAAAAAAAAAAAAAAAAAAAA");
    const ok = body(await tool(LAYERS, cwd, { overlay2_root: `${W}/overlay2`, start: ids[2] }));
    assert.equal(ok.layers_total, 3);
    assert.equal(ok.status, "complete");
    const v = await view(cwd, ok);
    assert.deepEqual([v["etc/base"].supplied_by, v["etc/mid"].supplied_by, v["etc/top"].supplied_by], [0, 1, 2]);
    // a lower layer whose link is not there, and one that is not an overlay2 short id
    await put(root, `${ids[2]}/lower`, "l/BBBBBBBBBBBBBBBBBBBBBBBBBB:l/CCCCCCCCCCCCCCCCCCCCCCCCCC:/var/lib/other/diff");
    const cut = body(await tool(LAYERS, cwd, { overlay2_root: `${W}/overlay2`, start: ids[2] }));
    assert.equal(cut.status, "partial");
    assert.equal(cut.missing_layers.length, 2);
    assert.match(cut.missing_layers[0].why, /is not there/);
    assert.match(cut.missing_layers[1].why, /another layout/);
    assert.equal(cut.layers_total, 2);
    assert.ok(cut.layers.every((l: Json) => l.state === "read"));
    // a link that leaves the store is never followed
    await symlink("../../../../etc", join(root, "l", "DDDDDDDDDDDDDDDDDDDDDDDDDD"));
    await put(root, `${ids[2]}/lower`, "l/DDDDDDDDDDDDDDDDDDDDDDDDDD");
    const esc = body(await tool(LAYERS, cwd, { overlay2_root: `${W}/overlay2`, start: ids[2] }));
    assert.match(esc.missing_layers[0].why, /does not point at/);
    // a layer named twice in one lower file (overlay2 lists every layer below, so a repeat is a loop)
    await put(root, `${ids[2]}/lower`, "l/BBBBBBBBBBBBBBBBBBBBBBBBBB:l/BBBBBBBBBBBBBBBBBBBBBBBBBB");
    const loop = body(await tool(LAYERS, cwd, { overlay2_root: `${W}/overlay2`, start: ids[2] }));
    assert.equal(loop.status, "partial");
    assert.match(loop.chain_notes.join(" "), /a loop/);
    // a start that is not a layer
    assert.match(refused(await tool(LAYERS, cwd, { overlay2_root: `${W}/overlay2`, start: "nope" })).error, /start layer/);
  });
});

test("container_layers tells a native whiteout (a character device 0/0) from an ordinary file, and says whether the opaque xattr could be read", async (t) => {
  await withCwd(async (cwd) => {
    const a = join(cwd, W, "a"), up = join(cwd, W, "up");
    await put(a, "gone", "x");
    await put(a, "keep", "x");
    await mkdir(up, { recursive: true });
    const made = spawnSync("mknod", [join(up, "gone"), "c", "0", "0"]);
    // the opaque xattr on a directory, where the file system lets this process set one
    await put(a, "dir/low", "x");
    await put(up, "dir/own", "x");
    const tried = spawnSync("setfattr", ["-n", "user.overlay.opaque", "-v", "y", join(up, "dir")]);
    const out = body(await tool(LAYERS, cwd, { layers: [`${W}/a`], upper: `${W}/up` }));
    const layer = out.layers.find((l: Json) => l.layer === 1);
    assert.equal(typeof layer.xattrs, "string");
    assert.ok(layer.xattrs === "readable" || /not readable here/.test(layer.xattrs));
    if (made.status === 0) {
      const v = await view(cwd, out);
      assert.equal(layer.native_whiteouts, 1);
      assert.equal(v["gone"].visible, false);
      assert.equal(v["gone"].why_not_visible, "deleted by layer 1");
      assert.equal(v["keep"].visible, true);
    } else {
      t.diagnostic(`mknod is not allowed here (${made.status}): the native whiteout case was not run`);
    }
    if (tried.status === 0 && layer.xattrs === "readable") {
      const v = await view(cwd, out);
      assert.equal(layer.native_opaque_dirs, 1);
      assert.equal(v["dir/low"].visible, false);
    } else {
      t.diagnostic("the user.overlay.opaque xattr could not be set or read here: the opaque case was not run");
    }
    // the answer says what it cannot tell for a layer with native whiteouts and unreadable xattrs
    assert.ok("opaque_directories_not_told_in_layers" in out.whiteout_kinds);
  });
});

test("container_layers does not follow a link, a link loop or a link out of a layer, and shows a name that is not UTF-8 as an escape", async () => {
  await withCwd(async (cwd) => {
    const a = join(cwd, W, "a");
    await mkdir(join(a, "d"), { recursive: true });
    await symlink(".", join(a, "d", "loop"));
    await symlink("b", join(a, "a"));
    await symlink("a", join(a, "b"));
    await symlink("/etc", join(a, "outside"));
    await writeFile(Buffer.concat([Buffer.from(join(a, "d") + "/"), Buffer.from([0xff, 0xfe, 0x41])]), "raw");
    const started = Date.now();
    const out = body(await tool(LAYERS, cwd, { layers: [`${W}/a`] }));
    assert.ok(Date.now() - started < 10_000);
    const v = await view(cwd, out);
    assert.deepEqual(["d/loop", "a", "b", "outside"].map((p) => v[p].type), ["symlink", "symlink", "symlink", "symlink"]);
    assert.ok(Object.keys(v).some((p) => p.includes("\udcff\udcfe")), "the raw name is kept as an escape");
    assert.equal(out.status, "complete");
    // a layer named by a link is refused
    await symlink("a", join(cwd, W, "alink"));
    assert.match(refused(await tool(LAYERS, cwd, { layers: [`${W}/alink`] })).error, /link is not followed/);
  });
});

test("container_layers follows 1,000 layers, refuses 4,097, and builds a view of a huge diff directory within the bounds", async () => {
  await withCwd(async (cwd) => {
    const dirs: string[] = [];
    for (let i = 0; i < 1000; i++) {
      await put(join(cwd, W, "deep", `l${i}`), `f${i % 10}`, `v${i}`);
      dirs.push(`${W}/deep/l${i}`);
    }
    const started = Date.now();
    const out = body(await tool(LAYERS, cwd, { layers: dirs }));
    assert.ok(Date.now() - started < 60_000);
    assert.equal(out.layers_total, 1000);
    const v = await view(cwd, out);
    assert.equal(v["f3"].supplied_by, 993, "the topmost layer that has it supplies it");
    assert.equal(v["f3"].changes.length, 100);
    assert.match(refused(await tool(LAYERS, cwd, { layers: Array.from({ length: 4097 }, () => dirs[0]) })).error, /1 to 4096/);
    // a directory of many files: bounded by max_seconds, partial, and named
    const big = join(cwd, W, "big");
    await mkdir(big, { recursive: true });
    for (let i = 0; i < 20000; i++) await writeFile(join(big, `f${i}`), "");
    const t0 = Date.now();
    const partial = body(await tool(LAYERS, cwd, { layers: [`${W}/big`], max_seconds: 0.05, limit: 5 }));
    assert.ok(Date.now() - t0 < 5000);
    assert.equal(partial.status, "partial");
    assert.match(partial.stopped_because, /max_seconds/);
    const whole = body(await tool(LAYERS, cwd, { layers: [`${W}/big`], limit: 5 }));
    assert.equal(whole.paths_in_view, 20000);
    assert.equal(whole.truncated, true);
    assert.equal(whole.status, "complete");
  });
});

test("container_layers copies named effective files only in a secret-output job, only under $OUT, and never over a file that is there", async () => {
  await withCwd(async (cwd) => {
    const { layers, upper } = await chain(cwd);
    const args = { layers, upper, copy: true, copy_paths: ["etc/hosts", "etc/passwd", "var/data", "root/new"] };
    assert.match(refused(await tool(LAYERS, cwd, args)).error, /copy_paths is refused outside a job/);
    assert.match(refused(await plainJob(LAYERS, cwd, args)).error, /not run as secret output/);
    assert.deepEqual(await filesUnder(join(cwd, "out")), []);
    const out = body(await asJob(cwd, args));
    const copied = Object.fromEntries(out.materialised.map((r: Json) => [r.path, r]));
    assert.equal(copied["etc/hosts"].copied, true);
    assert.equal(copied["etc/hosts"].supplied_by, 1);
    assert.equal(await readFile(join(cwd, "out", "layers-view", "etc/hosts"), "utf8"), "new hosts, longer\n");
    assert.equal(copied["root/new"].copied, true);
    assert.match(copied["etc/passwd"].why, /deleted or hidden/);
    assert.match(copied["var/data"].why, /supplied as dir/);
    assert.equal(out.status, "partial", "files asked for and not copied make it partial");
    // a rerun into the same $OUT: the same bytes are named again, a different file takes the next name, nothing is replaced
    await writeFile(join(cwd, "out", "layers-view", "root/new"), "someone else's, longer than the copy\n");
    const again = body(await asJob(cwd, { layers, upper, copy: true, copy_paths: ["etc/hosts", "root/new"] }, {}, "out"));
    const names = (await filesUnder(join(cwd, "out", "layers-view"))).sort();
    assert.deepEqual(names, ["etc/hosts", "root/new", "root/new-2"]);
    assert.equal(await readFile(join(cwd, "out", "layers-view", "root/new"), "utf8"), "someone else's, longer than the copy\n");
    assert.equal(await readFile(join(cwd, "out", "layers-view", "root/new-2"), "utf8"), "n\n");
    assert.equal(again.materialised[0].placed_as.endsWith("etc/hosts"), true);
    // nothing outside $OUT was written
    assert.deepEqual((await filesUnder(join(cwd, W))).filter((f) => !/^(a|b|up)\//.test(f)), []);
    const manifest = JSON.parse(await readFile(join(TOOLS, "container_layers", "manifest.json"), "utf8"));
    assert.deepEqual(manifest.secret_output, { when_args: ["copy"] });
    // hostile paths in copy_paths
    for (const bad of [["../x"], ["/etc/passwd"], ["a/../../x"], [""], [1], "x", ["a\u0000b"], Array.from({ length: 1001 }, () => "etc/hosts")]) {
      const run = await asJob(cwd, { layers, upper, copy: true, copy_paths: bad }, {}, "out3");
      assert.doesNotMatch(run.stderr, /Traceback/);
      assert.equal(JSON.parse(run.stdout).status, "failed", JSON.stringify(bad).slice(0, 40));
    }
  });
});

test("container_layers answers hostile arguments in JSON and never with a traceback", async () => {
  await withCwd(async (cwd) => {
    await put(join(cwd, W, "a"), "f", "x");
    const cases: unknown[] = [{}, [], "x", { layers: "a" }, { layers: [] }, { layers: [1] }, { layers: [""] }, { layers: ["a\u0000"] }, { layers: ["\ud800"] }, { layers: [`${W}/a`], start: "x" },
      { layers: [`${W}/a`], overlay2_root: W }, { overlay2_root: W }, { overlay2_root: W, start: 5 }, { overlay2_root: W, start: "a", upper: "x" }, { layers: [`${W}/a`], max_seconds: 0 },
      { layers: [`${W}/a`], max_seconds: 10 ** 400 }, { layers: [`${W}/a`], limit: -3 }, { layers: [`${W}/a`], path_prefix: "../x" }, { layers: [`${W}/a`], path_prefix: "/etc" },
      { layers: [`${W}/a`], path_prefix: 7 }, { layers: [`${W}/nope`] }, { layers: [`${W}/a/f`] }, { layers: ["x".repeat(300)] }, { layers: [`${W}/a`], upper: 5 }];
    for (const args of cases) {
      const run = await tool(LAYERS, cwd, args);
      assert.doesNotMatch(run.stderr, /Traceback/, JSON.stringify(args).slice(0, 60));
      assert.equal(JSON.parse(run.stdout).status, "failed", JSON.stringify(args).slice(0, 60));
    }
    const deep = spawnSync("python3", [LAYERS], { cwd, input: "[".repeat(100_000), encoding: "utf8" });
    assert.doesNotMatch(deep.stderr, /Traceback/);
    assert.equal(JSON.parse(deep.stdout).status, "failed");
  });
});

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
  test(`container_layers ends on ${signal} with one document and exit 128 plus the signal`, async () => {
    await withCwd(async (cwd) => {
      const big = join(cwd, W, "big");
      await mkdir(big, { recursive: true });
      for (let i = 0; i < 60000; i++) await writeFile(join(big, `f${i}`), "");
      const run = startDetached(LAYERS, cwd, { layers: [`${W}/big`], limit: 5 }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
      await new Promise((r) => setTimeout(r, 300));
      run.signal(signal);
      const code = await Promise.race([run.closed, new Promise<"late">((r) => setTimeout(() => r("late"), 30_000))]);
      if (code === "late") {
        run.killGroup();
        assert.fail(`the tool ignored ${signal}`);
      }
      const num = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 }[signal];
      const docs = run.stdout().trim().split("\n").filter(Boolean);
      assert.equal(docs.length, 1, "exactly one document");
      const doc = JSON.parse(docs[0]);
      // the walk was still going: a last word; if the tool had already answered, it is the answer and exit 0
      if (doc.stopped_by_signal !== undefined) {
        assert.equal(code, 128 + num);
        assert.equal(doc.status, "failed");
      } else {
        assert.equal(code, 0);
      }
      assert.deepEqual((await readdir(join(cwd, "out", "tool-output")).catch(() => [])).filter((n) => n.startsWith(".")), []);
    });
  });
}

test("container_layers' manifest declares what the script reads, carries the script's sha256 and the version PARSER names", async () => {
  const manifest = JSON.parse(await readFile(join(TOOLS, "container_layers", "manifest.json"), "utf8"));
  const script = await readFile(LAYERS);
  assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"));
  assert.match(script.toString("utf8"), new RegExp(`^PARSER = "container_layers/${manifest.version}"$`, "m"));
  assert.match(manifest.description, /`status`.*`status_basis`/);
  for (const key of ["layers", "upper", "overlay2_root", "start", "path_prefix", "copy", "copy_paths", "limit", "max_seconds"]) assert.ok(key in manifest.params, key);
  assert.match(String(script.toString("utf8").match(/^MAX_SECONDS = [0-9.]+/m)), /MAX_SECONDS = 105/);
  assert.ok(105 < manifest.timeout_seconds);
  // the PLACE block is the one the windows tools carry
  const place = (t: string): string => t.slice(t.indexOf("# BEGIN SHARED PLACE"), t.indexOf("# END SHARED PLACE"));
  const windows = await readFile(join(TOOLS, "..", "..", "windows-forensics", "tools", "regkv", "run.py"), "utf8");
  assert.equal(place(script.toString("utf8")), place(windows));
});
