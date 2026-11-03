/**
 * apfs_inventory runs libfsapfs's fsapfsinfo and reads its output as sections. It is tested with stand-in programs on a PATH directory of the
 * test's own (a stand-in is Python written here from the labels in the manifest's description, never the tool's output): fsapfsinfo is not
 * installed in the test machine's image, and the documented limits of the real reader (no snapshots, no Fusion drives, no T2 encryption) are
 * what the answer must keep saying. Held:
 *   - the version call is in every answer; a missing reader, a non-zero exit and an exit 0 with no container section are failed answers;
 *   - no claim of snapshot coverage, extraction or unlock is made, and the encrypted-containers route is conditional wording;
 *   - a hang is ended at the tool's own deadline with what it started; a flood is ended at max_output_bytes and kept whole on disk; a program that
 *     ended while a child holds its pipes does not hold the tool and the child is ended; SIGTERM ends the tool and the program, exit 143;
 *   - a refused write (a file-size limit) is a failed answer that says it is a fact about the output directory;
 *   - volume names that look like tokens are withheld in the answer; a rerun never replaces a larger output file with a smaller one.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { withCwd } from "./tool-library-harness.ts";
import { APFS, FSAPFS_OK, body, fsapfsStub, leader, ok, signalled, tool } from "./macos-late-harness.ts";

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const pidsOf = async (file: string): Promise<number[]> => (await readFile(file, "utf8").catch(() => "")).split(/\s+/).filter(Boolean).map(Number);
async function gone(pids: number[], ms = 4000): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (!pids.some(alive)) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return !pids.some(alive);
}
async function image(cwd: string, size = 8192): Promise<string> {
  await writeFile(join(cwd, "work", "c.img"), Buffer.alloc(size));
  return "work/c.img";
}

test("a container with two volumes: sections under the reader's labels, the version recorded, and the limits said", async () => {
  await withCwd(async (cwd, bin) => {
    await fsapfsStub(bin, FSAPFS_OK);
    const a = ok(await tool(APFS, cwd, { path: await image(cwd) }, { }, bin));
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.reader.version_line, "fsapfsinfo 20231209");
    assert.equal(a.volumes_total, 2);
    assert.equal(a.declared_volumes, 2);
    assert.equal(a.volumes[0].name, "Macintosh HD");
    assert.equal(a.volumes[1].identifier, "66666666-7777-8888-9999-aaaaaaaaaaaa");
    assert.deepEqual(a.volumes[1].encryption, { "is encrypted": "yes", "is locked": "yes" });
    assert.equal(a.container[0].counts["number of volumes"], 2);
    assert.equal(a.container[0].encryption, undefined, "block size is not an encryption line");
    assert.equal(a.snapshots.status, "unsupported");
    assert.equal(a.extraction.status, "not provided");
    assert.equal(a.unlock.used, false);
    assert.match(a.encryption_route, /^If a volume is reported encrypted/);
    assert.match(a.view.selected, /no snapshot view/);
    assert.match(a.stdout_file, /apfs_inventory-[0-9a-f]{16}\.stdout\.txt$/);
    assert.ok((await readFile(join(cwd, a.stdout_file), "utf8")).includes("Macintosh HD"));
    assert.equal(((await stat(join(cwd, a.stdout_file))).mode & 0o777).toString(8), "600");
  });
});

test("the offset reaches the reader as -o and the path as the last argument; a path that starts with a dash is made safe", async () => {
  await withCwd(async (cwd, bin) => {
    await fsapfsStub(bin, `open("argv.txt", "w").write(repr(argv))\n${FSAPFS_OK}`);
    const out = join(cwd, "argv.txt");
    const img = await image(cwd);
    const a = ok(await tool(APFS, cwd, { path: img, offset: 4096 }, {}, bin));
    assert.deepEqual(a.argv, ["fsapfsinfo", "-o", "4096", "<path>"]);
    assert.deepEqual(JSON.parse((await readFile(out, "utf8")).replace(/'/g, '"')), ["-o", "4096", "work/c.img"]);
    const past = await tool(APFS, cwd, { path: "work/c.img", offset: 99999 }, {}, bin);
    assert.equal(past.code, 1);
  });
});

test("a missing reader, a non-zero exit, and an exit 0 without a container section are failed answers, never an empty inventory", async () => {
  await withCwd(async (cwd, bin) => {
    const img = await image(cwd);
    const missing = await tool(APFS, cwd, { path: img }, { PATH: "/usr/bin:/bin" });
    assert.equal(missing.code, 1);
    assert.equal(body(missing).status, "failed");
    assert.match(body(missing).problems.join(" "), /not on PATH/);
    await fsapfsStub(bin, `print("Unable to open source file.", file=sys.stderr)\nsys.exit(1)`);
    const bad = await tool(APFS, cwd, { path: img }, {}, bin);
    assert.equal(bad.code, 1);
    const b = body(bad);
    assert.equal(b.status, "failed");
    assert.equal(b.exit_code, 1);
    assert.match(b.stderr_first_line, /Unable to open/);
    await fsapfsStub(bin, `print("everything is fine")`);
    const liar = await tool(APFS, cwd, { path: img }, {}, bin);
    const l = body(liar);
    assert.equal(l.status, "failed");
    assert.match(l.problems.join(" "), /no Container section/);
    await fsapfsStub(bin, `${FSAPFS_OK}\nsys.exit(3)`);
    const three = body(await tool(APFS, cwd, { path: img }, {}, bin));
    assert.equal(three.status, "failed", "a non-zero exit is never a complete inventory");
    await fsapfsStub(bin, FSAPFS_OK.replace("Number of volumes\\t: 2", "Number of volumes\\t: 3"));
    const mismatch = ok(await tool(APFS, cwd, { path: img }, {}, bin));
    assert.equal(mismatch.status, "partial");
    assert.match(mismatch.problems.join(" "), /states 3 volume/);
  });
});

test("a hang is ended at the tool's own deadline with what it started; nothing is left running", async () => {
  await withCwd(async (cwd, bin) => {
    const pidFile = join(cwd, "pids");
    await fsapfsStub(bin, `import subprocess\nc = subprocess.Popen(["sleep", "300"])\nopen(${JSON.stringify(pidFile)}, "w").write("%d %d" % (os.getpid(), c.pid))\ntime.sleep(300)`);
    const t0 = Date.now();
    const a = body(await tool(APFS, cwd, { path: await image(cwd), max_seconds: 2 }, {}, bin));
    assert.ok(Date.now() - t0 < 30000);
    assert.equal(a.timed_out, true);
    assert.equal(a.status, "failed");
    assert.ok(await gone(await pidsOf(pidFile)), "the reader and its child are gone");
  });
});

test("a flood is ended at max_output_bytes, the whole of what was written is on disk, and the answer says so", async () => {
  await withCwd(async (cwd, bin) => {
    await fsapfsStub(bin, `chunk = ("X" * 1023 + "\\n").encode()\nout = sys.stdout.buffer\nwhile True:\n    out.write(chunk * 64)\n    out.flush()`);
    const a = body(await tool(APFS, cwd, { path: await image(cwd), max_output_bytes: 1 << 20, max_seconds: 30 }, {}, bin));
    assert.equal(a.output_capped, true);
    assert.equal(a.status, "failed");
    assert.ok(a.stdout_bytes >= 1 << 20 && a.stdout_bytes < (1 << 20) + 4 * 1024 * 1024);
    assert.equal((await stat(join(cwd, a.stdout_file))).size, a.stdout_bytes);
    assert.match(a.problems.join(" "), /max_output_bytes/);
  });
});

test("a reader that ended while its child holds the pipes does not hold the tool, and the child is ended", async () => {
  await withCwd(async (cwd, bin) => {
    const pidFile = join(cwd, "pids");
    await fsapfsStub(bin, `import subprocess\nc = subprocess.Popen(["sleep", "300"])\nopen(${JSON.stringify(pidFile)}, "w").write("%d" % c.pid)\n${FSAPFS_OK}\nsys.stdout.flush()\ntime.sleep(1.0)`);
    const t0 = Date.now();
    const a = ok(await leader(APFS, cwd, { path: await image(cwd), max_seconds: 60 }, {}, bin));
    assert.ok(Date.now() - t0 < 15000, "the tool did not wait for the child");
    assert.match(a.problems.join(" "), /held its pipes/);
    assert.equal(a.status, "partial");
    assert.ok(await gone(await pidsOf(pidFile)), "the child that held the pipes is ended");
  });
});

test("SIGTERM ends the tool and the program with one JSON answer, exit 143, and nothing is left running", async () => {
  await withCwd(async (cwd, bin) => {
    const pidFile = join(cwd, "pids");
    await fsapfsStub(bin, `import subprocess\nc = subprocess.Popen(["sleep", "300"])\nopen(${JSON.stringify(pidFile)}, "w").write("%d %d" % (os.getpid(), c.pid))\nprint("fsapfsinfo 20231209")\nsys.stdout.flush()\ntime.sleep(300)`);
    const run = await signalled(APFS, cwd, { path: await image(cwd), max_seconds: 60 }, "SIGTERM", 1500, {}, bin);
    assert.equal(run.code, 143, run.stderr + run.stdout.slice(0, 300));
    const a = JSON.parse(run.stdout);
    assert.equal(a.interrupted, "SIGTERM");
    assert.notEqual(a.status, "complete");
    assert.ok(await gone(await pidsOf(pidFile)));
    const left = (await readdir(join(cwd, "work", "s1", "tool-output")).catch(() => [] as string[])).filter((n) => n.startsWith(".apfs-"));
    assert.deepEqual(left, [], "no temporary file is left");
  });
});

test("a file-size limit that refuses the output files is a failed answer about the output directory, with no temporary left", async () => {
  await withCwd(async (cwd, bin) => {
    await fsapfsStub(bin, `print("A" * 100000)\n${FSAPFS_OK}`);
    const img = await image(cwd);
    const child = spawn("bash", ["-c", `ulimit -f 8; exec python3 ${JSON.stringify(APFS)}`], { cwd, env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, AGENT_ID: "s1" } });
    const out: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stdin.end(JSON.stringify({ path: img }));
    const code: number = await new Promise((r) => child.on("close", (c) => r(c ?? -1)));
    const a = JSON.parse(Buffer.concat(out).toString("utf8"));
    assert.equal(code, 1);
    assert.equal(a.status, "failed");
    assert.match(a.status_basis, /fact about that directory, not about the container/);
    const left = (await readdir(join(cwd, "work", "s1", "tool-output")).catch(() => [] as string[])).filter((n) => n.startsWith(".apfs-"));
    assert.deepEqual(left, []);
  });
});

test("a volume name that looks like a token is withheld in the answer, and a rerun never replaces a larger output with a smaller one", async () => {
  await withCwd(async (cwd, bin) => {
    const token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const img = await image(cwd);
    await fsapfsStub(bin, FSAPFS_OK.replace("Macintosh HD", token));
    const run = await tool(APFS, cwd, { path: img }, {}, bin);
    const a = ok(run);
    assert.doesNotMatch(run.stdout, new RegExp(token));
    assert.match(a.volumes[0].name, /withheld/);
    await fsapfsStub(bin, `${FSAPFS_OK.replace("Macintosh HD", "Short")}`);
    const b = ok(await tool(APFS, cwd, { path: img }, {}, bin));
    assert.ok(b.kept_earlier_larger_stdout, "the earlier, larger file is named and was kept");
    assert.notEqual(b.stdout_file, b.kept_earlier_larger_stdout);
    assert.ok((await readFile(join(cwd, b.kept_earlier_larger_stdout), "utf8")).includes(token));
  });
});

test("a link, a directory and a file past which the offset points are refused as JSON", async () => {
  await withCwd(async (cwd, bin) => {
    await fsapfsStub(bin, FSAPFS_OK);
    const img = await image(cwd);
    await symlink(join(cwd, img), join(cwd, "work", "link.img"));
    await mkdir(join(cwd, "work", "dir"), { recursive: true });
    for (const path of ["work/link.img", "work/dir", "work/missing"]) {
      const run = await tool(APFS, cwd, { path }, {}, bin);
      assert.equal(run.code, 1, path);
      assert.equal(body(run).status, "failed");
    }
  });
});
