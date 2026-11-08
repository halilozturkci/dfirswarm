/**
 * The Linux pack: container_inventory, against the on-disk shapes the runtimes write: Docker's container directory (config.v2.json,
 * hostconfig.json, <id>-json.log with {"log","stream","time"} lines) and image store (repositories.json, imagedb/content/sha256/<id> with
 * rootfs.diff_ids, layerdb/sha256/<chain id>/{cache-id,size}), containers/storage's JSON lists (Podman) and the CRI log format
 * (`<RFC3339Nano> <stream> <P|F> <text>`) under var/log/pods. Every fixture is built by the test from those shapes, never from the tool's output.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { TOOLS, asJob as plainJob, body, filesUnder, put, refused, rowsOf, startDetached, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const INV = join(TOOLS, "container_inventory", "run.py");
const asJob = (cwd: string, args: unknown, env: Record<string, string> = {}, outName = "out"): ReturnType<typeof plainJob> =>
  plainJob(INV, cwd, args, undefined, { SECRET_OUTPUT: "1", ...env }, outName);
const R = "work/r";
const hex = (n: number, c = "a"): string => c.repeat(64).slice(0, 64).replace(/./g, (_x, i) => ((i + n) % 16).toString(16));
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
const chain = (diffs: string[]): string[] => {
  const out: string[] = [];
  for (const d of diffs) out.push(out.length ? "sha256:" + sha(out[out.length - 1] + " " + d) : d);
  return out;
};
const json = (o: unknown): string => JSON.stringify(o);

async function entries(cwd: string, out: Json): Promise<Json[]> {
  return rowsOf(cwd, out, "entries");
}
async function everything(cwd: string, skip: string[] = []): Promise<string> {
  const parts: string[] = [];
  for (const rel of await filesUnder(join(cwd, "out"))) if (!skip.includes(rel)) parts.push(await readFile(join(cwd, "out", rel), "utf8"));
  return parts.join("\n");
}

const C1 = hex(1), C2 = hex(2), IMG = hex(7);
const DIFFS = ["sha256:" + hex(11), "sha256:" + hex(12), "sha256:" + hex(13)];

/** A Docker data root: two containers on one image whose second layer is missing from layerdb. */
async function docker(cwd: string, extra: { env?: string[]; cmd?: string[]; args?: string[]; labels?: Record<string, string>; binds?: string[] } = {}): Promise<void> {
  const base = join(cwd, R, "var/lib/docker");
  for (const [cid, name, state] of [[C1, "/web", { Running: true, Pid: 4321, ExitCode: 0, StartedAt: "2026-02-14T09:00:00.123456789Z", FinishedAt: "0001-01-01T00:00:00Z" }],
    [C2, "/db", { Running: false, Pid: 0, ExitCode: 137, OOMKilled: true, StartedAt: "2026-02-14T08:00:00Z", FinishedAt: "2026-02-14T08:30:00Z" }]] as const) {
    await put(base, `containers/${cid}/config.v2.json`, json({
      ID: cid, Created: "2026-02-14T07:59:59.5Z", Path: "/entry.sh", Args: extra.args ?? ["--serve", "--port=80"], State: state, Image: "sha256:" + IMG, Name: name, RestartCount: 2, Driver: "overlay2",
      LogPath: `/var/lib/docker/containers/${cid}/${cid}-json.log`,
      Config: { Env: extra.env ?? ["PATH=/usr/bin", "TOKEN=x"], Cmd: extra.cmd ?? ["nginx"], Entrypoint: ["/entry.sh"], Labels: extra.labels ?? { a: "b" }, User: "1000", WorkingDir: "/srv" },
      MountPoints: { "/data": { Source: "/host/data", Destination: "/data", RW: true, Type: "bind" } },
    }));
    await put(base, `containers/${cid}/hostconfig.json`, json({ Privileged: cid === C1, CapAdd: ["SYS_ADMIN"], CapDrop: ["NET_RAW"], Binds: extra.binds ?? ["/host/data:/data:rw"], NetworkMode: "bridge",
      RestartPolicy: { Name: "always" }, SecurityOpt: ["seccomp=unconfined", "label=something"], Devices: [], PortBindings: { "80/tcp": [] }, LogConfig: { Type: "json-file" } }));
  }
  await put(base, `containers/${C1}/${C1}-json.log`, `{"log":"hello\\n","stream":"stdout","time":"2026-02-14T09:00:01.000000001Z"}\n{"log":"bye\\n","stream":"stderr","time":"2026-02-14T09:05:00.5Z"}\nnot a record\n`);
  await put(base, `containers/${C1}/${C1}-json.log.1`, `{"log":"older\\n","stream":"stdout","time":"2026-02-13T09:00:01Z"}\n`);
  const imgRoot = "image/overlay2";
  await put(base, `${imgRoot}/repositories.json`, json({ Repositories: { nginx: { "nginx:latest": "sha256:" + IMG, ["nginx@sha256:" + "0".repeat(64)]: "sha256:" + IMG } } }));
  await put(base, `${imgRoot}/imagedb/content/sha256/${IMG}`, json({ architecture: "amd64", os: "linux", created: "2026-01-01T00:00:00Z", config: { Cmd: ["nginx"], Env: ["A=b"] },
    rootfs: { type: "layers", diff_ids: DIFFS }, history: [{}, {}, {}] }));
  const chains = chain(DIFFS);
  for (const [i, c] of chains.entries()) {
    if (i === 1) continue; // the second layer is missing
    await put(base, `${imgRoot}/layerdb/sha256/${c.replace("sha256:", "")}/cache-id`, hex(30 + i));
    await put(base, `${imgRoot}/layerdb/sha256/${c.replace("sha256:", "")}/size`, String(1000 * (i + 1)));
  }
}

test("container_inventory reads a Docker tree: containers, config locators, lifecycle, mounts, capabilities, logs, images and a missing layer by chain id", async () => {
  await withCwd(async (cwd) => {
    await docker(cwd);
    const out = body(await tool(INV, cwd, { root: R }));
    const rows = await entries(cwd, out);
    const containers = rows.filter((r) => r.kind === "container");
    assert.deepEqual(containers.map((c) => c.container_id).sort(), [C1, C2].sort());
    const web = containers.find((c) => c.container_id === C1) as Json;
    assert.equal(web.config_version, "v2");
    assert.ok(web.config_file.endsWith(`containers/${C1}/config.v2.json`));
    assert.deepEqual([web.name, web.created, web.image_id, web.image_in_imagedb, web.restart_count, web.driver], ["/web", "2026-02-14T07:59:59.5Z", "sha256:" + IMG, true, 2, "overlay2"]);
    assert.equal(web.state.running, true);
    assert.equal(web.state.pid, 4321);
    assert.equal(web.state.startedat, "2026-02-14T09:00:00.123456789Z");
    assert.equal(web.command.args.count, 2);
    assert.equal(web.environment.count, 2);
    assert.equal(web.labels.count, 1);
    assert.deepEqual(web.mounts[0], { destination: { path: "/data" }, source: { path: "/host/data" }, type: "bind", read_write: true });
    assert.equal(web.host_config.privileged, true);
    assert.deepEqual([web.host_config.cap_add, web.host_config.cap_drop], [["SYS_ADMIN"], ["NET_RAW"]]);
    assert.deepEqual(web.host_config.security_opt, ["seccomp=unconfined"], "an option that lowers isolation is shown, a label is a count");
    assert.equal(web.host_config.security_opt_total, 2);
    assert.deepEqual(web.host_config.binds, [{ source: { path: "/host/data" }, destination: { path: "/data" }, mode: "rw" }]);
    assert.equal(web.logs.length, 2);
    const log = web.logs.find((l: Json) => l.rotation === null) as Json;
    assert.deepEqual([log.lines, log.records_in_shape, log.lines_out_of_shape, log.first_time, log.last_time], [3, 2, 1, "2026-02-14T09:00:01.000000001Z", "2026-02-14T09:05:00.5Z"]);
    assert.equal(web.logs.find((l: Json) => l.rotation === 1).first_time, "2026-02-13T09:00:01Z");
    const db = containers.find((c) => c.container_id === C2) as Json;
    assert.deepEqual([db.state.exitcode, db.state.oomkilled], [137, true]);
    // the image and its layers
    const image = rows.find((r) => r.kind === "image") as Json;
    assert.equal(image.image_id, "sha256:" + IMG);
    assert.equal(image.reference_count, 2);
    assert.deepEqual(image.references, ["nginx:latest", null], "a digest reference is not a plain name");
    assert.equal(image.containers_using, 2);
    assert.equal(image.layers, 3);
    assert.equal(image.layers_missing, 1);
    const layers = await rowsOf(cwd, out, "layers");
    const chains = chain(DIFFS);
    assert.deepEqual(layers.map((l) => [l.index, l.chain_id, l.layerdb]), chains.map((c, i) => [i, c, i === 1 ? "missing" : "present"]));
    assert.equal(layers[0].overlay_directory, hex(30));
    assert.equal(layers[2].size_bytes, 3000);
    assert.equal(out.status, "partial");
    assert.match(out.status_basis, /layer\(s\) an image names are not in the layer store/);
    assert.deepEqual([out.images_used_by_containers.distinct_images, out.images_used_by_containers.most_containers_on_one_image], [1, 2]);
    assert.equal(out.layer_summary.missing_or_unlisted, 1);
  });
});

test("container_inventory never prints an environment, a command, an argument, a label, a bind or a log line, and writes the stored ones whole to the sealed text file only", async () => {
  await withCwd(async (cwd) => {
    const canaries = ["CANARYenvA1", "CANARYcmdB2", "CANARYargC3", "CANARYlabelD4", "CANARYbindE5", "CANARYlogF6"];
    const [env, cmd, arg, label, bind, logc] = canaries;
    await docker(cwd, { env: [`SECRET=${env}`], cmd: [cmd], args: [arg], labels: { k: label }, binds: [`/host/${bind}:/data:ro`] });
    await put(join(cwd, R), `var/lib/docker/containers/${C1}/${C1}-json.log`, `{"log":"${logc}\\n","stream":"stdout","time":"2026-02-14T09:00:01Z"}\n`);
    const run = await asJob(cwd, { root: R, write_text: true, limit: 1 });
    const out = body(run);
    const text = await readFile(join(cwd, "out", "container-text.jsonl"), "utf8");
    const answer = run.stdout + run.stderr + (await everything(cwd, ["container-text.jsonl"])) + JSON.stringify(await filesUnder(join(cwd, "out")));
    for (const canary of [env, cmd, arg, label]) assert.ok(!answer.includes(canary), `${canary} is in the answer`);
    assert.ok(!answer.includes(logc), "a log line's text is not in the answer");
    for (const canary of [env, cmd, arg, label, bind]) assert.ok(text.includes(canary), `${canary} is in the text file`);
    assert.ok(!text.includes(logc), "a log's text is not copied");
    assert.equal((await stat(join(cwd, "out", "container-text.jsonl"))).mode & 0o777, 0o600);
    assert.equal(out.text.written, 2);
  });
});

test("container_inventory keeps write_text out of ordinary calls and refuses it, creating nothing, unless the job was run as secret output", async () => {
  await withCwd(async (cwd) => {
    await docker(cwd);
    assert.match(refused(await tool(INV, cwd, { root: R, write_text: true })).error, /write_text is refused outside a job/);
    assert.match(refused(await plainJob(INV, cwd, { root: R, write_text: true })).error, /not run as secret output/);
    assert.deepEqual(await filesUnder(join(cwd, "out")), []);
    const manifest = JSON.parse(await readFile(join(TOOLS, "container_inventory", "manifest.json"), "utf8"));
    assert.deepEqual(manifest.secret_output, { when_args: ["write_text"] });
    body(await asJob(cwd, { root: R, write_text: true }, {}, "out2"));
    assert.match(refused(await asJob(cwd, { root: R, write_text: true }, {}, "out2")).error, /already exists/);
  });
});

test("container_inventory streams a 50 MB json log within its bounds and pages what it lists", async () => {
  await withCwd(async (cwd) => {
    await docker(cwd);
    const line = `{"log":"${"x".repeat(80)}\\n","stream":"stdout","time":"2026-02-14T09:00:01.000000001Z"}\n`;
    const last = `{"log":"last\\n","stream":"stdout","time":"2026-02-14T23:59:59Z"}\n`;
    const big = Buffer.concat([Buffer.from(line.repeat(Math.floor((50 * 1024 * 1024) / line.length))), Buffer.from(last)]);
    await writeFile(join(cwd, R, `var/lib/docker/containers/${C1}/${C1}-json.log`), big);
    const started = Date.now();
    const out = body(await tool(INV, cwd, { root: R, limit: 1 }));
    assert.ok(Date.now() - started < 30_000);
    const row = (await entries(cwd, out)).find((r) => r.container_id === C1) as Json;
    const log = row.logs.find((l: Json) => l.rotation === null);
    assert.equal(log.bytes, big.length);
    assert.equal(log.lines_out_of_shape, 0);
    assert.equal(log.last_time, "2026-02-14T23:59:59Z");
    assert.equal(log.first_time, "2026-02-14T09:00:01.000000001Z");
    assert.equal(out.entries_total >= 3, true);
    assert.equal(out.truncated, true, "one entry inline, all in the paging file");
  });
});

test("container_inventory reads hostile JSON without a traceback: deep nesting, a huge string, a repeated key, a wrong type and a file over the parse limit", async () => {
  await withCwd(async (cwd) => {
    const base = join(cwd, R, "var/lib/docker/containers");
    const ids = [hex(21), hex(22), hex(23), hex(24), hex(25), hex(26)];
    await put(base, `${ids[0]}/config.v2.json`, "[".repeat(100_000) + "]".repeat(100_000));
    await put(base, `${ids[1]}/config.v2.json`, `{"ID":"${ids[1]}","Config":{"Env":["A=${"x".repeat(6 * 1024 * 1024)}"]},"Name":"/big"}`);
    await put(base, `${ids[2]}/config.v2.json`, `{"ID":"${ids[2]}","Name":"/one","Name":"/two","Image":"sha256:${IMG}"}`);
    await put(base, `${ids[3]}/config.v2.json`, json({ ID: ids[3], Config: "not an object", MountPoints: [1], State: 5, RestartCount: "many", Name: 7 }));
    await put(base, `${ids[4]}/config.v2.json`, `{"ID":"${ids[4]}","pad":"${"y".repeat(9 * 1024 * 1024)}"}`);
    await put(base, `${ids[5]}/config.v2.json`, `{"ID":"${ids[5]}","n":${"9".repeat(5000)}}`);
    const out = body(await tool(INV, cwd, { root: R }));
    assert.equal(out.status, "partial");
    const rows = await entries(cwd, out);
    const by = (id: string): Json => rows.find((r) => r.container_id === id) as Json;
    assert.equal(by(ids[0]).config_version, "unreadable");
    // (a parser that reads 100,000 levels without a RecursionError, as the newer interpreters do, reads a list: the file is still unreadable, for the other reason)
    assert.match(by(ids[0]).errors[0], /nested deeper|the top level is not an object/);
    assert.equal(by(ids[1]).environment.count, 1);
    assert.ok(by(ids[1]).environment.bytes > 6 * 1024 * 1024);
    assert.equal(by(ids[2]).name, "/two");
    assert.match(by(ids[2]).errors.join(" "), /1 repeated key/);
    assert.deepEqual([by(ids[3]).restart_count, by(ids[3]).state, by(ids[3]).name], [null, null, null]);
    assert.match(by(ids[3]).errors.join(" "), /Config is not an object/);
    assert.match(by(ids[4]).errors[0], /larger than the 8388608/);
    assert.equal(by(ids[5]).config_version, "unreadable", "an integer past the interpreter's digit limit is a parse failure, named");
    assert.equal(out.read_errors.total >= 3, true);
  });
});

test("container_inventory lists a container directory with the older config.json only, and a directory that is not an id, as unsupported", async () => {
  await withCwd(async (cwd) => {
    const base = join(cwd, R, "var/lib/docker/containers");
    await put(base, `${hex(31)}/config.json`, "{}");
    await put(base, "not-an-id/config.v2.json", "{}");
    const out = body(await tool(INV, cwd, { root: R }));
    assert.equal(out.unsupported.total, 2);
    assert.match(out.unsupported.shown.map((u: Json) => u.why).join(" "), /config\.json is the older layout/);
    assert.equal((await entries(cwd, out)).find((r) => r.container_id === hex(31)).config_version, "unsupported");
    assert.equal(out.status, "partial");
  });
});

test("container_inventory reads a Podman rootless store and a Kubernetes node's CRI logs, each on its own shape, and lists containerd's bolt database as unsupported", async () => {
  await withCwd(async (cwd) => {
    const store = join(cwd, R, "home/alice/.local/share/containers/storage");
    const L1 = hex(41), L2 = hex(42), PI = hex(43), PC = hex(44);
    await put(store, "overlay-layers/layers.json", json([{ id: L1, created: "2026-02-01T00:00:00Z", "diff-size": 5 }, { id: L2, parent: L1, created: "2026-02-01T00:01:00Z" }, { id: hex(45), parent: hex(99) }]));
    await put(store, "overlay-images/images.json", json([{ id: PI, names: ["docker.io/library/alpine:latest"], layer: L2, created: "2026-02-01T00:02:00Z" }]));
    await put(store, "overlay-containers/containers.json", json([{ id: PC, names: ["web"], image: PI, layer: L2, created: "2026-02-02T00:00:00Z", metadata: json({ "image-name": "alpine", name: "web" }) }]));
    await put(store, `overlay-containers/${PC}/userdata/config.json`, json({ process: { args: ["sh", "-c", "run"], env: ["K=V"] } }));
    const pods = join(cwd, R, "var/log/pods/default_web-0_" + "1234abcd-1111-2222-3333-444455556666/app");
    await put(pods, "0.log", "2026-02-14T09:00:00.000000001Z stdout F first\n2026-02-14T09:00:01Z stderr P part\n2026-02-14T09:00:01Z stderr F rest\nbad\n");
    await put(pods, "1.log", "2026-02-14T10:00:00Z stdout F again\n");
    await put(join(cwd, R), "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db", Buffer.alloc(4096));
    const out = body(await tool(INV, cwd, { root: R }));
    const rows = await entries(cwd, out);
    const ctr = rows.find((r) => r.runtime === "podman" && r.kind === "container") as Json;
    assert.deepEqual([ctr.container_id, ctr.names, ctr.image_id, ctr.layer_listed, ctr.owner_home, ctr.metadata.parsed], [PC, ["web"], PI, true, "home/alice", true]);
    assert.equal(ctr.command.args.count, 3);
    assert.equal(ctr.environment.count, 1);
    const img = rows.find((r) => r.runtime === "podman" && r.kind === "image") as Json;
    assert.deepEqual([img.image_id, img.references, img.top_layer_listed], [PI, ["docker.io/library/alpine:latest"], true]);
    const layers = (await rowsOf(cwd, out, "layers")).filter((l) => l.runtime === "podman");
    assert.equal(layers.length, 3);
    assert.equal(layers.filter((l) => l.parent_listed === false).length, 1, "a layer whose parent is not in the list");
    const pod = rows.find((r) => r.kind === "pod_container") as Json;
    assert.deepEqual([pod.namespace, pod.pod, pod.pod_uid, pod.container, pod.restarts_seen], ["default", "web-0", "1234abcd-1111-2222-3333-444455556666", "app", 2]);
    const log0 = pod.logs.find((l: Json) => l.file.endsWith("0.log")) as Json;
    assert.deepEqual([log0.lines, log0.records_in_shape, log0.lines_out_of_shape, log0.first_time, log0.last_time], [4, 3, 1, "2026-02-14T09:00:00.000000001Z", "2026-02-14T09:00:01Z"]);
    assert.match(pod.node_scope, /control plane/);
    const bolt = rows.find((r) => r.runtime === "containerd") as Json;
    assert.equal(bolt.state, "unsupported");
    assert.equal(out.unsupported.shown.some((u: Json) => u.runtime === "containerd"), true);
    assert.match(out.containerd, /unsupported/);
    // the runtimes can be asked for one at a time
    const only = body(await tool(INV, cwd, { root: R, runtimes: ["kubernetes"] }));
    assert.deepEqual(Object.keys(only.by_kind), ["pod_container"]);
  });
});

test("container_inventory does not follow a link, reads a data-root named by storage_roots, and refuses one outside the root", async () => {
  await withCwd(async (cwd) => {
    await docker(cwd);
    await mkdir(join(cwd, "work", "elsewhere"), { recursive: true });
    await mkdir(join(cwd, R, "var/log"), { recursive: true });
    await symlink("../../elsewhere", join(cwd, R, "var/log/pods"));
    const out = body(await tool(INV, cwd, { root: R }));
    assert.ok(out.locations.shown.some((l: Json) => l.path === "var/log/pods" && /not followed/.test(l.state)));
    // the same tree under an unusual data-root
    await mkdir(join(cwd, R, "data"), { recursive: true });
    const run = spawnSync("cp", ["-r", join(cwd, R, "var/lib/docker"), join(cwd, R, "data/docker2")]);
    assert.equal(run.status, 0);
    const moved = body(await tool(INV, cwd, { root: R, runtimes: ["containerd"], storage_roots: ["data/docker2"] }));
    assert.equal(moved.by_kind.container, 2);
    assert.match(refused(await tool(INV, cwd, { root: R, storage_roots: ["/etc"] })).error, /inside the root/);
  });
});

test("container_inventory answers hostile arguments in JSON, refuses a link or a disk image as the root, and gives JSON for a full disk", async () => {
  await withCwd(async (cwd) => {
    await docker(cwd);
    const cases: unknown[] = [{}, [], "x", { root: 5 }, { root: "" }, { root: "a\u0000b" }, { root: "\ud800" }, { root: R, runtimes: "docker" }, { root: R, runtimes: ["nope"] }, { root: R, runtimes: [] },
      { root: R, storage_roots: "x" }, { root: R, storage_roots: [1] }, { root: R, limit: 0 }, { root: R, max_seconds: -1 }, { root: R, max_seconds: 10 ** 400 }, { root: R, write_text: "yes" }, { root: "work/none" }];
    for (const args of cases) {
      const run = await tool(INV, cwd, args);
      assert.doesNotMatch(run.stderr, /Traceback/, JSON.stringify(args).slice(0, 60));
      assert.equal(JSON.parse(run.stdout).status, "failed", JSON.stringify(args).slice(0, 60));
    }
    await symlink("r", join(cwd, "work", "rlink"));
    assert.match(refused(await tool(INV, cwd, { root: "work/rlink" })).error, /not a link/);
    await put(cwd, "work/disk.dd", Buffer.concat([Buffer.from("EVF\x09\x0d\x0a\xff\x00", "latin1"), Buffer.alloc(600)]));
    assert.match(refused(await tool(INV, cwd, { root: "work/disk.dd" })).error, /disk image|not a link/);
    const deep = spawnSync("python3", [INV], { cwd, input: "[".repeat(100_000), encoding: "utf8" });
    assert.doesNotMatch(deep.stderr, /Traceback/);
    assert.equal(JSON.parse(deep.stdout).status, "failed");
    await mkdir(join(cwd, "out"), { recursive: true });
    const env = { ...process.env, AGENT_ID: "s1", JOB_ID: "j000001", OUT: join(cwd, "out"), SECRET_OUTPUT: "1" };
    const full = spawnSync("bash", ["-c", `ulimit -f 4; exec python3 ${INV}`], { cwd, input: JSON.stringify({ root: R, limit: 1, write_text: true }), encoding: "utf8", env });
    assert.doesNotMatch(full.stderr, /Traceback/);
    assert.equal(JSON.parse(full.stdout).status, "failed");
  });
});

test("container_inventory honours max_seconds on a large store and names the place it stopped in", async () => {
  await withCwd(async (cwd) => {
    const base = join(cwd, R, "var/lib/docker/containers");
    await mkdir(base, { recursive: true });
    for (let i = 0; i < 6000; i++) {
      const id = (i.toString(16).padStart(8, "0")).repeat(8);
      await mkdir(join(base, id), { recursive: true });
      await writeFile(join(base, id, "config.v2.json"), json({ ID: id, Name: "/n", Config: { Env: ["A=b"] } }));
    }
    const started = Date.now();
    const out = body(await tool(INV, cwd, { root: R, max_seconds: 0.05, limit: 3 }));
    const took = (Date.now() - started) / 1000;
    assert.ok(took < 5, `took ${took}s`);
    assert.equal(out.status, "partial");
    assert.match(out.stopped_because, /max_seconds/);
    assert.ok(out.locations.shown.some((l: Json) => /stopped/.test(l.state)));
  });
});

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
  test(`container_inventory ends on ${signal} with one last word naming the paging file it had begun`, async () => {
    await withCwd(async (cwd) => {
      const base = join(cwd, R, "var/lib/docker/containers");
      await mkdir(base, { recursive: true });
      for (let i = 0; i < 20000; i++) {
        const id = (i.toString(16).padStart(8, "0")).repeat(8);
        await mkdir(join(base, id), { recursive: true });
        await writeFile(join(base, id, "config.v2.json"), `{"ID":"${id}","Name":"/n"}`);
      }
      await mkdir(join(cwd, "out", "tool-output"), { recursive: true });
      const run = startDetached(INV, cwd, { root: R, limit: 3 }, { JOB_ID: "j000001", OUT: join(cwd, "out") });
      const until = Date.now() + 90_000;
      for (;;) {
        const names = await readdir(join(cwd, "out", "tool-output")).catch(() => [] as string[]);
        if (names.some((n) => n.startsWith("."))) break;
        if (Date.now() > until) {
          run.killGroup();
          assert.fail("the tool never began a paging file");
        }
        await new Promise((r) => setTimeout(r, 30));
      }
      run.signal(signal);
      const code = await Promise.race([run.closed, new Promise<"late">((r) => setTimeout(() => r("late"), 30_000))]);
      if (code === "late") {
        run.killGroup();
        assert.fail(`the tool ignored ${signal}`);
      }
      const num = { SIGTERM: 15, SIGINT: 2, SIGHUP: 1 }[signal];
      assert.equal(code, 128 + num);
      const docs = run.stdout().trim().split("\n");
      assert.equal(docs.length, 1);
      const word = JSON.parse(docs[0]);
      assert.deepEqual([word.status, word.stopped_by_signal], ["failed", num]);
      assert.deepEqual((await readdir(join(cwd, "out", "tool-output"))).filter((n) => n.startsWith(".")), []);
      assert.ok(word.paging_files_kept.entries);
    });
  });
}

test("container_inventory's manifest declares what the script reads, carries the script's sha256 and the version PARSER names", async () => {
  const manifest = JSON.parse(await readFile(join(TOOLS, "container_inventory", "manifest.json"), "utf8"));
  const script = await readFile(INV);
  assert.equal(manifest.sha256, createHash("sha256").update(script).digest("hex"));
  assert.match(script.toString("utf8"), new RegExp(`^PARSER = "container_inventory/${manifest.version}"$`, "m"));
  assert.match(manifest.description, /`status`.*`status_basis`/);
  for (const key of ["root", "runtimes", "storage_roots", "limit", "max_seconds", "write_text"]) assert.ok(key in manifest.params, key);
  assert.match(String(script.toString("utf8").match(/^MAX_SECONDS = [0-9.]+/m)), /MAX_SECONDS = 105/);
  assert.ok(105 < manifest.timeout_seconds);
});
