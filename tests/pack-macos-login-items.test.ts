/**
 * macos_login_items resolves a background-item store (an NSKeyedArchiver graph) with the path of references behind each field. Held here with
 * keyed archives built by plistlib from the encoding rules (a root NSDictionary of NS.keys/NS.objects, NSArray, items as class instances whose
 * properties are references), never from the tool's output:
 *   - fields, reference_path and via_objects; the dictionary key an item sits under; NSURL, NSUUID, NSDate resolved; data by presence and length only;
 *   - dangling references, a cycle, a self-reference, a very deep chain and a graph with exponential sharing all end in JSON, bounded, with rows saying why;
 *   - a store that is not a keyed archive, or has no item, is named and partial, never an empty complete answer;
 *   - canaries in property names and values and in bookmark data (a path inside a bookmark is never in the answer);
 *   - a FIFO and a symlink named like a store are not opened or followed; counts equal the file; SIGTERM ends with one answer.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { withCwd } from "./tool-library-harness.ts";
import { BTM, btmFile, everything, ok, signalled, storeSpec, tool } from "./macos-late-harness.ts";

const ITEM = { uuid: "item-uuid", name: "Helper", executablePath: "/Applications/Helper.app/Contents/MacOS/Helper", teamIdentifier: "EQHXZ8M8AV", bundleIdentifier: "com.example.helper", disposition: 3, type: 8, parentIdentifier: "com.example.parent", developerName: "Example Inc." };

test("an item is resolved with every property under its archive name, the path of references, and the key it sits under", async () => {
  await withCwd(async (cwd) => {
    const file = await btmFile(cwd, "BackgroundItems-v8.btm", storeSpec([ITEM, { ...ITEM, name: "Second", bundleIdentifier: "com.example.second", disposition: 2 }]));
    const a = ok(await tool(BTM, cwd, { path: file }));
    assert.equal(a.status, "complete", a.status_basis + JSON.stringify(a.problems));
    assert.equal(a.entry_count, 2);
    const item = a.entries[0];
    assert.equal(item.row_type, "item");
    assert.equal(item.class, "Item");
    assert.equal(item.container_key, "itemsByUserIdentifier");
    assert.equal(item.fields.executablePath.value, ITEM.executablePath);
    assert.equal(item.fields.teamIdentifier.value, "EQHXZ8M8AV");
    assert.equal(item.fields.disposition.value, 3, "the state is the archive's raw number");
    assert.ok(item.fields.executablePath.reference_path.at(-1).endsWith(".executablePath"));
    assert.equal(item.fields.executablePath.reference_path[0], "$top.root");
    assert.ok(item.fields.executablePath.via_objects.length >= 1);
    assert.deepEqual(item.roles.state.sort(), ["disposition", "type"]);
    assert.ok(item.roles.team_identifier && item.roles.bundle_identifier && item.roles.developer_name && item.roles.parent);
    assert.match(item.notes, /not evidence that the item ran/);
    assert.match(a.note, /registered item is not a running one/);
  });
});

test("NSURL, NSUUID and NSDate are resolved as the keyed-archive rules say; data is present and its length, never its bytes", async () => {
  await withCwd(async (cwd) => {
    const canary = "BOOKMARKPATHCANARY/private/secret";
    const spec = storeSpec([{ name: "x", bundleIdentifier: "com.example.x" }]);
    const objs = spec.objects as unknown[];
    const item = objs.find((o) => typeof o === "object" && o !== null && "bundleIdentifier" in (o as object)) as Record<string, unknown>;
    const at = (v: unknown): number => (objs.push(v), objs.length - 1);
    const cNSURL = at({ $classname: "NSURL", $classes: ["NSURL", "NSObject"] });
    const cUUID = at({ $classname: "NSUUID", $classes: ["NSUUID", "NSObject"] });
    const cDate = at({ $classname: "NSDate", $classes: ["NSDate", "NSObject"] });
    const cData = at({ $classname: "NSData", $classes: ["NSData", "NSObject"] });
    const rel = at("file:///Applications/Helper.app/");
    item.url = { uid: at({ $class: { uid: cNSURL }, "NS.relative": { uid: rel }, "NS.base": { uid: 0 } }) };
    item.uuid = { uid: at({ $class: { uid: cUUID }, "NS.uuidbytes": { bytes: "000102030405060708090a0b0c0d0e0f" } }) };
    item.generation = { uid: at({ $class: { uid: cDate }, "NS.time": 700000000.5 }) };
    item.bookmark = { uid: at({ $class: { uid: cData }, "NS.data": { bytes: Buffer.concat([Buffer.from("book"), Buffer.from(canary)]).toString("hex") } }) };
    const run = await tool(BTM, cwd, { path: await btmFile(cwd, "evidence/backgrounditems.btm", spec) });
    const a = ok(run);
    const f = a.entries[0].fields;
    assert.deepEqual(f.url.value._nsurl, { relative: "file:///Applications/Helper.app/", base: null });
    assert.equal(f.uuid.value._uuid, "00010203-0405-0607-0809-0a0b0c0d0e0f");
    assert.deepEqual(f.generation.value._date, { time_raw: 700000000.5, utc: "2023-03-08T20:26:40.500000Z" });
    assert.deepEqual(f.bookmark.value._data, { present: true, bytes: 4 + canary.length, magic: "book" });
    const text = await everything(cwd, run.stdout);
    assert.doesNotMatch(text, /BOOKMARKPATHCANARY/);
    assert.doesNotMatch(text, new RegExp(Buffer.from(canary).toString("hex")));
  });
});

test("a dangling reference, a cycle and a self-reference are rows with a reason, and the answer is partial and JSON", async () => {
  await withCwd(async (cwd) => {
    const spec = storeSpec([{ name: "a", bundleIdentifier: "com.example.a" }]);
    const objs = spec.objects as unknown[];
    const item = objs.find((o) => typeof o === "object" && o !== null && "bundleIdentifier" in (o as object)) as Record<string, unknown>;
    const idx = objs.indexOf(item);
    item.executablePath = { uid: 9999 };
    item.parentIdentifier = { uid: idx };
    const selfDict = objs.length;
    objs.push({ "NS.objects": [{ uid: selfDict }], $class: { uid: 2 } });
    item.container = { uid: selfDict };
    const a = ok(await tool(BTM, cwd, { path: await btmFile(cwd, "BackgroundItems-v4.btm", spec) }));
    assert.equal(a.status, "partial");
    const reasons = a.entries.filter((e: { row_type: string }) => e.row_type === "unresolved").map((e: { reason: string }) => e.reason).join("\n");
    assert.match(reasons, /does not have/);
    assert.match(reasons, /its own ancestor/);
    assert.equal(a.files[0].state, "parsed in part");
  });
});

test("a chain of 20,000 nested objects and a graph that shares one object a million ways end in JSON within bounds", async () => {
  await withCwd(async (cwd) => {
    const objects: unknown[] = ["$null"];
    const n = 20000;
    for (let i = 0; i < n; i++) objects.push({ $class: { uid: n + 1 }, "NS.objects": [{ uid: i + 2 }] });
    objects.push({ $classname: "NSArray", $classes: ["NSArray"] });
    objects.push("end");
    const deep = await btmFile(cwd, "deep.btm", { objects, top: { root: { uid: 1 } } });
    const t0 = Date.now();
    const a = ok(await tool(BTM, cwd, { path: deep }));
    assert.ok(Date.now() - t0 < 30000);
    assert.equal(a.status, "partial");
    assert.ok(a.entries.some((e: { reason?: string }) => /depth bound/.test(e.reason ?? "")));
    // exponential sharing: 40 levels, each holds the next one twice
    const shared: unknown[] = ["$null", { $class: { uid: 43 }, name: { uid: 42 }, bundleIdentifier: { uid: 42 }, "x": { uid: 2 } }];
    for (let i = 2; i < 41; i++) shared.push({ $class: { uid: 43 }, "NS.objects": [{ uid: i + 1 }, { uid: i + 1 }] });
    shared.push({ $class: { uid: 43 }, "NS.objects": [] });
    shared.push("leaf");
    shared.push({ $classname: "NSArray", $classes: ["NSArray"] });
    const t1 = Date.now();
    const b = ok(await tool(BTM, cwd, { path: await btmFile(cwd, "shared.btm", { objects: shared, top: { root: { uid: 1 } } }) }));
    assert.ok(Date.now() - t1 < 30000, "linear in objects, not in paths");
    assert.ok(["complete", "partial"].includes(b.status));
  });
});

test("max_nodes bounds a file: the rest is not followed, the file is named, the answer is partial", async () => {
  await withCwd(async (cwd) => {
    const items = Array.from({ length: 50 }, (_, i) => ({ name: `n${i}`, bundleIdentifier: `com.example.n${i}` }));
    const a = ok(await tool(BTM, cwd, { path: await btmFile(cwd, "BackgroundItems-v4.btm", storeSpec(items)), max_nodes: 40 }));
    assert.equal(a.status, "partial");
    assert.match(a.files[0].reason, /node bound/);
  });
});

test("a plist that is not a keyed archive, a store with no item, and a file that is not a plist are named, and never an empty complete answer", async () => {
  await withCwd(async (cwd) => {
    await btmFile(cwd, "d/backgrounditems.btm", { plain: { a: 1 }, objects: [], top: {} });
    await btmFile(cwd, "d/BackgroundItems-v3.btm", { objects: ["$null", "text"], top: { root: { uid: 1 } } });
    await writeFile(join(cwd, "work", "d", "BackgroundItems-v1.btm"), "not a plist at all");
    const a = ok(await tool(BTM, cwd, { path: "work/d" }));
    assert.equal(a.status, "partial");
    assert.equal(a.entry_count, 0);
    const states = a.files.map((f: { state: string }) => f.state).sort();
    assert.deepEqual(states, ["failed", "unsupported", "unsupported"]);
    await mkdir(join(cwd, "work", "empty"), { recursive: true });
    const none = ok(await tool(BTM, cwd, { path: "work/empty" }));
    assert.equal(none.status, "partial");
    assert.match(none.problems.join(" "), /no background-item store/);
  });
});

test("a canary in a property name and in a value is judged by the boundary; a token-shaped value is withheld", async () => {
  await withCwd(async (cwd) => {
    const token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    const run = await tool(BTM, cwd, { path: await btmFile(cwd, "evidence/BackgroundItems-v4.btm", storeSpec([{ ...ITEM, [token]: "x", name: token }])) });
    const a = ok(run);
    const text = await everything(cwd, run.stdout);
    assert.doesNotMatch(text.replace(/work\/[^"\n]*/g, ""), new RegExp(token));
    assert.match(JSON.stringify(a.entries[0].fields.name.value), /withheld/);
  });
});

test("a FIFO and a link named like a store are not opened or followed; the counts equal the file", async () => {
  await withCwd(async (cwd) => {
    await btmFile(cwd, "d/BackgroundItems-v4.btm", storeSpec([ITEM]));
    assert.equal(spawnSync("mkfifo", [join(cwd, "work", "d", "backgrounditems.btm")]).status, 0);
    await symlink(join(cwd, "work", "d", "BackgroundItems-v4.btm"), join(cwd, "work", "d", "BackgroundItems-v9.btm"));
    const t0 = Date.now();
    const a = ok(await tool(BTM, cwd, { path: "work/d", out_file: "work/rows.jsonl" }));
    assert.ok(Date.now() - t0 < 20000);
    assert.equal(a.walk.links_not_followed, 1);
    assert.equal(a.walk.not_regular_files, 1);
    assert.equal(a.status, "partial");
    assert.equal((await readFile(join(cwd, "work", "rows.jsonl"), "utf8")).split("\n").filter(Boolean).length, a.entry_count);
  });
});

test("SIGTERM ends the sweep with one JSON answer, exit 143, and the rows written are whole", async () => {
  await withCwd(async (cwd) => {
    const items = Array.from({ length: 4000 }, (_, i) => ({ ...ITEM, name: `n${i}`, bundleIdentifier: `com.example.n${i}` }));
    const file = await btmFile(cwd, "BackgroundItems-v4.btm", storeSpec(items));
    const run = await signalled(BTM, cwd, { path: file, out_file: "work/rows.jsonl" }, "SIGTERM", 1200);
    assert.ok(run.code === 143 || run.code === 0, run.stderr);
    const a = JSON.parse(run.stdout);
    if (run.code === 143) assert.equal(a.interrupted, "SIGTERM");
    const lines = (await readFile(join(cwd, "work", "rows.jsonl"), "utf8")).split("\n").filter(Boolean);
    assert.equal(lines.length, a.entry_count);
    for (const l of lines) JSON.parse(l);
  });
});
