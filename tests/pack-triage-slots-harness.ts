/**
 * triage-collection: the helpers of the slot suites (tests/pack-triage-slots.test.ts for collection_id, tests/pack-triage-slots-index.test.ts for
 * collection_index, one file per tool so that each stays well under the per-file limit of Node 22): every output slot of both tools, driven end to end
 * with random secret canaries.
 *
 * The earlier suites plant a handful of fixed strings in the slots their author listed; three slots that nobody listed printed
 * evidence-derived text raw (the path of a log found inside collected data, the directory of a copy log, the level word of a
 * Velociraptor log row used as a dictionary key). This suite plants a random secret of a listed shape in EVERY place the two
 * tools print something that came from the evidence (every kind of file, directory and link name, every CSV header and cell,
 * every JSON key and value of uploads.json, results and log.json, every UAC line kind, every copy-log column, the arguments the
 * tool echoes), 200 plants per slot, rotating through the shapes, runs the tool in the four contexts (a job or not, limit 1 or
 * the default) and scans the answer, stderr, every file the run created and every file NAME for any 12-character window of a
 * planted secret. The sealed values file is the only place a secret may be, and only when asked.
 *
 * The same trees are then run again with the sanitiser REMOVED (its entry points replaced by the identity before main runs):
 * the independent check at the serialisation boundary alone must keep every canary out of every channel.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPySnippet } from "./tool-library-harness.ts";
import { ID, INDEX, KAPE_COPY_HEADER, body, kapeCopyRow, put, tool, veloLogRow, veloResultRow, veloUploadsRow, withCwd } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";
import { CANARY_PY } from "./pack-triage-canaries.ts";

export const N = Number(process.env.TRIAGE_SLOT_PLANTS ?? 200);

const SLOTS_PY = CANARY_PY + String.raw`
import collections, json, os, random, re, stat, sys

TOKEN = re.compile(r"[^\s\"',;<>\\]{12,}")


def build(tool, n, seed):
    rng = random.Random(seed)
    plants = collections.OrderedDict()

    def P(slot, safe=False):
        pool = names(("listed",), safe_only=safe)
        name = pool[len(plants.get(slot, [])) % len(pool)]
        text, cores = make(name, rng)
        plants.setdefault(slot, []).append([text, cores, name])
        return text

    def flat(text):
        return text.replace("\n", " ")

    def put(rel, data=b"", mode=None):
        full = os.path.join("inputs", "t", rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())
        if mode is not None:
            os.chmod(full, mode)

    def csvq(text):
        return '"%s"' % text.replace('"', '""')

    isroot = hasattr(os, "geteuid") and os.geteuid() == 0
    copy_header = "CopiedTimestamp,SourceFile,DestinationFile,FileSize,SourceFileSha1,DeferredCopy,CreatedOnUtc,ModifiedOnUtc,LastAccessedOnUtc,CopyDuration"

    def copy_row(src, dst, size="1", modified="2026-01-02 03:04:05.678"):
        return ",".join(["2026-02-14 09:12:00.123", csvq(src), csvq(dst), csvq(size), "da39a3ee5e6b4b0d3255bfef95601890afd80709", "False",
                         "2026-01-01 00:00:00.000", csvq(modified), "2026-01-03 00:00:00.000", "0.0123"])

    for i in range(n):
        if tool == "id":
            put("o%04d/%s.E01" % (i, P("object_path", True)), b"EVF\t\r\n\xff\x00" + bytes(16))
            os.makedirs(os.path.join("inputs", "t", "l%04d" % i), exist_ok=True)
            os.symlink("/nonexistent", os.path.join("inputs", "t", "l%04d" % i, P("symlink_name", True)))
            os.makedirs(os.path.join("inputs", "t", "f%04d" % i), exist_ok=True)
            os.mkfifo(os.path.join("inputs", "t", "f%04d" % i, P("fifo_name", True)))
            if not isroot:
                os.makedirs(os.path.join("inputs", "t", "u%04d" % i, P("unreadable_directory", True)))
                os.chmod(os.path.join("inputs", "t", "u%04d" % i, plants["unreadable_directory"][-1][0]), 0)
            put("[root]/c%04d/%s/uac.log" % (i, P("log_inside_collected_data", True)), b"x")
            put("uploads/a%04d/%s/uploads.json" % (i, P("log_inside_uploads", True)), b"x")
            run_id = P("kape_run_id_and_directory", True)
            put("k%04d/%s/%s_SkipLog.csv" % (i, run_id, run_id), "SourceFile,Reason\nC:\\a,denied\n")
            put("v%04d/%s/uploads.json" % (i, P("velociraptor_container_directory", True)), json.dumps({"vfs_path": "x", "file_size": 5, "uploaded_size": 1}) + "\n")
            put("w%04d/uploads.json" % i, json.dumps({"vfs_path": "x", "file_size": 5, "uploaded_size": 5}) + "\n")
            put("w%04d/results/%s.json" % (i, P("velociraptor_results_file_name", True)), json.dumps({"Upload": {"Path": "C:/x", "StoredName": "s", "Error": "e"}}) + "\n")
            put("z%04d/%s/SYSTEM" % (i, P("family_path", True)), b"x")
            put("m%04d/%s/[root]/x" % (i, P("uac_marker_directory", True)), b"x")
            e, h, u, c = P("uac_error_line"), P("uac_host_line"), P("uac_unlabelled_line"), P("uac_command_stderr_line")
            put("a%04d/uac.log" % i, "\n".join(["2026-02-14 09:12:00 +0000 INF start", "2026-02-14 09:12:01 +0000 ERR " + flat(e),
                                                "2026-02-14 09:12:02 +0000 INF hostname " + flat(h), "cannot open " + flat(u) + ": Permission denied",
                                                "2026-02-14 09:12:03 +0000 CMD ls /x 2> " + flat(c)]) + "\n")
            t, r = P("skip_target"), P("skip_reason")
            put("s%04d/A_SkipLog.csv" % i, "SourceFile,Reason\n%s,%s\n" % (csvq(t), csvq(r)))
            uh, uv, uw = P("unrecognised_header"), P("unrecognised_value"), P("unrecognised_value_2")
            put("s%04d/B_SkipLog.csv" % i, "%s,Other\n%s,%s\n" % (csvq(uh), csvq(uv), csvq(uw)))
            h1, h2, c1, c2 = P("skip_extra_header"), P("skip_extra_header_2"), P("skip_extra_cell"), P("skip_extra_cell_2")
            put("y%04d/A_SkipLog.csv" % i, "SourceFile,Reason,%s,%s\nC:\\a,denied,%s,%s\n" % (csvq(h1), csvq(h2), csvq(c1), csvq(c2)))
            put("y%04d/B_CopyLog.csv" % i, "SourceFile,%s\nC:\\a,x\n" % csvq(P("copy_log_header")))
            put("s%04d/C_ConsoleLog.txt" % i, "[2026-02-14 09:12:00.1234567 | ERR] %s\n" % flat(P("console_log_line")))
            vk, vv, vt, vs, vc = P("uploads_key", True), P("uploads_value"), P("uploads_type"), P("uploads_started"), P("uploads_component")
            put("x%04d/uploads.json" % i, json.dumps({"vfs_path": P("uploads_vfs_path"), "file_size": 9, "uploaded_size": 1, "Type": vt, "started": vs,
                                                      "_Components": [vc], vk: vv}) + "\n")
            rk, rv, rn, ke, kd = P("results_top_key", True), P("results_top_value"), P("results_nested_value"), P("results_error"), P("results_nested_key", True)
            put("x%04d/results/Art.json" % i, json.dumps({"Upload": {"Path": P("results_upload_path"), "StoredName": "s", "Error": ke, kd: "v", "Extra": rn}, rk: rv}) + "\n")
            lm, lk, lv, ll = P("log_json_message"), P("log_json_extra_key", True), P("log_json_extra_value"), P("log_json_level", True)
            put("x%04d/log.json" % i, json.dumps({"level": "ERROR", "message": lm, lk: lv}) + "\n" + json.dumps({"level": ll, "message": "m"}) + "\n"
                + json.dumps({"level": "WARN", "message": P("log_json_warning")}) + "\n")
        else:
            put("p%04d/%s" % (i, P("path", True)), b"x")
            os.makedirs(os.path.join("inputs", "t", "q%04d" % i), exist_ok=True)
            os.symlink("/nonexistent", os.path.join("inputs", "t", "q%04d" % i, P("symlink_name", True)))
            if not isroot:
                os.makedirs(os.path.join("inputs", "t", "u%04d" % i, P("unreadable_directory", True)))
                os.chmod(os.path.join("inputs", "t", "u%04d" % i, plants["unreadable_directory"][-1][0]), 0)
            put("h%04d/C/%s" % (i, P("hypothesis_below_C", True)), b"x")
            put("r%04d/[root]/etc/%s" % (i, P("hypothesis_below_uac_root", True)), b"x")
            suffix = P("stream_suffix", True)
            put("m%04d/doc.txt_$%s" % (i, suffix), b"x")
            os.makedirs(os.path.join("inputs", "t", "n%04d" % i), exist_ok=True)
            target = flat(P("symlink_target"))
            os.symlink(target[:900], os.path.join("inputs", "t", "n%04d" % i, "lnk"))
            # the same tree names the copy log's directory as a plant: a log at inputs/c2/<plant>/
    if tool == "index":
        rows = [copy_header]
        for i in range(n):
            f = "f%04d.txt" % i
            put("../c/C/" + f, b"x")
            rows.append(copy_row(flat(P("copy_log_source")), "D:\\kape\\C\\" + f, flat(P("copy_log_size")), flat(P("copy_log_modified"))))
            g = "g%04d.txt" % i
            put("../c/C/" + g, b"x")
            rows.append(copy_row(flat(P("copy_log_ambiguous_a")), "D:\\kape\\C\\" + g))
            rows.append(copy_row(flat(P("copy_log_ambiguous_b")), "D:\\kape\\C\\" + g))
        with open("inputs/c/20260101_CopyLog.csv", "w") as fh:
            fh.write("\n".join(rows) + "\n")
        for i in range(n):
            d = P("copy_log_directory", True)
            put("../c2/%s/20260101_CopyLog.csv" % d, copy_header + "\n" + copy_row("C:\\s\\z%d.txt" % i, "D:\\k\\C\\z%d.txt" % i) + "\n")
            put("../c2/%s/C/z%d.txt" % (d, i), b"x")
    json.dump(plants, open("plants.json", "w"))


def scan(cwd, captured):
    os.chdir(cwd)
    """The text of every channel except the sealed values file: the answers, stderr, every file the run created, every file name."""
    plants = json.load(open("plants.json"))
    parts, names_seen = [], []
    for path in captured:
        parts.append(open(path, "rb").read())
    for base, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if not (base == "." and d in ("inputs", "captured"))]
        for f in files:
            full = os.path.join(base, f)
            names_seen.append(full.encode("utf-8", "surrogateescape"))
            if f.endswith("-values.jsonl") or f == "plants.json":
                continue
            parts.append(open(full, "rb").read())
        names_seen += [os.path.join(base, d).encode("utf-8", "surrogateescape") for d in dirs]
    parts.append(b"\n".join(names_seen))
    text = b"\n".join(parts).decode("utf-8", "replace")
    wanted = set()
    for slot, items in plants.items():
        for _plant, cores, _name in items:
            for core in cores:
                for k in range(0, max(len(core) - 11, 0)):
                    wanted.add(core[k:k + 12])
    seen = set()
    for token in TOKEN.findall(text):
        for k in range(0, len(token) - 11):
            gram = token[k:k + 12]
            if gram in wanted:
                seen.add(gram)
    report = {}
    for slot, items in plants.items():
        leaked, shapes = 0, collections.Counter()
        for _plant, cores, name in items:
            hit = any(core[k:k + 12] in seen for core in cores for k in range(0, max(len(core) - 11, 0)))
            if hit:
                leaked += 1
                shapes[name] += 1
        report[slot] = {"planted": len(items), "leaked": leaked, "shapes": dict(shapes)}
    return report


def unlock(cwd):
    for base, dirs, files in os.walk(cwd):
        for d in dirs:
            try:
                os.chmod(os.path.join(base, d), 0o755)
            except OSError:
                pass


if __name__ == "__main__":
    if sys.argv[1] == "build":
        build(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    elif sys.argv[1] == "unlock":
        unlock(sys.argv[2])
    else:
        print(json.dumps(scan(sys.argv[2], sys.argv[3:])))
`;

// The tool with its sanitiser taken out: scrub, scrub_all and shown become the identity before main runs, so only what stands
// at the serialisation boundary independently of them can keep a canary out.
const BARE_PY = String.raw`
import runpy, sys
script = sys.argv[1]
sys.argv = [script]
import importlib.util
spec = importlib.util.spec_from_file_location("bare_tool", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for name in ("scrub", "scrub_all", "shown"):
    if hasattr(mod, name):
        setattr(mod, name, (lambda text, *rest: text) if name != "scrub_all" else (lambda value: value))
mod.main()
`;

async function runBare(script: string, cwd: string, args: Json, env: Record<string, string>) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn("python3", ["-c", BARE_PY, script], { cwd, env: { ...process.env, AGENT_ID: "s1", ...env } });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
    child.stdin.end(JSON.stringify(args));
  });
}

async function scanLeaks(cwd: string, captured: string[]): Promise<Record<string, { planted: number; leaked: number; shapes: Record<string, number> }>> {
  const run = await runPySnippet(SLOTS_PY, ["scan", cwd, ...captured], null);
  assert.equal(run.code, 0, run.stderr);
  return JSON.parse(run.stdout);
}

/** Run one tool in the four contexts over trees of random canaries and return, per slot, how many plants leaked, summed over the contexts. */
export async function drive(which: "id" | "index", bare: boolean) {
  const cwd = await mkdtemp(join(tmpdir(), `triage-slots-${which}-`));
  const script = which === "id" ? ID : INDEX;
  try {
    await mkdir(join(cwd, "inputs"), { recursive: true });
    await mkdir(join(cwd, "captured"), { recursive: true });
    const build = await new Promise<number | null>((resolve) => {
      const child = spawn("python3", ["-c", SLOTS_PY, "build", which, String(N), "7"], { cwd, stdio: ["ignore", "inherit", "inherit"] });
      child.on("close", resolve);
    });
    assert.equal(build, 0, "the fixture trees were built");
    const results: Record<string, { planted: number; leaked: number; shapes: Record<string, number> }> = {};
    const contexts = [{ job: true, limit: 1 }, { job: true, limit: undefined }, { job: false, limit: 1 }, { job: false, limit: undefined }];
    const roots = which === "id" ? ["inputs/t"] : ["inputs/t", "inputs/c", "inputs/c2"];
    const outcomes: Json[] = [];
    for (const [index, context] of contexts.entries()) {
      await rm(join(cwd, "work"), { recursive: true, force: true });
      await rm(join(cwd, "out"), { recursive: true, force: true });
      await rm(join(cwd, "captured"), { recursive: true, force: true });
      await mkdir(join(cwd, "work", "s1"), { recursive: true });
      await mkdir(join(cwd, "out"), { recursive: true });
      await mkdir(join(cwd, "captured"), { recursive: true });
      const captured: string[] = [];
      for (const [r, root] of roots.entries()) {
        const args: Json = { root, ...(context.limit ? { limit: context.limit } : {}) };
        const env: Record<string, string> = context.job ? { JOB_ID: `j00${index}${r}00`, OUT: join(cwd, "out") } : {};
        const run = bare ? await runBare(script, cwd, args, env) : await tool(script, cwd, args, env);
        assert.doesNotMatch(run.stderr, /Traceback/, `${which} ${JSON.stringify(context)} ${root}`);
        outcomes.push({ context, root, code: run.code, status: (() => { try { return JSON.parse(run.stdout).status; } catch { return "not JSON"; } })() });
        const file = join(cwd, "captured", `${r}.out`);
        await writeFile(file, run.stdout + "\n" + run.stderr);
        captured.push(file);
      }
      // the arguments the tool echoes: a root that does not exist, a parameter it does not know
      const plants = JSON.parse(await readFile(join(cwd, "plants.json"), "utf8"));
      const names: string[] = Object.values(plants as Record<string, Json[]>).flat().filter((p: Json) => /^[A-Za-z0-9_.-]{12,80}$/.test(p[0])).slice(0, 12).map((p: Json) => p[0]);
      for (const [k, name] of names.entries()) {
        for (const args of [{ root: `inputs/${name}` }, { root: roots[0], [name]: 1, ...(context.limit ? { limit: context.limit } : {}) }]) {
          const env: Record<string, string> = context.job ? { JOB_ID: `j00${index}${k}77`, OUT: join(cwd, "out") } : {};
          const run = bare ? await runBare(script, cwd, args, env) : await tool(script, cwd, args, env);
          const file = join(cwd, "captured", `arg-${k}-${Object.keys(args).length}.out`);
          await writeFile(file, run.stdout + "\n" + run.stderr);
          captured.push(file);
        }
      }
      const report = await scanLeaks(cwd, captured);
      for (const [slot, v] of Object.entries(report)) {
        const sum = (results[slot] ??= { planted: 0, leaked: 0, shapes: {} });
        sum.planted += v.planted;
        sum.leaked += v.leaked;
        for (const [shape, n] of Object.entries(v.shapes)) sum.shapes[shape] = (sum.shapes[shape] ?? 0) + n;
      }
    }
    return { results, outcomes };
  } finally {
    await new Promise((resolve) => spawn("python3", ["-c", SLOTS_PY, "unlock", cwd], { stdio: "ignore" }).on("close", resolve));
    await rm(cwd, { recursive: true, force: true }).catch(() => {});
  }
}

export function leaks(results: Record<string, { planted: number; leaked: number; shapes: Record<string, number> }>): string[] {
  return Object.entries(results).filter(([, v]) => v.leaked > 0).map(([slot, v]) => `${slot}: ${v.leaked} of ${v.planted} ${JSON.stringify(v.shapes)}`);
}
