/**
 * References in a tool job's arguments (IMPROVEMENT-PLAN-2 item D4). A seat
 * cites a job's file as `job:<id>/<path>` everywhere else, and in eight runs
 * it gave that form to tools as a path (eleven jobs of one run failed on
 * "no such file"), wrote `$OUT/x` where one tool wanted a relative name, and
 * learned each tool's dialect by its refusals. No pack tool reads a
 * reference itself, so the job service does it for all of them: an argument
 * that is wholly a reference to a sealed file or directory is replaced by
 * the path the worker sees it at, `$OUT` and `${OUT}` at the head of an
 * argument are the job's output directory, and a reference that names
 * nothing is refused before the job runs, with the form that works.
 *
 * Only a whole string is read as a reference: a reference inside a longer
 * text (a note, a pattern) is left alone.
 */
import { lstatSync } from "node:fs";
import { join, normalize } from "node:path";

/** One argument that was a reference, where it was, and what it became. */
export type ArgRef = { at: string; from: string; to: string; object: string };

export type ArgRefsResult = { ok: true; args: Record<string, unknown>; resolved: ArgRef[] } | { ok: false; reason: string };

/** What the service knows of a job: its state, or undefined when the run has no such job. */
export type JobStateOf = (id: string) => string | undefined;

const JOB = /^job:(j\d{6})(?:\/(.*))?$/s;
const IMPORT = /^import:([a-z0-9-]{1,64})(?:\/(.*))?$/s;
const INPUT = /^input:(.+)$/s;
const OUT = /^(?:\$OUT|\$\{OUT\})(\/.*)?$/s;

/** A path inside an object: no parent step, no absolute path, no NUL; "" for the object itself. */
function inside(rel: string | undefined): string | null {
  const r = (rel ?? "").replace(/^\/+/, "");
  if (!r) return "";
  if (r.includes("\0")) return null;
  const n = normalize(r).replace(/\/+$/, "");
  if (n === ".." || n.startsWith("../") || n.startsWith("/")) return null;
  return n === "." ? "" : n;
}

function shape(abs: string): "file" | "dir" | null {
  try {
    const st = lstatSync(abs);
    return st.isFile() ? "file" : st.isDirectory() ? "dir" : null;
  } catch {
    return null;
  }
}

/**
 * The arguments with every whole-string reference replaced by its
 * run-relative path, and `$OUT` / `${OUT}` at a string's head by `{OUT}`
 * (which the service makes the job's output directory when it runs); or the
 * refusal for the first reference that names nothing. `resolved` lists what
 * was replaced, for the job's record and its scope.
 */
export function resolveToolArgs(S: string, tool: string, args: Record<string, unknown>, jobState: JobStateOf): ArgRefsResult {
  const resolved: ArgRef[] = [];
  let refusal: string | null = null;
  const refuse = (at: string, text: string): string => {
    refusal ??= `tool ${tool}: ${at} ${text}`;
    return "";
  };
  const one = (v: string, at: string): string => {
    const out = OUT.exec(v);
    if (out) return `{OUT}${out[1] ?? ""}`;
    const j = JOB.exec(v);
    const i = j ? null : IMPORT.exec(v);
    if (j || i) {
      const kind = j ? "job" : "import";
      const id = (j ?? i)![1]!;
      // A seat names a job's file from its listing, where it stands under out/: both forms name the same file.
      const rel = inside(((j ?? i)![2] ?? "").replace(/^out(\/|$)/, ""));
      if (rel === null) return refuse(at, `is ${JSON.stringify(v.slice(0, 200))}: the path inside a ${kind} has no parent step`);
      if (j) {
        const state = jobState(id);
        if (state === undefined) return refuse(at, `names ${kind}:${id}, and this run has no job ${id} (jobs lists them)`);
        if (state !== "committed") return refuse(at, `names job:${id}, whose output is not sealed yet (it is ${state}): a tool reads a job's files once job_status says it is committed`);
      }
      const base = j ? `store/jobs/${id}/out` : `store/imports/${id}/out`;
      const path = rel ? `${base}/${rel}` : base;
      if (!shape(join(S, path))) return refuse(at, `names ${kind}:${id}${rel ? `/${rel}` : ""}, and ${kind} ${id} has no ${rel || "output"} (${j ? `job_status ${id}` : "the board's post of it"} lists its files; a name is written as the listing has it)`);
      resolved.push({ at, from: v, to: path, object: `${kind}:${id}` });
      return path;
    }
    const inp = INPUT.exec(v);
    if (inp) {
      const rel = inside(inp[1]);
      if (rel === null || rel === "") return refuse(at, `is ${JSON.stringify(v.slice(0, 200))}: an input is input:<its path under inputs/>`);
      const path = `inputs/${rel}`;
      if (!shape(join(S, path))) return refuse(at, `names input:${rel}, and the run has no inputs/${rel} (inputs.json lists the inputs by path)`);
      resolved.push({ at, from: v, to: path, object: `input:${rel}` });
      return path;
    }
    return v;
  };
  const walk = (v: unknown, at: string, depth: number): unknown => {
    if (typeof v === "string") return one(v, at);
    if (depth > 8) return v;
    if (Array.isArray(v)) return v.map((x, k) => walk(x, `${at}[${k}]`, depth + 1));
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x, `${at}.${k}`, depth + 1)]));
    return v;
  };
  const out = Object.fromEntries(Object.entries(args).map(([k, v]) => [k, walk(v, k, 0)]));
  if (refusal) return { ok: false, reason: refusal };
  return { ok: true, args: out, resolved };
}

/** What a job's answer says of the references it was given, in one sentence; "" when there were none. */
export function argRefsWords(resolved: ArgRef[]): string {
  if (!resolved.length) return "";
  const shown = resolved.slice(0, 3).map((r) => `${r.at}: ${r.from} is ${r.to}`);
  return `The tool was given ${resolved.length === 1 ? "the path of the reference" : "the paths of the references"} in its arguments (${shown.join("; ")}${resolved.length > 3 ? `; and ${resolved.length - 3} more` : ""}).`;
}
