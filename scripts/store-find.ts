/**
 * "Which job holds it?", answered from the store's own indexes.
 *
 * A seat that has seen a file name or a value and wants the job that holds
 * it ran `grep -r` and `find` over store/ in its own shell: 17 to 108 such
 * calls a run, up to 20 minutes each, several stopped at the shell's limit,
 * and one run recorded an 894 MB dump as "truncated by the case" because a
 * refusal did not say the file was in another job. A name or a sha256 is
 * found here from each job's manifest index, without reading a file; a
 * search for text in the files is a job, which this suggests ready to run.
 *
 * `jobsListing` is the other question the seats built their own tool for:
 * what jobs are there, in what state, and why does mine wait.
 */
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { manifestOf, storePaths } from "./evidence-store.ts";

export type Found = { ref: string; bytes: number; sha256: string };
export type FindResult = { ok: true; matched: number; returned: number; hits: Found[]; searched: { jobs: number; imports: number; files: number }; complete: boolean; note?: string } | { ok: false; reason: string };

export const FIND_LIMIT_MAX = 200;

/**
 * Files of sealed job outputs and imports whose path holds `name` (case-insensitive; a `*` matches any run of
 * characters) or whose sha256 is `sha256`. Bounded: at most `limit` hits are returned and every one is counted.
 */
export async function storeFind(sandbox: string, q: { name?: string; sha256?: string; limit?: number; job?: string }): Promise<FindResult> {
  const name = typeof q.name === "string" ? q.name.trim() : "";
  const sha = typeof q.sha256 === "string" ? q.sha256.trim().toLowerCase() : "";
  if (!name && !sha) return { ok: false, reason: "give name (a file name or a part of a path; * matches any run of characters) or sha256 (the 64 hex digits of a file's content)" };
  if (sha && !/^[0-9a-f]{64}$/.test(sha)) return { ok: false, reason: "sha256 is 64 hex digits" };
  if (name.length > 300) return { ok: false, reason: "name is at most 300 characters" };
  const limit = Math.min(Math.max(1, Math.floor(q.limit ?? 50)), FIND_LIMIT_MAX);
  const re = name ? new RegExp(name.split("*").map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*"), "i") : null;
  const P = storePaths(sandbox);
  const hits: Found[] = [];
  let matched = 0, files = 0, jobs = 0, imports = 0, complete = true;
  for (const [kind, dir] of [["job", P.jobs], ["import", P.imports]] as const) {
    const ids = (await readdir(dir).catch(() => [] as string[])).filter((id) => !q.job || id === q.job).sort();
    for (const id of ids) {
      const view = await manifestOf(join(dir, id, "manifest.json")).catch(() => null);
      if (!view) {
        if (kind === "job") complete = complete && false === (await readdir(join(dir, id)).then((n) => n.includes("job.json")).catch(() => false));
        continue;
      }
      kind === "job" ? (jobs += 1) : (imports += 1);
      for await (const rows of view.files()) {
        for (const f of rows) {
          files += 1;
          if ((re && !re.test(f.path)) || (sha && f.sha256 !== sha)) continue;
          matched += 1;
          if (hits.length < limit) hits.push({ ref: `${kind}:${id}/${f.path}`, bytes: f.bytes, sha256: f.sha256 });
        }
      }
    }
  }
  return {
    ok: true,
    matched,
    returned: hits.length,
    hits,
    searched: { jobs, imports, files },
    complete,
    note:
      (complete ? "" : "Some jobs have finished and are not sealed yet: their files are not in this answer (jobs lists them). ") +
      (matched > hits.length ? `${matched - hits.length} more match: narrow the name, or name a job. ` : "") +
      "This finds files by name or by content hash, from the manifests. To search inside the files for text, run a job: " +
      `job_run(command: "grep -rlaF -- '<text>' store/jobs/<id>/out | head -100", inputs: ["job:<id>"], timeout_seconds: 900) over the job that holds them, not a grep in your own shell.`,
  };
}

export type JobRow = { job: string; state: string; status?: string; what: string; by: string; lead?: string; waiting?: string; files?: number; bytes?: number };

type JobLike = { id: string; state: string; status?: string; spec: { kind: string; tool?: string; recipe?: string; command?: string }; requester: { agent: string }; outputs?: { files?: number; bytes?: number }; accepted_at?: string };

/** The run's jobs for a seat: its own, a lead's, or all; the open ones first, each with why it waits. At most `limit` rows, all counted. */
export function jobsListing(
  all: readonly JobLike[],
  o: { who: string; scope?: string; lead?: string; leadOf?: (job: string) => string | undefined; waitWords?: (j: JobLike) => string | undefined; limit?: number },
): { ok: true; total: number; returned: number; counts: Record<string, number>; jobs: JobRow[]; note?: string } {
  const scope = o.scope === "all" || o.scope === "lead" ? o.scope : "mine";
  const open = (s: string) => ["accepted", "running", "finished", "fenced"].includes(s);
  const picked = all.filter((j) => (scope === "all" ? true : scope === "lead" ? o.leadOf?.(j.id) === o.lead : j.requester.agent === o.who));
  const counts: Record<string, number> = {};
  for (const j of picked) counts[j.state] = (counts[j.state] ?? 0) + 1;
  const limit = Math.min(Math.max(1, Math.floor(o.limit ?? 40)), 100);
  const ordered = [...picked].sort((a, b) => Number(open(b.state)) - Number(open(a.state)) || (b.accepted_at ?? b.id).localeCompare(a.accepted_at ?? a.id));
  const rows = ordered.slice(0, limit).map((j): JobRow => {
    const what = j.spec.tool ? `tool ${j.spec.tool}` : j.spec.recipe ? `recipe ${j.spec.recipe}` : j.spec.kind === "import" ? "import" : `command: ${(j.spec.command ?? "").replace(/\s+/g, " ").slice(0, 80)}`;
    const lead = o.leadOf?.(j.id);
    const waiting = open(j.state) ? o.waitWords?.(j) : undefined;
    return { job: j.id, state: j.state, ...(j.status ? { status: j.status } : {}), what, by: j.requester.agent, ...(lead ? { lead } : {}), ...(waiting ? { waiting } : {}), ...(j.outputs?.files !== undefined ? { files: j.outputs.files, bytes: j.outputs.bytes } : {}) };
  });
  return { ok: true, total: picked.length, returned: rows.length, counts, jobs: rows, ...(picked.length > rows.length ? { note: `${picked.length - rows.length} more, older: job_status(job_id) reads any one` } : {}) };
}
