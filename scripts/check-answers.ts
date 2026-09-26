#!/usr/bin/env node
/**
 * A goal's check (ADR 0002): every named section of the report rests on the
 * ledger. A section passes when it cites (#<seq> or E-<seq>, a range such as
 * #72–#74 too) at least one standing finding whose refs all resolve, or one
 * standing search that found nothing (kind absence): an answer, or a search
 * that says where it looked and how. How sure the swarm said it was is not
 * asked: a check on confidence would teach a swarm to declare it.
 *
 * Nothing here knows a case: the goal names the sections, as its questions
 * are numbered. Run from the sandbox, as every check is:
 *
 *   node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" \
 *     --report work/report.md --sections 1,2,3,4,5
 *
 * Exit 0 when every section does; 1 when one does not (each named, with what
 * it cited and why none of it counts); 2 on a usage error.
 */
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveRef } from "./evidence-store.ts";

type Entry = { seq: number; kind: string; refs?: string[]; supersedes?: number };

/** The seqs a text cites: #12, E-12, and every seq of a range #12–#15 (at most 50 a range). */
export function citedSeqs(text: string): number[] {
  const out = new Set<number>();
  for (const m of text.matchAll(/(?:#|\bE-)(\d{1,5})(?:\s*[–-]\s*(?:#|E-)?(\d{1,5}))?/g)) {
    const a = Number(m[1]);
    const b = m[2] ? Number(m[2]) : a;
    if (b >= a && b - a <= 50) for (let n = a; n <= b; n += 1) out.add(n);
    else out.add(a);
  }
  return [...out];
}

/** The report's sections by number: the text under `## <n>.` up to the next `## `. */
export function sections(report: string): Map<string, string> {
  const out = new Map<string, string>();
  let current: string | null = null;
  for (const line of report.split("\n")) {
    const h = /^##\s+(\d+)\./.exec(line);
    if (h) {
      current = h[1];
      out.set(current, "");
      continue;
    }
    if (/^##\s/.test(line)) {
      current = null;
      continue;
    }
    if (current) out.set(current, `${out.get(current)}${line}\n`);
  }
  return out;
}

export async function checkAnswers(sandbox: string, reportPath: string, wanted: string[]): Promise<{ ok: boolean; lines: string[] }> {
  const S = resolve(sandbox);
  const report = await readFile(join(S, reportPath), "utf8").catch(() => null);
  if (report === null) return { ok: false, lines: [`no ${reportPath}`] };
  const entries = (await readFile(join(S, "ledger", "entries.jsonl"), "utf8").catch(() => ""))
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Entry);
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = new Set(entries.map((e) => e.supersedes).filter((n): n is number => typeof n === "number"));
  const parts = sections(report);
  const lines: string[] = [];
  let ok = true;
  for (const n of wanted) {
    const text = parts.get(n);
    if (text === undefined) {
      ok = false;
      lines.push(`section ${n}: no "## ${n}." heading in ${reportPath}`);
      continue;
    }
    const cited = citedSeqs(text);
    const why: string[] = [];
    let rests: string | null = null;
    for (const seq of cited) {
      const e = bySeq.get(seq);
      if (!e) continue;
      if (replaced.has(seq)) {
        why.push(`#${seq} is superseded`);
        continue;
      }
      if (e.kind === "absence") {
        rests = `#${seq} (a search that found nothing)`;
        break;
      }
      if (e.kind !== "finding") continue;
      if (!e.refs?.length) {
        why.push(`#${seq} names no refs`);
        continue;
      }
      const bad: string[] = [];
      for (const r of e.refs) if (!(await resolveRef(S, r)).ok) bad.push(r);
      if (bad.length) {
        why.push(`#${seq}'s refs ${bad.join(", ")} do not resolve`);
        continue;
      }
      rests = `#${seq} (a finding with refs)`;
      break;
    }
    if (rests) lines.push(`section ${n}: rests on ${rests}`);
    else {
      ok = false;
      lines.push(`section ${n}: rests on no standing finding with refs and no search that found nothing${cited.length ? ` (cites ${cited.map((s) => `#${s}`).join(", ")}${why.length ? `: ${why.join("; ")}` : ""})` : " (cites no ledger entry)"}`);
    }
  }
  return { ok, lines };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (name: string) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const report = opt("--report");
  const wanted = (opt("--sections") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!report || !wanted.length) {
    process.stderr.write("usage: check-answers.ts --report <path> --sections 1,2,3 [--sandbox DIR]\n");
    process.exit(2);
  }
  const r = await checkAnswers(opt("--sandbox") ?? process.cwd(), report, wanted);
  process.stdout.write(`${r.lines.join("\n")}\n`);
  process.exit(r.ok ? 0 : 1);
}
