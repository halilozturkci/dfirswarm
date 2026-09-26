#!/usr/bin/env node
/**
 * A goal's check (ADR 0002): every named section of the report rests on the
 * ledger. A section's entries are those it cites (#<seq> or E-<seq>, a range
 * such as #72–#74 too) and those that name it in `answers`. It passes when
 * one of them, standing, is:
 * - a finding with refs that all resolve, at least one of them an object of
 *   the run (unresolved:<why> alone names none): answered;
 * - a search that found nothing (absence), complete, with refs that resolve
 *   when it has any: answered, as not found;
 * - a limitation: the examination could not establish it, and says why:
 *   examination-limited, which a reader is told apart from answered.
 * A hypothesis never answers. A finding resting on the kept output of a job
 * that failed passes and is named. How sure the swarm said it was is not
 * asked: a check on confidence would teach a swarm to declare it. A ledger
 * whose chain is broken answers nothing.
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
import { verifyLedgerChain } from "../extensions/protocol.ts";
import { committedLogHashes, resolveRef } from "./evidence-store.ts";

type Entry = { seq: number; kind: string; refs?: string[]; supersedes?: number; answers?: string[]; completion?: string; reason?: string; status?: string };

/** A section id as the goal numbers it: "3", "Q3" and "q3" are section 3. */
export function sectionId(id: string): string {
  return id.trim().replace(/^q(?=\d)/i, "");
}

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

export type SectionOutcome = "answered" | "limited" | "unanswered";

export async function checkAnswers(sandbox: string, reportPath: string, wanted: string[]): Promise<{ ok: boolean; lines: string[]; outcomes: Record<string, SectionOutcome> }> {
  const S = resolve(sandbox);
  const outcomes: Record<string, SectionOutcome> = {};
  const report = await readFile(join(S, reportPath), "utf8").catch(() => null);
  if (report === null) return { ok: false, lines: [`no ${reportPath}`], outcomes };
  const text = await readFile(join(S, "ledger", "entries.jsonl"), "utf8").catch(() => "");
  const chain = verifyLedgerChain(text);
  if (!chain.ok) return { ok: false, lines: [`the ledger's chain is broken at line ${chain.broken_at} (${chain.reason}): no section can rest on it`], outcomes };
  const entries = text
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Entry);
  const bySeq = new Map(entries.map((e) => [e.seq, e]));
  const replaced = new Set(entries.map((e) => e.supersedes).filter((n): n is number => typeof n === "number"));
  const logs = await committedLogHashes(S);
  const parts = sections(report);
  const lines: string[] = [];
  let ok = true;
  for (const n of wanted) {
    const body = parts.get(n);
    if (body === undefined) {
      ok = false;
      outcomes[n] = "unanswered";
      lines.push(`section ${n}: no "## ${n}." heading in ${reportPath}`);
      continue;
    }
    const cited = citedSeqs(body);
    // Entries that name the section themselves come first: the agent said so, the prose need not.
    const tagged = entries.filter((e) => !replaced.has(e.seq) && (e.answers ?? []).some((a) => sectionId(a) === sectionId(n))).map((e) => e.seq);
    const candidates = [...new Set([...tagged, ...cited])];
    const why: string[] = [];
    let answered: string | null = null;
    let limited: string | null = null;
    for (const seq of candidates) {
      const e = bySeq.get(seq);
      if (!e) continue;
      const via = tagged.includes(seq) ? ", tagged for this section" : "";
      if (replaced.has(seq)) {
        why.push(`#${seq} is superseded`);
        continue;
      }
      if (e.kind === "hypothesis") {
        why.push(`#${seq} is a hypothesis (${e.status ?? "open"}), not an answer`);
        continue;
      }
      if (e.kind === "limitation") {
        limited ??= `#${seq} (a limitation: ${e.reason ?? "no reason"}${via})`;
        continue;
      }
      if (e.kind !== "finding" && e.kind !== "absence") continue;
      if (e.kind === "absence" && e.completion && e.completion !== "complete") {
        why.push(`#${seq} is a search that was ${e.completion}: it holds only for what was searched`);
        continue;
      }
      if (e.kind === "finding" && !e.refs?.length) {
        why.push(`#${seq} names no refs`);
        continue;
      }
      const bad: string[] = [];
      const failed: string[] = [];
      let objects = 0;
      for (const r of e.refs ?? []) {
        const got = await resolveRef(S, r, { verify: true, committedLogs: logs });
        if (!got.ok) bad.push(r);
        else {
          if (got.kind !== "unresolved") objects += 1;
          if (got.status && got.status !== "ok") failed.push(`${r} (job ${got.status})`);
        }
      }
      if (bad.length) {
        why.push(`#${seq}'s refs ${bad.join(", ")} do not resolve`);
        continue;
      }
      if (e.kind === "finding" && !objects) {
        why.push(`#${seq} rests on unresolved: refs only, which name no object of the run`);
        continue;
      }
      const onFailed = failed.length ? `; on the kept output of a job that did not succeed: ${failed.join(", ")}` : "";
      answered = e.kind === "absence" ? `#${seq} (a search that found nothing${via}${onFailed})` : `#${seq} (a finding with refs${via}${onFailed})`;
      break;
    }
    if (answered) {
      outcomes[n] = "answered";
      lines.push(`section ${n}: rests on ${answered}`);
    } else if (limited) {
      outcomes[n] = "limited";
      lines.push(`section ${n}: examination-limited, rests on ${limited}`);
    } else {
      ok = false;
      outcomes[n] = "unanswered";
      lines.push(`section ${n}: rests on no standing finding with refs, no complete search that found nothing and no limitation${candidates.length ? ` (cites ${candidates.map((s) => `#${s}`).join(", ")}${why.length ? `: ${why.join("; ")}` : ""})` : " (cites no ledger entry)"}`);
    }
  }
  const count = (o: SectionOutcome) => Object.values(outcomes).filter((x) => x === o).length;
  lines.push(`sections: ${count("answered")} answered, ${count("limited")} examination-limited, ${count("unanswered")} unanswered`);
  return { ok, lines, outcomes };
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
