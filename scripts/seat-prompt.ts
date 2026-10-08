/**
 * The lines of every seat's prompt that hold for the whole run, written at kickoff.
 *
 *   node --experimental-strip-types scripts/seat-prompt.ts --sandbox DIR [--self-compact] [--forging]
 *       [--seat ID]... [--pack-dir DIR]... [--seats-only]
 *
 * Writes two kinds of file under <sandbox>/.pi/, which Pi appends to its own
 * prompt sections (every run of a seat keeps them, the runs a hand-off starts
 * included; the prompt before_agent_start forces does not outlive the run a
 * user prompt starts):
 *
 * - APPEND_SYSTEM.md, the run's: the index of the packs (extensions/skills.ts,
 *   within the entry, pack and run budgets, a pack's router alone above them),
 *   the self-compaction mechanics, the read-only inputs rule from inputs.json,
 *   the forging rule. Always written: empty when none of these applies, so an
 *   operator's own ~/.pi/agent/APPEND_SYSTEM.md is never what a seat gets.
 * - seat-<id>.md for each --seat: the seat's id and the stop rule. `--seats-only` writes
 *   these alone (the probe's, which is made after the run's files).
 *
 * The kickoff passes both to every seat with --append-system-prompt, which
 * replaces Pi's discovery of the global file as well. The wording is one place,
 * extensions/seat-prompt.ts; the extension recognises these lines in the prompt
 * it is given and says only what they do not. Prints one JSON line, the
 * report: the skills section's (what it shows, what is over budget, which pack
 * could not be read) and `lines`, the run-wide lines written.
 */
import { lstatSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readInputsManifest } from "../extensions/protocol-core.ts";
import { runPromptLines, seatPromptLine } from "../extensions/seat-prompt.ts";
import { readPackIndexes, renderSkillsSection } from "../extensions/skills.ts";

type Options = { sandbox: string; selfCompact: boolean; forging: boolean; seats: string[]; packDirs: string[]; seatsOnly: boolean };

function parse(argv: string[]): Options | string {
  const o: Options = { sandbox: "", selfCompact: false, forging: false, seats: [], packDirs: [], seatsOnly: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--sandbox") o.sandbox = argv[++i] ?? "";
    else if (a === "--self-compact") o.selfCompact = true;
    else if (a === "--forging") o.forging = true;
    else if (a === "--seat") o.seats.push(argv[++i] ?? "");
    else if (a === "--pack-dir") o.packDirs.push(argv[++i] ?? "");
    else if (a === "--seats-only") o.seatsOnly = true;
    else return `unknown argument ${a}`;
  }
  if (!o.sandbox) return "--sandbox is required";
  if (o.seats.some((s) => !/^[A-Za-z0-9_-]+$/.test(s))) return "a --seat is an agent id: letters, digits, - and _";
  return o;
}

/**
 * A file written fresh: the name is removed first and the file made with `wx`, so a link planted at the name
 * (a host pane's bash can write the whole sandbox, and a resume runs the kickoff again in it) is replaced and
 * never written through.
 */
function writeFresh(path: string, text: string): void {
  rmSync(path, { force: true });
  writeFileSync(path, text, { flag: "wx", mode: 0o644 });
}

async function write(o: Options): Promise<number> {
  const dir = join(o.sandbox, ".pi");
  if (lstatSync(dir, { throwIfNoEntry: false })?.isSymbolicLink()) throw new Error(`${dir} is a link`);
  mkdirSync(dir, { recursive: true });
  const skills = o.packDirs.length && !o.seatsOnly ? renderSkillsSection(await readPackIndexes(o.packDirs)) : null;
  const inputs = o.seatsOnly ? null : await readInputsManifest(o.sandbox);
  const lines = runPromptLines({ inputs, forging: o.forging, selfCompact: o.selfCompact });
  const parts = [...(skills?.text ? [skills.text] : []), ...lines];
  if (!o.seatsOnly) writeFresh(join(dir, "APPEND_SYSTEM.md"), parts.length ? `${parts.join("\n\n")}\n` : "");
  for (const seat of o.seats) writeFresh(join(dir, `seat-${seat}.md`), `${seatPromptLine(seat)}\n`);
  const names = [...(o.selfCompact ? ["self_compact"] : []), ...(inputs ? ["inputs"] : []), ...(o.forging ? ["forging"] : [])];
  process.stdout.write(`${JSON.stringify({ written: Boolean(skills?.text), ...(skills?.report ?? {}), lines: names, seats: o.seats })}\n`);
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const o = parse(argv);
  if (typeof o === "string") {
    process.stderr.write(`seat-prompt.ts: ${o}\nusage: seat-prompt.ts --sandbox DIR [--self-compact] [--forging] [--seat ID]... [--pack-dir DIR]... [--seats-only]\n`);
    return 2;
  }
  try {
    return await write(o);
  } catch (err) {
    // The kickoff says this line: a file it could not write is named, not "Node.js v24".
    process.stderr.write(`seat-prompt.ts: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

if (process.argv[1] && /seat-prompt\.ts$/.test(process.argv[1])) {
  process.exitCode = await main(process.argv.slice(2));
}
