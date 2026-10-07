/**
 * The Skills section of a run's prompt, written at kickoff.
 *
 *   node --experimental-strip-types scripts/skills-section.ts <out-file> <pack-dir>...
 *
 * Reads each pack's `skills/INDEX.md`, renders the section within the entry,
 * pack and run budgets (extensions/skills.ts: a pack's router alone above
 * them) and writes it to <out-file>, which swarm.sh points at the sandbox's
 * `.pi/APPEND_SYSTEM.md`: Pi puts that file in its own prompt sections, so
 * every run of every seat carries it, the runs a hand-off starts included. A
 * pack set that carries no skill leaves no file (and removes a stale one).
 * Prints one JSON line, the section's report (what it shows, what is over
 * budget, which pack could not be read), for the kickoff to say.
 */
import { rmSync, writeFileSync } from "node:fs";
import { readPackIndexes, renderSkillsSection } from "../extensions/skills.ts";

async function main(argv: string[]): Promise<number> {
  const [out, ...dirs] = argv;
  if (!out || dirs.length === 0) {
    process.stderr.write("usage: skills-section.ts <out-file> <pack-dir>...\n");
    return 2;
  }
  const { text, report } = renderSkillsSection(await readPackIndexes(dirs));
  if (text) writeFileSync(out, `${text}\n`, { mode: 0o644 });
  else rmSync(out, { force: true });
  process.stdout.write(`${JSON.stringify({ written: text !== "", ...report })}\n`);
  return 0;
}

if (process.argv[1] && /skills-section\.ts$/.test(process.argv[1])) {
  process.exitCode = await main(process.argv.slice(2));
}
