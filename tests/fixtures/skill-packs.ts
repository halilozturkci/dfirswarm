/**
 * Pack directories as pack.sh seals them, for the suites that need a run's
 * packs without depending on the shipped ones: front matter per skill and an
 * INDEX.md generated from it (the router line included when one skill says
 * `router: true`).
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export type SkillSpec = { title: string; when: string; needs?: string[]; tools?: string[]; body: string; router?: boolean };

/** A pack directory as pack.sh seals one: front matter per skill, INDEX.md generated from it. */
export async function writePack(root: string, id: string, version: string, skills: Record<string, SkillSpec>): Promise<string> {
  const dir = join(root, id);
  await mkdir(join(dir, "skills"), { recursive: true });
  await writeFile(join(dir, "pack.json"), JSON.stringify({ id, version }));
  const lines = ["# Skills in this pack", "", 'Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.', ""];
  const routers = Object.entries(skills).filter(([, s]) => s.router).map(([k]) => k);
  if (routers.length === 1) lines.push(`Router: \`${routers[0]}\``, "");
  for (const [skillId, spec] of Object.entries(skills).sort(([a], [b]) => a.localeCompare(b))) {
    const file = join(dir, "skills", `${skillId}.md`);
    await mkdir(dirname(file), { recursive: true });
    await writeFile(
      file,
      `---\nid: ${skillId}\ntitle: ${spec.title}\nwhen: ${spec.when}\nneeds: [${(spec.needs ?? []).join(", ")}]\ntools: [${(spec.tools ?? []).join(", ")}]\nrequires_host: []\n${spec.router ? "router: true\n" : ""}---\n\n${spec.body}\n`,
    );
    lines.push(`- \`${skillId}\` ${spec.title}: ${spec.when}`);
  }
  lines.push("");
  await writeFile(join(dir, "skills", "INDEX.md"), lines.join("\n"));
  return dir;
}

export const PREFETCH_BODY = "Read the run count first, then the last eight run times. A prefetch file proves a run, not who ran it.\n\n    prefetch_mam FILE\n\nRecord: the executable, the count, the times.";

export async function twoPacks(root: string): Promise<{ a: string; b: string }> {
  const a = await writePack(root, "pack-a", "1.2.0", {
    "evidence/one": { title: "The first note", when: "Before anything else.", needs: ["evidence/two", "other/x"], tools: ["tool_alpha"], body: PREFETCH_BODY },
    "evidence/two": { title: "The second note", when: "After the first.", body: "Second body, short." },
    "evidence/three": { title: "A third note", when: "Rarely.", body: "Third body." },
    "evidence/four": { title: "A fourth note", when: "Rarely too.", body: "Fourth body." },
    "shared/dup": { title: "In both packs", when: "Whenever.", body: "The copy from pack A." },
  });
  const b = await writePack(root, "pack-b", "0.4.1", {
    "other/x": { title: "Another pack's note", when: "On the other side.", body: "X body." },
    "shared/dup": { title: "In both packs", when: "Whenever.", body: "The copy from pack B." },
  });
  return { a, b };
}

