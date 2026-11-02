/**
 * The checks every pack with a router holds to (docs/packs.md, "Routers"; docs/packs.md section 8, "Skill size").
 *
 * A router is the one note of a pack that says which other note answers which question. When a run's skills index
 * is over its budget the prompt shows each pack that names a router by that router's one line
 * (`renderSkillsSection`, extensions/skills.ts), so the router is what a seat sees of the pack, and it has to
 * name every leaf, once, without holding a rule of its own.
 *
 * `routerChecks` registers, for one pack, the tests that say so:
 *
 * - the router exists, is the pack's only one, is at most 400 tokens, opens with "Use when ... Not for ...", names
 *   no tool and no program, holds no sentence of rule, names every other skill of the pack exactly once and no
 *   skill of another pack, and every skill id the pack had before the router is still a skill;
 * - the pack's index is at most 1,000 tokens as the harness counts it (the entry lines of INDEX.md, each bytes /
 *   4.245 rounded up; the header lines are not counted), and the harness reads the router the index names;
 * - the pack fits the run's budget because of the router: the pack's real index beside a pack that cannot be
 *   shortened and fills the rest of the 2,500 tokens is over budget without the router (the report names the pack
 *   as having none) and exactly at budget with it, shown by its one line;
 * - the profiles of images/profiles.json that carry the pack, and the combinations of up to three packs that carry
 *   it, are rendered from the real packs: a run over budget shows the pack by its router alone, and the same run
 *   without the router shows more. A profile that fits today (network, mobile) is also rendered with the run budget
 *   forced one token under its index, and the pack must then be shown by its router.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { estimateTokens, readPackIndex, renderSkillsSection, SKILL_BUDGET, type PackIndex, type SkillBudget } from "../extensions/skills.ts";
import { ROOT } from "./tool-library-harness.ts";

const TOKENS = (text: string): number => Buffer.byteLength(text) / 4.245;
const ROUTER_MAX = 400;

// A router line says where to read, never what to do. The shape check (no `. : ;`, a few words) lets a rule through when it has no
// punctuation ("Never replay a recovered token"), so a line is also refused when it holds a word of obligation or prohibition, or when
// it opens with an imperative verb (a one-word group heading such as "Identify" or "Start" is a name, not an order).
const OBLIGATION = /\b(never|always|must|should|shall|ensure|avoid|mandatory|forbidden|prohibited|do not|don't|cannot|only if|only when|unless)\b/i;
const IMPERATIVE = /^(never|always|do|don't|use|run|load|read|check|treat|state|write|record|cite|replay|open|verify|confirm|report|keep|call|ask|pick|choose|make|take|put|set|stop|find|look|see|say|name|mark|label|reject|refuse|accept|trust|assume|prefer|compare|extract|decode|decrypt|crack|try|test|scan|search|list)\b/i;
const HEADING_WORDS = 5;
const PHRASE_WORDS = 8;
const wordCount = (t: string): number => t.split(/\s+/).filter(Boolean).length;

// What a leaf is about, as words: lower case, at least three letters, no function words, a crude stem (a suffix off, six letters at most),
// so "protects" and "protectors" meet and "the", "of" and "what" do not count.
const STOP = new Set("the and for with from not any all one two than then there their them your you our can may will would should could into onto over under out about before after only also each every both other such via per use used using note notes what which who how when where whether this that these those its are".split(" "));
function contentWords(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.toLowerCase().match(/[a-z0-9]+/g) ?? []) {
    if (raw.length < 3 || STOP.has(raw)) continue;
    let w = raw;
    for (const suf of ["ings", "ing", "ions", "ion", "ies", "ed", "es", "s"]) {
      if (w.endsWith(suf) && w.length - suf.length >= 3) {
        w = w.slice(0, -suf.length);
        break;
      }
    }
    out.add(w.slice(0, 6));
  }
  return out;
}
const sharedWords = (a: Set<string>, b: Set<string>): number => [...a].filter((w) => b.has(w)).length;

type Skill = { id: string; meta: Record<string, string | string[]>; body: string; text: string };

async function loadSkills(dir: string): Promise<Map<string, Skill>> {
  const out = new Map<string, Skill>();
  const walk = async (d: string): Promise<void> => {
    for (const e of await readdir(d, { withFileTypes: true })) {
      if (e.isDirectory()) await walk(join(d, e.name));
      else if (e.name.endsWith(".md") && e.name !== "INDEX.md") {
        const text = await readFile(join(d, e.name), "utf8");
        const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
        assert.ok(m, `${e.name} has front matter`);
        const meta: Record<string, string | string[]> = {};
        for (const line of m[1]!.split("\n")) {
          const [k, ...rest] = line.split(":");
          const v = rest.join(":").trim();
          meta[k!.trim()] = v.startsWith("[") ? v.slice(1, -1).split(",").map((x) => x.trim()).filter(Boolean) : v;
        }
        out.set(String(meta.id), { id: String(meta.id), meta, body: text.slice(m[0].length), text });
      }
    }
  };
  await walk(dir);
  return out;
}

/** The pack's directory closure by `depends` (the pack itself last), as the kickoff resolves a profile. */
async function closure(ids: string[], seen = new Set<string>(), order: string[] = []): Promise<string[]> {
  for (const id of ids) {
    if (seen.has(id)) continue;
    seen.add(id);
    const m = JSON.parse(await readFile(join(ROOT, "packs", id, "pack.json"), "utf8")) as { depends?: string[] };
    await closure((m.depends ?? []).map((d) => d.split(/[<>=!~ ]/)[0]!), seen, order);
    order.push(id);
  }
  return order;
}

async function renderOf(ids: string[], drop?: string, budget: SkillBudget = SKILL_BUDGET): Promise<ReturnType<typeof renderSkillsSection>["report"]> {
  const packs: PackIndex[] = [];
  for (const id of await closure(ids)) {
    const p = await readPackIndex(join(ROOT, "packs", id));
    packs.push(id === drop ? { ...p, router: null } : p);
  }
  return renderSkillsSection(packs, budget).report;
}

/** A pack that names no router and costs exactly `tokens`: the rest of a run, in the one respect the budget reads. */
function filler(tokens: number): PackIndex {
  const line = "- `filler/x` x";
  return { id: "filler", version: "", dir: "", entries: [{ id: "filler/x", line, tokens }], router: null, tokens };
}

function subsetsUpTo3(ids: string[], mustHave: string): string[][] {
  const others = ids.filter((i) => i !== mustHave);
  const out: string[][] = [[mustHave]];
  for (let i = 0; i < others.length; i++) {
    out.push([mustHave, others[i]!]);
    for (let j = i + 1; j < others.length; j++) out.push([mustHave, others[i]!, others[j]!]);
  }
  return out;
}

export type RouterSpec = {
  /** The pack's directory name under packs/. */
  pack: string;
  /** The router's id (`<topic>/router`). */
  router: string;
  /**
   * Every skill id of the pack before the router: other packs' `needs` and text name them, so all stay. This list is
   * written out per pack, so a PR that adds a leaf to the pack (a Phase C skill) must add its id here in the same
   * commit; the tests below say so (the pack's skills are one more than this list, and the router names each of them).
   */
  before: string[];
  /** Skills of other packs the pack's text names that the router must not (it names its own leaves only). */
  foreign?: string[];
  /** The profiles of images/profiles.json that carry the pack, and whether the pack is shown by its router in each (by the run's own budget). */
  profiles: string[];
};

export function routerChecks(spec: RouterSpec): void {
  const PACK = join(ROOT, "packs", spec.pack);
  const SKILLS = join(PACK, "skills");

  test(`${spec.pack}: the router is the pack's only router, within 400 tokens, and names every other skill exactly once; every old id is alive`, async () => {
    const skills = await loadSkills(SKILLS);
    const routers = [...skills.values()].filter((s) => s.meta.router === "true");
    assert.deepEqual(routers.map((s) => s.id), [spec.router], "one router, and it is the one named");
    const router = skills.get(spec.router)!;
    assert.ok(TOKENS(router.text) <= ROUTER_MAX, `the router is ${Math.round(TOKENS(router.text))} tokens`);
    assert.ok(TOKENS(router.text) >= 100, "a router that says nothing routes nothing");
    const first = router.body.trim().split("\n")[0]!;
    assert.match(first, /^Use when .*\bNot for\b/, "the router opens with Use when ... Not for ...");
    assert.deepEqual(router.meta.tools ?? [], [], "the router lists no tool");
    assert.deepEqual(router.meta.requires_host ?? [], [], "the router lists no program");
    assert.deepEqual(router.meta.needs ?? [], [], "the router needs nothing: it is read alone");
    // Every other skill is named once, as a line of its own; none twice, none missing, none of another pack.
    const named = [...router.body.matchAll(/`([a-z0-9-]+\/[a-z0-9-]+)`/g)].map((m) => m[1]!);
    assert.equal(new Set(named).size, named.length, `a skill is named twice: ${named.filter((n, i) => named.indexOf(n) !== i).join(", ")}`);
    assert.deepEqual([...named].sort(), [...skills.keys()].filter((id) => id !== spec.router).sort());
    for (const id of spec.foreign ?? []) assert.ok(!router.body.includes(id), `the router names ${id}, which is another pack's`);
    // No rule and no tool instruction: after the opening line a group heading (no code, short) or one line per leaf (the id, then
    // a few words), nothing longer, no sentence, no command.
    const lines = router.body.trim().split("\n").slice(1).filter((l) => l.trim());
    const leafLine = /^(`[a-z0-9-]+\/[a-z0-9-]+`) ([^`.:;]{3,70})$/;
    const heading = /^[A-Za-z][^`.:;]{1,40}$/;
    const phrases = new Map<string, string>();
    for (const l of lines) {
      const leaf = leafLine.exec(l);
      assert.ok(leaf || heading.test(l), `a router line is a heading or an id and a few words: "${l}"`);
      const said = leaf ? leaf[2]! : l;
      const limit = leaf ? PHRASE_WORDS : HEADING_WORDS;
      assert.ok(wordCount(said) <= limit, `a router ${leaf ? "phrase" : "heading"} is at most ${limit} words: "${l}"`);
      assert.ok(!OBLIGATION.test(said), `a router line holds no obligation or prohibition: "${l}"`);
      assert.ok(!IMPERATIVE.test(said) || (!leaf && wordCount(said) === 1), `a router line does not open with an order: "${l}"`);
      if (leaf) phrases.set(leaf[1]!.slice(1, -1), said);
    }
    // The phrase tells where to read, so it has to be about its leaf: it shares a content word with the leaf's title or when, and no other
    // leaf of the pack shares more (two leaves' phrases swapped, a router that sends a question to the wrong note, fail here). A failure
    // means the phrase says something the leaf does not; rewrite the phrase from the leaf's title and when.
    const about = new Map([...skills.values()].map((k) => [k.id, contentWords(`${k.meta.title ?? ""} ${k.meta.when ?? ""}`)]));
    for (const [id, said] of phrases) {
      const mine = sharedWords(contentWords(said), about.get(id)!);
      assert.ok(mine >= 1, `the router's phrase for ${id} shares no content word with its title or when: "${said}"`);
      for (const [other, words] of about) {
        if (other === id || other === spec.router) continue;
        assert.ok(sharedWords(contentWords(said), words) <= mine, `the router's phrase for ${id} ("${said}") fits ${other} better than ${id}`);
      }
    }
    assert.ok(!/```/.test(router.body), "no code block");
    // It names no tool and no program of the pack (an id may spell one: `aws/cloudtrail` is not the program `aws`).
    const bare = router.body.replace(/`[a-z0-9-]+\/[a-z0-9-]+`/g, "");
    const tools = (await readdir(join(PACK, "tools"), { withFileTypes: true }).catch(() => [])).filter((e) => e.isDirectory()).map((e) => e.name);
    const host = JSON.parse(await readFile(join(PACK, "requires", "host.json"), "utf8").catch(() => '{"binaries":[]}')) as { binaries: Array<{ name: string }> };
    for (const name of [...tools, ...host.binaries.map((b) => b.name)]) {
      assert.ok(!new RegExp(`(?<![\\w.-])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w-])`, "i").test(bare), `the router names ${name}`);
    }
    // The ids of the pack as they were before the router (other packs' `needs` and text name them): all of them still resolve.
    for (const id of spec.before) assert.ok(skills.has(id), `${id} is still a skill`);
    assert.equal(skills.size, spec.before.length + 1, "the router is the only new skill");
    // The generated index names it as the pack's router, which is the line the harness reads.
    const index = await readFile(join(SKILLS, "INDEX.md"), "utf8");
    assert.ok(index.split("\n").includes(`Router: \`${spec.router}\``), "INDEX.md says Router: ...");
    const manifest = JSON.parse(await readFile(join(PACK, "pack.json"), "utf8")) as { skills: number; method_only?: Array<{ path: string }> };
    assert.equal(manifest.skills, skills.size, "pack.json counts the router");
    assert.ok((manifest.method_only ?? []).some((e) => e.path === `skills/${spec.router}.md`), "the router names nothing of the pack's own, so it is method_only");
  });

  test(`${spec.pack}: the pack index is at most 1,000 tokens counted as the harness counts it, and the harness reads the router`, async () => {
    // Past 1,000 the harness shows the pack by its router alone in every run. The budget is on the entry lines of INDEX.md
    // (extensions/skills.ts readPackIndex), each its bytes / 4.245 rounded up; the header lines are not counted.
    const text = await readFile(join(SKILLS, "INDEX.md"), "utf8");
    const lines = text.split("\n").map((l) => l.trim()).filter((l) => /^- `[^`]+`/.test(l));
    const parsed = await readPackIndex(PACK);
    assert.deepEqual(parsed.entries.map((e) => e.line), lines, "the harness reads every entry line of the file, and no other");
    assert.equal(lines.reduce((n, l) => n + estimateTokens(l), 0), parsed.tokens);
    assert.ok(parsed.tokens <= SKILL_BUDGET.pack, `the ${spec.pack} index is ${parsed.tokens} tokens of entries, over ${SKILL_BUDGET.pack}`);
    assert.equal(parsed.entries.length, spec.before.length + 1);
    assert.equal(parsed.router, spec.router, "the harness reads the router the index names");
    const entry = parsed.entries.find((e) => e.id === spec.router)!;
    assert.ok(entry.tokens <= SKILL_BUDGET.entry, `the router's entry is ${entry.tokens} tokens`);
    assert.ok(entry.tokens < parsed.tokens / 4, "the router's line is a fraction of the pack's index: that is what showing it instead saves");
  });

  test(`${spec.pack}: beside a pack that fills the rest of the run's budget, the pack fits only because of its router`, async () => {
    const pack = await readPackIndex(PACK);
    const routerTokens = pack.entries.find((e) => e.id === spec.router)!.tokens;
    const rest = filler(SKILL_BUDGET.run - routerTokens);
    // With the router: the run is over, the pack is shown by its one line, and the entries shown are exactly the budget.
    const withRouter = renderSkillsSection([rest, pack]);
    assert.equal(withRouter.report.mode, "routers");
    assert.equal(withRouter.report.packs.find((p) => p.id === spec.pack)!.shown, "router");
    assert.equal(withRouter.report.shown_tokens, SKILL_BUDGET.run);
    assert.ok(withRouter.text.includes(`\`${spec.router}\``), "the prompt carries the router's line");
    for (const e of pack.entries.filter((x) => x.id !== spec.router)) assert.ok(!withRouter.text.includes(`\`${e.id}\``), `${e.id} is not in the prompt`);
    assert.deepEqual(withRouter.report.no_router, ["filler"], "only the pack that names none could not be shortened");
    // Without it the same run shows the whole pack, over the budget, and the report says which pack could not be shortened.
    const without = renderSkillsSection([rest, { ...pack, router: null }]);
    assert.ok(without.report.shown_tokens > SKILL_BUDGET.run, `without the router the run shows ${without.report.shown_tokens} tokens`);
    assert.equal(without.report.shown_tokens, SKILL_BUDGET.run - routerTokens + pack.tokens);
    assert.ok(without.report.no_router.includes(spec.pack));
    assert.ok(without.text.includes(`\`${pack.entries.find((e) => e.id !== spec.router)!.id}\``), "the whole pack is in the prompt");
  });

  test(`${spec.pack}: in the profiles and in every combination of up to three packs that carry it, a run over budget shows the pack by its router alone`, async () => {
    const profiles = JSON.parse(await readFile(join(ROOT, "images", "profiles.json"), "utf8")).profiles as Record<string, string[] | { packs: string[] }>;
    const sets: Array<[string, string[]]> = [];
    for (const name of spec.profiles) {
      const raw = profiles[name];
      assert.ok(raw, `profile ${name} exists`);
      const ids = Array.isArray(raw) ? raw : raw.packs;
      assert.ok((await closure(ids)).includes(spec.pack), `profile ${name} carries ${spec.pack}`);
      sets.push([`profile ${name}`, ids]);
    }
    const everyPack = (await readdir(join(ROOT, "packs"))).filter((p) => p !== "computer-forensics-base").sort();
    for (const ids of subsetsUpTo3(everyPack, spec.pack)) sets.push([`base + ${ids.join(" + ")}`, ids]);
    let over = 0;
    let fits = 0;
    for (const [label, ids] of sets) {
      const withRouter = await renderOf(ids);
      const without = await renderOf(ids, spec.pack);
      const mine = withRouter.packs.find((p) => p.id === spec.pack)!;
      // The harness's own verdict: a run is over when its entries, after any pack over the pack budget is shown by its router, pass the run's.
      const runOver = withRouter.over_budget.some((s) => s.startsWith("run "));
      const overBudget = runOver || mine.tokens > SKILL_BUDGET.pack;
      assert.equal(mine.router, spec.router, `${label}: the harness reads the router`);
      if (overBudget) {
        over++;
        assert.equal(mine.shown, "router", `${label}: ${withRouter.index_tokens} tokens of entries, the pack is shown by its router alone`);
        assert.equal(without.packs.find((p) => p.id === spec.pack)!.shown, "full", `${label}: without a router the pack is shown whole`);
        assert.ok(without.shown_tokens > withRouter.shown_tokens, `${label}: the run shows more without the router (${without.shown_tokens} against ${withRouter.shown_tokens})`);
        assert.ok(without.no_router.includes(spec.pack), `${label}: the report names the pack as having none`);
      } else {
        fits++;
        assert.equal(mine.shown, "full", `${label}: ${withRouter.index_tokens} tokens of entries fit, so the pack is shown whole`);
        assert.ok(withRouter.shown_tokens <= SKILL_BUDGET.run, `${label}: the run shows ${withRouter.shown_tokens} tokens`);
        // A run that fits today (the network and mobile profiles) is not a test of the router by itself: force the run budget one token
        // under what the run shows and the pack must be shown by its router, which is what it will be when the run carries more. (What the run shows,
        // not what the whole index costs: a pack over the pack budget is already shown by its router, and a budget between the two shortens nothing more.)
        const forced = await renderOf(ids, undefined, { ...SKILL_BUDGET, run: withRouter.shown_tokens - 1 });
        assert.equal(forced.packs.find((p) => p.id === spec.pack)!.shown, "router", `${label}: with the run budget forced to ${withRouter.shown_tokens - 1} the pack is shown by its router`);
        assert.ok(forced.shown_tokens < withRouter.shown_tokens);
      }
    }
    assert.ok(over + fits === sets.length && sets.length >= spec.profiles.length + 1);
  });
}
