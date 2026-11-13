/**
 * The process and memory dumps a catalogue lists (IMPROVEMENT-PLAN-2 item
 * E7): when a kickoff generation is published, its member table is read
 * once for members whose name is a dump's (a crash or process dump, a
 * hibernation, page or swap file, a VM's memory file), and the seats are
 * told which there are, how large, and what in the run's packs reads one.
 * In eight runs of one case a process dump sat in the image for hours before
 * a seat opened it, and three seats found it apart.
 *
 * By name only: nothing is opened. A dump under another name is not found
 * here, and the post says so.
 */
import { createReadStream, existsSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";

/** A member whose name is a dump's. */
export type DumpMember = { path: string; bytes: number; locator: string; kind: string };

const KINDS: Array<[RegExp, string]> = [
  [/(^|[\\/])hiberfil\.sys$/i, "hibernation file"],
  [/(^|[\\/])(pagefile|swapfile)\.sys$/i, "page or swap file"],
  [/(^|[\\/])memory\.dmp$/i, "kernel crash dump"],
  [/\.(dmp|mdmp|hdmp)$/i, "process or crash dump"],
  [/\.(vmem|vmsn|vmss|lime|core|mem)$/i, "memory image"],
];

/** What kind of dump a path's name says it is, or null. */
export function dumpKind(path: string): string | null {
  for (const [re, kind] of KINDS) if (re.test(path)) return kind;
  return null;
}

/** How many dump members a post names (the largest first); the count of all is said. */
export const DUMPS_SHOWN = 12;
/** A member table is read to this many rows; past it the answer says it stopped. */
export const DUMP_ROWS_MAX = 5_000_000;

/**
 * The dump-named members of a generation's member table (members.tsv with a
 * header naming `path` and `size`), read as a stream: the largest
 * DUMPS_SHOWN, the count and bytes of all, and whether the table was read
 * whole.
 */
export async function dumpMembers(tsv: string, shown: number = DUMPS_SHOWN): Promise<{ total: number; bytes: number; top: DumpMember[]; rows: number; whole: boolean } | null> {
  if (!existsSync(tsv)) return null;
  const rl = createInterface({ input: createReadStream(tsv, { encoding: "utf8" }), crlfDelay: Infinity });
  let cols: { path: number; size: number; locator: number } | null = null;
  let rows = 0;
  let total = 0;
  let bytes = 0;
  let whole = true;
  const top: DumpMember[] = [];
  try {
    for await (const line of rl) {
      const f = line.split("\t");
      if (!cols) {
        cols = { path: f.indexOf("path"), size: f.indexOf("size"), locator: f.indexOf("locator") };
        if (cols.path < 0 || cols.size < 0) return null;
        continue;
      }
      rows += 1;
      if (rows > DUMP_ROWS_MAX) {
        whole = false;
        break;
      }
      const path = f[cols.path] ?? "";
      const kind = dumpKind(path);
      if (!kind) continue;
      const n = Number(f[cols.size]);
      if (!Number.isFinite(n) || n <= 0) continue;
      total += 1;
      bytes += n;
      top.push({ path, bytes: n, locator: cols.locator >= 0 ? (f[cols.locator] ?? "") : "", kind });
      if (top.length > shown * 4) {
        top.sort((a, b) => b.bytes - a.bytes);
        top.length = shown;
      }
    }
  } finally {
    rl.close();
  }
  top.sort((a, b) => b.bytes - a.bytes || a.path.localeCompare(b.path));
  top.length = Math.min(top.length, shown);
  return { total, bytes, top, rows, whole };
}

const size = (n: number): string => (n >= 1024 ** 3 ? `${(n / 1024 ** 3).toFixed(1)} GiB` : n >= 1024 ** 2 ? `${(n / 1024 ** 2).toFixed(1)} MiB` : n >= 1024 ? `${Math.round(n / 1024)} KiB` : `${n} B`);
const cut = (s: string, n: number): string => (s.length > n ? `…${s.slice(-(n - 1))}` : s);

/**
 * The post for a generation that lists dumps, or null when it lists none:
 * each of the largest with its size and how to name it, the count of all,
 * and the tools of the run's packs that read a dump (`readers`, by name;
 * none loaded is said, since a seat would otherwise write its own parser).
 */
export function dumpsPost(generation: string, over: string, found: { total: number; bytes: number; top: DumpMember[]; whole: boolean }, readers: string[]): string | null {
  if (!found.total) return null;
  const lines = found.top.map((d) => `- ${cut(d.path, 160)} (${size(d.bytes)}, ${d.kind}${d.locator ? `; ${d.locator}` : ""})`);
  const more = found.total > found.top.length ? ` These are the ${found.top.length} largest; catalog_search over ${generation} finds the rest by name.` : "";
  const how = readers.length
    ? `In this run's packs ${readers.join(", ")} ${readers.length === 1 ? "reads" : "read"} one: extract the member as a job, then run the tool on it.`
    : "No tool of this run's packs reads a dump by its structure: extract the member as a job and say in a limitation what you could not read.";
  return [
    `The catalogue ${generation} of ${over} lists ${found.total} member${found.total === 1 ? "" : "s"} named as a process or memory dump (${size(found.bytes)} in all). A dump holds what a process had in memory when it was written (keys, decoded strings, unpacked code), which the files on disk may not.${more}`,
    ...lines,
    `${how} Found by name alone${found.whole ? "" : `, in the first ${DUMP_ROWS_MAX} rows`}: a dump under another name is not in this list.`,
  ].join("\n");
}

/** The member table of a generation, where the catalogue keeps it. */
export function membersTsv(S: string, generation: string): string {
  return join(S, "catalog", "gen", generation, "members.tsv");
}
