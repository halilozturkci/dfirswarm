/**
 * The copied parts of the linux tools. A tool of this pack is standalone (none imports another), so the code that pages, keeps text and
 * answers a stop signal is copied into each tool that needs it. Each copy sits between BEGIN and END markers, one family per text:
 *
 *   LINUX PARTS  fail, the argument readers, status_of, LosslessPage, TextFile and the rest: in every tool that pages or keeps text
 *   LINUX STOP   the last word of a stop signal (STATE, _on_signal): in every such tool whose stop is not the SHARED PROCESS block's
 *   LINUX IMAGE  the disk-image refusal: in every tool that reads a file or an extracted root
 *
 * These cases hold each text equal across its carriers (the carriers are found by walking the pack's tools, not named), hold a floor on
 * how many there are, show that a one-byte drift fails the check, and run the disk-image block alone against a file whose read would block.
 */
import assert from "node:assert/strict";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet, withCwd } from "./tool-library-harness.ts";

const TOOLS = join(ROOT, "packs", "linux-forensics", "tools");
const FAMILIES = ["PARTS", "STOP", "IMAGE"] as const;
type Family = (typeof FAMILIES)[number];
const FLOOR: Record<Family, number> = { PARTS: 9, STOP: 7, IMAGE: 8 };

async function sources(): Promise<Record<string, string>> {
  const found: Record<string, string> = {};
  for (const e of await readdir(TOOLS, { withFileTypes: true })) {
    if (e.isDirectory()) found[e.name] = await readFile(join(TOOLS, e.name, "run.py"), "utf8").catch(() => "");
  }
  return found;
}

/** The text of a family from its BEGIN line to its END line, or null; a tool with two pairs of one family is a failure of its own. */
function blockOf(text: string, family: Family): string | null {
  const begin = `# BEGIN LINUX ${family}\n`;
  const end = `# END LINUX ${family}`;
  const first = text.indexOf(begin);
  if (first < 0) return null;
  assert.equal(text.indexOf(begin, first + 1), -1, `a second ${begin.trim()} in one tool is a second variant`);
  const stop = text.indexOf(end, first);
  assert.ok(stop > first, `${begin.trim()} has no END line`);
  assert.equal(text.indexOf(end, stop + 1), -1, `a second ${end} in one tool`);
  return text.slice(first, stop + end.length);
}

/** Every family's carriers must hold one text: returns the names of the tools that differ from the first. */
function drift(all: Record<string, string>, family: Family): string[] {
  const blocks = Object.entries(all).map(([name, text]) => [name, blockOf(text, family)] as const).filter(([, b]) => b !== null);
  const [, reference] = blocks[0];
  return blocks.filter(([, b]) => b !== reference).map(([name]) => name);
}

test("each marked text of the linux tools is byte-equal in every carrier, and there are carriers enough", async () => {
  const all = await sources();
  for (const family of FAMILIES) {
    const carriers = Object.entries(all).filter(([, text]) => blockOf(text, family) !== null).map(([name]) => name);
    assert.ok(carriers.length >= FLOOR[family], `${family}: ${carriers.length} carriers (${carriers.join(", ")}), at least ${FLOOR[family]} expected`);
    assert.deepEqual(drift(all, family), [], `${family} differs between its carriers`);
  }
});

test("a tool that pages or keeps text carries the parts, and a tool that reads a file or a root carries the image block, not a copy outside the markers", async () => {
  const all = await sources();
  for (const [name, text] of Object.entries(all)) {
    const pages = /^class (LosslessPage|TextFile)\b/m.test(text);
    assert.equal(blockOf(text, "PARTS") !== null, pages, `${name}: LosslessPage/TextFile and the PARTS markers go together`);
    if (pages) {
      const outside = text.replace(blockOf(text, "PARTS") as string, "");
      assert.doesNotMatch(outside, /^class (LosslessPage|TextFile)\b|^def (fail|status_of|read_args)\(/m, `${name}: a part is defined outside the markers`);
    }
    assert.equal(blockOf(text, "IMAGE") !== null, /^def refuse_disk_image\b/m.test(text), `${name}: refuse_disk_image and the IMAGE markers go together`);
    if (/^def _on_signal\b/m.test(text) && blockOf(text, "STOP") === null) {
      assert.match(text, /# BEGIN SHARED PROCESS/, `${name}: a stop outside LINUX STOP is the SHARED PROCESS block's`);
    }
  }
});

test("a one-byte drift in one carrier is found", async () => {
  const all = await sources();
  for (const family of FAMILIES) {
    const carriers = Object.keys(all).filter((name) => blockOf(all[name], family) !== null);
    const victim = carriers.at(-1) as string;
    const block = blockOf(all[victim], family) as string;
    const planted = { ...all, [victim]: all[victim].replace(block, block.replace("def ", "def  ")) };
    assert.notEqual(planted[victim], all[victim], "the plant changed something");
    assert.deepEqual(drift(planted, family), [victim], `${family}: a changed byte in ${victim} was not found`);
  }
});

test("the image block, run alone, opens a file without blocking and lets a file whose read would wait go on to the tool's own checks", async () => {
  const all = await sources();
  const block = (blockOf(all.auth_log, "IMAGE") as string).split("\n").filter((l) => !l.startsWith("# BEGIN") && !l.startsWith("# END")).join("\n");
  const program = String.raw`
import os, stat, sys, errno
class Refused(Exception):
    pass
def fail(message, **extra):
    raise Refused(message)
` + block + String.raw`
path = sys.argv[1]
flags = []
real_open, real_read = os.open, os.read
def watched_open(p, f, *a):
    flags.append(f)
    return real_open(p, f, *a)
def blocked_read(fd, n):
    raise BlockingIOError(errno.EAGAIN, "would block")      # what a non-blocking read of /proc/kmsg answers when there is nothing to read
os.open, os.read = watched_open, blocked_read
try:
    refuse_disk_image(path, "path")
    print("went on", all(f & os.O_NONBLOCK for f in flags) and len(flags) == 1)
except Refused as exc:
    print("refused", exc)
os.read = real_read
`;
  await withCwd(async (cwd) => {
    await mkdir(join(cwd, "work"), { recursive: true });
    const file = join(cwd, "work", "waits.log");
    await writeFile(file, "a regular file\n");
    const waits = await runPySnippet(program, [file], null);
    assert.equal(waits.code, 0, waits.stderr);
    assert.equal(waits.stdout.trim(), "went on True", "the open is non-blocking and a read that would wait is no image");
    // The same block refuses a real image by its first bytes (the QCOW2 magic), so the harness above is not just passing everything.
    const image = join(cwd, "work", "disk.bin");
    await writeFile(image, Buffer.concat([Buffer.from("QFI\xfb", "latin1"), Buffer.alloc(600)]));
    const refused = await runPySnippet(program.replace("os.open, os.read = watched_open, blocked_read", "pass"), [image], null);
    assert.match(refused.stdout, /^refused path is a disk image/);
  });
});
