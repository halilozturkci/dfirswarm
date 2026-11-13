/**
 * computer-forensics-base: ioc_scan says what chunk_needles says about a compressed or packed container, in the same words.
 *
 * Both scanners read the bytes of a file as they are stored. chunk_needles learned to say so when the file begins like a container (an
 * AD1 or EWF segment, a ZIP, gzip and the rest): the answer is partial, names the container and says the content was not searched.
 * ioc_scan read the same file and answered `complete`. It now carries the same table, the same reading of it and the same sentence:
 * the three texts are held equal here, and the two tools are run on the same files. The rules of the note that names ioc_scan
 * (filesystem/scanners) are in its answer, its refusals, its manifest and the note's card.
 */
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { test } from "node:test";
import { call, CFB, ROOT, withRun, type Doc } from "./pack-base-media-fixture.ts";

const source = (tool: string): Promise<string> => readFile(join(CFB, "tools", tool, "run.py"), "utf8");
const between = (text: string, from: string, to: string): string => {
  const a = text.indexOf(from);
  const b = text.indexOf(to, a);
  assert.ok(a >= 0 && b > a, `the text from "${from.slice(0, 40)}" is there`);
  return text.slice(a, b);
};
const undent = (text: string): string => text.split("\n").map((l) => l.replace(/^ {4}/, "")).join("\n");

test("the table of containers, the function that reads it and the sentence of the answer are one text in the two scanners", async () => {
  const [needles, ioc] = await Promise.all([source("chunk_needles"), source("ioc_scan")]);
  const table = (t: string): string => between(t, "# A stream that is a compressed or packed container", "\n\n\n");
  assert.equal(table(ioc), table(needles), "CONTAINERS, with its comment");
  const reading = (t: string): string => between(t, "def container_of(head):", "    return None\n");
  assert.equal(reading(ioc), reading(needles), "container_of");
  const wordsOfNeedles = between(needles, "if container is not None:\n    # The stored bytes were searched", "print_answer(answer)").replace(/\n+$/, "");
  const wordsOfIoc = undent(between(ioc, "    if container is not None:\n        # The stored bytes were searched", "    if unique_only and locators.hidden:")).replace(/\n+$/, "");
  assert.equal(wordsOfIoc, wordsOfNeedles, "the sentence, and how the segment is named");
  assert.ok(wordsOfNeedles.length > 500);
  // The library twin is the pack's file, byte for byte.
  for (const file of ["run.py", "manifest.json"]) {
    assert.ok((await readFile(join(ROOT, "tool-library", "ioc_scan", file))).equals(await readFile(join(CFB, "tools", "ioc_scan", file))), `tool-library/ioc_scan/${file}`);
  }
});

test("ioc_scan and chunk_needles answer partial for the same containers, name them alike, and stay complete for a plain file", async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    const needle = "marker-in-the-content";
    // An AD1 segment header (segment 2 of 12), a gzip stream and a ZIP local header, each with the needle absent from the stored bytes.
    const ad1 = Buffer.alloc(4096);
    ad1.write("ADSEGMENTEDFILE\0", 0, "latin1");
    ad1.writeUInt32LE(2, 0x18);
    ad1.writeUInt32LE(12, 0x1c);
    await writeFile(join(run, dir, "image part.ad2"), ad1);
    await writeFile(join(run, dir, "notes.gz"), gzipSync(Buffer.from(`${needle} `.repeat(200))));
    await writeFile(join(run, dir, "bundle.zip"), Buffer.concat([Buffer.from("PK\x03\x04", "latin1"), Buffer.alloc(200)]));
    await writeFile(join(run, dir, "plain.bin"), Buffer.from(`before ${needle} after`));
    for (const [name, format, what] of [["image part.ad2", "AccessData AD1 logical image", "segment 2 of 12 of an AccessData AD1 logical image"], ["notes.gz", "gzip stream", "a gzip stream"], ["bundle.zip", "ZIP archive", "a ZIP archive"]] as const) {
      const answers: Doc[] = [];
      for (const tool of ["ioc_scan", "chunk_needles"]) {
        const r = await call(tool, run, { path: `${dir}/${name}`, needles: needle }, { out });
        assert.equal(r.code, 0, `${tool} ${name}: ${r.stdout}${r.stderr}`);
        assert.deepEqual([r.doc.status, r.doc.complete, r.doc.container.format, r.doc.container.what, r.doc.container.content_searched], ["partial", false, format, what, false], `${tool} ${name}`);
        assert.match(r.doc.status_basis, new RegExp(`^the stream is ${what}.*Its content is compressed or packed and was not searched: the bytes were scanned as they are stored`), `${tool} ${name}`);
        answers.push(r.doc);
      }
      const lead = (d: Doc): string => String(d.status_basis).split(" Of the stored bytes: ")[0]!;
      assert.equal(lead(answers[0]!), lead(answers[1]!), `the two tools say the same of ${name}`);
      assert.deepEqual(answers[0]!.container, answers[1]!.container);
    }
    // The gzip file holds the needle 200 times in its content and nowhere in its stored bytes: the miss is said to be no negative.
    const gz = await call("ioc_scan", run, { path: `${dir}/notes.gz`, needles: needle }, { out });
    assert.equal(gz.doc.hit_count_returned, 0);
    assert.match(gz.doc.status_basis, /a needle that was not found is not shown to be absent from the content \(its content is deflated: write it out with archive_extract and scan that\)/);
    // A scan that begins past the file's head still reads the head for what the file is.
    const later = await call("ioc_scan", run, { path: `${dir}/notes.gz`, needles: needle, start: 20 }, { out });
    assert.equal(later.doc.container.format, "gzip stream");
    const plain = await call("ioc_scan", run, { path: `${dir}/plain.bin`, needles: needle }, { out });
    assert.deepEqual([plain.doc.status, plain.doc.complete, plain.doc.container, plain.doc.hit_count_returned], ["complete", true, undefined, 1]);
  });
});

test("the rules of filesystem/scanners are in ioc_scan's answer, its refusals, its manifest and the note's card", async () => {
  const manifest = JSON.parse(await readFile(join(CFB, "tools", "ioc_scan", "manifest.json"), "utf8")) as Doc;
  assert.match(manifest.description, /A file whose first bytes are a compressed or packed container's .* is scanned as it is stored, and the answer says so/);
  const sibling = JSON.parse(await readFile(join(CFB, "tools", "chunk_needles", "manifest.json"), "utf8")) as Doc;
  const sentence = (d: string): string => /(?:A stream|A file) whose first bytes are a compressed or packed container's(.*?how to reach it\.)/.exec(d)![1]!;
  assert.equal(sentence(manifest.description), sentence(sibling.description), "the two manifests say it in one wording");
  await withRun(async (run, out) => {
    await writeFile(join(run, "inputs/case files/plain.bin"), "some bytes");
    const ok = await call("ioc_scan", run, { path: "inputs/case files/plain.bin", needles: "bytes" }, { out });
    const rules = ok.doc.rules as string[];
    assert.ok(rules.length >= 3 && rules.length <= 5);
    for (const rule of rules) assert.ok(manifest.description.includes(rule), rule.slice(0, 60));
    assert.match(rules[0]!, /is answered partial with `container`: write its content out/);
    const refused = await call("ioc_scan", run, { path: "inputs/case files/absent.bin", needles: "x" }, { out });
    assert.notEqual(refused.code, 0);
    assert.deepEqual(refused.doc.rules, rules, "a refusal carries the rules");
  });
  const note = await readFile(join(CFB, "skills", "filesystem", "scanners.md"), "utf8");
  const card = /^card: (.+)$/m.exec(note)?.[1] ?? "";
  assert.ok(card.length > 100 && card.length <= 700);
  assert.match(card, /\{"path": "<file>", "needles": "a\|b"\}/);
  assert.match(card, /answers partial with `container`/);
  assert.match(card, /\{"start": <next_start>\}/);
});
