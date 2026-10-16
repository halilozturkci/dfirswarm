/**
 * The SHARED BOUNDARY block of the windows-forensics tools, driven in-process (tests/fixtures/windows-boundary-driver.py cuts it out of each tool that
 * carries it): the cases that an independent review of the block found, each asserted on every tool that carries the block.
 *
 *  - time and memory: a run of backslashes (the escape patterns were quadratic), many names that become one placeholder (the renaming was cubic),
 *    every pattern of the block driven with hostile repeated shapes;
 *  - the backstop and the layers each on their own and together: user-info with a random user (the deny-list used to cut the user and leave the
 *    context), a password holding `/` and `+`, a user over 64 characters, a GitLab token glued to hexadecimal digits;
 *  - the report of where something was replaced does not print a withheld key;
 *  - hexadecimal data is decoded by the backstop, a typed field holds the characters of its type, a value that is not a string is sealed;
 *  - the pieces a cut leaves behind, the placeholders the block writes, the order of withheld names, the `contains` blind spot, the status basis.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, withCwd } from "./tool-library-harness.ts";
import { WIN, failed, tool } from "./windows-pack-harness.ts";

type Result = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const DRIVER = join(ROOT, "tests", "fixtures", "windows-boundary-driver.py");
const BEGIN = "# BEGIN SHARED BOUNDARY";
const END = "# END SHARED BOUNDARY";

/** The tools of this checkout that carry the block. */
async function carriers(): Promise<string[]> {
  const out: string[] = [];
  for (const name of (await readdir(WIN)).sort()) {
    const text = await readFile(join(WIN, name, "run.py"), "utf8").catch(() => "");
    if (text.includes(BEGIN)) out.push(name);
  }
  return out;
}

const modules = new Map<string, Promise<{ file: string; dir: string }>>();
/** The block of a tool, with the imports it needs, as a module file. */
function moduleOf(name: string): Promise<{ file: string; dir: string }> {
  let made = modules.get(name);
  if (!made) {
    made = (async () => {
      const text = await readFile(join(WIN, name, "run.py"), "utf8");
      const dir = await mkdtemp(join(tmpdir(), "win-block-"));
      const file = join(dir, "block.py");
      await writeFile(file, "import re, json, os, sys\nfrom pathlib import Path\n" + text.slice(text.indexOf(BEGIN), text.indexOf(END) + END.length) + "\n");
      return { file, dir };
    })();
    modules.set(name, made);
  }
  return made;
}

async function drive(name: string, kase: string, ...extra: string[]): Promise<Result> {
  const { file } = await moduleOf(name);
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [DRIVER, file, kase, ...extra]);
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => out.push(c));
    child.stderr.on("data", (c: Buffer) => err.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      const text = Buffer.concat(out).toString("utf8");
      if (code !== 0) reject(new Error(`${name} ${kase}: exit ${code}: ${Buffer.concat(err).toString("utf8")}`));
      else resolve(JSON.parse(text) as Result);
    });
  });
}

const names = await carriers();

test("the block is found in the tools of this checkout", () => {
  assert.ok(names.length >= 1, "at least one tool carries the shared boundary block");
});

for (const name of names) {
  test(`${name}: a run of backslashes is read in linear time (64k and 256k characters), in a name, in text and in hexadecimal data`, async () => {
    const r = await drive(name, "backslashes");
    for (const [k, v] of Object.entries(r)) if (k !== "escape_removed") assert.ok((v as number) < 2.5, `${k}: ${v} s`);
    assert.equal(r.escape_removed, true, "an escaped invisible character is still taken out");
  });

  test(`${name}: 6,000 names that become one placeholder are renamed in linear time and bounded memory`, async () => {
    const r = await drive(name, "same_marker_keys");
    assert.ok(r.seconds < 5, `${r.seconds} s`);
    assert.equal(r.keys, 6000);
    assert.ok(r.longest_key < 100, `a key of ${r.longest_key} characters`);
    assert.ok(r.json_bytes < 3_000_000, `${r.json_bytes} bytes of JSON`);
    assert.ok(r.peak_growth_mb < 150, `${r.peak_growth_mb} MB`);
    assert.equal(r.distinct_values_kept, true, "every value is under a key of its own");
    assert.equal(r.odd_keys_json, true, "a key that is not text still serialises");
  });

  test(`${name}: every pattern of the block against hostile repeated shapes of 16,000 characters and their prefixes`, async () => {
    const r = await drive(name, "redos", "16000");
    assert.deepEqual(r.slow, [], `slower than 2.5 s: ${JSON.stringify(r.slow)}`);
  });

  test(`${name}: strings past the 100,000-character window of the old PEM pattern (110,000, 262,144 and 1 MiB), with a token that makes a layer change them, are judged in CPU seconds, not minutes, and the token is not printed`, async () => {
    const r = await drive(name, "big", "110000,262144,1048576");
    assert.deepEqual(r.slow, [], `slower than 4 s of CPU, or the leading token printed: ${JSON.stringify(r.slow)}`);
    assert.ok(r.cases >= 40, `${r.cases} cases`);
  });

  test(`${name}: an answer that takes longer than the seal budget has the rest of its strings replaced whole, is partial, and the clock stops`, async () => {
    const r = await drive(name, "budget");
    assert.equal(r.status, "partial");
    assert.ok(r.late_marks >= 30, `${r.late_marks} strings replaced for the clock`);
    assert.equal(r.unjudged_printed, 0, "no string that was not judged is printed");
    assert.equal(r.short_kept, true, "short plain strings and the structure of the answer are kept");
    assert.equal(r.tail_withheld, true);
    assert.ok(r.counted >= r.late_marks, "they are counted under their own reason");
    assert.equal(r.clock_stopped, true);
    assert.equal(r.after, true, "the next seal is not late");
    assert.equal(r.stop_late, true, "a seal that starts past the tool's hard stop withholds what is not short and plain");
    assert.equal(r.stop_cleared, true);
    assert.ok(r.seconds < 8, `${r.seconds} s of CPU`);
    assert.match(r.basis, /^\d+ string\(s\) still held/);
  });

  test(`${name}: a contains filter sees the text the answer prints: a true piece of a secret that only the backstop replaces and a wrong one give the same answer`, async () => {
    const r = await drive(name, "contains_sealed");
    assert.equal(r.plants, 16);
    assert.equal(r.differ, 0, "a true piece, the whole secret and a wrong needle are told apart in the count or in the blind spot");
    assert.equal(r.secret_in_sealed, 0, "the text the filter reads does not hold the secret");
    assert.equal(r.counters_moved, 0, "sealing a string for the filter counts and lists nothing");
    assert.equal(r.whole_string_gone, r.plants, "the rest of a replaced string cannot be matched either: the filter reads what is printed");
    assert.deepEqual(r.blind_when_hidden, [false, true]);
    assert.deepEqual(r.plain_text_found, [true, false]);
    assert.deepEqual(r.plain_text_absent, [false, false]);
  });

  test(`${name}: the residue check does not take the attributes of an event (RelatedActivityID="", EventSourceName=, processorArchitecture=) for a padded base64 key`, async () => {
    const r = await drive(name, "residue_fp");
    assert.equal(r.replaced_by_the_backstop, 0, "nothing is replaced by the backstop");
    assert.equal(r.attributes_kept, r.n);
    assert.equal(r.status_complete, r.n, "the answers stay complete");
    assert.equal(r.real_b64_found, true, "a real padded base64 key is still found");
  });

  test(`${name}: acronym names are plain, a typed version has the shape of a version, sk- with a late digit, a full-width token in hexadecimal data, and the names of the component store`, async () => {
    const r = await drive(name, "shapes_p3");
    assert.deepEqual(r.names_changed, [], "NumberOfGPOsDownloaded and its kind are plain names");
    assert.equal(r.random_names_withheld, 100, "random names of 24 characters are still withheld");
    assert.deepEqual(r.version_ok_flagged, []);
    assert.equal(r.version_base62_flagged, 200, "a base62 string that starts with a digit is not a version, for the backstop on its own");
    assert.equal(r.sk_late_digit_flagged_backstop, true);
    assert.equal(r.sk_late_digit_layer2, true);
    assert.equal(r.sk_words_kept, true);
    assert.deepEqual(r.wide_hex_flagged, [true, true, true], "UTF-8, UTF-16LE and UTF-16BE hexadecimal data holding a full-width token");
    assert.deepEqual(r.wide_hex_printed, [false, false]);
    assert.equal(r.random_binary_still_printed, 20, "random bytes with no text in them are still printed (documented)");
    assert.deepEqual(r.winsxs_kept, [true, true, true, true, true, true], "names of the component store are shown in a name and a key slot");
    assert.deepEqual(r.winsxs_in_path_and_key_kept, [true, true], "a component of the component store in a path or a key is not replaced by the backstop");
    assert.equal(r.dressed_in_path_not_printed, true, "a secret dressed as one, in a path, is not printed");
    assert.equal(r.text_slot_not_exempt, true, "free text is not exempt");
    assert.equal(r.winsxs_hash_names_cut_once, true, "a component name that is a hash is cut by layer 1 and not replaced again by the backstop");
    assert.deepEqual(r.dressed_exempt, [false, false, false], "a secret dressed as one is not exempt");
  });

  test(`${name}: user-info with a random user, a password holding / and +, and a user over 64 characters: none printed, by the layers alone, the backstop alone and together`, async () => {
    const r = await drive(name, "userinfo");
    for (const mode of ["together", "layers_only", "backstop_only"]) {
      for (const [family, count] of Object.entries(r[mode] as Record<string, number>)) assert.equal(count, 0, `${mode}: ${family} printed in ${count} of ${r.n}`);
    }
  });

  test(`${name}: a GitLab token glued to hexadecimal digits is not printed in a text, host, path, key or URL slot, by the layers alone, the backstop alone and together`, async () => {
    const r = await drive(name, "glued");
    for (const [slot, count] of Object.entries(r.whole as Record<string, number>)) assert.equal(count, 0, `${slot}: ${count} of ${r.n}`);
    assert.deepEqual(r.alone, { backstop_only: 0, layers_only: 0 });
  });

  test(`${name}: the place of a replacement never prints a withheld key (a secret-shaped key beside a value only the backstop replaces)`, async () => {
    const r = await drive(name, "replaced_at");
    assert.equal(r.keys_printed, 0, `${r.keys_printed} of ${r.plants} keys printed whole`);
    assert.equal(r.windows_printed, 0, `${r.windows_printed} of ${r.plants} keys printed in part`);
    assert.equal(r.with_place, r.plants, "every replacement says where");
  });

  test(`${name}: hexadecimal data is decoded by the backstop on its own; a typed field holds the characters of its type; random bytes with no text are printed (the documented limit)`, async () => {
    const r = await drive(name, "hex");
    assert.equal(r.claimed_hex_flagged, r.claimed_hex, "the backstop alone flags every hex-encoded shape it claims");
    assert.equal(r.claimed_hex_printed, 0, "and the whole pipeline prints none");
    assert.equal(r.random_binary_printed, r.random_binary, "binary with no text in it is shown: the documentation says so, so this must stay true");
    assert.equal(r.ip_field_base64_replaced, r.ip_field, "base64 in a field typed as an address is replaced by the backstop alone");
  });

  test(`${name}: a value that is not text, a number or a container is sealed as the text str() makes of it`, async () => {
    const r = await drive(name, "scalars");
    assert.equal(r.secret_printed, false);
    assert.equal(r.pieces_kept, true);
  });

  test(`${name}: every placeholder the block writes is one of the fixed list, taken for a placeholder by both patterns`, async () => {
    const r = await drive(name, "labels");
    assert.ok(r.markers > 10, "the case made placeholders");
    assert.deepEqual(r.not_recognised, []);
  });

  test(`${name}: a cut that leaves a piece of a secret between two cuts is caught, and the words of the text itself are not taken for one`, async () => {
    const r = await drive(name, "residue");
    for (const [shape, counts] of Object.entries(r)) {
      if (shape.startsWith("benign")) continue;
      assert.deepEqual(counts, [0, 0], `${shape}: [whole, a 12-character piece] printed in 300 plants`);
    }
    assert.deepEqual(r.benign_changed, [], "benign strings are unchanged");
    assert.equal(r.benign_backstop_replaced, 0, "the backstop leaves lines alone whose own words repeat the name of a secret");
  });

  test(`${name}: withheld names are listed by the text shown for each and the placeholders in an order of their own, new every run; contains says when the needle could be hidden`, async () => {
    const r = await drive(name, "order_and_contains");
    assert.ok(r.distinct_orders > 10, "the order of equal placeholders changes with the salt");
    assert.equal(r.rank_order_always, false, "the order of the raw names is not the printed order");
    assert.equal(r.plain_names_sorted_among_themselves, true);
    assert.ok(r.backstop_only_distinct_orders > 10, "names the layers show and the backstop replaces are in an order of their own too");
    assert.equal(r.backstop_only_rank_order_always, false, "and it is not the order of their raw text");
    assert.equal(r.order_counts_nothing, true, "judging for the order is not withholding");
    assert.deepEqual(r.contains_hit_shown, [true, false]);
    assert.deepEqual(r.contains_in_withheld, [false, true], "not found in the text shown, and text is withheld: blind");
    assert.deepEqual(r.contains_nothing_withheld, [false, false], "not found and nothing withheld: a real absence");
    assert.equal(r.blind_does_not_depend_on_needle, true, "the blind spot says nothing of what the hidden text is");
  });

  test(`${name}: the status basis of a backstop-partial answer does not begin with a separator`, async () => {
    const r = await drive(name, "basis");
    assert.equal(r.status, "partial");
    assert.match(r.basis, /^\d+ string\(s\) still held/);
  });

  test(`${name}: arguments that are a JSON array are refused as JSON with a status, never a traceback`, async () => {
    for (const bad of [[], [1, 2], "text", 7, null]) {
      await withCwd(async (cwd) => {
        const run = await tool(name, cwd, bad);
        const answer = failed(run);
        assert.equal(answer.status, "failed", JSON.stringify(bad));
        assert.match(String(answer.error), /JSON object|is not installed/i, JSON.stringify(bad));      // a tool whose library is missing says so first: still JSON, still a status
      });
    }
  });
}

test("the scratch modules are removed", async () => {
  for (const made of modules.values()) await rm((await made).dir, { recursive: true, force: true });
});
