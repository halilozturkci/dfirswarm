/**
 * encrypted-containers: the three tools print names, paths and header strings that come from evidence, and stop on signals. They share
 * blocks of code, held equal here, and this suite holds the withholding rule to random canaries built from pieces (never a literal
 * that looks like a secret) with the rates the manifests state, and holds the independent output check to a sanitiser that is removed.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { ROOT, runPySnippet } from "./tool-library-harness.ts";

const TOOLS = join(ROOT, "packs", "encrypted-containers", "tools");
const RKS = join(TOOLS, "recovery_key_scan", "run.py");
const AP = join(TOOLS, "archive_probe", "run.py");
const CID = join(TOOLS, "crypto_id", "run.py");
const NETWORK = join(ROOT, "packs", "network-forensics", "tools", "pcap_summary", "run.py");
const WINDOWS = join(ROOT, "packs", "windows-forensics", "tools", "regkv", "run.py");

async function block(path: string, name: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const begin = `# BEGIN SHARED ${name}`;
  const end = `# END SHARED ${name}`;
  const start = text.indexOf(begin);
  const stop = text.indexOf(end);
  assert.ok(start >= 0 && stop > start, `${path} carries the ${name} block`);
  assert.equal(text.indexOf(begin, start + 1), -1, "once");
  return text.slice(start, stop + end.length);
}

test("the tools carry the same blocks, byte for byte", async () => {
  for (const name of ["WITHHOLDING", "NAMES", "STOP"]) {
    const copies = await Promise.all([RKS, AP, CID].map((p) => block(p, name)));
    for (const other of copies.slice(1)) assert.equal(other, copies[0], `${name} differs between the tools`);
    assert.ok(copies[0].length > 1000);
  }
  for (const name of ["PLACE", "PAGE"]) {
    const copies = await Promise.all([RKS, AP].map((p) => block(p, name)));
    assert.equal(copies[1], copies[0], `${name} differs`);
  }
  // The blocks that are another pack's are the other pack's text: the network withholding block, the network process block (the
  // archive_probe 7z child) and the windows no-replace paging blocks. Their owners converge them later; until then they are copies.
  assert.equal(await block(RKS, "WITHHOLDING"), await block(NETWORK, "WITHHOLDING"));
  assert.equal(await block(AP, "PROCESS"), await block(join(ROOT, "packs", "network-forensics", "tools", "pcap_extract", "run.py"), "PROCESS"));
  assert.equal(await block(RKS, "PLACE"), await block(WINDOWS, "PLACE"));
  assert.equal(await block(RKS, "PAGE"), await block(WINDOWS, "PAGE"));
});

test("no tool starts a program in a session of its own", async () => {
  for (const path of [RKS, AP, CID]) {
    const text = await readFile(path, "utf8");
    assert.doesNotMatch(text.replace(/^\s*#.*$/gm, "").replace(/"""[\s\S]*?"""/g, ""), /start_new_session|setsid|process_group/, path);
  }
});

/** Python that loads the withholding and names blocks of a tool and answers a list of calls. */
const DRIVER = String.raw`
import json, re, sys
data = json.load(sys.stdin)
text = open(sys.argv[1], encoding="utf-8").read()
ns = {"re": re}
for name in ("WITHHOLDING", "NAMES"):
    b, e = "# BEGIN SHARED " + name, "# END SHARED " + name
    exec(text[text.index(b):text.index(e)], ns)
out = []
for call, arg in data["calls"]:
    out.append(ns[call](arg))
print(json.dumps({"out": out, "strings": ns["NAMES"]["strings"]}))
`;

async function call(fn: "shown" | "withhold", values: string[], path = RKS): Promise<string[]> {
  const run = await runPySnippet(DRIVER, [path], { calls: values.map((v) => [fn, v]) });
  assert.equal(run.code, 0, run.stderr);
  return (JSON.parse(run.stdout) as { out: string[] }).out;
}

// --- canaries, built from pieces ------------------------------------------------------------------------------------------------

let seed = 20261020;
function rnd(): number {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return seed / 2 ** 32;
}
const pick = (alphabet: string, n: number) => Array.from({ length: n }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join("");
const HEX = "0123456789abcdef";
const DIGITS = "0123456789";
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const UPPER_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const groups = (n: number, k: number, sep: string, alphabet: string) => Array.from({ length: n }, () => pick(alphabet, k)).join(sep);
const six = (sep: string) => groups(8, 6, sep, DIGITS);
const joinParts = (...parts: string[]) => parts.join("");

/** Sixteen or more hexadecimal digits with both letters and digits in them. */
function hexWithBoth(n: number): string {
  for (;;) {
    const s = pick(HEX, n);
    if (/[a-f]/.test(s) && /[0-9]/.test(s)) return s;
  }
}
const fullWidth = (s: string) => Array.from(s).map((c) => (c >= "!" && c <= "~" ? String.fromCharCode(c.charCodeAt(0) - 0x21 + 0xff01) : c)).join("");
const LOOK_ALIKES: Record<string, string> = { a: "\u0430", c: "\u0441", e: "\u0435", o: "\u043e", p: "\u0440", x: "\u0445", y: "\u0443", A: "\u0410", B: "\u0412", E: "\u0415", K: "\u041a", M: "\u041c", H: "\u041d", O: "\u041e", P: "\u0420", C: "\u0421", T: "\u0422", X: "\u0425" };
/** Half of the letters that have a look-alike written as the Cyrillic letter. */
const lookAlikes = (s: string) => Array.from(s).map((c) => (LOOK_ALIKES[c] && rnd() < 0.5 ? LOOK_ALIKES[c] : c)).join("");
function constrained(n: number): string {
  for (;;) {
    const s = pick(ALNUM, n);
    if (/[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s)) return s;
  }
}

/** [shape, builder, the share of draws the rule may let through, written in the manifests (percent, the measured rate plus margin)]. */
const SHAPES: Array<[string, () => string, number]> = [
  ["hex16", () => pick(HEX, 16), 0],
  ["hex32", () => pick(HEX, 32), 0],
  ["hex64", () => pick(HEX, 64), 0],
  ["decimal12", () => pick(DIGITS, 12), 0],
  ["decimal20", () => pick(DIGITS, 20), 0],
  ["decimal10", () => pick(DIGITS, 10), 0],
  ["alnum40", () => pick(ALNUM, 40), 1],
  ["alnum12", () => pick(ALNUM, 12), 2],
  ["alnum9", () => pick(ALNUM, 9), 4],
  ["alnum8", () => pick(ALNUM, 8), 4],
  ["lowercase+digits 12", () => pick("abcdefghijklmnopqrstuvwxyz0123456789", 12), 6],
  ["letters24", () => pick(LETTERS, 24), 5],
  ["dashed 4x4", () => groups(4, 4, "-", UPPER_DIGITS), 1],
  ["dotted 4x4", () => groups(4, 4, ".", UPPER_DIGITS), 1],
  ["recovery password, dashed", () => six("-"), 0],
  ["recovery password, spaces", () => six(" "), 0],
  ["recovery password, dots", () => six("."), 0],
  ["recovery password, underscores", () => six("_"), 0],
  ["recovery password, no separator", () => six(""), 0],
  // Any one to three characters that are not letters or digits join the groups; a path's separators do too.
  ...[["en dash", "\u2013"], ["em dash", "\u2014"], ["hyphen U+2010", "\u2010"], ["non-breaking hyphen", "\u2011"], ["minus sign", "\u2212"], ["middle dot", "\u00b7"],
      ["comma", ","], ["semicolon", ";"], ["colon", ":"], ["plus", "+"], ["pipe", "|"], ["tab", "\t"], ["two spaces", "  "]].map(([label, sep]): [string, () => string, number] =>
    [`recovery password, ${label}`, () => six(sep), 0]),
  // One decimal digit glued to the first or the last group: the groups are still eight groups of six digits.
  ...[["comma", ","], ["en dash", "\u2013"], ["pipe", "|"], ["plus", "+"], ["semicolon", ";"], ["colon", ":"], ["hyphen", "-"], ["none", ""]].flatMap(([label, sep]): Array<[string, () => string, number]> => [
    [`recovery password, ${label}, a digit glued to the first group`, () => pick(DIGITS, 1) + six(sep), 0],
    [`recovery password, ${label}, a digit glued to the last group`, () => six(sep) + pick(DIGITS, 1), 0],
    [`recovery password, ${label}, a digit glued to both ends`, () => pick(DIGITS, 1) + six(sep) + pick(DIGITS, 1), 0],
  ]),
  ["recovery password, two groups to a component over four components", () => Array.from({ length: 4 }, () => groups(2, 6, "-", DIGITS)).join("/"), 0],
  ["recovery password, two groups to a component over four components with backslashes", () => Array.from({ length: 4 }, () => groups(2, 6, "-", DIGITS)).join("\\"), 0],
  ["recovery password, one group to a component", () => six("/"), 0],
  ["recovery password, full-width", () => fullWidth(six("-")), 0],
  ["12 letters and digits, half of the letters Cyrillic look-alikes", () => lookAlikes(pick(ALNUM, 12)), 3],
  ["16 letters and digits, half of the letters Cyrillic look-alikes", () => lookAlikes(pick(ALNUM, 16)), 2],
  ["mixed-case letters and digits of 8 with a capital, a small letter and a digit", () => constrained(8), 0],
  ["mixed-case letters and digits of 12 with a capital, a small letter and a digit", () => constrained(12), 0],
  ["mixed-case letters and digits of 40 with a capital, a small letter and a digit", () => constrained(40), 0],
  ["aws access key id", () => joinParts("AK", "IA", pick(UPPER_DIGITS, 16)), 0],
  ["password assignment", () => joinParts("pass", "word=", pick(ALNUM, 14)), 0],
  ["api key assignment", () => joinParts("api", "_key: ", pick(ALNUM, 24)), 0],
  ["user-info", () => joinParts("us", "er:", pick(ALNUM, 10), "@host"), 0],
];
// Shapes the rule does not recognise, by design, and says so: they are PRINTED. A test that fails if they start being withheld would
// pin an accident; this one pins the statement in the manifests.
const NOT_RECOGNISED: Array<[string, () => string]> = [
  ["7-character identifier", () => pick(ALNUM, 7)],
  ["9-digit number", () => pick(DIGITS, 9)],
  ["lowercase-only word-length run", () => pick("abcdefghijklmnopqrstuvwxyz", 14)],
  ["all-capital letters-only run of 24", () => pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 24)],
  ["all-capital letters-only run of 40", () => pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 40)],
  ["three groups of four capitals and digits", () => groups(3, 4, "-", UPPER_DIGITS)],
  ["three groups of five capitals and digits", () => groups(3, 5, ".", UPPER_DIGITS)],
];
const DRAWS = 300;

for (const [shape, build, allowed] of SHAPES) {
  test(`names: a ${shape} in a member name is withheld in ${DRAWS} draws (at most ${allowed}% may pass), in every slot`, async () => {
    const ids = Array.from({ length: DRAWS }, build);
    for (const slot of ["docs/%s.txt", "%s/inside.txt", "a/%s/b/c.bin", "report_%s_final.docx", "%s"]) {
      const shownNames = await call("shown", ids.map((id) => slot.replace("%s", id)));
      const printed = ids.filter((id, i) => shownNames[i].includes(id)).length;
      assert.ok(printed * 100 <= allowed * DRAWS, `${shape}, slot ${slot}: ${printed} of ${DRAWS} printed whole`);
    }
    const text = await call("withhold", ids.map((id) => `7z said: ${id} is not readable`));
    const printed = ids.filter((id, i) => text[i].includes(id)).length;
    assert.ok(printed * 100 <= allowed * DRAWS, `${shape}, free text: ${printed} of ${DRAWS} printed whole`);
  });
}

test("names: the shapes the rule does not recognise are printed, as the manifests say", async () => {
  for (const [shape, build] of NOT_RECOGNISED) {
    const ids = Array.from({ length: 50 }, build);
    const out = await call("shown", ids.map((id) => `docs/${id}.txt`));
    assert.equal(ids.filter((id, i) => out[i].includes(id)).length, 50, shape);
  }
});

test("names: ordinary names are shown as they are, and a withheld part leaves the rest of the name", async () => {
  const ordinary = ["README.txt", "docs/Quarterly Report 2024.docx", "IMG_20230401_123456.jpg", "src/main/java/App.java", "Windows/System32/config/SOFTWARE",
                    "backup.tar.gz", "My Documents/notes_final_v2.txt", "MyDocument.nib", "QtNetwork.framework", "2024-01-15-meeting.md"];
  assert.deepEqual(await call("shown", ordinary), ordinary);
  const id = pick(HEX, 32);
  const [cut] = await call("shown", [`vault/${id}/statement final.pdf`]);
  assert.equal(cut, "vault/<identifier-shaped text withheld>/statement final.pdf");
  const [named] = await call("shown", [joinParts("docs/pass", "word=", pick(ALNUM, 14), ".txt")]);
  assert.match(named, /^docs\/password=<secret-shaped text withheld>$/);
  const key = six("-");
  const [recovery] = await call("shown", [`docs/${key}.txt`]);
  assert.equal(recovery, "docs/<recovery-password-shaped name withheld>");
  // A placeholder is not judged again: the rule is idempotent.
  assert.deepEqual(await call("shown", [recovery, cut, named]), [recovery, cut, named]);
});

test("names: invisible and full-width forms are judged after folding, and the whole string goes", async () => {
  const id = pick(HEX, 16);
  const zeroWidth = id.slice(0, 8) + "​" + id.slice(8);
  const fullWidth = Array.from(id).map((c) => String.fromCharCode(c.charCodeAt(0) - 0x21 + 0xff01)).join("");
  const out = await call("shown", [`a/${zeroWidth}.txt`, `a/${fullWidth}.txt`]);
  for (const s of out) assert.match(s, /withheld/);
  assert.ok(!out[0].includes(id.slice(0, 8)) && !out[1].includes(fullWidth));
});

// --- time: every regular expression of the three blocks, at 4,096 and 32,768 characters -----------------------------------------

const HUNT = String.raw`
import json, re, sys, time
text = open(sys.argv[1], encoding="utf-8").read()
ns = {"re": re}
for name in ("WITHHOLDING", "NAMES"):
    b, e = "# BEGIN SHARED " + name, "# END SHARED " + name
    exec(text[text.index(b):text.index(e)], ns)
ns["MAX_JUDGED"] = 1 << 20
def gens(n):
    yield "a" * n
    yield "a-" * (n // 2)
    yield "a." * (n // 2)
    yield "1-" * (n // 2)
    yield "1111-" * (n // 5)
    yield "1111_aaaa-" * (n // 10)
    yield "A1b2" * (n // 4)
    yield "/".join(["aB3x"] * (n // 5))
    yield "pass" * (n // 4)
    yield "password " * (n // 9) + "="
    yield "password" + " " * n + "x"
    yield "password=" * (n // 9)
    yield "token:" + "a" * n
    yield "@" * n
    yield "//" + "a:" * (n // 2) + "@"
    yield "a:b@" * (n // 4)
    yield "​" * n
    yield "0" * n + "a"
    yield ("0123456789ab" * (n // 12))[:n]
    yield "-----BEGIN " + "A " * (n // 2)
    yield "eyJ" + "a" * (n // 2) + "." + "b" * (n // 2)
    yield "Bearer " + "a" * n
    yield "ab12" + "-ab12" * (n // 5)
rows = []
for n in (4096, 32768):
    worst = 0.0
    for g in gens(n):
        for fn in ("shown", "withhold"):
            t = time.process_time(); ns[fn](g); worst = max(worst, time.process_time() - t)
        t = time.process_time(); ns["seal"]({"k": g}); worst = max(worst, time.process_time() - t)
    rows.append([n, round(worst, 3)])
print(json.dumps(rows))
`;

test("names: no regular expression of the blocks takes more than a second on 4,096 or 32,768 adversarial characters", async () => {
  for (const path of [RKS, AP, CID]) {
    const run = await runPySnippet(HUNT, [path], null);
    assert.equal(run.code, 0, run.stderr);
    for (const [n, worst] of JSON.parse(run.stdout) as Array<[number, number]>) assert.ok(worst < 1, `${n} characters took ${worst} s in ${path}`);
  }
});

// --- the output check, with the first layer removed ----------------------------------------------------------------------------------

const BACKSTOP = String.raw`
import json, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
ns = {"re": re}
for name in ("WITHHOLDING", "NAMES"):
    b, e = "# BEGIN SHARED " + name, "# END SHARED " + name
    exec(text[text.index(b):text.index(e)], ns)
ns["_judge"] = lambda t, whole: (t, False)         # the sanitiser is gone: shown() and withhold() now print what they are given
data = json.load(sys.stdin)
sealed = ns["seal"]({"rows": [{"name": ns["shown"](s)} for s in data["strings"]], "all_results": "store/jobs/j000001/out/tool-output/x-0123456789abcdef.jsonl"})
print(json.dumps({"rows": sealed["rows"], "kept": sealed["all_results"], "replaced": ns["NAMES"]["replaced"]}))
`;

test("the output check replaces what the first layer would have let through (sanitiser removed), and leaves the tool's own file names", async () => {
  const strings = [
    `docs/${six("-")}.txt`, `docs/${six("_")}.txt`, joinParts("docs/pass", "word=", pick(ALNUM, 14), ".txt"), joinParts("AK", "IA", pick(UPPER_DIGITS, 16)),
    joinParts("-----BEGIN RSA PRIV", "ATE KEY-----"), pick(HEX, 40), pick(ALNUM, 40) + pick(DIGITS, 6),
    // what the check alone did not catch: hexadecimal of 16 to 24 digits, user-info, a full-width or invisibly split recovery password
    `docs/${hexWithBoth(16)}.bin`, `docs/${hexWithBoth(20)}.bin`, joinParts("https://us", "er:", pick(ALNUM, 10), "@host/x"), joinParts("//", pick(ALNUM, 9), "@host"),
    `docs/${fullWidth(six("-"))}.txt`, `docs/${six("-").slice(0, 20)}\u200b${six("-").slice(20)}.txt`,
  ];
  const fine = ["README.txt", "docs/Quarterly Report 2024.docx", "e1f2a3b4-1111-4222-8333-444455556666", "dos_date=0x2e6e dos_time=0x4d96", "https://example.org/a/b?c=d"];
  for (const path of [RKS, AP, CID]) {
    const run = await runPySnippet(BACKSTOP, [path], { strings: [...strings, ...fine] });
    assert.equal(run.code, 0, run.stderr);
    const got = JSON.parse(run.stdout) as { rows: Array<{ name: string }>; kept: string; replaced: number };
    strings.forEach((s, i) => assert.equal(got.rows[i].name, "<withheld by the output check>", `${s.slice(0, 12)}... in ${path}`));
    fine.forEach((s, i) => assert.equal(got.rows[strings.length + i].name, s));
    assert.match(got.kept, /^store\/jobs\/j000001\/out\/tool-output\//);
    assert.equal(got.replaced, strings.length);
  }
});

// --- what the layer-2 check alone does not catch, said as a test so that the manifests' sentence cannot drift ---------------------------

test("the output check alone does not catch a number of 10 to 20 digits or an identifier of up to 23 characters: only the rule withholds them", async () => {
  const strings = [`docs/${pick(DIGITS, 12)}.bin`, `docs/${pick(DIGITS, 20)}.bin`, `docs/${pick(ALNUM, 12)}Qz1.bin`];
  for (const path of [RKS, AP, CID]) {
    const run = await runPySnippet(BACKSTOP, [path], { strings });
    assert.equal(run.code, 0, run.stderr);
    const got = JSON.parse(run.stdout) as { rows: Array<{ name: string }>; replaced: number };
    assert.equal(got.replaced, 0, path);
    strings.forEach((s, i) => assert.equal(got.rows[i].name, s));
  }
});

const SEAL_ONLY = String.raw`
import json, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
ns = {"re": re}
for name in ("WITHHOLDING", "NAMES"):
    b, e = "# BEGIN SHARED " + name, "# END SHARED " + name
    exec(text[text.index(b):text.index(e)], ns)
data = json.load(sys.stdin)
print(json.dumps({"rows": ns["seal"]({"rows": data["strings"]})["rows"], "replaced": ns["NAMES"]["replaced"]}))
`;

test("the output check alone passes a recovery password with a separator outside its five, or cut over path components: the first layer holds those", async () => {
  const passes = [`docs/${six(",")}.txt`, `docs/${six("\u2013")}.txt`, `docs/${six("|")}.txt`, `docs/${six("+")}.txt`,
                  `docs/${Array.from({ length: 4 }, () => groups(2, 6, "-", DIGITS)).join("/")}.txt`, `docs/${six("/")}.txt`];
  const caught = [`docs/${six("-")}.txt`, `docs/${pick(DIGITS, 1)}${six("-")}.txt`, `docs/${six(".")}${pick(DIGITS, 1)}.txt`, `docs/${six(" ")}.txt`];
  for (const path of [RKS, AP, CID]) {
    const run = await runPySnippet(SEAL_ONLY, [path], { strings: [...passes, ...caught] });
    assert.equal(run.code, 0, run.stderr);
    const got = JSON.parse(run.stdout) as { rows: string[]; replaced: number };
    passes.forEach((s, i) => assert.equal(got.rows[i], s, `${s.length} characters in ${path}`));
    caught.forEach((_s, i) => assert.equal(got.rows[passes.length + i], "<withheld by the output check>", `${path}`));
    assert.equal(got.replaced, caught.length);
  }
});

// --- the rule is given bounded text -----------------------------------------------------------------------------------------

const LONG = "<text too long to judge withheld>";

const BOUNDS = String.raw`
import json, re, sys, time, unicodedata
text = open(sys.argv[1], encoding="utf-8").read()
ns = {"re": re}
for name in ("WITHHOLDING", "NAMES"):
    b, e = "# BEGIN SHARED " + name, "# END SHARED " + name
    exec(text[text.index(b):text.index(e)], ns)
S = "／"
flagged = "AK" + "IA" + "A" * 16
rows = {}
def timed(label, fn, arg):
    ns["_CACHE"].clear()
    t0 = time.process_time(); out = fn(arg); rows[label] = [round(time.process_time() - t0, 3), out[:40]]
# the two families of the review, at the sizes of a ZIP name and of a 7z header string
timed("run+solidus", ns["shown"], "a" * 30000 + "!" + S + (flagged + "!" + S) * 20)
timed("pieces+solidus", ns["shown"], ("ab12" + S) * 9000 + flagged)
timed("run+slash, free text", ns["withhold"], "a" * 40000 + "!/" + (flagged + "!/") * 60)
timed("pieces+slash, free text", ns["withhold"], "ab12/" * 12000 + flagged)
# the worst a judged string can be: runs just inside the bound, with as many flagged spans behind them as fit
worst = 0.0
for run in (100, 200, 256):
    for sep in ("/", S):
        s = ("a" * run + "!" + sep + (flagged + "!" + sep) * 200)[:4096]
        for fn in ("shown", "withhold"):
            ns["_CACHE"].clear()
            t0 = time.process_time(); ns[fn](s); worst = max(worst, time.process_time() - t0)
rows["worst inside the bound"] = [round(worst, 3), ""]
# what the bound does and does not take
ns["_CACHE"].clear()
rows["verdicts"] = [0, [ns["withhold"]("x" * 4097), ns["withhold"]("a" * 300 + "/" + "b" * 10), ns["withhold"]("a" * 300), ns["shown"]("d/" * 5000 + "f.txt"),
                        ns["withhold"]("ﷺ" * 300), ns["shown"]("ab/" * 3000)]]
print(json.dumps(rows))
`;

test("names: strings the token rule of the shared block would take quadratic time on are withheld whole, and nothing inside the bound takes long", async () => {
  for (const path of [RKS, AP, CID]) {
    const run = await runPySnippet(BOUNDS, [path], null);
    assert.equal(run.code, 0, run.stderr);
    const rows = JSON.parse(run.stdout) as Record<string, [number, unknown]>;
    for (const [label, [cpu]] of Object.entries(rows)) assert.ok(cpu < 1, `${label}: ${cpu} CPU s in ${path}`);
    const verdicts = rows.verdicts[1] as string[];
    assert.equal(verdicts[0], LONG, "longer than 4096 characters");
    assert.equal(verdicts[1], LONG, "a run of more than 256 name characters beside a /");
    assert.notEqual(verdicts[2], LONG, "the same run without a / is judged: by shape, not as unjudged text");
    assert.equal(verdicts[3], LONG, "a path of more than 8192 characters");
    assert.equal(verdicts[4], LONG, "a text that folds to more than the bound (U+FDFA is 18 characters)");
    assert.equal(verdicts[5], LONG, "a path of 9000 characters");
  }
});

const CACHE = String.raw`
import json, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
ns = {"re": re}
for name in ("WITHHOLDING", "NAMES"):
    b, e = "# BEGIN SHARED " + name, "# END SHARED " + name
    exec(text[text.index(b):text.index(e)], ns)
for i in range(6000):
    ns["shown"]("%05d" % i + "x" * 3990)
print(json.dumps({"entries": len(ns["_CACHE"]), "bytes": ns["_CACHE_BYTES"][0]}))
`;

test("names: the cache of judged strings is bounded by size, not only by the number of strings", async () => {
  for (const path of [RKS, AP, CID]) {
    const run = await runPySnippet(CACHE, [path], null);
    assert.equal(run.code, 0, run.stderr);
    const got = JSON.parse(run.stdout) as { entries: number; bytes: number };
    assert.ok(got.bytes < 17 << 20, `${got.bytes} bytes held in ${path}`);
    assert.ok(got.entries < 6000, "the cache stopped taking strings");
  }
});

test("names: a Cyrillic or Greek letter that is written like a Latin one is read as the Latin one", async () => {
  const cyrillicId = lookAlikes("aeoc9QxK4pYh");
  assert.ok(!/^[\x00-\x7f]*$/.test(cyrillicId));
  const [out] = await call("shown", [`docs/${cyrillicId}.txt`]);
  assert.equal(out, "docs/<identifier-shaped text withheld>", "a hit that only the folded text shows withholds the whole component");
  // A word in a script of its own is not touched.
  const words = ["docs/Документ.txt", "docs/Πλάνο 2024.txt", "docs/研究レポート.docx"];
  assert.deepEqual(await call("shown", words), words);
});
