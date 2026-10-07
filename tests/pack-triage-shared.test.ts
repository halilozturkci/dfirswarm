/**
 * triage-collection: the two tools carry one shared block (the error form, where an output may be written, the lossless table,
 * the secret-safe values file, the withholding of credential-shaped strings, the head classifier), held equal here; the
 * withholding is held to a table written from the shapes it names, never from a tool's output; and the manifests carry the
 * sha256 of their scripts, say what they read, and name exactly the parameters their scripts read.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { runPySnippet } from "./tool-library-harness.ts";
import { ID, INDEX, TOOLS } from "./pack-triage-harness.ts";
import type { Json } from "./pack-triage-harness.ts";

const BEGIN = "# ---- BEGIN SHARED BLOCK";
const END = "# ---- END SHARED BLOCK";

async function block(path: string): Promise<string> {
  const text = await readFile(path, "utf8");
  const start = text.indexOf(BEGIN);
  const end = text.indexOf(END);
  assert.ok(start >= 0 && end > start, `${path} carries the shared block`);
  assert.equal(text.indexOf(BEGIN, start + 1), -1, "once");
  return text.slice(start, text.indexOf("\n", end) + 1);
}

test("the two tools carry the same shared block, byte for byte", async () => {
  const [a, b] = await Promise.all([block(ID), block(INDEX)]);
  assert.equal(a, b);
  assert.ok(a.length > 8000);
});

const CODE = `
import json, os, sys, tempfile
os.chdir(tempfile.mkdtemp())          # the table writes under work/<agent>/tool-output of the working directory
data = json.load(sys.stdin)
ns = {}
exec(data["block"], ns)
scrub = ns["scrub"]
out = {"scrub": {t: scrub(t) for t in data["text"]}, "count": ns["WITHHELD"]["count"]}
# a lone surrogate (a byte that was not UTF-8) in a text and in a table row never raises
bad = "name\\udcffend"
out["surrogate_scrub"] = ascii(scrub(bad))
t = ns["Table"]("t", 1, always=True)
t.add({"p": bad})
t.add({"p": "plain"})
out["table"] = t.finish()
first = scrub("tok ghp_Zq7Svb9Kt00123456789abcdefghijKLMNOP end")
out["same_id"] = scrub("tok ghp_Zq7Svb9Kt00123456789abcdefghijKLMNOP end") == first
out["keyed"] = ns["scrub_all"]({"ghp_Zq7Svb9Kt00123456789abcdefghijKLMNOP": "v"})
print(json.dumps(out))
`;

// Each shape written from the format it names, never from a tool's output. The last element of a pair is the part that must not survive.
const PEM_BODY = "MIIEowIBAAKCAQEAq7ZkP3rT9vLmN2xWc5YhB8dF1gJ4sUo6aEi0";
const SHAPED: Array<[string, string]> = [
  ["recovery 123456-234567-345678-456789-567890-678901-789012-890123 key", "234567-345678"],               // eight groups of six digits
  ["recovery 123456 234567 345678 456789 567890 678901 789012 890123", "234567 345678"],
  ["recovery 123456234567345678456789567890678901789012890123 key", "234567345678"],                         // no separator
  ["AKIAIOSFODNN7EXAMPLE used", "IOSFODNN7"],                                                             // the example access key id AWS documents
  ["ghp_" + "Zq7Svb9Kt00123456789abcdefghijKLMNOP", "Zq7Svb9Kt0"],                                            // a GitHub personal access token: ghp_ and 36 characters
  ["backup_ghp_" + "Zq7Svb9Kt00123456789abcdefghijKLMNOP", "Zq7Svb9Kt0"],                                     // a token after an underscore
  ["my_sk-" + "Zq7Svb9Kt00123456789abcdef", "Zq7Svb9Kt0"],
  ["xoxb-1234567890-abcdefghij", "1234567890"],                                                           // a Slack bot token prefix
  ["https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXX", "XXXXXXXXXX"],
  ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP", "dBjftJeZ4C"],                         // a JSON web token
  ["eyJhbGciOiJSQS1PQUVQIiwiZW5jIjoiQTI1NkdDTSJ9.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUm.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4.XFBoMYUZodetZdvTiFvSkQ", "OKOawDo13g"],   // a JWE: five parts
  [`-----BEGIN OPENSSH PRIVATE KEY-----\n${PEM_BODY}\n-----END OPENSSH PRIVATE KEY-----`, PEM_BODY.slice(0, 20)],  // the body and the END line go with the header
  [`-----BEGIN RSA PRIVATE KEY----- ${PEM_BODY} and no end line`, PEM_BODY.slice(0, 20)],                   // no END: to the end of the field
  ["-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF" + "abcdefghijklmnop", "lQOYBFabcd"],
  ["PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\nAAAAIFxxPuttyBodyxx\nPrivate-MAC: 0123456789abcdef", "AAAAIFxxPu"],
  ["fetch http://alice:Pa55w0rd@files.example.test/x", "Pa55w0rd"],
  ["connect ftp://svc:Wint3r@Synth77@10.0.0.1/drop", "Synth77"],                                              // a password that holds an @
  ["get https://admin:Pa/ss9Word@files.example.test/x", "ss9Word"],                                        // a password that holds a /
  ["get https://user:p?w#d@host.example.test/x", "w#d@"],                                                    // a ? and a #
  ["get //user:hunter22@host.example.test/x", "hunter22"],                                                  // no scheme
  ["ssh admin:hunter22@10.0.0.5 'ls'", "hunter22"],                                                         // no slashes at all
  ["Authorization: Basic dXNlcjpTZWNyZXRQYXNzd29yZDEy", "dXNlcjpTZWNy"],
  ["proxy-authorization=Bearer abcdefghijklmnop.qrstuv", "abcdefghij"],
  ["aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYQ7vT2mZ9nB4c", "wJalrXUtnF"],
  ["aws_session_token: FQoGZXIvYXdzEBYaDOutOfBandSessionToken", "FQoGZXIvYX"],
  ["login password=Zebra7Quartz refused", "Zebra7Quartz"],
  ["https://x.example.test/blob?sv=2024&sig=abcdefghijklmnopqrstuvwx%3D&se=1", "abcdefghij"],
  ["mysql -u root -pS3cretPw db", "S3cretPw"],
  ["sshpass -p S3cretPw ssh host", "S3cretPw"],
];
const NOT_SHAPED = [
  "{3F2504E0-4F89-11D3-9A0C-0305E82C3301}",                                          // a GUID
  "d41d8cd98f00b204e9800998ecf8427e",                                                // an md5
  "CMD.EXE-0BD30981.pf",                                                             // a Prefetch name
  "nmmhkkegccagdldgiimedpiccmgmieda",                                                // a Chromium extension id
  "S-1-5-21-1004336348-1177238915-682003330-512",                                    // a SID
  "2026-02-14T09_12_00_1234567_CopyLog.csv",
  "Users/alice/AppData/Local/Microsoft/Windows/INetCache/IE/ABCD1234/file[1].txt",
  "123456-234567-345678-456789-567890-678901-789012",                                 // seven groups: not a recovery password
  "1234567-234567-345678-456789-567890-678901-789012-890123",                         // a group of seven digits
  "disk-image-for-the-quarterly-review-of-the-finance-share.vhdx",                   // contains sk- inside a word
  "http://files.example.test/path/no-user-info",
  "https://example.com:8443/users/@alice",                                           // a port, and an @ in the path
  "https://host/path?email=a@b.com",
  "C:\\Users\\a\\Library\\icon@2x.png",                                              // a file name with an @
  "Library/Caches/com.foo:bar@2x.png",
  "foo@example.com wrote to bar@example.org",
  "token: expired; password: required",                                              // the words alone, no value after =
  "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\n-----END CERTIFICATE-----",    // a certificate is public
];

test("the withholding replaces the shapes it names, whole, leaves names that merely look random alone, and never raises on a lone surrogate", async () => {
  const run = await runPySnippet(CODE, [], { block: await block(ID), text: [...SHAPED.map(([text]) => text), ...NOT_SHAPED] });
  assert.equal(run.code, 0, run.stderr);
  const got: Json = JSON.parse(run.stdout);
  for (const [text, secret] of SHAPED) {
    assert.match(got.scrub[text], /<[A-Za-z -]+ withheld, \d+ characters, W\d{6}>/, `${text.slice(0, 50)} is withheld`);
    assert.ok(!got.scrub[text].includes(secret), `${JSON.stringify(secret)} does not survive in ${JSON.stringify(got.scrub[text])}`);
  }
  const plain = (s: string) => s.replace(/W\d{6}/g, "W");
  assert.equal(plain(got.scrub[SHAPED[0][0]]), "recovery <recovery-password-shaped text withheld, 55 characters, W> key");
  assert.equal(plain(got.scrub[SHAPED[3][0]]), "<access-key-shaped text withheld, 20 characters, W> used");
  assert.equal(plain(got.scrub["connect ftp://svc:Wint3r@Synth77@10.0.0.1/drop"]), "connect ftp://<user-info of a URL withheld, 18 characters, W>@10.0.0.1/drop");
  assert.equal(plain(got.scrub["Authorization: Basic dXNlcjpTZWNyZXRQYXNzd29yZDEy"]), "Authorization: Basic <credential after a header withheld, 28 characters, W>");
  assert.equal(plain(got.scrub["mysql -u root -pS3cretPw db"]), "mysql -u root -p<password option withheld, 8 characters, W> db");
  for (const text of NOT_SHAPED) assert.equal(got.scrub[text], text, `${JSON.stringify(text)} is a name or a public thing, not a secret`);
  assert.equal(got.count, SHAPED.length);
  assert.equal(got.surrogate_scrub, ascii("name\udcffend"));
  assert.equal(got.table.matched, 2);
  assert.equal(got.table.truncated, true);
  // the same text always gets the same finding id, and a key of a dictionary is scrubbed like a value
  assert.equal(got.same_id, true);
  assert.equal(Object.keys(got.keyed).length, 1);
  assert.ok(Object.keys(got.keyed).every((k) => !k.includes("Zq7Svb9Kt0")));
});

function ascii(text: string): string {
  return `'${[...text].map((c) => (c.charCodeAt(0) < 128 ? c : `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)).join("")}'`;
}

const NAMES = ["collection_id", "collection_index"];

test("every manifest has a use, a raised version, the sha256 of its script and a description that says what is and is not measured", async () => {
  const versions: Record<string, number> = { collection_id: 3, collection_index: 4 };
  for (const name of NAMES) {
    const manifest: Json = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    assert.ok(manifest.use?.names?.length >= (name === "collection_id" ? 5 : 1), `${name} says what it reads`);
    assert.equal(manifest.version, versions[name]);
    assert.equal(manifest.sha256, createHash("sha256").update(await readFile(join(TOOLS, name, "run.py"))).digest("hex"), `${name} sha256`);
    assert.ok(manifest.timeout_seconds >= 3600 && manifest.params.time_limit_seconds, `${name}: a deadline that ends before the kill`);
    assert.match(manifest.description, /does not say|not measured|does not measure|not read/i, `${name} says what it does not measure`);
    assert.match(manifest.description, /secret_output: true/, `${name} says the job runs with secret_output: true`);
    assert.doesNotMatch(manifest.description, /recognise which collector|recognises the shape|undoing the rewrites|restor/i, `${name} still carries an old promise`);
  }
  const id: Json = JSON.parse(await readFile(join(TOOLS, "collection_id", "manifest.json"), "utf8"));
  assert.doesNotMatch(id.description, /what a logical acquisition of this shape cannot contain/);
  assert.match(id.description, /never a\s+physical image/);
  const index: Json = JSON.parse(await readFile(join(TOOLS, "collection_index", "manifest.json"), "utf8"));
  assert.match(index.description, /never called the original path/);
});

test("the parameters a manifest names are the parameters its script reads", async () => {
  for (const name of NAMES) {
    const manifest: Json = JSON.parse(await readFile(join(TOOLS, name, "manifest.json"), "utf8"));
    const script = await readFile(join(TOOLS, name, "run.py"), "utf8");
    const read = new Set<string>();
    for (const m of script.matchAll(/(?:args\.get|want_str|want_bool|want_int)\((?:args, )?"([a-z_]+)"/g)) read.add(m[1]);
    const named = new Set(Object.keys(manifest.params));
    assert.deepEqual([...read].filter((p) => !named.has(p)).sort(), [], `${name}: parameters the script reads and the manifest does not name`);
    assert.deepEqual([...named].filter((p) => !read.has(p)).sort(), [], `${name}: parameters the manifest names and the script does not read`);
    const example = JSON.parse(manifest.example);
    for (const key of Object.keys(example)) assert.ok(named.has(key), `${name} example uses ${key}`);
  }
});

test("the tools carry no hard-coded claim about what a delivery cannot contain, and the old text is gone from the scripts", async () => {
  for (const name of NAMES) {
    const script = await readFile(join(TOOLS, name, "run.py"), "utf8");
    assert.doesNotMatch(script, /unallocated space, so no carving|no inode and no -o offset|cannot_contain|physical image"|probably dropped|original_path/);
    assert.doesNotMatch(script, /os\.walk\(/, `${name} walks with scandir, following no link`);
  }
});

// A name that is not UTF-8 reaches Python as a str with a lone surrogate. Some file systems (APFS) refuse to hold such a name,
// so the entry is made up: a directory entry whose name carries the surrogate and whose stat fails, which is how the tools meet
// one they cannot read. Both tools must write it as an escape, in the answer and in the file, and never raise.
const SURROGATE_CODE = `
import importlib.util, io, json, os, sys, tempfile
script, kind = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("lib", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
root = tempfile.mkdtemp()
os.chdir(root)
os.makedirs("c")
real_scandir = os.scandir

class Entry:
    name = "bad\\udcffname.E01"
    path = os.path.join("c", name)
    def stat(self, follow_symlinks=True):
        raise PermissionError(13, "Permission denied", self.path)
    def is_symlink(self): return False
    def is_dir(self, follow_symlinks=True): raise PermissionError(13, "Permission denied", self.path)
    def is_file(self, follow_symlinks=True): raise PermissionError(13, "Permission denied", self.path)

class Listing(list):
    def __enter__(self): return self
    def __exit__(self, *a): return False

def fake_scandir(path):
    if str(path) == "c":
        return Listing([Entry()])
    return real_scandir(path)

os.scandir = fake_scandir
sys.stdin = io.StringIO(json.dumps({"root": "c", "limit": 1}))
mod.main()
`;

test("a name that is not UTF-8, even one the tool cannot stat, is an escape in the answer and the file in both tools", async () => {
  for (const script of [ID, INDEX]) {
    const run = await runPySnippet(SURROGATE_CODE, [script, "x"], null);
    assert.equal(run.code, 0, run.stderr);
    assert.doesNotMatch(run.stderr, /Traceback|UnicodeEncodeError/);
    const out = JSON.parse(run.stdout);
    assert.equal(out.status, "partial");
    assert.match(run.stdout, /bad\\udcffname\.E01/);
    assert.equal((out.census ?? out.walk).errors, 1);
  }
});
