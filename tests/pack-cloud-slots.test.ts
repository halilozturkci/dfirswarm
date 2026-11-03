/**
 * The cloud tools carry the shared WITHHOLDING block and route every slot they print to one of three treatments (the comment above
 * their routing code says which): a designed-visible identifier is printed as it is, free text goes through the credential rules,
 * a named field goes through the name layer. This is the slot table, and the shapes CLD-05 added, run through all three tools.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { SIGNIN, TRAIL, UAL, body, ct, everythingBut, put, tool, trail, withDir } from "./cloud-pack-harness.ts";
import { leaked } from "./cloud-pack-secrets.ts";

const PW = "Hu7!kQ2zRw9x";
const PW2 = "Zq9!Xw7Vb6Nm";
const AKID = "AKIA" + "IOSFODNN7EXAMPLE";
const SHA = "a".repeat(64);
const GUID = "11111111-2222-3333-4444-555555555555";
const ARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
const IDENTIFIERS = [AKID, SHA, GUID, ARN];

// free text that holds a credential of a CLD-05 shape, and an identifier beside it
const TEXTS: Array<[string, string]> = [
  ["a numeric Value in a pair", '[{"Name":"pin","Value":48151623}]'],
  ["an array Value in a pair", `[{"Name":"Password","Value":["${PW}","x"]}]`],
  ["a NewValue after an OldValue", `[{"Name":"Password","OldValue":"${PW2}","NewValue":"${PW}"}]`],
  ["a Value over 4,096 characters", `[{"Name":"Password","Value":"${PW}${"Q".repeat(5000)}"}]`],
  ["mysql -p", `mysql -uroot -p${PW} db`],
  ["curl -u", `curl -u admin:${PW} https://h.example/x`],
  ["a bcrypt hash", "hash $2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"],
];

const carriers = {
  cloudtrail_parse: { script: TRAIL, file: "t.json", make: (t: string) => trail(ct({ eventID: GUID, eventSource: "ec2.amazonaws.com", eventName: "RunInstances", userIdentity: { type: "IAMUser", accessKeyId: AKID, arn: ARN }, requestParameters: { note: t, digest: SHA } })), args: { link_sessions: false } },
  ual_parse: { script: UAL, file: "u.json", make: (t: string) => JSON.stringify([{ Id: GUID, Operation: "Set-Mailbox", UserId: "alice@example.org", CreationTime: "2026-02-14T09:00:00Z", RecordType: 1, Workload: "Exchange", ClientInfoString: t, ObjectId: ARN, Digest: SHA, AppAccessContext: { AKID: AKID } }]), args: {} },
  signin_analyse: { script: SIGNIN, file: "s.json", make: (t: string) => JSON.stringify({ value: [{ id: GUID, correlationId: SHA, createdDateTime: "2026-02-14T09:00:00Z", userPrincipalName: "alice@example.org", userId: GUID, appDisplayName: "App", ipAddress: "198.51.100.1", userAgent: t, status: { errorCode: 0, additionalDetails: AKID + " " + ARN } }] }), args: {} },
} as const;

for (const [label, text] of TEXTS) {
  test(`all three tools withhold ${label} from free text and print the identifiers beside it`, async () => {
    for (const [name, c] of Object.entries(carriers)) {
      await withDir(async (cwd) => {
        await put(cwd, `work/ev/${c.file}`, c.make(text));
        const run = await tool(c.script, cwd, { path: `work/ev/${c.file}`, ...c.args });
        body(run);
        const everything = await everythingBut(cwd, run.stdout + run.stderr, []);
        for (const secret of [PW, "48151623", "N9qo8uLOickgx2ZMRZoMye"]) {
          if (text.includes(secret)) assert.equal(leaked(secret, everything), undefined, `${name} printed ${secret.slice(0, 4)}... of ${label}`);
        }
        assert.match(everything, /withheld/, `${name} says it withheld ${label}`);
        for (const id of [AKID, GUID, SHA]) assert.ok(everything.includes(id), `${name} printed the identifier ${id.slice(0, 8)}`);
      });
    }
  });
}

test("the cloud tools carry the shared block and keep a 1 MiB gate: a 100,000-character text is scanned, not withheld whole", async () => {
  for (const c of Object.values(carriers)) {
    const text = await readFile(c.script, "utf8");
    assert.match(text, /# BEGIN SHARED WITHHOLDING/);
    assert.match(text, /^WITHHOLD_LIMIT = MAX_SCAN_CHARS/m);
  }
  await withDir(async (cwd) => {
    const note = "benign words ".repeat(7700) + ` password=${PW} `;
    await put(cwd, "work/ev/t.json", carriers.cloudtrail_parse.make(note));
    const run = await tool(TRAIL, cwd, { path: "work/ev/t.json", link_sessions: false });
    const everything = await everythingBut(cwd, run.stdout + run.stderr, []);
    assert.equal(leaked(PW, everything), undefined);
    assert.match(everything, /benign words benign words/, "the text around the credential is printed");
    assert.doesNotMatch(everything, /text longer than/);
  });
});
