/**
 * What each job image can do is found by known-answer probes and told to the seats.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { capabilitiesPost, probeImages, probeScript, readProbe } from "../scripts/image-capabilities.ts";
import type { HubCall } from "../scripts/supply-probe.ts";

test("the probe script is valid shell and answers one line a capability on this host, whatever it holds", () => {
  const dir = mkdtempSync(join(tmpdir(), "imgcap-"));
  const script = join(dir, "probe.sh");
  writeFileSync(script, probeScript("iVBORw0KGgo="));
  execFileSync("bash", ["-n", script]);
  const out = execFileSync("bash", [script], { env: { ...process.env, OUT: dir }, encoding: "utf8", timeout: 120_000 });
  const caps = readProbe(out);
  assert.deepEqual(caps.map((c) => c.id), ["disasm-x86-64", "qr-decode", "video-decode", "image-read", "ocr", "brotli", "numpy", "compile-c", "crypto-lib"]);
  for (const c of caps) assert.ok(c.ok ? Boolean(c.by) : Boolean(c.said), `${c.id} says with what, or why not`);
});

test("one probe job per image; the post says what works with what and what does not; an image that could not be probed says so", async () => {
  const calls: Array<[string, Record<string, unknown>]> = [];
  const call: HubCall = async (fn, arg) => {
    calls.push([fn, arg]);
    if (fn === "jobSubmit") return arg.profile === "mobile" ? { ok: false, reason: "no job image for profile mobile" } : { ok: true, job: { job: arg.profile === "disk" ? "j000002" : "j000003" } };
    return arg.job_id === "j000002"
      ? { ok: true, job: { state: "committed" }, stdout: { text: "cap disasm-x86-64 no objdump here disassembles only elf64-littleaarch64; no r2, no capstone\ncap image-read ok python3 Pillow\ncap ocr no no OCR engine: text in a picture is read by eye (the read tool) only\n" } }
      : { ok: true, job: { state: "committed" }, stdout: { text: "cap disasm-x86-64 ok r2 -a x86 -b 64\ncap image-read ok python3 Pillow\n" } };
  };
  const r = await probeImages(call, ["disk", "re", "mobile"], { qr: "QUJD", sleep: async () => undefined });
  assert.deepEqual(calls.filter(([fn]) => fn === "jobSubmit").map(([, a]) => a.profile), ["disk", "re", "mobile"]);
  assert.ok(Array.isArray(r.disk) && Array.isArray(r.re) && !Array.isArray(r.mobile));
  const post = capabilitiesPost(r);
  assert.match(post, /- disk: WORKS: read a PNG's pixels \(python3 Pillow\)\. DOES NOT: disassemble x86-64 code: objdump here disassembles only elf64-littleaarch64; no r2, no capstone; read text from a picture: no OCR engine/);
  assert.match(post, /- re: WORKS: disassemble x86-64 code \(r2 -a x86 -b 64\)/);
  assert.match(post, /- mobile: not tested \(no job image for profile mobile\)/);
  assert.match(post, /your own VM is not a job image/);
  assert.ok(post.length < 2500);
});
