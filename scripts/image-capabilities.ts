/**
 * What each job image of a run can do, found by known-answer probes run in
 * a worker VM of that image right after kickoff, and told to the seats.
 *
 *   image-capabilities.ts <sandbox> --hub-admin SOCKET --profiles disk,re,full
 *
 * The seats of eight runs spent 25 to 30 jobs a run finding out what their
 * images held, and still believed wrong things: `objdump` is in every image
 * and disassembles only the image's own architecture (three runs decoded
 * x86-64 opcodes by hand); Pillow is in the job images and not in the seat
 * VM, where seats tested for it and then wrote PNG decoders; no image reads
 * text from a picture. The fixed toolbox table says a program is present, not
 * what it does. One job per image answers that, with an input whose answer
 * is known, and the answer goes on the board and into job-capabilities.json.
 */
import { readFile, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { probeQrBase64, PROBE_PAYLOAD, type HubCall } from "./supply-probe.ts";

export type Capability = { id: string; what: string; ok: boolean; by?: string; said?: string };

/** One shell script that tries each capability and prints a line `cap <id> <ok|no> <by or why>` for each. */
export function probeScript(qrPngBase64: string): string {
  // x86-64 bytes for: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
  const X86 = "554889e531c05dc3";
  return [
    "set +e",
    'cd "$OUT" || exit 1',
    `printf %s '${qrPngBase64}' | base64 -d > probe.png`,
    `printf %s '${X86}' | xxd -r -p > code.bin 2>/dev/null || python3 -c "import sys;open('code.bin','wb').write(bytes.fromhex('${X86}'))"`,
    'say() { printf "cap %s %s %s\\n" "$1" "$2" "$3"; }',
    // disassembly of x86-64: any of objdump (multi-arch), radare2, capstone
    'd=""; if objdump -D -b binary -m i386:x86-64 code.bin 2>/dev/null | grep -q "push.*rbp"; then d="objdump -m i386:x86-64"; elif command -v r2 >/dev/null 2>&1 && r2 -q -a x86 -b 64 -c "pd 5" code.bin 2>/dev/null | grep -q "push rbp"; then d="r2 -a x86 -b 64"; elif python3 -c "import capstone;m=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);assert next(m.disasm(open(\'code.bin\',\'rb\').read(),0)).mnemonic==\'push\'" 2>/dev/null; then d="python3 capstone"; fi',
    'if [ -n "$d" ]; then say disasm-x86-64 ok "$d"; else say disasm-x86-64 no "objdump here disassembles only $(objdump -i 2>/dev/null | sed -n 2p | tr -d " " || echo its-own-architecture); no r2, no capstone"; fi',
    `if [ "$(zbarimg -q --raw probe.png 2>/dev/null)" = "${PROBE_PAYLOAD}" ]; then say qr-decode ok zbarimg; elif python3 -c "import cv2;d=cv2.QRCodeDetector();assert d.detectAndDecode(cv2.imread('probe.png'))[0]=='${PROBE_PAYLOAD}'" 2>/dev/null; then say qr-decode ok "python3 cv2"; elif python3 -c "from pyzbar.pyzbar import decode;from PIL import Image;assert decode(Image.open('probe.png'))[0].data==b'${PROBE_PAYLOAD}'" 2>/dev/null; then say qr-decode ok "python3 pyzbar"; else say qr-decode no "no program here decodes a QR symbol from a PNG"; fi`,
    'if ffmpeg -v error -f lavfi -i testsrc=duration=1:size=64x64:rate=5 -c:v mpeg4 p.mp4 2>/dev/null && [ "$(ffprobe -v error -count_frames -select_streams v:0 -show_entries stream=nb_read_frames -of csv=p=0 p.mp4 2>/dev/null)" = 5 ]; then say video-decode ok "ffmpeg, ffprobe"; else say video-decode no "no ffmpeg here that writes and reads back a clip"; fi',
    'if python3 -c "from PIL import Image;im=Image.open(\'probe.png\');assert im.size[0]>20" 2>/dev/null; then say image-read ok "python3 Pillow"; elif (magick probe.png probe.pnm || convert probe.png probe.pnm) 2>/dev/null; then say image-read ok ImageMagick; else say image-read no "no Pillow and no ImageMagick that reads a PNG"; fi',
    'if command -v tesseract >/dev/null 2>&1 && tesseract --version >/dev/null 2>&1; then say ocr ok tesseract; else say ocr no "no OCR engine: text in a picture is read by eye (the read tool) only"; fi',
    'if python3 -c "import brotli;assert brotli.decompress(brotli.compress(b\'x\'))==b\'x\'" 2>/dev/null; then say brotli ok "python3 brotli"; else say brotli no "no brotli: a br-encoded cache body is not inflated here"; fi',
    'if python3 -c "import numpy" 2>/dev/null; then say numpy ok "python3 numpy"; else say numpy no "no numpy"; fi',
    'if command -v gcc >/dev/null 2>&1 && printf "int main(){return 0;}" > t.c && gcc t.c -o /tmp/t.out 2>/dev/null && /tmp/t.out; then say compile-c ok gcc; else say compile-c no "no working C compiler (and $OUT is no-exec: build under /tmp)"; fi',
    'if python3 -c "from Crypto.Cipher import ChaCha20" 2>/dev/null || python3 -c "from cryptography.hazmat.primitives.ciphers import algorithms" 2>/dev/null; then say crypto-lib ok "python3 cryptography or pycryptodome"; else say crypto-lib no "no Python crypto library: use the pack tools, or write the primitive"; fi',
    "rm -f probe.png code.bin p.mp4 probe.pnm t.c",
    "exit 0",
  ].join("\n");
}

const WHAT: Record<string, string> = {
  "disasm-x86-64": "disassemble x86-64 code",
  "qr-decode": "decode a QR symbol from a PNG",
  "video-decode": "write and decode a video clip",
  "image-read": "read a PNG's pixels",
  ocr: "read text from a picture",
  brotli: "inflate brotli",
  numpy: "numpy",
  "compile-c": "compile and run C",
  "crypto-lib": "a Python crypto library",
};

/** The probe job's stdout, read: one capability per `cap` line; a capability with no line was not tried. */
export function readProbe(stdout: string): Capability[] {
  const out: Capability[] = [];
  for (const line of stdout.split("\n")) {
    const m = /^cap (\S+) (ok|no) (.*)$/.exec(line.trim());
    if (!m) continue;
    out.push({ id: m[1]!, what: WHAT[m[1]!] ?? m[1]!, ok: m[2] === "ok", ...(m[2] === "ok" ? { by: m[3]!.trim() } : { said: m[3]!.trim() }) });
  }
  return out;
}

/** The post the seats get: per image, what works and with what, and what does not. */
export function capabilitiesPost(byProfile: Record<string, Capability[] | { error: string }>): string {
  const lines = Object.entries(byProfile).map(([profile, caps]) => {
    if (!Array.isArray(caps)) return `- ${profile}: not tested (${caps.error})`;
    const yes = caps.filter((c) => c.ok).map((c) => `${c.what} (${c.by})`);
    const no = caps.filter((c) => !c.ok).map((c) => `${c.what}: ${c.said}`);
    return `- ${profile}: WORKS: ${yes.join("; ") || "none of the tested"}. DOES NOT: ${no.join("; ") || "none of the tested"}.`;
  });
  return `JOB IMAGE CAPABILITIES, each tested in a worker VM of that image with an input whose answer is known (job_run profile: <name> picks the image; your own VM is not a job image and holds less):\n${lines.join("\n")}\nA capability that does not work in any image is not there: do not probe for it again, ask the operator for a program (a request), or use a pack tool that does not need it. The whole is in job-capabilities.json.`;
}

export async function probeImages(call: HubCall, profiles: string[], o: { qr?: string; timeoutS?: number; sleep?: (ms: number) => Promise<void> } = {}): Promise<Record<string, Capability[] | { error: string }>> {
  const script = probeScript(o.qr ?? probeQrBase64());
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const out: Record<string, Capability[] | { error: string }> = {};
  const ids = new Map<string, string>();
  for (const profile of profiles) {
    const sub = await call("jobSubmit", { command: script, inputs: [], profile, timeout_seconds: 180, note: `known-answer capability probes of the ${profile} job image` });
    const id = String((sub.job as { job?: string } | undefined)?.job ?? "");
    if (sub.ok !== true || !id) out[profile] = { error: String(sub.reason ?? "the probe job was not accepted") };
    else ids.set(profile, id);
  }
  const until = Date.now() + (o.timeoutS ?? 900) * 1000;
  for (const [profile, id] of ids) {
    let st: Record<string, unknown> = {};
    for (;;) {
      st = await call("jobStatus", { job_id: id });
      const state = String((st.job as { state?: string } | undefined)?.state ?? "");
      if (state === "committed" || state === "cancelled" || Date.now() > until) break;
      await sleep(2000);
    }
    const state = String((st.job as { state?: string } | undefined)?.state ?? "");
    const caps = readProbe(String((st.stdout as { text?: string } | undefined)?.text ?? ""));
    out[profile] = state === "committed" && caps.length ? caps : { error: `the probe job ${id} ${state === "committed" ? "printed nothing" : `did not finish (${state || "no state"})`}` };
  }
  return out;
}

async function main(argv: string[]): Promise<number> {
  const [sandbox, ...rest] = argv;
  const opt = (name: string) => (rest.includes(name) ? rest[rest.indexOf(name) + 1] : undefined);
  const admin = opt("--hub-admin");
  const profiles = (opt("--profiles") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!sandbox || !admin || !profiles.length) {
    console.error("usage: image-capabilities.ts <sandbox> --hub-admin SOCKET --profiles NAME[,NAME]");
    return 2;
  }
  const call: HubCall = (fn, arg) =>
    new Promise((resolve, reject) => {
      let answer = "";
      const socket = connect(admin);
      socket.setTimeout(60_000, () => { socket.destroy(); reject(new Error("the hub did not answer")); });
      socket.setEncoding("utf8");
      socket.on("error", reject);
      socket.on("data", (c) => (answer += c));
      socket.on("close", () => { try { resolve(JSON.parse(answer.trim().split("\n")[0] ?? "{}") as Record<string, unknown>); } catch (err) { reject(err as Error); } });
      socket.on("connect", () => socket.write(`${JSON.stringify({ op: "call", fn, args: [sandbox, arg] })}\n`));
    });
  const result = await probeImages(call, profiles);
  const file = join(sandbox, "job-capabilities.json");
  const had = await readFile(file, "utf8").then((t) => JSON.parse(t) as Record<string, unknown>).catch(() => ({}));
  await writeFile(file, `${JSON.stringify({ ...had, at: new Date().toISOString(), images: result }, null, 2)}\n`);
  await call("systemPost", { tag: "result", to: "all", key: "job-capabilities", body: capabilitiesPost(result) }).catch(() => undefined);
  console.log(JSON.stringify(result));
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (err) => { console.error(`image-capabilities: ${(err as Error).message}`); process.exit(1); });
}
