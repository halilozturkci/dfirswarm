/**
 * computer-forensics-base: frame_survey, every frame of a video on contact sheets, the runs that stand out, frames at native size and a
 * checked container repair.
 *
 * The capability is done when a ten-frame captioned stretch inside a clip with no scene cut is found by the default call. The clip is
 * made here: 150 frames of a slowly drifting gradient are drawn pixel by pixel, a row of white marks (the caption) is drawn into frames
 * 60 to 69, and the host's ffmpeg encodes them (MPEG-4 part 2, its own encoder). A host with no ffmpeg and ffprobe cannot make the clip
 * or decode it: the cases that need them are skipped there, with that reason, and the two that do not still run on every host: the
 * answer of an image with no decoder (failed, one JSON document, the reason), and a stand-in decoder that leaves a late child holding
 * its output pipe (an abandoned holder), which must not hold the tool.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { inflateSync } from "node:zlib";
import { CLEAN } from "./host-gates.ts";
import { call, CFB, filesBelow, py, withRun, type Doc } from "./pack-base-media-fixture.ts";

const HAVE = spawnSync("ffmpeg", ["-version"]).status === 0 && spawnSync("ffprobe", ["-version"]).status === 0;
const NO_DECODER: string | false = HAVE ? false : "this host has no ffmpeg and ffprobe on PATH: the clip cannot be encoded or decoded here (the job image declares them in the pack's requires/host.json)";

/** 150 frames of 320 x 180 RGB on stdout: a gradient that drifts one step a frame, and twelve white marks in frames 60 to 69. */
const FRAMES = String.raw`
import sys
w, h, n = 320, 180, 150
out = sys.stdout.buffer
for i in range(n):
    rows = []
    for y in range(h):
        row = bytearray()
        green = y * 255 // h
        for x in range(w):
            row += bytes(((x + i) * 255 // (w + n), green, 128))
        rows.append(row)
    if 60 <= i < 70:
        for k in range(12):
            for y in range(140, 152):
                x0 = 60 + k * 16
                rows[y][x0 * 3:(x0 + 10) * 3] = b"\xff\xff\xff" * 10
    out.write(b"".join(rows))
`;

function clip(run: string, name: string, extra: string[] = []): void {
  const frames = spawnSync("python3", ["-I", "-c", FRAMES], { maxBuffer: 64 << 20 });
  assert.equal(frames.status, 0);
  const r = spawnSync("ffmpeg", ["-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", "320x180", "-r", "25", "-i", "-", "-c:v", "mpeg4", "-q:v", "4", ...extra, join(run, name)], { input: frames.stdout, maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, r.stderr.toString());
}

const pngSize = (b: Buffer): [number, number] => [b.readUInt32BE(16), b.readUInt32BE(20)];

test("the default call finds a ten-frame captioned stretch in a clip with no scene cut, and tiles every frame with its number and time", { skip: NO_DECODER }, async () => {
  await withRun(async (run, out) => {
    clip(run, "inputs/case files/clip one.mp4");
    const r = await call("frame_survey", run, { video: "inputs/case files/clip one.mp4" }, { out });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.stderr, "");
    const a = r.doc;
    assert.equal(a.status, CLEAN, a.status_basis);
    assert.deepEqual([a.mode, a.frames_decoded, a.frames_the_container_says, a.first_frame, a.last_frame, a.every, a.tile, a.sheets], ["survey", 150, 150, 0, 149, 1, "160 x 90", 3]);
    assert.equal(a.scene_cuts.count, 0, "the clip has no scene cut");
    assert.equal(a.runs_total, 1);
    const run1 = a.runs[0] as Doc;
    assert.deepEqual([run1.first_frame, run1.last_frame, run1.frames_decoded_in_run], [60, 69, 10], "the captioned stretch, frame for frame");
    assert.deepEqual([run1.first_time, run1.last_time], ["0:02.40", "0:02.76"]);
    // The caption is at x 60 to 246, y 140 to 152 of the 320 x 180 frame: the region of the run holds it, and little else.
    const [x0, y0, x1, y1] = run1.region_native_pixels as number[];
    assert.ok(x0 <= 60 && x1 >= 246 && y0 <= 140 && y1 >= 152 && x1 - x0 <= 220 && y1 - y0 <= 40, `region ${run1.region_native_pixels}`);
    assert.deepEqual(run1.sheets, ["store/jobs/j000001/out/frame_survey/sheet-0002.png"]);
    assert.equal(a.windows_that_stand_out[0].first_frame, 60);
    assert.deepEqual(a.sheet_files.map((s: Doc) => [s.first_frame, s.last_frame]), [[0, 59], [60, 119], [120, 149]]);
    assert.deepEqual(a.times, { from_the_frames_own_presentation_time: 150, from_frame_over_rate: 0, rate: 25 });
    assert.deepEqual(filesBelow(out), ["frame_survey/frames.tsv", "frame_survey/sheet-0001.png", "frame_survey/sheet-0002.png", "frame_survey/sheet-0003.png", "frame_survey/windows.tsv"]);
    // A sheet is 10 tiles wide and 6 high, each 160 x 90 with a label under it.
    assert.deepEqual(pngSize(await readFile(join(out, "frame_survey", "sheet-0001.png"))), [1640, 648]);
    const rows = (await readFile(join(out, "frame_survey", "frames.tsv"), "utf8")).trim().split("\n").map((l) => l.split("\t"));
    assert.equal(rows.length, 151);
    assert.deepEqual(rows[61]!.slice(0, 3), ["60", "2.400000", "the frame's presentation time"]);
    assert.ok(Number(rows[61]![3]) > 0.03 && Number(rows[71]![3]) > 0.03 && Number(rows[65]![3]) < 0.01, "the score rises where the caption comes and goes, not inside it");
  });
});

test("a sampled or capped survey is partial and says what it skipped; a range of frames is written at native size", { skip: NO_DECODER }, async () => {
  await withRun(async (run, out) => {
    clip(run, "inputs/case files/clip one.mp4");
    const sampled = await call("frame_survey", run, { video: "inputs/case files/clip one.mp4", every: 5 }, { out });
    assert.deepEqual([sampled.doc.status, sampled.doc.complete, sampled.doc.frames_decoded, sampled.doc.last_frame], ["partial", false, 30, 145]);
    assert.match(sampled.doc.skipped[0], /4 of every 5 frames between the samples \(every: 5\): a run shorter than 5 frames can fall between two samples/);
    const capped = await call("frame_survey", run, { video: "inputs/case files/clip one.mp4", max_frames: 40 }, { out });
    assert.deepEqual([capped.doc.status, capped.doc.frames_decoded], ["partial", 40]);
    assert.match(capped.doc.skipped[0], /every frame after frame 39 \(max_frames 40 was reached\): go on with start_frame 40/);
    const rest = await call("frame_survey", run, { video: "inputs/case files/clip one.mp4", start_frame: 40 }, { out });
    assert.deepEqual([rest.doc.frames_decoded, rest.doc.first_frame, rest.doc.last_frame, rest.doc.runs[0].first_frame, rest.doc.runs[0].last_frame], [110, 40, 149, 60, 69]);
    assert.equal(rest.doc.status, "partial", "a survey that began past frame 0 is not the whole stream");

    const frames = await call("frame_survey", run, { video: "inputs/case files/clip one.mp4", mode: "extract", first: 68, last: 70 }, { out });
    assert.deepEqual([frames.doc.status, frames.doc.frames_written, frames.doc.size], [CLEAN, 3, "320 x 180 (native)"]);
    assert.deepEqual(frames.doc.frames.map((f: Doc) => [f.frame, f.time]), [[68, "0:02.72"], [69, "0:02.76"], [70, "0:02.80"]]);
    const dir = frames.doc.output_directory.replace("store/jobs/j000001/out/", "");
    const with69 = await readFile(join(out, dir, "frame-000069.png"));
    assert.deepEqual(pngSize(with69), [320, 180]);
    const past = await call("frame_survey", run, { video: "inputs/case files/clip one.mp4", mode: "extract", first: 148, last: 155 }, { out });
    assert.deepEqual([past.doc.status, past.doc.frames_written], ["partial", 2]);
    assert.match(past.doc.status_basis, /the stream gave 2 of the 8 frames asked for/);
  });
});

test("repair: a moov at the end is moved, a cut file keeps what decodes, an AVI gets its index, and a missing moov is not rebuilt; the claim is the frames the copy decodes", { skip: NO_DECODER }, async () => {
  await withRun(async (run, out) => {
    const dir = "inputs/case files";
    clip(run, `${dir}/whole.mp4`);
    clip(run, `${dir}/front.mp4`, ["-movflags", "+faststart"]);
    clip(run, `${dir}/whole.avi`);
    py(String.raw`
import sys
d = sys.argv[1]
whole = open(d + "/whole.mp4", "rb").read()
open(d + "/no moov.mp4", "wb").write(whole[:len(whole) * 2 // 3])          # the moov is at the end: a cut loses it
front = open(d + "/front.mp4", "rb").read()
open(d + "/cut data.mp4", "wb").write(front[:len(front) * 2 // 3])          # the moov is in front: a cut loses samples
avi = open(d + "/whole.avi", "rb").read()
open(d + "/no index.avi", "wb").write(avi[:avi.rfind(b"idx1")])
open(d + "/not a video.bin", "wb").write(b"plain bytes " * 50)
`, [join(run, dir)], run);

    const moved = await call("frame_survey", run, { video: `${dir}/whole.mp4`, mode: "repair" }, { out });
    assert.deepEqual(moved.doc.diagnosis.findings.map((f: Doc) => f.finding), ["moov at end"]);
    assert.deepEqual([moved.doc.status, moved.doc.original.frames_that_decode, moved.doc.repaired.frames_that_decode], [CLEAN, 150, 150]);
    assert.match(moved.doc.claim, /the repaired copy decodes 150 frames; the original decodes 150 as it is\. That count is all that was verified/);
    // The copy is where the answer says, and its moov is now in front of its media data.
    const copy = await readFile(join(out, moved.doc.repaired.file.replace("store/jobs/j000001/out/", "")));
    assert.ok(copy.indexOf("moov") > 0 && copy.indexOf("moov") < copy.indexOf("mdat"));

    const cut = await call("frame_survey", run, { video: `${dir}/cut data.mp4`, mode: "repair" }, { out });
    assert.deepEqual(cut.doc.diagnosis.findings.map((f: Doc) => f.finding), ["mdat cut"]);
    assert.ok(cut.doc.repaired.frames_that_decode > 50 && cut.doc.repaired.frames_that_decode < 150, `the copy decodes ${cut.doc.repaired.frames_that_decode} frames`);
    assert.match(cut.doc.could_not[0], /the samples that lay past the end of the file/);
    assert.notEqual(cut.doc.status, "failed");
    assert.match(cut.doc.claim, new RegExp(`the repaired copy decodes ${cut.doc.repaired.frames_that_decode} frames`));

    // A survey of the cut file is never `complete`, whatever the decoder's exit code: its own lines about errors make it partial.
    const surveyed = await call("frame_survey", run, { video: `${dir}/cut data.mp4` }, { out });
    assert.equal(surveyed.doc.status, "partial");
    assert.ok(surveyed.doc.frames_decoded > 50 && surveyed.doc.frames_decoded < 150);
    assert.match(JSON.stringify(surveyed.doc.partial_reasons), /the decoder wrote \d+ line\(s\) about errors while it decoded/);
    assert.ok(surveyed.doc.decoder_said.length >= 1);

    const gone = await call("frame_survey", run, { video: `${dir}/no moov.mp4`, mode: "repair" }, { out });
    assert.equal(gone.code, 1);
    assert.deepEqual(gone.doc.diagnosis.findings.map((f: Doc) => f.finding), ["moov missing", "mdat cut"]);
    assert.deepEqual([gone.doc.status, gone.doc.rebuilt, gone.doc.repaired], ["failed", [], undefined]);
    assert.match(gone.doc.could_not[0], /the moov box: its sample tables and codec configuration are not in the file/);
    assert.match(gone.doc.status_basis, /no repaired copy was written/);

    const avi = await call("frame_survey", run, { video: `${dir}/no index.avi`, mode: "repair" }, { out });
    assert.ok(avi.doc.diagnosis.findings.some((f: Doc) => f.finding === "index missing"));
    assert.equal(avi.doc.repaired.frames_that_decode, 150);
    assert.match(avi.doc.rebuilt[0], /the index \(idx1\) and the RIFF sizes/);
    const rebuilt = await readFile(join(out, avi.doc.repaired.file.replace("store/jobs/j000001/out/", "")));
    assert.ok(rebuilt.includes("idx1"), "the copy has an index again");

    const other = await call("frame_survey", run, { video: `${dir}/not a video.bin`, mode: "repair" }, { out });
    assert.deepEqual([other.code, other.doc.status], [1, "failed"]);
    assert.match(other.doc.error, /neither an ISO media box nor a RIFF AVI header/);
    const unreadable = await call("frame_survey", run, { video: `${dir}/not a video.bin` }, { out });
    assert.deepEqual([unreadable.code, unreadable.doc.status], [1, "failed"]);
    assert.match(unreadable.doc.status_basis, /no frame was decoded.*\{"mode": "repair"\}/);
  });
});

test("an image with no decoder answers failed with that reason in one JSON document, and repair still prints the container's diagnosis", async () => {
  await withRun(async (run, out) => {
    // An MP4 by its boxes alone: ftyp, a short mdat, no moov. No decoder is asked to read it.
    const box = (kind: string, body: Buffer): Buffer => {
      const head = Buffer.alloc(8);
      head.writeUInt32BE(8 + body.length, 0);
      head.write(kind, 4, "latin1");
      return Buffer.concat([head, body]);
    };
    await writeFile(join(run, "inputs/case files/boxes only.mp4"), Buffer.concat([box("ftyp", Buffer.from("isom\0\0\0\0isom")), box("mdat", Buffer.alloc(64))]));
    for (const mode of ["survey", "extract"]) {
      const r = await call("frame_survey", run, { video: "inputs/case files/boxes only.mp4", mode, first: 0 }, { out, path: "/usr/bin:/bin" });
      assert.equal(r.code, 1);
      assert.equal(r.stderr, "");
      assert.equal(r.doc.status, "failed");
      assert.match(r.doc.error, /^no video decoder is in this image: ffmpeg and ffprobe are not on PATH/);
      assert.match(r.doc.status_basis, /no frame was decoded, and that says nothing about the video/);
      assert.deepEqual(r.doc.decoder, { ffmpeg: false, ffprobe: false });
    }
    const repair = await call("frame_survey", run, { video: "inputs/case files/boxes only.mp4", mode: "repair" }, { out, path: "/usr/bin:/bin" });
    assert.equal(repair.doc.status, "failed");
    assert.deepEqual(repair.doc.diagnosis.findings.map((f: Doc) => f.finding), ["moov missing"]);
    assert.match(repair.doc.status_basis, /the container was read \(diagnosis\) but nothing was repaired or verified: no video decoder is in this image/);
    assert.deepEqual(filesBelow(out), [], "nothing was written");
  });
});

test("a decoder that ends and leaves a late child holding its pipe (an abandoned holder) does not hold the tool: partial, in time", async () => {
  await withRun(async (run, out) => {
    const bin = join(run, "work", "bin");
    await mkdir(bin, { recursive: true });
    await writeFile(join(bin, "ffprobe"), `#!/bin/sh\necho '{"streams": [{"codec_name": "standin", "width": 320, "height": 180, "avg_frame_rate": "25/1", "nb_frames": "9"}], "format": {"format_name": "standin", "duration": "0.36"}}'\n`);
    // Three whole tiles (160 x 90 x 3 bytes each), then a child that keeps standard output open for four seconds and writes again.
    await writeFile(join(bin, "ffmpeg"), `#!/bin/sh\nhead -c 129600 /dev/zero\n( sleep 4; head -c 43200 /dev/zero ) &\nexit 0\n`);
    for (const name of ["ffprobe", "ffmpeg"]) await chmod(join(bin, name), 0o755);
    await writeFile(join(run, "inputs/case files/any.mp4"), "the stand-ins read no byte of it");
    const r = await call("frame_survey", run, { video: "inputs/case files/any.mp4" }, { out, path: `${bin}:/usr/bin:/bin`, limitMs: 30_000 });
    assert.equal(r.killed, false);
    assert.ok(r.ms < 3500, `the tool answered in ${r.ms} ms, before the holder's four seconds were up`);
    assert.equal(r.doc.status, "partial", r.stdout);
    assert.equal(r.doc.frames_decoded, 3, "the frames the decoder wrote before it ended, and none of the late child's");
    assert.match(JSON.stringify(r.doc.partial_reasons), /the decoder ended but something it started kept its output pipe open: the end of the stream was not seen/);
    assert.ok("program_group" in r.doc);
    assert.deepEqual(r.doc.times, { from_the_frames_own_presentation_time: 0, from_frame_over_rate: 3, rate: 25 });
  });
});

/** The pixel rows of an 8-bit RGB PNG of one IDAT whose rows all use filter 0 (what the tool writes), read from the format: the bytes, and the size. */
function pngRgb(b: Buffer): { width: number; height: number; pixels: Buffer } {
  const [width, height] = pngSize(b);
  assert.deepEqual([b[24], b[25]], [8, 2], "8-bit RGB");
  const parts: Buffer[] = [];
  for (let at = 8; at < b.length; ) {
    const length = b.readUInt32BE(at);
    if (b.toString("latin1", at + 4, at + 8) === "IDAT") parts.push(b.subarray(at + 8, at + 8 + length));
    at += 12 + length;
  }
  const raw = inflateSync(Buffer.concat(parts));
  const rows: Buffer[] = [];
  for (let y = 0; y < height; y++) {
    assert.equal(raw[y * (width * 3 + 1)], 0, "filter 0");
    rows.push(raw.subarray(y * (width * 3 + 1) + 1, (y + 1) * (width * 3 + 1)));
  }
  return { width, height, pixels: Buffer.concat(rows) };
}

/** The clip turned by a display matrix (the container's own; no frame re-encoded), or false when this ffmpeg has no way to say one. */
function rotated(run: string, from: string, to: string): boolean {
  for (const args of [["-display_rotation", "90", "-i", join(run, from), "-c", "copy"], ["-i", join(run, from), "-c", "copy", "-metadata:s:v:0", "rotate=90"]]) {
    const r = spawnSync("ffmpeg", ["-v", "error", "-y", ...args, join(run, to)]);
    const said = spawnSync("ffprobe", ["-v", "error", "-select_streams", "v", "-show_entries", "stream", "-of", "json", join(run, to)], { encoding: "utf8" });
    if (r.status === 0 && /"rotat(e|ion)"/.test(said.stdout)) return true;
  }
  return false;
}

test("a video with a display rotation is extracted at the size the decoder gives: every byte where it belongs, and the turn said", { skip: NO_DECODER }, async (t) => {
  await withRun(async (run, out) => {
    clip(run, "inputs/case files/clip one.mp4");
    if (!rotated(run, "inputs/case files/clip one.mp4", "inputs/case files/turned.mp4")) {
      t.skip("this ffmpeg writes no display rotation (-display_rotation is ffmpeg 6's; the rotate tag an older muxer's): there is no turned video to examine");
      return;
    }
    const r = await call("frame_survey", run, { video: "inputs/case files/turned.mp4", mode: "extract", first: 62, last: 62 }, { out });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.doc.status, CLEAN, r.doc.status_basis);
    assert.equal(r.doc.size, "180 x 320 (native)", "the frame as the decoder gives it, turned");
    assert.match(r.doc.rotation_note, /display rotation of -?90 degrees: the decoder turns each frame as a player shows it .* 180 x 320 \(coded 320 x 180\)/);
    const png = await readFile(join(out, "frame_survey", "frame-000062.png"));
    const got = pngRgb(png);
    assert.deepEqual([got.width, got.height], [180, 320]);
    // The same frame as ffmpeg itself renders it, as raw RGB: the tool's PNG holds those bytes, row for row.
    const ref = spawnSync("ffmpeg", ["-v", "error", "-i", join(run, "inputs/case files/turned.mp4"), "-vf", "select=eq(n\\,62)", "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", "-"], { maxBuffer: 64 << 20 });
    assert.equal(ref.status, 0);
    assert.equal(ref.stdout.length, 180 * 320 * 3);
    assert.ok(got.pixels.equals(ref.stdout), "the frame is the decoder's own, not its bytes cut at the coded size");
    // The survey tiles the turned frame, at its own shape.
    const surveyed = await call("frame_survey", run, { video: "inputs/case files/turned.mp4", max_frames: 10 }, { out });
    assert.deepEqual([surveyed.doc.tile, surveyed.doc.tile_keeps_shape], ["160 x 284", true]);
  });
});

/** Ten frames of a picture 8 pixels wide and 720 high, lossless (FFV1 in Matroska): a frame far taller than wide. */
function tall(run: string, name: string): void {
  const frames = spawnSync("python3", ["-I", "-c", "import sys\nfor i in range(10): sys.stdout.buffer.write(bytes((y * 255 // 720, i * 20, 128)[c] for y in range(720) for _ in range(8) for c in range(3)))"], { maxBuffer: 64 << 20 });
  assert.equal(frames.status, 0);
  const r = spawnSync("ffmpeg", ["-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", "8x720", "-r", "25", "-i", "-", "-c:v", "ffv1", join(run, name)], { input: frames.stdout, maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, r.stderr.toString());
}

test("a frame far taller than wide is tiled in a bounded box, and a sheet too large to hold is refused", { skip: NO_DECODER }, async () => {
  await withRun(async (run, out) => {
    tall(run, "inputs/case files/tall.mkv");
    const r = await call("frame_survey", run, { video: "inputs/case files/tall.mkv", max_seconds: 10 }, { out, limitMs: 60_000 });
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.doc.status, CLEAN, r.doc.status_basis);
    assert.equal(r.doc.frames_decoded, 10);
    // The tile is at most twice as high as the box is wide (160): 320 high, and narrowed with it; the old tile was 160 x 14400.
    assert.deepEqual([r.doc.tile, r.doc.tile_keeps_shape], ["4 x 320", false]);
    assert.match(r.doc.tile_note, /a frame of 8 x 720 does not fit a tile 160 wide and at most 320 high with its shape: its tile is 4 x 320/);
    assert.deepEqual(pngSize(await readFile(join(out, "frame_survey", "sheet-0001.png"))), [1640, 6 * (320 + 18)]);
    assert.ok(r.doc.seconds < 5, `the survey took ${r.doc.seconds} s`);
    // At the largest tile and sheet a call may ask for, a sheet of such tiles would be over 500 MB: refused before anything is decoded.
    const big = await call("frame_survey", run, { video: "inputs/case files/tall.mkv", tile_width: 480, columns: 20, rows: 20 }, { out });
    assert.deepEqual([big.code, big.doc.status], [1, "failed"]);
    assert.match(big.doc.error, /a sheet of 20 x 20 tiles of 10 x 960 pixels is \d+ bytes, over the 201326592 this tool holds at once/);
  });
});

test("a decoder that ends while a late child floods its pipe is read for a bounded time and size, and the frames read after it ended are said", async () => {
  await withRun(async (run, out) => {
    const bin = join(run, "work", "bin");
    await mkdir(bin, { recursive: true });
    await writeFile(join(bin, "ffprobe"), `#!/bin/sh\necho '{"streams": [{"codec_name": "standin", "width": 320, "height": 180, "avg_frame_rate": "25/1"}], "format": {"format_name": "standin"}}'\n`);
    // Three whole tiles (160 x 90 x 3 bytes each), then a child that writes 50 MB more after the decoder has ended (about 1,150 tiles).
    await writeFile(join(bin, "ffmpeg"), `#!/bin/sh\ncase "$*" in *-version*) echo "ffmpeg version 9.0"; exit 0;; esac\nhead -c 129600 /dev/zero\n( sleep 0.3; head -c 50000000 /dev/zero ) &\nexit 0\n`);
    for (const name of ["ffprobe", "ffmpeg"]) await chmod(join(bin, name), 0o755);
    await writeFile(join(run, "inputs/case files/any.mp4"), "the stand-ins read no byte of it");
    const r = await call("frame_survey", run, { video: "inputs/case files/any.mp4", max_seconds: 20 }, { out, path: `${bin}:/usr/bin:/bin`, limitMs: 40_000 });
    assert.equal(r.killed, false);
    assert.equal(r.doc.status, "partial", r.stdout);
    assert.ok(r.doc.frames_decoded >= 3 && r.doc.frames_decoded <= 3 + Math.ceil((1 << 20) / 43200), `${r.doc.frames_decoded} frames: at most a mebibyte's worth past the decoder's three`);
    assert.match(JSON.stringify(r.doc.partial_reasons), /kept its output pipe open: the end of the stream was not seen \(\d+ of the frames counted here were read after the decoder had ended/);
    assert.ok(r.ms < 10_000, `answered in ${r.ms} ms`);
  });
});

test("a name with an error word is not an error, a second video stream is said, and a refused number states its own range", { skip: NO_DECODER }, async () => {
  await withRun(async (run, out) => {
    clip(run, "inputs/case files/missing corrupt error.mp4");
    const named = await call("frame_survey", run, { video: "inputs/case files/missing corrupt error.mp4", max_frames: 30 }, { out });
    assert.equal(named.doc.decoder_said, undefined, JSON.stringify(named.doc.decoder_said));
    assert.ok(!JSON.stringify(named.doc.partial_reasons ?? []).includes("about errors"), "the file's own name is not a line about an error");
    clip(run, "inputs/case files/a.mp4");
    const two = spawnSync("ffmpeg", ["-v", "error", "-y", "-i", join(run, "inputs/case files/a.mp4"), "-i", join(run, "inputs/case files/a.mp4"), "-map", "0:v", "-map", "1:v", "-c", "copy", join(run, "inputs/case files/two.mkv")]);
    assert.equal(two.status, 0, two.stderr.toString());
    const both = await call("frame_survey", run, { video: "inputs/case files/two.mkv", max_frames: 10 }, { out });
    assert.match(both.doc.streams_note, /the file has 2 video streams and this tool reads the first \(0:v:0\) only/);
    assert.equal(both.doc.stream.video_streams, 2);
    for (const [args, range] of [[{ every: 0 }, "every must be a whole number from 1 to 100000"], [{ tile_width: 10 }, "tile_width must be a whole number from 64 to 480"], [{ columns: 50 }, "columns must be a whole number from 1 to 20"]] as const) {
      const r = await call("frame_survey", run, { video: "inputs/case files/a.mp4", ...args }, { out });
      assert.equal(r.doc.error, range);
    }
  });
});

test("the rules are in the manifest, in every refusal and on the note's card, and the manifest declares the decoder", async () => {
  const manifest = JSON.parse(await readFile(join(CFB, "tools", "frame_survey", "manifest.json"), "utf8")) as Doc;
  assert.deepEqual(manifest.requires, ["ffmpeg", "ffprobe"]);
  const host = JSON.parse(await readFile(join(CFB, "requires", "host.json"), "utf8")) as { binaries: Doc[] };
  for (const name of ["ffmpeg", "ffprobe"]) assert.equal(host.binaries.find((b) => b.name === name)?.optional, true, `${name} is declared, optional`);
  await withRun(async (run, out) => {
    const r = await call("frame_survey", run, {}, { out });
    assert.equal(r.code, 1);
    const rules = r.doc.rules as string[];
    assert.ok(rules.length >= 3 && rules.length <= 5);
    for (const rule of rules) assert.ok(manifest.description.includes(rule));
    assert.match(r.doc.error, /video is required.*Survey first, with the default call/);
    const bad = await call("frame_survey", run, { video: "inputs/case files/x.mp4", mode: "extract" }, { out, path: "/usr/bin:/bin" });
    assert.equal(bad.doc.status, "failed");
  });
  const note = await readFile(join(CFB, "skills", "data", "video.md"), "utf8");
  const card = /^card: (.+)$/m.exec(note)?.[1] ?? "";
  assert.ok(card.length > 100 && card.length <= 700);
  assert.match(card, /\{"mode": "extract", "first": N, "last": M\}/);
  assert.match(card, /No ffmpeg in the image: status failed, not an empty video/);
});
