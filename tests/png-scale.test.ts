/**
 * An image a seat reads is made small enough to look at before it goes to
 * the model; what cannot be read is left alone.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { decodePng, encodePng, LONG_SIDE_MAX, pngForModel, scaleDown, type Decoded } from "../extensions/png-scale.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function gradient(w: number, h: number, channels: 3 | 4): Decoded {
  const pixels = Buffer.alloc(w * h * channels);
  for (let y = 0; y < h; y += 1) for (let x = 0; x < w; x += 1) {
    const o = (y * w + x) * channels;
    pixels[o] = (x * 7 + y * 3) & 0xff; pixels[o + 1] = (x * 13) & 0xff; pixels[o + 2] = (y * 11 + x) & 0xff;
    if (channels === 4) pixels[o + 3] = 255 - (x & 0x7f);
  }
  return { width: w, height: h, channels, pixels };
}

test("what is written is read back pixel for pixel, with and without alpha", () => {
  for (const ch of [3, 4] as const) {
    const img = gradient(37, 23, ch);
    const back = decodePng(encodePng(img));
    assert.ok(back);
    assert.deepEqual([back!.width, back!.height, back!.channels], [37, 23, ch]);
    assert.ok(back!.pixels.equals(img.pixels));
  }
});

test("a PNG written by another program is read: a QR symbol from the generator (grey, filter 0) keeps its modules after scaling", () => {
  const dir = mkdtempSync(join(tmpdir(), "pngscale-"));
  execFileSync("python3", ["-I", join(ROOT, "scripts", "lib", "qrgen.py"), "dfirswarm-probe", join(dir, "q.png"), "--scale", "100"]);
  const png = readFileSync(join(dir, "q.png"));
  const img = decodePng(png)!;
  assert.deepEqual([img.width, img.height, img.channels], [2900, 2900, 3]);
  const small = scaleDown(img);
  assert.equal(Math.max(small.width, small.height), LONG_SIDE_MAX);
  // The centre of the top-left finder is dark, the quiet zone is light, in both.
  const at = (d: Decoded, fx: number, fy: number) => d.pixels[(Math.floor(fy * d.height) * d.width + Math.floor(fx * d.width)) * d.channels]!;
  for (const d of [img, small]) {
    assert.ok(at(d, 7.5 / 29, 7.5 / 29) < 40, "finder centre dark");
    assert.ok(at(d, 1 / 29, 1 / 29) > 215, "quiet zone light");
  }
});

test("a large image is scaled for the model and says from what; a small one, a JPEG and a broken file are left alone", () => {
  const big = encodePng(gradient(3200, 1800, 3));
  const s = pngForModel(big, { minBytes: 1 })!;
  assert.ok(s, "scaled");
  assert.deepEqual([s.from.width, s.from.height], [3200, 1800]);
  assert.deepEqual([s.to.width, s.to.height], [1568, 882]);
  assert.ok(s.to.bytes < s.from.bytes);
  assert.ok(decodePng(s.data), "what comes out is a PNG this reads");
  assert.equal(pngForModel(encodePng(gradient(800, 600, 3)), { minBytes: 1 }), null, "already small in pixels");
  assert.equal(pngForModel(big, { minBytes: big.length + 1 }), null, "small in bytes");
  assert.equal(pngForModel(Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(400_000)])), null, "a JPEG");
  assert.equal(pngForModel(Buffer.concat([big.subarray(0, 60), Buffer.alloc(400_000)])), null, "a PNG cut short");
  assert.equal(decodePng(Buffer.alloc(10)), null);
});
