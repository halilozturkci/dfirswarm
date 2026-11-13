/**
 * The images a model call carries, at most (extensions/agent-swarm.ts
 * capImages, imageLimit, providerImageLimit). A seat of the run sf4406b read
 * 71 images; its provider took 32 a request, refused six turns in a row on the
 * same context, and the seat was lost for 74 minutes. Past the limit the
 * oldest images are left out of what the model is sent (the session keeps
 * them), in batches so the history changes rarely; a provider's refusal lowers
 * the limit to its own; the board no longer says "only this turn failed" for
 * a refusal that comes again on every turn.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { capImages, IMAGE_LEFT_OUT, imageLimit, MAX_IMAGES_DEFAULT, providerImageLimit } from "../extensions/agent-swarm.ts";
import { providerErrorPost } from "../extensions/finish-line.ts";

const img = (n: number) => ({ type: "image", data: `d${n}`, mimeType: "image/jpeg" });
const result = (...blocks: unknown[]) => ({ role: "toolResult", content: blocks });

test("past the cap the oldest images go until half of it is left, each as a line; the same number goes until the cap is passed again; 0 leaves all", () => {
  const msgs = [result({ type: "text", text: "a" }, img(1)), result(img(2), img(3)), { role: "user", content: "words" }, result(img(4)), result(img(5))];
  const none = capImages(msgs, 5);
  assert.deepEqual([none.dropped, none.images], [0, 5]);
  const four = capImages(msgs, 4);
  assert.deepEqual([four.dropped, four.images], [3, 5], "over 4: down to 2");
  const left = (m: unknown) => JSON.stringify(m).includes("an image left out of this call");
  assert.deepEqual(four.messages.map(left), [true, true, false, false, false]);
  assert.equal((four.messages[0] as { content: Array<{ type: string; text?: string }> }).content[0]!.text, "a", "other blocks stay");
  assert.equal((four.messages[0] as { content: Array<{ text?: string }> }).content[1]!.text, IMAGE_LEFT_OUT.replace("{cap}", "4"));
  assert.deepEqual(msgs[0]!.content[1], img(1), "the session's own messages are not changed");
  // A new image: the same three go (the history changes nowhere new) until the cap is passed again.
  const more = [...msgs, result(img(6))];
  assert.equal(capImages(more, 4, 3).dropped, 3);
  const many = [...more, result(img(7)), result(img(8))];
  assert.equal(capImages(many, 4, 3).dropped, 6, "past the cap again: down to half");
  assert.equal(capImages(msgs, 0).dropped, 0);
});

test("the limit: SWARM_MAX_IMAGES, 0 for none, the default otherwise; the provider's number from its refusal", () => {
  assert.equal(imageLimit({}), MAX_IMAGES_DEFAULT);
  assert.equal(imageLimit({ SWARM_MAX_IMAGES: "0" }), 0);
  assert.equal(imageLimit({ SWARM_MAX_IMAGES: "10" }), 10);
  assert.equal(imageLimit({ SWARM_MAX_IMAGES: "x" }), MAX_IMAGES_DEFAULT);
  assert.equal(providerImageLimit('400 {"error":{"code":"too_many_images","message":"Too many images: at most 32 images per request"}}'), 32);
  assert.equal(providerImageLimit("400 too_many_images"), 0, "a refusal that names no number");
  assert.equal(providerImageLimit("429 Too Many Requests"), null);
});

test("the board: a refusal that comes again on every turn says what the harness changed, not that only this turn failed", () => {
  const plain = providerErrorPost("s1", "p/m", "429 Too Many Requests");
  assert.match(plain, /Only this turn failed\. s1's work/);
  const images = providerErrorPost("s1", "p/m", "400 too_many_images", "From the next turn the harness sends s1's newest 24 images only (the session keeps the rest), so the next turn should go through.");
  assert.doesNotMatch(images, /Only this turn failed/);
  assert.match(images, /ended with: 400 too_many_images\. From the next turn the harness sends s1's newest 24 images only .* s1's work, its leads/);
});
