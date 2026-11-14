/**
 * A forged tool's arguments are brought to the types its manifest declares.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { coerceArgs } from "../extensions/forged-args.ts";

test("what a string plainly is under its declared type is taken as that, and said (the runs' 14 crashed calls)", () => {
  const params = { candidates: { type: "array" }, offset: { type: "integer" }, ratio: { type: "number" }, deep: { type: "boolean" }, opts: { type: "object" }, path: { type: "string" }, keys: { type: "array" } };
  const r = coerceArgs(params, { candidates: "[1, 2, 3]", offset: "4096", ratio: "0.5", deep: "TRUE", opts: '{"a": 1}', path: "42", keys: "204724, 204715,abc" });
  assert.deepEqual(r.args, { candidates: [1, 2, 3], offset: 4096, ratio: 0.5, deep: true, opts: { a: 1 }, path: "42", keys: [204724, 204715, "abc"] });
  assert.equal(r.coerced.length, 6, "the string parameter is left alone");
  assert.match(r.coerced.join("; "), /candidates \(a string\) was taken as an array of 3/);
  assert.deepEqual(coerceArgs({ offset: { type: "integer" } }, { offset: "0x10" }).args, { offset: 16 });
});

test("what is not plainly of the type is left as it came; values already of the type are untouched", () => {
  const params = { n: { type: "integer" }, list: { type: "array" }, o: { type: "object" }, flag: { type: "boolean" } };
  const args = { n: "12.5", list: "[1, 2", o: "[1]", flag: "yes", extra: "kept" };
  const r = coerceArgs(params, args);
  assert.deepEqual(r.args, args);
  assert.deepEqual(r.coerced, []);
  assert.deepEqual(coerceArgs(params, { n: 3, list: [1], o: {}, flag: false }).coerced, []);
  assert.deepEqual(coerceArgs(undefined, { a: "1" }), { args: { a: "1" }, coerced: [] });
});
