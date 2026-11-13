/**
 * A job's $OUT is given a write quota of its own (scripts/job-service.ts
 * outQuotaMb): microsandbox bounds a bind with none to 4 GiB (measured on
 * msb: a write stops at 4,294,967,296 bytes), which stopped three
 * whole-image AD1 extractions of one run part way through a file.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { MSB_DEFAULT_QUOTA_MB, outQuotaMb } from "../scripts/job-service.ts";

test("$OUT's quota is the free room less what the service keeps free, never below msb's 4 GiB default; the environment can set it", () => {
  assert.equal(MSB_DEFAULT_QUOTA_MB, 4096);
  assert.equal(outQuotaMb(300_000, 4096, {}), 295_904, "the disk's room, less the service's reserve");
  assert.equal(outQuotaMb(6000, 4096, {}), 4096, "never below what a job could write before");
  assert.equal(outQuotaMb(null, 4096, {}), 4096, "room unknown: the default");
  assert.equal(outQuotaMb(300_000, 4096, { SWARM_JOB_OUT_QUOTA_MB: "20000" }), 20_000);
  assert.equal(outQuotaMb(300_000, 4096, { SWARM_JOB_OUT_QUOTA_MB: "nope" }), 295_904);
});
