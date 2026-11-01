/**
 * The one way the tests read a tool's peak resident memory.
 *
 * `ru_maxrss` on Linux still counts the process image that exec replaced, so a
 * child forked from a parent that holds a few hundred MB reads as that big
 * whatever the tool does. The helper (tests/fixtures/peak_rss.py) reads VmHWM of
 * the image the process runs now, and falls back to the rusage only where there
 * is no /proc (macOS, where the replaced image is not counted).
 *
 * A wrapper run with `python3 -c` starts with `peakRssPrelude()`; it then has
 *   run_peak(args, input=..., capture_output=True, timeout=...)  -> (CompletedProcess, child peak in bytes)
 *   self_peak_bytes()                                           -> this process's peak in bytes
 * No test calls `getrusage(...).ru_maxrss` itself (tests/peak-rss.test.ts).
 */
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const PEAK_RSS_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

/** Python source to put first in a `python3 -c` wrapper. */
export function peakRssPrelude(): string {
  return `import sys\nsys.path.insert(0, ${JSON.stringify(PEAK_RSS_DIR)})\nfrom peak_rss import run_peak, self_peak_bytes\n`;
}
