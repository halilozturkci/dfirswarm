/**
 * The bound on what the hub answers a seat's board call with.
 *
 * A post has had a bound and a side file since the first runs; an answer
 * had none. On the run s5d814f the "Finish: not ready" line carried every
 * object a partial sweep had not searched (137,703 names) into `wait`,
 * `inbox`, `leads` and the hand-off: 76 MB answers, a request of 19 million
 * tokens, and all eight seats' links closed within ten minutes. Each source
 * of such text is bounded where it is made; this is the wall behind them. An
 * answer past the bound is a fault of the harness: it is kept whole on disk
 * and the seat is told so, by name, instead of being sent it.
 */

/** The functions whose answers carry a file's bytes or the tool library whole: bounded by their own rules, not this one. */
export const UNBOUNDED_FNS: ReadonlySet<string> = new Set(["fileDiff", "restoreFileVersion", "listFileHistory", "listForgedTools", "netFetch", "jobStatus", "jobSubmit"]);

export function rpcAnswerMax(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.SWARM_RPC_ANSWER_MAX_BYTES);
  return Number.isFinite(n) && n >= 16 * 1024 ? Math.floor(n) : 256 * 1024;
}

/** A job's answer may carry a page of stdout: it has its own page bound, and this wall is set well above it. */
export const JOB_ANSWER_MAX = 2 * 1024 * 1024;

export type RpcAnswer = { ok: boolean; result?: unknown; error?: string };
export type Kept = { path: string; bytes: number; sha256: string } | { write_error: string };

/**
 * The answer to send for `fn`: the answer itself within the bound, else one that says the answer was too large, how
 * large, and where it was kept whole. `keep` writes the whole answer to the run's kept outputs.
 */
export async function boundRpcAnswer(fn: string, answer: RpcAnswer, keep: (text: string) => Promise<Kept>, max = rpcAnswerMax()): Promise<{ answer: RpcAnswer; cut?: { fn: string; bytes: number; max: number; kept?: string } }> {
  const limit = fn === "jobStatus" || fn === "jobSubmit" ? Math.max(max, JOB_ANSWER_MAX) : UNBOUNDED_FNS.has(fn) ? Infinity : max;
  if (limit === Infinity) return { answer };
  const text = JSON.stringify(answer);
  const bytes = Buffer.byteLength(text);
  if (bytes <= limit) return { answer };
  const kept = await keep(text).catch((err: Error) => ({ write_error: err.message }) as Kept);
  const where = "path" in kept ? `kept whole at ${kept.path} (${kept.bytes} bytes, sha256 ${kept.sha256}): read it in pages (read with offset and limit, or a job) if you need it` : `and could not be kept (${kept.write_error})`;
  return {
    answer: { ok: false, error: `the hub's answer to ${fn} was ${bytes} bytes, over the bound of ${limit} on an answer: it was not sent, ${where}. This is a fault of the harness, not of your call: call again with a narrower request (a filter, a page, an id) and tell the operator on the board` },
    cut: { fn, bytes, max: limit, ...("path" in kept ? { kept: kept.path } : {}) },
  };
}

/** One item of a list in a header or digest, cut to a bound with a mark that it was cut. */
export function boundItem(item: string, max = 400): string {
  return item.length <= max ? item : `${item.slice(0, max - 40)}… (${item.length} characters; whole in finish status)`;
}

/**
 * A list of gate items for a header that every answer carries: the caller's own first, each cut to a bound, at most
 * `show` of them, and the rest as a count. `mine` says which items are the caller's.
 */
export function boundItems(items: readonly string[], mine: (item: string) => boolean, o: { show?: number; each?: number } = {}): { text: string; total: number; own: number; shown: number } {
  const show = o.show ?? 6;
  const own = items.filter(mine);
  const others = items.filter((i) => !mine(i));
  const picked = [...own, ...others].slice(0, show).map((i) => boundItem(i, o.each ?? 400));
  const rest = items.length - picked.length;
  const text = `${picked.join("; ")}${rest > 0 ? `${picked.length ? "; " : ""}and ${rest} more (finish status lists every one)` : ""}`;
  return { text, total: items.length, own: own.length, shown: picked.length };
}
