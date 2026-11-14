/**
 * A value read from the hub before every model call, served within a deadline.
 *
 * The seat's `context` hook reads the budget twice and the sentinel once
 * before each model call. With a hub that is busy those three round trips
 * were the longest wait of the run: 136, 158 and 181 seat-minutes in the runs
 * s01a4f4, s17fdfe and s5d814f, against 2.4 in a run whose hub was free,
 * while the model's own latency did not move. A read that does not answer
 * within the deadline gives the last value it did answer with, and goes on
 * in the background so the next call has a newer one. Only a first read,
 * with nothing known yet, is waited for whole.
 */
export type LastKnown<T> = { read(fn: () => Promise<T>): Promise<T>; age(): number | null; stale(): number };

export function lastKnown<T>(deadlineMs: number, now: () => number = Date.now): LastKnown<T> {
  let known: { value: T; at: number } | null = null;
  let flying: Promise<void> | null = null;
  let failed: unknown = null;
  let staleServed = 0;
  return {
    async read(fn) {
      if (!flying) {
        failed = null;
        flying = fn()
          .then((value) => {
            known = { value, at: now() };
          })
          .catch((err) => {
            failed = err ?? new Error("read failed");
          })
          .finally(() => {
            flying = null;
          });
      }
      const mine = flying;
      if (!known) {
        await mine;
        if (known) return (known as { value: T }).value;
        throw failed ?? new Error("read failed");
      }
      let timer: ReturnType<typeof setTimeout> | undefined;
      const inTime = await Promise.race([mine.then(() => true), new Promise<boolean>((r) => (timer = setTimeout(() => r(false), deadlineMs)))]);
      if (timer) clearTimeout(timer);
      if (!inTime) staleServed += 1;
      return known.value;
    },
    age: () => (known ? now() - known.at : null),
    stale: () => staleServed,
  };
}
