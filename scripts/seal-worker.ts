/**
 * A worker thread of the store's seal (evidence-store.ts sealTree): it
 * hashes the files it is handed, makes each read-only and links it to
 * store/blobs/<sha256>, so the process that owns the store (the hub) only
 * hands out names and collects digests. It also makes a large manifest's
 * head and index (manifest-index.ts), which means parsing the manifest.
 *
 * Every file it finishes is one fixed-size record appended to its own
 * progress log before the next file is touched: a seal that is killed has
 * lost only the file each worker was on, and the next seal reads the logs
 * and hashes the rest.
 *
 *   record (SEAL_RECORD_BYTES): u32le the file's place in the walk, f64le its size, 32 bytes its sha256
 *
 * Nothing here decides anything: which files, in which order they are
 * named in the manifest and what a failure means are the seal's.
 */
import { createHash } from "node:crypto";
import { chmodSync, closeSync, linkSync, openSync, readSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { parentPort, workerData } from "node:worker_threads";
import { indexManifestFile } from "./manifest-index.ts";

export const SEAL_RECORD_BYTES = 44;

/** `seal_worker` marks the thread as one of the seal's: this file is also imported for its types and its record size. */
export type SealWorkerData = { seal_worker: true; blobs: string; log: string; tmp: string };
/** `rels` are names as bytes, one character per byte (latin1): a name need not be UTF-8. */
export type SealWorkerTask = { op: "hash"; id: number; root: string; rels: string[]; ords: number[] } | { op: "index"; id: number; manifestPath: string };
/** Per file: its place, then its sha256 and size, or null and the error's code when it could not be read. */
export type SealWorkerDone = { id: number; done?: Array<[number, string | null, number | string]>; error?: string };

if (parentPort && (workerData as SealWorkerData | null)?.seal_worker === true) {
  const port = parentPort;
  const data = workerData as SealWorkerData;
  const buf = Buffer.allocUnsafe(1 << 20);
  const rec = Buffer.alloc(SEAL_RECORD_BYTES);
  let log = -1;

  const sha256Of = (path: Buffer): string => {
    const h = createHash("sha256");
    const fd = openSync(path, "r");
    try {
      for (;;) {
        const n = readSync(fd, buf, 0, buf.length, null);
        if (!n) break;
        h.update(n === buf.length ? buf : buf.subarray(0, n));
      }
    } finally {
      closeSync(fd);
    }
    return h.digest("hex");
  };

  const hashBatch = (task: Extract<SealWorkerTask, { op: "hash" }>): SealWorkerDone => {
    if (log < 0) log = openSync(data.log, "a");
    const root = Buffer.from(`${task.root}/`);
    const done: Array<[number, string | null, number | string]> = [];
    for (let i = 0; i < task.rels.length; i += 1) {
      const full = Buffer.concat([root, Buffer.from(task.rels[i], "latin1")]);
      let sha: string;
      try {
        try {
          sha = sha256Of(full);
        } catch (err) {
          // A tool running as root in its VM can leave a file mode 000: the host owns it, so it is opened up and read.
          if ((err as NodeJS.ErrnoException).code !== "EACCES" && (err as NodeJS.ErrnoException).code !== "EPERM") throw err;
          chmodSync(full, 0o644);
          sha = sha256Of(full);
        }
      } catch (err) {
        done.push([task.ords[i], null, (err as NodeJS.ErrnoException).code ?? "error"]);
        continue;
      }
      const st = statSync(full);
      chmodSync(full, 0o444);
      const blob = `${data.blobs}/${sha}`;
      try {
        linkSync(full, blob);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") {
          // The same bytes are already kept (by an earlier job, or by another worker a moment ago):
          // this occurrence becomes a link to them, put in place by a rename so the name is never missing.
          try {
            const kept = statSync(blob);
            if (kept.size === st.size && kept.ino !== st.ino) {
              linkSync(blob, data.tmp);
              renameSync(data.tmp, full);
            }
          } catch {
            // A blob with no room for another link: the occurrence stays its own copy.
            try {
              unlinkSync(data.tmp);
            } catch {
              // none was made
            }
          }
        }
        // A file system without hard links keeps the occurrence as its own copy.
      }
      rec.writeUInt32LE(task.ords[i], 0);
      rec.writeDoubleLE(st.size, 4);
      rec.write(sha, 12, 32, "hex");
      writeSync(log, rec);
      done.push([task.ords[i], sha, st.size]);
    }
    return { id: task.id, done };
  };

  try {
    unlinkSync(data.tmp);
  } catch {
    // none left by an earlier seal
  }
  port.on("message", (task: SealWorkerTask) => {
    if (task.op === "index") {
      indexManifestFile(task.manifestPath).then(
        () => port.postMessage({ id: task.id } satisfies SealWorkerDone),
        (err: Error) => port.postMessage({ id: task.id, error: err.message } satisfies SealWorkerDone),
      );
      return;
    }
    try {
      port.postMessage(hashBatch(task));
    } catch (err) {
      port.postMessage({ id: task.id, error: (err as Error).message } satisfies SealWorkerDone);
    }
  });
}
