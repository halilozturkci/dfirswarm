import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { mkdir, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * What a test needs of the host, said once, for the cases that are true only where it holds.
 *
 * NO_ADOPTION is the skip reason of a case that needs a host where the tool can adopt the orphans of a program (Linux: PR_SET_CHILD_SUBREAPER).
 * Where it cannot (macOS) the shared PROCESS block answers "partial" and says so, which is its honest answer, so a case that expects the answer
 * of a host that can (complete, a leftover found and ended) is skipped there, not bent. The darwin and refused cases of the process-apply suites
 * run on every host with the host patched, and they cover the answer of a host that cannot.
 */
export const NO_ADOPTION: string | false =
  process.platform === "linux"
    ? false
    : "this host cannot adopt orphaned processes (PR_SET_CHILD_SUBREAPER is Linux's): the tool answers partial here, which the darwin cases of the process-apply suites cover";

/** The skip reason of a case that needs another Linux-only facility, named by what. */
export const onlyLinux = (what: string): string | false => (process.platform === "linux" ? false : what + " is Linux's");

/** The interpreter the tests run tools with, by its real path. Where a case narrows PATH it must still lead to this one: macOS has Xcode's Python 3.9 in /usr/bin, and the tools need 3.11. */
export const PYTHON3: string = spawnSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).stdout.trim();

/** A directory (made if need be) that holds only a link named python3 to the interpreter above: put it first on a narrowed PATH. */
export async function interpreterDir(dir: string): Promise<string> {
  await mkdir(dir, { recursive: true });
  await symlink(PYTHON3, join(dir, "python3")).catch(() => undefined);
  return dir;
}

/** The skip reason of a case whose stand-in starts a writer with the setsid command (util-linux): macOS does not have it. */
export const NO_SETSID: string | false = spawnSync("sh", ["-c", "command -v setsid"]).status === 0 ? false : "the setsid command (util-linux) is not on this host";

/** The skip reason of a case that mounts a tmpfs of a few kilobytes in a user and mount namespace (unshare -rm) to make a full disk: a container without that right (the pack-tool CI job's) cannot. */
export const NO_TMPFS_NAMESPACE: string | false = (() => {
  const dir = mkdtempSync(join(tmpdir(), "tmpfs-probe-"));
  try {
    const r = spawnSync("unshare", ["-rm", "sh", "-c", 'mount -t tmpfs -o size=4k tmpfs "$1"', "sh", dir], { encoding: "utf8" });
    return r.status === 0 ? false : "this host does not allow a tmpfs mount in a user and mount namespace (unshare -rm): " + (r.stderr || "").trim().slice(0, 120);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
})();
