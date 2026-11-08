import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

/**
 * The skip reason of a case that makes or walks a hundred thousand files or more and bounds the time it takes (the 600,000 files of recovery_key_scan, the 100,000 homes of shell_history):
 * on a hosted macOS runner (APFS) making them takes longer than the case, and the file around it, are given (they were cut at 120 and 300 seconds), which says nothing of the tool.
 * The Linux jobs run them.
 */
export const SLOW_BIG_TREES: string | false = process.platform === "darwin" ? "a tree of 100,000 files or more takes minutes to make and walk on a macOS runner's file system: the Linux jobs run this case" : false;

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

/** What a clean run of a tool that runs a program answers on this host: `complete` where the tool can adopt orphans (Linux), `partial` (saying why) where it cannot. */
export const CLEAN: "complete" | "partial" = process.platform === "linux" ? "complete" : "partial";

/** The skip reason of a case that reads another process's command line, environment or descriptors from /proc, which macOS does not have. */
export const NO_PROC: string | false = existsSync("/proc/self") ? false : "this host has no /proc: the case reads another process's command line, environment or descriptors from it";

/** The skip reason of a case that makes a namespace with the unshare command (util-linux), which macOS does not have. */
export const NO_UNSHARE: string | false = spawnSync("sh", ["-c", "command -v unshare"]).status === 0 ? false : "the unshare command (util-linux) is not on this host";
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

/** The machine type the interpreter reports (what a tool reads with platform.machine()): `x86_64` on an amd64 host, `arm64` or `aarch64` on an Apple Silicon or an arm64 Linux host. */
export const MACHINE: string = spawnSync(PYTHON3, ["-c", "import platform; print(platform.machine().lower())"], { encoding: "utf8" }).stdout.trim();

/**
 * The skip reason of a case that needs the mac_apt recipe to apply: the recipe answers "does not apply here" on an arm64 host (mac_apt 1.33.2 is installed in the amd64 worker image only, its statx helper has
 * no syscall number for aarch64). That is the recipe's own answer; a case that needs the recipe to run mac_apt states what the host holds.
 */
export const NO_MAC_APT: string | false =
  MACHINE === "aarch64" || MACHINE === "arm64" ? "this host is " + MACHINE + ": the macos-triage recipe answers 'does not apply here' (mac_apt is installed in the amd64 worker image only)" : false;

/** The skip reason of a case that keeps two files whose names differ only by case (macOS: the file system folds case, so the second name is the first). */
export const NO_CASE_SENSITIVE_FS: string | false = (() => {
  const dir = mkdtempSync(join(tmpdir(), "case-probe-"));
  try {
    writeFileSync(join(dir, "a"), "x");
    return existsSync(join(dir, "A")) ? "the temporary file system folds case: two names that differ only by case are one file here" : false;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
})();

/** The skip reason of a case that needs a file name that is not UTF-8 (macOS' APFS refuses one with EILSEQ). */
export const NO_RAW_NAMES: string | false = (() => {
  const dir = mkdtempSync(join(tmpdir(), "name-probe-"));
  try {
    writeFileSync(Buffer.concat([Buffer.from(dir + "/"), Buffer.from([0xff, 0xfe, 0x41])]), "x");
    return false;
  } catch {
    return "this file system refuses a name that is not UTF-8 (EILSEQ): the case runs on Linux";
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
})();
