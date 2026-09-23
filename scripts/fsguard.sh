#!/usr/bin/env bash
# fsguard: run a command with directories read-only, or no-exec, at the kernel.
#
# The swarm's inputs/ must be readable by every tool an agent has — Pi's own
# read/write/edit, bash, python, node, a forged tool — and writable by none of
# them. Tool-level checks cover the tools the harness sees; a shell command
# is only detected after the fact. This wrapper closes that gap where the
# host can do it:
#
#   seatbelt  macOS: /usr/bin/sandbox-exec with a profile that allows
#             everything and denies file-write* under each --ro path. Covers
#             create, write, unlink, rename, chmod, chflags, xattr, and the
#             directory itself, for the whole process tree. A --noexec path
#             gets (deny process-exec* (subpath ...)): nothing under it can be
#             started as a program.
#   mountns   Linux: a user + mount namespace. With bubblewrap: the root
#             read-only, --rw paths bound back writable, --ro paths bound
#             read-only, --no-read and --no-socket-tree paths hidden under an
#             empty tmpfs, --no-socket files covered by /dev/null, a fresh
#             /proc in a pid namespace of its own. Without bubblewrap: the
#             same binds and masks from `unshare`, minus the read-only root.
#             Needs unprivileged user namespaces, like netguard's netns mode.
#   landlock  Linux: the Landlock LSM, from scripts/landlock.py, no namespace
#             at all. A write allowlist and a read denial that survive the
#             places user namespaces do not reach — Docker's default seccomp
#             profile, Ubuntu's AppArmor restriction. It cannot seal a socket.
#   linux     Both, layered: the namespace for the masks and the pid tree,
#             Landlock for the allowlist. What `auto` picks on a Linux host
#             that has both.
#   none      Nothing is available: the command runs unguarded and stderr says
#             so. The harness still detects and heals shell writes.
#
# --noexec is for evidence pulled out of an image: a dropped binary is for
# reading, never for running. It stops `./sample.exe` and `bash sample.sh`
# started through exec; an interpreter told to read the file (`python3
# sample.py`) still reads it, so the harness also strips execute bits there.
#
# Usage:
#   --rw is the other direction: with one or more --rw paths the profile denies
#   file-write* everywhere and allows it back only under those paths (plus the
#   devices and the temp directory an ordinary tool needs). It answers "the
#   agent can write anywhere the examiner can", which detection cannot. On
#   Linux it is Landlock, or bubblewrap's read-only root, or both.
#
#   --no-read DIR denies reading a directory and everything under it. Reads
#   are otherwise open, which is deliberate; this is for material about the
#   case itself that the agents must not simply find.
#
#   --no-socket PATH denies connecting to one Unix socket; --no-socket-tree
#   DIR denies every socket under a directory. A control socket in reach of a
#   guarded process is a hole through every other rule, because the process on
#   the other end is not guarded. Neither path has to exist yet. Landlock
#   alone cannot do this (measured); the namespace modes mask the path.
#
#   --in-place keeps the guard in the calling process: no fork, so a pane's
#   shell stays the process its terminal is watching. Costs the pid namespace.
#
#   fsguard.sh [--ro DIR ...] [--rw DIR ...] [--noexec DIR ...]
#              [--no-socket PATH ...] [--no-socket-tree DIR ...]
#              [--no-read DIR ...] [--mode auto|seatbelt|mountns|landlock|linux|none]
#              [--in-place]
#              [--dry-run] -- <command> [args...]
#
# The command sees SWARM_FSGUARD=<mode> in its environment, so a process can
# tell whether it is guarded. Exit code is the command's.
set -euo pipefail

MODE="${SWARM_FSGUARD_MODE:-auto}"
DRY_RUN=0
IN_PLACE=0
RO=()
NOEXEC=()
RW=()
NOSOCK=()
NOSOCKTREE=()
NOREAD=()

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ro) RO+=("$2"); shift 2 ;;
    --rw) RW+=("$2"); shift 2 ;;
    --no-socket) NOSOCK+=("$2"); shift 2 ;;
    --no-socket-tree) NOSOCKTREE+=("$2"); shift 2 ;;
    --no-read) NOREAD+=("$2"); shift 2 ;;
    --noexec) NOEXEC+=("$2"); shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --in-place) IN_PLACE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) echo "fsguard: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ${#RO[@]} -eq 0 && ${#NOEXEC[@]} -eq 0 && ${#RW[@]} -eq 0 && ${#NOSOCK[@]} -eq 0 && ${#NOSOCKTREE[@]} -eq 0 && ${#NOREAD[@]} -eq 0 ]]; then
  echo "fsguard: at least one --ro DIR, --rw DIR, --noexec DIR or --no-socket PATH is required" >&2
  exit 2
fi
if [[ $# -eq 0 && "$DRY_RUN" -eq 0 ]]; then
  echo "fsguard: no command after --" >&2
  exit 2
fi

# Absolute, resolved paths: the kernel matches on what a path really is.
#
# canon_dir <flag> <dir> sets CANON_DIR to the resolved directory, or exits 2
# when it is not one. It sets a global rather than printing so that it is not
# called in $( ), where the exit would only leave the subshell. Call it as a
# bare statement, never in `&&` or `if`, so set -e still covers the cd.
CANON_DIR=""
canon_dir() {
  if [[ ! -d "$2" ]]; then
    echo "fsguard: $1 $2 is not a directory" >&2
    exit 2
  fi
  CANON_DIR="$(cd "$2" && pwd -P)"
}
ABS=()
for dir in ${RO[@]+"${RO[@]}"}; do
  canon_dir --ro "$dir"
  ABS+=("$CANON_DIR")
done
RW_ABS=()
for dir in ${RW[@]+"${RW[@]}"}; do
  canon_dir --rw "$dir"
  RW_ABS+=("$CANON_DIR")
done
NOEXEC_ABS=()
for dir in ${NOEXEC[@]+"${NOEXEC[@]}"}; do
  canon_dir --noexec "$dir"
  NOEXEC_ABS+=("$CANON_DIR")
done

# The canonical form of a path that may not exist yet.
#
# seatbelt matches on the resolved path: a rule written against `/var/...`
# does not stop a connection to the same socket reached as `/private/var/...`
# — measured, and `$TMPDIR` on macOS is exactly that shape. The other lists
# canonicalise with `cd && pwd -P`, which needs the directory to be there.
# A socket that does not exist yet is the ordinary case for a deny, so this
# resolves the deepest part that does exist and keeps the rest verbatim.
canon_maybe() {
  local p="$1" head tail=""
  [[ "$p" != /* ]] && p="$PWD/$p"
  head="$p"
  while [[ ! -d "$head" && "$head" != "/" ]]; do
    tail="/$(basename "$head")$tail"
    head="$(dirname "$head")"
  done
  printf '%s' "$(cd "$head" && pwd -P)$tail"
}

NOSOCK_ABS=()
for dir in ${NOSOCK[@]+"${NOSOCK[@]}"}; do
  NOSOCK_ABS+=("$(canon_maybe "$dir")")
done
NOREAD_ABS=()
for dir in ${NOREAD[@]+"${NOREAD[@]}"}; do
  NOREAD_ABS+=("$(canon_maybe "$dir")")
done
NOSOCKTREE_ABS=()
for dir in ${NOSOCKTREE[@]+"${NOSOCKTREE[@]}"}; do
  NOSOCKTREE_ABS+=("$(canon_maybe "$dir")")
done

seatbelt_supported() {
  [[ "$(uname -s)" == "Darwin" && -x /usr/bin/sandbox-exec ]]
}

mountns_supported() {
  [[ "$(uname -s)" == "Linux" ]] || return 1
  command -v unshare >/dev/null 2>&1 || return 1
  unshare -rm true 2>/dev/null || return 1
  return 0
}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
landlock_supported() {
  [[ "$(uname -s)" == "Linux" ]] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  python3 "$HERE/landlock.py" --dry-run -- true 2>/dev/null | grep -q '^abi: [1-9]'
}

# bubblewrap gives the namespace mode its read-only root. Two probes: whether
# it runs here at all, and whether it may mount a fresh /proc — it may not
# inside a container whose /proc has paths masked over it (Docker), and then
# the pid namespace is skipped rather than the whole guard.
bwrap_supported() {
  command -v bwrap >/dev/null 2>&1 || return 1
  bwrap --unshare-user --ro-bind / / --dev /dev -- true 2>/dev/null
}
bwrap_proc_supported() {
  bwrap --unshare-user --unshare-pid --proc /proc --ro-bind / / --dev /dev -- true 2>/dev/null
}

case "$MODE" in
  auto)
    if seatbelt_supported; then MODE="seatbelt"
    elif mountns_supported && landlock_supported; then MODE="linux"
    elif mountns_supported; then MODE="mountns"
    elif landlock_supported; then MODE="landlock"
    else
      MODE="none"
      echo "fsguard: WARNING no kernel guard on this host (need macOS sandbox-exec, or Linux with unprivileged user namespaces or Landlock); running unguarded" >&2
    fi ;;
  seatbelt) seatbelt_supported || { echo "fsguard: --mode seatbelt needs macOS with /usr/bin/sandbox-exec" >&2; exit 3; } ;;
  mountns) mountns_supported || { echo "fsguard: --mode mountns needs Linux with unprivileged user namespaces (unshare -rm)" >&2; exit 3; } ;;
  landlock) landlock_supported || { echo "fsguard: --mode landlock needs Linux 5.13+ with the Landlock LSM, and python3" >&2; exit 3; } ;;
  linux) mountns_supported && landlock_supported || { echo "fsguard: --mode linux needs both unprivileged user namespaces and Landlock" >&2; exit 3; } ;;
  none) ;;
  *) echo "fsguard: unknown --mode $MODE" >&2; exit 2 ;;
esac

# The Landlock half, as an argument array: the same vocabulary, canonical
# paths, so the two halves of `linux` mode see one set of rules. An array,
# not a `printf %q` string for `eval` to take apart again.
# In `linux` mode a --ro path that lies beneath a --rw path is the mount
# layer's job — a read-only bind on top of the writable one — and is left out
# of the Landlock rules, so the writable root keeps its creation rights. In
# landlock-only mode there is no mount layer and Landlock carves it instead.
LL_ARGS=()
landlock_args() {
  local p r inner
  LL_ARGS=()
  for p in ${RW_ABS[@]+"${RW_ABS[@]}"}; do LL_ARGS+=(--rw "$p"); done
  for p in ${ABS[@]+"${ABS[@]}"}; do
    inner=0
    if [[ "$MODE" == "linux" ]]; then
      for r in ${RW_ABS[@]+"${RW_ABS[@]}"}; do [[ "$p" == "$r"/* ]] && inner=1; done
    fi
    [[ "$inner" -eq 1 ]] || LL_ARGS+=(--ro "$p")
  done
  for p in ${NOEXEC_ABS[@]+"${NOEXEC_ABS[@]}"}; do LL_ARGS+=(--noexec "$p"); done
  for p in ${NOREAD_ABS[@]+"${NOREAD_ABS[@]}"}; do LL_ARGS+=(--no-read "$p"); done
}

# The pane's root reaps its own orphans, so the trace gate's walk up the
# process tree from any process in the pane ends at the pane, never at init.
# Under a pid namespace the namespace's init already does this; the flag
# costs nothing there. It belongs to the pane's exec, not to the rule set.
landlock_exec() {
  landlock_args
  exec python3 "$HERE/landlock.py" ${LL_ARGS[@]+"${LL_ARGS[@]}"} --subreaper -- "$@"
}

# What the namespace half will use, decided once.
#
# --in-place is for a caller that must keep its own pid and its place at the
# head of the terminal's foreground group: the pane hook, where a shell
# re-runs itself under the guard and the terminal multiplexer then starts an
# agent *in that shell*. bubblewrap always forks — it keeps a supervisor
# outside the namespace — so the process the terminal sees is bwrap, not a
# shell, and Herdr refuses to start an agent there ("agent target pane is not
# an available shell", measured on an Ubuntu server). `unshare` without
# --fork execs in place, so the chain stays one pid all the way to the shell.
#
# A pid namespace cannot be had that way: it exists only for a child. So
# --in-place trades the pid namespace (peers' /proc stays visible) for a
# guard the multiplexer can live with. The write allowlist, the read-only
# binds and the masks are unaffected, and the record says what the panes got.
NS_TOOL="none"; NS_PIDNS=0
if [[ "$MODE" == "mountns" || "$MODE" == "linux" ]]; then
  if [[ "$IN_PLACE" -eq 1 ]]; then
    NS_TOOL="unshare"
    NS_PIDNS=0
  elif bwrap_supported; then
    NS_TOOL="bwrap"
    bwrap_proc_supported && NS_PIDNS=1
  else
    NS_TOOL="unshare"
    unshare -rmpf true 2>/dev/null && NS_PIDNS=1
  fi
fi

# Seatbelt profile: allow everything, deny every write operation under the
# paths. `subpath` matches the directory itself and everything below it, so
# the directory cannot be renamed or removed either. file-write* already
# refuses a hard link whose source is under the path (verified on macOS 27);
# the explicit file-link rule says so in the profile and holds on releases
# that split the two. A path with a double quote or a backslash is escaped
# the way the profile language expects.
# Escape a path the way the profile language expects.
sb_quote() {
  local q="${1//\\/\\\\}"
  printf '%s' "${q//\"/\\\"}"
}

# The devices and scratch paths any ordinary tool needs to be able to write.
# Without /dev/null every command containing `2>/dev/null` fails, and without
# the temp directory python's NamedTemporaryFile, git and pip all stop.
SEATBELT_WRITE_ESSENTIALS=(
  "/dev/null" "/dev/zero" "/dev/random" "/dev/urandom" "/dev/tty"
  "/dev/stdout" "/dev/stderr" "/dev/dtracehelper"
)
# Only the file descriptors. The per-user temp area is deliberately NOT here:
# with TMPDIR pointed inside the run (the kickoff does that), python's
# NamedTemporaryFile, git, node, sqlite3 and tar all work with
# /private/var/folders and /tmp closed — measured — and a run that cannot
# write outside itself cannot leave case material outside itself either.
SEATBELT_WRITE_SUBPATHS=("/dev/fd")

seatbelt_profile() {
  printf '(version 1)\n(allow default)\n'
  local p q
  # A write allowlist, when one is asked for. Reads stay open: a deny-default
  # profile cannot even start /bin/echo (measured — SIGABRT before main), and
  # what this is protecting against is a run writing outside itself, not a run
  # reading a manual page. Later rules override earlier ones, so the broad
  # deny comes first and the sandbox's own tree is allowed back afterwards.
  if [[ ${#RW_ABS[@]} -gt 0 ]]; then
    printf '(deny file-write* (subpath "/"))\n'
    for p in ${RW_ABS[@]+"${RW_ABS[@]}"}; do
      q="$(sb_quote "$p")"
      printf '(allow file-write* (subpath "%s"))\n' "$q"
    done
    for p in "${SEATBELT_WRITE_ESSENTIALS[@]}"; do
      printf '(allow file-write* (literal "%s"))\n' "$(sb_quote "$p")"
    done
    for p in "${SEATBELT_WRITE_SUBPATHS[@]}"; do
      [[ -d "$p" ]] || continue
      printf '(allow file-write* (subpath "%s"))\n' "$(sb_quote "$p")"
    done
  fi
  for p in ${ABS[@]+"${ABS[@]}"}; do
    q="$(sb_quote "$p")"
    printf '(deny file-write* (subpath "%s"))\n' "$q"
    printf '(deny file-link (subpath "%s"))\n' "$q"
  done
  for p in ${NOEXEC_ABS[@]+"${NOEXEC_ABS[@]}"}; do
    q="$(sb_quote "$p")"
    printf '(deny process-exec* (subpath "%s"))\n' "$q"
  done
  # A Unix socket the guarded process may not connect to. The write allowlist
  # says nothing about sockets, and a control socket is a way out of every
  # rule above it: whatever answers on the other side runs outside this
  # profile. Connecting needs no write permission, so this is its own rule.
  #
  for p in ${NOSOCK_ABS[@]+"${NOSOCK_ABS[@]}"}; do
    printf '(deny network-outbound (literal "%s"))\n' "$(sb_quote "$p")"
  done
  # A directory denies every socket under it — one rule for a default socket,
  # a client socket and every named session's. Measured: seatbelt honours
  # `subpath` for `network-outbound` on a Unix socket, not only `literal`.
  #
  # Which of the two a path gets is the caller's decision, not the disk's.
  # This used to choose by `-d`, so a socket that did not exist yet — the
  # ordinary case, since Herdr creates it when a session starts — quietly got
  # a `literal` rule that covers nothing under it.
  for p in ${NOSOCKTREE_ABS[@]+"${NOSOCKTREE_ABS[@]}"}; do
    printf '(deny network-outbound (subpath "%s"))\n' "$(sb_quote "$p")"
  done
  # A directory the guarded process may not read.
  #
  # The write allowlist leaves reads open on purpose — a deny-default profile
  # cannot start `/bin/echo` (measured) — so everything on this machine is
  # legible to a pane. That is usually right: an examiner's tools live out
  # there. It is wrong for one thing, and only one: material about the case
  # the agents are working, which they are supposed to derive from the
  # evidence rather than find lying about. A previous run's findings on the
  # same case are exactly that.
  for p in ${NOREAD_ABS[@]+"${NOREAD_ABS[@]}"}; do
    printf '(deny file-read* (subpath "%s"))\n' "$(sb_quote "$p")"
  done
}

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "mode: $MODE"
  for p in ${ABS[@]+"${ABS[@]}"}; do
    echo "read-only: $p"
  done
  for p in ${RW_ABS[@]+"${RW_ABS[@]}"}; do
    echo "writable: $p"
  done
  for p in ${NOEXEC_ABS[@]+"${NOEXEC_ABS[@]}"}; do
    echo "no-exec: $p"
  done
  for p in ${NOSOCK_ABS[@]+"${NOSOCK_ABS[@]}"}; do
    echo "no-socket: $p"
  done
  for p in ${NOSOCKTREE_ABS[@]+"${NOSOCKTREE_ABS[@]}"}; do
    echo "no-socket-tree: $p"
  done
  for p in ${NOREAD_ABS[@]+"${NOREAD_ABS[@]}"}; do
    echo "no-read: $p"
  done
  if [[ "$MODE" == "seatbelt" ]]; then
    echo "profile:"
    seatbelt_profile | sed 's/^/  /'
  fi
  if [[ "$MODE" == "mountns" || "$MODE" == "linux" ]]; then
    echo "namespace: $NS_TOOL"
    echo "pidns: $([[ "$NS_PIDNS" -eq 1 ]] && echo yes || echo no)"
    [[ "$IN_PLACE" -eq 1 ]] && echo "in-place: yes (no fork; the caller keeps its pid, and there is no pid namespace)"
    if [[ ${#RW_ABS[@]} -gt 0 && "$NS_TOOL" != "bwrap" && "$MODE" == "mountns" ]]; then
      echo "note: --rw needs bubblewrap in mountns mode; the write allowlist is NOT applied"
    fi
    if [[ ${#NOEXEC_ABS[@]} -gt 0 && "$NS_TOOL" == "bwrap" && "$MODE" == "mountns" ]]; then
      echo "note: bubblewrap has no noexec bind; --noexec rests on the stripped execute bits"
    fi
  fi
  if [[ "$MODE" == "landlock" || "$MODE" == "linux" ]]; then
    landlock_args
    python3 "$HERE/landlock.py" ${LL_ARGS[@]+"${LL_ARGS[@]}"} --subreaper --dry-run -- true | grep -E '^(abi|rules):' | sed 's/^/landlock /'
    if [[ "$MODE" == "landlock" && ${#NOSOCK_ABS[@]}+${#NOSOCKTREE_ABS[@]} -gt 0 ]]; then
      echo "note: Landlock cannot seal a socket; --no-socket is NOT applied in landlock mode"
    fi
  fi
  if [[ $# -gt 0 ]]; then
    printf 'command:  '; printf ' %q' "$@"; echo
  fi
  exit 0
fi

if [[ ${#RW_ABS[@]} -gt 0 && "$MODE" == "none" ]]; then
  echo "fsguard: WARNING no guard on this host; the write allowlist is NOT applied" >&2
fi

export SWARM_FSGUARD="$MODE"

# The namespace half. Runs the inner command inside a user + mount (+ pid)
# namespace with the binds and masks in place.
#
# bubblewrap first: `--ro-bind / /` is the read-only root that makes `--rw`
# an allowlist, and it sets up the pid namespace and a fresh /proc in the
# same call. Nested user namespaces stay allowed on purpose: netguard makes
# its own network namespace around pi, inside this one. A pane that nests a
# namespace can overlay what it sees under a read-only path (measured); it
# cannot change the bytes, and the sweep outside the pane notices.
#
# Without bubblewrap, `unshare` gives everything but the read-only root: the
# read-only and noexec binds, the tmpfs masks, the pid namespace. In `linux`
# mode Landlock supplies the allowlist either way.
ns_exec() {
  local p
  if [[ "$NS_TOOL" == "bwrap" ]]; then
    local args=(--unshare-user)
    if [[ ${#RW_ABS[@]} -gt 0 ]]; then args+=(--ro-bind / /); else args+=(--bind / /); fi
    # No private /tmp: with a read-only root it is read-only, the way seatbelt
    # leaves it, and the kickoff points TMPDIR inside the run. A tmpfs there
    # would let a pane "write" outside the sandbox into a directory that dies
    # with it, which a test cannot tell from a real escape.
    args+=(--dev /dev)
    [[ "$NS_PIDNS" -eq 1 ]] && args+=(--unshare-pid --proc /proc)
    for p in ${RW_ABS[@]+"${RW_ABS[@]}"}; do args+=(--bind "$p" "$p"); done
    for p in ${ABS[@]+"${ABS[@]}"}; do [[ -e "$p" ]] && args+=(--ro-bind "$p" "$p"); done
    for p in ${NOREAD_ABS[@]+"${NOREAD_ABS[@]}"}; do [[ -d "$p" ]] && args+=(--tmpfs "$p"); done
    for p in ${NOSOCKTREE_ABS[@]+"${NOSOCKTREE_ABS[@]}"}; do [[ -d "$p" ]] && args+=(--tmpfs "$p"); done
    for p in ${NOSOCK_ABS[@]+"${NOSOCK_ABS[@]}"}; do [[ -e "$p" ]] && args+=(--ro-bind /dev/null "$p"); done
    exec bwrap "${args[@]}" -- "$@"
  fi
  FSGUARD_RO_LIST="$(printf '%s\n' ${ABS[@]+"${ABS[@]}"})"
  FSGUARD_NOEXEC_LIST="$(printf '%s\n' ${NOEXEC_ABS[@]+"${NOEXEC_ABS[@]}"})"
  FSGUARD_MASK_LIST="$(printf '%s\n' ${NOREAD_ABS[@]+"${NOREAD_ABS[@]}"} ${NOSOCKTREE_ABS[@]+"${NOSOCKTREE_ABS[@]}"})"
  FSGUARD_SOCK_LIST="$(printf '%s\n' ${NOSOCK_ABS[@]+"${NOSOCK_ABS[@]}"})"
  FSGUARD_UID="$(id -u)"; FSGUARD_GID="$(id -g)"; FSGUARD_PIDNS="$NS_PIDNS"
  export FSGUARD_RO_LIST FSGUARD_NOEXEC_LIST FSGUARD_MASK_LIST FSGUARD_SOCK_LIST FSGUARD_UID FSGUARD_GID FSGUARD_PIDNS
  local flags="-rm"
  [[ "$NS_PIDNS" -eq 1 ]] && flags="-rmpf"
  exec unshare "$flags" -- bash -c '
    set -e
    if [ "$FSGUARD_PIDNS" = 1 ]; then mount -t proc proc /proc 2>/dev/null || true; fi
    while IFS= read -r p; do
      [ -n "$p" ] && [ -e "$p" ] || continue
      mount --bind "$p" "$p" && mount -o remount,bind,ro "$p"
    done <<< "$FSGUARD_RO_LIST"
    while IFS= read -r p; do
      [ -n "$p" ] && [ -e "$p" ] || continue
      mount --bind "$p" "$p" && mount -o remount,bind,noexec "$p"
    done <<< "$FSGUARD_NOEXEC_LIST"
    while IFS= read -r p; do
      [ -n "$p" ] && [ -d "$p" ] || continue
      mount -t tmpfs -o ro,size=1k none "$p"
    done <<< "$FSGUARD_MASK_LIST"
    while IFS= read -r p; do
      [ -n "$p" ] && [ -e "$p" ] || continue
      mount --bind /dev/null "$p"
    done <<< "$FSGUARD_SOCK_LIST"
    exec unshare -U --map-user="$FSGUARD_UID" --map-group="$FSGUARD_GID" -- "$@"
  ' fsguard "$@"
}

case "$MODE" in
  seatbelt)
    profile="$(seatbelt_profile)"
    exec /usr/bin/sandbox-exec -p "$profile" "$@"
    ;;
  mountns)
    if [[ ${#RW_ABS[@]} -gt 0 && "$NS_TOOL" != "bwrap" ]]; then
      echo "fsguard: WARNING --rw needs bubblewrap in mountns mode; the write allowlist is NOT applied" >&2
    fi
    ns_exec "$@"
    ;;
  landlock)
    if [[ ${#NOSOCK_ABS[@]}+${#NOSOCKTREE_ABS[@]} -gt 0 ]]; then
      echo "fsguard: WARNING Landlock cannot seal a socket; --no-socket is NOT applied" >&2
    fi
    landlock_exec "$@"
    ;;
  linux)
    # The namespace outside, Landlock inside it: the masks and the pid tree
    # from the one, the allowlist from the other, and each holds where the
    # other cannot.
    landlock_args
    ns_exec python3 "$HERE/landlock.py" ${LL_ARGS[@]+"${LL_ARGS[@]}"} --subreaper -- "$@"
    ;;
  none)
    exec "$@"
    ;;
esac
