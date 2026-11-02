#!/usr/bin/env bash
# memory-windows: Volatility 3's first pass over one Windows memory image.
#
#   run.sh detect --target TARGET          exit 0 applies, 1 does not, 2 cannot tell (applies: "unknown")
#   run.sh run --target TARGET --out DIR
#
# TARGET is JSON, inline or a file: {"paths": [...], "name": "inputs/x.mem"}.
# detect gates on the name (and file(1) when the name says nothing) before it
# asks Volatility, so a PDF or a pcap never costs a windows.info run, and
# gives offline windows.info RECIPE_PROBE_SECONDS (default 30). run writes
# windows.info.txt and one file per plugin, each step time-boxed
# (RECIPE_STEP_SECONDS, default 900) with its stderr kept whole beside it,
# plus index.tsv, steps.jsonl (one record per step: the command, its exit, how
# long it took and what it wrote) and coverage.json, which a run writes as
# partial before its first step and again after each outcome. A TERM, INT or HUP
# ends the one step running (by the pid it was started with), writes coverage.json
# as partial and interrupted, answers once as JSON and exits 128 plus the signal.
#
# Volatility always runs with --offline: the symbol tables are the ones the
# image holds, and nothing is fetched. An image with no table for the
# kernel stops the run after windows.info, whose output is kept, with the
# kernel named as missing and coverage partial; no plugin that needs symbols
# is run.
#
# When the image holds no symbol table for the kernel, detect and run say so
# with a `missing` entry naming the kernel (PDB, GUID, age, as Volatility's
# automagic asked for it): the census writes it to catalog/missing.json and a
# kickoff stops on it unless --allow-missing-symbols; a generation's post
# says it. A probe that does not answer in time says that whether the image
# holds the table is unknown, the same way: the start does not go on blind.
set -uo pipefail
trap "" XFSZ        # a write past a file-size limit fails with EFBIG and is reported, instead of ending the script with the signal and no answer

have() { command -v "$1" >/dev/null 2>&1; }
TMPF=""        # a temporary file outside the output directory (mktemp), removed when a stop ends the script
final() { trap '' TERM INT HUP; }     # the answer is about to be written: a stop signal from here on changes nothing, or it would add a second document

target_field() {
  python3 - "$1" "$2" <<'PY'
import json, os, sys
arg, field = sys.argv[1], sys.argv[2]
try:
    t = json.load(open(arg, encoding="utf-8")) if os.path.isfile(arg) else json.loads(arg)
except (ValueError, OSError, RecursionError):
    t = None
if not isinstance(t, dict):
    sys.exit(0)        # nothing is printed: the caller answers "the target is not a readable file" as JSON
paths = t.get("paths") or []
if not isinstance(paths, list):
    paths = []
def _ok(v):
    try:
        v.encode("utf-8")
        return True
    except (AttributeError, UnicodeEncodeError):
        return False
paths = [p if _ok(p) else "" for p in paths]      # a lone surrogate or a non-string cannot be printed: it is no path
if not _ok(t.get("name") or ""):
    t["name"] = ""
print((paths[0] if paths else "") if field == "paths0" else (t.get("name") or (paths[0] if paths else "")))
PY
}

looks_like_memory() {
  local img="$1" name magic
  name="$(basename "$img" | tr 'A-Z' 'a-z')"
  case "$name" in
    *.pdf|*.pcap|*.pcapng|*.evtx|*.txt|*.json|*.csv|*.md|*.html|*.htm|*.xml|\
    *.jpg|*.jpeg|*.png|*.gif|*.zip|*.gz|*.xz|*.7z|*.tar|*.doc|*.docx|*.xls|*.xlsx|\
    *.ppt|*.pptx|*.mp3|*.mp4|*.wav|*.log|*.js|*.css|*.e01|*.ex01|*.vmdk|*.vhd|*.vhdx)
      return 1 ;;
    *.mem|*.dmp|*.vmem|*.raw|*.lime|*.crash|*.dump|*.core|hiberfil.sys|pagefile.sys)
      return 0 ;;
  esac
  if have file; then
    magic="$(file -b "$img" 2>/dev/null | tr 'A-Z' 'a-z')"
    case "$magic" in
      *crash*dump*|*hibernation*file*|*memory*dump*) return 0 ;;
    esac
  fi
  return 1
}

# --- a write that can fail is checked, and the answer claims no more than was written --------------------------------------------
# A file-size limit (ulimit -f) or a full disk makes a step's output stop short while the program that wrote it may still exit 0, so the
# exit code alone cannot say that an output is whole. Every file of the run is looked at at the end: one that reached the limit is cut,
# and a run with a cut file is not complete. coverage.json is written whole or not at all, and the answer is built from what this script
# knows, never by reading coverage.json back.
FSIZE_LIMIT_BYTES="$(python3 -c 'import resource; l = resource.getrlimit(resource.RLIMIT_FSIZE)[0]; print(l if l > 0 else 0)' 2>/dev/null || echo 0)"
[[ "$FSIZE_LIMIT_BYTES" =~ ^[0-9]+$ ]] || FSIZE_LIMIT_BYTES=0
WRITE_FAILED=0     # a file of the run could not be written whole
WRITE_REFUSED_SEEN=0   # a step's output was refused by the disk or a size limit (the wrapper said so): nothing then says what the image holds
STEP_REFUSED=0
COV_REQ=""         # the status the last coverage call asked for
COV_TEXT=""        # and what it said it covered
COV_STATUS=""      # the status the coverage file carries (a limit that stopped a step makes a complete one partial)
COV_OK=1           # 0 when coverage.json could not be written whole
cut_by_limit() { # cut_by_limit <file>: the file reached the size limit, so it stopped short
  (( FSIZE_LIMIT_BYTES > 0 )) && [[ -f "$1" ]] && (( $(wc -c < "$1") >= FSIZE_LIMIT_BYTES ))
}
sweep_outputs() { # every file of the run (but coverage.json, which is whole or absent) that reached the size limit is named
  local f rel
  while IFS= read -r f; do
    rel="${f#"$out/"}"
    [[ "$rel" == coverage.json || "$rel" == coverage.json.tmp ]] && continue
    if cut_by_limit "$f"; then
      notes+=("$rel reached the file-size limit (ulimit -f) and stopped short: it is not whole")
      WRITE_FAILED=1
    fi
  done < <(find "$out" -type f 2>/dev/null)
}
disk_probe() { # a full disk cuts a step's output while the program still exits 0: a small write beside the outputs says whether it is still full
  local p="$out/.disk_probe.tmp"
  if ! head -c 4096 /dev/zero > "$p" 2>/dev/null || [[ "$(wc -c < "$p" 2>/dev/null)" != 4096 ]]; then
    notes+=("the disk under the output directory refused a probe write of 4 KiB: files of the run may be cut short, and nothing here can tell which")
    WRITE_FAILED=1
  fi
  rm -f "$p"
}
finish_checks() { # before the answer: look at every file, and say it in the coverage file when one is not whole
  disk_probe
  sweep_outputs
  if (( WRITE_FAILED )); then
    local st="$COV_REQ"
    [[ "$st" == complete ]] && st=partial
    coverage "$st" "$COV_TEXT; a file of the run could not be written whole (see errors)"
  fi
  ANSWER_STATUS="$COV_STATUS"
  if (( ! COV_OK )) && [[ "$ANSWER_STATUS" == complete ]]; then ANSWER_STATUS=partial; fi
}

STEP_TIMEOUT="${RECIPE_STEP_SECONDS:-900}"
PROBE_TIMEOUT="${RECIPE_PROBE_SECONDS:-30}"
[[ "$STEP_TIMEOUT" =~ ^[0-9]+$ && "$PROBE_TIMEOUT" =~ ^[0-9]+$ ]] || { final; echo '{"ok": false, "error": "RECIPE_STEP_SECONDS and RECIPE_PROBE_SECONDS are whole numbers"}'; exit 2; }
out=""
cmd=""
notes=()
stopped_by=""

exec 3>&1     # the real standard output, for the stop answer: the redirections of the step being waited for are still in force when a trap runs
# --- steps and stopping ---------------------------------------------------------------------------------------------------------
# Every step is started in the background and waited for, so that a signal to this script is acted on at once (a trap waits for a
# foreground command to end) and the step to end is known by its pid. perl's alarm then exec makes the command the process itself.
CHILD=""
alive() { # alive <pid>: running, and not a zombie waiting to be reaped
  kill -0 "$1" 2>/dev/null || return 1
  local st
  st="$(sed -n 's/^State:[[:space:]]*\(.\).*/\1/p' "/proc/$1/status" 2>/dev/null)"
  [[ "$st" != Z ]]
}
# The step runs under a small perl wrapper (one process, its own group): it sets the alarm, runs the program with its output on a pipe, and
# copies the pipe to the file with every write checked. A full disk or a file-size limit that cuts the output makes the step exit 74 at that
# moment, whether or not the program noticed, so no later look at the disk is needed. Exit codes are the program's, or 128 + its signal.
STEP_PERL='use POSIX ();
use Fcntl;
use Time::HiRes ();
setpgrp(0, 0);
my $secs = shift @ARGV;
my $mark = $ENV{STEP_MARK};
pipe(my $r, my $w) or exit 70;
my $pid = fork();
exit 70 unless defined $pid;
if (!$pid) {
  close $r;
  open(STDOUT, ">&", $w) or POSIX::_exit(70);
  close $w;
  exec { $ARGV[0] } @ARGV;
  print STDERR "$ARGV[0]: $!\n";
  POSIX::_exit(127);
}
close $w;
sub members {
  my @m;
  if (opendir(my $d, "/proc")) {
    for my $e (readdir $d) {
      next unless $e =~ /^[0-9]+$/;
      next if $e == $$;
      open(my $f, "<", "/proc/$e/stat") or next;
      my $s = <$f>;
      close $f;
      next unless defined $s;
      $s =~ s/^.*\) //;
      my @f = split / /, $s;
      push @m, $e if defined $f[2] && $f[2] == $$;
    }
    closedir $d;
  }
  return @m;
}
sub hit { my $sig = shift; kill $sig, $_ for members(); kill $sig, $pid; }
my ($term_at, $killed, $stopped, $bad, $buf, $status, $eof) = (0, 0, 0, 0, "", 0, 0);
$SIG{TERM} = $SIG{INT} = $SIG{HUP} = sub { $stopped = 1; hit("TERM"); };
my $start = Time::HiRes::time();
sub pump {
  my $n = sysread($r, $buf, 65536);
  if (!defined $n) { return 2 if $!{EINTR} || $!{EAGAIN}; return 0; }
  return 0 if $n == 0;
  return 1 if $bad;
  my $off = 0;
  while ($off < $n) {
    my $k = syswrite(STDOUT, $buf, $n - $off, $off);
    if (!defined $k) { next if $!{EINTR}; $bad = "$!"; hit("TERM"); last; }
    $off += $k;
  }
  return 1;
}
while (1) {
  my $got = waitpid($pid, POSIX::WNOHANG());
  if ($got == $pid) { $status = $?; last; }
  my $now = Time::HiRes::time();
  if (!$term_at && $now - $start >= $secs) { $term_at = $now; hit("TERM"); }
  if ($term_at && !$killed && $now - $term_at >= 2) { $killed = 1; hit("KILL"); }
  if (!$eof) {
    my $rin = "";
    vec($rin, fileno($r), 1) = 1;
    my $n = select(my $rout = $rin, undef, undef, 0.1);
    if ($n > 0) { $eof = 1 if pump() == 0; }
  } else {
    Time::HiRes::sleep(0.05);
  }
}
my $fl = fcntl($r, F_GETFL, 0);
fcntl($r, F_SETFL, $fl | O_NONBLOCK) if defined $fl;
while (pump() == 1) { }
hit("KILL");
if ($bad) {
  if (defined $mark && length $mark) { if (open(my $m, ">", $mark)) { close $m; } }
  print STDERR "the step output could not be written whole ($bad)\n";
  exit 74;
}
exit 142 if $term_at;
exit 143 if $stopped;
exit(($status & 127) ? 128 + ($status & 127) : ($status >> 8));'
bg() { # bg <seconds> <cmd...>: the command with a deadline; its redirections are the caller's
  local secs="$1" rc
  shift
  STEP_REFUSED=0
  rm -f "$STEP_MARK"
  STEP_MARK="$STEP_MARK" perl -e "$STEP_PERL" "$secs" "$@" 3>&- &
  CHILD=$!
  wait "$CHILD"
  rc=$?
  CHILD=""
  if [[ -e "$STEP_MARK" ]]; then                # the wrapper's own word that a write was refused: not an exit code a program can also give
    rm -f "$STEP_MARK"
    STEP_REFUSED=1; WRITE_REFUSED_SEEN=1; WRITE_FAILED=1
    notes+=("the output of ${*:1:3} could not be written whole: the disk or a file-size limit refused a write while the step ran")
  fi
  return "$rc"
}
on_signal() { # on_signal <name> <number>
  local name="$1" num="$2" pids p i
  trap '' TERM INT HUP                  # a second signal while this one is answered changes nothing: the answer is one document
  pids="$CHILD"
  [[ -n "$pids" ]] || pids="$(jobs -p 2>/dev/null)"
  for p in $pids; do kill -TERM "$p" 2>/dev/null; done
  for p in $pids; do
    i=0
    while (( i < 30 )) && alive "$p"; do sleep 0.1; i=$((i + 1)); done
    kill -KILL -- "-$p" 2>/dev/null          # the step's own process group: the program is the wrapper's child
    if alive "$p"; then kill -KILL "$p" 2>/dev/null; fi
    wait "$p" 2>/dev/null
  done
  if [[ -n "$TMPF" ]]; then rm -f "$TMPF" "$TMPF.stderr"; fi         # the probe's temporary file, if one was being written
  if [[ -n "${out:-}" ]]; then rm -f "$out/.fsstat.tmp"; fi          # the hidden file the file-system probe was writing
  if [[ "$cmd" == run && -n "$out" && -d "$out" ]]; then
    stopped_by="SIG$name"
    notes+=("stopped by SIG$name: the step that was running was ended and the steps after it were not run")
    coverage partial "interrupted by SIG$name: what was written before it is kept, and the steps after it were not run"
    echo "{\"ok\": false, \"status\": \"partial\", \"interrupted\": true, \"signal\": \"SIG$name\"}" >&3
  elif [[ "$cmd" == detect ]]; then
    echo "{\"applies\": false, \"interrupted\": true, \"signal\": \"SIG$name\", \"why\": \"the probe was stopped by SIG$name before it could tell\"}" >&3
  else
    echo "{\"ok\": false, \"interrupted\": true, \"signal\": \"SIG$name\"}" >&3
  fi
  exit $((128 + num))
}
trap 'on_signal TERM 15' TERM
trap 'on_signal INT 2' INT
trap 'on_signal HUP 1' HUP

# step_record <outfile> <exit> <seconds> <limit> <cmd...>: one line of
# steps.jsonl per step, written whatever the step's outcome was.
step_record() {
  python3 - "$out" "$@" <<'PY'
import json, os, sys
out, file, rc, seconds, limit, *argv = sys.argv[1:]
rel = os.path.relpath(file, out)
rec = {"step": rel, "argv": argv, "exit": int(rc), "seconds": int(seconds), "limit_seconds": int(limit),
       "timed_out": int(rc) == 142}
for key, path in (("output", file), ("stderr", file + ".stderr")):
    if os.path.isfile(path):
        rec[key] = {"file": os.path.relpath(path, out), "bytes": os.path.getsize(path)}
try:
    with open(os.path.join(out, "steps.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
except OSError as exc:              # a full disk or a file-size limit: said on stderr in a word, and the run goes on
    sys.stderr.write("steps.jsonl could not be written: %s\n" % (exc.strerror or exc.__class__.__name__))
PY
}

# Sets STEP_R to "ok" or a reason naming the stderr file (not printed: a command substitution would be a foreground step the stop
# handling cannot see).
STEP_R=""
run_step() { # run_step <limit> <outfile> <cmd...>
  local limit="$1" file="$2"; shift 2
  local rc=0 began="$SECONDS"
  bg "$limit" "$@" > "$file" 2> "$file.stderr" || rc=$?
  [[ -s "$file.stderr" ]] || rm -f "$file.stderr"
  if [[ "$rc" -ne 0 ]]; then [[ -s "$file" ]] || rm -f "$file"; fi
  step_record "$file" "$rc" "$((SECONDS - began))" "$limit" "$@"
  if [[ "$rc" -eq 0 ]]; then STEP_R=ok; return 0; fi
  local err=""
  if [[ -f "$file.stderr" ]]; then
    err="$(head -c 200 "$file.stderr" | tr '\n' ' ')"
    err="$err; all of stderr: ${file#"$out/"}.stderr"
  fi
  STEP_R="failed (exit $rc${err:+: $err})"
  if (( STEP_REFUSED )); then STEP_R="its output could not be written whole (the disk or a file-size limit refused a write)"; fi
}

index_row() {
  [[ -f "$out/$1" ]] || return 0
  if ! printf '%s\t%s\n' "$1" "$2" >> "$out/index.tsv" 2>/dev/null; then
    WRITE_FAILED=1
    notes+=("index.tsv could not be written whole")
  fi
  return 0
}

# kernel_missing <stdout> <stderr> <shown> [timeout seconds]: the `missing`
# list (JSON) for an image whose kernel table this image lacks, the kernel
# named from the symbol-server address Volatility asked for offline; with a
# timeout, that it is unknown whether the image holds it.
kernel_missing() {
  python3 - "$@" <<'PY'
import json, re, sys
out, err, shown = sys.argv[1:4]
timeout = sys.argv[4] if len(sys.argv) > 4 else ""
# What Volatility's automagic asked for is in its log. A log can be large, so it
# is read in blocks, up to a budget, with a carry so a name cut by a block's end
# is still found; the first match ends the search.
BUDGET = 16 * 1024 * 1024
BLOCK = 1 << 20
CARRY = 512
rx = re.compile(r"/download/symbols/([A-Za-z0-9_.-]+\.pdb)/([0-9A-Fa-f]{32})([0-9A-Fa-f]{1,8})/")
m, spent = None, 0
for f in (err, out):
    tail = ""
    try:
        with open(f, encoding="utf-8", errors="replace") as fh:
            while not m and spent <= BUDGET:
                block = fh.read(BLOCK)
                if not block:
                    break
                spent += len(block)
                text = tail + block
                m = rx.search(text)
                tail = text[-CARRY:]
    except OSError:
        pass
    if m or spent > BUDGET:
        break
if timeout:
    print(json.dumps([{"kind": "symbols", "what": f"vol --offline windows.info did not answer within {timeout}s on {shown}: whether this image holds the symbol table of its kernel is unknown, so what reads it may find nothing (raise RECIPE_PROBE_SECONDS, or SWARM_CATALOG_MEMORY_PROBE_TIMEOUT)"}]))
elif m:
    pdb, guid, age = m.group(1), m.group(2).upper(), int(m.group(3), 16)
    print(json.dumps([{"kind": "symbols", "identity": {"pdb": pdb, "guid": guid, "age": age},
                       "what": f"the symbol table of the Windows kernel {pdb} {guid} age {age}, which {shown} runs: this image does not hold it, so its Windows plugins cannot read it offline (what needs no kernel table still works: strings, YARA, carving)"}]))
else:
    print(json.dumps([{"kind": "symbols", "what": f"the symbol table of the Windows kernel {shown} runs: this image does not hold it, and the kernel's identity was not named" + (" (the log was read up to a budget of %d bytes)" % BUDGET if spent > BUDGET else "")}]))
PY
}

_coverage_write() {
  STOPPED_BY="$stopped_by" python3 - "$out/coverage.json" "$1" "$2" "${missing_json:-[]}" "${notes[@]+"${notes[@]}"}" <<'PY'
import json, os, sys
path, status, covered, missing, *notes = sys.argv[1:]
steps = []
try:
    with open(os.path.join(os.path.dirname(path), "steps.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                try:
                    steps.append(json.loads(line))
                except ValueError:          # a record cut short by a full disk or a file-size limit is skipped, not a traceback
                    pass
except OSError:
    pass
doc = {"recipe": "memory-windows", "status": status, "status_basis": covered, "covered": covered,
       "not_covered": "every other Volatility plugin; YARA without supplied rules; non-Windows images; unsupported hibernation or crash-dump variants",
       "missing": json.loads(missing),
       "limits_hit": [note for note in notes if "exit 142" in note],
       "errors": notes,
       "steps": steps}
if os.environ.get("STOPPED_BY"):
    doc["interrupted"] = True
    doc["signal"] = os.environ["STOPPED_BY"]
tmp = path + ".tmp"
try:
    with open(tmp, "w") as fh:
        json.dump(doc, fh, indent=2)
    os.replace(tmp, path)               # whole or not at all: an earlier coverage file stands when this one cannot be written
except OSError as exc:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    # An earlier coverage file must not stand and say more than this run did: a short one that says so takes its place, or none stays.
    short = {"recipe": doc["recipe"], "status": "partial", "status_basis": "the full coverage file could not be written (%s)" % (exc.strerror or exc.__class__.__name__)}
    try:
        with open(tmp, "w") as fh:
            json.dump(short, fh)
        os.replace(tmp, path)
    except OSError:
        for leftover in (tmp, path):
            try:
                os.unlink(leftover)
            except OSError:
                pass
    sys.stderr.write("coverage.json could not be written: %s\n" % (exc.strerror or exc.__class__.__name__))
    sys.exit(1)
PY
}

coverage() { # coverage <status> <covered>: the coverage file, whole or not at all; the status and the outcome are kept for the answer
  COV_REQ="$1"; COV_TEXT="$2"; COV_STATUS="$1"
  if _coverage_write "$1" "$2"; then COV_OK=1; else COV_OK=0; fi
}

cmd="${1:-}"; shift || true
target=""
probe_out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target|--out|--probe-out)
      # A flag with no value is an error, not a loop: `shift 2` with one word left shifts nothing.
      [[ $# -ge 2 ]] || { echo "{\"ok\": false, \"error\": \"$1 needs a value\"}"; exit 2; }
      case "$1" in --target) target="$2" ;; --out) out="$2" ;; --probe-out) probe_out="$2" ;; esac
      shift 2 ;;
    *) final; echo '{"ok": false, "error": "unknown argument"}'; exit 2 ;;
  esac
done
[[ -n "$target" ]] || { final; echo '{"ok": false, "error": "--target is required"}'; exit 2; }
img="$(target_field "$target" paths0)"
shown="$(target_field "$target" name)"
[[ -n "$img" && -f "$img" ]] || { final; echo '{"applies": "unknown", "why": "the target is not a regular file, so it cannot be told what it is", "ok": false, "error": "the target is not a readable file"}'; exit 2; }

# perl runs every step (its clock, its process group, its checked writer), so it must be here; the marker file is the wrapper's word that a
# write was refused, in a directory of its own that goes with the script.
if ! have perl; then
  final
  if [[ "$cmd" == detect ]]; then
    echo '{"applies": "unknown", "why": "perl is not installed: every step of this recipe runs under a perl wrapper that bounds its time and checks its output, so nothing was asked of the image"}'
  else
    echo '{"ok": false, "status": "failed", "error": "perl is not installed", "status_basis": "every step of this recipe runs under a perl wrapper that bounds its time and checks its output, so nothing was run and nothing is said about the image"}'
  fi
  exit 2
fi
STEP_MARK_DIR="$(mktemp -d 2>/dev/null)" || { final; echo '{"ok": false, "status": "failed", "applies": "unknown", "error": "no temporary directory could be made", "status_basis": "nothing was run and nothing is said about the image"}'; exit 2; }
STEP_MARK="$STEP_MARK_DIR/refused"
trap 'rm -rf "$STEP_MARK_DIR"' EXIT

case "$cmd" in
  detect)
    looks_like_memory "$img" || { final; echo '{"applies": false, "why": "not memory by its name or file(1)"}'; exit 1; }
    have vol || { final; echo '{"applies": "unknown", "why": "looks like memory, but vol is not in this image"}'; exit 2; }
    # What vol says about a file it does not recognise is kept, when the
    # caller gives a place for it (--probe-out), not thrown away.
    if [[ -n "$probe_out" ]]; then mkdir -p "$probe_out"; probe="$probe_out/windows.info.txt"; else probe="$(mktemp)"; TMPF="$probe"; fi
    rc=0
    bg "$PROBE_TIMEOUT" vol --offline -vv -q -f "$img" windows.info > "$probe" 2> "$probe.stderr" || rc=$?
    [[ -s "$probe.stderr" ]] || rm -f "$probe.stderr"
    if [[ "$rc" -eq 0 ]] && grep -qi "NTBuildLab\|Kernel Base\|SystemTime" "$probe"; then
      rm -f "$probe" "$probe.stderr"; final; echo '{"applies": true, "why": "Volatility windows.info names a Windows image"}'; exit 0
    fi
    # Volatility can identify and stack a Windows layer before discovering
    # that the exact offline symbol table is absent. That is applicable-but-
    # blocked, not "not Windows"; keep both probe files for diagnosis.
    if { [[ -f "$probe.stderr" ]] && grep -qi "DTB was found" "$probe.stderr" && grep -qi "symbol_table_name" "$probe" "$probe.stderr" 2>/dev/null; } || \
       grep -qs '/download/symbols/.*\.pdb/' "$probe.stderr"; then
      miss="$(kernel_missing "$probe" "$probe.stderr" "$shown")"
      [[ -n "$probe_out" ]] || rm -f "$probe" "$probe.stderr"
      final; python3 -c 'import json, sys; print(json.dumps({"applies": True, "why": "Volatility recognized Windows memory, but the matching offline symbol table is absent; run will fail until the image supplies it", "missing": json.loads(sys.argv[1])}))' "$miss"
      exit 0
    fi
    if [[ "$rc" -eq 142 ]]; then
      # Not a pass: whether the image holds the kernel's table is unknown,
      # and the start says so rather than going on blind.
      miss="$(kernel_missing "$probe" "$probe.stderr" "$shown" "$PROBE_TIMEOUT")"
      [[ -s "$probe" ]] || rm -f "$probe"
      [[ -n "$probe_out" ]] || rm -f "$probe" "$probe.stderr"
      final; python3 -c 'import json, sys; print(json.dumps({"applies": "unknown", "why": "offered to Volatility as memory; windows.info did not answer within %ss" % sys.argv[2], "missing": json.loads(sys.argv[1])}))' "$miss" "$PROBE_TIMEOUT"
      exit 2
    fi
    [[ -s "$probe" ]] || rm -f "$probe"
    [[ -n "$probe_out" ]] || rm -f "$probe" "$probe.stderr"
    if (( WRITE_REFUSED_SEEN )); then
      final; echo '{"applies": "unknown", "why": "a write was refused (a file-size limit or a full disk) while windows.info ran, so it cannot be told what the image holds"}'; exit 2
    fi
    final; echo '{"applies": false, "why": "offered to Volatility as memory; windows.info named no Windows memory image"}'; exit 1
    ;;
  run)
    [[ -n "$out" ]] || { final; echo '{"ok": false, "error": "run needs --out DIR"}'; exit 2; }
    mkdir -p "$out" 2>/dev/null && [[ -d "$out" && -w "$out" ]] || { final; echo '{"ok": false, "status": "failed", "error": "--out cannot be used: it is not a directory that can be made and written", "status_basis": "the output directory could not be made, so nothing was run"}'; exit 2; }
    : > "$out/index.tsv"; : > "$out/steps.jsonl"
    # Said before the first step, so a run stopped anywhere leaves a coverage
    # file that says it did not finish.
    coverage partial "started; no step has finished (the run stopped before its end)"
    # Volatility reads the symbol tables the image holds, and fetches nothing:
    # every step runs with --offline. An image with no table for its kernel stops
    # the run after windows.info, whose output is kept, with the kernel named.
    symbols="held in the image"
    VOLNET=(--offline)
    run_step "$STEP_TIMEOUT" "$out/windows.info.txt" vol --offline -q -f "$img" windows.info; r="$STEP_R"
    index_row "windows.info.txt" "OS, build, capture time of $shown (vol --offline windows.info)"
    index_row "windows.info.txt.stderr" "what vol --offline windows.info said on stderr"
    index_row "steps.jsonl" "one record per step: the command, its exit, how long it took and what it wrote"
    if [[ "$r" != ok ]] || ! grep -qi "NTBuildLab\|Kernel Base\|SystemTime" "$out/windows.info.txt" 2>/dev/null; then
      if grep -qi "symbol" "$out/windows.info.txt" "$out/windows.info.txt.stderr" 2>/dev/null; then
        # The image lacks the table: said in coverage (missing), and no plugin that
        # reads kernel structures is run, since none would find them.
        missing_json="$(kernel_missing "$out/windows.info.txt" "$out/windows.info.txt.stderr" "$shown")"
        notes+=("vol --offline windows.info on $shown: no symbol table for this kernel in the image; it was not fetched, and the plugins that need it were not run")
        coverage partial "windows.info was attempted offline; no symbol table for this kernel in the image, so no Windows plugin was run"
        finish_checks
        final; python3 -c 'import json,sys; d = {"ok": True, "status": sys.argv[1], "missing": json.loads(sys.argv[2])}
if sys.argv[3] != "1":
    d["coverage_error"] = "coverage.json could not be written whole: the earlier one, if any, stands"
print(json.dumps(d))' "$ANSWER_STATUS" "${missing_json:-[]}" "$COV_OK"
        exit 0
      fi
      if [[ "$r" == ok ]]; then why="ran but named no Windows image"; else why="$r"; fi
      notes+=("vol windows.info on $shown: $why")
      coverage failed "nothing"
      final; echo '{"ok": false, "status": "failed"}'
      exit 2
    fi
    finished=0
    coverage partial "windows.info finished; no plugin has yet (this file is rewritten after each step, so a run stopped part way says how far it got)"
    for plugin in pslist psscan pstree cmdline netscan malfind vadinfo handles modules svcscan dlllist; do
      run_step "$STEP_TIMEOUT" "$out/$plugin.txt" vol ${VOLNET[@]+"${VOLNET[@]}"} -q -f "$img" "windows.$plugin"; r="$STEP_R"
      [[ "$r" == ok ]] || notes+=("vol windows.$plugin on $shown: $r")
      index_row "$plugin.txt" "vol windows.$plugin over $shown"
      finished=$((finished + 1))
      coverage partial "windows.info and $finished of eleven plugins have finished; the run did not reach its end (this file is rewritten after each step)"
    done
    while IFS= read -r f; do
      rel="${f#"$out/"}"; [[ "$rel" == windows.info.txt.stderr ]] || index_row "$rel" "what the step writing ${rel%.stderr} said on stderr"
    done < <(find "$out" -type f -name '*.stderr' | sort)
    if [[ ${#notes[@]} -gt 0 ]]; then coverage partial "windows.info and the plugins that finished; symbols $symbols"; else coverage complete "windows.info and eleven plugins; symbols $symbols"; fi
    finish_checks
    final; python3 -c 'import json,sys; d = {"ok": True, "status": sys.argv[1]}
if sys.argv[2] != "1":
    d["coverage_error"] = "coverage.json could not be written whole: the earlier one, if any, stands"
print(json.dumps(d))' "$ANSWER_STATUS" "$COV_OK"
    ;;
  *) final; echo '{"applies": "unknown", "why": "a usage error, so nothing was asked", "ok": false, "error": "usage: run.sh detect --target T | run --target T --out DIR"}'; exit 2 ;;
esac
