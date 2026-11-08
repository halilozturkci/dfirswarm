#!/usr/bin/env bash
# disk-volumes: The Sleuth Kit's first pass over one disk image.
#
#   run.sh detect --target TARGET          exit 0 applies, 1 does not, 2 cannot tell (applies: "unknown")
#   run.sh run --target TARGET --out DIR
#
# TARGET is JSON, inline or a file: {"paths": [...], "name": "inputs/x.E01"};
# the image is paths[0] (a segment set's first segment: libewf reads the rest).
# Or {"descriptor": "<layer-<sha256>.json>"} (optionally descriptor_sha256 and verify_sources): a layer descriptor from layer_describe stands
# for the image. It is read whole and checked first (its bytes must hash to its name, it must list no missing dependency, and its sources must still be
# what it records); its sources go to the Sleuth Kit in order and its sector size is passed as -b when it is not 512. descriptor.json keeps what was read.
# With a partition table (`mmls`): partitions.txt and, per filesystem
# partition, p<start>/{fsstat.txt, bodyfile.txt, filelist.txt, timeline.csv}.
# With none but a filesystem at sector 0 (`fsstat`): the same under p0. Each
# step is time-boxed (RECIPE_STEP_SECONDS, default 900, and never more than the
# recipe's own clock has left: RECIPE_SECONDS, default 14400 as recipe.json's
# limits.seconds, less a margin of a twentieth, at most 60 seconds). A step that
# the clock leaves no time for is not started, and coverage.json names it in
# limits_hit. A step keeps what it wrote
# to stderr whole beside its output as <file>.stderr. A TERM, INT or HUP ends
# the one step running (by the pid it was started with), writes coverage.json as
# partial and interrupted, answers once as JSON and exits 128 plus the signal.
# index.tsv lists what was
# written (file, what) and coverage.json what was and was not covered, with an
# inventory of every allocated partition entry and what became of it: read
# (fsstat read a file system there), failed (it was tried and fsstat or a step
# did not finish), unsupported (a layer TSK does not read, an LVM or RAID member)
# or structural (a container or a partition that holds no file system by
# definition: an extended partition, swap, a Microsoft reserved or a BIOS boot
# partition). complete means nothing was failed or unsupported. A partition name is the evidence's own text (mmls prints a GPT name raw), so a
# row of the table is taken only as mmls writes one, in sequence, and its start sector only as digits: a line that is not a row is a note in
# coverage.json, never a partition or a directory name. coverage.json is
# written as partial before the first step, and the body file's times are read as
# UTC (mactime -z UTC), which is the zone its timeline.csv says.
set -uo pipefail
trap "" XFSZ        # a write past a file-size limit fails with EFBIG and is reported, instead of ending the script with the signal and no answer

have() { command -v "$1" >/dev/null 2>&1; }
TMPF=""        # a temporary file outside the output directory (mktemp), removed when a stop ends the script
final() { trap '' TERM INT HUP; }     # the answer is about to be written: a stop signal from here on changes nothing, or it would add a second document

target_field() { # target_field <json or file> <paths0|name>
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
if field == "paths0":
    print(paths[0] if paths else "")
elif field in ("descriptor", "descriptor_sha256", "verify_sources"):
    v = t.get(field)
    print("" if v is None else ("true" if v is True else str(v)) if _ok(str(v)) else "")
else:
    print(t.get("name") or (paths[0] if paths else ""))
PY
}

# descriptor_load <ref> <pin> <verify>: a layer descriptor read and checked the way image_layout, icat_extract and chunk_needles read it (copied text).
# It writes one JSON document on stdout: the descriptor's file, sha256, layer, sector_size, images (the paths the Sleuth Kit is given, in order) and
# checked; or {"error": ...}. The message never quotes a path from the descriptor.
descriptor_load() {
  python3 - "$1" "$2" "$3" "${4:-}" <<'PY'
import json, os, sys, time
# ---- the descriptor (layer_describe's file), read the same way in image_layout, icat_extract, chunk_needles and byte_range_extract -----
DESCRIPTOR_MAX = 16 * 1024 * 1024
DESCRIPTOR_VERIFY_SECONDS = 120          # the clock for verify_sources (a descriptor is checked before the program runs)
DESCRIPTOR_LAYERS = ("raw", "split_raw", "ewf", "vmdk", "vhd", "vhdx", "qcow", "aff")


class DescriptorError(Exception):
    """The descriptor cannot be used. The message never quotes a path or text from the descriptor."""


def load_descriptor(ref, pin=None, verify_sources=False, deadline=None):
    """Read a layer descriptor and check it before anything is run on what it names. A dict: file, sha256, sector_size, unit, layer, images
    (the paths a Sleuth Kit program is given, in order), sources, media_bytes, volumes (the allocated slots fsstat read: offset_sectors,
    offset_bytes, fs_type) and checked ("sizes" or "sha256"). It is refused when its bytes do not hash to the name it carries (layer-<sha256>.json),
    when it is not the shape layer_describe writes, when it lists a dependency that is not declared, when a source is no longer a regular file of
    the size it records, or when a volume's offset is not inside the media. A source swapped for another of the same size is NOT found unless
    verify_sources is true, which reads every source again and compares its sha256."""
    import hashlib as _hashlib
    import re as _re
    import stat as _stat
    if not isinstance(ref, str) or not ref or "\\0" in ref:
        raise DescriptorError("descriptor is a path to a layer descriptor file")
    if pin is not None and (not isinstance(pin, str) or not _re.fullmatch(r"[0-9a-f]{64}", pin)):
        raise DescriptorError("descriptor_sha256 is 64 lower-case hexadecimal digits")
    try:
        fd = os.open(ref, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise DescriptorError("the descriptor cannot be opened: %s" % (exc.strerror or exc.__class__.__name__))
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            raise DescriptorError("the descriptor is not a regular file")
        if st.st_size > DESCRIPTOR_MAX:
            raise DescriptorError("the descriptor is larger than %d bytes" % DESCRIPTOR_MAX)
        data = b""
        while len(data) <= DESCRIPTOR_MAX:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            data += block
    except OSError as exc:
        raise DescriptorError("the descriptor cannot be read: %s" % (exc.strerror or exc.__class__.__name__))
    finally:
        os.close(fd)
    if len(data) > DESCRIPTOR_MAX:
        raise DescriptorError("the descriptor is larger than %d bytes" % DESCRIPTOR_MAX)
    sha = _hashlib.sha256(data).hexdigest()
    name = os.path.basename(ref)
    if name != "layer-%s.json" % sha:
        raise DescriptorError("the descriptor's bytes do not hash to the name it carries (layer-<sha256>.json): it was changed, renamed, or is not a descriptor layer_describe wrote")
    if pin is not None and pin != sha:
        raise DescriptorError("the descriptor's sha256 is not the one descriptor_sha256 pins")
    try:
        doc = json.loads(data.decode("ascii"))
    except (ValueError, RecursionError):
        raise DescriptorError("the descriptor is not JSON")
    if not isinstance(doc, dict) or doc.get("kind") != "layer_descriptor" or doc.get("descriptor_version") != 1:
        raise DescriptorError("the descriptor is not a layer descriptor of version 1")
    if doc.get("status") not in ("complete", "partial"):
        raise DescriptorError("the descriptor's status is not complete or partial")
    size = doc.get("sector_size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 512 or size > 65536 or size % 512:
        raise DescriptorError("the descriptor's sector_size is not a multiple of 512 from 512 to 65536")
    if doc.get("missing_dependencies"):
        raise DescriptorError("the descriptor lists a dependency that is not declared (missing_dependencies): the set is not whole")
    layer = (doc.get("container") or {}).get("layer") if isinstance(doc.get("container"), dict) else None
    if layer not in DESCRIPTOR_LAYERS:
        raise DescriptorError("the descriptor's container layer is not one this tool knows")
    sources = doc.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 10000:
        raise DescriptorError("the descriptor lists no sources, or too many")
    for i, s in enumerate(sources):
        if not isinstance(s, dict) or s.get("index") != i or not isinstance(s.get("path"), str) or not s["path"] or "\\0" in s["path"]:
            raise DescriptorError("source %d of the descriptor is malformed" % i)
        if not isinstance(s.get("bytes"), int) or isinstance(s.get("bytes"), bool) or s["bytes"] < 0:
            raise DescriptorError("source %d of the descriptor has no size" % i)
        if s.get("sha256") is not None and not (isinstance(s["sha256"], str) and _re.fullmatch(r"[0-9a-f]{64}", s["sha256"])):
            raise DescriptorError("source %d of the descriptor has a malformed sha256" % i)
    used = sources if layer in ("raw", "split_raw", "ewf") else sources[:1]
    checked = "sizes"
    for s in used:
        try:
            fd = os.open(s["path"], os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            raise DescriptorError("source %d can no longer be opened: %s" % (s["index"], exc.strerror or exc.__class__.__name__))
        try:
            st = os.fstat(fd)
            if not _stat.S_ISREG(st.st_mode):
                raise DescriptorError("source %d is no longer a regular file" % s["index"])
            if st.st_size != s["bytes"]:
                raise DescriptorError("source %d is %d bytes, the descriptor says %d: it changed after the descriptor was made" % (s["index"], st.st_size, s["bytes"]))
            if verify_sources:
                if s.get("sha256") is None:
                    raise DescriptorError("source %d has no sha256 in the descriptor, so verify_sources cannot check it" % s["index"])
                h = _hashlib.sha256()
                while True:
                    block = os.read(fd, 1 << 20)
                    if not block:
                        break
                    h.update(block)
                    if deadline is not None and time.monotonic() > deadline:
                        raise DescriptorError("the time budget ran out while source %d was being verified" % s["index"])
                if h.hexdigest() != s["sha256"]:
                    raise DescriptorError("source %d no longer hashes to the sha256 the descriptor records" % s["index"])
                checked = "sha256"
        except OSError as exc:
            raise DescriptorError("source %d cannot be read: %s" % (s["index"], exc.strerror or exc.__class__.__name__))
        finally:
            os.close(fd)
    media = doc.get("media") if isinstance(doc.get("media"), dict) else {}
    media_bytes = media.get("bytes") if isinstance(media.get("bytes"), int) and not isinstance(media.get("bytes"), bool) else None
    unit = doc.get("partition_unit") if isinstance(doc.get("partition_unit"), int) and not isinstance(doc.get("partition_unit"), bool) else size
    volumes = []
    for p in doc.get("partitions") if isinstance(doc.get("partitions"), list) else []:
        fs = p.get("filesystem") if isinstance(p, dict) else None
        if not isinstance(fs, dict) or fs.get("readable") is not True:
            continue
        sectors, byte_offset = p.get("offset_sectors"), p.get("offset_bytes")
        if not isinstance(sectors, int) or isinstance(sectors, bool) or sectors < 0 or not isinstance(byte_offset, int) or byte_offset != sectors * unit:
            raise DescriptorError("a volume of the descriptor has an offset that is not its sector offset times the sector size")
        if media_bytes is not None and byte_offset >= media_bytes:
            raise DescriptorError("a volume of the descriptor starts at byte %d, past the end of the %d-byte media" % (byte_offset, media_bytes))
        volumes.append({"offset_sectors": sectors, "offset_bytes": byte_offset, "fs_type": fs.get("fs_type") if isinstance(fs.get("fs_type"), str) else None})
    return {"file": name, "sha256": sha, "sector_size": size, "unit": unit, "layer": layer, "images": [s["path"] for s in used], "sources": sources,
            "media_bytes": media_bytes, "volumes": volumes, "checked": checked, "status": doc["status"]}


def descriptor_offset(desc, given):
    """The volume offset in sectors a tool uses with a descriptor: the one the caller names, which must be a volume of the descriptor; else the only volume."""
    starts = [v["offset_sectors"] for v in desc["volumes"]]
    if given is not None:
        if given not in starts:
            raise DescriptorError("offset %s is not a volume of the descriptor (its volumes start at sectors %s)" % (given, ", ".join(str(s) for s in starts) or "none"))
        return given
    if len(starts) == 1:
        return starts[0]
    raise DescriptorError(("the descriptor has no volume fsstat read" if not starts else "the descriptor has several volumes; pass offset= (a start sector)") +
                          ((": " + ", ".join(str(s) for s in starts)) if starts else ""))

try:
    d = load_descriptor(sys.argv[1], sys.argv[2] or None, sys.argv[3] == "true", time.monotonic() + min(DESCRIPTOR_VERIFY_SECONDS, int(sys.argv[4]) if sys.argv[4].isdigit() else DESCRIPTOR_VERIFY_SECONDS))
    print(json.dumps({"file": d["file"], "sha256": d["sha256"], "layer": d["layer"], "sector_size": d["sector_size"], "images": d["images"], "checked": d["checked"]}))
except DescriptorError as exc:
    print(json.dumps({"error": str(exc)}))
PY
}
desc_get() { # desc_get <json file> <key|image N>
  python3 - "$1" "$2" "${3:-}" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
key = sys.argv[2]
if key == "image":
    print(d["images"][int(sys.argv[3])])
elif key == "images":
    print(len(d["images"]))
else:
    print(d.get(key, ""))
PY
}

# table_rows <partitions.txt>: the rows of mmls's table that are partition entries, one "ROW<TAB>start<TAB>description"
# each, and one "NOTE<TAB>text" for every line after the header that is not a row, or is a row out of sequence. mmls
# prints a GPT partition name raw, so a name holding a line break can put a second, forged "row" in the table: a row is
# taken only when it has the shape mmls writes (a slot, a table column and three runs of ten or more ASCII digits: mmls
# prints them %.10, and a name of 36 UTF-16 units, or a Mac name of 32 bytes, cannot hold a line that long), the number
# the table is at and an end and a length that agree with the start, and the start sector is the digits of the third
# column and nothing else. A description has its control characters replaced.
table_rows() {
  python3 - "$1" <<'PY'
import re, sys
sys.stdout.reconfigure(encoding="utf-8")
row = re.compile(r"^([0-9]{3,}):[ \t]+(Meta|-+|[0-9]{3,}(?::[0-9]{3,})?)[ \t]+([0-9]{10,})[ \t]+([0-9]{10,})[ \t]+([0-9]{10,})[ \t]+(\S.*)$")
ctl = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")
raw = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
expect, header = 0, False
for no, line in enumerate(raw.split("\n"), 1):
    line = line.rstrip("\r")
    if not header:
        if "Slot" in line and "Start" in line and "Description" in line:
            header = True
            continue
        if not row.match(line):
            continue
    if not line.strip():
        continue
    m = row.match(line)
    if not m or int(m.group(1)) != expect:
        why = "is not a row of the table" if not m else "is row %d where row %d was due" % (int(m.group(1)), expect)
        print("NOTE\tline %d of partitions.txt %s (a partition name holding a line break would do this): it is not read as a partition: %s" % (no, why, ctl.sub("?", line)[:120]))
        continue
    start, end, length = int(m.group(3)), int(m.group(4)), int(m.group(5))
    if end < start or length != end - start + 1:
        expect += 1
        print("NOTE\tline %d of partitions.txt has an end (%d) and a length (%d) that do not agree with its start (%d): it is not read as a partition: %s" % (no, end, length, start, ctl.sub("?", line)[:120]))
        continue
    expect += 1
    if m.group(2) == "Meta" or set(m.group(2)) == {"-"}:
        continue
    print("ROW\t%d\t%s" % (start, ctl.sub("?", m.group(6).strip())))
PY
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
  if ! head -c 4096 /dev/zero > "$p" 2>/dev/null || [[ "$(wc -c < "$p" 2>/dev/null | tr -d ' ')" != 4096 ]]; then
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
PROBE_TIMEOUT="${RECIPE_PROBE_SECONDS:-120}"
[[ "$STEP_TIMEOUT" =~ ^[0-9]+$ && "$PROBE_TIMEOUT" =~ ^[0-9]+$ ]] || { final; echo '{"ok": false, "error": "RECIPE_STEP_SECONDS and RECIPE_PROBE_SECONDS are whole numbers"}'; exit 2; }
# The recipe's own clock: recipe.json's limits.seconds (a test holds the two equal), less a margin of a twentieth, at most a minute, for
# the index and the coverage. SECONDS is the shell's own count of seconds since it began.
TOTAL_SECONDS="${RECIPE_SECONDS:-14400}"
[[ "$TOTAL_SECONDS" =~ ^[0-9]+$ ]] || TOTAL_SECONDS=14400
MARGIN=$((TOTAL_SECONDS / 20)); (( MARGIN > 60 )) && MARGIN=60
DEADLINE=$((TOTAL_SECONDS - MARGIN))
out=""
cmd=""
notes=()
unstarted=()   # the steps the recipe's clock left no time for, by their command line
cut_short=()   # the steps that were given only the time the clock had left, and used it
stopped_by=""
inventory=()   # one "start<TAB>description<TAB>outcome<TAB>why" per allocated partition entry

exec 3>&1     # the real standard output, for the stop answer: the redirections of the step being waited for are still in force when a trap runs
# --- steps and stopping ---------------------------------------------------------------------------------------------------------
# Every step is started in the background and waited for, so that a signal to this script is acted on at once (a trap waits for a
# foreground command to end) and the step to end is known by its pid. perl's alarm then exec makes the command the process itself.
CHILD=""
alive() { # alive <pid>: running, and not a zombie waiting to be reaped
  kill -0 "$1" 2>/dev/null || return 1
  local st
  if [[ -r "/proc/$1/status" ]]; then
    st="$(sed -n 's/^State:[[:space:]]*\(.\).*/\1/p' "/proc/$1/status" 2>/dev/null)"
  else                                  # no /proc (macOS): ps tells the state
    st="$(ps -o stat= -p "$1" 2>/dev/null | tr -d ' ')"
    st="${st:0:1}"
  fi
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
my $mark = delete $ENV{STEP_MARK};     # the program does not get it
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
  } elsif (open(my $p, "-|", "ps", "-A", "-o", "pid=,pgid=")) {     # no /proc (macOS): ps lists the group
    for my $line (<$p>) {
      my ($e, $g) = $line =~ /^[[:space:]]*([0-9]+)[[:space:]]+([0-9]+)/;
      next unless defined $g;
      next if $e == $$;
      push @m, $e if $g == $$;
    }
    close $p;
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
  unlink $mark if defined $mark && length $mark;     # armed by the caller; an unlink needs no room, so a full disk cannot stop the word
  print STDERR "the step output could not be written whole ($bad)\n";
  exit 74;
}
exit 142 if $term_at;
exit 143 if $stopped;
exit(($status & 127) ? 128 + ($status & 127) : ($status >> 8));'
TSK_B=()           # -b <sector size>, when a descriptor's is not 512
IMG_EXTRA=()       # the sources of a descriptor after the first, given to every Sleuth Kit program after the image
bg() { # bg <seconds> <cmd...>: the command with a deadline; its redirections are the caller's
  local secs="$1" rc
  shift
  if (( ${#TSK_B[@]} + ${#IMG_EXTRA[@]} > 0 )); then
    case "$1" in
      mmls|fsstat|fls|img_stat|icat|istat)
        local prog="$1" last
        shift
        last="${*: -1}"
        set -- "$prog" ${TSK_B[@]+"${TSK_B[@]}"} "$@"
        if [[ "$last" == "$img" ]]; then set -- "$@" ${IMG_EXTRA[@]+"${IMG_EXTRA[@]}"}; fi ;;
    esac
  fi
  STEP_REFUSED=0
  local armed=1
  : > "$STEP_MARK" 2>/dev/null || armed=0          # armed before the step: the wrapper unlinks it to say a write was refused
  STEP_MARK="$STEP_MARK" perl -e "$STEP_PERL" "$secs" "$@" 3>&- &
  CHILD=$!
  wait "$CHILD"
  rc=$?
  CHILD=""
  if (( ! armed )); then                        # the marker could not be made (no inodes, no room): whether a write was refused is not known
    STEP_REFUSED=1; WRITE_REFUSED_SEEN=1; WRITE_FAILED=1
    notes+=("whether the output of ${*:1:3} was written whole is not known: the file that carries the wrapper's word could not be made")
  elif [[ ! -e "$STEP_MARK" ]]; then            # the wrapper took it away: its word that a write was refused, not an exit code a program can also give
    STEP_REFUSED=1; WRITE_REFUSED_SEEN=1; WRITE_FAILED=1
    notes+=("the output of ${*:1:3} could not be written whole: the disk or a file-size limit refused a write while the step ran")
  fi
  rm -f "$STEP_MARK"
  return "$rc"
}
# boxed <cmd...>: bg with RECIPE_STEP_SECONDS or what the recipe's clock has left, whichever is less; 125 when there is none left.
boxed() {
  local secs="$STEP_TIMEOUT" left=$((DEADLINE - SECONDS)) label="$*" rc
  if (( left <= 0 )); then
    unstarted+=("${label:0:160}")
    return 125
  fi
  local limited=0
  if (( left < secs )); then secs=$left; limited=1; fi
  bg "$secs" "$@"
  rc=$?
  if (( rc == 142 && limited )); then cut_short+=("${label:0:160}"); fi
  return "$rc"
}
probe() { bg "$PROBE_TIMEOUT" "$@"; } # a detect-time call with a deadline, like every other step
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
note_entry() { # note_entry <start> <description> <outcome> <why>
  inventory+=("$(printf '%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4")")
}

# Run a command with a deadline; stdout to a file, stderr whole beside it as
# <file>.stderr when there is any. Sets STEP_R to "ok" or a reason naming that file (not printed: a command substitution would be a
# foreground step the stop handling cannot see).
STEP_R=""
run_step() { # run_step <outfile> <cmd...>
  local file="$1"; shift
  local rc=0
  boxed "$@" > "$file" 2> "$file.stderr" || rc=$?
  [[ -s "$file.stderr" ]] || rm -f "$file.stderr"
  if [[ "$rc" -eq 0 ]]; then
    STEP_R=ok
    return 0
  fi
  [[ -s "$file" ]] || rm -f "$file"
  if [[ "$rc" -eq 125 ]]; then
    STEP_R="not started (the recipe's time limit left none for it)"
    return 0
  fi
  local err=""
  if [[ -f "$file.stderr" ]]; then
    err="$(head -c 200 "$file.stderr" | tr '\n' ' ')"
    err="$err; all of stderr: ${file#"$out/"}.stderr"
  fi
  STEP_R="failed (exit $rc${err:+: $err})"
  if (( STEP_REFUSED )); then STEP_R="its output could not be written whole (the disk or a file-size limit refused a write)"; fi
}

index_row() { # index_row <file relative to out> <what>
  [[ -f "$out/$1" ]] || return 0
  if ! printf '%s\t%s\n' "$1" "$2" >> "$out/index.tsv" 2>/dev/null; then
    WRITE_FAILED=1
    notes+=("index.tsv could not be written whole")
  fi
}

fsstat_boxed() { boxed fsstat "$@"; }

# reads_a_file_system <start> <img>: does fsstat read one there (a time-boxed call, its words kept only to look for the answer).
reads_a_file_system() {
  local f rc=0
  f="$(mktemp)"; TMPF="$f"
  boxed fsstat -o "$1" "$2" > "$f" 2>/dev/null || rc=$?
  if (( rc == 125 )); then rm -f "$f"; TMPF=""; return 2; fi        # not started: it is not known whether a file system is there
  grep -q '^File System Type:' "$f" 2>/dev/null && rc=0 || rc=1
  rm -f "$f"; TMPF=""
  return "$rc"
}

coverage() { # coverage <status> <covered>: the coverage file, whole or not at all; the status and the outcome are kept for the answer
  COV_REQ="$1"; COV_TEXT="$2"; COV_STATUS="$1"
  if [[ "$1" == complete ]] && (( ${#unstarted[@]} + ${#cut_short[@]} > 0 )); then COV_STATUS=partial; fi
  if _coverage_write "$1" "$2"; then COV_OK=1; else COV_OK=0; fi
}

volume() { # volume <img> <shown name> <start> <description>
  local img="$1" shown="$2" start="$3" desc="$4" pdir r why
  [[ "$start" =~ ^[0-9]+$ ]] || return  # a start sector is digits; it names a directory
  pdir="$out/p$start"
  mkdir -p "$pdir"
  candidate_volumes=$((candidate_volumes + 1))
  if ! have fsstat; then
    notes+=("fsstat missing: cannot establish whether the candidate at sector $start is a readable filesystem")
    note_entry "$start" "$desc" failed "fsstat is not in this image"
    return
  fi
  run_step "$pdir/fsstat.txt" fsstat -o "$start" "$img"; r="$STEP_R"
  if [[ "$r" != ok ]]; then
    notes+=("candidate partition at sector $start is not a readable filesystem: $r")
    why="fsstat did not read a file system there"
    [[ "$r" == "not started"* ]] && why="fsstat was not started (the recipe's time limit left none for it)"
    note_entry "$start" "$desc" failed "$why"
    index_row "p$start/fsstat.txt" "fsstat output for unreadable candidate at sector $start ($desc)"
    # Keep the historical best-effort fls probes as diagnostics. They do not
    # make the candidate a readable volume, even if they leave partial output.
    if have fls; then
      run_step "$pdir/bodyfile.txt" fls -m / -r -o "$start" "$img"; r="$STEP_R"
      [[ "$r" == ok ]] || notes+=("fls body file at sector $start: $r")
      index_row "p$start/bodyfile.txt" "diagnostic body-file probe for unreadable candidate at sector $start"
      run_step "$pdir/filelist.txt" fls -r -p -o "$start" "$img"; r="$STEP_R"
      [[ "$r" == ok ]] || notes+=("fls path list at sector $start: $r")
      index_row "p$start/filelist.txt" "diagnostic path-list probe for unreadable candidate at sector $start"
    fi
    return
  fi
  volumes=$((volumes + 1))
  note_entry "$start" "$desc" read "fsstat read a file system"
  index_row "p$start/fsstat.txt" "filesystem header at sector $start ($desc)"
  if have fls; then
    run_step "$pdir/bodyfile.txt" fls -m / -r -o "$start" "$img"; r="$STEP_R"
    [[ "$r" == ok ]] || notes+=("fls body file at sector $start: $r")
    index_row "p$start/bodyfile.txt" "body file (fls -m -r), every file with MAC times, for mactime/grep"
    run_step "$pdir/filelist.txt" fls -r -p -o "$start" "$img"; r="$STEP_R"
    [[ "$r" == ok ]] || notes+=("fls path list at sector $start: $r")
    index_row "p$start/filelist.txt" "path list (fls -r -p): inode, type and full path per line; icat -o $start $shown <inode>"
  else
    notes+=("fls missing: no body file or path list for $shown")
  fi
  if ! have mactime; then
    notes+=("mactime missing: no timeline.csv for the filesystem at sector $start")
  elif [[ -s "$pdir/bodyfile.txt" ]]; then
    # The body file's times are epoch seconds; -z UTC and TZ=UTC make the rendering the UTC the row says.
    TZ=UTC run_step "$pdir/timeline.csv" mactime -b "$pdir/bodyfile.txt" -d -y -z UTC; r="$STEP_R"
    [[ "$r" == ok ]] || notes+=("mactime at sector $start: $r")
    index_row "p$start/timeline.csv" "MAC timeline (mactime -d -y -z UTC): date, size, MACB, mode, uid, gid, inode, name — UTC"
  fi
}

# probe_fs <fsstat arguments>: does fsstat read a file system there, as a detect-time call (no pipe: a pipeline is a foreground wait).
probe_fs() {
  local f rc=1
  f="$(mktemp)"; TMPF="$f"
  probe fsstat "$@" > "$f" 2>/dev/null || true
  grep -q '^File System Type:' "$f" 2>/dev/null && rc=0
  rm -f "$f"; TMPF=""
  return "$rc"
}

_coverage_write() { # _coverage_write <status> <covered> — notes become errors
  STOPPED_BY="$stopped_by" python3 - "$out/coverage.json" "$1" "$2" "${#notes[@]}" "${#unstarted[@]}" "${#cut_short[@]}" "${notes[@]+"${notes[@]}"}" "${unstarted[@]+"${unstarted[@]}"}" "${cut_short[@]+"${cut_short[@]}"}" "${inventory[@]+"${inventory[@]}"}" <<'PY'
import json, os, sys
path, status, covered, n_notes, n_unstarted, n_cut, *rest = sys.argv[1:]
n, u, c = int(n_notes), int(n_unstarted), int(n_cut)
notes, unstarted, cut, entries = rest[:n], rest[n:n + u], rest[n + u:n + u + c], rest[n + u + c:]
limits_hit = ["seconds: not started, the recipe's time limit left none for it: " + s for s in unstarted] + ["seconds: stopped at the recipe's time limit: " + s for s in cut]
if limits_hit and status == "complete":
    status = "partial"
    covered += "; the recipe's time limit stopped or left out steps (see limits_hit)"
inventory = []
for e in entries:
    start, desc, outcome, why = (e.split("\t") + ["", "", "", ""])[:4]
    inventory.append({"start_sector": int(start) if start.isdigit() else start, "description": desc, "outcome": outcome, "why": why})
doc = {"recipe": "disk-volumes", "status": status, "status_basis": covered, "covered": covered,
       "not_covered": "file contents, carving, encrypted volumes, volume shadow copies",
       "inventory": inventory, "limits_hit": limits_hit, "errors": notes}
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
HELPER_FAILED=0
img="$(target_field "$target" paths0)" || HELPER_FAILED=1     # a helper that could not even start (the macOS bash keeps a here document over 512 bytes in a temporary file, which a file-size limit or a full disk refuses) says nothing about the image
shown="$(target_field "$target" name)"
DESC_TMP=""
descriptor_ref="$(target_field "$target" descriptor)"
if [[ -n "$descriptor_ref" ]]; then
  # A layer descriptor stands for the image: its sources are the image, and its sector size is the sector size. It is checked whole before anything runs.
  DESC_TMP="$(mktemp 2>/dev/null)" || { final; echo '{"applies": "unknown", "why": "no temporary file could be made to read the descriptor", "ok": false, "error": "no temporary file"}'; exit 2; }
  descriptor_load "$descriptor_ref" "$(target_field "$target" descriptor_sha256)" "$(target_field "$target" verify_sources)" "$(( DEADLINE - SECONDS > 1 ? DEADLINE - SECONDS : 1 ))" > "$DESC_TMP" 2>/dev/null
  derr="$(desc_get "$DESC_TMP" error 2>/dev/null)"
  if [[ -n "$derr" || ! -s "$DESC_TMP" ]]; then
    rm -f "$DESC_TMP"; DESC_TMP=""
    final; echo "{\"applies\": \"unknown\", \"ok\": false, \"status\": \"failed\", \"error\": \"the descriptor cannot be used\", \"status_basis\": \"the descriptor was refused, so nothing was run and nothing is said about the image\", \"why\": \"the descriptor cannot be used: $(printf '%s' "$derr" | tr -c 'A-Za-z0-9 ,.:;()_-' ' ' | head -c 300)\"}"
    exit 2
  fi
  img="$(desc_get "$DESC_TMP" image 0)"
  n_images="$(desc_get "$DESC_TMP" images)"
  i=1
  while (( i < n_images )); do IMG_EXTRA+=("$(desc_get "$DESC_TMP" image "$i")"); i=$((i + 1)); done
  dsz="$(desc_get "$DESC_TMP" sector_size)"
  if [[ "$dsz" != 512 ]]; then TSK_B=(-b "$dsz"); fi
  [[ -n "$shown" && "$shown" != "$(target_field "$target" paths0)" ]] || shown="$img"
fi
if (( HELPER_FAILED )) && [[ -z "$img" ]]; then
  final
  echo '{"applies": "unknown", "ok": false, "status": "failed", "error": "the recipe could not read the target", "why": "a write was refused (a file-size limit or a full disk) or python3 could not be run, so the target could not be read: nothing was asked of the image", "status_basis": "the recipe could not read the target, so nothing was run and nothing is said about the image"}'
  exit 2
fi
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
STEP_MARK_DIR=""
trap '[[ -n "${DESC_TMP:-}" ]] && rm -f "$DESC_TMP"; [[ -n "${STEP_MARK_DIR:-}" ]] && rm -rf "$STEP_MARK_DIR"; [[ -n "${out:-}" ]] && rm -f "$out/.fsstat.tmp" "$out/.disk_probe.tmp"; [[ -n "${TMPF:-}" ]] && rm -f "$TMPF" "$TMPF.stderr"; true' EXIT
STEP_MARK_DIR="$(mktemp -d 2>/dev/null)" || { final; echo '{"ok": false, "status": "failed", "applies": "unknown", "error": "no temporary directory could be made", "status_basis": "nothing was run and nothing is said about the image"}'; exit 2; }
STEP_MARK="$STEP_MARK_DIR/refused"

case "$cmd" in
  detect)
    if have mmls && probe mmls "$img" >/dev/null 2>&1; then
      final; echo '{"applies": true, "why": "a partition table (mmls)"}'; exit 0
    fi
    if have fsstat && probe_fs "$img"; then
      final; echo '{"applies": true, "why": "a filesystem at sector 0 (fsstat)"}'; exit 0
    fi
    # A volume carved or copied out of a disk can keep the disk's offset
    # with no table before it (Ali Hadi #10's recovered Kali prefix: ext4
    # at sector 2048). The two usual starts are tried.
    for o in 63 2048; do
      if have fsstat && probe_fs -o "$o" "$img"; then
        echo "{\"applies\": true, \"why\": \"a filesystem at sector $o with no partition table (fsstat -o $o)\"}"; exit 0
      fi
    done
    if ! have mmls && ! have fsstat; then
      final; echo '{"applies": "unknown", "why": "mmls and fsstat are not in this image"}'; exit 2
    fi
    if (( WRITE_REFUSED_SEEN )); then
      final; echo '{"applies": "unknown", "why": "a write was refused (a file-size limit or a full disk) while the probes ran, so it cannot be told what the image holds"}'; exit 2
    fi
    final; echo '{"applies": false, "why": "no partition table and no filesystem at sector 0, 63 or 2048"}'; exit 1
    ;;
  run)
    [[ -n "$out" ]] || { final; echo '{"ok": false, "error": "run needs --out DIR"}'; exit 2; }
    mkdir -p "$out" 2>/dev/null && [[ -d "$out" && -w "$out" ]] || { final; echo '{"ok": false, "status": "failed", "error": "--out cannot be used: it is not a directory that can be made and written", "status_basis": "the output directory could not be made, so nothing was run"}'; exit 2; }
    : > "$out/index.tsv"
    if [[ -n "$DESC_TMP" ]]; then
      # the descriptor the run read through, beside the other outputs (it is no limit and no error, so it is not a note)
      if cp "$DESC_TMP" "$out/descriptor.json" 2>/dev/null; then
        index_row "descriptor.json" "the layer descriptor this run read through: its file and sha256, the layer, the sources given to the Sleuth Kit in order, and how they were checked"
      else
        WRITE_FAILED=1
        notes+=("descriptor.json could not be written whole")
      fi
    fi
    volumes=0
    candidate_volumes=0
    # Said before the first step, so a run stopped anywhere leaves a coverage file that says it was.
    coverage partial "started; no step has finished (the run stopped before its end)"
    mmls_rc=127
    if have mmls; then
      mmls_rc=0
      boxed mmls "$img" > "$out/partitions.txt" 2> "$out/mmls.stderr" || mmls_rc=$?
      [[ -s "$out/mmls.stderr" ]] || rm -f "$out/mmls.stderr"
    fi
    if [[ "$mmls_rc" -eq 0 ]]; then
      index_row "partitions.txt" "partition table of $shown (mmls)"
      while IFS=$'\t' read -r kind start desc; do
        if [[ "$kind" == NOTE ]]; then notes+=("$start"); continue; fi
        # What holds no file system by definition is named in the inventory and not counted against coverage:
        # an extended partition is a container of the rows after it, swap and a reserved or boot partition
        # hold none ("DOS Extended" used to match `*Ext*`).
        # A description is the table's word for the partition, not what is in it: an entry named for swap, a
        # reserved area, LVM or RAID is first asked of fsstat, and only one it reads nothing in is classed by its
        # name. (An extended partition holds the table of the rows after it, never a file system of its own.)
        case "$desc" in
          *Extended*) note_entry "$start" "$desc" structural "an extended partition is a container of the rows after it"; continue ;;
        esac
        case "$desc" in
          *Swap*|*swap*|*Microsoft\ reserved*|*Microsoft\ Reserved*|*BIOS\ boot*|*BIOS\ Boot*|*Logical\ Volume\ Manager*|*LVM*|*RAID*|*raid*)
            reads_a_file_system "$start" "$img"; fsrc=$?
            if [[ "$fsrc" -eq 0 ]]; then
              volume "$img" "$shown" "$start" "$desc"
              continue
            elif [[ "$fsrc" -eq 2 ]]; then
              notes+=("fsstat was not started for the candidate at sector $start ($desc): the recipe's time limit left none for it")
              note_entry "$start" "$desc" failed "fsstat was not started (the recipe's time limit left none for it)"
              continue
            fi ;;
        esac
        case "$desc" in
          *Swap*|*swap*) note_entry "$start" "$desc" structural "swap holds no file system (fsstat read none there)"; continue ;;
          *Microsoft\ reserved*|*Microsoft\ Reserved*) note_entry "$start" "$desc" structural "a Microsoft reserved partition holds no file system (fsstat read none there)"; continue ;;
          *BIOS\ boot*|*BIOS\ Boot*) note_entry "$start" "$desc" structural "a BIOS boot partition holds no file system (fsstat read none there)"; continue ;;
        esac
        # A layer another reader opens (target-query, lvm2, mdadm); it is named, not read as a filesystem.
        case "$desc" in
          *Logical\ Volume\ Manager*|*LVM*)
            notes+=("an LVM physical volume at sector $start ($desc): fsstat read no file system there, and TSK does not read the layer; its logical volumes are not covered")
            note_entry "$start" "$desc" unsupported "an LVM physical volume: fsstat read none, and TSK does not read the layer"
            continue ;;
          *RAID*|*raid*)
            notes+=("a RAID member at sector $start ($desc): fsstat read no file system there, and TSK does not read the layer; the array's file system is not covered")
            note_entry "$start" "$desc" unsupported "a RAID member: fsstat read none, and TSK does not read the layer"
            continue ;;
        esac
        # Everything else is tried: fsstat, not a list of descriptions, says whether a file system is there.
        volume "$img" "$shown" "$start" "$desc"
      done < <(table_rows "$out/partitions.txt")
      if [[ "$volumes" -eq 0 ]]; then
        coverage partial "a partition table and $candidate_volumes candidate partition(s), but no readable filesystem"
      elif [[ ${#notes[@]} -gt 0 ]]; then
        coverage partial "partition table and $volumes readable filesystem(s) from $candidate_volumes candidate partition(s), with steps that did not finish"
      else
        coverage complete "partition table and $volumes readable filesystem(s) from $candidate_volumes candidate partition(s)"
      fi
    else
      # No table read: a raw volume has none, and mmls says so on stderr (kept as mmls.stderr). A mmls that did not
      # finish, or is not here, is said: no table is then not established.
      rm -f "$out/partitions.txt"
      if [[ "$mmls_rc" -eq 127 ]]; then
        notes+=("mmls is not in this image: whether the image has a partition table was not asked")
      elif [[ "$mmls_rc" -eq 125 ]]; then
        notes+=("mmls was not started (the recipe's time limit left none for it): whether the image has a partition table is not established")
      elif [[ "$mmls_rc" -ge 128 ]]; then
        notes+=("mmls did not finish within ${STEP_TIMEOUT} seconds (exit $mmls_rc): whether the image has a partition table is not established")
      fi
      if have fsstat && fsstat_boxed "$img" > "$out/.fsstat.tmp" 2>/dev/null && grep -q '^File System Type:' "$out/.fsstat.tmp"; then
        fstype="$(sed -n 's/^File System Type: *//p' "$out/.fsstat.tmp" | head -1)"
        rm -f "$out/.fsstat.tmp"
        printf 'No partition table: %s is one %s volume starting at sector 0 (use the tools without -o).\n' "$shown" "$fstype" > "$out/partitions.txt" || WRITE_FAILED=1
        index_row "partitions.txt" "no partition table: $shown is a single $fstype volume"
        volume "$img" "$shown" 0 "$fstype (logical volume, no partition table)"
        if [[ ${#notes[@]} -gt 0 ]]; then
          coverage partial "single $fstype volume, with steps that did not finish"
        else
          coverage complete "single $fstype volume"
        fi
      else
        rm -f "$out/.fsstat.tmp"
        at=""
        for o in 63 2048; do
          if have fsstat && fsstat_boxed -o "$o" "$img" > "$out/.fsstat.tmp" 2>/dev/null && grep -q '^File System Type:' "$out/.fsstat.tmp"; then at="$o"; break; fi
        done
        if [[ -n "$at" ]]; then
          fstype="$(sed -n 's/^File System Type: *//p' "$out/.fsstat.tmp" | head -1)"
          rm -f "$out/.fsstat.tmp"
          printf 'No partition table: %s holds one %s volume starting at sector %s (use the tools with -o %s).\n' "$shown" "$fstype" "$at" "$at" > "$out/partitions.txt" || WRITE_FAILED=1
          index_row "partitions.txt" "no partition table: $shown holds one $fstype volume at sector $at"
          volume "$img" "$shown" "$at" "$fstype (no partition table, at sector $at)"
          if [[ ${#notes[@]} -gt 0 ]]; then
            coverage partial "one $fstype volume at sector $at, with steps that did not finish"
          else
            coverage complete "one $fstype volume at sector $at"
          fi
        else
          rm -f "$out/.fsstat.tmp"
          if [[ ${#unstarted[@]} -gt 0 ]]; then
            notes+=("no partition table was read and no file system was found, but the recipe's time limit left no time for every step (limits_hit names them): the image is not shown to have none")
            coverage partial "nothing was read before the recipe's time limit"
            final; echo '{"ok": false, "status": "partial"}'
            exit 2
          fi
          if (( WRITE_REFUSED_SEEN )); then
            coverage partial "nothing could be read: a write was refused (a file-size limit or a full disk), so the image is not shown to have no partition table or file system"
            finish_checks
            final; echo '{"ok": false, "status": "partial", "status_basis": "a write was refused while the image was probed; nothing here is a statement about what the image holds"}'
            exit 2
          fi
          notes+=("no partition table (mmls), and no filesystem at sector 0, 63 or 2048 (fsstat)")
          coverage unsupported "nothing"
          final; echo '{"ok": false, "status": "unsupported"}'
          exit 2
        fi
      fi
    fi
    # What every step wrote to stderr, listed beside its output.
    while IFS= read -r f; do
      rel="${f#"$out/"}"
      index_row "$rel" "what the step writing ${rel%.stderr} said on stderr"
    done < <(find "$out" -type f -name '*.stderr' | sort)
    finish_checks
    final; python3 -c 'import json,sys; d = {"ok": True, "status": sys.argv[1], "volumes": int(sys.argv[2]), "candidate_volumes": int(sys.argv[3])}
if sys.argv[4] != "1":
    d["coverage_error"] = "coverage.json could not be written whole: the earlier one, if any, stands"
print(json.dumps(d))' "$ANSWER_STATUS" "$volumes" "$candidate_volumes" "$COV_OK"
    ;;
  *)
    final; echo '{"applies": "unknown", "why": "a usage error, so nothing was asked", "ok": false, "error": "usage: run.sh detect --target T | run --target T --out DIR"}'
    exit 2
    ;;
esac
