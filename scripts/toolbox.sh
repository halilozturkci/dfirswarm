#!/usr/bin/env bash
# toolbox: what the forensic tools on this host are, before any money is spent.
#
#   scripts/toolbox.sh <sandbox> dfir[,crypto,linux] [--required] [--image FILE] [--requires CAPS]
#
# --requires CAPS: what the case's questions need done (video-decode,
# qr-decode, …, from the goal's metadata block `requires:` or the kickoff's
# --requires). Each capability is met when one of its programs is present and,
# where it has one, passes a probe that does the work (zbarimg reads a PNG).
# toolbox.json gains "requires": [{capability, met, by, wanted, use}]; one not
# met is a WARN line before anything starts, a BLOCKER with --required. On
# Batman III three questions closed not determinable for want of a video
# decoder and a QR reader nobody had asked the image for.
#
# Writes <sandbox>/toolbox.json: {"preset", "checked_at", "present": [{name,
# version, use}], "missing": [{name, use, install}]}. Missing tools are a WARN
# line, or a BLOCKER (exit 3) with --required. swarm.sh renders the same into
# SWARM.md so the agents start knowing what they have.
#
# --image FILE: this is a microVM run's image, checked inside a throwaway VM
# of it (scripts/vm.ts toolbox). FILE is {"image", "programs": [{name, why,
# pack, required, not_in_image}]}: every program the run's packs name is
# checked too, the install hints are the VM's (nobody here runs brew), and
# --required holds only for what a pack requires — the presets are advisory in
# a VM, where the image is the toolset and no preset set is in every image. A
# program that belongs to another system (not_in_image: Apple's log, a
# collector run on the source host) is listed under not_applicable, never
# missing.
set -euo pipefail

sandbox="${1:-}"
preset="${2:-dfir}"
required=0
image_file=""
requires=""
shift 2 2>/dev/null || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --required) required=1; shift ;;
    --image) image_file="$2"; shift 2 ;;
    --requires) requires="$2"; shift 2 ;;
    *) echo "toolbox: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$sandbox" && -d "$sandbox" ]] || { echo "toolbox: usage: toolbox.sh <sandbox> dfir[,crypto,linux] [--required] [--image FILE]" >&2; exit 2; }
# One case is not another: an encryption case wants aescrypt and dislocker,
# a Linux case wants the journal readers, and neither is worth checking for
# on a Windows disk. Sets are comma-separated; dfir is what every case gets.
IFS="," read -r -a PRESETS <<< "$preset"
for one in "${PRESETS[@]}"; do
  case "$one" in
    dfir|crypto|linux) ;;
    *) echo "toolbox: unknown set $one (dfir, crypto, linux)" >&2; exit 2 ;;
  esac
done

# name | how to get a version | what it is for | how to install it
TOOLS=(
  "mmls|mmls -V 2>&1 | head -1|partition table of a disk image (The Sleuth Kit)|brew install sleuthkit"
  "fls|fls -V 2>&1 | head -1|file listing and body file of a filesystem (The Sleuth Kit)|brew install sleuthkit"
  "icat|icat -V 2>&1 | head -1|extract a file by inode (The Sleuth Kit)|brew install sleuthkit"
  "mactime|mactime -V 2>&1 | head -1|timeline from a body file (The Sleuth Kit)|brew install sleuthkit"
  "vol|vol --help 2>&1 | head -1|memory forensics (Volatility 3)|pipx install volatility3"
  "regipy-dump|python3 -c 'import regipy; print(getattr(regipy, \"__version__\", \"ok\"))'|registry hives (regipy, python)|python3 -m pip install --user regipy"
  "evtx_dump|python3 -c 'import Evtx; print(\"python-evtx ok\")'|Windows event logs (python-evtx)|python3 -m pip install --user python-evtx"
  "esedbexport|esedbexport -V 2>&1 | head -1|ESE databases: WebCacheV01.dat, SRUDB.dat, spartan.edb (libesedb)|brew install libesedb; apt-get install libesedb-utils"
  "yara|yara --version 2>&1 | head -1|pattern sweeps over files and memory|brew install yara"
  "exiftool|exiftool -ver 2>&1 | head -1|file metadata|brew install exiftool"
  "sqlite3|sqlite3 -version 2>&1 | head -1|browser and application databases|preinstalled on macOS; apt-get install sqlite3"
  "strings|strings --version 2>&1 | head -1 || echo bsd|printable strings in binaries|preinstalled"
  "python3|python3 --version 2>&1|scripts and forged tools|https://python.org"
)

# What a case about encryption needs, and what a Linux image needs. Added to
# the list only when the kickoff asks for them, so a Windows disk case is not
# told it is missing dislocker.
#
# The crypto set is arranged around one distinction, learned on BelkaCTF #6:
# **mounting is privileged, reading is not.** `dislocker`, `bdemount` and
# `vhdimount` are FUSE tools — they want a mount point, which on macOS means
# a kernel extension and on Linux a setuid helper, and neither is available
# inside this sandbox. `pybde`, `pyvhdi`, `pytsk3` and `dfvfs` open the same
# formats as files, decrypt in user space and hand back a byte stream. A run
# with no root can still read a BitLocker volume inside a VHDX inside an
# alternate data stream — but only if those libraries are there.
# Shadow copies are the same kind of thing: libvshadow reads a VSS store in
# place, so it sits here beside dfvfs, which needs pyvshadow to open one. The
# Linux set's XFS and LVM readers (xfsprogs' xfs_db -r, libvslvm) follow the
# same rule: no mount, no device mapper.
CRYPTO_TOOLS=(
  "aescrypt|python3 -c 'import pyAesCrypt; print(\"pyAesCrypt ok\")'|AES Crypt containers (pyAesCrypt)|python3 -m pip install --user pyAesCrypt"
  "dislocker|dislocker -V 2>&1 | head -1|BitLocker volumes|brew install dislocker"
  "bdeinfo|bdeinfo -V 2>&1 | head -1|BitLocker volume headers and protectors, without mounting (libbde)|brew install libbde; apt-get install libbde-utils"
  "pybde|python3 -c 'import pybde; print(pybde.get_version())'|unlock and read a BitLocker volume in place, no root and no mount (libbde python bindings)|python3 -m pip install --user libbde-python"
  "vhdiinfo|vhdiinfo -V 2>&1 | head -1|VHD and VHDX virtual disks, without mounting (libvhdi)|brew install libvhdi; apt-get install libvhdi-utils"
  "pyvhdi|python3 -c 'import pyvhdi; print(pyvhdi.get_version())'|read a VHD/VHDX in place (libvhdi python bindings)|python3 -m pip install --user libvhdi-python"
  "luksdeinfo|luksdeinfo -V 2>&1 | head -1|LUKS volumes, without mounting (libluksde)|brew install libluksde; apt-get install libluksde-utils"
  "qemu-img|qemu-img --version 2>&1 | head -1|convert VHDX, VMDK, QCOW2 to raw so the rest of the toolbox can read them|brew install qemu; apt-get install qemu-utils"
  "pytsk3|python3 -c 'import pytsk3; print(pytsk3.get_version())'|read a filesystem from a byte stream instead of a mount point (The Sleuth Kit python bindings)|python3 -m pip install --user pytsk3"
  "dfvfs|python3 -c 'import dfvfs; print(dfvfs.__version__)'|stack the layers — EWF, VHDX, BitLocker, LUKS, NTFS — in one process, no mount and no root|python3 -m pip install --user dfvfs"
  "openssl|openssl version 2>&1|keys, certificates, raw ciphers|preinstalled"
  "gpg|gpg --version 2>&1 | head -1|OpenPGP keys and messages|brew install gnupg"
  "john|john --list=build-info 2>&1 | head -1|passphrases on recovered key material|brew install john-jumbo"
  "vshadowinfo|vshadowinfo -V 2>&1 | head -1|Volume Shadow Copy stores on an NTFS volume, without mounting (libvshadow)|apt-get install libvshadow-utils"
  "pyvshadow|python3 -c 'import pyvshadow; print(pyvshadow.get_version())'|read each shadow copy as a byte stream, and what dfvfs needs to open one (libvshadow python bindings)|python3 -m pip install --user libvshadow-python"
)
LINUX_TOOLS=(
  "ext4fuse|ext4fuse --version 2>&1 | head -1|reading ext4 without root|brew install ext4fuse"
  "journalctl|journalctl --version 2>&1 | head -1|systemd journals from a mounted root|apt-get install systemd"
  "bulk_extractor|bulk_extractor -V 2>&1 | head -1|carving features out of a raw image|brew install bulk_extractor"
  "xfs_db|xfs_db -V 2>&1 | head -1|XFS without mounting: xfs_db -r -f <image> reads the superblock, inodes and directories (xfsprogs)|apt-get install xfsprogs"
  "vslvminfo|vslvminfo -V 2>&1 | head -1|LVM volume groups: every logical volume and its segments, without mapping them (libvslvm)|apt-get install libvslvm-utils"
  "pyvslvm|python3 -c 'import pyvslvm; print(pyvslvm.get_version())'|read a logical volume as one byte stream across its segments, and what dfvfs needs for LVM (libvslvm python bindings)|python3 -m pip install --user libvslvm-python"
)
for one in "${PRESETS[@]}"; do
  case "$one" in
    crypto) TOOLS+=("${CRYPTO_TOOLS[@]}") ;;
    linux) TOOLS+=("${LINUX_TOOLS[@]}") ;;
  esac
done

# What a question may need done, and the programs that do it (any one
# serves): name | programs | what for. A probe, where one is given, runs the
# program on a small input, because a program that is there may still not do
# the work (a zbarimg built without ImageMagick's PNG coder reads no PNG).
CAPABILITIES=(
  "video-decode|ffmpeg ffprobe|decode a video's frames and streams"
  "audio-decode|ffmpeg sox|decode audio streams"
  "qr-decode|zbarimg|decode QR codes and barcodes in images (zbar)"
  "ocr|tesseract|read the text in an image"
  "image-convert|magick convert|convert and inspect images (ImageMagick)"
  "pdf-text|pdftotext mutool|the text of a PDF"
  "office-macros|olevba|macros in Office documents (oletools)"
  "archive-7z|7z 7zz|7-Zip archives and the formats 7-Zip opens"
  "pcap|tshark tcpdump|network captures"
  "stego|steghide zsteg stegseek|common steganography in images and audio"
  "memory|vol|memory images (Volatility 3)"
)
# An 8x8 white PNG: a zbarimg that can read PNG finds no symbol in it (exit 4).
PROBE_PNG="iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAAAAADhZOFXAAAAEElEQVR42mP8zwABTAwUMQBJQQEPkWFcdwAAAABJRU5ErkJggg=="
capability_probe() { # <program>: 0 when it does the work, 1 when it does not; no probe is 0
  case "$1" in
    zbarimg)
      local d rc=0
      d="$(mktemp -d)"
      if printf '%s' "$PROBE_PNG" | base64 -d > "$d/probe.png" 2>/dev/null || printf '%s' "$PROBE_PNG" | base64 -D > "$d/probe.png" 2>/dev/null; then
        zbarimg -q "$d/probe.png" >/dev/null 2>&1 || rc=$?
      else
        rc=0
      fi
      rm -rf "$d"
      # 0: a symbol, 4: none found; anything else (2: ImageMagick could not read it) is a reader that cannot read.
      [[ "$rc" -eq 0 || "$rc" -eq 4 ]] ;;
    *) return 0 ;;
  esac
}
wanted_caps=()
if [[ -n "$requires" ]]; then
  IFS="," read -r -a wanted_caps <<< "$requires"
  for cap in "${wanted_caps[@]}"; do
    known=0
    for spec in "${CAPABILITIES[@]}"; do [[ "${spec%%|*}" == "$cap" ]] && known=1; done
    if [[ "$known" -eq 0 ]]; then
      echo "toolbox: unknown capability $cap ($(for spec in "${CAPABILITIES[@]}"; do printf '%s ' "${spec%%|*}"; done | sed 's/ $//'))" >&2
      exit 2
    fi
  done
fi

# In an image: the packs' own programs, and the VM's install hint.
image_ref=""
pack_required=" "
not_applicable="[]"
VM_HINT="not in this image: an agent may pip-install it into its own VM (--allow-install), or build an image that has it (images/README.md)"
if [[ -n "$image_file" ]]; then
  image_ref="$(jq -r '.image // ""' "$image_file")"
  not_applicable="$(jq -c '[.programs[]? | select(.not_in_image) | {name, pack: (.pack // ""), why: .not_in_image}]' "$image_file")"
  while IFS=$'\t' read -r pname pwhy ppack preq; do
    [[ -n "$pname" ]] || continue
    [[ "$preq" == "true" ]] && pack_required+="$pname "
    dup=0
    for spec in "${TOOLS[@]}"; do [[ "${spec%%|*}" == "$pname" ]] && dup=1; done
    [[ "$dup" -eq 1 ]] && continue
    TOOLS+=("$pname|$pname --version 2>&1 | head -1|$pwhy ($ppack)|$VM_HINT")
  done < <(jq -r '.programs[]? | select(.not_in_image | not) | [.name, (.why // ""), (.pack // ""), (.required | tostring)] | @tsv' "$image_file")
fi

present=()
missing=()
warn=()
for spec in "${TOOLS[@]}"; do
  # The version probe is a pipeline with a `|` of its own, so the fields are
  # taken from both ends: the name first, the install hint and the use last.
  # (Split from the left, every tool's use read " head -1".)
  name="${spec%%|*}"; rest="${spec#*|}"
  install="${rest##*|}"; rest="${rest%|*}"
  use="${rest##*|}"; probe="${rest%|*}"
  # A Python library is not on PATH by its name: it is there when the probe's
  # import works. Only binaries are looked up with command -v.
  case "$probe" in
    "python3 -c "*)
      if version="$(bash -c "$probe" 2>/dev/null | head -1)" && [[ -n "$version" ]]; then ok=1; else ok=0; version=""; fi ;;
    *) if command -v "$name" >/dev/null 2>&1; then ok=1; version="$(bash -c "$probe" 2>/dev/null | head -1 | tr -d '\r' || true)"; else ok=0; version=""; fi ;;
  esac
  if [[ "$ok" -eq 1 ]]; then
    present+=("$(jq -cn --arg n "$name" --arg v "${version:-present}" --arg u "$use" '{name: $n, version: $v, use: $u}')")
  else
    [[ -n "$image_file" ]] && install="$VM_HINT"
    missing+=("$(jq -cn --arg n "$name" --arg u "$use" --arg i "$install" '{name: $n, use: $u, install: $i}')")
    warn+=("$name")
  fi
done

# The capabilities the case requires: met by a program present that passes its probe.
cap_rows=()
cap_unmet=()
for cap in ${wanted_caps[@]+"${wanted_caps[@]}"}; do
  for spec in "${CAPABILITIES[@]}"; do
    [[ "${spec%%|*}" == "$cap" ]] || continue
    rest="${spec#*|}"; progs="${rest%%|*}"; use="${rest#*|}"
    by=()
    unusable=()
    for prog in $progs; do
      command -v "$prog" >/dev/null 2>&1 || continue
      if capability_probe "$prog"; then by+=("$prog"); else unusable+=("$prog"); fi
    done
    met=false
    [[ "${#by[@]}" -gt 0 ]] && met=true
    cap_rows+=("$(jq -cn --arg c "$cap" --argjson met "$met" --arg by "${by[*]-}" --arg wanted "$progs" --arg u "$use" --arg bad "${unusable[*]-}" \
      '{capability: $c, met: $met, by: ($by | split(" ") | map(select(. != ""))), wanted: ($wanted | split(" ")), use: $u}
       + (if $bad == "" then {} else {present_but_failed_probe: ($bad | split(" "))} end)')")
    if [[ "$met" == false ]]; then
      if [[ "${#unusable[@]}" -gt 0 ]]; then
        cap_unmet+=("$cap (${unusable[*]} is there and could not do it on a test input)")
      else
        cap_unmet+=("$cap (none of: $progs)")
      fi
    fi
  done
done

# An image that describes itself (images/install.py writes tools.md) is named
# to the swarm by that file: the contract points at it and lists no program.
tools_md=""
[[ -n "$image_file" && -f "${DFIRSWARM_TOOLS_MD:-/etc/dfirswarm/tools.md}" ]] && tools_md="/etc/dfirswarm/tools.md"

printf '%s\n' "${present[@]+"${present[@]}"}" | jq -s --arg preset "$preset" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg image "$image_ref" --argjson missing "$(printf '%s\n' "${missing[@]+"${missing[@]}"}" | jq -s '.')" \
  --argjson na "$not_applicable" --arg tools_md "$tools_md" \
  --argjson requires "$(printf '%s\n' "${cap_rows[@]+"${cap_rows[@]}"}" | jq -s '.')" \
  '{preset: $preset, checked_at: $at, present: ., missing: $missing}
   + (if ($requires | length) > 0 then {requires: $requires} else {} end)
   + (if $image == "" then {context: "host"} else {context: "image", image: $image} end)
   + (if ($na | length) > 0 then {not_applicable: $na} else {} end)
   + (if $tools_md != "" then {tools_md: $tools_md} else {} end)' > "$sandbox/toolbox.json"

if [[ "${#warn[@]}" -gt 0 ]]; then
  blocking=("${warn[@]}")
  if [[ -n "$image_file" ]]; then
    # In an image, --required means what the packs require; a preset tool
    # the image lacks is said, not fatal.
    blocking=()
    for name in "${warn[@]}"; do [[ "$pack_required" == *" $name "* ]] && blocking+=("$name"); done
  fi
  if [[ "$required" -eq 1 && "${#blocking[@]}" -gt 0 ]]; then
    echo "BLOCKER: --toolbox-required and these tools are missing: ${blocking[*]}. See toolbox.json for the install commands." >&2
    exit 3
  fi
  echo "WARN: toolbox: missing ${warn[*]} (install commands in toolbox.json)" >&2
fi
if [[ "${#cap_unmet[@]}" -gt 0 ]]; then
  where="this host"
  [[ -n "$image_file" ]] && where="the image"
  if [[ "$required" -eq 1 ]]; then
    echo "BLOCKER: --toolbox-required and the case requires what $where cannot do: ${cap_unmet[*]}. The questions that need it would close not determinable; supply a program (material add, then job_run programs) or use an image that has it." >&2
    exit 3
  fi
  for u in "${cap_unmet[@]}"; do
    echo "WARN: the case requires ${u%% *} and $where cannot do it ${u#* }. The questions that need it may close not determinable; supply a program (material add, then job_run programs), use an image that has it, or stop now." >&2
  done
fi
echo "toolbox: $(( ${#present[@]} )) present, ${#missing[@]} missing$( [[ "${#cap_rows[@]}" -gt 0 ]] && echo ", $(( ${#cap_rows[@]} - ${#cap_unmet[@]} ))/${#cap_rows[@]} required capabilities met") -> $sandbox/toolbox.json"
