#!/usr/bin/env bash
# Move the Debian snapshot date the images install from, and with --digests the
# two base image digests, and change nothing else.
#
#   scripts/apt-snapshot-bump.sh [TIMESTAMP] [--digests] [--root DIR]
#
# TIMESTAMP is a snapshot.debian.org timestamp (YYYYMMDDTHHMMSSZ); without one
# it is today, 00:00:00 UTC. The date is in images/debian-snapshot and in the
# `ARG APT_SNAPSHOT=` line of images/base.Dockerfile (the build refuses a
# mismatch). --digests also rewrites the `@sha256:` of the two FROM lines to the
# multi-arch index digest of the tag on that line, read with
# `docker buildx imagetools inspect`, which reads the manifest and no layers.
# --root DIR works on a copy of the repository (the tests do).
# $APT_SNAPSHOT_INSPECT, when set, is the command that prints that inspect
# output for a reference (the tests give it a stand-in).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stamp=""
digests=0
while [ $# -gt 0 ]; do
  case "$1" in
    --digests) digests=1 ;;
    --root) shift; root="$(cd "$1" && pwd)" ;;
    -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) stamp="$1" ;;
  esac
  shift
done
[ -n "$stamp" ] || stamp="$(date -u +%Y%m%dT000000Z)"
if ! printf '%s' "$stamp" | grep -Eq '^[0-9]{8}T[0-9]{6}Z$'; then
  echo "not a snapshot timestamp (YYYYMMDDTHHMMSSZ): $stamp" >&2
  exit 2
fi

file="$root/images/debian-snapshot"
dockerfile="$root/images/base.Dockerfile"
[ -f "$file" ] && [ -f "$dockerfile" ] || { echo "no images/debian-snapshot or images/base.Dockerfile under $root" >&2; exit 1; }

printf '%s\n' "$stamp" > "$file"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed "s/^ARG APT_SNAPSHOT=.*/ARG APT_SNAPSHOT=$stamp/" "$dockerfile" > "$tmp"
cat "$tmp" > "$dockerfile"
grep -q "^ARG APT_SNAPSHOT=$stamp\$" "$dockerfile" || { echo "images/base.Dockerfile has no ARG APT_SNAPSHOT= line" >&2; exit 1; }

if [ "$digests" = 1 ]; then
  inspect() { # <ref>: the multi-arch index digest
    if [ -n "${APT_SNAPSHOT_INSPECT:-}" ]; then $APT_SNAPSHOT_INSPECT "$1"; else docker buildx imagetools inspect "$1"; fi \
      | awk '/^Digest:/ { print $2; exit }'
  }
  for tag in debian:bookworm-slim node:24-bookworm-slim; do
    d="$(inspect "$tag")"
    printf '%s' "$d" | grep -Eq '^sha256:[0-9a-f]{64}$' || { echo "could not read the digest of $tag (got: ${d:-nothing})" >&2; exit 1; }
    sed "s#^\(FROM $tag\)@sha256:[0-9a-f]\{64\}#\1@$d#" "$dockerfile" > "$tmp"
    cat "$tmp" > "$dockerfile"
    grep -q "^FROM $tag@$d" "$dockerfile" || { echo "images/base.Dockerfile has no FROM $tag@sha256:... line" >&2; exit 1; }
  done
fi
echo "snapshot date: $stamp"
