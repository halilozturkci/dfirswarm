# The agent image the harness boots for every seat: an agent runtime and
# nothing case-specific. Profile images (disk, memory, re, ...) are generated
# from the packs by images/recipe.py and build on this one.
#
#   docker build -f images/base.Dockerfile -t dfirswarm-base:dev-arm64 images
#   docker save dfirswarm-base:dev-arm64 | msb load
#
# (dev-<arch>: dev-arm64 on Apple silicon, dev-amd64 elsewhere, the tag the
# kickoff looks for when no lock file names a digest.)
#
# The harness's own code (extensions, prompts, pack skills and tools) is not
# baked in: it is mounted read-only from the host at boot, where the guest's
# root cannot change it, and the launcher that starts Pi comes with the
# harness too (scripts/vm.ts), so an image outlives any number of harness
# changes.
# seekfix (images/seekfix.c): SEEK_DATA and SEEK_HOLE on a virtiofs mount as
# Linux means them. msb on a macOS host swaps the two, and GNU grep then calls
# every mounted text file past its first buffer "binary".
#
# Every apt install, here and in every profile image built on this one, comes
# from snapshot.debian.org at one date, the one in images/debian-snapshot (the
# ARG below repeats it; the build refuses a mismatch, and
# scripts/apt-snapshot-bump.sh moves both). The base images are pinned to
# their digests, the tag kept beside each for the reader. Both move on
# purpose: the date by a monthly pull request (.github/workflows/apt-snapshot.yml),
# the digests by scripts/apt-snapshot-bump.sh --digests.
ARG APT_SNAPSHOT=20261030T000000Z
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS seekfix
ARG APT_SNAPSHOT
COPY debian-snapshot /tmp/debian-snapshot
RUN set -eu; d="$(tr -d '[:space:]' < /tmp/debian-snapshot)"; rm /tmp/debian-snapshot; \
    [ "$d" = "$APT_SNAPSHOT" ] || { echo "images/debian-snapshot ($d) and the ARG ($APT_SNAPSHOT) differ" >&2; exit 1; }; \
    printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s/\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "$d" "$d" > /etc/apt/sources.list.d/debian.sources; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99snapshot
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
COPY seekfix.c /src/seekfix.c
RUN gcc -O2 -Wall -Wextra -Werror -shared -fPIC -o /seekfix.so /src/seekfix.c -ldl

FROM node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c
ARG APT_SNAPSHOT
COPY debian-snapshot /tmp/debian-snapshot
RUN set -eu; d="$(tr -d '[:space:]' < /tmp/debian-snapshot)"; rm /tmp/debian-snapshot; \
    [ "$d" = "$APT_SNAPSHOT" ] || { echo "images/debian-snapshot ($d) and the ARG ($APT_SNAPSHOT) differ" >&2; exit 1; }; \
    printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/%s/\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/%s/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' "$d" "$d" > /etc/apt/sources.list.d/debian.sources; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99snapshot

ARG PI_VERSION=1.4.0
# Pi is installed as a project in /opt/pi, not globally, so that its undici can be
# overridden: Pi's own release still pins undici 8.10.2, which has
# GHSA-xjj6-f33q-929c, GHSA-4qv8-2p9j-2685 and GHSA-f72v-6w45-q472, and Pi talks
# to the model endpoints through it. The override is the repository's own
# (package.json), and install.py --base fails the build if any undici under Pi
# is older than 8.12.2. `pi` is linked onto PATH. When Pi's release moves its
# own pin past 8.12.2, drop the override.
RUN mkdir -p /opt/pi \
 && printf '{"name":"dfirswarm-pi","private":true,"dependencies":{"@earendil-works/pi-coding-agent":"%s"},"overrides":{"undici":"^8.12.2"}}\n' "${PI_VERSION}" > /opt/pi/package.json \
 && cd /opt/pi \
 && npm install --omit=dev --no-audit --no-fund \
 && ln -s /opt/pi/node_modules/.bin/pi /usr/local/bin/pi \
 && npm cache clean --force

# What every seat uses whatever the case: Python with venv for the pack
# tools, the small utilities an examiner's shell has and the prompts assume
# (strings, hexdump, the archive tools, ripgrep, which the agents reached for
# in their own VMs on two rounds and did not find), and socat, which bridges
# the hub's vsock port to the Unix socket the extension dials.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates python3 python3-venv python3-pip jq sqlite3 file xxd socat procps \
      binutils bsdextrautils less unzip p7zip-full xz-utils bzip2 zstd curl libimage-exiftool-perl ripgrep \
 && rm -rf /var/lib/apt/lists/*

# Not for redistribution until its licences have been reviewed, the rule the
# packs' programs follow too (images/README.md): Debian's GPL programs want a
# written source offer, and none is written yet. NONREDISTRIBUTABLE names what
# holds the image back, in its record and its NOTICE; every profile built on
# this image carries both on (install.py). (The venv's dissect.util is
# Apache-2.0 from 3.5, the floor library-python.txt pins.)
ARG REDISTRIBUTABLE=false
ARG NONREDISTRIBUTABLE="debian-gpl-packages"

# The tool library's Python imports, in a venv every profile builds on: a
# library tool reaches a run through --tools-from whatever its packs, so a
# tool that imports regipy must not work only in the disk image.
#
# Then the record, taken last, in the fields a profile image has: the whole
# Debian package list and the venv (what a VM holds at stop is diffed against
# them, so the image's own packages are never "installed outside the image"),
# /etc/dfirswarm/NOTICE and the SBOM, /etc/dfirswarm/sbom.json.
COPY library-python.txt install.py /tmp/dfirswarm-build/
RUN python3 -m venv /opt/dfir/venv \
 && /opt/dfir/venv/bin/pip install --no-cache-dir -r /tmp/dfirswarm-build/library-python.txt \
 && REDISTRIBUTABLE="$REDISTRIBUTABLE" NONREDISTRIBUTABLE="$NONREDISTRIBUTABLE" PI_VERSION="$PI_VERSION" \
      python3 /tmp/dfirswarm-build/install.py --base \
 && rm -rf /tmp/dfirswarm-build
ENV PATH=/opt/dfir/venv/bin:$PATH

# Preloaded into every process; it acts only on a FUSE file whose server
# answers SEEK_DATA and SEEK_HOLE the macOS way round.
COPY --from=seekfix /seekfix.so /usr/local/lib/dfirswarm/seekfix.so
RUN echo /usr/local/lib/dfirswarm/seekfix.so > /etc/ld.so.preload

# No image-wide licence label: an image is an aggregate of separately
# licensed programs, and each keeps its own (/etc/dfirswarm/NOTICE). The
# redistributable label is the same one a profile image carries; a profile
# whose packs hold nothing marked otherwise inherits this one.
LABEL org.opencontainers.image.title="dfirswarm-base" \
      org.opencontainers.image.source="https://github.com/halilozturkci/dfirswarm" \
      dev.dfirswarm.profile="base" \
      dev.dfirswarm.pi-version="${PI_VERSION}" \
      dev.dfirswarm.apt-snapshot="${APT_SNAPSHOT}" \
      dev.dfirswarm.redistributable="${REDISTRIBUTABLE}"
