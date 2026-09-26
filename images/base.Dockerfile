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
FROM debian:bookworm-slim AS seekfix
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
COPY seekfix.c /src/seekfix.c
RUN gcc -O2 -Wall -Wextra -Werror -shared -fPIC -o /seekfix.so /src/seekfix.c -ldl

FROM node:24-bookworm-slim

ARG PI_VERSION=0.87.0
RUN npm install -g --no-audit --no-fund "@earendil-works/pi-coding-agent@${PI_VERSION}" \
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
# packs' programs follow too (images/README.md): the venv holds dissect.util,
# which is AGPL-3.0, and Debian's GPL programs want a written source offer.
# Every profile built on this image carries the flag on (install.py).
ARG REDISTRIBUTABLE=false
ARG NONREDISTRIBUTABLE="dissect.util"

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
      dev.dfirswarm.redistributable="${REDISTRIBUTABLE}"
