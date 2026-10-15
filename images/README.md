# VM images

`--isolation microvm` boots every agent in its own microVM (microsandbox),
from an OCI image with Pi inside. Nothing of the harness is baked in, so one
image outlives any number of harness changes. The extensions, the scripts
and the prompts are a copy the kickoff takes (in the hub's directory, outside
the run), mounted read-only where the checkout is, so a `git pull` mid-run
reaches no agent. The run's packs are mounted read-only from where
`scripts/pack.sh` installed them (`$DFIRSWARM_HOME/packs/<id>`), after the
kickoff has verified each against its checksums; they are not copied. The
launcher and probe scripts are written into each VM by the SDK.

| File | What it is |
|---|---|
| `base.Dockerfile` | The agent runtime every seat boots: Node, Pi, Python with a venv at `/opt/dfir/venv` holding what the tool library imports (`library-python.txt`), and the small tools an examiner's shell has (`strings`, `hexdump`, `file`, `xxd`, `sqlite3`, `jq`, the archive tools), plus `socat` for the hub link, and `seekfix.c` preloaded (on a macOS host msb swaps `SEEK_DATA` and `SEEK_HOLE` on a mount, and GNU grep then calls a large text file binary; the shim swaps them back only where it sees the swapped answers). It records itself as a profile image does (`install.py --base`): the whole package inventory, a NOTICE, an SBOM, and that it is not for redistribution (it holds Debian's GPL programs, whose source offer is not written yet; its record and NOTICE name that as `debian-gpl-packages`). |
| `library-python.txt` | The Python packages the tool library's tools import. In the base, so a library tool handed to any run with `--tools-from` works whatever the run's packs; `tests/recipe.test.sh` keeps it in step with the tools' imports. |
| `profiles.json` | A profile is a set of packs: `disk`, `memory`, `re`, `network`, `linux`, `mobile`, `macos`, `cloud`, `triage`, `core`, `full` — and `web`, the base with Chromium, which `--playwright` boots (the browser tools drive it with this repository's Playwright, mounted read-only). `disk` holds computer-forensics-base, encrypted-containers, virtualization-backup-forensics and windows-forensics; `full` holds every pack under `packs/` (with the dependencies of each), and `tests/recipe.test.sh` fails when a pack is missing from it. `macos` (macos-forensics), `cloud` (cloud-forensics) and `triage` (triage-collection) each hold one pack and the base pack: a macOS case no longer rides the `mobile` image, and a cloud or triage case no longer rides `full` (`disk` was never involved). `re` holds the ransomware pack beside reverse-engineering. `core` holds the base pack (computer-forensics-base) and nothing else: its programs (the Sleuth Kit, plaso, dissect, bulk_extractor and the rest it names) and no other pack's; it is the image of a run whose only pack is the base pack. |
| `recipe.py` | Turns a profile's packs — every `requires/host.json` and `requires/python.txt`, with each pack's dependencies — into a Dockerfile (with a builder stage per program built from source), a spec and a NOTICE. `profile-for PACK...` names the profile that serves a run's packs, in this order: the smallest profile that holds them (they and their dependencies are among its packs; `full` holds every pack, so it is the answer for a pack no smaller profile lists); for a pack no profile lists, an installed pro or third-party one, the smallest profile whose packs name every program they name and install every library their tools import; else `full`. A pack no profile lists that names nothing the base pack does not name (stdlib Python that depends on the base pack, or a pack that names only Sleuth Kit programs) is covered by `core`; one that names a program the base pack lacks (`vol`, `tshark`, `pwsh`) goes to the smallest profile that names it, and one that needs programs only `full` has together goes to `full`, since `core` lacks them. A run with no packs, or an unlisted pack that names and depends on nothing, is `base`. Membership comes first because a pack whose tools use nothing beyond the base's is covered by every profile, and covering alone would pick one of them by chance. Of the candidates of a step the tie rule picks: `full` last, then the fewest packs, then the fewest programs the profile's packs name, then the profile's name; the order of `profiles.json` decides nothing (`tests/recipe.test.sh` shuffles it). It reads each pack where a run does: a path as given, an id from `$DFIRSWARM_HOME/packs` and then this repository, so an installed pro or third-party pack is matched by what it names. `--tools-from DIR` adds the programs a tool directory's manifests name (`requires`): among the candidates of that order, an image smaller than `full` that has them all is preferred. `check-lock FILE` refuses an images lock entry that is not pinned by digest. |
| `install.py` | Runs inside the build: installs what the spec names, fetches each pinned artefact (download, `.deb`, source, a source a builder stage compiles, or a data file a program reads) and checks its sha256, fails on a required package it cannot install and, at the end, on any program the packs name that is not on PATH, optional ones too, unless it is left out on purpose (no build for this architecture) or the build says `--allow-missing-optional` (see "Disk space"), and writes `/etc/dfirswarm/image.json` — every program it found, every package version (the image's whole Debian list and its venv too), each pack's version and seal, and what it could not install — `/etc/dfirswarm/NOTICE`, `/etc/dfirswarm/sbom.json` and `/etc/dfirswarm/tools.md`, the list an agent greps. |

## When the profiles change

What a host that built images before this change has to know:

- **New profiles.** `macos`, `cloud`, `triage` and `core` are new. A macOS case used
  to ride the `mobile` image, and cloud and triage cases rode `full`, so a
  host that built only `full` or `mobile` now has to build the profile the
  run's pack names (`python3 images/recipe.py profile-for PACK...` says
  which), or pass `--image`. A kickoff that cannot find a job image says so
  and, for a pack's jobs, runs them in the default image. `core` is the image
  of a run whose only pack is the base pack (see below).
- **A pinned lock needs the new entries.** The kickoff reads
  `.images[<profile>][<arch>]` from the lock (`SWARM_IMAGES_LOCK`, else
  `images/images.lock.json`); a profile the lock does not name is not an
  error, it falls back to the unpinned local name
  `dfirswarm-<profile>:dev-<arch>`, and `scripts/swarm.sh image-for` then
  shows `digest: null`. A lock kept elsewhere (a private build repository's
  `images.lock.json`) needs entries for `core`, `macos`, `cloud` and `triage`,
  built and pushed there, before runs of those packs are pinned again.
- **A run of several packs.** A profile is chosen because it holds the run's
  packs, not because it names the same programs. Where a smaller image used to
  serve a run by chance, `full` now does: `ransomware-response` with
  `windows-forensics`, with `encrypted-containers`, or with `memory-forensics`
  resolved to `disk`, `disk` and `memory`, and now resolve to `full`, since no
  profile but `full` holds both. The jobs of each pack still run in the
  smallest image that holds it (`re`, `disk`, `memory`); the default image,
  which holds every pack of the run, is `full`. A host that built only `disk`
  or `memory` needs `full` for those runs, or `--image`.
- **The base pack alone.** `computer-forensics-base` names the Sleuth Kit
  programs, which the `base` image lacks. A run whose only pack is the base
  pack now boots `core`, the profile of that pack alone (it was `memory`, the
  first of the six two-pack profiles in the order of the file). It is the
  smallest profile that holds the base pack: of the candidates the tie rule
  takes `full` last, then the fewest packs, then the fewest programs the
  profile's packs name, then the name, and the order of `profiles.json` decides
  nothing. A host that built `memory` and not `core` needs `core` for these
  runs, or `--image`. An unlisted pack that depends on the base pack and names
  only programs the base pack names (stdlib Python, or a pack that names only
  Sleuth Kit programs, with or without that dependency) is covered by `core`
  too. `core` lacks the programs of the other packs: a pack that names `vol`,
  `tshark` or `pwsh` goes to the smallest profile that names it, and a pack
  that needs programs no profile but `full` has together goes to `full`. A run
  with no packs at all, or an unlisted pack that names nothing and depends on
  nothing, is served by `base`.
- **The base pack in a run of several packs.** Every profile holds the base
  pack, so its jobs run in an image the run boots anyway: the one most of the
  run's packs run in, then the profile of the fewest packs, then the name. The
  set of images a run boots is the same as before for a run without a pack of
  the new profiles (the three `ransomware-response` pairs above and the base pack alone aside), but in
  some runs the base pack's jobs now run in another image of that set than
  before, where `memory` took them whenever `memory` was booted:
  linux-forensics with memory-forensics runs them in `linux`,
  memory-forensics with mobile-forensics in `mobile`, and four larger runs in
  `linux`, `re`, `re` or `mobile`. Because `disk` holds
  virtualization-backup-forensics beside its three packs, four pairs that `disk`
  used to win on the fewest packs (encrypted-containers or windows-forensics
  with reverse-engineering or ransomware-response) run the base pack's jobs in
  `re` instead. When every other pack of the run goes to
  `full`, which the base pack does not join, `core` is booted for its jobs
  (`memory` was before): the number of images does not grow.
  `tests/recipe.test.sh` pins each of these placements against a table frozen
  from before the change.

## What a run checks

- **Each VM's probe** looks for every program the run's packs require. One
  missing stops the kickoff, unless the agents may install (`--allow-install`),
  and then they are told. An image built from another version of a pack, or one
  that records no pack versions, is said and recorded (`vm/<id>.json`,
  `image_fit`).
- **One image, by digest.** The kickoff resolves the image's tag to a digest
  once (`msb image inspect`), pulling it first when this host does not have it
  — before the run's clock starts, and refused with how to build it when no
  registry has it. Every VM must boot that digest; custody names one that did
  not, and the report shows the image's own record.
- **At stop**, each VM lists what it holds that its image did not — apt
  packages against the image's whole package list, the image's venv against its
  record. Every image records both, the base included, so a fresh VM lists
  nothing. An install outside the seat's recorded toolchain is named in
  custody. The list is the guest's own report, taken by its root; the kept
  disk snapshot is the authority.

## Build your own

```bash
docker build -f images/base.Dockerfile -t dfirswarm-base:dev-arm64 images
# memory and full only: the PDBs of the curated kernels, into the host's store,
# accepting their supplier's terms (see "Symbol tables" below)
scripts/swarm.sh symbols fetch --accept-terms --accepted-by "Your Name"
python3 images/recipe.py build memory --out /tmp/img-memory --base dfirswarm-base:dev-arm64 --allow-nonredistributable
docker build -t dfirswarm-memory:dev-arm64 /tmp/img-memory
docker save dfirswarm-memory:dev-arm64 -o /tmp/memory.tar
"$(node --experimental-strip-types scripts/vm.ts msb-path)" load -i /tmp/memory.tar
```

(`amd64` on an Intel or AMD Linux host.) Check what you built from the inside:
`docker run --rm -v "$PWD/tests:/t:ro" dfirswarm-memory:dev-arm64 sh /t/image-programs.sh`
compiles a C program, finds an AES key schedule planted in random bytes (one of
them past 4 GiB) and round-trips a message through steghide, for each of those
programs the image holds; the `images` workflow runs it on every profile it
builds. The memory image downloads 840 MB of symbol tables and indexes them
once, which adds several minutes to its build; with `DFIRSWARM_DATA_DIR` (or
`--data-from DIR`, or `$DFIRSWARM_HOME/data` when it exists) naming a directory
that holds a copy, by its sha256 or its file name, a rebuild takes it from there
and downloads nothing (the copy is
bound into the build step, never copied into a layer). `--symbol-set` chooses
which symbol sets the image takes: `curated,broad` (the default), one of
them, or `none`. A kickoff with `--pack
memory-forensics` then runs its jobs in `dfirswarm-memory:dev-<arch>` on its
own, while its agents boot the base; name any other with `--image`.

**Disk space.** Docker Desktop keeps every image, layer and build cache in one
virtual disk of a fixed size, and a build needs room there beyond the image it
makes: its layers, the build cache, and what apt and pip download while it
runs. Images built on an arm64 Mac on 2026-10-01 measured 1.3 GB (the base)
to 4.8 GB (`full`), and a memory image holding Volatility's symbol tables
4.0 GB; how much more a build needs at its peak was not measured (UNKNOWN).
Look before you build:

```bash
docker system df                                              # images, build cache, what could be reclaimed
docker run --rm --entrypoint df dfirswarm-base:dev-arm64 -h /  # Avail: the free space in Docker's disk
```

(Any image you have answers the second as well: it is the same disk.) When it
is short, apt fails inside the build. That used to cost programs silently: an
optional program's builder stage recorded the failure and ended well, Docker
cached the stage as it was, and the images built after the disk was freed
lacked bulk_extractor and aeskeyfind until a `--no-cache` rebuild, saying so
only in `image.json`. Now a builder stage whose program did not build fails,
so Docker caches nothing of it, and the install fails at its end when any
program the packs name is not on PATH and was not left out on purpose (a
download with no build for this architecture, a source or a build pinned for
others). The message names each program; nothing is tagged. Free the space
and build again; no `--no-cache` is needed. `recipe.py build
--allow-missing-optional` builds an image without such programs on purpose:
`image.json` names them under `missing_allowed` and says why under
`not_installed`, `tests/image-programs.sh` skips them and says so, and its
`spec.json` and every builder stage it lets fail carry a build id of their
own. Each invocation of `recipe.py build` generates a fresh id, so a newly
generated context reruns the install and those stages. **Before retrying an
image built with this flag, run `recipe.py build` again with the same options.**
If you reuse the existing context instead, run `docker build --no-cache -t
dfirswarm-memory:dev-arm64 /tmp/img-memory`. Repeating plain `docker build`
with the same context can reuse its earlier gaps: the context's id has not
changed. The normal build without this flag fails on an unexpected absence
and can be retried with its existing context and cache.

**`--allow-nonredistributable`.** Every program in the packs is marked
`redistributable: false` until its licence has been reviewed for
redistribution (GPL, AGPL, the Volatility Software License, CPL/IPL and the
rest; the NOTICE lists each with its licence). A build that would hold one
stops without the flag. With it, the image is for this machine or a private
registry (an image that carries pinned `install.data` is for the machine that
built it alone: see below): its label, its `image.json` and its NOTICE all say
it is not for redistribution. Never push such an image anywhere public. The base is not for
redistribution either, under the same rule (`base.Dockerfile` says why), and a
profile carries its base's flag: `web`, whose packs hold nothing, builds
without the flag and is still marked not for redistribution.

**What an image says about itself.** Four files under `/etc/dfirswarm/`,
in every image:

- `image.json` — the profile, its packs with their versions and seals, every
  program found and where, what could not be installed and why (and, in an
  image built with `--allow-missing-optional`, which programs it lacks:
  `missing_allowed`), the whole Debian package list (`dpkg_all`) and the venv
  (`pip`), and whether the image may be redistributed.
- `NOTICE` — every pack program with its pack, its licence and where it came
  from; then every global npm package and every Python package in the venv
  with the licence its metadata states. Debian's packages keep theirs in
  `/usr/share/doc/<package>/copyright`.
- `sbom.json` — a CycloneDX 1.5 SBOM, written at build time from the same
  inventory: each Debian, Python and npm package with its version and package
  URL, and each pinned download with the sha256 it was checked against.
- `tools.md` — what an agent in the VM reads: one line a program, with what
  it is for in its pack's words, its pack and the version its package record
  holds; the Python libraries the packs and the tool library install, with the
  note on each; and what a pack names that the image does not hold. The run's
  contract points at this file and names no program itself.

**Not signed yet.** No image is signed, and nothing verifies a signature. A
run names its image by digest (the lock, or the tag resolved once at
kickoff) and custody says whether every VM booted that digest, which proves
the VMs ran the same image, not who built it. Signing belongs where images
are published, the private `dfirswarm-pro` repository: `cosign sign` by
digest after the push (keyless, from the workflow's identity) and `cosign
attest --type cyclonedx` with the image's own `sbom.json`. The kickoff would
then run `cosign verify` on the lock's digest before it pulls.

**Pinned artefacts.** A program no Debian package or PyPI project provides
carries what the image needs in its pack's `requires/host.json`, as data: the
harness knows the kinds, never a program. `pack.sh seal` refuses an entry
without an https URL and a whole sha256; the build refuses bytes that are not
the pinned ones and an archive that reaches outside its directory, before
anything is unpacked, installed or built.

- `install.download` — a version, and per architecture the URL, its sha256
  and the program's path inside the archive; an architecture with no entry is
  recorded as not installed. MemProcFS, avml, hayabusa (its static build: the
  glibc one needs a newer glibc than Debian 12's), velociraptor, uac and
  PowerShell come this way. A `.deb` is handed to apt from where it was
  checked, so what it depends on comes from Debian: radare2 (upstream's
  package per architecture) and Zeek (the Zeek project's own `zeek-8.0-core`
  for Debian 12; `bin` names where the package puts it, `/opt/zeek/bin`).
- `run` — the interpreter a program needs: `python`, or a program the image
  holds. Eric Zimmerman's MFTECmd, EvtxECmd and RECmd are their net9 zips,
  one for every architecture, each run by `dotnet`, which the same pack pins
  as a download of its own (the .NET 9 runtime per architecture): a runtime
  is installed once, before what runs on it.
- `install.source` — one archive for every architecture, a tag's tarball,
  unpacked under `/opt/dfir/src/<name>` without its top directory, less the
  paths in `skip`; `pip` is run there in a venv of its own
  (`/opt/dfir/src/<name>/.venv`), so one program's pins (ALEAPP's
  beautifulsoup4 4.8.2, iLEAPP's numpy 1.26.4) never move another's or the
  tool library's; `entry` goes on PATH as the pack names the program, run
  with the checkout on `PYTHONPATH`, as from a clone. Zircolite, mac_apt,
  UnifiedLogReader, iLEAPP and ALEAPP come this way; `build_deps` are there
  for the build only, `apt_deps` stay. `env` is the environment of its pip:
  mac_apt pins pytsk3 20230125, an sdist whose bundled Sleuth Kit finds the
  libbfio headers the image has for libewf and is then built against libbfio
  without being linked to it, so it would not import; its pack sets
  `ac_cv_header_libbfio_h=no` and the build leaves libbfio out. `arches`
  names the architectures a source is for: mac_apt 1.33.2 looks its statx
  syscall up by `platform.machine()` and knows `arm64` (macOS's name) but
  not `aarch64` (Linux's), so it stops at import on Linux arm64; its packs
  pin it for amd64, and an arm64 image records it as not installed, with why.
- `install.build` — a source archive compiled in a builder stage of its own
  (`./configure --prefix=/opt/dfir/tools/<name>`, `make`, `make
  install-strip`), from the same base; only the prefix is copied into the
  image, so the compiler and the `-dev` packages are not in it, and every
  profile that builds the program shares the stage's cache; `env` is the
  environment of its configure and make. A build that
  fails is recorded beside what it left and fails its stage, optional or not
  (see "Disk space"); one pinned for other architectures (`arches`) ends its
  stage well, recorded as not built here. bulk_extractor (not packaged for Debian 12) comes
  this way. A source with no configure script names its own steps
  (`commands`, each an argument list run in the unpacked tree, with `{prefix}`
  and `{jobs}` filled in) and may be patched first (`patches`, each a url and
  a sha256, applied in order with `patch -p1`): aeskeyfind, which Debian
  packages for amd64 and i386 only, is Debian's pinned upstream tarball and
  Debian's four pinned patches (files over 4 GB among them), built with `make`
  on every architecture.
- `install.data` — a file a program reads and that is not a program: a
  symbol pack, a rule set. One entry, a list of them, or `{"list": FILE}`: a
  file of the pack holding a `template` (an entry with `{field}` placeholders)
  and `entries` (one object of fields each), expanded entry by entry, so a
  curated list carries identities and hashes and no copy of the same install
  steps. One url, its sha256 and its size (`bytes`, a download stops past it) for every architecture, put
  under the name it has at its url (or `file`) in `into` inside the directory
  of a Python package of the image's venv (`package`), where the program looks
  for it. `warm` is a command run once the file is there, for a program that
  indexes what it finds the first time it runs and would otherwise do it in
  every VM the image boots; a warm that fails is recorded (`warm: failed` in
  `image.json`) and does not lose the file. `check` is a command that must
  succeed once the file is there (the program finds it): a build whose check
  fails does not keep the file, and the images workflow runs every data
  entry's check again with no network. The entry says whether it is
  `redistributable` (the image is not, when either it or its program is not)
  and carries its own `licence`, which goes in the NOTICE beside the program's.
  It hangs from a program's entry and is its own record in `image.json`
  (`downloads`, kind `data`), in the SBOM as a `data` component, and in
  `tools.md` under "Data the programs read". A pinned data file that cannot be
  fetched **fails the build even when its program is optional**: the pack
  pinned it on purpose, and an image without it would say the program is there
  while what it reads is not. `recipe.py build --allow-missing-data` goes on
  without it; the image then records it under `not_installed.data`, and a
  kickoff says so as a WARN. An entry may name a `set`; `recipe.py build
  --symbol-set` leaves out the sets it does not name, and the image records
  each under `omitted.data`, apart from a failure (a kickoff says that too).
  An entry with `commands` is a source the build turns into what the program
  reads: fetched into a work directory, each command run (an argument list,
  `{file}` the source, `{dir}` where the program looks), every file in
  `outputs` then required, hashed and, with `canonical`, compared by its
  content with the pinned `canonical_sha256` (json-canon/1, below); `converter`
  pins the version of the package that converts, `keep: false` drops the
  source. An entry with `acquire: "operator"` is never fetched by the build:
  it comes from the operator's store (`--symbols-from`) with the operator's
  recorded acceptance of its terms, or the build stops before Docker. The
  record keeps source and outputs apart: `source` (url, sha256, bytes, where
  it came from), `transform` (the commands, the converter, the package's and
  Python's versions), `outputs` (path, sha256, bytes, content hash and rule,
  identity), `distribution_policy`, `acceptance`. Volatility's Windows symbol
  tables come this way (next section).
- An apt line with `-t bookworm-backports` takes its package from the image's
  own Debian backports, added from the mirror the image already uses and from
  nowhere else: Suricata.
- `not_in_image` (with why) — a program that belongs to another system:
  Apple's `log` (macOS only; UnifiedLogReader.py reads the same archives in
  the image) and CyLR (a collector, run on the host being collected). It is
  listed under `not_applicable` in `image.json` and the NOTICE, and a VM's
  toolbox check lists it there too, never as missing; a pack may not require
  one.

Every pinned artefact is in `image.json` (`downloads`, each with its kind,
version, URL and sha256), the NOTICE and the SBOM; a source's own venv is
listed there package by package with its licences. A program that nothing
above installs is listed under `not_installed.manual`; no profile has one
today.

## Volatility, its symbol tables, and what is not redistributed

Volatility 3 helps a memory examination a great deal, and its licence (the
Volatility Software License 1.0) does not let this project distribute it with
its work. So we do not: the memory and `full` images hold it because their
build installs it (`pip install volatility3==2.28.2`, `packs/memory-forensics`,
pinned because a table's content hash holds for one converter version), the
image that results is built by whoever runs it, and its label, `image.json`
and NOTICE say it is not for redistribution. **No image that carries
`install.data` (the Volatility symbol tables) is pushed from any workflow of
ours, the pro one included**: we never distribute Volatility or its data,
whoever runs the images builds their own, and Pro builds those per customer
(the roadmap's "Images for programs we cannot redistribute"). The `images`
workflow builds and boots, never pushes. Each data entry says
`distribution_policy: "local-only"`, and the image's label
`dev.dfirswarm.data` names what it carries, so a pusher can refuse it by
inspecting the image. A label is not a legal clearance.

### Symbol tables

A Windows plugin needs the symbol table of the exact kernel it reads, and
Volatility would fetch the PDB from Microsoft the first time it sees a kernel:
not in a VM with no network, and never by a seat. The memory and `full` images
carry two sets, pinned in the memory pack (`install.data` of `vol`):

- **curated**: the exact kernels `packs/memory-forensics/requires/symbols.windows.json`
  lists. Each entry is a public identity (PDB name, GUID, age) with the PDB's
  sha256 and size, the content hash the table converted from it must have, the
  converter version that hash holds for, and a note: identifiers and hashes,
  no Microsoft file. Acquisition is two steps, the first the operator's own:
  1. `scripts/swarm.sh symbols fetch --accept-terms --accepted-by NAME [--from DIR]`
     puts each PDB into the host's store,
     `$DFIRSWARM_HOME/symbols/blobs/sha256/<sha256>` (refused inside a synced
     folder), held to its pinned sha256 and size, and writes into the store's
     `manifest.json` who accepted Microsoft's symbol-server terms, when, for
     which bytes, and how: whether a terminal was on both ends (`attended`),
     the account, the host, the command. Every earlier acceptance is kept
     beside the current one, and each is a line of `fetched.jsonl`. Without
     `--accept-terms` and `--accepted-by` it refuses; nothing stands in for
     the name. `--from DIR` takes a copy you already hold;
     without it each is downloaded from `msdl.microsoft.com`, HTTPS on every
     hop, at most two redirects and only to `*.blob.core.windows.net` (the
     signed address is never logged), no more bytes than pinned, within about
     ten minutes (600 s, plus one read's socket timeout).
  2. `recipe.py build` reads the store (`--symbols-from`, by default
     `$DFIRSWARM_HOME/symbols`) and stops before Docker when a curated PDB, or
     the acceptance of its terms, is not there, and when the acceptance was
     unattended (a process's, not a person's at a terminal) unless
     `--allow-unattended-acceptance`; it prints the acceptance it bakes. The
     context then holds a copy of the PDB under `data/` (bound into the build,
     never in a layer): `--out` is refused inside a synced folder or a git
     checkout, and `data/` is removed once the image is built. The build converts each PDB
     with Volatility's own `pdbconv` inside the image, with no network, checks
     the table's content against the pinned hash, puts it where Volatility
     looks (`…/volatility3/symbols/windows/<pdb>/<GUID>-<age>.json.xz`),
     checks that `vol -q isfinfo` lists exactly one table with that identity
     (Volatility reads the last one its index finds when there are several, in
     no fixed order, so a second table from a broad set fails the build), and
     drops the PDB. `image.json` records the source, the transform, the table
     (its bytes' sha256, its content hash, its identity) and the acceptance.
  A table's bytes change at every conversion (`pdbconv` writes the time it ran
  into `metadata.producer.datetime`), so the pin is on its content:
  **json-canon/1** decompresses it (xz or gzip), parses the JSON refusing a
  duplicate key and a non-finite number, removes the paths the pin names (that
  one field) and hashes `json.dumps(sort_keys=True, ensure_ascii=True)` with
  the default separators, UTF-8, no trailing newline (`images/install.py`,
  `canonical_sha256`). A kernel a case needs is one more entry in the list.
- **broad**: the Volatility Foundation's `windows.zip` from
  `downloads.volatilityfoundation.org`, a bundle of 2019 (last changed
  2019-10-16), 839,727,133 bytes; `vol -q isfinfo` reports 3,014 tables from
  it (the arm64 build of 2026-10-01). The
  build checks its sha256 (the one the Foundation publishes in its
  `SHA256SUMS`), puts it as named in the venv's `volatility3/symbols/` and
  lists it once (`vol -q isfinfo`). Volatility indexes every table it finds
  the first time it runs, which took 3 minutes 22 seconds for this pack on a
  fast machine and would be repeated in every VM; the index is built at image
  build time and a fresh container lists the pack in well under a second; in
  a worker VM, whose `HOME` is `/root`, the index the build left is found and
  `vol -q isfinfo` answers in 0.2 seconds (measured 2026-10-01). It covers the
  Windows builds of 2019 and earlier, not every one of them.

`recipe.py build --symbol-set` chooses: `curated,broad` by default, either one,
or `none`. A set left out is recorded as omitted (`image.json` `omitted.data`,
`tools.md`), never as a failure, and a kickoff says so. CI never fetches a
Microsoft PDB and never builds the curated set: a pull request builds with
`none` and checks the omission, the weekly boot with `broad`; the curated
path, the canonical hash and the refusals are tested with small synthetic
fixtures (`tests/recipe.test.sh`, `tests/symbols.test.sh`).

**A kernel the image lacks.** The base pack's `memory-windows` recipe asks
Volatility, offline, at the census's detect, about each memory input; when the
image holds no table for its kernel it names the kernel (the PDB, GUID and age
Volatility's automagic asked for), and when its probe does not answer within
`RECIPE_PROBE_SECONDS` (30 s; `SWARM_CATALOG_MEMORY_PROBE_TIMEOUT`) it says
that whether the table is held is unknown. The verdict is about the image the
census ran in, which the start names; with one memory pack that is the image
its jobs run in. With `--catalog`, a
table the image lacks is written to `catalog/missing.json`, said in the
catalogue's README, and is a BLOCKER at `start --check` (which runs the
census's detect in a throwaway VM) and at the start, unless
`--allow-missing-symbols`: the run then goes on with what needs no kernel
table (strings, YARA, carving), and every seat reads what is missing. A seat
fetches nothing: a run under the CTF case policy grants no sockets, and
[ADR 0012](../docs/adr/0012-a-dynamic-network-decided-by-rules-and-made-on-the-host.md)
has the operator's rules decide what a run may reach. It closes a lead
`needs_operator` naming the PDB, the GUID and the age; the operator adds the
kernel to the curated list and rebuilds, or makes the table and supplies it
to the run (`swarm.sh tool-supply <run> add <dir> --source …`), and the seat
points Volatility at it with `-s`.

**Their licences, in the NOTICE.** Our reading, not legal advice. Each data
entry's NOTICE lines name its supplier, source, terms, derivation and
restriction. The Volatility Software License 1.0
(<https://www.volatilityfoundation.org/license/vsl-v1.0>) says its "Software"
includes "any data (such as operating system profiles or configuration
information)" provided with the software, and we read the Foundation's tables
as such data. Every table, the Foundation's and ours, is generated from
Microsoft's public symbol files, whose Microsoft Symbol Server licence terms of
June 2022
(<https://learn.microsoft.com/en-us/legal/windows-sdk/microsoft-symbol-server-license-terms>)
allow use "solely for purposes of performance, security or functional
debugging and testing of your software as used with Microsoft software, or as
otherwise authorized by Microsoft" and say you may not "share, publish, rent,
or lease the Symbol Items, or provide the Symbol Items as stand-alone
offerings for others to use". Microsoft's terms grant use for debugging and
testing your software; whether examining a third party's memory image falls
inside that is not decided here. The NOTICE of the image has both clauses in
full.

Other small programs the packs now name, for what a run asked for and no image
had: `steghide` (the base pack, so in every image), `aeskeyfind` (memory),
`gcc` and `make` (memory and re: a C scanner over a memory image Python cannot
hold, a decoder for a format no library reads; the compiler stays in the image,
unlike the one a pip build installs and removes), and Pillow (the base pack's
`requires/python.txt`). Left out on purpose: wordlist front ends for
steganography, ImageMagick, ffmpeg and OpenCV (large, with
codecs and delegates and a policy of their own), and anything that reads
credential artefacts out of Windows memory, which is decided separately.

## Prebuilt images

The pro edition's prebuilt, digest-pinned images are built in the private
`dfirswarm-pro` repository and pushed there as private packages: an image
bundles separately licensed programs, and a package published from this
public repository is public. **Not the images that carry `install.data`** (the
memory and `full` images, with Volatility's symbol tables): none of our
workflows pushes those, the pro one included, since a private registry still
copies the tables to GitHub and to every customer who pulls; Pro builds them
per customer, under the customer's own acceptance of the licences. A workflow
that publishes images checks that `spec.json` of the build context lists no
`data` before it pushes, and builds no profile that does. Point a kickoff at a
lock file:

```bash
SWARM_IMAGES_LOCK=/path/to/dfirswarm-pro/images.lock.json scripts/swarm.sh start --isolation microvm ...
```

Check a lock before pointing a run at it: `python3 images/recipe.py check-lock
/path/to/images.lock.json` refuses an entry that is not `name@sha256:` and 64
hex digits, since a tag can move under a run and a digest cannot. The kickoff
reads `.images[<profile>][<arch>]` from the lock and boots what it names.

A private image needs a registry login first (`msb registry login ghcr.io -u <user> --password-stdin`
on a desktop with a keychain; `docker login ghcr.io` on a server, whose
credentials msb reads).

## No network

An examiner's machine with no route out can still run VMs, once the image is
on it: `msb save <ref> -o image.tar` (or `docker save`) on a machine that has
it, carry the file across, `msb load -i image.tar`, and start with `--image
<ref>`. The kickoff then finds the image and pulls nothing. Two things still
want the network: the Windows symbol table of a kernel neither the curated list
nor the 2019 bundle holds (fetch its PDB on a connected machine, carry it across,
`swarm.sh symbols fetch --from DIR --accept-terms`, and rebuild; or make the
table there and supply it to the run) and capa's rules (`capa --rules` with a
directory you carried across). A rebuild on a machine with no route out takes
the Foundation's bundle from `DFIRSWARM_DATA_DIR`. A model the run calls has to be reachable too, or local
(`--local-only`).
