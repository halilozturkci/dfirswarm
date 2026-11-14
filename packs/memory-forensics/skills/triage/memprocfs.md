---
id: triage/memprocfs
title: MemProcFS and its FUSE prerequisite
when: You will read an image as a MemProcFS tree, or a mount failed or is in doubt.
needs: []
card: vol_readiness {"views": ["fuse"]} says whether /dev/fuse and a fusermount helper are there: blocked is the host's lack, not a finding about the image; mem_fs answers it as no_fuse and starts nothing. mem_fs passes MemProcFS no flag for symbols, caches or forensic mode. List first ({"mode": "list"}) and cite the MemProcFS version with the paths. A mount that came up shows the engine started, not that the image was read whole. A cleanup problem means the mount may remain: report it and do not read the tree again. Does not show: that a missing path means the object is absent.
tools: [mem_fs, vol_readiness]
requires_host: [memprocfs]
---

Use when you plan to read an image with `mem_fs`, or a MemProcFS call failed. Not for the lifecycle, the export and the preservation of a region (`processes/preserve-regions`) or for choosing plugins (`triage/volatility`).

**What it needs.** The pack pins MemProcFS 5.18.11 (the `memprocfs` binary, `requires/host.json`, with `libfuse2`, `liblz4-1` and `libusb-1.0-0`). A mount also needs a `/dev/fuse` the process can open and a `fusermount3` or `fusermount` helper: the image build installs only the library, so a host may lack them. `vol_readiness` (view `fuse`) says whether they are there: `blocked` is a lack of the host, not a finding about the image. `mem_fs` answers the same lack as a `no_fuse` object (`blocked_by`, `what_to_do`) and starts nothing.

**Configuration.** `mem_fs` passes MemProcFS no flag about symbols, caches or its forensic mode, so none is used. Whether MemProcFS contacts a symbol server is governed by the job's network policy, and the pinned binary's behaviour in that respect was not verified. Say which MemProcFS version and which virtual paths a listing showed (`list` first): the paths depend on the version and the image.

**Readiness is not completion.** A mount that came up shows the engine started; it does not show that the image was read whole, that a page was resident or that a listing is complete. A failed clean-up (an engine that cannot be ended, an unmount helper that does not answer) is a named `cleanup` problem in the answer and the mount may remain: report it and do not read the tree again.

**Shows.** Whether the host can mount at all, and which MemProcFS built the paths you cite.

**Does not show.** That a mounted tree is a whole process or a whole image; that a missing path means the object is absent.

Record: the MemProcFS version, the image's hash, the paths listed, the `vol_readiness` fuse verdict and any `cleanup` problem.
Sensitive output: `mem_fs` text and export write memory content: run them as jobs with `secret_output: true` and `write_values` (`processes/preserve-regions` says how); a name that matters is read the same way.
