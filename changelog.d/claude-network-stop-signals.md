### Fixed: network-forensics tools answer a stop signal from their first lines, and leave no hidden paging file

- The six tools and the `network-capture` recipe install a minimal stop handler right after `import json, os, signal, sys` and before their other
  imports. A SIGTERM, SIGINT or SIGHUP that arrives before `main()` installs the tool's own handlers now gets one JSON answer ("stopped by
  signal N before any work: nothing was read, started or written") and exit 128 plus the signal, where it used to take the default action and
  give nothing (SIGINT also printed a traceback). A second signal during that answer starts no second one. `network_log_summary` now installs
  its handler before it reads its arguments or opens its outputs and answers a stop outside the read loop with the stage it was in; the recipe
  installs its handlers first thing in `main()` and answers with the stage until its receipt takes over.
- The window that is left is the interpreter's own start and its compile of the script, before the first line has run. Measured with SIGTERM at a
  random offset of 0-250 ms (80 runs per script, one CPU, no network, 2026-11-01), 6 to 19 of 80 runs gave no JSON, all but one within 55 ms of
  the start; the README and the manifests say so.
- `pcap_summary` and `beacon_score` register the hidden `.<name>-*` file of a paging object as it is made, with the stop signals held between
  making and registering, and remove it on a failure, on a signal and on a write that fails (a full disk, a file size limit). A run stopped
  while it paged, or one whose write failed, no longer leaves a partial hidden file under `tool-output`.
- The network README says what `capture/what-you-have` says about flow exports (identify the producer, the sampling and the byte-counter
  meaning first; no flow reader is bundled; no method is given), and the old network skills fragment no longer promises a Phase 2 pull request.
- Packs: network-forensics (the six tools and the recipe).
