### Changed: the network-forensics README names what the shared process block leaves open

The four network carriers that start an engine (`zeek_run`, `suricata_run`, `pcap_extract` and the `network-capture` recipe) hold the one shared process text, unchanged and pinned by `tests/pack-shared-process.test.ts`. The pack's README now says once, in the words of that block's header, what the block still leaves open after the sweep: a process id reused between the identity check and the signal, a tree that cannot be listed, macOS (libproc not run on macOS here, a daemon that holds the pipes of a finished program not found), the Linux rule that also ends a process of the tool's group that holds one of its pipes, and a tool killed with SIGKILL between the stop of the tree and the kill. No tool changed.

Pack network-forensics.
