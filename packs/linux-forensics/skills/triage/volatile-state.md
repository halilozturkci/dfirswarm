---
id: triage/volatile-state
title: What each kind of acquisition holds
when: Saying what a disk, collection, /proc, memory or live output can show.
needs: []
card: linux_triage {"source": "<image or extracted root>", "out_dir": "work/<your id>/<name>"} runs no command on the target and reports no running state; execution_complete is not coverage. Say which acquisition each statement rests on: a disk image holds no process list, sockets or mounts; a collection holds what its collector chose; a captured /proc is not one instant; saved live output is a collector's view. Does not show: that a process or connection was absent, or that a command output is true.
tools: [linux_triage]
requires_host: []
---

Use when you decide what a Linux acquisition can say about running state. Not for choosing parsers on a disk image (`triage/system-profile`) or for memory analysis itself (the memory pack, when it is loaded).

Five kinds of acquisition hold different state, and one source never stands in for another:
- a disk image or copy holds files: configuration, logs, binaries, and the data of processes only where they wrote it (swap, hibernation, core dumps, temporary files). It holds no process list, no open sockets and no mounts as they were;
- a logical collection (a triage package) holds the files and command outputs its collector chose, as of when it ran; what it left out is not shown to be absent. Read the collection's own manifest before its files;
- a captured `/proc` or `/sys` tree is a copy of the kernel's view at the moment of copying, taken a file at a time, so it is not one instant. Many entries are empty or unreadable to an unprivileged copy, and a process that ended during the copy is a partial directory;
- a memory image holds what was in RAM at its time, which the disk lacks, and it needs its own analysis (the memory pack, named only when it is loaded; its triage notes say what an image holds);
- live command output (`ps`, `ss`, `mount`, `lsof` saved to a file) is the examiner's or the collector's view on a machine that may be compromised, as of the time and shell it ran in, and it can be changed by a rootkit or by the collector's own account.

Interpret only the acquisitions you were supplied, and say which of the five each statement rests on. State what disappeared: a power-off or reboot ended the processes, sockets, caches, `tmpfs` contents and the cleared `/run`, so their absence from a disk image is expected and shows nothing. `linux_triage` reads disk images, partitions and extracted trees through dissect.target; it runs no command on the target and does not report running state, and its `execution_complete` says processes exited 0, which is not coverage. If a collection names a tool's output as the source for a process or network claim, cite that file and its time.

Shows: which kinds of state each supplied source can hold. Does not show: that a process or connection was not there because a disk lacks it, or that a command output is true of the machine it came from. Record: each acquisition, its kind, the time it was taken, what it omitted, and the claims each supports.

Sensitive output: process arguments and environments in a collection can hold secrets. Keep `linux_triage` in a `secret_output` job when you read them; cite the file and line, never a value or a hash of it.
