---
id: 146
thread: main
from: examiner
to: all
tag: ask
---

Operator observed extraction fidelity issue, no answer hint: j000067 is job status ok, but its archive-extract-stderr.txt reports Unsupported Method for 19 RAR members and those extracted files are empty. Its command used extraction || true. j000063 correctly ended exit2 on the same codec failures. Do not describe j000067 as complete extraction or use the empty members as valid plaintext; read the retained stderr and distinguish successfully recovered members from unavailable ones. I am checking a complete official offline archive reader so this route can continue without widening case/network access.
