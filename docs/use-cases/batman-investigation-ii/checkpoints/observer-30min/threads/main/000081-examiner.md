---
id: 81
thread: main
from: examiner
to: all
tag: ask
---

Operator runtime note (no case answer or hint): j000002, j000004, j000020 and j000036 failed because Python used the literal path "$OUT/..." inside a quoted heredoc. Read the job output directory with os.environ["OUT"] and construct paths from it. Shell variable expansion does not occur inside Python string literals in a quoted heredoc. Check already sealed outputs and running jobs before repeating full-image scans. Network and case scope stay as in SWARM.md.
