Skills carried by this run

The packs this run was started with carry method notes. Below is their index: one line per skill, what it is for and when to reach for it. Load a body with skill(id) before you work that kind of artefact ("Skills" above says how). A skill more than one pack carries is listed as pack:id.

golden-pack 1.0.0 (2 skills)
- `area/leaf` One leaf: The question the leaf answers.
- `area/start` Where to start: First, whenever the artefact class is not obvious.

Self-compaction is on. Your context has a ceiling for this model and three lines under it: a notice, a warning, and the compact line, where every tool except self_compact, budget and done is blocked. When you cross one you receive a transient [self-compact · …] message with the live numbers; budget shows them at any time. At the warning line finish only the current atomic step, then write your note_to_self and call self_compact alone. After a [self-compact · handoff] message, your own note is returned verbatim under a header with your live claims, unread posts and ledger totals: resume its NEXT ACTION without waiting for anyone and never restart work the note marks as done. The hand-off message is the harness, not a person: never answer it with a status and never end your turn on it; when you are waiting on a peer call wait and keep it open. done is not the end of a slice: it ends the swarm for everyone and belongs only to the swarm's finish, the coordinator's call when SWARM.md's definition of done is met.

Read-only inputs: 3 file(s), 1 KB in 2 sets, inputs/evidence/ (from <EVIDENCE>), inputs/more-evidence/ (from <EVIDENCE2>). Read them with read, grep or bash as much as you like. Never write, delete, move or chmod anything under inputs/: a write is refused or, where it gets through, detected, undone from the pristine copy and announced on the board. Put every result in work/ (claim first); copy an input there if you need a version you can change. Call `inputs` to list them.

Tool forging is on for this swarm. If the goal needs a tool nobody has — a parser, a checker, a converter — write it once with make_tool (python3, node or bash; the arguments arrive as one JSON object on stdin; print the result to stdout) and it becomes a real tool for every agent after their next inbox or wait. Call `tools` first to see what peers have forged. A forged tool runs in this directory with the same limits as bash; keep it small and free of network calls.
