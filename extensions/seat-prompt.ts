/**
 * The lines of a seat's prompt that hold for the whole run, written once.
 *
 * The prompt `before_agent_start` forces lasts for the run a user prompt
 * starts. The run a self-compact hand-off starts is begun by a custom message,
 * has no `before_agent_start`, and goes back to Pi's own prompt sections
 * (tests/skills-e2e.test.ts shows the requests through the real CLI). A line
 * that only the forced prompt carried was therefore gone from every request
 * after the first hand-off: the seat's id, the stop rule, the read-only inputs
 * rule, the forging rule, the self-compaction mechanics.
 *
 * What does not change during a run is written by the kickoff
 * (scripts/seat-prompt.ts) to two files Pi appends to its own prompt sections,
 * which every run keeps: `.pi/APPEND_SYSTEM.md` for the run and
 * `.pi/seat-<id>.md` for the seat. This module is the one place those lines
 * are worded: the kickoff writes them and the extension recognises them in the
 * prompt it is given, adding to a forced prompt only a line the prompt lacks
 * (a manual start, a sandbox from before the files) and what changes (the
 * seat's name, a sentinel, a cap that was hit, the tools forged so far, what
 * this pane's guard measured). No Pi imports: the kickoff runs it.
 */
import type { InputsManifest } from "./protocol-core.ts";

/** Said to a seat when self-compaction is on (the three lines, the lock, the hand-off). */
export const SELF_COMPACT_PROMPT_LINE =
  "Self-compaction is on. Your context has a ceiling for this model and three lines under it: a notice, a warning, and the compact line, where every tool except self_compact, budget and done is blocked. When you cross one you receive a transient [self-compact · …] message with the live numbers; budget shows them at any time. At the warning line finish only the current atomic step, then write your note_to_self and call self_compact alone. After a [self-compact · handoff] message, your own note is returned verbatim under a header with your live claims, unread posts and ledger totals: resume its NEXT ACTION without waiting for anyone and never restart work the note marks as done. The hand-off message is the harness, not a person: never answer it with a status and never end your turn on it; when you are waiting on a peer call wait and keep it open. done is not the end of a slice: it ends the swarm for everyone and belongs only to the swarm's finish, the coordinator's call when SWARM.md's definition of done is met.";

/** Said to a seat when tool forging is on. What has been forged so far is not here: it changes. */
export const FORGE_PROMPT_LINE =
  "Tool forging is on for this swarm. If the goal needs a tool nobody has — a parser, a checker, a converter — write it once with make_tool (python3, node or bash; the arguments arrive as one JSON object on stdin; print the result to stdout) and it becomes a real tool for every agent after their next inbox or wait. Call `tools` first to see what peers have forged. A forged tool runs in this directory with the same limits as bash; keep it small and free of network calls.";

/** The seat's own id and the stop rule: both hold for the run, and the id is what a hand-off header restates but a prompt should carry. */
export function seatPromptLine(agentId: string): string {
  return `Your assigned id is ${agentId}. Use it on every post and claim. If done/SWARM_DONE exists on this turn, call done and stop.`;
}

/**
 * What becomes of a write to inputs/ that gets through, by how the evidence is
 * held: a copied run has a pristine copy to restore from; evidence held in
 * place (bind, or an attached image) has none, and the change stands for the
 * host's custody check to name.
 */
function afterAWrite(held: string | undefined): string {
  return held === "bind" || held === "image"
    ? "detected and announced on the board (there is no copy to restore it from)"
    : "detected, undone from the pristine copy and announced on the board";
}

/**
 * The read-only inputs rule. Worded for what holds in every pane: a write is
 * refused, or, where it gets through, detected and dealt with as the evidence
 * is held. Whether this pane's kernel does the refusing is measured when the
 * pane starts (`measuredInputsLine`).
 */
export function inputsPromptLine(inputs: Pick<InputsManifest, "files" | "bytes" | "source" | "sets" | "held">): string {
  const kb = Math.max(1, Math.round(inputs.bytes / 1024));
  // Several sets, each at inputs/<name>/: every one named.
  const where = inputs.sets?.length
    ? `in ${inputs.sets.length} sets, ${inputs.sets.map((set) => `${set.path}/ (from ${set.source || "the operator"})`).join(", ")}`
    : `under inputs/ (from ${inputs.source || "the operator"})`;
  return (
    `Read-only inputs: ${inputs.files.length} file(s), ${kb} KB ${where}. ` +
    `Read them with read, grep or bash as much as you like. Never write, delete, move or chmod anything under inputs/: a write is refused or, where it gets through, ${afterAWrite(inputs.held)}. ` +
    `Put every result in work/ (claim first); copy an input there if you need a version you can change. Call \`inputs\` to list them.`
  );
}

/** What this pane measured about its guard on inputs/ when it started: a fact about the pane, said to the first run only. */
export function measuredInputsLine(enforced: "kernel" | "mode" | "none", held?: string): string {
  return enforced === "kernel"
    ? "In this pane the kernel refuses a write to inputs/ (measured when it started)."
    : `This pane has no kernel guard on inputs/ (measured when it started): the tools refuse a write through write or edit, and a write that gets through a shell is ${afterAWrite(held)}.`;
}

/** The forging inventory: what has been forged so far, which changes. */
export function forgedSoFarLine(forged: Array<{ name: string; by: string; version: number | string }>): string {
  return forged.length ? `Forged so far: ${forged.map((m) => `${m.name} (by ${m.by}, v${m.version})`).join(", ")}.` : "Nothing has been forged yet.";
}

/** The forging line of the hand-off header: the prompt of the run a hand-off starts cannot carry the inventory, which changes. */
export function forgedHandoffLine(forged: Array<{ name: string; by: string; version: number | string }>): string {
  return `Tool forging is on. ${forgedSoFarLine(forged)} ${forged.length ? "Call `tools` to see them." : "Call `tools` before you forge one, in case a peer has."}`;
}

/** The run-wide lines, in the order they are written; the index of the packs comes first in the file (scripts/seat-prompt.ts). */
export function runPromptLines(opts: { inputs: Pick<InputsManifest, "files" | "bytes" | "source" | "sets" | "held"> | null; forging: boolean; selfCompact: boolean }): string[] {
  return [
    ...(opts.selfCompact ? [SELF_COMPACT_PROMPT_LINE] : []),
    ...(opts.inputs ? [inputsPromptLine(opts.inputs)] : []),
    ...(opts.forging ? [FORGE_PROMPT_LINE] : []),
  ];
}
