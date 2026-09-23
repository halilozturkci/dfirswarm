/**
 * How a trace event is classified, shared by the console server
 * (`scripts/ui/model.ts`) and the client (`screens/detail/agents-panel.tsx`)
 * so the two cannot drift. Pure: no node imports, safe for the browser bundle.
 */

/** A tool call the agent would count as having gone wrong. */
export function isFailureEvent(e: { tool: string; result: unknown }): boolean {
  if (e.tool === "claim_violation") return true;
  const r = e.result;
  if (typeof r !== "object" || r === null) return false;
  const rec = r as Record<string, unknown>;
  return rec.ok === false || typeof rec.error === "string" || rec.timed_out === true || rec.blocked === true;
}
