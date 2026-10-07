/**
 * The method a run carried. A pack ships skills the agents fetch by name, and
 * every fetch is on the trace, so this tab can answer three questions the rest
 * of the console cannot: which method was in force, which parts of it the swarm
 * actually read, and which parts it carried and never opened.
 *
 * The last one matters most. A pack whose skills go unread is weight in the
 * context window and a signal that the index line for that skill does not say
 * when to reach for it.
 *
 * The numbers come from the whole trace (the server's `skill_use`, the same
 * code the context audit runs): a seat's prompt carried the index, how many
 * bodies it loaded and what they cost, which a later row names or uses (a
 * proxy, labelled as one), and which a compaction took out of its context.
 */
import { useMemo } from "react";
import { Package } from "lucide-react";
import { Chip, PhaseHead, SerifH } from "@/components/console";
import { EmptyState } from "@/components/states";
import { useAgentColours } from "@/lib/agent-colour";
import { relTime } from "@/lib/format";
import { useAgentNames } from "@/lib/hooks";
import { skillUse } from "@/lib/skill-metrics";
import type { SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

function AgentChips({ agents, colour, names }: {
  agents: string[];
  colour: (id: string) => string;
  names: (id: string) => string;
}) {
  return (
    <span className="flex flex-wrap gap-1">
      {agents.map((a) => (
        <span key={a} className={cn("rounded px-1.5 py-0.5 text-[11px] font-mono", colour(a))} title={a}>
          {names(a)}
        </span>
      ))}
    </span>
  );
}

export function PacksPanel({ view }: { view: SwarmView }) {
  const colour = useAgentColours(view.agents);
  const names = useAgentNames(view.agents);
  const packs = view.packs ?? [];
  const secrets = (view.registry as { pack_secrets?: Record<string, { names?: string[]; mode?: string }> } | null)?.pack_secrets;

  // The server counts over the whole trace; an older one sends only the tail, which is counted here.
  const use = useMemo(() => view.skill_use ?? skillUse(view.traces, view.agents.map((a) => a.id)), [view.skill_use, view.traces, view.agents]);
  const { bySkill, packOf, readKeys } = useMemo(() => {
    const bySkill = new Map(use.by_skill.map((row) => [row.key, row]));
    // Which pack a skill id belongs to when the row did not say: the first pack
    // that has it, which is the order the kickoff resolved.
    const packOf = new Map<string, string>();
    for (const p of packs) for (const s of p.skills) if (!packOf.has(s.id)) packOf.set(s.id, p.id);
    // What was loaded, by `pack:id` (and by bare id for a row that carries no pack).
    const readKeys = new Set(use.by_skill.map((row) => (row.pack ? `${row.pack}:${row.id}` : row.id)));
    return { bySkill, packOf, readKeys };
  }, [use, packs]);
  const wasRead = (pack: string, id: string) => readKeys.has(`${pack}:${id}`) || readKeys.has(id);
  const loadsTotal = use.totals.loads;
  const indexReads = use.totals.index_reads;

  const packTools = useMemo(() => view.tools.filter((t) => typeof t.pack === "string" && t.pack), [view.tools]);

  if (!packs.length) {
    return (
      <EmptyState
        icon={<Package />}
        title="This run carried no pack"
        hint="A pack brings method the agents fetch with the skill tool, tools seeded into the run, and the host binaries a case needs. Start a swarm with --pack (or pick one at Kickoff) and what the swarm consulted shows up here. A run without one behaves exactly as it always has."
      />
    );
  }

  const consulted = [...bySkill.values()];
  const carried = packs.flatMap((p) => p.skills.map((s) => ({ ...s, pack: p.id })));
  const untouched = carried.filter((s) => !wasRead(s.pack, s.id));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <SerifH>The method this run carried</SerifH>
        <span className="text-xs text-muted-foreground">
          {loadsTotal} skill {loadsTotal === 1 ? "load" : "loads"} across {use.totals.seats_that_loaded} of {use.totals.seats} agent(s)
          {indexReads ? `, and the index asked for ${indexReads}×` : ""}
        </span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {packs.map((p) => {
          const mine = carried.filter((s) => s.pack === p.id);
          const read = mine.filter((s) => wasRead(s.pack, s.id)).length;
          const toolsUsed = packTools.filter((t) => t.pack === p.id && t.calls > 0).length;
          return (
            <div key={p.id} className="rounded-lg border p-3 space-y-2">
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-medium">{p.name}</span>
                <Chip>{p.version}</Chip>
              </div>
              <p className="text-xs text-muted-foreground">{p.description}</p>
              <div className="flex flex-wrap gap-3 text-xs">
                <span><b>{read}</b> of {mine.length} skills consulted</span>
                <span><b>{toolsUsed}</b> of {packTools.filter((t) => t.pack === p.id).length} tools called</span>
              </div>
              <p className="font-mono text-[11px] text-muted-foreground">
                manifest {p.manifest_sha256.slice(0, 16)}
                {p.installed ? "" : " · no longer installed on this host"}
              </p>
              {secrets?.[p.id] ? (
                // What the kickoff did with the pack's secrets, from the run
                // record: injected into VMs bound to their hosts, exposed to
                // host panes, withheld, or never set.
                <p className={cn("text-xs [overflow-wrap:anywhere]", secrets[p.id].mode === "exposed" ? "text-brick-ink" : secrets[p.id].mode === "withheld" || secrets[p.id].mode === "not-set" ? "text-saffron-ink" : "text-muted-foreground")}>
                  secrets {(secrets[p.id].names ?? []).join(", ")} · {secrets[p.id].mode ?? "?"}
                </p>
              ) : null}
            </div>
          );
        })}
      </div>

      <div className="space-y-2">
        <PhaseHead title="What the swarm read" />
        {consulted.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-muted-foreground">
                  <th className="py-1 pr-3 font-normal">Skill</th>
                  <th className="py-1 pr-3 font-normal">Pack</th>
                  <th className="py-1 pr-3 font-normal">Loads</th>
                  <th className="py-1 pr-3 font-normal">Tokens</th>
                  <th className="py-1 pr-3 font-normal">Who read it</th>
                  <th className="py-1 font-normal">Last</th>
                </tr>
              </thead>
              <tbody>
                {consulted.map((row) => (
                  <tr key={row.key} className="border-t align-top">
                    <td className="py-1.5 pr-3 font-mono text-[12px]">{row.id}</td>
                    <td className="py-1.5 pr-3 text-xs text-muted-foreground">{row.pack ?? packOf.get(row.id) ?? "unknown"}</td>
                    <td className="py-1.5 pr-3 tabular-nums">{row.loads}</td>
                    <td className="py-1.5 pr-3 tabular-nums">{row.tokens.toLocaleString("en-US")}</td>
                    <td className="py-1.5 pr-3">
                      <AgentChips agents={row.agents} colour={colour} names={names} />
                    </td>
                    <td className="py-1.5 text-xs text-muted-foreground">{relTime(row.last)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            The packs were loaded and no agent opened a skill. Either the case did not need the method, or the index does not say when to reach for it.
          </p>
        )}
      </div>

      {untouched.length ? (
        <div className="space-y-2">
          <PhaseHead title="Carried, and never opened" />
          <p className="text-xs text-muted-foreground">
            These travelled with the run and no agent asked for them. On a case they do not fit that is right; when the case did need one, its line in the index is not saying so.
          </p>
          <ul className="grid gap-1 sm:grid-cols-2">
            {untouched.map((s) => (
              <li key={s.id} className="text-xs">
                <span className="font-mono">{s.id}</span>
                <span className="text-muted-foreground"> · {s.title}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {packTools.length ? (
        <div className="space-y-2">
          <PhaseHead title="Tools the packs brought" />
          {packTools.some((t) => t.calls > 0) ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-muted-foreground">
                    <th className="py-1 pr-3 font-normal">Tool</th>
                    <th className="py-1 pr-3 font-normal">Pack</th>
                    <th className="py-1 pr-3 font-normal">Calls</th>
                    <th className="py-1 font-normal">Who called it</th>
                  </tr>
                </thead>
                <tbody>
                  {packTools.filter((t) => t.calls > 0).sort((a, b) => b.calls - a.calls).map((t) => (
                    <tr key={t.name} className="border-t align-top">
                      <td className="py-1.5 pr-3 font-mono text-[12px]">{t.name}</td>
                      <td className="py-1.5 pr-3 text-xs text-muted-foreground">{t.pack}</td>
                      <td className="py-1.5 pr-3 tabular-nums">{t.calls}</td>
                      <td className="py-1.5"><AgentChips agents={t.users} colour={colour} names={names} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              None of them was called. The agents worked the evidence with the shell instead, which is a fair answer on a small case and a question worth asking on a large one.
            </p>
          )}
          {packTools.some((t) => t.calls === 0) ? (
            <p className="text-xs text-muted-foreground">
              <span className="text-foreground">Carried, never called:</span>{" "}
              <span className="font-mono">{packTools.filter((t) => t.calls === 0).map((t) => t.name).join(", ")}</span>
            </p>
          ) : null}
        </div>
      ) : null}

      <div className="space-y-2">
        <PhaseHead title="By agent" />
        <p className="text-xs text-muted-foreground">
          &ldquo;Used after load&rdquo; is a proxy: a later row of the same agent names the skill, or calls a tool the skill names. An agent can apply a note
          without naming it, so &ldquo;no trace of use&rdquo; is not proof it was not used. A compaction takes the bodies it summarises out of an agent&rsquo;s context
          (the newest part of the history stays); &ldquo;loaded again&rdquo; counts the ones it asked for afterwards. &ldquo;Index in prompt&rdquo; means Pi&rsquo;s own
          prompt carried this run&rsquo;s index, which every run of the agent keeps; an index the extension had to add lasts for the first run only.
        </p>
        {use.totals.loads_without_tools > 0 ? (
          <p className="text-xs text-saffron-ink">
            {use.totals.loads_without_tools} of the loads come from rows written before the harness recorded each skill&rsquo;s tools: for those only a mention of the id
            can show use, so &ldquo;no trace of use&rdquo; counts them as unused (an upper bound).
          </p>
        ) : null}
        {use.seats.some((x) => x.loads > 0 && x.lost_basis === "compact_done") ? (
          <p className="text-xs text-saffron-ink">
            For some agents the trace has no row saying which bodies a compaction took out, so every compaction is counted as taking every body loaded before it: an upper bound.
          </p>
        ) : null}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th className="py-1 pr-3 font-normal">Agent</th>
                <th className="py-1 pr-3 font-normal">Index in prompt</th>
                <th className="py-1 pr-3 font-normal">Loads</th>
                <th className="py-1 pr-3 font-normal">Tokens</th>
                <th className="py-1 pr-3 font-normal">Used after load</th>
                <th className="py-1 pr-3 font-normal">No trace of use</th>
                <th className="py-1 pr-3 font-normal">Done</th>
                <th className="py-1 pr-3 font-normal">Taken out by a compaction</th>
                <th className="py-1 pr-3 font-normal">Loaded again</th>
                <th className="py-1 font-normal">Skills</th>
              </tr>
            </thead>
            <tbody>
              {use.seats.map((seat) => (
                <tr key={seat.agent} className="border-t align-top">
                  <td className="py-1.5 pr-3">
                    <span className={cn("rounded px-1.5 py-0.5 text-[11px] font-mono", colour(seat.agent))} title={seat.agent}>{names(seat.agent)}</span>
                  </td>
                  <td className="py-1.5 pr-3 text-xs">
                    {seat.index_in_prompt
                      ? `yes${seat.index_tokens !== null ? ` · ${seat.index_tokens.toLocaleString("en-US")} tokens` : ""}`
                      : seat.index_source === "extension"
                        ? "first run only (the extension added it)"
                        : seat.index_source === "stale"
                          ? "another pack set's"
                          : seat.index_source === "none"
                            ? "the packs list no skill"
                            : "no row"}
                  </td>
                  <td className="py-1.5 pr-3 tabular-nums">{seat.loads}</td>
                  <td className="py-1.5 pr-3 tabular-nums">{seat.tokens_loaded.toLocaleString("en-US")}</td>
                  <td className="py-1.5 pr-3 tabular-nums">{seat.referenced}</td>
                  <td className="py-1.5 pr-3 tabular-nums">{seat.unused}</td>
                  <td className="py-1.5 pr-3 tabular-nums">{seat.done}</td>
                  <td className="py-1.5 pr-3 tabular-nums">{seat.lost_at_compaction}</td>
                  <td className="py-1.5 pr-3 tabular-nums">{seat.refetched}</td>
                  <td className="py-1.5 font-mono text-[11px] text-muted-foreground">
                    {seat.loads ? [...new Set(seat.detail.map((d) => d.id))].join(", ") : "read no skill"}
                    {seat.failed ? ` · ${seat.failed} missed` : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
