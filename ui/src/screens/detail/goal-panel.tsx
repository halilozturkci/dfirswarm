/**
 * The contract this swarm is running under.
 *
 * Read-only, and deliberately so. `SWARM.md` is a protected path inside the
 * sandbox: an agent that could edit its own definition of done could certify
 * itself, and a contract that changed under a running swarm would leave half
 * the team working to a goal the other half never saw. So this panel shows what
 * the agents see, and the way to change it is to take a copy into a new run.
 */
import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { BookOpen, Check, Copy, FileText, Pencil, TerminalSquare } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { useResource } from "@/lib/live";
import type { SwarmView } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ErrorState, LoadingState } from "@/components/states";
import { inputsGuardSummary } from "./inputs-panel";
import { cn } from "@/lib/utils";

type Fact = { label: string; value: string; title?: string; tone?: "warn" };

/**
 * Everything the kickoff decided, in one row, in the order an operator would
 * ask about it: where the agents run, what they may reach, what they may do
 * to the evidence, and what stops them.
 */
function frameFacts(view: SwarmView): Fact[] {
  const r = (view.registry ?? {}) as Record<string, unknown>;
  const layout = (view.layout ?? {}) as Record<string, unknown>;
  const s = view.summary;
  const out: Fact[] = [];
  if (s.workspace_id) {
    const tabs = typeof layout.tabs === "number" ? `${layout.tabs} tab${layout.tabs === 1 ? "" : "s"} · ` : "";
    out.push({ label: "Panes", value: `${s.workspace_id} · ${tabs}${s.n} panes`, title: "The Herdr workspace this run's agents live in" });
  }
  if (view.inputs) {
    out.push({
      label: "Inputs",
      value: `read-only · ${inputsGuardSummary(view.inputs).text}`,
      title: "Agents read inputs/ and can never write it; this is the guard each pane actually got",
    });
  }
  out.push({
    label: "Network",
    value:
      r.net === "open" ? "open" : r.net === "local" ? "local endpoints only" : r.net === "hosts" ? `allowlist + ${String(r.allow_hosts ?? "")}` : "allowlist only",
    tone: r.net === "open" ? "warn" : undefined,
    title: "What the panes could reach through netguard",
  });
  if (r.toolbox && r.toolbox !== "off") out.push({ label: "Toolbox", value: String(r.toolbox), title: "The tool sets checked on this host before the run started" });
  if (r.catalog === true) out.push({ label: "Catalog", value: "first pass done", title: "The standard first pass over the evidence ran before any agent" });
  if (r.quarantine === true) out.push({ label: "Quarantine", value: "no-exec on extracts", title: "Nothing under work/extracted or work/quarantine can execute" });
  out.push({ label: "Forging", value: r.tool_forging ? "on" : "off", title: "Whether agents could write tools with make_tool and share them" });
  // Absent on runs older than the feature; those say nothing rather than "off".
  const selfCompact = view.registry?.self_compact;
  if (selfCompact && typeof selfCompact === "object") {
    // A line the operator left unset next to one they set is a default
    // fitted to it per seat; its number is not the line the agents ran at.
    const set = selfCompact.set;
    const fitted = set && (set.notice_at || set.warn_at || set.compact_at);
    const shown = (spec: string | undefined, fallback: string, isSet: boolean | undefined) => `${spec || fallback}${fitted && !isSet ? " (default, fitted)" : ""}`;
    out.push({
      label: "Self compaction",
      value: selfCompact.enabled
        ? `on · notice ${shown(selfCompact.notice_at, "40%", set?.notice_at)} · warning ${shown(selfCompact.warn_at, "50%", set?.warn_at)} · compact ${shown(selfCompact.compact_at, "60%", set?.compact_at)}${selfCompact.model ? ` · summaries by ${selfCompact.model}` : ""}`
        : "off",
      title:
        "Whether agents compacted their own context, the three lines against each model's ceiling (per-model entries after a comma), and the model the summaries went to. A default marked fitted was moved to fit the lines the operator set; each agent's compact_config trace row has the numbers it ran at",
    });
  }
  // Absent on runs older than the bound; those say nothing rather than a number they never had.
  if (typeof view.registry?.inbox_page_chars === "number") {
    out.push({
      label: "Inbox page",
      value: view.registry.inbox_page_chars > 0 ? `${view.registry.inbox_page_chars.toLocaleString()} chars of post text per delivery` : "unbounded",
      title: "How much post text one inbox or wait delivery carried; whole posts only, the rest stayed unread for the next call",
    });
  }
  if (r.allow_install === true) out.push({ label: "Install", value: "pypi into the sandbox", title: "Agents could pip-install into work/.toolchain; no root, no system packages" });
  out.push({ label: "Hard kill", value: view.budget?.hard_kill ? "on" : "off", title: "Whether a cap steer shuts the session down or waits out the grace period" });
  if (typeof r.cap_per_agent_usd === "number" && r.cap_per_agent_usd > 0) {
    out.push({ label: "Per agent", value: `$${r.cap_per_agent_usd}`, title: "What one agent may spend before it is steered to finish and stopped" });
  }
  return out;
}

export function GoalPanel({ view, version }: { view: SwarmView; version: number }) {
  const navigate = useNavigate();
  const id = view.summary.id;
  const loader = useCallback(() => api.contract(id), [id]);
  const contract = useResource(loader, version, [id]);
  const [saveName, setSaveName] = useState("");
  const [note, setNote] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  // The goal document the operator submitted, as opposed to the rendered
  // contract: it is the part worth carrying into the next run.
  const goalDocument = useMemo(() => view.goal_document.trim(), [view.goal_document]);

  async function saveToLibrary() {
    setBusy(true);
    setNote(null);
    try {
      const doc = await api.saveGoal(saveName.trim().toLowerCase(), goalDocument);
      setNote({ tone: "ok", text: `Saved to the library as ${doc.name}.` });
    } catch (err) {
      setNote({ tone: "bad", text: err instanceof ApiError ? err.message : (err as Error).message });
    } finally {
      setBusy(false);
    }
  }

  // What started this run, in the operator's own words. It was nowhere in the
  // console: a reader could see the goal and the models but not the command,
  // the evidence set or the flags that framed them — the first thing anybody
  // asks when they open a finished run. `--env` values are redacted at the
  // kickoff, so this is safe to show.
  const registry = (view.registry ?? {}) as Record<string, unknown>;
  const command = typeof registry.command === "string" ? registry.command : "";
  const inputsSource = view.inputs?.source ?? "";

  return (
    <div className="space-y-4">
      <section className="card p-4 space-y-3">
        <h2 className="flex items-center gap-1.5 text-[14px] font-semibold text-ink">
          <TerminalSquare className="size-4" /> How this run was started
        </h2>
        {command ? (
          <div className="relative">
            <pre className="m-0 max-h-[9rem] overflow-auto rounded-lg border border-line bg-paper-2 px-3 py-2.5 text-[11.5px] leading-[1.6] text-ink">
              <code className="whitespace-pre-wrap break-words">{command}</code>
            </pre>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="absolute right-1.5 top-1.5 h-7 bg-paper/80"
              onClick={() => {
                void navigator.clipboard?.writeText(command);
                setCopied(true);
                setTimeout(() => setCopied(false), 1400);
              }}
            >
              {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        ) : (
          <p className="m-0 text-[12px] text-ink-2">
            This run predates the command being recorded. What it ran under is below, read back from the
            registry.
          </p>
        )}
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-[12px]">
          <dt className="text-ink-3">Evidence</dt>
          <dd className="m-0 break-all font-mono text-[11.5px] text-ink-2">
            {inputsSource ? `${inputsSource} · ${view.inputs?.files.length ?? 0} file(s)` : "none given"}
          </dd>
          <dt className="text-ink-3">Sandbox</dt>
          <dd className="m-0 break-all font-mono text-[11.5px] text-ink-2">{String(registry.sandbox ?? "—")}</dd>
          <dt className="text-ink-3">Case</dt>
          <dd className="m-0 text-ink-2">
            {String(registry.case_id ?? "—")}
            {registry.examiner ? ` · ${String(registry.examiner)}` : ""}
          </dd>
        </dl>

        {/*
          The frame this run ran under. These facts were four chips in the
          hero band, in the most valuable strip on the page, where an operator
          reads them once and then looks past them for the rest of the run.
          They belong with the command that set them.
        */}
        <div>
          <div className="label-caps mb-1.5 text-ink-3">The frame it ran under</div>
          <div className="flex flex-wrap gap-1.5">
            {frameFacts(view).map((fact) => (
              <span
                key={fact.label}
                title={fact.title}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[11.5px]",
                  fact.tone === "warn"
                    ? "border-saffron/40 bg-saffron-soft text-saffron-ink"
                    : "border-line bg-paper-2 text-ink-2",
                )}
              >
                <span className="text-ink-3">{fact.label}</span> {fact.value}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section className="card p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="flex items-center gap-1.5 text-[14px] font-semibold text-ink">
            <FileText className="size-4" /> Goal document
          </h2>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => navigate("/new", { state: { goal: goalDocument, label: view.summary.label } })}
          >
            <Pencil className="size-3.5" /> Edit a copy and relaunch
          </Button>
        </div>
        <p className="text-[12px] leading-[1.5] text-ink-2">
          What this swarm was asked to do, with its own definition of done and the checks{" "}
          <code>await-done.sh</code> runs. Editing it here would change the contract under a
          running team, so the button above opens a copy in the kickoff form instead.
        </p>
        <pre className="max-h-[28rem] overflow-auto rounded-md border border-line bg-paper-2/50 p-3 font-mono text-[12px] leading-[1.5] text-ink whitespace-pre-wrap">
          {goalDocument || "(this run used the default goal file)"}
        </pre>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={saveName}
            onChange={(e) => setSaveName(e.target.value)}
            placeholder="keep-it-as…"
            className="min-w-[12rem] flex-1 font-mono"
            aria-label="Name to save this goal under"
          />
          <Button type="button" variant="secondary" size="sm" disabled={!saveName.trim() || busy} onClick={saveToLibrary}>
            <BookOpen className="size-3.5" /> Save to library
          </Button>
        </div>
        {note ? (
          <p className={note.tone === "ok" ? "flex items-center gap-1 text-[11.5px] text-kelp-ink" : "text-[11.5px] text-brick-ink"}>
            {note.tone === "ok" ? <Check className="size-3.5" /> : null}
            {note.text}
          </p>
        ) : null}
      </section>

      <section className="card p-4 space-y-3">
        <h2 className="text-[14px] font-semibold text-ink">SWARM.md, as the agents see it</h2>
        <p className="text-[12px] leading-[1.5] text-ink-2">
          The goal document plus the frame the harness adds: who is on the team (and, on a
          mixed swarm, what each of them is running), the caps, and the bail-out. This file is
          harness-owned: an edit or write is blocked and a claim on it refused. A shell
          write cannot be blocked, so that one is detected and announced instead — which
          is why the checks that certify a run are read from the registry, not from here.
        </p>
        {contract.loading ? <LoadingState label="Reading SWARM.md…" /> : null}
        {contract.error ? <ErrorState error={contract.error} onRetry={contract.reload} /> : null}
        {contract.data ? (
          <pre className="max-h-[32rem] overflow-auto rounded-md border border-line bg-paper-2/50 p-3 font-mono text-[12px] leading-[1.5] text-ink whitespace-pre-wrap">
            {contract.data.text}
          </pre>
        ) : null}
      </section>
    </div>
  );
}
