import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, Check, CircleDashed, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input, Textarea } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Chip, SerifH } from "@/components/console";
import { GoalLibrary } from "@/components/goal-library";
import { CUSTOM_MODEL, MODEL_REF, ModelTeamEditor, modelOptions, providerOf, ReadyDot, rowCap, teamProblems, teamSpec, teamTotal, type TeamRow } from "@/components/model-team";
import { InlineNote } from "@/components/states";
import { JobCard } from "@/components/jobs-drawer";
import { api, ApiError } from "@/lib/api";
import { useLive, useResource } from "@/lib/live";
import type { InputsLibrary, Job, NetMode, SwarmRow } from "@/lib/types";
import { cn } from "@/lib/utils";

/**
 * What the panes may reach, in the order a kickoff should consider it.
 * Guarded first because a run whose agents can fetch anything has a record
 * with a hole in it: what came in, and what could have gone out, is no longer
 * something the report can answer.
 */
const NET_CHOICES: ReadonlyArray<{ value: NetMode; label: string; hint: string }> = [
  {
    value: "guarded",
    label: "Guarded",
    hint: "Netguard's allowlist: the providers this team needs and nothing else.",
  },
  {
    value: "hosts",
    label: "Guarded + hosts",
    hint: "The same allowlist plus the names you give — a package index, a symbol server, the one site a case needs.",
  },
  {
    value: "open",
    label: "Open",
    hint: "No guard at all: the panes reach whatever this machine can.",
  },
  {
    value: "local",
    label: "Local only",
    hint: "Every model must be served from this machine or network; the allowlist is those endpoints and nothing else, and Pi makes no startup calls.",
  },
];

/**
 * A goal is a markdown document that carries its own finish line. The harness
 * refuses one without a definition of done, and await-done.sh runs the
 * `## Checks` lines, so this default is a working example rather than a
 * sentence of prose.
 */
const DEFAULT_GOAL = `## Goal

Peer agents share this isolated folder. Each of you introduces yourself on
threads/main, then the team writes one file containing every assigned agent
id. Claim the file before writing it and yield on a conflict.

## Definition of done

\`work/hello.txt\` exists and contains every id listed in \`team.json\`, one per line.

## Checks

- \`test -f work/hello.txt\`
- \`ids=$(jq -e -r '.agents[].id' team.json) && for id in $ids; do grep -qw "$id" work/hello.txt || exit 1; done\`
`;

const GOAL_MAX = 32_000;
const HAS_DOD = /^##[ \t]*Definition of done[ \t]*$/im;
/** The server's own limits (scripts/ui/actions.ts validateStart), so the form refuses what the route would. */
const WALL_CLOCK_MAX = 240;
const ALLOW_HOSTS_MAX = 20;

/** swarm.sh's own default when --wall-clock is omitted, by team size. */
function defaultWallClock(n: number): number {
  return n >= 20 ? 20 : n >= 10 ? 15 : 8;
}

/** What the goal document says about itself — the same reading the harness does. */
function readGoal(text: string) {
  const hasDod = HAS_DOD.test(text);
  let inChecks = false;
  let fence: string | null = null;
  let checks = 0;
  const paths = new Set<string>();
  let approvals = 0;
  for (const line of text.split(/\r?\n/)) {
    const f = /^\s*(```+|~~~+)/.exec(line);
    if (f) {
      if (fence === null) fence = f[1][0];
      else if (f[1][0] === fence) fence = null;
      continue;
    }
    if (fence !== null) continue;
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      inChecks = h[1].length === 2 && /^Checks\s*$/i.test(h[2].trim());
      continue;
    }
    if (!inChecks) continue;
    const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
    if (!bullet) continue;
    for (const span of bullet[1].match(/`[^`]+`/g) ?? []) {
      checks += 1;
      for (const p of span.match(/\b(work|threads|test|done)\/[\w./*-]+/g) ?? []) paths.add(p.split("/")[0]);
      // A review the checks demand: the pelican goal greps the board for
      // `approved`, every case goal for `sign-off`.
      if (/approved|sign-?off/i.test(span) && /threads\//.test(span)) approvals += 1;
    }
  }
  return { hasDod, checks, paths: [...paths], approvals };
}

/** What swarm.sh accepts for a compact line: 150000, 150k, 0.5m, or 60%, optionally followed by per-model overrides (60%,openai/gpt-5.4-mini=55%). */
const COMPACT_SPEC = /^(?:[A-Za-z0-9][A-Za-z0-9._:-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:-]*)?=)?\d+(?:\.\d+)?[kKmM%]?(?:\s*,\s*(?:[A-Za-z0-9][A-Za-z0-9._:-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:-]*)?=)?\d+(?:\.\d+)?[kKmM%]?)*$/;

type FormState = {
  mode: "single" | "team";
  model: string;
  customModel: string;
  team: TeamRow[];
  cap_usd: string;
  /** The brake for a team that bills nothing; a second brake for any other. */
  cap_tokens: string;
  n: number;
  goal: string;
  label: string;
  wall_clock: string;
  playwright: boolean;
  /** What the panes may reach: the allowlist, the allowlist plus hosts, or everything. */
  net: NetMode;
  /** Host names for the middle setting, as typed. */
  allow_hosts: string;
  hard_kill: boolean;
  tool_forging: boolean;
  /** Agents compact their own context against three lines on each model's ceiling. On by default. */
  self_compact: boolean;
  /** The three lines as typed: a token count (150k) or a percentage of the ceiling (60%); blank means the default. */
  compact_notice_at: string;
  compact_warn_at: string;
  compact_at: string;
  /** The model every summary call goes to; empty means the agent's own. */
  compact_model: string;
  /** How much post text one inbox/wait delivery carries; empty means the default (40000), 0 removes the bound. */
  inbox_page_chars: string;
  /** A set from the inputs library, handed to the swarm read-only. */
  inputs: string;
  inputs_enforce: "auto" | "on" | "off";
  /** copy: a read-only copy under inputs/. bind: no copy, the source held read-only by the kernel. image: a disk image attached read-only. */
  inputs_attach: "copy" | "bind" | "image";
  /** The image file inside the set, when attaching an image. */
  inputs_image: string;
  /** Refuse an inputs directory above this many MB; blank means no ceiling. */
  inputs_max_mb: string;
  /** Run ids held unreadable in every pane: the clean room for a re-run on the same evidence. */
  no_read: string[];
  /** A run whose forged tools seed this swarm's tools/. */
  tools_from: string;
  /** With a toolbox: a missing tool is a refusal to start, not a warning. */
  toolbox_required: boolean;
  /** With allow_install: the package index stays off the allowlist. */
  no_pypi: boolean;
  /** What one agent may spend before it is steered to finish and stopped. */
  cap_per_agent: string;
  /** Run the standard first pass over the evidence before the agents start. */
  catalog: boolean;
  /** Tool sets the case needs: "", "dfir", "dfir,crypto", "auto", "off". */
  toolbox: string;
  /** Nothing carved out of the evidence may execute. */
  quarantine: boolean;
  /** Agents may install Python packages the case needs, into the sandbox. */
  allow_install: boolean;
  case_id: string;
  examiner: string;
  no_start: boolean;
};

function Row({ ok, children }: { ok: boolean | "pending"; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2.5 text-[13px] leading-[1.4]">
      {ok === true ? <Check className="mt-0.5 size-[18px] shrink-0 text-moss" strokeWidth={2.6} /> : ok === "pending" ? <CircleDashed className="mt-0.5 size-[18px] shrink-0 text-saffron" /> : <CircleDashed className="mt-0.5 size-[18px] shrink-0 text-brick" />}
      <span>{children}</span>
    </div>
  );
}

/** The roots the server reads sets from, and, when the server allows it, a way to add one. */
function InputsRoots({ lib, onChange }: { lib: InputsLibrary | null; onChange: () => void }) {
  const [busy, setBusy] = useState<number | null>(null);
  if (!lib) return null;
  return (
    <div className="flex flex-col gap-1.5">
      <span className="label-caps">Evidence root{lib.roots.length === 1 ? "" : "s"}</span>
      <ul className="m-0 flex list-none flex-col gap-1 p-0">
        {lib.roots.map((r, i) => (
          <li key={r.path} className="flex items-center gap-2 text-[12px]">
            <code className={cn("min-w-0 flex-1 truncate", r.ok ? "text-ink" : "text-brick-ink")} title={r.path}>{r.path}</code>
            {r.ok ? null : <span className="shrink-0 text-brick-ink">missing</span>}
            <span className="shrink-0 text-ink-3">{r.source === "env" ? "from the server's start" : "added here"}</span>
            {r.source === "ui" && lib.runtime_roots ? (
              <Button
                variant="ghost"
                size="sm"
                disabled={busy === i}
                onClick={async () => {
                  setBusy(i);
                  try { await api.removeInputsRoot(i); onChange(); } finally { setBusy(null); }
                }}
                aria-label={`Remove root ${r.path}`}
              >
                remove
              </Button>
            ) : null}
          </li>
        ))}
      </ul>
      {lib.runtime_roots ? <InputsRootAdder onAdded={onChange} /> : null}
    </div>
  );
}

/** One field and one button: an absolute path on the server, checked there. */
function InputsRootAdder({ onAdded }: { onAdded: () => void }) {
  const [path, setPath] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!path.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.addInputsRoot(path.trim());
      setPath("");
      onAdded();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <Input
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); void submit(); } }}
          placeholder="/absolute/path/on/this/server"
          className="flex-1 font-mono text-[12px]"
          aria-label="New evidence root"
          disabled={busy}
        />
        <Button variant="secondary" size="sm" disabled={busy || !path.trim()} onClick={() => void submit()}>Add root</Button>
      </div>
      {error ? <span className="text-[12px] text-brick-ink">{error}</span> : null}
      <span className="text-[11.5px] text-ink-3">Needs the server token. Every directory directly under it becomes a set the LAN can see the name of.</span>
    </div>
  );
}

/**
 * The clean room: earlier runs whose directories every pane holds unreadable,
 * so a second swarm on the same evidence cannot read the back of the book.
 * The runs on this evidence come first; any run can be chosen.
 */
function CleanRoom({ chosen, runs, evidence, onChange }: { chosen: string[]; runs: SwarmRow[]; evidence: string | null; onChange: (ids: string[]) => void }) {
  const candidates = runs
    .filter((r) => !chosen.includes(r.id))
    .sort((a, b) => Number(Boolean(b.inputs_source && b.inputs_source === evidence)) - Number(Boolean(a.inputs_source && a.inputs_source === evidence)) || b.started_at.localeCompare(a.started_at));
  return (
    <div className="flex flex-col gap-1.5">
      <span className="label-caps">Clean room<span className="ml-1 font-normal normal-case tracking-normal text-ink-3">· earlier runs kept unreadable · optional</span></span>
      {chosen.length ? (
        <div className="flex flex-wrap gap-1.5">
          {chosen.map((id) => (
            <Button key={id} type="button" variant="secondary" size="sm" className="font-mono" onClick={() => onChange(chosen.filter((x) => x !== id))} aria-label={`Stop hiding run ${id}`}>
              {id} ×
            </Button>
          ))}
        </div>
      ) : null}
      <Select
        size="sm"
        mono
        value=""
        onChange={(v) => { if (v) onChange([...chosen, v]); }}
        aria-label="Add a run to keep unreadable"
        placeholder={runs.length ? "add a run…" : "no earlier runs"}
        disabled={runs.length === 0}
        searchPlaceholder="Filter runs…"
        options={candidates.map((r) => ({
          value: r.id,
          label: r.id,
          hint: `${r.label || r.goal.slice(0, 50)}${r.inputs_source && r.inputs_source === evidence ? " · same evidence" : r.inputs_source ? " · other evidence" : " · no evidence"}`,
          meta: r.done ? "finished" : r.state,
          keywords: `${r.label} ${r.inputs_source ?? ""}`,
        }))}
      />
      <span className="text-[12px] leading-[1.5] text-ink-2">Their work, threads and ledger are unreadable in every pane where the host has a kernel write guard, and the record says whether it was applied.</span>
    </div>
  );
}

/** 12 KB, 3.4 MB, 1.2 GB: what a picker can show beside a set. */
function humanSize(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function KickoffScreen() {
  const navigate = useNavigate();
  const location = useLocation();
  const carried = (location.state ?? null) as { goal?: string; label?: string } | null;
  const live = useLive();
  const modelsLoader = useCallback(() => api.models(), []);
  const models = useResource(modelsLoader, 0);
  const readinessLoader = useCallback(() => api.readiness(), []);
  const readiness = useResource(readinessLoader, 0);
  const providers = readiness.data?.providers;
  const goalsLoader = useCallback(() => api.goals(), []);
  const goals = useResource(goalsLoader, 0);
  const libraryLoader = useCallback(() => api.library(), []);
  const library = useResource(libraryLoader, 0);
  const inputsLoader = useCallback(() => api.inputs(), []);
  const inputsLib = useResource(inputsLoader, 0);
  // Earlier runs: the ones that forged tools seed a toolbox, the ones on this evidence are what a clean room hides.
  const swarmsLoader = useCallback(() => api.swarms(), []);
  const earlier = useResource(swarmsLoader, 0);
  const [form, setForm] = useState<FormState>({
    mode: "single",
    model: "",
    customModel: "",
    team: [],
    cap_usd: "5",
    cap_tokens: "",
    n: 2,
    goal: carried?.goal?.trim() || DEFAULT_GOAL,
    label: "",
    wall_clock: "",
    playwright: false,
    net: "guarded",
    allow_hosts: "",
    hard_kill: false,
    tool_forging: false,
    self_compact: true,
    compact_notice_at: "",
    compact_warn_at: "",
    compact_at: "",
    compact_model: "",
    inbox_page_chars: "",
    inputs: "",
    inputs_enforce: "auto",
    inputs_attach: "copy",
    inputs_image: "",
    inputs_max_mb: "",
    no_read: [],
    tools_from: "",
    toolbox_required: false,
    no_pypi: false,
    cap_per_agent: "",
    catalog: false,
    toolbox: "",
    quarantine: false,
    allow_install: false,
    case_id: "",
    examiner: "",
    no_start: false,
  });

  // What the operator typed, as host names: commas or spaces, lower case.
  const hostList = useMemo(
    () => form.allow_hosts.split(/[\s,]+/).map((h) => h.trim().toLowerCase()).filter(Boolean),
    [form.allow_hosts],
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  // The three compact lines as typed, trimmed. They only count while the
  // switch is on: a value left behind in a hidden field must not reach the
  // kickoff, and must not block it either.
  const compactSpecs = useMemo(
    () => (form.self_compact ? [form.compact_notice_at.trim(), form.compact_warn_at.trim(), form.compact_at.trim()] : ["", "", ""]),
    [form.self_compact, form.compact_notice_at, form.compact_warn_at, form.compact_at],
  );

  // The default is the first model whose provider is actually usable, not the
  // first in the list — a kickoff that swarm.sh would refuse is a bad default.
  // Until readiness answers, the first model stands in; once it answers, a
  // default the operator has not touched moves to a ready one.
  const [modelTouched, setModelTouched] = useState(false);
  useEffect(() => {
    const list = models.data?.models ?? [];
    if (!list.length) return;
    const ready = providers ? list.find((m) => providers[providerOf(m)]?.status === "ready") : undefined;
    if (!form.model) setForm((f) => ({ ...f, model: ready ?? list[0] }));
    else if (!modelTouched && ready && form.model !== ready && providers?.[providerOf(form.model)]?.status !== "ready") setForm((f) => ({ ...f, model: ready }));
  }, [models.data, providers, form.model, modelTouched]);

  const job: Job | null = jobId ? live.jobs[jobId] ?? null : null;
  const effectiveModel = form.model === CUSTOM_MODEL ? form.customModel.trim() : form.model;
  const capNum = form.cap_usd.trim() === "" ? 0 : Number(form.cap_usd);
  const capTokensNum = form.cap_tokens.trim() === "" ? 0 : Number(form.cap_tokens);
  const teamMode = form.mode === "team";
  const effectiveN = teamMode ? teamTotal(form.team) : form.n;
  // The models this form would start, and whether every one of them is served
  // from this machine or network. A team that bills nothing is braked by
  // tokens, not dollars, and the form says so before swarm.sh has to.
  const chosenModels = useMemo(
    () => (teamMode ? form.team.map((r) => r.model.trim()).filter(Boolean) : form.model === CUSTOM_MODEL ? (form.customModel.trim() ? [form.customModel.trim()] : []) : form.model ? [form.model] : []),
    [teamMode, form.team, form.model, form.customModel],
  );
  const localOf = useCallback(
    (m: string) => providers?.[providerOf(m)]?.local === true || models.data?.local?.some((l) => l.model === m) === true,
    [providers, models.data],
  );
  const allLocal = chosenModels.length > 0 && chosenModels.every(localOf);
  const notLocal = chosenModels.filter((m) => !localOf(m));
  const read = useMemo(() => readGoal(form.goal), [form.goal]);
  const chosenSet = useMemo(() => inputsLib.data?.sets.find((s) => s.id === form.inputs) ?? null, [inputsLib.data, form.inputs]);

  // Credentials are checked the way swarm.sh checks them; a model whose
  // provider is not ready is a warning here and a refusal there.
  const notReady = useMemo(() => {
    if (!providers) return [] as string[];
    const chosen = teamMode ? form.team.map((r) => r.model.trim()).filter(Boolean) : effectiveModel ? [effectiveModel] : [];
    const out = new Set<string>();
    for (const m of chosen) {
      const r = providers[providerOf(m)];
      if (r && r.status !== "ready" && r.status !== "unknown" && r.status !== "local") out.add(providerOf(m));
    }
    return [...out];
  }, [providers, teamMode, form.team, effectiveModel]);
  // A local server Pi will not list yet: not a login problem, a one-line
  // models.json edit, and the form has to name it as that.
  const needsKey = useMemo(() => {
    if (!providers) return [] as string[];
    const chosen = teamMode ? form.team.map((r) => r.model.trim()).filter(Boolean) : effectiveModel ? [effectiveModel] : [];
    return [...new Set(chosen.map(providerOf).filter((p) => providers[p]?.status === "local"))];
  }, [providers, teamMode, form.team, effectiveModel]);

  const problems = useMemo(() => {
    const out: string[] = [];
    if (teamMode) {
      out.push(...teamProblems(form.team));
      // A model cap above the swarm cap could never bind; the harness refuses it, so say it here.
      for (const row of form.team) {
        const c = rowCap(row);
        if (c !== undefined && capNum > 0 && c > capNum) out.push(`${row.model || "a model"} has a cap of $${c}, above the swarm's $${capNum}.`);
      }
    }
    else if (!form.no_start && !MODEL_REF.test(effectiveModel)) out.push("Model must look like provider/id.");
    if (form.cap_usd.trim() && (!Number.isFinite(capNum) || capNum < 0)) out.push("USD cap must be a number.");
    if (form.cap_tokens.trim() && (!Number.isInteger(capTokensNum) || capTokensNum < 1)) out.push("Token cap must be a whole number above zero.");
    if (allLocal) {
      if (capTokensNum < 1) out.push("This team bills nothing, so a USD cap cannot stop it: give it a token cap.");
    } else if (!(capNum > 0)) out.push("USD cap must be a positive number.");
    if (form.net === "local" && !allLocal) out.push(chosenModels.length ? `Local only needs every model to be local; ${notLocal.join(", ")} is not.` : "Local only needs a local model.");
    if (form.net === "hosts" && hostList.length > ALLOW_HOSTS_MAX) out.push(`At most ${ALLOW_HOSTS_MAX} extra hosts.`);
    if (!Number.isInteger(effectiveN) || effectiveN < 1 || effectiveN > 30) out.push("N must be 1–30.");
    if (form.label && !/^[A-Za-z0-9_-]{1,40}$/.test(form.label)) out.push("Label: letters, digits, - and _ only.");
    if (form.wall_clock && (!Number.isInteger(Number(form.wall_clock)) || Number(form.wall_clock) < 1 || Number(form.wall_clock) > WALL_CLOCK_MAX)) out.push(`Wall clock must be whole minutes, 1–${WALL_CLOCK_MAX}.`);
    if (form.goal.trim() && !read.hasDod) out.push('The goal needs a "## Definition of done" heading — the swarm has to know when to stop.');
    if (form.self_compact && compactSpecs.some((spec) => spec && !COMPACT_SPEC.test(spec))) out.push("Compact thresholds are a token count (150k) or a percentage (60%), optionally with per-model overrides (60%,openai/gpt-5.4-mini=55%).");
    if (form.self_compact && form.compact_model.trim() && !MODEL_REF.test(form.compact_model.trim())) out.push("The summary model is provider/id.");
    if (form.inbox_page_chars.trim() && !/^\d{1,9}$/.test(form.inbox_page_chars.trim())) out.push("The inbox page is a whole number of characters (0 for no bound).");
    return out;
  }, [form, effectiveModel, capNum, capTokensNum, allLocal, notLocal, chosenModels.length, hostList.length, teamMode, effectiveN, read.hasDod, compactSpecs]);

  useEffect(() => {
    if (job && job.status === "ok" && job.swarm_id) {
      const t = setTimeout(() => navigate(`/swarms/${job.swarm_id}`), 900);
      return () => clearTimeout(t);
    }
  }, [job, navigate]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (problems.length) return;
    setSubmitting(true);
    setError(null);
    try {
      const accepted = await api.start({
        model: teamMode ? "" : effectiveModel,
        models: teamMode ? teamSpec(form.team) : undefined,
        cap_usd: capNum,
        cap_tokens: capTokensNum > 0 ? capTokensNum : undefined,
        n: effectiveN,
        goal: form.goal.trim() || undefined,
        label: form.label || undefined,
        wall_clock: form.wall_clock ? Number(form.wall_clock) : undefined,
        playwright: form.playwright,
        net: form.net,
        allow_hosts: form.net === "hosts" ? hostList : undefined,
        hard_kill: form.hard_kill,
        tool_forging: form.tool_forging,
        self_compact: form.self_compact,
        compact_notice_at: compactSpecs[0] || undefined,
        compact_warn_at: compactSpecs[1] || undefined,
        compact_at: compactSpecs[2] || undefined,
        compact_model: form.self_compact && form.compact_model.trim() ? form.compact_model.trim() : undefined,
        inbox_page_chars: form.inbox_page_chars.trim() ? Number(form.inbox_page_chars.trim()) : undefined,
        inputs: form.inputs && form.inputs_attach !== "image" ? form.inputs : undefined,
        inputs_enforce: form.inputs && form.inputs_attach !== "image" ? form.inputs_enforce : undefined,
        inputs_attach: form.inputs && form.inputs_attach === "bind" ? "bind" : undefined,
        inputs_image: form.inputs && form.inputs_attach === "image" && form.inputs_image ? `${form.inputs}/${form.inputs_image}` : undefined,
        inputs_max_mb: form.inputs && form.inputs_attach === "copy" && form.inputs_max_mb ? Number(form.inputs_max_mb) : undefined,
        no_read: form.no_read.length ? form.no_read : undefined,
        tools_from: form.tools_from || undefined,
        toolbox_required: form.toolbox && form.toolbox !== "off" ? form.toolbox_required : undefined,
        no_pypi: form.allow_install ? form.no_pypi : undefined,
        cap_per_agent: form.cap_per_agent ? Number(form.cap_per_agent) : undefined,
        catalog: form.catalog,
        toolbox: form.toolbox || undefined,
        quarantine: form.quarantine,
        allow_install: form.allow_install,
        case_id: form.case_id || undefined,
        examiner: form.examiner || undefined,
        no_start: form.no_start,
      });
      setJobId(accepted.id);
      live.mergeJobs([accepted]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : (err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  const command = `swarm.sh start ${teamMode ? `--models "${teamSpec(form.team) || "?"}"` : `--model ${effectiveModel || "?"}`}${capNum > 0 ? ` --cap-usd ${form.cap_usd}` : allLocal ? "" : " --cap-usd ?"}${capTokensNum > 0 ? ` --cap-tokens ${capTokensNum}` : allLocal ? " --cap-tokens ?" : ""} --n ${effectiveN}${form.wall_clock ? ` --wall-clock ${form.wall_clock}` : ""}${form.net === "open" ? " --no-netguard" : form.net === "local" ? " --local-only" : form.net === "hosts" ? hostList.map((h) => ` --allow-host ${h}`).join("") : ""}${form.playwright ? " --playwright" : ""}${form.hard_kill ? " --hard-kill" : ""}${form.tool_forging ? " --allow-tool-forging" : ""}${form.self_compact ? "" : " --no-self-compact"}${compactSpecs[0] ? ` --compact-notice-at ${compactSpecs[0]}` : ""}${compactSpecs[1] ? ` --compact-warn-at ${compactSpecs[1]}` : ""}${compactSpecs[2] ? ` --compact-at ${compactSpecs[2]}` : ""}${form.self_compact && form.compact_model.trim() ? ` --compact-model ${form.compact_model.trim()}` : ""}${form.inbox_page_chars.trim() ? ` --inbox-page-chars ${form.inbox_page_chars.trim()}` : ""}${form.inputs && form.inputs_attach === "image" ? ` --inputs-image ${chosenSet ? `${chosenSet.root}/${chosenSet.name}` : "<set>"}/${form.inputs_image || "<image>"}` : form.inputs ? ` --inputs ${chosenSet ? `${chosenSet.root}/${chosenSet.name}` : "<set>"}${form.inputs_attach === "bind" ? " --inputs-bind" : ""}${form.inputs_enforce !== "auto" ? ` --inputs-enforce ${form.inputs_enforce}` : ""}${form.inputs_attach === "copy" && form.inputs_max_mb ? ` --inputs-max-mb ${form.inputs_max_mb}` : ""}` : ""}${form.no_read.map((id) => ` --no-read <runs>/${id}`).join("")}${form.tools_from ? ` --tools-from <runs>/${form.tools_from}/tools` : ""}${form.catalog ? " --catalog" : ""}${form.toolbox ? ` --toolbox ${form.toolbox}` : ""}${form.toolbox && form.toolbox !== "off" && form.toolbox_required ? " --toolbox-required" : ""}${form.quarantine ? " --quarantine" : ""}${form.allow_install ? " --allow-install" : ""}${form.allow_install && form.no_pypi ? " --no-pypi" : ""}${form.cap_per_agent ? ` --cap-per-agent ${form.cap_per_agent}` : ""}${form.case_id ? ` --case-id ${form.case_id}` : ""}${form.examiner ? ` --examiner "${form.examiner}"` : ""}${form.no_start ? " --no-start" : ""}`;

  return (
    <form onSubmit={submit} className="mx-auto grid w-full max-w-[1680px] gap-8 px-4 py-7 sm:px-10 lg:grid-cols-[minmax(0,1fr)_500px]">
      {/* the goal is the contract */}
      <section className="flex min-w-0 flex-col gap-3.5">
        <div>
          <Link to="/" className="inline-flex items-center gap-1 text-[12px] text-ink-2 hover:text-ink">
            <ArrowLeft className="size-3.5" /> Swarms
          </Link>
          <SerifH as="h1" size={40} className="mt-1">
            The goal is the contract.
          </SerifH>
          <p className="mt-2 max-w-[640px] text-[14px] leading-[1.5] text-ink-2 [text-wrap:pretty]">
            It becomes <span className="font-mono">SWARM.md</span>. Peers cannot rewrite it, and its checks are what certifies the run — so the finish line is written here, first, before anyone chooses a model.
          </p>
        </div>

        <GoalLibrary
          goals={goals.data?.goals ?? []}
          loading={goals.loading}
          library={library.data?.entries ?? []}
          libraryLoading={library.loading}
          current={form.goal}
          defaultText={DEFAULT_GOAL}
          onLoad={(text, name) => setForm((f) => ({ ...f, goal: text, label: f.label || (/^[A-Za-z0-9_-]{1,40}$/.test(name) ? name : "") }))}
          onSuggest={(s) =>
            setForm((f) => ({
              ...f,
              n: s.seats !== undefined ? Math.max(1, Math.round(s.seats)) : f.n,
              cap_usd: s.cap_usd !== undefined ? String(s.cap_usd) : f.cap_usd,
              wall_clock: s.wall_clock !== undefined ? String(Math.round(s.wall_clock)) : f.wall_clock,
            }))
          }
          onSaved={() => goals.reload()}
        />

        <div className="card grid overflow-hidden rounded-xl lg:grid-cols-[minmax(0,1fr)_232px]">
          <label htmlFor="goal" className="sr-only">
            Goal document
          </label>
          <Textarea
            id="goal"
            spellCheck={false}
            value={form.goal}
            onChange={(e) => setForm({ ...form, goal: e.target.value })}
            maxLength={GOAL_MAX}
            className="min-h-[520px] resize-none rounded-none border-0 border-r border-paper-2 bg-card px-[22px] py-5 font-mono text-[12.5px] leading-[1.6] focus-visible:ring-0"
          />
          <div className="flex flex-col gap-4 bg-[#f8f6f1] px-[18px] py-5">
            <span className="label-caps">Will it know when it's done?</span>
            <Row ok={read.hasDod}>
              <strong>Definition of done</strong> {read.hasDod ? "present" : "missing — the harness refuses to start without one"}
            </Row>
            <Row ok={read.checks > 0 ? true : "pending"}>
              <strong>
                {read.checks} check{read.checks === 1 ? "" : "s"}
              </strong>{" "}
              {read.checks ? "found, in backticks under ## Checks" : "— without any, the sentinel is the only signal"}
            </Row>
            {read.checks ? (
              <Row ok={read.paths.length > 0 ? true : "pending"}>
                {read.paths.length ? (
                  <>
                    Checks read <span className="font-mono">{read.paths.map((p) => `${p}/`).join(", ")}</span>
                  </>
                ) : (
                  "No check names a sandbox path — is anything being verified?"
                )}
              </Row>
            ) : null}
            <Row ok={read.approvals > 0 ? true : "pending"}>{read.approvals ? "Needs a sign-off from the agents — nobody can certify alone" : "No sign-off check: the swarm certifies itself with the checks above"}</Row>
            <div className="h-px bg-paper-3" />
            <span className="text-[12px] leading-[1.5] text-ink-2">The harness refuses a goal with no finish line. It does not judge whether the checks are good — that is still yours.</span>
            <span className="font-mono text-[11.5px] text-ink-3">
              {form.goal.length.toLocaleString()} / {GOAL_MAX.toLocaleString()} chars
            </span>
            <button type="button" className="self-start text-[12px] text-ink-3 hover:text-ink" onClick={() => setForm({ ...form, goal: DEFAULT_GOAL })}>
              reset to the hello goal
            </button>
          </div>
        </div>
      </section>

      {/* team, caps, safety, launch */}
      <aside className="flex flex-col gap-4">
        <section className="card flex flex-col gap-3 rounded-xl p-[18px_20px]">
          <div className="flex items-center justify-between gap-2">
            <SerifH as="h3" size={22}>
              Team
            </SerifH>
            <div className="inline-flex rounded-full border border-line p-0.5" role="group" aria-label="Team mode">
              {(["single", "team"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  aria-pressed={form.mode === mode}
                  onClick={() =>
                    setForm((f) => ({
                      ...f,
                      mode,
                      team: mode === "team" && f.team.length === 0 ? [{ model: f.model === CUSTOM_MODEL ? f.customModel : f.model, count: f.n, cap: "" }] : f.team,
                    }))
                  }
                  className={cn("h-[26px] rounded-full px-3 text-[12px] font-medium", form.mode === mode ? "bg-ink text-paper" : "text-ink-2 hover:text-ink")}
                >
                  {mode === "single" ? "One model" : "Mixed team"}
                </button>
              ))}
            </div>
          </div>
          {teamMode ? (
            <>
              <ModelTeamEditor rows={form.team} onChange={(team) => setForm({ ...form, team })} known={models.data?.models ?? []} disabled={models.loading} readiness={providers} />
              <p className="m-0 text-[12px] leading-[1.5] text-ink-2">Each agent's model goes on the board, so peers can hand a slice to whoever suits it. A cheaper vendor to grind, a stronger one to design, a different one to review.</p>
            </>
          ) : (
            <>
              <Select
                id="model"
                mono
                value={form.model}
                onChange={(v) => {
                  setModelTouched(true);
                  setForm({ ...form, model: v });
                }}
                options={modelOptions(models.data?.models ?? [], providers)}
                disabled={models.loading}
                placeholder={models.loading ? "Loading models…" : "Choose a model"}
                searchPlaceholder="Filter models…"
                aria-label="Model"
              />
              {form.model === CUSTOM_MODEL ? (
                <div className="flex items-center gap-2">
                  <ReadyDot model={effectiveModel} readiness={providers} />
                  <Input value={form.customModel} onChange={(e) => setForm({ ...form, customModel: e.target.value })} placeholder="provider/model-id" className="flex-1 font-mono" autoFocus />
                </div>
              ) : null}
              <label className="flex flex-col gap-1.5">
                <span className="label-caps">Agents · N = {form.n}</span>
                <div className="flex items-center gap-3">
                  <input type="range" min={1} max={30} value={form.n} onChange={(e) => setForm({ ...form, n: Number(e.target.value) })} className="w-full accent-kelp" aria-label="N" />
                  <Input type="number" min={1} max={30} value={form.n} onChange={(e) => setForm({ ...form, n: Number(e.target.value) })} className="w-20 tabular" aria-label="N" />
                </div>
              </label>
              <p className="m-0 text-[12px] text-ink-3">{models.data ? (models.data.source === "pi" ? "From pi --list-models on the server." : "Static list; pi was not found on the server.") : "Loading model list…"}</p>
            </>
          )}

          {/* which providers can be used right now, from pi auth check */}
          <div className="flex flex-col gap-1.5 border-t border-paper-3 pt-2.5">
            <div className="flex items-baseline justify-between">
              <span className="label-caps">Credentials · pi auth check</span>
              {readiness.data ? <span className="font-mono text-[10.5px] text-ink-3">{new Date(readiness.data.checked_at).toLocaleTimeString()}</span> : null}
            </div>
            {readiness.error && !readiness.data ? (
              <span className="text-[12px] text-brick-ink">Could not check: {readiness.error.message}</span>
            ) : !readiness.data ? (
              <span className="text-[12px] text-ink-3">Checking each provider…</span>
            ) : (
              <div className="flex flex-wrap gap-1.5" aria-label="Provider readiness">
                {Object.values(readiness.data.providers)
                  .sort((a, b) => (a.status === b.status ? a.provider.localeCompare(b.provider) : a.status === "ready" ? -1 : b.status === "ready" ? 1 : 0))
                  .map((r) => (
                    <Chip key={r.provider} tone={r.status === "ready" ? "kelp" : r.status === "invalid" ? "brick" : r.status === "not_ready" ? "neutral" : "saffron"} mono>
                      {r.provider} · {r.status === "ready" ? (r.local ? "local · free" : r.auth_type === "oauth" ? "subscription" : r.auth_type === "api_key" ? "api key" : "ready") : r.status === "not_ready" ? "not logged in" : r.status === "local" ? "local · needs a placeholder key" : r.status}
                    </Chip>
                  ))}
              </div>
            )}
            {notReady.length ? (
              <InlineNote tone="warn">
                {notReady.join(", ")} {notReady.length === 1 ? "is" : "are"} not logged in — swarm.sh will refuse to start. Run <span className="font-mono">pi auth login {notReady[0]}</span> (or set the provider's key), then reload.
              </InlineNote>
            ) : null}
            {needsKey.length ? (
              <InlineNote tone="warn">
                {needsKey.join(", ")} {needsKey.length === 1 ? "is a local server" : "are local servers"} Pi will not list until <span className="font-mono">models.json</span> gives {needsKey.length === 1 ? "it" : "them"} a placeholder <span className="font-mono">"apiKey": "local"</span> — there is no login. swarm.sh prints the whole snippet if you start anyway.
              </InlineNote>
            ) : null}
          </div>
        </section>

        <section className="card grid grid-cols-2 gap-3.5 rounded-xl p-[18px_20px]">
          <label className="flex flex-col gap-1.5">
            <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">USD cap<span className="ml-1 font-normal normal-case tracking-normal text-ink-3">· whole swarm{allLocal ? " · not in force" : ""}</span></span>
            <div className={cn("flex h-10 items-center gap-1.5 rounded-lg border border-line bg-card px-3", allLocal && "opacity-60")}>
              <span className="text-ink-3">$</span>
              <input inputMode="decimal" value={form.cap_usd} onChange={(e) => setForm({ ...form, cap_usd: e.target.value })} className="w-full border-0 bg-transparent font-mono text-[16px] text-ink outline-none" aria-label="USD cap" />
            </div>
          </label>
          <label className="flex flex-col gap-1.5">
            <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Token cap<span className="ml-1 font-normal normal-case tracking-normal text-ink-3">{allLocal ? "· the brake" : "· optional"}</span></span>
            <div className="flex h-10 items-center rounded-lg border border-line bg-card px-3">
              <input inputMode="numeric" value={form.cap_tokens} onChange={(e) => setForm({ ...form, cap_tokens: e.target.value })} placeholder={allLocal ? "5000000" : "none"} className="w-full border-0 bg-transparent font-mono text-[16px] text-ink outline-none placeholder:text-ink-3" aria-label="Token cap" />
            </div>
          </label>
          {allLocal ? (
            <span className="col-span-2 text-[12px] leading-[1.5] text-kelp-ink">
              Every model here is served from this machine or network and bills nothing, so Pi reports $0 whatever happens. The token cap is the brake: tokens over every turn, context re-sent each time — a few million for a small goal on two agents.
            </span>
          ) : null}
          <label className="flex flex-col gap-1.5">
            <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Wall clock<span className="ml-1 font-normal normal-case tracking-normal text-ink-3">· minutes</span></span>
            <div className="flex h-10 items-center rounded-lg border border-line bg-card px-3">
              <input inputMode="numeric" value={form.wall_clock} onChange={(e) => setForm({ ...form, wall_clock: e.target.value })} placeholder={String(defaultWallClock(effectiveN))} className="w-full border-0 bg-transparent font-mono text-[16px] text-ink outline-none placeholder:text-ink-3" aria-label="Wall clock minutes" />
            </div>
          </label>
          <span className="col-span-2 text-[12px] leading-[1.5] text-ink-2">
            {form.wall_clock ? "" : `Blank means swarm.sh's default of ${defaultWallClock(effectiveN)} min for ${effectiveN} agent${effectiveN === 1 ? "" : "s"}. `}
            At either cap every agent is steered once; two minutes later the harness writes the sentinel itself. A subscription's spend here is Pi's estimate, not a charge.
          </span>
        </section>

        <section className="card flex flex-col gap-2.5 rounded-xl border-paper-3 bg-paper-2 p-[16px_20px]" aria-label="Read-only inputs">
          <div className="flex items-center gap-2.5 text-[13px]">
            <Lock className="size-4 text-kelp-ink" /> Read-only inputs · files the swarm may read and never change
          </div>
          {inputsLib.data && !inputsLib.data.configured ? (
            <div className="flex flex-col gap-2 text-[12px] leading-[1.5] text-ink-2">
              <span>
                This server has no evidence root yet. Each directory directly under a root becomes a set a kickoff can hand a swarm as <code>inputs/</code>, copied and read-only. Name one when you start the console:
              </span>
              <pre className="m-0 overflow-x-auto rounded-lg bg-band px-3 py-2 font-mono text-[12px] text-band-ink">scripts/swarm.sh ui --inputs-root /path/to/evidence</pre>
              {inputsLib.data.runtime_roots ? <InputsRootAdder onAdded={() => inputsLib.reload()} /> : (
                <span className="text-ink-3">To add roots from this form instead, start it with <code>--allow-inputs-root-from-ui</code>. That lets anyone holding the token expose a directory on this machine, so it is off unless you say so.</span>
              )}
            </div>
          ) : (
            <>
              <InputsRoots lib={inputsLib.data} onChange={() => inputsLib.reload()} />
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_auto]">
                <label className="flex flex-col gap-1">
                  <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Input set</span>
                  <Select
                    mono
                    value={form.inputs}
                    onChange={(v) => setForm({ ...form, inputs: v })}
                    disabled={inputsLib.loading}
                    placeholder={inputsLib.loading ? "Reading the evidence roots…" : "none"}
                    searchPlaceholder="Filter sets…"
                    aria-label="Input set"
                    options={[
                      { value: "", label: "none", hint: "the swarm reads nothing but the goal" },
                      ...(inputsLib.data?.sets ?? []).map((s) => ({
                        value: s.id,
                        label: s.name,
                        group: (inputsLib.data?.roots.length ?? 0) > 1 ? s.root : undefined,
                        meta: `${s.files} file${s.files === 1 ? "" : "s"} · ${humanSize(s.bytes)}`,
                        hint: s.sample.slice(0, 3).join(", ") + (s.files > 3 ? ", …" : ""),
                        keywords: `${s.root} ${s.sample.join(" ")}`,
                      })),
                    ]}
                  />
                </label>
                <label className={cn("flex flex-col gap-1", !form.inputs && "opacity-50")}>
                  <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Kernel guard</span>
                  <Select
                    value={form.inputs_enforce}
                    onChange={(v) => setForm({ ...form, inputs_enforce: v as FormState["inputs_enforce"] })}
                    disabled={!form.inputs}
                    aria-label="Inputs enforcement"
                    options={[
                      { value: "auto", label: "auto", hint: "kernel when the host can" },
                      { value: "on", label: "on", hint: "refuse to start without it" },
                      { value: "off", label: "off", hint: "detect and heal only" },
                    ]}
                  />
                </label>
              </div>
              {form.inputs ? (
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <label className="flex flex-col gap-1">
                    <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Attach as</span>
                    <Select
                      value={form.inputs_attach}
                      onChange={(v) => setForm({ ...form, inputs_attach: v as FormState["inputs_attach"], inputs_image: v === "image" ? (chosenSet?.images[0] ?? "") : "" })}
                      aria-label="How the evidence is attached"
                      options={[
                        { value: "copy", label: "copy", hint: "a read-only copy under inputs/; the source is never touched" },
                        { value: "bind", label: "bind in place", hint: "no copy: the source itself is held read-only by the kernel, for evidence too large to copy" },
                        { value: "image", label: "disk image", hint: chosenSet?.images.length ? "attach a dmg, iso or img read-only (macOS)" : "no dmg, iso or img in this set", disabled: !chosenSet?.images.length },
                      ]}
                    />
                  </label>
                  {form.inputs_attach === "image" ? (
                    <label className="flex flex-col gap-1">
                      <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Image</span>
                      <Select mono value={form.inputs_image} onChange={(v) => setForm({ ...form, inputs_image: v })} aria-label="Disk image" placeholder="choose an image" options={(chosenSet?.images ?? []).map((f) => ({ value: f, label: f }))} />
                    </label>
                  ) : form.inputs_attach === "copy" ? (
                    <label className="flex flex-col gap-1">
                      <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Size ceiling<span className="ml-1 font-normal normal-case tracking-normal text-ink-3">· MB · optional</span></span>
                      <div className="flex h-10 items-center rounded-lg border border-line bg-card px-3">
                        <input inputMode="numeric" value={form.inputs_max_mb} onChange={(e) => setForm({ ...form, inputs_max_mb: e.target.value })} placeholder="none" className="w-full border-0 bg-transparent font-mono text-[16px] text-ink outline-none placeholder:text-ink-3" aria-label="Inputs size ceiling in MB" />
                      </div>
                    </label>
                  ) : (
                    <span className="self-end pb-2.5 text-[12px] leading-[1.5] text-ink-2">Nothing is copied. The harness refuses this on a host without a kernel guard, because the source would be writable.</span>
                  )}
                </div>
              ) : null}
              <span className="text-[12px] leading-[1.5] text-ink-2">
                {chosenSet
                  ? `${chosenSet.files} file${chosenSet.files === 1 ? "" : "s"}, ${humanSize(chosenSet.bytes)}${chosenSet.sample.length ? `: ${chosenSet.sample.join(", ")}${chosenSet.files > chosenSet.sample.length ? ", …" : ""}` : ""}${form.inputs_attach === "bind" ? ". Held read-only in place by the kernel; nothing is copied, and the source stays exactly as it is." : form.inputs_attach === "image" ? ". The image is attached read-only and used as inputs/; the kernel refuses every write to it." : ". Copied into inputs/ at kickoff; edit, write and claim_file refuse it, a shell write is undone and announced, and on macOS and Linux the panes run with it read-only at the kernel."}`
                  : inputsLib.data?.sets.length
                    ? "Pick a set to hand the swarm files to analyse. Results go in work/; the inputs stay as they were."
                    : "No sets yet: a set is a directory directly under a root, so put the evidence for one case in its own directory there."}
              </span>
              <CleanRoom
                chosen={form.no_read}
                runs={earlier.data ?? []}
                evidence={chosenSet ? `${chosenSet.root}/${chosenSet.name}` : null}
                onChange={(no_read) => setForm({ ...form, no_read })}
              />
            </>
          )}
        </section>

        <section className="card flex flex-col gap-2.5 rounded-xl border-paper-3 bg-paper-2 p-[16px_20px]" aria-label="Case settings">
          <div className="flex items-center gap-2.5 text-[13px]">
            <Lock className="size-4 text-kelp-ink" /> Case · the first pass, the tools, the no-exec rule, the identifiers
          </div>
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-3 text-[13px]">
              <span>
                Evidence catalog
                <span className="block text-[12px] leading-[1.5] text-ink-2">
                  The standard first pass over the inputs before any agent starts: partition table, file list, body file and MAC timeline for a disk image; process, command line and injection lists for a memory image. Needs an input set.
                </span>
              </span>
              <Switch checked={form.catalog} onCheckedChange={(v) => setForm({ ...form, catalog: v })} aria-label="Evidence catalog" disabled={!form.inputs} />
            </div>
            <div className="flex items-center justify-between gap-3 text-[13px]">
              <span>
                Install what the case needs
                <span className="block text-[12px] leading-[1.5] text-ink-2">
                  Agents may <code>pip install</code> from <code>pypi.org</code> into <code>work/.toolchain/</code>, inside the sandbox, when the host is missing a reader the case turns on. Still no root and no system packages. Off by default; what was installed belongs in the ledger.
                </span>
              </span>
              <Switch checked={form.allow_install} onCheckedChange={(v) => setForm({ ...form, allow_install: v, no_pypi: v ? form.no_pypi : false })} aria-label="Allow install" />
            </div>
            <div className={cn("ml-4 flex items-center justify-between gap-3 border-l-2 border-line pl-3 text-[13px]", !form.allow_install && "opacity-50")}>
              <span>
                Keep the package index off the allowlist
                <span className="block text-[12px] leading-[1.5] text-ink-2">Installs come only from what pip has cached on this host; <code>pypi.org</code> is not reachable from the panes. For a run whose record must show no new download.</span>
              </span>
              <Switch checked={form.no_pypi} disabled={!form.allow_install} onCheckedChange={(v) => setForm({ ...form, no_pypi: v })} aria-label="No package index" />
            </div>
            <div className="flex items-center justify-between gap-3 text-[13px]">
              <span>
                Quarantine
                <span className="block text-[12px] leading-[1.5] text-ink-2">
                  Nothing under <code>work/extracted/</code> or <code>work/quarantine/</code> may execute: no-exec at the kernel, and execute bits stripped.
                </span>
              </span>
              <Switch checked={form.quarantine} onCheckedChange={(v) => setForm({ ...form, quarantine: v })} aria-label="Quarantine" />
            </div>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <label className="flex flex-col gap-1">
              <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Toolbox</span>
              <Select
                value={form.toolbox}
                onChange={(v) => setForm({ ...form, toolbox: v })}
                aria-label="Toolbox"
                options={[
                  { value: "", label: "none", hint: "check nothing" },
                  { value: "auto", label: "auto", hint: "dfir when the catalog is on" },
                  { value: "dfir", label: "dfir", hint: "Sleuth Kit, libewf, Volatility, YARA and the parsers a case needs" },
                  { value: "dfir,crypto", label: "dfir, crypto" },
                  { value: "dfir,linux", label: "dfir, linux" },
                  { value: "dfir,crypto,linux", label: "dfir, crypto, linux" },
                  { value: "crypto", label: "crypto" },
                  { value: "linux", label: "linux" },
                  { value: "off", label: "off", hint: "skip the check even when the catalog is on" },
                ]}
              />
            </label>
            <label className="flex flex-col gap-1.5">
              <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">USD cap<span className="ml-1 font-normal normal-case tracking-normal text-ink-3">· one agent{allLocal ? " · not in force" : " · optional"}</span></span>
              <div className={cn("flex h-10 items-center gap-1.5 rounded-lg border border-line bg-card px-3", allLocal && "opacity-60")}>
                <span className="text-ink-3">$</span>
                <input inputMode="decimal" value={form.cap_per_agent} onChange={(e) => setForm({ ...form, cap_per_agent: e.target.value })} placeholder="none" className="w-full border-0 bg-transparent font-mono text-[16px] text-ink outline-none placeholder:text-ink-3" aria-label="Per-agent USD cap" />
              </div>
            </label>
            <label className="flex flex-col gap-1">
              <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Case id</span>
              <Input value={form.case_id} onChange={(e) => setForm({ ...form, case_id: e.target.value })} placeholder="AH-C11" aria-label="Case id" />
            </label>
            <label className="flex flex-col gap-1">
              <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Examiner</span>
              <Input value={form.examiner} onChange={(e) => setForm({ ...form, examiner: e.target.value })} placeholder="who is running it" aria-label="Examiner" />
            </label>
          </div>
          <div className="flex items-center justify-between gap-3 text-[13px]">
            <span>
              Refuse to start without the toolbox
              <span className="block text-[12px] leading-[1.5] text-ink-2">A tool the toolbox names and the host lacks is a refusal at kickoff, not a warning in the record. For a case that cannot be worked without its parsers.</span>
            </span>
            <Switch checked={form.toolbox_required} disabled={!form.toolbox || form.toolbox === "off"} onCheckedChange={(v) => setForm({ ...form, toolbox_required: v })} aria-label="Toolbox required" />
          </div>
          <label className="flex flex-col gap-1">
            <span className="label-caps flex min-h-[2.1em] items-start leading-[1.35]">Start with the tools of<span className="ml-1 font-normal normal-case tracking-normal text-ink-3">· an earlier run · optional</span></span>
            <Select
              mono
              value={form.tools_from}
              onChange={(v) => setForm({ ...form, tools_from: v })}
              aria-label="Tools from an earlier run"
              placeholder="none"
              searchPlaceholder="Filter runs…"
              options={[
                { value: "", label: "none", hint: "the agents start with the lab's tools and write what they lack" },
                ...(earlier.data ?? [])
                  .filter((r) => r.tools_forged > 0)
                  .map((r) => ({ value: r.id, label: r.id, hint: r.label || r.goal.slice(0, 60), meta: `${r.tools_forged} tool${r.tools_forged === 1 ? "" : "s"}`, keywords: r.label })),
              ]}
            />
            <span className="text-[12px] leading-[1.5] text-ink-2">Every tool that run forged, with its manifest and hash, is in each agent's list from the first turn. The library grows across cases.</span>
          </label>
          <span className="text-[12px] leading-[1.5] text-ink-2">
            The case id and the examiner are recorded in the registry, the contract and the summary, so a run can be filed. A per-agent cap steers that one agent to finish and stops it; the swarm goes on.
          </span>
        </section>

        <section className="card flex flex-col gap-2.5 rounded-xl border-paper-3 bg-paper-2 p-[16px_20px]">
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-3 text-[13px]">
              <span className="flex items-center gap-2.5">
                <Lock className="size-4 text-kelp-ink" /> Network · what the panes may reach
              </span>
              <div className="inline-flex rounded-full border border-line p-0.5" role="group" aria-label="Network">
                {NET_CHOICES.map((c) => (
                  <button
                    key={c.value}
                    type="button"
                    onClick={() => setForm({ ...form, net: c.value })}
                    aria-pressed={form.net === c.value}
                    className={cn(
                      "rounded-full px-3 py-1 text-[12px] font-medium",
                      form.net === c.value ? "bg-kelp text-white" : "text-ink-2",
                    )}
                  >
                    {c.label}
                  </button>
                ))}
              </div>
            </div>
            <p className="text-[12px] text-ink-2">{NET_CHOICES.find((c) => c.value === form.net)?.hint}</p>
            {form.net === "hosts" ? (
              <Input
                value={form.allow_hosts}
                onChange={(e) => setForm({ ...form, allow_hosts: e.target.value })}
                placeholder="pypi.org files.pythonhosted.org"
                aria-label="Allowed hosts"
                className="font-mono text-[13px]"
              />
            ) : null}
            {form.net === "hosts" && hostList.length === 0 ? (
              <p className="text-[12px] text-band-brick">Name at least one host, or choose Guarded.</p>
            ) : null}
            {form.net === "open" ? (
              <p className="text-[12px] text-band-brick">
                Everything the agents fetch, and anything they could send, is then outside the run's record. Do not use it on evidence.
              </p>
            ) : null}
            {form.net === "local" && !allLocal ? (
              <p className="text-[12px] text-band-brick">{chosenModels.length ? `${notLocal.join(", ")} is not a local model; Local only is refused with a cloud model on the team.` : "Pick a local model first."}</p>
            ) : null}
          </div>
          <label className="flex items-center justify-between gap-3 text-[13px]">
            <span>Playwright · browser tools for goals that must render something</span>
            <Switch checked={form.playwright} onCheckedChange={(v) => setForm({ ...form, playwright: v })} aria-label="Playwright" />
          </label>
          <label className="flex items-center justify-between gap-3 text-[13px]">
            <span>Hard kill · shut the session at the steer instead of after the grace</span>
            <Switch checked={form.hard_kill} onCheckedChange={(v) => setForm({ ...form, hard_kill: v })} aria-label="Hard kill" />
          </label>
          <label className="flex items-center justify-between gap-3 text-[13px]">
            <span>Tool forging · agents may write tools with make_tool and share them (runs as a subprocess, same limits as bash)</span>
            <Switch checked={form.tool_forging} onCheckedChange={(v) => setForm({ ...form, tool_forging: v })} aria-label="Tool forging" />
          </label>
          <label className="flex items-center justify-between gap-3 text-[13px]">
            <span>Self compaction · agents compact their own context: notice 40% · warning 50% · compact 60% of each model's ceiling</span>
            <Switch checked={form.self_compact} onCheckedChange={(v) => setForm({ ...form, self_compact: v })} aria-label="Self compaction" />
          </label>
          {form.self_compact ? (
            <div className="ml-4 flex flex-wrap items-end gap-3 border-l-2 border-line pl-3 text-[13px]">
              {(
                [
                  ["compact_notice_at", "notice", "40%"],
                  ["compact_warn_at", "warning", "50%"],
                  ["compact_at", "compact", "60%"],
                ] as Array<["compact_notice_at" | "compact_warn_at" | "compact_at", string, string]>
              ).map(([key, label, placeholder]) => (
                <label key={key} className="flex flex-col gap-1">
                  <span className="label-caps">{label}</span>
                  <Input value={form[key]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} placeholder={placeholder} className="w-[84px] font-mono" aria-label={`Compact ${label} line`} />
                </label>
              ))}
              <span className="pb-2 text-[12px] leading-[1.5] text-ink-2">tokens (150k) or % of the ceiling; per model after a comma (60%,openai/gpt-5.4-mini=55%)</span>
              <label className="flex flex-col gap-1">
                <span className="label-caps">summary model</span>
                <Input value={form.compact_model} onChange={(e) => setForm({ ...form, compact_model: e.target.value })} placeholder="agent's own" className="w-[220px] font-mono" aria-label="Summary model" />
              </label>
              <span className="pb-2 text-[12px] leading-[1.5] text-ink-2">provider/id for every summary call; a cheap model for expensive seats</span>
            </div>
          ) : null}
          <label className="flex items-center justify-between gap-3 text-[13px]">
            <span>Inbox page · how much post text one inbox or wait delivery carries; whole posts only, the rest stays unread for the next call (0 removes the bound)</span>
            <Input value={form.inbox_page_chars} onChange={(e) => setForm({ ...form, inbox_page_chars: e.target.value })} placeholder="40000" className="w-[96px] font-mono" aria-label="Inbox page characters" />
          </label>
          <label className="flex items-center justify-between gap-3 text-[13px]">
            <span>Prepare only · write the sandbox, launch nothing</span>
            <Switch checked={form.no_start} onCheckedChange={(v) => setForm({ ...form, no_start: v })} aria-label="Prepare only" />
          </label>
          <div className="flex items-center gap-2.5 border-t border-paper-3 pt-2 text-[12.5px] text-ink-2">
            <Check className="size-4 text-kelp-ink" /> Credentials stay in Pi's own store; nothing is passed to the panes
          </div>
        </section>

        <label className="flex flex-col gap-1.5">
          <span className="label-caps">Label · optional</span>
          <Input value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="what this run is for" className="h-9 rounded-lg" />
        </label>

        <div className="flex flex-col gap-2.5">
          <code className="block whitespace-pre-wrap break-all rounded-lg bg-band px-3 py-2.5 font-mono text-[11.5px] leading-[1.5] text-[#e6e1d6]">{command}</code>
          {problems.length ? (
            <ul className="m-0 flex list-none flex-col gap-1 p-0">
              {problems.map((p) => (
                <li key={p}>
                  <Chip tone="saffron" className="h-auto whitespace-normal py-1 text-[12px]">
                    {p}
                  </Chip>
                </li>
              ))}
            </ul>
          ) : null}
          <Button type="submit" disabled={submitting || problems.length > 0} className="h-12 rounded-[10px] text-[15px]">
            <ArrowRight /> {form.no_start ? "Prepare the sandbox" : "Start the swarm"}
          </Button>
          {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
          {job ? <JobCard job={job} /> : null}
        </div>
      </aside>
    </form>
  );
}
