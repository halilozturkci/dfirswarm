/**
 * What the host could say about the run once nothing was running any more:
 * custody.json, which stop (or the hub, at the end of a VM run) writes after
 * re-hashing the evidence, checking the trace and ledger chains, and putting
 * each VM's disk away. The console used to show none of it, so a changed
 * evidence file or a secret aimed at the wrong host was only in a file
 * nobody opens. Every name is shown whole: nothing here is cut.
 */
import { useCallback } from "react";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { Chip } from "@/components/console";
import { api } from "@/lib/api";
import { bytes, dateTime } from "@/lib/format";
import { useResource } from "@/lib/live";
import type { ClockReference, CustodyCheck, CustodyView, OperatorAudit, SwarmView } from "@/lib/types";
import { cn } from "@/lib/utils";

function Names({ label, names }: { label: string; names: string[] }) {
  if (!names.length) return null;
  return (
    <details className="text-[12px]">
      <summary className="cursor-pointer text-ink-2">
        {names.length} {label}
      </summary>
      <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px] text-ink">
        {names.map((n) => (
          <li key={n} className="[overflow-wrap:anywhere]">
            {n}
          </li>
        ))}
      </ul>
    </details>
  );
}

function Row({ label, bad, children }: { label: string; bad?: boolean; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1 border-t border-line py-2 sm:grid-cols-[140px_minmax(0,1fr)]">
      <span className="label-caps pt-0.5">{label}</span>
      <div className={cn("flex min-w-0 flex-col gap-1 text-[12.5px] [overflow-wrap:anywhere]", bad ? "text-brick-ink" : "text-ink-2")}>{children}</div>
    </div>
  );
}

function evidenceLine(e: NonNullable<CustodyView["evidence"]>): { text: string; bad: boolean } {
  if ("unverifiable" in e) return { text: `unverifiable: ${e.unverifiable}`, bad: true };
  const anchored = e.manifest_anchored === true ? "manifest anchored to the kickoff's record" : e.manifest_anchored === false ? "MANIFEST REWRITTEN: not the one the kickoff recorded" : "manifest not anchored (no kickoff record to compare)";
  // Skipped is what the deadline left unread: the verdict does not cover it.
  const skipped = e.skipped.length ? ` · ${e.skipped.length} NOT RE-READ before the deadline` : "";
  if (e.unchanged && e.complete) return { text: `unchanged since the run began · ${e.files} file${e.files === 1 ? "" : "s"} re-hashed in full · ${anchored}`, bad: e.manifest_anchored === false };
  if (e.changed.length || e.missing.length || e.added.length || e.manifest_anchored === false) {
    return { text: `CHANGED · ${e.changed.length} changed, ${e.missing.length} missing, ${e.added.length} added of ${e.files}${skipped} · ${anchored}`, bad: true };
  }
  return { text: `NOT FULLY RE-HASHED · ${e.files - e.skipped.length} of ${e.files} checked unchanged${skipped} · ${anchored}`, bad: true };
}

const CHECK_TONE: Record<CustodyCheck["status"], "moss" | "brick" | "saffron" | "neutral"> = {
  passed: "moss",
  failed: "brick",
  incomplete: "saffron",
  unavailable: "brick",
  not_applicable: "neutral",
};

/** Each check custody made, with its status: an omitted or failed check is never a quiet pass. */
function Checks({ checks }: { checks: CustodyCheck[] }) {
  if (!checks.length) return null;
  return (
    <div className="flex flex-col gap-1 border-t border-line py-2" aria-label="Custody checks">
      <span className="label-caps">Checks</span>
      <ul className="m-0 flex list-none flex-col gap-1 p-0">
        {checks.map((c) => (
          <li key={c.name} className="flex flex-wrap items-baseline gap-2 text-[12.5px]">
            <Chip tone={CHECK_TONE[c.status]}>{c.status.replace("_", " ")}</Chip>
            <span className="text-ink">{c.name}</span>
            {c.expected !== undefined ? (
              <span className="font-mono text-[11px] text-ink-3">
                {c.checked ?? 0} of {c.expected}
              </span>
            ) : null}
            {c.reason ? <span className={cn("[overflow-wrap:anywhere]", c.status === "not_applicable" || c.status === "passed" ? "text-ink-3" : "text-brick-ink")}>{c.reason}</span> : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

function clockText(r: ClockReference | null, when: string): string | null {
  if (!r) return null;
  if (r.offset_ms === null) return `${when}: ${r.url} not read (${r.error ?? "no answer"})`;
  return `${when}: the host ${r.offset_ms >= 0 ? "behind" : "ahead of"} ${r.url} by ${Math.abs(r.offset_ms)} ms (± ${r.precision_ms} ms)`;
}

/** What the verdict sealed, how it is held, and how to check it again. */
function Sealed({ c, id }: { c: CustodyView; id: string }) {
  const clocks = [clockText(c.time_reference?.kickoff ?? null, "at kickoff"), clockText(c.time_reference?.custody ?? null, "at custody")].filter((x): x is string => Boolean(x));
  return (
    <>
      {c.acquisition !== undefined ? (
        <Row label="Acquisition hashes" bad={!!c.acquisition?.mismatched.length}>
          {!c.acquisition
            ? "not given at kickoff (--inputs-hashes): unchanged means since the kickoff hashed the evidence, not against the imager's own numbers"
            : c.acquisition.mismatched.length
              ? `DO NOT MATCH: ${c.acquisition.mismatched.join(", ")}`
              : `${c.acquisition.matched} of ${c.acquisition.given} digests from ${c.acquisition.source ?? "the file given"} match the evidence as re-hashed`}
          {c.acquisition?.not_compared.length ? <Names label="not compared" names={c.acquisition.not_compared} /> : null}
          {c.acquisition?.source_sha256 ? <span className="font-mono text-[11px] text-ink-3">the hash list's sha256 {c.acquisition.source_sha256}</span> : null}
        </Row>
      ) : null}
      {c.seal ? (
        <Row label="Sealed">
          <span>
            trace {c.seal.trace.lines} lines · ledger {c.seal.ledger.entries} entries{c.seal.attestations.lines ? ` · ${c.seal.attestations.lines} attestations` : ""}
            {c.seal.journal ? ` · store journal ${c.seal.journal.lines} lines` : ""}
          </span>
          <span className="font-mono text-[11px] text-ink-3">trace's last line {c.seal.trace.last_line_sha256 ?? "none"}</span>
          {c.seal.ledger.head ? <span className="font-mono text-[11px] text-ink-3">ledger head {c.seal.ledger.head}</span> : null}
          {c.seal.journal?.head ? <span className="font-mono text-[11px] text-ink-3">journal head {c.seal.journal.head}</span> : null}
        </Row>
      ) : null}
      {c.attestations ? (
        <Row label="Attestations" bad={!c.attestations.intact}>
          {c.attestations.intact ? `${c.attestations.lines} line${c.attestations.lines === 1 ? "" : "s"}, chain intact: a second author of an entry, appended beside it` : `CHAIN BROKEN: ${c.attestations.detail}`}
        </Row>
      ) : null}
      {c.operator_check ? (
        <Row label="Operator audit" bad={!c.operator_check.intact || c.operator_check.unmatched.length > 0}>
          {c.operator_check.intact ? `${c.operator_check.detail} · ${c.operator_check.matched} of ${c.operator_check.trace_actions} operator line(s) on the trace are on it` : `CHAIN BROKEN: ${c.operator_check.detail}`}
          {c.operator_check.unmatched.length ? <Names label="operator lines on the trace not on the audit" names={c.operator_check.unmatched.map((u) => `${u.at} ${u.command} ${u.argv.join(" ")}`)} /> : null}
        </Row>
      ) : null}
      <Row label="Signature" bad={!!c.signature?.error}>
        {c.signature ? (c.signature.error ? `NOT SIGNED: ${c.signature.error}` : `custody.json.sig · ssh key ${c.signature.key ?? "(fingerprint not recorded)"} · namespace dfirswarm-custody`) : "custody.json is not signed (--custody-sign-key)"}
      </Row>
      <Row label="Timestamp" bad={!!c.timestamp?.error}>
        {c.timestamp ? (c.timestamp.error ? `NOT TIMESTAMPED: ${c.timestamp.error}` : `RFC 3161 from ${c.timestamp.authority ?? "?"} · ${c.timestamp.gen_time ?? "time not read"}`) : "no trusted timestamp (--custody-timestamp-url)"}
      </Row>
      <Row label="Reference clock">{clocks.length ? clocks.join(" · ") : "no reference clock named (--time-reference)"}</Row>
      {c.models ? (
        <Row label="Models">
          <span>{[...new Set(c.models.team.map((m) => m.model ?? "not recorded"))].join(", ")} (as given to the agents)</span>
          <span className="text-ink-3">{c.models.gateway_answered ? `the gateway saw ${c.models.gateway_answered.join(", ") || "none"} answer` : "no host-side record of which model ids answered (no model gateway)"}</span>
        </Row>
      ) : null}
      {c.timing ? (
        <Row label="Custody's cost">
          {Math.round(c.timing.total_ms / 1000)} s · {bytes(c.timing.evidence_bytes)} of evidence re-read{c.timing.evidence_mb_per_s ? ` at ${c.timing.evidence_mb_per_s} MB/s` : ""}
        </Row>
      ) : null}
      <Row label="Check it again">
        <code className="font-mono text-[11.5px]">scripts/swarm.sh custody-verify {id}</code>
        <span className="text-ink-3">writes nothing: every check again, the sealed prefix of the trace, the lines written after the seal, the signature and the timestamp token</span>
      </Row>
      <Row label="The anchors">
        <span className="text-ink-3">files of the operator's own account beside the run: they hold the agents to account; a signature and a trusted timestamp hold the verdict itself</span>
      </Row>
    </>
  );
}

export function CustodyPanel({ view }: { view: SwarmView }) {
  const c = view.custody;
  const phase = view.summary.phase;
  const id = view.summary.id;
  const loadOperator = useCallback(() => api.operator(id), [id]);
  const operator = useResource<OperatorAudit>(loadOperator, 0, [id, "operator"]);
  if (!c) {
    const pending = phase === "running" || phase === "prepared" || view.summary.finishing;
    return (
      <div className="space-y-4">
        <section className="card flex items-start gap-2.5 p-4 text-[12.5px] text-ink-2" aria-label="Custody">
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-ink-3" />
          <span>
            {pending ? (
              <>
                Custody is taken when the run stops: the host re-hashes the evidence, checks the trace and ledger chains and each VM, and seals the verdict into <code>custody.json</code>, anchored outside the run. {view.summary.finishing ? "The hub is putting the VMs away now; custody follows." : ""}
              </>
            ) : (
              <>
                No custody was taken for this run: no <code>custody.json</code>. <code>scripts/swarm.sh stop {id}</code> takes it (the hub takes it itself at the end of a VM run), or run <code>scripts/custody.ts</code> on the sandbox.
              </>
            )}
          </span>
        </section>
        <RunRecord view={view} operator={operator.data} />
      </div>
    );
  }
  const clean = c.verdict === "clean";
  const ev = c.evidence ? evidenceLine(c.evidence) : null;
  return (
    <section className="card space-y-2 p-4" aria-label="Custody">
      <div className="flex flex-wrap items-center gap-2">
        {clean ? <ShieldCheck className="size-4 text-moss" /> : <ShieldAlert className="size-4 text-brick" />}
        <span className="text-[14px] font-medium text-ink">Custody</span>
        <Chip tone={clean ? "moss" : "brick"}>{clean ? "clean" : `${c.problems.length} to look at`}</Chip>
        {c.at ? <span className="font-mono text-[11.5px] text-ink-3">taken {dateTime(c.at)}</span> : null}
        {c.anchor ? <span className="text-[11.5px] text-ink-3">custody.json {c.anchor}</span> : null}
      </div>
      {c.summary ? <p className="m-0 font-mono text-[11.5px] leading-[1.55] text-ink-2 [overflow-wrap:anywhere]">{c.summary}</p> : null}
      {c.problems.length ? (
        <ul className="m-0 flex list-disc flex-col gap-0.5 pl-5 text-[12.5px] text-brick-ink">
          {c.problems.map((p) => (
            <li key={p} className="[overflow-wrap:anywhere]">
              {p}
            </li>
          ))}
        </ul>
      ) : null}
      <Checks checks={c.checks ?? []} />
      <div className="flex flex-col">
        <Row label="Evidence" bad={ev?.bad}>
          {ev ? ev.text : "no evidence was given to this run"}
          {c.evidence && !("unverifiable" in c.evidence) && c.evidence.digests ? (
            <span className="text-ink-3">
              sha256 compared on {c.evidence.digests.sha256}
              {c.evidence.digests.md5 ? `, md5 on ${c.evidence.digests.md5}` : ""}
              {c.evidence.digests.sha1 ? `, sha1 on ${c.evidence.digests.sha1}` : ""}
              {c.evidence.checked ? ` · ${c.evidence.checked.files} files by their bytes, ${c.evidence.checked.links} links by their target, ${c.evidence.checked.special} special files by their kind` : ""}
            </span>
          ) : null}
          {view.inputs?.source_checked ? <span className={view.inputs.source_checked.mismatches ? "text-brick-ink" : "text-ink-3"}>at the kickoff the copy was {view.inputs.source_checked.detail}</span> : null}
          {c.evidence && !("unverifiable" in c.evidence) ? (
            <>
              <Names label="changed" names={c.evidence.changed} />
              <Names label="missing" names={c.evidence.missing} />
              <Names label="added" names={c.evidence.added} />
              <Names label="not re-read before the deadline (the verdict does not cover them)" names={c.evidence.skipped} />
            </>
          ) : null}
        </Row>
        {c.incomplete ? (
          <Row label="Incomplete" bad>
            {c.incomplete}
          </Row>
        ) : null}
        {c.sessions_not_files.length ? (
          <Row label="Sessions" bad>
            {c.sessions_not_files.length} name{c.sessions_not_files.length === 1 ? "" : "s"} under the sessions not a regular file, so sealed as nothing
            <Names label="not a file" names={c.sessions_not_files} />
          </Row>
        ) : null}
        <Row label="Trace chain" bad={!c.trace || !c.trace.lines || !c.trace.intact || c.trace.lost > 0 || c.trace.refused_spills.length > 0}>
          {!c.trace
            ? "not checked"
            : !c.trace.lines
              ? "NO TRACE"
              : `${c.trace.lines} lines · ${c.trace.intact ? "chain intact" : `CHAIN NOT INTACT${c.trace.detail ? `: ${c.trace.detail}` : ""}`}${c.trace.unverified ? ` · ${c.trace.unverified} unverified` : ""}${c.trace.disputed ? ` · ${c.trace.disputed} disputed` : ""}${c.trace.spilled ? ` · ${c.trace.spilled} outside the chain (spilled)` : ""}${c.trace.lost ? ` · ${c.trace.lost} LOST` : ""}`}
          {c.trace?.refused_spills.length ? (
            <ul className="m-0 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px]">
              {c.trace.refused_spills.map((r) => (
                <li key={r.path} className="[overflow-wrap:anywhere]">
                  SPILL NOT READ: {r.path} is {r.why}
                </li>
              ))}
            </ul>
          ) : null}
        </Row>
        <Row label="Ledger chain" bad={!!c.ledger && !c.ledger.intact}>
          {!c.ledger
            ? "no ledger"
            : `${c.ledger.entries} entr${c.ledger.entries === 1 ? "y" : "ies"}${c.ledger.chained !== null && c.ledger.chained !== c.ledger.entries ? `, ${c.ledger.chained} chained` : ""} · ${c.ledger.intact ? "chain intact" : `NOT INTACT${c.ledger.detail ? `: ${c.ledger.detail}` : ""}`}`}
          {c.ledger ? (
            <>
              <Names label="on the trace and missing from the ledger (deleted)" names={c.ledger.missing_from_ledger} />
              <Names label="in the ledger and never on the trace (seq; written without the tool)" names={c.ledger.not_on_trace.map(String)} />
            </>
          ) : null}
        </Row>
        {c.artifacts ? (
          <Row label="Artifact index">
            {c.artifacts.files} file{c.artifacts.files === 1 ? "" : "s"} · {bytes(c.artifacts.bytes)}
            {c.artifacts.skipped ? ` · ${c.artifacts.skipped} not hashed` : ""}
            {c.artifacts.index_sha256 ? <span className="font-mono text-[11px] text-ink-3">artifacts.json sha256 {c.artifacts.index_sha256}</span> : null}
          </Row>
        ) : null}
        {c.tool_outputs ? (
          <Row label="Kept outputs" bad={!!(c.tool_outputs.missing.length || c.tool_outputs.mismatched.length || c.tool_outputs.refused.length)}>
            {c.tool_outputs.verified} of {c.tool_outputs.referenced} verified against the trace
            <Names label="missing" names={c.tool_outputs.missing} />
            <Names label="not matching the trace" names={c.tool_outputs.mismatched} />
            <Names label="refused" names={c.tool_outputs.refused} />
          </Row>
        ) : null}
        {c.vms?.map((vm) => {
          const away = vm.stopped && !vm.kept && !vm.snapshot?.startsWith("failed");
          // A stop on the credential's own host is a failed request, not a
          // leak; one aimed elsewhere (or not known to be its own) is the alarm.
          const elsewhere = vm.secret_violations.filter((x) => x.own_host !== true);
          const ownHost = vm.secret_violations.filter((x) => x.own_host === true);
          const bad = !away || vm.image_differs || elsewhere.length > 0 || vm.installed_outside.length > 0 || !!vm.runtime_changed;
          return (
            <Row key={vm.agent} label={`VM ${vm.agent}`} bad={bad}>
              <span>
                {away ? "put away" : `NOT PUT AWAY${vm.kept ? `: ${vm.kept}` : ""}`}
                {vm.snapshot ? ` · snapshot ${vm.snapshot}` : " · no snapshot"}
                {vm.runtime_changed ? ` · msb changed ${vm.runtime_changed}` : ""}
              </span>
              {vm.image_differs ? (
                <span>
                  IMAGE DIGEST DIFFERS: booted <code>{vm.image}</code>, the run expected <code>{vm.expected_image}</code>
                </span>
              ) : null}
              {elsewhere.length ? (
                <div>
                  {elsewhere.length} secret placeholder{elsewhere.length === 1 ? "" : "s"} aimed at a host not its own, stopped by msb:
                  <ul className="m-0 mt-0.5 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px]">
                    {elsewhere.map((x, i) => (
                      <li key={i} className="[overflow-wrap:anywhere]">
                        {x.at} · {x.env} → {x.host} {x.method} {x.path}
                        {x.location ? ` (${x.location})` : ""} · {x.action}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {ownHost.length ? (
                <details className="text-ink-2">
                  <summary className="cursor-pointer">
                    {ownHost.length} request{ownHost.length === 1 ? "" : "s"} to the credential's own host stopped by msb, on a placeholder it found outside the headers: not a leak, each request failed
                  </summary>
                  <ul className="m-0 mt-0.5 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px]">
                    {ownHost.map((x, i) => (
                      <li key={i} className="[overflow-wrap:anywhere]">
                        {x.at} · {x.env} → {x.host} {x.method} {x.path}
                        {x.location ? ` (${x.location}${x.match_form ? `, ${x.match_form}` : ""})` : ""}
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
              {vm.installed_outside.length ? <span>installed outside the image and the toolchain record: {vm.installed_outside.join(", ")}</span> : null}
              {vm.installed_note ? <span className="text-ink-3">{vm.installed_note}</span> : null}
              {(() => {
                // What the VM's own record adds: the kept disk and msb's database.
                const rec = view.vms?.find((v) => v.agent === vm.agent);
                if (!rec) return null;
                return (
                  <>
                    {rec.snapshot_detail?.path ? (
                      <span className="text-ink-3">
                        disk at <span className="font-mono">{rec.snapshot_detail.path}</span>
                        {rec.snapshot_detail.bytes !== null ? ` · ${bytes(rec.snapshot_detail.bytes)}` : ""}
                      </span>
                    ) : null}
                    {rec.msb_db ? (
                      <span className={rec.msb_db === "scrubbed" || rec.msb_db === "no database" ? "text-ink-3" : "text-saffron-ink"}>
                        {rec.msb_db === "scrubbed" ? "msb's database cleared of its configuration" : `msb's database ${rec.msb_db}: a secret's value may remain in it`}
                      </span>
                    ) : null}
                  </>
                );
              })()}
              {vm.record_sha256 ? <span className="font-mono text-[11px] text-ink-3">record sha256 {vm.record_sha256}</span> : null}
            </Row>
          );
        })}
        <Sealed c={c} id={id} />
      </div>
      <RunRecord view={view} operator={operator.data} />
    </section>
  );
}

/**
 * What produced the run and who acted on it: the provenance and the host
 * clock the kickoff recorded, the custody deadline, the disk and the hold,
 * and the operator's own record for this run (runs/operator-audit.jsonl,
 * chained, and the operator lines on the run's trace).
 */
function RunRecord({ view, operator }: { view: SwarmView; operator: OperatorAudit | null }) {
  const r = view.registry;
  const p = r?.provenance;
  const clock = r?.host_clock;
  const timeout = r?.custody_timeout_sec;
  const hold = view.summary.hold ?? null;
  const stops = (operator?.lines ?? []).filter((l) => l.command === "stop");
  return (
    <div className="flex flex-col">
      {p ? (
        <Row label="Provenance" bad={p.harness_dirty === true}>
          <span>
            harness {p.harness_commit ?? "?"}
            {p.harness_dirty ? " · WITH LOCAL CHANGES" : ""} · Node {p.node_version ?? "?"} · Pi {p.pi_version ?? "?"}
            {p.msb_version ? ` · msb ${p.msb_version}` : ""} · {p.os ?? "?"} {p.arch ?? ""}
          </span>
          {p.image_digest ? <span className="font-mono text-[11px] text-ink-3">image {p.image_digest}</span> : null}
        </Row>
      ) : null}
      {clock ? (
        <Row label="Host clock" bad={clock.synced === false}>
          {clock.tz ?? "?"} ({clock.abbreviation ?? "?"}, UTC{clock.utc_offset ?? "?"}) ·{" "}
          {clock.synced === true ? `in sync (${clock.source ?? "?"})` : clock.synced === false ? "NOT in sync" : "sync unknown"} · the run's own processes in {clock.run_processes_tz ?? "UTC"}
        </Row>
      ) : null}
      {timeout !== undefined || r?.disk_encryption || hold ? (
        <Row label="Record" bad={r?.disk_encryption === "off"}>
          {timeout !== undefined ? <span>custody deadline {timeout} s</span> : null}
          {r?.disk_encryption ? <span>the runs directory's disk: encryption {r.disk_encryption}</span> : null}
          {hold ? <span>on legal hold{hold.reason ? `: ${hold.reason}` : ""}{hold.at ? ` since ${hold.at}` : ""}</span> : null}
        </Row>
      ) : null}
      {operator ? (
        <Row label="Who did what" bad={!operator.intact}>
          <span>
            {stops.length ? `stopped by ${stops.map((l) => `${l.os_user}@${l.host} via ${l.via} at ${l.at}`).join("; ")}` : "no stop recorded in the operator's record"} · the operator's record: {operator.detail}
          </span>
          {operator.lines.length ? (
            <details className="text-[12px]">
              <summary className="cursor-pointer text-ink-2">{operator.lines.length} command{operator.lines.length === 1 ? "" : "s"} on this run</summary>
              <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px]">
                {operator.lines.map((l, i) => (
                  <li key={i} className={cn("[overflow-wrap:anywhere]", l.chained ? "text-ink-2" : "text-brick-ink")}>
                    {l.at} · {l.os_user}@{l.host} · {l.via} · {l.command} {l.argv.join(" ")}
                    {l.chained ? "" : " · NOT CHAINED to the line before"}
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
          {operator.trace.length ? (
            <details className="text-[12px]">
              <summary className="cursor-pointer text-ink-2">{operator.trace.length} operator line{operator.trace.length === 1 ? "" : "s"} on the run's trace</summary>
              <ul className="m-0 mt-1 flex list-none flex-col gap-0.5 p-0 font-mono text-[11.5px]">
                {operator.trace.map((t, i) => (
                  <li key={i} className="[overflow-wrap:anywhere] text-ink-2">
                    {t.at} · {t.tool} · {t.command} · {t.via}
                    {t.os_user !== "?" ? ` · ${t.os_user}` : ""}
                    {t.verified ? "" : " · unverified (from another shell)"}
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
        </Row>
      ) : null}
    </div>
  );
}
