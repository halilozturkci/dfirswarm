// Operator-side read-only verification. Full diagnostics stay private.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { verifyCustody } from '../../../../scripts/custody.ts';
import { verifyEventChain, verifyLedgerChain } from '../../../../extensions/protocol.ts';
import { verifyLeadChain } from '../../../../extensions/leads.ts';
import { verifyJournalText } from '../../../../scripts/evidence-store.ts';

const [sandbox, privateReport, summaryFile] = process.argv.slice(2);
if (!sandbox || !privateReport || !summaryFile) throw Error('sandbox privateReport summaryFile required');
const read = p => readFileSync(p, 'utf8');
const trace = verifyEventChain(read(`${sandbox}/traces/events.jsonl`), JSON.parse(read(`${sandbox}.trace-anchor.json`)));
const ledgerRaw = verifyLedgerChain(read(`${sandbox}/ledger/entries.jsonl`));
const { hashes, ...ledger } = ledgerRaw;
const chains = {};
for (const [key, rel] of Object.entries({ leads: 'leads/leads.jsonl', finish: 'leads/finish.jsonl',
  questions: 'questions/questions.jsonl', requests: 'requests/requests.jsonl' })) {
  chains[key] = verifyLeadChain(read(`${sandbox}/${rel}`));
}
const j = verifyJournalText(read(`${sandbox}/store/journal.jsonl`));
chains.journal = { total: j.lines.length, head: j.head, ok: !j.error, error: j.error ?? null };
mkdirSync(dirname(privateReport), { recursive: true, mode: 0o700 });
console.log(JSON.stringify({ phase: 'read-only custody/store verification' }));
const result = await verifyCustody(sandbox, { timeoutSec: 600,
  runsDir: dirname(sandbox), scratchDir: `${dirname(privateReport)}/custody-scratch` });
writeFileSync(privateReport, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
const summary = { run: 's421201', at: new Date().toISOString(),
  kind: 'read-only observer verification of interrupted run; no stop or custody seal written',
  trace, ledger, chains, formal_verdict_verifies: result.ok,
  private_report: privateReport,
  report_shape: Object.keys(result),
  no_mutations_to_original: true, all14_complete: false, flag_verified: false };
// No raw tool content, examiner thought text, or authentication values in this summary.
if (result.now?.checks) summary.current_checks = result.now.checks.map(x => ({ name: x.name, status: x.status }));
if (result.checks) summary.current_checks = result.checks.map(x => ({ name: x.name, status: x.status }));
if (Array.isArray(result.now)) summary.current_checks = result.now.map(x => ({
  name: x.name, status: x.status, reason: x.reason ?? null,
  expected: x.expected ?? null, checked: x.checked ?? null }));
summary.readonly_touched_count = result.touched?.length ?? null;
mkdirSync(dirname(summaryFile), { recursive: true });
writeFileSync(summaryFile, JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify({ complete: true, formal_verdict_verifies: result.ok,
  trace_ok: trace.ok, ledger_ok: ledger.ok, chain_results: Object.fromEntries(Object.entries(chains).map(([k, v]) => [k, v.ok])) }));
