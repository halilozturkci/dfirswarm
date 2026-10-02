import json,re,pathlib,datetime
root=pathlib.Path('.')
entries=[json.loads(s) for s in (root/'ledger/entries.jsonl').read_text().splitlines()]
by={e['seq']:e for e in entries}; superseded={e.get('supersedes') for e in entries}
reviews=[json.loads(s) for s in (root/'ledger/attestations.jsonl').read_text().splitlines()]
disputes_path=root/'ledger/disputes.jsonl'
dispute_rows=[json.loads(s) for s in disputes_path.read_text().splitlines()] if disputes_path.exists() else []
active_disputes=set()
for d in dispute_rows:
 key=(d.get('seq'),d.get('by'))
 if d.get('act')=='withdraw' or d.get('withdraw'):active_disputes.discard(key)
 else:active_disputes.add(key)
disputed_seqs={k[0] for k in active_disputes}
def role_rows(e):
 rows=[]
 for key in ('support','limitations','contrary'):
  for item in e.get(key,[]):
   if isinstance(item,dict):rows.append(item)
   else:rows.append({'seq':int(str(item).removeprefix('E-'))})
 return rows
# Actual first done checker identified these retained failed-job bounds.
# Narrow register guard, not an independent job-success assessment.
known_failed_bounds={26,73,143,178}
def failed_bounds(e,seen=None,qualified=None):
 seen=set() if seen is None else seen
 qualified=set() if qualified is None else set(qualified)
 qualified.update(int(q['ref'][2:]) for q in e.get('qualifies',[]) if re.fullmatch(r'E-\d+',q.get('ref','')))
 if e['seq'] in seen:return []
 seen.add(e['seq']);bad=[]
 for row in role_rows(e):
  seq=row['seq'];f=by.get(seq)
  if seq in known_failed_bounds and seq not in qualified:bad.append(seq)
  if f:bad+=failed_bounds(f,seen,qualified)
 return bad
def disputed_chain(e,seen=None):
 seen=set() if seen is None else seen
 if e['seq'] in seen:return []
 seen.add(e['seq'])
 ancestors=set();cur=e
 while cur and cur['seq'] not in ancestors:
  ancestors.add(cur['seq']);cur=by.get(cur.get('supersedes'))
 bad=list(ancestors & disputed_seqs)
 for s in role_rows(e):
  if s['seq'] in by:bad+=disputed_chain(by[s['seq']],seen)
 return bad

replacement={e['supersedes']:e['seq'] for e in entries if e.get('supersedes')}
def support_scope(e,seen=None):
 seen=set() if seen is None else seen
 if e['seq'] in seen:return seen
 seen.add(e['seq'])
 for s in role_rows(e):
  if s['seq'] in by:support_scope(by[s['seq']],seen)
 return seen

def stale_support(e,seen=None,scope=None):
 seen=set() if seen is None else seen
 scope=support_scope(e) if scope is None else scope
 if e['seq'] in seen:return []
 seen.add(e['seq']);bad=[]
 for s in role_rows(e):
  seq=s['seq'];f=by.get(seq);current=seq;walk=set()
  while current in replacement and current not in walk:
   walk.add(current);current=replacement[current]
  # A superseded entry is usable only beside its standing correction.
  unpaired=seq in superseded and current not in scope
  if not f or unpaired or (s.get('hash') and s['hash']!=f.get('hash')):
   bad.append(seq)
  if f:bad+=stale_support(f,seen,scope)
 return bad
answers={e['section'].split(':')[1]:e for e in entries if e['kind']=='answer' and e.get('section','').startswith('question:') and e['seq'] not in superseded}
text=['# Batman Investigation II — working evidence report','\nDraft: investigation remains open until all 14 exact answers and independent reviews are established. This is not a completion claim.\n','## Scope and method','Synthetic offline CTF; assumes P-1. Original supplied memory and unknown.data remained read-only. External evidence endpoints were not contacted. Recovered programs were examined as data, not executed. Evidence provenance, qualifications and corrections are in `ledger/ledger.md`. Operator-supplied reference programs are distinguished from original evidence.\n']
table={}
for n in range(1,15):
 e=answers.get(str(n));text.append(f'## {n}.')
 if not e:text.append('Investigation pending; no established answer recorded.\n');continue
 bad=disputed_chain(e);stale=stale_support(e);failed=failed_bounds(e)
 disposition='disputed candidate; not established' if bad else ('stale support; not established' if stale else ('unqualified failed-job bounds; not releasable' if failed else e['result']))
 answer_value=e['value'];answer_note=''
 # Q6's standing value wraps its exact tuple in Markdown and then qualifies it.
 # Keep that qualification in prose, not in the exact-answer table/code span.
 if n==6 and answer_value.startswith('`'):
  match=re.fullmatch(r'`([^`]+)`\s*(.*)',answer_value,re.S)
  if not match:raise ValueError('Q6 exact tuple could not be separated from its qualification')
  answer_value,answer_note=match.groups()
 text.append(f"Answer (E-{e['seq']}, {disposition}): `{answer_value}`\n")
 if answer_note:text.append(answer_note+'\n')
 text.append(e.get('reasoning','')+'\n')
 contrary=e.get('contrary_none_why')
 if not contrary:
  contrary=', '.join('E-'+str(c['seq'] if isinstance(c,dict) else str(c).removeprefix('E-')) for c in e.get('contrary',[])) or 'No contrary ledger entries specified.'
 text.append('Contrary evidence / alternatives: '+contrary+' '+e.get('alternatives_open','')+'\n')
 rr=[r for r in reviews if r.get('seq')==e['seq'] and r.get('target')==e.get('hash')]
 if bad:text.append('Standing dispute in support chain: '+','.join('E-'+str(s) for s in sorted(set(bad)))+'. Do not release as established.')
 if stale:text.append('Missing/superseded/hash-mismatched support: '+','.join('E-'+str(s) for s in sorted(set(stale)))+'. Do not release as established.')
 if failed:text.append('Checker-identified failed-job bounds without explicit qualification: '+','.join('E-'+str(s) for s in sorted(set(failed)))+'. The attempted methods do not supply positive findings or absence evidence; do not release this defective chain as established.')
 for q in e.get('qualifies',[]):text.append('Retained-output qualification ('+q['ref']+'): '+q['why'])
 for r in rr:
  if e['seq']==302 and r['by']=='s42120107':
   text.append('Review qualification: s42120107 reported in main #479 that one recipient-email byte locator failed verification because of an offset typo. That locator is not treated as verified here; the review preserves the declared-open intended-contact part. Separate current s42120108 source-first reproduction of the mail/persona parts is recorded independently.')
  if e['seq']==302 and r['by']=='s42120108':
   text.append('Review qualification: s42120108 reported in main #480 that two additional locators were flagged because their fields were not literal values stated in the answer/support text. Those locators are not treated as verified here. The reviewer independently re-read the original MIME and account-identity sources for the mail/persona parts; intended contact remains declared open.')
  old_refs=sorted({int(x) for x in re.findall(r'E-(\d+)',json.dumps(r))} & superseded)
  for old in old_refs:
   current=old;walk=set()
   while current in replacement and current not in walk:
    walk.add(current);current=replacement[current]
   corrected=by.get(current,{})
   text.append(f"Historical review qualification ({r['by']}): E-{old} quoted below is superseded by standing E-{current}. The wording is retained as a historical record, not a present coverage/completeness assertion. Current scope: {corrected.get('coverage_actual',corrected.get('value',''))}")
 if n in (1,2) and 150 in by and 150 not in superseded:
  text.append('Current communication coverage is E-150. It is a targeted volatile-memory/MIME investigation, not proof of disk allocated/deleted/unallocated/slack completeness. Scope: '+by[150].get('coverage_actual',''))
 text.append('Recorded review wording: '+ ('; '.join(f"{r['by']}: {r.get('strength','finding review')}; {r.get('how','')}" for r in rr) if rr else 'Independent review pending.')+'\n')
 for r in rr:
  ar=r.get('answer_review',{})
  for label,key in [('Reproduced','reproduced'),('Read only','read'),('Inference','inference'),('Alternatives weighed','alternatives'),('Discriminator','discriminator')]:
   v=ar.get(key)
   if v:text.append(f"{label} ({r['by']}): "+(v if isinstance(v,str) else json.dumps(v,ensure_ascii=False)))
 established=[r for r in rr if r.get('strength')=='established' and r['by']!=e['by']]
 if e['result']=='established' and established and not bad and not stale and not failed:
  table[str(n)]={'answer':answer_value,'status':'established','support':['E-'+str(e['seq'])]+['E-'+str(s['seq']) for s in e.get('support',[])],'author':e['by'],'reviewer':established[-1]['by']}
 text.append('### Sources and derivation')
 for s in role_rows(e):
  f=by.get(s['seq'])
  if not f:continue
  text.append(f"- E-{f['seq']}: {f['value']} Source: {f.get('source','')}. Derivation/locator: {f.get('evidence','')}. Objects: {', '.join('`'+r+'`' for r in f.get('refs',[]))}.")
 # Explicit bounded follow-up: an unclassified opaque value is not a userkey.
 extra_bounded={1:{303},14:{227,233,254}}
 bounded_scope={
  233:'Only the 17,664 enumerated CBC/ECB-hostkeys followed by CTR-page configurations were tested; other architectures remain open.',
  254:'Only 192 enumerated derivation/mode combinations were tested; unknown serializers, key derivations and other constructions remain open.'
 }
 supplements=[f for f in entries if f['seq'] not in superseded and f['kind']!='answer' and (any(r.get('to')==e['seq'] for r in f.get('rel',[])) or f['seq'] in extra_bounded.get(n,set())) and f['seq'] not in support_scope(e)]
 if supplements:
  text.append('### Supplementary observations — not substitutes for answer establishment or review')
  for f in supplements:
   relation=','.join(r['kind'] for r in (f.get('rel') or []) if r.get('to')==e['seq']) or 'later bounded route; not answer establishment'
   status='disputed' if disputed_chain(f) else ('stale support' if stale_support(f) else f['kind'])
   bound=bounded_scope.get(f['seq']) or f.get('indicates') or f['value']
   text.append(f"- E-{f['seq']} ({status}; {relation}): {f['value']} Locator: {f.get('evidence','')}. Scope/bound: {bound} Objects: {', '.join('`'+r+'`' for r in f.get('refs',[]))}.")
 text.append('')
 # Exact reviewed-table release is separately gated; no placeholder fields.
text.append('## Timeline')
events=sorted([e for e in entries if e['kind']=='event' and e['seq'] not in superseded],key=lambda e:datetime.datetime.fromisoformat(e['ts'].replace('Z','+00:00')))
for e in events:
 text.append(f"- {e['ts']} — {e['value']} (E-{e['seq']}; clock: {e.get('clock','unspecified')}; source: {e.get('source','')}; locator: {e.get('evidence','')})")
text += ['## Reconstruction','2024-01-05 17:12:47 UTC: retained incoming transaction0.0069 ETH; tx-linked note identifies Edward Nigma (E-10,E-135).','2024-01-05 17:15:19 UTC: retained outgoing payment0.006154298932728 ETH to recorded recipient; tx-linked note identifies Oswald Cobblepot. Gasfee0.000745701067272 ETH is separate (E-10,E-131).','2024-01-07 08:39 UTC: installer-prefetch/setup-log metadata aligns with per-user Exodus uninstall registration (E-33,E-76,E-83).','2024-01-07 09:05 UTC: Exodus config created, distinct from installation (E-45).','2024-01-07 09:52:35 (log zone unspecified): Squirrel updater self-update, not replacement installation time (E-47,E-137).','The wallet code selects hourly historical USD pricing for transaction display. Both transactions map to the17:00UTC bin; rate2233.8489501324125 gives15.41 and13.75USD, not daily rates or fee-inclusive totals (E-90,E-99,E-102).','The recovered mail request, attached contact.rar, encrypted database, password-manager deleted record, and screen-noted archive require their separate authenticated recovery chains; unresolved links are not filled by conjecture.']
(root/'work/s42120101/report-draft.md').write_text('\n\n'.join(text))
(root/'work/s42120101/reviewed-answers.json').write_text(json.dumps(table,indent=2))
print('Draft answer sections', sorted(answers,key=int),'reviewed',sorted(table,key=int))
if set(table)=={str(i) for i in range(1,15)}:
 (root/'work/s42120101/answers.json').write_text(json.dumps(table,indent=2))
 print('All14 reviewed; answers.json ready for manual checks/publication')
