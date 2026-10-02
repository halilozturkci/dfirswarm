from pathlib import Path
import subprocess,os,json,time,datetime,shutil,hashlib,signal
REPO=Path('/Users/halilozturkci/DFIR/dfirswarm')
PREP=Path('/tmp/dfirswarm-batman-ii-preparation')
RUNS=Path('/Users/halilozturkci/DFIR/SwarmRuns-vm')
CASE=REPO/'docs/use-cases/batman-investigation-ii'
env=dict(os.environ,DFIRSWARM_HOME=str(PREP/'home'),SWARM_RUNS_DIR=str(RUNS))
cmd=['bash','scripts/swarm.sh','start','--models','openai-codex/gpt-6.1-sol=4,openai-codex/gpt-daybreak-blue-latest=3,openai-codex/gpt-6-luna=3','--n','10','--cap-usd','0','--cap-tokens','30000000','--until-solved','--goal-file',str(PREP/'goal.md'),'--label','batman-investigation-ii-10-models','--inputs','/Users/halilozturkci/DFIR/SwarmInputs/batman-investigation-ii','--inputs-max-mb','6000','--pack','memory-forensics','--image','dfirswarm-memory:symbols-arm64','--brains-with-packs','--workers','4','--worker-memory','6144','--vm-memory','4096','--vm-cpus','2','--worker-cpus','2','--vm-disk','12288','--allow-oauth-in-vm','--allow-tool-forging','--no-pypi','--network','closed','--policy','ctf','--contact','passive','--more-evidence','no','--lookups','none','--no-read','/Users/halilozturkci/DFIR/SampleCases/DFIR-LABS/solutions','--no-read',str(REPO/'docs/use-cases'),'--no-read','/Users/halilozturkci/DFIR/Private/dfir-labs-dl','--stall-minutes','10']
(PREP/'launch-arguments.json').write_text(json.dumps(cmd,indent=2)+'\n')
old={r['id'] for r in json.loads((RUNS/'registry.json').read_text())['runs']}
startlog=(PREP/'swarm-start.log').open('w')
p=subprocess.Popen(cmd,cwd=REPO,env=env,stdout=startlog,stderr=subprocess.STDOUT)
print(json.dumps({'phase':'starting','pid':p.pid}),flush=True)
while p.poll() is None:time.sleep(2)
startlog.close()
print(json.dumps({'phase':'start_returned','exit':p.returncode,'tail':(PREP/'swarm-start.log').read_text()[-5000:]}),flush=True)
if p.returncode:raise SystemExit(p.returncode)
runs={r['id']:r for r in json.loads((RUNS/'registry.json').read_text())['runs']}
new=set(runs)-old
if len(new)!=1:raise RuntimeError('cannot uniquely identify started run')
run=next(iter(new));rec=runs[run];sandbox=Path(rec['sandbox'])
(PREP/'active-run.json').write_text(json.dumps({'run':run,'sandbox':str(sandbox),'controller_pid':os.getpid()},indent=2)+'\n')
(CASE/'run-metadata.json').write_text(json.dumps({'run':run,'sandbox':str(sandbox),'controller_pid':os.getpid(),'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'state':'LIVE','models':{'openai-codex/gpt-6.1-sol':4,'openai-codex/gpt-daybreak-blue-latest':3,'openai-codex/gpt-6-luna':3}},indent=2)+'\n')
uif=(PREP/'ui-server.log').open('w');os.chmod(PREP/'ui-server.log',0o600)
ui=subprocess.Popen(['bash','scripts/swarm.sh','ui','--port','43174'],cwd=REPO,env=env,stdout=uif,stderr=subprocess.STDOUT)
print(json.dumps({'phase':'monitoring','run':run,'sandbox':str(sandbox),'ui_port':43174}),flush=True)
def mirror():
 dest=CASE/'live-record';dest.mkdir(exist_ok=True)
 roots=['traces/events.jsonl','ledger/entries.jsonl','ledger/attestations.jsonl','ledger/disputes.jsonl','questions/questions.jsonl','leads/leads.jsonl','store/journal.jsonl','team.json','SWARM.md','inputs.json','budget.json']
 roots += [str(f.relative_to(sandbox)) for d in ['.pi-sessions','threads','tool-output'] if (sandbox/d).exists() for f in (sandbox/d).rglob('*') if f.is_file() and not f.is_symlink()]
 rows=[]
 for rel in roots:
  src=sandbox/rel
  if not src.is_file() or src.is_symlink():continue
  target=dest/rel;target.parent.mkdir(parents=True,exist_ok=True)
  temp=target.with_name(target.name+'.pending')
  with src.open('rb') as inf,temp.open('wb') as outf:shutil.copyfileobj(inf,outf,1024*1024)
  temp.replace(target)
  rows.append({'path':rel,'bytes':target.stat().st_size})
 (dest/'LIVE-SNAPSHOT.json').write_text(json.dumps({'run':run,'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'state':'LIVE; not a final custody verdict','files':rows},indent=2)+'\n')
while True:
 mirror()
 trace=sandbox/'traces/events.jsonl';ledger=sandbox/'ledger/entries.jsonl'
 answers=[]
 if ledger.exists():
  for line in ledger.read_text().splitlines():
   try:
    e=json.loads(line)
    if e.get('kind')=='answer':answers.append({'seq':e.get('seq'),'section':e.get('section'),'result':e.get('result')})
   except json.JSONDecodeError:pass
 print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'run':run,'trace_bytes':trace.stat().st_size if trace.exists() else 0,'answer_entries':answers[-20:],'candidate_file':(sandbox/'work/answers.json').exists(),'ui_alive':ui.poll() is None}),flush=True)
 if (PREP/'stop-after-verification').exists():
  with (PREP/'swarm-stop.log').open('w') as log:q=subprocess.run(['bash','scripts/swarm.sh','stop',run],cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT)
  mirror();print(json.dumps({'phase':'stopped','run':run,'exit':q.returncode}),flush=True)
  if q.returncode==0:break
 if (PREP/'leave-controller').exists():break
 time.sleep(30)
ui.terminate();uif.close()
