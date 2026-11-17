"""Manual RQ2: regression -> separate pilot -> manually selected full group.

Only this scheduler knows the matrix. Five independent scientific entrypoints
own their workflows; no experiment imports another experiment's results.
Historical RQ2, MAGIQ, RQ3 and RQ4 are never launched by this suite.
"""
import argparse,hashlib,json,os,random,signal,subprocess,sys,time,shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
METHODS=('GReDAC','SAGA-author-source@7372111')


def fingerprint():
    files=[p for d in ('gredac','experiments') for p in (ROOT/d).glob('*.py')]
    files+=list((ROOT/'experiments/data').glob('*.json'))+[ROOT/'pyproject.toml']
    files += [p for p in Path(__file__).parent.rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def idle():
    active=[]
    for p in Path('/proc').glob('[0-9]*/cmdline'):
        if int(p.parent.name)==os.getpid():continue
        try:
            v=p.read_bytes().split(b'\0')
            if b'-m' in v and v[v.index(b'-m')+1].startswith(b'experiments.'):
                active.append(dict(pid=int(p.parent.name),module=v[v.index(b'-m')+1].decode()))
        except (OSError,IndexError):pass
    assert not active,('other experiments running; do not interfere',active)


def environment():
    from importlib.metadata import distributions
    binary=Path(os.environ.get('RQ2_MONGOD') or shutil.which('mongod') or 'mongod')
    return dict(python=sys.executable,packages={d.metadata['Name']:d.version for d in distributions()},
        mongodb=str(binary),mongodb_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        commit_delay_bound_seconds=float(os.environ.get('GREDAC_COMMIT_DELAY_BOUND','.05')))


def jobs(stage,group='flow'):
    assert group=='flow', 'Current public step 1 only; use rq2_later for dialogue/structure'
    configurations=[dict(block='flow',flow=f,identity='roots-dynamic',replacement=r,requests=32,units=128) for f,r in
        [('F1',None),('F2','caller'),('F3','service')]]
    configurations += [dict(block='dialogue',requests=n,identity='cold') for n in (1,8,32,128,512,2048)]
    for axis,key,values in [('depth','depth',(1,2,4,8,16)),('quota','units',(64,256,1024,4096)),('fragmentation','cover',(1,4,16,64,256))]:
        configurations += [dict(block='structure',axis=axis,**{key:value},requests=9,identity='ready') for value in values]
    if stage=='pilot':
        configurations=[c for c in configurations if c['block']=='flow'
            or (c['block']=='dialogue' and c['requests'] in (1,2048))
            or (c.get('axis')=='depth' and c['depth']==16) or (c.get('axis')=='quota' and c['units']==4096)
            or (c.get('axis')=='fragmentation' and c['cover']==256)]
    if group=='flow':configurations=[c for c in configurations if c['block']=='flow']
    grouped={key:[] for key in ('flow','dialogue','depth','quota','fragmentation')}
    for i,c in enumerate(configurations):
        for rep in range(1 if stage=='pilot' else 6):
            methods=METHODS if c['block']!='structure' else METHODS[:1]
            if rep%2:methods=tuple(reversed(methods))
            pair=f'{i:02d}-{rep}';group=c.get('axis',c['block'])
            grouped[group].append([dict(module='experiments.rq2_v2.'+group,case=dict(c,method=m),repeat=rep,pair=pair) for m in methods])
    result=[]
    for group,items in grouped.items():
        random.Random(61293+sum(map(ord,group))).shuffle(items)
        result += [j for pair in items for j in pair]
    return result


def checked(path,stage,source,env):
    m=json.loads((Path(path)/'manifest.json').read_text())
    assert m['stage']==stage and m['status']=='PASS','prior validation failed or wrong stage'
    assert m['source_sha256']==source,'source/input differs from validated version'
    assert m['environment']==env,'dependency/binary/commit-bound setting changed'
    assert len(m['attempts'])==(4 if stage=='regression' else len(jobs('pilot',m['group']))) and all(a['exitcode']==0 for a in m['attempts'])
    return m


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage',required=True,choices=('regression','pilot','full'));p.add_argument('--out',type=Path,required=True)
    p.add_argument('--regression-results',type=Path);p.add_argument('--pilot-results',type=Path)
    p.add_argument('--confirm-pilot-reviewed',action='store_true');p.add_argument('--check-only',action='store_true')
    p.add_argument('--group',choices=('flow',),default='flow',help='Current step 1 only; use rq2_later for steps 2 and 3')
    a=p.parse_args();source=fingerprint();env=environment()
    if a.stage=='pilot':assert a.regression_results;checked(a.regression_results,'regression',source,env)
    if a.stage=='full':
        assert a.pilot_results and a.confirm_pilot_reviewed
        m=checked(a.pilot_results,'pilot',source,env);checked(m['regression_results'],'regression',source,env)
        assert m['group']=='all' or a.group=='flow','flow-only validation cannot authorize full groups 2/3'
    plan=[dict(module=n,case=None,pair='regression',repeat=0) for n in
        ('experiments.alignment_regression','experiments.gredac_regression','experiments.rq2_v2.optimization_regression','experiments.rq2_v2.regression')] if a.stage=='regression' else jobs(a.stage,a.group)
    if a.check_only:print(json.dumps(dict(stage=a.stage,attempts=len(plan),llm_calls=0,jobs=plan),indent=2));return
    idle()
    from .common import configure
    configure();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    meta=dict(stage=a.stage,group=a.group,status='RUNNING',source_sha256=source,environment=env,
        regression_results=str(a.regression_results.resolve()) if a.regression_results else None,
        pilot_results=str(a.pilot_results.resolve()) if a.pilot_results else None,
        attempts=[],llm_api_calls=0,planned=len(plan),started_unix=time.time(),affinity=sorted(os.sched_getaffinity(0)),
        acceptability_budget=None,interpretation='cost facts only; no unfrozen acceptability claim')
    def save():(out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
    save();(out/'plan.json').write_text(json.dumps(plan,indent=2))
    for i,job in enumerate(plan):
        idle();assert fingerprint()==source,'source changed during batch'
        dest=out/f'run-{i:03d}';cmd=[sys.executable,'-u','-m',job['module'],'--out',str(dest)]
        if job['case'] is not None:cmd += ['--case-json',json.dumps(job['case']),'--repeat-index',str(job['repeat'])]
        print('START',i+1,'/',len(plan),job['case'] or job['module'],flush=True);begin=time.monotonic();timeout=False
        with (out/f'run-{i:03d}.log').open('w') as log:
            proc=subprocess.Popen(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=proc.wait(timeout=1800)
            except subprocess.TimeoutExpired:timeout=True;os.killpg(proc.pid,signal.SIGKILL);code=proc.wait()
        row=dict(**job,directory=dest.name,command=cmd,exitcode=code,timeout=timeout,seconds=time.monotonic()-begin)
        if code==0 and job['case'] is not None:row['result']=json.loads((dest/'summary.json').read_text())['results'][0]
        meta['attempts'].append(row);save();print('PASS' if code==0 else 'FAIL',i+1,flush=True)
        # Developer checks stop at the first fault; full formal jobs retain
        # failures and continue the fixed plan without replacement attempts.
        if code and a.stage!='full':break
    meta['ended_unix']=time.time();meta['status']='PASS' if len(meta['attempts'])==len(plan) and all(a['exitcode']==0 for a in meta['attempts']) else 'FAIL';save()
    if a.stage!='regression':
        from .results import report
        report(out)
    print(json.dumps(dict(status=meta['status'],attempted=len(meta['attempts']),out=str(out))),flush=True)
    if meta['status']!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
