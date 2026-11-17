"""Independent serial allocation-policy suite: regression / pilot / fixed 120.

No full run can start until identical code/environment has passed regression
and six development arms. Formal failures remain in place and are never retried.
This scheduler never invokes another performance experiment or a model API.
"""
import argparse,hashlib,itertools,json,os,signal,subprocess,sys,time
from pathlib import Path
from experiments.allocation_policy.suite import fingerprint as protected_fingerprint
from experiments.rq2_later.suite import environment
from experiments.rq2_v2.suite import idle

ROOT=Path(__file__).resolve().parents[2]
PACKAGE=Path(__file__).resolve().parent
REGRESSIONS=('experiments.alignment_regression','experiments.gredac_regression',
    'experiments.rq2_v2.optimization_regression','experiments.allocation_policy.regression','experiments.allocation_policy_v2.regression')


def fingerprint():
    source=protected_fingerprint()
    for base in (PACKAGE,ROOT/'docs/allocation-policy-v2'):
        for p in base.rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts and (p.suffix in ('.py','.json','.sh') or p.name=='PLAN.md'):
                source[p.relative_to(ROOT).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
    return dict(sorted(source.items()))


def jobs(stage):
    assert stage in ('pilot','full')
    split='formal' if stage=='full' else 'development'
    return json.loads((PACKAGE/(split+'_instances.json')).read_text())['cases']


def checked(path,stage,source,env):
    m=json.loads((Path(path)/'manifest.json').read_text())
    assert m['stage']==stage and m['status']=='PASS'
    assert m['source_sha256']==source,'source/plan differs from validation'
    assert m['environment']==env,'environment differs from validation'
    n=len(REGRESSIONS) if stage=='regression' else len(jobs('pilot'))
    assert len(m['attempts'])==n and all(a['exitcode']==0 for a in m['attempts'])
    return m


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage',required=True,choices=('regression','pilot','full'));p.add_argument('--out',type=Path,required=True)
    p.add_argument('--regression-results',type=Path);p.add_argument('--pilot-results',type=Path)
    p.add_argument('--confirm-pilot-reviewed',action='store_true');p.add_argument('--check-only',action='store_true')
    a=p.parse_args();source=fingerprint();env=environment()
    assert protected_fingerprint()==json.loads((PACKAGE/'protected_baseline.json').read_text())
    if a.stage=='pilot':assert a.regression_results;checked(a.regression_results,'regression',source,env)
    if a.stage=='full':
        assert a.pilot_results and a.confirm_pilot_reviewed
        m=checked(a.pilot_results,'pilot',source,env);checked(m['regression_results'],'regression',source,env)
    plan=[dict(module=m,case=None) for m in REGRESSIONS] if a.stage=='regression' else [dict(module='experiments.allocation_policy_v2.run',case=c) for c in jobs(a.stage)]
    if a.check_only:
        print(json.dumps(dict(stage=a.stage,planned=len(plan),llm_calls=0,jobs=plan),indent=2));return
    idle()
    from experiments.rq2_v2.common import configure
    configure();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    meta=dict(stage=a.stage,status='RUNNING',source_sha256=source,environment=env,
        regression_results=str(a.regression_results.resolve()) if a.regression_results else None,
        pilot_results=str(a.pilot_results.resolve()) if a.pilot_results else None,planned=len(plan),attempts=[],
        started_unix=time.time(),llm_api_calls=0,unit='matched random-instance triples with isolated policy arms')
    def save():(out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
    save();(out/'plan.json').write_text(json.dumps(plan,indent=2))
    for i,job in enumerate(plan):
        idle();assert fingerprint()==source,'source changed during run'
        dest=out/f'run-{i:03d}';cmd=[sys.executable,'-u','-m',job['module'],'--out',str(dest)]
        if job['case'] is not None:cmd+=['--case-json',json.dumps(job['case']),'--repeat-index',str(job['case']['index'])]
        print('START',i+1,'/',len(plan),job['case'] or job['module'],flush=True)
        start=time.monotonic();timeout=False
        with (out/f'run-{i:03d}.log').open('w') as log:
            proc=subprocess.Popen(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=proc.wait(timeout=1800)
            except subprocess.TimeoutExpired:timeout=True;os.killpg(proc.pid,signal.SIGKILL);code=proc.wait()
        row=dict(**job,directory=dest.name,command=cmd,exitcode=code,timeout=timeout,seconds=time.monotonic()-start)
        if code==0 and job['case'] is not None:row['result']=json.loads((dest/'summary.json').read_text())['results'][0]
        meta['attempts'].append(row);save();print('PASS' if code==0 else 'FAIL',i+1,flush=True)
        if code and a.stage!='full':break
    meta['ended_unix']=time.time();meta['status']='PASS' if len(meta['attempts'])==len(plan) and all(a['exitcode']==0 for a in meta['attempts']) else 'FAIL';save()
    if a.stage!='regression':
        from .results import report
        report(out)
    print(json.dumps(dict(status=meta['status'],attempted=len(meta['attempts']),out=str(out))),flush=True)
    if meta['status']!='PASS':raise SystemExit(1)


if __name__=='__main__':main()
