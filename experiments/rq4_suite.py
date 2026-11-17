"""Shared RQ4 environment helpers, with an inactive historical scheduler.

The public CLI below is disabled. Current execution uses rq4_full_40g's fixed
39-attempt plan. Older scheduling functions remain importable historical code,
not an alternative recommended experiment or an automatic extension policy.
"""
import argparse,hashlib,json,os,random,signal,subprocess,sys,time,platform,ssl,sqlite3
from importlib.metadata import version
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
WAIT='experiments/data/rq4_rq3_wait_v2.json'
GROUPS='ABD'


def fingerprint():
    files=[p for d in ('gredac','experiments') for p in (ROOT/d).glob('*.py')]
    files+=list((ROOT/'experiments/data').glob('*.json'))+[ROOT/'pyproject.toml']
    files+=list((ROOT/'docs/rq4-manual-v2').glob('*.sh'))
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def runtime_environment():
    return dict(python=sys.version,executable=sys.executable,sqlite=sqlite3.sqlite_version,
        openssl=ssl.OPENSSL_VERSION,cryptography=version('cryptography'),platform=platform.platform())


def cases(group,stage='full',services=None):
    """Fixed public argument matrix; this is scheduling, not experiment logic."""
    small=stage=='smoke';repeats=1 if small else 3
    scales=services or {'A':[2,8] if small else [1,8,32,128,512,1024],
        'B':[2,8] if small else [1,8,32,128,512,1024],
        'D':[2] if small else [8,64]}[group]
    modules=dict(A='rq4_contacts',B='rq4_fanout',D='rq4_team_faults')
    extra={'A':['--wait-file',WAIT],'B':['--rounds','2' if small else '12','--wait-file',WAIT],
        'D':['--teams','2' if small else '8','--rounds','3' if small else '12',
             '--inject-at','0.25' if small else '6','--wait-file',WAIT]}[group]
    jobs=[]
    for k in scales:
        for point in (['none','before_commit','after_commit'] if group=='D' else [None]):
            for rep in range(repeats):
                cfg=dict(services=k)
                if point:cfg['point']=point
                jobs.append(dict(group=group,module='experiments.'+modules[group],case=cfg,repeat=rep,
                    args=['--workers','2' if small else ('8' if group=='D' else '32'),
                          '--slot-bits','15','--repeats','1',*extra]))
    random.Random(43211+ord(group)).shuffle(jobs);return jobs


def extension_allowed(attempts,group,k):
    rows=[a for a in attempts if a['group']==group and a.get('case',{}).get('services')==k]
    return len(rows)==3 and all(a['exitcode']==0 and a.get('result',{}).get('within_budget') is True for a in rows)


def idle_experiments():
    """Do not contend with a user-started RQ2/RQ3/RQ4 process."""
    found=[]
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        if int(path.parent.name)==os.getpid():continue
        try:
            argv=path.read_bytes().split(b'\0')
            if b'-m' in argv:
                i=argv.index(b'-m')
                if i+1<len(argv) and argv[i+1].startswith(b'experiments.'):
                    found.append(dict(pid=int(path.parent.name),module=argv[i+1].decode()))
        except (OSError,ValueError):pass
    if found:raise RuntimeError('Other experiment processes are active: '+json.dumps(found))


def validate(previous,stage,source):
    saved=json.loads((Path(previous)/'manifest.json').read_text())
    assert saved['stage']==stage and saved['status']=='PASS','prior validation not PASS'
    assert saved['source_sha256']==source,'source/input changed since validation; preserve old runs and validate new version'
    assert saved['commit_delay_bound_seconds']==float(os.environ.get('GREDAC_COMMIT_DELAY_BOUND','0.05')),'commit-delay setting differs from validation'
    assert saved['runtime_environment']==runtime_environment(),'runtime environment changed since validation'
    expected=3 if stage=='regression' else 7
    assert len(saved['attempts'])==expected and all(x['exitcode']==0 for x in saved['attempts'])
    return saved


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage',choices=['regression','smoke','full'],required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--regression-results',type=Path)
    p.add_argument('--validation-results',type=Path)
    p.add_argument('--confirm-validation-reviewed',action='store_true')
    p.add_argument('--check-only',action='store_true',help='validate CLI and print schedule without creating output or running tasks')
    a=p.parse_args();source=fingerprint()
    if a.stage=='smoke':
        assert a.regression_results,'smoke needs regression results';validate(a.regression_results,'regression',source)
    if a.stage=='full':
        assert a.validation_results and a.confirm_validation_reviewed,'full needs reviewed smoke results'
        prior=validate(a.validation_results,'smoke',source)
        assert prior.get('regression_results'),'smoke must cite a passed regression'
        validate(prior['regression_results'],'regression',source)
    jobs=[dict(group='REG',module=m,args=[],case=None,repeat=0) for m in
        ('experiments.alignment_regression','experiments.gredac_regression','experiments.rq4_regression')] if a.stage=='regression' else [j for g in GROUPS for j in cases(g,a.stage)]
    if a.check_only:
        print(json.dumps(dict(stage=a.stage,base_attempts=len(jobs),max_extensions=12 if a.stage=='full' else 0,
            llm_api_calls=0,jobs=jobs),indent=2));return
    idle_experiments()
    from .rq4_support import configure
    configure();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    report=dict(stage=a.stage,status='RUNNING',source_sha256=source,started_unix=time.time(),
        llm_api_calls=0,source_version='RQ4-manual-v2',python=sys.executable,runtime_environment=runtime_environment(),
        affinity=sorted(os.sched_getaffinity(0)),commit_delay_bound_seconds=float(os.environ.get('GREDAC_COMMIT_DELAY_BOUND','0.05')),
        regression_results=str(a.regression_results.resolve()) if a.regression_results else None,
        validation_results=str(a.validation_results.resolve()) if a.validation_results else None,
        planned_base=len(jobs),groups=GROUPS,wait_file=WAIT,
        extension_limit=12 if a.stage=='full' else 0,attempts=[],extension_decisions=[])
    def save():(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    save();(out/'plan.json').write_text(json.dumps(dict(jobs=jobs,max_extensions=report['extension_limit']),indent=2)+'\n')
    def execute(job):
        assert fingerprint()==source,'source/input changed during frozen batch'
        idle_experiments();i=len(report['attempts']);dest=out/f'run-{i:03d}'
        cmd=[sys.executable,'-u','-m',job['module'],*job['args'],'--out',str(dest)]
        if job['case'] is not None:cmd+=['--case-json',json.dumps(job['case']),'--repeat-index',str(job['repeat'])]
        print('START',i+1,job['group'],job['case'],'repeat',job['repeat'],flush=True)
        begin=time.monotonic();timed_out=False
        with (out/f'run-{i:03d}.log').open('w') as log:
            proc=subprocess.Popen(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=proc.wait(timeout=1800)
            except subprocess.TimeoutExpired:timed_out=True;os.killpg(proc.pid,signal.SIGKILL);code=proc.wait()
        row=dict(**job,directory=dest.name,command=cmd,exitcode=code,timed_out=timed_out,seconds=time.monotonic()-begin)
        if code==0 and job['case'] is not None:row['result']=json.loads((dest/'summary.json').read_text())['results'][0]
        if code!=0:
            meta=json.loads((dest/'manifest.json').read_text()) if (dest/'manifest.json').exists() else {}
            row['failure_kind']='timeout' if timed_out else meta.get('failure_kind','execution_or_audit_failure')
        report['attempts'].append(row);save();print('PASS' if not code else 'FAIL',i+1,flush=True)
        return code
    if a.stage=='regression':
        for job in jobs:
            if execute(job):break
    else:
        for g in GROUPS:
            for job in jobs:
                if job['group']==g:execute(job)
            if a.stage=='full' and g in 'AB':
                prior_k=1024
                for k in (2048,4096):
                    allowed=extension_allowed(report['attempts'],g,prior_k)
                    report['extension_decisions'].append(dict(group=g,from_services=prior_k,to_services=k,run=allowed,
                        rule='all three preceding largest-scale attempts succeeded and passed budgets'));save()
                    if not allowed:break
                    for job in cases(g,'full',[k]):execute(job)
                    prior_k=k
    report['failed']=sum(x['exitcode']!=0 for x in report['attempts'])
    report['status']='FAIL' if report['failed'] else 'PASS';report['ended_unix']=time.time();save()
    if a.stage!='regression':
        # Postprocessing starts only after every timed job is over.
        code=subprocess.run([sys.executable,'-m','experiments.rq4_report','--root',str(out)],cwd=ROOT).returncode
        report['report_exitcode']=code;save()
        if code:raise SystemExit(code)
    print(json.dumps(dict(status=report['status'],attempted=len(report['attempts']),out=str(out))),flush=True)
    if report['failed']:raise SystemExit(1)

if __name__=='__main__':
    raise SystemExit('Legacy scheduler disabled in the public copy. Use experiments.rq4_full_40g; see docs/REPRODUCE.md.')
