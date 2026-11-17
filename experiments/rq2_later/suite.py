"""Manual, serial, independently gated steps 2 and 3; never starts step 1.

Regression, pilot and full are separate user/developer actions. Full requires
the exact source/environment validated by the selected group's pilot. Every
formal attempt is retained; no automatic retry, replacement or next group.
"""
import argparse
import hashlib
import json
import os
import platform
import random
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from experiments.rq2_v2.suite import fingerprint as protected_fingerprint, idle

ROOT=Path(__file__).resolve().parents[2]
PACKAGE=Path(__file__).resolve().parent
REGRESSIONS=('experiments.alignment_regression','experiments.gredac_regression',
    'experiments.rq2_v2.optimization_regression','experiments.rq2_v2.regression',
    'experiments.rq2_later.regression')


def fingerprint():
    source=protected_fingerprint()
    for base in (PACKAGE,ROOT/'docs/rq2-gredac-later'):
        for p in base.rglob('*'):
            if p.is_file() and p.suffix in ('.py','.json','.sh') and '__pycache__' not in p.parts:
                source[p.relative_to(ROOT).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
    return dict(sorted(source.items()))


def environment():
    from importlib.metadata import distributions
    return dict(python=sys.executable,version=platform.python_version(),hostname=platform.node(),
        platform=platform.platform(),sqlite=sqlite3.sqlite_version,
        packages={d.metadata['Name']:d.version for d in distributions()},
        commit_delay_bound_seconds=float(os.environ.get('GREDAC_COMMIT_DELAY_BOUND','.05')),
        slot_bits=15,diagnostics_buffered=True,affinity=sorted(os.sched_getaffinity(0))[:8],
        transport='independent process loopback TCP/TLS1.3',persistence='WAL/FULL',
        contact_seconds=3600,task_deadline_seconds=7200)


def jobs(stage,group):
    assert stage in ('pilot','full') and group in ('dialogue','structure')
    shared=dict(method='GReDAC',identity='roots-dynamic',slot_bits=15,actions=['query'])
    if group=='dialogue':
        configs=[dict(shared,block='dialogue',requests=n,issued=2048,units=2048,depth=1,cover=1)
                 for n in ((1,2048) if stage=='pilot' else (1,8,32,128,512,2048))]
    else:
        configs=[]
        for axis,key,values in [('depth','depth',(1,2,4,8,16)),('quota','units',(64,256,1024,4096)),
                                ('fragmentation','cover',(1,4,16,64,256))]:
            for value in ((values[0],values[-1]) if stage=='pilot' else values):
                c=dict(shared,block='structure',axis=axis,requests=9,issued=32768,depth=4,units=256,cover=1)
                c[key]=value;configs.append(c)
    ordered=[]
    for axis in (('dialogue',) if group=='dialogue' else ('depth','quota','fragmentation')):
        items=[dict(module='experiments.rq2_later.'+axis,case=c,repeat=r)
            for c in configs if c.get('axis',c['block'])==axis for r in range(1 if stage=='pilot' else 6)]
        random.Random(61293+sum(map(ord,axis))).shuffle(items)
        ordered.extend(items)
    return ordered


def checked(path,stage,source,env,group=None):
    m=json.loads((Path(path)/'manifest.json').read_text())
    assert m['stage']==stage and m['status']=='PASS','validation incomplete/failed'
    assert m['source_sha256']==source,'code/scripts changed since validation'
    assert m['environment']==env,'environment changed since validation'
    if group is not None:assert m['group']==group,'pilot belongs to another group'
    expected=len(REGRESSIONS) if stage=='regression' else len(jobs('pilot',m['group']))
    assert len(m['attempts'])==expected and all(a['exitcode']==0 for a in m['attempts'])
    return m


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage',required=True,choices=('regression','pilot','full'))
    p.add_argument('--group',choices=('dialogue','structure'))
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--regression-results',type=Path)
    p.add_argument('--pilot-results',type=Path)
    p.add_argument('--confirm-pilot-reviewed',action='store_true')
    p.add_argument('--check-only',action='store_true')
    a=p.parse_args()
    assert a.stage=='regression' or a.group is not None,'choose exactly one group'
    source,env=fingerprint(),environment()
    protected=json.loads((PACKAGE/'protected_baseline.json').read_text())
    assert protected_fingerprint()==protected,'protected first-group/core source changed'
    if a.stage=='pilot':
        assert a.regression_results
        checked(a.regression_results,'regression',source,env)
    if a.stage=='full':
        assert a.pilot_results and a.confirm_pilot_reviewed
        m=checked(a.pilot_results,'pilot',source,env,a.group)
        checked(m['regression_results'],'regression',source,env)
    plan=[dict(module=n,case=None,repeat=0) for n in REGRESSIONS] if a.stage=='regression' else jobs(a.stage,a.group)
    if a.check_only:
        print(json.dumps(dict(stage=a.stage,group=a.group,attempts=len(plan),llm_calls=0,jobs=plan),indent=2))
        return
    idle()
    from experiments.rq2_v2.common import configure
    configure()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    meta=dict(stage=a.stage,group=a.group,status='RUNNING',source_sha256=source,environment=env,
        regression_results=str(a.regression_results.resolve()) if a.regression_results else None,
        pilot_results=str(a.pilot_results.resolve()) if a.pilot_results else None,
        attempts=[],llm_api_calls=0,planned=len(plan),started_unix=time.time(),
        independent_unit='fresh task process, participants, databases and state per setting/repetition',
        task_timing='infrastructure excluded; users separate; root and dynamic identity work included',
        acceptability_budget=None)
    def save():(out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
    save();(out/'plan.json').write_text(json.dumps(plan,indent=2))
    for i,job in enumerate(plan):
        idle();assert fingerprint()==source,'source changed during batch'
        dest=out/f'run-{i:03d}'
        cmd=[sys.executable,'-u','-m',job['module'],'--out',str(dest)]
        if job['case'] is not None:
            cmd+=['--case-json',json.dumps(job['case']),'--repeat-index',str(job['repeat'])]
        print('START',i+1,'/',len(plan),job['case'] or job['module'],flush=True)
        begin=time.monotonic();timeout=False
        with (out/f'run-{i:03d}.log').open('w') as log:
            proc=subprocess.Popen(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=proc.wait(timeout=1800)
            except subprocess.TimeoutExpired:
                timeout=True;os.killpg(proc.pid,signal.SIGKILL);code=proc.wait()
        row=dict(**job,directory=dest.name,command=cmd,exitcode=code,timeout=timeout,seconds=time.monotonic()-begin)
        if code==0 and job['case'] is not None:
            row['result']=json.loads((dest/'summary.json').read_text())['results'][0]
        meta['attempts'].append(row);save()
        print('PASS' if code==0 else 'FAIL',i+1,flush=True)
        if code and a.stage!='full':break
    meta['ended_unix']=time.time()
    meta['status']='PASS' if len(meta['attempts'])==len(plan) and all(a['exitcode']==0 for a in meta['attempts']) else 'FAIL'
    save()
    if a.stage!='regression':
        from .results import report
        report(out)
    print(json.dumps(dict(status=meta['status'],attempted=len(meta['attempts']),out=str(out))),flush=True)
    if meta['status']!='PASS':raise SystemExit(1)


if __name__=='__main__':main()
