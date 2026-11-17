"""Manual, fixed RQ4 batch: A15 + B15 + D9; no extension or replacement.

This file only schedules the existing independent public experiment CLIs.
Each case gets new processes, protocol state and result directory. Groups run
serially. Historical suites/freezes are preserved; this batch has its own freeze.
--check-only validates the frozen source, environment and exact 39-case schedule
without creating result directories, launching agents or executing workloads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import time

from .rq4_suite import ROOT, WAIT, idle_experiments, runtime_environment

DOCS=ROOT/'docs/rq4-full-40g'
FREEZE=DOCS/'FREEZE.json'


def fingerprint():
    files=[p for d in ('gredac','experiments') for p in (ROOT/d).rglob('*.py')]
    files+=list((ROOT/'experiments/data').rglob('*.json'))
    files+=[ROOT/'pyproject.toml',DOCS/'RUN_FULL.sh',DOCS/'README.md']
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def jobs():
    """Freeze three independent repeats; K is services, not caller teams.

    A/B: one caller, K service teams, shared Authority during initial setup.
    D: eight caller teams, each with eight services; its existing layout and
    24-GiB limit remain unchanged. Fixed order per group, no adaptive extension.
    """
    result=[]
    for group,module in [('A','rq4_contacts'),('B','rq4_fanout'),('D','rq4_team_faults')]:
        group_jobs=[]
        args=['--workers','8' if group=='D' else '32','--slot-bits','15',
              '--repeats','1','--order-seed','43101','--wait-file',WAIT]
        if group in 'AB':args+=['--optimize-initial-config']
        if group in 'BD':args+=['--rounds','12']
        if group=='D':args+=['--teams','8','--inject-at','6']
        for k in ([8] if group=='D' else [1,8,32,128,256]):
            for point in (['none','before_commit','after_commit'] if group=='D' else [None]):
                for rep in range(3):
                    case=dict(services=k)
                    if point:case['point']=point
                    group_jobs.append(dict(group=group,module='experiments.'+module,
                        case=case,repeat=rep,args=[*args,'--services',str(k)]))
        random.Random(43211+ord(group)).shuffle(group_jobs)
        result+=group_jobs
    return result


def validate():
    frozen=json.loads(FREEZE.read_text())
    if fingerprint()!=frozen['source_sha256']:
        raise RuntimeError('Source/input differs from docs/rq4-full-40g/FREEZE.json; do not mix versions.')
    if jobs()!=frozen['jobs']:
        raise RuntimeError('Schedule differs from the frozen 39-case matrix.')
    if not frozen.get('public_release',False) and runtime_environment()!=frozen['runtime_environment']:
        raise RuntimeError('Python/runtime environment changed since freeze.')
    if float(os.environ.get('GREDAC_COMMIT_DELAY_BOUND','0.05'))!=0.05:
        raise RuntimeError('GREDAC_COMMIT_DELAY_BOUND must be 0.05.')
    if os.environ.get('GREDAC_BUFFER_DIAGNOSTICS'):
        raise RuntimeError('Unset GREDAC_BUFFER_DIAGNOSTICS for this batch.')
    return frozen


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--check-only',action='store_true')
    a=p.parse_args();frozen=validate();schedule=jobs()
    if a.check_only:
        print(json.dumps(dict(status='CHECK_ONLY_PASS',attempts=len(schedule),
            groups={g:sum(j['group']==g for j in schedule) for g in 'ABD'},
            ab_services=[1,8,32,128,256],memory_budget_gib=dict(AB=40,D=24),
            d_teams=8,d_services_per_team=8,repeats=3,extension_limit=0,
            api_calls=0,out=str(a.out.resolve()),jobs=schedule),indent=2));return
    idle_experiments()
    from .rq4_support import configure
    configure();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    (out/'frozen.json').write_text(json.dumps(frozen,indent=2)+'\n')
    (out/'plan.json').write_text(json.dumps(dict(jobs=schedule,max_extensions=0),indent=2)+'\n')
    report=dict(stage='full',status='RUNNING',source_version='RQ4-full-40g-20261112',
        source_sha256=frozen['source_sha256'],runtime_environment=runtime_environment(),
        started_unix=time.time(),affinity=sorted(os.sched_getaffinity(0)),
        commit_delay_bound_seconds=0.05,memory_budget_gib=dict(AB=40,D=24),
        llm_api_calls=0,planned_base=len(schedule),extension_limit=0,groups='ABD',
        wait_file=WAIT,attempts=[])
    def save():(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    save()
    for i,job in enumerate(schedule):
        validate();idle_experiments()
        dest=out/f'run-{i:03d}';logpath=out/f'run-{i:03d}.log'
        cmd=[sys.executable,'-u','-m',job['module'],*job['args'],'--out',str(dest),
             '--case-json',json.dumps(job['case']),'--repeat-index',str(job['repeat'])]
        print('START',i+1,'/',len(schedule),job['group'],job['case'],'repeat',job['repeat'],flush=True)
        begin=time.monotonic();timed_out=False
        with logpath.open('w') as log:
            proc=subprocess.Popen(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=proc.wait(timeout=1800)
            except subprocess.TimeoutExpired:
                timed_out=True;os.killpg(proc.pid,signal.SIGKILL);code=proc.wait()
        row=dict(**job,directory=dest.name,command=cmd,exitcode=code,
                 timed_out=timed_out,seconds=time.monotonic()-begin)
        if code==0:
            row['result']=json.loads((dest/'summary.json').read_text())['results'][0]
        else:
            meta=json.loads((dest/'manifest.json').read_text()) if (dest/'manifest.json').exists() else {}
            row['failure_kind']='timeout' if timed_out else meta.get('failure_kind','execution_or_audit_failure')
        # Retain accepted monitoring/cleanup anomalies; do not silently treat
        # main-process success as evidence of complete resource-sample coverage.
        content=logpath.read_text(errors='replace')
        row['measurement_warnings']=[label for marker,label in
            [('Exception in thread','background_thread_exception'),('PermissionError:','permission_error_in_log')]
            if marker in content]
        report['attempts'].append(row);save()
        print('PASS' if code==0 else 'FAIL',i+1,'budget',row.get('result',{}).get('within_budget'),
              'measurement_warnings',row['measurement_warnings'],flush=True)
    report['failed']=sum(r['exitcode']!=0 for r in report['attempts'])
    report['status']='FAIL' if report['failed'] else 'PASS';report['ended_unix']=time.time();save()
    # All timed cases finish before postprocessing; capacity-budget failures
    # remain separate from protocol/execution failures, including in the report.
    code=subprocess.run([sys.executable,'-m','experiments.rq4_report','--root',str(out)],cwd=ROOT).returncode
    report['report_exitcode']=code;save()
    print(json.dumps(dict(status=report['status'],attempted=len(report['attempts']),out=str(out))),flush=True)
    if code or report['failed']:raise SystemExit(code or 1)


if __name__=='__main__':main()
