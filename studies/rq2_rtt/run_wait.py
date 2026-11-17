"""Independent MANUAL delayed dialogue experiment; no automatic other groups.

Full defaults: N=1,8,32,128,512,2048 x6, fixed 2048 units, one profile per
invocation. --check-only verifies files/config and does not create processes
or results. Actual execution preserves every failure without replacement.
"""
import argparse,json,os,random,shutil,signal,subprocess,sys,time
from pathlib import Path
from .model import PROFILES,bindings,load_data,sha

ROOT=Path(__file__).resolve().parents[2]
PACKAGE=Path(__file__).resolve().parent


def ensure_idle():
    from experiments.rq2_v2.suite import idle
    idle()
    # The existing guard recognizes experiments.*. This new independent
    # namespace also rejects another RTT batch, without touching its process.
    for cmdline in Path('/proc').glob('[0-9]*/cmdline'):
        if int(cmdline.parent.name)==os.getpid():continue
        try:
            args=cmdline.read_bytes().split(b'\0')
            if b'-m' in args:
                module=args[args.index(b'-m')+1]
                assert module not in (b'studies.rq2_rtt.run_wait',b'studies.rq2_rtt.wait_case'),('another RTT task is running',cmdline.parent.name)
        except (OSError,IndexError):pass


def frozen_code():
    freeze=json.loads((PACKAGE/'DRIVER_FREEZE.json').read_text())
    for rel,digest in freeze['files_sha256'].items():assert sha(ROOT/rel)==digest,('frozen source changed',rel)
    return freeze


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--profile',choices=PROFILES,default='local')
    p.add_argument('--enable-rtt',action='store_true');p.add_argument('--check-only',action='store_true')
    p.add_argument('--requests',default='1,8,32,128,512,2048');p.add_argument('--repeats',type=int,default=6)
    p.add_argument('--data',type=Path,default=PACKAGE/'data');a=p.parse_args()
    assert a.profile=='local' or a.enable_rtt,'remote profile requires explicit --enable-rtt'
    assert not a.enable_rtt or a.profile!='local','use no --enable-rtt for measured loopback control'
    ns=list(map(int,a.requests.split(',')));assert len(ns)==len(set(ns)) and set(ns)<={1,8,32,128,512,2048}
    assert 1<=a.repeats<=6
    code=frozen_code();data,freeze=load_data(a.data)
    assert sha(a.data/'FREEZE.json')==code['dataset_freeze_sha256'],'different RTT dataset'
    jobs=[dict(N=n,repeat=r) for n in ns for r in range(a.repeats)]
    random.Random(16112026).shuffle(jobs)
    if a.check_only:
        print(json.dumps(dict(status='PASS',check_only=True,tasks=len(jobs),profile=a.profile,injected_wait=a.enable_rtt,
            requests=ns,repeats=a.repeats,issued=2048,llm_calls=0,timeout_s=3000,
            validation=code['validation'])));return
    from experiments.rq2_later.suite import environment
    ensure_idle();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    # Compact public pool copy avoids loading raw ping metadata in every role.
    samples=out/'runtime-samples.json';samples.write_text(json.dumps({k:[s[1] for s in v['samples']] for k,v in data['pools'].items()},separators=(',',':'))+'\n')
    for rel in code['files_sha256']:
        dest=out/'source'/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,dest)
    meta=dict(status='RUNNING',profile=a.profile,injected_wait=a.enable_rtt,plan=jobs,attempts=[],
        source_freeze=code,environment=environment(),dataset_freeze_sha256=sha(a.data/'FREEZE.json'),
        runtime_samples_sha256=sha(samples),started_unix=time.time(),llm_calls=0,
        measurement='physical loopback TCP/TLS plus separately recorded artificial RTT waits; NOT a WAN measurement',
        security_ttl_unchanged=True,controller_wait_timeout_s=2400,per_task_watchdog_s=3000,
        note='Task timer includes instrumentation and process-local sample loading. No subtraction as protocol speedup.')
    def save():(out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
    save()
    for i,job in enumerate(jobs):
        ensure_idle();assert frozen_code()==code
        name=f'run-{i:03d}';dest=out/name
        settings=dict(profile=a.profile,seed=freeze['seed'],run=name,bindings=bindings(data,freeze['seed'],name,0),runtime_samples=str(samples))
        config=out/(name+'-rtt.json');config.write_text(json.dumps(settings,indent=2)+'\n')
        cfg=dict(method='GReDAC',identity='roots-dynamic',slot_bits=15,actions=['query'],block='dialogue',requests=job['N'],issued=2048,units=2048,depth=1,cover=1)
        command=[sys.executable,'-u','-m','studies.rq2_rtt.wait_case','--out',str(dest),'--case-json',json.dumps(cfg),'--repeat-index',str(job['repeat'])]
        env=dict(os.environ,RQ2_RTT_ENABLED='1' if a.enable_rtt else '0',RQ2_RTT_CONFIG=str(config))
        print('START',i+1,'/',len(jobs),job,flush=True);start=time.monotonic();timed_out=False
        with (out/(name+'.log')).open('w') as log:
            proc=subprocess.Popen(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:exitcode=proc.wait(timeout=3000)
            except subprocess.TimeoutExpired:
                timed_out=True;os.killpg(proc.pid,signal.SIGKILL);exitcode=proc.wait()
            except BaseException:
                os.killpg(proc.pid,signal.SIGTERM);proc.wait();raise
        record=dict(**job,directory=name,exitcode=exitcode,timeout=timed_out,seconds=time.monotonic()-start,config=str(config),command=command)
        if exitcode==0:record['measured_with_wait']=json.loads((dest/'summary.json').read_text())['results'][0]
        records=[]
        if dest.exists():
            for f in dest.glob('protocol/network/actors/*/rtt-waits.jsonl'):
                records.extend(json.loads(line) for line in f.read_text().splitlines())
        record['wait_rpc_records']=len(records)
        record['requested_wait_seconds']=sum(w['requested_seconds'] for row in records for w in row['waits'])
        record['actual_wait_seconds']=sum(w['actual_seconds'] for row in records for w in row['waits'])
        # Every successful task must match the audited protocol message count.
        record['wait_evidence_ok']=not a.enable_rtt or (len(records)==17+2*job['N'] and all(r['result']=='ok' for r in records))
        meta['attempts'].append(record);save();print('PASS' if exitcode==0 and record['wait_evidence_ok'] else 'FAIL',i+1,flush=True)
    meta['status']='PASS' if all(r['exitcode']==0 and r['wait_evidence_ok'] for r in meta['attempts']) else 'FAIL'
    meta['ended_unix']=time.time();save();print(json.dumps(dict(status=meta['status'],out=str(out),tasks=len(jobs))))
    if meta['status']!='PASS':raise SystemExit(1)


if __name__=='__main__':main()
