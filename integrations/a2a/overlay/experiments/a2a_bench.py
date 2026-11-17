"""MANUAL ONLY: paired joint bridge overhead or unchanged-entry before/after review."""
import argparse,json,random,subprocess,sys,os,hashlib
from pathlib import Path

SETTINGS={'Q1':(1,1,256),'Q2':(4,1,256),'Q3':(16,1,256),
          'Q4':(1,1,4096),'Q5':(1,1,16384),'Q6':(4,4,256)}

def main():
    p=argparse.ArgumentParser(__doc__)
    p.add_argument('--out',required=True)
    p.add_argument('--paths',default='direct-joint,bridge-joint')
    p.add_argument('--settings',default=','.join(SETTINGS))
    p.add_argument('--repeats',type=int,default=5)
    p.add_argument('--window-seconds',type=float,default=30)
    p.add_argument('--warmup-seconds',type=float,default=5)
    p.add_argument('--pool-units',type=int,default=32768)
    p.add_argument('--slot-bits',type=int,default=15)
    p.add_argument('--transfer-block',type=int,default=64)
    p.add_argument('--contact-seconds',type=float,default=600)
    p.add_argument('--lease-seconds',type=float,default=600)
    p.add_argument('--order-seed',type=int,default=43101)
    p.add_argument('--legacy-review',action='store_true')
    p.add_argument('--baseline-root',type=Path)
    p.add_argument('--execute',action='store_true',help='Explicit manual authorization to run performance/warmup')
    p.add_argument('--print-plan',action='store_true',help='No initialization, requests or warmup')
    a=p.parse_args();root=Path(__file__).resolve().parents[1]
    assert a.repeats>0 and a.window_seconds>0 and a.warmup_seconds>=0
    assert 0<a.transfer_block<=a.pool_units<=2**a.slot_bits
    assert a.pool_units%a.transfer_block==0
    paths=['legacy-before','legacy-after'] if a.legacy_review else a.paths.split(',')
    assert set(paths)<=set(['direct-joint','bridge-joint','legacy-before','legacy-after'])
    if a.legacy_review:assert a.baseline_root and (a.baseline_root/'gredac/endpoint.py').is_file()
    names=a.settings.split(',');assert set(names)<=set(SETTINGS)
    pairs=[(q,rep) for q in names for rep in range(a.repeats)]
    rng=random.Random(a.order_seed);rng.shuffle(pairs);jobs=[]
    for q,rep in pairs:
        order=paths.copy();rng.shuffle(order)
        for path in order:
            callers,services,size=SETTINGS[q]
            jobs.append(dict(setting=q,repeat=rep,path=path,callers=callers,services=services,payload_bytes=size,
                code_root=str(a.baseline_root.resolve() if path=='legacy-before' else root),
                **{k:getattr(a,k) for k in ['window_seconds','warmup_seconds','pool_units','slot_bits',
                    'transfer_block','contact_seconds','lease_seconds','order_seed']}))
    if a.print_plan:
        print(json.dumps(dict(executed=False,warmup_executed=False,jobs=jobs),indent=2));return
    if not a.execute:p.error('Manual performance execution requires --execute; use --print-plan to inspect only.')
    out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=False)
    (out/'plan.json').write_text(json.dumps(dict(jobs=jobs,paired=True,serial=True,worker=str(Path(__file__).with_name('a2a_bench_worker.py'))),indent=2))
    worker=Path(__file__).with_name('a2a_bench_worker.py')
    (out/'worker.sha256').write_text(hashlib.sha256(worker.read_bytes()).hexdigest()+'  '+str(worker)+'\n')
    status=[]
    for i,job in enumerate(jobs):
        dest=out/('run-%03d'%i);job={**job,'out':str(dest)}
        (out/('job-%03d.json'%i)).write_text(json.dumps(job,indent=2))
        env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env.pop('GREDAC_A2A_TESTING',None)
        print('START',i+1,len(jobs),job['path'],job['setting'],flush=True)
        with (out/('run-%03d.log'%i)).open('w') as log:
            code=subprocess.run([sys.executable,str(worker),'--job',str(out/('job-%03d.json'%i))],
                env=env,stdout=log,stderr=subprocess.STDOUT).returncode
        status.append(dict(index=i,job=job,returncode=code))
        (out/'execution.json').write_text(json.dumps(status,indent=2))
        if code:raise SystemExit('Run failed; evidence retained. No replacement sample: '+str(dest))
        print('DONE',i+1,flush=True)

if __name__=='__main__':main()
