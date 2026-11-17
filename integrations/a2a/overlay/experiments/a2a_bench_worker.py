"""Only a2a_bench --execute invokes this file. Source root selected before imports."""
import argparse,os,json,sys,time,threading,hashlib,traceback,platform
from pathlib import Path
from types import SimpleNamespace
from collections import Counter
import concurrent.futures

def main():
    parser=argparse.ArgumentParser(__doc__);parser.add_argument('--job',required=True);args=parser.parse_args()
    job=json.loads(Path(args.job).read_text());root=Path(job['code_root']).resolve()
    sys.path.insert(0,str(root));os.environ['GREDAC_SLOT_BITS']=str(job['slot_bits'])
    os.environ.pop('GREDAC_A2A_TESTING',None)
    from experiments.support import Run,write_json,stats
    from gredac.crypto import canonical,digest,Denied
    from experiments.network_client import Client,Mesh
    bridge=job['path']=='bridge-joint';legacy=job['path'].startswith('legacy-')
    if bridge:
        from experiments.a2a_bridge.client import BridgeClient
        client_class=BridgeClient
    else:client_class=Client
    run=Run(SimpleNamespace(out=job['out'],slot_bits=job['slot_bits'],repeats=1,**{'job':job}),'a2a_manual_benchmark')
    records=[];record_lock=threading.Lock();resource_stop=threading.Event();resource_rows=[]
    source_hashes={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
        for folder in ['gredac','experiments'] for p in (root/folder).rglob('*.py') if '__pycache__' not in p.parts}
    write_json(run.out/'source-sha256.json',source_hashes)
    write_json(run.out/'effective-config.json',dict(job,python=sys.executable,python_version=platform.python_version(),
        cryptography=__import__('importlib.metadata',fromlist=['version']).version('cryptography'),
        semantic_scope='joint only; one host real mutual TLS/TCP plus private UDS for bridge',
        budget_includes_warmup=True,lease_starts_before_initial_issuance=True))
    def monitor():
        while not resource_stop.is_set():
            row={'monotonic':time.monotonic()}
            for name in ['pressure/cpu','pressure/io','pressure/memory','diskstats','meminfo','stat']:
                try:row[name]=Path('/proc',name).read_text()
                except OSError:pass
            resource_rows.append(row);resource_stop.wait(1)
    rt=threading.Thread(target=monitor,daemon=True);rt.start()
    lab=None
    try:
        lab=client_class(run,'network',contact_seconds=job['contact_seconds'])
        lab.deadline=time.monotonic()+job['lease_seconds']
        lab.context('c',['s1','s2'])
        for source in ['s1','s2']:lab.source(source,job['pool_units'],['c'])
        root_right=lab.right('O-c','O','c');service_root=lab.right('R-c','R','c',side='service')
        services=[lab.right('service-'+str(j),'S'+str(j),'c',service_root,side='service') for j in range(job['services'])]
        allslots={s:list(range(job['pool_units'])) for s in ['s1','s2']}
        held=lab.seed(root_right,allslots)
        if not bridge:
            for rid in services:lab.set_handler(rid,'fixed',target=lab.rights[rid]['owner'])
        callers=[lab.right('caller-'+str(j),'A'+str(j),'c',root_right) for j in range(job['callers'])]
        allocated=[[] for _ in callers];holdings={}
        for index,start in enumerate(range(0,job['pool_units'],job['transfer_block'])):
            j=index%len(callers);block=list(range(start,start+job['transfer_block']))
            allocated[j].extend(block)
            holdings[j]=lab.delegate(held,callers[j],{s:block for s in ['s1','s2']})
        wallets=[lab.reserve(holdings[j],services[j%len(services)],{s:allocated[j] for s in ['s1','s2']}) for j in range(len(callers))]
        lab.freeze_setup()
        if not legacy:
            from experiments.a2a_bridge.codec import make_card,envelope
            cards=lab.cards if bridge else {rid:make_card(lab.rights[rid]['owner']) for rid in services}
        business_args={'benchmark':True,'padding':''}
        business_args['padding']='x'*(job['payload_bytes']-len(canonical(business_args)))
        assert len(canonical(business_args))==job['payload_bytes']
        barrier=threading.Barrier(len(callers)+1);release=threading.Event();setup_lock=threading.Lock();times={};fatal=[]
        def worker(j):
            try:
                with setup_lock:lab.discover(holdings[j],services[j%len(services)])
                barrier.wait(timeout=120)
            except BaseException:
                barrier.abort();release.set();raise
            release.wait();seq=0
            while time.monotonic()<times['end']:
                phase='warmup' if time.monotonic()<times['measure'] else 'measurement'
                start=time.monotonic();request_id='a%d-r%d'%(j,seq);seq+=1
                run.local.phase=phase
                payload=business_args if legacy else envelope(wallets[j].service,cards[wallets[j].service],request_id,'echo.read',business_args,'benchmark')
                try:
                    answer=lab.consume_next(wallets[j],request_id,'query',payload)
                    result=answer['service_receipt']['body']['result']
                    if bridge:
                        assert result['business_status']=='OK'
                        result=result['a2a_response']['message']['parts'][0]['data']['value']
                    assert result['target']==lab.rights[wallets[j].service]['owner'] and result['value']==digest(payload)
                    assert len(canonical(result))==256
                    row=dict(caller=j,request=request_id,phase=phase,start=start,end=time.monotonic(),accepted=True,
                        key=answer['key'],payload_wire_bytes=len(canonical(payload)),delivery_state=answer['delivery_state'])
                except Exception as exc:
                    row=dict(caller=j,request=request_id,phase=phase,start=start,end=time.monotonic(),accepted=False,
                             error=type(exc).__name__,code=getattr(exc,'code',str(exc)))
                    fatal.append(row)
                with record_lock:records.append(row)
                if not row['accepted']:break
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(callers)) as pool:
            futures=[pool.submit(worker,j) for j in range(len(callers))]
            barrier.wait(timeout=120)
            start=time.monotonic();times.update(start=start,measure=start+job['warmup_seconds'],end=start+job['warmup_seconds']+job['window_seconds'])
            release.set()
            for future in futures:future.result()
        audit=lab.close();lab=None
        valid=[r for r in records if r['accepted'] and r['phase']=='measurement' and r['end']<=times['end']]
        allaccepted=[r for r in records if r['accepted']]
        assert audit['new_requests']==len(allaccepted)
        assert audit['spent_by_source']=={s:len(allaccepted) for s in ['s1','s2']}
        budget_censored=any(r.get('code')=='NO_LOCAL_UNUSED_UNIT' for r in fatal)
        summary=dict(path=job['path'],setting=job['setting'],not_a_stable_capacity_claim=True,
            budget_censored=budget_censored,failures=fatal,measured_completed=len(valid),
            completed_per_second=len(valid)/job['window_seconds'],warmup_and_measurement_admissions=len(allaccepted),
            latency_seconds=stats([r['end']-r['start'] for r in valid]),audit=audit,window=times,
            in_flight_after_window=sum(r['accepted'] and r['end']>times['end'] for r in records),
            raw_samples='requests.jsonl',resources='host-resources.json')
        with (run.out/'requests.jsonl').open('w') as f:
            for row in records:f.write(json.dumps(row)+'\n')
        if fatal and not budget_censored:
            write_json(run.out/'partial-summary.json',summary)
            raise RuntimeError('performance run had non-budget errors; retained, do not replace')
        run.finish([summary])
    except BaseException:
        failure=traceback.format_exc()
        write_json(run.out/'failure.json',dict(traceback=failure,records=records))
        run.manifest.update(status='FAIL',traceback=failure);write_json(run.out/'manifest.json',run.manifest);raise
    finally:
        resource_stop.set();rt.join(3);write_json(run.out/'host-resources.json',resource_rows)
        for mesh in Mesh.live:mesh.close()

if __name__=='__main__':main()
