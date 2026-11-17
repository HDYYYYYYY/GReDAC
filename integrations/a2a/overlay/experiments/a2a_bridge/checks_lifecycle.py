"""B3 lifecycle and controlled/randomized schedules over real role RPC."""
import copy,json,threading,time,random,concurrent.futures
from pathlib import Path
from .testing import Fixture,response,parallel,denied
from ..support import write_json

def lifecycle(run):
    rows=[]
    with Fixture(run,'B3-lifecycle',size=16,delegate_size=8) as f:
        l=f.lab;c=l.right('C','C','c',f.a);hc=l.delegate(f.h,c,{'s1':[0,1,2],'s2':[0,1,2]})
        wc=l.reserve(hc,f.srv,{'s1':[0,1,2],'s2':[0,1,2]})
        b=l.right('B','B','c',f.root);hb=l.delegate(f.held,b,{'s1':[8,9],'s2':[8,9]})
        wb=l.reserve(hb,f.srv,{'s1':[8,9],'s2':[8,9]})
        for i in [0,1]:f.send(i,'child-'+str(i),'research.aggregate',{'rows':[]},w=wc)
        l.call('O','revoke',{'id':f.a});returned,slots=l.recovery(f.w,f.root,actor='O')
        assert slots=={'s1':list(range(2,8)),'s2':list(range(2,8))}
        rows.append(dict(id='L01',passed=True,returned=slots,oracle=f.snapshot()))
        ev=[f.reject(lambda:f.send(2,'old-A')),f.reject(lambda:f.send(2,'old-C',w=wc))]
        d=l.right('D','D','c',f.root);hd=l.delegate(returned,d,slots);wd=l.reserve(hd,f.srv,slots)
        result=f.send(2,'new-D',w=wd);assert response(result)=={}
        rows.append(dict(id='L02',passed=True,old_material=ev))
        assert response(f.send(8,'unrelated-B',w=wb))=={}
        rows.append(dict(id='L03',passed=True,oracle=f.snapshot()))
        packet=f.packet('new-D',caller='D')
        l.call('R','revoke',{'id':f.srv});s2=l.right('srv2','S2','c',f.sroot,side='service')
        found=l.discover(hd);assert [m['member'] for m in found['members']]==[s2]
        w2=l.reserve(hd,s2,slots)
        assert response(f.send(3,'new-service',w=w2,srv=s2))=={}
        retry=f.raw(packet,caller='D');assert retry['replay'] and retry['service_receipt']['body']['service_right']==f.srv
        rows.append(dict(id='L04',passed=True,old_member=f.srv,new_member=s2,oracle=f.snapshot()))
        audit=f.close()
        events=[json.loads(x) for x in (l.path/'network/actors/Authority/events.jsonl').read_text().splitlines()]
        rpc=[x for x in events if x['kind']=='rpc-received'];freeze=next(i for i,x in enumerate(rpc) if x['method']=='freeze')
        assert all(x['method'] in ('audit','stats','stop') for x in rpc[freeze+1:])
        rows.append(dict(id='L05',passed=True,authority_runtime_messages=0,audit=audit))
    with Fixture(run,'B3-isolation-one',endpoint='G1') as a, Fixture(run,'B3-isolation-two',endpoint='G2') as b:
        a.send(0);packet=a.packet('r0')
        ev=b.reject(lambda:b.raw(packet))
        a.lab.call('O','revoke',{'id':a.a})
        assert response(b.send(0,args={'independent':True}))=={'independent':True}
        rows.append(dict(id='L06',passed=True,cross_endpoint=ev,second=b.snapshot()))
    return rows

def packet(f,request_id='race',slot=0,action='echo.read',args=None):
    p=f.payload(request_id,action,args);op='summary' if action=='research.aggregate' else 'query'
    return f.lab.mesh.call('A','a2a_test',op='packet',wallet=f.w.id,request_id=request_id,
        operation=op,selections={s:slot for s in f.lab.requirements['c'][op]},payload=p)

def ordered_pair(functions,order):
    # A completion event forces the two commit orders. Both workers still run
    # independently; no test sleeps pretend that a commit has occurred.
    event=threading.Event()
    def first():
        try:return functions[order]()
        finally:event.set()
    def second():
        assert event.wait(20);return functions[1-order]()
    wrapped=[None,None];wrapped[order]=first;wrapped[1-order]=second
    return parallel(wrapped,ordered=True)

def race_case(run,name,kind,seed,order=None):
    with Fixture(run,name,size=8) as f:
        l=f.lab;p=packet(f)
        if kind=='R01':
            outs=parallel([lambda:f.raw(p) for _ in range(16)],seed,prepare=f.prepare_raw)
            assert all(x['ok'] for x in outs)
            assert sum(not x['result']['replay'] for x in outs)==1
            assert f.snapshot()==dict(requests=1,spent={'s1':1},business={'S':1})
        elif kind=='R02':
            packets=[packet(f,'race-'+str(i),action='research.aggregate',args={'rows':[]}) for i in range(16)]
            outs=parallel([lambda p=p:f.raw(p,'summary') for p in packets],seed,prepare=f.prepare_raw)
            assert sum(x['ok'] for x in outs)==1
            assert f.snapshot()==dict(requests=1,spent={'s1':1,'s2':1},business={'S':1})
        elif kind=='R03':
            child=l.right('C','C','c',f.a);h=l.delegate(f.h,child,{'s1':[0],'s2':[0]});child_wallet=[]
            def transfer():
                child_wallet.append(l.reserve(h,f.srv,{'s1':[0],'s2':[0]}));return {'transferred':True}
            funcs=[lambda:f.raw(p),transfer]
            outs=ordered_pair(funcs,order) if order is not None else parallel(funcs,seed)
            assert sum(x['ok'] for x in outs)==1,outs
            if outs[1]['ok']:f.send(0,'child-spend',w=child_wallet[0])
            assert f.snapshot()['requests']==1 and f.business_count()==1
        elif kind=='R04':
            funcs=[lambda:f.raw(p),lambda:l.call('O','revoke',{'id':f.a})]
            outs=ordered_pair(funcs,order) if order is not None else parallel(funcs,seed)
            assert outs[1]['ok']
            if order==1:assert not outs[0]['ok']
            if order==0:assert outs[0]['ok']
            assert f.snapshot()['requests']==int(outs[0]['ok'])
            assert f.business_count()==int(outs[0]['ok'])
        elif kind=='R05':
            l.call('O','revoke',{'id':f.a})
            funcs=[lambda:f.raw(p),lambda:l.call('O','return',{'id':f.a})]
            outs=ordered_pair(funcs,order) if order is not None else parallel(funcs,seed)
            assert not outs[0]['ok'] and outs[1]['ok']
            assert len(outs[1]['result']['body']['rows'])==16
            second=l.call('O','return',{'id':f.a});assert not second['body']['rows']
            assert f.snapshot()['requests']==0
        elif kind=='R06':
            p=packet(f,args={'delay_ms':100})
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                job=pool.submit(f.raw,p)
                until=time.monotonic()+10
                while f.business_count()==0 and time.monotonic()<until:time.sleep(.002)
                assert f.business_count()==1
                start=time.monotonic();revoked=l.call('O','revoke',{'id':f.a});end=time.monotonic()
                result=job.result(timeout=10)
            assert revoked['body']['time']>=result['decision_time']
            assert f.snapshot()['requests']==1 and f.business_count()==1
            outs=[dict(admission_time=result['decision_time'],revoke_requested=start,
                       revoke_recorded=revoked['body']['time'],revoke_ack=end)]
        else:raise ValueError(kind)
        observed=f.snapshot()
        # Full public request inputs and outcomes retained on server.
        write_json(l.path/'schedule.json',dict(kind=kind,seed=seed,order=order,packet=p,outcomes=outs,oracle=observed,not_performance=True))
        return dict(id=kind,seed=seed,order=order,passed=True,oracle=observed,evidence=str(l.path/'schedule.json'))

def races(run,seeds,rounds):
    rows=[]
    for kind in ['R01','R02','R03','R04','R05','R06']:
        orders=[0,1] if kind in ('R03','R04','R05') else [None]
        cases=[]
        for j,order in enumerate(orders):
            cases.append(race_case(run,kind+'-controlled-'+str(j),kind,0,order))
        for seed in seeds:
            for j in range(rounds):
                cases.append(race_case(run,kind+'-seed-'+str(seed)+'-'+str(j),kind,seed*1000+j))
            print('PASS',kind,'seed',seed,'rounds',rounds,flush=True)
        rows.append(dict(id=kind,passed=True,controlled=len(orders),exploration=len(seeds)*rounds,cases=cases))
        write_json(run.out/('partial-'+kind+'.json'),rows[-1])
    return rows
