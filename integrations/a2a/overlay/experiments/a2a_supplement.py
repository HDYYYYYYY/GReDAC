"""Additional receiver-card and concurrent-return checks; not performance."""
from contextlib import closing
import os,json,copy,sqlite3,hashlib,shutil
from pathlib import Path
from .support import parser,Run,write_json

def main():
    p=parser(__doc__);p.set_defaults(slot_bits=10,repeats=1)
    p.add_argument('--acceptance-root',required=True,help='Completed a2a_regression output directory containing B3 schedules')
    p.add_argument('--schedule-seeds',default='101,202,303')
    p.add_argument('--rounds',type=int,default=20)
    a=p.parse_args();assert a.rounds>0
    acceptance=Path(a.acceptance_root);previous=json.loads((acceptance/'manifest.json').read_text())
    assert previous['status']=='PASS' and 'B3' in previous['config']['suites'].split(','),'B3 regression must complete first'
    expected_slow=1+len(previous['config']['schedule_seeds'].split(','))*previous['config']['rounds']
    os.environ['GREDAC_SLOT_BITS']=str(a.slot_bits);os.environ['GREDAC_A2A_TESTING']='1'
    from .a2a_bridge.testing import Fixture,parallel
    from .a2a_bridge.checks_lifecycle import packet
    from gredac.crypto import digest,canonical
    run=Run(a,'a2a_supplement');rows=[]
    root=Path(__file__).resolve().parents[1]
    for path in (root/'experiments/a2a_bridge').glob('*.py'):
        dest=run.out/'source'/path.relative_to(root);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dest)
        run.manifest['source_sha256'][str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
    run.manifest['code_fingerprint']=hashlib.sha256(json.dumps(run.manifest['source_sha256'],sort_keys=True).encode()).hexdigest()
    run.manifest.update(not_performance=True,llm_api_calls=0)
    try:
        with Fixture(run,'N16-receiver') as f:
            l=f.lab;r=l.rights[f.srv];desc=l.mesh.call('S','describe',right=f.srv)
            from .a2a_bridge.codec import binding
            info=dict(context='c',service='c',member=f.srv,endpoint='G',
                endpoint_address=l.identities['G']['endpoint'],member_address=l.identities['S']['endpoint'],
                **binding(l.cards[f.srv],f.srv))
            variants=[]
            for mode in ['url','digest','right']:
                bad=copy.deepcopy(info)
                if mode=='url':
                    bad['card']['supportedInterfaces'][0]['url']='http://127.0.0.1:22/'
                    bad['card_digest']=digest(bad['card'])
                elif mode=='digest':bad['card_digest']='0'*64
                else:bad['service_right']='another-member'
                variants.append(f.reject(lambda bad=bad:l.call('R','publish',dict(info=bad,chain=desc['chain'],identities=desc['identities']))))
            rows.append(dict(id='N16-receiver',passed=True,variants=variants))
        with Fixture(run,'P02-public-client') as f:
            from .a2a_bridge.client import BridgeResult
            first=f.lab.send(f.w,'api-query','api-query',arguments={'hello':'sdk'})
            assert first.admission_status=='ADMITTED' and first.business_status=='OK'
            assert first.a2a_response['message']['parts'][0]['data']['value']=={'hello':'sdk'}
            second=f.lab.send(f.w,'api-summary','api-summary',action='research.aggregate',arguments={'rows':[]})
            assert second.admission_status=='ADMITTED' and second.business_status=='OK'
            assert f.snapshot()['spent']=={'s1':2,'s2':1}
            f.lab.mesh.call('G','arm_fault',point='response_loss')
            lost=f.lab.send(f.w,'api-lost','api-lost',arguments={'keep':'original'})
            assert lost.admission_status=='TRANSPORT_UNKNOWN'
            saved=f.lab.retry(f.w,'api-lost')
            recovered=BridgeResult.admitted(saved,'api-lost','api-lost')
            assert recovered.admission_status=='ADMITTED' and recovered.business_status=='OK' and saved['replay']
            assert f.snapshot()==dict(requests=3,spent={'s1':3,'s2':1},business={'S':3})
            rows.append(dict(id='P02-public-client',passed=True,source_selection=f.snapshot(),exact_pending_retry=True))
        schedules=[('barrier',0)]+[(str(seed)+'-'+str(j),seed*1000+j) for seed in map(int,a.schedule_seeds.split(',')) for j in range(a.rounds)]
        for label,seed in schedules:
            with Fixture(run,'R05-duplicate-'+label,size=8) as f:
                l=f.lab;pck=packet(f);l.call('O','revoke',{'id':f.a})
                outs=parallel([lambda:l.call('O','return',{'id':f.a}),
                               lambda:l.call('O','return',{'id':f.a}),
                               lambda:f.raw(pck)],seed)
                assert outs[0]['ok'] and outs[1]['ok'] and not outs[2]['ok']
                a0,a1=outs[0]['result']['body'],outs[1]['result']['body']
                u0={(r['source'],r['slot']) for r in a0['rows']};u1={(r['source'],r['slot']) for r in a1['rows']}
                if a0['operation']==a1['operation']:assert a0==a1
                else:assert not u0&u1
                assert len(u0|u1)==16 and f.snapshot()['requests']==0 and f.business_count()==0
                write_json(l.path/'schedule.json',dict(seed=seed,outcomes=outs,oracle=f.snapshot()))
                rows.append(dict(id='R05-concurrent-return',passed=True,seed=seed,returned_unique=len(u0|u1)))
        # Reconcile the slow-handler ordering against durable service finish,
        # rather than just checking wall-clock durations in the caller.
        checked=[]
        for path in sorted(acceptance.glob('R06-*/schedule.json')):
            value=json.loads(path.read_text());times=value['outcomes'][0]
            with closing(sqlite3.connect('file:'+str(path.parent/'network/actors/S/a2a/bridge.sqlite')+'?mode=ro',uri=True)) as db:
                finish=db.execute('SELECT finished FROM business').fetchone()[0]
            assert times['revoke_requested']<finish<=times['revoke_recorded']<=times['revoke_ack']
            checked.append(dict(path=str(path),business_finished=finish,**times))
        assert len(checked)==expected_slow,(len(checked),expected_slow)
        rows.append(dict(id='R06-durable-order',passed=True,cases=checked))
        run.finish(rows)
    finally:
        from .network_client import Mesh
        for mesh in Mesh.live:mesh.close()

if __name__=='__main__':main()
