"""B3 F01-F08 fault checks, fresh worker process and databases for each repeat."""
from contextlib import closing
import os,json,sqlite3,shutil,hashlib,time
from pathlib import Path
from .support import parser,matrix,write_json

def guard_state(f):
    p=f.lab.path/'network/actors/G/guard.sqlite'
    with closing(sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True)) as db:
        rows=[(k,key,json.loads(v)) for k,key,v in db.execute('SELECT kind,key,value FROM records')]
    requests={key:v for k,key,v in rows if k=='requests'}
    states={key:v['state'] for k,key,v in rows if k=='forwarding'}
    spent={}
    for k,key,v in rows:
        if k=='positions' and v['state']=='spent':spent[v['source']]=spent.get(v['source'],0)+1
    return dict(requests=len(requests),keys=list(requests),states=states,spent=spent)

def execute(run,args,case,rep):
    from .a2a_bridge.testing import Fixture
    root=Path(__file__).resolve().parents[1]
    for p in (root/'experiments/a2a_bridge').glob('*.py'):
        dest=run.out/'source'/p.relative_to(root);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
        run.manifest['source_sha256'][str(p.relative_to(root))]=hashlib.sha256(p.read_bytes()).hexdigest()
    run.manifest['code_fingerprint']=hashlib.sha256(json.dumps(run.manifest['source_sha256'],sort_keys=True).encode()).hexdigest()
    run.manifest.update(not_performance=True,sdk='a2a-sdk==1.3.0',llm_api_calls=0)
    point=case['point'];mode=case['mode']
    with Fixture(run,'fixture') as f:
        l=f.lab;arguments={};error=None
        if point in ('F01','F02','F03'):
            name={'F01':'before_admission_commit','F02':'after_pending','F03':'after_attempted'}[point]
            l.mesh.call('G','a2a_test',op='endpoint_fault',point=name,mode=mode)
        elif point in ('F04','F05'):
            l.mesh.call('S','a2a_fault',point='after_starting' if point=='F04' else 'after_business',mode='exit')
        elif point=='F06':l.mesh.call('G','arm_fault',point='after_service_response')
        elif point=='F07':l.mesh.call('G','arm_fault',point='response_loss')
        elif point=='F08':
            if mode=='exception':arguments={'fail':True}
            elif mode=='timeout':
                l.mesh.call('S','a2a_service',timeout=.03);arguments={'delay_ms':150}
            elif mode=='oversize':
                l.mesh.call('S','a2a_service',timeout=.2);arguments={'response_bytes':262145}
        try:initial=f.send(0,'fault',args=arguments)
        except Exception as exc:error=dict(type=type(exc).__name__,message=str(exc)[:300])
        if point!='F08':assert error is not None,'injected fault did not interrupt request'
        before=guard_state(f)
        if point=='F01':
            assert before['requests']==0 and before['spent']=={} and f.business_count()==0
        else:
            assert before['requests']==1 and before['spent']=={'s1':1}
        if point in ('F01','F02','F03') and mode=='exit' or point=='F06':
            proc=l.mesh.processes['G'];proc.join(5);assert proc.exitcode==73
            l.restart_endpoint();proc.close()
        elif point in ('F01','F02','F03'):
            assert l.mesh.processes['G'].is_alive()
            l.mesh.call('G','resume_delivery')
        elif point in ('F04','F05'):
            proc=l.mesh.processes['S'];proc.join(5);assert proc.exitcode==74
            expected=0 if point=='F04' else 1
            assert f.business_count()==expected
            if point=='F05':
                with closing(sqlite3.connect(l.path/'network/actors/S/a2a/bridge.sqlite')) as db:
                    assert db.execute('SELECT COUNT(*) FROM business WHERE finished IS NOT NULL').fetchone()[0]==1
            l.mesh.restart('S');proc.close()
            l.mesh.call('R','a2a_test',op='resend_right',right=f.srv)
            l.mesh.call('S','a2a_service');l.publish_service(f.srv)
            assert f.business_count()==expected
            # Explicit adversarial duplicate delivery probe, NOT core recovery or
            # a supported G backfill operation. It must never invoke SDK again.
            probe=l.mesh.call('G','a2a_test',op='replay_delivery',key=before['keys'][0])
            assert probe['body']['result']['business_status']=='UNKNOWN'
            assert f.business_count()==expected
        if point=='F08':
            result=initial
            time.sleep(.2 if mode=='timeout' else 0)
            status=result['service_receipt']['body']['result']['business_status']
            assert status==('ERROR' if mode=='exception' else 'UNKNOWN'),status
            packet=f.packet('fault');retry=f.raw(packet)
            assert retry['replay'] and retry['service_receipt']==result['service_receipt']
        else:
            result=l.retry(f.w,'fault')
            if point=='F01':assert not result['replay'] and result['delivery_state']=='delivered'
            elif point in ('F02','F07'):assert result['replay'] and result['delivery_state']=='delivered'
            else:assert result['replay'] and result['delivery_state']=='attempted' and result['service_receipt'] is None
        after=guard_state(f)
        assert after['requests']==1 and after['spent']=={'s1':1}
        expected=0 if point in ('F03','F04') else 1
        assert f.business_count()==expected
        # Return excludes the consumed unit even when the result is unknown.
        l.call('O','revoke',{'id':f.a});held,slots=l.recovery(f.w,f.root,actor='O')
        assert 0 not in slots['s1'] and len(slots['s1'])==15
        evidence=dict(point=point,mode=mode,repeat=rep,error=error,before=before,after=after,
            business_executions=f.business_count(),result=result,returned=slots,not_performance=True)
        write_json(run.out/'fault-evidence.json',evidence)
        audit=f.close()
    return dict(id=point,mode=mode,repeat=rep,passed=True,not_performance=True,audit=audit,
                evidence='fault-evidence.json',business_executions=expected)

def main():
    p=parser(__doc__);p.set_defaults(slot_bits=10,repeats=3)
    p.add_argument('--points',default='F01,F02,F03,F04,F05,F06,F07,F08')
    args=p.parse_args();os.environ['GREDAC_SLOT_BITS']=str(args.slot_bits);os.environ['GREDAC_A2A_TESTING']='1'
    cases=[]
    for point in args.points.split(','):
        modes=['exit','connection'] if point in ('F01','F02','F03') else ['exception','timeout','oversize'] if point=='F08' else ['exit']
        cases.extend(dict(point=point,mode=mode) for mode in modes)
    matrix(args,__spec__.name,cases,execute)

if __name__=='__main__':main()
