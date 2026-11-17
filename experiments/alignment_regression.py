"""GReDAC alignment checks: isolated attacks, real TCP flows and crashes.

Test-only mutation is explicit here; neither business drivers nor Agents read
another participant's ledger. Local white-box tests are not performance data.
Network tests use independent role processes and receive only public receipts.
No external model is called. Every invocation requires a new evidence folder.
"""
import copy,json,time,hashlib
from pathlib import Path
from .support import parser,Run,write_json

def denied(fn,code=None):
    from gredac.crypto import Denied
    try:fn()
    except Denied as e:
        if code:assert e.code==code,(e.code,code)
        return e.code
    raise AssertionError('negative test unexpectedly accepted')

def local_checks(run):
    from gredac.crypto import SCHEME,CODEC,SLOT_BITS,Signer,domain_for,ident,canonical,cover,anchor_secret
    from gredac.storage import Store,MonotonicClock,position_key
    from gredac.capabilities import Forest
    from gredac.authority import AgentAuthority
    from gredac.material import pack,unpack
    from gredac.participant import accept_return
    results=[];store=Store(run.out/'binding.sqlite');forest=Forest(store)
    a,g='22'*32,'33'*32;master=bytes.fromhex('11'*32);domain=domain_for(['query'],range(8));outputs=[]
    for source,context,guard in [('s','c','G'),('s','c','G2'),('s2','c','G'),('s','c2','G')]:
        store.put('source_masters',source,master.hex())
        anchor=dict(id=a,source=source,context=context,guard=guard,scheme=SCHEME,codec=CODEC,slot_bits=SLOT_BITS)
        cap=dict(gid=g,anchor=a,source=source,context=context,guard=guard,holder_right='root',
            key_parent=dict(kind='anchor',id=a),domain=domain,cover=list(cover(domain)))
        store.put('anchors',a,anchor);store.put('caps',g,cap)
        bundle=forest.rebuild(g);outputs.append(bundle.seeds)
        assert bundle.seeds==type(bundle).initial(g,a,anchor_secret(master,a,source,context,guard),domain).seeds
    assert len({canonical({k:v.hex() for k,v in x.items()}) for x in outputs})==4
    for field,value in [('guard','other'),('codec','other'),('scheme','other'),('slot_bits',SLOT_BITS+1)]:
        bad={**anchor,field:value};store.put('anchors',a,bad);denied(lambda:forest.rebuild(g),'ANCHOR_BINDING')
    store.put('anchors',a,anchor)
    child={**cap,'gid':'44'*32,'key_parent':dict(kind='cap',id=g),'guard':'other'}
    store.put('caps',child['gid'],child);denied(lambda:forest.rebuild(child['gid']),'KEY_PARENT_BINDING');store.close()
    results.append(dict(test='source_context_endpoint_codec_parent_binding',passed=True))
    # Directly count cap reads in initial unit binding; no timing extrapolation.
    class CounterStore:
        def __init__(self):self.gets=0;self.puts=0
        def get(self,*a):self.gets+=1;raise AssertionError('repeated capability read')
        def put(self,*a):self.puts+=1
    counts=CounterStore();authority=AgentAuthority.__new__(AgentAuthority);authority.store=counts
    authority.forest=Forest(counts);rows=[dict(source='s',slot=i,hard_actions=['query'],deadline=100) for i in range(1024)]
    authority._bind(rows,dict(gid=g,anchor=a,holder_right='root'),dict(context='c',id='root',owner='O',deadline=100),domain_for(['query'],range(1024)))
    assert counts.gets==0 and counts.puts==1024
    results.append(dict(test='1024_unit_bind_no_cap_reparse',cap_reads=counts.gets,unit_writes=counts.puts,passed=True))
    cap={**cap,'domain':domain_for(['query'],range(1024)),'cover':list(cover(domain_for(['query'],range(1024))))}
    signed=Signer('parent').envelope(dict(caps=[cap],previous={position_key('s',i):'old-'+str(i//512) for i in range(1024)}))
    value=dict(description=signed,chain=[signed],records={position_key('s',i):dict(source='s',slot=i,ownership='x',
        hard_actions=['query'],deadline=100,holder_right='child') for i in range(1024)},business=[{'z':1,'a':2},[3,2,1]])
    encoded=pack(value);assert canonical(unpack(encoded))==canonical(value)
    receipt_rows=[value['records'][position_key('s',i)] for i in (0,1,10,11,2,3)]
    assert unpack(pack({'rows':receipt_rows}))=={'rows':receipt_rows},'signed row order changed'
    before,after=len(canonical(value)),len(canonical(encoded));assert after<before/4
    results.append(dict(test='lossless_prefix_record_and_predecessor_encoding',logical_json_bytes=before,compact_wire_bytes=after,passed=True))
    # Build a local fixture solely to mutate received signed material and
    # validate recipient behavior. No such mutation occurs in workloads.
    from .local_client import Client
    from gredac.offline import transfer,receive_delegation
    lab=Client(run,'recipient-checks',endpoint_id='G-test');lab.context('c',['s']);lab.source('s',8,['c'])
    root=lab.right('O-c','O','c');sr=lab.right('R-c','R','c',side='service');srv=lab.right('srv','S','c',sr,side='service')
    held=lab.seed(root,{'s':list(range(8))});rid=lab.right('child','A','c',root,actions=['query'])
    h=lab.delegate(held,rid,{'s':[0,1]},actions=['query']);wallet=lab.reserve(h,srv,{'s':[0,1]})
    fresh,description=transfer(held,rid,{'s':[2]},['query'],lab.actor('O'))
    payload=dict(description=description,authorization=lab.authorizations[rid],chain=held.chain+[lab.authorizations[rid],description],
        keys={k:b.public_secrets() for k,b in fresh.bundles.items()},records=fresh.records,task_info=fresh.task_info)
    receive_delegation(payload,lab.rights[rid],lab.actor('O').public,'G-test',lab.rights[root])
    rogue=Signer('rogue');bad=copy.deepcopy(payload);bad['description']=rogue.envelope(description['body'])
    denied(lambda:receive_delegation(bad,lab.rights[rid],rogue.public,'G-test',lab.rights[root]),'AUTHENTICATED_PARENT_REQUIRED')
    lab.call('O','revoke',{'id':rid});receipt=lab.call('O','return',{'id':rid})
    def forged(change):
        body=copy.deepcopy(receipt['body']);change(body)
        env=lab.endpoint.control.envelope(body);env['request']=receipt['request'];return env
    mutations=[lambda b:b.update(operation='wrong'),lambda b:b.update(target='wrong'),
        lambda b:b['rows'].append(copy.deepcopy(b['rows'][0])),lambda b:b['rows'][0]['current_cap'].update(anchor='ff'*32),
        lambda b:b['rows'][0].update(hard_actions=['delete']),lambda b:b['rows'][0].update(deadline=10**20),
        lambda b:b['records'][next(iter(b['records']))].update(units=[])]
    before_records=copy.deepcopy(held.records)
    for f in mutations:
        denied(lambda f=f:accept_return(forged(f),held,lab.rights[root],rid,'G-test',lab.endpoint_public))
        assert held.records==before_records,'invalid receipt partially changed local records'
    restored,slots=lab.receive_return(receipt,root,rid);assert slots=={'s':[0,1]}
    assert all(restored.records[position_key('s',i)]['hard_actions']==['query'] for i in (0,1))
    lab.close();results.append(dict(test='authenticated_parent_and_return_semantics',negative_cases=8,passed=True))
    # Deadline counterexamples: pre-COMMIT expiry rolls back; a deliberate
    # delay beyond the assumed bound is measured and NOT called a safe commit.
    observations=[];clock=MonotonicClock();s=Store(run.out/'deadline.sqlite',observations.append)
    def late_before(where):
        if where=='before_commit':time.sleep(.04)
    s.commit_hook=late_before
    def reject_expired():
        with s.transaction():s.put('x','a',1);s.guard_deadline(clock.now()+.03,clock,.01)
    denied(reject_expired,'FINAL_DEADLINE_CHECK');assert s.get('x','a') is None
    s.commit_hook=lambda where:time.sleep(.06) if where=='after_final_check' else None
    with s.transaction():s.put('x','b',1);s.guard_deadline(clock.now()+.04,clock,.01)
    t=observations[-1];assert t['committed'] and not t['assumed_delay_bound_held'] and not t['durable_before_deadline_observed']
    assert t['sql_commit_return_monotonic']>=t['sql_commit_start_monotonic']>t['final_check_monotonic']
    write_json(run.out/'deadline-counterexamples.json',observations);s.close()
    results.append(dict(test='final_deadline_recheck_and_real_commit_observation',passed=True,deliberate_assumption_violation_retained=True))
    return results

def modern_packet_checks(run):
    """White-box negative packets plus an actual SQLite COMMIT exception.

    Local MemoryBIO is intentionally used only for controllable mutation.
    Network/process behavior is independently tested below, never inferred
    from this fixture's timings. No business driver obtains these secrets.
    """
    import sqlite3
    from .local_client import Client
    from gredac.crypto import ident,domain_for,digest
    from gredac.roles import ACTCallerContact,ACTServiceRole,verified,PROTOCOL
    from gredac.offline import Wallet
    lab=Client(run,'modern-packets');lab.context('c',['s']);lab.source('s',8,['c'])
    root=lab.right('O-c','O','c');sr=lab.right('R-c','R','c',side='service');srv=lab.right('srv','S','c',sr,side='service')
    held=lab.seed(root,{'s':list(range(8))});rid=lab.right('A','A','c',root,actions=['query'])
    h=lab.delegate(held,rid,{'s':[0,1,2,3]},actions=['query']);lab.sync(h,srv)
    caller,service=lab.rights[rid],lab.rights[srv];expires=lab.clock.now()+60
    role=ACTServiceRole(lab.actor('S'),service,lab.chains[srv],lab.identities,lab.endpoint_public)
    lab.roles[srv]=role;lab.transport.add(role)
    init=ACTCallerContact(lab.actor('A'),caller,service,expires,h.chain)
    act=role.respond(init.begin(),caller['public_key']);init.finish(act)
    lane=dict(id=ident(),caller=caller,service=service,act=act,task_info=h.task_info,sources=['s'])
    link=lab.pki.link('A','G');receipt=lab.endpoint.session_act(lane,link)
    session=verified(receipt,lab.endpoint_public,protocol=PROTOCOL,endpoint='G',kind='session-receipt',lane_digest=digest(lane))['session']
    w=Wallet(lane,h,session,None,link)
    packet=w.packet('query','valid',{'s':0},payload={'value':1})
    assert 'channel' not in packet and 'key' not in session
    bad=copy.deepcopy(packet);bad['payload']['value']=2
    denied(lambda:lab.endpoint.charge(bad,'query',link),'FULL_PAYLOAD_BINDING')
    bad=copy.deepcopy(packet);bad['proofs']['s']='00'*32
    denied(lambda:lab.endpoint.charge(bad,'query',link),'BAD_CAP_TAG')
    bad=copy.deepcopy(packet);bad['act']['body']['receiver']='Other'
    denied(lambda:lab.endpoint.charge(bad,'query',link),'REQUEST_ACT_BINDING')
    denied(lambda:w.packet('summary','widen',{'s':1}),None)
    accepted=lab.endpoint.charge(packet,'query',link);assert not accepted['replay']
    # Even after admission a changed proof is NOT an exact retry, although
    # the canonical body/request ID is identical.
    bad=copy.deepcopy(packet);bad['proofs']['s']='00'*32
    denied(lambda:lab.endpoint.charge(bad,'query',link),'REQUEST_ID_CONFLICT')
    assert lab.endpoint.charge(packet,'query',link)['replay']
    calls=[];role.handler=lambda message:calls.append(message['key']) or {'executed':True}
    class FailCompletion:
        def __init__(self,db):self.db=db;self.fail=False
        def __getattr__(self,k):return getattr(self.db,k)
        def execute(self,sql,*args):
            if sql=='COMMIT' and self.fail:
                self.fail=False;raise sqlite3.OperationalError('injected completion COMMIT failure')
            return self.db.execute(sql,*args)
    proxy=FailCompletion(lab.g.db);lab.g.db=proxy
    lab.g.commit_hook=lambda point:setattr(proxy,'fail',True) if point=='before_delivery_completion' else None
    uncertain=w.packet('query','completion-failed',{'s':1},payload={'value':2})
    try:lab.endpoint.charge(uncertain,'query',link)
    except sqlite3.OperationalError:pass
    else:raise AssertionError('completion COMMIT failure was not injected')
    assert len(calls)==1
    lab.g.commit_hook=None;lab.g.close();lab.g.open();lab.endpoint.resume_delivery()
    response=lab.endpoint.charge(uncertain,'query',link)
    assert response['replay'] and response['delivery_state']=='attempted' and response['service_receipt'] is None and len(calls)==1
    result=lab.close()
    from .endpoint_audit import audit
    independent=audit(lab.path/'guard.sqlite')
    return dict(test='act_only_packet_tamper_exact_retry_and_completion_commit_failure',passed=True,
        audit=result,independent=independent,business_executions_after_commit_failure=len(calls),negative_packet_cases=5)

def network_checks(run):
    from .network_client import Client
    from gredac.crypto import domain_for,Denied
    lab=Client(run,'network-lifecycle',endpoint_id='G-alt');lab.context('c',['s'],tasks=['plan','check']);lab.source('s',16,['c'])
    root=lab.right('O-c','O','c');sr=lab.right('R-c','R','c',side='service');srv=lab.right('srv','S','c',sr,side='service')
    scope=domain_for(['query'],range(16))+domain_for(['summary'],range(8,16))
    held=lab.seed(root,{'s':list(range(16))},domains={'s':scope});lab.freeze_setup()
    a=lab.right('A','A','c',root);ha=lab.delegate(held,a,{'s':list(range(16))},domains={'s':scope})
    b=lab.right('Bchild','Bchild','c',a,actions=['query']);hb=lab.delegate(ha,b,{'s':list(range(8))},actions=['query'])
    c=lab.right('C','C','c',b,actions=['query']);hc=lab.delegate(hb,c,{'s':list(range(4))},actions=['query'])
    w=lab.reserve(hc,srv,{'s':list(range(4))})
    lab.mesh.call(lab.endpoint_id,'arm_fault',point='response_loss')
    try:lab.charge(w,{'s':0},'lost',payload={'task':'plan'})
    except (OSError,ConnectionError):pass
    else:raise AssertionError('injected TCP response loss not observed')
    lab.call('Bchild','revoke',{'id':c});returned,slots=lab.recovery(w,b,actor='Bchild');assert slots=={'s':[1,2,3]}
    lab.call('R','revoke',{'id':srv});srv2=lab.right('srv2','S2','c',sr,side='service')
    retried=lab.retry(w,'lost');assert retried['replay'] and retried['participants']==['C','S']
    new=lab.right('C2','C2','c',b,actions=['query']);hn=lab.delegate(returned,new,slots,actions=['query']);wn=lab.reserve(hn,srv2,slots)
    lab.consume_next(wn,'new',payload={'task':'plan'})
    wb=lab.reserve(hb,srv2,{'s':[4,5]})
    lab.charge(wb,{'s':4},'multi-plan',payload={'task':'plan'});lab.charge(wb,{'s':5},'multi-check',payload={'task':'check'})
    wa=lab.reserve(ha,srv2,{'s':[8]});lab.charge(wa,{'s':8},'joint-scope','summary')
    denied(lambda:lab.probe_old(w,'stale',{'s':2}),'KNOWN_REVOKED')
    # A fresh connection with the same caller legitimately reuses registered
    # record references; the endpoint validates references, not blind IDs.
    lab.reserve(hn,srv2,{'s':[2,3]})
    audit=lab.close();assert audit['new_requests']==5 and audit['spent_by_source']=={'s':5}
    path=lab.path/'network';authority_events=[json.loads(x) for x in (path/'actors/Authority/events.jsonl').read_text().splitlines()]
    rpc=[x for x in authority_events if x['kind']=='rpc-received'];freeze=next(i for i,x in enumerate(rpc) if x['method']=='freeze')
    assert all(x['method'] in ('audit','stats','stop') for x in rpc[freeze+1:]),rpc[freeze+1:]
    method_rows=[]
    for p in path.rglob('rpc-sent.jsonl'):method_rows.extend(json.loads(x) for x in p.read_text().splitlines())
    assert not any(x['method'] in ('contact_install','service_install') for x in method_rows)
    evidence=[json.loads(x) for p in path.rglob('events.jsonl') for x in p.read_text().splitlines()]
    packets=[x['packet'] for x in evidence if x['kind']=='request_receipt']
    assert packets and all('channel' not in p and p['act']['body']['profile']=='tls-act-v1' for p in packets)
    assert all('ephemeral' not in x['act']['body'] and 'confirmation' not in x for x in evidence if x['kind']=='contact')
    from .endpoint_audit import audit as verify_database
    independent=verify_database(path/'actors'/lab.endpoint_id/'guard.sqlite',path/'actors/Authority/authority.sqlite')
    return dict(test='tcp_recursive_bilateral_multitask_retry_return_replacements',passed=True,audit=audit,independent=independent,authority_runtime_messages=0)

def delivery_crash(run):
    from .network_client import Client
    lab=Client(run,'delivery-crash',endpoint_id='G-fault');lab.context('c',['s']);lab.source('s',8,['c'])
    root=lab.right('O-c','O','c');sr=lab.right('R-c','R','c',side='service');srv=lab.right('srv','S','c',sr,side='service')
    held=lab.seed(root,{'s':list(range(8))});rid=lab.right('A','A','c',root);h=lab.delegate(held,rid,{'s':list(range(8))})
    w=lab.reserve(h,srv,{'s':list(range(8))});lab.freeze_setup()
    lab.mesh.call(lab.endpoint_id,'arm_fault',point='after_service_response')
    try:lab.charge(w,{'s':0},'uncertain-business')
    except (OSError,ConnectionError):pass
    else:raise AssertionError('process exit not observed')
    p=lab.mesh.processes[lab.endpoint_id];p.join(3);assert p.exitcode==73
    assert lab.mesh.call('S','stats')['business_calls']==1
    lab.restart_endpoint();answer=lab.retry(w,'uncertain-business')
    assert answer['replay'] and answer['delivery_state']=='attempted' and answer['service_receipt'] is None
    assert lab.mesh.call('S','stats')['business_calls']==1,'service executed twice after completion loss'
    lab.call('O','revoke',{'id':rid});restored,slots=lab.recovery(w,root,actor='O');assert 0 not in slots['s']
    replacement=lab.right('A2','A2','c',root);h2=lab.delegate(restored,replacement,slots);w2=lab.reserve(h2,srv,slots)
    lab.consume_next(w2,'fresh-after-recovery');audit=lab.close()
    assert audit['new_requests']==2 and audit['delivery_states']=={'attempted':1,'delivered':1}
    from .endpoint_audit import audit as verify_database
    path=lab.path/'network/actors'
    independent=verify_database(path/lab.endpoint_id/'guard.sqlite',path/'Authority/authority.sqlite')
    return dict(test='service_executed_completion_lost_no_reexecution',passed=True,audit=audit,independent=independent,
        business_outcome='original result intentionally unresolved; no external exactly-once claim')

def main():
    p=parser(__doc__);p.set_defaults(repeats=1,slot_bits=10);a=p.parse_args();run=Run(a,'alignment_regression');results=[]
    try:
        results.extend(local_checks(run));write_json(run.out/'partial_results.json',results)
        results.append(modern_packet_checks(run));write_json(run.out/'partial_results.json',results)
        results.append(network_checks(run));write_json(run.out/'partial_results.json',results)
        results.append(delivery_crash(run));run.finish(results)
    except BaseException:
        import traceback
        run.manifest.update(status='FAIL',traceback=traceback.format_exc());write_json(run.out/'manifest.json',run.manifest);raise
    finally:
        from .network_client import Mesh
        for mesh in Mesh.live:mesh.close()

if __name__=='__main__':main()
