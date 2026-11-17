"""Shared Authority deployment and relevant public configuration, no LLM.

Two independent cooperations reuse one Authority listener but not issuance
keys/stores/freeze state. Tests use public RPCs while live. Only AFTER shutdown,
read-only database inspection verifies persistence/key separation. No runtime
Agent allocation decision reads another participant's database.
"""
import copy,json,os,sqlite3,traceback
from .support import parser,Run,write_json


def checks(run):
    from .network_client import Mesh
    from .network_federation import Cooperation
    from gredac.crypto import Denied,verify_signature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    mesh=Mesh(run.out/'network',optimize_initial_config=True,shared_authority='AuthorityShared')
    sent=[];proofs=[];original=mesh.call
    def capture(destination,method,**args):
        if method=='configure':sent.append(dict(destination=destination,pid=mesh.processes[destination].pid,args=copy.deepcopy(args)))
        answer=original(destination,method,**args)
        if method=='initial_control' and args['operation']=='right':proofs.append((args['_scope'],copy.deepcopy(answer)))
        return answer
    mesh.call=capture
    def denied(fn,code):
        try:fn()
        except Denied as e:assert e.code==code,(e.code,code)
        else:raise AssertionError('negative request accepted')
    try:
        x=Cooperation(run,'first',16,'G1',mesh,service='S1',connect=False)
        initial=x.lab.mesh.call('AuthorityShared','audit');assert initial['frozen']
        before=len(sent)
        # This must work after G1 has frozen; G1 must not receive another
        # configure, nor freeze the new G2 namespace in the same process.
        y=Cooperation(run,'second',16,'G2',mesh,service='S2',connect=False)
        assert x.lab.authority_id==y.lab.authority_id=='AuthorityShared'
        assert 'R' not in mesh.processes and len(mesh.processes)==11
        assert not any(s['destination']=='AuthorityShared' and s['args'].get('_scope')=='G1' for s in sent[before:])
        assert x.lab.mesh.call('AuthorityShared','audit')['authority_calls']==initial['authority_calls']
        px=x.lab.mesh.config['authority_public'];py=y.lab.mesh.config['authority_public'];assert px!=py
        envelope=next(p for s,p in proofs if s=='G1')
        verify_signature(px,envelope['body'],envelope['signature'])
        denied(lambda:verify_signature(py,envelope['body'],envelope['signature']),'BAD_SIGNATURE')
        denied(lambda:mesh.call('AuthorityShared','configure',_scope='G1',routes={},registrations={}),
            'AUTHORITY_CONFIGURATION_FROZEN')
        denied(lambda:x.lab.mesh.call('UO','initial_control',operation='source',args={}),
            'INITIAL_AUTHORITY_FROZEN')
        # Reconstruct only PUBLIC delivered maps. Every scope gets exactly
        # its own members + Driver; outer TLS pins are the identity's union.
        delivered={};full=[]
        for row in sent:
            a=row['args'];key=(row['destination'],row['pid'],a.get('_scope'))
            if key not in delivered:full.append(key)
            state=delivered.setdefault(key,{'routes':{},'registrations':{}})
            for group in state:state[group].update(a[group])
        byscope={s.scope:s for s in mesh.scopes}
        for (name,pid,scope),state in delivered.items():
            if scope:
                # Authority freezes before the caller is installed only if
                # the original flow does so; this fixture freezes last.
                allowed=byscope[scope].members|{'Driver'}
            else:
                allowed={'Driver',name}
                for s in mesh.scopes:
                    if name in s.members:allowed.update(s.members)
            assert set(state['routes'])==allowed,(name,scope,set(state['routes']),allowed)
            assert set(state['registrations'])==allowed
        assert 'G2' not in delivered[('S1',mesh.processes['S1'].pid,None)]['routes']
        n=len(sent);mesh.configure();assert len(sent)==n,'no-change configure sent'
        assert mesh.config_distribution['delta'] and mesh.config_distribution['skipped']
        write_json(run.out/'public-configure.json',sent)
        mesh.finish_initial_configuration()
        x.connect();y.connect();x.request(0,'x');y.request(0,'y')
        # Invalidated child cannot make a fresh request; legitimate parent
        # return/redelegation still works after changing deployment only.
        x.lab.call('O','revoke',{'id':x.holding.right})
        try:x.request(1,'revoked')
        except Denied:pass
        else:raise AssertionError('revoked child admitted')
        h,slots=x.lab.recovery(x.wallet,x.root,actor='O');assert sorted(slots['budget'])==list(range(1,16))
        rid=x.lab.right('replacement','Replacement','first',x.root)
        ch=x.lab.delegate(h,rid,slots);w=x.lab.reserve(ch,x.service,slots)
        x.lab.charge(w,{'budget':1},'recovered');y.request(1,'unaffected')
        audits=[x.close(),y.close()];assert all(a['audit']=='PASS' and a['new_requests']==2 and a['initial_authority_frozen'] for a in audits)
        assert all(r['pid']!=os.getpid() for n,r in mesh.routes.items() if n!='Driver')
        assert len({p.pid for p in mesh.processes.values()})==len(mesh.processes)
        keys=[px,py]
    finally:mesh.finish_initial_configuration();mesh.close()
    # Explicit post-run white-box persistence test, never a live data path.
    persistent=[]
    for scope,context,key in zip(['G1','G2'],['first','second'],keys):
        path=mesh.path/'actors/AuthorityShared/cooperations'/scope/'authority.sqlite'
        db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
        try:
            assert db.execute('PRAGMA journal_mode').fetchone()[0]=='wal'
            def rows(kind):return {k:json.loads(v) for k,v in db.execute('SELECT key,value FROM records WHERE kind=?',(kind,))}
            assert set(rows('contexts'))=={context}
            secret=rows('control_keys')['Authority-control']
            public=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret)).public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
            assert public==key
            persistent.append(dict(scope=scope,path=str(path),context=context,authority_public=public,journal_mode='wal'))
        finally:db.close()
    return [dict(test='shared_authority_independent_signing_freeze_and_persistence',passed=True,stores=persistent),
        dict(test='relevant_full_delta_no_change_and_outer_tls_pins',passed=True,first_recipient_spaces=len(full),distribution=mesh.config_distribution),
        dict(test='real_tcp_independent_agents_two_cooperations_return_replacement',passed=True,audits=audits)]


def main():
    p=parser(__doc__);p.set_defaults(repeats=1,slot_bits=8);a=p.parse_args();run=Run(a,'rq4_shared_setup_regression')
    try:run.finish(checks(run))
    except BaseException:
        run.manifest.update(status='FAIL',traceback=traceback.format_exc());write_json(run.out/'manifest.json',run.manifest);raise


if __name__=='__main__':main()
