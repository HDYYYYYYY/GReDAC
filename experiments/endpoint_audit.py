"""Read-only durable evidence audit, independent of workload/client verdicts.

Replay B's committed event order: initial issuance, whole-scope transfers,
revocations, exact admissions and returns. Reverify stored signatures, complete
message tags and channel binding using ONLY B's initial restricted packages.
Never reads issuer masters to reconstruct a verifier. Each database is audited
in a fresh process with its recorded address width. Audits are not benchmarks.
"""
import argparse,json,os,sqlite3,subprocess,sys
from pathlib import Path


class ReadStore:
    def __init__(self,path):self.db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    def get(self,kind,key,default=None):
        r=self.db.execute('SELECT value FROM records WHERE kind=? AND key=?',(kind,str(key))).fetchone()
        return json.loads(r[0]) if r else default
    def all(self,kind):return {k:json.loads(v) for k,v in self.db.execute('SELECT key,value FROM records WHERE kind=?',(kind,))}


def audit(path,authority_path=None):
    from gredac.crypto import canonical,decode,digest,verify_signature,by_slot,point,channel_mac
    from gredac.endpoint import RestrictedForest
    from gredac.storage import position_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    b=ReadStore(path);a=ReadStore(authority_path or path.with_name('authority.sqlite'))
    endpoints={c['body']['endpoint'] for c in b.all('initial_certificates').values()}
    assert len(endpoints)==1;endpoint=next(iter(endpoints))
    authority=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(a.get('control_keys','Authority-control'))).public_key().public_bytes_raw().hex()
    control=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(b.get('control_keys','Endpoint-control-'+endpoint))).public_key().public_bytes_raw().hex()
    assert not b.all('source_masters')
    rights=b.all('rights');caps=b.all('caps');sources=b.all('sources');contexts=b.all('contexts')
    certs=b.all('initial_certificates');auth=b.all('authorizations');transfers=b.all('transfers')
    for signed in certs.values():
        body=signed['body'];verify_signature(authority,body,signed['signature'])
        approval=body['approvals']
        for who,sig in approval['approvals'].items():verify_signature(body['registrations'][who]['public_key'],approval['body'],sig)
        for g,h in body['key_digests'].items():assert digest(b.get('initial_keys',g))==h
    for signed in auth.values():
        body=signed['body'];verify_signature(rights[body['parent']]['public_key'],body,signed['signature'])
        if 'child_proof' in body:verify_signature(body['right']['public_key'],body['right'],body['child_proof'])
        else:
            assert body['identity_binding']=='registered-tls-key'
            assert b.get('registrations',body['right']['owner'])['public_key']==body['right']['public_key']
    for row in transfers.values():verify_signature(rights[row['body']['parent']]['public_key'],row['body'],row['signature'])
    for row in b.all('operations').values():
        verify_signature(b.get('registrations',row['body']['actor'])['public_key'],row['body'],row['signature'])
        verify_signature(control,row['result']['body'],row['result']['signature'])
    expected={};revoked=set();spent=set();seen_requests=set();keys={};forest=RestrictedForest(b)
    for kind,raw in b.db.execute('SELECT kind,value FROM events ORDER BY seq'):
        e=json.loads(raw)
        if kind=='initial':
            body=certs[e['id']]['body']
            for cap in body['caps']:
                r=rights[cap['holder_right']];spec=sources[cap['source']]
                for i,actions in by_slot(cap['domain']).items():
                    k=position_key(cap['source'],i);assert k not in expected
                    expected[k]=dict(state='unused',version=1,holder_right=r['id'],context=cap['context'],
                        current_cap=dict(anchor=cap['anchor'],gid=cap['gid'],holder_right=r['id']),ownership=body['id'],
                        hard_actions=sorted(actions),hard_contexts=[cap['context']],deadline=min(spec['deadline'],r['deadline']))
        elif kind=='transfer':
            body=transfers[e['id']]['body'];child=rights[body['child']]
            assert not set(child['deps'])&revoked
            scope=set()
            for cap in body['caps']:
                parent=caps[cap['key_parent']['id']]
                assert set(cap['domain'])<=set(parent['domain']) and cap['anchor']==parent['anchor']
                for i,actions in by_slot(cap['domain']).items():
                    k=position_key(cap['source'],i);assert k not in scope;scope.add(k);row=expected[k]
                    assert row['state']=='unused' and row['holder_right']==body['parent']
                    assert row['current_cap']['gid']==parent['gid'] and row['ownership']==body['previous'][k]
                    assert set(actions)<=set(row['hard_actions']) and e['time']<row['deadline']
                    row.update(holder_right=child['id'],current_cap=dict(anchor=cap['anchor'],gid=cap['gid'],holder_right=child['id']),
                        ownership=body['id'],version=row['version']+1,hard_actions=sorted(actions),deadline=min(row['deadline'],child['deadline']))
            assert scope==set(body['previous'])
        elif kind=='revoke':revoked.add(e['dep'])
        elif kind=='charge':
            assert e['key'] not in seen_requests and not set(e['deps'])&revoked;seen_requests.add(e['key'])
            rec=b.get('requests',e['key']);body=bytes.fromhex(rec['body']);fields,vector=decode(body)
            session=b.get('sessions',fields['session'].decode());act=session['act']
            verify_signature(rights[session['binding']['service_right']]['public_key'],act['body'],act['signature'])
            assert all(fields[k]==v.encode() for k,v in session['binding'].items())
            assert rec['authenticated_caller']==session['binding']['caller_identity']
            if session.get('profile')=='tls-act-v1':assert rec['channel'] is None and rec['act']==session['act']
            else:assert rec['channel']==channel_mac(bytes.fromhex(session['key']),body)
            assert [s for s,*_ in vector]==contexts[e['context']]['req'][e['operation']]
            for j,(s,i,anchor,gid,ell) in enumerate(vector):
                k=position_key(s,i);row=expected[k]
                assert k not in spent and row['state']=='unused'
                assert row['current_cap']==e['cap_bindings'][j] and row['current_cap']['gid']==gid
                assert anchor==row['current_cap']['anchor'] and row['holder_right']==fields['caller_right'].decode()
                assert row['context']==fields['context'].decode()
                assert row['ownership']==ell==e['ownerships'][j] and row['version']==e['versions'][j]
                # This is decision-time eligibility only. Durable deadline
                # claims require the separate transaction COMMIT observation.
                assert e['operation'] in row['hard_actions'] and e.get('decision_time',e.get('commit_time'))<row['deadline']
                if gid not in keys:keys[gid]=forest.rebuild(gid)
                assert rec['proofs'][s]==keys[gid].tag(point(e['operation'],i),body)
                row['state']='spent';spent.add(k)
        elif kind=='return':
            for returned in e['rows']:
                k=position_key(returned['source'],returned['slot']);row=expected[k]
                assert row['state']=='unused' and set(rights[row['holder_right']]['deps'])&revoked
                assert returned['hard_actions']==row['hard_actions'] and returned['hard_contexts']==row['hard_contexts'] and returned['deadline']==row['deadline']
                cap=caps[row['current_cap']['gid']]
                while cap['holder_right']!=returned['holder_right']:cap=caps[cap['key_parent']['id']]
                assert cap['gid']==returned['current_cap']['gid'] and returned['version']==row['version']+1
                row.update({k:returned[k] for k in row})
            for state,units in [('escrow',e['escrow']),('retired',e['retired'])]:
                for k in units:assert expected[k]['state']=='unused';expected[k]['state']=state
    actual=b.all('positions')
    for k,row in expected.items():assert all(actual[k][f]==v for f,v in row.items()),(k,row,actual[k])
    assert {k for k,v in actual.items() if v['state']=='spent'}==spent
    forwarding=b.all('forwarding');effects=b.all('effects')
    assert set(b.all('requests'))==seen_requests==set(forwarding)
    assert all(r['state'] in ('pending','attempted','delivered') for r in forwarding.values())
    assert set(effects)=={k for k,r in forwarding.items() if r['state']=='delivered'}
    # Service execution evidence is distinct from B's forwarding state. Verify
    # that the actual receiver signed the exact B-admitted payload and identity.
    delivered=0
    for key,effect in b.all('effects').items():
        if 'delivery' not in effect:continue  # historical v3.1 evidence remains auditable
        envelope,receipt=effect['delivery'],effect['receipt'];msg=envelope['body'];ack=receipt['body']
        assert msg['kind']=='service-delivery' and ack['kind']=='service-receipt'
        assert msg['protocol']==ack['protocol']=='fixed-endpoint-v3.1' and msg['endpoint']==ack['endpoint']==endpoint
        verify_signature(control,msg,envelope['signature'])
        verify_signature(b.get('registrations',msg['service'])['public_key'],ack,receipt['signature'])
        decision=b.get('requests',key)['decision']
        assert msg['key']==ack['key']==key and msg['context']==decision['context']==ack['context']
        assert msg['service']==decision['participants'][1]==ack['service']
        fields,_=decode(bytes.fromhex(b.get('requests',key)['body']))
        assert msg['service_right']==fields['service_right'].decode()==ack['service_right']
        assert canonical(msg['payload'])==fields['full_payload'] and msg['operation']==decision['operation']
        assert ack['delivery_digest']==digest(envelope) and ack['payload_digest']==digest(msg['payload'])
        delivered+=1
    if b.all('service_directory'):assert delivered==sum(r['state']=='delivered' for r in forwarding.values())
    for source,spec in sources.items():assert sum(r['source']==source for r in actual.values())==spec['size']
    result=dict(database=str(path),status='PASS',positions=len(actual),allocated=len(expected),requests=len(seen_requests),
        initial_certificates=len(certs),authorizations=len(auth),transfers=len(transfers),revocations=len(revoked),
        verified_tags=sum(len(r['decision']['sources']) for r in b.all('requests').values()),verified_service_receipts=delivered,
        unresolved_deliveries=sum(r['state']!='delivered' for r in forwarding.values()))
    a.db.close();b.db.close();return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('path',type=Path);p.add_argument('--slot-bits',type=int)
    args=p.parse_args()
    if args.path.is_file():
        assert args.slot_bits;os.environ['GREDAC_SLOT_BITS']=str(args.slot_bits)
        print(json.dumps(audit(args.path)));return
    reports=[]
    for path in sorted(args.path.rglob('guard.sqlite')):
        manifest=json.loads((path.parent.parent/'manifest.json').read_text());bits=manifest['config']['slot_bits']
        process=subprocess.run([sys.executable,'-m',__spec__.name,str(path),'--slot-bits',str(bits)],capture_output=True,text=True)
        if process.returncode:raise RuntimeError(str(path)+'\n'+process.stderr)
        reports.append(json.loads(process.stdout))
    assert reports
    result=dict(status='PASS',databases=len(reports),requests=sum(r['requests'] for r in reports),reports=reports)
    (args.path/'V31_AUDIT.json').write_text(json.dumps(result,indent=2));print(json.dumps({k:v for k,v in result.items() if k!='reports'}))


if __name__=='__main__':main()
