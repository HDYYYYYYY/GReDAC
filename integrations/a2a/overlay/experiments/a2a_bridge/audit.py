"""Read-only reconciliation independent of adapter admission and SDK code."""
from contextlib import closing
import json,sqlite3,hashlib
from pathlib import Path

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()

def audit(actors,endpoint='G'):
    actors=Path(actors)
    with closing(sqlite3.connect('file:'+str(actors/endpoint/'guard.sqlite')+'?mode=ro',uri=True)) as db:
        rows=[(kind,key,json.loads(value)) for kind,key,value in db.execute('SELECT kind,key,value FROM records')]
    records={}
    for kind,key,value in rows:records.setdefault(kind,{})[key]=value
    requests=records.get('requests',{});forwarding=records.get('forwarding',{});effects=records.get('effects',{})
    mapped=records.get('a2a_messages',{});keys=[r['admission_key'] for r in mapped.values()]
    assert len(keys)==len(set(keys))==len(requests)
    for row in mapped.values():
        key=row['admission_key'];assert key in requests and row['payload_digest']==digest(forwarding[key]['payload'])
    inboxes=0;started=0;finished=0;completed=0
    for path in actors.glob('*/a2a/bridge.sqlite'):
        with closing(sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True)) as db:
            inbox={k:(fp,state,json.loads(body),json.loads(response) if response else None)
                   for k,fp,state,body,response in db.execute('SELECT * FROM inbox')}
            business=list(db.execute('SELECT key,request_digest,finished,result_digest FROM business'))
        for key,(fp,state,body,result) in inbox.items():
            identity,admission=json.loads(key)
            assert identity==endpoint and admission in forwarding
            assert body['key']==admission and body['service']==path.parent.parent.name
            assert fp==digest(body) and body['payload']==forwarding[admission]['payload']
            assert state in ('starting','completed')
            if state=='completed':
                assert result is not None;completed+=1
                if admission in effects:assert result==effects[admission]['receipt']['body']['result']
        for key,request_digest,done,result_digest in business:
            assert key in inbox and request_digest==digest(inbox[key][2]['payload']['request'])
            if done is not None:assert result_digest;finished+=1
        inboxes+=len(inbox);started+=len(business)
    assert started<=inboxes<=len(requests)
    return dict(passed=True,message_mappings=len(mapped),admissions=len(requests),service_inboxes=inboxes,
                sdk_business_started=started,sdk_business_finished=finished,service_completed=completed)
