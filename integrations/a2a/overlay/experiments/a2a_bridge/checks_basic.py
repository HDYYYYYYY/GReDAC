"""B1 and B2: schema, authenticated network, atomic rejection and private gate."""
from contextlib import closing
import copy,json,sqlite3,ssl,socket
from importlib.metadata import version
import httpx
from gredac.crypto import canonical,digest,Denied
from gredac.roles import check_envelope
from gredac.endpoint import PROTOCOL
from gredac.rpc import Client as RPC
from .codec import *
from .testing import Fixture,response,denied

def b1(run):
    rows=[]
    with Fixture(run,'B1') as f:
        l=f.lab;info=l.mesh.call('S','a2a_info')
        with httpx.Client(transport=httpx.HTTPTransport(uds=info['uds']),trust_env=False) as h:
            card=h.get('http://a2a.local/.well-known/agent-card.json').json()
        assert card==l.cards[f.srv] and version('a2a-sdk')=='1.3.0'
        rows.append(dict(id='P01',passed=True,sdk=version('a2a-sdk'),pid=info['pid'],uds=info['uds']))
        r=f.send(0,args={'value':'hello'});assert response(r)=={'value':'hello'}
        assert f.snapshot()==dict(requests=1,spent={'s1':1},business={'S':1})
        rows.append(dict(id='P02',passed=True,oracle=f.snapshot()))
        r=f.send(1,action='research.aggregate',args={'rows':[dict(id='a',value=7,reference='ref-a')]})
        assert response(r)['total']==7
        assert f.snapshot()['spent']=={'s1':2,'s2':1}
        rows.append(dict(id='P03',passed=True,oracle=f.snapshot()))
        rs=[f.send(i,args={'n':i}) for i in (2,3,4)]
        assert len({r['lane'] for r in rs})==1 and len({r['key'] for r in rs})==3
        rows.append(dict(id='P04',passed=True,requests=3))
        data={'unicode':'中文🙂','empty':{},'list':[],'bool':True,'null':None,
              'integers':[-(2**53-1),0,2**53-1], 'order':[3,1,2]}
        assert response(f.send(5,args=data))==data
        p=f.payload('normal','echo.read',data)
        reordered=json.loads(json.dumps(p,sort_keys=True,ensure_ascii=False))
        assert canonical(validate_payload(reordered))==canonical(p)
        invalid=['{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}','{"x":9007199254740992}']
        bad=0
        for raw in invalid:denied(lambda raw=raw:loads(raw));bad+=1
        deep={}
        for _ in range(17):deep={'x':deep}
        denied(lambda:clean(deep));bad+=1
        denied(lambda:loads(' '*65537));bad+=1
        for change in [lambda v:v.update(tenant='x'),lambda v:v['message'].update(kind='message'),
                       lambda v:v['message'].update(MessageId='x'),lambda v:v['message']['parts'][0].update(text='x')]:
            req=copy.deepcopy(p['request']);change(req);denied(lambda:normalize_send_request(req));bad+=1
        rows.append(dict(id='P06',passed=True,negative_variants=bad,positive=data))
        req=copy.deepcopy(p['request']);req['configuration']={'returnImmediately':False}
        assert normalize_send_request(req)==p['request']
        events=[json.loads(x) for x in (l.path/'network/actors/S/a2a/bridge-events.jsonl').read_text().splitlines()]
        ids=[e['rpc_id'] for e in events if e['kind']=='gate_accepted']
        assert len(ids)==len(set(ids)) and all(i!=p['request']['message']['messageId'] for i in ids)
        rows.append(dict(id='P07',passed=True,rpc_ids=len(ids)))
        with closing(sqlite3.connect(l.path/'network/actors/S/a2a/bridge.sqlite')) as db:
            assoc=db.execute('SELECT sdk_context,sdk_task FROM business').fetchall()
        assert assoc and all(c and t for c,t in assoc) and 'contextId' not in p['request']['message']
        rows.append(dict(id='P08',passed=True,generated_associations=len(assoc)))
        r=f.send(6,args={'fail':True})
        assert r['service_receipt']['body']['result']['business_status']=='ERROR'
        rows.append(dict(id='P09',passed=True,oracle=f.snapshot()))
        for i,size in enumerate([256,4096,16384],7):
            assert response(f.send(i,args={'padding':'x'*size}))=={'padding':'x'*size}
        rows.append(dict(id='P10',passed=True,bytes=[256,4096,16384]))
        p=f.payload('stable','echo.read',{'retry':True});r=f.send(10,'stable',payload=p);packet=f.packet('stable')
        before=f.snapshot()
        for i in range(10):
            if i==3:l.update_card(f.srv,'2')
            if i==6:l.call('O','revoke',{'id':f.a})
            retry=f.raw(packet)
            assert retry['key']==r['key'] and retry['replay'] and retry['service_receipt']==r['service_receipt']
        assert f.snapshot()==before
        rows.append(dict(id='P05',passed=True,retries=10,after_card_update=True,after_revoke=True,oracle=before))
    return rows

def b2(run):
    rows=[]
    with Fixture(run,'B2',size=32) as f:
        l=f.lab;f.send(0);original=f.packet('r0');info=l.mesh.call('S','a2a_info')
        # No client certificate, then a valid caller certificate with the wrong peer pin.
        before=f.snapshot();ctx=ssl.create_default_context(cafile=str(l.mesh.path/'pki/ca.pem'));ctx.check_hostname=False
        rejected=False
        try:
            with socket.create_connection(('127.0.0.1',l.mesh.routes['G']['port']),timeout=3) as sock:
                with ctx.wrap_socket(sock,server_hostname='G') as secure:
                    secure.sendall(b'\x00\x00\x00\x02{}')
                    rejected=not bool(secure.recv(16))
        except (ssl.SSLError,OSError):rejected=True
        assert rejected and f.snapshot()==before
        badroutes=copy.deepcopy(l.mesh.routes);badroutes['G']['public']='00'*32
        c=RPC(l.mesh.path/'pki','A',badroutes,l.path/'wrong-pin.jsonl')
        try:
            try:c.call('G','endpoint_charge',packet=original,operation='query')
            except (Denied,OSError,ssl.SSLError):pass
            else:raise AssertionError('bad pin accepted')
        finally:c.close()
        assert f.snapshot()==before
        rows.append(dict(id='N01',passed=True,variants=2))
        l.ensure('Outsider')
        rows.append(dict(id='N02',passed=True,evidence=f.reject(lambda:f.raw(original,caller='Outsider'))))
        changes=['caller','receiver','caller_right','service_right','context','endpoint']
        evidence=[]
        for key in changes:
            p=copy.deepcopy(original);p['act']['body'][key]='changed'
            evidence.append(f.reject(lambda p=p:f.raw(p)))
        rows.append(dict(id='N03',passed=True,variants=len(evidence),evidence=evidence))
        evidence=[]
        for key in ['arguments','application_case']:
            p=copy.deepcopy(original);p['payload']['request']['message']['parts'][0]['data'][key]={'x':1} if key=='arguments' else 'changed'
            evidence.append(f.reject(lambda p=p:f.raw(p)))
        rows.append(dict(id='N04',passed=True,variants=2,evidence=evidence))
        evidence=[]
        for change in [lambda p:p['payload']['request']['message'].update(messageId='changed'),
            lambda p:p['payload'].update(operation='GetTask'),
            lambda p:p['payload'].update(card_digest='0'*64),
            lambda p:p['payload'].update(action_map_version='changed')]:
            p=copy.deepcopy(original);change(p);evidence.append(f.reject(lambda p=p:f.raw(p)))
        old=original['payload']
        evidence.append(f.reject(lambda:f.send(2,'new-outer',payload=old),'A2A_MESSAGE_ID_CONFLICT'))
        other=l.reserve(f.h,f.srv,f.slots)
        evidence.append(f.reject(lambda:f.send(2,'new-session',w=other,payload=old),'A2A_MESSAGE_ID_CONFLICT'))
        rows.append(dict(id='N05',passed=True,variants=len(evidence),evidence=evidence))
        p=f.payload('delete','fixture.delete',{'id':'isolated'})
        rows.append(dict(id='N06',passed=True,evidence=f.reject(lambda:f.send(2,'delete',payload=p,operation='query'),'A2A_OPERATION_BINDING')))
        reg=l.ensure('BadChild');parent=l.rights[f.a]
        body=dict(id='bad-child',owner='BadChild',context='c',side='caller',parent=f.a,
            actions=['query'],public_key=reg['public_key'],deadline=parent['deadline'],depth=parent['depth']-1)
        evidence=[]
        for patch in [dict(actions=['delete']),dict(deadline=parent['deadline']+100),dict(depth=parent['depth']+1)]:
            bad={**body,**patch};evidence.append(f.reject(lambda bad=bad:l.mesh.call('A','authorize_child',parent=f.a,body=bad)))
        rows.append(dict(id='N07',passed=True,variants=3,evidence=evidence))
        # Required-source variants are authenticated with correct caller-held keys.
        evidence=[]
        p=f.payload('missing','research.aggregate',{'rows':[]})
        evidence.append(f.reject(lambda:l.charge(f.w,{'s1':2},'missing','summary',p),'REQUIRED_SOURCE_SET'))
        p=f.payload('extra')
        evidence.append(f.reject(lambda:l.charge(f.w,{'s1':2,'s2':2},'extra','query',p),'REQUIRED_SOURCE_SET'))
        # Duplicate sources cannot be represented by the caller mapping; mutate canonical wire.
        from gredac.crypto import E,parse_e
        p=copy.deepcopy(original);parts=parse_e(bytes.fromhex(p['body']));vector=parse_e(parts[-1])
        p['body']=E(*parts[:-1],E(*vector,vector[1])).hex()
        evidence.append(f.reject(lambda:f.raw(p)))
        rows.append(dict(id='N09',passed=True,variants=3,evidence=evidence))
        evidence=[f.reject(lambda:f.send(0,'spent-new'),'POSITION_SPENT_OR_FENCED')]
        child=l.right('C','C','c',f.a);h=l.delegate(f.h,child,{'s1':[1],'s2':[1]});w=l.reserve(h,f.srv,{'s1':[1],'s2':[1]})
        evidence.append(f.reject(lambda:f.send(1,'transferred-new')))
        rows.append(dict(id='N10',passed=True,variants=2,evidence=evidence))
        with httpx.Client(transport=httpx.HTTPTransport(uds=info['uds']),trust_env=False) as h:
            rpc=dict(jsonrpc='2.0',id='probe',method='SendMessage',params=original['payload']['request'])
            before=f.snapshot()
            for headers in [{},{'X-GReDAC-Ticket':'fake'}]:
                assert h.post(URL,json=rpc,headers=headers).status_code==403
            assert f.snapshot()==before
            rows.append(dict(id='N11',passed=True,variants=2))
            methods=['SendStreamingMessage','GetTask','CancelTask','SubscribeToTask','GetExtendedAgentCard','sign','configure','arm_fault','handler']
            for method in methods:assert h.post(URL,json={**rpc,'method':method}).status_code==403
            assert h.post(URL,json=[rpc]).status_code==403
            assert h.post('http://a2a.local/other',json=rpc).status_code==403
            assert f.snapshot()==before
            rows.append(dict(id='N14',passed=True,variants=len(methods)+2))
            rows.append(dict(id='N18',passed=True,methods=methods[-4:]))
        evidence=[]
        for where in ['request','message']:
            p=f.payload('meta-'+where)
            (p['request'] if where=='request' else p['request']['message'])['metadata']={'approved':True,'identity':'G'}
            evidence.append(f.reject(lambda p=p:f.send(2,'meta-'+where,payload=p,operation='query')))
        rows.append(dict(id='N13',passed=True,variants=2,evidence=evidence))
        evidence=[]
        for key in ['taskId','contextId','referenceTaskIds']:
            p=f.payload('task-'+key);p['request']['message'][key]=['other'] if key=='referenceTaskIds' else 'other'
            evidence.append(f.reject(lambda p=p:f.send(2,'task-'+key,payload=p,operation='query')))
        rows.append(dict(id='N15',passed=True,variants=3,evidence=evidence))
        receipt=f.sent[0]['service_receipt'];evidence=[]
        for change in [lambda p:p['body'].update(service='other'),
            lambda p:p['body'].update(payload_digest='0'*64),
            lambda p:p['body']['result']['a2a_response']['message']['parts'][0]['data'].update(value='tampered')]:
            bad=copy.deepcopy(receipt);change(bad)
            evidence.append(f.reject(lambda bad=bad:check_envelope(bad,l.rights[f.srv]['public_key'],protocol=PROTOCOL)))
        rows.append(dict(id='N17',passed=True,variants=3,evidence=evidence))
        stale=f.payload('stale');l.update_card(f.srv,'2')
        evidence=[f.reject(lambda:f.send(2,'stale',payload=stale),'A2A_STALE_CARD')]
        saved=l.cards[f.srv];bad=copy.deepcopy(saved);bad['supportedInterfaces'][0]['url']='http://127.0.0.1:22/'
        l.cards[f.srv]=bad
        evidence.append(f.reject(lambda:l.publish_service(f.srv)));l.cards[f.srv]=saved
        found=l.discover(f.h);assert found['members'][0]['card_digest']==digest(saved)
        rows.append(dict(id='N16',passed=True,variants=2,evidence=evidence))
        # Authorization tombstones are checked on every fresh message.
        l.call('R','revoke',{'id':f.srv})
        ev=f.reject(lambda:f.send(2,'service-revoked'),'KNOWN_REVOKED')
        s2=l.right('srv2','S2','c',f.sroot,side='service')
        w2=l.reserve(f.h,s2,f.slots);l.call('O','revoke',{'id':f.a})
        ev2=f.reject(lambda:f.send(2,'caller-revoked',w=w2,srv=s2),'KNOWN_REVOKED')
        rows.append(dict(id='N08',passed=True,variants=2,evidence=[ev,ev2],expiry='covered separately in N08-expiry'))
    return rows
