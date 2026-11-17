"""Targeted boundary tests using real HTTP and signed delivery."""
import asyncio,copy,json,sqlite3,time
from pathlib import Path
import httpx
from gredac.crypto import Signer,canonical,require
from gredac.roles import ACTServiceRole,check_envelope
from gredac.endpoint import PROTOCOL
from gredac.rpc import Client as RPC
from ..network_client import HoldingRef
from .codec import envelope,URL
from .service import BridgeService
from .fixtures import execute
from .testing import Fixture,denied

def boundary(run):
    rows=[];variants=[]
    for mode in ['replay','body','target']:
        b=BridgeService(run.out/('N12-'+mode),'S',execute)
        other=BridgeService(run.out/('N12-'+mode+'-other'),'Other',execute) if mode=='target' else None
        g,s=Signer('G'),Signer('S')
        right=dict(id='srv',owner='S',context='c',public_key=s.public)
        role=ACTServiceRole(s,right,[],{},g.public,'G');role.handler=b.receive_admitted
        payload=envelope('srv',b.card,'message','echo.read',{'value':1})
        signed=g.envelope(dict(protocol=PROTOCOL,endpoint='G',kind='service-delivery',key='admission',
            service='S',service_right='srv',context='c',payload=payload,operation='query'))
        original=b.transport.send_message;observed=[]
        async def intercepted(request,*,context):
            params=copy.deepcopy(payload['request'])
            token=context.service_parameters['X-GReDAC-Ticket']
            rpc=dict(jsonrpc='2.0',id='attacker-rpc-id',method='SendMessage',params=params)
            if mode=='body':
                rpc['params']['message']['parts'][0]['data']['arguments']['value']=999
                response=await b.http.post(URL,json=rpc,headers={'X-GReDAC-Ticket':token})
                assert response.status_code==403;observed.append('changed body denied')
            elif mode=='target':
                async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=other.uds),trust_env=False) as h:
                    response=await h.post(URL,json=rpc,headers={'X-GReDAC-Ticket':token})
                assert response.status_code==403;observed.append('other service denied')
            result=await original(request,context=context)
            if mode=='replay':
                response=await b.http.post(URL,json=rpc,headers={'X-GReDAC-Ticket':token})
                assert response.status_code==403;observed.append('spent ticket denied')
            return result
        b.transport.send_message=intercepted
        try:
            receipt=role.receive(signed);count=b.description()['business_executions']
            assert count==(0 if mode=='body' else 1)
            assert role.receive(signed)==receipt if mode!='body' else role.receive(signed)['body']['result']['business_status']=='UNKNOWN'
            if other:assert other.description()['business_executions']==0
            variants.append(dict(mode=mode,checks=observed,business=count,
                                 phase='signed delivery already admitted; no new G admission'))
        finally:
            b.close()
            if other:other.close()
    rows.append(dict(id='N12',passed=True,variants=variants))
    for side in ['caller','service']:
        with Fixture(run,'N08-expiry-'+side) as f:
            l=f.lab;name='ShortCaller' if side=='caller' else 'ShortService'
            reg=l.ensure(name);parent=f.a if side=='caller' else f.sroot
            par=l.rights[parent];deadline=time.monotonic()+2
            body=dict(id='short-'+side,owner=name,context='c',side=side,parent=parent,
                actions=['query','summary'],public_key=reg['public_key'],deadline=deadline,depth=par['depth']-1)
            info=l.mesh.call(par['owner'],'authorize_child',parent=parent,body=body)
            rid=body['id'];l.rights[rid]=info['right'];l.chains[rid]=info['chain'];l.holdings[rid]=HoldingRef(rid)
            if side=='caller':
                h=l.delegate(f.h,rid,{'s1':[0],'s2':[0]})
                w=l.reserve(h,f.srv,{'s1':[0],'s2':[0]})
            else:
                l.service_ids.append(rid);l.publish_service(rid);w=l.reserve(f.h,rid,f.slots)
            time.sleep(max(0,deadline-time.monotonic())+.03)
            ev=f.reject(lambda:f.send(0,'expired-'+side,w=w,srv=w.service),['RIGHT_EXPIRED','ACT_OR_HARD_EXPIRED'])
            rows.append(dict(id='N08-expiry-'+side,passed=True,evidence=ev))
    with Fixture(run,'N16-N18-boundary') as f:
        l=f.lab;pub=l.publish_service(f.srv);bad=copy.deepcopy(pub)
        bad['body']['info']['card']['version']='forged'
        ev=f.reject(lambda:check_envelope(bad,l.endpoint_public,protocol=PROTOCOL))
        rows.append(dict(id='N16-signed-card',passed=True,evidence=ev))
        c=RPC(l.mesh.path/'pki','A',l.mesh.routes,l.path/'controller-probe.jsonl')
        variants=[]
        try:
            for dest,method,args in [('G','a2a_enable',{}),('S','a2a_service',{}),('S','handler',{'kind':'echo'}),
                ('G','arm_fault',{'point':'before_commit'}),('A','configure',{}),('S','sign',{'body':{'arbitrary':True}})]:
                variants.append(f.reject(lambda dest=dest,method=method,args=args:c.call(dest,method,**args)))
        finally:c.close()
        rows.append(dict(id='N18-controller',passed=True,variants=len(variants),evidence=variants))
    return rows
