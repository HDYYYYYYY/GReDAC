"""Role-owned state and operations for the TCP experiment profile.

Each invocation of process_main owns exactly one identity and listener. An
Agent owns its private key, Holdings, Wallets, public ACT contacts and model
history. Authority/B own separate databases; no driver reads them at runtime.
Only the explicit post-run audit reads B's ledger, inside B's own process.
"""
import copy,json,os,threading,time
from pathlib import Path
from types import SimpleNamespace
from collections import Counter
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from gredac.crypto import Signer,Bundle,Denied,canonical,digest,ident,domain_for,by_slot,require,verify_signature
from gredac.pki import PKI
from gredac.storage import Store,MonotonicClock,position_key
from gredac.endpoint import SetupAuthority,Endpoint,PROTOCOL
from gredac.offline import Holding,Wallet,authorize,transfer,receive_delegation
from gredac.roles import ACTCallerContact,ACTServiceRole,verified,check_envelope
from gredac.participant import authorization_path,accept_return
from gredac.rpc import Client,Server,AcceptedLink

class Node:
    def __init__(self,name,directory,path,signer):
        self.name,self.directory,self.path,self.signer=name,Path(directory),Path(path),signer
        self.path.mkdir(parents=True,exist_ok=True);self.routes={};self.regs={};self.rights={};self.chains={}
        self.holdings={};self.wallets={};self.roles={};self.authorizations={};self.installs={}
        self.root_proofs={};self.parents={};self.registered_records=set()
        self.clock=MonotonicClock();self.lock=threading.RLock();self.record_lock=threading.Lock()
        self.api=None;self.history=[];self.facts=None;self.artifacts={};self.business_seconds=0.;self.business_calls=0
        self.authority=None;self.endpoint=None;self.store=None;self.transactions=[];self.frozen=False
        self.peer=Client(directory,name,self.routes,self.path/'rpc-sent.jsonl')
        self.pki=PKI.__new__(PKI);self.pki.root=x509.load_pem_x509_certificate((self.directory/'ca.pem').read_bytes())
        self.pki.identities={};self.pki.ca_path=self.directory/'ca.pem';self.pki.directory=self.directory
        self.handler={'kind':'echo'};self.pending_controls={};self.contacts={};self.initialized=set();self.spaces={}
    def record(self,kind,body):
        with self.record_lock:
            if not hasattr(self,'diagnostics'):
                from gredac.rpc import DiagnosticLog
                self.diagnostics=DiagnosticLog(self.path/'events.jsonl')
            self.diagnostics.append(dict(kind=kind,pid=os.getpid(),identity=self.name,**body))
    def rpc(self,destination,method,**args):
        if hasattr(self,'scope'):args['_scope']=self.scope
        return self.peer.call(destination,method,**args)
    def locate(self,name,address,public=None):
        """Use delivered task/directory addresses, not an implicit local lookup."""
        from urllib.parse import urlparse
        parsed=urlparse(address)
        require(parsed.scheme=='tls' and parsed.hostname=='127.0.0.1' and parsed.port,'NETWORK_ADDRESS_PROFILE')
        route={**self.routes[name],'port':parsed.port}
        if public is not None:route['public']=public
        self.routes[name]=route
    def link(self,peer):return AcceptedLink(peer['name'],self.name,peer['public'],self.signer.public)
    def dispatch(self,method,args,peer):
        scope=args.pop('_scope',None)
        if scope is not None:
            if scope not in self.spaces:
                require(peer['name']=='Driver' and method=='configure','UNKNOWN_COOPERATION')
                space=Node(self.name,self.directory,self.path/'cooperations'/scope,self.signer)
                space.scope=scope;space.server=self.server;self.spaces[scope]=space
            return self.spaces[scope].dispatch(method,args,peer)
        # Driver can schedule operations, never obtain keys/histories directly.
        if method in ('configure','setup','model_config','ask','feedback','facts','artifact','handler','audit','freeze','stats','stop','arm_fault'):
            require(peer['name']=='Driver','CONTROLLER_ONLY')
        if method=='configure':
            require(not (self.authority and self.frozen),'AUTHORITY_CONFIGURATION_FROZEN')
            self.routes.update(args['routes']);self.regs.update(args['registrations'])
            self.endpoint_id=args.get('endpoint',getattr(self,'endpoint_id','G'))
            self.authority_name=args.get('authority',getattr(self,'authority_name','Authority'))
            self.endpoint_public=args.get('endpoint_public',getattr(self,'endpoint_public',None))
            self.authority_public=args.get('authority_public',getattr(self,'authority_public',None))
            if self.authority:
                with self.store.transaction():
                    for name,reg in self.regs.items():
                        old=self.store.get('registrations',name)
                        require(old is None or old==reg,'IDENTITY_CHANGED');self.store.put('registrations',name,reg)
            return dict(pid=os.getpid(),identity=self.name)
        if method=='setup':
            self.store=Store(self.path/('authority.sqlite' if args['kind']=='authority' else 'guard.sqlite'),self.transactions.append)
            if args['kind']=='authority':
                self.authority=SetupAuthority(self.store,self.clock,self.pki,'joint')
                for name,reg in self.regs.items():self.store.put('registrations',name,reg)
                return self.authority.signer.public
            self.endpoint=Endpoint(self.store,self.clock,self.pki,args['authority_public'],endpoint=self.name,
                session_seconds=args['contact_seconds'],margin=args.get('commit_delay_bound',.05),clock_error=0.,
                delivery=lambda e:self.rpc(e['body']['service'],'service_receive',envelope=e))
            return self.endpoint.control.public
        if method=='sign':
            require(peer['name']=='Driver' or (args['body'].get('owner')==self.name and args['body'].get('parent')
                and {'context','actions','depth','public_key','side'}<=set(args['body'])),'SIGN_REQUESTER')
            return self.signer.sign(args['body'])
        if method=='initial_control':
            require(peer['name']=='Driver','CONTROLLER_ONLY');require(not self.frozen,'INITIAL_AUTHORITY_FROZEN')
            body=dict(actor=self.name,operation=args['operation'],id=ident(),args=args['args'])
            return self.rpc(self.authority_name,'authority_accept',body=body,signature=self.signer.sign(body))
        if method=='authority_accept':
            require(peer['name']==args['body']['actor'],'AUTHORITY_TLS_ACTOR');require(not self.frozen,'INITIAL_AUTHORITY_FROZEN')
            return self.authority.accept(args['body'],args['signature'])
        if method=='initial_package':
            require(peer['name']=='Driver','CONTROLLER_ONLY');require(not self.frozen,'INITIAL_AUTHORITY_FROZEN')
            certificate,material=self.authority.initial_certificate(args['right'],args['caps'])
            initial=self.rpc(self.endpoint_id,'initialize',certificate=certificate,material=material)
            root=next(r for r in certificate['body']['roots'] if r['id']==args['right'])
            return self.rpc(root['owner'],'initial_receive',certificate=certificate,material=material,initial=initial)
        if method=='initialize':
            require(peer['name']==self.authority_name,'INITIAL_DELIVERY_IDENTITY')
            return self.endpoint.initialize(args['certificate'],args['material'])
        if method=='install_right':
            right=args['right'];chain=args['chain'];require(right['owner']==self.name,'RIGHT_HOLDER')
            root_proof=args['root_proof']
            names={root_proof['body']['owner']}|{x['body']['right']['owner'] for x in chain if x['body']['kind']=='authorization'}
            for name in names:self.pki.validate(self.regs[name]['certificate'],self.regs[name])
            path=authorization_path(root_proof,chain,self.authority_public,self.regs,self.endpoint_id)
            if right['parent']:
                authorization=chain[-1];parent=path.get(right['parent'])
                require(parent is not None and path.get(right['id'])==right,'AUTHENTICATED_PARENT_PATH')
                require(peer['name']==parent['owner'] and peer['public']==parent['public_key'],'DELEGATION_TLS_PARENT')
                verified(authorization,parent['public_key'],protocol=PROTOCOL,endpoint=self.endpoint_id,kind='authorization',parent=parent['id'],right=right)
                self.parents[right['id']]=parent
            else:require(peer['name']=='Driver' and root_proof['body']==right,'INITIAL_RIGHT_PROVISIONING')
            self.root_proofs[right['id']]=root_proof
            self.rights[right['id']]=right;self.chains[right['id']]=chain
            self.holdings.setdefault(right['id'],Holding(right['id'],chain=chain))
            if right['side']=='service' and right['parent']:
                self.roles[right['id']]=ACTServiceRole(self.signer,right,chain,self.regs,self.endpoint_public,self.endpoint_id)
                self.roles[right['id']].handler=self.business
            return right
        if method=='authorize_child':
            require(peer['name']=='Driver','CONTROLLER_ONLY');parent=self.rights[args['parent']];child=args['body']['owner']
            right,description=authorize(parent,None,args['body'],self.endpoint_id,prove_child=False)
            authorization=self.signer.envelope(description);chain=self.chains[parent['id']]+[authorization]
            self.authorizations[right['id']]=authorization;self.rights[right['id']]=right
            self.rpc(child,'install_right',right=right,chain=chain,root_proof=self.root_proofs[parent['id']])
            self.root_proofs[right['id']]=self.root_proofs[parent['id']]
            return dict(right=right,chain=chain)
        if method=='initial_receive':
            require(peer['name']==self.authority_name,'INITIAL_DELIVERY_IDENTITY')
            c=args['certificate'];verify_signature(self.authority_public,c['body'],c['signature']);cert=c['body']
            right=next(r for r in cert['roots'] if r['side']=='caller');require(right['owner']==self.name,'INITIAL_OWNER')
            self.initial_service_root=next(r for r in cert['roots'] if r['side']=='service')
            h=self.holdings[right['id']]
            for cap in cert['caps']:
                gid=cap['gid'];keys=args['material'][gid];require(digest(keys)==cert['key_digests'][gid],'INITIAL_KEY_DIGEST')
                h.caps[gid]=cap;h.bundles[gid]=Bundle(gid,cap['anchor'],tuple(cap['domain']),{p:bytes.fromhex(k) for p,k in keys.items()})
                for i,actions in by_slot(cap['domain']).items():
                    h.records[position_key(cap['source'],i)]=dict(source=cap['source'],slot=i,state='unused',holder_right=right['id'],
                        owner=self.name,context=right['context'],endpoint=self.endpoint_id,current_cap=dict(anchor=cap['anchor'],gid=gid,holder_right=right['id']),
                        ownership=args['initial'],hard_actions=sorted(actions),hard_contexts=[right['context']],deadline=min(cert['sources'][cap['source']]['deadline'],right['deadline']))
            return dict(right=right['id'],units=len(h.records))
        if method=='send_task_info':
            require(peer['name']=='Driver','CONTROLLER_ONLY')
            return self.rpc(args['recipient'],'receive_task_info',right=args['right'],info=args['info'])
        if method=='receive_task_info':
            require(peer['name']==self.initial_service_root['owner'],'COOPERATION_SERVICE_ROOT')
            require(args['info']['context']==self.rights[args['right']]['context'] and args['info']['endpoint']==self.endpoint_id,'TASK_INFO_BINDING')
            self.holdings[args['right']].task_info=args['info'];return True
        if method=='delegate':
            require(peer['name']=='Driver','CONTROLLER_ONLY');h=self.holdings[args['parent']];rid=args['child'];right=self.rights[rid]
            new,signed=transfer(h,rid,args['selections'],args['actions'],self.signer,domains=args.get('domains'))
            payload=dict(keys={g:b.public_secrets() for g,b in new.bundles.items()},description=signed,
                authorization=self.authorizations[rid],chain=h.chain+[self.authorizations[rid],signed],records=new.records,task_info=new.task_info)
            return self.rpc(right['owner'],'receive_delegation',payload=payload,right=rid)
        if method=='receive_delegation':
            right=self.rights[args['right']];parent=self.parents[right['id']]
            require(peer['name']==parent['owner'],'DELEGATION_TLS_PARENT')
            h=receive_delegation(args['payload'],right,peer['public'],self.endpoint_id,parent)
            self.holdings[right['id']]=h;self.chains[right['id']]=h.chain
            self.record('delegation_received',dict(parent=peer['name'],right=right['id'],description=args['payload']['description'],units=len(h.records)))
            return dict(right=right['id'],units=len(h.records))
        if method=='describe':return self.roles[args['right']].describe()
        if method=='holding_chain':return self.holdings[args['right']].chain
        if method=='material_size':
            require(peer['name']=='Driver','CONTROLLER_ONLY');h=self.holdings[args['right']]
            return len(canonical(dict(right=self.rights[h.right],task_info=h.task_info,caps=h.caps,records=h.records,
                keys={g:b.public_secrets() for g,b in h.bundles.items()})))
        if method=='prove':return self.roles[args['right']].prove(args['body'])
        if method=='control':
            require(peer['name']=='Driver','CONTROLLER_ONLY');op=args['operation'];data=args['args']
            key=canonical([op,data]).decode();body=self.pending_controls.setdefault(key,dict(protocol=PROTOCOL,endpoint=self.endpoint_id,
                actor=self.name,operation=op,id=ident(),args=data))
            result=self.rpc(self.endpoint_id,'endpoint_control',body=body,signature=self.signer.sign(body))
            verified(result,self.endpoint_public,protocol=PROTOCOL,endpoint=self.endpoint_id,request_digest=digest(body))
            self.pending_controls.pop(key,None);self.record('control_receipt',dict(request=body,response=result));return result
        if method=='endpoint_control':
            require(peer['name']==args['body']['actor'],'CONTROL_TLS_ACTOR');return self.endpoint.accept(args['body'],args['signature'])
        if method=='discover':
            require(peer['name']=='Driver','CONTROLLER_ONLY');return self.discover(args['right'],args.get('known'))
        if method=='endpoint_discover':return self.endpoint.discover(args['body'],args['signature'],self.regs[peer['name']],self.link(peer))
        if method=='sync':return self.endpoint.sync(**args)
        if method=='contact_respond':return self.roles[args['right']].respond(args['request'],peer['public'])
        if method=='session':
            return self.endpoint.session_act(args['lane'],self.link(peer))
        if method=='reserve':
            require(peer['name']=='Driver','CONTROLLER_ONLY');return self.reserve(**args)
        if method=='recontact':
            require(peer['name']=='Driver','CONTROLLER_ONLY');w=self.wallets[args['wallet']]
            directory=self.discover(w.holding.right,w.lane['service']['id']);require(directory['members'],'NO_SERVICE_CANDIDATE')
            selected=next((m for m in directory['members'] if m['member']==w.lane['service']['id']),directory['members'][0])
            return self.reserve(w.holding.right,selected['member'],args['selections'],args['contact_seconds'])
        if method=='charge':
            require(peer['name']=='Driver','CONTROLLER_ONLY');w=self.wallets[args['wallet']]
            pending=w.prepare(args['operation'],args['request_id'],args['selections'],args.get('payload'))
            return self.submit(w,pending)
        if method=='consume_next':
            require(peer['name']=='Driver','CONTROLLER_ONLY');w=self.wallets[args['wallet']]
            uncertain=w.holding.uncertain_units();choices={}
            for source in w.lane['sources']:
                available=[r for k,r in w.holding.records.items() if r['source']==source and r['state']=='unused'
                    and r['holder_right']==w.holding.right and args['operation'] in r['hard_actions'] and k not in uncertain]
                require(available,'NO_LOCAL_UNUSED_UNIT');choices[source]=min(r['slot'] for r in available)
            pending=w.prepare(args['operation'],args['request_id'],choices,args.get('payload'))
            self.record('unit_selection',dict(request=args['request_id'],selections=choices,origin='caller_protocol_client'))
            return self.submit(w,pending)
        if method=='retry':
            require(peer['name']=='Driver','CONTROLLER_ONLY');w=self.wallets[args['wallet']]
            return self.submit(w,w.holding.pending[args['request_id']])
        if method=='endpoint_charge':return self.endpoint.charge(args['packet'],args['operation'],self.link(peer))
        if method=='probe_old':
            require(peer['name']=='Driver','CONTROLLER_ONLY');w=self.wallets[args['wallet']]
            packet=w.packet('query',args['request_id'],args['selections'],{'probe':True})
            return self.rpc(self.endpoint_id,'endpoint_charge',packet=packet,operation='query')
        if method=='receive_return':
            require(peer['name']=='Driver','CONTROLLER_ONLY')
            return accept_return(args['envelope'],self.holdings[args['receiver']],self.rights[args['receiver']],
                args['target'],self.endpoint_id,self.endpoint_public)
        if method=='service_receive':
            require(peer['name']==self.endpoint_id,'SERVICE_TLS_ENDPOINT')
            return self.roles[args['envelope']['body']['service_right']].receive(args['envelope'])
        if method=='business_direct':
            # No-system still uses independent service execution over TLS.
            require(not self.roles,'PROTOCOL_ADMISSION_REQUIRED')
            return self.business(dict(payload=args['payload']))
        if method=='calculate_cost':
            require(peer['name']=='Driver','CONTROLLER_ONLY')
            from .travel_domain import calculator
            return calculator(args['arguments'])
        if method=='business_request':
            require(peer['name']=='Driver','CONTROLLER_ONLY')
            return self.rpc(args['service'],'business_direct',payload=args['payload'])
        if method=='handler':self.handler=args;return True
        if method=='facts':self.facts=args['value'];return True
        if method=='artifact':self.artifacts[args['name']]=copy.deepcopy(args['value']);return True
        if method=='model_config':return self.model_config(**args)
        if method=='ask':return self.ask(**args)
        if method=='feedback':
            self.api.feedback(self.history,args['call_id'],args['value']);self.save_history();return True
        if method=='freeze':self.frozen=True;return dict(self.authority.calls) if self.authority else True
        if method=='stats':
            import resource
            from gredac.metrics import process_snapshot
            nodes=[self,*self.spaces.values()]
            roles=sorted({'Authority' if n.authority else 'B' if n.endpoint else 'service' if n.roles else 'Agent' for n in nodes})
            return dict(pid=os.getpid(),business_seconds=sum(n.business_seconds for n in nodes),business_calls=sum(n.business_calls for n in nodes),api_calls=len(self.api.calls) if self.api else 0,
                max_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,process_cpu_seconds=time.process_time(),
                process=process_snapshot(),roles=roles)
        if method=='arm_fault':
            require(self.endpoint is not None,'FAULT_ENDPOINT_ONLY')
            if args['point']=='response_loss':self.server.drop_response_method='endpoint_charge';return True
            def crash(where):
                if where==args['point']:
                    self.record('injected_process_exit',dict(point=where,time=time.monotonic()));os._exit(73)
            self.store.commit_hook=crash;return True
        if method=='resume_delivery':
            require(peer['name']=='Driver','CONTROLLER_ONLY');return self.endpoint.resume_delivery()
        if method=='audit':return self.audit()
        if method=='stop':
            threading.Thread(target=self.server.shutdown,daemon=True).start();return True
        raise ValueError('unknown RPC '+str(method))
    def discover(self,rid,known):
        info=self.holdings[rid].task_info;self.locate(self.endpoint_id,info['endpoint_address'])
        body=dict(protocol=PROTOCOL,endpoint=self.endpoint_id,actor=self.name,
            context=info['context'],service=info['service'],known_member=known,challenge=ident())
        reply=self.rpc(self.endpoint_id,'endpoint_discover',body=body,signature=self.signer.sign(body))
        return verified(reply,self.endpoint_public,protocol=PROTOCOL,endpoint=self.endpoint_id,kind='directory',
            request_digest=digest(body),context=info['context'],service=info['service'])
    def reserve(self,right,service,selections,contact_seconds):
        h=self.holdings[right];require(not {position_key(s,i) for s,v in selections.items() for i in v}&h.uncertain_units(),'LOCAL_OUTCOME_UNCERTAIN')
        found=self.discover(right,service);require(found['known_valid'],'SERVICE_TARGET_INVALID')
        desc=next(r for r in found['members'] if r['member']==service);srv=desc['right'];caller=self.rights[right]
        self.locate(srv['owner'],desc['member_address'],srv['public_key'])
        chain=[];seen=set();chain_ids=[]
        for signed in h.chain+desc['chain']:
            ref=digest(signed)
            if ref not in seen:chain.append(signed);seen.add(ref);chain_ids.append(ref)
        names={self.name,srv['owner']}|{x['body']['right']['owner'] for x in chain if x['body']['kind']=='authorization'}
        chain=[{'ref':ref} if ref in self.registered_records else x for x,ref in zip(chain,chain_ids)]
        chain_digest=digest(chain)
        challenge=ident();body=dict(protocol=PROTOCOL,endpoint=self.endpoint_id,chain_digest=chain_digest,challenge=challenge)
        proofs={self.name:self.signer.sign(body),srv['owner']:self.rpc(srv['owner'],'prove',right=service,body=body)}
        reply=self.rpc(self.endpoint_id,'sync',chain=chain,identities={n:self.regs[n] for n in names},proofs=proofs,challenge=challenge,required=[right,service])
        checked=verified(reply,self.endpoint_public,protocol=PROTOCOL,endpoint=self.endpoint_id,kind='sync-receipt',challenge=challenge,chain_digest=chain_digest,required=[right,service])
        require(checked['registered_records']==chain_ids,'REGISTERED_PREFIX_BINDING')
        self.registered_records.update(checked['registered_records'])
        expires=min(self.clock.now()+contact_seconds,caller['deadline'],srv['deadline'])
        contact=ACTCallerContact(self.signer,caller,srv,expires,h.chain,self.endpoint_id)
        request=contact.begin();act=self.rpc(srv['owner'],'contact_respond',right=service,request=request)
        contact.finish(act)
        for source,slots in selections.items():
            for slot in slots:
                row=h.records[position_key(source,slot)];require(row['holder_right']==right,'LOCAL_POSITION_UNKNOWN')
        # The holding is the one caller-local record set. ACT/session does not
        # duplicate all unit rows/capabilities or reserve a frozen unit list.
        lane=dict(id=ident(),caller=caller,service=srv,act=act,rows=[],caps={},sources=sorted(selections),deadline=expires,lease=expires,task_info=h.task_info)
        wire={k:v for k,v in lane.items() if k not in ('rows','caps')}
        receipt=self.rpc(self.endpoint_id,'session',lane=wire)
        session=verified(receipt,self.endpoint_public,protocol=PROTOCOL,endpoint=self.endpoint_id,kind='session-receipt',lane_digest=digest(wire))['session']
        require('key' not in session and session['profile']=='tls-act-v1','ACT_ONLY_SESSION')
        self.wallets[lane['id']]=Wallet(lane,h,session,None,None)
        self.record('contact',dict(request=request,act=act,receipt=receipt,profile='tls-act-v1'))
        return dict(id=lane['id'],right=right,service=service,selections=selections,expires=session['expires'])
    def submit(self,w,pending):
        packet=pending['packet'];rid=pending['request_id']
        try:result=self.rpc(self.endpoint_id,'endpoint_charge',packet=packet,operation=pending['operation'])
        except Denied as exc:
            if getattr(exc,'admission_rejected',False):w.resolve(pending,False)
            self.record('request_denied',dict(request_id=rid,code=exc.code,packet=packet));raise
        session=pending['session'];service=pending['service']
        expected=canonical([self.endpoint_id,session['lane'],session['binding']['context'],session['binding']['caller_right'],
            session['binding']['service_right'],session['binding']['session'],rid]).decode()
        require(result['key']==expected and result['sources']==[[s,i] for s,i in sorted(pending['selections'].items())],'RECEIPT_BINDING')
        if result.get('service_receipt'):
            check_envelope(result['service_receipt'],service['public_key'],protocol=PROTOCOL,endpoint=self.endpoint_id,kind='service-receipt',
                key=expected,service=service['owner'],service_right=service['id'],context=pending['caller']['context'],payload_digest=digest(packet['payload']))
        w.resolve(pending,True);self.record('request_receipt',dict(request_id=rid,packet=packet,response=result));return result
    def business(self,body):
        started=time.monotonic()
        self.business_calls+=1;self.record('business_handler_started',dict(request_key=body.get('key'),count=self.business_calls))
        try:
            if self.handler['kind']=='scene':
                from .business_service import execute
                return execute(self.facts,body['payload'],self.artifacts)
            if self.handler['kind']=='fixed':
                result=dict(target=self.handler['target'],value=digest(body['payload']),padding='')
                result['padding']='x'*(256-len(canonical(result)));return result
            if self.handler['kind']=='native':
                # Historical fixed-size business fixture; no comparator protocol.
                result=dict(value=digest(body['payload']),padding='')
                result['padding']='x'*(256-len(canonical(result)));return result
            return dict(payload_digest=digest(body['payload']))
        finally:self.business_seconds+=time.monotonic()-started
    def model_config(self,prompt,model,max_calls,max_tokens,format_retries=0,test_profile=None,api_key=None):
        from .llm_api import StrictAPI
        if test_profile:
            require(os.environ.get('GREDAC_OFFLINE_REGRESSION')=='1','TEST_ONLY')
            from .network_regression import FixtureAPI
            self.api=FixtureAPI(test_profile)
        else:
            from .rq3_retest import credential
            self.api=StrictAPI(api_key or credential(),model,max_calls,self.path,max_tokens=max_tokens)
        self.history=[dict(role='system',content=prompt)];self.format_retries=format_retries;return True
    def save_history(self):
        (self.path/'history.json').write_text(json.dumps(self.history,ensure_ascii=False,indent=2))
    def ask(self,offered,observation,case,remaining):
        from .agent_input import text
        first=len(self.api.calls)
        for attempt in range(min(1+self.format_retries,remaining)):
            try:
                args,cid=self.api.call(self.name,self.history,offered,observation,case)
                self.save_history();return dict(arguments=args,call_id=cid,calls=self.api.calls[first:],pid=os.getpid())
            except Exception as exc:
                rows=self.api.calls[first:];last=rows[-1] if rows else {}
                if 'response' not in last or attempt==min(1+self.format_retries,remaining)-1:
                    self.save_history();return dict(error=type(exc).__name__+': '+str(exc),calls=rows,pid=os.getpid())
                # The model authors the correction. Preserve raw rejected output,
                # provide the actual validation error, never fill missing fields.
                observation=dict(validation_error=str(exc),attempt=attempt+1,
                    rejected_response=last['response']['choices'][0]['message'],
                    instruction='Correct your previous action using exactly the offered tool and schema. Supply all required fields; use permitted enum labels. Do not change unrelated correct facts.')
                self.record('model_format_correction',dict(attempt=attempt+1,error=str(exc)))
        return dict(error='episode API cap',calls=self.api.calls[first:],pid=os.getpid())
    def audit(self):
        if hasattr(self,'diagnostics'):self.diagnostics.flush()
        self.peer.diagnostics.flush()
        if self.endpoint:
            requests=self.store.all('requests');seen=set();counts=Counter()
            for r in requests.values():
                for source,slot in r['decision']['sources']:
                    require((source,slot) not in seen,'AUDIT_DOUBLE_SPEND');seen.add((source,slot));counts[source]+=1
                    require(self.store.get('positions',position_key(source,slot))['state']=='spent','AUDIT_SPENT')
            forwarding=self.store.all('forwarding');effects=self.store.all('effects')
            require(set(forwarding)==set(requests) and set(effects)=={k for k,v in forwarding.items() if v['state']=='delivered'},'AUDIT_DELIVERY_COUNT')
            require(all(v['state'] in ('pending','attempted','delivered') for v in forwarding.values()),'AUDIT_DELIVERY_STATE')
            observed={t['txid']:t for t in self.transactions if t['committed'] and 'sql_commit_return_monotonic' in t}
            deadlines=[]
            for r in requests.values():
                t=observed.get(r['decision'].get('admission_tx'))
                deadlines.append(dict(request=r['decision']['key'],observation=t,
                    conclusion='observed' if t is not None else 'unobserved_after_crash; not a deadline proof'))
            result=dict(audit='PASS',new_requests=len(requests),spent_by_source=dict(counts),endpoint_calls=dict(self.endpoint.calls),
                delivery_states=dict(Counter(v['state'] for v in forwarding.values())),deadline_evidence=deadlines,
                assumed_check_to_commit_bound_seconds=self.endpoint.margin,
                assumed_clock_error_seconds=self.endpoint.clock_error,
                timing_scope='COMMIT return is an observed durable-completion upper bound; configured delay is an explicit assumption, not an OS guarantee')
        elif self.authority:result=dict(authority_calls=dict(self.authority.calls),frozen=self.frozen)
        else:result=dict(identity=self.name,pid=os.getpid(),holdings=list(self.holdings),wallets=list(self.wallets),business_seconds=self.business_seconds)
        if self.store:
            with (self.path/'transactions.jsonl').open('w') as f:
                for r in self.transactions:f.write(json.dumps(r)+'\n')
            self.store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        (self.path/'audit.json').write_text(json.dumps(result,indent=2));return result

def process_main(name,directory,path,pipe):
    """Pipe only boots public CSR/certificate; runtime traffic is TLS/TCP."""
    signer=Signer(name);pki=PKI.__new__(PKI)
    existing=Path(directory)/(name+'.key.pem')
    if existing.exists():
        signer.private=serialization.load_pem_private_key(existing.read_bytes(),None)
        signer.public=signer.private.public_key().public_bytes_raw().hex()
    pipe.send(dict(public=signer.public,csr=PKI.csr(pki,signer),pid=os.getpid()))
    registration=pipe.recv()
    directory=Path(directory);(directory/(name+'.crt.pem')).write_text(registration['certificate'])
    secret=directory/(name+'.key.pem')
    secret.write_bytes(signer.private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));secret.chmod(0o600)
    node=Node(name,directory,path,signer);node.routes.update(pipe.recv())
    server=Server(node,port=node.routes.get(name,{}).get('port',0));node.server=server;pipe.send(dict(port=server.server_address[1],pid=os.getpid()))
    pipe.close()
    try:server.serve_forever(poll_interval=.05)
    finally:
        node.peer.close();server.server_close()
        if hasattr(node,'diagnostics'):node.diagnostics.flush()
        if node.store:node.store.close()
        if hasattr(node,'native') and node.native.store:node.native.store.close()
        for space in node.spaces.values():
            space.peer.close()
            if hasattr(space,'diagnostics'):space.diagnostics.flush()
            if space.store:space.store.close()
