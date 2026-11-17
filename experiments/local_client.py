"""Local fixture assembly for the fixed-endpoint protocol; no workload and no simulated security decisions.

Legacy Client remains frozen for historical reproducibility. Authority is an
initial issuer, Endpoint is the sole runtime ledger, and local Holdings retain
the signed derivation history. Timers measure actual calls, not modeled RTTs.
"""
import copy,json,time,threading
from collections import Counter
from .client import Client as Measurements
from .support import stats,write_json
from gredac.crypto import SCHEME,Bundle,Signer,Denied,canonical,digest,ident,domain_for,require,by_slot,verify_signature
from gredac.endpoint import SetupAuthority,Endpoint,PROTOCOL
from gredac.offline import Holding,Wallet,authorize,transfer,receive_delegation
from gredac.roles import CallerContact,ServiceRole,ServiceTransport,verified
from gredac.storage import Store,MonotonicClock,position_key
from gredac.pki import PKI


class Client(Measurements):
    def __init__(self,run,case,lease=5,contact_seconds=30,endpoint_id="G",shared_pki=None,shared_signers=None):
        self.endpoint_id=endpoint_id
        self.run,self.case=run,case;self.path=run.out/case;self.path.mkdir(parents=True,exist_ok=False)
        self.clock,self.ids,self.holdings=MonotonicClock(),shared_signers if shared_signers is not None else {},{}
        self.transactions=[];self.install_metrics=[];self.admission_commits={};self.components=[]
        self.rights={};self.chains={};self.authorizations={};self.identities={};self.local_caps={};self.initial_frozen=False
        self.deadline=self.clock.now()+7200;self.contact_seconds=contact_seconds
        self.pki=shared_pki if shared_pki is not None else PKI(self.path/'pki');self.a=Store(self.path/'authority.sqlite',self.observe)
        self.g=Store(self.path/'guard.sqlite',self.observe)
        self.authority=SetupAuthority(self.a,self.clock,self.pki,'joint')
        for name,owner in [('UO','UO'),('UR','UR'),('O','UO'),('R','UR'),(self.endpoint_id,'UO'),('Authority','UO')]:
            self.identities[name]=self.authority.bootstrap_identity(self.actor(name),owner)
        self.endpoint=Endpoint(self.g,self.clock,self.pki,self.authority.signer.public,endpoint=self.endpoint_id,session_seconds=contact_seconds)
        self.transport=ServiceTransport(self.pki,self.endpoint_id);self.endpoint.delivery=self.transport.deliver
        # Endpoint control verification key is provisioned at initial setup.
        # Runtime roles never obtain private endpoint state through this fixture.
        self.endpoint_public=self.endpoint.control.public;self.published=set();self.initialized_contexts=set()
        self.roles={};self.contact_messages=[];self.discovery_messages=[];self.control_messages=[];self.denials=[]
        self.spend_messages=[];self.delegation_messages=[]
        self.pending_controls={}
        run.manifest['protocol']=dict(name=PROTOCOL,authority_role='initial issuance only',
            runtime_ledger='fixed B / guard.sqlite',key_root='initial restricted packages only',
            return_rule='nearest eligible original parent capability; no new anchor',
            deadline_margin_seconds=self.endpoint.margin,clock_scope='single-host monotonic',
            service_execution='synchronous under B global store lock; charge/body_ns include service',
            client_recovery='pending requests survive B failure; client process failure excluded',
            deadline_bound='configured check-to-commit allowance; not a proved OS scheduling bound')
        self.instrument()

    def instrument(self):
        for obj,name,component in [(self.authority,'accept','Authority')]+[
                (self.endpoint,n,'Endpoint') for n in ('initialize','sync','accept','discover','session','charge')]:
            original=getattr(obj,name)
            def measured(*args,_fn=original,_name=name,_component=component,**kwargs):
                old=getattr(self.run.local,'component',None);self.run.local.component=_component
                start,cpu=time.perf_counter_ns(),time.thread_time_ns()
                try:return _fn(*args,**kwargs)
                finally:
                    self.components.append(dict(component=_component,operation=_name,
                        phase=getattr(self.run.local,'phase','setup'),work=getattr(self.run.local,'work',None),
                        start_ns=start,end_ns=time.perf_counter_ns(),thread_cpu_ns=time.thread_time_ns()-cpu))
                    self.run.local.component=old
            setattr(obj,name,measured)

    def observe(self,row):
        super().observe({**row,'component':getattr(self.run.local,'component',None),
                         'work':getattr(self.run.local,'work',None)})

    def call(self,actor,operation,args):
        if operation in ('context','source','right','seed'):
            require(not self.initial_frozen,'INITIAL_AUTHORITY_FROZEN')
            return self.measure('authority.'+operation,lambda:self.authority.call(self.actor(actor),operation,args))
        if operation=='revoke' and not args['id'].startswith(('ctx:','task:','coop:','source:')):
            chain=self.chains.get(args['id'],[])
            names={x['body']['right']['owner'] for x in chain if x['body']['kind']=='authorization'}
            args={**args,'chain':chain,'identities':{n:self.identities[n] for n in names}}
        pending=canonical([actor,operation,args]).decode()
        body=self.pending_controls.setdefault(pending,dict(protocol=PROTOCOL,endpoint=self.endpoint_id,actor=actor,operation=operation,id=ident(),args=args))
        link=self.measure('tls.control',lambda:self.pki.link(actor,self.endpoint_id))
        request=json.loads(link.transfer(canonical(body)))
        result=self.measure('endpoint.'+operation,lambda:self.endpoint.accept(request,self.actor(actor).sign(body)))
        result=json.loads(link.transfer(canonical(result),reply=True))
        self.measure('client.control_receipt',lambda:verified(result,self.endpoint_public,
            protocol=PROTOCOL,endpoint=self.endpoint_id,request_digest=digest(body)))
        self.control_messages.append(dict(request=body,response=result))
        self.pending_controls.pop(pending,None)
        return result

    def context(self,cid,sources,tasks=None,cooperation='g'):
        body=dict(id=cid,tasks=tasks or [cid],cooperation=cooperation,
            caller_approver='UO',service_approver='UR',caller_root='O-'+cid,service_root='R-'+cid,
            req={op:sources for op in ('query','summary')},basis={s:s for s in sources},
            deadline=self.deadline,scheme=SCHEME,endpoint=self.endpoint_id)
        self.call('UO','context',dict(body=body,approvals={o:self.actor(o).sign(body) for o in ('UO','UR')}))

    def source(self,source,size,contexts):
        self.call('UO','source',dict(id=source,issuer='UO',controller='UO',approval='issue-'+source,
            size=size,contexts=contexts,basis=source,actions=['query','summary'],deadline=self.deadline,
            endpoint=self.endpoint_id))

    def freeze_setup(self):
        self.initial_frozen=True;self.initial_counts=dict(self.authority.calls)

    def right(self,rid,holder,cid,parent=None,side='caller',actions=None):
        par=self.rights[parent] if parent else None;child=self.actor(holder)
        if holder not in self.identities:
            reg=self.pki.identities[holder][2] if holder in self.pki.identities else self.measure('pki.identity',lambda:self.pki.issue(holder,child.public,self.pki.csr(child),side))
            require(reg['public_key']==child.public,'SHARED_IDENTITY_KEY')
            self.pki.materialize(child,reg);self.identities[holder]=reg
        body=dict(id=rid,owner=holder,context=cid,side=side,parent=parent,actions=sorted(actions or ['query','summary']),
                  public_key=child.public,deadline=min(self.deadline,par['deadline']) if par else self.deadline,
                  depth=par['depth']-1 if par else 32)
        require(rid not in self.rights,'IMMUTABLE_RIGHT')
        if par:
            body,description=authorize(par,child,body,self.endpoint_id)
            signed=self.measure('parent.authorize',lambda:self.actor(par['owner']).envelope(description))
            self.authorizations[rid]=signed
            self.chains[rid]=self.chains[parent]+[signed]
        else:
            self.call('UO' if side=='caller' else 'UR','right',{**body,'proof':child.sign(body)})
            body=self.a.get('rights',rid);self.chains[rid]=[]
        self.rights[rid]=body;self.holdings[rid]=Holding(rid,chain=self.chains[rid])
        if side=='service' and parent:
            names={self.rights[parent]['owner'],holder}|{x['body']['right']['owner'] for x in self.chains[rid]}
            role=ServiceRole(child,body,self.chains[rid],{n:self.identities[n] for n in names},self.endpoint_public,self.endpoint_id)
            self.roles[rid]=role;self.transport.add(role)
            if cid in self.initialized_contexts:self.publish_service(rid)
        return rid

    def publish_service(self,rid,actor=None):
        """The service-side manager publishes; this does not modify caller hints."""
        role=self.roles[rid];r=role.right;desc=role.describe()
        actor=actor or self.rights[r['parent']]['owner']
        info=dict(context=r['context'],service=r['context'],member=rid,endpoint=self.endpoint_id,
            endpoint_address=self.identities[self.endpoint_id]['endpoint'],member_address=self.identities[r['owner']]['endpoint'])
        result=self.call(actor,'publish',dict(info=info,chain=desc['chain'],identities=desc['identities']))
        self.published.add(rid);return result

    def seed(self,rid,selections,domains=None):
        caps=self.call('UO','seed',dict(right=rid,domains=domains if domains is not None else {s:domain_for(['query','summary'],v) for s,v in selections.items()}))
        certificate,material=self.measure('initial.restricted_keys',lambda:self.authority.initial_certificate(rid,caps))
        # Both deliveries contain exactly the same restricted packages. Neither
        # party receives source masters or anchor seeds; TLS is MemoryBIO.
        payload=dict(certificate=certificate,material=material)
        for name in (self.endpoint_id,self.rights[rid]['owner']):
            link=self.pki.link('Authority',name);received=json.loads(link.transfer(canonical(payload)))
            require(received==payload,'INITIAL_DELIVERY')
        initial=self.measure('endpoint.initialize',lambda:self.endpoint.initialize(certificate,material))
        verify_signature(self.authority.signer.public,certificate['body'],certificate['signature'])
        holding=self.holdings[rid]
        for cap in caps:
            gid=cap['gid'];self.local_caps[gid]=cap;holding.caps[gid]=cap
            holding.bundles[gid]=Bundle(gid,cap['anchor'],tuple(cap['domain']),{p:bytes.fromhex(k) for p,k in material[gid].items()})
        # Reconstruct only certified initial records. No B ledger access: local
        # numeric versions are neither known nor needed by the caller.
        r=self.rights[rid];cert=certificate['body']
        for cap in caps:
            spec=cert['sources'][cap['source']]
            for i,actions in by_slot(cap['domain']).items():
                holding.records[position_key(cap['source'],i)]=dict(source=cap['source'],slot=i,state='unused',
                    holder_right=rid,owner=r['owner'],context=r['context'],endpoint=self.endpoint_id,
                    current_cap=dict(anchor=cap['anchor'],gid=cap['gid'],holder_right=rid),ownership=initial,
                    hard_actions=sorted(actions),hard_contexts=[r['context']],deadline=min(spec['deadline'],r['deadline']))
        self.initialized_contexts.add(r['context'])
        candidates=[sid for sid,role in self.roles.items() if role.right['context']==r['context']]
        for sid in candidates:
            if sid not in self.published:self.publish_service(sid)
        # R -> O cooperation information, then inherited during offline delivery.
        if not holding.task_info:
            info=dict(context=r['context'],service=r['context'],endpoint=self.endpoint_id,
                endpoint_address=self.identities[self.endpoint_id]['endpoint'],known_member=candidates[0] if candidates else None)
            root_service=next(x for x in cert['roots'] if x['side']=='service')
            link=self.pki.link(root_service['owner'],r['owner'])
            holding.task_info=json.loads(link.transfer(canonical(info)))
        return holding

    def delegate(self,parent,rid,selections,actions=None,domains=None):
        # Entire operation uses parent-local secrets, descriptions and records.
        # Child delivery precedes Endpoint synchronization, even for grandchild.
        new,signed=self.measure('parent.derive_and_sign',lambda:transfer(parent,rid,selections,
            actions or ['query','summary'],self.actor(self.rights[parent.right]['owner']),domains=domains))
        new.chain=parent.chain+[self.authorizations[rid],signed]
        material={g:b.public_secrets() for g,b in new.bundles.items()}
        link=self.measure('tls.delegation',lambda:self.pki.link(self.rights[parent.right]['owner'],self.rights[rid]['owner']))
        payload=dict(keys=material,description=signed,authorization=self.authorizations[rid],
                     chain=new.chain,records=new.records,task_info=new.task_info)
        delivered=json.loads(link.transfer(canonical(payload)))
        # Discard the sender-created Holding. Only the receiver's parsed output
        # is installed; delivery/verification failure leaves its old state intact.
        received=self.measure('child.receive',lambda:receive_delegation(delivered,self.rights[rid],link.caller_public,self.endpoint_id,self.rights[parent.right]))
        self.chains[rid]=received.chain;self.holdings[rid]=received;self.local_caps.update(received.caps)
        self.delegation_messages.append(dict(child=rid,payload_digest=digest(delivered),
            description=delivered['description'],authorization=delivered['authorization'],
            records=copy.deepcopy(received.records),key_digests={g:digest(k) for g,k in delivered['keys'].items()}))
        return received

    def sync(self,holding,service,descriptor=None):
        # The service supplies public chain material and signs its own proof.
        descriptor=descriptor or self.roles[service].describe()
        chain=[];seen=set()
        for signed in holding.chain+descriptor['chain']:
            d=digest(signed)
            if d not in seen:seen.add(d);chain.append(signed)
        names=[self.rights[holding.right]['owner'],descriptor['right']['owner']];challenge=ident()
        body=dict(protocol=PROTOCOL,endpoint=self.endpoint_id,chain_digest=digest(chain),challenge=challenge)
        proofs={names[0]:self.actor(names[0]).sign(body),names[1]:self.roles[service].prove(body)}
        needed=set(names)|{x['body']['right']['owner'] for x in chain if x['body']['kind']=='authorization'}
        known={**self.identities,**descriptor['identities']};identities={n:known[n] for n in needed}
        link=self.measure('tls.sync',lambda:self.pki.link(names[0],self.endpoint_id))
        sent=json.loads(link.transfer(canonical(dict(chain=chain,identities=identities,proofs=proofs,challenge=challenge,required=[holding.right,service]))))
        result=self.measure('endpoint.sync',lambda:self.endpoint.sync(**sent))
        result=json.loads(link.transfer(canonical(result),reply=True))
        verified(result,self.endpoint_public,protocol=PROTOCOL,endpoint=self.endpoint_id,kind='sync-receipt',
            challenge=challenge,chain_digest=digest(chain),required=[holding.right,service])
        return result

    def discover(self,holding,known=None):
        info=holding.task_info;owner=self.rights[holding.right]['owner']
        body=dict(protocol=PROTOCOL,endpoint=info['endpoint'],actor=owner,context=info['context'],
            service=info['service'],known_member=known if known is not None else info.get('known_member'),challenge=ident())
        link=self.measure('tls.discovery',lambda:self.pki.link(owner,info['endpoint']))
        result=self.measure('endpoint.discover',lambda:self.endpoint.discover(body,self.actor(owner).sign(body),self.identities[owner],link))
        parsed=verified(result,self.endpoint_public,protocol=PROTOCOL,endpoint=self.endpoint_id,kind='directory',
            request_digest=digest(body),context=info['context'],service=info['service'])
        self.discovery_messages.append(dict(request=body,response=result));return parsed

    def contact_material(self,holding,service,descriptor=None):
        """A and Rj exchange signed messages; no function receives both secrets."""
        caller=self.rights[holding.right];role=self.roles[service];srv=(descriptor or role.describe())['right']
        expires=min(self.clock.now()+self.contact_seconds,caller['deadline'],srv['deadline'])
        initiator=CallerContact(self.actor(caller['owner']),caller,srv,expires,holding.chain,self.endpoint_id)
        link=self.pki.link(caller['owner'],srv['owner'])
        request=initiator.begin();act=role.respond(json.loads(link.transfer(canonical(request))),link.caller_public)
        act=json.loads(link.transfer(canonical(act),reply=True));confirmation=initiator.finish(act)
        installation=role.install(json.loads(link.transfer(canonical(confirmation))))
        self.contact_messages.append(dict(request=request,act=act,confirmation=confirmation))
        return act,initiator.key,confirmation,installation

    def reserve(self,holding,service,selections):
        """Register suffix, authenticate contact, reference units; no reservation."""
        require(not {position_key(s,i) for s,v in selections.items() for i in v}&holding.uncertain_units(),
                'LOCAL_OUTCOME_UNCERTAIN')
        found=self.discover(holding,service)
        if not found['known_valid']:
            error=Denied('SERVICE_TARGET_INVALID');error.directory=found;raise error
        descriptor=next(r for r in found['members'] if r['member']==service)
        self.sync(holding,service,descriptor)
        caller,srv=self.rights[holding.right],descriptor['right']
        expires=min(self.clock.now()+self.contact_seconds,caller['deadline'],srv['deadline'])
        act,key,confirmation,installation=self.measure('contact.local',lambda:self.contact_material(holding,service,descriptor))
        rows=[];caps={}
        for source,slots in selections.items():
            for slot in slots:
                row=holding.records.get(position_key(source,slot))
                require(row and row['holder_right']==holding.right,'LOCAL_POSITION_UNKNOWN')
                row={**row,'install':row['ownership']};rows.append(row)
                gid=row['current_cap']['gid'];caps[gid]=holding.caps[gid]
        lane=dict(id=ident(),caller=caller,service=srv,act=act,rows=rows,caps=caps,deadline=expires,lease=expires,task_info=holding.task_info)
        # Selection records stay caller-local. The fixed endpoint registered
        # capabilities at sync; ACT installation need not retransmit a quota
        # snapshot, and new requests authenticate their own current vector.
        wire_lane={k:v for k,v in lane.items() if k not in ('rows','caps')}
        link=self.measure('tls.handshake',lambda:self.pki.link(caller['owner'],self.endpoint_id))
        service_link=self.measure('tls.service_install',lambda:self.pki.link(srv['owner'],self.endpoint_id))
        receipt=self.measure('endpoint.session',lambda:self.endpoint.session(wire_lane,confirmation,installation,link,service_link))
        session=verified(receipt,self.endpoint_public,protocol=PROTOCOL,endpoint=self.endpoint_id,kind='session-receipt',lane_digest=digest(wire_lane))['session']
        require(session['key']==key.hex(),'CONTACT_KEY_CONFIRMATION')
        self.install_metrics.append(dict(phase=getattr(self.run.local,'phase','setup'),lane=lane['id'],lane_bytes=len(canonical(wire_lane)),
            rows=len(rows),cap_bytes=sum(len(canonical(c)) for c in caps.values()),authority_runtime_calls=0))
        return Wallet(lane,holding,session,key,link)

    def charge(self,wallet,selections,request_id,operation='query',payload=None):
        pending=self.measure('client.packet',lambda:wallet.prepare(operation,request_id,selections,payload),request_id=request_id)
        return self._submit(wallet,pending)

    def retry(self,wallet,request_id):
        """Explicitly resolve a surviving caller's old request, never re-encode it."""
        require(request_id in wallet.holding.pending,'NO_PENDING_REQUEST')
        return self._submit(wallet,wallet.holding.pending[request_id])

    def _submit(self,wallet,pending):
        packet,operation,request_id=pending['packet'],pending['operation'],pending['request_id']
        attempt=dict(request_id=request_id,packet=copy.deepcopy(packet),operation=operation,outcome='uncertain')
        self.spend_messages.append(attempt)
        try:result=self.measure('guard.charge',lambda:self.endpoint.charge(packet,operation,pending['link']),request_id=request_id)
        except Denied as error:
            attempt.update(outcome='rejected' if getattr(error,'admission_rejected',False) else 'uncertain',code=error.code)
            self.denials.append(dict(request_id=request_id,operation=operation,packet=packet,
                code=error.code,stage='endpoint.charge',endpoint_calls=dict(self.endpoint.calls)))
            if hasattr(error,'directory'):
                verified(error.directory,self.endpoint_public,protocol=PROTOCOL,endpoint=self.endpoint_id,kind='directory-hint',request_digest=digest(packet))
                self.discovery_messages.append(dict(rejected_request=request_id,response=error.directory))
            if getattr(error,'admission_rejected',False):wallet.resolve(pending,False)
            raise
        except Exception as error:
            attempt.update(outcome='uncertain',error_type=type(error).__name__);raise
        # The reply arrived on the authenticated A--B channel. Bind it to this
        # exact session/request before recording local expenditure.
        session,service=pending['session'],pending['service']
        expected=canonical([self.endpoint_id,session['lane'],session['binding']['context'],
            session['binding']['caller_right'],session['binding']['service_right'],
            session['binding']['session'],request_id]).decode()
        require(result['key']==expected and result['sources']==[[s,i] for s,i in sorted(pending['selections'].items())],'RECEIPT_BINDING')
        if result.get('service_receipt'):
            verified(result['service_receipt'],service['public_key'],protocol=PROTOCOL,endpoint=self.endpoint_id,
                kind='service-receipt',key=expected,service=service['owner'],
                service_right=service['id'],context=pending['caller']['context'],payload_digest=digest(packet['payload']))
        wallet.resolve(pending,True);attempt.update(outcome='resolved',response=result)
        return result

    def renew(self,wallet):
        selections={}
        for old in wallet.lane['rows']:
            row=wallet.holding.records[position_key(old['source'],old['slot'])]
            if row['state']=='unused' and position_key(row['source'],row['slot']) not in wallet.holding.uncertain_units():
                selections.setdefault(row['source'],[]).append(row['slot'])
        fresh=self.reserve(wallet.holding,wallet.lane['service']['id'],selections)
        wallet.lane,wallet.session,wallet.channel_key,wallet.link=fresh.lane,fresh.session,fresh.channel_key,fresh.link
        return fresh.session['expires']

    def recontact(self,wallet,selections):
        """Caller resolves its stale hint at B; it explicitly obtains a new ACT."""
        found=self.discover(wallet.holding,wallet.lane['service']['id'])
        require(found['members'],'NO_SERVICE_CANDIDATE')
        target=next((r for r in found['members'] if r['member']==wallet.lane['service']['id']),found['members'][0])
        known={s:[i for i in slots if position_key(s,i) not in wallet.holding.uncertain_units()]
               for s,slots in selections.items()}
        return self.reserve(wallet.holding,target['member'],known)

    def recovery(self,wallet,receiver,actor=None):
        # The chosen controller requests, but B selects the eligible ancestor.
        actor=actor or self.rights[receiver]['owner']
        result=self.call(actor,'return',{'id':wallet.holding.right})
        return self.receive_return(result,receiver,wallet.holding.right)

    def receive_return(self,envelope,receiver,target,request=None):
        """Normal and fault-injection paths use the same recipient verification."""
        from gredac.participant import accept_return
        holding=self.holdings[receiver]
        slots=accept_return(envelope,holding,self.rights[receiver],target,self.endpoint_id,self.endpoint_public,request)
        return holding,slots

    def breakdown(self,work=None):
        cs=[r for r in self.components if r['phase']=='measurement' and (work is None or r['work']==work)]
        ts=[r for r in self.transactions if r['phase']=='measurement' and (work is None or r['work']==work)]
        return dict(components={c:dict(calls=sum(r['component']==c for r in cs),
            wall_ms=sum((r['end_ns']-r['start_ns'])/1e6 for r in cs if r['component']==c),
            thread_cpu_ms=sum(r['thread_cpu_ns']/1e6 for r in cs if r['component']==c)) for c in ('Authority','Endpoint')},
            storage={s:{k:sum(r[k]/1e6 for r in ts if r['store']==s) for k in
                ('lock_wait_ns','begin_ns','body_ns','commit_or_rollback_ns')} for s in ('authority.sqlite','guard.sqlite')})

    def close(self):
        requests=self.g.all('requests');seen=set();counts=Counter();deadline_checks=[]
        commits={t['txid']:t for t in self.transactions if t['committed'] and 'sql_commit_return_monotonic' in t}
        for r in requests.values():
            d=r['decision'];assert len(d['sources'])==len(set(s for s,i in d['sources']))
            request_id=json.loads(d['key'])[-1]
            if d.get('admission_tx') in commits:
                physical=commits[d['admission_tx']]['sql_commit_return_monotonic']
                deadline_checks.append(dict(request_id=request_id,commit=physical,deadline=d['deadline'],late=physical>=d['deadline']))
            for s,i in d['sources']:
                assert (s,i) not in seen;seen.add((s,i));counts[s]+=1
                assert self.g.get('positions',position_key(s,i))['state']=='spent'
        forwarding=self.g.all('forwarding')
        assert set(forwarding)==set(requests)
        assert all(r['state'] in ('pending','attempted','delivered') for r in forwarding.values())
        assert set(self.g.all('effects'))=={k for k,r in forwarding.items() if r['state']=='delivered'}
        assert not self.g.all('source_masters')
        if self.initial_frozen:assert dict(self.authority.calls)==self.initial_counts
        for s,spec in self.g.all('sources').items():
            rows=[r for r in self.g.all('positions').values() if r['source']==s]
            assert len(rows)==spec['size'] and counts[s]<=spec['size']
        result=dict(protocol=PROTOCOL,audit='PASS',new_requests=len(requests),spent_by_source=dict(counts),
            delivery_states=dict(Counter(r['state'] for r in forwarding.values())),
            authority_calls=dict(self.authority.calls),endpoint_calls=dict(self.endpoint.calls),
            initial_authority_frozen=self.initial_frozen,breakdown=self.breakdown())
        result['physical_deadline_audit']=dict(observed=len(deadline_checks),late=sum(x['late'] for x in deadline_checks),
            unobserved=len(requests)-len(deadline_checks))
        write_json(self.path/'deadline-checks.json',deadline_checks)
        write_json(self.path/'components.json',self.components)
        write_json(self.path/'role-messages.json',dict(contacts=self.contact_messages,discovery=self.discovery_messages,
            controls=self.control_messages,denials=self.denials,delegations=self.delegation_messages,spends=self.spend_messages,
            pending={rid:[dict(request_id=q,packet=p['packet']) for q,p in h.pending.items()]
                     for rid,h in self.holdings.items() if h.pending}))
        with (self.path/'transactions.jsonl').open('w') as f:
            for t in self.transactions:f.write(json.dumps(t)+'\n')
        for db in (self.a,self.g):db.db.execute('PRAGMA wal_checkpoint(TRUNCATE)');db.close()
        result['database_bytes']=sum(p.stat().st_size for p in self.path.glob('*.sqlite'))
        write_json(self.path/'case.json',result);return result
