"""GReDAC fixed-endpoint runtime and persistent unit accounting.

Authority produces initial certificates only. This object has NO Authority
reference, source master, or anchor seed. Parent signatures express offline
delegation; only this ledger's commit changes current spending ownership.
Return restores the nearest eligible parent's existing capability, with a
fresh ownership record and monotonically narrowed per-position restrictions.
"""
import copy
import hashlib
import hmac
import json
import struct
from collections import Counter,defaultdict
from .authority import AgentAuthority
from .capabilities import Forest
from .crypto import (ACTIONS,SCHEME,CODEC,SLOT_BITS,Bundle,Denied,Signer,canonical,
    by_slot,channel_mac,cover,decode,digest,ident,point,require,verify_signature)
from .storage import position_key
from .rpc import json_message

PROTOCOL='fixed-endpoint-v3.1'


class SetupAuthority(AgentAuthority):
    """Reuse validated initial issuance; forbid all old runtime operations."""
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.forest.retain_hard_snapshot=False
    def bootstrap_identity(self,actor,owner):
        # Multiple independent cooperations may share the same actual identity
        # and PKI. Reuse its certificate, while each issuer keeps its own record.
        if actor.name not in self.pki.identities:
            return super().bootstrap_identity(actor,owner)
        reg=copy.deepcopy(self.pki.identities[actor.name][2])
        require(reg['public_key']==actor.public,'SHARED_IDENTITY_KEY')
        with self.store.transaction():
            require(not self.store.get('registrations',actor.name),'IDENTITY_EXISTS')
            self.store.put('registrations',actor.name,reg)
        return reg

    def accept(self,request,signature):
        require(request['operation'] in ('context','source','right','seed'),'INITIAL_AUTHORIZATION_ONLY')
        if request['operation']=='right':
            require(request['args']['parent'] is None,'PARENT_MUST_SIGN_DESCENDANT')
        return super().accept(request,signature)

    def op_context(self,actor,args):
        approved=copy.deepcopy(args)
        result=super().op_context(actor,args)
        self.store.put('initial_approvals',args['body']['id'],approved)
        return result

    def op_seed(self,actor,args):
        caps=super().op_seed(actor,args)
        # The current protocol carries source policy + certified capability;
        # the per-unit initial snapshot is exactly reconstructible from them.
        # Legacy AgentAuthority retains its historical snapshot for old audits.
        for cap in caps:
            cap.pop('hard_snapshot',None);self.store.put('caps',cap['gid'],cap)
        return caps

    def initial_certificate(self,right,caps):
        """Release only already-committed initial keys, never source/anchor keys."""
        r=self.right(right);ctx=self.context(r['context'])
        roots=[self.right(ctx[k]) for k in ('caller_root','service_root')]
        material={c['gid']:self.forest.rebuild(c['gid']).public_secrets() for c in caps}
        body=dict(protocol=PROTOCOL,kind='initial',endpoint=ctx.get('endpoint','G'),
            id='initial-'+digest([right,[c['gid'] for c in caps]]),context=ctx,
            sources={c['source']:self.store.get('sources',c['source']) for c in caps},
            roots=roots,caps=caps,registrations=self.store.all('registrations'),
            approvals=self.store.get('initial_approvals',ctx['id']),
            key_digests={g:digest(s) for g,s in material.items()})
        return self.signer.envelope(body),material


class RestrictedForest(Forest):
    """Rebuild from initial restricted packages; there is no master-key fallback."""
    def rebuild(self,gid,memo=None):
        memo={} if memo is None else memo
        if gid in memo:return memo[gid]
        cap=self.cap(gid)
        require(cap['cover']==list(cover(cap['domain'])),'CAP_COVER_CHANGED')
        seeds=self.store.get('initial_keys',gid)
        if seeds is not None:
            result=Bundle(gid,cap['anchor'],tuple(cap['domain']),{p:bytes.fromhex(k) for p,k in seeds.items()})
        else:
            parent=cap['key_parent'];require(parent['kind']=='cap','NO_INITIAL_RESTRICTED_KEY')
            old=self.cap(parent['id'])
            require(all(old[k]==cap[k] for k in ('source','context','guard','anchor')),'KEY_PARENT_BINDING')
            result=self.rebuild(old['gid'],memo).child(gid,cap['domain'])
        memo[gid]=result
        return result


class Endpoint:
    def __init__(self,store,clock,pki,authority_public,endpoint='G',session_seconds=30,margin=0.,delivery=None,clock_error=0.):
        self.store,self.clock,self.pki=store,clock,pki
        self.authority_public,self.name=authority_public,endpoint
        self.session_seconds,self.margin=float(session_seconds),float(margin)
        self.clock_error=float(clock_error)
        self.control=Signer.persistent(store,'Endpoint-control-'+endpoint)
        self.forest=RestrictedForest(store);self.key_cache={};self.calls=Counter()
        self.delivery=delivery

    def _deadline(self,value,code):
        require(self.clock.now()+self.margin+self.clock_error<value,code)
        self.store.guard_deadline(value,self.clock,self.margin,self.clock_error)

    def _identity(self,reg):
        self.pki.validate(reg['certificate'],reg)
        name=reg['agent_id'];old=self.store.get('registrations',name)
        require(old is None or old['public_key']==reg['public_key'],'IDENTITY_REBIND_REQUIRES_APPROVAL')
        if old is None:self.store.put('registrations',name,reg)

    def registration(self,name):
        reg=self.store.get('registrations',name);require(reg is not None,'IDENTITY_NOT_REGISTERED')
        return reg

    def initialize(self,certificate,material):
        body=certificate['body'];verify_signature(self.authority_public,body,certificate['signature'])
        require(body['protocol']==PROTOCOL and body['kind']=='initial' and body['endpoint']==self.name,'INITIAL_ENDPOINT')
        require(set(material)==set(body['key_digests']) and all(digest(material[g])==v for g,v in body['key_digests'].items()),'INITIAL_KEY_BINDING')
        self.calls['initialize']+=1
        with self.store.transaction():
            old=self.store.get('initial_records',body['id'])
            if old:
                require(old==digest(body),'INITIAL_ID_CONFLICT');return body['id']
            ctx=body['context'];previous=self.store.get('contexts',ctx['id'])
            require(previous is None or previous==ctx,'IMMUTABLE_CONTEXT')
            require(ctx.get('endpoint','G')==self.name,'CROSS_ENDPOINT')
            for reg in body['registrations'].values():self._identity(reg)
            self.store.put('contexts',ctx['id'],ctx)
            for r in body['roots']:
                require(r['parent'] is None and r['id']==ctx[r['side']+'_root'],'ROOT_SNAPSHOT')
                require(self.registration(r['owner'])['public_key']==r['public_key'],'ROOT_IDENTITY_SNAPSHOT')
                old=self.store.get('rights',r['id']);require(old is None or old==r,'IMMUTABLE_RIGHT')
                self.store.put('rights',r['id'],r)
            for source,spec in body['sources'].items():
                require(spec.get('endpoint','G')==self.name,'CROSS_ENDPOINT')
                old=self.store.get('sources',source)
                require(old is None or old==spec,'SOURCE_ALREADY_ISSUED')
                if old is None:
                    issue=spec['approval']+'/'+source
                    require(not self.store.get('issuances',issue),'SOURCE_ALREADY_ISSUED')
                    self.store.put('sources',source,spec);self.store.put('issuances',issue,True)
                    for i in range(spec['size']):
                        self.store.put('positions',position_key(source,i),dict(source=source,slot=i,state='unbound',
                            version=0,current_cap=None,hard_actions=sorted(spec['actions']),
                            hard_contexts=spec['contexts'],deadline=spec['deadline'],endpoint=self.name))
            for cap in body['caps']:
                require(cap['guard']==self.name and cap['context']==ctx['id'],'INITIAL_CAP_BINDING')
                require(cap['key_parent']['kind']=='anchor' and cap['cover']==list(cover(cap['domain'])),'INITIAL_CAP_SCOPE')
                right=self.right(cap['holder_right']);require(right['parent'] is None and right['side']=='caller','INITIAL_HOLDER')
                require(sorted(material[cap['gid']])==sorted(cap['cover']),'INITIAL_KEY_COVER')
                require(not self.store.get('caps',cap['gid']),'GID_REUSE')
                for i,actions in by_slot(cap['domain']).items():
                    row=self.store.get('positions',position_key(cap['source'],i))
                    require(row and row['state']=='unbound','INITIAL_POSITION_REISSUE')
                    require(set(actions)<=set(right['actions'])&set(row['hard_actions']),'HARD_LABEL')
                    row.update(state='unused',version=1,holder_right=right['id'],owner=right['owner'],context=ctx['id'],
                        current_cap=dict(anchor=cap['anchor'],gid=cap['gid'],holder_right=right['id']),
                        ownership=body['id'],hard_actions=sorted(actions),hard_contexts=[ctx['id']],
                        deadline=min(row['deadline'],right['deadline']))
                    self.store.put('positions',position_key(cap['source'],i),row)
                self.store.put('caps',cap['gid'],cap);self.store.put('initial_keys',cap['gid'],material[cap['gid']])
                self.store.put('anchors',cap['anchor'],dict(id=cap['anchor'],source=cap['source'],context=ctx['id']))
            self.store.put('initial_records',body['id'],digest(body))
            self.store.put('initial_certificates',body['id'],certificate)
            self.store.event('initial',dict(id=body['id'],time=self.clock.now()))
        return body['id']

    def _active(self,deps):
        require(not any(self.store.get('revoked',d) for d in deps),'KNOWN_REVOKED')

    def context(self,cid):
        ctx=self.store.get('contexts',cid);require(ctx is not None,'UNKNOWN_CONTEXT')
        self._active(ctx['deps']+['right:'+ctx['caller_root'],'right:'+ctx['service_root']])
        self._deadline(ctx['deadline'],'CONTEXT_EXPIRED')
        return ctx

    def right(self,rid,valid=True):
        r=self.store.get('rights',rid);require(r is not None,'UNKNOWN_RIGHT')
        if valid:
            self.context(r['context']);self._active(r['deps'])
            self._deadline(r['deadline'],'RIGHT_EXPIRED')
        return r

    def path(self,rid,overlay=None):
        result=[];seen=set();overlay=overlay or {}
        while rid:
            require(rid not in seen,'RIGHT_CYCLE');seen.add(rid)
            r=overlay.get(rid) or self.right(rid,False);result.append(r);rid=r['parent']
        return result

    def _verify_chain(self,chain,identities,apply):
        """Static validation also supports cancelling a never-registered suffix.

        apply=False deliberately performs NO transfers or hard-label changes.
        Parent-to-child staged views are used in both cases; current ownership
        checks are performed only by the atomic synchronization transaction.
        """
        rights={};caps={}
        for reg in identities.values():
            self.pki.validate(reg['certificate'],reg)
            old=self.store.get('registrations',reg['agent_id'])
            require(old is None or old['public_key']==reg['public_key'],'IDENTITY_REBIND_REQUIRES_APPROVAL')
        for signed in chain:
            if set(signed)=={'ref'}:
                ref=signed['ref'];signed=self.store.get('chain_records',ref)
                require(signed is not None and digest(signed)==ref,'UNKNOWN_REGISTERED_PREFIX')
            body=signed['body'];require(body.get('protocol')==PROTOCOL and body['endpoint']==self.name,'DELEGATION_ENDPOINT')
            parent=rights.get(body['parent']) or self.right(body['parent'],False)
            ctx=self.context(parent['context'])
            verify_signature(parent['public_key'],body,signed['signature'])
            require(body['context']==parent['context'],'DELEGATION_CONTEXT')
            # Cancelling a target may inspect its already-revoked description,
            # but authorization of the controller is checked independently.
            if apply:self._active(parent['deps'])
            self._deadline(parent['deadline'],'PARENT_EXPIRED')
            if body['kind']=='authorization':
                r=body['right'];reg=identities.get(r['owner']) or self.registration(r['owner'])
                require(reg['public_key']==r['public_key'],'CHILD_IDENTITY_BINDING')
                require(r['parent']==parent['id'] and r['context']==parent['context'] and r['side']==parent['side'],'RIGHT_PARENT_CONTEXT')
                require(r['actions'] and set(r['actions'])<=set(parent['actions']) and
                    r['deadline']<=parent['deadline'] and 0<=r['depth']<parent['depth'],'RIGHT_WIDENING')
                require(r['deps']==sorted(set(parent['deps']+['right:'+r['id']])),'RIGHT_DEPENDENCIES')
                if 'child_proof' in body:verify_signature(r['public_key'],r,body['child_proof'])
                else:require(body.get('identity_binding')=='registered-tls-key','CHILD_IDENTITY_MODE')
                old=self.store.get('rights',r['id']) or rights.get(r['id'])
                require(old is None or old==r,'IMMUTABLE_RIGHT')
                if apply:self._active(r['deps'])
                rights[r['id']]=r
                if apply:
                    self._identity(reg);self.store.put('rights',r['id'],r)
                    self.store.put('authorizations',r['id'],signed)
            else:
                require(body['kind']=='transfer','CHAIN_KIND')
                child=rights.get(body['child']) or self.right(body['child'],False)
                require(child['parent']==parent['id'] and child['side']=='caller' and child['context']==parent['context'],'DELEGATION_PARENT')
                old=self.store.get('transfers',body['id']);body_digest=digest(body)
                if old:require(old['digest']==body_digest,'TRANSFER_ID_CONFLICT')
                if apply:self._active(child['deps'])
                seen=set()
                require(body['caps'],'EMPTY_TRANSFER')
                for cap in body['caps']:
                    par=caps.get(cap['key_parent']['id']) or self.forest.cap(cap['key_parent']['id'])
                    require(cap['key_parent']['kind']=='cap' and par['holder_right']==parent['id'],'CAP_PARENT_HOLDER')
                    require(all(cap[k]==par[k] for k in ('source','context','guard','anchor')) and cap['guard']==self.name,'CAP_PARENT_BINDING')
                    require(cap['holder_right']==child['id'] and cap['domain'] and set(cap['domain'])<=set(par['domain'])
                            and cap['cover']==list(cover(cap['domain'])),'CHILD_OUTSIDE_PARENT')
                    existing=self.store.get('caps',cap['gid']) or caps.get(cap['gid'])
                    require(existing is None or (existing==cap and old is not None),'GID_REUSE')
                    require(cap['operation']==body['id'],'CAP_TRANSFER_BINDING')
                    require(cap['gid']!=par['gid'],'GID_REUSE')
                    parent_binding=self.forest_binding(par);child_binding=self.forest_binding(cap)
                    for slot,actions in by_slot(cap['domain']).items():
                        key=position_key(cap['source'],slot);require(key not in seen,'DUPLICATE_TRANSFER_POSITION');seen.add(key)
                        require(set(actions)<=set(child['actions']),'RIGHT_ACTIONS')
                        if apply and old is None:
                            row=self.store.get('positions',key)
                            require(row and row['state']=='unused','POSITION_NOT_FREE')
                            require(row['endpoint']==self.name and row['context']==ctx['id'],'CROSS_ENDPOINT_OR_CONTEXT')
                            require(row['holder_right']==parent['id'] and row['current_cap']==parent_binding
                                and row['ownership']==body['previous'][key],'CURRENT_OWNERSHIP_BINDING')
                            self._active(['source:'+cap['source']])
                            require(set(actions)<=set(row['hard_actions']) and ctx['id'] in row['hard_contexts']
                                and row['deadline']>self.clock.now()+self.margin,'HARD_LABEL')
                            self._deadline(row['deadline'],'HARD_LABEL')
                            row.update(holder_right=child['id'],owner=child['owner'],current_cap=child_binding,
                                ownership=body['id'],version=row['version']+1,hard_actions=sorted(actions),
                                deadline=min(row['deadline'],child['deadline']))
                            self.store.put('positions',key,row)
                    caps[cap['gid']]=cap
                    if apply and old is None:self.store.put('caps',cap['gid'],cap)
                require(set(body['previous'])==seen,'EXACT_TRANSFER_SCOPE')
                if apply and old is None:
                    self.store.put('transfers',body['id'],dict(digest=body_digest,body=body,signature=signed['signature']))
                    self.store.event('transfer',dict(id=body['id'],parent=parent['id'],child=child['id'],units=len(seen),time=self.clock.now()))
            if apply:self.store.put('chain_records',digest(signed),signed)
        return rights,caps

    @staticmethod
    def forest_binding(cap):
        return dict(anchor=cap['anchor'],gid=cap['gid'],holder_right=cap['holder_right'])

    def sync(self,chain,identities,proofs,challenge,required):
        """One serializable suffix transaction, including both authorization paths."""
        body=dict(protocol=PROTOCOL,endpoint=self.name,chain_digest=digest(chain),challenge=challenge)
        for name,signature in proofs.items():
            reg=identities.get(name) or self.registration(name)
            self.pki.validate(reg['certificate'],reg);verify_signature(reg['public_key'],body,signature)
        require(len(required)==2 and proofs,'KEY_POSSESSION_REQUIRED');self.calls['sync']+=1
        with self.store.transaction():
            rights,_=self._verify_chain(chain,identities,True)
            caller,service=[self.right(rid) for rid in required]
            require(caller['side']=='caller' and service['side']=='service' and caller['context']==service['context'],'SYNC_PARTICIPANTS')
            require(set(proofs)=={caller['owner'],service['owner']},'KEY_POSSESSION_REQUIRED')
            for name in proofs:
                require(any(r['owner']==name for r in rights.values()) or self.store.get('registrations',name),'CHAIN_IDENTITY')
            self.store.event('sync',dict(challenge=challenge,descriptions=len(chain),time=self.clock.now()))
        return self.control.envelope(dict(protocol=PROTOCOL,endpoint=self.name,kind='sync-receipt',
            registered=True,descriptions=len(chain),challenge=challenge,chain_digest=body['chain_digest'],required=required,
            registered_records=[x['ref'] if set(x)=={'ref'} else digest(x) for x in chain]))

    def _members(self,cid,service):
        """Only current authorization determines directory eligibility."""
        result=[]
        for row in self.store.get('service_directory',canonical([cid,service]).decode(),{}).values():
            try:self.right(row['member'])
            except Denied:continue
            result.append(copy.deepcopy(row))
        return sorted(result,key=lambda r:r['member'])

    def discover(self,request,signature,registration,link):
        """Authenticated snapshot, not permission, reservation, or liveness probe."""
        body=json.loads(link.transfer(canonical(request)))
        self.pki.validate(registration['certificate'],registration)
        require(link.caller==registration['agent_id']==body['actor'] and link.receiver==self.name,'DIRECTORY_IDENTITY')
        verify_signature(registration['public_key'],body,signature)
        require(body['protocol']==PROTOCOL and body['endpoint']==self.name,'CONTROL_ENDPOINT')
        self.calls['discover']+=1
        with self.store.lock:
            self.context(body['context']);members=self._members(body['context'],body['service'])
        reply=self.control.envelope(dict(protocol=PROTOCOL,endpoint=self.name,kind='directory',
            request_digest=digest(body),context=body['context'],service=body['service'],
            known_member=body.get('known_member'),known_valid=any(r['member']==body.get('known_member') for r in members),members=members))
        return json.loads(link.transfer(canonical(reply),reply=True))

    def _controller(self,actor,target,overlay=None):
        path=self.path(target,overlay);ctx=self.store.get('contexts',path[0]['context'])
        if actor==ctx[path[0]['side']+'_approver']:return
        require(any(r['owner']==actor and not any(self.store.get('revoked',d) for d in r['deps'])
            and r['deadline']>self.clock.now() for r in path[1:]),'CONTROL_AUTHORITY')

    def call(self,actor,op,args,op_id=None):
        body=dict(protocol=PROTOCOL,endpoint=self.name,actor=actor.name,operation=op,id=op_id or ident(),args=args)
        return self.accept(body,actor.sign(body))

    def accept(self,body,signature):
        require(body['protocol']==PROTOCOL and body['endpoint']==self.name,'CONTROL_ENDPOINT')
        reg=(body['args'].get('identities',{}).get(body['actor']) if body['operation']=='publish' else None) or self.registration(body['actor'])
        self.pki.validate(reg['certificate'],reg);verify_signature(reg['public_key'],body,signature)
        require(body['operation'] in ('revoke','return','renew','publish'),'RUNTIME_OPERATION')
        self.calls[body['operation']]+=1;key=body['actor']+'/'+body['id']
        with self.store.transaction():
            old=self.store.get('operations',key)
            if old:
                require(old['digest']==digest(body),'OP_ID_CONFLICT');return old['result']
            result=getattr(self,'_op_'+body['operation'])(body['actor'],body['args'],key)
            result=self.control.envelope({**result['body'],'protocol':PROTOCOL,'endpoint':self.name,'request_digest':digest(body)})
            # The signed digest authenticates these public request bytes for
            # the eventual recipient, even when a different controller asked.
            result['request']=copy.deepcopy(body)
            self.store.put('operations',key,dict(digest=digest(body),body=body,signature=signature,result=result))
            self.store.event('control',dict(operation=body['operation'],ref=key,actor=body['actor'],time=self.clock.now()))
        return result

    def _op_publish(self,actor,args,key):
        # A service root/eligible original ancestor manages only its subtree.
        # Publishing a description never grants caller spending rights.
        chain=args['chain'];require(all(x['body']['kind']=='authorization' and
            x['body']['right']['side']=='service' for x in chain),'SERVICE_CHAIN_ONLY')
        self._verify_chain(chain,args['identities'],True)
        info=copy.deepcopy(args['info']);member=self.right(info['member'])
        require(member['side']=='service' and member['context']==info['context'] and
                info['endpoint']==self.name and bool(info['service']),'SERVICE_INFO_BINDING')
        self._controller(actor,member['id'])
        info.update(identity=member['owner'],public_key=member['public_key'],
                    right=member,chain=chain,identities=args['identities'])
        directory_key=canonical([info['context'],info['service']]).decode()
        members=self.store.get('service_directory',directory_key,{})
        members[info['member']]=info;self.store.put('service_directory',directory_key,members)
        self.store.event('publish',dict(member=member['id'],context=info['context'],operation=key))
        return self.control.envelope(dict(kind='publish',operation=key,info=info))

    def _op_revoke(self,actor,args,key):
        target=args['id']
        if target.startswith(('task:','ctx:','coop:','source:')):
            if target.startswith('source:'):
                spec=self.store.get('sources',target[7:]);require(spec and actor==spec['controller'],'CONTROL_AUTHORITY')
            else:
                contexts=[c for c in self.store.all('contexts').values() if target in c['deps']]
                require(contexts and all(actor in (c['caller_approver'],c['service_approver']) for c in contexts),'CONTROL_AUTHORITY')
            dep=target
        else:
            overlay,_=self._verify_chain(args.get('chain',[]),args.get('identities',{}),False)
            self._controller(actor,target,overlay);dep='right:'+target
        prior=self.store.get('revoked',dep)
        if prior:return self.control.envelope(prior)
        result=dict(kind='revoke',dep=dep,operation=key,time=self.clock.now())
        self.store.put('revoked',dep,result);self.store.event('revoke',result)
        return self.control.envelope(result)

    def _op_return(self,actor,args,key):
        target=args['id'];self._controller(actor,target)
        original=self.right(target,False)
        require(any(self.store.get('revoked',d) for d in original['deps']),'RETURN_REQUIRES_REVOCATION')
        require(original['side']=='caller','SERVICE_HAS_NO_CALLER_BUDGET')
        returned=[];escrow=[];retired=[];records={};cap_cache={}
        def get_cap(gid):
            if gid not in cap_cache:cap_cache[gid]=self.forest.cap(gid)
            return cap_cache[gid]
        for unit,row in self.store.all('positions').items():
            if row['state']!='unused' or row.get('holder_right') is None:continue
            path=self.path(row['holder_right'])
            if target not in {r['id'] for r in path}:continue
            if row['deadline']<=self.clock.now()+self.margin:
                row['state']='retired';retired.append(unit);self.store.put('positions',unit,row);continue
            if self.store.get('revoked','source:'+row['source']):
                row['state']='escrow';escrow.append(unit);self.store.put('positions',unit,row);continue
            # Search the original authorization chain, not an arbitrary receiver.
            receiver=None
            for candidate in path[1:]:
                try:self.right(candidate['id']);receiver=candidate;break
                except Denied:pass
            if receiver is None:
                row['state']='escrow';escrow.append(unit);self.store.put('positions',unit,row);continue
            cap=get_cap(row['current_cap']['gid'])
            while cap['holder_right']!=receiver['id']:
                require(cap['key_parent']['kind']=='cap','RETURN_PARENT_CAP_MISSING')
                cap=get_cap(cap['key_parent']['id'])
            record='return-'+digest([key,receiver['id'],cap['gid']])
            records.setdefault(record,dict(receiver=receiver['id'],cap=cap['gid'],units=[]))['units'].append(unit)
            row.update(holder_right=receiver['id'],owner=receiver['owner'],current_cap=self.forest_binding(cap),
                ownership=record,version=row['version']+1)
            self._deadline(row['deadline'],'RETURN_UNIT_EXPIRED')
            # H_u, consumed state and all revocations are deliberately retained.
            self.store.put('positions',unit,row);returned.append(copy.deepcopy(row))
        result=dict(kind='return',operation=key,target=target,rows=returned,escrow=escrow,retired=retired,records=records,time=self.clock.now())
        for record,info in records.items():self.store.put('return_records',record,{**info,'operation':key})
        self.store.event('return',result)
        # Numeric versions are B-local concurrency state, not caller inputs.
        return self.control.envelope({**result,'rows':[{k:v for k,v in row.items() if k!='version'} for row in returned]})

    def _op_renew(self,actor,args,key):
        # A renewal is a NEW service-signed ACT/session, never an Authority lease.
        raise Denied('RENEW_REQUIRES_SERVICE_ACT')

    def session(self,lane,confirmation,installation,link,service_link):
        """Receive A's lane/confirmation and Rj's key installation separately."""
        from .roles import verified
        self.calls['session']+=1
        lane=json.loads(link.transfer(canonical(lane)));act=lane['act']['body']
        installation=json.loads(service_link.transfer(canonical(installation)))
        actor,receiver=act['caller'],act['receiver']
        verify_signature(self.registration(receiver)['public_key'],act,lane['act']['signature'])
        require(link.caller==actor and link.receiver==self.name and service_link.caller==receiver
            and service_link.receiver==self.name,'TLS_PARTICIPANT')
        installed=verified(installation,self.registration(receiver)['public_key'],protocol=PROTOCOL,endpoint=self.name,
            kind='contact-install',session=act['session'],service=receiver,act_digest=digest(lane['act']))
        channel_key=bytes.fromhex(installed['key'])
        verified(confirmation,self.registration(actor)['public_key'],protocol=PROTOCOL,endpoint=self.name,
            kind='contact-confirm',session=act['session'],caller=actor,act_digest=digest(lane['act']),
            confirmation=channel_mac(channel_key,canonical(lane['act'])))
        with self.store.transaction():
            caller=self.right(lane['caller']['id']);service=self.right(lane['service']['id']);ctx=self.context(caller['context'])
            require(caller['side']=='caller' and service['side']=='service' and service['context']==ctx['id'],'SESSION_CONTEXT')
            require(actor==caller['owner'] and receiver==service['owner'],'PARTICIPANTS')
            require(act['context']==ctx['id'] and act['caller_right']==caller['id'] and act['service_right']==service['id']
                and act['caller']==actor and act['receiver']==receiver and act['endpoint']==self.name,'ACT_BINDING')
            require(act['expires']<=min(ctx['deadline'],caller['deadline'],service['deadline'])
                and act['expires']>self.clock.now()+self.margin,'ACT_DEADLINE')
            self._deadline(act['expires'],'ACT_DEADLINE')
            c,s=self.registration(actor),self.registration(receiver)
            require(c['public_key']==caller['public_key'] and s['public_key']==service['public_key'],'IDENTITY_KEY_BINDING')
            binding=dict(scheme=SCHEME,context=ctx['id'],rule_snapshot=ctx['rule_snapshot'],cooperation=ctx['cooperation'],
                guard=self.name,lane=lane['id'],act=act['id'],caller_identity=actor,caller_key_version=c['key_ref'],
                service_identity=receiver,service_key_version=s['key_ref'],caller_right=caller['id'],service_right=service['id'],session=act['session'])
            session=dict(binding=binding,lane=lane['id'],key=channel_key.hex(),expires=act['expires'],act=lane['act'])
            prior=self.store.get('sessions',act['session'])
            if prior:
                require(prior==session,'SESSION_ID_CONFLICT')
            else:
                self.store.put('sessions',act['session'],session);self.store.put('lanes',lane['id'],lane)
                self.store.event('session',dict(id=act['session'],time=self.clock.now()))
        result=self.control.envelope(dict(protocol=PROTOCOL,endpoint=self.name,kind='session-receipt',
            lane_digest=digest(lane),session=session))
        return json.loads(link.transfer(canonical(result),reply=True))

    def session_act(self,lane,link):
        """Current contact: certified TLS caller plus service-signed ACT only.

        Persist public session bindings for exact retries. No application DH,
        confirmation MAC, secret key delivery, or service key-install RPC.
        The older session() is retained solely for compatibility regressions.
        """
        lane=json.loads(link.transfer(canonical(lane)));act=lane['act']['body']
        require(act.get('profile')=='tls-act-v1' and act['kind']=='ACT' and act['protocol']==PROTOCOL,'ACT_PROFILE')
        self.calls['session']+=1
        with self.store.transaction():
            caller=self.right(lane['caller']['id']);service=self.right(lane['service']['id']);ctx=self.context(caller['context'])
            c,s=self.registration(caller['owner']),self.registration(service['owner'])
            require(link.caller==caller['owner'] and link.caller_public==caller['public_key'] and link.receiver==self.name,'TLS_PARTICIPANT')
            verify_signature(service['public_key'],act,lane['act']['signature'])
            require(caller['side']=='caller' and service['side']=='service' and service['context']==ctx['id'],'SESSION_CONTEXT')
            require(act['endpoint']==self.name and act['context']==ctx['id'] and act['caller']==caller['owner']
                and act['receiver']==service['owner'] and act['caller_right']==caller['id'] and act['service_right']==service['id'],'ACT_BINDING')
            require(c['public_key']==caller['public_key'] and s['public_key']==service['public_key'],'IDENTITY_KEY_BINDING')
            require(self.clock.now()+self.margin<act['expires']<=min(ctx['deadline'],caller['deadline'],service['deadline']),'ACT_DEADLINE')
            self._deadline(act['expires'],'ACT_DEADLINE')
            binding=dict(scheme=SCHEME,context=ctx['id'],rule_snapshot=ctx['rule_snapshot'],cooperation=ctx['cooperation'],
                guard=self.name,lane=lane['id'],act=act['id'],caller_identity=caller['owner'],caller_key_version=c['key_ref'],
                service_identity=service['owner'],service_key_version=s['key_ref'],caller_right=caller['id'],service_right=service['id'],session=act['session'])
            session=dict(binding=binding,lane=lane['id'],expires=act['expires'],act=lane['act'],profile='tls-act-v1')
            prior=self.store.get('sessions',act['session']);require(prior is None or prior==session,'SESSION_ID_CONFLICT')
            if prior is None:
                self.store.put('sessions',act['session'],session);self.store.put('lanes',lane['id'],lane)
                self.store.event('session',dict(id=act['session'],time=self.clock.now(),profile='tls-act-v1'))
        result=self.control.envelope(dict(protocol=PROTOCOL,endpoint=self.name,kind='session-receipt',lane_digest=digest(lane),session=session))
        return json.loads(link.transfer(canonical(result),reply=True))

    def charge(self,packet,actual_operation,link):
        try:return self._charge(packet,actual_operation,link)
        except Denied as error:
            # No automatic request retry or ACT rewrite. Return an authenticated
            # discovery hint only after normal authentication reached revocation.
            if error.code in ('KNOWN_REVOKED','RIGHT_EXPIRED'):
                fields,_=decode(bytes.fromhex(packet['body']))
                lane=self.store.get('lanes',fields['lane'].decode())
                if lane:
                    info=lane['task_info']
                    error.directory=self.control.envelope(dict(protocol=PROTOCOL,endpoint=self.name,kind='directory-hint',
                        request_digest=digest(packet),context=info['context'],service=info['service'],
                        members=self._members(info['context'],info['service'])))
            raise

    def _charge(self,packet,actual_operation,link):
        """Authenticated lookup precedes expiry/revocation for exact retries."""
        self.calls['charge']+=1;delivered=json_message(link,packet)
        body=bytes.fromhex(delivered['body']);fields,vector=decode(body)
        session=self.store.get('sessions',fields['session'].decode())
        require(session and link.caller==session['binding']['caller_identity'] and link.receiver==self.name,'TLS_SESSION_IDENTITY')
        require(all(fields[k]==v.encode() for k,v in session['binding'].items()),'SESSION_BINDING')
        require(fields['full_payload']==canonical(delivered['payload']) and
                fields['actual_operation']==struct.pack('>I',ACTIONS[actual_operation]),'FULL_PAYLOAD_BINDING')
        modern=session.get('profile')=='tls-act-v1'
        if modern:
            require(link.caller_public==self.registration(link.caller)['public_key'],'TLS_CALLER_KEY')
            require(delivered.get('act')==session['act'] and 'channel' not in delivered,'REQUEST_ACT_BINDING')
        else:require(hmac.compare_digest(channel_mac(bytes.fromhex(session['key']),body),delivered['channel']),'CHANNEL_AUTHENTICATION')
        key=canonical([self.name,session['lane'],fields['context'].decode(),session['binding']['caller_right'],
            session['binding']['service_right'],session['binding']['session'],fields['request_id'].decode()]).decode()
        fp=digest(delivered) if modern else hashlib.sha256(body).hexdigest()
        try:
            with self.store.transaction() as transaction:
                old=self.store.get('requests',key)
                if old:
                    require(old['fingerprint']==fp,'REQUEST_ID_CONFLICT')
                    decision={**old['decision'],'replay':True}
                else:
                    caller=self.right(session['binding']['caller_right']);service=self.right(session['binding']['service_right'])
                    ctx=self.context(caller['context'])
                    require(actual_operation in ctx['req'] and actual_operation in caller['actions'] and actual_operation in service['actions'],'ACTION_SCOPE')
                    req=ctx['req'][actual_operation]
                    require([s for s,*_ in vector]==req and set(delivered['proofs'])==set(req),'REQUIRED_SOURCE_SET')
                    self._active(['source:'+s for s in req]);changes=[]
                    for source,slot,aid,gid,ownership in vector:
                        row=self.store.get('positions',position_key(source,slot))
                        require(row and row['state']=='unused','POSITION_SPENT_OR_FENCED')
                        require(row['endpoint']==self.name and row['context']==ctx['id'] and row['holder_right']==caller['id'],'POSITION_OWNER_OR_CONTEXT')
                        require(row['current_cap']==dict(anchor=aid,gid=gid,holder_right=caller['id']) and row['ownership']==ownership,'CURRENT_CAP_BINDING')
                        require(actual_operation in row['hard_actions'] and ctx['id'] in row['hard_contexts'],'HARD_LABEL')
                        if gid not in self.key_cache:self.key_cache[gid]=self.forest.rebuild(gid,self.key_cache)
                        require(hmac.compare_digest(self.key_cache[gid].tag(point(actual_operation,slot),body),delivered['proofs'][source]),'BAD_CAP_TAG')
                        changes.append(row)
                    deadline=min(session['expires'],ctx['deadline'],caller['deadline'],service['deadline'],*(r['deadline'] for r in changes))
                    self._deadline(deadline,'ACT_OR_HARD_EXPIRED')
                    for row in changes:
                        row['state']='spent';self.store.put('positions',position_key(row['source'],row['slot']),row)
                    decision=dict(key=key,lane=session['lane'],context=ctx['id'],operation=actual_operation,
                        participants=[caller['owner'],service['owner']],sources=[[r['source'],r['slot']] for r in changes],
                        cap_bindings=[r['current_cap'] for r in changes],ownerships=[r['ownership'] for r in changes],
                        versions=[r['version'] for r in changes],deps=sorted(set(caller['deps']+service['deps']+['source:'+s for s in req])),
                        decision_time=self.clock.now(),admission_tx=transaction['txid'],deadline=deadline,replay=False)
                    self.store.put('requests',key,dict(body=body.hex(),fingerprint=fp,decision=decision,
                        proofs=delivered['proofs'],channel=delivered.get('channel'),act=delivered.get('act'),authenticated_caller=link.caller))
                    self.store.put('forwarding',key,dict(state='pending',operation=actual_operation,payload=delivered['payload'],
                        service=service['owner'],service_right=service['id'],context=ctx['id']))
                    self.store.event('charge',decision)
        except Denied as error:
            # An authenticated request reached the decision lookup; this failed
            # transaction admitted nothing. Earlier authentication failures and
            # post-commit service failures do not establish non-consumption.
            if error.code!='REQUEST_ID_CONFLICT':error.admission_rejected=True
            raise
        # A retry only queries the durable decision. Explicit recovery drains
        # pending delivery to the ORIGINAL admitted member, never its replacement.
        if not decision['replay']:
            try:self.deliver(key)
            except Denied as error:
                # A service rejection after admission does not undo the debit.
                # The in-process transport exposes this phase to the client;
                # a real transport would need an authenticated status message.
                error.admitted=True;raise
        effect=self.store.get('effects',key)
        response={**{k:v for k,v in decision.items() if k!='versions'},
                  'delivery_state':self.store.get('forwarding',key)['state'],
                  'service_receipt':effect['receipt'] if effect else None}
        return json_message(link,response,reply=True)

    def deliver(self,key):
        # Deliberately synchronous research profile: service execution holds
        # this Store's global lock. body_ns/guard.charge include delivery and
        # handler time; this is not slow-service isolation or pure crypto cost.
        from .roles import check_envelope
        with self.store.lock:
            row=self.store.get('forwarding',key);require(row is not None,'NO_ADMISSION')
            if row['state']=='delivered':return
            # Durable attempted precedes the external call. A missing result
            # can mean execution happened: never invoke that service again.
            # This is at-most-one send attempt, not external exactly-once.
            if row['state']=='attempted':return
            require(row['state']=='pending','FORWARDING_STATE')
            require(not self.store.get('effects',key),'DUPLICATE_INITIAL_FORWARD')
            require(self.delivery is not None,'SERVICE_TRANSPORT_MISSING')
            message=self.control.envelope(dict(protocol=PROTOCOL,endpoint=self.name,kind='service-delivery',key=key,
                **{k:row[k] for k in ('operation','payload','service','service_right','context')}))
            message_digest=digest(message)
            with self.store.transaction():
                row['state']='attempted';row['delivery_digest']=message_digest
                self.store.put('forwarding',key,row)
            receipt=self.delivery(message)
            check_envelope(receipt,self.registration(row['service'])['public_key'],protocol=PROTOCOL,endpoint=self.name,
                kind='service-receipt',key=key,service=row['service'],service_right=row['service_right'],
                context=row['context'],delivery_digest=message_digest,payload_digest=digest(row['payload']))
            if self.store.commit_hook:self.store.commit_hook('after_service_response')
            with self.store.transaction():
                self.store.put('effects',key,dict(operation=row['operation'],payload=row['payload'],delivery=message,receipt=receipt))
                row['state']='delivered';self.store.put('forwarding',key,row)
                if self.store.commit_hook:self.store.commit_hook('before_delivery_completion')

    def resume_delivery(self):
        for key,row in self.store.all('forwarding').items():
            if row['state']=='pending':self.deliver(key)
