"""GReDAC parent-local signing/derivation and Authority-free contact.

No ledger is read here. A signed transfer is a proposal, not a reservation:
the endpoint later registers the full suffix atomically. Conflicting offline
proposals can both possess keys; only one can acquire current ownership.
"""
import copy
import hashlib
import threading
from dataclasses import dataclass,field
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .crypto import Bundle,canonical,cover,domain_for,by_slot,ident,digest,require,verify_signature
from .endpoint import PROTOCOL
from .guard import Wallet as WireWallet
from .storage import position_key


@dataclass
class Holding:
    right:str
    caps:dict=field(default_factory=dict)
    bundles:dict=field(default_factory=dict)
    records:dict=field(default_factory=dict)
    chain:list=field(default_factory=list)
    task_info:dict=field(default_factory=dict)
    # Surviving caller state only; no B lookup and no client-crash persistence.
    pending:dict=field(default_factory=dict)
    pending_lock:object=field(default_factory=threading.RLock,repr=False,compare=False)

    def uncertain_units(self):
        with self.pending_lock:
            return {position_key(s,i) for p in self.pending.values() for s,i in p['selections'].items()}


def authorize(parent,child,body,endpoint='G',prove_child=True):
    require(body['parent']==parent['id'] and body['context']==parent['context'],'LOCAL_PARENT')
    require(set(body['actions'])<=set(parent['actions']) and body['deadline']<=parent['deadline']
            and 0<=body['depth']<parent['depth'],'LOCAL_WIDENING')
    body={**body,'deps':sorted(set(parent['deps']+['right:'+body['id']]))}
    description=dict(protocol=PROTOCOL,endpoint=endpoint,kind='authorization',parent=parent['id'],
                     context=parent['context'],right=body)
    if prove_child:description['child_proof']=child.sign(body)
    else:description['identity_binding']='registered-tls-key'
    return body,description


def transfer(parent,child,selections,actions,signer,domains=None):
    """One description binds exact joint action-slot domains and predecessor records."""
    grouped={};previous={};tid=ident();out=Holding(child,task_info=copy.deepcopy(parent.task_info))
    endpoint=parent.task_info.get('endpoint','G')
    # Explicit domains express a relation, not its Cartesian closure. Every
    # selected unit must occur, but its allowed actions can differ from peers.
    allowed={s:by_slot(d) for s,d in domains.items()} if domains is not None else {
        s:{i:sorted(actions) for i in slots} for s,slots in selections.items()}
    require(set(allowed)==set(selections) and all(set(allowed[s])==set(v)
        for s,v in selections.items()),'LOCAL_DOMAIN_SELECTION')
    uncertain=parent.uncertain_units()
    for source,slots in selections.items():
        for slot in slots:
            k=position_key(source,slot);row=parent.records[k]
            require(k not in uncertain,'LOCAL_OUTCOME_UNCERTAIN')
            require(allowed[source][slot] and set(allowed[source][slot])<=set(row['hard_actions']),'LOCAL_HARD_LABEL')
            grouped.setdefault((source,row['current_cap']['gid']),[]).append(slot)
            previous[k]=row['ownership']
    for (source,gid),slots in grouped.items():
        old=parent.caps[gid];domain=sorted(p for i in slots for p in domain_for(allowed[source][i],[i]));new=ident()
        require(old['guard']==endpoint,'LOCAL_ENDPOINT_BINDING')
        cap=dict(gid=new,anchor=old['anchor'],source=source,context=old['context'],guard=endpoint,
                 holder_right=child,key_parent=dict(kind='cap',id=gid),domain=domain,
                 cover=list(cover(domain)),operation=tid)
        out.caps[new]=cap;out.bundles[new]=parent.bundles[gid].child(new,domain)
        for slot in slots:
            k=position_key(source,slot);row=copy.deepcopy(parent.records[k])
            row.update(holder_right=child,current_cap=dict(anchor=cap['anchor'],gid=new,holder_right=child),
                       ownership=tid,hard_actions=sorted(allowed[source][slot]))
            out.records[k]=row
    require(grouped,'EMPTY_TRANSFER')
    body=dict(protocol=PROTOCOL,endpoint=endpoint,kind='transfer',id=tid,parent=parent.right,
              child=child,context=next(iter(out.caps.values()))['context'],caps=list(out.caps.values()),previous=previous)
    return out,signer.envelope(body)


def receive_delegation(payload,child,parent_public,endpoint='G',parent_right=None):
    """Receive through the parent's authenticated confidential channel.

    No sender Holding or ledger is an input. Verify the immediate parent and
    intended child, then rebuild independent bundles/records from received
    bytes. B still verifies the complete ancestry and actual ownership at sync.
    The TLS channel authenticates auxiliary records and secret key material;
    the signed transfer binds the capability scopes and predecessor records.
    """
    require(parent_right is not None and parent_right['id']==child['parent']
        and parent_right['public_key']==parent_public and parent_right['context']==child['context']
        and parent_right['side']==child['side'],'AUTHENTICATED_PARENT_REQUIRED')
    signed=payload['description'];body=signed['body'];auth=payload['authorization']
    verify_signature(parent_public,body,signed['signature'])
    verify_signature(parent_public,auth['body'],auth['signature'])
    require(body['protocol']==PROTOCOL and body['endpoint']==endpoint and body['kind']=='transfer'
        and body['child']==child['id'] and body['parent']==child['parent']
        and body['context']==child['context'],'CHILD_DELIVERY_BINDING')
    require(auth['body']['kind']=='authorization' and auth['body']['right']==child
        and auth['body']['parent']==child['parent'],'CHILD_AUTHORIZATION_BINDING')
    if 'child_proof' in auth['body']:verify_signature(child['public_key'],child,auth['body']['child_proof'])
    else:require(auth['body'].get('identity_binding')=='registered-tls-key','CHILD_IDENTITY_MODE')
    require(payload['chain'][-2:]==[auth,signed],'CHILD_CHAIN_BINDING')
    out=Holding(child['id'],chain=copy.deepcopy(payload['chain']),task_info=copy.deepcopy(payload['task_info']))
    require(out.task_info['context']==child['context'] and out.task_info['endpoint']==endpoint,'CHILD_TASK_BINDING')
    require(set(payload['keys'])=={c['gid'] for c in body['caps']},'CHILD_KEY_SET')
    for received in body['caps']:
        cap=copy.deepcopy(received);gid=cap['gid'];material=payload['keys'][gid]
        require(cap['holder_right']==child['id'] and cap['context']==child['context']
            and cap['operation']==body['id'] and cap['guard']==endpoint,'CHILD_CAP_BINDING')
        require(cap['cover']==list(cover(cap['domain'])) and sorted(material)==cap['cover'],'CHILD_KEY_COVER')
        seeds={p:bytes.fromhex(k) for p,k in material.items()}
        require(all(len(k)==32 for k in seeds.values()),'CHILD_KEY_LENGTH')
        out.caps[gid]=cap;out.bundles[gid]=Bundle(gid,cap['anchor'],tuple(cap['domain']),seeds)
        for slot,actions in by_slot(cap['domain']).items():
            k=position_key(cap['source'],slot);row=copy.deepcopy(payload['records'][k])
            require(k not in out.records and row['source']==cap['source'] and row['slot']==slot
                and row['holder_right']==child['id'] and row['ownership']==body['id']
                and row['current_cap']==dict(anchor=cap['anchor'],gid=gid,holder_right=child['id'])
                and row['hard_actions']==actions and row['context']==child['context']
                and row['endpoint']==endpoint,'CHILD_RECORD_BINDING')
            row.update(owner=child['owner'],deadline=min(row['deadline'],child['deadline']))
            out.records[k]=row
    require(set(out.records)==set(payload['records'])==set(body['previous']),'CHILD_RECORD_SET')
    return out


def establish(caller,receiver,caller_right,service_right,context,expires):
    """Two identity signatures, ephemeral X25519/HKDF and service-signed ACT.

    Identity registration is independent PKI, not per-contact task approval.
    This is an in-process cryptographic contact, NOT a network RTT measurement.
    """
    c,s=X25519PrivateKey.generate(),X25519PrivateKey.generate()
    init=dict(protocol=PROTOCOL,endpoint='G',session=ident(),context=context,
              caller=caller.name,receiver=receiver.name,caller_right=caller_right['id'],
              service_right=service_right['id'],ephemeral=c.public_key().public_bytes_raw().hex(),
              responder_ephemeral=s.public_key().public_bytes_raw().hex(),expires=expires)
    proof=caller.sign(init);verify_signature(caller_right['public_key'],init,proof)
    salt=hashlib.sha256(canonical(init)).digest()
    def kdf(shared):return HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=PROTOCOL.encode()).derive(shared)
    key=kdf(c.exchange(s.public_key()));require(key==kdf(s.exchange(c.public_key())),'KEY_CONFIRMATION')
    act=receiver.envelope({**init,'id':ident(),'kind':'ACT','caller_proof':proof})
    verify_signature(service_right['public_key'],act['body'],act['signature'])
    return act,key,init


class Wallet(WireWallet):
    """Reuse canonical wire codec; its historical `install` field carries ell.

    It is an immutable ownership record, not an installation or reservation.
    There is no second allocation ledger. This alias changes no cryptography.
    """
    def packet(self,operation,request_id,selection,payload=None,**kwargs):
        # ACT authenticates a participant pair, not a frozen quota list. Use
        # caller-held records for new requests; prepare() retains exact bytes
        # for retries, so later ownership changes cannot silently rewrite them.
        rows={}
        for s,i in selection.items():
            row=self.holding.records[position_key(s,i)]
            rows[s,i]={**row,'install':row['ownership']}
        rows.update(kwargs.pop('row_overrides',None) or {})
        # Reuse the canonical codec without scanning a historical unit list on
        # every request. Do not mutate the original wallet or pending packets.
        codec=WireWallet({**self.lane,'rows':[]},self.holding,self.session,self.channel_key,self.link)
        return codec.packet(operation,request_id,selection,payload,row_overrides=rows,**kwargs)

    def prepare(self,operation,request_id,selections,payload=None):
        """Keep exact retry bytes until authenticated resolution, across ACTs.

        One holding shares pending state across its sessions. Completed records
        remain B-authoritative: this blocks only unconfirmed units, not the
        deliberate stale/spent requests used by security tests.
        """
        payload={'text':request_id} if payload is None else payload
        intent=digest([operation,selections,payload])
        with self.holding.pending_lock:
            old=self.holding.pending.get(request_id)
            if old:
                require(old['intent']==intent,'PENDING_REQUEST_CONFLICT');return old
            require(not {position_key(s,i) for s,i in selections.items()}&self.holding.uncertain_units(),
                    'LOCAL_OUTCOME_UNCERTAIN')
            pending=dict(intent=intent,packet=self.packet(operation,request_id,selections,payload),
                operation=operation,request_id=request_id,selections=copy.deepcopy(selections),
                session=copy.deepcopy(self.session),service=copy.deepcopy(self.lane['service']),
                caller=copy.deepcopy(self.lane['caller']),link=self.link)
            self.holding.pending[request_id]=pending
            return pending

    def resolve(self,pending,spent):
        with self.holding.pending_lock:
            if spent:
                for s,i in pending['selections'].items():self.holding.records[position_key(s,i)]['state']='spent'
            if self.holding.pending.get(pending['request_id']) is pending:
                del self.holding.pending[pending['request_id']]
