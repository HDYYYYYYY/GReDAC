"""Small logical roles and authenticated messages for GReDAC.

Roles hold their own signer and public peer records, never an Endpoint/Store.
The experiment owns process scheduling; these objects own protocol decisions.
TLS MemoryBIO is an in-process transport, not a network latency model.
"""
import copy,hashlib,json,threading
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .crypto import canonical,digest,ident,require,verify_signature,channel_mac

PROTOCOL='fixed-endpoint-v3.1'


def check_envelope(envelope,public,**bindings):
    """Verify all signature/binding checks when no returned body is needed."""
    body=envelope['body'];verify_signature(public,body,envelope['signature'])
    require(all(body.get(k)==v for k,v in bindings.items()),'RECEIPT_BINDING')


def verified(envelope,public,**bindings):
    """Authenticate, then return an isolated copy for consumers that use it."""
    check_envelope(envelope,public,**bindings)
    return copy.deepcopy(envelope['body'])


def shared_key(private,peer,body):
    secret=private.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(peer)))
    return HKDF(algorithm=hashes.SHA256(),length=32,salt=hashlib.sha256(canonical(body)).digest(),
                info=PROTOCOL.encode()).derive(secret)


class CallerContact:
    """A owns only A's signing key and ephemeral secret; peer data are public."""
    def __init__(self,signer,right,service,expires,chain=None,endpoint="G"):
        self.endpoint=endpoint
        self.signer,self.right,self.service=signer,right,service
        self.description=copy.deepcopy(dict(right=right,chain=chain or []))
        self.ephemeral=X25519PrivateKey.generate()
        self.init=dict(protocol=PROTOCOL,endpoint=self.endpoint,kind='contact-init',session=ident(),
            caller=signer.name,receiver=service['owner'],caller_right=right['id'],
            service_right=service['id'],context=right['context'],expires=expires,
            ephemeral=self.ephemeral.public_key().public_bytes_raw().hex())

    def begin(self):return self.signer.envelope({**self.init,'caller_description':self.description})

    def finish(self,response):
        act=verified(response,self.service['public_key'],**{**self.init,'kind':'ACT'})
        self.key=shared_key(self.ephemeral,act['responder_ephemeral'],act)
        body=dict(protocol=PROTOCOL,endpoint=self.endpoint,kind='contact-confirm',
            session=act['session'],caller=self.signer.name,act_digest=digest(response),
            confirmation=channel_mac(self.key,canonical(response)))
        return self.signer.envelope(body)


class ServiceRole:
    """One service identity. No caller secret, B ledger, or task planner.

    Default service is a deterministic echo. E3 installs its controlled SQL
    tool here. Business-state handover and external exactly-once are excluded.
    """
    def __init__(self,signer,right,chain,identities,endpoint_public,endpoint="G"):
        self.endpoint=endpoint
        self.signer,self.right=signer,copy.deepcopy(right)
        self.chain,self.identities=copy.deepcopy(chain),copy.deepcopy(identities)
        self.endpoint_public=endpoint_public;self.contacts={};self.handler=None

    def describe(self):
        return dict(right=self.right,chain=self.chain,identities=self.identities)

    def prove(self,body):return self.signer.sign(body)

    def respond(self,request,peer_public):
        # The descriptor is part of A's received signed message, not a Python
        # right injected by the experiment. B verifies the full chain at sync.
        received=verified(request,peer_public,protocol=PROTOCOL,endpoint=self.endpoint,kind='contact-init')
        caller=received['caller_description']['right']
        require(caller['public_key']==peer_public and caller['context']==self.right['context'],'CONTACT_CALLER_BINDING')
        init=verified(request,peer_public,protocol=PROTOCOL,endpoint=self.endpoint,kind='contact-init',
            caller=caller['owner'],caller_right=caller['id'],receiver=self.signer.name,
            service_right=self.right['id'],context=self.right['context'])
        require(init['expires']<=min(caller['deadline'],self.right['deadline']),'CONTACT_DEADLINE')
        ephemeral=X25519PrivateKey.generate()
        init.pop('caller_description')
        body={**init,'kind':'ACT','id':ident(),
              'responder_ephemeral':ephemeral.public_key().public_bytes_raw().hex()}
        act=self.signer.envelope(body);key=shared_key(ephemeral,init['ephemeral'],body)
        self.contacts[body['session']]=(act,key,caller)
        return act

    def install(self,confirmation):
        pending=self.contacts[confirmation['body']['session']];act,key,caller=pending
        verified(confirmation,caller['public_key'],protocol=PROTOCOL,endpoint=self.endpoint,kind='contact-confirm',
            session=act['body']['session'],caller=caller['owner'],act_digest=digest(act),
            confirmation=channel_mac(key,canonical(act)))
        return self.signer.envelope(dict(protocol=PROTOCOL,endpoint=self.endpoint,kind='contact-install',
            session=act['body']['session'],service=self.signer.name,act_digest=digest(act),key=key.hex()))

    def receive(self,envelope):
        """Accept only B-authenticated delivery bound to this exact member."""
        body=verified(envelope,self.endpoint_public,protocol=PROTOCOL,endpoint=self.endpoint,kind='service-delivery',
            service=self.signer.name,service_right=self.right['id'],context=self.right['context'])
        # The full admitted payload is delivered by B, never re-read from a
        # caller-side variable. Previously admitted work may arrive after revoke.
        result=self.handler(body) if self.handler else dict(payload_digest=digest(body['payload']))
        return self.signer.envelope(dict(protocol=PROTOCOL,endpoint=self.endpoint,kind='service-receipt',
            key=body['key'],service=self.signer.name,service_right=self.right['id'],
            context=self.right['context'],delivery_digest=digest(envelope),
            payload_digest=digest(body['payload']),result=result))


class ServiceTransport:
    """Small address book for local processes, not the authoritative directory.

    Routing resolves the identity B already admitted. Each thread owns its TLS
    record state. Reusing a connection avoids a new handshake per fine-grained
    message. Directory availability and authorization remain B's decisions.
    """
    def __init__(self,pki,endpoint="G"):self.pki=pki;self.endpoint=endpoint;self.members={};self.local=threading.local()

    def add(self,role):self.members[role.right['id']]=role

    def deliver(self,envelope):
        body=envelope['body'];role=self.members.get(body['service_right'])
        require(role and role.signer.name==body['service'],'SERVICE_ROUTE_IDENTITY')
        links=getattr(self.local,'links',None)
        if links is None:links={};self.local.links=links
        if role.signer.name not in links:links[role.signer.name]=self.pki.link(self.endpoint,role.signer.name)
        link=links[role.signer.name]
        received=json.loads(link.transfer(canonical(envelope)))
        response=role.receive(received)
        return json.loads(link.transfer(canonical(response),reply=True))


class ACTCallerContact:
    """Current GReDAC: TLS proves possession; service signs an ACT, no DH/MAC."""
    def __init__(self,signer,right,service,expires,chain=None,endpoint='G'):
        self.signer,self.right,self.service=signer,right,service
        self.init=dict(protocol=PROTOCOL,endpoint=endpoint,kind='contact-init',profile='tls-act-v1',
            session=ident(),caller=signer.name,receiver=service['owner'],caller_right=right['id'],
            service_right=service['id'],context=right['context'],expires=expires)
        self.description=dict(right=right,chain=chain or [])
    def begin(self):return {**self.init,'caller_description':self.description}
    def finish(self,act):
        return verified(act,self.service['public_key'],**{**self.init,'kind':'ACT'})


class ACTServiceRole(ServiceRole):
    """Reuses authenticated delivery receipts; no application key installation."""
    def respond(self,request,peer_public):
        caller=request['caller_description']['right']
        require(caller['public_key']==peer_public and caller['owner']==request['caller']
            and caller['id']==request['caller_right'] and caller['context']==self.right['context'],'CONTACT_CALLER_BINDING')
        require(request['protocol']==PROTOCOL and request['endpoint']==self.endpoint
            and request['profile']=='tls-act-v1' and request['receiver']==self.signer.name
            and request['service_right']==self.right['id'] and request['context']==self.right['context'],'ACT_BINDING')
        require(request['expires']<=min(caller['deadline'],self.right['deadline']),'CONTACT_DEADLINE')
        body={k:v for k,v in request.items() if k!='caller_description'}
        return self.signer.envelope({**body,'kind':'ACT','id':ident()})
