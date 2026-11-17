"""GReDAC role assembly shared by independent experiment drivers.

This module contains no experiment schedule and reads no other run's output.
Each cooperation has one immutable budget bound to its own endpoint. An
optional shared PKI/signers dictionary represents the *same* caller identity
across cooperations, not different keys given the same display name.
"""
from gredac.crypto import canonical,digest,require
from gredac.storage import position_key
from .local_client import Client


class Cooperation:
    def __init__(self,run,name='c',units=128,endpoint='G',pki=None,signers=None,
                 caller='A',service='S',connect=True):
        self.lab=lab=Client(run,name,contact_seconds=1800,endpoint_id=endpoint,
                           shared_pki=pki,shared_signers=signers)
        self.name=name;self.source='budget';self.units=units
        lab.context(name,[self.source],tasks=['planning','checking'],cooperation=name)
        lab.source(self.source,units,[name])
        self.root=lab.right('O-'+name,'O',name)
        # Each service has a distinct owner Agent, while UR remains the initial
        # approving organisation. Registration is setup, not service discovery.
        owner='R'+service
        if owner not in lab.identities:
            lab.identities[owner]=lab.authority.bootstrap_identity(lab.actor(owner),'UR')
        self.service_root=lab.right('R-'+name,owner,name,side='service')
        self.service=lab.right('service-'+name,service,name,self.service_root,side='service')
        self.root_holding=lab.seed(self.root,{self.source:list(range(units))})
        rid=lab.right('caller-'+name,caller,name,self.root)
        self.holding=lab.delegate(self.root_holding,rid,{self.source:list(range(units))})
        lab.roles[self.service].handler=self.handle
        lab.freeze_setup()
        self.wallet=None;self.used=set()
        if connect:self.connect()

    def handle(self,body):
        """Controlled business service: compute from the authenticated payload.

        Returning a digest plus padding gives exactly 256 bytes of business
        result under canonical JSON. Correctness is checked by the caller,
        using its own request, only after verifying the actual service receipt.
        """
        result=dict(target=self.name,value=digest(body['payload']),padding='')
        result['padding']='x'*(256-len(canonical(result)))
        return result

    def connect(self):
        self.wallet=self.lab.reserve(self.holding,self.service,
            {self.source:list(range(self.units))})
        return self.wallet

    def request(self,slot,rid,payload=None):
        payload=payload if payload is not None else dict(target=self.name,request=rid,padding='')
        if 'padding' in payload:
            payload={**payload,'padding':''}
            payload['padding']='p'*(1024-len(canonical(payload)))
        result=self.lab.charge(self.wallet,{self.source:slot},rid,payload=payload)
        business=result['service_receipt']['body']['result']
        require(business==self.handle(dict(payload=payload)),'BUSINESS_RESULT')
        self.used.add(slot)
        return result

    def close(self):return self.lab.close()

