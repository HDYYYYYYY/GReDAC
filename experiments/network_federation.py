"""Independent one-to-many cooperations using the common TCP Agent runtime."""
from gredac.crypto import canonical,digest,require
from .network_client import Client

class Cooperation:
    def __init__(self,run,name,units,endpoint,mesh,caller='A',service='S',connect=True):
        self.lab=lab=Client(run,name,contact_seconds=1800,endpoint_id=endpoint,mesh=mesh)
        self.name,self.source,self.units=name,'budget',units;self.used=set()
        lab.context(name,[self.source],tasks=['planning','checking'],cooperation=name);lab.source(self.source,units,[name])
        self.root=lab.right('O-'+name,'O',name);owner='R'+service
        self.service_root=lab.right('R-'+name,owner,name,side='service')
        self.service=lab.right('service-'+name,service,name,self.service_root,side='service')
        self.root_holding=lab.seed(self.root,{self.source:list(range(units))})
        rid=lab.right('caller-'+name,caller,name,self.root)
        self.holding=lab.delegate(self.root_holding,rid,{self.source:list(range(units))})
        lab.set_handler(self.service,'fixed',target=name);lab.freeze_setup();self.wallet=None
        if connect:self.connect()
    def handle(self,body):
        result=dict(target=self.name,value=digest(body['payload']),padding='')
        result['padding']='x'*(256-len(canonical(result)));return result
    def connect(self):
        self.wallet=self.lab.reserve(self.holding,self.service,{self.source:list(range(self.units))});return self.wallet
    def request(self,slot,rid,payload=None):
        payload=payload if payload is not None else dict(target=self.name,request=rid,padding='')
        if 'padding' in payload:
            payload={**payload,'padding':''};payload['padding']='p'*(1024-len(canonical(payload)))
        result=self.lab.charge(self.wallet,{self.source:slot},rid,payload=payload)
        require(result['service_receipt']['body']['result']==self.handle(dict(payload=payload)),'BUSINESS_RESULT')
        self.used.add(slot);return result
    def close(self):return self.lab.close()
