"""Driver adapter; caller-owned Wallets and exact retry packets remain unchanged."""
from dataclasses import dataclass, asdict
from ..network_client import Client
from gredac.crypto import Denied
from .codec import envelope,binding,classify_operation

@dataclass
class BridgeResult:
    admission_status: str
    delivery_state: str|None
    request_id: str
    message_id: str
    service_receipt: dict|None=None
    a2a_response: dict|None=None
    business_status: str='UNKNOWN'
    decision: dict|None=None
    error: str|None=None

    @classmethod
    def admitted(cls,result,request_id,message_id):
        receipt=result.get('service_receipt');business=receipt['body']['result'] if receipt else {}
        return cls('ADMITTED',result['delivery_state'],request_id,message_id,receipt,
                   business.get('a2a_response'),business.get('business_status','UNKNOWN'),result)

class BridgeClient(Client):
    def __init__(self,*args,**kwargs):
        self.cards={};self.requirements={};super().__init__(*args,**kwargs)
        self.mesh.call(self.endpoint_id,'a2a_enable')
    def context(self,cid,sources,**kw):
        super().context(cid,sources,**kw)
        self.requirements[cid]={op:list(sources) for op in ('query','summary')}
    def publish_service(self,rid,actor=None):
        r=self.rights[rid]
        if rid not in self.cards:
            self.cards[rid]=self.mesh.call(r['owner'],'a2a_service')['card']
        desc=self.mesh.call(r['owner'],'describe',right=rid)
        info=dict(context=r['context'],service=r['context'],member=rid,endpoint=self.endpoint_id,
            endpoint_address=self.identities[self.endpoint_id]['endpoint'],
            member_address=self.identities[r['owner']]['endpoint'],**binding(self.cards[rid],rid))
        return self.call(actor or self.rights[r['parent']]['owner'],'publish',
                         dict(info=info,chain=desc['chain'],identities=desc['identities']))
    def update_card(self,rid,version):
        self.cards[rid]=self.mesh.call(self.rights[rid]['owner'],'a2a_service',version=version)['card']
        return self.publish_service(rid)
    def payload(self,service,message_id,action='echo.read',arguments=None,application_case='fixture'):
        return envelope(service,self.cards[service],message_id,action,arguments,application_case)
    def send(self,wallet,request_id,message_id,action='echo.read',arguments=None,application_case='fixture'):
        value=self.payload(wallet.service,message_id,action,arguments,application_case)
        try:
            operation=classify_operation(value);cid=self.rights[wallet.holding.right]['context']
            sources=self.requirements.get(cid,{}).get(operation,sorted(wallet.selections))
            result=self.mesh.call(self.rights[wallet.holding.right]['owner'],'a2a_send',
                wallet=wallet.id,request_id=request_id,payload=value,sources=sources)
            return BridgeResult.admitted(result,request_id,message_id)
        except Denied as exc:
            return BridgeResult('REJECTED' if getattr(exc,'admission_rejected',False) else 'TRANSPORT_UNKNOWN',
                None,request_id,message_id,error=exc.code)
        except (OSError,ConnectionError):
            return BridgeResult('TRANSPORT_UNKNOWN',None,request_id,message_id,error='CONNECTION')
    def restart_endpoint(self):
        # Restore extension before pending recovery; the original core owns recovery.
        self.mesh.restart(self.endpoint_id)
        public=self.mesh.call(self.endpoint_id,'setup',kind='endpoint',authority_public=self.mesh.config['authority_public'],
            contact_seconds=self.contact_seconds,commit_delay_bound=self.commit_delay_bound)
        assert public==self.endpoint_public
        self.mesh.call(self.endpoint_id,'a2a_enable')
        return self.mesh.call(self.endpoint_id,'resume_delivery')
