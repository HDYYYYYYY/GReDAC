"""Optional GReDAC 1.2 adapter: one cooperation, one shared budget.

Both arms call the same controlled business handler. With-system results
must travel through B admission and the actual service's signed response.
Without-system has ordinary TLS identities but no Authority, capabilities,
quota ledger, revocation protocol or invented safety scores.
Model prompts/role changes and all business decisions remain in the scenes.
"""
import copy,time
from .support import write_json

class BusinessToolError(Exception):
    """A model-supplied business argument was rejected after valid admission."""

class AgentCommunicationError(RuntimeError):
    """Failure reaching/executing the role process, not a DeepSeek HTTP error."""

class TaskBackend:
    def __init__(self,run,case,enabled,roles):
        self.run,self.case,self.enabled=run,case,enabled;self.roles=roles
        self.spans=[];self.lab=None;self.counter=0;self.cursor=0;self.facts=None
        self.contexts={c:['B'] for c in ('plan','check','joint')}
        self.business_seconds=0.;self.delivery_evidence=[]
        self.perform('setup',self.setup)
        if self.lab is not None:self.mesh=self.lab.mesh
        else:
            from .network_client import Mesh
            self.mesh=Mesh(run.out/case/'network')
        for name in roles.values():self.mesh.add(name)
        self.mesh.call(roles['service'],'handler',kind='scene')
        self.active_caller=roles['lead'];self.active_service=roles['service']
        self.configured_models=set()
        run.manifest['transport']='independent Agent processes; mutual TLS1.3 over real loopback TCP'

    def perform(self,label,fn):
        if not self.enabled:return None
        start=time.monotonic()
        try:
            with self.run.phase('measurement'):return fn()
        finally:self.spans.append(dict(label=label,start=start,end=time.monotonic(),seconds=time.monotonic()-start))

    def setup(self):
        from .network_client import Client
        self.lab=lab=Client(self.run,self.case,contact_seconds=1800)
        lab.context('collaboration',['B'],tasks=['planning','checking'])
        lab.source('B',128,['collaboration'])
        self.root=lab.right('O-collaboration','O','collaboration')
        self.sroot=lab.right('R-collaboration','R','collaboration',side='service')
        self.service=lab.right('provider',self.roles['service'],'collaboration',self.sroot,side='service')
        self.root_holding=lab.seed(self.root,{'B':list(range(128))})
        rid=lab.right('lead',self.roles['lead'],'collaboration',self.root)
        self.holding=lab.delegate(self.root_holding,rid,{'B':list(range(128))})
        self.planner_holding=self.holding
        self.install_handler()
        self.wallet=lab.reserve(self.holding,self.service,{'B':list(range(128))})
        self.worker=self.roles['worker'];lab.freeze_setup()

    def install_handler(self):
        self.lab.set_handler(self.service,'scene')

    def set_facts(self,value):
        self.facts=value
        self.mesh.call(self.active_service,'facts',value=value)

    def save_artifact(self,name,value):
        self.mesh.call(self.active_service,'artifact',name=name,value=value)

    def ask_agent(self,api,identity,prompt,offered,observation,case,remaining):
        """Dispatch a task; the receiver owns history and performs the API call."""
        if identity not in self.configured_models:
            self.mesh.call(identity,'model_config',prompt=prompt,model=api.model,max_calls=api.limit,
                max_tokens=api.max_tokens,format_retries=getattr(api,'format_retries',0),test_profile=getattr(api,'test_profile',None),api_key=getattr(api,'key',None))
            self.configured_models.add(identity)
        left=min(remaining,api.limit-len(api.calls));assert left>0,'API budget exhausted'
        try:response=self.mesh.call(identity,'ask',offered=offered,observation=observation,case=case,remaining=left)
        except (OSError,ConnectionError,RuntimeError) as exc:
            raise AgentCommunicationError(type(exc).__name__+': '+str(exc)) from exc
        for row in response['calls']:
            row={**row,'index':len(api.calls),'actor_pid':response['pid']};api.calls.append(row)
            with (self.run.out/'api_calls.jsonl').open('a',encoding='utf-8') as f:f.write(__import__('json').dumps(row,ensure_ascii=False)+'\n')
        if 'error' in response:raise RuntimeError(response['error'])
        return response['arguments'],lambda value:self.mesh.call(identity,'feedback',call_id=response['call_id'],value=value)

    def delegate(self):
        def apply():
            lab=self.lab;rid=lab.right('worker',self.worker,'collaboration',self.holding.right)
            self.holding=lab.delegate(self.holding,rid,{'B':list(range(self.cursor,128))})
            self.wallet=lab.reserve(self.holding,self.service,{'B':list(range(self.cursor,128))})
        result=self.perform('delegate',apply);self.active_caller=self.roles['worker'];return result

    def spend(self,ctx,operation,payload):
        request=dict(task=ctx,request=payload)
        from gredac.crypto import digest
        fingerprint=digest(self.facts)
        if fingerprint!=getattr(self,'_sent_facts',None):
            self.mesh.call(self.active_service,'facts',value=self.facts);self._sent_facts=fingerprint
        if not self.enabled:
            # Same application request and receiver-side business tools, with
            # no authority, capability, quota or revocation protocol objects.
            return self.mesh.call(self.active_caller,'business_request',service=self.active_service,payload=request)
        def apply():
            self.counter+=1
            result=self.lab.consume_next(self.wallet,'request-'+str(self.counter),operation,request)
            self.cursor+=1
            receipt=result['service_receipt']
            self.delivery_evidence.append(dict(task=ctx,request=payload,receipt=receipt))
            return receipt['body']['result']
        return self.perform('spend:'+ctx,apply)

    def replace(self,side):
        new=self.roles['worker' if side=='caller' else 'service']+'Replacement'
        self.mesh.add(new)
        if side=='service':
            self.mesh.call(new,'handler',kind='scene');self.mesh.call(new,'facts',value=self.facts)
        def apply():
            lab=self.lab;old=self.wallet
            if side=='caller':
                lab.call(self.roles['lead'],'revoke',{'id':self.holding.right})
                returned,slots=lab.recovery(old,self.planner_holding.right,actor=self.roles['lead'])
                self.worker=self.roles['worker']+'Replacement'
                rid=lab.right('worker-replacement',self.worker,'collaboration',returned.right)
                self.holding=lab.delegate(returned,rid,slots)
                self.wallet=lab.reserve(self.holding,self.service,slots)
            else:
                # Service change does NOT return or recreate caller budget.
                lab.call('R','revoke',{'id':self.service})
                self.service=lab.right('provider-replacement',self.roles['service']+'Replacement',
                    'collaboration',self.sroot,side='service')
                self.install_handler()
                self.wallet=lab.recontact(old,{'B':list(range(self.cursor,128))})
                assert self.wallet.holding is old.holding
            self.after_replacement('plan',side,old)
        result=self.perform('replace:'+side,apply)
        if side=='caller':self.active_caller=new
        else:self.active_service=new
        return result

    def after_replacement(self,ctx,side,old):pass

    def close(self):
        resources={n:self.mesh.call(n,'stats') for n in self.mesh.processes}
        self.business_seconds=sum(r['business_seconds'] for r in resources.values())
        write_json(self.run.out/self.case/'role_resources.json',resources)
        if not self.enabled:
            self.mesh.close();return dict(protocol_present=False,business_tool_seconds=self.business_seconds)
        write_json(self.lab.path/'protocol_spans.json',self.spans)
        write_json(self.lab.path/'business_deliveries.json',self.delivery_evidence)
        breakdown=self.lab.breakdown();audit=self.lab.close()
        return dict(protocol_present=True,audit=audit,breakdown=breakdown,
            direct_seconds=sum(r['seconds'] for r in self.spans)-self.business_seconds,
            business_tool_seconds=self.business_seconds)
