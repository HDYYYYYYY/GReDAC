"""Public experiment facade; private role state lives only in child processes.

Driver handles below contain IDs and public metadata, never GGM seeds,
session keys, remote database connections or model histories. RPC timings
include real loopback TLS/TCP plus process scheduling. Actor startup/setup
is measured separately; it must not be described as cryptographic cost.
"""
import hashlib,json,multiprocessing,os,ssl,time,threading
from pathlib import Path
from types import SimpleNamespace
from gredac.crypto import Signer,SCHEME,ident,domain_for,canonical
from gredac.pki import PKI
from gredac.rpc import Client as RPC
from .support import write_json

class Mesh:
    live=[]
    def __init__(self,path,pq=False,optimize_initial_config=False,shared_authority=None):
        self.path=Path(path);self.path.mkdir(parents=True,exist_ok=True)
        self.pq=pq;self.driver=Signer('Driver')
        if pq:
            raise ValueError('Unsupported comparator profile; use the author SAGA adapter or GReDAC')
        else:
            self.pki=PKI(self.path/'pki');reg=self.pki.issue('Driver',self.driver.public,self.pki.csr(self.driver),'controller');self.pki.materialize(self.driver,reg)
        self.routes={'Driver':dict(public=self.peer_pin(reg),port=0,pid=os.getpid())}
        self.registrations={'Driver':reg};self.processes={};self.config={};self.closed=False
        self.scopes=[];self.frozen_authorities=set()
        # RQ4 A/B opt-in deployment: one TLS Authority process, one existing
        # Node/SetupAuthority/SQLite store (and signing key) per cooperation.
        self.shared_authority=shared_authority
        # Public bootstrap metadata only; never an authorization-result cache.
        # Opt-in callers must end this mode before contacts/runtime/recovery.
        self.optimize_initial_config=optimize_initial_config;self._config_acked={}
        self.config_distribution=dict(full=0,delta=0,skipped=0,failed=0,
            route_entries=0,registration_entries=0,scalar_entries=0)
        self.rpc=RPC(self.path/'pki','Driver',self.routes,self.path/'driver-rpc.jsonl')
        self.live.append(self)
        self.resource_rows=[];self.resource_stop=threading.Event()
        self.resource_thread=threading.Thread(target=self.sample_loop,daemon=True);self.resource_thread.start()
    def sample_resources(self):
        from gredac.metrics import process_snapshot
        roles={'Driver':os.getpid(),**{n:p.pid for n,p in list(self.processes.items())}}
        self.resource_rows.append(dict(time=time.monotonic(),roles={n:process_snapshot(pid) for n,pid in roles.items()}))
    def sample_loop(self):
        while not self.resource_stop.wait(1):self.sample_resources()
    def peer_pin(self,reg):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(reg['certificate'])).hexdigest() if self.pq else reg['public_key']
    def add(self,name,owner='agent'):
        if name in self.processes:return self.registrations[name]
        from .network_actor import process_main
        ctx=multiprocessing.get_context('spawn');parent,child=ctx.Pipe()
        process=ctx.Process(target=process_main,args=(name,str(self.path/'pki'),str(self.path/'actors'/name),child),name='agent-'+name,daemon=True)
        process.start();child.close();assert parent.poll(30),'actor bootstrap timeout'
        public=parent.recv();reg=self.registrations.get(name)
        if reg is None:
            reg=self.pki.issue(name) if self.pq else self.pki.issue(name,public['public'],public['csr'],owner)
            reg['public_key']=public['public']
        assert reg['public_key']==public['public'],'restart changed identity'
        bootstrap=self.routes if not self.shared_authority else {n:r for n,r in self.routes.items() if n in ('Driver',name)}
        parent.send(reg);parent.send(bootstrap);assert parent.poll(30),'actor listener timeout'
        address=parent.recv();parent.close()
        reg['endpoint']='tls://127.0.0.1:'+str(address['port'])+'/'+name
        self.registrations[name]=reg;self.routes[name]={**address,'public':self.peer_pin(reg)};self.processes[name]=process
        self.configure();return reg
    def configure(self,**values):
        self.config.update(values)
        versions=self._public_config_versions() if self.optimize_initial_config else None
        for name,process in self.processes.items():
            if process.is_alive() and name not in self.frozen_authorities:
                # Server TLS checks run before scope dispatch. Its public pin
                # map must contain the union of this identity's cooperations,
                # while an individual scoped Node receives only its members.
                members=None
                if self.shared_authority:
                    members={'Driver',name}
                    for scope in self.scopes:
                        if name in scope.members:members.update(scope.members)
                self._send_configuration(name,self.config,versions=versions,members=members)
        for scope in self.scopes:scope._configure_receivers(versions)
        write_json(self.path/'processes.json',dict(driver_pid=os.getpid(),roles=self.routes,transport='mutual TLS1.3 over loopback TCP'))
    @staticmethod
    def _config_versions(values):
        # Hash values now: registration endpoints can be mutated in place on
        # restart. Retaining references would miss those changes.
        return {k:hashlib.sha256(canonical(v)).digest() for k,v in values.items()}
    def _public_config_versions(self):
        return dict(routes=self._config_versions(self.routes),registrations=self._config_versions(self.registrations))
    def _send_configuration(self,name,values,scope=None,versions=None,members=None):
        scope_arg={} if scope is None else {'_scope':scope}
        routes=self.routes if members is None else {n:r for n,r in self.routes.items() if n in members}
        registrations=self.registrations if members is None else {n:r for n,r in self.registrations.items() if n in members}
        if not self.optimize_initial_config:
            return self.call(name,'configure',routes=routes,registrations=registrations,**values,**scope_arg)
        versions=versions if versions is not None else self._public_config_versions()
        if members is not None:versions={group:{n:h for n,h in hashes.items() if n in members} for group,hashes in versions.items()}
        current={**versions,'values':self._config_versions(values)}
        # New process OR cooperation always receives the entire configuration.
        key=(name,self.processes[name].pid,scope);previous=self._config_acked.get(key)
        maps=dict(routes=routes,registrations=registrations,values=values)
        delta={group:{k:maps[group][k] for k,h in hashes.items()
            if previous is None or previous[group].get(k)!=h} for group,hashes in current.items()}
        if previous is not None and not any(delta.values()):
            self.config_distribution['skipped']+=1;return
        kind='full' if previous is None else 'delta';self.config_distribution[kind]+=1
        for group,metric in [('routes','route_entries'),('registrations','registration_entries'),('values','scalar_entries')]:
            self.config_distribution[metric]+=len(delta[group])
        try:
            result=self.call(name,'configure',routes=delta['routes'],registrations=delta['registrations'],**delta['values'],**scope_arg)
        except BaseException:
            self.config_distribution['failed']+=1;raise
        # Only successful real TCP/TLS delivery advances the public snapshot.
        self._config_acked[key]=current;return result
    def finish_initial_configuration(self):
        if not self.optimize_initial_config:return
        self.optimize_initial_config=False;self._config_acked.clear()
        write_json(self.path/'initial_config_distribution.json',dict(**self.config_distribution,
            ended_monotonic=time.monotonic(),enabled_after_preparation=False,
            scope='public bootstrap configuration only; counts include attempted sends; bytes in driver-rpc.jsonl'))
    def call(self,destination,method,**args):return self.rpc.call(destination,method,**args)
    def restart(self,name):
        process=self.processes.pop(name);process.join(3);assert not process.is_alive(),'only an exited process can restart'
        return self.add(name)
    def close(self):
        if self.closed:return
        self.sample_resources();self.resource_stop.set();self.resource_thread.join()
        write_json(self.path/'process_resources.json',dict(samples=self.resource_rows,
            scope='all role PIDs and driver; periodic simultaneous RSS; CPU/I/O lifetime counters; no summation of nested RPC wall times',
            crash_limitation='exited PIDs may have only last sampled counters, a lower bound; no imputed crash interval'))
        for name,p in self.processes.items():
            if p.is_alive():
                try:self.call(name,'stop')
                except (ConnectionError,OSError):pass
        for p in self.processes.values():
            p.join(5)
            if p.is_alive():p.terminate();p.join(5)
        self.rpc.close();self.closed=True

class ScopedMesh:
    """Same identity/process across independent cooperation namespaces."""
    def __init__(self,mesh,scope):
        self.base,self.scope=mesh,scope;self.config={};self.members=set();mesh.scopes.append(self)
        self.frozen_authorities=set()
        self.registrations,self.routes=mesh.registrations,mesh.routes
    @property
    def processes(self):return {n:self.base.processes[n] for n in self.members if n in self.base.processes}
    def add(self,name,owner='agent'):
        new_member=name not in self.members;existing=name in self.base.processes
        self.members.add(name);reg=self.base.add(name,owner)
        # Adding an already-running identity to a new cooperation still needs
        # the outer TLS pin union updated before any scoped peer messages.
        if self.base.shared_authority and new_member and existing:self.base.configure()
        self.configure();return reg
    def call(self,destination,method,**args):return self.base.call(destination,method,_scope=self.scope,**args)
    def configure(self,**values):
        self.config.update(values)
        self._configure_receivers()
    def _configure_receivers(self,versions=None):
        if self.base.optimize_initial_config and versions is None:versions=self.base._public_config_versions()
        for name,process in self.processes.items():
            if process.is_alive() and name not in self.base.frozen_authorities and name not in self.frozen_authorities:
                members=self.members|{'Driver'} if self.base.shared_authority else None
                self.base._send_configuration(name,self.config,self.scope,versions,members)
    def close(self):pass # Federation owns the shared process set.

class HoldingRef:
    def __init__(self,right):self.right=right

class WalletRef:
    def __init__(self,value,holding):
        self.id=value['id'];self.holding=holding;self.service=value['service'];self.selections=value['selections'];self.expires=value['expires']
        self.lane={'rows':[dict(source=s,slot=i) for s,v in self.selections.items() for i in v], 'service':{'id':self.service}}

class Client:
    def __init__(self,run,case,contact_seconds=1800,endpoint_id='G',mesh=None,**unused):
        self.run,self.case=run,case;self.path=run.out/case;self.path.mkdir(parents=True,exist_ok=False)
        self.mesh=ScopedMesh(mesh,endpoint_id) if mesh is not None else Mesh(self.path/'network');self.own_mesh=mesh is None
        self.endpoint_id=endpoint_id;self.authority_id=(mesh.shared_authority or 'Authority'+endpoint_id) if mesh is not None else 'Authority';self.contact_seconds=contact_seconds
        self.rights={};self.chains={};self.holdings={};self.initialized=set();self.service_ids=[];self.frozen=False
        self.deadline=time.monotonic()+7200;self.identities=self.mesh.registrations
        self.commit_delay_bound=float(os.environ.get('GREDAC_COMMIT_DELAY_BOUND','0.05'))
        assert self.commit_delay_bound>=0
        roots=('UO','UR','O') if mesh is not None and mesh.shared_authority else ('UO','UR','O','R')
        for name in (*roots,self.authority_id,endpoint_id):self.mesh.add(name)
        authority_public=self.mesh.call(self.authority_id,'setup',kind='authority')
        self.endpoint_public=self.mesh.call(endpoint_id,'setup',kind='endpoint',authority_public=authority_public,contact_seconds=contact_seconds,
            commit_delay_bound=self.commit_delay_bound)
        self.mesh.configure(endpoint=endpoint_id,authority=self.authority_id,authority_public=authority_public,endpoint_public=self.endpoint_public)
        run.manifest.update(transport='independent role processes; mutual TLS1.3/TCP over 127.0.0.1',
            measurement='actual single-host multiprocess network timings; not WAN latency',
            role_state='Agent private keys, capabilities, sessions and model histories stay in owner processes',
            deadline_assumptions=dict(clock_error_seconds=0,check_to_commit_bound_seconds=self.commit_delay_bound,
                scope='single-host monotonic; bound is assumed and observed per commit, not proven; process restart only, no host reboot'))
    def measure(self,label,fn,**metadata):return self.run.measure(self.case,label,fn,**metadata)
    def ensure(self,name):return self.mesh.add(name)
    def actor(self,name):
        reg=self.ensure(name);return SimpleNamespace(public=reg['public_key'],name=name)
    def call(self,actor,operation,args):
        self.ensure(actor)
        if operation in ('context','source','right','seed'):
            assert not self.frozen
            return self.measure('authority.'+operation,lambda:self.mesh.call(actor,'initial_control',operation=operation,args=args))
        if operation=='revoke' and args['id'] in self.chains:
            chain=self.chains[args['id']];names={x['body']['right']['owner'] for x in chain if x['body']['kind']=='authorization'}
            args={**args,'chain':chain,'identities':{n:self.identities[n] for n in names}}
        return self.measure('endpoint.'+operation,lambda:self.mesh.call(actor,'control',operation=operation,args=args))
    def context(self,cid,sources,tasks=None,cooperation='g'):
        body=dict(id=cid,tasks=tasks or [cid],cooperation=cooperation,caller_approver='UO',service_approver='UR',
            caller_root='O-'+cid,service_root='R-'+cid,req={op:sources for op in ('query','summary')},basis={s:s for s in sources},
            deadline=self.deadline,scheme=SCHEME,endpoint=self.endpoint_id)
        self.call('UO','context',dict(body=body,approvals={n:self.mesh.call(n,'sign',body=body) for n in ('UO','UR')}))
    def source(self,source,size,contexts):
        return self.call('UO','source',dict(id=source,issuer='UO',controller='UO',approval='issue-'+source,size=size,
            contexts=contexts,basis=source,actions=['query','summary'],deadline=self.deadline,endpoint=self.endpoint_id))
    def right(self,rid,holder,cid,parent=None,side='caller',actions=None):
        reg=self.ensure(holder);par=self.rights[parent] if parent else None
        body=dict(id=rid,owner=holder,context=cid,side=side,parent=parent,actions=sorted(actions or ['query','summary']),
            public_key=reg['public_key'],deadline=min(self.deadline,par['deadline']) if par else self.deadline,depth=par['depth']-1 if par else 32)
        if parent:
            result=self.mesh.call(par['owner'],'authorize_child',parent=parent,body=body);body=result['right'];chain=result['chain']
        else:
            signed=self.call('UO' if side=='caller' else 'UR','right',{**body,'proof':self.mesh.call(holder,'sign',body=body)})
            body=signed['body']
            chain=[];self.mesh.call(holder,'install_right',right=body,chain=chain,root_proof=signed)
        self.rights[rid]=body;self.chains[rid]=chain;self.holdings[rid]=HoldingRef(rid)
        if side=='service' and parent:
            self.service_ids.append(rid)
            if cid in self.initialized:self.publish_service(rid)
        return rid
    def publish_service(self,rid,actor=None):
        r=self.rights[rid];desc=self.mesh.call(r['owner'],'describe',right=rid)
        info=dict(context=r['context'],service=r['context'],member=rid,endpoint=self.endpoint_id,
            endpoint_address=self.identities[self.endpoint_id]['endpoint'],member_address=self.identities[r['owner']]['endpoint'])
        return self.call(actor or self.rights[r['parent']]['owner'],'publish',dict(info=info,chain=desc['chain'],identities=desc['identities']))
    def seed(self,rid,selections,domains=None):
        caps=self.call('UO','seed',dict(right=rid,domains=domains if domains is not None else {s:domain_for(['query','summary'],v) for s,v in selections.items()}))
        self.mesh.call(self.authority_id,'initial_package',right=rid,caps=caps)
        r=self.rights[rid];self.initialized.add(r['context']);candidates=[s for s in self.service_ids if self.rights[s]['context']==r['context']]
        for s in candidates:self.publish_service(s)
        info=dict(context=r['context'],service=r['context'],endpoint=self.endpoint_id,
            endpoint_address=self.identities[self.endpoint_id]['endpoint'],known_member=candidates[0] if candidates else None)
        service_root=next(x for x in self.rights.values() if x['context']==r['context'] and x['side']=='service' and x['parent'] is None)
        self.mesh.call(service_root['owner'],'send_task_info',recipient=r['owner'],right=rid,info=info);return self.holdings[rid]
    def delegate(self,parent,rid,selections,actions=None,domains=None):
        self.measure('parent.derive_deliver',lambda:self.mesh.call(self.rights[parent.right]['owner'],'delegate',parent=parent.right,
            child=rid,selections=selections,actions=actions or ['query','summary'],domains=domains))
        # Public chain retrieval is a signed-description interface, not a ledger read.
        self.chains[rid]=self.mesh.call(self.rights[rid]['owner'],'holding_chain',right=rid)
        return self.holdings[rid]
    def discover(self,holding,known=None):return self.mesh.call(self.rights[holding.right]['owner'],'discover',right=holding.right,known=known)
    def reserve(self,holding,service,selections):
        value=self.measure('contact.network',lambda:self.mesh.call(self.rights[holding.right]['owner'],'reserve',right=holding.right,
            service=service,selections=selections,contact_seconds=self.contact_seconds))
        return WalletRef(value,holding)
    def charge(self,wallet,selections,request_id,operation='query',payload=None):
        return self.measure('request.network',lambda:self.mesh.call(self.rights[wallet.holding.right]['owner'],'charge',wallet=wallet.id,
            selections=selections,request_id=request_id,operation=operation,payload=payload))
    def consume_next(self,wallet,request_id,operation='query',payload=None):
        return self.measure('request.network',lambda:self.mesh.call(self.rights[wallet.holding.right]['owner'],'consume_next',wallet=wallet.id,
            request_id=request_id,operation=operation,payload=payload))
    def retry(self,wallet,request_id):return self.mesh.call(self.rights[wallet.holding.right]['owner'],'retry',wallet=wallet.id,request_id=request_id)
    def probe_old(self,wallet,request_id,selections):
        return self.mesh.call(self.rights[wallet.holding.right]['owner'],'probe_old',wallet=wallet.id,request_id=request_id,selections=selections)
    def recovery(self,wallet,receiver,actor=None):
        envelope=self.call(actor or self.rights[receiver]['owner'],'return',{'id':wallet.holding.right})
        slots=self.mesh.call(self.rights[receiver]['owner'],'receive_return',envelope=envelope,receiver=receiver,target=wallet.holding.right)
        return self.holdings[receiver],slots
    def recontact(self,wallet,selections):
        value=self.mesh.call(self.rights[wallet.holding.right]['owner'],'recontact',wallet=wallet.id,selections=selections,contact_seconds=self.contact_seconds)
        return WalletRef(value,wallet.holding)
    def freeze_setup(self):
        self.initial_counts=self.mesh.call(self.authority_id,'freeze');self.frozen=True
        base=self.mesh.base if isinstance(self.mesh,ScopedMesh) else self.mesh
        if base.shared_authority:self.mesh.frozen_authorities.add(self.authority_id)
        else:base.frozen_authorities.add(self.authority_id)
    def set_handler(self,rid,kind,**args):return self.mesh.call(self.rights[rid]['owner'],'handler',kind=kind,**args)
    def restart_endpoint(self):
        base=self.mesh.base if isinstance(self.mesh,ScopedMesh) else self.mesh
        base.restart(self.endpoint_id)
        public=self.mesh.call(self.endpoint_id,'setup',kind='endpoint',authority_public=self.mesh.config['authority_public'],contact_seconds=self.contact_seconds,
            commit_delay_bound=self.commit_delay_bound)
        assert public==self.endpoint_public,'durable endpoint identity changed'
        return self.mesh.call(self.endpoint_id,'resume_delivery')
    def breakdown(self):return {'scope':'network RPC/component traces and actor-local transactions; nested spans not additive'}
    def close(self):
        try:
            result=self.mesh.call(self.endpoint_id,'audit');a=self.mesh.call(self.authority_id,'audit')
            if self.frozen:assert a['authority_calls']==self.initial_counts,'Authority used after initial setup'
            result.update(authority_calls=a['authority_calls'],initial_authority_frozen=a['frozen'],protocol='fixed-endpoint-v3.1',transport='TCP/TLS')
            for n in self.mesh.processes:
                if n not in (self.endpoint_id,self.authority_id):self.mesh.call(n,'audit')
            write_json(self.path/'case.json',result);return result
        finally:
            if self.own_mesh:self.mesh.close()
