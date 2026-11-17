"""Experiment-only process boundary, not a production transport/fallback.

One spawned worker owns a team's K runtime Endpoint/SQLite objects. The
supervisor retains caller credentials and exact pending bytes. Messages cross
a local pipe; TLS records are real MemoryBIO inside the worker. Pipe timing is
not Internet performance. Durable protocol data are re-opened after real exit.
"""
import json,multiprocessing,threading,time,traceback
from collections import Counter


def worker(conn,specs,crash):
    from gredac.storage import Store,MonotonicClock
    from gredac.endpoint import Endpoint
    from gredac.crypto import Denied
    from gredac.roles import ServiceTransport
    endpoints={};links={};transactions=[];operations=[]
    for spec in specs:
        name=spec['endpoint'];store=Store(spec['database'],lambda row,n=name:transactions.append(dict(endpoint=n,**row)))
        transport=ServiceTransport(spec['pki'],name)
        from gredac.crypto import canonical,digest
        for role in spec['roles']:
            def handler(body,target=spec['name']):
                result=dict(target=target,value=digest(body['payload']),padding='')
                result['padding']='x'*(256-len(canonical(result)));return result
            role.handler=handler;transport.add(role)
        endpoints[name]=Endpoint(store,MonotonicClock(),spec['pki'],spec['authority_public'],
            endpoint=name,session_seconds=1800,delivery=transport.deliver)
    armed=None
    conn.send(dict(ready=True,pid=__import__('os').getpid(),time=time.monotonic()))
    while True:
        msg=conn.recv();op=msg['operation'];name=msg.get('endpoint')
        if op=='stop':
            conn.send(dict(ok=True,transactions=transactions,operations=operations,
                process_cpu_seconds=time.process_time(),max_rss_kib=__import__('resource').getrusage(__import__('resource').RUSAGE_SELF).ru_maxrss));return
        if op=='arm':armed=msg['point'];conn.send(dict(ok=True));continue
        ep=endpoints[name];args=msg['args'];kwargs=msg['kwargs']
        pki=specs[0]['pki']
        for identity,reg in msg.get('new_identities',{}).items():
            # New caller certificate provisioned by the independent PKI. This
            # adds transport knowledge, not runtime authorization; sync still
            # validates the actual delegation chain at B.
            pki.validate(reg['certificate'],reg)
            pki.identities[identity]=(pki.directory/(identity+'.crt.pem'),pki.directory/(identity+'.key.pem'),reg)
        def link(pair):
            key=tuple(pair)
            if key not in links:links[key]=specs[0]['pki'].link(*pair)
            return links[key]
        if op=='charge':args[-1]=link(args[-1])
        elif op=='discover':args[-1]=link(args[-1])
        elif op=='session':args[-2]=link(args[-2]);args[-1]=link(args[-1])
        if armed and op=='charge':
            point=armed;armed=None
            def hook(where):
                if where==point:
                    from pathlib import Path
                    Path(crash).write_text(json.dumps(dict(point=point,time=time.monotonic(),
                        endpoint=name,transactions=transactions)))
                    __import__('os')._exit(73)
            ep.store.commit_hook=hook
        start=time.monotonic();cpu=time.process_time()
        try:
            if op=='resume_delivery':result=ep.resume_delivery()
            else:result=getattr(ep,op)(*args,**kwargs)
            conn.send(dict(ok=True,result=result))
        except Denied as exc:
            conn.send(dict(ok=False,code=exc.code,attributes={k:v for k,v in vars(exc).items() if k!='code'}))
        except Exception as exc:conn.send(dict(ok=False,error=repr(exc),traceback=traceback.format_exc()))
        finally:operations.append(dict(endpoint=name,operation=op,start=start,end=time.monotonic(),cpu_seconds=time.process_time()-cpu))


class TeamProcess:
    def __init__(self,federation):
        self.f=federation;self.lock=threading.Lock();self.trace=[]
        self.specs=[]
        for member in federation.members:
            lab=member.lab
            # Spawn serializes participants' fixture material, not live SSL or
            # SQLite. Only public controls and the service roles run in child.
            for role in lab.roles.values():role.handler=None
            self.specs.append(dict(name=member.name,endpoint=lab.endpoint_id,database=str(lab.g.path),pki=lab.pki,
                authority_public=lab.authority.signer.public,roles=list(lab.roles.values())))
            lab.g.close()
        self.start()

    def start(self):
        # fork happens only before request threads start, or through forkserver
        # snapshots? cryptographic private keys are not pickleable. The driver
        # uses fork with target Stores closed and their locks idle; no production
        # restart guarantee for arbitrary multi-threaded application code.
        ctx=multiprocessing.get_context('fork');self.conn,child=ctx.Pipe()
        self.process=ctx.Process(target=worker,args=(child,self.specs,str(self.f.run.out/'crash.json')))
        self.process.daemon=True
        self.process.start();child.close();self.ready=self.conn.recv()
        self.sent_identities=set(self.specs[0]['pki'].identities)

    def rpc(self,name,operation,*args,**kwargs):
        from gredac.crypto import Denied
        args=list(args);pairs=[]
        if operation in ('charge','discover'):pairs=[args[-1].caller,args[-1].receiver]
        elif operation=='session':pairs=[args[-2].caller,args[-2].receiver,args[-1].caller,args[-1].receiver]
        additions={n:self.specs[0]['pki'].identities[n][2] for n in pairs if n not in self.sent_identities}
        if operation in ('charge','discover'):args[-1]=[args[-1].caller,args[-1].receiver]
        elif operation=='session':
            args[-2]=[args[-2].caller,args[-2].receiver];args[-1]=[args[-1].caller,args[-1].receiver]
        start=time.monotonic()
        with self.lock:
            self.conn.send(dict(endpoint=name,operation=operation,args=args,kwargs=kwargs,new_identities=additions))
            while not self.conn.poll(.01):
                if not self.process.is_alive():raise ConnectionError('team protocol process exited')
                if time.monotonic()-start>30:raise TimeoutError('team process response timeout')
            result=self.conn.recv()
            self.sent_identities.update(additions)
        self.trace.append(dict(operation=operation,endpoint=name,start=start,end=time.monotonic()))
        if not result['ok']:
            if 'code' in result:
                exc=Denied(result['code']);exc.__dict__.update(result['attributes']);raise exc
            raise RuntimeError(result)
        return result.get('result')

    def arm(self,point):
        with self.lock:
            self.conn.send(dict(operation='arm',point=point));assert self.conn.recv()['ok']

    def close(self):
        self.conn.send(dict(operation='stop'));data=self.conn.recv();self.process.join()
        from .support import write_json
        prefix=self.f.members[0].name
        write_json(self.f.run.out/(prefix+'-worker-transactions.json'),data['transactions'])
        write_json(self.f.run.out/(prefix+'-worker-operations.json'),{k:v for k,v in data.items() if k!='transactions'})
        write_json(self.f.run.out/(prefix+'-worker-ipc.json'),self.trace)


class EndpointProxy:
    def __init__(self,team,endpoint):self.team=team;self.name=endpoint;self.calls=Counter()
    def __getattr__(self,operation):
        def call(*args,**kwargs):
            self.calls[operation]+=1;return self.team.rpc(self.name,operation,*args,**kwargs)
        return call
