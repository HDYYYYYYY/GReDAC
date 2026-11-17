"""Functional-test assembly and independent evidence; never a performance driver."""
from contextlib import closing
import copy,json,sqlite3,threading,time
from pathlib import Path
from gredac.crypto import SCHEME,Denied,canonical,digest
from gredac.rpc import Client as RPC
from .client import BridgeClient
from .codec import classify_operation
from ..endpoint_audit import audit as independent_audit

def denied(fn,code=None):
    try:fn()
    except Denied as e:
        if code is not None:assert e.code in ([code] if isinstance(code,str) else code),(e.code,code)
        return e.code
    raise AssertionError('negative input accepted')

class Fixture:
    def __init__(self,run,name,size=16,split=True,delegate_size=None,endpoint='G'):
        self.fd_before=len(list(Path('/proc/self/fd').iterdir()))
        self.lab=l=BridgeClient(run,name,contact_seconds=600,endpoint_id=endpoint)
        if split:
            body=dict(id='c',tasks=['c'],cooperation='cooperation-'+endpoint,caller_approver='UO',service_approver='UR',
                caller_root='O-c',service_root='R-c',req={'query':['s1'],'summary':['s1','s2']},
                basis={'s1':'s1','s2':'s2'},deadline=l.deadline,scheme=SCHEME,endpoint=l.endpoint_id)
            l.call('UO','context',dict(body=body,approvals={n:l.mesh.call(n,'sign',body=body) for n in ('UO','UR')}))
            l.requirements['c']=body['req']
        else:l.context('c',['s1','s2'])
        for s in ['s1','s2']:l.source(s,size,['c'])
        self.root=l.right('O-c','O','c');self.sroot=l.right('R-c','R','c',side='service')
        self.srv=l.right('srv','S','c',self.sroot,side='service')
        self.slots={s:list(range(size)) for s in ['s1','s2']}
        self.held=l.seed(self.root,self.slots)
        self.slots={s:list(range(delegate_size or size)) for s in ['s1','s2']}
        self.a=l.right('A','A','c',self.root);self.h=l.delegate(self.held,self.a,self.slots)
        self.w=l.reserve(self.h,self.srv,self.slots);l.freeze_setup()
        self.sent=[];self.closed=False
        self.raw_local=threading.local();self.raw_clients=[];self.raw_setup_lock=threading.Lock()
    def payload(self,mid,action='echo.read',args=None,srv=None,case='fixture'):
        return self.lab.payload(srv or self.srv,mid,action,args,case)
    def send(self,slot,rid=None,action='echo.read',args=None,w=None,srv=None,payload=None,operation=None):
        w=w or self.w;rid=rid or 'r'+str(slot)
        p=payload or self.payload(rid,action,args,srv or w.service)
        op=operation or classify_operation(p)
        sources=self.lab.requirements['c'][op]
        result=self.lab.charge(w,{s:slot for s in sources},rid,op,p)
        self.sent.append(result);return result
    def snapshot(self):
        a=self.lab.mesh.call(self.lab.endpoint_id,'audit')
        counts={}
        for srv in self.lab.cards:
            owner=self.lab.rights[srv]['owner']
            try:counts[owner]=self.lab.mesh.call(owner,'a2a_info')['business_executions']
            except (OSError,ConnectionError):counts[owner]=self.business_count(owner)
        return dict(requests=a['new_requests'],spent=a['spent_by_source'],business=counts)
    def reject(self,fn,code=None):
        before=self.snapshot();error=denied(fn,code);after=self.snapshot()
        assert before==after,(before,after,error)
        return dict(code=error,before=before,after=after)
    def packet(self,rid,caller='A'):
        p=self.lab.path/'network/actors'/caller/'events.jsonl'
        rows=[json.loads(s) for s in p.read_text().splitlines()]
        return next(x['packet'] for x in reversed(rows) if x.get('request_id')==rid and 'packet' in x)
    def prepare_raw(self):
        # Authenticate channels before the request-race barrier. The original
        # accept loop performs TLS handshake synchronously; it is not changed.
        # A denied controller-only stats request establishes identity only:
        # no admission, protected action or performance warmup is performed.
        with self.raw_setup_lock:
            c=RPC(self.lab.mesh.path/'pki','A',self.lab.mesh.routes,
                  self.lab.path/('probe-A-thread-'+str(threading.get_ident())+'.jsonl'))
            denied(lambda:c.call(self.lab.endpoint_id,'stats'),'CONTROLLER_ONLY')
            self.raw_local.client=c;self.raw_clients.append(c)
    def raw(self,packet,operation='query',caller='A'):
        existing=getattr(self.raw_local,'client',None) if caller=='A' else None
        c=existing or RPC(self.lab.mesh.path/'pki',caller,self.lab.mesh.routes,
              self.lab.path/('probe-'+caller+'-'+str(threading.get_ident())+'.jsonl'))
        try:return c.call(self.lab.endpoint_id,'endpoint_charge',packet=packet,operation=operation)
        finally:
            if existing is None:c.close()
    def business_count(self,name='S'):
        p=self.lab.path/'network/actors'/name/'a2a/bridge.sqlite'
        with closing(sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True)) as db:
            return db.execute('SELECT COUNT(*) FROM business').fetchone()[0]
    def dispose(self):
        if getattr(self,'disposed',False):return
        for c in self.raw_clients:c.close()
        self.lab.mesh.close()
        # Mesh.live deliberately retains old experiment handles. Long A2A
        # matrices must release exited multiprocessing.Process sentinel FDs.
        for process in self.lab.mesh.processes.values():
            assert not process.is_alive()
            process.close()
        from ..network_client import Mesh
        if self.lab.mesh in Mesh.live:Mesh.live.remove(self.lab.mesh)
        self.disposed=True
        after=len(list(Path('/proc/self/fd').iterdir()))
        targets={}
        import os
        for fd in Path('/proc/self/fd').iterdir():
            try:targets[fd.name]=os.readlink(fd)
            except OSError:pass
        (self.lab.path/'resource-cleanup.json').write_text(json.dumps(dict(before=self.fd_before,after=after,closed_process_handles=True,targets=targets)))
        assert after<=self.fd_before+2,(self.fd_before,after)
    def close(self):
        if self.closed:return
        self.closed=True
        for c in self.raw_clients:c.close()
        try:
            result=self.lab.close()
            actors=self.lab.path/'network/actors'
            checked=independent_audit(actors/self.lab.endpoint_id/'guard.sqlite',actors/'Authority/authority.sqlite')
            assert checked.get('passed',True),checked
            from .audit import audit as bridge_audit
            return dict(core=result,independent=checked,bridge=bridge_audit(actors,self.lab.endpoint_id))
        finally:self.dispose()
    def __enter__(self):return self
    def __exit__(self,*exc):
        if exc[0] is None:self.close()
        else:self.dispose()

def response(result):
    r=result['service_receipt']['body']['result']
    assert r['business_status']=='OK',r
    return r['a2a_response']['message']['parts'][0]['data']['value']

def parallel(functions,seed=0,ordered=False,prepare=None):
    import concurrent.futures,random
    barrier=threading.Barrier(len(functions));rng=random.Random(seed)
    delays=[rng.random()*.004 for _ in functions]
    def one(i,fn):
        try:
            if prepare:prepare()
            barrier.wait(timeout=30)
        except BaseException:
            barrier.abort();raise
        if not ordered:time.sleep(delays[i])
        start=time.monotonic()
        try:return dict(ok=True,result=fn(),start=start,end=time.monotonic())
        except Denied as e:return dict(ok=False,error=e.code,start=start,end=time.monotonic())
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(functions)) as pool:
        jobs=[pool.submit(one,i,fn) for i,fn in enumerate(functions)]
        return [j.result(timeout=30) for j in jobs]
