"""Opt-in experiment-only waiting around unchanged real TCP/TLS RPCs.

This does NOT turn loopback into a WAN. Sleep models successful-path delay;
kernel congestion, packet loss and bandwidth are unchanged. All protocol
messages, cryptography, checks and commits still run in their original role.
Default disabled. No original source file imports this module.
"""
import collections,contextvars,json,os,random,time
from pathlib import Path
from .model import OPERATIONS,DIAGNOSTICS,path_key,stable_seed

CURRENT=contextvars.ContextVar('rq2_rtt_call',default=None)
INSTALLED=False


def pause(row,part,seconds,sleep=time.sleep,clock=time.monotonic_ns):
    if seconds<=0:return
    start=clock();sleep(seconds);end=clock()
    row.setdefault('waits',[]).append(dict(part=part,requested_seconds=seconds,start_ns=start,end_ns=end,actual_seconds=(end-start)/1e9))


def install():
    global INSTALLED
    if INSTALLED:return
    INSTALLED=True
    import gredac.rpc as rpc
    enabled=os.environ.get('RQ2_RTT_ENABLED')=='1'
    config=json.loads(Path(os.environ['RQ2_RTT_CONFIG']).read_text()) if enabled else None
    # The suite prepares a compact public RTT pool file once per task. Loading
    # it is experimental overhead, measured and disclosed separately; it is
    # never an authorization/state cache. Original participant DBs stay private.
    began=time.monotonic()
    sample_data=json.loads(Path(config['runtime_samples']).read_text()) if enabled else None
    load_seconds=time.monotonic()-began
    counts=collections.Counter()
    old_call,old_send,old_receive,old_close=rpc.Client.call,rpc.send,rpc.receive,rpc.Client.close

    def call(self,destination,method,**kwargs):
        # Preserve Client.call(destination, method, **args). In particular,
        # handler(..., target='rq2') carries `target` in the message payload;
        # instrumentation must not bind that field as the RPC destination.
        target=destination
        control=self.name=='Driver' and method=='rq2_conversation'
        row=None
        if enabled and self.name!='Driver' and target!='Driver' and method not in DIAGNOSTICS:
            if method not in OPERATIONS:raise ValueError('unmapped protocol RPC for RTT: '+method)
            key=path_key(self.name,target,config['profile'],config['bindings'])
            counts[(self.name,target,method)]+=1;serial=counts[(self.name,target,method)]
            links=getattr(self.local,'links',{});epochs=getattr(self.local,'epochs',{})
            route=self.routes[target];epoch=(route.get('pid'),route['port'],route['public'])
            new=target not in links or epochs.get(target)!=epoch
            ix=None;rtt=0.
            if key:
                rng=random.Random(stable_seed(config['seed'],config['run'],self.name,target,method,serial,key))
                ix=rng.randrange(len(sample_data[key]));rtt=sample_data[key][ix]/1000
            row=dict(source=self.name,target=target,method=method,serial=serial,path=key,
                sample_index=ix,rtt_seconds=rtt,new_connection=new,waits=[],result='error',
                process_dataset_load_seconds=load_seconds,task_run=config['run'],pid=os.getpid())
        token=CURRENT.set(dict(row=row,control=control,send_seen=False,receive_seen=False))
        try:
            value=old_call(self,target,method,**kwargs)
            if row is not None:row['result']='ok'
            return value
        finally:
            CURRENT.reset(token)
            if row is not None:
                if not hasattr(self,'rtt_diagnostics'):self.rtt_diagnostics=rpc.DiagnosticLog(self.trace.parent/'rtt-waits.jsonl')
                self.rtt_diagnostics.append(row)

    def send(conn,value):
        state=CURRENT.get()
        if state is not None:
            assert not state['send_seen'],'unexpected multiple sends inside a protocol RPC'
            state['send_seen']=True;row=state['row']
            if row:
                # Extra handshake delay is a labeled proxy after real local
                # TCP/TLS establishment. We do not intercept TLS packets.
                if row['new_connection']:pause(row,'modeled_tcp_tls_setup',2*row['rtt_seconds'])
                pause(row,'request_half_rtt',row['rtt_seconds']/2)
        return old_send(conn,value)

    def receive(conn):
        state=CURRENT.get()
        if state is not None and state['control']:
            # Only this driver command encompasses the complete N-request
            # task. Per-request 120s timeout and all security TTLs stay intact.
            conn.settimeout(2400)
        result=old_receive(conn)
        if state is not None:
            assert not state['receive_seen'];state['receive_seen']=True
            if state['row']:pause(state['row'],'reply_half_rtt',state['row']['rtt_seconds']/2)
        return result

    def close(self):
        try:return old_close(self)
        finally:
            if hasattr(self,'rtt_diagnostics'):self.rtt_diagnostics.flush()
    rpc.Client.call=call;rpc.send=send;rpc.receive=receive;rpc.Client.close=close


def process_main(name,directory,path,pipe):
    from experiments.network_actor import process_main as original
    from experiments.rq2_later.hooks import install as original_hooks
    from experiments.rq2_v2 import timing
    timing.start(os.environ['RQ2_TIMING_DIR'],'GReDAC',name,os.environ['RQ2_RUN_ID'])
    original_hooks();install()
    try:original(name,directory,path,pipe)
    finally:timing.TRACE.flush()


def enable_driver(trace):
    import experiments.network_actor as actor
    from experiments.rq2_later.hooks import install as original_hooks
    original_hooks();install();actor.process_main=process_main
