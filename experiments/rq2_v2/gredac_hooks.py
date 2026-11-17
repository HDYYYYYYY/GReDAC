"""Process-local measurement wrappers. The saved protocol files do not change.

Only high-level primitives are wrapped: no per-bit/per-unit timing records.
Transaction durations still come from the existing Store observer. Wrapper
CPU/wall costs are disclosed and never silently subtracted.
"""
import contextlib,functools,os,sys
from . import timing


def install():
    import experiments.network_actor as actor
    import gredac.rpc as rpc
    import gredac.crypto as crypto
    import gredac.offline as offline
    import gredac.endpoint as endpoint
    import gredac.roles as roles
    import gredac.storage as storage
    # Already imported aliases must call the same original via its wrapper.
    for mod,names in [(offline,['authorize','transfer','receive_delegation']),
                      (crypto,['verify_signature'])]:
        for name in names:
            old,new=timing.wrap(mod,name,mod.__name__+'.'+name)
            for m in list(sys.modules.values()):
                if m and getattr(m,'__name__','').startswith(('gredac.','experiments.network_actor')):
                    if getattr(m,name,None) is old:setattr(m,name,new)
    for cls,names in [(crypto.Bundle,['child','tag']), (crypto.Signer,['sign']),
        (endpoint.Endpoint,['initialize','sync','discover','_verify_chain','_op_revoke','_op_return','session_act','charge','deliver']),
        (roles.ACTCallerContact,['begin','finish']), (roles.ACTServiceRole,['respond'])]:
        for name in names:
            if hasattr(cls,name):timing.wrap(cls,name,cls.__name__+'.'+name)
    for name in ('encode','send'):timing.wrap(rpc,name,'rpc.'+name)
    old_receive=rpc.receive
    def receive(*args,**kwargs):
        # Server's passive listener wait can outlive the entire task and ends
        # with ordinary EOF at teardown. It is not request-processing work.
        if timing.CURRENT.get() is None:return old_receive(*args,**kwargs)
        with timing.TRACE.span('rpc.receive'):return old_receive(*args,**kwargs)
    rpc.receive=receive
    old_store=storage.Store.__init__
    def store_init(self,path,transaction_observer=None):
        def observe(value):
            if transaction_observer:transaction_observer(value)
            parent=timing.CURRENT.get();phase=parent['phase'] if parent else 'unassigned'
            row=timing.TRACE.interval('storage.transaction',phase,parent=parent,transaction_id=value['txid'])
            row.update(start_ns=value['start_ns'],end_ns=value['end_ns'],result='ok' if value['committed'] else 'rollback',
                durations_ns={k:value[k] for k in ('lock_wait_ns','begin_ns','body_ns','commit_or_rollback_ns')})
        return old_store(self,path,observe)
    storage.Store.__init__=store_init
    original=rpc.Client.call
    @functools.wraps(original)
    def call(self,destination,method,**args):
        cid=timing.TRACE.next_message(self.name,destination,method,'send')
        with timing.TRACE.span('rpc.call.'+method,correlation_id=cid,edge='send',peer=destination):
            return original(self,destination,method,**args)
    rpc.Client.call=call
    original_dispatch=actor.Node.dispatch
    @functools.wraps(original_dispatch)
    def dispatch(self,method,args,peer):
        cid=timing.TRACE.next_message(peer['name'],self.name,method,'receive')
        with timing.TRACE.span('rpc.handle.'+method,correlation_id=cid,edge='receive',peer=peer['name']):
            if method=='rq2_conversation':
                # Experiment application scheduling, not a protocol endpoint:
                # one controller command, then actual requests in the caller
                # process, just as the author Agent.connect native loop.
                assert peer['name']=='Driver'
                return conversation(self,args,peer,original_dispatch)
            if method=='rq2_evidence':
                assert peer['name']=='Driver'
                return dict(pid=os.getpid(),results=getattr(self,'rq2_results',[]))
            return original_dispatch(self,method,args,peer)
    actor.Node.dispatch=dispatch


def conversation(node,args,peer,dispatch):
    """Only the deterministic application loop; all protocol calls original."""
    from . import business
    trace=timing.TRACE;slots=args['slots'];begin=args['begin'];count=args['count']
    results=getattr(node,'rq2_results',None)
    if results is None:node.rq2_results=results=[]
    def one(index,slot,first):
        # First request's outer span also includes its required new contact,
        # as in the native author's connect() path. Hot requests stay local
        # to one request/response. No protocol operation is moved or omitted.
        scope=contextlib.nullcontext() if first else trace.span('hot_request',request_id=f'business-{index}')
        with scope:
            payload=business.request(index)
            value=dispatch(node,'charge',dict(wallet=wallet['id'],selections={'budget':slot},
                request_id=f'business-{index}',operation='query',payload=payload),peer)
            result=value['service_receipt']['body']['result'];business.verify(index,result)
            results.append(dict(index=index,slot=slot,result=result,pid=os.getpid()))
        trace.event('result_verified',index=index)
        if first and args['replacement']:trace.event('replacement_first_result_verified')
    with trace.span('service_first_use','III.first',display_phase=True):
        trace.event('service_first_use_begin')
        with trace.span('first_request',request_id=f'business-{begin}'):
            if args.get('old_wallet'):
                wallet=dispatch(node,'recontact',dict(wallet=args['old_wallet'],selections={'budget':slots},contact_seconds=3600),peer)
            else:
                wallet=node.reserve(args['right'],args['service'],{'budget':slots},3600)
            one(begin,slots[0],True)
        trace.event('first_result_verified')
    if count>1:
        with trace.span('hot_request_sequence','III.hot',display_phase=True):
            for j in range(1,count):one(begin+j,slots[j],False)
    return dict(wallet=wallet,completed=count,pid=os.getpid())


def process_main(name,directory,path,pipe):
    # Same original network process and public bootstrap; only tracing differs.
    from experiments.network_actor import process_main as original
    timing.start(os.environ['RQ2_TIMING_DIR'],'GReDAC',name,os.environ['RQ2_RUN_ID']);install()
    try:original(name,directory,path,pipe)
    finally:timing.TRACE.flush()


def enable_driver(trace):
    import experiments.network_actor as actor
    # Spawn imports this module in a new interpreter, so its actor module is
    # pristine and process_main above reaches the original implementation.
    install();actor.process_main=process_main
