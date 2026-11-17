"""Experiment application inside each real Agent process.

Driver supplies only policy/count, not the final allocation. The parent builds
the legal local view, selects, then invokes the existing delegate implementation.
All original checks and protocol RPCs remain. The new control RPC is application
orchestration, not an additional GReDAC authorization or a query to B's database.
"""
import os
from experiments.rq2_v2 import timing,gredac_hooks
from experiments.allocation_policy.selectors import choose,LocalClaims
from .workload import background_layout,source_groups


def legal_local(node,right):
    from gredac.storage import position_key
    h=node.holdings[right];r=node.rights[right];now=node.clock.now()
    assert r['owner']==node.name and r['side']=='caller' and r['context']=='c'
    assert 'query' in r['actions'] and now<r['deadline']
    claims=node.allocation_claims.blocked(right)
    uncertain=h.uncertain_units();available=[]
    for row in h.records.values():
        unit=row['slot'];cap=h.caps.get(row['current_cap']['gid'])
        if (row['source']=='budget' and row['state']=='unused' and row['owner']==node.name
            and row['holder_right']==right and row['context']=='c' and row['endpoint']==node.endpoint_id
            and 'query' in row['hard_actions'] and 'c' in row['hard_contexts'] and now<row['deadline']
            and cap is not None and cap['holder_right']==right and cap['guard']==node.endpoint_id
            and cap['context']=='c' and cap['gid'] in h.bundles
            and unit not in claims and position_key('budget',unit) not in uncertain):
            available.append(unit)
    assert len(available)==len(set(available))
    return sorted(available)


def install():
    import experiments.network_actor as actor
    from gredac.crypto import require,digest
    original=actor.Node.dispatch

    def dispatch(node,method,args,peer):
        if not hasattr(node,'allocation_claims'):node.allocation_claims=LocalClaims()
        if method in ('allocation_select_delegate','allocation_view','allocation_background'):
            require(peer['name']=='Driver','CONTROLLER_ONLY')
            right=args['parent']
            with timing.TRACE.span('allocation.legal_local_view','selection'):
                available=legal_local(node,right)
            if method=='allocation_view':return dict(pid=os.getpid(),available=available)
            if method=='allocation_background':
                return dict(pid=os.getpid(),available=available,events=background_layout(available,args['seed']))
            with timing.TRACE.span('allocation.choose','selection',strategy=args['strategy']) as row:
                selected=choose(available,args['count'],args['strategy'],args['seed'])
            assert len(selected)==args['count'] and set(selected)<=set(available)
            evidence=dict(parent=right,child=args['child'],participant=node.name,pid=os.getpid(),
                strategy=args['strategy'],seed=args['seed'],available=available,available_digest=digest(available),
                selected=selected,selected_digest=digest(selected),algorithm_ns=row['end_ns']-row['start_ns'],
                key_source_groups=source_groups(node.holdings[right],selected))
            # Node.record supplies the actual process PID itself.
            node.record('allocation_choice',{k:v for k,v in evidence.items() if k!='pid'})
            delivered=dispatch(node,'delegate',dict(parent=right,child=args['child'],
                selections={'budget':selected},actions=['query']),peer)
            after=legal_local(node,right)
            assert not set(selected)&set(after)
            return dict(delivered=delivered,evidence=evidence,available_after=after)
        if method=='delegate':
            # Preserve the original real transfer. Marking local uncertainty
            # before it avoids freeing units if the response is lost.
            require(peer['name']=='Driver','CONTROLLER_ONLY')
            assert set(args['selections'])=={'budget'}
            node.allocation_claims.sent(args['parent'],args['selections']['budget'])
            return original(node,method,args,peer)
        if method=='receive_return':
            answer=original(node,method,args,peer)  # verifies signature/bindings first
            node.allocation_claims.returned(args['receiver'],answer.get('budget',[]))
            return answer
        return original(node,method,args,peer)

    actor.Node.dispatch=dispatch
    gredac_hooks.install()
    timing.wrap(actor.Node,'reserve','contact.establish')


def process_main(name,directory,path,pipe):
    from experiments.network_actor import process_main as original
    timing.start(os.environ['RQ2_TIMING_DIR'],'GReDAC',name,os.environ['RQ2_RUN_ID'])
    install()
    try:original(name,directory,path,pipe)
    finally:timing.TRACE.flush()


def enable_driver(trace):
    import experiments.network_actor as actor
    install();actor.process_main=process_main
