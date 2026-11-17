"""One isolated policy arm: real background, parent-local allocation, 9 requests.

Only deterministic task scheduling is in this driver. Final choices execute
inside A3; every grant/return is communicated and verified by the existing
participant implementations. Database access occurs only after all actors stop.
"""
import hashlib,json,os,shutil,traceback
from pathlib import Path
from experiments.rq2_v2 import timing,gredac_hooks
from experiments.rq2_v2.common import Resources,configure,parser
from experiments.rq2_v2.gredac_adapter import Adapter
from .selectors import background_events,expected_free


def execute(run,cfg):
    from .actor import enable_driver
    from experiments.network_client import HoldingRef
    from experiments.support import write_json
    trace=timing.TRACE;gredac_hooks.enable_driver=enable_driver
    total_requests=9+(128 if cfg['background']=='fragmented' else 0)
    adapter=Adapter(run,dict(cfg,method='GReDAC',block='flow',requests=total_requests))
    execute.active=adapter
    adapter.infrastructure();trace.event('infrastructure_ready')
    with trace.span('user_prerequisites','prerequisite'):adapter.users([])
    trace.event('task_begin')
    with trace.span('baseline_preparation','preparation'):
        adapter.identities([]);adapter.setup(1024)
        parent='O'
        for child in ('A1','A2','A3'):
            adapter.handoff(parent,child,list(range(1024)));parent=child
    lab=adapter.lab;parent_right=adapter.holdings['A3'].right
    events=background_events(cfg['repeat'],cfg['development']) if cfg['background']=='fragmented' else []
    background=[];begin=0
    with trace.span('background_construction','background'):
        for e in events:
            name=e['member'];spent=e['consume']
            adapter.handoff('A3',name,e['units'])
            # Whole 256-unit capability is synced; request order picks exactly
            # the scheduled 32 units, not an artificially edited ledger.
            ordered=spent+[u for u in e['units'] if u not in set(spent)]
            adapter.conversation(begin,len(spent),ordered);begin+=len(spent)
            with trace.span('background_revoke_return','background',member=name):
                rev=lab.call('A3','revoke',dict(id=adapter.holdings[name].right))
                returned,slots=lab.recovery(adapter.wallet,parent_right,actor='A3')
                assert sorted(slots['budget'])==sorted(set(e['units'])-set(spent))
                adapter.holdings['A3']=returned
            background.append(dict(**e,revocation=rev,returned=sorted(slots['budget'])))
    write_json(run.out/'background.json',dict(events=background,requests=begin))
    before=lab.mesh.call('A3','allocation_view',parent=parent_right)
    # This compares public experimental evidence; it never supplies choices
    # or overwrites the parent's received holding/return data.
    assert before['pid']!=os.getpid() and before['available']==expected_free(cfg['background'],cfg['repeat'],cfg['development'])
    with trace.span('final_identity_authorization','II'):
        adapter.dynamic_identity('A4')
        rid=lab.right('A4-c','A4','c',parent_right,actions=['query'])
    with trace.span('final_selection_and_delegation','II'):
        value=lab.mesh.call('A3','allocation_select_delegate',parent=parent_right,child=rid,
            count=256,strategy=cfg['strategy'],seed=cfg['seed'])
    selection=value['evidence'];selected=selection['selected']
    assert selection['pid']==before['pid'] and selection['available']==before['available']
    assert len(selected)==len(set(selected))==256 and not set(selected)&set(value['available_after'])
    # Signed public chain retrieval is the same operation as Client.delegate.
    lab.chains[rid]=lab.mesh.call('A4','holding_chain',right=rid)
    adapter.holdings['A4']=HoldingRef(rid);adapter.current='A4'
    write_json(run.out/'allocation.json',dict(**selection,available_after=value['available_after']))
    with trace.span('final_contact_and_requests','III'):
        adapter.conversation(begin,9,selected)
    trace.event('task_end')
    adapter.audit_close()
    return dict(background_requests=begin,total_requests=total_requests)


def main():
    from .suite import ROOT,fingerprint
    from experiments.support import Run,write_json
    args=parser(__doc__).parse_args();configure();cfg=json.loads(args.case_json)
    args.repeats=1;args.slot_bits=15
    run=Run(args,'allocation_policy')
    frozen=fingerprint()
    for rel in frozen:
        dest=run.out/'source'/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,dest)
    run.manifest.update(source_sha256=frozen,code_fingerprint=hashlib.sha256(json.dumps(frozen,sort_keys=True).encode()).hexdigest(),
        case=cfg,driver_revision='allocation-policy-1',independent_unit='background/repetition/policy arm with fresh processes and DBs')
    os.environ['RQ2_TIMING_DIR']=str(run.out/'timing');os.environ['RQ2_RUN_ID']=run.out.name
    trace=timing.start(run.out/'timing','GReDAC','Driver',run.out.name);monitor=Resources(run.out)
    try:
        execute(run,cfg);trace.flush();monitor.close()
        from .results import summarize
        run.finish([summarize(run.out,cfg)])
    except BaseException as e:
        active=getattr(execute,'active',None)
        if active:
            try:active.cleanup()
            except Exception:pass
        from experiments.network_client import Mesh
        for mesh in Mesh.live:
            if not mesh.closed:
                try:mesh.close()
                except Exception:pass
        trace.flush();monitor.close();run.save_samples()
        run.manifest.update(status='FAIL',error=repr(e),traceback=traceback.format_exc())
        write_json(run.out/'manifest.json',run.manifest);raise


if __name__=='__main__':main()
