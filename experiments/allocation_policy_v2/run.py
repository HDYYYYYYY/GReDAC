"""One fresh real-process arm. Four parent-local choices, no ledger decisions.

The driver freezes counts, schedules business events and retains public evidence.
Each parent independently builds its eligible set, chooses and delegates in its
own process. Temporary background branches use A3's rank-based plan; actual
consumption, revocation and verified return construct the holes.
"""
import hashlib,json,os,shutil,traceback
from experiments.rq2_v2 import timing,gredac_hooks
from experiments.rq2_v2.common import Resources,configure,parser
from experiments.rq2_v2.gredac_adapter import Adapter
from .workload import background_layout


def execute(run,cfg):
    from .actor import enable_driver
    from experiments.network_client import HoldingRef
    from experiments.support import write_json
    trace=timing.TRACE;gredac_hooks.enable_driver=enable_driver
    # Cardinality follows frozen rank rules, not any strategy outcome.
    planned=background_layout(range(cfg['demands'][2]),cfg['background_seed']) if cfg['background']=='fragmented' else []
    total_requests=9+sum(len(e['consume']) for e in planned)
    adapter=Adapter(run,dict(cfg,method='GReDAC',block='flow',requests=total_requests))
    execute.active=adapter
    adapter.infrastructure();trace.event('infrastructure_ready')
    with trace.span('user_prerequisites','prerequisite'):adapter.users([])
    trace.event('task_begin')
    with trace.span('baseline_preparation','preparation'):
        adapter.identities([]);adapter.setup(2048)
    lab=adapter.lab;parent='O';allocations=[];background=[];begin=0
    for layer,child in enumerate(('A1','A2','A3','A4'),1):
        parent_right=adapter.holdings[parent].right
        if layer==4:
            # Background plans are computed from A3's actual local holding.
            with trace.span('background_construction','background'):
                if cfg['background']=='fragmented':
                    plan=lab.mesh.call('A3','allocation_background',parent=parent_right,seed=cfg['background_seed'])
                    assert plan['pid']!=os.getpid()
                    assert plan['events']==background_layout(allocations[-1]['selected'],cfg['background_seed'])
                    write_json(run.out/'background_plan.json',plan)
                    for e in plan['events']:
                        name=e['member'];spent=e['consume']
                        adapter.handoff('A3',name,e['units'])
                        ordered=spent+[u for u in e['units'] if u not in set(spent)]
                        adapter.conversation(begin,len(spent),ordered);begin+=len(spent)
                        with trace.span('background_revoke_return','background',member=name):
                            rev=lab.call('A3','revoke',dict(id=adapter.holdings[name].right))
                            returned,slots=lab.recovery(adapter.wallet,parent_right,actor='A3')
                            assert sorted(slots['budget'])==sorted(set(e['units'])-set(spent))
                            adapter.holdings['A3']=returned
                        background.append(dict(**e,revocation=rev,returned=sorted(slots['budget'])))
            write_json(run.out/'background.json',dict(events=background,requests=begin))
        # One nonoverlapping direct span includes dynamic identity, authorization,
        # local eligibility/selection, real delivery and public chain retrieval.
        with trace.span('layer.delegation','II',layer=layer,parent_agent=parent,child_agent=child):
            with trace.span('layer.identity_authorization','II',layer=layer):
                adapter.dynamic_identity(child)
                rid=lab.right(child+'-c',child,'c',parent_right,actions=['query'])
            with trace.span('layer.select_delegate','II',layer=layer):
                value=lab.mesh.call(parent,'allocation_select_delegate',parent=parent_right,child=rid,
                    count=cfg['demands'][layer-1],strategy=cfg['strategy'],seed=cfg['selection_seeds'][layer-1])
            selection=value['evidence'];selected=selection['selected']
            assert selection['pid']!=os.getpid()
            assert len(selected)==len(set(selected))==cfg['demands'][layer-1]
            assert set(selected)<=set(selection['available'])
            assert value['available_after']==sorted(set(selection['available'])-set(selected))
            lab.chains[rid]=lab.mesh.call(child,'holding_chain',right=rid)
            adapter.holdings[child]=HoldingRef(rid);adapter.current=child
        allocations.append(dict(**selection,layer=layer,demand=cfg['demands'][layer-1],
            available_after=value['available_after']))
        write_json(run.out/'allocations.json',allocations)
        parent=child
    with trace.span('final_contact_and_requests','III'):
        adapter.conversation(begin,9,allocations[-1]['selected'])
    trace.event('task_end')
    adapter.audit_close()
    return dict(background_requests=begin,total_requests=total_requests)


def main():
    from .suite import ROOT,fingerprint
    from experiments.support import Run,write_json
    args=parser(__doc__).parse_args();configure();cfg=json.loads(args.case_json)
    args.repeats=1;args.slot_bits=15
    run=Run(args,'allocation_policy_v2')
    frozen=fingerprint()
    for rel in frozen:
        dest=run.out/'source'/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,dest)
    run.manifest.update(source_sha256=frozen,code_fingerprint=hashlib.sha256(json.dumps(frozen,sort_keys=True).encode()).hexdigest(),
        case=cfg,driver_revision='allocation-policy-v2-1',independent_unit='background/random-instance/policy arm with fresh processes and DBs')
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
