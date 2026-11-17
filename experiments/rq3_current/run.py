"""Manual, bounded retest on the SAME 20261108 formal instances.

Pilot and full are separate invocations. Full requires the completed pilot's
manifest, identical frozen inputs/source/settings and explicit human review.
No whole-task replacement or automatic scale expansion; bounded model retries are frozen.
"""
import argparse,copy,hashlib,importlib,json,os,random,time
from collections import Counter
from pathlib import Path
from experiments.support import Run,write_json
from experiments.evaluation_batch import hashes,ROOT
from experiments.evaluation_support import EvaluationSession
from experiments.llm_api import StrictAPI

from experiments.rq3_retest import PILOT,ORDER,credential
from .policy import CAPS,TOKENS,LABEL,settings,fingerprint
from . import workflows as rq3_workflows
from .runtime import install_driver,retry_statistics

def summarize(results,scenes=None):
    """Pair-level descriptive statistics; never drop an unsuccessful arm.

    Wall/API differences include the two models' different decisions and
    inference latency. They are not pure cryptographic incremental costs.
    Missing timing on constructor failure stays missing, not zero-imputed.
    """
    from experiments.support import stats
    answer={}
    for scene in scenes or list(dict.fromkeys(r['scene'] for r in results)):
        rows=[r for r in results if r['scene']==scene];pairs=[]
        for seed in sorted({r['seed'] for r in rows}):
            arms={r['with_system']:r for r in rows if r['seed']==seed}
            if len(arms)!=2:continue
            a,b=arms[True],arms[False]
            pair=dict(seed=seed,with_flow=a['flow_complete'],without_flow=b['flow_complete'],
                with_business=a['business_pass'],without_business=b['business_pass'],
                with_failure=a.get('failure_origin'),without_failure=b.get('failure_origin'))
            for metric in ('total_seconds','api_seconds','api_calls'):
                pair[metric+'_difference']=a[metric]-b[metric] if metric in a and metric in b else None
            pairs.append(pair)
        arms={}
        for enabled in (True,False):
            subset=[r for r in rows if r['with_system']==enabled]
            arms['with' if enabled else 'without']=dict(episodes=len(subset),
                flow_complete=sum(r['flow_complete'] for r in subset),
                business_evaluated=sum(r.get('business_evaluated',True) for r in subset),
                business_pass=sum(r['business_pass'] is True for r in subset) if any(r.get('business_evaluated',True) for r in subset) else None,
                failure_origins=dict(Counter(r.get('failure_origin') or ('incomplete_process' if not r['flow_complete'] else 'none') for r in subset)),
                system_unexpected_interruptions=sum(r['system_unexpected_interruption'] for r in subset),
                protocol_audit_failures=sum(r.get('protocol_correct') is False for r in subset) if enabled else None,
                timing={m:stats([r[m] for r in subset if m in r]) for m in
                    ('total_seconds','api_seconds','api_calls','direct_protocol_seconds')})
        answer[scene]=dict(arms=arms,pairs=pairs,paired_differences={m:stats([r[m] for r in pairs if r[m] is not None])
            for m in ('total_seconds_difference','api_seconds_difference','api_calls_difference')})
    return dict(label=LABEL,statistical_unit='existing instance pair',scenes=answer,
        caveat='Same-test-set retest; paired total/API differences include model trajectory variation. No independent new-test-set or pure-crypto-overhead claim.')

def validate_pilot(pilot,frozen):
    pilot=Path(pilot);prior=json.loads((pilot/'frozen.json').read_text())
    assert prior==frozen,'new source/retry/prompt settings require a matching new pilot; old v051 cannot authorize this batch'
    m=json.loads((pilot/'manifest.json').read_text())
    assert m['status']=='COMPLETED' and m['episodes']==30
    assert m['system_unexpected_interruptions']==m['protocol_audit_failures']==0
    print('Pilot freeze and protocol gate PASS (model failures remain in the results)',flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage',choices=['pilot','full'],required=True);p.add_argument('--out',required=True)
    p.add_argument('--model',default='deepseek-flash');p.add_argument('--pilot-results')
    # All three existing scenes are fixed for this retest.
    # Flow-only is mandatory here; business tools remain active.
    p.add_argument('--confirm-pilot-reviewed',action='store_true')
    p.add_argument('--max-calls',type=int,required=True,help='Exact cap for selected scenes: 2 * instances per scene * sum of scene caps')
    p.add_argument('--check-only',action='store_true',help='Validate arguments, instances and caps without API or result directory')
    a=p.parse_args();a.repeats=1;a.slot_bits=8;a.scenes=list(CAPS);a.flow_only=True
    input_path=ROOT/'experiments/data/rq3_20261108_instances.json';data=json.loads(input_path.read_text())
    assert len(a.scenes)==len(set(a.scenes)),'duplicate scene selection'
    frozen=settings(a.model,input_path)
    protected=json.loads((Path(__file__).parent/'protected_baseline.json').read_text())
    assert all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in protected.items()),'protected current core/source changed'
    selected={s:[e for e in data[s]['formal'] if a.stage=='full' or e['seed'] in PILOT[s]] for s in a.scenes}
    n=5 if a.stage=='pilot' else 25
    assert all(len(v)==n and len({x['seed'] for x in v})==n for v in selected.values())
    cap=2*n*sum(CAPS[s] for s in a.scenes);expected=2*n*len(a.scenes)
    assert a.max_calls==cap,'API hard cap must match frozen stage; no automatic expansion'
    if a.stage=='full':
        assert a.pilot_results and a.confirm_pilot_reviewed,'full requires a completed pilot and explicit human review'
        if not a.check_only or (Path(a.pilot_results)/'manifest.json').exists():
            validate_pilot(a.pilot_results,frozen)
        else:print('Pilot gate pending: new matching real pilot is required before full execution',flush=True)
    if a.check_only:
        print(json.dumps(dict(stage=a.stage,episodes=expected,api_hard_cap=cap,evaluation=frozen['evaluation'],instances={s:[e['seed'] for e in v] for s,v in selected.items()},label=LABEL),ensure_ascii=False));return
    from experiments.rq2_v2.suite import idle
    idle()
    # Validate credentials without displaying them; actors load them themselves.
    assert credential()
    run=Run(a,'rq3_current_retest')
    install_driver()
    from gredac.crypto import SLOT_BITS
    assert SLOT_BITS==8,'initialize address width before importing protocol modules'
    import shutil
    for rel in frozen['source_sha256']:
        dest=run.out/'source'/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,dest)
    run.manifest['source_sha256']=frozen['source_sha256']
    write_json(run.out/'frozen.json',frozen)
    write_json(run.out/'instances.json',selected);(run.out/'original_instances.json').write_bytes(input_path.read_bytes())
    results=[];attempts=0;scheduled=[]
    for scene in a.scenes:
        entries=selected[scene];jobs=[(e,[True,False] if i%2==0 else [False,True]) for i,e in enumerate(entries)]
        random.Random(ORDER[scene]).shuffle(jobs)
        scheduled.extend(dict(scene=scene,seed=e['seed'],arms=arms) for e,arms in jobs)
    write_json(run.out/'schedule.json',dict(jobs=scheduled,api_hard_cap=cap,episodes=expected,label=LABEL))
    for job in scheduled:
        scene=job['scene'];entry=next(e for e in selected[scene] if e['seed']==job['seed'])
        module=importlib.import_module('experiments.'+scene+'_scene')
        for enabled in job['arms']:
            assert frozen==settings(a.model,input_path),'source/settings changed during frozen run'
            case=scene+'-'+str(entry['seed'])+('-with' if enabled else '-without');session=None;error=None;returned=False
            api=StrictAPI('',a.model,min(CAPS[scene],cap-attempts),run.out,max_tokens=TOKENS[scene]);api.format_retries=0
            start=time.monotonic()
            try:
                session=EvaluationSession(run,api,case,enabled,module.ROLES,frozen['prompts'][scene],limit=CAPS[scene])
                fn={'travel':module.execute,'academic':rq3_workflows.execute_academic,'calendar':rq3_workflows.execute_calendar}[scene]
                fn(session,entry['seed'],copy.deepcopy(entry['facts']));returned=True
            except Exception as exc:error=type(exc).__name__+': '+str(exc)
            if session is not None:
                try:r=session.evaluate(scene,module.ROLES,module.judge,error,returned,evaluate_business=not a.flow_only)
                finally:session.backend.mesh.close()
            else:r=dict(scene=scene,case=case,with_system=enabled,flow_complete=False,business_pass=None,business_evaluated=False,failure=error,
                failure_origin='system_protocol_runtime' if enabled else 'experiment_driver',system_unexpected_interruption=enabled,
                protocol_correct=False if enabled else None,api_calls=len(api.calls),total_seconds=time.monotonic()-start)
            from experiments.network_client import Mesh
            for mesh in Mesh.live:mesh.close()
            Mesh.live.clear()
            charged=getattr(api,'attempts_reserved',len(api.calls));attempts+=charged;assert attempts<=cap
            r.update(api_budget_charged=charged,api_attempts_unconfirmed=charged-len(api.calls),retry_statistics=retry_statistics(api.calls),seed=entry['seed'],label=LABEL,stage=a.stage,evaluation=frozen['evaluation'],input_business_sha256=entry['business_sha256'])
            path=run.out/case;path.mkdir(exist_ok=True);write_json(path/'result.json',r);results.append(r)
            write_json(run.out/'partial_results.json',results);run.save_samples()
            columns=['scene','case','flow_complete','failure_origin','api_calls']
            if not a.flow_only:columns.insert(3,'business_pass')
            print(json.dumps({k:r.get(k) for k in columns},ensure_ascii=False),flush=True)
    run.finish(results);write_json(run.out/'paired_summary.json',summarize(results,a.scenes))
    write_json(run.out/'retry_summary.json',dict(episodes=[dict(case=r['case'],with_system=r['with_system'],**r['retry_statistics']) for r in results],
        caveat='All attempts count toward the cap and API/task time. Missing usage is unknown, not free. No whole-task replacement.'))
    run.manifest.update(status='COMPLETED',label=LABEL,episodes=len(results),expected_episodes=expected,llm_api_calls=sum(r['api_calls'] for r in results),api_budget_charged=attempts,
        api_hard_cap=cap,system_unexpected_interruptions=sum(r['system_unexpected_interruption'] for r in results),
        protocol_audit_failures=sum(r.get('protocol_correct') is False for r in results),
        model=a.model,scenes=a.scenes,evaluation=frozen['evaluation'],transport=frozen['transport'],new_independent_test_instances=False)
    write_json(run.out/'manifest.json',run.manifest)
    print(json.dumps(dict(status='COMPLETED',episodes=len(results),api_calls=sum(r['api_calls'] for r in results),api_budget_charged=attempts,api_hard_cap=cap)),flush=True)

if __name__=='__main__':main()
