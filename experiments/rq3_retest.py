"""Manual, bounded retest on the SAME 20261108 formal instances.

Pilot and full are separate invocations. Full requires the completed pilot's
manifest, identical frozen inputs/source/settings and explicit human review.
No attempt replacement, automatic API retry or automatic scale expansion.
"""
import argparse,copy,hashlib,importlib,json,os,random,time
from collections import Counter
from pathlib import Path
from .support import Run,write_json
from .evaluation_batch import hashes,ROOT
from .evaluation_support import EvaluationSession
from .llm_api import StrictAPI
from . import rq3_workflows

CAPS=dict(travel=50,academic=72,calendar=72)
TOKENS=dict(travel=2048,academic=6144,calendar=4096)
PILOT=dict(travel=[209000,209004,209010,209015,209024],
    academic=[219000,219007,219012,219021,219022],calendar=[229000,229001,229007,229012,229024])
ORDER=dict(travel=91031,academic=91032,calendar=91033)
LABEL='同一测试集上的修复后复测 / repair retest on the same test set'

def summarize(results,scenes=None):
    """Pair-level descriptive statistics; never drop an unsuccessful arm.

    Wall/API differences include the two models' different decisions and
    inference latency. They are not pure cryptographic incremental costs.
    Missing timing on constructor failure stays missing, not zero-imputed.
    """
    from .support import stats
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

def credential():
    value=os.environ.get('DEEPSEEK_API_KEY')
    if value:return value
    filename=os.environ.get('DEEPSEEK_CREDENTIAL_FILE')
    if not filename:raise RuntimeError('Set DEEPSEEK_API_KEY or DEEPSEEK_CREDENTIAL_FILE')
    path=Path(filename)
    document=json.loads(path.read_text())
    if document.get('api_key'):return document['api_key']
    values=document.get('env',{})
    for name in ('DEEPSEEK_API_KEY','ANTHROPIC_AUTH_TOKEN','ANTHROPIC_API_KEY','OPENAI_API_KEY'):
        if values.get(name):return values[name]
    raise RuntimeError('configured DeepSeek credential unavailable; no credential printed')

def validate_pilot(pilot,frozen):
    """Allow explicit expansion of scene coverage, retaining all other freezes.

    The pilot already froze prompts/tools/data for ALL scenes. A full command
    may explicitly select more scenes; this does not make them pilot-tested.
    The one runner revision enabling this gate is accepted only when its AST
    outside this validation function is identical to the pilot's saved code.
    All other source hashes and settings must still match exactly.
    """
    import ast
    pilot=Path(pilot);prior=json.loads((pilot/'frozen.json').read_text())
    prior_scenes=list(prior.get('scenes',CAPS));formal_scenes=list(frozen.get('scenes',CAPS))
    assert set(prior_scenes)<=set(formal_scenes),'formal scene scope must contain the reviewed pilot scope'
    previous={k:v for k,v in prior.items() if k!='scenes'}
    current={k:v for k,v in frozen.items() if k!='scenes'}
    old_hashes=previous.pop('source_sha256');new_hashes=current.pop('source_sha256')
    assert previous==current,'inputs, prompts, tools or settings changed since pilot; full is blocked'
    changes=sorted(n for n in set(old_hashes)|set(new_hashes) if old_hashes.get(n)!=new_hashes.get(n))
    runner='experiments/rq3_retest.py'
    if changes:
        assert changes==[runner],'non-gate source changed since pilot; full is blocked'
        before=pilot/'source'/runner;after=ROOT/runner
        assert hashlib.sha256(before.read_bytes()).hexdigest()==old_hashes[runner],'pilot source snapshot mismatch'
        assert hashlib.sha256(after.read_bytes()).hexdigest()==new_hashes[runner],'current source snapshot mismatch'
        def execution_ast(path):
            tree=ast.parse(path.read_text(encoding='utf-8-sig'))
            tree.body=[n for n in tree.body if not (isinstance(n,ast.FunctionDef) and n.name=='validate_pilot')]
            return ast.dump(tree,include_attributes=False)
        assert execution_ast(before)==execution_ast(after),'runner execution logic changed since pilot; full is blocked'
    manifest=json.loads((pilot/'manifest.json').read_text())
    expected=2*sum(len(PILOT[s]) for s in prior_scenes)
    assert manifest['status']=='COMPLETED' and manifest['episodes']==expected,'pilot not complete'
    assert manifest['system_unexpected_interruptions']==0 and manifest['protocol_audit_failures']==0,'pilot protocol checks failed'
    print(json.dumps(dict(pilot_gate='PASS',pilot_scenes=prior_scenes,formal_scenes=formal_scenes,
        scenes_without_this_pilot=[s for s in formal_scenes if s not in prior_scenes],
        pilot_episodes=expected,source_changes_limited_to_runner_gate=changes),ensure_ascii=False),flush=True)

def settings(model,inputs,scenes=None,flow_only=False):
    prompts={s:importlib.import_module('.'+s+'_scene',__package__).PROMPTS for s in CAPS}
    # Retest-only prompt additions: actual rejection/revision is allowed.
    prompts=copy.deepcopy(prompts)
    prompts['calendar']['worker']=prompts['calendar']['worker'].replace('Return a full schedule every time.',
        'Return a full schedule when proposing; reference tools only select its saved proposal ID.')
    prompts['calendar']['service']=prompts['calendar']['service'].replace('When accepting, reproduce the exact schedule.',
        'When accepting, reference the saved proposal ID without rewriting its schedule.')
    prompts['calendar']['lead']=prompts['calendar']['lead'].replace('Copy the agreed meeting/slot/room values exactly.',
        'Identify the exact submitted proposal by ID when accepting or requesting revision.')
    prompts['calendar']['worker']+=' For reference tools select the saved proposal ID; do not recopy a schedule. Keep reasoning under 100 words.'
    prompts['calendar']['service']+=' Use proposal_ref to identify your actual decision. Do not reproduce the schedule in comments.'
    prompts['calendar']['lead']+=' Use proposal_ref to approve or request revision of an existing proposal; do not recopy it.'
    return dict(label=LABEL,model=model,scenes=list(CAPS) if scenes is None else list(scenes),
        evaluation='flow_only' if flow_only else 'flow_and_business',
        caps=CAPS,max_tokens=TOKENS,format_extra_attempts=2,
        max_academic_revisions=4,max_calendar_rounds_per_phase=4,pilot=PILOT,order=ORDER,prompts=prompts,
        input_sha256=hashlib.sha256(inputs.read_bytes()).hexdigest(),source_sha256=hashes(),
        commit_delay_bound_seconds=float(os.environ.get('GREDAC_COMMIT_DELAY_BOUND','0.05')),
        protection_scope='admitted business requests and authenticated service-tool results; model-role observations/reviews are separate test-orchestrated TLS messages, not independently debited',
        transport='independent processes, mutual TLS1.3, loopback TCP',slot_bits=8)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage',choices=['pilot','full'],required=True);p.add_argument('--out',required=True)
    p.add_argument('--model',default='deepseek-flash');p.add_argument('--pilot-results')
    p.add_argument('--scenes',nargs='+',choices=list(CAPS),default=list(CAPS),help='Only schedule these scenes; fixed pilot/full instances remain unchanged')
    p.add_argument('--flow-only',action='store_true',help='Skip final business oracle; retain workflow tools, five-stage process verdict and protocol audit')
    p.add_argument('--confirm-pilot-reviewed',action='store_true')
    p.add_argument('--max-calls',type=int,required=True,help='Exact cap for selected scenes: 2 * instances per scene * sum of scene caps')
    p.add_argument('--check-only',action='store_true',help='Validate arguments, instances and caps without API or result directory')
    a=p.parse_args();a.repeats=1;a.slot_bits=8
    input_path=ROOT/'experiments/data/rq3_20261108_instances.json';data=json.loads(input_path.read_text())
    assert len(a.scenes)==len(set(a.scenes)),'duplicate scene selection'
    frozen=settings(a.model,input_path,a.scenes,a.flow_only)
    selected={s:[e for e in data[s]['formal'] if a.stage=='full' or e['seed'] in PILOT[s]] for s in a.scenes}
    n=5 if a.stage=='pilot' else 25
    assert all(len(v)==n and len({x['seed'] for x in v})==n for v in selected.values())
    cap=2*n*sum(CAPS[s] for s in a.scenes);expected=2*n*len(a.scenes)
    assert a.max_calls==cap,'API hard cap must match frozen stage; no automatic expansion'
    if a.stage=='full':
        assert a.pilot_results and a.confirm_pilot_reviewed,'full requires a completed pilot and explicit human review'
        if not a.check_only:
            validate_pilot(a.pilot_results,frozen)
    if a.check_only:
        print(json.dumps(dict(stage=a.stage,episodes=expected,api_hard_cap=cap,evaluation=frozen['evaluation'],instances={s:[e['seed'] for e in v] for s,v in selected.items()},label=LABEL),ensure_ascii=False));return
    # Validate credentials without displaying them; actors load them themselves.
    assert credential()
    run=Run(a,'rq3_network_retest');write_json(run.out/'frozen.json',frozen)
    write_json(run.out/'instances.json',selected);(run.out/'original_instances.json').write_bytes(input_path.read_bytes())
    results=[];attempts=0;scheduled=[]
    for scene in a.scenes:
        entries=selected[scene];jobs=[(e,[True,False] if i%2==0 else [False,True]) for i,e in enumerate(entries)]
        random.Random(ORDER[scene]).shuffle(jobs)
        scheduled.extend(dict(scene=scene,seed=e['seed'],arms=arms) for e,arms in jobs)
    write_json(run.out/'schedule.json',dict(jobs=scheduled,api_hard_cap=cap,episodes=expected,label=LABEL))
    for job in scheduled:
        scene=job['scene'];entry=next(e for e in selected[scene] if e['seed']==job['seed'])
        module=importlib.import_module('.'+scene+'_scene',__package__)
        for enabled in job['arms']:
            assert frozen==settings(a.model,input_path,a.scenes,a.flow_only),'source/settings changed during frozen run'
            case=scene+'-'+str(entry['seed'])+('-with' if enabled else '-without');session=None;error=None;returned=False
            api=StrictAPI('',a.model,min(CAPS[scene],cap-attempts),run.out,max_tokens=TOKENS[scene]);api.format_retries=2
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
            from .network_client import Mesh
            for mesh in Mesh.live:mesh.close()
            Mesh.live.clear()
            attempts+=len(api.calls);assert attempts<=cap
            r.update(seed=entry['seed'],label=LABEL,stage=a.stage,evaluation=frozen['evaluation'],input_business_sha256=entry['business_sha256'])
            path=run.out/case;path.mkdir(exist_ok=True);write_json(path/'result.json',r);results.append(r)
            write_json(run.out/'partial_results.json',results);run.save_samples()
            columns=['scene','case','flow_complete','failure_origin','api_calls']
            if not a.flow_only:columns.insert(3,'business_pass')
            print(json.dumps({k:r.get(k) for k in columns},ensure_ascii=False),flush=True)
    run.finish(results);write_json(run.out/'paired_summary.json',summarize(results,a.scenes))
    run.manifest.update(status='COMPLETED',label=LABEL,episodes=len(results),expected_episodes=expected,llm_api_calls=attempts,
        api_hard_cap=cap,system_unexpected_interruptions=sum(r['system_unexpected_interruption'] for r in results),
        protocol_audit_failures=sum(r.get('protocol_correct') is False for r in results),
        model=a.model,scenes=a.scenes,evaluation=frozen['evaluation'],transport=frozen['transport'],new_independent_test_instances=False)
    write_json(run.out/'manifest.json',run.manifest)
    print(json.dumps(dict(status='COMPLETED',episodes=len(results),api_calls=attempts,api_hard_cap=cap)),flush=True)

if __name__=='__main__':main()
