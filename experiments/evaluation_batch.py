"""Serial paired runner with frozen inputs and an explicit attempt budget.

Every scheduled arm is attempted exactly once. A failed API/action ends that
arm, is preserved in the denominator, and does not cause answer repair or
replacement. This module shares infrastructure, not domain workflow logic.
"""
import argparse,copy,getpass,hashlib,importlib,json,os,random
from pathlib import Path
from .support import Run,write_json
from .llm_api import StrictAPI
from .evaluation_support import EvaluationSession

CAPS={'travel':40,'academic':40,'calendar':40}
TOKENS={'travel':1800,'academic':3072,'calendar':3072}
ORDER={'travel':41031,'academic':41032,'calendar':41033}
ROOT=Path(__file__).resolve().parents[1]


def hashes():
    paths=sorted(list((ROOT/'gredac').glob('*.py'))+list((ROOT/'experiments').glob('*.py'))+
                 list((ROOT/'experiments/data').glob('*.json'))+[ROOT/'pyproject.toml']+
                 [p for p in (ROOT/'vendor').rglob('*') if p.is_file() and '.git' not in p.parts
                  and (p.suffix in ('.c','.h','.so','.json') or p.name in ('LICENSE','README.md','Makefile'))])
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def main(scene=None):
    p=argparse.ArgumentParser(description=__doc__)
    if scene is None:p.add_argument('--scene',required=True,choices=list(CAPS))
    p.add_argument('--out',required=True);p.add_argument('--split',choices=['development','formal'],required=True)
    p.add_argument('--dev-index',type=int,choices=[0,1,2],default=0)
    p.add_argument('--model',default='deepseek-flash');p.add_argument('--key-prompt',action='store_true')
    p.add_argument('--freeze-file');p.add_argument('--slot-bits',type=int,default=8);p.add_argument('--repeats',type=int,choices=[1],default=1)
    a=p.parse_args();scene=scene or a.scene
    module=importlib.import_module('.'+scene+'_scene',__package__)
    input_path=ROOT/'experiments/data/rq3_20261108_instances.json'
    all_inputs=json.loads(input_path.read_text());cases=all_inputs[scene][a.split]
    if a.split=='development':
        cases=cases[a.dev_index:a.dev_index+1]
        assert len(cases)==1,'development candidate not allocated'
    else:
        assert len(cases)==25 and a.freeze_file,'formal requires 25 frozen pairs'
        frozen=json.loads(Path(a.freeze_file).read_text())
        assert frozen['source_sha256']==hashes(),'frozen code/input changed'
        assert frozen['model']==a.model and frozen['slot_bits']==a.slot_bits
        assert frozen['caps']==CAPS and frozen['max_tokens']==TOKENS and frozen['order_seeds']==ORDER
    key=getpass.getpass('DeepSeek API key: ') if a.key_prompt else os.environ['DEEPSEEK_API_KEY']
    run=Run(a,'llm75_'+scene)
    (run.out/'frozen_inputs.json').write_bytes(input_path.read_bytes())
    if a.freeze_file:(run.out/'freeze.json').write_bytes(Path(a.freeze_file).read_bytes())
    api=StrictAPI(key,a.model,2*len(cases)*CAPS[scene],run.out,max_tokens=TOKENS[scene])
    jobs=[dict(seed=c['seed'],arms=[True,False] if i%2==0 else [False,True]) for i,c in enumerate(cases)]
    random.Random(ORDER[scene]).shuffle(jobs)
    lookup={c['seed']:c for c in cases}
    policy=dict(scene=scene,split=a.split,roles=module.ROLES,prompts=module.PROMPTS,jobs=jobs,
        model=a.model,temperature=0,thinking='disabled',max_tokens=TOKENS[scene],
        max_episode_calls=CAPS[scene],max_batch_calls=api.limit,order_seed=ORDER[scene],
        input_sha256=hashlib.sha256(input_path.read_bytes()).hexdigest(),
        pair_unit='one new instance; two independent real API trajectories; no repeated trials',
        protocol_safety='with-system only; no-system is not_applicable')
    write_json(run.out/'pairing.json',policy);results=[]
    for job in jobs:
        entry=lookup[job['seed']]
        for enabled in job['arms']:
            case=str(job['seed'])+('-with' if enabled else '-without')
            # Constructor failures are also a scheduled attempt, not silently
            # dropped. No new process or database is used to replace it.
            s=None;error=None;returned=False
            try:
                s=EvaluationSession(run,api,case,enabled,module.ROLES,module.PROMPTS,limit=CAPS[scene])
                kwargs={'continue_on_business_rejection':True} if scene=='calendar' else {}
                module.execute(s,job['seed'],copy.deepcopy(entry['facts']),**kwargs)
                returned=True
            except Exception as exc:error=type(exc).__name__+': '+str(exc)
            if s is not None:r=s.evaluate(scene,module.ROLES,module.judge,error,returned)
            else:
                path=run.out/case;path.mkdir(exist_ok=True)
                write_json(path/'facts.json',entry['facts'])
                r=dict(scene=scene,case=case,with_system=enabled,flow_complete=False,business_pass=False,
                    failure=error,failure_origin='system_protocol_runtime' if enabled else 'experiment_driver',
                    system_unexpected_interruption=enabled,protocol_correct=False if enabled else None,
                    protocol_applicability='applicable' if enabled else 'not_applicable',api_calls=0,
                    total_seconds=0,api_seconds=0,direct_protocol_seconds=0,diagnostic_seconds=0,usage={},served_models=[])
            r.update(seed=job['seed'],input_business_sha256=entry['business_sha256'],split=a.split)
            write_json(run.out/case/'result.json',r);results.append(r)
            write_json(run.out/'partial_results.json',results);run.save_samples()
            print(json.dumps({k:r[k] for k in ('scene','case','flow_complete','business_pass','api_calls','failure_origin')},ensure_ascii=False),flush=True)
    run.finish(results)
    run.manifest.update(status='COMPLETED',episodes=len(results),expected_episodes=2*len(cases),
        llm_api_calls=len(api.calls),api_hard_cap=api.limit,
        flow_complete=sum(r['flow_complete'] for r in results),business_pass=sum(r['business_pass'] for r in results),
        served_models=sorted({m for r in results for m in r['served_models']}))
    write_json(run.out/'manifest.json',run.manifest)
    print(json.dumps({'status':'COMPLETED','scene':scene,'episodes':len(results),'api_calls':len(api.calls)}),flush=True)
if __name__=='__main__':main()
