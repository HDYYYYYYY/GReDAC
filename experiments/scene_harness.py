"""Shared paired measurement harness; contains NO domain actions or answers.

Each scene supplies independent input construction, workflow and judge. Both
arms run that same workflow with only the protocol backend enabled/disabled.
The harness records model calls and logical business-admission boundaries in
both arms, enabling actual gap measurement even without protocol objects.
"""
import argparse,getpass,hashlib,json,os,random,time
from collections import Counter
from .support import Run,write_json
from .llm_api import StrictAPI
from .task_backend import TaskBackend,BusinessToolError
from .travel_domain import tool,obj,integer,choice

def text_field():return {'type':'string'}
def array(schema):return {'type':'array','items':schema}

class Session:
    backend_type=TaskBackend
    def __init__(self,run,api,case,enabled,roles,prompts,limit=28):
        self.run,self.api,self.case,self.enabled=run,api,case,enabled
        self.first_call=len(api.calls);self.limit=limit;self.started=time.monotonic()
        self.roles=dict(roles);self.prompts=prompts;self.histories={};self.events=[];self.admissions=[]
        self.backend=self.backend_type(run,case,enabled,roles)
        self.path=run.out/case;self.path.mkdir(exist_ok=True)
        self.artifacts={};self.facts=None
    def save(self,name,value):
        self.artifacts[name]=value;write_json(self.path/(name+'.json'),value)
        self.backend.save_artifact(name,value)
    def inputs(self,value):
        self.facts=value;self.backend.set_facts(value);self.save('facts',value)
    def event(self,kind,origin='controller',**values):
        self.events.append(dict(kind=kind,origin=origin,time=time.monotonic(),**values))
        write_json(self.path/'events.json',self.events)
    def ask(self,role,offered,observation):
        if len(self.api.calls)-self.first_call>=self.limit:raise RuntimeError('episode API cap')
        who=self.roles[role]
        if isinstance(self.api,StrictAPI) or getattr(self.api,'process_owned',False):
            return self.backend.ask_agent(self.api,who,self.prompts[role],offered,observation,self.case,
                self.limit-(len(self.api.calls)-self.first_call))
        h=self.histories.setdefault(who,[dict(role='system',content=self.prompts[role])])
        args,cid=self.api.call(who,h,offered,observation,self.case)
        return args,lambda value:self.api.feedback(h,cid,value)
    def admit(self,context,payload):
        start=time.monotonic()
        result=self.backend.spend(context,'summary' if context=='joint' else 'query',payload)
        end=time.monotonic()
        self.admissions.append(dict(index=len(self.admissions),context=context,start=start,end=end,
            caller=self.roles['lead'] if not any(e['kind']=='delegation' for e in self.events) else self.roles['worker'],
            service=self.roles['service'],with_protocol=self.enabled))
        write_json(self.path/'business_requests.json',self.admissions)
        if isinstance(result,dict) and '_business_tool_error' in result:
            raise BusinessToolError(result['_business_tool_error'])
        return result
    def delegate(self):
        self.backend.delegate();self.event('delegation','model',worker=self.roles['worker'])
    def replace(self,side):
        # This event is permission revocation. Business changes are different
        # event kinds and never call this method implicitly.
        self.backend.replace(side)
        key='worker' if side=='caller' else 'service'
        self.roles[key]+='Replacement';self.event(side+'_recovery',replacement=self.roles[key])
        if side=='service':
            for name,value in self.artifacts.items():self.backend.save_artifact(name,value)
    def finish(self,judge,error):
        ended=time.monotonic();verdict=judge(self.facts,self.artifacts,self.events)
        audit=self.backend.close();calls=self.api.calls[self.first_call:]
        counts=Counter(r['context'] for r in self.admissions)
        expected={'B':sum(counts.values())}
        if self.enabled:
            actual=audit['audit']['spent_by_source']
            assert all(actual.get(k,0)==v for k,v in expected.items()),(actual,expected)
        else:assert not list(self.path.rglob('*.sqlite'))
        result=dict(case=self.case,with_system=self.enabled,**verdict,failure=error,
            joint_pass=verdict['business_pass'] and verdict['coverage_pass'] and error is None,
            api_calls=len(calls),total_seconds=ended-self.started,
            api_seconds=sum(c['seconds'] for c in calls),
            direct_protocol_seconds=sum(s['seconds'] for s in self.backend.spans),
            judge_audit_seconds=time.monotonic()-ended,protocol=audit,expected_spent=expected,
            usage={k:sum(c.get('response',{}).get('usage',{}).get(k,0) for c in calls)
                   for k in ('prompt_tokens','completion_tokens','total_tokens')})
        write_json(self.path/'result.json',result);return result

def coverage(events):
    return {k:any(e['kind']==k for e in events) for k in
            ('stable','delegation','multitask','caller_recovery','service_recovery')}

def run_scene(name,roles,prompts,execute,judge):
    p=argparse.ArgumentParser(description='Independent paired '+name+' real-LLM experiment')
    p.add_argument('--out',required=True);p.add_argument('--seeds',required=True)
    p.add_argument('--model',default='deepseek-flash');p.add_argument('--max-calls',type=int,required=True)
    p.add_argument('--key-prompt',action='store_true');p.add_argument('--order-seed',type=int,default=19517)
    p.add_argument('--slot-bits',type=int,default=8);p.add_argument('--repeats',type=int,default=1)
    args=p.parse_args();key=getpass.getpass('DeepSeek API key: ') if args.key_prompt else os.environ['DEEPSEEK_API_KEY']
    run=Run(args,name);api=StrictAPI(key,args.model,args.max_calls,run.out,max_tokens=3072)
    seeds=[int(x) for x in args.seeds.split(',')];assert len(set(seeds))==len(seeds)
    jobs=[(seed,[True,False] if i%2==0 else [False,True]) for i,seed in enumerate(seeds)]
    random.Random(args.order_seed).shuffle(jobs)
    policy=dict(roles=roles,prompts=prompts,jobs=jobs,model=args.model,temperature=0,
        thinking='disabled',max_tokens=3072,max_episode_calls=28,api_max_calls=args.max_calls)
    policy['sha256']=hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest()
    write_json(run.out/'pairing.json',policy);results=[]
    for seed,arms in jobs:
        for enabled in arms:
            s=Session(run,api,str(seed)+('-with' if enabled else '-without'),enabled,roles,prompts)
            error=None
            try:execute(s,seed)
            except Exception as exc:error=type(exc).__name__+': '+str(exc)
            result=s.finish(judge,error);result['seed']=seed
            write_json(s.path/'result.json',result);results.append(result)
            write_json(run.out/'partial_results.json',results)
            print(json.dumps({k:result[k] for k in ('case','joint_pass','api_calls','failure')},ensure_ascii=False),flush=True)
            if error and ('DeepSeek HTTP' in error or 'API budget' in error):break
        if error and ('DeepSeek HTTP' in error or 'API budget' in error):break
    run.finish(results)
    run.manifest.update(status='PASS' if len(results)==2*len(seeds) and all(r['joint_pass'] for r in results)
        else 'COMPLETED_WITH_FAILURES',llm_api_calls=len(api.calls),episodes=len(results),
        expected_episodes=2*len(seeds),served_models=sorted({c.get('response',{}).get('model','unavailable') for c in api.calls}))
    write_json(run.out/'manifest.json',run.manifest)
    print(json.dumps({'experiment_status':run.manifest['status'],'api_calls':len(api.calls)}),flush=True)
