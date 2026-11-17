"""OFFLINE fixtures only: no LLM evidence, never used by live scene drivers.

Scripted test outputs exercise workflow/backend/schema and independent
oracles. They are explicitly counted as zero real API calls. Mutated numeric
results, invented scope and calendar resource conflicts must be rejected.
"""
import argparse,copy,json
from .support import Run,write_json
from .scene_harness import Session
from .travel_domain import validate
from . import academic_scene,calendar_scene
from .academic_data import aggregate_rows

class Scripted:
    def __init__(self):self.calls=[];self.inputs=[];self.initial=None;self.last_report=None
    def feedback(self,h,cid,value):h.append(dict(role='tool',tool_call_id=cid,content=json.dumps(value)))
    def call(self,role,h,offered,o,case):
        self.inputs.append(copy.deepcopy((role,offered,o)))
        name=offered['function']['name']
        if 'dossier' in o and o['dossier']:self.initial=o['dossier']
        if name=='request_dossier':v={'study':'effect_cost_anomaly'}
        elif name=='summarize_dossier':v={'summary':'Offline fixture summary.','evidence_ids':['D01']}
        elif name=='delegate_analyst':v={'worker':'ResearchAnalyst','tasks':['effect','cost','anomaly']}
        elif name=='aggregate_rows':v={'row_ids':[r['id'] for r in self.initial['rows']]}
        elif name in ('draft_report','revise_report'):
            revision=o['revision'];ids=[r['id'] for r in self.initial['rows']]
            findings={'effect':'B_faster_light_only','cost':'B_more_expensive','anomaly':'retain_anomaly_no_causal_claim'}
            v=dict(revision=revision,markdown=f'OFFLINE TEST revision {revision}. '+
                ' '.join(['This synthetic fixture retains all data and bounds its evidence based conclusions.']*18),
                table=aggregate_rows(self.initial,ids),
                conclusions=[dict(topic=t,finding=f,scope='measured_only',claim='offline fixture',evidence_ids=ids) for t,f in findings.items()],
                addressed_issues=[i['id'] for i in o.get('review',{}).get('issues',[])])
            self.last_report=v
        elif name=='review_report':v={'issues':[dict(id='issue'+str(o['round']),comment='Clarify scope.',evidence_ids=['D01'])]}
        elif name=='check_report':v={'report':o['current_report']}
        elif name=='approve_report':v={'decision':'accept','revision':2,'reason':'offline fixture'}
        elif name=='request_calendar':v={'projects':['A','B']}
        elif name=='brief_constraints':v={'briefing':'Offline fixture.'}
        elif name=='delegate_scheduler':v={'worker':'SharedScheduler','projects':['A','B']}
        elif name=='propose_schedule':
            slots=[0,2,4,1,3,5] if o['phase']=='initial' else [0,6,7,1,8,9]
            ids=['A-kickoff','A-design','A-review','B-kickoff','B-design','B-review']
            v={'schedule':[dict(meeting=m,slot=t,room='R1' if m.endswith('review') else 'R2') for m,t in zip(ids,slots)],'reasoning':'offline fixture'}
        elif name=='check_calendar':v={'schedule':o['proposal']['schedule'],'phase':o['phase']}
        elif name=='agree_schedule':v={'decision':'accept','schedule':o['proposal']['schedule'],'comments':'offline fixture'}
        else:raise AssertionError(name)
        validate(v,offered['function']['parameters']);self.calls.append(dict(seconds=0,response={}))
        return v,str(len(self.calls))

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True)
    p.add_argument('--slot-bits',type=int,default=8);p.add_argument('--repeats',type=int,default=1)
    args=p.parse_args();run=Run(args,'scene_regression');results=[]
    for module,seed in [(academic_scene,85011),(calendar_scene,86011)]:
        inputs=[];saved=[]
        for enabled in (True,False):
            api=Scripted();s=Session(run,api,module.__name__.split('.')[-1]+str(enabled),enabled,module.ROLES,module.PROMPTS)
            module.execute(s,seed);r=s.finish(module.judge,None)
            assert r['joint_pass'],r
            if enabled:assert r['protocol']['audit']['authority_calls']['control:revoke']==6
            r.update(scripted_actions=r['api_calls'],api_calls=0,test_only='OFFLINE scripted fixture, NOT real LLM evidence')
            write_json(s.path/'result.json',r);results.append(r);inputs.append(api.inputs);saved.append(s)
        assert inputs[0]==inputs[1],'protocol leaked into model inputs'
        s=saved[0];mutated=copy.deepcopy(s.artifacts)
        if module is academic_scene:
            for row in mutated['report2']['table']:row['row_ids'].reverse()
            assert module.judge(s.facts,mutated,s.events)['business_pass'],'evidence order is not an answer difference'
            duplicate=copy.deepcopy(mutated)
            duplicate['report2']['table'][0]['row_ids'][0]=duplicate['report2']['table'][0]['row_ids'][1]
            assert not module.judge(s.facts,duplicate,s.events)['business_pass'],'duplicate evidence row accepted'
            mutated['report2']['table'][0]['mean_latency_ms']+=1
            assert not module.judge(s.facts,mutated,s.events)['business_pass']
            mutated=copy.deepcopy(s.artifacts);mutated['report2']['conclusions'][0]['scope']='causal'
        else:
            mutated['changed_final']['schedule'][1]['slot']=0
            # Future change must not be present in initial model observations.
            for _,_,observation in inputs[0]:
                if observation.get('phase')=='initial':assert 'change' not in observation['calendar'] if 'calendar' in observation else True
        assert not module.judge(s.facts,mutated,s.events)['business_pass']
    run.finish(results)
    print('PASS: two scene workflows, paired semantic inputs, all-context revocation, independent negative checks; zero API calls')
if __name__=='__main__':main()
