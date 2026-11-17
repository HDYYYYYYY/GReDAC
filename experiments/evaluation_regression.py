"""OFFLINE test-only actions; never imported by an online scene or runner.

Preflight witnesses are explicit test inputs, not live tools. Test quality
failure separately from process completion and verify both paired model
observations are identical. No output here is counted as real LLM evidence.
"""
import argparse,copy,json
from pathlib import Path
from .support import Run,write_json
from .evaluation_support import EvaluationSession
from .evaluation_judge import process_verdict,failure_category
from .scene_regression import Scripted
from .travel_domain import calculator,validate
from . import travel_scene,academic_scene,calendar_scene


class Fixture(Scripted):
    def __init__(self,initial,proof):
        super().__init__();self.initial=initial;self.proof=proof;self.calc=None

    def call(self,role,h,offered,o,case):
        name=offered['function']['name']
        travel={'quote','select_option','delegate_worker','request_quote','verify_cost','calculate_cost','submit_check','finish'}
        if name in travel or name=='propose_schedule':
            self.inputs.append(copy.deepcopy((role,offered,o)))
            if name=='quote':v={'key':o['remaining'][0]}
            elif name=='select_option':v={'id':max(o['options'],key=lambda x:(x['rating'],x['unit_price']))['id']}
            elif name=='delegate_worker':v={'worker':'PriceWorker'}
            elif name=='request_quote':v={'key':o['assignment']}
            elif name=='verify_cost':v={'scope':'current_quotes'}
            elif name=='calculate_cost':
                v={**o['trip'],'lines':[dict(key=k,unit_price=q['unit_price']) for k,q in o['quotes'].items()]}
                self.calc=calculator(v)
            elif name=='submit_check':v={'total':self.calc['total']}
            elif name=='finish':v={'choices':{k:q['id'] for k,q in o['quotes'].items()},'total':o['checked_total']}
            else:v={'schedule':copy.deepcopy(self.proof[o['phase']+'_witness']),'reasoning':'OFFLINE fixture only'}
            validate(v,offered['function']['parameters']);self.calls.append(dict(seconds=0,response={}))
            return v,str(len(self.calls))
        result=super().call(role,h,offered,o,case)
        if name in ('draft_report','revise_report'):
            for c in result[0]['conclusions']:
                if c['topic']=='effect':c['finding']=self.proof['effect']
                elif c['topic']=='cost':c['finding']=self.proof['cost_direction']
                elif c['topic']=='anomaly':c['evidence_ids']=[self.initial['anomaly_id']]
        return result


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--feasibility',required=True)
    p.add_argument('--slot-bits',type=int,default=8);p.add_argument('--repeats',type=int,default=1)
    a=p.parse_args();run=Run(a,'llm75_offline_regression');results=[]
    data=json.loads((Path(__file__).parent/'data/llm75_instances.json').read_text())
    proofs=json.loads(Path(a.feasibility).read_text())['scenes']
    for scene,module in [('travel',travel_scene),('academic',academic_scene),('calendar',calendar_scene)]:
        # All five academic profiles, plus the two independent development
        # inputs for travel/calendar. These are not API/model evaluations.
        cases=data[scene]['formal'][:5] if scene=='academic' else data[scene]['development']
        for entry in cases:
            proof=next(x for x in proofs[scene] if x['seed']==entry['seed']);inputs=[]
            for enabled in (True,False):
                api=Fixture(copy.deepcopy(entry['facts']),proof)
                s=EvaluationSession(run,api,scene+str(entry['seed'])+str(enabled),enabled,module.ROLES,module.PROMPTS,limit=32)
                kw={'continue_on_business_rejection':True} if scene=='calendar' else {}
                module.execute(s,entry['seed'],copy.deepcopy(entry['facts']),**kw)
                result=s.evaluate(scene,module.ROLES,module.judge,None,True)
                assert result['flow_complete'] and result['business_pass'],result
                assert result['protocol_correct'] is (True if enabled else None)
                if enabled:
                    assert len(result['safety_checks'])==6 and all(r['passed'] for r in result['safety_checks'])
                    assert result['protocol']['audit']['authority_calls']['control:revoke']==6
                else:assert result['safety_checks'] is None
                result.update(api_calls=0,offline_scripted_actions=len(api.calls),test_only=True)
                write_json(s.path/'result.json',result);results.append(result);inputs.append(api.inputs)
                bad=copy.deepcopy(s.artifacts)
                if scene=='travel':bad['final']['total']+=1
                elif scene=='academic':bad['report2']['revision']=999
                else:bad['changed_final']['schedule'][0]['slot']=99
                assert not module.judge(s.facts,bad,s.events)['business_pass']
                assert process_verdict(scene,module.ROLES,s.events,s.actions,s.admissions,bad,True,None)['flow_complete']
                missing=[e for e in s.events if e['kind']!='delegation']
                assert not process_verdict(scene,module.ROLES,missing,s.actions,s.admissions,s.artifacts,True,None)['flow_complete']
                empty=copy.deepcopy(s.artifacts)
                if scene=='travel':empty['final']['choices']={}
                elif scene=='academic':empty['report2']['markdown']=' '
                else:empty['final_calendar']=[]
                assert not process_verdict(scene,module.ROLES,s.events,s.actions,s.admissions,empty,True,None)['flow_complete']
                if scene=='academic':
                    from .academic_data import check_report
                    reordered=copy.deepcopy(s.artifacts['report2'])
                    for row in reordered['table']:row['row_ids'].reverse()
                    assert not check_report(s.facts,reordered)['violations']
            assert inputs[0]==inputs[1],'protocol mode leaked into model observations'
    assert failure_category('bad JSON','api',{'response':{}})=='model_action_format'
    assert failure_category('timeout','api',{'error':'timeout'})=='api_transport_or_service'
    assert failure_category('unexpected denial','protocol',{})=='system_protocol_runtime'
    run.finish(results);print(f'PASS: {len(results)} offline workflows, five academic profiles, paired inputs, process/quality separation; ZERO API calls')
if __name__=='__main__':main()
