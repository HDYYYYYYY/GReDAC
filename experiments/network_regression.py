"""OFFLINE regression fixtures only. ZERO external API calls.

FixtureAPI is constructed inside each Agent process, never in live runs.
Known feasibility witnesses are test inputs, not production business tools.
Tests compare exact serialized model requests, real process IDs/listeners,
business-oracle negatives, old-credential rejection and persistent ledgers.
"""
import argparse,copy,json,os
from pathlib import Path
from types import SimpleNamespace
from .agent_input import text,object_order
from .llm_api import StrictAPI

class FixtureAPI:
    feedback=staticmethod(StrictAPI.feedback)
    def __init__(self,profile):
        from .evaluation_regression import Fixture
        self.fixture=Fixture(profile['initial'],profile['proof']);self.calls=[];self.profile=profile;self.injected=set();self.previous=None
    def call(self,role,history,offered,o,case):
        from .travel_domain import validate
        name=offered['function']['name'];history.append(dict(role='user',content=text(o)))
        request=dict(messages=object_order(history),tools=[object_order(offered)],model='OFFLINE_FIXTURE')
        if 'validation_error' in o:o=self.previous
        else:self.previous=copy.deepcopy(o)
        if name=='check_report' and 'report_ref' in offered['function']['parameters']['properties']:
            value={'report_ref':o['submitted_report_id']}
        elif name=='check_calendar' and 'proposal_ref' in offered['function']['parameters']['properties']:
            value={'proposal_ref':o['proposal_ref'],'phase':o['phase']}
        elif name=='agree_schedule' and 'proposal_ref' in offered['function']['parameters']['properties']:
            # Exercise a legitimate requested third round, not forced assent.
            revision=self.profile.get('extra_round') and o['proposal_ref'].endswith('2')
            value=dict(decision='revise' if revision else 'accept',proposal_ref=o['proposal_ref'],comments='OFFLINE requested clarification' if revision else 'OFFLINE approval')
        elif name=='approve_report':
            rev=o['report']['revision'];value=dict(decision='revise' if self.profile.get('extra_round') and rev==2 else 'accept',revision=rev,reason='OFFLINE decision')
        elif name=='review_report':value={'issues':[dict(id='R'+str(o['round'])+'-1',comment='Clarify measured scope.',evidence_ids=['D01'])]}
        else:
            if name in ('draft_report','revise_report'):o={**o,'instruction':o.get('instruction','')}
            value,_=self.fixture.call(role,history,offered,o,case)
        broken=self.profile.get('inject_format') and name not in self.injected and name in ('review_report','revise_report','propose_schedule')
        if broken:
            self.injected.add(name)
            if name=='review_report':value['issues'][0].pop('id')
            if name=='revise_report':value['conclusions'][0]['finding']='INVALID_ENUM_TEST'
        if self.profile.get('always_bad'):value.pop(next(iter(value)))
        cid='fixture-'+str(len(self.calls));tc=dict(id=cid,type='function',function=dict(name=name,arguments=text(value)))
        response=dict(choices=[dict(message=dict(role='assistant',content=None,tool_calls=[tc]),finish_reason='tool_calls')],model='OFFLINE_FIXTURE',usage={})
        if broken and name=='propose_schedule':
            tc['function']['arguments']=tc['function']['arguments'][:-7];response['choices'][0]['finish_reason']='length'
        self.calls.append(dict(case=case,role=role,request=request,response=response,seconds=0,scripted=True,status='ok',api_process_pid=os.getpid()))
        try:
            parsed=json.loads(tc['function']['arguments']);validate(parsed,offered['function']['parameters'])
        except Exception as e:
            self.calls[-1].update(status='error',error=str(e));raise
        history.append(response['choices'][0]['message']);return value,cid

def main():
    from .support import Run,write_json
    from .evaluation_support import EvaluationSession
    from . import travel_scene,academic_scene,calendar_scene,rq3_workflows
    from .rq3_retest import settings,CAPS,TOKENS
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True);p.add_argument('--feasibility',required=True)
    p.add_argument('--scenes',nargs='+',choices=list(CAPS),default=list(CAPS));p.add_argument('--flow-only',action='store_true')
    a=p.parse_args();a.repeats=1;a.slot_bits=8;run=Run(a,'network_regression')
    from gredac.crypto import Denied
    os.environ['GREDAC_OFFLINE_REGRESSION']='1'
    data_path=Path(__file__).parent/'data/rq3_20261108_instances.json';data=json.loads(data_path.read_text())
    proofs=json.loads(Path(a.feasibility).read_text())['scenes'];pol=settings('OFFLINE_FIXTURE',data_path,a.scenes,a.flow_only);results=[]
    assert text({'b':{'z':0,'a':1},'a':[{'d':2,'c':3}]})==text({'a':[{'c':3,'d':2}],'b':{'a':1,'z':0}})
    assert text([1,2])!=text([2,1])
    for scene,module in [('travel',travel_scene),('academic',academic_scene),('calendar',calendar_scene)]:
        if scene not in a.scenes:continue
        entry=data[scene]['formal'][0];proof=next(x for x in proofs[scene] if x['seed']==entry['seed']);inputs=[]
        for enabled in (True,False):
            api=SimpleNamespace(process_owned=True,model='OFFLINE_FIXTURE',limit=72,max_tokens=TOKENS[scene],calls=[],format_retries=2,
                test_profile=dict(initial=entry['facts'],proof=proof,extra_round=True,inject_format=True))
            s=EvaluationSession(run,api,scene+str(enabled),enabled,module.ROLES,pol['prompts'][scene],limit=72)
            try:
                fn={'travel':module.execute,'academic':rq3_workflows.execute_academic,'calendar':rq3_workflows.execute_calendar}[scene]
                fn(s,entry['seed'],copy.deepcopy(entry['facts']))
                routes=s.backend.mesh.routes;assert all(r['pid']!=os.getpid() for n,r in routes.items() if n!='Driver')
                assert len({r['pid'] for n,r in routes.items() if n!='Driver'})==len(routes)-1
                assert len({r['port'] for n,r in routes.items() if n!='Driver'})==len(routes)-1
                assert all(c['actor_pid']!=os.getpid() for c in api.calls)
                assert all(c['api_process_pid']==c['actor_pid'] for c in api.calls)
                if enabled:
                    try:s.backend.mesh.call(s.roles['service'],'business_direct',payload={'request':{'action':'read_dossier'}})
                    except Denied as e:assert e.code=='PROTOCOL_ADMISSION_REQUIRED'
                    else:raise AssertionError('protected service bypassed B')
                    try:s.backend.mesh.call(s.backend.lab.endpoint_id,'endpoint_control',body=dict(actor='UO'),signature='00')
                    except Denied as e:assert e.code=='CONTROL_TLS_ACTOR'
                    else:raise AssertionError('claimed sender identity accepted')
                oracle_calls=[]
                def forbidden_oracle(*args):
                    oracle_calls.append(True);raise AssertionError('flow-only invoked final business oracle')
                r=s.evaluate(scene,module.ROLES,forbidden_oracle if a.flow_only else module.judge,None,True,evaluate_business=not a.flow_only)
                assert r['flow_complete'],r
                if a.flow_only:assert not oracle_calls and r['business_pass'] is None and r['business_verdict'] is None and not r['business_evaluated']
                else:assert r['business_pass'],r
                assert r['protocol_correct'] is (True if enabled else None),r
                r.update(seed=entry['seed'],api_calls=0,offline_scripted_actions=len(api.calls),test_only=True);results.append(r)
                write_json(s.path/'result.json',r)
                inputs.append([text(c['request']) for c in api.calls])
                bad=copy.deepcopy(s.artifacts)
                if scene=='travel':bad['final']['total']+=1
                elif scene=='academic':bad['report_final']['revision']=999
                else:bad['changed_final']['schedule'][0]['slot']=99
                if a.flow_only:
                    from .evaluation_judge import process_verdict
                    assert process_verdict(scene,module.ROLES,s.events,s.actions,s.admissions,bad,True,None)['flow_complete']
                    missing=[e for e in s.events if e['kind']!='delegation']
                    assert not process_verdict(scene,module.ROLES,missing,s.actions,s.admissions,bad,True,None)['flow_complete']
                    assert not process_verdict(scene,module.ROLES,s.events,s.actions,s.admissions,bad,False,'API interrupted')['flow_complete']
                else:assert not module.judge(s.facts,bad,s.events)['business_pass'],'independent oracle accepted corrupt business answer'
                if scene=='academic':assert len(s.artifacts['revision_history'])==3,'model-requested extra revision blocked'
            finally:s.backend.mesh.close()
        assert inputs[0]==inputs[1],scene+' model inputs differ byte-for-byte'
    # Real correction control flow with a deliberately malformed offline model:
    # remaining episode budget is smaller than the per-action retry allowance.
    entry=data['academic']['formal'][0];proof=next(x for x in proofs['academic'] if x['seed']==entry['seed'])
    api=SimpleNamespace(process_owned=True,model='OFFLINE_FIXTURE',limit=2,max_tokens=6144,calls=[],format_retries=2,
        test_profile=dict(initial=entry['facts'],proof=proof,always_bad=True))
    s=EvaluationSession(run,api,'correction-bound',False,academic_scene.ROLES,pol['prompts']['academic'],limit=2)
    try:
        from .travel_domain import tool,choice
        offered=tool('request_dossier','Request the dossier.',{'study':choice(['effect_cost_anomaly'])})
        try:s.ask('lead',offered,{'instruction':'Request the dossier.'})
        except RuntimeError:pass
        else:raise AssertionError('malformed output was repaired by program')
        assert len(api.calls)==2 and all(c['status']=='error' for c in api.calls)
        try:s.ask('lead',offered,{})
        except RuntimeError as e:assert 'episode API cap' in str(e)
        else:raise AssertionError('episode API hard cap bypassed')
        assert s.backend.mesh.call(s.roles['lead'],'stats')['api_calls']==2
        results.append(dict(test='bounded_model_correction_and_episode_cap',passed=True,offline_actions=2,api_calls=0))
    finally:s.backend.mesh.close()
    # Freeze/gate unit check: no credentials or external model involved.
    from .rq3_retest import validate_pilot,summarize
    gate=run.out/'test-only-pilot-gate';gate.mkdir()
    pilot_episodes=10*len(a.scenes)
    manifest=dict(status='COMPLETED',episodes=pilot_episodes,system_unexpected_interruptions=0,protocol_audit_failures=0)
    write_json(gate/'frozen.json',pol);write_json(gate/'manifest.json',manifest);validate_pilot(gate,pol)
    failures=[('episodes',pilot_episodes-1),('status','RUNNING'),('system_unexpected_interruptions',1),('protocol_audit_failures',1)]
    for key,value in failures:
        write_json(gate/'manifest.json',{**manifest,key:value})
        try:validate_pilot(gate,pol)
        except AssertionError:pass
        else:raise AssertionError('invalid pilot gate accepted '+key)
    write_json(gate/'manifest.json',manifest)
    try:validate_pilot(gate,{**pol,'model':'CHANGED'})
    except AssertionError:pass
    else:raise AssertionError('changed settings accepted')
    sample=[dict(scene='travel',seed=1,with_system=e,flow_complete=e,business_pass=False,
        system_unexpected_interruption=False,protocol_correct=True if e else None,api_calls=5,total_seconds=1) for e in (True,False)]
    report=summarize(sample);assert report['scenes']['travel']['arms']['without']['episodes']==1
    assert len(report['scenes']['travel']['pairs'])==1 and not report['scenes']['travel']['pairs'][0]['without_flow']
    results.append(dict(test='pilot_freeze_gate_and_failed_pair_retention',passed=True,api_calls=0))
    if a.flow_only:
        report=summarize([r for r in results if 'scene' in r],a.scenes)
        assert set(report['scenes'])==set(a.scenes)
        assert all(v['business_pass'] is None and v['business_evaluated']==0 for s in report['scenes'].values() for v in s['arms'].values())
    run.finish(results);print(f'PASS: {2*len(a.scenes)} cross-process fixture workflows + correction cap + freeze/pair gates; zero external API calls')

if __name__=='__main__':main()
