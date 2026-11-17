"""OFFLINE only: fault fixtures + real-process/TLS paired workflows.

No external API requests. Fixture answers are restricted to this regression;
the live runner has no test_profile and does not load feasibility witnesses.
"""
import argparse,copy,json,os
from http.client import IncompleteRead
from pathlib import Path
from types import SimpleNamespace


def process_main(name,directory,path,pipe):
    from .runtime import install_actor
    from experiments import network_actor
    install_actor();original_config=network_actor.Node.model_config
    def configured(node,**args):
        value=original_config(node,**args)
        profile=args.get('test_profile') or {}
        if profile.get('transient_identity')==node.name:
            original=node.api.call;pending=True
            def call(role,history,offered,observation,case):
                nonlocal pending
                if pending:
                    pending=False
                    from experiments.agent_input import text,object_order
                    history.append(dict(role='user',content=text(observation)))
                    node.api.calls.append(dict(case=case,role=role,status='error',error='OFFLINE IncompleteRead(1387 bytes read)',
                        seconds=0,scripted=True,api_process_pid=os.getpid(),request=dict(messages=object_order(history),
                        tools=[object_order(offered)],model='OFFLINE_FIXTURE')))
                    raise IncompleteRead(b'x'*1387)
                return original(role,history,offered,observation,case)
            node.api.call=call
        return value
    network_actor.Node.model_config=configured
    network_actor.process_main(name,directory,path,pipe)


def unit_checks():
    from .runtime import one_attempt,transient
    checks=[]
    class FakeAPI:
        def __init__(self,failures):self.failures=list(failures);self.calls=[]
        def call(self,role,history,offered,observation,case):
            history.append(dict(role='user',content=json.dumps(observation,sort_keys=True)))
            row=dict(request=copy.deepcopy(history),seconds=0,status='error');self.calls.append(row)
            kind=self.failures.pop(0) if self.failures else 'ok'
            if kind=='timeout':raise TimeoutError('OFFLINE timeout')
            if kind=='read-empty':raise IncompleteRead(b'')
            if kind=='read-partial':raise IncompleteRead(b'x'*1387)
            if kind=='401':row['http_status']=401;raise RuntimeError('HTTP 401')
            if kind=='format':row['response']={'choices':[{'finish_reason':'length'}]};raise ValueError('OFFLINE bad JSON')
            row.update(status='ok',response={'usage':{'total_tokens':1}})
            return {'model_generated':'fixture'},'cid'
    def run(failures,cap=30):
        api=FakeAPI(failures);log=[]
        node=SimpleNamespace(api=api,name='test',history=[],record=lambda kind,body:log.append(body['attempt_outcome']),save_history=lambda:None)
        from . import runtime
        old_sleep=runtime.time.sleep;runtime.time.sleep=lambda n:None
        try:
            for _ in range(6):
                r=one_attempt(node,{'function':{'name':'task'}},{'facts':'original'},'test',cap-len(api.calls),'action-1')
                if not r.get('retry'):return r,api,log
            raise AssertionError('unbounded retry')
        finally:runtime.time.sleep=old_sleep
    r,api,log=run(['timeout']);assert 'arguments' in r and len(api.calls)==2
    assert api.calls[0]['request']==api.calls[1]['request'],'transient changed generation input'
    assert log[-1]['requested_wait_seconds']==1
    r,api,log=run(['timeout']*8);assert 'error' in r and len(api.calls)==3
    assert [x['requested_wait_seconds'] for x in log]==[0,1,2]
    r,api,log=run(['401']);assert 'error' in r and len(api.calls)==1
    checks.append('transient_exact_input_two_extra_limit_401_no_retry')
    # Match both partial-body sizes observed in the real 30-task pilot.
    # Failed generations do not execute tools and must resend identical input.
    for kind in ['read-empty','read-partial']:
        r,api,log=run([kind]);assert 'arguments' in r and len(api.calls)==2
        assert api.calls[0]['request']==api.calls[1]['request']
        assert log[0]['kind']=='api_transient' and log[0]['will_retry']
        assert log[1]['requested_wait_seconds']==1
        r,api,log=run([kind]*8);assert 'error' in r and len(api.calls)==3
        assert [x['requested_wait_seconds'] for x in log]==[0,1,2]
        r,api,log=run([kind],1);assert 'error' in r and len(api.calls)==1
        assert not log[0]['will_retry']
    assert not transient({'response':{}},IncompleteRead(b''))
    assert not transient({'http_status':401},IncompleteRead(b''))
    assert not transient({},ValueError('malformed complete JSON'))
    checks.append('incomplete_read_empty_partial_same_input_two_extra_limit_episode_cap')
    r,api,log=run(['read-empty','format','read-partial','format','format'])
    assert 'error' in r and len(api.calls)==5
    checks.append('incomplete_read_and_format_share_five_attempt_limit')
    r,api,log=run(['format']*4);assert 'arguments' in r and len(api.calls)==5
    r,api,log=run(['format']*8);assert 'error' in r and len(api.calls)==5
    r,api,log=run(['format']*8,2);assert 'error' in r and len(api.calls)==2
    r,api,log=run(['timeout','format','format','format','format']);assert 'error' in r and len(api.calls)==5
    checks.append('five_action_attempts_shared_total_episode_cap_and_format_no_program_repair')
    assert transient({'http_status':429},RuntimeError()) and transient({'http_status':503},RuntimeError())
    assert not transient({'http_status':403},RuntimeError())
    checks.append('transient_http_classification_permanent_errors_stop')
    from experiments.travel_domain import validate
    from .workflows import schedule_proposal_tool
    root=Path(__file__).resolve().parents[2]
    initial=json.loads((root/'experiments/data/rq3_20261108_instances.json').read_text())['calendar']['formal'][0]['facts']
    offered=schedule_proposal_tool(initial);schema=offered['function']['parameters']
    # Syntax-only fixture, not a business solution. Test the exact live schema.
    value=dict(schedule=[dict(meeting=m['id'],slot=0,room='R1') for m in initial['meetings']],reasoning='x'*630)
    for length in (600,601,630,1029,3583,7985):
        value['reasoning']='x'*length;before=copy.deepcopy(value)
        validate(value,schema);assert value==before,'validation truncated the explanation'
    invalid=[{k:v for k,v in value.items() if k!='reasoning'},
        {**value,'reasoning':123},{**value,'schedule':value['schedule'][:5]},
        {**value,'extra':'not permitted'}]
    for field,bad in [('meeting','nonexistent'),('slot',12),('room','R3')]:
        candidate=copy.deepcopy(value);candidate['schedule'][0][field]=bad;invalid.append(candidate)
    for candidate in invalid:
        try:validate(candidate,schema)
        except AssertionError:pass
        else:raise AssertionError('required schedule validation weakened')
    checks.append('calendar_long_explanation_preserved_required_fields_types_six_meetings_enums')
    # Exercise the actual strict client with local HTTP-response fixtures only.
    # A complete longer explanation is accepted unchanged; wrong tool names and
    # incomplete JSON still fail. No external request or answer repair occurs.
    from experiments.llm_api import StrictAPI
    from unittest.mock import patch
    from tempfile import TemporaryDirectory
    from io import BytesIO
    with TemporaryDirectory(prefix='rq3-schema-offline-') as directory:
        api=StrictAPI('','OFFLINE_FIXTURE',3,Path(directory))
        for tool_name,arguments,valid in [('propose_schedule',json.dumps(value),True),
                ('agree_schedule',json.dumps(value),False),('propose_schedule','{"reasoning":',False)]:
            response={'choices':[{'message':{'tool_calls':[{'id':'offline','type':'function',
                'function':{'name':tool_name,'arguments':arguments}}]}}]}
            with patch('urllib.request.urlopen',return_value=BytesIO(json.dumps(response).encode())) as http:
                try:
                    actual,_=api.call('test',[],offered,{'instruction':'OFFLINE'},'syntax-only')
                except (AssertionError,json.JSONDecodeError):assert not valid
                else:assert valid and actual==value
                assert http.call_count==1
        assert [r['status'] for r in api.calls]==['ok','error','error']
    checks.append('strict_client_long_text_unchanged_wrong_tool_and_incomplete_JSON_rejected')
    return checks


def main():
    from experiments.support import Run,write_json
    from experiments.evaluation_support import EvaluationSession
    from experiments import travel_scene,academic_scene,calendar_scene
    from experiments.agent_input import text
    from . import workflows
    from .policy import settings,CAPS,TOKENS,fingerprint
    from .runtime import install_driver,retry_statistics
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);a=p.parse_args();a.repeats=1;a.slot_bits=8
    os.environ['GREDAC_OFFLINE_REGRESSION']='1';run=Run(a,'rq3_current_regression');checks=unit_checks()
    root=Path(__file__).resolve().parents[2];inputs=root/'experiments/data/rq3_20261108_instances.json'
    data=json.loads(inputs.read_text());proofs=json.loads((root/'docs/rq3-retest/FEASIBILITY_TEST_ONLY.json').read_text())['scenes']
    pol=settings('OFFLINE_FIXTURE',inputs);install_driver()
    from experiments import network_actor
    from gredac.crypto import SLOT_BITS
    assert SLOT_BITS==8
    from .regression import process_main as test_process
    network_actor.process_main=test_process
    results=[]
    for scene,module in [('travel',travel_scene),('academic',academic_scene),('calendar',calendar_scene)]:
        entry=data[scene]['formal'][0];proof=next(x for x in proofs[scene] if x['seed']==entry['seed']);paired=[]
        for enabled in (True,False):
            api=SimpleNamespace(process_owned=True,model='OFFLINE_FIXTURE',limit=CAPS[scene],max_tokens=TOKENS[scene],calls=[],
                test_profile=dict(initial=entry['facts'],proof=proof,extra_round=True,inject_format=True,transient_identity=module.ROLES['lead']))
            s=EvaluationSession(run,api,scene+str(enabled),enabled,module.ROLES,pol['prompts'][scene],limit=CAPS[scene])
            try:
                fn={'travel':module.execute,'academic':workflows.execute_academic,'calendar':workflows.execute_calendar}[scene]
                fn(s,entry['seed'],copy.deepcopy(entry['facts']))
                def forbidden(*args):raise AssertionError('business oracle invoked in flow-only mode')
                r=s.evaluate(scene,module.ROLES,forbidden,None,True,evaluate_business=False)
                assert r['flow_complete'] and r['protocol_correct'] is (True if enabled else None),r
                assert not r['business_evaluated'] and r['business_pass'] is None
                routes=s.backend.mesh.routes
                assert len({v['pid'] for v in routes.values()})==len(routes)
                assert all(c['api_process_pid']==c['actor_pid']!=os.getpid() for c in api.calls)
                retry=retry_statistics(api.calls);assert retry['recovered_actions']>=1 and retry['failed_attempts_by_kind']['api_transient']==1
                assert len(api.calls)<=CAPS[scene]
                assert all(r['passed'] for r in s.backend.safety_checks)
                paired.append([text(c['request']) for c in api.calls])
                results.append(dict(scene=scene,with_system=enabled,flow_complete=True,protocol_correct=r['protocol_correct'],
                    retry=retry,offline_fixture_calls=len(api.calls),real_api_calls=0))
            finally:s.backend.mesh.close()
        assert paired[0]==paired[1],scene+' paired inputs differ'
        checks.append(scene+'_paired_cross_process_TCP_TLS_same_inputs_five_stages_recovery_and_ledger')
    from .run import validate_pilot
    gate=run.out/'OFFLINE-test-only-gate';gate.mkdir()
    write_json(gate/'frozen.json',pol);write_json(gate/'manifest.json',dict(status='COMPLETED',episodes=30,
        system_unexpected_interruptions=0,protocol_audit_failures=0))
    validate_pilot(gate,pol)
    try:validate_pilot(gate,{**pol,'retry':{'max_action_attempts':99}})
    except AssertionError:pass
    else:raise AssertionError('changed retry policy accepted')
    checks.append('pilot_requires_identical_retry_prompts_and_source')
    protected=json.loads((Path(__file__).parent/'protected_baseline.json').read_text())
    import hashlib
    assert all(hashlib.sha256((root/n).read_bytes()).hexdigest()==h for n,h in protected.items())
    checks.append(f'all_{len(protected)}_public_baseline_files_unchanged')
    run.finish(results);run.manifest.update(status='PASS',checks=checks,real_api_calls=0,source_sha256=fingerprint())
    write_json(run.out/'manifest.json',run.manifest);print('PASS',len(checks),'checks; six real-process offline workflows; zero real API calls')


if __name__=='__main__':main()
