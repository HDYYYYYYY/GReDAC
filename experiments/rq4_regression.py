"""RQ4 measurement/orchestration regressions, without performance or LLM runs.

Synthetic rows here test arithmetic and failure semantics only. They are not
saved as experimental observations. Actual TCP/commit recovery is exercised
separately by the bounded smoke command.
"""
import argparse,json,tempfile
from pathlib import Path
from .support import write_json


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);checks=[]
    from .rq4_full_40g import jobs as current_jobs
    jobs=current_jobs()
    assert len(jobs)==39 and {g:sum(x['group']==g for x in jobs) for g in 'ABD'}=={'A':15,'B':15,'D':9}
    assert {x['case']['services'] for x in jobs if x['group'] in 'AB'}=={1,8,32,128,256}
    assert {x['case']['services'] for x in jobs if x['group']=='D'}=={8}
    assert all('fixed_load' not in x['module'] and '--downtime' not in x['args'] for x in jobs)
    checks.append('current_39_fixed_attempts_AB_max256_D8_no_C_or_extensions')
    from .rq4_waits import Waits,DEFAULT_WAIT,union_seconds,sleep_selected
    from types import SimpleNamespace
    calibration=Waits(SimpleNamespace(out=a.out,manifest={}),DEFAULT_WAIT)
    assert calibration.data['selected_episodes']==150
    for scene,bucket in calibration.data['scenes'].items():
        assert bucket['episodes']==50 and bucket['with_system']==bucket['without_system']==25
        for gap in bucket['business']:
            assert abs(gap['seconds']-(gap['raw_gap_seconds']-gap['protocol_union_seconds']))<1e-8
            assert gap['protocol_union_seconds']==0 or gap['with_system']
    checks.append('latest_150_selected_tasks_both_arms_three_scenes_and_gap_accounting')
    assert union_seconds([(0,8),(2,4),(6,10)],3,9)==6
    assert union_seconds([(0,2),(4,6)],1,5)==2
    checks.append('nested_protocol_union_clipped_to_business_gap')
    assert calibration.plan('A',0,2)==calibration.plan('A',0,8)[:2]
    assert calibration.plan('B',0,2)==calibration.plan('B',0,11)[:2]
    assert calibration.plan('D',0,11,0)==calibration.plan('D',0,11,0)
    assert calibration.plan('D',0,11,0)!=calibration.plan('D',0,11,1)
    assert all(x['kind']=='api' for x in calibration.plan('A',0,20))
    assert all(x['kind']=='business' for x in calibration.plan('D',0,20))
    checks.append('deterministic_K_prefix_fault_pairs_independent_team_streams_and_wait_kind')
    for sample in calibration.plan('A',2,100)+calibration.plan('B',2,100):
        source=calibration.data['scenes'][sample['scene']][sample['kind']][sample['sample_index']]
        assert source['seconds']==sample['requested_wait_s'] and source['case']==sample['source_case']
    checks.append('sampled_observations_unchanged_no_clipping_or_double_wait')
    from unittest.mock import patch
    sample=calibration.plan('A',0,1)[0]
    with patch('experiments.rq4_waits.time.sleep') as sleeper,patch('experiments.rq4_waits.time.monotonic',side_effect=[10.,12.]):
        waited=sleep_selected(sample);sleeper.assert_called_once_with(sample['requested_wait_s'])
        assert waited['actual_wait_s']==2 and waited['requested_wait_s']==sample['requested_wait_s']
    checks.append('sleep_requested_and_actual_separate_regression_clock_not_performance')
    source=(Path(__file__).parent/'rq4_team_faults.py').read_text()
    assert 'time.sleep(' not in source and "event['injected_downtime']=0" in source and "process.exitcode==73" in source
    checks.append('real_process_exit_preserved_no_artificial_fault_downtime')
    assert current_jobs()==jobs  # A run outcome cannot alter this fixed plan.
    checks.append('current_plan_has_no_result_dependent_extension')
    from .rq4_support import request_stats,Monitor
    samples=[dict(release=0,submitted=.1,thread_start=.3,start=.4,end=.6,error=None),
        dict(release=0,submitted=.1,thread_start=.3,start=.4,end=.8,error='failure')]
    s=request_stats(samples);assert s['completed']==1 and s['failed']==1 and abs(s['queue_ms']['mean']-300)<1e-6
    assert s['response_ms']['n']==1 and s['attempt_response_ms']['n']==2
    checks.append('failed_request_not_success_throughput_queue_decomposition')
    from .rq4_report import window
    w=window(samples,[],0,.7);assert w['completed']==1 and w['released']==2 and w['crossing_window_end']==1
    assert window([],[],1,1)['completed_rps'] is None
    checks.append('window_completions_and_crossing_requests_explicit')
    from .rq4_report import fault_pairs,components
    with tempfile.TemporaryDirectory() as td:
        root=Path(td);attempts=[]
        for label,start,stop,point in [('control',100,110,'none'),('fault',200,205,'before_commit')]:
            (root/label/'t1s-metrics').mkdir(parents=True)
            write_json(root/label/'t1s-metrics/requests.json',[
                dict(phase='measurement',release=start+1,end=start+1.5,error=None),
                dict(phase='measurement',release=start+3,end=start+3.5,error=None)])
            write_json(root/label/'management_operations.json',[])
            attempts.append(dict(group='D',exitcode=0,case=dict(services=2,point=point),repeat=0,directory=label,
                result=dict(teams=2,traffic_begin=start,traffic_end=stop,event=dict(actual_crash=start+2,new_delegation_and_consumption=start+6))))
        pair=fault_pairs(root,attempts)[0]
        assert pair['phases']['before']['throughput_difference_rps']==0
        assert pair['phases']['event']['complete_window'] is False
        assert pair['phases']['after']['status']=='no_common_observation_window'
        assert pair['phases']['event']['fault']['completed']==1
        trace=root/'transactions.jsonl'
        trace.write_text(json.dumps(dict(start_ns=10**12,end_ns=10**12+1000,begin_ns=1000))+'\n')
        durations=components(root)['transaction_fields_ms']
        assert set(durations)=={'begin_ns'} and durations['begin_ns']['mean']==.001
    checks.append('matched_fault_windows_exclude_target_and_mark_truncation')
    checks.append('transaction_durations_exclude_absolute_clock_values')
    # Use actual process sampling, not historical per-PID peaks.
    from types import SimpleNamespace
    m=Monitor(SimpleNamespace(out=a.out));m.sample();summary=m.close()
    assert summary['sampled_peak_total_rss_kib']>0 and (a.out/'resources.json').exists()
    checks.append('simultaneous_sampled_rss_and_resource_file')
    from .rq4_support import Federation,CapacityLimit
    import time
    fake=Federation.__new__(Federation);fake.start=time.monotonic();fake.members=[];fake.k=64
    fake.monitor=SimpleNamespace(memory=lambda:10*1024**2);fake.artifacts=a.out
    fake.memory_budget_gib=24;fake.check_preparation()
    fake.memory_budget_gib=8
    try:fake.check_preparation()
    except CapacityLimit:pass
    else:raise AssertionError('8 GiB capacity boundary was ignored')
    checks.append('multi_team_resource_budget_separate_from_single_team_capacity')
    # Frozen CLI source must not quietly select the legacy MemoryBIO runner.
    for module in ('rq4_contacts','rq4_fanout','rq4_team_faults'):
        text=(Path(__file__).parent/(module+'.py')).read_text()
        assert 'from .rq4_matrix import matrix' in text and 'rq4_fault_transport' not in text
    checks.append('all_three_entries_use_current_network_case_runner')
    write_json(a.out/'manifest.json',dict(status='PASS',tests=checks,llm_api_calls=0,measurement_scope='regression only'))
    print(json.dumps(dict(status='PASS',checks=len(checks))),flush=True)
if __name__=='__main__':main()
