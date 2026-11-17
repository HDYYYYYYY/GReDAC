"""Frozen design and timing regression; actual protocol is exercised in pilot."""
import argparse
import ast
import json
import os
from collections import Counter
from pathlib import Path


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    os.environ['GREDAC_SLOT_BITS']='15'
    from .suite import jobs,PACKAGE,protected_fingerprint
    checks=[]
    second=jobs('full','dialogue');third=jobs('full','structure')
    assert len(second)==36 and len(third)==84
    assert Counter(j['case']['requests'] for j in second)=={n:6 for n in (1,8,32,128,512,2048)}
    assert all(j['case']['method']=='GReDAC' and j['case']['issued']==j['case']['units']==2048 for j in second)
    checks.append('36_GReDAC_dialogue_attempts_fixed_2048_no_comparison')
    for axis,key,values in [('depth','depth',(1,2,4,8,16)),('quota','units',(64,256,1024,4096)),('fragmentation','cover',(1,4,16,64,256))]:
        subset=[j for j in third if j['case']['axis']==axis]
        assert Counter(j['case'][key] for j in subset)=={v:6 for v in values}
        assert all(j['case']['requests']==9 and j['case']['issued']==32768 for j in subset)
    assert [j['case']['axis'] for j in third]==['depth']*30+['quota']*24+['fragmentation']*30
    checks.append('84_structure_attempts_three_independent_axes_and_order')
    assert len(jobs('pilot','dialogue'))==2 and len(jobs('pilot','structure'))==6
    assert not any(j['module'].endswith('.flow') for j in second+third)
    checks.append('independent_extreme_pilots_no_flow_or_LLM_entry')
    from .fragmentation import selected
    from gredac.crypto import SLOT_BITS,cover,domain_for
    assert SLOT_BITS==15
    for c in (1,4,16,64,256):
        scope=selected(c)
        assert len(set(scope))==256 and max(scope)<512 and len(cover(domain_for(['query'],scope)))==c
    checks.append('actual_minimal_prefix_cover_not_interval_count')
    assert protected_fingerprint()==json.loads((PACKAGE/'protected_baseline.json').read_text())
    checks.append('149_core_and_first_group_source_files_identical')
    from experiments.rq2_v2.results import stats,union_ns
    assert stats([]) is None and stats([1,2,3])['p50']==2
    assert union_ns([(0,10),(2,4),(8,12)])==12
    from .results import flattened
    assert flattened({'hot_ms':None})['hot_p95_ms'] is None
    checks.append('N1_has_no_hot_stat_nested_intervals_not_added')
    # First-group fingerprint ignores the new sibling package, by design.
    # All new package files are instead covered by its own recursive freeze.
    from .suite import fingerprint
    assert set(protected_fingerprint())<set(fingerprint())
    for path in PACKAGE.glob('*.py'):ast.parse(path.read_text())
    checks.append('separate_recursive_freeze_valid_python')
    from experiments.rq2_v2 import timing
    trace=timing.start(a.out/'timing','GReDAC','test','test')
    with trace.span('parent','II') as outer:
        with trace.span('child') as inner:pass
    trace.flush()
    assert outer['start_ns']<=inner['start_ns']<=inner['end_ns']<=outer['end_ns']
    assert inner['parent_span_id']==outer['span_id']
    checks.append('real_monotonic_clock_preserved_parent_relation')
    (a.out/'manifest.json').write_text(json.dumps(dict(status='PASS',tests=checks,llm_api_calls=0),indent=2))
    print('PASS',len(checks),'later-step checks')


if __name__=='__main__':main()
