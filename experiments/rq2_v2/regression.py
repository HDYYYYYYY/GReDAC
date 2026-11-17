"""Matrix/measurement tests; real roles and quota bounds are checked in pilot."""
import argparse,ast,hashlib,json,os,tempfile,time,zipfile
from pathlib import Path


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    os.environ['GREDAC_SLOT_BITS']='15';checks=[]
    from .suite import jobs
    formal=jobs('full');pilot=jobs('pilot')
    assert len(formal)==36 and len(pilot)==6
    assert len(jobs('full','flow'))==36 and len(jobs('pilot','flow'))==6
    assert all(j['case']['requests']==32 and j['case']['units']==128 for j in jobs('full','flow'))
    assert all(j['case']['block']=='flow' for j in formal)
    pairs={j['pair'] for j in formal};assert len(pairs)==18
    for pair in pairs:
        arms=[j for j in formal if j['pair']==pair];assert len(arms)==2 and arms[0]['case']['method']!=arms[1]['case']['method']
    checks.append('36_formal_6_flow_pilot_18_pairs_no_extra_repeats')
    from .fragmentation import selected
    from gredac.crypto import cover,domain_for,SLOT_BITS
    for c in (1,4,16,64,256):
        slots=selected(c);assert len(set(slots))==256 and len(cover(domain_for(['query'],slots)))==c and max(slots)<512
    assert SLOT_BITS==15;checks.append('real_minimal_cover_and_fixed_address_width')
    from .business import request,result,encoded,verify
    for i in (0,1,2047):assert len(encoded(request(i)))==1024 and len(encoded(result(request(i))))==256;verify(i,result(request(i)))
    try:verify(0,result(request(1)))
    except AssertionError:pass
    else:raise AssertionError('business verifier accepts a wrong result')
    checks.append('same_business_bytes_and_independent_wrong_result_rejection')
    from .results import union_ns
    assert union_ns([(0,10),(2,5),(8,12),(15,17)])==14
    checks.append('nested_and_overlapping_intervals_not_double_counted')
    root=Path(__file__).parent;source=json.loads((root/'author_source.json').read_text())
    with zipfile.ZipFile(root/'author_source.zip') as z:
        for name,h in source['files'].items():assert hashlib.sha256(z.read(name)).hexdigest()==h
    assert source['commit']=='7372111bea150e32cee390a616849316d2780bfc'
    checks.append('author_committed_sources_exact_no_untracked_extensions')
    for name in ('author.py','author_worker.py','gredac_adapter.py'):
        ast.parse((root/name).read_text())
    assert 'native_network' not in (root/'author.py').read_text()
    checks.append('author_adapter_excludes_self_written_native_protocol')
    from . import timing
    t=timing.start(a.out/'timing','regression','test','test')
    with t.span('outer','II') as outer:
        with t.span('inner') as inner:pass
    assert inner['parent_span_id']==outer['span_id'] and inner['phase']=='II'
    assert outer['start_ns']<=inner['start_ns']<=inner['end_ns']<=outer['end_ns'];t.flush()
    checks.append('physical_clock_parent_phase_and_raw_samples')
    # Observe, do not subtract or extrapolate, the wrapper bookkeeping cost.
    n=10000;start=time.perf_counter_ns()
    for _ in range(n):pass
    empty=time.perf_counter_ns()-start;start=time.perf_counter_ns()
    for _ in range(n):
        with t.span('bookkeeping'):pass
    wrapped=time.perf_counter_ns()-start
    (a.out/'wrapper_overhead.json').write_text(json.dumps(dict(iterations=n,empty_ns=empty,wrapped_ns=wrapped,
        estimated_increment_ns_per_call=(wrapped-empty)/n,scope='regression bookkeeping diagnostic, not protocol performance; never subtracted')))
    (a.out/'manifest.json').write_text(json.dumps(dict(status='PASS',tests=checks,llm_api_calls=0),indent=2))
    print('PASS',len(checks),'RQ2 checks')

if __name__=='__main__':main()
