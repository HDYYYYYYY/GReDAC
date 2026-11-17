"""Independent acceptance from original rows; never called by live tools.

Checks numerical/evidence/scope/revision consistency, NOT unrestricted prose
truth or writing quality. Does not import the aggregation/checking tools.
"""
def judge(initial,artifacts,events):
    coverage={k:any(e['kind']==k for e in events) for k in
        ('stable','delegation','multitask','caller_recovery','service_recovery')}
    errors=[]
    if not initial:return dict(business_pass=False,coverage=coverage,coverage_pass=all(coverage.values()),errors=['missing input'])
    expected={}
    for group in {r['group'] for r in initial['rows']}:
        records=[r for r in initial['rows'] if r['group']==group]
        expected[group]=dict(group=group,count=3,row_ids=sorted(r['id'] for r in records),
            mean_latency_ms=int(sum(r['latency_ms'] for r in records)/3),
            mean_throughput_rps=int(sum(r['throughput_rps'] for r in records)/3),
            mean_cost_units=int(sum(r['cost_units'] for r in records)/3))
    final=artifacts.get('report_final',artifacts.get('report2'))
    aggregate=artifacts.get('aggregates',[])
    # Evidence row order has no semantic meaning. Preserve multiplicity so a
    # duplicated/missing row is still rejected; never alter numeric outputs.
    normalize=lambda table:{r['group']:{**r,'row_ids':sorted(r['row_ids'])} for r in table}
    if len(aggregate)!=4 or normalize(aggregate)!=expected:errors.append('calculator omitted source rows')
    if not final:errors.append('no final report')
    else:
        table=final.get('table',[])
        if len(table)!=4 or normalize(table)!=expected:errors.append('all-record table incorrect')
        claims={c['topic']:c for c in final.get('conclusions',[])}
        if set(claims)!={'effect','cost','anomaly'} or len(final.get('conclusions',[]))!=3:errors.append('claim coverage')
        all_ids={r['id'] for r in initial['rows']}
        for topic,claim in claims.items():
            if claim['scope']!='measured_only':errors.append('unsupported scope')
            if topic in ('effect','cost') and not all_ids<=set(claim['evidence_ids']):errors.append('incomplete comparison evidence')
            if topic=='anomaly' and initial['anomaly_id'] not in claim['evidence_ids']:errors.append('missing anomaly evidence')
        faster={w:expected['B-'+w]['mean_latency_ms']<expected['A-'+w]['mean_latency_ms'] for w in ('light','heavy')}
        expected_effect=('B_faster_all' if all(faster.values()) else
            'B_faster_light_only' if faster['light'] and not faster['heavy'] else
            'A_faster_all' if not any(faster.values()) else 'unexpected_data')
        if claims.get('effect',{}).get('finding')!=expected_effect:errors.append('effect interpretation')
        a_cost=sum(r['cost_units'] for r in initial['rows'] if r['group'].startswith('A-'))
        b_cost=sum(r['cost_units'] for r in initial['rows'] if r['group'].startswith('B-'))
        expected_cost='B_more_expensive' if b_cost>a_cost else 'A_more_expensive' if a_cost>b_cost else 'equal_cost'
        if claims.get('cost',{}).get('finding')!=expected_cost:errors.append('cost interpretation')
        if claims.get('anomaly',{}).get('finding')!='retain_anomaly_no_causal_claim':errors.append('anomaly interpretation')
        if len(final.get('markdown','').split())<150:errors.append('report too short')
    revisions=[h['revision'] for h in artifacts.get('revision_history',[])] or [1,2]
    if revisions!=list(range(1,len(revisions)+1)) or not 2<=len(revisions)<=4:errors.append('invalid revision history')
    for revision in revisions:
        old=artifacts.get('report'+str(revision-1),{});new=artifacts.get('report'+str(revision),{})
        review=artifacts.get('review'+str(revision),{})
        issues={i['id'] for i in review.get('issues',[])}
        if not issues:errors.append('no actual reviewer issues')
        if new.get('revision')!=revision or old.get('markdown')==new.get('markdown'):errors.append('no authored revision')
        if not issues<=set(new.get('addressed_issues',[])):errors.append('unaddressed review issues')
    for key in ('partner_approval','lead_approval'):
        approval=artifacts.get(key,{})
        if approval.get('decision')!='accept' or approval.get('revision')!=revisions[-1]:errors.append('no final agreement: '+key)
    return dict(business_pass=not errors,coverage=coverage,coverage_pass=all(coverage.values()),errors=errors)
