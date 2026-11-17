"""Independent calendar verifier; uses pairwise overlap, not live-tool code."""
def valid(initial,schedule,changed):
    errors=[]
    if not isinstance(schedule,list):return ['missing schedule']
    definition={m['id']:m for m in initial['meetings']}
    ids=[r.get('meeting') for r in schedule]
    if len(ids)!=6 or len(set(ids))!=6 or set(ids)!=set(definition):return ['meeting set mismatch']
    deadline=initial['change']['new_deadline'] if changed else initial['initial_deadline']
    lookup={r['meeting']:r for r in schedule}
    for item in schedule:
        m=definition[item['meeting']];start=item.get('slot');room=initial['rooms'].get(item.get('room'))
        if type(start) is not int or not 0<=start<deadline:errors.append('time range');continue
        if room is None or start not in room['available'] or len(m['attendees'])>room['capacity']:errors.append('room constraint')
        for person in m['attendees']:
            allowed=initial['change']['resulting_expert_available'] if changed and person=='Expert' else initial['availability'][person]
            if start not in allowed:errors.append('availability '+person)
        if any(lookup[pre]['slot']+definition[pre]['duration']>start for pre in m['after']):errors.append('precedence')
    for i,left in enumerate(schedule):
        for right in schedule[i+1:]:
            a,b=definition[left['meeting']],definition[right['meeting']]
            overlap=left['slot']<right['slot']+b['duration'] and right['slot']<left['slot']+a['duration']
            if overlap and (left['room']==right['room'] or set(a['attendees'])&set(b['attendees'])):errors.append('resource overlap')
    return errors

def judge(initial,artifacts,events):
    coverage={k:any(e['kind']==k for e in events) for k in
        ('stable','delegation','multitask','caller_recovery','service_recovery')}
    if not initial:return dict(business_pass=False,coverage=coverage,coverage_pass=all(coverage.values()),errors=['missing input'])
    initial_schedule=artifacts.get('initial_final',{}).get('schedule')
    final=artifacts.get('changed_final',{}).get('schedule');errors=valid(initial,initial_schedule,False)+valid(initial,final,True)
    canonical=lambda s:sorted(s,key=lambda r:r['meeting']) if isinstance(s,list) else None
    for prefix,target in [('initial',initial_schedule),('changed',final)]:
        for role in ('partner','lead'):
            decision=artifacts.get(prefix+'_'+role,{})
            selected=(artifacts.get(decision.get('proposal_ref'),{}).get('schedule') if 'proposal_ref' in decision else decision.get('schedule'))
            if decision.get('decision')!='accept' or canonical(selected)!=canonical(target):errors.append(prefix+' '+role+' agreement')
    if canonical(initial_schedule)==canonical(final):errors.append('no actual rescheduling')
    if not any(e['kind']=='business_person_unavailable' for e in events):errors.append('missing business event')
    return dict(business_pass=not errors,coverage=coverage,coverage_pass=all(coverage.values()),errors=errors)
