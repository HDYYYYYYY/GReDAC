"""Local deterministic calendar inputs and violation-only checking tool.

No scheduler/search/repair algorithm exists here. The fixed personnel change
is identical in both arms and independent of the model's initial schedule.
It forces at least part of the initial agreement to move. Permission changes
are emitted separately by the workflow and do not cancel business meetings.
"""
import random

def facts(seed):
    rng=random.Random(seed)
    availability={p:list(range(12)) for p in ('LeadA','LeadB','Expert','Owner','QA')}
    availability['Expert']=list(range(2,8))
    availability['LeadA'].remove(rng.choice([8,9,10]))
    availability['LeadB'].remove(rng.choice([2,6,7]))
    availability['Owner'].remove(rng.choice([2,3,6,8,10,11]))
    rooms={'R1':dict(capacity=4,available=list(range(12))),
           'R2':dict(capacity=2,available=list(range(12)))}
    # Use ONE seeded closure; do not draw a different closure for each slot.
    blocked=rng.choice([2,3,6,8,10,11]);rooms['R1']['available']=[i for i in range(12) if i!=blocked]
    meetings=[]
    for project in ('A','B'):
        for stage in ('kickoff','design','review'):
            people=['Lead'+project]+(['Owner'] if stage=='kickoff' else ['Expert'] if stage=='design' else ['Expert','Owner','QA'])
            predecessor=[] if stage=='kickoff' else [project+'-'+('kickoff' if stage=='design' else 'design')]
            meetings.append(dict(id=project+'-'+stage,project=project,attendees=people,duration=1,after=predecessor))
    rng.shuffle(meetings)
    return dict(seed=seed,label='local controlled calendar, no external calendar writes',
        slot_definition='12 consecutive one-hour slots; one slot per meeting',meetings=meetings,
        rooms=rooms,availability=availability,initial_deadline=8,
        change=dict(kind='person_unavailable',person='Expert',unavailable_slots=[2,3,4,5],
            resulting_expert_available=[6,7,8,9,10,11],new_deadline=12,
            explanation='Expert becomes unavailable in earlier slots; both projects authorize the later window.'))

def check_calendar(initial,schedule,phase):
    """Return violations only. Never return a suggested or repaired schedule."""
    meetings={m['id']:m for m in initial['meetings']};issues=[]
    if len(schedule)!=len(meetings) or {x['meeting'] for x in schedule}!=set(meetings):issues.append('each of six meetings exactly once')
    available=dict(initial['availability'])
    if phase=='changed':available['Expert']=initial['change']['resulting_expert_available']
    deadline=initial['initial_deadline'] if phase=='initial' else initial['change']['new_deadline']
    used_people={};used_rooms={};by_id={x['meeting']:x for x in schedule}
    for item in schedule:
        if item['meeting'] not in meetings:issues.append('unknown meeting');continue
        m=meetings[item['meeting']];slot=item['slot'];room=initial['rooms'].get(item['room'])
        if not room:issues.append('unknown room');continue
        if not 0<=slot<deadline:issues.append(m['id']+': outside authorized time window')
        if slot not in room['available'] or room['capacity']<len(m['attendees']):issues.append(m['id']+': room unavailable/capacity')
        if (item['room'],slot) in used_rooms:issues.append(m['id']+': room conflict with '+used_rooms[item['room'],slot])
        used_rooms[item['room'],slot]=m['id']
        for person in m['attendees']:
            if slot not in available[person]:issues.append(m['id']+': '+person+' unavailable')
            if (person,slot) in used_people:issues.append(m['id']+': '+person+' overlaps '+used_people[person,slot])
            used_people[person,slot]=m['id']
        for before in m['after']:
            if before not in by_id or by_id[before]['slot']>=slot:issues.append(m['id']+': predecessor order')
    return dict(valid=not issues,violations=issues,phase=phase)

def canonical(schedule):return sorted(schedule,key=lambda r:r['meeting'])
