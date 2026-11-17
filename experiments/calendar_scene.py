"""Independent two-project calendar negotiation with a fixed business change.

Models select all times/rooms, review conflicts and explicitly agree. Two
bounded rounds before and after the change allow revision; no search solver
or program-supplied schedule is available to the models. All failures remain.
"""
from .scene_harness import run_scene,tool,obj,integer,choice,text_field,array
from .calendar_data import facts,check_calendar,canonical
from .calendar_oracle import judge

ROLES=dict(lead='ProjectALead',worker='SharedScheduler',service='ProjectBLead')
ONE='Make exactly ONE offered tool call per response; wait for its result. Do not batch tool calls. '
PROMPTS={
 'lead':ONE+'Coordinate two projects. Read all calendar constraints, delegate both projects to the same scheduler, '
    'and approve only a valid, partner-agreed schedule. Copy the agreed meeting/slot/room values exactly.',
 'worker':ONE+'Schedule ALL six meetings for both projects. Choose times and rooms yourself using original constraints. '
    'One hour per meeting; kickoff before design before review for each project. Shared Expert/Owner/rooms cannot overlap. '
    'R2 holds only two people; reviews need R1. Use check_calendar, then revise from actual violations/reviewer feedback. '
    'Do not omit meetings. After personnel change use the NEW Expert availability and deadline. '
    'Role replacement does not cancel meetings or reset commitments. Return a full schedule every time.',
 'service':ONE+'Represent Project B and shared-resource stakeholders. Independently check the proposed six-meeting schedule '
    'against availability, room capacity, no overlaps and dependencies. The checking tool reports violations. '
    'Accept only if valid; otherwise request revision with concrete comments. When accepting, reproduce the exact schedule.'}

def schedule_schema(initial):
    return array(obj(dict(meeting=choice([m['id'] for m in initial['meetings']]),
        slot={'type':'integer','minimum':0,'maximum':11},room=choice(['R1','R2']))))

def execute(s,seed,initial=None,continue_on_business_rejection=False):
    initial=facts(seed) if initial is None else initial
    s.inputs(initial);schema=schedule_schema(initial)
    public={k:v for k,v in initial.items() if k!='change'}
    _,reply=s.ask('lead',tool('request_calendar','Request joint constraints for the two projects.',
        {'projects':array(choice(['A','B']))}),{'instruction':'Request both projects A and B.'})
    public=s.admit('plan',{'action':'read_calendar'})
    briefing,breply=s.ask('service',tool('brief_constraints','Explain the joint scheduling constraints.',
        {'briefing':text_field()}),{'calendar':public,'instruction':'Do not propose an automatic reference schedule.'})
    breply({'status':'delivered'});reply(briefing);s.save('briefing',briefing);s.event('stable')
    delegation,reply=s.ask('lead',tool('delegate_scheduler','Delegate both projects to SharedScheduler.',
        {'worker':choice(['SharedScheduler']),'projects':array(choice(['A','B']))}),{'instruction':'Delegate A and B to the SAME scheduler.'})
    assert set(delegation['projects'])=={'A','B'},'incomplete task delegation'
    s.save('delegation_decision',delegation);s.delegate();reply({'assigned':True})
    previous=None;review=None
    agreement=tool('agree_schedule','Accept or request revision; if accepting copy the exact full schedule.',
        {'decision':choice(['accept','revise']),'schedule':schema,'comments':text_field()})
    for phase in ('initial','changed'):
        visible=public if phase=='initial' else initial
        if phase=='changed':
            s.event('business_person_unavailable',change=initial['change'])
            # Explicit permission event, separate from the personnel calendar event.
            s.replace('caller')
        for round_index in (1,2):
            proposal,reply=s.ask('worker',tool('propose_schedule','Choose a complete feasible six-meeting schedule.',
                {'schedule':schema,'reasoning':text_field()}),
                {'phase':phase,'round':round_index,'calendar':visible,'previous':previous,'partner_feedback':review,
                 'instruction':'Use initial Expert availability before the change; resulting_expert_available afterwards. Check all constraints.'})
            reply({'status':'proposal_recorded'});s.save(phase+'_proposal'+str(round_index),proposal)
            copied,reply=s.ask('worker',tool('check_calendar','Validate your actual proposed schedule; returns conflicts, no solution.',
                {'schedule':schema,'phase':choice([phase])}),{'proposal':proposal,'phase':phase})
            assert canonical(copied['schedule'])==canonical(proposal['schedule']),'checked a different schedule'
            check=s.admit('plan',{'action':'check_calendar','phase':phase,'schedule':copied['schedule']})
            reply(check);s.save(phase+'_check'+str(round_index),check)
            proposal=s.admit('check' if phase=='initial' else 'joint',{'action':'negotiate','phase':phase,'proposal':proposal})['proposal']
            review,reply=s.ask('service',agreement,{'phase':phase,'calendar':visible,'proposal':proposal,'checker':check})
            reply({'status':'sent_to_scheduler'});s.save(phase+'_review'+str(round_index),review)
            previous=proposal
            if phase=='initial' and round_index==1:s.event('multitask',worker=s.roles['worker'],projects=['A','B'],contexts=['plan','check'])
            if phase=='changed' and round_index==1:s.replace('service')
        s.save(phase+'_final',proposal);s.save(phase+'_partner',review)
        lead,reply=s.ask('lead',agreement,{'phase':phase,'calendar':visible,'proposal':proposal,
            'partner':review,'checker':check,'instruction':'Make your own approval decision; accept only the same valid schedule.'})
        reply({'status':'recorded'});s.save(phase+'_lead',lead)
        if phase=='initial':
            agreed=(check['valid'] and review['decision']==lead['decision']=='accept'
                and canonical(review['schedule'])==canonical(lead['schedule'])==canonical(proposal['schedule']))
            s.event('initial_business_agreement',origin='model_decisions',accepted=agreed)
            # The new process metric allows an unresolved initial candidate to
            # enter the prescribed change stage. It does NOT fabricate assent;
            # the independent business judge still rejects either disagreement.
            if not continue_on_business_rejection:assert agreed,'initial agreement failed'
    s.save('final_calendar',proposal['schedule'])

if __name__=='__main__':run_scene('calendar_scene',ROLES,PROMPTS,execute,judge)
