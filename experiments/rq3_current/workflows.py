"""RQ3-only bounded collaboration changes. No generated business answers.

The workflow prescribes two reviews and two permission replacement events.
The models choose drafts, revisions and assent. Checkers inspect an explicit
model-selected artifact ID. Four extra negotiation/revision opportunities are
allowed, never unbounded retries; every rejected attempt remains in evidence.
"""
from experiments.scene_harness import tool,obj,choice,integer,text_field,array
from experiments import academic_scene,calendar_scene
from .policy import ROUNDS

def execute_academic(s,seed,initial):
    s.inputs(initial);ids=[r['id'] for r in initial['rows']];evidence=ids+[d['id'] for d in initial['materials']]
    _,reply=s.ask('lead',tool('request_dossier','Request the study dossier.',{'study':choice(['effect_cost_anomaly'])}),
        {'instruction':'Request the original dossier and partner evidence.'})
    dossier=s.admit('plan',{'action':'read_dossier'})
    brief,feedback=s.ask('service',tool('summarize_dossier','Explain study scope and limitations.',
        {'summary':text_field(),'evidence_ids':array(choice(evidence))}),{'dossier':dossier})
    feedback({'status':'delivered'});reply(brief);s.save('material_summary',brief);s.event('stable')
    action,reply=s.ask('lead',tool('delegate_analyst','Delegate effect, cost and anomaly analysis to the same analyst.',
        {'worker':choice(['ResearchAnalyst']),'tasks':array(choice(['effect','cost','anomaly']))}),
        {'instruction':'Delegate all three tasks to ResearchAnalyst.'})
    assert set(action['tasks'])=={'effect','cost','anomaly'},'incomplete delegation tasks'
    s.save('delegation_decision',action);s.delegate();reply({'assigned':True})
    selected,reply=s.ask('worker',tool('aggregate_rows','Compute on selected original rows, without exclusions.',
        {'row_ids':array(choice(ids))}),{'dossier':initial,'instruction':'Use all twelve original rows.'})
    aggregates=s.admit('plan',selected);reply(aggregates);s.save('aggregates',aggregates)
    report,reply=s.ask('worker',academic_scene.report_tool('draft_report',initial),
        {'revision':0,'aggregates':aggregates,'instruction':'Author a complete report, four rows, three claims and evidence. Use the declared finding enums exactly.'})
    reply({'stored_as':'report0'});s.save('report0',report);history=[]
    for revision in range(1,ROUNDS+1):
        # Two required reviews, followed by up to four model-requested revisions.
        current='report'+str(revision-1)
        report=s.admit('check' if revision==1 else 'joint',{'action':'review_report','report':report})['report']
        review,reply=s.ask('service',tool('review_report','Review independently. Each issue needs its own stable ID, comment and evidence IDs.',
            {'issues':{**array(obj({'id':{'type':'string','pattern':'^R[0-9]+-[0-9]+$'},'comment':{'type':'string','minLength':1},
                'evidence_ids':array(choice(evidence))})),'minItems':1,'maxItems':4}}),
            {'round':revision,'dossier':initial,'report':report,'aggregates':aggregates,
             'prior_decisions':s.artifacts.get('publication_decisions'),
             'instruction':'Give concrete substantive clarification or correction requests. Every issue MUST have id, comment, evidence_ids; use IDs R'+str(revision)+'-1, R'+str(revision)+'-2. Do not manufacture incorrect arithmetic.'})
        assert review['issues'] and len({i['id'] for i in review['issues']})==len(review['issues']),'empty or duplicate review issue IDs'
        reply({'status':'sent_to_author'});s.save('review'+str(revision),review)
        if revision==1:s.event('multitask',worker=s.roles['worker'],contexts=['plan','check']);s.replace('caller')
        if revision==2:s.replace('service')
        report,reply=s.ask('worker',academic_scene.report_tool('revise_report',initial),
            {'revision':revision,'dossier':initial,'previous_report':report,'review':review,'aggregates':aggregates,
             'instruction':'Author a substantive revision addressing all issue IDs. Keep correct numeric facts. Use exact schema categories, not free-text labels.'})
        name='report'+str(revision);reply({'stored_as':name});s.save(name,report)
        selected,reply=s.ask('worker',tool('check_report','Check the already submitted report by its ID; no recopy required.',
            {'report_ref':choice([name])}),{'submitted_report_id':name,'report':report})
        checked=s.admit('check',{'action':'consistency_check',**selected});reply(checked);s.save('consistency'+str(revision),checked)
        history.append(dict(revision=revision,previous=current,report=name,review='review'+str(revision)))
        if revision<2:continue
        final=s.admit('joint',{'action':'final_partner_review','report':report})['report']
        approval=tool('approve_report','Make your actual publication decision; request revision when necessary.',
            {'decision':choice(['accept','reject','revise']),'revision':integer(),'reason':text_field()})
        partner,reply=s.ask('service',approval,{'dossier':initial,'report':final,'revision_history':history,
            'actual_reviews':{h['review']:s.artifacts[h['review']] for h in history},'checker':checked,
            'remaining_revision_rounds':ROUNDS-revision,'instruction':'Do not automatically agree. Explicitly request revision if needed.'})
        reply({'status':'recorded'});s.save('partner_approval',partner)
        lead,reply=s.ask('lead',approval,{'report':final,'partner':partner,'revision_history':history,'checker':checked,
            'remaining_revision_rounds':ROUNDS-revision,'instruction':'Make your independent decision on this actual revision.'})
        reply({'status':'recorded'});s.save('lead_approval',lead)
        s.save('publication_decisions',dict(partner=partner,lead=lead));s.save('revision_history',history)
        s.save('report_final',report);s.save('result_table',report['table']);s.save('claim_evidence',report['conclusions'])
        if partner['decision']==lead['decision']=='accept':break
        if revision==ROUNDS:s.event('negotiation_limit',origin='controller_limit',scene='academic',rounds=revision)
    (s.path/'report.md').write_text(report['markdown'],encoding='utf-8')

def schedule_proposal_tool(initial):
    # Brevity is a prompting preference, not a condition for flow completion.
    # Keep required fields, string type and six complete meeting records.
    return tool('propose_schedule','Submit all six meetings. Keep reasoning concise.',
        {'schedule':{**calendar_scene.schedule_schema(initial),'minItems':6,'maxItems':6},
         'reasoning':text_field()})


def execute_calendar(s,seed,initial):
    s.inputs(initial);public={k:v for k,v in initial.items() if k!='change'}
    _,reply=s.ask('lead',tool('request_calendar','Request constraints for both projects.',{'projects':array(choice(['A','B']))}),
        {'instruction':'Request projects A and B.'})
    visible=s.admit('plan',{'action':'read_calendar'})
    briefing,feedback=s.ask('service',tool('brief_constraints','Explain constraints without generating a reference solution.',
        {'briefing':text_field()}),{'calendar':visible})
    feedback({'status':'delivered'});reply(briefing);s.save('briefing',briefing);s.event('stable')
    delegation,reply=s.ask('lead',tool('delegate_scheduler','Delegate both projects to the shared scheduler.',
        {'worker':choice(['SharedScheduler']),'projects':array(choice(['A','B']))}),{'instruction':'Delegate A and B to the SAME SharedScheduler.'})
    assert set(delegation['projects'])=={'A','B'},'incomplete delegation tasks'
    s.save('delegation_decision',delegation);s.delegate();reply({'assigned':True})
    previous=None;feedback=None
    for phase in ('initial','changed'):
        visible=public if phase=='initial' else initial
        if phase=='changed':s.event('business_person_unavailable',change=initial['change']);s.replace('caller')
        for round_index in range(1,ROUNDS+1):
            proposal,reply=s.ask('worker',schedule_proposal_tool(initial),
                {'phase':phase,'round':round_index,'calendar':visible,'previous':previous,'partner_feedback':feedback,
                 'instruction':'Choose slot and room for every meeting. Use the current availability and dependencies. You may revise a prior valid proposal in response to the other team.'})
            name=phase+'_proposal'+str(round_index);s.save(name,proposal);reply({'stored_as':name})
            selected,reply=s.ask('worker',tool('check_calendar','Check exactly this saved proposal by ID. The tool returns violations, never a solution.',
                {'proposal_ref':choice([name]),'phase':choice([phase])}),{'proposal_ref':name,'proposal':proposal,'phase':phase})
            check=s.admit('plan',{'action':'check_calendar',**selected});reply(check);s.save(phase+'_check'+str(round_index),check)
            received=s.admit('check' if phase=='initial' else 'joint',{'action':'negotiate','phase':phase,'proposal':proposal})['proposal']
            agreement=tool('agree_schedule','Independently accept or request revision of the referenced proposal. Do not recopy its schedule.',
                {'decision':choice(['accept','revise']),'proposal_ref':choice([name]),'comments':text_field()})
            partner,reply=s.ask('service',agreement,{'phase':phase,'calendar':visible,'proposal_ref':name,'proposal':received,'checker':check,
                'instruction':'Give an actual decision and concrete correction requests when needed.'})
            reply({'status':'sent_to_scheduler'});s.save(phase+'_review'+str(round_index),partner)
            lead,reply=s.ask('lead',agreement,{'phase':phase,'calendar':visible,'proposal_ref':name,'proposal':proposal,'checker':check,'partner':partner})
            reply({'status':'recorded'});s.save(phase+'_lead',lead);s.save(phase+'_partner',partner);s.save(phase+'_final',proposal)
            if phase=='initial' and round_index==1:s.event('multitask',worker=s.roles['worker'],contexts=['plan','check'],projects=['A','B'])
            if phase=='changed' and round_index==1:s.replace('service')
            agreed=check['valid'] and partner['decision']==lead['decision']=='accept'
            previous=proposal;feedback=dict(partner=partner,lead=lead,checker=check)
            # The replacement service must actually review and admit work.
            if agreed and (phase=='initial' or round_index>=2):break
            if round_index==ROUNDS:s.event('negotiation_limit',origin='controller_limit',scene='calendar',phase=phase)
        if phase=='initial':s.event('initial_business_agreement',origin='model_decisions',accepted=agreed)
    s.save('final_calendar',proposal['schedule'])
