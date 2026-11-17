"""Independent academic collaboration: long dossier -> draft -> two revisions.

Every report/claim/review/approval is a REAL model output. Stage order and two
permission replacement events are prescribed; their content is not. The
calculator/checker operate only when the model calls them. Final acceptance
is a separate module unavailable to models or business tools.
"""
from .scene_harness import run_scene,tool,obj,integer,choice,text_field,array
from .academic_data import facts,aggregate_rows,check_report
from .academic_oracle import judge

ROLES=dict(lead='ResearchLead',worker='ResearchAnalyst',service='DataReviewer')
ONE='Make exactly ONE offered tool call per response, then wait for its result. Never batch calls. '
LABELS=('The effect labels compare all-record MEAN LATENCY: B_faster_all means B has lower latency in both conditions; '
        'B_faster_light_only means B has lower latency in light but not in heavy; A_faster_all means A has lower latency in both. '
        'These are schema categories, not full sentences. Explain both conditions in the claim text. ')
PROMPTS={
 'lead':ONE+LABELS+'Coordinate research and data-analysis teams. Read the dossier, delegate to the analyst when offered, '
    'and approve only the actual final revision. Do not invent data or provide a reference answer.',
 'worker':ONE+LABELS+'Read the full original dossier and all twelve data rows. Use aggregate_rows on ALL rows, retain the anomaly, '
    'then author a report with four complete numeric table rows and three claims: latency effect, cost, anomaly. '
    'For effect/cost cite all 12 data row IDs; for anomaly cite its row. Scope is justified only by the supplied study. '
    'Do not copy an informal memo as truth. A report needs at least 150 English words. '
    'Address each reviewer issue ID with substantive wording revisions. Use actual computed aggregates exactly.',
 'service':ONE+LABELS+'Act as the collaborating data-analysis reviewer. Read original material and data, check the current report '
    'against them, and give at least one specific issue or requested clarification in each review round. '
    'Every issue object MUST include id, comment and evidence_ids. Use unique IDs such as R1-1 or R2-1. '
    'Cite actual evidence IDs. Review observed latency, cost and anomaly treatment, avoid causal/general claims. '
    'Approval is your actual judgement; do not automatically accept an invalid final report.'}

def report_tool(name,initial):
    groups=sorted({r['group'] for r in initial['rows']});ids=[r['id'] for r in initial['rows']]
    evidence=ids+[d['id'] for d in initial['materials']]
    table=obj(dict(group=choice(groups),count=integer(),row_ids=array(choice(ids)),
        mean_latency_ms=integer(),mean_throughput_rps=integer(),mean_cost_units=integer()))
    conclusions=obj(dict(topic=choice(['effect','cost','anomaly']),finding=choice([
        'B_faster_all','B_faster_light_only','A_faster_all','B_more_expensive','A_more_expensive','equal_cost',
        'retain_anomaly_no_causal_claim','drop_outlier','proved_storage_cause']),
        scope=choice(['measured_only','general_capacity','causal']),claim=text_field(),evidence_ids=array(choice(evidence))))
    return tool(name,'Author the complete report, table and evidence map; use ALL input rows.',
        dict(revision=integer(),markdown=text_field(),table=array(table),conclusions=array(conclusions),
             addressed_issues=array(text_field())))

def execute(s,seed,initial=None):
    # A frozen input may be supplied by a new batch; historical CLI still uses
    # its original generator. Both paired arms receive the exact same object.
    initial=facts(seed) if initial is None else initial
    s.inputs(initial);ids=[r['id'] for r in initial['rows']]
    evidence=ids+[d['id'] for d in initial['materials']]
    _,reply=s.ask('lead',tool('request_dossier','Request the study dossier.',{'study':choice(['effect_cost_anomaly'])}),
        {'instruction':'Request the study dossier and partner evidence before analysis.'})
    initial=s.admit('plan',{'action':'read_dossier'})
    summary,sreply=s.ask('service',tool('summarize_dossier','Explain study scope and material limitations.',
        {'summary':text_field(),'evidence_ids':array(choice(evidence))}),{'dossier':initial})
    sreply({'status':'delivered'});reply(summary);s.save('material_summary',summary);s.event('stable')
    decision,reply=s.ask('lead',tool('delegate_analyst','Delegate analysis and evidence checking to the analyst.',
        {'worker':choice(['ResearchAnalyst']),'tasks':array(choice(['effect','cost','anomaly']))}),
        {'instruction':'Delegate all three analysis tasks to the same ResearchAnalyst.'})
    assert set(decision['tasks'])=={'effect','cost','anomaly'},'incomplete delegation tasks'
    s.save('delegation_decision',decision);s.delegate();reply({'worker':'ResearchAnalyst','assigned':True})
    selected,reply=s.ask('worker',tool('aggregate_rows','Aggregate the selected raw rows, without exclusions.',
        {'row_ids':array(choice(ids))}),{'dossier':initial,'instruction':'Read original materials and calculate all 12 rows.'})
    aggregates=s.admit('plan',selected);reply(aggregates);s.save('aggregates',aggregates)
    draft,reply=s.ask('worker',report_tool('draft_report',initial),{'revision':0,'aggregates':aggregates,
        'instruction':'Write the full draft. Do not drop the anomaly. All-record means, at least 150 English words.'})
    reply({'status':'recorded'});s.save('report0',draft)
    for revision in (1,2):
        ctx='check' if revision==1 else 'joint'
        draft=s.admit(ctx,{'action':'review_report','report':draft})['report']
        review,reply=s.ask('service',tool('review_report','Give concrete evidence-backed revision requests. Every issue requires id, comment, evidence_ids.',
            {'issues':array(obj({'id':text_field(),'comment':text_field(),'evidence_ids':array(choice(evidence))}))}),
            {'round':revision,'report':draft,'aggregates':aggregates,'checker':s.artifacts.get('consistency',{}),
             'instruction':'Give at least one substantive clarification/revision request, even if arithmetic is correct. '
                'Each issue MUST contain its own id (R'+str(revision)+'-1, etc.), comment, and evidence_ids.'})
        reply({'status':'sent_to_author'});s.save('review'+str(revision),review)
        if revision==1:
            s.event('multitask',worker=s.roles['worker'],contexts=['plan','check'])
            s.replace('caller')
        else:s.replace('service')
        draft,reply=s.ask('worker',report_tool('revise_report',initial),
            {'revision':revision,'dossier':initial if revision==1 else None,'previous_report':draft,
             'review':review,'aggregates':aggregates,'instruction':'Revise the full report, address each issue ID, preserve correct facts.'})
        reply({'status':'recorded'});s.save('report'+str(revision),draft)
        if revision==1:
            copied,reply=s.ask('worker',tool('check_report','Check the current complete report for numeric/reference consistency.',
                {'report':report_tool('unused',initial)['function']['parameters']}),{'current_report':draft})
            checked=s.admit('check',{'action':'consistency_check','report':copied['report']})
            reply(checked);s.save('consistency',checked)
    approval=tool('approve_report','Accept or reject actual final revision two.',
                  {'decision':choice(['accept','reject']),'revision':integer(),'reason':text_field()})
    draft=s.admit('joint',{'action':'final_partner_review','report':draft})['report']
    # A replacement reviewer has no predecessor chat history. Hand over actual
    # drafts and reviews so it can verify the revision-to-issue mapping itself.
    handover={k:s.artifacts[k] for k in ('report0','review1','report1','review2')}
    partner,reply=s.ask('service',approval,{'dossier':initial,'report':draft,'revision_history':handover,
        'instruction':'Review independently and decide. Assess the supplied issue history and final claim text; labels follow the schema definitions.'})
    reply({'status':'recorded'});s.save('partner_approval',partner)
    lead,reply=s.ask('lead',approval,{'report':draft,'partner':partner,'revision_history':handover,
        'instruction':'Make your final publication decision using the complete revision history.'})
    reply({'status':'recorded'});s.save('lead_approval',lead)
    # Deliver exactly model-authored artifacts, without correcting their values.
    (s.path/'report.md').write_text(draft['markdown'],encoding='utf-8')
    s.save('result_table',draft['table']);s.save('claim_evidence',draft['conclusions'])

if __name__=='__main__':run_scene('academic_scene',ROLES,PROMPTS,execute,judge)
