"""Independent process outcome, distinct from the three business oracles.

This checks performed actions/identities/admissions, not just stage labels.
No numerical answer, version number, approval decision or calendar validity
is required to finish a process. Those remain secondary business outcomes.
"""

STAGES=('stable','delegation','multitask','caller_recovery','service_recovery')
TERMINAL={'travel':('final','quotes','checks'),
          'academic':('report2','result_table','claim_evidence','partner_approval','lead_approval'),
          'calendar':('final_calendar','initial_final','changed_final','initial_lead','changed_lead')}
DELEGATE={'travel':'delegate_worker','academic':'delegate_analyst','calendar':'delegate_scheduler'}


def process_verdict(scene,roles,events,actions,admissions,artifacts,returned,error):
    accepted=[a for a in actions if a['status']=='returned']
    coverage={k:any(e['kind']==k for e in events) for k in STAGES}
    evidence={
        'initial_bilateral_calls':any(a['identity']==roles['lead'] for a in accepted) and any(a['identity']==roles['service'] for a in accepted),
        'model_delegation_action':any(a['tool']==DELEGATE[scene] for a in accepted),
        'same_worker_multiple_contexts':any(len({r['context'] for r in admissions if r['caller']==who})>=2
              for who in (roles['worker'],roles['worker']+'Replacement')),
        'replacement_worker_called':any(a['identity']==roles['worker']+'Replacement' for a in accepted),
        'replacement_service_called':any(a['identity']==roles['service']+'Replacement' for a in accepted),
        'post_caller_replacement_admission':False,
        'post_service_replacement_admission':False,
        'terminal_artifacts':all(k in artifacts for k in TERMINAL[scene]),
        'normal_return':returned,
    }
    # Presence of an empty JSON object is not a delivered result. This is a
    # structural completion condition, not a semantic correctness test.
    if scene=='academic':
        final=artifacts.get('report_final',artifacts.get('report2',{}))
        evidence['nonempty_delivery']=bool(final.get('markdown','').strip() and artifacts.get('result_table') and artifacts.get('claim_evidence'))
    elif scene=='calendar':evidence['nonempty_delivery']=bool(artifacts.get('final_calendar'))
    else:evidence['nonempty_delivery']=bool(artifacts.get('final',{}).get('choices'))
    for side in ('caller','service'):
        es=[e for e in events if e['kind']==side+'_recovery']
        if es:evidence['post_'+side+'_replacement_admission']=any(r['start']>=es[-1]['time'] for r in admissions)
    flow=error is None and all(coverage.values()) and all(evidence.values())
    return dict(flow_complete=flow,stage_coverage=coverage,process_evidence=evidence,
                process_missing=[k for k,v in {**coverage,**evidence}.items() if not v])


def failure_category(error,layer,last_call):
    if error is None:return None
    if any(t in error for t in ('episode API cap','API budget exhausted','input budget exceeded')):return 'explicit_model_budget_limit'
    if layer=='protocol':return 'system_protocol_runtime'
    if layer=='api':
        return 'model_action_format' if last_call and 'response' in last_call else 'api_transport_or_service'
    if layer=='model_action':return 'model_action_semantics'
    if layer=='oracle':return 'experiment_business_judge'
    if layer=='audit':return 'system_protocol_audit'
    return 'experiment_driver'
