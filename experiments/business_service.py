"""Controlled tools executed inside the receiving Agent process.

No oracle/solution search. Inputs to calculators/checkers are model-authored.
Registered report/schedule references are exact previously submitted objects.
"""
import copy

def execute(facts,payload,artifacts):
    try:
        d=payload.get('request',payload);kind=d.get('action',d.get('tool'))
        if kind=='get_quote':return copy.deepcopy(facts['tables'][d['key']])
        if kind=='read_dossier':return copy.deepcopy(facts)
        if kind=='read_calendar':return {k:copy.deepcopy(v) for k,v in facts.items() if k!='change'}
        if 'row_ids' in d:
            from .academic_data import aggregate_rows
            return aggregate_rows(facts,d['row_ids'])
        if kind=='consistency_check':
            from .academic_data import check_report
            report=artifacts[d['report_ref']] if 'report_ref' in d else d['report']
            return check_report(facts,report)
        if kind=='check_calendar':
            from .calendar_data import check_calendar
            schedule=artifacts[d['proposal_ref']]['schedule'] if 'proposal_ref' in d else d['schedule']
            return check_calendar(facts,schedule,d['phase'])
        return copy.deepcopy(d)
    except (AssertionError,KeyError,TypeError,ValueError) as exc:
        return {'_business_tool_error':type(exc).__name__+': '+str(exc)}
