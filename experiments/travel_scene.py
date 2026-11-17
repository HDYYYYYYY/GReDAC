"""Travel's existing task, using the same all-context backend as other scenes.

All prices, choices, calculator arguments, submitted totals and the final
answer come from actual model actions. Role replacement changes the worker
used by BOTH planning and checking; no stale worker history is used to check.
"""
from .scene_harness import tool,integer,choice
from .travel_domain import KEYS,PROMPTS as ORIGINAL_PROMPTS,CALC_TOOL,obj,calculator
from .travel_oracle import judge as travel_judge

ROLES=dict(lead='Planner',worker='PriceWorker',service='Provider')
PROMPTS={k:ORIGINAL_PROMPTS[v] for k,v in ROLES.items()}


def execute(s,seed,initial):
    s.inputs(initial);quotes={};checks=[];delegated=False;partial=False;full=False;final=None;last_checked=None
    trip={k:initial[k] for k in ('days','people','meals_per_day','rooms','vehicles')}
    while final is None:
        if len(quotes)==1 and not delegated:
            action,reply=s.ask('lead',tool('delegate_worker','Delegate remaining pricing and checking work.',
                {'worker':choice(['PriceWorker'])}),dict(stage='delegate',quotes=quotes,trip=trip))
            s.save('delegation_decision',action);s.delegate();delegated=True
            reply({'worker':'PriceWorker','status':'assigned'})
        elif (len(quotes)==2 and not partial) or (len(quotes)==6 and not full):
            _,reply=s.ask('lead',tool('verify_cost','Ask the shared price worker to check known quotes.',
                {'scope':choice(['current_quotes'])}),dict(stage='check',quotes=quotes,trip=trip))
            s.admit('check',{'tool':'check_cost','quotes':quotes})
            arguments,calc_reply=s.ask('worker',CALC_TOOL,dict(task='checking',quotes=quotes,trip=trip,
                instruction='Pass exactly these quotes and trip facts to calculate_cost.'))
            calculated=s.backend.mesh.call(s.roles['worker'],'calculate_cost',arguments=arguments);calc_reply(calculated)
            submitted,check_reply=s.ask('worker',tool('submit_check','Submit the total returned by calculate_cost.',
                {'total':integer()}),{'task':'checking','instruction':'Submit the calculated total.'})
            check_reply({'status':'recorded'})
            s.admit('joint',{'tool':'record_joint_check','submitted':submitted})
            checks.append(dict(keys=sorted(quotes),arguments=arguments,tool_result=calculated,submitted_total=submitted['total']))
            s.save('checks',checks);last_checked=submitted['total']
            s.event('multitask','model',worker=s.roles['worker'],contexts=['plan','check','joint'],quotes=len(quotes))
            if len(quotes)==2:partial=True
            else:full=True
            reply({'checked_total':last_checked,'quote_count':len(quotes)})
        elif len(quotes)==6:
            final,reply=s.ask('lead',tool('finish','Submit all selected IDs and checked total.',
                {'choices':obj({k:{'type':'string'} for k in KEYS}),'total':integer()}),
                dict(stage='finish',quotes=quotes,checked_total=last_checked,trip=trip))
            reply({'status':'submitted'});s.save('final',final)
        else:
            remaining=sorted(set(KEYS)-set(quotes))
            action,reply=s.ask('lead',tool('quote','Request an uncompleted city/service quote.',
                {'key':choice(remaining)}),dict(stage='quote',quotes=quotes,remaining=remaining,trip=trip,
                worker=s.roles['worker'] if delegated else s.roles['lead'],provider=s.roles['service']))
            key=action['key']
            if delegated:
                request,wreply=s.ask('worker',tool('request_quote','Request the currently assigned city/service.',
                    {'key':choice(KEYS)}),dict(task='planning',assignment=key,instruction='Use this current assignment key exactly.'))
                assert request['key']==key,'worker changed assignment'
            options=s.admit('plan',{'tool':'get_quote','key':key})
            answer,preply=s.ask('service',tool('select_option','Select maximum rating, tie highest unit_price.',
                {'id':choice([q['id'] for q in options])}),dict(key=key,options=options))
            selected=next(q for q in options if q['id']==answer['id'])
            preply(selected);quotes[key]=selected
            if delegated:wreply(selected)
            reply(selected);s.save('quotes',quotes)
            s.event('quote','model',key=key,quote=selected,worker=s.roles['worker'] if delegated else s.roles['lead'],service=s.roles['service'])
            if len(quotes)==1:s.event('stable')
            if len(quotes)==3:s.replace('caller')
            if len(quotes)==5:s.replace('service')


def judge(initial,artifacts,events):
    result=travel_judge(initial,artifacts.get('quotes',{}),artifacts.get('checks',[]),artifacts.get('final'),events)
    result['errors']=[name for name,ok in [('quote_selection',result['correct_quotes']),
        ('final_choices_or_total',result['correct_final']),('calculator_checks',len(result['check_results'])==2 and all(result['check_results']))] if not ok]
    return result


if __name__=='__main__':
    from .evaluation_batch import main
    main('travel')
