"""Independent post-run judge. Does not import calculator or business helpers.

It derives reference selections and integer costs directly from initial facts.
No result or reference total is returned to an agent before it submits.
"""


def judge(initial,quotes,checks,final,events):
    expected={};totals={};optimal_ids={}
    for key,options in initial['tables'].items():
        ordered=sorted(options,key=lambda x:(-x['rating'],-x['unit_price']))
        expected[key]=ordered[0]
        # Two vendors can tie in BOTH rating and price. The policy permits
        # either; do not invent a hidden array-order tiebreak for the judge.
        optimal_ids[key]={q['id'] for q in options if
                         (q['rating'],q['unit_price'])==(ordered[0]['rating'],ordered[0]['unit_price'])}
        city,category=key.split('/')
        base=ordered[0]['unit_price']*initial['days'][city]
        if category=='restaurant':base*=initial['people']*initial['meals_per_day']
        elif category=='hotel':base*=initial['rooms']
        else:base*=initial['vehicles']
        totals[key]=base
    coverage={kind:any(e['kind']==kind for e in events) for kind in
              ('stable','delegation','multitask','caller_recovery','service_recovery')}
    check_results=[]
    for row in checks:
        keys=row['keys']
        args=row['arguments']
        input_ok=(all(args[k]==initial[k] for k in ('days','people','meals_per_day','rooms','vehicles'))
                  and len(args['lines'])==len(keys)
                  and {x['key']:x['unit_price'] for x in args['lines']}==
                      {k:expected[k]['unit_price'] for k in keys})
        ok=(len(keys)==len(set(keys)) and all(k in totals for k in keys) and
            row['submitted_total']==sum(totals[k] for k in keys) and input_ok)
        check_results.append(ok)
    correct_quotes=(set(quotes)==set(expected) and all(
        q['id'] in optimal_ids[key] and q in initial['tables'][key] for key,q in quotes.items()))
    correct_final=bool(final and final.get('total')==sum(totals.values()) and
                       set(quotes)==set(expected) and
                       final.get('choices')=={k:v['id'] for k,v in quotes.items()})
    business=correct_quotes and correct_final and len(checks)==2 and all(check_results)
    return dict(business_pass=business,coverage=coverage,coverage_pass=all(coverage.values()),
                joint_pass=business and all(coverage.values()),correct_quotes=correct_quotes,
                correct_final=correct_final,check_results=check_results,expected_total=sum(totals.values()))
