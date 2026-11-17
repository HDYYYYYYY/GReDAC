"""Synthetic travel facts, strict tool schemas and a transparent calculator.

The calculator has NO access to the reference catalogue/oracle. It computes
only model-provided arguments. Wrong prices, days, people or choices are NOT
corrected. Provider lookup returns the selected input row, not the best row.
"""
import random
import re


KEYS=[city+'/'+cat for city in ('London','Paris') for cat in ('hotel','car','restaurant')]


def facts(seed):
    rng=random.Random(seed)
    tables={key:[dict(id=key.replace('/','-')+'-'+str(i),rating=r,
                    unit_price=rng.randrange(25,180)*(3 if key.endswith('hotel') else 1))
                 for i,r in enumerate((4.1,4.8,4.8))] for key in KEYS}
    return dict(seed=seed,tables=tables,days={'London':rng.randrange(2,5),'Paris':rng.randrange(2,5)},
                people=rng.randrange(1,4),meals_per_day=2,rooms=1,vehicles=1)


def obj(properties):
    return {'type':'object','properties':properties,'required':list(properties),'additionalProperties':False}
def integer():return {'type':'integer','minimum':0}
def choice(values):return {'type':'string','enum':list(values)}
def tool(name,description,properties):
    return {'type':'function','function':dict(name=name,description=description,strict=True,
                                             parameters=obj(properties))}


def validate(value,schema):
    """Small strict subset used by these declared schemas; fail, never repair."""
    typ=schema['type']
    if typ=='object':
        assert isinstance(value,dict) and set(value)==set(schema['properties']),'object fields differ'
        for k,s in schema['properties'].items():validate(value[k],s)
    elif typ=='array':
        assert isinstance(value,list),'expected array'
        assert schema.get('minItems',0)<=len(value)<=schema.get('maxItems',float('inf')),'array length outside schema'
        for item in value:validate(item,schema['items'])
    elif typ=='integer':assert type(value) is int and value>=schema.get('minimum',0) and value<=schema.get('maximum',float('inf')),'expected integer in schema range'
    elif typ=='string':
        assert isinstance(value,str),'expected string'
        assert len(value)>=schema.get('minLength',0),'empty required text'
        if 'pattern' in schema:assert re.search(schema['pattern'],value),'invalid identifier pattern'
    else:raise AssertionError('unsupported local schema')
    if 'enum' in schema:assert value in schema['enum'],'invalid enum'


def calculator(arguments):
    """Public business arithmetic, not a ground-truth answer provider."""
    line_totals={}
    for line in arguments['lines']:
        key=line['key'];city,category=key.split('/')
        assert key not in line_totals,'duplicate cost line'
        count=(arguments['rooms'] if category=='hotel' else arguments['vehicles']
               if category=='car' else arguments['people']*arguments['meals_per_day'])
        line_totals[key]=line['unit_price']*arguments['days'][city]*count
    return dict(line_totals=line_totals,total=sum(line_totals.values()))


CALC_TOOL=tool('calculate_cost',
    'Compute supplied quote costs. Pass the given trip facts exactly. Room/night, vehicle/day, '
    'restaurant/person/meal. Never do mental arithmetic; use this result.',
    dict(lines={'type':'array','items':obj({'key':choice(KEYS),'unit_price':integer()})},
         days=obj({'London':integer(),'Paris':integer()}),people=integer(),
         meals_per_day=integer(),rooms=integer(),vehicles=integer()))


PROMPTS={
 'Planner':'You coordinate a two-city travel task. Make exactly ONE tool call in each response. '
    'Even when several quotes remain, request only ONE and wait for its tool result before acting again. '
    'Never batch multiple tool calls. Use the offered function, never free-form JSON. '
    'The current tool set defines the permitted workflow stage. Delegate after the first quote; '
    'check after two quotes and after all six. Choose an uncompleted service. '
    'Retain valid quotes when caller/provider roles are replaced. At finish copy checked total '
    'and quote IDs exactly; do not recompute. Prefer maximum rating then highest unit_price.',
 'PriceWorker':'Make exactly ONE tool call per response, then wait for the tool result. '
    'You are the same price worker across planning and checking tasks. Use the CURRENT '
    'offered function. For request_quote use the current assignment key, ignoring previous tasks. '
    'For checking call calculate_cost with every currently provided quote and the exact trip facts. '
    'Use the tool result to submit_check; do not calculate totals yourself.',
 'Provider':'Make exactly ONE tool call per response. You are a travel provider. First find the '
    'largest rating; among options with that rating choose the LARGEST numeric unit_price. '
    'The task explicitly prefers the more expensive option in a rating tie. Compare the actual '
    'numbers, not their array positions or IDs. Call select_option with its ID. Do not invent a quote.'}
