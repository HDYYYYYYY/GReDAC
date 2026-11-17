"""Strict first-release profile; no task, streaming, metadata or arbitrary URL."""
import json, math
from google.protobuf.json_format import ParseDict, MessageToDict
from a2a.types.a2a_pb2 import SendMessageRequest, AgentCard
from gredac.crypto import canonical, digest, require, Denied

PROFILE = 'gredac-a2a-envelope-v1'
MAP_VERSION = 'fixture-actions-v1'
URL = 'http://a2a.local/rpc'
MAX_REQUEST = 65536
MAX_RESPONSE = 262144
ACTIONS = {'echo.read':'query', 'calendar.read':'query', 'expense.read':'query',
           'calendar.check':'summary', 'expense.calculate':'summary',
           'research.aggregate':'summary', 'fixture.delete':'delete'}

def clean(value, depth=0):
    require(depth <= 16, 'A2A_DEPTH')
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try: value.encode('utf-8')
            except UnicodeError: raise Denied('A2A_UNICODE')
        return value
    if isinstance(value, (int, float)):
        require(not isinstance(value, float) or math.isfinite(value), 'A2A_NUMBER')
        require(value == int(value) and abs(value) <= 2**53-1, 'A2A_SAFE_INTEGER')
        return int(value)
    if isinstance(value, list): return [clean(v, depth+1) for v in value]
    require(isinstance(value, dict) and all(isinstance(k,str) for k in value), 'A2A_JSON')
    return {k:clean(v, depth+1) for k,v in value.items()}

def loads(raw, limit=MAX_REQUEST):
    require(isinstance(raw,(str,bytes)) and len(raw.encode('utf-8') if isinstance(raw,str) else raw)<=limit, 'A2A_SIZE')
    def pairs(items):
        obj={}
        for k,v in items:
            require(k not in obj, 'A2A_DUPLICATE_KEY');obj[k]=v
        return obj
    try:
        return clean(json.loads(raw,object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Denied('A2A_NUMBER'))))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Denied('A2A_JSON') from exc

def fields(obj, required, optional=()):
    require(isinstance(obj,dict) and set(required)<=set(obj)<=set(required)|set(optional),'A2A_FIELDS')

def normalize_send_request(value):
    value=clean(value)
    fields(value, ['message'], ['configuration'])
    if 'configuration' in value:
        fields(value['configuration'], [], ['returnImmediately'])
        require(value['configuration'].get('returnImmediately',False) is False,'A2A_SYNC_ONLY')
    msg=value['message'];fields(msg,['messageId','role','parts'])
    require(isinstance(msg['messageId'],str) and 0<len(msg['messageId'])<=256,'A2A_MESSAGE_ID')
    require(msg['role']=='ROLE_USER','A2A_ROLE')
    require(isinstance(msg['parts'],list) and len(msg['parts'])==1,'A2A_ONE_DATA_PART')
    fields(msg['parts'][0],['data'])
    data=msg['parts'][0]['data'];fields(data,['action','application_case','arguments'])
    require(isinstance(data['action'],str) and data['action'] in ACTIONS,'A2A_ACTION')
    require(isinstance(data['application_case'],str) and 0<len(data['application_case'])<=256,'A2A_CASE')
    require(isinstance(data['arguments'],dict),'A2A_ARGUMENTS')
    try:
        result=clean(MessageToDict(ParseDict({'message':msg},SendMessageRequest(),ignore_unknown_fields=False)))
    except (ValueError, TypeError) as exc: raise Denied('A2A_PROTOBUF') from exc
    require(result=={'message':msg},'A2A_LOSSLESS')
    require(len(canonical(result))<=MAX_REQUEST,'A2A_SIZE')
    return result

def validate_payload(value):
    value=clean(value)
    fields(value,['profile','protocol_version','service_right','card_digest','action_map_version','operation','request'])
    require(value['profile']==PROFILE and value['protocol_version']=='1.0' and value['operation']=='SendMessage','A2A_PROFILE')
    require(value['action_map_version']==MAP_VERSION,'A2A_MAP_VERSION')
    require(isinstance(value['service_right'],str) and value['service_right'],'A2A_SERVICE_RIGHT')
    require(isinstance(value['card_digest'],str) and len(value['card_digest'])==64,'A2A_CARD_DIGEST')
    normalized=normalize_send_request(value['request'])
    require(canonical(normalized)==canonical(value['request']),'A2A_NONCANONICAL')
    require(len(canonical(value))<=MAX_REQUEST,'A2A_SIZE')
    return value

def classify_operation(payload):
    value=validate_payload(payload)
    return ACTIONS[value['request']['message']['parts'][0]['data']['action']]

def make_card(name, version='1'):
    return MessageToDict(ParseDict(dict(name=name,description='Protected GReDAC synchronous fixture',
        version=version,supportedInterfaces=[dict(url=URL,protocolBinding='JSONRPC',protocolVersion='1.0')],
        capabilities={},defaultInputModes=['application/json'],defaultOutputModes=['application/json'],
        skills=[dict(id='fixtures',name='Deterministic fixtures',description='One admitted action per request',tags=['fixture'])]),AgentCard()))

def validate_card(card):
    require(isinstance(card,dict),'A2A_CARD')
    try: normalized=MessageToDict(ParseDict(card,AgentCard(),ignore_unknown_fields=False))
    except (ValueError,TypeError) as exc: raise Denied('A2A_CARD') from exc
    require(canonical(normalized)==canonical(card),'A2A_CARD_CANONICAL')
    require(card.get('supportedInterfaces')==[dict(url=URL,protocolBinding='JSONRPC',protocolVersion='1.0')],'A2A_FIXED_ROUTE')
    require(not card.get('capabilities') and card.get('defaultInputModes')==['application/json']
        and card.get('defaultOutputModes')==['application/json'],'A2A_CARD_PROFILE')
    return card

def envelope(service_right, card, message_id, action, arguments=None, application_case='fixture'):
    return validate_payload(dict(profile=PROFILE,protocol_version='1.0',service_right=service_right,
        card_digest=digest(validate_card(card)),action_map_version=MAP_VERSION,operation='SendMessage',
        request=normalize_send_request(dict(message=dict(messageId=message_id,role='ROLE_USER',
            parts=[dict(data=dict(action=action,application_case=application_case,arguments=arguments or {}))])))))

def binding(card, service_right):
    return dict(profile=PROFILE,card=validate_card(card),card_digest=digest(card),
                action_map_version=MAP_VERSION,service_right=service_right)
