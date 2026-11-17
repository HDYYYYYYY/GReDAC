"""Opt-in glue. Core owns all authorization, quota and replay decisions."""
import copy
from gredac.crypto import canonical, digest, require
from .codec import PROFILE, MAP_VERSION, validate_payload, validate_card, classify_operation

def install_endpoint(endpoint):
    if getattr(endpoint,'a2a_enabled',False): return
    original_publish=endpoint._op_publish
    def publish(actor,args,key):
        info=args['info']
        profile=info.get('profile')
        require(profile in (None,PROFILE),'A2A_PROFILE')
        if profile==PROFILE:
            validate_card(info['card'])
            require(info['card_digest']==digest(info['card']) and info['action_map_version']==MAP_VERSION
                and info['service_right']==info['member'],'A2A_PUBLISH_BINDING')
        old=endpoint.store.get('a2a_profiles',info['member'])
        require(not old or profile==PROFILE,'A2A_PROFILE_DOWNGRADE')
        result=original_publish(actor,args,key)
        if profile==PROFILE:
            endpoint.store.put('a2a_profiles',info['member'],copy.deepcopy(info))
        return result
    def admit(packet,session,key,operation):
        sr=session['binding']['service_right']
        current=endpoint.store.get('a2a_profiles',sr)
        payload=packet['payload']
        marked=isinstance(payload,dict) and payload.get('profile')==PROFILE
        if current is None:
            require(not marked,'A2A_SERVICE_NOT_PUBLISHED')
            return
        value=validate_payload(payload)
        require(value['service_right']==sr,'A2A_ACT_SERVICE')
        require(value['card_digest']==current['card_digest'] and value['action_map_version']==current['action_map_version'],'A2A_STALE_CARD')
        require(classify_operation(value)==operation,'A2A_OPERATION_BINDING')
        b=session['binding']
        dedup=canonical([endpoint.name,b['context'],b['caller_right'],sr,value['request']['message']['messageId']]).decode()
        prior=endpoint.store.get('a2a_messages',dedup)
        require(prior is None,'A2A_MESSAGE_ID_CONFLICT')
        endpoint.store.put('a2a_messages',dedup,dict(admission_key=key,payload_digest=digest(value)))
    endpoint._op_publish=publish
    endpoint.admission_hook=admit
    endpoint.a2a_enabled=True

def dispatch(node,method,args,peer):
    require(peer['name']=='Driver','CONTROLLER_ONLY')
    if method=='a2a_test':
        import os
        require(os.environ.get('GREDAC_A2A_TESTING')=='1','A2A_TEST_DISABLED')
        from .fault_hooks import control
        return control(node,args)
    if method=='a2a_send':
        from gredac.storage import position_key
        w=node.wallets[args['wallet']];operation=classify_operation(args['payload'])
        require(set(args['sources'])<=set(w.lane['sources']),'A2A_SOURCE_HINT')
        uncertain=w.holding.uncertain_units();selections={}
        for source in args['sources']:
            rows=[r for k,r in w.holding.records.items() if r['source']==source
                and r['state']=='unused' and r['holder_right']==w.holding.right
                and operation in r['hard_actions'] and k not in uncertain]
            require(rows,'NO_LOCAL_UNUSED_UNIT');selections[source]=min(r['slot'] for r in rows)
        return node.submit(w,w.prepare(operation,args['request_id'],selections,args['payload']))
    if method=='a2a_enable':
        require(node.endpoint is not None,'A2A_ENDPOINT_ONLY')
        install_endpoint(node.endpoint);return dict(profile=PROFILE)
    if method=='a2a_service':
        from .service import BridgeService
        from .fixtures import execute
        if hasattr(node,'a2a_bridge'):node.a2a_bridge.close()
        def business(data):
            node.business_calls+=1
            node.record('business_handler_started',dict(request_key=data['_admission_key'],count=node.business_calls))
            return execute(data)
        node.a2a_bridge=BridgeService(node.path/'a2a',node.name,business,timeout=args.get('timeout',5),
            version=args.get('version','1'))
        node.handler={'kind':'a2a_bridge'}
        return node.a2a_bridge.description()
    if method=='a2a_info':
        return node.a2a_bridge.description()
    if method=='a2a_fault':
        import os
        require(os.environ.get('GREDAC_A2A_TESTING')=='1','A2A_TEST_DISABLED')
        node.a2a_bridge.fault=args['point'];node.a2a_bridge.fault_mode=args.get('mode','exit');return True
    raise ValueError('unknown adapter control '+method)
