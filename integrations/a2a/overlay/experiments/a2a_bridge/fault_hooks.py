"""Controller-only, environment-gated semantic test hooks. Never used by B5."""
import os,time
from gredac.crypto import require

def control(node,args):
    op=args['op']
    if op=='packet':
        w=node.wallets[args['wallet']]
        return w.packet(args['operation'],args['request_id'],args['selections'],args['payload'])
    if op=='endpoint_fault':
        point=args['point'];mode=args.get('mode','exit')
        require(point in ('before_admission_commit','after_pending','after_attempted'),'A2A_FAULT_POINT')
        def fault(where):
            states=[r['state'] for r in node.store.all('forwarding').values()]
            matched=(point=='before_admission_commit' and where=='before_commit' and 'pending' in states
                or point=='after_pending' and where=='after_commit' and 'pending' in states
                or point=='after_attempted' and where=='after_commit' and 'attempted' in states)
            if matched:
                node.store.commit_hook=None
                node.record('injected_fault',dict(point=point,mode=mode,time=time.monotonic()))
                if mode=='exit':os._exit(73)
                node.server.drop_response_method='endpoint_charge'
                raise ConnectionError('injected connection loss '+point)
        node.store.commit_hook=fault;return True
    if op=='replay_delivery':
        from gredac.endpoint import PROTOCOL
        key=args['key'];row=node.store.get('forwarding',key)
        require(row is not None,'TEST_ADMISSION_REQUIRED')
        envelope=node.endpoint.control.envelope(dict(protocol=PROTOCOL,endpoint=node.name,
            kind='service-delivery',key=key,**{k:row[k] for k in ('operation','payload','service','service_right','context')}))
        return node.rpc(row['service'],'service_receive',envelope=envelope)
    if op=='resend_right':
        rid=args['right'];r=node.rights[rid]
        require(r['parent'] in node.chains and r['parent'] in node.rights,'TEST_PARENT')
        return node.rpc(r['owner'],'install_right',right=r,
            chain=node.chains[r['parent']]+[node.authorizations[rid]],root_proof=node.root_proofs[rid])
    raise ValueError('unknown test operation')
