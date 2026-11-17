"""Participant-side validation from authenticated public records, no ledger.

An authenticated peer is not automatically the authorization's parent.
The root Authority proof and parent-signed path establish that relationship.
Return verification checks the exact signed grouping and inherited limits;
only the trusted endpoint can determine the globally recoverable unused set.
"""
import copy
from .crypto import require,verify_signature,digest,by_slot
from .storage import position_key
from .roles import verified,PROTOCOL

def authorization_path(root_proof,chain,authority_public,registrations,endpoint):
    root=root_proof['body'];verify_signature(authority_public,root,root_proof['signature'])
    require(root['parent'] is None,'INITIAL_AUTHORIZATION_ROOT')
    require(registrations[root['owner']]['public_key']==root['public_key'],'ROOT_IDENTITY_BINDING')
    rights={root['id']:root}
    for signed in chain:
        b=signed['body']
        if b['kind']!='authorization':continue
        require(b['protocol']==PROTOCOL and b['endpoint']==endpoint,'AUTHORIZATION_ENDPOINT')
        parent=rights.get(b['parent']);require(parent is not None,'AUTHORIZATION_PATH_GAP')
        verify_signature(parent['public_key'],b,signed['signature']);child=b['right']
        require(child['parent']==parent['id'] and child['side']==parent['side']
            and child['context']==b['context']==parent['context'],'AUTHORIZATION_PATH_BINDING')
        require(registrations[child['owner']]['public_key']==child['public_key'],'CHILD_IDENTITY_BINDING')
        require(child['actions'] and set(child['actions'])<=set(parent['actions'])
            and child['deadline']<=parent['deadline'] and 0<=child['depth']<parent['depth'],'RIGHT_WIDENING')
        require(child['deps']==sorted(set(parent['deps']+['right:'+child['id']])),'RIGHT_DEPENDENCIES')
        old=rights.get(child['id']);require(old is None or old==child,'IMMUTABLE_RIGHT');rights[child['id']]=child
    return rights

def accept_return(envelope,holding,right,target,endpoint,endpoint_public,request=None):
    b=verified(envelope,endpoint_public,protocol=PROTOCOL,endpoint=endpoint,kind='return',target=target)
    request=request or envelope.get('request');require(request is not None,'RETURN_REQUEST_REQUIRED')
    require(request['operation']=='return' and request['args']['id']==target and request['endpoint']==endpoint
        and b['request_digest']==digest(request) and b['operation']==request['actor']+'/'+request['id'],'RETURN_OPERATION_BINDING')
    rows={};groups={};slots={};scopes={}
    for row in b['rows']:
        unit=position_key(row['source'],row['slot']);require(unit not in rows,'RETURN_DUPLICATE_UNIT')
        cap=holding.caps.get(row['current_cap']['gid']);prior=holding.records.get(unit)
        require(cap is not None and cap['gid'] in holding.bundles and prior is not None,'RETURN_UNKNOWN_UNIT_OR_CAP')
        require(row['current_cap']==dict(anchor=cap['anchor'],gid=cap['gid'],holder_right=right['id'])
            and cap['holder_right']==right['id'] and cap['source']==row['source'] and cap['guard']==endpoint,'RETURN_CAP_BINDING')
        if cap['gid'] not in scopes:scopes[cap['gid']]=by_slot(cap['domain'])
        allowed=scopes[cap['gid']].get(row['slot'],[])
        require(row['state']=='unused' and row['holder_right']==right['id'] and row['owner']==right['owner']
            and row['context']==cap['context']==right['context'] and row['endpoint']==endpoint,'RETURN_RECIPIENT_BINDING')
        require(row['hard_actions'] and set(row['hard_actions'])<=set(allowed)&set(prior['hard_actions'])
            and row['hard_contexts'] and set(row['hard_contexts'])<=set(prior['hard_contexts'])
            and row['context'] in row['hard_contexts']
            and row['deadline']<=min(prior['deadline'],right['deadline']),'RETURN_INHERITED_LIMITS')
        record='return-'+digest([b['operation'],right['id'],cap['gid']])
        require(row['ownership']==record,'RETURN_RECORD_BINDING')
        groups.setdefault(record,[]).append(unit);rows[unit]=copy.deepcopy(row)
        slots.setdefault(row['source'],[]).append(row['slot'])
    require(set(groups)==set(b['records']),'RETURN_EXACT_GROUPS')
    for record,units in groups.items():
        meta=b['records'][record]
        require(meta['receiver']==right['id'] and sorted(meta['units'])==sorted(units)
            and len(meta['units'])==len(set(meta['units']))
            and all(rows[u]['current_cap']['gid']==meta['cap'] for u in units),'RETURN_EXACT_UNITS')
    require(not set(rows)&set(b['escrow']+b['retired']),'RETURN_STATE_CONFLICT')
    # All checks complete before any local state mutation.
    holding.records.update(rows)
    return slots
