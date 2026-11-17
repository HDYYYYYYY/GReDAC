"""Agent Authority: low-frequency identity/contact/control and permanent positions."""
import copy
import secrets
from collections import Counter, defaultdict
from .crypto import (ACTIONS, SLOT_BITS, SCHEME, Signer, canonical, digest, ident,
                     point, by_slot, require, verify_signature, Denied)
from .capabilities import Forest
from .storage import position_key


class AgentAuthority:
    def __init__(self, store, clock, pki, mode, lease_seconds=5.0, contact_seconds=30.0):
        self.store, self.clock, self.pki, self.mode = store, clock, pki, mode
        self.signer, self.forest = Signer.persistent(store, 'Authority-control'), Forest(store)
        self.guard_public = None
        self.calls, self.operation = Counter(), ''
        require(lease_seconds > 0, 'LEASE_DURATION')
        self.lease_seconds = float(lease_seconds)
        # Explicit research configuration for sustained measurements; default
        # preserves the original contact profile. All hard-deadline checks stay.
        require(contact_seconds > 0, 'CONTACT_DURATION')
        self.contact_seconds = float(contact_seconds)

    def bootstrap_identity(self, actor, owner):
        reg = self.pki.issue(actor.name, actor.public, self.pki.csr(actor), owner)
        reg['contact_public_key'] = actor.contact.public_key().public_bytes_raw().hex()
        with self.store.transaction():
            require(not self.store.get('registrations', actor.name), 'IDENTITY_EXISTS')
            self.store.put('registrations', actor.name, reg)
        self.pki.materialize(actor, reg)
        return reg

    def registration(self, name):
        reg = self.store.get('registrations', name)
        require(reg is not None, 'IDENTITY_NOT_REGISTERED')
        self.pki.validate(reg['certificate'], reg)
        return reg

    def verifier_delivery(self, command):
        verify_signature(self.signer.public, command['body'], command['signature'])
        lane = command['body']['lane']
        # Serialize a fresh material release with revocation/cancellation.
        with self.store.transaction():
            require(self.store.get('lanes', lane['id']) == lane, 'UNKNOWN_INSTALL')
            self._lane_control(lane)
            self.calls['verifier_delivery'] += 1
            material = ({} if self.mode == 'signed-local' else
                        {gid: self.forest.rebuild(gid).public_secrets() for gid in lane['caps']})
        return material

    def online_charge(self, engine, signed_forward):
        self.calls['charge'] += 1
        body = signed_forward['body']
        verify_signature(self.guard_public, body, signed_forward['signature'])
        require(engine.store is self.store, 'WRONG_CHARGE_AUTHORITY')
        return engine.charge(body['packet'], body['route'], body['session'])

    def call(self, actor, op, args, op_id=None):
        request = {'actor': actor.name, 'operation': op, 'id': op_id or ident(), 'args': args}
        return self.accept(request, actor.sign(request))

    def accept(self, request, signature):
        reg = self.registration(request['actor'])
        verify_signature(reg['public_key'], request, signature)
        self.calls['control:' + request['operation']] += 1
        key = request['actor'] + '/' + request['id']
        with self.store.transaction():
            old = self.store.get('operations', key)
            if old:
                require(old['fingerprint'] == digest(request), 'OP_ID_CONFLICT')
                return old['result']
            self.operation = key
            method = getattr(self, 'op_' + request['operation'], None)
            require(method is not None, 'UNKNOWN_OPERATION')
            result = method(request['actor'], copy.deepcopy(request['args']))
            self.store.put('operations', key, {'fingerprint': digest(request), 'result': result})
            self.store.event('control', {'operation': request['operation'], 'ref': key,
                                         'actor': request['actor'], 'time': self.clock.now()})
        return result

    def _active(self, deps):
        require(not any(self.store.get('revoked', d) for d in deps), 'REVOKED')

    def _lane_control(self, lane):
        require(not self.store.get('cancellations', lane['id']), 'LANE_CANCELLED')
        self._active(lane['deps'])
        require(self.clock.now() < lane['deadline'], 'EXPIRED')

    def _recovery_receiver(self, original_right):
        # The prototype policy is the nearest currently valid caller ancestor.
        for candidate in self.path(original_right)[1:]:
            try:
                receiver = self.right(candidate['id'])
                self.context(receiver['context'])
                return receiver
            except Denied:
                pass
        return None

    def context(self, cid):
        ctx = self.store.get('contexts', cid)
        require(ctx is not None, 'UNKNOWN_CONTEXT')
        self._active(ctx['deps'])
        require(ctx['deadline'] > self.clock.now(), 'CONTEXT_EXPIRED')
        return ctx

    def right(self, rid, valid=True):
        right = self.store.get('rights', rid)
        require(right is not None, 'UNKNOWN_RIGHT')
        if valid:
            require(right['deadline'] > self.clock.now(), 'RIGHT_EXPIRED')
            self._active(right['deps'])
        return right

    def path(self, rid):
        result = []
        while rid:
            right = self.right(rid, valid=False)
            result.append(right)
            rid = right['parent']
        return result

    def op_context(self, actor, args):
        body = args['body']
        require(actor == body['caller_approver'], 'NOT_OWNER_APPROVER')
        require(not self.store.get('contexts', body['id']), 'IMMUTABLE_CONTEXT')
        for owner in (body['caller_approver'], body['service_approver']):
            verify_signature(self.registration(owner)['public_key'], body, args['approvals'][owner])
        require(body['req'] and set(body['req']) <= set(ACTIONS), 'CONTEXT_ACTIONS')
        body['req'] = {op: sorted(set(s)) for op, s in body['req'].items()}
        require(all(body['req'].values()), 'EMPTY_SOURCE_RULE')
        body['rule_snapshot'] = digest({'req': body['req'], 'basis': body['basis']})
        body['deps'] = sorted(['ctx:' + body['id'], 'coop:' + body['cooperation']]
                              + ['task:' + t for t in body['tasks']])
        self._active(body['deps'])
        self.store.put('contexts', body['id'], body)
        return body

    def op_source(self, actor, args):
        require(actor == args['issuer'] and actor in ('UO', 'UR'), 'NOT_SOURCE_ISSUER')
        key = args['approval'] + '/' + args['id']
        require(not self.store.get('sources', args['id'])
                and not self.store.get('issuances', key), 'SOURCE_ALREADY_ISSUED')
        require(0 < args['size'] <= 2**SLOT_BITS, 'SOURCE_SIZE')
        self.store.put('sources', args['id'], args)
        self.store.put('issuances', key, True)
        self.store.put('source_masters', args['id'], secrets.token_hex(32))
        for i in range(args['size']):
            self.store.put('positions', position_key(args['id'], i), {
                'source': args['id'], 'slot': i, 'state': 'unbound', 'version': 0,
                'current_cap': None, 'hard_actions': sorted(args['actions']),
                'hard_contexts': args['contexts'], 'deadline': args['deadline']})
        return {'source': args['id'], 'issued': args['size']}

    def op_right(self, actor, args):
        require(not self.store.get('rights', args['id']), 'IMMUTABLE_RIGHT')
        ctx = self.context(args['context'])
        require(args['side'] in ('caller', 'service'), 'RIGHT_SIDE')
        proof = args.pop('proof')
        verify_signature(args['public_key'], args, proof)
        require(args['actions'] and set(args['actions']) <= set(ctx['req']), 'RIGHT_ACTIONS')
        deps = ctx['deps'][:]
        if args['parent']:
            parent = self.right(args['parent'])
            require(actor == parent['owner'], 'NOT_PARENT_OWNER')
            require(parent['side'] == args['side'] and parent['context'] == ctx['id'],
                    'RIGHT_PARENT_CONTEXT')
            require(set(args['actions']) <= set(parent['actions'])
                    and args['deadline'] <= parent['deadline']
                    and 0 <= args['depth'] < parent['depth'], 'RIGHT_WIDENING')
            deps = parent['deps'][:]
        else:
            require(actor == ctx[args['side'] + '_approver']
                    and args['id'] == ctx[args['side'] + '_root'], 'ROOT_SNAPSHOT')
            reg = self.registration(args['owner'])
            require(reg['public_key'] == args['public_key'], 'ROOT_IDENTITY_SNAPSHOT')
        args['actions'] = sorted(set(args['actions']))
        args['deps'] = sorted(set(deps + ['right:' + args['id']]))
        args['operation'] = self.operation
        self.store.put('rights', args['id'], args)
        result = self.signer.envelope(args)
        self.store.put('right_descriptors', args['id'], result)
        return result

    def op_challenge(self, actor, args):
        right = self.right(args['right'])
        parent = self.right(right['parent'])
        require(parent['owner'] == actor, 'NOT_PARENT_OWNER')
        body = {'id': ident(), 'right': right['id'], 'parent': actor,
                'expires': self.clock.now()+10, 'used': False}
        self.store.put('challenges', body['id'], body)
        return body

    def op_register(self, actor, args):
        body = args['body']
        right = self.right(body['right'])
        parent = self.right(right['parent'])
        challenge = self.store.get('challenges', body['challenge'])
        require(challenge and not challenge['used'] and challenge['expires'] > self.clock.now()
                and challenge['right'] == right['id'] and challenge['parent'] == actor,
                'REGISTRATION_CHALLENGE')
        require(parent['owner'] == actor and right['owner'] == body['agent_id']
                and right['public_key'] == body['public_key'], 'PARENT_REGISTRATION_BINDING')
        verify_signature(body['public_key'], body, args['proof'])
        require(not self.store.get('registrations', body['agent_id']), 'IMMUTABLE_REGISTRATION')
        reg = self.pki.issue(body['agent_id'], body['public_key'], args['csr'],
                             self.context(right['context'])[right['side'] + '_approver'])
        require(digest(args['csr']) == body['csr_ref'], 'CSR_BINDING')
        reg['contact_public_key'] = body['contact_public_key']
        reg['registration_operation'] = self.operation
        self.store.put('registrations', body['agent_id'], reg)
        challenge['used'] = True
        self.store.put('challenges', challenge['id'], challenge)
        return reg

    def _scope(self, right, source, domain):
        ctx = self.context(right['context'])
        self._active(['source:' + source])
        spec = self.store.get('sources', source)
        require(spec and ctx['id'] in spec['contexts']
                and ctx['basis'].get(source) == spec['basis'], 'SOURCE_CONTEXT_BASIS')
        projected = by_slot(domain)
        require(projected, 'EMPTY_DOMAIN')
        rows = []
        for slot, actions in projected.items():
            row = self.store.get('positions', position_key(source, slot))
            require(row is not None, 'PADDING_SLOT_NOT_ISSUED')
            require(set(actions) <= set(right['actions']) & set(row['hard_actions'])
                    and right['context'] in row['hard_contexts']
                    and row['deadline'] > self.clock.now(), 'HARD_LABEL')
            rows.append(row)
        return rows

    def _bind(self, rows, cap, right, domain):
        scopes = by_slot(domain)
        # The immutable capability is already available. Do not reread and
        # JSON-parse its entire scope/snapshot once per budget unit.
        binding = {k:cap[k] for k in ('anchor','gid','holder_right')}
        for row in rows:
            row.update(state='free', context=right['context'], holder_right=right['id'],
                       owner=right['owner'], current_cap=binding.copy(),
                       hard_actions=sorted(set(row['hard_actions']) & set(scopes[row['slot']])),
                       deadline=min(row['deadline'], right['deadline']))
            self.store.put('positions', position_key(row['source'], row['slot']), row)

    def op_seed(self, actor, args):
        right = self.right(args['right'])
        ctx = self.context(right['context'])
        require(actor == ctx['caller_approver'] and right['side'] == 'caller'
                and not right['parent'], 'INITIAL_SEED_AUTHORITY')
        result = []
        for source, domain in args['domains'].items():
            rows = self._scope(right, source, domain)
            require(all(r['state'] == 'unbound' for r in rows), 'NOT_UNISSUED_CAPACITY')
            cap = self.forest.create(source, ctx['id'], right['id'], domain,
                                     rows, self.operation)
            self._bind(rows, cap, right, domain)
            result.append(cap)
        return result

    def _receipt(self, signed):
        receipt = signed['body']
        verify_signature(self.guard_public, receipt, signed['signature'])
        require(receipt['kind'] == 'seal-receipt', 'RECEIPT_KIND')
        require(not self.store.get('used_receipts', receipt['id']), 'RECEIPT_ALREADY_USED')
        keys = [position_key(r['source'], r['slot']) for r in receipt['rows']]
        require(len(keys) == len(set(keys)), 'RECEIPT_DUPLICATE')
        for r in receipt['rows']:
            row = self.store.get('positions', position_key(r['source'], r['slot']))
            require(row and row['state'] == 'held'
                    and all(row[k] == r[k] for k in
                            ('lane', 'install', 'version', 'holder_right', 'current_cap')),
                    'STALE_RECEIPT')
        return receipt

    def op_delegate(self, actor, args):
        parent, child = self.right(args['parent']), self.right(args['child'])
        require(parent['owner'] == actor and child['parent'] == parent['id']
                and child['side'] == 'caller' and child['context'] == parent['context'],
                'DELEGATION_PARENT')
        sealed = None
        if args.get('receipt'):
            sealed = self._receipt(args['receipt'])
            require(all(r['outcome'] == 'unused' for r in sealed['rows']), 'CANNOT_DELEGATE_SPENT')
        targets = {(s, i) for s, domain in args['domains'].items() for i in by_slot(domain)}
        if sealed:
            require(targets == {(r['source'], r['slot']) for r in sealed['rows']},
                    'EXACT_DELEGATION_TARGET')
        grouped = defaultdict(list)
        row_groups = defaultdict(list)
        for source, domain in args['domains'].items():
            for row in self._scope(child, source, domain):
                require(row['state'] == ('held' if sealed else 'free'), 'POSITION_NOT_FREE')
                require(row.get('holder_right') == parent['id'], 'NOT_PARENT_POSITION')
                selected = args['parents'][source][str(row['slot'])]
                require(row['current_cap'] is not None
                        and row['current_cap']['gid'] == selected, 'CURRENT_CAP_MISMATCH')
                cap = self.forest.cap(selected)
                require(cap['holder_right'] == parent['id'] and cap['anchor'] == row['current_cap']['anchor'],
                        'CURRENT_CAP_HOLDER')
                desired = [p for p in domain if p % 2**SLOT_BITS == row['slot']]
                require(set(desired) <= set(cap['domain']), 'CHILD_OUTSIDE_PARENT')
                grouped[(source, selected)].extend(desired)
                row_groups[(source, selected)].append(row)
        result = []
        for (source, parent_gid), domain in grouped.items():
            rows = row_groups[(source, parent_gid)]
            cap = self.forest.create(source, child['context'], child['id'], domain,
                                     rows, self.operation, parent=parent_gid)
            self._bind(rows, cap, child, domain)
            result.append(cap)
        if sealed:
            self.store.put('used_receipts', sealed['id'], True)
        return result

    def op_reserve(self, actor, args):
        caller, service = self.right(args['caller']), self.right(args['service'])
        ctx = self.context(caller['context'])
        require(actor == caller['owner'] and caller['side'] == 'caller'
                and service['side'] == 'service' and service['context'] == ctx['id'], 'LANE_PARTICIPANTS')
        require(self.registration(actor)['public_key'] == caller['public_key']
                and self.registration(service['owner'])['public_key'] == service['public_key'],
                'REGISTERED_IDENTITY_REQUIRED')
        contact = self.store.get('acts', args['act'])
        require(contact is not None, 'NO_ACT')
        act = contact['body']
        require(act['caller_right'] == caller['id'] and act['service_right'] == service['id']
                and act['context'] == ctx['id'] and act['expires'] > self.clock.now(), 'ACT_BINDING')
        actions = sorted(set(caller['actions']) & set(service['actions']))
        require(actions, 'LANE_ACTIONS')
        required = set().union(*(set(ctx['req'][op]) for op in actions))
        require(set(args['slots']) == required, 'LANE_SOURCE_SET')
        deps = sorted(set(caller['deps'] + service['deps'] + ['source:' + s for s in args['slots']]))
        self._active(deps)  # Check the complete set before issuing a new lease/install.
        lane_id, rows, caps = ident(), [], {}
        for source, slots in args['slots'].items():
            require(slots and len(slots) == len(set(slots)), 'DUPLICATE_SLOT')
            for slot in slots:
                row = self.store.get('positions', position_key(source, slot))
                require(row and row['state'] == 'free', 'POSITION_NOT_FREE')
                require(row['holder_right'] == caller['id'] and row['current_cap'], 'CURRENT_HOLDER')
                gid = row['current_cap']['gid']
                cap = self.forest.cap(gid)
                require(cap['context'] == ctx['id'] and cap['holder_right'] == caller['id'], 'CURRENT_CAP_MISMATCH')
                require(all(point(op, slot) in cap['domain'] for op in actions), 'LANE_CAP_SCOPE')
                expected = row['version']
                row.update(state='held', lane=lane_id, install=ident(), version=expected+1)
                self.store.put('positions', position_key(source, slot), row)
                rows.append({**row, 'expected': expected})
                caps[gid] = cap
        lane = {'id': lane_id, 'guard': 'G', 'context': ctx, 'caller': caller, 'service': service,
                'actions': actions, 'act': contact, 'rows': rows, 'caps': caps, 'deps': deps,
                'deadline': min(ctx['deadline'], caller['deadline'], service['deadline'],
                                act['expires'], *(r['deadline'] for r in rows))}
        lane['lease'] = min(self.clock.now()+self.lease_seconds, lane['deadline'])
        if self.mode != 'signed-local':
            lane['verifier_digests'] = {gid: digest(self.forest.rebuild(gid).public_secrets()) for gid in caps}
        else:
            lane['verifier_digests'] = {}
        self.store.put('lanes', lane_id, lane)
        self.store.event('reserve', lane)
        return self.signer.envelope({'kind': 'install', 'lane': lane})

    def op_prepare_seal(self, actor, args):
        lane = self.store.get('lanes', args['lane'])
        require(lane is not None, 'UNKNOWN_LANE')
        require(actor in {r['owner'] for r in self.path(lane['caller']['id'])}
                or actor == lane['context']['caller_approver'], 'SEAL_AUTHORITY')
        rows = []
        for original in lane['rows']:
            row = self.store.get('positions', position_key(original['source'], original['slot']))
            if row['state'] != 'held' or row.get('lane') != lane['id']:
                continue
            if args.get('slots') is not None and row['slot'] not in args['slots'].get(row['source'], []):
                continue
            require(row['current_cap'] == original['current_cap'], 'CURRENT_CAP_MISMATCH')
            rows.append({**row, 'expected': original['expected']})
        require(rows, 'NOTHING_TO_SEAL')
        return self.signer.envelope({'kind': 'seal', 'id': ident(), 'lane': lane['id'], 'rows': rows})

    def op_reclaim(self, actor, args):
        receipt = self._receipt(args['receipt'])
        returned = []
        for r in receipt['rows']:
            row = self.store.get('positions', position_key(r['source'], r['slot']))
            original = self.right(row['holder_right'], valid=False)
            ctx = self.store.get('contexts', original['context'])
            require(actor == ctx['caller_approver'] or actor in {x['owner'] for x in self.path(original['id'])},
                    'RECLAIM_AUTHORITY')
            if r['outcome'] == 'spent':
                row['state'] = 'spent'
            else:
                receiver = self._recovery_receiver(original['id'])
                row['old_cap'] = row['current_cap']
                row['current_cap'] = None
                row['state'] = ('retired' if row['deadline'] <= self.clock.now()
                                else 'free_pending_reissue' if receiver else 'escrow')
                row['receiver'] = receiver['id'] if receiver else None
                if receiver:
                    row.update(holder_right=receiver['id'], owner=receiver['owner'])
                returned.append(copy.deepcopy(row))
            self.store.put('positions', position_key(r['source'], r['slot']), row)
        self.store.put('used_receipts', receipt['id'], True)
        cancellation = self.store.get('cancellations', receipt['lane'])
        if cancellation and not any(r['state'] == 'held' and r.get('lane') == receipt['lane']
                                    for r in self.store.all('positions').values()):
            cancellation['state'] = 'cancelled_settled'
            self.store.put('cancellations', receipt['lane'], cancellation)
        self.store.event('reclaim', {'receipt': receipt, 'returned': returned, 'time': self.clock.now()})
        return returned

    def _reissue(self, actor, args, creation):
        right = self.right(args['right'])
        ctx = self.context(right['context'])
        require(actor == ctx['caller_approver'], 'INDEPENDENT_OWNER_APPROVAL_REQUIRED')
        require(self.registration(right['owner'])['public_key'] == right['public_key'], 'RECOVERY_IDENTITY')
        result = []
        for source, slots in args['slots'].items():
            domain, rows = [], []
            for slot in slots:
                row = self.store.get('positions', position_key(source, slot))
                require(row is not None, 'UNKNOWN_POSITION')
                if creation == 'recovery':
                    require(row['state'] == 'free_pending_reissue' and row['current_cap'] is None,
                            'NOT_PENDING_RECOVERY')
                    # Re-evaluate on the original path in this same commit, never
                    # on a caller-selected history or an unrelated same-owner Right.
                    receiver = self._recovery_receiver(row['old_cap']['holder_right'])
                    require(receiver and receiver['id'] == right['id'], 'RECOVERY_RECEIVER')
                    row['receiver'] = receiver['id']
                else:
                    require(row['state'] == 'free' and row['current_cap'], 'MIGRATION_NOT_FREE')
                    old_context = self.store.get('contexts', row['context'])
                    require(old_context['caller_approver'] == actor, 'MIGRATION_AUTHORITY')
                    require(row['current_cap']['gid'] == args['parents'][source][str(slot)],
                            'CURRENT_CAP_MISMATCH')
                allowed = sorted(set(row['hard_actions']) & set(right['actions']))
                require(allowed, 'NO_RECOVERY_ACTIONS')
                domain.extend(point(op, slot) for op in allowed)
                rows.append(row)
            self._scope(right, source, domain)
            cap = self.forest.create(source, ctx['id'], right['id'], domain, rows,
                                     self.operation, creation=creation)
            self._bind(rows, cap, right, domain)
            result.append(cap)
        self.store.event(creation, {'caps': result, 'time': self.clock.now()})
        return result

    def op_recover(self, actor, args):
        return self._reissue(actor, args, 'recovery')

    def op_migrate(self, actor, args):
        return self._reissue(actor, args, 'migration')

    def op_revoke(self, actor, args):
        kind, target = args.get('kind', 'right'), args['id']
        if kind == 'right':
            right = self.right(target, valid=False)
            ctx = self.store.get('contexts', right['context'])
            allowed = {r['owner'] for r in self.path(target)} | {ctx[right['side']+'_approver']}
        else:
            require(kind in ('task', 'coop', 'source', 'ctx'), 'REVOKE_KIND')
            allowed = {'UO', 'UR'}
        require(actor in allowed, 'REVOCATION_AUTHORITY')
        body = {'kind': 'revoke', 'dep': kind+':'+target, 'time': self.clock.now()}
        self.store.put('revoked', body['dep'], body)
        self.store.event('revoke', body)
        return self.signer.envelope(body)

    def op_renew(self, actor, args):
        lane = self.store.get('lanes', args['lane'])
        require(lane and actor == lane['caller']['owner'], 'NOT_LANE_OWNER')
        self._lane_control(lane)
        return self.signer.envelope({'kind': 'renew', 'lane': lane['id'],
                'lease': min(self.clock.now()+self.lease_seconds, lane['deadline']), 'deps': lane['deps']})

    def op_cancel(self, actor, args):
        lane = self.store.get('lanes', args['lane'])
        require(lane and actor in (lane['caller']['owner'], lane['context']['caller_approver']),
                'CANCEL_AUTHORITY')
        old = self.store.get('cancellations', lane['id'])
        if old:
            return {'lane': lane['id'], 'state': old['state'], 'refunded': 0}
        self.store.put('cancellations', lane['id'], {'state': 'cancel_pending', 'operation': self.operation})
        return {'lane': lane['id'], 'state': 'cancel_pending', 'refunded': 0}

    def op_otk(self, actor, args):
        require(not self.store.get('otks', args['id']), 'OTK_REUSE')
        self.store.put('otks', args['id'], {**args, 'owner': actor, 'used': False})
        return args['id']

    def op_permit(self, actor, args):
        caller, service = self.right(args['caller']), self.right(args['service'])
        require(actor == caller['owner'] and caller['context'] == service['context'], 'CONTACT_RIGHTS')
        ctx, otk = self.context(caller['context']), self.store.get('otks', args['otk'])
        require(otk and not otk['used'] and otk['owner'] == service['owner'], 'OTK_UNAVAILABLE')
        c, s = self.registration(actor), self.registration(service['owner'])
        body = {'kind': 'OTKPermit', 'id': ident(), 'otk': args['otk'], 'otk_public': otk['public'],
                'caller': actor, 'receiver': service['owner'], 'caller_right': caller['id'],
                'service_right': service['id'], 'caller_key': c['key_ref'], 'receiver_key': s['key_ref'],
                'caller_contact': c['contact_public_key'], 'receiver_contact': s['contact_public_key'],
                'context': ctx['id'], 'cooperation': ctx['cooperation'], 'expires': self.clock.now()+self.contact_seconds}
        result = self.signer.envelope(body)
        self.store.put('permits', body['id'], result)
        return result

    def op_redeem(self, actor, args):
        signed = self.store.get('permits', args['permit'])
        require(signed is not None, 'UNKNOWN_PERMIT')
        permit = signed['body']
        self.right(permit['caller_right'])
        self.right(permit['service_right'])
        require(actor == permit['receiver'] and permit['expires'] > self.clock.now(), 'PERMIT_BINDING')
        require(args['init']['permit'] == permit['id'], 'PERMIT_BINDING')
        verify_signature(self.registration(permit['caller'])['public_key'], args['init'], args['proof'])
        otk = self.store.get('otks', permit['otk'])
        require(not otk['used'] and not self.store.get('redeemed', permit['id']), 'OTK_ALREADY_REDEEMED')
        otk['used'] = True
        self.store.put('otks', permit['otk'], otk)
        self.store.put('redeemed', permit['id'], args['init'])
        return permit

    def op_act(self, actor, args):
        body = args['body']
        permit = self.store.get('permits', body['permit'])['body']
        self.right(permit['caller_right'])
        self.right(permit['service_right'])
        require(actor == permit['receiver'] and self.store.get('redeemed', permit['id']), 'ACT_REDEEM')
        verify_signature(self.registration(actor)['public_key'], body, args['signature'])
        for k in ('caller_right', 'service_right', 'context', 'caller', 'receiver'):
            require(body[k] == permit[k], 'ACT_BINDING')
        require(body['session'] == self.store.get('redeemed', permit['id'])['session'], 'ACT_SESSION_BINDING')
        require(body['expires'] <= permit['expires'] and not self.store.get('acts', body['id']), 'ACT_ID')
        self.store.put('acts', body['id'], args)
        return args
