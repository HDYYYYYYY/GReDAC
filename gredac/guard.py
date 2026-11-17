"""Interaction Guard and shared atomic charge engine; no master/anchor secrets."""
import copy
import hashlib
import hmac
import json
import struct
from dataclasses import dataclass, field
from .crypto import (SCHEME, ACTIONS, SLOT_BITS, Bundle, Denied, canonical, channel_mac,
                     decode, digest, encode, ident, point, require, verify_signature, Signer)
from .storage import position_key


class ChargeEngine:
    def __init__(self, store, clock, authority_public, control_signer, mode):
        self.store, self.clock = store, clock
        self.authority_public, self.control_signer, self.mode = authority_public, control_signer, mode

    def command(self, envelope, kind):
        verify_signature(self.authority_public, envelope['body'], envelope['signature'])
        require(envelope['body']['kind'] == kind, 'CONTROL_KIND')
        return envelope['body']

    def install(self, command, material):
        lane = self.command(command, 'install')['lane']
        with self.store.transaction():
            old = self.store.get('install_results', lane['id'])
            if old:
                require(old['digest'] == digest(lane), 'INSTALL_ID_CONFLICT')
                return old
            require(not any(self.store.get('revoked', d) for d in lane['deps']), 'KNOWN_REVOKED')
            for row in lane['rows']:
                current = self.store.get('live', position_key(row['source'], row['slot']),
                                         {'version': 0, 'state': 'idle'})
                require(not self.store.get('fences', row['install']), 'INSTALL_FENCED')
                require(current['version'] == row['expected']
                        and current['state'] in ('idle', 'closed-unused'), 'INSTALL_VERSION_OR_STATE')
                cap = lane['caps'][row['current_cap']['gid']]
                require(row['current_cap'] == {'anchor': cap['anchor'], 'gid': cap['gid'],
                                                'holder_right': cap['holder_right']}, 'INSTALL_CAP_BINDING')
            if self.mode != 'signed-local':
                require(set(material) == set(lane['verifier_digests']), 'VERIFIER_SET')
                for gid, seeds in material.items():
                    require(digest(seeds) == lane['verifier_digests'][gid], 'VERIFIER_BINDING')
                    require(sorted(seeds) == sorted(lane['caps'][gid]['cover']), 'VERIFIER_COVER')
            for row in lane['rows']:
                self.store.put('live', position_key(row['source'], row['slot']), {**row, 'state': 'unused'})
            for gid, seeds in material.items():
                self.store.put('verifiers', gid, seeds)
            self.store.put('installed_lanes', lane['id'], lane)
            result = {'digest': digest(lane), 'installed': lane['id']}
            self.store.put('install_results', lane['id'], result)
            self.store.event('install', {'lane': lane['id'], 'time': self.clock.now()})
        return result

    def notice(self, command):
        body = self.command(command, 'revoke')
        with self.store.transaction():
            self.store.put('revoked', body['dep'], body)
            self.store.event('notice', body)

    def renew(self, command):
        body = self.command(command, 'renew')
        with self.store.transaction():
            lane = self.store.get('installed_lanes', body['lane'])
            require(lane and lane['deps'] == body['deps'], 'LEASE_BINDING')
            require(not any(self.store.get('revoked', d) for d in lane['deps']), 'KNOWN_REVOKED')
            require(body['lease'] <= lane['deadline'], 'LEASE_HARD_LIMIT')
            lane['lease'] = max(lane['lease'], body['lease'])
            self.store.put('installed_lanes', lane['id'], lane)

    def seal(self, command):
        body = self.command(command, 'seal')
        with self.store.transaction():
            old = self.store.get('seal_results', body['id'])
            if old:
                require(old['digest'] == digest(body), 'SEAL_ID_CONFLICT')
                return old['receipt']
            result = []
            for target in body['rows']:
                u = position_key(target['source'], target['slot'])
                row = self.store.get('live', u, {'version': 0, 'state': 'idle'})
                if row.get('install') == target['install']:
                    require(row['version'] == target['version']
                            and row['current_cap'] == target['current_cap'], 'SEAL_CAP_VERSION')
                    require(row['state'] in ('unused', 'spent', 'closed-unused', 'closed-spent'), 'SEAL_STATE')
                    outcome = 'spent' if row['state'].endswith('spent') else 'unused'
                else:
                    require(row['version'] == target['expected']
                            and row['state'] in ('idle', 'closed-unused'), 'STALE_SEAL')
                    row, outcome = dict(target), 'unused'
                row['state'] = 'closed-' + outcome
                self.store.put('live', u, row)
                self.store.put('fences', target['install'], True)
                result.append({k: target[k] for k in ('source', 'slot', 'lane', 'install',
                                                       'version', 'holder_right', 'current_cap')}
                              | {'outcome': outcome})
            receipt = self.control_signer.envelope({'kind': 'seal-receipt', 'id': body['id'],
                        'guard': 'G', 'lane': body['lane'], 'rows': result, 'time': self.clock.now()})
            self.store.put('seal_results', body['id'], {'digest': digest(body), 'receipt': receipt})
            self.store.event('seal', receipt['body'])
        return receipt

    def charge(self, packet, actual_operation, session):
        body = bytes.fromhex(packet['body'])
        fields, vector = decode(body)
        require(fields['full_payload'] == canonical(packet['payload']), 'FULL_PAYLOAD_BINDING')
        require(fields['actual_operation'] == struct.pack('>I', ACTIONS[actual_operation]), 'ACTUAL_OPERATION')
        for name, value in session['binding'].items():
            require(fields[name] == value.encode(), 'SESSION_BINDING')
        request_id = fields['request_id'].decode()
        key = canonical(['G', session['lane'], session['binding']['context'],
                         session['binding']['caller_right'], session['binding']['service_right'],
                         session['binding']['session'], request_id]).decode()
        fp = hashlib.sha256(body).hexdigest()
        with self.store.transaction():
            old = self.store.get('requests', key)
            if old:
                require(old['fingerprint'] == fp, 'REQUEST_ID_CONFLICT')
                return {**old['decision'], 'replay': True}
            lane = self.store.get('installed_lanes', session['lane'])
            require(lane is not None, 'NO_LANE')
            require(not any(self.store.get('revoked', d) for d in lane['deps']),
                    'REVOKED' if self.mode == 'online-authority' else 'KNOWN_REVOKED')
            require(self.clock.now()+0.001 < min(lane['lease'], lane['deadline']), 'LEASE_OR_HARD_EXPIRED')
            require(actual_operation in lane['actions'], 'ACTION_SCOPE')
            req = lane['context']['req'][actual_operation]
            require([s for s, *_ in vector] == req, 'REQUIRED_SOURCE_SET')
            require(set(packet['proofs']) == set(req) if self.mode != 'signed-local'
                    else not packet['proofs'], 'PROOF_SET')
            changes = []
            for source, slot, aid, gid, install in vector:
                row = self.store.get('live', position_key(source, slot))
                require(row and row['lane'] == lane['id']
                        and row['holder_right'] == lane['caller']['id'], 'POSITION_OWNER_OR_CONTEXT')
                require(row['state'] == 'unused' and not self.store.get('fences', row['install']),
                        'POSITION_SPENT_OR_FENCED')
                require(row['current_cap'] == {'anchor': aid, 'gid': gid,
                        'holder_right': lane['caller']['id']} and row['install'] == install, 'CURRENT_CAP_BINDING')
                require(actual_operation in row['hard_actions']
                        and lane['context']['id'] in row['hard_contexts'], 'HARD_LABEL')
                if self.mode != 'signed-local':
                    seeds = self.store.get('verifiers', row['current_cap']['gid'])
                    require(seeds is not None, 'VERIFIER_CACHE_MISSING')
                    cap = lane['caps'][row['current_cap']['gid']]
                    bundle = Bundle(cap['gid'], cap['anchor'], tuple(cap['domain']),
                                    {p: bytes.fromhex(k) for p, k in seeds.items()})
                    expected = bundle.tag(point(actual_operation, slot), body)
                    require(hmac.compare_digest(expected, packet['proofs'][source]), 'BAD_CAP_TAG')
                changes.append(row)
            require(self.clock.now()+0.001 < min(lane['lease'], lane['deadline']), 'FINAL_DEADLINE')
            for row in changes:
                row['state'] = 'spent'
                self.store.put('live', position_key(row['source'], row['slot']), row)
            decision = {'key': key, 'lane': lane['id'], 'context': lane['context']['id'],
                        'operation': actual_operation, 'participants': [lane['caller']['owner'], lane['service']['owner']],
                        'sources': [[r['source'], r['slot']] for r in changes],
                        'cap_bindings': [r['current_cap'] for r in changes], 'deps': lane['deps'],
                        'commit_time': self.clock.now(), 'lease': lane['lease'], 'replay': False}
            self.store.put('requests', key, {'body': body.hex(), 'fingerprint': fp, 'decision': decision})
            self.store.event('charge', decision)
        return decision


class InteractionGuard:
    def __init__(self, store, authority, clock, pki, mode):
        self.store, self.authority, self.clock, self.pki, self.mode = store, authority, clock, pki, mode
        self.control = Signer.persistent(store, 'Guard-control')
        authority.guard_public = self.control.public
        self.authority_store = authority.store if mode == 'online-authority' else store
        self.engine = ChargeEngine(self.authority_store, clock, authority.signer.public, self.control, mode)
        self.authority_link = pki.link('G', 'Authority') if mode == 'online-authority' else None

    def install(self, command, material):
        result = self.engine.install(command, material)
        lane = command['body']['lane']
        if self.mode == 'online-authority':
            with self.store.transaction():
                self.store.put('installed_lanes', lane['id'], lane)
        return result

    def session(self, lane, actor, receiver, channel_key, link):
        act = lane['act']['body']
        verify_signature(self.authority.registration(receiver.name)['public_key'], act, lane['act']['signature'])
        require(link.caller == actor.name and link.receiver == 'G', 'TLS_PARTICIPANT')
        require(actor.name == lane['caller']['owner'] and receiver.name == lane['service']['owner'], 'PARTICIPANTS')
        c, s = self.authority.registration(actor.name), self.authority.registration(receiver.name)
        binding = {'scheme': SCHEME, 'context': lane['context']['id'],
                   'rule_snapshot': lane['context']['rule_snapshot'], 'cooperation': lane['context']['cooperation'],
                   'guard': 'G', 'lane': lane['id'], 'act': act['id'],
                   'caller_identity': actor.name, 'caller_key_version': c['key_ref'],
                   'service_identity': receiver.name, 'service_key_version': s['key_ref'],
                   'caller_right': lane['caller']['id'], 'service_right': lane['service']['id'],
                   'session': act['session']}
        session = {'binding': binding, 'lane': lane['id'], 'key': channel_key.hex()}
        with self.store.transaction():
            require(not self.store.get('sessions', act['session']), 'SESSION_EXISTS')
            self.store.put('sessions', act['session'], session)
            self.store.event('tls-session', link.info | {'session': act['session']})
        return session

    def charge(self, packet, actual_operation, link):
        # Actual TLS records are produced and decrypted on every public call.
        delivered = json.loads(link.transfer(canonical(packet)))
        fields, _ = decode(bytes.fromhex(delivered['body']))
        session = self.store.get('sessions', fields['session'].decode())
        require(session and link.caller == session['binding']['caller_identity']
                and link.receiver == 'G', 'TLS_SESSION_IDENTITY')
        require(hmac.compare_digest(channel_mac(bytes.fromhex(session['key']), bytes.fromhex(delivered['body'])),
                                    delivered['channel']), 'CHANNEL_AUTHENTICATION')
        try:
            if self.mode == 'online-authority':
                forwarded = self.control.envelope({'packet': delivered, 'route': actual_operation,
                                                    'session': session})
                forwarded = json.loads(self.authority_link.transfer(canonical(forwarded)))
                decision = self.authority.online_charge(self.engine, forwarded)
                decision = json.loads(self.authority_link.transfer(canonical(decision), reply=True))
            else:
                decision = self.engine.charge(delivered, actual_operation, session)
        except Denied as error:
            with self.store.transaction():
                self.store.event('denied', {'reason': error.code, 'time': self.clock.now()})
            raise
        with self.store.transaction():
            if not self.store.get('effects', decision['key']):
                self.store.put('effects', decision['key'], {'operation': actual_operation, 'payload': delivered['payload']})
        returned = json.loads(link.transfer(canonical(decision), reply=True))
        return returned


@dataclass
class Holding:
    right: str
    caps: dict = field(default_factory=dict)
    bundles: dict = field(default_factory=dict)


@dataclass
class Wallet:
    lane: dict
    holding: Holding
    session: dict
    channel_key: bytes
    link: object

    def packet(self, operation, request_id, selection, payload=None, row_overrides=None,
               bundle_overrides=None, bad_proofs=False):
        payload = {'text': request_id} if payload is None else payload
        rows = {(r['source'], r['slot']): r for r in self.lane['rows']}
        rows.update(row_overrides or {})
        fields = {k: v.encode() for k, v in self.session['binding'].items()}
        fields.update(request_id=request_id.encode(), actual_operation=struct.pack('>I', ACTIONS[operation]),
                      full_payload=canonical(payload))
        vector = []
        for source, slot in selection.items():
            row = rows[(source, slot)]
            current = row['current_cap']
            vector.append((source, slot, current['anchor'], current['gid'], row['install']))
        body = encode(fields, vector)
        proofs = {}
        if self.holding.bundles:
            for source, slot, _, gid, _ in vector:
                bundle = (bundle_overrides or {}).get(source, self.holding.bundles.get(gid))
                try:
                    require(bundle is not None, 'CLIENT_CAP_MISSING')
                    proofs[source] = bundle.tag(point(operation, slot), body)
                except Denied:
                    if not bad_proofs:
                        raise
                    proofs[source] = '00'*32
        packet={'body': body.hex(), 'payload': payload, 'proofs': proofs}
        if self.channel_key is not None:packet['channel']=channel_mac(self.channel_key,body)
        else:packet['act']=self.session['act']
        return packet
