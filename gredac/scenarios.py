"""Deterministic v3 examples; identities/cryptographic secrets are fresh per run."""
import copy
import hashlib
import json
import platform
import sqlite3
import ssl
from importlib.metadata import version
from pathlib import Path
from . import source_manifest
from .authority import AgentAuthority
from .contact import establish
from .crypto import (ACTIONS, SCHEME, Signer, Denied, canonical, digest, domain_for,
                     point, by_slot, ident)
from .guard import InteractionGuard, Holding, Wallet
from .pki import PKI
from .storage import Clock, Store, position_key


class Lab:
    def __init__(self, directory, mode, scenario):
        self.directory, self.mode, self.scenario = Path(directory), mode, scenario
        self.directory.mkdir(parents=True, exist_ok=False)
        self.clock, self.identities, self.holdings, self.checks = Clock(), {}, {}, []
        self.pki = PKI(self.directory / 'pki')
        self.authority_store, self.guard_store = Store(self.directory/'authority.sqlite'), Store(self.directory/'guard.sqlite')
        self.authority = AgentAuthority(self.authority_store, self.clock, self.pki, mode)
        for name, owner in (('UO', 'UO'), ('UR', 'UR'), ('O', 'UO'), ('R', 'UR'),
                             ('G', 'UO'), ('Authority', 'UO')):
            self.authority.bootstrap_identity(self.actor(name), owner)
        self.guard = InteractionGuard(self.guard_store, self.authority, self.clock, self.pki, mode)

    def actor(self, name):
        if name not in self.identities:
            self.identities[name] = Signer(name)
        return self.identities[name]

    def call(self, actor, operation, args, op_id=None):
        return self.authority.call(self.actor(actor), operation, args, op_id)

    def context(self, cid, req):
        tasks = {'chi1': ['T1'], 'chi2': ['T2'], 'chi12': ['T1', 'T2']}[cid]
        body = {'id': cid, 'tasks': tasks, 'cooperation': 'g1',
                'caller_approver': 'UO', 'service_approver': 'UR',
                'caller_root': 'O-'+cid, 'service_root': 'R-'+cid,
                'req': {op: req for op in ('query', 'summary')},
                'basis': {'J1': 'T1', 'J2': 'T2', 'P': 'project', 'B_g1': 'coop:g1'},
                'deadline': 1900.0, 'scheme': SCHEME}
        return self.call('UO', 'context', {'body': body,
            'approvals': {name: self.actor(name).sign(body) for name in ('UO', 'UR')}})

    def issue(self, source):
        allowed = {'J1': ['chi1', 'chi12'], 'J2': ['chi2', 'chi12'],
                   'P': ['chi2', 'chi12'], 'B_g1': ['chi1', 'chi2', 'chi12']}[source]
        issuer = 'UR' if source == 'B_g1' else 'UO'
        return self.call(issuer, 'source', {'id': source, 'issuer': issuer, 'controller': 'UO',
             'approval': 'source-approval/'+source, 'size': 8, 'contexts': allowed,
             'basis': {'J1': 'T1', 'J2': 'T2', 'P': 'project', 'B_g1': 'coop:g1'}[source],
             'actions': ['query', 'summary'], 'deadline': 2000.0})

    def right(self, rid, holder, cid, side='caller', parent=None, actions=None, register=True):
        child = self.actor(holder)
        parent_right = self.authority.right(parent) if parent else None
        actor = parent_right['owner'] if parent else ('UO' if side == 'caller' else 'UR')
        body = {'id': rid, 'owner': holder, 'context': cid, 'side': side, 'parent': parent,
                'actions': actions or ['query', 'summary'], 'public_key': child.public,
                'deadline': 1800.0, 'depth': parent_right['depth']-1 if parent else 8}
        result = self.call(actor, 'right', {**body, 'proof': child.sign(body)})['body']
        if parent and register and not self.authority_store.get('registrations', holder):
            self.register(rid)
        self.holdings.setdefault(rid, Holding(rid))
        return result

    def register(self, rid):
        right = self.authority.right(rid)
        parent = self.authority.right(right['parent'])
        child, actor = self.actor(right['owner']), parent['owner']
        challenge = self.call(actor, 'challenge', {'right': rid})
        csr = self.pki.csr(child)
        body = {'agent_id': child.name, 'right': rid, 'public_key': child.public,
                'contact_public_key': child.contact.public_key().public_bytes_raw().hex(),
                'challenge': challenge['id'], 'csr_ref': digest(csr)}
        result = self.call(actor, 'register', {'body': body, 'proof': child.sign(body), 'csr': csr})
        self.pki.materialize(child, result)
        return result

    def receive(self, rid, caps, parent=None):
        holding = self.holdings.setdefault(rid, Holding(rid))
        for cap in caps:
            holding.caps[cap['gid']] = cap
            if self.mode != 'signed-local':
                if cap['key_parent']['kind'] == 'cap':
                    bundle = parent.bundles[cap['key_parent']['id']].child(cap['gid'], cap['domain'])
                    expected = self.authority.forest.rebuild(cap['gid'])
                    self.check('actual parent Split->Grant matches independent reconstruction',
                               bundle.public_secrets() == expected.public_secrets())
                else:
                    bundle = self.authority.forest.rebuild(cap['gid'])
                holding.bundles[cap['gid']] = bundle
        return holding

    def seed(self, rid, sources):
        domains = {s: domain_for(['query', 'summary'], range(8)) for s in sources}
        result = self.call('UO', 'seed', {'right': rid, 'domains': domains})
        return self.receive(rid, result)

    def parent_map(self, domains):
        return {s: {str(i): self.authority_store.get('positions', position_key(s, i))['current_cap']['gid']
                    for i in by_slot(domain)} for s, domain in domains.items()}

    def seal(self, wallet, slots=None, actor='UO'):
        args = {'lane': wallet.lane['id']}
        if slots is not None:
            args['slots'] = slots
        command = self.call(actor, 'prepare_seal', args)
        return self.guard.engine.seal(command)

    def delegate(self, parent, child, domains, wallet=None, parents=None):
        args = {'parent': parent.right, 'child': child, 'domains': domains,
                'parents': parents or self.parent_map(domains)}
        if wallet:
            selected = {s: list(by_slot(d)) for s, d in domains.items()}
            args['receipt'] = self.seal(wallet, selected, self.authority.right(parent.right)['owner'])
        result = self.call(self.authority.right(parent.right)['owner'], 'delegate', args)
        return self.receive(child, result, parent=parent)

    def reserve(self, holding, service, slots, install=True):
        caller = self.authority.right(holding.right)
        receiver = self.authority.right(service)
        signed_act, key, contact = establish(self.authority, self.actor(caller['owner']),
                                             self.actor(receiver['owner']), holding.right, service)
        command = self.call(caller['owner'], 'reserve', {'caller': holding.right,
                            'service': service, 'slots': slots, 'act': signed_act['body']['id']})
        material = self.authority.verifier_delivery(command)
        if not install:
            return command, material, key
        return self.activate(holding, command, material, key)

    def activate(self, holding, command, material, key):
        self.guard.install(command, material)
        lane = command['body']['lane']
        link = self.pki.link(lane['caller']['owner'], 'G')
        session = self.guard.session(lane, self.actor(lane['caller']['owner']),
                                     self.actor(lane['service']['owner']), key, link)
        return Wallet(lane, holding, session, key, link)

    def consume(self, wallet, request_id, selection, operation='query', **kwargs):
        packet = wallet.packet(operation, request_id, selection, **kwargs)
        before = self.authority.calls['charge']
        result = self.guard.charge(packet, operation, wallet.link)
        self.check('charge authority location/'+request_id,
                   self.authority.calls['charge']-before == int(self.mode == 'online-authority'))
        return packet, result

    def state(self):
        kinds = ('positions', 'live', 'requests', 'effects', 'caps', 'anchors', 'fences')
        return digest([[db.all(k) for k in kinds] for db in (self.authority_store, self.guard_store)])

    def check(self, name, condition, detail=None):
        self.checks.append({'name': name, 'passed': bool(condition), 'detail': detail})
        if not condition:
            raise AssertionError(name+': '+str(detail))

    def denied(self, name, fn, codes=None):
        before = self.state()
        try:
            fn()
        except Denied as error:
            self.check(name, codes is None or error.code in codes, error.code)
            self.check(name+'/no ledger mutation', self.state() == before)
            return error.code
        raise AssertionError('Expected rejection: '+name)

    def finish(self, expected):
        from .verify import verify_run
        manifest = {'schema': 'saga-v3-core-0.1', 'mode': self.mode, 'scenario': self.scenario,
             'expected_spent': expected, 'checks': self.checks, 'authority_calls': dict(self.authority.calls),
             'source_files': source_manifest(), 'runtime': {'python': platform.python_version(),
             'platform': platform.platform(), 'sqlite': sqlite3.sqlite_version,
             'cryptography': version('cryptography'), 'openssl': ssl.OPENSSL_VERSION},
             'clock': 'controlled logical time', 'transport': 'real TLS1.3 via memory BIO, no HTTP/socket deployment',
             'authority_public': self.authority.signer.public, 'guard_control_public': self.guard.control.public}
        (self.directory/'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        with (self.directory/'events.jsonl').open('w', encoding='utf-8') as stream:
            for role, db in (('Authority', self.authority_store), ('Guard', self.guard_store)):
                for seq, kind, raw in db.db.execute('SELECT seq,kind,value FROM events ORDER BY seq'):
                    stream.write(json.dumps({'role': role, 'seq': seq, 'kind': kind, 'data': json.loads(raw)})+'\n')
        self.authority_store.close()
        self.guard_store.close()
        result = verify_run(self.directory)
        (self.directory/'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        return result


def bilateral_flow(lab):
    lab.context('chi1', ['J1', 'B_g1'])
    for source in ('J1', 'B_g1'):
        lab.issue(source)
    lab.right('O-chi1', 'O', 'chi1')
    lab.right('R-chi1', 'R', 'chi1', 'service')
    root = lab.seed('O-chi1', ['J1', 'B_g1'])
    old_root = copy.deepcopy(root)
    lab.right('A-chi1', 'A', 'chi1', parent='O-chi1')
    parent = lab.delegate(root, 'A-chi1', {s: domain_for(['query', 'summary'], range(8)) for s in ('J1', 'B_g1')})
    lab.right('R1-chi1', 'R1', 'chi1', 'service', 'R-chi1', ['query'])
    lab.right('R2-chi1', 'R2', 'chi1', 'service', 'R-chi1', ['summary'])
    wallet_a = lab.reserve(parent, 'R1-chi1', {s: list(range(8)) for s in ('J1', 'B_g1')})
    lab.consume(wallet_a, 'A-0', {'J1': 0, 'B_g1': 0})
    lab.check('query-only service does not permanently narrow caller other actions',
              lab.authority_store.get('positions', position_key('J1', 1))['hard_actions'] == ['query', 'summary'])
    lab.right('AP-chi1', 'AP', 'chi1', parent='A-chi1', actions=['query'])
    child = lab.delegate(parent, 'AP-chi1', {s: domain_for(['query'], [4, 5, 6, 7]) for s in ('J1', 'B_g1')}, wallet_a)
    wallet_ap = lab.reserve(child, 'R1-chi1', {s: [4, 5, 6, 7] for s in ('J1', 'B_g1')})
    if lab.mode != 'signed-local':
        for cap in child.caps.values():
            p = parent.bundles[cap['key_parent']['id']]
            c = child.bundles[cap['gid']]
            lab.check('new gid changes same-point secret', p.leaf(point('query', 4)) != c.leaf(point('query', 4)))
            lab.check('child retains geometric prefix 001', list(c.seeds) == ['001'])
    old_parent = wallet_a.packet('query', 'old-parent-4', {'J1': 4, 'B_g1': 4})
    lab.denied('parent cannot spend transferred positions', lambda: lab.guard.charge(old_parent, 'query', wallet_a.link))
    first, _ = lab.consume(wallet_ap, 'AP-4', {'J1': 4, 'B_g1': 4})
    lab.consume(wallet_ap, 'AP-5', {'J1': 5, 'B_g1': 5})
    revoke = lab.call('O', 'revoke', {'id': 'A-chi1'})
    lab.guard.engine.notice(revoke)
    pending_packet = wallet_ap.packet('query', 'revoked-6', {'J1': 6, 'B_g1': 6})
    lab.denied('caller ancestor revocation', lambda: lab.guard.charge(pending_packet, 'query', wallet_ap.link),
                {'KNOWN_REVOKED', 'REVOKED'})
    lab.check('old exact result remains readable', lab.guard.charge(first, 'query', wallet_ap.link)['replay'])
    for wallet in (wallet_a, wallet_ap):
        receipt = lab.seal(wallet)
        lab.call('UO', 'reclaim', {'receipt': receipt})
        lab.denied('duplicate receipt under new operation id', lambda r=receipt: lab.call('UO', 'reclaim', {'receipt': r}),
                   {'RECEIPT_ALREADY_USED'})
    lab.right('C-chi1', 'C', 'chi1', parent='O-chi1', actions=['query'])
    desired = {s: domain_for(['query'], [6, 7]) for s in ('J1', 'B_g1')}
    lab.denied('pending positions cannot be delegated', lambda: lab.delegate(root, 'C-chi1', desired,
                parents={s: {str(i): next(c['gid'] for c in root.caps.values() if c['source'] == s)
                             for i in (6, 7)} for s in desired}), {'POSITION_NOT_FREE'})
    masters = lab.authority_store.all('source_masters')
    caps = lab.call('UO', 'recover', {'right': 'O-chi1', 'slots': {s: [1, 2, 3, 6, 7] for s in desired}})
    recovered = lab.receive('O-chi1', caps)
    lab.check('recovery retains fixed source masters', masters == lab.authority_store.all('source_masters'))
    lab.check('mixed recovery scope has exact five-block canonical cover',
              all(c['cover'] == ['00001', '0001', '0011', '01001', '0101'] for c in caps))
    stale = {s: {str(i): next(c['gid'] for c in old_root.caps.values() if c['source'] == s)
                 for i in (6, 7)} for s in desired}
    lab.denied('R1 regression: same owner cannot pick historical wide parent',
               lambda: lab.delegate(recovered, 'C-chi1', desired, parents=stale), {'CURRENT_CAP_MISMATCH'})
    current_c = lab.delegate(recovered, 'C-chi1', desired)
    wallet_c = lab.reserve(current_c, 'R1-chi1', {s: [6, 7] for s in desired})
    if lab.mode != 'signed-local':
        forged_bundles = {}
        for cap in current_c.caps.values():
            stale_cap = next(c for c in old_root.caps.values() if c['source'] == cap['source'])
            forged_bundles[cap['source']] = old_root.bundles[stale_cap['gid']].child(cap['gid'], cap['domain'])
        forged = wallet_c.packet('query', 'old-root-forgery', {'J1': 6, 'B_g1': 6}, bundle_overrides=forged_bundles)
        lab.denied('all old root packages do not authenticate restored branch',
                   lambda: lab.guard.charge(forged, 'query', wallet_c.link), {'BAD_CAP_TAG'})
    lab.consume(wallet_c, 'C-6', {'J1': 6, 'B_g1': 6})
    service_stop = lab.call('R', 'revoke', {'id': 'R1-chi1'})
    lab.guard.engine.notice(service_stop)
    spare = wallet_c.packet('query', 'service-revoked-7', {'J1': 7, 'B_g1': 7})
    lab.denied('service-side ancestor also stops lane', lambda: lab.guard.charge(spare, 'query', wallet_c.link),
               {'KNOWN_REVOKED', 'REVOKED'})
    return {'C1': wallet_c, 'root': recovered}


def multitask_flow(lab, previous):
    lab.context('chi2', ['J2', 'P', 'B_g1'])
    lab.issue('J2')
    lab.issue('P')
    lab.right('O-chi2', 'O', 'chi2')
    lab.right('R-chi2', 'R', 'chi2', 'service')
    root2 = lab.seed('O-chi2', ['J2', 'P'])
    migration_domains = {'B_g1': domain_for(['query', 'summary'], [1, 2])}
    caps = lab.call('UO', 'migrate', {'right': 'O-chi2', 'slots': {'B_g1': [1, 2]},
                                     'parents': lab.parent_map(migration_domains)})
    root2 = lab.receive('O-chi2', caps)
    lab.right('C-chi2', 'C', 'chi2', parent='O-chi2', actions=['query'])
    lab.right('R1-chi2', 'R1', 'chi2', 'service', 'R-chi2', ['query'])
    domains = {'J2': domain_for(['query'], [0, 1]), 'P': domain_for(['query'], [0, 1]),
               'B_g1': domain_for(['query'], [1, 2])}
    c2 = lab.delegate(root2, 'C-chi2', domains)
    wallet = lab.reserve(c2, 'R1-chi2', {'J2': [0, 1], 'P': [0, 1], 'B_g1': [1, 2]})
    lab.check('C uses same registered identity across contexts',
              wallet.session['binding']['caller_key_version']
              == previous['C1'].session['binding']['caller_key_version'])
    partial = wallet.packet('query', 'missing-Bg', {'J2': 0, 'P': 0})
    lab.denied('missing source causes no partial commit', lambda: lab.guard.charge(partial, 'query', wallet.link),
               {'REQUIRED_SOURCE_SET'})
    lab.consume(wallet, 'C-task2', {'J2': 0, 'P': 0, 'B_g1': 1})
    lab.check('shared source never reissued', len(lab.authority_store.all('sources')) == 4)
    return wallet


def demo(directory, mode, scenario):
    lab = Lab(directory, mode, scenario)
    previous = bilateral_flow(lab)
    expected = {'J1': 4, 'B_g1': 4}
    if scenario == 'multitask':
        multitask_flow(lab, previous)
        expected = {'J1': 4, 'J2': 1, 'P': 1, 'B_g1': 5}
    return lab.finish(expected)
