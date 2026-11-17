"""Focused v3 conformance/negative controls; not a security proof."""
import copy
import hashlib
import json
import secrets
import threading
from datetime import timedelta
from .crypto import (ACTIONS, WIDTH, Bundle, Denied, E, H, anchor_secret, canonical,
                     channel_mac, cover, decode, domain_for, encode, ident, point, split)
from .pki import PKI, utc_now
from .scenarios import Lab, bilateral_flow, multitask_flow, demo
from .storage import position_key


def crypto_tests():
    checks = 0

    def check(value):
        nonlocal checks
        checks += 1
        if not value:
            raise AssertionError('RDF cryptographic/encoding conformance')

    def reject(fn):
        try:
            fn()
        except Denied:
            check(True)
        else:
            check(False)

    def independent_e(*parts):
        return b'B0-v3' + b''.join(len(p).to_bytes(4, 'big')+p for p in parts)

    def independent_h(kind, key, payload=b''):
        return hashlib.sha256(independent_e(kind.encode(), key, payload)).digest()

    check(hashlib.sha256(b'abc').hexdigest() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    check(E(b'ab', b'c') != E(b'a', b'bc') and E(b'a', b'') != E(b'a'))
    root, aid = bytes(range(32)), bytes(range(32)).hex()
    binding = independent_e(b'J1', b'chi1', b'G', b'B0-v3', b'fixed-op-first-v1', b'\x00\x03')
    check(anchor_secret(root, aid, 'J1', 'chi1')
          == independent_h('anchor', root, independent_e(bytes.fromhex(aid), binding)))
    check(independent_h('anchor', root, independent_e(bytes.fromhex(aid), binding))
          != hashlib.sha256(independent_e(b'anchor', root, bytes.fromhex(aid), binding)).digest())
    for bad in (b'0', b'1', b'\x02'):
        reject(lambda bad=bad: H('split', root, bad))
    reject(lambda: H('grant', root, b'x'*31))
    reject(lambda: H('spend', b'x'*33))
    reject(lambda: cover([]))
    gid1, gid2 = ident(), ident()
    parent = Bundle.initial(gid1, aid, root, domain_for(['query', 'summary'], range(8)))
    child = parent.child(gid2, domain_for(['query'], [4, 5, 6, 7]))
    check(list(parent.seeds) == ['0'] and list(child.seeds) == ['001'])
    check(parent.leaf(point('query', 6)) != child.leaf(point('query', 6)))
    expected = independent_h('grant', independent_h('split', independent_h('split', parent.seeds['0'], b'\x00'), b'\x01'), bytes.fromhex(gid2))
    check(child.seeds['001'] == expected)
    check(child.seeds['001'] != split(H('grant', parent.seeds['0'], bytes.fromhex(gid2)), '01'))
    reject(lambda: child.leaf(point('summary', 6)))
    reject(lambda: child.leaf(point('query', 2)))
    reject(lambda: child.child(ident(), domain_for(['summary'], [4])))
    fragmented = Bundle(gid1, aid, tuple(parent.domain),
                        {f'{p:0{WIDTH}b}': parent.leaf(p) for p in parent.domain})
    reject(lambda: fragmented.child(ident(), domain_for(['query'], [4, 5, 6, 7])))
    pairs, evaluations = 0, 0
    # Exhaust all nonempty nested sets of eight actual query positions.
    for mask in range(1, 256):
        domain = [i for i in range(8) if mask >> i & 1]
        p = Bundle.initial(ident(), aid, root, domain)
        child_mask = mask
        while child_mask:
            wanted = [i for i in range(8) if child_mask >> i & 1]
            c = p.child(ident(), wanted)
            check(list(c.seeds) == list(cover(wanted)))
            for target in wanted:
                q = next(prefix for prefix in c.seeds if f'{target:0{WIDTH}b}'.startswith(prefix))
                ancestor = next(prefix for prefix in p.seeds if q.startswith(prefix))
                key = p.seeds[ancestor]
                for bit in q[len(ancestor):]:
                    key = independent_h('split', key, bytes([int(bit)]))
                key = independent_h('grant', key, bytes.fromhex(c.gid))
                for bit in f'{target:0{WIDTH}b}'[len(q):]:
                    key = independent_h('split', key, bytes([int(bit)]))
                check(key == c.leaf(target))
                evaluations += 1
            pairs += 1
            child_mask = (child_mask-1) & mask
    return {'passed': True, 'checks': checks, 'nested_domains': pairs, 'leaf_evaluations': evaluations}


def basic(lab, deferred=False):
    lab.context('chi1', ['J1', 'B_g1'])
    for source in ('J1', 'B_g1'):
        lab.issue(source)
    lab.right('O-chi1', 'O', 'chi1')
    lab.right('R-chi1', 'R', 'chi1', 'service')
    root = lab.seed('O-chi1', ['J1', 'B_g1'])
    lab.right('A-chi1', 'A', 'chi1', parent='O-chi1')
    lab.right('R1-chi1', 'R1', 'chi1', 'service', 'R-chi1', ['query'])
    holding = lab.delegate(root, 'A-chi1', {s: domain_for(['query', 'summary'], range(8)) for s in ('J1', 'B_g1')})
    if deferred:
        return holding, lab.reserve(holding, 'R1-chi1', {s: [0, 1] for s in ('J1', 'B_g1')}, install=False)
    return holding, lab.reserve(holding, 'R1-chi1', {s: list(range(8)) for s in ('J1', 'B_g1')})


def protocol_tests(directory, mode):
    lab = Lab(directory, mode, 'protocol-identity')
    holding, wallet = basic(lab)
    reg = lab.authority.registration('A')
    lab.denied('valid other certificate cannot masquerade as A',
               lambda: lab.pki.link('A', 'G', present_as='R'), {'CERTIFICATE_IDENTITY'})
    lab.denied('expired certificate', lambda: lab.pki.validate(reg['certificate'], reg, utc_now()+timedelta(days=2)),
               {'CERTIFICATE_TIME'})
    lab.denied('not-yet-valid certificate', lambda: lab.pki.validate(reg['certificate'], reg, utc_now()-timedelta(days=2)),
               {'CERTIFICATE_TIME'})
    wrong_pki = PKI(lab.directory/'untrusted-ca')
    lab.denied('certificate from another CA', lambda: wrong_pki.validate(reg['certificate'], reg), {'CERTIFICATE_SIGNATURE'})
    lab.denied('source cannot be reissued using a new operation id',
               lambda: lab.call('UO', 'source', lab.authority_store.get('sources', 'J1')), {'SOURCE_ALREADY_ISSUED'})
    packet = wallet.packet('query', 'bad-payload', {'J1': 1, 'B_g1': 1})
    packet['payload'] = {'text': 'changed without matching complete M'}
    lab.denied('entire payload is bound', lambda: lab.guard.charge(packet, 'query', wallet.link), {'FULL_PAYLOAD_BINDING'})
    missing = wallet.packet('query', 'missing-source', {'J1': 1})
    lab.denied('source omission has no partial debit', lambda: lab.guard.charge(missing, 'query', wallet.link), {'REQUIRED_SOURCE_SET'})
    if mode != 'signed-local':
        original = wallet.packet('query', 'message-before', {'J1': 1, 'B_g1': 1})
        altered = wallet.packet('query', 'message-after', {'J1': 1, 'B_g1': 1})
        altered['proofs'] = original['proofs']
        lab.denied('all source tags bind same complete message',
                   lambda: lab.guard.charge(altered, 'query', wallet.link), {'BAD_CAP_TAG'})
        gid = wallet.lane['rows'][0]['current_cap']['gid']
        db = lab.guard.authority_store
        material = db.get('verifiers', gid)
        with db.transaction():
            db.db.execute('DELETE FROM records WHERE kind=? AND key=?', ('verifiers', gid))
        valid = wallet.packet('query', 'missing-verifier', {'J1': 1, 'B_g1': 1})
        lab.denied('missing verifier does not trigger public-history/client-seed fallback',
                   lambda: lab.guard.charge(valid, 'query', wallet.link), {'VERIFIER_CACHE_MISSING'})
        with db.transaction():
            db.put('verifiers', gid, material)
    # TLS links are separate; competing requests share the same logical session.
    links = [lab.pki.link('A', 'G') for _ in range(2)]
    packets = [wallet.packet('query', 'race-'+str(i), {'J1': 0, 'B_g1': 0}) for i in range(2)]
    barrier, outcomes = threading.Barrier(2), []

    def worker(index):
        barrier.wait()
        try:
            outcomes.append(('accepted', lab.guard.charge(packets[index], 'query', links[index])))
        except Denied as e:
            outcomes.append(('denied', e.code))
        except Exception as e:
            outcomes.append(('unexpected', repr(e)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lab.check('concurrent vectors cannot double spend', sorted(x[0] for x in outcomes) == ['accepted', 'denied'], outcomes)
    for store in (lab.authority_store, lab.guard_store):
        store.close()
        store.open()
    winner_fp = next(r['fingerprint'] for r in lab.guard.authority_store.all('requests').values())
    winner = next(p for p in packets if hashlib.sha256(bytes.fromhex(p['body'])).hexdigest() == winner_fp)
    lab.check('durable old result after reopening DB', lab.guard.charge(winner, 'query', wallet.link)['replay'])
    act = wallet.lane['act']['body']
    init = lab.authority_store.get('redeemed', act['permit'])
    lab.denied('one-time contact material cannot be redeemed twice', lambda: lab.call('R1', 'redeem',
        {'permit': act['permit'], 'init': init, 'proof': lab.actor('A').sign(init)}), {'OTK_ALREADY_REDEEMED'})
    result = lab.call('O', 'revoke', {'id': 'A-chi1'}, 'same-revoke')
    lab.check('control retry reuses durable result', lab.call('O', 'revoke', {'id': 'A-chi1'}, 'same-revoke') == result)
    lab.denied('same op id cannot change parameters',
               lambda: lab.call('O', 'revoke', {'id': 'O-chi1'}, 'same-revoke'), {'OP_ID_CONFLICT'})
    late_act = {**wallet.lane['act']['body'], 'id': ident()}
    lab.denied('late ACT cannot republish contact after ancestor revocation',
               lambda: lab.call('R1', 'act', lab.actor('R1').envelope(late_act)), {'REVOKED'})
    return lab.finish({'J1': 1, 'B_g1': 1})


def window_tests(directory, mode):
    lab = Lab(directory, mode, 'lease-window')
    _, wallet = basic(lab)
    lab.call('O', 'revoke', {'id': 'A-chi1'})
    lab.denied('revoked Right cannot renew', lambda: lab.call('A', 'renew', {'lane': wallet.lane['id']}), {'REVOKED'})
    if mode == 'online-authority':
        p = wallet.packet('query', 'within-window', {'J1': 0, 'B_g1': 0})
        lab.denied('online sees committed revoke immediately', lambda: lab.guard.charge(p, 'query', wallet.link), {'REVOKED'})
        spent = 0
    else:
        lab.clock.advance(1)
        lab.consume(wallet, 'within-window', {'J1': 0, 'B_g1': 0})
        spent = 1
    lab.clock.advance(5)
    p = wallet.packet('query', 'after-window', {'J1': 1, 'B_g1': 1})
    lab.denied('absolute lease limits lost-notification consumption', lambda: lab.guard.charge(p, 'query', wallet.link),
               {'LEASE_OR_HARD_EXPIRED', 'REVOKED'})
    return lab.finish({'J1': spent, 'B_g1': spent})


def cancellation_tests(directory, mode, activate_first=False):
    lab = Lab(directory, mode, 'cancel-activated' if activate_first else 'cancel-unactivated')
    holding, deferred = basic(lab, deferred=True)
    command, material, key = deferred
    lane = command['body']['lane']
    lab.call('UO', 'cancel', {'lane': lane['id']})
    lab.check('local cancellation does not refund possible in-flight install', all(
        lab.authority_store.get('positions', position_key(s, i))['state'] == 'held'
        for s in ('J1', 'B_g1') for i in (0, 1)))
    if activate_first:
        wallet = lab.activate(holding, command, material, key)
        lab.consume(wallet, 'installation-won-race', {'J1': 0, 'B_g1': 0})
    seal_cmd = lab.call('UO', 'prepare_seal', {'lane': lane['id']})
    receipt = lab.guard.engine.seal(seal_cmd)
    lab.call('UO', 'reclaim', {'receipt': receipt})
    lab.check('cancellation becomes terminal only after exact settlement',
              lab.authority_store.get('cancellations', lane['id'])['state'] == 'cancelled_settled')
    if not activate_first:
        lab.denied('late unactivated install is fenced', lambda: lab.guard.install(command, material), {'INSTALL_FENCED'})
    else:
        before = lab.state()
        lab.guard.install(command, material)
        lab.check('old installation ACK replay does not reactivate closed rows', lab.state() == before)
    remaining = [1] if activate_first else [0, 1]
    result = lab.call('UO', 'recover', {'right': 'O-chi1', 'slots': {s: remaining for s in ('J1', 'B_g1')}})
    lab.receive('O-chi1', result)
    return lab.finish({'J1': int(activate_first), 'B_g1': int(activate_first)})


def joint_task_tests(directory, mode):
    lab = Lab(directory, mode, 'joint-context')
    previous = bilateral_flow(lab)
    c2 = multitask_flow(lab, previous)
    lab.context('chi12', ['J1', 'B_g1', 'J2', 'P', 'B_g1'])
    lab.right('O-chi12', 'O', 'chi12')
    lab.right('R-chi12', 'R', 'chi12', 'service')
    wanted = {'J1': [1], 'J2': [2], 'P': [2], 'B_g1': [3]}
    domains = {s: domain_for(['query', 'summary'], slots) for s, slots in wanted.items()}
    caps = lab.call('UO', 'migrate', {'right': 'O-chi12', 'slots': wanted, 'parents': lab.parent_map(domains)})
    root = lab.receive('O-chi12', caps)
    lab.right('C-chi12', 'C', 'chi12', parent='O-chi12', actions=['query'])
    lab.right('R1-chi12', 'R1', 'chi12', 'service', 'R-chi12', ['query'])
    child = lab.delegate(root, 'C-chi12', {s: domain_for(['query'], slots) for s, slots in wanted.items()})
    wallet = lab.reserve(child, 'R1-chi12', wanted)
    packet, result = lab.consume(wallet, 'joint-context-query', {s: slots[0] for s, slots in wanted.items()})
    lab.check('joint context deduplicates Bg exactly once',
              len(result['sources']) == 4 and [s for s, _ in result['sources']].count('B_g1') == 1)
    stopped = lab.call('UO', 'revoke', {'kind': 'task', 'id': 'T1'})
    lab.guard.engine.notice(stopped)
    retry_new = wallet.packet('query', 'new-after-task-stop', {s: slots[0] for s, slots in wanted.items()})
    lab.denied('T1 termination stops chi12 through approval dependency',
               lambda: lab.guard.charge(retry_new, 'query', wallet.link), {'REVOKED', 'KNOWN_REVOKED'})
    lab.consume(c2, 'T2-remains-valid', {'J2': 1, 'P': 1, 'B_g1': 2})
    return lab.finish({'J1': 5, 'J2': 3, 'P': 3, 'B_g1': 7})


def registration_tests(directory, mode):
    lab = Lab(directory, mode, 'dynamic-registration')
    holding, wallet = basic(lab)
    lab.right('Z-chi1', 'Z', 'chi1', parent='A-chi1', actions=['query'], register=False)
    lab.denied('logical child not yet registered cannot open TLS', lambda: lab.pki.link('Z', 'G'),
               {'TLS_IDENTITY_UNPUBLISHED'})
    challenge = lab.call('A', 'challenge', {'right': 'Z-chi1'})
    child = lab.actor('Z')
    csr = lab.pki.csr(child)
    from .crypto import digest
    body = {'agent_id': 'Z', 'right': 'Z-chi1', 'public_key': child.public,
            'contact_public_key': child.contact.public_key().public_bytes_raw().hex(),
            'challenge': challenge['id'], 'csr_ref': digest(csr)}
    wrong_proof = {'body': body, 'proof': lab.actor('A').sign(body), 'csr': csr}
    lab.denied('parent cannot replace child possession proof', lambda: lab.call('A', 'register', wrong_proof), {'BAD_SIGNATURE'})
    wrong_csr = lab.pki.csr(lab.actor('CsrOther'))
    changed_body = {**body, 'csr_ref': digest(wrong_csr)}
    lab.denied('CSR cannot substitute another identity key', lambda: lab.call('A', 'register',
        {'body': changed_body, 'proof': child.sign(changed_body), 'csr': wrong_csr}), {'CSR_KEY_MISMATCH'})
    args = {'body': body, 'proof': child.sign(body), 'csr': csr}
    reg = lab.call('A', 'register', args, 'register-Z')
    lab.pki.materialize(child, reg)
    lab.check('registration retry does not reissue certificate', lab.call('A', 'register', args, 'register-Z') == reg)
    lab.denied('consumed registration challenge cannot be replayed under new op id',
               lambda: lab.call('A', 'register', args), {'REGISTRATION_CHALLENGE'})
    lab.check('published child certificate supports actual mutual TLS', lab.pki.link('Z', 'G').info['version'] == 'TLSv1.3')
    lab.denied('new root cannot silently change old context root binding',
               lambda: lab.right('changed-root', 'ChangedRoot', 'chi1'), {'ROOT_SNAPSHOT'})
    reg_a = copy.deepcopy(lab.authority.registration('A'))
    reg_a['public_key'] = child.public
    lab.denied('certificate public key must match registration',
               lambda: lab.pki.validate(lab.authority.registration('A')['certificate'], reg_a), {'CERTIFICATE_KEY'})
    return lab.finish({'J1': 0, 'B_g1': 0})


def self_test(directory):
    from .regressions import source_revocation, cancelled_renewal, recovery_reselection
    crypto = crypto_tests()
    print('PASS RDF crypto:', crypto, flush=True)
    results = []
    for mode in ('joint', 'signed-local', 'online-authority'):
        for scenario in ('bilateral', 'multitask'):
            r = demo(directory/'demos'/mode/scenario, mode, scenario)
            results.append(r)
            print('PASS', mode, scenario, flush=True)
        for label, fn in (('protocol', protocol_tests), ('window', window_tests),
                          ('cancel-unactivated', cancellation_tests),
                          ('cancel-activated', lambda p, m: cancellation_tests(p, m, True)),
                          ('joint-context', joint_task_tests), ('registration', registration_tests),
                          ('source-revocation', source_revocation),
                          ('cancelled-renewal', cancelled_renewal),
                          ('recovery-reselection', recovery_reselection)):
            r = fn(directory/'tests'/mode/label, mode)
            results.append(r)
            print('PASS', mode, label, flush=True)
    return {'status': 'PASS', 'crypto': crypto, 'runs': len(results), 'results': results}
