"""Regression scenarios for source revocation, cancellation and recovery policy."""
import copy
from .crypto import domain_for, point
from .scenarios import Lab
from .storage import position_key


def source_revocation(directory, mode):
    from .tests import basic
    lab = Lab(directory, mode, 'source-revocation')
    holding, deferred = basic(lab, deferred=True)
    command, material, key = deferred
    wallet = lab.activate(holding, command, material, key)
    lab.consume(wallet, 'before-source-revoke', {'J1': 0, 'B_g1': 0})
    lab.right('AP-chi1', 'AP', 'chi1', parent='A-chi1', actions=['query'])
    lab.context('chi12', ['J1', 'B_g1'])
    lab.right('O-chi12', 'O', 'chi12')
    lab.call('UO', 'revoke', {'kind': 'source', 'id': 'J1'})
    # No Guard notice: a fresh Authority grant must not restart the old window.
    lab.clock.advance(6)
    act = command['body']['lane']['act']['body']['id']
    lab.denied('revoked source cannot acquire a fresh install beyond original window',
               lambda: lab.call('A', 'reserve', {'caller': holding.right, 'service': 'R1-chi1',
                    'slots': {'J1': [2], 'B_g1': [2]}, 'act': act}), {'REVOKED'})
    lab.denied('revoked source cannot renew',
               lambda: lab.call('A', 'renew', {'lane': wallet.lane['id']}), {'REVOKED'})
    lab.denied('revoked source cannot release fresh verifier material',
               lambda: lab.authority.verifier_delivery(command), {'REVOKED'})
    requested = {'J1': domain_for(['query'], [2])}
    lab.denied('revoked source cannot delegate free capacity', lambda: lab.call('A', 'delegate', {
        'parent': holding.right, 'child': 'AP-chi1', 'domains': requested,
        'parents': lab.parent_map(requested)}), {'REVOKED'})
    lab.denied('revoked source cannot migrate free capacity', lambda: lab.call('UO', 'migrate', {
        'right': 'O-chi12', 'slots': {'J1': [2]}, 'parents': lab.parent_map(requested)}), {'REVOKED'})
    old_packet = wallet.packet('query', 'old-lease-expired', {'J1': 1, 'B_g1': 1})
    lab.denied('old lane remains bounded without notification',
               lambda: lab.guard.charge(old_packet, 'query', wallet.link),
               {'LEASE_OR_HARD_EXPIRED', 'REVOKED'})
    # Settlement remains available after revocation; reissue does not.
    receipt = lab.seal(wallet)
    lab.call('UO', 'reclaim', {'receipt': receipt})
    lab.denied('revoked source cannot recover even accurately unused positions',
               lambda: lab.call('UO', 'recover', {'right': 'O-chi1', 'slots': {'J1': [1]}}), {'REVOKED'})
    # An unseeded revoked source cannot get its first capability either.
    lab.context('chi2', ['B_g1'])
    lab.right('O-chi2', 'O', 'chi2')
    lab.right('R-chi2', 'R', 'chi2', 'service')
    lab.issue('J2')
    lab.call('UO', 'revoke', {'kind': 'source', 'id': 'J2'})
    lab.denied('revoked source cannot seed a first capability', lambda: lab.call('UO', 'seed', {
        'right': 'O-chi2', 'domains': {'J2': domain_for(['query'], [0])}}), {'REVOKED'})
    # Independent source/context still progresses with the same identities.
    domains = {'B_g1': domain_for(['query', 'summary'], [2])}
    caps = lab.call('UO', 'migrate', {'right': 'O-chi2', 'slots': {'B_g1': [2]},
                                   'parents': lab.parent_map(domains)})
    independent = lab.receive('O-chi2', caps)
    other = lab.reserve(independent, 'R-chi2', {'B_g1': [2]})
    lab.consume(other, 'unrelated-source-still-works', {'B_g1': 2})
    return lab.finish({'J1': 1, 'B_g1': 2, 'J2': 0})


def cancelled_renewal(directory, mode):
    from .tests import basic
    lab = Lab(directory, mode, 'cancelled-renewal')
    holding, deferred = basic(lab, deferred=True)
    command, material, key = deferred
    lane = command['body']['lane']
    lab.clock.advance(1)
    renewal_args = {'lane': lane['id']}
    prior = lab.call('A', 'renew', renewal_args, 'renew-before-cancel')
    lab.call('UO', 'cancel', renewal_args)
    lab.clock.advance(1)
    lab.denied('cancel_pending prevents a new renewal',
               lambda: lab.call('A', 'renew', renewal_args), {'LANE_CANCELLED'})
    lab.denied('cancel_pending prevents a new verifier-material release',
               lambda: lab.authority.verifier_delivery(command), {'LANE_CANCELLED'})
    again = lab.call('A', 'renew', renewal_args, 'renew-before-cancel')
    lab.check('old renewal retry returns unchanged absolute deadline', again == prior)
    # Already issued material can be in flight; cancellation is not remote Seal.
    wallet = lab.activate(holding, command, material, key)
    lab.guard.engine.renew(prior)
    lab.check('previously committed renewal does not restart its deadline',
              lab.guard.authority_store.get('installed_lanes', lane['id'])['lease']
              == prior['body']['lease'])
    lab.consume(wallet, 'in-flight-install-before-seal', {'J1': 0, 'B_g1': 0})
    receipt = lab.seal(wallet)
    returned = lab.call('UO', 'reclaim', {'receipt': receipt})
    lab.check('cancellation settles only exact unused positions',
              {(r['source'], r['slot']) for r in returned} == {('J1', 1), ('B_g1', 1)})
    lab.check('cancellation is terminal after accurate settlement',
              lab.authority_store.get('cancellations', lane['id'])['state'] == 'cancelled_settled')
    lab.denied('settled cancellation also prevents new renewal',
               lambda: lab.call('A', 'renew', renewal_args), {'LANE_CANCELLED'})
    lab.denied('settled cancellation also prevents verifier release',
               lambda: lab.authority.verifier_delivery(command), {'LANE_CANCELLED'})
    old = wallet.packet('query', 'late-after-settlement', {'J1': 1, 'B_g1': 1})
    lab.denied('old renewal cannot revive sealed positions',
               lambda: lab.guard.charge(old, 'query', wallet.link), {'POSITION_SPENT_OR_FENCED'})
    independent = lab.reserve(holding, 'R1-chi1', {'J1': [2], 'B_g1': [2]})
    lab.consume(independent, 'other-lane-remains-valid', {'J1': 2, 'B_g1': 2})
    return lab.finish({'J1': 2, 'B_g1': 2})


def recovery_reselection(directory, mode):
    from .tests import basic
    lab = Lab(directory, mode, 'recovery-reselection')
    parent, wallet = basic(lab)
    old_root = copy.deepcopy(lab.holdings['O-chi1'])
    lab.right('AP-chi1', 'AP', 'chi1', parent='A-chi1', actions=['query'])
    domains = {s: domain_for(['query'], [0, 1, 2]) for s in ('J1', 'B_g1')}
    child = lab.delegate(parent, 'AP-chi1', domains, wallet)
    child_wallet = lab.reserve(child, 'R1-chi1', {s: [0, 1, 2] for s in domains})
    lab.consume(child_wallet, 'child-spent-0', {'J1': 0, 'B_g1': 0})
    lab.call('A', 'revoke', {'id': 'AP-chi1'})
    returned = lab.call('UO', 'reclaim', {'receipt': lab.seal(child_wallet)})
    lab.check('initial pending receiver is nearest valid A', all(r['receiver'] == 'A-chi1' for r in returned))
    slots = {s: [1, 2] for s in domains}
    args = {'right': 'O-chi1', 'slots': slots}
    lab.denied('cannot skip a still-valid nearest ancestor',
               lambda: lab.call('UO', 'recover', args), {'RECOVERY_RECEIVER'})
    lab.right('C-chi1', 'C', 'chi1', parent='O-chi1', actions=['query'])
    lab.call('O', 'revoke', {'id': 'A-chi1'})
    lab.denied('invalid old receiver cannot recover', lambda: lab.call('UO', 'recover', {
        'right': 'A-chi1', 'slots': slots}), {'REVOKED'})
    lab.denied('unrelated Right cannot receive recovered units', lambda: lab.call('UO', 'recover', {
        'right': 'C-chi1', 'slots': slots}), {'RECOVERY_RECEIVER'})
    lab.denied('reselection still requires independent owner approval',
               lambda: lab.call('O', 'recover', args), {'INDEPENDENT_OWNER_APPROVAL_REQUIRED'})
    caps = lab.call('UO', 'recover', args, 'recover-to-current-ancestor')
    lab.check('recovery retry does not mint another anchor',
              lab.call('UO', 'recover', args, 'recover-to-current-ancestor') == caps)
    lab.check('all restored capabilities use fresh anchors',
              all(c['anchor'] not in {old['anchor'] for old in old_root.caps.values()} for c in caps))
    for source in slots:
        row = lab.authority_store.get('positions', position_key(source, 1))
        original = next(r for r in returned if r['source'] == source and r['slot'] == 1)
        lab.check('reselection retains hard labels and original recovery path',
                  row['receiver'] == row['holder_right'] == 'O-chi1'
                  and row['hard_actions'] == original['hard_actions'] == ['query']
                  and row['hard_contexts'] == original['hard_contexts']
                  and row['deadline'] <= original['deadline']
                  and row['old_cap']['holder_right'] == 'AP-chi1')
    root = lab.receive('O-chi1', caps)
    current = lab.delegate(root, 'C-chi1', {s: domain_for(['query'], [1, 2]) for s in slots})
    new_wallet = lab.reserve(current, 'R1-chi1', slots)
    if mode != 'signed-local':
        stale = {}
        for cap in current.caps.values():
            old = next(c for c in old_root.caps.values() if c['source'] == cap['source'])
            stale[cap['source']] = old_root.bundles[old['gid']].child(cap['gid'], cap['domain'])
        packet = new_wallet.packet('query', 'old-secret-after-reselection', {'J1': 1, 'B_g1': 1},
                                   bundle_overrides=stale)
        lab.denied('old packages cannot authenticate after reselection and delegation',
                   lambda: lab.guard.charge(packet, 'query', new_wallet.link), {'BAD_CAP_TAG'})
    lab.consume(new_wallet, 'new-branch-actually-spends', {'J1': 1, 'B_g1': 1})
    lab.denied('fresh operation id cannot reissue the same restored units',
               lambda: lab.call('UO', 'recover', args), {'NOT_PENDING_RECOVERY'})
    return lab.finish({'J1': 2, 'B_g1': 2})
