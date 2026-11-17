"""Read-only artifact oracle; does not call Authority, Guard or Forest.rebuild."""
import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from . import source_manifest
from .crypto import ACTIONS, canonical, cover, decode, digest, point


def read_database(path):
    uri = Path(path).resolve().as_uri() + '?mode=ro'
    db = sqlite3.connect(uri, uri=True)
    records = {}
    for kind, key, value in db.execute('SELECT kind,key,value FROM records'):
        records.setdefault(kind, {})[key] = json.loads(value)
    events = [(s, k, json.loads(v)) for s, k, v in db.execute('SELECT seq,kind,value FROM events ORDER BY seq')]
    db.close()
    return records, events


def verify_run(directory):
    directory = Path(directory)
    manifest = json.loads((directory/'manifest.json').read_text())
    a, ae = read_database(directory/'authority.sqlite')
    g, ge = read_database(directory/'guard.sqlite')
    online = manifest['mode'] == 'online-authority'
    authority, authority_events = (a, ae) if online else (g, ge)
    checks, errors = 0, []

    def check(condition, label):
        nonlocal checks
        checks += 1
        if not condition:
            errors.append(label)

    def ancestors(rid):
        result, seen = [], set()
        while rid:
            check(rid not in seen and rid in a['rights'], 'invalid Right ancestry')
            if rid in seen or rid not in a['rights']:
                break
            seen.add(rid)
            result.append(rid)
            rid = a['rights'][rid]['parent']
        return result

    check(all(c['passed'] for c in manifest['checks']), 'scenario assertion failed')
    check(not g.get('source_masters') and not g.get('anchors'), 'Guard received a source master/anchor record')
    for gid, cap in a.get('caps', {}).items():
        check(gid == cap['gid'] and cap['cover'] == list(cover(cap['domain'])), 'invalid canonical Cap')
        check(cap['anchor'] in a['anchors'], 'missing anchor')
        parent = cap['key_parent']
        if parent['kind'] == 'cap':
            old = a['caps'][parent['id']]
            check(old['source'] == cap['source'] and old['anchor'] == cap['anchor']
                  and old['context'] == cap['context'] and set(cap['domain']) <= set(old['domain']),
                  'invalid key-parent relation')
            check(a['rights'][cap['holder_right']]['parent'] == old['holder_right'],
                  'logical parent and normal key parent disagree')
            for snapshot in cap['hard_snapshot']:
                check(snapshot['current_cap']['gid'] == old['gid']
                      and snapshot['current_cap']['anchor'] == old['anchor']
                      and snapshot['holder_right'] == old['holder_right'],
                      'R1: delegation used a historical/noncurrent parent')
        else:
            check(parent == {'kind': 'anchor', 'id': cap['anchor']}, 'anchor key-parent mismatch')
    requests = authority.get('requests', {})
    effects = g.get('effects', {})
    charge_seq = {v['key']: seq for seq, kind, v in authority_events if kind == 'charge'}
    revokes = [(seq, v) for seq, kind, v in ae if kind == 'revoke']
    consumed = set()
    for key, record in requests.items():
        decision = record['decision']
        fields, vector = decode(bytes.fromhex(record['body']))
        lane = a['lanes'][decision['lane']]
        ctx, operation = lane['context'], decision['operation']
        check([s for s, *_ in vector] == sorted(set(ctx['req'][operation])), 'wrong required sources')
        check([[s, i] for s, i, *_ in vector] == decision['sources'], 'authenticated/debited positions differ')
        check(record['fingerprint'] == hashlib.sha256(bytes.fromhex(record['body'])).hexdigest(), 'wrong fingerprint')
        check(operation in lane['actions'] and fields['full_payload'] == canonical(effects[key]['payload']),
              'actual operation/payload mismatch')
        deps = set(ctx['deps']) | {'right:'+rid for rid in ancestors(lane['caller']['id'])}
        deps |= {'right:'+rid for rid in ancestors(lane['service']['id'])}
        deps |= {'source:'+s for s in {r['source'] for r in lane['rows']}}
        check(set(decision['deps']) == deps, 'incomplete bilateral dependency set')
        check(decision['commit_time']+0.001 < min(decision['lease'], lane['deadline']), 'admission after deadline')
        rows = {(r['source'], r['slot']): r for r in lane['rows']}
        for source, slot, anchor, gid, install in vector:
            u = (source, slot)
            check(u not in consumed, 'duplicate canonical spend '+str(u))
            consumed.add(u)
            row, cap = rows[u], a['caps'][gid]
            check(row['current_cap'] == {'anchor': anchor, 'gid': gid,
                                         'holder_right': lane['caller']['id']}
                  and row['install'] == install and point(operation, slot) in cap['domain'],
                  'wrong current Cap/installation/domain')
            check(operation in row['hard_actions'], 'hard action widened')
        for seq, revoke in revokes:
            if revoke['dep'] in deps:
                check(seq > charge_seq[key] if online else decision['commit_time'] < revoke['time']+5,
                      'new admission beyond revocation profile')
    check(set(effects) == set(requests), 'unique local effects differ from admissions')
    balances = {}
    for source, spec in a.get('sources', {}).items():
        rows = [r for r in a['positions'].values() if r['source'] == source]
        check(len(rows) == spec['size'] and {r['slot'] for r in rows} == set(range(spec['size'])),
              'source issuance/position mismatch')
        counts = Counter()
        for row in rows:
            state = row['state']
            if state == 'held':
                live = authority.get('live', {}).get(canonical([source, row['slot']]).decode())
                check(live and live['install'] == row['install'] and live['current_cap'] == row['current_cap'],
                      'held capacity lacks corresponding Guard record')
                state = 'spent' if live and live['state'] in ('spent', 'closed-spent') else 'held-unused'
            check(state in ('unbound', 'free', 'free_pending_reissue', 'held-unused', 'spent', 'escrow', 'retired'),
                  'unknown position state')
            check((state == 'spent') == ((source, row['slot']) in consumed), 'spent/control history mismatch')
            if state == 'free':
                cap = a['caps'][row['current_cap']['gid']]
                check(cap['holder_right'] == row['holder_right'] and cap['context'] == row['context'], 'free Cap binding')
            if state == 'free_pending_reissue':
                check(row['current_cap'] is None, 'pending row has usable current Cap')
            counts[state] += 1
        check(sum(counts.values()) == spec['size'], 'source conservation failed')
        balances[source] = {'issued': spec['size'], **{state: counts[state] for state in
                            ('free', 'held-unused', 'spent', 'free_pending_reissue', 'escrow', 'retired', 'unbound')}}
    for _, kind, value in ae:
        if kind != 'reclaim':
            continue
        unused = {(r['source'], r['slot']) for r in value['receipt']['rows'] if r['outcome'] == 'unused'}
        check({(r['source'], r['slot']) for r in value['returned']} == unused, 'refund not exact unused set')
        for row in value['returned']:
            check(row['current_cap'] is None and row['state'] in ('free_pending_reissue', 'escrow', 'retired'),
                  'reclaim skipped pending/terminal stage')
    tls = [v for _, kind, v in ge if kind == 'tls-session']
    check(all(v['version'] == 'TLSv1.3' and not v['session_reused'] for v in tls), 'TLS session profile')
    check({s: b['spent'] for s, b in balances.items()} == manifest['expected_spent'], 'scenario final debit count')
    charge_calls = manifest['authority_calls'].get('charge', 0)
    check(charge_calls >= len(requests) if online else charge_calls == 0, 'wrong charge authority location')
    result = {'status': 'PASS' if not errors else 'FAIL', 'mode': manifest['mode'],
              'scenario': manifest['scenario'], 'oracle_checks': checks,
              'scenario_checks': len(manifest['checks']), 'unique_admissions': len(requests),
              'business_effects': len(effects), 'sources': balances, 'tls_sessions': len(tls),
              'logical_authority_charge_calls': charge_calls,
              'source_matches_current': manifest['source_files'] == source_manifest(), 'errors': errors}
    if errors:
        raise AssertionError(json.dumps(result, indent=2))
    return result
