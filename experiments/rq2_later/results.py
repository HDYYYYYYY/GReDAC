"""Read-only, reproducible summaries from physical spans and saved evidence.

Inclusive derivation/delivery/verification/synchronization observations are
separate columns, never added together as end-to-end latency. All statistics
across repetitions use one observation per independent run; hot p95 is first
computed within a run. Failed attempts remain in denominators and CSV rows.
"""
import csv
import json
import statistics
from pathlib import Path
from experiments.rq2_v2 import timing
from experiments.rq2_v2.results import stats, union_ns


def summarize(out, cfg):
    rows = timing.normalize(timing.load(out / 'timing'))
    (out / 'trace.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
    spans = [r for r in rows if r['kind'] == 'span']
    assert all(r['end_ns'] is not None and r['result'] == 'ok' for r in spans)
    assert len({r['host_id'] for r in rows}) == 1
    byid = {r['span_id']: r for r in spans}

    def event(name):
        selected = [r['time_ns'] for r in rows if r['kind'] == 'event' and r['operation'] == name]
        assert len(selected) == 1, (name, len(selected))
        return selected[0]

    def select(operation):
        return [r for r in spans if r['operation'] == operation]

    def only(operation):
        found = select(operation)
        assert len(found) == 1, (operation, len(found))
        return found[0]

    def duration(r):
        return (r['end_ns'] - r['start_ns']) / 1e6

    def total(found):
        return union_ns([(r['start_ns'], r['end_ns']) for r in found]) / 1e6

    def descendants(parent, operation=None):
        def child(r):
            seen = set()
            pid = r.get('parent_span_id')
            while pid in byid and pid not in seen:
                if pid == parent['span_id']:
                    return True
                seen.add(pid)
                pid = byid[pid].get('parent_span_id')
            return False
        return [r for r in spans if (operation is None or r['operation'] == operation) and child(r)]

    # Every boundary is directly observed. No environment startup interval is
    # retained as a task cost. User provisioning is measured separately.
    ready, users, user_end = map(event, ('infrastructure_ready', 'user_prerequisites_begin', 'user_prerequisites_ready'))
    start, authorized, end = map(event, ('task_participant_prepare_begin', 'task_authorization_or_handoff_begin', 'task_finish'))
    assert ready <= users < user_end <= start < authorized < end
    assert not any(r['operation'] == 'infrastructure_start' for r in spans)
    contact = only('contact.establish')
    first = only('first_request')
    hot = sorted(select('hot_request'), key=lambda r: r['start_ns'])
    assert len(hot) == cfg['requests'] - 1
    assert first['start_ns'] <= contact['start_ns'] < contact['end_ns'] < first['end_ns']
    assert first['end_ns'] <= (hot[0]['start_ns'] if hot else end)
    result_events = [r['time_ns'] for r in rows if r['kind'] == 'event' and r['operation'] == 'result_verified']
    assert len(result_events) == cfg['requests']
    dynamic = sorted([r for r in spans if r['operation'].startswith('identity.dynamic.')], key=lambda r:r['start_ns'])
    depth = cfg['depth']
    expected = ['S1'] + [f'A{i}' for i in range(1, depth + 1)]
    assert sorted(r['operation'].removeprefix('identity.dynamic.') for r in dynamic) == sorted(expected)
    assert all(authorized < r['start_ns'] < r['end_ns'] < contact['start_ns'] for r in dynamic)
    roots = [r for r in spans if r['operation'].startswith('identity.prepare.')]
    assert sorted(r['operation'] for r in roots) == ['identity.prepare.O', 'identity.prepare.R']

    task_ms = (end - start) / 1e6
    oneoff_ms = (contact['end_ns'] - start) / 1e6
    first_after = (first['end_ns'] - contact['end_ns']) / 1e6
    phases = {p:total([r for r in spans if r.get('display_phase') and r['phase'] == p])
              for p in ('I', 'II', 'III.first', 'III.hot')}
    prep_ms = (contact['start_ns'] - start) / 1e6
    hot_total = total(hot)
    residual = task_ms - oneoff_ms - first_after - hot_total
    assert residual >= -1e-8
    # This nonnegative residual contains real inter-request scheduling, event
    # bookkeeping and task finish, not an invented estimate of network delay.
    output = dict(**cfg, T_task_ms=task_ms,
        T_user_prerequisites_ms=(user_end-users)/1e6, T_with_users_ms=(end-users)/1e6,
        T_root_identity_ms=(authorized-start)/1e6,
        T_dynamic_identity_ms=total(dynamic), T_all_identity_operations_ms=total(roots+dynamic),
        T_initialization_ms=phases['I'], T_preparation_ms=prep_ms,
        T_contact_ms=duration(contact), T_first_use_ms=duration(first),
        T_first_request_after_contact_ms=first_after, T_oneoff_ms=oneoff_ms,
        T_end_ms=(end-max(result_events))/1e6, T_remaining_gaps_and_finish_ms=max(0.,residual),
        amortized_task_ms=task_ms/cfg['requests'], amortized_oneoff_ms=oneoff_ms/cfg['requests'],
        hot_ms=stats([duration(r) for r in hot]), phase_ms=phases,
        seed_count=None, complete_delivery_request_bytes=None,
        measurement_scope='physical single-host multiprocess TCP/TLS; infrastructure excluded; authenticated users separately',
        acceptability_claim='not assessed: no frozen business latency budget')

    # Each layer has its own evidence: local derivation, actual parent->child
    # delivery, child verification, and the final first persistent sync at B.
    layers = []
    for parent in sorted(select('delegation'), key=lambda r:r['start_ns']):
        transfer = descendants(parent, 'gredac.offline.transfer')
        delivery = descendants(parent, 'rpc.call.receive_delegation')
        verification = descendants(parent, 'gredac.offline.receive_delegation')
        auth = descendants(parent, 'rpc.call.install_right')
        derived = descendants(parent, 'Bundle.child')
        assert len(transfer) == len(delivery) == len(verification) == len(auth) == 1
        assert len(derived) == 1  # one capability/source/action in this profile

        def encoded_size(call):
            enc = [r for r in descendants(call, 'rpc.encode') if r['participant'] == call['participant']]
            assert len(enc) == 1
            return enc[0]['serialized_bytes']

        seeds = transfer[0]['seed_secret_bytes'] // 32
        assert seeds == len(derived[0]['cover'])
        auth_bytes, transfer_bytes = encoded_size(auth[0]), encoded_size(delivery[0])
        d = dict(parent=parent['parent_agent'], child=parent['child_agent'],
            span_id=parent['span_id'], delegation_ms=duration(parent),
            dynamic_identity_ms=total([r for r in descendants(parent) if r['operation'].startswith('identity.dynamic.')]),
            derivation_and_description_ms=duration(transfer[0]), ggm_derivation_ms=duration(derived[0]),
            delivery_roundtrip_ms=duration(delivery[0]), child_verification_ms=duration(verification[0]),
            seed_count=seeds, seed_secret_bytes=seeds*32, minimal_prefixes=derived[0]['cover'],
            authorization_request_bytes=auth_bytes, transfer_request_bytes=transfer_bytes,
            complete_delivery_request_bytes=auth_bytes+transfer_bytes,
            complete_delivery_framed_bytes=auth_bytes+transfer_bytes+8,
            material_scope='actual encoded full authorization and transfer requests, including all chain/keys/records/task info and RPC envelopes; no TLS overhead')
        layers.append(d)
    assert len(layers) == depth
    assert layers[-1]['seed_count'] == cfg['cover']
    # Original public material_size diagnostic excludes the chain. Retain
    # both logical documents separately; their sum is NOT wire byte length.
    holdings = json.loads((out/'materials.json').read_text())
    final = next(m for m in holdings if m['participant'] == f'A{depth}')
    sync = only('Endpoint.sync')
    sync_rpc = only('rpc.call.sync')
    assert contact['start_ns'] <= sync_rpc['start_ns'] <= sync['start_ns'] < sync['end_ns'] <= sync_rpc['end_ns'] <= contact['end_ns']
    output.update(T_derivation_ms=sum(v['derivation_and_description_ms'] for v in layers),
        T_ggm_derivation_ms=sum(v['ggm_derivation_ms'] for v in layers),
        T_delivery_ms=sum(v['delivery_roundtrip_ms'] for v in layers),
        T_child_verification_ms=sum(v['child_verification_ms'] for v in layers),
        T_first_sync_ms=duration(sync_rpc), T_B_first_sync_ms=duration(sync),
        T_final_delegation_ms=layers[-1]['delegation_ms'],
        seed_count=layers[-1]['seed_count'], seed_secret_bytes=layers[-1]['seed_secret_bytes'],
        complete_delivery_request_bytes=layers[-1]['complete_delivery_request_bytes'],
        all_layers_delivery_request_bytes=sum(v['complete_delivery_request_bytes'] for v in layers),
        final_logical_holding_bytes=final['material_bytes'], final_chain_bytes=final['chain_bytes'],
        final_holding_and_chain_document_bytes=final['material_bytes']+final['chain_bytes'])
    (out/'delegation_layers.json').write_text(json.dumps(layers, indent=2))
    (out/'timing_schema.json').write_text(json.dumps(dict(version='rq2-later-1',
        clock='CLOCK_MONOTONIC/ns on one host',
        oneoff='task_participant_prepare_begin -> contact.establish.end; includes task identities, I/II and first contact, excludes first business consumption',
        preparation='task_participant_prepare_begin -> contact.establish.start',
        first='first_request includes contact; first_request_after_contact is contact.end -> first_request.end',
        overlap='derivation includes GGM; delivery includes child verification; contact includes sync; identity is also included in its real stage; never sum these columns',
        material='real encoded requests before TLS; logical holding+chain documents shown separately; no secret key exported by measurement'), indent=2))
    return output


METRICS = ('T_task_ms','T_user_prerequisites_ms','T_with_users_ms','T_root_identity_ms',
    'T_dynamic_identity_ms','T_all_identity_operations_ms','T_initialization_ms',
    'T_preparation_ms','T_contact_ms','T_first_use_ms','T_first_request_after_contact_ms',
    'T_oneoff_ms','T_end_ms','T_remaining_gaps_and_finish_ms','amortized_task_ms',
    'amortized_oneoff_ms','T_derivation_ms','T_ggm_derivation_ms','T_delivery_ms',
    'T_child_verification_ms','T_first_sync_ms','T_B_first_sync_ms','T_final_delegation_ms',
    'seed_count','seed_secret_bytes','complete_delivery_request_bytes',
    'all_layers_delivery_request_bytes','final_logical_holding_bytes','final_chain_bytes',
    'final_holding_and_chain_document_bytes','hot_mean_ms','hot_p50_ms','hot_p95_ms')


def flattened(result):
    flat = dict(result)
    for key in ('mean','p50','p95'):
        flat['hot_'+key+'_ms'] = (result.get('hot_ms') or {}).get(key)
    return flat


def report(root):
    meta = json.loads((root/'manifest.json').read_text())
    out = root/'analysis'
    out.mkdir(exist_ok=True)
    attempts = meta['attempts']
    rows, groups = [], {}
    for a in attempts:
        key = json.dumps(a['case'], sort_keys=True)
        groups.setdefault(key, []).append(a)
        r = flattened(a.get('result', {}))
        rows.append(dict(run=a['directory'], repeat=a['repeat'], exitcode=a['exitcode'],
            **a['case'], **{k:r.get(k) for k in METRICS}))
    with (out/'runs.csv').open('w', newline='') as f:
        fields=list(dict.fromkeys(k for row in rows for k in row))
        w=csv.DictWriter(f, fields);w.writeheader();w.writerows(rows)
    grouped=[]
    for key, items in groups.items():
        good=[flattened(a['result']) for a in items if a['exitcode']==0]
        grouped.append(dict(case=json.loads(key), attempts=len(items), passed=len(good),
            metrics={k:stats([r[k] for r in good if r.get(k) is not None]) for k in METRICS}))
    (out/'group_summary.json').write_text(json.dumps(grouped, indent=2))
    lines=['# GReDAC RQ2 '+meta['group'], '',
        f"Stage: {meta['stage']}; attempted {len(attempts)}/{meta['planned']}; failures {sum(a['exitcode']!=0 for a in attempts)}; LLM calls 0.", '',
        'Each table value is the median of independent successful run metrics. Failures remain in the denominators; requests are not pooled across repetitions.', '',
        'Infrastructure startup is excluded. User prerequisites are separate. Root identity preparation and actual dynamic member creation are included in task cost.', '',
        'N/A denotes no observation (in particular no hot requests at N=1), never a zero cost. Pilot data are development checks, not formal performance evidence.', '']
    def cell(g,k):
        v=g['metrics'][k]
        return 'N/A' if v is None else f"{v['p50']:.3f}"
    if meta['group']=='dialogue':
        cols=['T_task_ms','T_preparation_ms','T_contact_ms','T_first_request_after_contact_ms',
              'amortized_task_ms','amortized_oneoff_ms','hot_mean_ms','hot_p50_ms','hot_p95_ms']
        lines += ['| N | Pass/attempt | '+' | '.join(cols)+' |','|---:|---:|'+'---:|'*len(cols)]
        for g in sorted(grouped,key=lambda g:g['case']['requests']):
            lines.append('| '+' | '.join([str(g['case']['requests']),f"{g['passed']}/{g['attempts']}",*[cell(g,k) for k in cols]])+' |')
    else:
        cols=['T_root_identity_ms','T_dynamic_identity_ms','T_initialization_ms','T_derivation_ms',
            'T_delivery_ms','T_child_verification_ms','T_first_sync_ms','seed_count','complete_delivery_request_bytes']
        for axis,key in [('depth','depth'),('quota','units'),('fragmentation','cover')]:
            lines += ['', '## '+axis,'','| Setting | Pass/attempt | '+' | '.join(cols)+' |','|---:|---:|'+'---:|'*len(cols)]
            for g in sorted([g for g in grouped if g['case']['axis']==axis],key=lambda g:g['case'][key]):
                lines.append('| '+' | '.join([str(g['case'][key]),f"{g['passed']}/{g['attempts']}",*[cell(g,k) for k in cols]])+' |')
    lines += ['', '## Scope and evidence', '',
        '- Derivation, delivery, verification and synchronization are inclusive observations; do not sum them. Per-layer final and cumulative metrics remain in delegation_layers.json.',
        '- Seeds are the actual received minimal GGM cover. Full delivery bytes include the native authorization and transfer request bodies and RPC envelopes, not TLS overhead. Logical holding and chain document sizes are separate.',
        '- Total/N includes necessary task finish. Oneoff/N ends when first contact returns, excluding first consumption. Residual gaps/finish are retained without assigning them to crypto/network.',
        '- All task results are computed by the service process and independently checked; Authority is frozen after initialization. This measures single-host TCP/TLS, not WAN or LLM time.',
        '- Every run preserves raw traces, resource samples, code, configuration, actual receipts and durable databases. No failed attempt is replaced; no acceptable-latency claim without a frozen budget.', '', '## Failures', '']
    lines += [f"- {a['directory']}: exit {a['exitcode']}, see original log/manifest." for a in attempts if a['exitcode']] or ['- None.']
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n')
    plot(out, meta['group'], attempts)


def plot(out, group, attempts):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    good=[flattened(a['result']) for a in attempts if a['exitcode']==0]
    charts=[('dialogue','requests',['amortized_task_ms','amortized_oneoff_ms','hot_mean_ms'])] if group=='dialogue' else [
        (a,k,['T_derivation_ms','T_delivery_ms','T_child_verification_ms','T_first_sync_ms'])
        for a,k in [('depth','depth'),('quota','units'),('fragmentation','cover')]]
    for axis,key,metrics in charts:
        rows=[r for r in good if r.get('axis',r['block'])==axis]
        fig,ax=plt.subplots()
        for metric in metrics:
            selected=[r for r in rows if r.get(metric) is not None]
            xs=sorted({r[key] for r in selected})
            if xs:
                line=ax.plot(xs,[statistics.median(r[metric] for r in selected if r[key]==x) for x in xs],marker='o',label=metric)[0]
                ax.scatter([r[key] for r in selected],[r[metric] for r in selected],s=12,alpha=.35,color=line.get_color())
        ax.set(xscale='log',xlabel=key,ylabel='Measured ms (inclusive columns not additive)')
        ax.grid(alpha=.2)
        if ax.lines:ax.legend(fontsize=7)
        fig.tight_layout();fig.savefig(out/(axis+'.png'),dpi=180);plt.close(fig)


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True)
    report(p.parse_args().root)
