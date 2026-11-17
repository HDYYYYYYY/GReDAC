"""Recompute RQ4 descriptive results from a single new batch, without reruns.

Cases/repetitions, not individual requests, are the independent units. Failed
attempts remain listed. Component spans are nested diagnostics, not additive
pieces of end-to-end latency. Fault windows use matched no-fault repetitions.
"""
import argparse,csv,json
from pathlib import Path
from .support import stats,write_json


def load(path,default=None):
    return json.loads(path.read_text()) if path.exists() else default


def window(rows,management,lo,hi):
    cohort=[r for r in rows if lo<=r['release']<hi]
    done=[r for r in rows if lo<=r['end']<hi and r['error'] is None]
    queries=[r for r in management if lo<=r['start']<hi]
    return dict(duration_seconds=max(0,hi-lo),released=len(cohort),completed=len(done),
        completed_rps=len(done)/(hi-lo) if hi>lo else None,
        failed=sum(r['error'] is not None for r in cohort),
        response_ms=stats([(r['end']-r['release'])*1000 for r in cohort if r['error'] is None]),
        crossing_window_end=sum(r['end']>=hi for r in cohort),
        management_ms=stats([(r['end']-r['start'])*1000 for r in queries]),
        management_failed=sum(r['error'] is not None for r in queries))


def fault_pairs(root,attempts):
    successful=[a for a in attempts if a['group']=='D' and a['exitcode']==0]
    controls={(a['case']['services'],a['repeat']):a for a in successful if a['case']['point']=='none'}
    pairs=[]
    def evidence(a):
        path=root/a['directory'];requests=[]
        for t in range(1,a['result']['teams']):
            requests+=load(path/f't{t}s-metrics/requests.json',[])
        requests=[r for r in requests if r['phase']=='measurement']
        return requests,[r for r in load(path/'management_operations.json',[]) if r['team']!=0]
    for fault in successful:
        if fault['case']['point']=='none':continue
        base=controls.get((fault['case']['services'],fault['repeat']))
        if base is None:
            pairs.append(dict(fault=fault['directory'],status='missing_successful_no_fault_pair'));continue
        f,b=fault['result'],base['result'];fr,fm=evidence(fault);br,bm=evidence(base)
        start=f['traffic_begin'];crash=f['event']['actual_crash']-start
        recovered=f['event']['new_delegation_and_consumption']-start
        stop=min(f['traffic_end']-start,b['traffic_end']-b['traffic_begin'])
        phases={}
        for name,lo,hi in [('before',0,crash),('event',crash,recovered),('after',recovered,f['traffic_end']-start)]:
            end=min(hi,stop)
            if end<=lo:phases[name]=dict(status='no_common_observation_window');continue
            phases[name]=dict(relative_start=lo,relative_end=end,complete_window=end>=hi,
                fault=window(fr,fm,start+lo,start+end),
                no_fault=window(br,bm,b['traffic_begin']+lo,b['traffic_begin']+end))
            x,y=phases[name]['fault'],phases[name]['no_fault']
            phases[name]['throughput_difference_rps']=x['completed_rps']-y['completed_rps']
            for metric in ('response_ms','management_ms'):
                if x[metric]['n'] and y[metric]['n']:
                    phases[name][metric+'_p95_difference']=x[metric]['p95']-y[metric]['p95']
        pairs.append(dict(services=fault['case']['services'],repeat=fault['repeat'],point=fault['case']['point'],
            fault=fault['directory'],no_fault=base['directory'],phases=phases,
            limitation='same requested workload/seeds, independent real executions; shortened/empty windows explicitly marked'))
    return pairs


def components(path):
    """Read measured RPC handler spans and raw transaction fields after timing."""
    buckets={};invalid=0
    for trace in path.rglob('events.jsonl'):
        for line in trace.read_text().splitlines():
            try:r=json.loads(line)
            except ValueError:invalid+=1;continue
            if r.get('kind')!='rpc-received':continue
            name=r['identity'];role='Authority' if name.startswith('Authority') else 'B' if name.startswith('G') else 'service' if name.startswith('S') else 'Agent_or_owner'
            key=role+'/'+r['method'];buckets.setdefault(key,[]).append((r['end']-r['start'])*1000)
    transaction_fields={}
    for trace in path.rglob('transactions.jsonl'):
        for line in trace.read_text().splitlines():
            try:r=json.loads(line)
            except ValueError:invalid+=1;continue
            for key,value in r.items():
                # These Store fields are durations; start_ns/end_ns are clock
                # readings and must never be summarized as operation latency.
                if key in ('lock_wait_ns','begin_ns','body_ns','commit_or_rollback_ns') and isinstance(value,(int,float)):
                    transaction_fields.setdefault(key,[]).append(value/1e6)
    return dict(rpc_handler_ms={k:stats(v) for k,v in buckets.items()},transaction_fields_ms={k:stats(v) for k,v in transaction_fields.items()},
        invalid_lines=invalid,scope='all observed setup/warmup/workload/audit spans; use raw timestamps to filter phases; nested RPC/transaction durations are not additive',
        crash_limit='in-memory transaction observations before process exit may be missing; not zero-imputed')


def build(root):
    manifest=load(root/'manifest.json');attempts=manifest['attempts'];rows=[]
    budgets=manifest.get('memory_budget_gib',dict(AB=8,D=24))
    for a in attempts:
        r=a.get('result',{});rows.append(dict(directory=a['directory'],group=a['group'],services=(a.get('case') or {}).get('services'),
            point=(a.get('case') or {}).get('point'),repeat=a['repeat'],exitcode=a['exitcode'],failure_kind=a.get('failure_kind'),
            within_budget=r.get('within_budget'),setup_seconds=r.get('setup_seconds'),contact_seconds=r.get('contact_all_seconds'),
            response_p95_ms=r.get('response_ms',{}).get('p95'),round_p95_ms=r.get('round_ms',{}).get('p95'),
            sampled_peak_rss_kib=r.get('sampled_peak_total_rss_kib'),failed_requests=r.get('failed'),
            business_rate_rps=r.get('business_rate_rps'),window_completed_rps=r.get('window_completed_rps'),
            contact_with_wait_seconds=r.get('contact_all_with_wait_seconds'),
            contact_protocol_p95_ms=r.get('contact_protocol_ms',{}).get('p95'),
            contact_wait_mean_seconds=r.get('contact_synthetic_wait_seconds',{}).get('mean'),
            synthetic_round_wait_seconds=r.get('synthetic_wait_seconds'),
            injected_downtime=r.get('event',{}).get('injected_downtime'),
            crash_to_new_success_seconds=r.get('event',{}).get('crash_to_new_success_seconds')))
    out=root/'analysis';out.mkdir(exist_ok=True)
    with (out/'runs.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else ['directory']);writer.writeheader();writer.writerows(rows)
    write_json(out/'fault_pairs.json',fault_pairs(root,attempts))
    write_json(out/'timing_components.json',{a['directory']:components(root/a['directory']) for a in attempts if (root/a['directory']).exists()})
    # Summaries are computed after every timed run, including failed cases.
    # Source indices and raw actual sleeps remain independently re-auditable.
    wait_rows={}
    for a in attempts:
        path=root/a['directory'];calibration=load(path/'wait_calibration.json')
        waits=load(path/'synthetic_waits.json',[])
        if a['group']=='A':
            contacts=load(path/'f-metrics/contacts.json',[])
            waits=[r['synthetic_wait'] for r in contacts if r.get('synthetic_wait')]
        if calibration:
            wait_rows[a['directory']]=dict(label=calibration['label'],sampling=calibration['sampling'],
                calibration_scenes={s:{k:b[k] for k in ('api_seconds','business_seconds')} for s,b in calibration['scenes'].items()},
                requested_seconds=stats([r['requested_wait_s'] for r in waits]),actual_seconds=stats([r['actual_wait_s'] for r in waits]),
                scene_counts={s:sum(r['scene']==s for r in waits) for s in calibration['scenes']})
    write_json(out/'wait_summary.json',wait_rows)
    lines=['# RQ4 one-to-many batch report','',f"Stage: {manifest['stage']}; attempted: {len(attempts)}; failed: {sum(a['exitcode']!=0 for a in attempts)}. Real LLM calls: 0.",'',
        'This is a fresh loopback TCP/mTLS batch. Historical MemoryBIO and previous batches are not pooled. Smoke data validates execution only, not capacity.', '',
        '| Group | Attempts | Successful executions | Passed capacity budget |','|---|---:|---:|---:|']
    for g in [g for g in 'ABCD' if any(a['group']==g for a in attempts)]:
        selected=[a for a in attempts if a['group']==g]
        passed=sum(a.get('result',{}).get('within_budget') is True for a in selected) if g in 'AB' else 'N/A'
        lines.append(f"| {g} | {len(selected)} | {sum(a['exitcode']==0 for a in selected)} | {passed} |")
    lines += ['', '## Capacity evidence', '']
    for g in 'AB':
        scales=sorted({a['case']['services'] for a in attempts if a['group']==g})
        for k in scales:
            selected=[a for a in attempts if a['group']==g and a['case']['services']==k]
            count=sum(a['exitcode']==0 and a.get('result',{}).get('within_budget') is True for a in selected)
            lines.append(f'- {g}, K={k}: {count}/{len(selected)} attempts satisfy the stated budgets. All values remain in runs.csv.')
    lines += ['', '## Failures', '']
    lines += [f"- {a['directory']}: {a.get('failure_kind','unknown')}, exit={a['exitcode']}; see its original log/manifest." for a in attempts if a['exitcode']!=0] or ['- None in this batch.']
    lines += ['', '## Measurement warnings', '']
    lines += [f"- {a['directory']}: {w}; inspect its original log and resource-sample coverage." for a in attempts for w in a.get('measurement_warnings',[])] or ['- None flagged by the batch launcher.']
    lines += ['', '## Interpretation limits', '',
        '- A samples recorded API durations; B/D sample net inter-business gaps. Three latest RQ3 scenes have equal sampling weight; tails and recorded retries remain. Synthetic waits are not new LLM measurements. A ready time includes waits; per-contact protocol spans exclude them. Busy interval union is not a hypothetical no-wait total.',
        f"- Preparation per team is limited to 600 s. Sampled total RSS is capped at {budgets['AB']} GiB for A/B, {budgets['D']} GiB for the whole D run; a budget stop is an implementation/environment boundary, not a protocol safety failure. If D cannot finish preparation, no fault/recovery outcome is claimed.",
        '- RSS is a same-sweep process sum; periodic sampling can miss short peaks. Process high-water sums are diagnostic only.',
        '- Real commit-boundary process exits cause D faults; no fixed artificial downtime is added. Scheduling, detection, target-group stop, uncertainty diagnostic and restart are distinct. Target callers survive; scripts pause target traffic and initiate restart, not autonomous self-healing.',
        '- fault_pairs.json aligns identical relative windows with the same-repeat no-fault run; empty/short windows and missing pairs are explicit. Small samples cannot prove absence of interference.',
        '- timing_components.json contains inclusive nested diagnostics, not an additive network/crypto decomposition. Exited-process gaps remain missing.',
        '- Three independent repetitions describe this measured host/configuration; medians are not a claim of stable capacity. No WAN or external exactly-once claim.',
        '- Raw per-team requests, RPC/transaction traces, databases, resource samples and source snapshots remain under each run directory.']
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);a=p.parse_args();build(a.root.resolve())
if __name__=='__main__':main()
