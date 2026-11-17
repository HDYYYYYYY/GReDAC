"""Read-only hot-request analysis for old/new RQ2 group-1 runs.

Uses EXISTING monotonic spans, so the before batch needs no new instrumentation
or rerun. No measurements are synthesized. Independent runs are the statistical
units; request samples and before/after-replacement segments stay identifiable.
The report directory must be new and outside both input batches.
"""
import argparse,csv,json,statistics
from collections import defaultdict
from pathlib import Path
from .results import stats,union_ns

BASELINE='results/rq2-flow-opt-full-20261110-150304'
PARTS=('caller_local_ms','caller_B_residual_ms','B_lock_wait_ms','B_begin_ms',
       'B_transaction_body_ms','B_commit_ms','B_other_ms','service_roundtrip_ms')


def duration(row):return row['end_ns']-row['start_ns']


def contained(child,parent):
    assert parent['start_ns']<=child['start_ns']<=child['end_ns']<=parent['end_ns'],('noncontained clock intervals',child['operation'],parent['operation'])


def unique(rows,operation):
    found=[r for r in rows if r['operation']==operation]
    assert len(found)==1,(operation,len(found))
    return found[0]


def samples(path,method):
    rows=[json.loads(x) for x in (path/'trace.jsonl').read_text().splitlines()]
    spans=[r for r in rows if r['kind']=='span' and r.get('end_ns') is not None and r['result']=='ok']
    assert len({(r['host_id'],r['clock_id']) for r in spans})==1,'cross-host clock subtraction is not supported'
    children=defaultdict(list)
    for r in spans:children[r.get('parent_span_id')].append(r)
    def below(root):
        out=[];pending=list(children[root['span_id']]);seen=set()
        while pending:
            r=pending.pop();sid=r['span_id'];assert sid not in seen,'span cycle';seen.add(sid)
            out.append(r);pending.extend(children[sid])
        return out
    first=sorted([r for r in spans if r['operation']=='first_request'],key=lambda r:r['start_ns'])
    hot=sorted([r for r in spans if r['operation']=='hot_request'],key=lambda r:r['start_ns']);result=[]
    for h in hot:
        row=dict(request_id=h['request_id'],participant=h['participant'],start_ns=h['start_ns'],end_ns=h['end_ns'],
            segment=sum(f['start_ns']<h['start_ns'] for f in first)-1,hot_ms=duration(h)/1e6)
        if method=='GReDAC':
            descendants=below(h);rpc=unique(descendants,'rpc.call.endpoint_charge');charge=unique(descendants,'Endpoint.charge')
            contained(rpc,h);contained(charge,rpc)
            bdesc=below(charge);service=unique(bdesc,'rpc.call.service_receive');contained(service,charge)
            transactions=[r for r in bdesc if r['operation']=='storage.transaction' and r['pid']==charge['pid']]
            assert len(transactions)==3,'ordinary successful admission must keep all three durable transactions'
            for t in transactions:
                contained(t,charge);assert sum(t['durations_ns'].values())==duration(t)
            intervals=[(t['start_ns'],t['end_ns']) for t in transactions]+[(service['start_ns'],service['end_ns'])]
            occupied=sum(hi-lo for lo,hi in intervals);assert occupied==union_ns(intervals),'overlapping B/service intervals cannot be added'
            parts=dict(caller_local_ms=duration(h)-duration(rpc),caller_B_residual_ms=duration(rpc)-duration(charge),
                B_other_ms=duration(charge)-occupied,service_roundtrip_ms=duration(service))
            for output,key in [('B_lock_wait_ms','lock_wait_ns'),('B_begin_ms','begin_ns'),
                               ('B_transaction_body_ms','body_ns'),('B_commit_ms','commit_or_rollback_ns')]:
                parts[output]=sum(t['durations_ns'][key] for t in transactions)
            assert min(parts.values())>=0 and sum(parts.values())==duration(h),'component accounting does not close'
            row.update({k:v/1e6 for k,v in parts.items()})
            receiver=unique(below(service),'rpc.handle.service_receive');contained(receiver,service)
            row.update(service_handler_inclusive_ms=duration(receiver)/1e6,
                service_transport_dispatch_residual_ms=(duration(service)-duration(receiver))/1e6,
                B_transactions=len(transactions),signatures=sum(r['operation']=='Signer.sign' for r in descendants),
                verifications=sum(r['operation']=='gredac.crypto.verify_signature' for r in descendants),
                capability_tags=sum(r['operation']=='Bundle.tag' for r in descendants))
            # Nested diagnostic times are NOT another additive breakdown.
            for label,operation in [('crypto_verify_inclusive_ms','gredac.crypto.verify_signature'),
                ('crypto_sign_inclusive_ms','Signer.sign'),('tag_inclusive_ms','Bundle.tag'),('rpc_encode_inclusive_ms','rpc.encode')]:
                row[label]=sum(duration(r) for r in descendants if r['operation']==operation)/1e6
            assert (row['signatures'],row['verifications'],row['capability_tags'])==(2,3,2),'protocol primitive count changed'
        else:
            # Author callback intervals are not Python parent contexts. Select
            # same-process send/recv observations by clock containment instead.
            selected=[r for r in spans if r['pid']==h['pid'] and r['thread_id']==h['thread_id']
                and h['start_ns']<=r['start_ns']<=r['end_ns']<=h['end_ns']
                and r['operation'] in ('author.agent.send','author.agent.recv')]
            occupied=union_ns([(r['start_ns'],r['end_ns']) for r in selected])
            row['native_send_recv_union_ms']=occupied/1e6
            row['native_other_ms']=(duration(h)-occupied)/1e6
            # B ledger/return semantics are absent, never imputed as zeros.
        result.append(row)
    return result


def aggregate(records):
    numeric={k for r in records for k,v in r.items() if isinstance(v,(int,float)) and k.endswith('_ms')}
    return {k:stats([r[k] for r in records if k in r]) for k in sorted(numeric)}


def batch(root,label):
    m=json.loads((root/'manifest.json').read_text());runs=[];raw=[]
    for a in m['attempts']:
        c=a.get('case') or {}
        if c.get('block')!='flow':continue
        assert c['units']==128 and c['requests']==32 and c['flow'] in ('F1','F2','F3'),'different workload'
        record=dict(batch=label,run=a['directory'],flow=c['flow'],method=c['method'],repeat=a['repeat'],
            pair=a['pair'],exitcode=a['exitcode'],status='failed_task' if a['exitcode'] else 'ok',case=c)
        if not a['exitcode']:
            try:
                request_rows=samples(root/a['directory'],c['method'])
                expected=31 if c['flow']=='F1' else 30;assert len(request_rows)==expected
                old=a['result']['hot_ms'];calculated=stats([r['hot_ms'] for r in request_rows])
                assert all(abs(old[k]-calculated[k])<1e-9 for k in ('mean','p50','p95')),'does not match original hot-request boundary'
                record.update(T_task=a['result']['T_task'],T_replace_first=a['result']['T_replace_first'],
                    metrics=aggregate(request_rows),segments={str(i):aggregate([r for r in request_rows if r['segment']==i])
                        for i in sorted({r['segment'] for r in request_rows})})
                for r in request_rows:raw.append(dict(batch=label,run=a['directory'],flow=c['flow'],method=c['method'],**r))
            except (AssertionError,KeyError,FileNotFoundError) as exc:
                record.update(status='measurement_error',error=str(exc))
        runs.append(record)
    assert runs,'no group-1 attempts'
    return m,runs,raw


def csv_file(path,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)


def report(baseline,current,out):
    baseline,current,out=[x.resolve() for x in (baseline,current,out)]
    assert baseline!=current and not out.is_relative_to(baseline) and not out.is_relative_to(current),'do not write into input results'
    old,old_runs,old_raw=batch(baseline,'before');new,new_runs,new_raw=batch(current,'after')
    # Pilot is valid only as an implementation/format check, never a matched
    # six-run performance comparison. Full comparison requires all 36 jobs.
    eligible=new['stage']=='full' and old['stage']=='full' and len(new_runs)==len(old_runs)==36
    if eligible:
        def design(m):return sorted(json.dumps({k:a[k] for k in ('case','repeat','pair')},sort_keys=True) for a in m['attempts'])
        assert design(old)==design(new),'matrix/order labels differ'
    out.mkdir(parents=True,exist_ok=False)
    runs=old_runs+new_runs;raw=old_raw+new_raw
    (out/'runs.json').write_text(json.dumps(runs,indent=2));csv_file(out/'requests.csv',raw)
    rows=[];components=[]
    for label in ('before','after'):
        for flow in ('F1','F2','F3'):
            for method in ('GReDAC','SAGA-author-source@7372111'):
                group=[r for r in runs if (r['batch'],r['flow'],r['method'])==(label,flow,method)]
                good=[r for r in group if r['status']=='ok']
                row=dict(batch=label,flow=flow,method=method,attempts=len(group),usable=len(good))
                for q in ('mean','p50','p95'):
                    row['hot_run_'+q+'_ms']=stats([r['metrics']['hot_ms'][q] for r in good])
                rows.append(row)
                if method=='GReDAC':
                    for part in PARTS:
                        components.append(dict(batch=label,flow=flow,component=part,
                            run_means_ms=[r['metrics'][part]['mean'] for r in good],
                            distribution=stats([r['metrics'][part]['mean'] for r in good])))
    (out/'summary.json').write_text(json.dumps(dict(groups=rows,components=components),indent=2))
    changes=[]
    if eligible:
        for flow in ('F1','F2','F3'):
            for method in ('GReDAC','SAGA-author-source@7372111'):
                a,b=[next(r for r in rows if (r['batch'],r['flow'],r['method'])==(label,flow,method)) for label in ('before','after')]
                for q in ('mean','p50','p95'):
                    av,bv=a['hot_run_'+q+'_ms'],b['hot_run_'+q+'_ms']
                    if av is not None and bv is not None:changes.append(dict(flow=flow,method=method,metric=q,
                        before_ms=av['p50'],after_ms=bv['p50'],delta_ms=bv['p50']-av['p50'],ratio=bv['p50']/av['p50']))
    (out/'changes.json').write_text(json.dumps(changes,indent=2))
    metadata=dict(baseline=str(baseline),current=str(current),formal_comparison=eligible,
        environment_equal=old['environment']==new['environment'],old_stage=old['stage'],new_stage=new['stage'],
        source_before=old['source_sha256'],source_after=new['source_sha256'],
        measurement_errors=[r for r in runs if r['status']=='measurement_error'],
        statistical_unit='independent run; batches are not simultaneous before/after pairs',
        direct_diagnostic_log_time=None,reason='not separately instrumented in old batch; contained in local/residual intervals, never imputed')
    (out/'manifest.json').write_text(json.dumps(metadata,indent=2))
    lines=['# RQ2 hot-request comparison','',
        'Formal comparison.' if eligible else '**Development/format validation only; no formal speedup estimate.**','',
        'All values below are medians across independent-run summaries (ms); requests are not pooled across runs or flows.', '',
        '| Batch | Flow | Method | Usable/attempted | Run mean | Run p50 | Run p95 |','|---|---|---|---:|---:|---:|---:|']
    def val(v):return 'N/A' if v is None else f"{v['p50']:.6f}"
    for r in rows:lines.append('| '+' | '.join([r['batch'],r['flow'],r['method'],f"{r['usable']}/{r['attempts']}",*[val(r['hot_run_'+q+'_ms']) for q in ('mean','p50','p95')]])+' |')
    lines+=['','## Components','',
        'requests.csv preserves each measured hot request and its before/after-replacement segment. runs.json preserves per-run and per-segment summaries. Components are mutually exclusive and sum exactly to each GReDAC hot-request interval; their **per-run means** also add. Medians of different components need not add.', '',
        '| Batch | Flow | Component | Median run mean (ms) |','|---|---|---|---:|']
    for c in components:lines.append(f"| {c['batch']} | {c['flow']} | {c['component']} | {val(c['distribution'])} |")
    lines+=['','- caller_local: request preparation/proof, caller receipt verification, business checking and local diagnostics outside the B RPC.',
        '- caller_B_residual: RPC roundtrip minus B charge interval; includes transport, codecs, dispatch and scheduling. It is **not pure network RTT**.',
        '- B lock/BEGIN/body/COMMIT: original transaction observer, three commits per ordinary request. Body includes checks/crypto/serialization/SQL; commit includes recorded transaction-finalization overhead.',
        '- B_other: remaining B charge work outside those three transactions and the service RPC; never imputed as pure crypto.',
        '- service_roundtrip: real B-to-service call, including service verification/business/receipt signing and communication. Service handler and its residual are saved as nested diagnostics only.',
        '- Crypto/serialization inclusive diagnostics must not be added again to exclusive components. Diagnostic log time is not independently observed in the baseline; no fabricated value is supplied.',
        '- SAGA keeps its native send/recv interval union and other Agent work; B ledger/recovery components are N/A, not zero.',
        '- Failures and trace errors remain in attempts. A complete-pair safety claim or an equal-security ranking cannot be inferred from latency.',
        '- Different run times/storage pressure and small n can affect observations. changes.json is descriptive across batch medians, not a causal paired speedup test.',
        '- Raw inputs are never rewritten; no new experiment, LLM call or protocol operation is performed.']
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n')
    plot(out,runs)
    return metadata


def plot(out,runs):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,3,figsize=(12,4))
    for ax,flow in zip(axes,('F1','F2','F3')):
        for i,(batch,method) in enumerate((b,m) for b in ('before','after') for m in ('GReDAC','SAGA-author-source@7372111')):
            values=[r['metrics']['hot_ms']['p50'] for r in runs if (r['batch'],r['flow'],r['method'],r['status'])==(batch,flow,method,'ok')]
            ax.scatter([i]*len(values),values,s=22,alpha=.75)
            if values:ax.plot([i-.15,i+.15],[statistics.median(values)]*2,color='black')
        ax.set(title=flow,xticks=range(4),xticklabels=['old S','old A','new S','new A'],ylabel='Per-run hot p50 (ms)');ax.grid(axis='y',alpha=.2)
    fig.suptitle('Independent run observations; S=GReDAC, A=author SAGA')
    fig.tight_layout();fig.savefig(out/'hot_request_runs.png',dpi=180);plt.close(fig)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--baseline',type=Path,default=Path(BASELINE))
    p.add_argument('--current',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();meta=report(a.baseline,a.current,a.out)
    print(json.dumps(dict(out=str(a.out),formal_comparison=meta['formal_comparison'],measurement_errors=len(meta['measurement_errors']))))
    if meta['measurement_errors']:raise SystemExit(1)
