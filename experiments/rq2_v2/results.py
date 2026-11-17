"""Recomputable boundaries and display mapping, never imputed measurements."""
import csv,json,statistics
from pathlib import Path
from . import timing


def union_ns(intervals):
    total=0;end=None
    for lo,hi in sorted(intervals):
        if end is None or lo>end:total+=hi-lo;end=hi
        elif hi>end:total+=hi-end;end=hi
    return total


def stats(values):
    values=sorted(values)
    if not values:return None
    def q(p):
        v=(len(values)-1)*p;i=int(v)
        return values[i]+(values[min(i+1,len(values)-1)]-values[i])*(v-i)
    return dict(n=len(values),mean=statistics.mean(values),p50=q(.5),p95=q(.95),minimum=values[0],maximum=values[-1])


def summarize(out,cfg):
    rows=timing.normalize(timing.load(out/'timing'))
    (out/'trace.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
    events={}
    for row in rows:
        if row['kind']=='event':events.setdefault(row['operation'],[]).append(row['time_ns'])
    flow=cfg['block']=='flow'
    boundaries=['infrastructure_ready','task_participant_prepare_begin','task_authorization_or_handoff_begin','task_finish']
    if not flow:boundaries.insert(0,'infrastructure_start_begin')
    for name in boundaries:
        assert len(events.get(name,[]))==1,('missing/duplicate timing boundary',name)
    end=events['task_finish'][0]
    starts=[events.get('infrastructure_start_begin',events['infrastructure_ready'])[0],events['infrastructure_ready'][0],
        events['task_participant_prepare_begin'][0],events['task_authorization_or_handoff_begin'][0]]
    assert starts==sorted(starts) and starts[-1]<end
    spans=[r for r in rows if r['kind']=='span']
    incomplete=[r for r in spans if r['end_ns'] is None or r['result']!='ok']
    assert not incomplete,('incomplete/failed operation spans',[(r['operation'],r['result']) for r in incomplete[:5]])
    first=sorted([r for r in spans if r['operation']=='first_request'],key=lambda r:r['start_ns'])
    hot=sorted([r for r in spans if r['operation']=='hot_request'],key=lambda r:r['start_ns'])
    assert len(first)+len(hot)==cfg['requests'],(len(first),len(hot),cfg['requests'])
    stages=[r for r in spans if r.get('display_phase')]
    phase_ms={p:union_ns([(r['start_ns'],r['end_ns']) for r in stages if r['phase']==p])/1e6 for p in ('I','II','III.first','III.hot','IV')}
    for p in list(phase_ms):
        if not any(r['phase']==p for r in stages):phase_ms[p]=None
    durations={key:(end-events[event][0])/1e9 for key,event in (
        ('T_task','task_participant_prepare_begin'),('T_ready','task_authorization_or_handoff_begin'))}
    durations['T_cold']=None if flow else (end-starts[0])/1e9
    results=events.get('result_verified',[]);assert len(results)==cfg['requests']
    replacement=None
    if cfg.get('replacement'):
        assert len(events.get('replacement_trigger',[]))==len(events.get('replacement_first_result_verified',[]))==1
        replacement=(events['replacement_first_result_verified'][0]-events['replacement_trigger'][0])/1e9
    main=durations['T_ready'] if cfg.get('identity')=='ready' or cfg['block']=='structure' else durations['T_task']
    result=dict(**cfg,**durations,primary_seconds=main,T_environment=None if flow else (starts[1]-starts[0])/1e9,
        T_identity=(starts[3]-starts[2])/1e9,T_end=(end-max(results))/1e9,
        T_replace_first=replacement,phase_ms=phase_ms,
        first_ms=stats([(r['end_ns']-r['start_ns'])/1e6 for r in first]),
        hot_ms=stats([(r['end_ns']-r['start_ns'])/1e6 for r in hot]),
        amortized_task_ms=durations['T_task']*1000/cfg['requests'],
        amortized_ready_ms=durations['T_ready']*1000/cfg['requests'],amortized_cold_ms=None if flow else durations['T_cold']*1000/cfg['requests'],
        display_rule='stage instances directly timed; union of their physical intervals, not sum of nested operations',
        acceptability_claim='not assessed: no predeclared business latency budget',
        missing_phase_reason={p:('native guarantee N/A' if cfg['method']!='GReDAC' and p in ('I','IV') else 'not triggered') for p,v in phase_ms.items() if v is None})
    if flow:
        assert 'infrastructure_start_begin' not in events
        prerequisites=(events['user_prerequisites_ready'][0]-events['user_prerequisites_begin'][0])/1e9
        result.update(T_user_prerequisites=prerequisites,T_with_user_prerequisites=(end-events['user_prerequisites_begin'][0])/1e9,
            prerequisite_scope='fresh user/account authentication measured separately; task starts with authenticated users, root Agents not yet prepared',
            identity_scope='roots only: O,R for GReDAC; O for native SAGA; S1 and all children/replacements created in II')
        dynamic=[r for r in rows if r['kind']=='event' and r['operation']=='dynamic_identity_ready']
        expected=['A1','A2','S1']+(['Anew'] if cfg.get('replacement')=='caller' else ['S2'] if cfg.get('replacement')=='service' else [])
        assert sorted(r['member'] for r in dynamic)==sorted(expected)
        assert all(r['time_ns']>starts[3] for r in dynamic)
        assert all(r['time_ns']>events['replacement_trigger'][0] for r in dynamic if r['member'] in ('Anew','S2'))
        result['segments']=[dict(segment=i,first_request_ms=(r['end_ns']-r['start_ns'])/1e6,
            hot_ms=stats([(h['end_ns']-h['start_ns'])/1e6 for h in hot if r['end_ns']<h['start_ns']<
                (first[i+1]['start_ns'] if i+1<len(first) else end)])) for i,r in enumerate(first)]
    task_start=starts[2]
    covered=union_ns([(max(task_start,r['start_ns']),min(end,r['end_ns'])) for r in stages
        if r['end_ns']>task_start and r['start_ns']<end])
    result['unattributed_task_seconds']=(end-task_start-covered)/1e9
    assert result['unattributed_task_seconds']>=0
    delegations=[r for r in stages if r['operation']=='delegation']
    if delegations:
        ordered=sorted(delegations,key=lambda r:r['start_ns'])
        result.update(delegation_path_ms=(ordered[-1]['end_ns']-ordered[0]['start_ns'])/1e6,
            final_delegation_ms=(ordered[-1]['end_ns']-ordered[-1]['start_ns'])/1e6,
            delegation_instances=len(ordered))
    # This is an index of measured metadata, not a sum of inclusive timings.
    material=[{k:r[k] for k in ('span_id','participant','phase','operation','unit_domain_size',
        'unit_records','capability_records','cover','prefix_cover','seed_secret_bytes','serialized_bytes') if k in r}
        for r in spans if any(k in r for k in ('seed_secret_bytes','serialized_bytes'))]
    (out/'material_observations.json').write_text(json.dumps(material,indent=2))
    (out/'stage_instances.json').write_text(json.dumps(stages,indent=2))
    (out/'timing_schema.json').write_text(json.dumps(dict(version='rq2-v2.2',clock='CLOCK_MONOTONIC/ns',
        phase_mapping={'I':'authorization setup','II':'delegation/native handoff','III.first':'first contact/use and publication','III.hot':'subsequent requests','IV':'revoke/return'},
        primitive_semantics='inclusive wall time; nested, parallel and remote observations not additive',
        remote_correlation='GReDAC per-peer operation sequence; SAGA socket endpoints and frame sequence; no protocol payload changes'),indent=2))
    return result


def report(root):
    meta=json.loads((root/'manifest.json').read_text());attempts=meta['attempts'];rows=[];paired=[]
    for a in attempts:
        r=a.get('result',{});row=dict(run=a['directory'],pair=a['pair'],repeat=a['repeat'],exitcode=a['exitcode'],**a['case'])
        row.update({k:r.get(k) for k in ('primary_seconds','T_task','T_ready','T_cold','T_environment','T_identity','T_user_prerequisites','T_with_user_prerequisites','T_end','T_replace_first','unattributed_task_seconds')})
        row.update({'phase_'+k+'_ms':v for k,v in r.get('phase_ms',{}).items()});rows.append(row)
    out=root/'analysis';out.mkdir(exist_ok=True)
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with (out/'runs.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fields);w.writeheader();w.writerows(rows)
    for pair in dict.fromkeys(a['pair'] for a in attempts if a['case']['block']!='structure'):
        arms={a['case']['method']:a for a in attempts if a['pair']==pair}
        if len(arms)!=2 or any(a['exitcode'] for a in arms.values()):paired.append(dict(pair=pair,status='incomplete_pair'));continue
        gredac=arms['GReDAC']['result'];saga=arms['SAGA-author-source@7372111']['result'];values={}
        for key in ('primary_seconds','T_task','T_ready','T_cold','amortized_task_ms','amortized_ready_ms','amortized_cold_ms'):
            x,y=gredac[key],saga[key]
            if x is not None and y is not None:values[key]=dict(GReDAC=x,SAGA=y,delta=x-y,ratio=x/y,relative_delta=(x-y)/y)
        paired.append(dict(pair=pair,status='complete',metrics=values))
    (out/'pairs.json').write_text(json.dumps(paired,indent=2))
    # Every distribution below has one observation per independent run/pair.
    # Request-level p95 is first computed within its own run, never pooled.
    groups={}
    for a in attempts:
        case=a['case'];key=json.dumps({k:v for k,v in case.items() if k!='method'},sort_keys=True)
        groups.setdefault(key,[]).append(a)
    grouped=[]
    for key,items in groups.items():
        for method in dict.fromkeys(a['case']['method'] for a in items):
            arms=[a for a in items if a['case']['method']==method];good=[a['result'] for a in arms if not a['exitcode']]
            metrics={k:stats([r[k] for r in good if r.get(k) is not None]) for k in
                ('T_task','T_ready','T_cold','T_environment','T_identity','T_user_prerequisites','T_with_user_prerequisites','T_end','T_replace_first',
                 'amortized_task_ms','amortized_ready_ms','amortized_cold_ms','delegation_path_ms','final_delegation_ms')}
            phases={p:stats([r['phase_ms'][p] for r in good if r['phase_ms'][p] is not None]) for p in ('I','II','III.first','III.hot','IV')}
            grouped.append(dict(case=json.loads(key),method=method,attempts=len(arms),passed=len(good),metrics=metrics,phases_ms=phases))
    (out/'group_summary.json').write_text(json.dumps(grouped,indent=2))
    lines=['# RQ2 author-source evaluation','',f"Stage: {meta['stage']}; attempts: {len(attempts)}; failed: {sum(a['exitcode']!=0 for a in attempts)}; LLM calls: 0.",'',
        'Official SAGA commit 7372111bea150e32cee390a616849316d2780bfc is executed; historical self-written native_network results are excluded.', '',
        '| Block | Attempts | Successful |','|---|---:|---:|']
    for block in ('flow','dialogue','structure'):
        a=[a for a in attempts if a['case']['block']==block];lines.append(f"| {block} | {len(a)} | {sum(x['exitcode']==0 for x in a)} |")
    lines += ['','## Q2-1: directly measured stage costs','',
        'Values are medians across independent successful runs, in ms. Full task costs are separately measured. N/A is not zero; - means not triggered or no successful observation.','',
        'Infrastructure startup is excluded, not a timed stage. User prerequisites are disclosed separately. Task starts before root Agent preparation; dynamic identities are included in II. SAGA paper describes deactivation; pinned author artifact has no executable interface.', '',
        '| Flow | Method | Passed/attempted | User prerequisites | Root identity | I | II | III first | III hot | IV | T_task | With users | Replacement first |',
        '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    def number(value,scale=1):return '-' if value is None else f"{value['p50']*scale:.3f}"
    for g in grouped:
        if g['case']['block']!='flow':continue
        phases=[('N/A' if g['method']!='GReDAC' and p in ('I','IV') else number(g['phases_ms'][p])) for p in ('I','II','III.first','III.hot','IV')]
        times=[number(g['metrics'][p],1000) for p in ('T_task','T_with_user_prerequisites','T_replace_first')]
        pre=[number(g['metrics'][p],1000) for p in ('T_user_prerequisites','T_identity')]
        lines.append('| '+' | '.join([g['case']['flow'],g['method'],f"{g['passed']}/{g['attempts']}",*pre,*phases,*times])+' |')
    lines += ['','## Q2-2: task amortization','',
        '| N | Method | Passed/attempted | Main T_task/N (ms) | Ready T_ready/N (ms) | Auxiliary T_cold/N (ms) |',
        '|---:|---|---:|---:|---:|---:|']
    for g in grouped:
        if g['case']['block']=='dialogue':
            lines.append('| '+' | '.join([str(g['case']['requests']),g['method'],f"{g['passed']}/{g['attempts']}",
                *[number(g['metrics'][p]) for p in ('amortized_task_ms','amortized_ready_ms','amortized_cold_ms')]])+' |')
    lines += ['','## Interpretation limits','', '- Main amortization: T_task/N, after infrastructure readiness; identity-ready and full cold-start are auxiliary.',
        '- I/II/III-first/III-hot/IV instances are directly measured; native absent guarantees are N/A. Cross-phase replacement is separate.',
        '- runs.csv retains every attempt. pairs.json uses run pairs, never requests, as independent observations. Missing arms are not zero.',
        '- MongoDB native default writeConcern differs from GReDAC SQLite WAL/FULL. This is complete-system cost, not solely GGM cost.',
        '- Actual loopback TCP/TLS only; no WAN claim. Buffered wrappers have overhead; raw CPU and inclusive spans must not be added to end-to-end time.',
        '- No frozen business latency budget was supplied, so this report makes no unconditional acceptable-overhead claim.',
        '- Pilot/regression runs do not constitute formal evidence. Formal failed samples are never replaced.', '', '## Failed attempts', '']
    lines += [f"- {a['directory']}: exit {a['exitcode']}; see original log/manifest." for a in attempts if a['exitcode']] or ['- None.']
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n')
    # Paper curves: descriptive medians and all run points; N=6 is not a
    # distribution-free stability guarantee. Empty/failed groups stay absent.
    plot(root,attempts)


def plot(root,attempts):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    good=[a['result'] for a in attempts if a['exitcode']==0]
    for metric in ('amortized_task_ms','amortized_ready_ms','amortized_cold_ms'):
        fig,ax=plt.subplots()
        for method in ('GReDAC','SAGA-author-source@7372111'):
            rows=[r for r in good if r['block']=='dialogue' and r['method']==method]
            xs=sorted({r['requests'] for r in rows})
            if xs:
                ax.plot(xs,[statistics.median(r[metric] for r in rows if r['requests']==x) for x in xs],marker='o',label=method)
                ax.scatter([r['requests'] for r in rows],[r[metric] for r in rows],alpha=.3,s=12)
        ax.set(xscale='log',xlabel='Business requests N',ylabel=metric.replace('_',' '));ax.grid(alpha=.2)
        if ax.lines:ax.legend()
        fig.tight_layout();fig.savefig(root/'analysis'/(metric+'.png'),dpi=180);plt.close(fig)
    for axis,key in [('depth','depth'),('quota','units'),('fragmentation','cover')]:
        fig,ax=plt.subplots();rows=[r for r in good if r.get('axis')==axis];xs=sorted({r[key] for r in rows})
        for phase in ('II','III.first'):
            if xs:ax.plot(xs,[statistics.median(r['phase_ms'][phase] for r in rows if r[key]==x) for x in xs],marker='o',label=phase)
        ax.set(xscale='log',xlabel=axis,ylabel='Measured stage interval union (ms)');ax.grid(alpha=.2)
        if ax.lines:ax.legend()
        fig.tight_layout();fig.savefig(root/'analysis'/('structure_'+axis+'.png'),dpi=180);plt.close(fig)


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);report(p.parse_args().root)
