"""Read-only validation of both measured RTT layouts. Copied audit routine from
compare_wait_20261117, changing only the explicit expected geographic profile.
No protocol or experiment modules are imported. Original evidence is unchanged.
"""
import argparse,bisect,collections,csv,datetime,json,math,platform,random,statistics,time
from pathlib import Path
import numpy as np
from .model import load_data,path_key,stable_seed,sha

NS=(1,8,32,128,512,2048)
BASE={('UO','Authority','authority_accept'):4,('UR','Authority','authority_accept'):1,
      ('Authority','G','initialize'):1,('Authority','O','initial_receive'):1,
      ('R','O','receive_task_info'):1,('R','S1','install_right'):1,('R','G','endpoint_control'):1,
      ('O','A1','install_right'):1,('O','A1','receive_delegation'):1,
      ('A1','G','endpoint_discover'):1,('A1','S1','prove'):1,('A1','G','sync'):1,
      ('A1','S1','contact_respond'):1,('A1','G','session'):1}
METRICS=('task_per_request_ms','oneoff_ms','oneoff_per_request_ms','oneoff_share',
         'first_request_ms','hot_mean_ms','hot_p50_ms','hot_p95_ms')


def read(path):return json.loads(path.read_text())


def csvwrite(path,rows):
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def med(values):return float(statistics.median(values)) if values else None


def audit_run(root,attempt,public_pools,data,evidence,profile):
    name=attempt['directory'];d=root/name;n=attempt['N'];files=[]
    def recorded(path):files.append(path);return read(path)
    assert attempt['exitcode']==0 and attempt['wait_evidence_ok']
    cfg=recorded(root/(name+'-rtt.json'));assert cfg['profile']==profile
    audit=recorded(d/'protocol_audit.json');business=recorded(d/'business_results.json')
    summary=recorded(d/'summary.json');s=summary['results'][0];run_manifest=recorded(d/'manifest.json')
    assert run_manifest['status']=='PASS' and summary['injected_rtt_wait'] and s['injected_rtt_wait']
    assert audit['audit']=='PASS' and audit['initial_authority_frozen']
    assert audit['new_requests']==n and audit['spent_by_source']=={'budget':n} and audit['delivery_states']=={'delivered':n}
    assert len(business)==n and {x['index'] for x in business}==set(range(n))
    assert all(x['observation'] and x['observation']['assumed_delay_bound_held'] for x in audit['deadline_evidence'])
    assert s['requests']==n and s['issued']==s['units']==2048 and s['depth']==1 and s['slot_bits']==15

    # Build sender/receiver correlation from original raw traces, not from a
    # promise in the batch status. Only finished, immutable run files are read.
    trace=d/'trace.jsonl';files.append(trace);sends={};receives={};events={};scopes=collections.defaultdict(list);pids={}
    for line in trace.open():
        r=json.loads(line);pids.setdefault(r['participant'],set()).add(r['pid'])
        if r['kind']=='event':events.setdefault(r['operation'],[]).append(r['time_ns'])
        elif r['kind']=='span':
            assert r['result']=='ok' and r['end_ns'] is not None
            if r.get('edge')=='send':sends[r['correlation_id']]=r
            if r.get('edge')=='receive':receives[r['correlation_id']]=r
            if r['operation'] in ('contact.establish','first_request','hot_request'):scopes[r['operation']].append(r)
    assert len(pids)==9 and all(len(v)==1 for v in pids.values()) and len(set(next(iter(v)) for v in pids.values()))==9
    start=events['task_participant_prepare_begin'][0];end=events['task_finish'][0]
    contact,first=scopes['contact.establish'][0],scopes['first_request'][0]
    hot=sorted(scopes.get('hot_request',[]),key=lambda r:r['start_ns'])
    assert len(hot)==n-1 and len(events['result_verified'])==n
    assert first['start_ns']<=contact['start_ns']<contact['end_ns']<first['end_ns']
    requests=[dict(start_ns=contact['end_ns'],end_ns=first['end_ns'],thread_cpu_ns=None)]+hot
    assert math.isclose((end-start)/1e6,s['T_task_ms'],abs_tol=1e-6)
    assert math.isclose((contact['end_ns']-start)/1e6,s['T_oneoff_ms'],abs_tol=1e-6)
    durations=np.array([(r['end_ns']-r['start_ns'])/1e6 for r in requests])
    assert math.isclose(durations[0],s['T_first_request_after_contact_ms'],abs_tol=1e-6)
    if n==1:assert s['hot_ms'] is None
    else:
        assert s['hot_ms']['n']==n-1
        for k,val in [('mean',np.mean(durations[1:])),('p50',np.percentile(durations[1:],50)),('p95',np.percentile(durations[1:],95))]:
            assert math.isclose(float(val),s['hot_ms'][k],abs_tol=1e-6)

    raw={};counts=collections.Counter();wait_rows=[]
    for f in sorted((d/'protocol/network/actors').glob('*/rpc-sent.jsonl')):
        files.append(f)
        for line in f.open():
            r=json.loads(line);key=(r['source'],r['target'],r['method']);counts[key]+=1
            raw[f'{key[0]}>{key[1]}:{key[2]}:{counts[key]}']=r
    for f in sorted((d/'protocol/network/actors').glob('*/rtt-waits.jsonl')):
        files.append(f);wait_rows.extend(json.loads(l) for l in f.open())
    expect=collections.Counter(BASE);expect[('A1','G','endpoint_charge')]=n;expect[('G','S1','service_receive')]=n
    assert collections.Counter((r['source'],r['target'],r['method']) for r in wait_rows)==expect
    assert len(wait_rows)==17+2*n
    actual_by_request=np.zeros(n);planned_by_request=np.zeros(n);rpc_cpu=np.zeros(n)
    totals=collections.defaultdict(float);phase_rows=[];rpc_rows=[]
    for r in wait_rows:
        assert r['result']=='ok' and r['task_run']==name
        cid=f'{r["source"]}>{r["target"]}:{r["method"]}:{r["serial"]}'
        sender=sends[cid];receiver=receives[cid];original=raw[cid]
        assert original['outcome']=='ok' and (original['handshake_seconds']>0)==r['new_connection']
        assert start<=sender['start_ns']<=receiver['start_ns']<=receiver['end_ns']<=sender['end_ns']<=end
        key=path_key(r['source'],r['target'],profile,cfg['bindings']);assert r['path']==key
        rtt=r['rtt_seconds'];waits=r['waits']
        if key is None:assert rtt==0 and not waits and r['sample_index'] is None
        else:
            ix=random.Random(stable_seed(cfg['seed'],cfg['run'],r['source'],r['target'],r['method'],r['serial'],key)).randrange(len(public_pools[key]))
            assert ix==r['sample_index'] and math.isclose(rtt,public_pools[key][ix]/1000,abs_tol=1e-12)
            assert math.isclose(rtt,data['pools'][key]['samples'][ix][1]/1000,abs_tol=1e-12)
            parts=(['modeled_tcp_tls_setup'] if r['new_connection'] else [])+['request_half_rtt','reply_half_rtt']
            durations_expected=([2*rtt] if r['new_connection'] else [])+[rtt/2,rtt/2]
            assert [w['part'] for w in waits]==parts
            for w,value in zip(waits,durations_expected):
                assert math.isclose(w['requested_seconds'],value,abs_tol=1e-12)
                assert math.isclose(w['actual_seconds'],(w['end_ns']-w['start_ns'])/1e9,abs_tol=1e-12)
                assert w['actual_seconds']>=value-1e-6
                assert sender['start_ns']<=w['start_ns']<=w['end_ns']<=sender['end_ns']
        requested=sum(w['requested_seconds'] for w in waits)*1000
        actual=sum(w['actual_seconds'] for w in waits)*1000
        if r['method'] in ('endpoint_charge','service_receive'):
            index=r['serial']-1;assert 0<=index<n
            assert requests[index]['start_ns']<=sender['start_ns']<=sender['end_ns']<=requests[index]['end_ns']
            phase='first_request' if index==0 else 'hot_request'
            actual_by_request[index]+=actual;planned_by_request[index]+=requested
            if r['method']=='endpoint_charge':
                assert not r['new_connection'];rpc_cpu[index]=original['thread_cpu_seconds']*1000
            else:assert key is None
        else:
            index=None
            phase='contact' if contact['start_ns']<=sender['start_ns']<=sender['end_ns']<=contact['end_ns'] else 'preparation'
        totals['planned_'+phase]+=requested;totals['actual_'+phase]+=actual
        rpc_rows.append(dict(run=name,N=n,correlation_id=cid,phase=phase,request_index=index,source=r['source'],target=r['target'],operation=r['method'],new_connection=r['new_connection'],path=key,sample_index=r['sample_index'],rtt_ms=rtt*1000,planned_wait_ms=requested,actual_wait_ms=actual,sender_ms=(sender['end_ns']-sender['start_ns'])/1e6,send_frame_bytes=original['sent_frame_bytes'],reply_frame_bytes=original['received_frame_bytes']))
    actual_total=sum(totals['actual_'+p] for p in ('preparation','contact','first_request','hot_request'))
    planned_total=sum(totals['planned_'+p] for p in ('preparation','contact','first_request','hot_request'))
    assert math.isclose(actual_total,attempt['actual_wait_seconds']*1000,abs_tol=1e-5)
    assert math.isclose(planned_total,attempt['requested_wait_seconds']*1000,abs_tol=1e-5)
    assert np.all(durations>=actual_by_request)
    oneoff_actual=totals['actual_preparation']+totals['actual_contact'];oneoff_planned=totals['planned_preparation']+totals['planned_contact']
    request_rows=[dict(run=name,N=n,index=i,kind='first' if i==0 else 'hot',measured_ms=float(durations[i]),planned_wait_ms=float(planned_by_request[i]),actual_wait_ms=float(actual_by_request[i]),non_wait_residual_ms=float(durations[i]-actual_by_request[i]),caller_rpc_thread_cpu_ms=float(rpc_cpu[i])) for i in range(n)]
    for phase,measured in [('preparation',s['T_preparation_ms']),('contact',s['T_contact_ms']),('first_request',durations[0]),('hot_request',float(durations[1:].sum()))]:
        phase_rows.append(dict(run=name,N=n,phase=phase,measured_inclusive_ms=measured,planned_wait_ms=totals['planned_'+phase],actual_wait_ms=totals['actual_'+phase],non_wait_residual_ms=measured-totals['actual_'+phase]))
    stats=recorded(d/'resources.json');assert len(stats)>=2
    warnings=[];log=root/(name+'.log');files.append(log);text=log.read_text(errors='replace')
    for word in ('Traceback','PermissionError','Exception in thread','WARNING'):
        if word in text:warnings.append(word)
    h=s['hot_ms'];row=dict(run=name,N=n,repeat=attempt['repeat'],profile='injected',kind='measured_with_artificial_wait',
        task_ms=s['T_task_ms'],task_per_request_ms=s['T_task_ms']/n,oneoff_ms=s['T_oneoff_ms'],oneoff_per_request_ms=s['T_oneoff_ms']/n,oneoff_share=s['T_oneoff_ms']/s['T_task_ms'],
        first_request_ms=float(durations[0]),hot_mean_ms=h['mean'] if h else None,hot_p50_ms=h['p50'] if h else None,hot_p95_ms=h['p95'] if h else None,
        actual_wait_ms=actual_total,planned_wait_ms=planned_total,sleep_overshoot_ms=actual_total-planned_total,
        non_wait_task_ms=s['T_task_ms']-actual_total,actual_oneoff_wait_ms=oneoff_actual,planned_oneoff_wait_ms=oneoff_planned,
        non_wait_oneoff_ms=s['T_oneoff_ms']-oneoff_actual,hot_actual_wait_mean_ms=float(actual_by_request[1:].mean()) if n>1 else None,
        hot_planned_wait_mean_ms=float(planned_by_request[1:].mean()) if n>1 else None,
        hot_non_wait_mean_ms=float((durations[1:]-actual_by_request[1:]).mean()) if n>1 else None,
        caller_hot_rpc_cpu_ms=float(rpc_cpu[1:].mean()) if n>1 else None,
        peak_sampled_rss_mib=max(v['sampled_total_rss_kib'] for v in stats)/1024,resource_samples=len(stats),
        resource_monitor_complete=not bool(warnings),
        resource_max_sample_gap_s=max((y['time_ns']-x['time_ns'])/1e9 for x,y in zip(stats,stats[1:])),
        hot_path=f'{cfg["bindings"]["east"]}>{cfg["bindings"]["europe"]}',warnings=';'.join(warnings))
    for f in files:evidence[str(f)]=sha(f)
    return row,request_rows,phase_rows,rpc_rows


def ledger_audit(root,attempt,evidence):
    """Read a temporary DB+WAL copy, leaving immutable original evidence alone."""
    import shutil,sqlite3,tempfile
    folder=root/attempt['directory']/'protocol/network/actors/G'
    paths=sorted(folder.glob('guard.sqlite*'))
    before={str(p):sha(p) for p in paths}
    with tempfile.TemporaryDirectory(prefix='rq2-ledger-audit-') as tmp:
        for p in paths:shutil.copy2(p,Path(tmp)/p.name)
        db=sqlite3.connect((Path(tmp)/'guard.sqlite').as_uri()+'?mode=ro',uri=True)
        try:
            assert db.execute('PRAGMA quick_check').fetchall()==[('ok',)]
            values=lambda kind:[json.loads(r[0]) for r in db.execute('SELECT value FROM records WHERE kind=?',(kind,))]
            positions=values('positions');requests=values('requests');forward=values('forwarding');effects=values('effects')
            n=attempt['N'];assert len(positions)==2048 and len(requests)==len(forward)==len(effects)==n
            states=collections.Counter(v['state'] for v in positions)
            assert states['spent']==n and states['unused']==2048-n
            used=[tuple(s) for r in requests for s in r['decision']['sources']]
            assert len(used)==len(set(used))==n and all(s[0]=='budget' for s in used)
            assert all(not r['decision']['replay'] for r in requests)
            assert all(v['state']=='delivered' for v in forward)
            assert set(used)=={(v['source'],v['slot']) for v in positions if v['state']=='spent'}
        finally:db.close()
    assert before=={str(p):sha(p) for p in paths}
    evidence.update(before)
    return dict(run=attempt['directory'],N=n,sqlite_integrity='PASS',positions=2048,spent=n,unused=2048-n,requests=n,deliveries=n,duplicate_units=0,source_files_unchanged=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('west','asia','data','estimate','out'):p.add_argument('--'+k,type=Path,required=True)
    a=p.parse_args();assert not a.out.exists();a.out.mkdir(parents=True)
    data,freeze=load_data(a.data);manifests={k:read(getattr(a,k)/'manifest.json') for k in ('west','asia')}
    mw,ma=manifests['west'],manifests['asia']
    assert mw['source_freeze']==ma['source_freeze'] and mw['plan']==ma['plan']
    assert mw['dataset_freeze_sha256']==ma['dataset_freeze_sha256']==sha(a.data/'FREEZE.json')
    rows=[];requests=[];phases=[];rpcs=[];ledgers=[];evidence={};errors=[]
    batchmeta={}
    for layout,profile in [('west','distributed'),('asia','authority_asia')]:
        root=getattr(a,layout);m=manifests[layout]
        assert m['status']=='PASS' and m['profile']==profile and m['injected_wait'] and m['llm_calls']==0
        assert len(m['attempts'])==36 and collections.Counter(x['N'] for x in m['attempts'])=={n:6 for n in NS}
        assert all({x['repeat'] for x in m['attempts'] if x['N']==n}==set(range(6)) for n in NS)
        assert sha(root/'runtime-samples.json')==m['runtime_samples_sha256']
        pools=read(root/'runtime-samples.json');assert set(pools)==set(data['pools'])
        for key,values in pools.items():assert values==[s[1] for s in data['pools'][key]['samples']]
        for rel,digest in m['source_freeze']['files_sha256'].items():assert sha(root/'source'/rel)==digest
        evidence[str(root/'manifest.json')]=sha(root/'manifest.json')
        evidence[str(root/'runtime-samples.json')]=sha(root/'runtime-samples.json')
        for attempt in m['attempts']:
            try:
                row,rr,pr,rp=audit_run(root,attempt,pools,data,evidence,profile)
                ledger=ledger_audit(root,attempt,evidence)
                for record in [row,*rr,*pr,*rp,ledger]:record['layout']=layout;record['profile']=profile
                rows.append(row);requests+=rr;phases+=pr;rpcs+=rp;ledgers.append(ledger)
                assert len(read(root/attempt['directory']/'protocol_audit.json')['deadline_evidence'])==attempt['N']
                print('AUDIT',layout,attempt['directory'],'PASS',flush=True)
            except Exception as exc:
                import traceback
                errors.append(dict(layout=layout,run=attempt['directory'],error=repr(exc),traceback=traceback.format_exc()))
        batchmeta[layout]=dict(batch=str(root.resolve()),completed=36,business_requests=16374,role_rpcs=33360,
            elapsed_seconds=m['ended_unix']-m['started_unix'],source_files_verified=len(m['source_freeze']['files_sha256']))
    if errors:
        (a.out/'AUDIT_FAILURE.json').write_text(json.dumps(errors,indent=2)+'\n');raise SystemExit('Audit failed; originals retained')
    assert len(rows)==72 and len(requests)==32748 and len(rpcs)==66720 and len(ledgers)==72
    # The same task order and independent link streams make non-Authority
    # requested waits exactly comparable; actual execution times can differ.
    by_rpc={(r['layout'],r['run'],r['correlation_id']):r for r in rpcs}
    paired=[]
    for rw in [r for r in rows if r['layout']=='west']:
        ra=next(r for r in rows if r['layout']=='asia' and r['run']==rw['run'])
        cw=read(a.west/(rw['run']+'-rtt.json'));ca=read(a.asia/(rw['run']+'-rtt.json'))
        assert (rw['N'],rw['repeat'],cw['seed'],cw['bindings'])==(ra['N'],ra['repeat'],ca['seed'],ca['bindings'])
        wr=[r for r in rpcs if r['layout']=='west' and r['run']==rw['run']]
        unchanged=0
        for r in wr:
            other=by_rpc['asia',r['run'],r['correlation_id']]
            if 'Authority' not in (r['source'],r['target']):
                for key in ('path','sample_index','rtt_ms','planned_wait_ms','new_connection'):assert r[key]==other[key],(r['run'],key)
                unchanged+=1
        paired.append(dict(run=rw['run'],N=rw['N'],repeat=rw['repeat'],non_authority_rpc_waits_identical=unchanged,
            task_per_request_difference_ms=ra['task_per_request_ms']-rw['task_per_request_ms'],
            oneoff_difference_ms=ra['oneoff_ms']-rw['oneoff_ms'],
            hot_mean_difference_ms=None if rw['hot_mean_ms'] is None else ra['hot_mean_ms']-rw['hot_mean_ms']))
    metrics=METRICS+('actual_wait_ms','non_wait_task_ms','hot_actual_wait_mean_ms','hot_non_wait_mean_ms','sleep_overshoot_ms')
    summary=[]
    for layout in ('west','asia'):
        for n in NS:
            rs=[r for r in rows if r['layout']==layout and r['N']==n]
            s=dict(layout=layout,N=n,independent_runs=6,kind='measured_with_artificial_wait')
            for k in metrics:
                vals=[r[k] for r in rs if r[k] is not None]
                s[k]=med(vals);s[k+'_min']=min(vals) if vals else None;s[k+'_max']=max(vals) if vals else None
            summary.append(s)
    for name,records in [('runs',rows),('figure_points',rows),('summary',summary),('requests',requests),('phase_breakdown',phases),('rpc_evidence',rpcs),('ledger_audit',ledgers),('paired_layouts',paired)]:csvwrite(a.out/(name+'.csv'),records)
    prior={int(r['N']):r for r in csv.DictReader((a.estimate/'summary.csv').open()) if r['profile']=='authority_asia'}
    diagnostic=[]
    for s in summary:
        if s['layout']=='asia':
            estimate=float(prior[s['N']]['task_per_request_ms'])
            diagnostic.append(dict(N=s['N'],historical_asia_estimate_ms=estimate,asia_injected_measured_ms=s['task_per_request_ms'],difference_percent=100*(s['task_per_request_ms']/estimate-1)))
    csvwrite(a.out/'historical_estimate_diagnostic.csv',diagnostic)
    warnings=[dict(layout=r['layout'],run=r['run'],N=r['N'],warning=r['warnings']) for r in rows if r['warnings']]
    manifest=dict(status='PASS',batches=batchmeta,formal_measured_runs=72,business_requests=32748,role_rpcs=66720,
        observations='No observed authorization, spend, delivery or deadline-bound failure',
        independent_sqlite_audits=72,warning_runs=warnings,input_sha256=evidence,
        driver_and_dataset_equal=True,unchanged_link_samples_equal=True,new_experiments_started=0,llm_calls=0,
        source_sha256=sha(Path(__file__)),current_curves='both measured with artificial RTT waits',
        measurement_limit='single-server TCP/TLS with injected propagation waits; not WAN deployment; batches ran at different times')
    (a.out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    make_figure(a.out,rows,summary)
    make_report(a.out,summary,manifest,diagnostic)
    print(json.dumps(dict(status='PASS',out=str(a.out),measured_tasks=72,warnings=warnings,summary=[{k:s[k] for k in ('layout','N','task_per_request_ms','oneoff_ms','hot_mean_ms')} for s in summary])),flush=True)


def make_figure(out,rows,summary):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,ax=plt.subplots(figsize=(8.6,5.8));fig.subplots_adjust(left=.12,right=.97,bottom=.20,top=.79)
    for layout,color,marker,label in [('asia','#cf7a30','v','Authority in Asia: measured with RTT waits'),('west','#8d4393','s','Authority in West US: measured with RTT waits')]:
        rs=[r for r in summary if r['layout']==layout];rr=[r for r in rows if r['layout']==layout]
        ax.plot([r['N'] for r in rs],[r['task_per_request_ms'] for r in rs],color=color,marker=marker,linestyle='-',linewidth=1.8,markersize=5,label=label)
        ax.scatter([r['N'] for r in rr],[r['task_per_request_ms'] for r in rr],color=color,marker=marker,s=16,alpha=.45)
    ax.set(xscale='log',yscale='log',xlabel='Business requests N',ylabel='Total task cost / N (ms)')
    ax.set_xticks(NS,labels=list(map(str,NS)));ax.grid(which='both',alpha=.18)
    ax.legend(loc='upper right',fontsize=8.5,framealpha=.93)
    fig.suptitle('RQ2: long-dialogue amortization',y=.97,fontsize=14)
    fig.text(.54,.90,'Six independent tasks per N and layout; curves show medians',ha='center',fontsize=9)
    fig.text(.54,.845,'O: West US   |   A1: East US   |   B + service team: Europe',ha='center',fontsize=9)
    fig.text(.54,.08,'Both curves: measured loopback TCP/TLS with artificial RTT waits, not WAN deployment.\nIdentical non-Authority wait samples; layouts executed in separate batches.',ha='center',fontsize=8.5)
    for ext in ('png','pdf','svg'):fig.savefig(out/('rq2_rtt_total_cost.'+ext),dpi=190)
    plt.close(fig)


def make_report(out,summary,manifest,diagnostic):
    by={(r['layout'],r['N']):r for r in summary}
    lines=['# RQ2第二组：两种Authority布局的注入等待实测','',
        '本次将Authority亚洲布局的历史估算曲线替换为新完成36次实测。美西布局原36次不变，现共72次独立任务；每种布局、每个N六次，两个布局分别统计。所有曲线均来自实际执行的同机TCP/TLS与抽样RTT等待，不是实际跨地域部署。没有重跑实验或更改协议。','',
        '![总成本摊销](rq2_rtt_total_cost.png)','',
        '- 橙色实线/下三角：Authority亚洲布局注入等待后的实测。',
        '- 紫色实线/方形：Authority美西布局注入等待后的实测。',
        '- 单面板；不恢复绿色本地、蓝色估算或右侧准备成本图。全部独立任务显示为小点，折线连接各N的任务中位数。','',
        '## 设置与可比性','',
        '初始2048单位，N=1/8/32/128/512/2048。调用根美西、子Agent美东、B和服务团队欧洲；只改变Authority的地域映射。两个批次的196份冻结源码、数据冻结、需求顺序、随机种子及端点绑定一致；逐条核实所有不涉及Authority的RPC所请求的RTT等待和连接标记相同。真实处理时间、调度及睡眠超时仍可能随运行时段不同而变化，因此不把所有时间差归因于Authority位置。','',
        '主计时排除基础设施启动，包含任务身份准备、授权、委派、首次联系、请求和收尾。新TCP/TLS连接的额外传播时间仍采用2RTT近似；不模拟带宽、拥塞或丢包。','',
        '## 每请求总成本（ms，六次任务中位数）','',
        '|N|美西Authority实测|亚洲Authority实测|','|---:|---:|---:|']
    for n in NS:lines.append(f"|{n}|{by['west',n]['task_per_request_ms']:.2f}|{by['asia',n]['task_per_request_ms']:.2f}|")
    w=by['west',2048];a=by['asia',2048]
    lines+=['',f"N=2048时，亚洲布局总成本{a['task_per_request_ms']:.2f}ms/请求，一次性准备分担{a['oneoff_per_request_ms']:.2f}ms/请求，后续请求均值{a['hot_mean_ms']:.2f}ms；美西对应为{w['task_per_request_ms']:.2f}、{w['oneoff_per_request_ms']:.2f}、{w['hot_mean_ms']:.2f}ms。长对话持续摊薄准备成本，后续请求仍承担通信、认证及核销；后续路径未发现Authority或父Agent调用。",'',
        '## 完整性与异常','',
        '两个批次各36/36通过。分别核验16,374次业务请求及33,360条角色RPC，合计32,748次请求、66,720条RPC；9个参与方为独立进程。重新从真实起止时间复算任务、首次和后续请求统计，逐条验证RTT样本索引、发送/接收关联及等待拆分。',
        '另在临时副本中打开每次运行的SQLite及WAL，72次数据库完整性、2048单位守恒、唯一核销及交付计数核验通过；原数据库字节未改变。未发现授权、核销、交付或记录中的提交时限失败。','']
    for r in manifest['warning_runs']:lines.append(f"- {r['layout']} / {r['run']}（N={r['N']}）：{r['warning']}。后台资源采样不完整；业务、账本和独立计时核验通过，样本保留。")
    lines+=['','## 历史估算与数据保存','',
        '历史亚洲估算只在 `historical_estimate_diagnostic.csv` 中保留用于诊断，不出现在当前主图，不与新实测混池。此前橙色估算版图表和所有历史原始结果保留。',
        '`runs.csv`共72行，显式记录layout；requests/rpc_evidence/phase_breakdown逐条分布局记录。`paired_layouts.csv`按相同需求和随机设置对应两批任务；它不是同时段随机交错试验。完整原始数据在 `../raw/` 两个独立批次目录，来源及校验见本组README与SOURCE_INDEX。',
        '未冻结业务时延预算，不宣称普遍可接受。每个N每布局只有六次任务，不能把请求或RTT抽样次数当作独立重复。']
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n')
    (out/'EVALUATION_SUPPLEMENT.md').write_text(f'''# RQ2长对话结果（两种布局均为注入等待实测）

我们以固定2048单位运行六种对话长度，每种布局每种长度六次，共72次任务。O、A1、服务团队及B分别映射到美西、美东和欧洲，Authority分别映射到美西与亚洲；在独立进程的同机TCP/TLS通信中注入冻结RIPE Atlas样本的RTT等待。两个布局保持源码、业务请求、端点绑定及非Authority链路的请求等待样本一致，分别统计。

两批各36次均完成，合计32,748条请求的核销与交付通过核验。N=2048时，亚洲布局总成本为{a['task_per_request_ms']:.2f}ms/请求，一次性成本分担{a['oneoff_per_request_ms']:.2f}ms，后续请求均值{a['hot_mean_ms']:.2f}ms；美西对应为{w['task_per_request_ms']:.2f}、{w['oneoff_per_request_ms']:.2f}及{w['hot_mean_ms']:.2f}ms。这说明一次性准备可被持续交互摊薄，逐请求通信与核销成本仍然存在。Authority不在后续请求路径上。

图中橙线和紫线均为注入等待后的实测。两批在不同时段运行，观察差异包含系统噪声；这不是实际跨地域网络测试，不模拟带宽和丢包。资源采样权限异常的原始日志保留，业务及计时证据完整；无预设业务预算，不声称普遍可接受。
''')


if __name__=='__main__':main()

