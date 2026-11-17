"""Offline audit/analysis, never consulted by the allocation decision.

Timing columns retain their inclusion relationships: delivery includes child
verification, first contact includes sync, transfer includes GGM derivation.
Paired savings use background+repeat, not pooled requests or ratio-of-medians.
"""
import csv,json,sqlite3,statistics
from collections import Counter
from pathlib import Path
from experiments.rq2_v2 import timing
from experiments.rq2_v2.results import stats,union_ns
from .selectors import expected_free,STRATEGIES

METRICS=('cover_count','secret_bytes','complete_request_bytes','complete_framed_bytes','delivery_roundtrip_bytes',
    'selection_ms','legal_view_ms','preparation_ms','background_ms','final_identity_authorization_ms',
    'derivation_ms','ggm_ms','delivery_ms','verification_ms','sync_ms','B_sync_ms','contact_ms',
    'first_use_ms','hot_mean_ms','final_9_requests_ms','allocation_and_use_ms','task_ms')


def summarize(out,cfg):
    from gredac.crypto import domain_for,cover
    from experiments.rq2_v2.business import verify
    rows=timing.normalize(timing.load(out/'timing'))
    (out/'trace.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
    spans=[r for r in rows if r['kind']=='span'];byid={r['span_id']:r for r in spans}
    assert all(r['end_ns'] is not None and r['result']=='ok' for r in spans)
    assert len({r['host_id'] for r in rows})==1
    def named(name):return [r for r in spans if r['operation']==name]
    def only(found):
        assert len(found)==1,(len(found),[r['operation'] for r in found]);return found[0]
    def ms(r):return (r['end_ns']-r['start_ns'])/1e6
    def children(parent,name):
        def belongs(r):
            seen=set();pid=r.get('parent_span_id')
            while pid in byid and pid not in seen:
                if pid==parent['span_id']:return True
                seen.add(pid);pid=byid[pid].get('parent_span_id')
            return False
        return [r for r in named(name) if belongs(r)]
    allocation=only(named('final_selection_and_delegation'));identity=only(named('final_identity_authorization'))
    use=only(named('final_contact_and_requests'))
    choice=only(children(allocation,'allocation.choose'))
    legal=only(children(allocation,'allocation.legal_local_view'))
    transfer=only(children(allocation,'gredac.offline.transfer'))
    derived=only(children(allocation,'Bundle.child'))
    received=only(children(allocation,'gredac.offline.receive_delegation'))
    delivery=only(children(allocation,'rpc.call.receive_delegation'))
    auth=only(children(identity,'rpc.call.install_right'))
    sync=only(children(use,'rpc.call.sync'));B_sync=only(children(use,'Endpoint.sync'))
    contact=only(children(use,'contact.establish'));first=only(children(use,'first_request'))
    hot=children(use,'hot_request');assert len(hot)==8
    def encoded(call):
        return only([r for r in children(call,'rpc.encode') if r['participant']==call['participant']])['serialized_bytes']
    auth_bytes,transfer_bytes=encoded(auth),encoded(delivery)
    a=json.loads((out/'allocation.json').read_text());picked=a['selected'];available=a['available']
    assert available==expected_free(cfg['background'],cfg['repeat'],cfg['development'])
    assert len(picked)==len(set(picked))==256 and set(picked)<=set(available)
    assert a['available_after']==sorted(set(available)-set(picked))
    prefixes=cover(domain_for(['query'],picked));secrets=32*len(prefixes)
    assert transfer['seed_secret_bytes']==received['seed_secret_bytes']==derived['seed_secret_bytes']==secrets
    assert derived['cover']==list(prefixes) and a['algorithm_ns']==choice['end_ns']-choice['start_ns']
    # Independently compare measured full request bytes to actual RPC framing.
    sent=[json.loads(x) for x in (out/'protocol/network/actors/A3/rpc-sent.jsonl').read_text().splitlines()]
    messages=[r for r in sent if r['target']=='A4' and r['method'] in ('install_right','receive_delegation')]
    assert len(messages)==2 and all(r['outcome']=='ok' for r in messages)
    frame_bytes=sum(r['sent_frame_bytes'] for r in messages)
    assert frame_bytes==auth_bytes+transfer_bytes+8
    roundtrip_bytes=sum(r['sent_frame_bytes']+r['received_frame_bytes'] for r in messages)
    n=9+(128 if cfg['background']=='fragmented' else 0)
    audit=json.loads((out/'protocol_audit.json').read_text())
    assert audit['audit']=='PASS' and audit['new_requests']==n and audit['initial_authority_frozen']
    receipts=json.loads((out/'business_results.json').read_text())
    assert len(receipts)==len({r['index'] for r in receipts})==n
    for r in receipts:verify(r['index'],r['result'])
    final=[r for r in receipts if r['index']>=n-9]
    assert [r['slot'] for r in final]==picked[:9]
    # Actors have closed before this read. It provides evidence only.
    dbpath=out/'protocol/network/actors/G/guard.sqlite'
    with sqlite3.connect(dbpath.resolve().as_uri()+'?mode=ro',uri=True) as db:
        assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        positions=[json.loads(v[0]) for v in db.execute("SELECT value FROM records WHERE kind='positions'")]
        revocations=[json.loads(v[0]) for v in db.execute("SELECT value FROM records WHERE kind='revoked'")]
    counts=Counter(r['state'] for r in positions)
    assert len(positions)==1024 and counts['spent']==n and counts['unused']==1024-n
    assert {r['slot'] for r in positions if r['holder_right']=='A4-c'}==set(picked)
    assert {r['slot'] for r in positions if r['holder_right']=='A3-c' and r['state']=='unused'}==set(available)-set(picked)
    assert len(revocations)==(4 if cfg['background']=='fragmented' else 0)
    bg=json.loads((out/'background.json').read_text())
    assert len(bg['events'])==len(revocations) and bg['requests']==n-9
    service_events=[json.loads(x) for x in (out/'protocol/network/actors/S1/events.jsonl').read_text().splitlines()]
    assert sum(r['kind']=='business_handler_started' for r in service_events)==n
    processes=json.loads((out/'protocol/network/processes.json').read_text())
    roles=processes['roles'];assert len({v['pid'] for v in roles.values()})==len(roles)
    assert a['pid']==roles['A3']['pid'] and a['pid']!=roles['Driver']['pid']
    events={r['operation']:r['time_ns'] for r in rows if r['kind']=='event'}
    observed=[e['observation'] for e in audit['deadline_evidence'] if e['observation']]
    record=dict(status='PASS',positions=dict(counts),new_requests=n,final_requests=9,
        background_requests=n-9,revocations=len(revocations),same_scope_and_local_no_overlap=True,
        actual_message_bytes_match=True,role_processes=len(roles),parent_selection_pid=a['pid'],
        deadline_bound_violations=sum(not e.get('assumed_delay_bound_held',True) for e in observed))
    (out/'allocation_audit.json').write_text(json.dumps(record,indent=2))
    result=dict(**cfg,cover_count=len(prefixes),secret_bytes=secrets,
        authorization_request_bytes=auth_bytes,transfer_request_bytes=transfer_bytes,
        complete_request_bytes=auth_bytes+transfer_bytes,complete_framed_bytes=frame_bytes,
        delivery_roundtrip_bytes=roundtrip_bytes,selection_ms=ms(choice),legal_view_ms=ms(legal),
        preparation_ms=ms(only(named('baseline_preparation'))),background_ms=ms(only(named('background_construction'))),
        final_identity_authorization_ms=ms(identity),derivation_ms=ms(transfer),ggm_ms=ms(derived),
        delivery_ms=ms(delivery),verification_ms=ms(received),sync_ms=ms(sync),B_sync_ms=ms(B_sync),
        contact_ms=ms(contact),first_use_ms=ms(first),hot_mean_ms=stats([ms(r) for r in hot])['mean'],
        final_9_requests_ms=ms(use),allocation_and_use_ms=(use['end_ns']-identity['start_ns'])/1e6,
        task_ms=(events['task_end']-events['task_begin'])/1e6,
        available_count=len(available),available_digest=a['available_digest'],selected_digest=a['selected_digest'],
        audit=record,measurement_scope='real single-host independent-process TCP/TLS; physical monotonic ns; WAL/FULL')
    (out/'metric_definitions.json').write_text(json.dumps(dict(
        selection='parent-local choose call, including list validation/sort, strategy construction and selection; excludes legal view/RPC',
        legal_view='filter parent holding using local claims and verified returns; no B read',
        material='actual encoded install_right + receive_delegation requests, complete contents and RPC envelopes, excludes responses and TLS; framed bytes add 4 per message',
        intervals='background/construction and final selection are separate; transfer includes GGM and signing, delivery includes child verification, contact includes sync; never sum inclusive columns',
        statistics='independent paired triples by background/repeat; request samples not independent repetitions'),indent=2))
    return result


def report(root):
    meta=json.loads((root/'manifest.json').read_text());attempts=meta['attempts'];out=root/'analysis';out.mkdir(exist_ok=True)
    rows=[];triples={}
    for a in attempts:
        c=a['case'];r=a.get('result',{})
        rows.append(dict(run=a['directory'],exitcode=a['exitcode'],**c,**{k:r.get(k) for k in METRICS}))
        triples.setdefault((c['background'],c['repeat']),{})[c['strategy']]=a
    with (out/'runs.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,list(dict.fromkeys(k for r in rows for k in r)));w.writeheader();w.writerows(rows)
    paired=[];groups=[]
    for (background,rep),arms in triples.items():
        good={s:a['result'] for s,a in arms.items() if a['exitcode']==0}
        if len(good)==3:
            assert len({r['available_digest'] for r in good.values()})==1,'unmatched legal sets'
            assert len({r['seed'] for r in good.values()})==1
        for ref in ('random','dispersed'):
            ok='subtree' in good and ref in good
            if ok:assert good['subtree']['available_digest']==good[ref]['available_digest']
            savings={k:1-good['subtree'][k]/good[ref][k] for k in METRICS if ok and good[ref][k]>0}
            paired.append(dict(background=background,repeat=rep,reference=ref,status='complete' if ok else 'unavailable',
                savings_fraction=savings,definition='1 - subtree/reference, matched independent runs; negative means slower/larger'))
    for bg in ('whole','fragmented'):
        for policy in STRATEGIES:
            arms=[a for a in attempts if a['case']['background']==bg and a['case']['strategy']==policy]
            good=[a['result'] for a in arms if a['exitcode']==0]
            groups.append(dict(background=bg,strategy=policy,attempts=len(arms),passed=len(good),
                metrics={k:stats([r[k] for r in good]) for k in METRICS}))
    (out/'group_summary.json').write_text(json.dumps(groups,indent=2))
    (out/'paired_savings.json').write_text(json.dumps(paired,indent=2))
    def number(g,k):
        v=g['metrics'][k];return 'N/A' if v is None else f"{v['p50']:.3f}"
    lines=['# 完整子树优先：独立实验结果','',
        f"阶段：{meta['stage']}；已执行 {len(attempts)}/{meta['planned']} 次；通过 {sum(a['exitcode']==0 for a in attempts)} 次；失败 {sum(a['exitcode']!=0 for a in attempts)} 次；LLM调用0。",'',
        '表格为独立运行指标的中位数；原始5点见CSV及图。一次运行内请求不作为独立重复。', '',
        '| 背景 | 策略 | 通过/执行 | 覆盖数 | 秘密B | 完整请求B | 选择ms | 派生ms | 交付往返ms | 首次同步ms |',
        '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for g in groups:
        lines.append('| '+' | '.join([g['background'],g['strategy'],f"{g['passed']}/{g['attempts']}",
            *[number(g,k) for k in ('cover_count','secret_bytes','complete_request_bytes','selection_ms','derivation_ms','delivery_ms','sync_ms')]])+' |')
    lines+=['','## 对应背景内的配对节省率','',
        '每个重复先算1−subtree/reference，再取5个配对比例中位数；负值表示变慢/变大，不用中位数之比替代。', '',
        '| 背景 | 参照 | 完整配对 | 秘密节省 | 完整请求节省 | 派生时间节省 | 交付时间节省 | 同步时间节省 |',
        '|---|---|---:|---:|---:|---:|---:|---:|']
    for bg in ('whole','fragmented'):
        for ref in ('random','dispersed'):
            good=[r for r in paired if r['background']==bg and r['reference']==ref and r['status']=='complete']
            values=[]
            for k in ('secret_bytes','complete_request_bytes','derivation_ms','delivery_ms','sync_ms'):
                v=[r['savings_fraction'][k] for r in good if k in r['savings_fraction']]
                values.append('N/A' if not v else f'{100*statistics.median(v):.2f}%')
            lines.append('| '+' | '.join([bg,ref,str(len(good)),*values])+' |')
    lines+=['','## 分配算法开销与背景成本','',
        '| 背景 | 策略 | 合法集合构造ms | 纯选择ms | 背景构造ms | 最终身份/授权ms | 分配至9请求结束ms |',
        '|---|---|---:|---:|---:|---:|---:|']
    for g in groups:
        lines.append('| '+' | '.join([g['background'],g['strategy'],*[number(g,k) for k in
            ('legal_view_ms','selection_ms','background_ms','final_identity_authorization_ms','allocation_and_use_ms')]])+' |')
    lines+=['','## 口径和限制','',
        '- 全部三臂从父Agent本地状态选取，未读取B账本作决策。转出单位保持本地占用，只有原receive_return验签成功的单位解除；背景不是直接写数据库。',
        '- whole为1024未用单位；fragmented由四支各256委派、各32消费、撤销及224合法返还得到896可用。该确定性背景保留8棵64单位完整子树，不代表所有碎片形状。',
        '- dispersed为人为分散压力参照，不声称数学最坏情况。subtree不改变权限、请求、密码结构或持久化；所有协议检查仍执行。',
        '- 秘密B仅为32B×实际种子数；完整请求B为最后一层授权及转移两条完整编码请求，含RPC封装，不含响应/TLS开销或全流程流量。真实帧头和往返字节另存。',
        '- 派生包含GGM/签名；交付往返包含子方验证；联系包含同步。不可把包含关系重复相加。准备、背景、合法集合构造与选择本体分开记录。',
        '- 时间包含同机TCP/TLS、存储和调度，非纯密码速度或WAN指标。每背景5个独立三元组，不能由字节减少直接推出时间同幅改善；负收益保留。',
        '- 初始前三层范围相同，最终只有选择策略变化。每臂新环境、相同背景事件和种子，顺序预先轮换；5次重复无法做到六排列完全平衡。',
        '- 所有失败保留，不补跑替换；正式代码/参数不因结果调整。背景消费与最终9次消费分别审计。开发验证与正式结果不混池。','', '## 失败', '']
    lines += [f"- {a['directory']}: exit {a['exitcode']}；保留原log/manifest。" for a in attempts if a['exitcode']] or ['- 无。']
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    plot(out,attempts)


def plot(out,attempts):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    good=[a['result'] for a in attempts if a['exitcode']==0]
    panels=[('materials',[('secret_bytes','Secret material (B)'),('complete_request_bytes','Full delivery requests (B)')]),
        ('timings',[('selection_ms','Selector (ms)'),('derivation_ms','Derive + descriptor (ms)'),
                    ('delivery_ms','Delivery round trip (ms)'),('sync_ms','First sync (ms)')])]
    colors=['#3478b8','#db9341','#888888']
    for name,metrics in panels:
        fig,axes=plt.subplots(2,len(metrics),figsize=(4*len(metrics),6),squeeze=False)
        for row,bg in enumerate(('whole','fragmented')):
            for col,(metric,label) in enumerate(metrics):
                ax=axes[row,col]
                for i,policy in enumerate(STRATEGIES):
                    values=[r[metric] for r in good if r['background']==bg and r['strategy']==policy]
                    if values:
                        ax.bar(i,statistics.median(values),color=colors[i],alpha=.65,width=.65)
                        offsets=[(j-(len(values)-1)/2)*.055 for j in range(len(values))]
                        ax.scatter([i+v for v in offsets],values,color=colors[i],edgecolor='black',linewidth=.35,s=24,zorder=3)
                ax.set_xticks(range(3),STRATEGIES,rotation=18);ax.set(ylabel=label,title=bg)
                ax.grid(axis='y',alpha=.2)
        fig.suptitle('Median and all independent runs; no request pooling')
        fig.tight_layout();fig.savefig(out/(name+'.png'),dpi=180);fig.savefig(out/(name+'.pdf'));plt.close(fig)


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);report(p.parse_args().root)
