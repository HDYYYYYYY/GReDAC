"""Offline proof audit and instance-paired analysis; never used for choices.

Four layer intervals are disjoint. Derivation contains GGM and signing, delivery
contains verification, contact contains sync: inclusive diagnostics are never
added together to estimate total time. Actual transfer bundles determine seed
counts, with source/anchor/parent-cap provenance retained separately.
"""
import csv,json,sqlite3,statistics
from collections import Counter
from pathlib import Path
from experiments.rq2_v2 import timing
from experiments.rq2_v2.results import stats,union_ns
from experiments.allocation_policy.selectors import STRATEGIES
from .workload import background_layout

LAYER_METRICS=('demand','available_count','mathematical_cover_count','actual_seed_count','key_source_count',
    'secret_bytes','complete_request_bytes','complete_framed_bytes','delivery_roundtrip_bytes',
    'legal_view_ms','selection_ms','identity_authorization_ms','derivation_ms','ggm_ms',
    'delivery_ms','verification_ms','layer_ms')
SUM_METRICS=('actual_seed_count','secret_bytes','complete_request_bytes','complete_framed_bytes',
    'delivery_roundtrip_bytes','legal_view_ms','selection_ms','identity_authorization_ms',
    'derivation_ms','ggm_ms','delivery_ms','verification_ms')
METRICS=tuple('chain_'+k for k in SUM_METRICS)+('chain_delegation_ms','preparation_ms','background_ms',
    'sync_ms','B_sync_ms','contact_ms','first_use_ms','hot_mean_ms','final_9_requests_ms',
    'chain_and_use_ms','task_ms','task_without_background_ms')


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
    def encoded(call):
        return only([r for r in children(call,'rpc.encode') if r['participant']==call['participant']])['serialized_bytes']
    allocations=json.loads((out/'allocations.json').read_text());assert len(allocations)==4
    bg=json.loads((out/'background.json').read_text());n=bg['requests']+9
    expected_events=background_layout(allocations[2]['selected'],cfg['background_seed']) if cfg['background']=='fragmented' else []
    assert len(bg['events'])==len(expected_events)
    spent=set()
    for e,expected in zip(bg['events'],expected_events):
        assert {k:e[k] for k in expected}==expected
        assert e['returned']==sorted(set(e['units'])-set(e['consume']))
        assert not spent&set(e['consume']);spent.update(e['consume'])
    assert len(spent)==bg['requests']
    materials=json.loads((out/'materials.json').read_text());layers=[]
    processes=json.loads((out/'protocol/network/processes.json').read_text());roles=processes['roles']
    assert len({v['pid'] for v in roles.values()})==len(roles)
    previous=list(range(2048))
    for a in allocations:
        level=a['layer'];parent=('O','A1','A2','A3')[level-1];child=f'A{level}'
        expected=sorted(set(previous)-spent) if level==4 else previous
        assert a['available']==expected and a['demand']==cfg['demands'][level-1]
        picked=a['selected'];assert len(picked)==len(set(picked))==a['demand']
        assert set(picked)<=set(expected) and a['available_after']==sorted(set(expected)-set(picked))
        assert a['pid']==roles[parent]['pid'] and a['pid']!=roles['Driver']['pid']
        outer=only([r for r in named('layer.delegation') if r['layer']==level])
        identity=only(children(outer,'layer.identity_authorization'))
        choice=only(children(outer,'allocation.choose'));legal=only(children(outer,'allocation.legal_local_view'))
        transfer=only(children(outer,'gredac.offline.transfer'))
        derived=children(outer,'Bundle.child');received=only(children(outer,'gredac.offline.receive_delegation'))
        delivery=only(children(outer,'rpc.call.receive_delegation'))
        auth=only(children(identity,'rpc.call.install_right'))
        auth_bytes,transfer_bytes=encoded(auth),encoded(delivery)
        groups=a['key_source_groups'];assert sorted(u for g in groups for u in g['units'])==picked
        assert len({(g['source'],g['anchor'],g['parent_gid']) for g in groups})==len(groups)
        chain=only([m for m in materials if m['participant']==child])['chain']
        body=only([r['body'] for r in chain if r['body'].get('kind')=='transfer' and r['body']['child']==child+'-c'])
        caps=body['caps'];actual=sum(len(c['cover']) for c in caps)
        assert len(caps)==len(groups)==len(derived)
        for group in groups:
            cap=only([c for c in caps if c['source']==group['source'] and c['anchor']==group['anchor'] and c['key_parent']['id']==group['parent_gid']])
            assert cap['domain']==list(domain_for(['query'],group['units']))
            assert cap['cover']==group['address_cover']==list(cover(cap['domain']))
            assert transfer['prefix_cover'][cap['gid']]==cap['cover']
        secrets=32*actual
        assert transfer['seed_secret_bytes']==received['seed_secret_bytes']==sum(r['seed_secret_bytes'] for r in derived)==secrets
        mathematical=len(cover(domain_for(['query'],picked)))
        assert mathematical<=actual
        assert a['algorithm_ns']==choice['end_ns']-choice['start_ns']
        sent=[json.loads(x) for x in (out/f'protocol/network/actors/{parent}/rpc-sent.jsonl').read_text().splitlines()]
        messages=[r for r in sent if r['target']==child and r['method'] in ('install_right','receive_delegation')]
        assert len(messages)==2 and all(r['outcome']=='ok' for r in messages)
        frame_bytes=sum(r['sent_frame_bytes'] for r in messages)
        assert frame_bytes==auth_bytes+transfer_bytes+8
        layers.append(dict(layer=level,demand=a['demand'],available_count=len(expected),
            mathematical_cover_count=mathematical,actual_seed_count=actual,key_source_count=len(groups),
            secret_bytes=secrets,authorization_request_bytes=auth_bytes,transfer_request_bytes=transfer_bytes,
            complete_request_bytes=auth_bytes+transfer_bytes,complete_framed_bytes=frame_bytes,
            delivery_roundtrip_bytes=sum(r['sent_frame_bytes']+r['received_frame_bytes'] for r in messages),
            legal_view_ms=ms(legal),selection_ms=ms(choice),identity_authorization_ms=ms(identity),
            derivation_ms=ms(transfer),ggm_ms=union_ns([(r['start_ns'],r['end_ns']) for r in derived])/1e6,
            delivery_ms=ms(delivery),verification_ms=ms(received),layer_ms=ms(outer),
            key_source_groups=groups,delivered_capabilities=caps,available_digest=a['available_digest'],selected_digest=a['selected_digest']))
        previous=picked
    use=only(named('final_contact_and_requests'));sync=only(children(use,'rpc.call.sync'))
    B_sync=only(children(use,'Endpoint.sync'));contact=only(children(use,'contact.establish'))
    first=only(children(use,'first_request'));hot=children(use,'hot_request');assert len(hot)==8
    audit=json.loads((out/'protocol_audit.json').read_text())
    assert audit['audit']=='PASS' and audit['new_requests']==n and audit['initial_authority_frozen']
    receipts=json.loads((out/'business_results.json').read_text())
    assert len(receipts)==len({r['index'] for r in receipts})==n
    for r in receipts:verify(r['index'],r['result'])
    final=sorted([r for r in receipts if r['index']>=n-9],key=lambda r:r['index'])
    assert [r['slot'] for r in final]==previous[:9]
    assert {r['slot'] for r in receipts if r['index']<n-9}==spent
    # Only after actors stop: independent persisted-state audit, no decisions.
    dbpath=out/'protocol/network/actors/G/guard.sqlite'
    with sqlite3.connect(dbpath.resolve().as_uri()+'?mode=ro',uri=True) as db:
        assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        positions=[json.loads(v[0]) for v in db.execute("SELECT value FROM records WHERE kind='positions'")]
        revocations=[json.loads(v[0]) for v in db.execute("SELECT value FROM records WHERE kind='revoked'")]
    counts=Counter(r['state'] for r in positions)
    assert len(positions)==2048 and counts['spent']==n and counts['unused']==2048-n
    assert {r['slot'] for r in positions if r['holder_right']=='A4-c'}==set(previous)
    # Ownership is an exact partition, including units retained at every level.
    for i,parent in enumerate(('O','A1','A2','A3')):
        expected=set(allocations[i]['available_after'])
        assert {r['slot'] for r in positions if r['holder_right']==parent+'-c' and r['state']=='unused'}==expected
    assert len(revocations)==(4 if cfg['background']=='fragmented' else 0)
    service=[json.loads(x) for x in (out/'protocol/network/actors/S1/events.jsonl').read_text().splitlines()]
    assert sum(r['kind']=='business_handler_started' for r in service)==n
    events={r['operation']:r['time_ns'] for r in rows if r['kind']=='event'}
    observed=[e['observation'] for e in audit['deadline_evidence'] if e['observation']]
    record=dict(status='PASS',positions=dict(counts),new_requests=n,final_requests=9,background_requests=n-9,
        revocations=len(revocations),all_layer_local_choices=True,ownership_partition_correct=True,
        actual_message_bytes_match=True,capability_provenance_verified=True,role_processes=len(roles),
        deadline_bound_violations=sum(not e.get('assumed_delay_bound_held',True) for e in observed))
    (out/'allocation_audit.json').write_text(json.dumps(record,indent=2))
    (out/'layers.json').write_text(json.dumps(layers,indent=2))
    background_ms=ms(only(named('background_construction')))
    task_ms=(events['task_end']-events['task_begin'])/1e6
    chain_ms=sum(r['layer_ms'] for r in layers)
    result=dict(**cfg,layers=layers,**{'chain_'+k:sum(r[k] for r in layers) for k in SUM_METRICS},
        chain_delegation_ms=chain_ms,preparation_ms=ms(only(named('baseline_preparation'))),background_ms=background_ms,
        sync_ms=ms(sync),B_sync_ms=ms(B_sync),contact_ms=ms(contact),first_use_ms=ms(first),
        hot_mean_ms=stats([ms(r) for r in hot])['mean'],final_9_requests_ms=ms(use),
        chain_and_use_ms=chain_ms+ms(use),task_ms=task_ms,task_without_background_ms=task_ms-background_ms,audit=record,
        measurement_scope='single-host independent-process TCP/TLS; physical monotonic ns; WAL/FULL')
    (out/'metric_definitions.json').write_text(json.dumps(dict(
        choice='parent-local eligible-view and choose spans separate; no B private read; cumulative totals include all four choices',
        seeds='actual Bundle.child output and delivered signed caps, by source/anchor/parent gid; mathematical address cover separately',
        material='install_right + receive_delegation full encoded requests, RPC envelopes and repeated ancestry included; excludes responses/TLS, framed adds 4 per message; roundtrip also saved',
        intervals='four directly measured layer spans are disjoint and include identity/selection; GGM nested in derivation, verification nested in delivery, sync nested in contact; do not add inclusive diagnostics',
        totals='chain_and_use=sum four disjoint layer spans + final contact/9-use span; task includes preparation/background/gaps, excludes infrastructure and user prerequisite; task_without_background subtracts measured background interval only',
        statistics='40 independent matched triples, 20 per background; later sets legitimately differ; 9 requests not independent repeats'),indent=2))
    return result


def write_csv(path,rows):
    if not rows:return
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,list(dict.fromkeys(k for r in rows for k in r)));w.writeheader();w.writerows(rows)


def report(root):
    meta=json.loads((root/'manifest.json').read_text());attempts=meta['attempts'];out=root/'analysis';out.mkdir(exist_ok=True)
    flat=[];layer_rows=[];triples={}
    for a in attempts:
        c=a['case'];r=a.get('result',{})
        flat.append(dict(run=a['directory'],exitcode=a['exitcode'],instance=c['instance_id'],background=c['background'],
            strategy=c['strategy'],demands=json.dumps(c['demands']),**{k:r.get(k) for k in METRICS}))
        triples.setdefault(c['instance_id'],{})[c['strategy']]=a
        for layer in r.get('layers',[]):
            layer_rows.append(dict(run=a['directory'],instance=c['instance_id'],background=c['background'],
                strategy=c['strategy'],layer=layer['layer'],**{k:layer[k] for k in LAYER_METRICS}))
    write_csv(out/'runs.csv',flat);write_csv(out/'layers.csv',layer_rows)
    paired=[];groups=[]
    for instance,arms in triples.items():
        good={s:a['result'] for s,a in arms.items() if a['exitcode']==0}
        # Matching applies to demands/rules, not the evolved held address sets.
        assert len({json.dumps({k:a['case'][k] for k in ('demands','demand_seed','selection_seeds','background_seed')},sort_keys=True) for a in arms.values()})==1
        bg=next(iter(arms.values()))['case']['background']
        for ref in ('random','dispersed'):
            ok='subtree' in good and ref in good
            chain={k:1-good['subtree'][k]/good[ref][k] for k in METRICS if ok and good[ref][k]>0}
            perlayer=[]
            if ok:
                for x,y in zip(good['subtree']['layers'],good[ref]['layers']):
                    perlayer.append(dict(layer=x['layer'],savings={k:1-x[k]/y[k] for k in LAYER_METRICS if y[k]>0}))
            paired.append(dict(instance=instance,background=bg,reference=ref,status='complete' if ok else 'unavailable',
                savings_fraction=chain,layers=perlayer))
    for bg in ('whole','fragmented'):
        for policy in STRATEGIES:
            arms=[a for a in attempts if a['case']['background']==bg and a['case']['strategy']==policy]
            good=[a['result'] for a in arms if a['exitcode']==0]
            groups.append(dict(background=bg,strategy=policy,attempts=len(arms),passed=len(good),
                metrics={k:stats([r[k] for r in good]) for k in METRICS},
                layers=[dict(layer=i,metrics={k:stats([r['layers'][i-1][k] for r in good]) for k in LAYER_METRICS}) for i in range(1,5)]))
    (out/'group_summary.json').write_text(json.dumps(groups,indent=2));(out/'paired_savings.json').write_text(json.dumps(paired,indent=2))
    def num(metrics,k):
        v=metrics[k];return 'N/A' if v is None else f"{v['p50']:.3f}"
    lines=['# 递归随机额度分配 v2：实际结果','',
        f"{meta['stage']}：执行{len(attempts)}/{meta['planned']}次，通过{sum(a['exitcode']==0 for a in attempts)}次，失败{sum(a['exitcode']!=0 for a in attempts)}次；LLM调用0。",'',
        '每背景20个独立随机实例，实例内三策略配对。下面是运行级中位数；CSV/图保留全部独立样本，九次请求不作为独立重复。开发结果不混入正式结果。','',
        '## 整条链','',
        '|背景|策略|通过/执行|累计种子|累计秘密B|累计请求B|选择ms|委派链ms|首次同步ms|链+9请求ms|背景ms|任务总ms|',
        '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    keys=('chain_actual_seed_count','chain_secret_bytes','chain_complete_request_bytes','chain_selection_ms',
        'chain_delegation_ms','sync_ms','chain_and_use_ms','background_ms','task_ms')
    for g in groups:lines.append('| '+' | '.join([g['background'],g['strategy'],f"{g['passed']}/{g['attempts']}",*[num(g['metrics'],k) for k in keys]])+' |')
    lines+=['','## 逐层材料与时间','',
        '|背景|策略|层|需求|实际种子|秘密B|完整请求B|合法集合ms|选择ms|派生ms|交付往返ms|整层ms|',
        '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    keys=('demand','actual_seed_count','secret_bytes','complete_request_bytes','legal_view_ms','selection_ms','derivation_ms','delivery_ms','layer_ms')
    for g in groups:
        for layer in g['layers']:lines.append('| '+' | '.join([g['background'],g['strategy'],str(layer['layer']),*[num(layer['metrics'],k) for k in keys]])+' |')
    lines+=['','## 实例配对收益（1−子树优先/参照）','',
        '先在每个实例内计算比例，再取中位数；括号为负收益实例数/完整配对数。不删除负值，不用中位数之比。','',
        '|背景|参照|秘密材料|完整请求|整条委派链时间|链+9请求时间|任务总时间|',
        '|---|---|---:|---:|---:|---:|---:|']
    for bg in ('whole','fragmented'):
        for ref in ('random','dispersed'):
            complete=[p for p in paired if p['background']==bg and p['reference']==ref and p['status']=='complete'];values=[]
            for k in ('chain_secret_bytes','chain_complete_request_bytes','chain_delegation_ms','chain_and_use_ms','task_ms'):
                vals=[p['savings_fraction'][k] for p in complete]
                values.append('N/A' if not vals else f'{100*statistics.median(vals):.2f}% ({sum(v<0 for v in vals)}/{len(vals)})')
            lines.append('| '+' | '.join([bg,ref,*values])+' |')
    lines+=['','## 解释边界','',
        '- 全部四层在父Agent进程中从本地合法状态选择；以原协议执行委派、同步、消费、撤销和验证后返还。未共享账本，离线数据库只在参与方退出后审计。',
        '- 背景按A3集合排序后的四个相对位置分段，每段消费floor(m/8)，每完整8元素块按冻结phase选一项；未满8的尾段不消费。最少剩224，末层需求最多192。',
        '- 同实例需求、背景规则与独立随机流相同，但各层策略造成后续集合不同；此差异是递归累积效应。顺序预先轮换，20不能整除6，因此六排列不完全平衡。',
        '- 种子取实际交付结果并按source/anchor/parent capability核验。数学地址覆盖单列；本单根场景可能恰好相等，不能据此跨来源合并。双来源相邻地址另有正确性回归。',
        '- 秘密字节仅32B×实际种子；完整请求为各层install_right及receive_delegation编码请求，含完整祖先材料/RPC封装，累计重复传输照计；不含响应/TLS。完整帧和往返字节另存，不声称全流程网络流量。',
        '- 四层总时间包含动态身份、合法集合、选择、签发、派生及交付。背景单列；链+9请求为五个不重叠区间之和；task包括准备、背景及间隙，不含基础设施/用户前置。不可将派生/GGM、交付/验证、联系/同步等包含关系重复相加。',
        '- 同机真实TCP/TLS、WAL/FULL及调度成本，非WAN或纯密码速度；记录同期资源，不把中位数称稳定极限。材料节省不保证同幅时间改善。',
        '- 单动作/任务/接收端、四层、给定随机范围与背景，不能外推任意拓扑/需求分布；dispersed只是刻意压力参照。无LLM，未重跑其他性能组。',
        '- 失败保留在120次分母，缺失配对标unavailable，不补跑替换或扩大规模。','', '## 失败','']
    lines += [f"- {a['directory']}: exit {a['exitcode']}，原始日志/manifest保留。" for a in attempts if a['exitcode']] or ['- 无。']
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8');plot(out,attempts,paired)


def plot(out,attempts,paired):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    good=[a['result'] for a in attempts if a['exitcode']==0];colors=['#3478b8','#db9341','#888888']
    panels=[('chain_materials',[('chain_secret_bytes','Cumulative secret bytes'),('chain_complete_request_bytes','Cumulative full request bytes')]),
        ('chain_timings',[('chain_selection_ms','Four selectors (ms)'),('chain_delegation_ms','Four delegations (ms)'),
            ('sync_ms','Final first sync (ms)'),('chain_and_use_ms','Chain + final 9 uses (ms)')])]
    for name,metrics in panels:
        fig,axes=plt.subplots(2,len(metrics),figsize=(4*len(metrics),6.7),squeeze=False)
        for row,bg in enumerate(('whole','fragmented')):
            for col,(metric,label) in enumerate(metrics):
                ax=axes[row,col]
                for i,policy in enumerate(STRATEGIES):
                    values=[r[metric] for r in good if r['background']==bg and r['strategy']==policy]
                    if values:
                        offsets=[(j-(len(values)-1)/2)*.025 for j in range(len(values))]
                        ax.scatter([i+v for v in offsets],values,color=colors[i],edgecolor='black',linewidth=.3,s=20,zorder=3)
                        ax.plot([i-.3,i+.3],[statistics.median(values)]*2,color=colors[i],lw=3)
                ax.set_xticks(range(3),STRATEGIES,rotation=18);ax.set(ylabel=label,title=bg);ax.grid(axis='y',alpha=.2)
        fig.suptitle('All independent instances and medians; no request pooling');fig.tight_layout()
        for ext in ('png','pdf'):fig.savefig(out/(name+'.'+ext),dpi=180)
        plt.close(fig)
    for metric,label,name in [('actual_seed_count','Actual delivered seeds','layer_seeds'),('layer_ms','Full layer (ms)','layer_times')]:
        fig,axes=plt.subplots(2,4,figsize=(15,7),squeeze=False)
        for row,bg in enumerate(('whole','fragmented')):
            for level in range(1,5):
                ax=axes[row,level-1]
                for i,policy in enumerate(STRATEGIES):
                    vals=[r['layers'][level-1] for r in good if r['background']==bg and r['strategy']==policy]
                    ax.scatter([v['demand'] for v in vals],[v[metric] for v in vals],color=colors[i],s=17,alpha=.8,label=policy)
                    if vals:ax.axhline(statistics.median(v[metric] for v in vals),color=colors[i],ls='--',lw=1)
                ax.set(title=f'{bg} L{level}',xlabel='Frozen integer demand',ylabel=label);ax.grid(alpha=.2)
        axes[0,0].legend(fontsize=8);fig.suptitle('Every instance by demand; dashed lines = medians');fig.tight_layout()
        for ext in ('png','pdf'):fig.savefig(out/(name+'.'+ext),dpi=180)
        plt.close(fig)
    fig,axes=plt.subplots(2,3,figsize=(12,6.6),squeeze=False)
    for row,bg in enumerate(('whole','fragmented')):
        for col,k in enumerate(('chain_secret_bytes','chain_complete_request_bytes','chain_and_use_ms')):
            ax=axes[row,col]
            for i,ref in enumerate(('random','dispersed')):
                vals=[100*p['savings_fraction'][k] for p in paired if p['background']==bg and p['reference']==ref and p['status']=='complete']
                ax.scatter([i+(j-(len(vals)-1)/2)*.025 for j in range(len(vals))],vals,color=colors[i+1],s=20)
                if vals:ax.plot([i-.3,i+.3],[statistics.median(vals)]*2,color='black',lw=2)
            ax.axhline(0,color='black',lw=.7);ax.set_xticks([0,1],['vs random','vs dispersed'])
            ax.set(ylabel='Paired savings (%)',title=bg+': '+('secret','full requests','chain + use')[col]);ax.grid(alpha=.2)
    fig.suptitle('1 - subtree/reference; all pairs, negative values retained');fig.tight_layout()
    for ext in ('png','pdf'):fig.savefig(out/('paired_savings.'+ext),dpi=180)
    plt.close(fig)


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);report(p.parse_args().root)
