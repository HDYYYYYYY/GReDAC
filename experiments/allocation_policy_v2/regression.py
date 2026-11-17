"""Feasibility, paired streams, all-level choices and key-provenance tests.

These are correctness tests, not performance samples. Exhaust all possible A3
sizes/phases for the background bound; replay all frozen instances locally for
selection feasibility. Actual protocol operation is exercised by the six pilot
arms and the existing protocol regressions in the suite.
"""
import argparse,json,os
from pathlib import Path
from .workload import generate,background_layout,source_groups,RANGES
from experiments.allocation_policy.selectors import STRATEGIES,choose


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);os.environ['GREDAC_SLOT_BITS']='15';checks=[]
    from .suite import jobs,PACKAGE,protected_fingerprint
    for split,stage,n in [('formal','full',120),('development','pilot',6)]:
        fixed=json.loads((PACKAGE/(split+'_instances.json')).read_text())
        assert fixed==json.loads(json.dumps(generate(split)))
        cases=jobs(stage);assert len(cases)==n
        for ins in fixed['instances']:
            arms=[c for c in cases if c['instance_id']==ins['instance_id']]
            assert len(arms)==3 and {c['strategy'] for c in arms}==set(STRATEGIES)
            assert all({k:c[k] for k in ins}==ins for c in arms)
            assert all(lo<=v<=hi for v,(lo,hi) in zip(ins['demands'],RANGES))
            streams=[ins['demand_seed'],ins['background_seed'],*ins['selection_seeds']]
            assert len(set(streams))==6
        # Every level uses the chosen strategy; later inputs are its own output.
        for c in cases:
            available=list(range(2048))
            for layer,demand in enumerate(c['demands']):
                if layer==3 and c['background']=='fragmented':
                    events=background_layout(available,c['background_seed'])
                    spent={u for e in events for u in e['consume']}
                    available=sorted(set(available)-spent)
                selected=choose(available,demand,c['strategy'],c['selection_seeds'][layer])
                assert len(set(selected))==len(selected)==demand and set(selected)<=set(available)
                assert choose(available,demand,c['strategy'],c['selection_seeds'][layer])==selected
                available=selected
    checks.append('120_formal_6_independent_pilot_arms_frozen_reproducible_all_levels_feasible')
    assert any(v&(v-1) for c in jobs('full') for v in c['demands'])
    assert not ({c['instance_id'] for c in jobs('full')}&{c['instance_id'] for c in jobs('pilot')})
    checks.append('non_power_two_demands_retained_development_separate')
    for n in range(256,385):
        for seed in range(8):
            # Both dense and isolated absolute IDs use the same rank rule.
            ev=background_layout(range(n),seed);sparse=background_layout([3*i+1 for i in range(n)],seed)
            spent=[u for e in ev for u in e['consume']]
            assert n-len(spent)>=224 and len(spent)==len(set(spent))
            assert sorted(u for e in ev for u in e['units'])==list(range(n))
            for e,s in zip(ev,sparse):
                assert len(e['consume'])==len(e['units'])//8
                assert e['consume_ranks']==s['consume_ranks']
                assert s['consume']==[3*u+1 for u in e['consume']]
    checks.append('all_129_A3_sizes_floor_partition_background_bound_224_rank_invariance')
    # Two adjacent addresses from distinct capabilities must never become one
    # delivered seed. This tests actual unchanged transfer(), not an estimate.
    from gredac.crypto import Bundle,Signer,ident,cover,domain_for
    from gredac.offline import Holding,transfer
    from gredac.storage import position_key
    h=Holding('p',task_info={'endpoint':'G'})
    for unit in [0,1]:
        gid=ident();anchor=ident();domain=domain_for(['query'],[unit])
        h.caps[gid]=dict(gid=gid,source='budget',anchor=anchor,context='c',guard='G',holder_right='p')
        h.bundles[gid]=Bundle.initial(gid,anchor,bytes([unit+1])*32,domain)
        h.records[position_key('budget',unit)]=dict(source='budget',slot=unit,hard_actions=['query'],
            current_cap={'gid':gid},ownership='initial',holder_right='p')
    groups=source_groups(h,[0,1]);assert len(groups)==2
    child,_=transfer(h,'child',{'budget':[0,1]},['query'],Signer('p'))
    assert len(cover(domain_for(['query'],[0,1])))==1
    assert sum(len(b.seeds) for b in child.bundles.values())==2
    assert sum(len(g['address_cover']) for g in groups)==2
    checks.append('actual_transfer_two_parent_capabilities_adjacent_addresses_2_seeds_not_1')
    assert protected_fingerprint()==json.loads((PACKAGE/'protected_baseline.json').read_text())
    checks.append('protected_core_and_v1_and_RQ2_sources_unchanged')
    (a.out/'manifest.json').write_text(json.dumps(dict(status='PASS',tests=checks,llm_calls=0),indent=2))
    print('PASS',len(checks),'v2 checks')


if __name__=='__main__':main()
