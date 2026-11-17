"""Independent, reproducible streams: demands, per-layer selection, background,
and ordering. No runtime strategy can consume the demand stream. Integer bounds
are inclusive; no power-of-two rounding, rejection sampling or failed replacement.
"""
import hashlib,itertools,json,random
from pathlib import Path
from experiments.allocation_policy.selectors import STRATEGIES

RANGES=((1024,1536),(512,768),(256,384),(64,192))


def seed_for(split,background,index,stream):
    value=f'allocation-v2-20261111|{split}|{background}|{index}|{stream}'
    return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8],'big')


def make_instance(split,background,index):
    demand_seed=seed_for(split,background,index,'demands')
    rng=random.Random(demand_seed)
    return dict(instance_id=f'{split}-{background}-{index:02d}',split=split,background=background,index=index,
        demands=[rng.randint(lo,hi) for lo,hi in RANGES],demand_seed=demand_seed,
        selection_seeds=[seed_for(split,background,index,f'select-{i}') for i in range(1,5)],
        background_seed=seed_for(split,background,index,'background'),issued=2048,depth=4,
        final_requests=9,slot_bits=15,action='query',task='c',endpoint='G')


def generate(split):
    count=20 if split=='formal' else 1
    instances=[make_instance(split,bg,i) for bg in ('whole','fragmented') for i in range(count)]
    order_seed=seed_for(split,'both',0,'instance-order')
    random.Random(order_seed).shuffle(instances)
    permutations=list(itertools.permutations(STRATEGIES))
    counter={'whole':0,'fragmented':0};cases=[]
    for ins in instances:
        bg=ins['background'];position=counter[bg];counter[bg]+=1
        order=permutations[(position+(3 if bg=='fragmented' else 0))%6]
        for strategy in order:cases.append(dict(ins,strategy=strategy,strategy_order=list(order)))
    return dict(schema='allocation-policy-v2-1',split=split,order_seed=order_seed,ranges=RANGES,
        instances=instances,cases=cases)


def background_layout(units,seed):
    """Four contiguous *rank* partitions, floor(m/8) consumed in each branch.

    One uniform phase in [0,7] per branch chooses positions 8*j+phase in its
    complete groups of eight. Incomplete trailing groups are not consumed.
    Absolute addresses are supplied by A3's own legal holding, not the driver.
    """
    units=sorted(units);n=len(units);rng=random.Random(seed);events=[]
    for j in range(4):
        lo,hi=n*j//4,n*(j+1)//4;part=units[lo:hi];phase=rng.randrange(8)
        ranks=[8*t+phase for t in range(len(part)//8)]
        events.append(dict(member=f'H{j}',rank_start=lo,rank_end=hi,phase=phase,
            consume_ranks=ranks,units=part,consume=[part[k] for k in ranks],
            return_count=len(part)-len(ranks)))
    return events


def source_groups(holding,selected):
    """Public unit/capability provenance only; never export a secret seed."""
    from gredac.crypto import cover,domain_for
    from gredac.storage import position_key
    groups={}
    for unit in selected:
        row=holding.records[position_key('budget',unit)];gid=row['current_cap']['gid'];cap=holding.caps[gid]
        key=(cap['source'],cap['anchor'],gid)
        groups.setdefault(key,[]).append(unit)
    return [dict(source=s,anchor=a,parent_gid=g,units=sorted(v),
        address_cover=list(cover(domain_for(['query'],v)))) for (s,a,g),v in sorted(groups.items())]


if __name__=='__main__':
    for split in ('formal','development'):
        p=Path(__file__).parent/(split+'_instances.json')
        assert not p.exists(),'never regenerate a frozen list in place'
        p.write_text(json.dumps(generate(split),indent=2)+'\n')
