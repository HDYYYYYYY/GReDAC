"""Policy correctness, local claim accounting, matrix and protection tests."""
import argparse,itertools,json,os,random
from pathlib import Path
from types import SimpleNamespace
from .selectors import STRATEGIES,choose,maximal_blocks,LocalClaims,expected_free,background_events


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);os.environ['GREDAC_SLOT_BITS']='15';checks=[]
    from gredac.crypto import cover,domain_for
    count=0
    # Exhaust small domains for every demand, including empty and exact-full.
    for mask in range(256):
        free=[i for i in range(8) if mask&(1<<i)]
        blocks=maximal_blocks(free,3)
        assert sorted(u for start,n in blocks for u in range(start,start+n))==free
        for n in range(len(free)+1):
            for policy in STRATEGIES:
                got=choose(free,n,policy,71,bits=3)
                assert len(got)==len(set(got))==n and set(got)<=set(free);count+=1
    checks.append(f'exhaustive_8_unit_domains_all_demands_{count}_selections')
    for args in [([1,1],1,'random'),([0,1],3,'subtree'),([-1],1,'dispersed'),([0],-1,'subtree'),([0],1,'unknown')]:
        try:choose(*args)
        except ValueError:pass
        else:raise AssertionError('bad input accepted')
    checks.append('invalid_duplicate_and_insufficient_inputs_rejected')
    for bg in ('whole','fragmented'):
        for rep in range(5):
            free=expected_free(bg,rep);assert len(free)==(1024 if bg=='whole' else 896)
            for policy in STRATEGIES:
                selected=choose(free,256,policy,90601+rep)
                assert len(set(selected))==256 and set(selected)<=set(free)
                c=len(cover(domain_for(['query'],selected)))
                if policy=='subtree':assert c==(1 if bg=='whole' else 4)
                if policy=='dispersed':assert c==256
                assert choose(free,256,policy,90601+rep)==selected
    checks.append('actual_GGM_cover_and_fixed_cardinality_whole_and_fragmented')
    assert choose(list(range(1024)),256,'random',1)!=choose(list(range(1024)),256,'random',2)
    checks.append('uniform_sample_without_replacement_seeded_and_reproducible')
    claims=LocalClaims();claims.sent('p',[1,2,3]);claims.returned('p',[2])
    assert claims.blocked('p')=={1,3};claims.sent('p',[2])
    try:claims.sent('p',[1])
    except ValueError:pass
    else:raise AssertionError('reallocation allowed')
    checks.append('transferred_and_unconfirmed_units_stay_blocked_partial_returns_only')
    from .actor import legal_local
    records={i:dict(slot=i,source='budget',state='unused',owner='A3',holder_right='p',context='c',endpoint='G',
        hard_actions=['query'],hard_contexts=['c'],deadline=20,current_cap={'gid':'g'}) for i in range(8)}
    records[4]['state']='spent';records[5]['deadline']=0;records[6]['owner']='other';records[7]['hard_actions']=[]
    h=SimpleNamespace(records=records,caps={'g':dict(gid='g',holder_right='p',guard='G',context='c')},bundles={'g':object()},uncertain_units=lambda:set())
    node=SimpleNamespace(holdings={'p':h},rights={'p':dict(owner='A3',side='caller',context='c',actions=['query'],deadline=20)},
        name='A3',endpoint_id='G',clock=SimpleNamespace(now=lambda:1),allocation_claims=claims)
    assert legal_local(node,'p')==[0]
    claims.returned('p',[2]);assert legal_local(node,'p')==[0,2]
    checks.append('parent_owned_view_excludes_spent_expired_wrong_owner_wrong_action_outgoing')
    for rep in range(5):
        ev=background_events(rep);assert len(ev)==4
        all_units=[u for e in ev for u in e['units']];spends=[u for e in ev for u in e['consume']]
        assert len(set(all_units))==1024 and len(set(spends))==128
        assert all(len(e['units'])==256 and len(e['consume'])==32 and set(e['consume'])<=set(e['units']) for e in ev)
    checks.append('background_disjoint_256_unit_grants_128_spends_896_returns')
    from .suite import jobs,protected_fingerprint,PACKAGE,fingerprint
    formal=jobs('full');pilot=jobs('pilot')
    assert len(formal)==30 and len(pilot)==6
    for bg in ('whole','fragmented'):
        for rep in range(5):
            arms=[j for j in formal if j['background']==bg and j['repeat']==rep]
            assert len(arms)==3 and {j['strategy'] for j in arms}==set(STRATEGIES) and len({j['seed'] for j in arms})==1
    assert all(c['development'] for c in pilot) and not any(c['development'] for c in formal)
    assert protected_fingerprint()==json.loads((PACKAGE/'protected_baseline.json').read_text())
    checks.append('30_matched_isolated_arms_6_pilots_protected_162_files_unchanged')
    (a.out/'manifest.json').write_text(json.dumps(dict(status='PASS',tests=checks,llm_calls=0),indent=2))
    print('PASS',len(checks),'allocation checks')


if __name__=='__main__':main()
