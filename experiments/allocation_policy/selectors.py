"""Pure local allocation rules for equivalent units under one fixed action.

No secret, authorization verdict or remote state is cached. The tree is the
dyadic unit-address tree under a fixed action prefix, not a new cryptosystem.
"""
import heapq
import random

STRATEGIES=('subtree','random','dispersed')


def maximal_blocks(units, bits=15):
    """Coalesce exact sibling blocks bottom-up; arbitrary holes remain holes."""
    blocks={(u,1) for u in units}
    for power in range(bits):
        size=1<<power
        for start,n in sorted(blocks.copy()):
            if n==size and start%(2*size)==0 and (start+size,size) in blocks:
                blocks.remove((start,size));blocks.remove((start+size,size))
                blocks.add((start,2*size))
    return sorted(blocks)


def choose(available,count,strategy,seed=0,bits=15):
    values=list(available)
    if len(set(values))!=len(values) or any(type(v) is not int or not 0<=v<2**bits for v in values):
        raise ValueError('invalid/duplicate unit')
    if type(count) is not int or not 0<=count<=len(values):raise ValueError('insufficient units/count')
    if strategy not in STRATEGIES:raise ValueError('unknown strategy')
    values.sort()
    if strategy=='random':return sorted(random.Random(seed).sample(values,count))
    if strategy=='dispersed':
        available=set(values)
        isolated=[u for u in values if (u^1) not in available]
        first=[u for u in values if u%2==0 and u+1 in available]
        second=[u+1 for u in first]
        # One leaf per complete sibling pair cannot merge; exhausted pairs
        # may need a second leaf. This is a stress heuristic, not a worst-case
        # theorem or a policy for non-equivalent semantic/endpoint labels.
        return sorted((isolated+first+second)[:count])
    heap=[(-n,start) for start,n in maximal_blocks(values,bits)]
    heapq.heapify(heap);out=[];remaining=count
    while remaining:
        negative,start=heapq.heappop(heap);size=-negative
        if size>remaining:
            half=size//2
            heapq.heappush(heap,(-half,start));heapq.heappush(heap,(-half,start+half))
        else:
            out.extend(range(start,start+size));remaining-=size
    return sorted(out)


class LocalClaims:
    """Application-local bookkeeping, not a second authoritative ledger.

    Stale parent copies stay excluded after transfer. Only units in a verified
    return release the claim. Unconfirmed/failed transfers are not optimistically
    released. This experiment does not restart caller processes.
    """
    def __init__(self):self.outstanding={}
    def blocked(self,right):return self.outstanding.setdefault(right,set())
    def sent(self,right,units):
        values=list(units)
        if len(set(values))!=len(values) or self.blocked(right)&set(values):raise ValueError('duplicate local allocation')
        self.blocked(right).update(values)
    def returned(self,right,units):
        # Caller invokes this ONLY after original signed-receipt verification.
        self.blocked(right).difference_update(units)


def background_events(repeat,development=False):
    phase=(repeat+(1 if development else 0))%4
    events=[]
    for q in range(4):
        units=list(range(256*q,256*(q+1)))
        spent=[256*q+offset+i for offset in (0,128) for i in range(phase,64,4)]
        events.append(dict(member=f'H{q}',units=units,consume=spent,return_count=224))
    return events


def expected_free(background,repeat,development=False):
    spent={u for e in background_events(repeat,development) for u in e['consume']} if background=='fragmented' else set()
    return sorted(set(range(1024))-spent)
