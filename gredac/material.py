"""Lossless research wire representation; signature semantics do not change.

Capabilities send their exact canonical prefix cover once, not domain+cover.
Unit maps group equal immutable row fields and encode exact slot intervals;
predecessor maps group by source and record ID, preserving every (u, ell).
Repeated signed records in one message are immutable object references.
Arrays, including model messages and business inputs, retain their order.
"""
import json
from .crypto import WIDTH,cover,canonical,require
from .storage import position_key

def intervals(values):
    out=[]
    for n in sorted(values):
        if out and n==out[-1][1]+1:out[-1][1]=n
        else:out.append([n,n])
    return out

def expand_scope(prefixes):
    out=[]
    for p in prefixes:
        require(len(p)<=WIDTH and all(c in '01' for c in p),'WIRE_PREFIX')
        first=int(p or '0',2)<<(WIDTH-len(p));out.extend(range(first,first+2**(WIDTH-len(p))))
    require(len(out)==len(set(out)),'WIRE_OVERLAPPING_SCOPE')
    return sorted(out)

def pack(value):
    # The historical codec identifier is a wire version, not system branding.
    table=[];known={}
    def visit(x,hint=None):
        if hint=='rows' and isinstance(x,list) and x and all(isinstance(v,dict) and
                {'slot','source','ownership','hard_actions'}<=set(v) for v in x):
            # Signed receipts contain ordered row lists. Group only adjacent
            # equal metadata; interval order preserves the ORIGINAL row order.
            groups=[];last=None
            for row in x:
                base={k:v for k,v in row.items() if k!='slot'};key=canonical(base);i=row['slot']
                if key!=last:groups.append([visit(base),[]]);last=key
                ranges=groups[-1][1]
                if ranges and i==ranges[-1][1]+1:ranges[-1][1]=i
                else:ranges.append([i,i])
            return [7,groups]
        if isinstance(x,list):return [1,[visit(v) for v in x]]
        if not isinstance(x,dict):return [5,x]
        if {'gid','domain','cover','key_parent'}<=set(x) and x['domain']==expand_scope(x['cover']):
            return [2,visit({k:v for k,v in x.items() if k not in ('domain','cover')}),x['cover']]
        if hint=='records' and x and all(isinstance(v,dict) and {'slot','source','ownership','hard_actions'}<=set(v)
                and k==position_key(v['source'],v['slot']) for k,v in x.items()):
            groups={}
            for row in x.values():
                base={k:v for k,v in row.items() if k!='slot'};key=canonical(base)
                groups.setdefault(key,[base,[]])[1].append(row['slot'])
            return [3,[[visit(base),intervals(slots)] for base,slots in groups.values()]]
        if hint=='previous' and x:
            parsed=[]
            for k,v in x.items():
                try:s,i=json.loads(k)
                except (ValueError,TypeError):break
                if not isinstance(s,str) or not isinstance(i,int) or k!=position_key(s,i) or not isinstance(v,str):break
                parsed.append((s,i,v))
            if len(parsed)==len(x):
                groups={}
                for s,i,v in parsed:groups.setdefault((s,v),[]).append(i)
                return [6,[[s,v,intervals(slots)] for (s,v),slots in groups.items()]]
        node=[0,[[k,visit(v,k)] for k,v in x.items()]]
        if {'body','signature'}<=set(x):
            key=canonical(x)
            if key not in known:known[key]=len(table);table.append(node)
            return [4,known[key]]
        return node
    root=visit(value);return dict(codec='sacred-wire-v1',root=root,immutable=table)

def unpack(value):
    # Match the existing wire bytes; see docs/NAMING.md.
    require(value.get('codec')=='sacred-wire-v1','WIRE_CODEC');table=value['immutable'];active=set();memo={}
    def slots(ranges):
        for lo,hi in ranges:
            require(isinstance(lo,int) and isinstance(hi,int) and 0<=lo<=hi<2**WIDTH,'WIRE_INTERVAL')
            yield from range(lo,hi+1)
    def visit(n):
        t,x,*rest=n
        if t==5:return x
        if t==1:return [visit(v) for v in x]
        if t==0:
            require(len({k for k,v in x})==len(x),'WIRE_DUPLICATE_KEY')
            return {k:visit(v) for k,v in x}
        if t==2:
            d=visit(x);domain=expand_scope(rest[0]);require(list(cover(domain))==rest[0],'WIRE_NONCANONICAL_SCOPE')
            return {**d,'domain':domain,'cover':rest[0]}
        if t==4:
            require(isinstance(x,int) and 0<=x<len(table) and x not in active,'WIRE_RECORD_REFERENCE')
            if x not in memo:
                active.add(x);memo[x]=visit(table[x]);active.remove(x)
            # Immutable descriptions are never mutated by the receiver.
            return memo[x]
        if t==3:
            out={}
            for b,ranges in x:
                base=visit(b)
                for i in slots(ranges):
                    k=position_key(base['source'],i);require(k not in out,'WIRE_DUPLICATE_UNIT');out[k]={**base,'slot':i}
            return out
        if t==6:
            out={}
            for s,v,ranges in x:
                for i in slots(ranges):
                    k=position_key(s,i);require(k not in out,'WIRE_DUPLICATE_PREDECESSOR');out[k]=v
            return out
        if t==7:
            return [{**visit(base),'slot':i} for base,ranges in x for i in slots(ranges)]
        raise ValueError('unknown wire node')
    return visit(value['root'])
