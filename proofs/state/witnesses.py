"""Reachable examples and deliberate broken-rule controls, not induction proofs."""
import json,hashlib,time
from pathlib import Path
import kernel as k
z=k.z;HERE=Path(__file__).resolve().parent

def simple(s):return {a:z.simplify(b,blast_select_store=True) for a,b in s.items()}
def finite_map(sort,default,pairs):
    out=z.K(sort,default)
    for key,value in pairs:out=z.Store(out,key,value)
    return out
def fixture():
    s=k.initial('witness');guards=[]
    def zero(sort):
        if sort==k.I:return z.IntVal(0)
        if sort==k.T:return z.RealVal(0)
        if sort==k.B:return z.BoolVal(False)
        if sort==k.S:return z.StringVal('')
        if sort==k.U:return k.U.unit(0,0)
        if sort==k.M:return request()
        if sort.kind()==z.Z3_ARRAY_SORT:return z.K(sort.domain(),zero(sort.range()))
        raise TypeError(sort)
    # Choose one concrete initial state; unlike invariant VCs these are finite
    # reachability controls. Unused catalogue rows have no authority.
    for field,value in list(s.items()):
        if z.is_const(value) and value.decl().kind()==z.Z3_OP_UNINTERPRETED:
            s[field]=zero(value.sort())
    s['requirements']=z.K(k.I,z.K(k.I,k.FALSE))
    s['requirements']=k.put(s['requirements'],[0,0,0],z.BoolVal(True))
    s['recovery_policy']=z.K(k.I,z.K(k.I,z.BoolVal(True)))
    scope=z.Store(k.FALSE,0,z.BoolVal(True));u=k.U.unit(0,0)
    cscope=z.Store(z.K(k.U,k.FALSE),u,scope)
    def step(result):
        nonlocal s
        guard,post=result;guards.append(z.simplify(guard));s=simple(post)
    step(k.add_right(s,-1,0,0,100,scope,100,20,root=True))
    step(k.add_right(s,-1,1,0,101,scope,100,20,root=True))
    step(k.declare_source(s,0,1,0,7,77,0))
    step(k.add_cap(s,-1,0,0,cscope,root=True))
    step(k.issue(s,0,0,100,z.StringVal('initial'),0))
    step(k.add_right(s,0,0,0,102,scope,90,19))
    step(k.add_cap(s,0,2,0,cscope))
    selected=z.Store(k.UFALSE,u,z.BoolVal(True))
    targets=z.Store(k.UNEG,u,1);pred=z.Store(k.UNEG,u,100)
    step(k.sync_group(s,2,selected,targets,pred,101,z.StringVal('caller-child'),1))
    step(k.add_right(s,1,1,0,103,scope,90,19))
    step(k.sync_service(s,3,102,z.StringVal('service-child'),1))
    return s,guards,u,scope,cscope

def request(q=10,payload='hello',cap=1,record=101,caller=102,da=2):
    sources=z.Store(k.FALSE,0,z.BoolVal(True));units=z.K(k.I,k.U.unit(0,0))
    return k.M.request(q,0,9,caller,103,da,3,0,z.StringVal(payload),sources,units,
      z.K(k.I,z.IntVal(77)),z.K(k.I,z.IntVal(cap)),z.K(k.I,z.IntVal(record)))
def act(caller=102,da=2):return k.ACT.act(caller,103,da,3,0,9,80)

def cases():
    s,trace,u,scope,cscope=fixture();m=request()
    g,p=k.admit(s,m,act(),102,103,7,5);p=simple(p)
    yield 'reachable_bilateral_admission',trace+[g,k.get(p['spent'],u)],'sat'
    g2,p2=k.admit(p,request(11),act(),102,103,7,6)
    yield 'original_duplicate_unit_rejected',trace+[g,g2],'unsat'
    broken=z.substitute(g2,(p['spent'],k.UFALSE))
    yield 'negative_without_spent_check_double_charge',trace+[g,broken,k.get(p2['charges'],u)==2],'sat'
    rg,rev=k.revoke(s,2,0,6);rev=simple(rev)
    oldg,_=k.admit(rev,request(12),act(),102,103,7,7)
    yield 'original_revoked_branch_rejected',trace+[rg,oldg],'unsat'
    broken=z.substitute(oldg,(rev['right_revoked'],k.FALSE))
    yield 'negative_without_revocation_check_old_branch',trace+[rg,broken],'sat'
    parents=z.K(k.U,z.IntVal(0))
    retg,ret=k.recover(rev,2,parents,103,z.StringVal('return'),7);ret=simple(ret)
    yield 'reachable_same_anchor_return',trace+[rg,retg,k.get(ret['cur_cap'],u)==0,
      k.get(ret['cur_record'],u)==103,k.get(ret['hard_scope'],u,0),z.Not(k.get(ret['spent'],u))],'sat'
    childg,new=k.add_right(ret,0,0,0,104,scope,85,19);new=simple(new)
    capg,new2=k.add_cap(new,0,4,0,cscope);new2=simple(new2)
    sel=z.Store(k.UFALSE,u,z.BoolVal(True));targets=z.Store(k.UNEG,u,2)
    oldpred=z.Store(k.UNEG,u,100)
    staleg,_=k.sync_group(new2,4,sel,targets,oldpred,104,z.StringVal('stale-child'),8)
    prefix=trace+[rg,retg,childg,capg]
    yield 'original_pre_return_record_rejected',prefix+[staleg],'unsat'
    broken=z.substitute(staleg,(new2['cur_record'],oldpred))
    yield 'negative_without_record_CAS_stale_description',prefix+[broken],'sat'
    freshpred=z.Store(k.UNEG,u,103)
    freshg,fresh=k.sync_group(new2,4,sel,targets,freshpred,104,z.StringVal('fresh-child'),8)
    fresh=simple(fresh)
    newg,last=k.admit(fresh,request(13,cap=2,record=104,caller=104,da=4),act(104,4),104,103,7,9)
    yield 'reachable_regrant_and_new_consumption',prefix+[freshg,newg,k.get(last['charges'],u)==1],'sat'
    retryg,_=k.retry(p,request(payload='tampered'),102)
    yield 'original_changed_payload_retry_rejected',trace+[g,retryg],'unsat'
    yield 'negative_without_full_message_retry_binding',trace+[g,
      k.get(p['request_seen'],10),k.get(p['request_caller'],10)==102,
      z.Not(k.message_eq(k.get(p['request_body'],10),request(payload='tampered')))],'sat'

def main():
    out=HERE/'witness_smt';out.mkdir(exist_ok=True);results=[]
    for name,assumptions,expected in cases():
        solver=z.Solver();solver.set(timeout=15000);solver.add(*(z.simplify(x,blast_select_store=True) for x in assumptions))
        raw=solver.to_smt2();(out/(name+'.smt2')).write_text(raw,encoding='utf-8')
        answer=str(solver.check());row={'name':name,'expected':expected,'result':answer,
          'sha256':hashlib.sha256(raw.encode()).hexdigest()};results.append(row)
        print(name,answer,flush=True)
        if answer=='sat':(out/(name+'.model.txt')).write_text(str(solver.model()),encoding='utf-8')
    (HERE/'WITNESSES.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    return 0 if all(x['expected']==x['result'] for x in results) else 1
if __name__=='__main__':raise SystemExit(main())
