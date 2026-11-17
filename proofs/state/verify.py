"""Unbounded-array induction VCs. Saves each standalone SMT-LIB query.

UNSAT checks the negation of a universally generalized obligation; SAT and
UNKNOWN are failures. No finite domain bound or desired invariant is added as
an operation guard. Logical frame cases are separately recorded.
"""
from pathlib import Path
import argparse,json,time,hashlib
import kernel as k
z=k.z
HERE=Path(__file__).resolve().parent

def invariants(s):
    d,a,o,q=z.Ints('inv_d inv_a inv_o inv_q');u=z.Const('inv_u',k.U)
    return {
      'rights':k.rights_inv(s),
      'sources':z.ForAll(d,k.source_fact(s,d)),
      'caps':k.caps_inv(s),
      'registered':z.ForAll([d,a],k.registered_fact(s,d,a)),
      'units':k.units_inv(s),
      'decisions':z.ForAll([q,u],k.decision_fact(s,q,u)),
      'charged':z.ForAll(u,k.charged_fact(s,u)),
    }

def local_claims(s):
    """Free constants are universally generalized, never finite enumeration."""
    d,a,b,o,q=z.Ints('test_d test_a test_b test_o test_q');u=z.Const('test_u',k.U)
    c=z.Int('test_c')
    return {
      'rights':[s['right_n']>=0,k.right_fact(s,d,a,o),k.tree_fact(s,d,a,b)],
      'sources':[k.source_fact(s,d)],
      'caps':[s['cap_n']>=0,k.cap_fact(s,c,a,d,u,o)],
      'registered':[k.registered_fact(s,c,a)],
      'units':[k.unit_fact(s,u,o)],
      'decisions':[k.decision_fact(s,q,u)],
      'charged':[k.charged_fact(s,u)],
    }

def transitions(s):
    d,parent,side,ctx,principal,depth,src,n,ep,anchor,c,ell,ctrl=z.Ints(
      'p_d p_parent p_side p_ctx p_principal p_depth p_src p_n p_ep p_anchor p_c p_ell p_ctrl')
    until,now=z.Reals('p_until p_now');body=z.String('p_body')
    scope=k.arr('p_scope',k.I,k.B);cscope=k.arr('p_cscope',k.U,k.I,k.B)
    sel=k.arr('p_sel',k.U,k.B);targets=k.arr('p_targets',k.U,k.I)
    pred=k.arr('p_pred',k.U,k.I);parents=k.arr('p_parents',k.U,k.I)
    m=z.Const('p_message',k.M);act=z.Const('p_act',k.ACT)
    caller,service=z.Ints('p_caller p_service');u=z.Const('p_unit',k.U)
    return {
      'add_root':k.add_right(s,parent,side,ctx,principal,scope,until,depth,root=True),
      'add_child':k.add_right(s,parent,side,ctx,principal,scope,until,depth),
      'declare_source':k.declare_source(s,src,n,ctx,ep,anchor,d),
      'add_initial_cap':k.add_cap(s,parent,d,src,cscope,root=True),
      'add_child_cap':k.add_cap(s,parent,d,src,cscope),
      'issue':k.issue(s,src,c,ell,body,now),
      'sync_group':k.sync_group(s,d,sel,targets,pred,ell,body,now),
      'sync_service':k.sync_service(s,d,ell,body,now),
      'registered_prefix':k.registered_prefix(s,d,ell,body,now),
      'admit':k.admit(s,m,act,caller,service,ep,now),
      'reject':k.reject(s,m,caller),
      'retry':k.retry(s,m,caller),
      'revoke':k.revoke(s,d,ctrl,now),
      'user_revoke':k.revoke(s,d,ctrl,now,user_approval=z.BoolVal(True)),
      'cancel':k.cancel(s,ell),
      'recover':k.recover(s,d,parents,ell,body,now),
      'block_context':k.block_context(s,ctx),
      'block_source':k.block_source(s,src),
      'mark_unknown':k.mark_unknown(s,u),
      'stutter':k.identity_step(s),
    }

def ground_facts(s):
    """Only universal elimination of the induction hypothesis (no new axiom).

    The deliberately redundant finite terms are instantiations, not a bound on
    identifiers, depth, source count, or the number of units.
    """
    d,a,b,o,q=z.Ints('test_d test_a test_b test_o test_q');u=z.Const('test_u',k.U)
    c=z.Int('test_c'); parent,holder,src=z.Ints('p_parent p_d p_src')
    target=k.get(k.arr('p_targets',k.U,k.I),u)
    chosen=k.get(k.arr('p_parents',k.U,k.I),u)
    cu=k.get(s['cur_cap'],u);hu=k.get(s['cur_holder'],u)
    ca=k.get(s['cap_at'],cu,chosen)
    cs=[c,a,parent,z.Int('p_c'),cu,target,ca,k.get(s['cap_at'],parent,d),k.get(s['cap_at'],c,d)]
    ds=[d,a,b,parent,holder,hu,chosen,s['right_n']]
    ds += [k.get(s['cap_holder'],x) for x in cs]
    ds += [k.get(s['right_parent'],holder),k.get(s['source_root'],src)]
    # Deduplicate without evaluating symbolic equalities.
    ds=list({x.sexpr():x for x in ds}.values());cs=list({x.sexpr():x for x in cs}.values())
    out=[s['right_n']>=0,s['cap_n']>=0,k.unit_fact(s,u,o),k.decision_fact(s,q,u),k.charged_fact(s,u)]
    for x in ds:
        for y in ds:out.append(k.right_fact(s,x,y,o))
    for x,y,w in [(d,a,b),(parent,a,b),(hu,holder,chosen),(hu,chosen,holder)]:
        out.append(k.tree_fact(s,x,y,w))
    for x in cs:
        for y in cs:
            for h in [d,chosen,holder]:out.append(k.cap_fact(s,x,y,h,u,o))
        for y in cs:out.append(k.registered_fact(s,x,y))
    for x in [d,src,k.usource(u)]+[k.get(s['cap_source'],x) for x in cs]:
        out.append(k.source_fact(s,x))
    return out

def obligations():
    s=k.fresh('pre');iv=invariants(s);init=invariants(k.initial())
    instances=ground_facts(s)
    for name,formula in init.items():yield 'base_'+name,[],formula
    for op,(guard,p) in transitions(s).items():
        post=local_claims(p)
        for name,formulas in post.items():
            # Even syntactic frames are submitted to the solver; simplification
            # can discharge them without unrolling irrelevant quantifiers.
            dependencies={
                  'rights':['rights'], 'sources':['rights','sources'],
                  'caps':['rights','sources','caps'],
                  'registered':['rights','caps','registered'],
                  'units':['rights','sources','caps','registered','units'],
                  'decisions':['sources','units','decisions','charged'],
                  'charged':['sources','units','decisions','charged']}
            for i,formula in enumerate(formulas):
                if op=='sync_group' and name=='registered':
                    # Existential elimination: every newly registered cap has
                    # a selected witness u. Prove that witness case without
                    # asking an SMT quantifier heuristic to discover it.
                    u=z.Const('test_u',k.U);a=z.Int('test_a')
                    chosen=k.get(k.arr('p_sel',k.U,k.B),u)
                    target=k.get(k.arr('p_targets',k.U,k.I),u)
                    lift=dict(p);x=z.Int('registered_lift_cap')
                    lift['cap_registered']=z.Lambda(x,z.Or(k.get(s['cap_registered'],x),x==target))
                    yield op+'_registered_new',instances+[guard,chosen],k.registered_fact(lift,target,a)
                    # Previously registered rows remain true, and activation
                    # only changes a right_registered bit to true.
                    old=dict(p);old['cap_registered']=s['cap_registered']
                    yield op+'_registered_old',instances+[guard],k.registered_fact(old,z.Int('test_c'),a)
                    continue
                yield op+'_'+name+'_'+str(i),instances+[guard],formula
        u=z.Const('test_u',k.U);o=z.Int('test_o');r=z.Int('test_d')
        for suffix,claim in {
          'spent_monotone':z.Implies(k.get(s['spent'],u),k.get(p['spent'],u)),
          'records_monotone':z.Implies(k.get(s['record_used'],r),k.get(p['record_used'],r)),
          'revocation_monotone':z.Implies(k.get(s['right_revoked'],r),k.get(p['right_revoked'],r)),
          'hard_scope_monotone':z.Implies(z.And(k.issued(s,u),k.get(p['hard_scope'],u,o)),k.get(s['hard_scope'],u,o)),
          'hard_deadline_monotone':z.Implies(k.issued(s,u),k.get(p['hard_until'],u)<=k.get(s['hard_until'],u)),
        }.items():yield op+'_'+suffix,instances+[guard],claim
    # Direct security consequences, in addition to invariant preservation.
    d,a,b,o,q,src,ep,caller,service=z.Ints('th_d th_a th_b th_o th_q th_src th_ep th_c th_r')
    now=z.Real('th_now');u=z.Const('th_u',k.U);m=z.Const('th_m',k.M);act=z.Const('th_act',k.ACT)
    g,p=k.admit(s,m,act,caller,service,ep,now)
    common=list(iv.values())+[g]
    yield 'admit_single_use',common+[k.selected_by(s,m,u)],z.And(
      z.Not(k.get(s['spent'],u)),k.get(p['charges'],u)==1,k.get(p['spent'],u))
    yield 'admit_exact_debit',common,k.get(p['charges'],u)==k.get(s['charges'],u)+z.If(k.selected_by(s,m,u),1,0)
    yield 'admit_bilateral_ancestors',common+[k.anc(s,k.M.rq_caller_auth(m),a)],z.And(
      z.Not(k.get(s['right_revoked'],a)),k.get(s['right_registered'],a))
    yield 'admit_service_ancestors',common+[k.anc(s,k.M.rq_service_auth(m),a)],z.And(
      z.Not(k.get(s['right_revoked'],a)),k.get(s['right_registered'],a))
    yield 'admit_current_record',common+[k.req_sources(s,m,src)],(
      k.get(k.M.rq_records(m),src)==k.get(s['cur_record'],k.get(k.M.rq_units(m),src)))
    g2,p2=k.admit(p,m,act,caller,service,ep,now)
    yield 'same_request_cannot_admit_twice',common,z.Not(g2)
    g3,p3=k.retry(p,m,caller)
    yield 'exact_retry_enabled_and_stutters',common,z.And(g3,k.eq_state(p,p3))
    rg,rp=k.revoke(s,d,a,now,user_approval=z.BoolVal(True))
    yield 'revoke_blocks_descendant',list(iv.values())+[rg,k.right(s,b),k.anc(s,b,d)],z.Not(k.rlive(rp,b,now))
    yield 'recovery_cap_exists',[k.unit_fact(s,u,o),
      k.cap_fact(s,k.get(s['cur_cap'],u),k.get(s['cur_cap'],u),d,u,o),
      k.issued(s,u),k.anc(s,k.get(s['cur_holder'],u),d)],z.And(
      k.cap(s,k.get(s['cap_at'],k.get(s['cur_cap'],u),d)),
      k.get(s['cap_holder'],k.get(s['cap_at'],k.get(s['cur_cap'],u),d))==d)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--filter',default='');ap.add_argument('--timeout-ms',type=int,default=12000)
    args=ap.parse_args();out=HERE/'smt';out.mkdir(exist_ok=True)
    results=[]
    for name,assumptions,claim in obligations():
        if args.filter and args.filter not in name:continue
        solver=z.Solver();solver.set(timeout=args.timeout_ms)
        solver.add(*assumptions,z.Not(claim))
        raw=solver.to_smt2();path=out/(name+'.smt2');path.write_text(raw,encoding='utf-8')
        t=time.monotonic();answer=solver.check();elapsed=time.monotonic()-t
        row={'name':name,'result':str(answer),'seconds':round(elapsed,4),
             'sha256':hashlib.sha256(raw.encode()).hexdigest()}
        if answer==z.unknown:row['reason']=solver.reason_unknown()
        if answer==z.sat:(out/(name+'.model.txt')).write_text(str(solver.model()),encoding='utf-8')
        results.append(row);print(name,answer,round(elapsed,3),flush=True)
    name='RESULTS'+('_'+args.filter if args.filter else '')+'.json'
    (HERE/name).write_text(json.dumps({'z3':z.get_version_string(),'results':results},indent=2),encoding='utf-8')
    return 0 if results and all(x['result']=='unsat' for x in results) else 1
if __name__=='__main__':raise SystemExit(main())
