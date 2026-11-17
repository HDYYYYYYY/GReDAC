"""GReDAC endpoint transition terms.

No import of the earlier Authority/lease/new-anchor state machine.  Immutable
catalogues are proof ghosts for parsed, structurally validated descriptions;
only registered flags and endpoint rows confer spending authority.  Arrays
range over arbitrary identifiers, rather than an enumerated test universe.
"""
from pathlib import Path
import sys
DEPS = Path(__file__).resolve().parents[2] / 'tamarin-v3' / '.deps'
if DEPS.exists(): sys.path.insert(0, str(DEPS))
import z3 as z

I, B, T, S = z.IntSort(), z.BoolSort(), z.RealSort(), z.StringSort()
U = z.Datatype('Sacred12Unit')
U.declare('unit', ('unit_source', I), ('unit_slot', I))
U = U.create()
def A(*sorts):
    out=sorts[-1]
    for key in reversed(sorts[:-1]): out=z.ArraySort(key,out)
    return out
def arr(name,*sorts): return z.Const(name,A(*sorts))
def get(a,*keys):
    for k in keys: a=z.Select(a,k)
    return a
def put(a, keys, value):
    if len(keys)==1:return z.Store(a,keys[0],value)
    return z.Store(a,keys[0],put(get(a,keys[0]),keys[1:],value))
def conj(xs): return z.And(*list(xs))
FALSE=z.K(I,z.BoolVal(False)); UFALSE=z.K(U,z.BoolVal(False))
NEG=z.K(I,z.IntVal(-1)); UNEG=z.K(U,z.IntVal(-1))

M=z.Datatype('Sacred12Request')
M.declare('request',('rq_id',I),('rq_context',I),('rq_session',I),
 ('rq_caller',I),('rq_service',I),('rq_caller_auth',I),('rq_service_auth',I),
 ('rq_action',I),('rq_payload',S),('rq_sources',A(I,B)),
 ('rq_units',A(I,U)),('rq_anchors',A(I,I)),('rq_caps',A(I,I)),('rq_records',A(I,I)))
M=M.create()
ACT=z.Datatype('Sacred12ACT')
ACT.declare('act',('act_caller',I),('act_service',I),('act_caller_auth',I),
 ('act_service_auth',I),('act_context',I),('act_session',I),('act_until',T))
ACT=ACT.create()

def fresh(prefix='s'):
    out={'right_n':z.Int(prefix+'_right_n'),'cap_n':z.Int(prefix+'_cap_n')}
    fields={
      'right_parent':(I,I),'right_side':(I,I),'right_context':(I,I),
      'right_principal':(I,I),'right_scope':(I,I,B),'right_until':(I,T),
      'right_depth':(I,I),'right_anc':(I,I,B),
      'right_registered':(I,B),'right_revoked':(I,B),'right_record':(I,I),
      'cap_parent':(I,I),'cap_holder':(I,I),'cap_source':(I,I),
      'cap_anchor':(I,I),'cap_scope':(I,U,I,B),'cap_anc':(I,I,B),
      'cap_at':(I,I,I),'cap_registered':(I,B),
      'source_known':(I,B),'source_issued':(I,B),'source_capacity':(I,I),
      'source_context':(I,I),'source_endpoint':(I,I),'source_anchor':(I,I),
      'source_root':(I,I),'source_initial_cap':(I,I),
      'source_active':(I,B),'context_active':(I,B),
      'requirements':(I,I,I,B),'recovery_policy':(I,I,B),
      'cur_cap':(U,I),'cur_holder':(U,I),'cur_record':(U,I),
      'hard_scope':(U,I,B),'hard_until':(U,T),'spent':(U,B),
      'charges':(U,I),'charge_request':(U,I),'usage_known':(U,B),
      'record_used':(I,B),'record_cancelled':(I,B),'record_body':(I,S),
      'request_seen':(I,B),'request_accepted':(I,B),'request_body':(I,M),
      'request_caller':(I,I),'request_deliveries':(I,I)}
    out.update({key:arr(prefix+'_'+key,*sorts) for key,sorts in fields.items()})
    return out

def initial(prefix='init'):
    s=fresh(prefix)
    s['right_n']=z.IntVal(0);s['cap_n']=z.IntVal(0)
    for key in ('right_registered','right_revoked','cap_registered',
      'source_known','source_issued','record_used','record_cancelled',
      'request_seen','request_accepted'):s[key]=FALSE
    s['spent']=UFALSE;s['charges']=z.K(U,z.IntVal(0))
    s['cur_cap']=UNEG;s['cur_holder']=UNEG;s['cur_record']=UNEG
    s['charge_request']=UNEG;s['usage_known']=z.K(U,z.BoolVal(True))
    s['hard_scope']=z.K(U,FALSE);s['hard_until']=z.K(U,z.RealVal(0))
    s['request_deliveries']=z.K(I,z.IntVal(0))
    s['right_record']=NEG
    s['source_active']=z.K(I,z.BoolVal(True))
    s['context_active']=z.K(I,z.BoolVal(True))
    return s

def right(s,d):return z.And(0<=d,d<s['right_n'])
def cap(s,c):return z.And(0<=c,c<s['cap_n'])
def anc(s,d,a):return get(s['right_anc'],d,a)
def canc(s,c,a):return get(s['cap_anc'],c,a)
def usource(u):return U.unit_source(u)
def valid_unit(s,u):
    src=usource(u)
    return z.And(get(s['source_known'],src),0<=U.unit_slot(u),
                 U.unit_slot(u)<get(s['source_capacity'],src))
def issued(s,u):return z.And(valid_unit(s,u),get(s['source_issued'],usource(u)))
def cscope(s,c,u,o):return get(s['cap_scope'],c,u,o)
def rlive(s,d,now):
    a=z.Int('live_ancestor')
    return z.And(right(s,d),get(s['context_active'],get(s['right_context'],d)),
      z.ForAll(a,z.Implies(anc(s,d,a),z.And(right(s,a),
       get(s['right_registered'],a),z.Not(get(s['right_revoked'],a)),
       z.Implies(get(s['right_parent'],a)>=0,
                 z.Not(get(s['record_cancelled'],get(s['right_record'],a)))),
       now<get(s['right_until'],a)))))
def right_fact(s,d,a,o):
    p=get(s['right_parent'],d)
    return z.Implies(right(s,d),z.And(
      -1<=p,p<d,z.Or(get(s['right_side'],d)==0,get(s['right_side'],d)==1),
      get(s['right_depth'],d)>=0,
      anc(s,d,a)==z.Or(d==a,z.And(p>=0,anc(s,p,a))),
      z.Implies(anc(s,d,a),z.And(right(s,a),a<=d,
       get(s['right_context'],d)==get(s['right_context'],a),
       get(s['right_side'],d)==get(s['right_side'],a),
       get(s['right_until'],d)<=get(s['right_until'],a),
       get(s['right_depth'],d)<=get(s['right_depth'],a)-z.If(d==a,0,1),
       z.Implies(get(s['right_scope'],d,o),get(s['right_scope'],a,o))))))
def rights_inv(s):
    d,a,o,b=z.Ints('ri_d ri_a ri_o ri_b')
    return z.And(s['right_n']>=0,z.ForAll([d,a,o],right_fact(s,d,a,o)),
      z.ForAll([d,a,b],tree_fact(s,d,a,b)))

def tree_fact(s,d,a,b):
    return z.Implies(right(s,d),z.And(
      z.Implies(z.And(anc(s,d,a),anc(s,a,b)),anc(s,d,b)),
      z.Implies(z.And(anc(s,d,a),anc(s,d,b)),
                z.Or(anc(s,a,b),anc(s,b,a)))))

def add_right(s,parent,side,context,principal,scope,until,depth,root=False,approved=z.BoolVal(True)):
    """Validate immutable descriptor, without activating a nonroot right."""
    d=s['right_n'];o=z.Int('new_right_action')
    guard=z.And(approved,depth>=0,z.Or(side==0,side==1),
      z.BoolVal(True) if root else z.And(right(s,parent),
       side==get(s['right_side'],parent),context==get(s['right_context'],parent),
       depth<get(s['right_depth'],parent),until<=get(s['right_until'],parent),
       z.ForAll(o,z.Implies(get(scope,o),get(s['right_scope'],parent,o)))))
    p=dict(s)
    vals={'right_parent':z.IntVal(-1) if root else parent,'right_side':side,
      'right_context':context,'right_principal':principal,'right_scope':scope,
      'right_until':until,'right_depth':depth,
      'right_anc':z.Store(FALSE if root else get(s['right_anc'],parent),d,z.BoolVal(True)),
      'right_registered':z.BoolVal(root)}
    for k,v in vals.items():p[k]=z.Store(s[k],d,v)
    p['right_n']=d+1
    # Do not erase a pre-existing tombstone on a public authorization ID.
    return guard,p

def source_fact(s,src):
    d=get(s['source_root'],src)
    return z.And(z.Implies(get(s['source_issued'],src),get(s['source_known'],src)),
      z.Implies(get(s['source_known'],src),z.And(
      get(s['source_capacity'],src)>=0,right(s,d),get(s['right_parent'],d)==-1,
      get(s['right_side'],d)==0,get(s['right_context'],d)==get(s['source_context'],src))))
def declare_source(s,src,capacity,context,endpoint,anchor,root,approved=z.BoolVal(True)):
    g=z.And(approved,z.Not(get(s['source_known'],src)),capacity>=0,
      right(s,root),get(s['right_parent'],root)==-1,get(s['right_side'],root)==0,
      context==get(s['right_context'],root))
    p=dict(s)
    for k,v in {'source_known':z.BoolVal(True),'source_capacity':capacity,
      'source_context':context,'source_endpoint':endpoint,'source_anchor':anchor,
      'source_root':root}.items():p[k]=z.Store(s[k],src,v)
    return g,p

def cap_fact(s,c,a,d,u,o):
    p=get(s['cap_parent'],c);h=get(s['cap_holder'],c);src=get(s['cap_source'],c)
    at=get(s['cap_at'],c,d)
    return z.Implies(cap(s,c),z.And(
      -1<=p,p<c,right(s,h),get(s['right_side'],h)==0,
      get(s['source_known'],src),get(s['right_context'],h)==get(s['source_context'],src),
      get(s['cap_anchor'],c)==get(s['source_anchor'],src),
      z.Implies(p==-1,h==get(s['source_root'],src)),
      z.Implies(p>=0,z.And(cap(s,p),get(s['cap_source'],p)==src,
        get(s['right_parent'],h)==get(s['cap_holder'],p))),
      canc(s,c,a)==z.Or(c==a,z.And(p>=0,canc(s,p,a))),
      z.Implies(canc(s,c,a),z.And(cap(s,a),a<=c,
        get(s['cap_source'],a)==src,get(s['cap_anchor'],a)==get(s['cap_anchor'],c),
        anc(s,h,get(s['cap_holder'],a)),
        z.Implies(cscope(s,c,u,o),cscope(s,a,u,o)))),
      z.Implies(cscope(s,c,u,o),z.And(valid_unit(s,u),usource(u)==src,get(s['right_scope'],h,o))),
      z.Implies(anc(s,h,d),z.And(cap(s,at),canc(s,c,at),get(s['cap_holder'],at)==d))))
def caps_inv(s):
    c,a,d,o=z.Ints('ci_c ci_a ci_d ci_o');u=z.Const('ci_u',U)
    return z.And(s['cap_n']>=0,z.ForAll([c,a,d,u,o],cap_fact(s,c,a,d,u,o)))

def add_cap(s,parent,holder,src,scope,root=False,authentic=z.BoolVal(True)):
    c=s['cap_n'];u=z.Const('cap_u',U);o=z.Int('cap_o')
    h=get(s['cap_holder'],parent)
    g=z.And(authentic,right(s,holder),get(s['right_side'],holder)==0,
      get(s['source_known'],src),get(s['right_context'],holder)==get(s['source_context'],src),
      holder==get(s['source_root'],src) if root else z.And(cap(s,parent),
       get(s['cap_source'],parent)==src,get(s['right_parent'],holder)==h),
      z.ForAll([u,o],z.Implies(get(scope,u,o),z.And(valid_unit(s,u),usource(u)==src,
       get(s['right_scope'],holder,o),z.BoolVal(True) if root else cscope(s,parent,u,o)))))
    p=dict(s)
    vals={'cap_parent':z.IntVal(-1) if root else parent,'cap_holder':holder,
      'cap_source':src,'cap_anchor':get(s['source_anchor'],src),'cap_scope':scope,
      'cap_anc':z.Store(FALSE if root else get(s['cap_anc'],parent),c,z.BoolVal(True)),
      'cap_at':z.Store(NEG if root else get(s['cap_at'],parent),holder,c),
      'cap_registered':z.BoolVal(False)}
    for k,v in vals.items():p[k]=z.Store(s[k],c,v)
    p['cap_n']=c+1
    return g,p

def registered_fact(s,c,a):
    return z.Implies(get(s['cap_registered'],c),z.And(cap(s,c),
      get(s['right_registered'],get(s['cap_holder'],c)),
      z.Implies(canc(s,c,a),get(s['cap_registered'],a))))

def unit_fact(s,u,o):
    c=get(s['cur_cap'],u);d=get(s['cur_holder'],u)
    return z.And(z.Implies(issued(s,u),z.And(
      cap(s,c),get(s['cap_registered'],c),d==get(s['cap_holder'],c),
      get(s['cap_source'],c)==usource(u),get(s['cap_anchor'],c)==get(s['source_anchor'],usource(u)),
      get(s['record_used'],get(s['cur_record'],u)),
      get(s['hard_until'],u)<=get(s['right_until'],d),
      z.Implies(get(s['hard_scope'],u,o),cscope(s,c,u,o)))),
      get(s['charges'],u)>=0,get(s['charges'],u)<=1,
      get(s['spent'],u)==(get(s['charges'],u)==1),
      z.Implies(z.Not(issued(s,u)),z.And(get(s['charges'],u)==0,z.Not(get(s['spent'],u)))))
def units_inv(s):
    u=z.Const('ui_u',U);o=z.Int('ui_o')
    return z.ForAll([u,o],unit_fact(s,u,o))

def new_record(s,ell,body):
    return z.And(ell>=0,z.Not(get(s['record_used'],ell)),z.Not(get(s['record_cancelled'],ell)))
def commit_record(s,p,ell,body):
    p['record_used']=z.Store(s['record_used'],ell,z.BoolVal(True))
    p['record_body']=z.Store(s['record_body'],ell,body)

def issue(s,src,c,ell,body,now,authentic=z.BoolVal(True)):
    u=z.Const('issue_u',U)
    hit=z.And(valid_unit(s,u),usource(u)==src)
    h=get(s['cap_holder'],c)
    g=z.And(authentic,get(s['source_known'],src),z.Not(get(s['source_issued'],src)),
      cap(s,c),get(s['cap_source'],c)==src,get(s['cap_parent'],c)==-1,
      h==get(s['source_root'],src),rlive(s,h,now),new_record(s,ell,body))
    p=dict(s);p['source_issued']=z.Store(s['source_issued'],src,z.BoolVal(True))
    p['source_initial_cap']=z.Store(s['source_initial_cap'],src,c)
    p['cap_registered']=z.Store(s['cap_registered'],c,z.BoolVal(True))
    for k,v in {'cur_cap':c,'cur_holder':h,'cur_record':ell,
      'hard_scope':get(s['cap_scope'],c,u),'hard_until':get(s['right_until'],h)}.items():
        p[k]=z.Lambda(u,z.If(hit,v,get(s[k],u)))
    commit_record(s,p,ell,body)
    return g,p

def activate_condition(s,d,now):
    return z.And(right(s,d),z.Not(get(s['right_registered'],d)),get(s['right_parent'],d)>=0,
      rlive(s,get(s['right_parent'],d),now),z.Not(get(s['right_revoked'],d)),
      now<get(s['right_until'],d))

def sync_group(s,d,selected,targets,preceding,ell,body,now,authentic=z.BoolVal(True)):
    """One complete signed multi-source description, as an atomic step.

    selected is the exact position projection of all its target cap scopes.
    Target caps and the child authorization may have been catalogued offline.
    """
    u,v=z.Consts('sync_u sync_v',U);o,c=z.Ints('sync_o sync_c')
    target=get(targets,u);old=get(s['cur_cap'],u)
    chosen=lambda x:get(selected,x)
    g=z.And(authentic,activate_condition(s,d,now),get(s['right_side'],d)==0,
      new_record(s,ell,body),z.Exists(u,chosen(u)),
      z.ForAll(u,z.Implies(chosen(u),z.And(
       issued(s,u),z.Not(get(s['spent'],u)),get(s['usage_known'],u),
       now<get(s['hard_until'],u),get(s['source_active'],usource(u)),
       get(s['cur_holder'],u)==get(s['right_parent'],d),
       get(s['cur_record'],u)==get(preceding,u),
       cap(s,target),z.Not(get(s['cap_registered'],target)),
       get(s['cap_holder'],target)==d,get(s['cap_parent'],target)==old,
       get(s['cap_source'],target)==usource(u),
       get(s['cap_registered'],old),
       z.Exists(o,cscope(s,target,u,o)),
       z.ForAll(o,z.Implies(cscope(s,target,u,o),get(s['hard_scope'],u,o)))))),
      z.ForAll([u,v,o],z.Implies(z.And(chosen(u),cscope(s,get(targets,u),v,o)),
          z.And(chosen(v),get(targets,v)==get(targets,u)))))
    p=dict(s)
    p['right_registered']=z.Store(s['right_registered'],d,z.BoolVal(True))
    p['right_record']=z.Store(s['right_record'],d,ell)
    is_target=z.Exists(u,z.And(chosen(u),get(targets,u)==c))
    p['cap_registered']=z.Lambda(c,z.Or(get(s['cap_registered'],c),is_target))
    for k,value in {'cur_cap':target,'cur_holder':d,'cur_record':ell,
      'hard_scope':get(s['cap_scope'],target,u),
      'hard_until':z.If(get(s['hard_until'],u)<=get(s['right_until'],d),
                       get(s['hard_until'],u),get(s['right_until'],d))}.items():
        p[k]=z.Lambda(u,z.If(chosen(u),value,get(s[k],u)))
    commit_record(s,p,ell,body)
    return g,p

def sync_service(s,d,ell,body,now,authentic=z.BoolVal(True)):
    g=z.And(authentic,activate_condition(s,d,now),get(s['right_side'],d)==1,
      new_record(s,ell,body))
    p=dict(s);p['right_registered']=z.Store(s['right_registered'],d,z.BoolVal(True))
    p['right_record']=z.Store(s['right_record'],d,ell)
    commit_record(s,p,ell,body)
    return g,p

def registered_prefix(s,d,ell,body,now,authentic=z.BoolVal(True)):
    g=z.And(authentic,get(s['record_used'],ell),get(s['record_body'],ell)==body,
      get(s['right_parent'],d)>=0,get(s['right_record'],d)==ell,
      z.Not(get(s['record_cancelled'],ell)),rlive(s,d,now))
    return g,dict(s)

def req_sources(s,m,src):return get(s['requirements'],M.rq_context(m),M.rq_action(m),src)
def selected_by(s,m,u):
    return z.And(req_sources(s,m,usource(u)),get(M.rq_units(m),usource(u))==u)
def act_binding(m,act,caller,service,now):
    return z.And(caller==M.rq_caller(m),service==M.rq_service(m),
      ACT.act_caller(act)==caller,ACT.act_service(act)==service,
      ACT.act_caller_auth(act)==M.rq_caller_auth(m),ACT.act_service_auth(act)==M.rq_service_auth(m),
      ACT.act_context(act)==M.rq_context(m),ACT.act_session(act)==M.rq_session(m),
      now<ACT.act_until(act))

def admission_guard(s,m,act,caller,service,endpoint,now,authentic=z.BoolVal(True),tags_valid=z.BoolVal(True)):
    da,dr=M.rq_caller_auth(m),M.rq_service_auth(m);o=M.rq_action(m);ctx=M.rq_context(m)
    src=z.Int('admit_src');u=get(M.rq_units(m),src);c=get(s['cur_cap'],u)
    return z.And(authentic,tags_valid,act_binding(m,act,caller,service,now),
      z.Not(get(s['request_seen'],M.rq_id(m))),
      rlive(s,da,now),rlive(s,dr,now),get(s['right_side'],da)==0,get(s['right_side'],dr)==1,
      get(s['right_principal'],da)==caller,get(s['right_principal'],dr)==service,
      get(s['right_context'],da)==ctx,get(s['right_context'],dr)==ctx,
      get(s['right_scope'],da,o),get(s['right_scope'],dr,o),
      z.ForAll(src,get(M.rq_sources(m),src)==req_sources(s,m,src)),
      z.ForAll(src,z.Implies(req_sources(s,m,src),z.And(
       issued(s,u),usource(u)==src,get(s['source_context'],src)==ctx,
       get(s['source_endpoint'],src)==endpoint,get(s['source_active'],src),
       z.Not(get(s['spent'],u)),get(s['usage_known'],u),now<get(s['hard_until'],u),
       get(s['cur_holder'],u)==da,get(M.rq_caps(m),src)==c,
       get(M.rq_records(m),src)==get(s['cur_record'],u),
       get(M.rq_anchors(m),src)==get(s['cap_anchor'],c),
       cscope(s,c,u,o),get(s['hard_scope'],u,o)))))

def admit(s,m,act,caller,service,endpoint,now,authentic=z.BoolVal(True),tags_valid=z.BoolVal(True)):
    g=admission_guard(s,m,act,caller,service,endpoint,now,authentic,tags_valid)
    q=M.rq_id(m);u=z.Const('admission_unit',U);hit=selected_by(s,m,u)
    p=dict(s)
    p['spent']=z.Lambda(u,z.Or(get(s['spent'],u),hit))
    p['charges']=z.Lambda(u,get(s['charges'],u)+z.If(hit,1,0))
    p['charge_request']=z.Lambda(u,z.If(hit,q,get(s['charge_request'],u)))
    for key,value in {'request_seen':z.BoolVal(True),'request_accepted':z.BoolVal(True),
      'request_body':m,'request_caller':caller,'request_deliveries':z.IntVal(1)}.items():
        p[key]=z.Store(s[key],q,value)
    return g,p

def reject(s,m,caller,authenticated=z.BoolVal(True)):
    q=M.rq_id(m);g=z.And(authenticated,caller==M.rq_caller(m),z.Not(get(s['request_seen'],q)))
    p=dict(s)
    for key,value in {'request_seen':z.BoolVal(True),'request_accepted':z.BoolVal(False),
      'request_body':m,'request_caller':caller,'request_deliveries':z.IntVal(0)}.items():
        p[key]=z.Store(s[key],q,value)
    return g,p

def message_eq(m,n):
    """Canonical equality ignores values of vector arrays outside their domain."""
    src=z.Int('message_equal_source')
    scalars=('rq_id','rq_context','rq_session','rq_caller','rq_service',
             'rq_caller_auth','rq_service_auth','rq_action','rq_payload','rq_sources')
    return z.And(*(getattr(M,f)(m)==getattr(M,f)(n) for f in scalars),
        z.ForAll(src,z.Implies(get(M.rq_sources(m),src),z.And(*(
          get(getattr(M,f)(m),src)==get(getattr(M,f)(n),src)
          for f in ('rq_units','rq_anchors','rq_caps','rq_records'))))))

def retry(s,m,caller,authenticated=z.BoolVal(True)):
    q=M.rq_id(m)
    return z.And(authenticated,get(s['request_seen'],q),message_eq(get(s['request_body'],q),m),
      caller==get(s['request_caller'],q)),dict(s)

def decision_fact(s,q,u):
    m=get(s['request_body'],q);hit=selected_by(s,m,u)
    return z.Implies(get(s['request_seen'],q),z.And(M.rq_id(m)==q,
      get(s['request_caller'],q)==M.rq_caller(m),
      get(s['request_deliveries'],q)==z.If(get(s['request_accepted'],q),1,0),
      z.Implies(z.And(get(s['request_accepted'],q),hit),z.And(
        issued(s,u),get(s['spent'],u),get(s['charges'],u)==1,get(s['charge_request'],u)==q))))
def charged_fact(s,u):
    q=get(s['charge_request'],u)
    return z.Implies(get(s['spent'],u),z.And(get(s['request_seen'],q),
      get(s['request_accepted'],q),selected_by(s,get(s['request_body'],q),u)))

def revoke(s,target,controller,now,user_approval=z.BoolVal(False),authentic=z.BoolVal(True)):
    g=z.And(authentic,right(s,target),z.Or(user_approval,z.And(right(s,controller),
      controller!=target,anc(s,target,controller),rlive(s,controller,now))))
    p=dict(s);p['right_revoked']=z.Store(s['right_revoked'],target,z.BoolVal(True))
    return g,p

def cancel(s,ell,authorized=z.BoolVal(True)):
    """Cancel a signed delegation-description ID (possibly not registered).

    The typed authenticated parser supplies `authorized`; issuance and return
    record IDs are not cancellation requests in the frozen protocol.
    """
    p=dict(s);p['record_cancelled']=z.Store(s['record_cancelled'],ell,z.BoolVal(True))
    return authorized,p

def eligible(s,src,d,now):
    return z.And(rlive(s,d,now),get(s['right_side'],d)==0,
      get(s['right_context'],d)==get(s['source_context'],src),get(s['recovery_policy'],src,d))
def nearest(s,target,src,p,now):
    b=z.Int('near_between')
    return z.And(p!=target,anc(s,target,p),eligible(s,src,p,now),
      z.ForAll(b,z.Implies(z.And(b!=target,b!=p,anc(s,target,b),anc(s,b,p)),
                           z.Not(eligible(s,src,b,now)))))
def recoverable(s,target,u,now):
    return z.And(issued(s,u),anc(s,get(s['cur_holder'],u),target),
      z.Not(get(s['spent'],u)),get(s['usage_known'],u),now<get(s['hard_until'],u))

def recover(s,target,parents,ell,body,now,authorized=z.BoolVal(True)):
    u=z.Const('return_unit',U);d=z.Int('return_candidate')
    chosen=get(parents,u);candidate=recoverable(s,target,u,now)
    hit=z.And(candidate,chosen>=0)
    c=get(s['cap_at'],get(s['cur_cap'],u),chosen)
    g=z.And(authorized,right(s,target),get(s['right_parent'],target)>=0,
      get(s['right_revoked'],target),new_record(s,ell,body),
      z.ForAll(u,z.Implies(candidate,z.Or(nearest(s,target,usource(u),chosen,now),
        z.And(chosen==-1,z.ForAll(d,z.Implies(z.And(d!=target,anc(s,target,d)),
                                            z.Not(eligible(s,usource(u),d,now)))))))))
    p=dict(s)
    for key,value in {'cur_cap':c,'cur_holder':chosen,'cur_record':ell}.items():
        p[key]=z.Lambda(u,z.If(hit,value,get(s[key],u)))
    commit_record(s,p,ell,body)
    return g,p

def block_context(s,ctx,authorized=z.BoolVal(True)):
    p=dict(s);p['context_active']=z.Store(s['context_active'],ctx,z.BoolVal(False))
    return authorized,p
def block_source(s,src,authorized=z.BoolVal(True)):
    p=dict(s);p['source_active']=z.Store(s['source_active'],src,z.BoolVal(False))
    return authorized,p
def mark_unknown(s,u):
    p=dict(s);p['usage_known']=z.Store(s['usage_known'],u,z.BoolVal(False))
    return issued(s,u),p
def identity_step(s):return z.BoolVal(True),dict(s)

def sync_batch(s,steps,contact_guard=z.BoolVal(True)):
    """Finite all-or-none wrapper; each step is a callback on provisional state.

    contact_guard checks both presented paths/approval dependencies. The
    induction theorem quantifies over arbitrary finite lists, not a fixed size.
    Post is the provisional state; commit requires the conjunction guard.
    Rejection returns the original state, as for every guard/post constructor.
    """
    current=s;guards=[contact_guard]
    for step in steps:
        g,current=step(current);guards.append(g)
    return conj(guards),current

def eq_state(s,p):return conj(s[k]==p[k] for k in s)
