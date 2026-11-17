"""Concrete joint trace using the SAME Z3 transitions and real RDF reference.

Two recursively delegated sides, two charged sources, intra-dialogue requests,
known-key attacks, cascade revoke, exact return under the SAME anchor, ABA,
fresh replacement, and service replacement. This is an interface/nonvacuity
witness, not an unbounded proof or a production protocol implementation.
"""
from pathlib import Path
import sys,json,hashlib,importlib.util,time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'state'))
import kernel as k
spec=importlib.util.spec_from_file_location('pcdf_reference',ROOT/'crypto'/'reference.py')
p=importlib.util.module_from_spec(spec);sys.modules[spec.name]=p;spec.loader.exec_module(p)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
z=k.z

def iv(x):return z.IntVal(x)
def rv(x):return z.RealVal(x)
def bv(x):return z.BoolVal(x)
def label(x):return ('id:'+str(x)).encode()
def table(sort,default,items):
    out=z.K(sort,default)
    for key,val in items:out=z.Store(out,key,val)
    return out
def actions(values):return table(k.I,bv(False),[(iv(v),bv(True)) for v in values])
def scalar(x):
    x=z.simplify(x)
    if z.is_int_value(x):return x.as_long()
    raise AssertionError('not concrete: '+str(x))

class Trace:
    def __init__(self):
        self.s=k.initial('witness');self.rows=[];self.counter=0;self.now=0
        self.s['requirements']=z.K(k.I,z.K(k.I,k.FALSE))
        required=table(k.I,bv(False),[(iv(src),bv(True)) for src in (100,101)])
        self.s['requirements']=k.put(self.s['requirements'],[iv(7),iv(0)],required)
        self.s['requirements']=k.put(self.s['requirements'],[iv(7),iv(1)],required)
        self.s['recovery_policy']=z.K(k.I,z.K(k.I,bv(True)))
        self.caps={};self.bundles={};self.endpoints={};self.keys={}
        self.geometry=p.Geometry(1,2,frozenset({0,1}),4)
        self.evidence=ROOT/'integration'/'queries';self.evidence.mkdir(exist_ok=True)
    def check(self,name,formula,expect=True):
        self.counter+=1;sl=z.Solver();sl.set(timeout=15000)
        sl.add(z.Not(formula) if expect else formula)
        raw=sl.to_smt2();path=self.evidence/(f'{self.counter:03d}_'+name+'.smt2')
        path.write_text(raw,encoding='utf-8');t=time.monotonic();answer=sl.check()
        self.rows.append({'name':name,'expected':expect,'negation_result':str(answer),
                          'seconds':round(time.monotonic()-t,4),
                          'query':str(path.relative_to(ROOT)),
                          'sha256':hashlib.sha256(raw.encode()).hexdigest()})
        if answer!=z.unsat:raise AssertionError(name+': '+str(answer)+' '+(sl.reason_unknown() if answer==z.unknown else str(sl.model())))
    def step(self,name,operation,expect=True):
        self.now+=1
        guard,post=operation(self.s);self.check(name,guard,expect)
        if expect:self.s={key:z.simplify(value) for key,value in post.items()}
    def value(self,field,*keys):return scalar(k.get(self.s[field],*(iv(x) if isinstance(x,int) else x for x in keys)))
    def identity(self,principal):
        if principal not in self.keys:self.keys[principal]=Ed25519PrivateKey.from_private_bytes(p.fixture_key('identity:'+str(principal)))
        return self.keys[principal]
    def signed(self,principal,body):
        key=self.identity(principal);sig=key.sign(body)
        try:key.public_key().verify(sig,body);return True
        except InvalidSignature:return False
    def right(self,parent,principal,side,scope,depth,name,root=False):
        d=scalar(self.s['right_n'])
        self.identity(principal)
        self.step(name,lambda s:k.add_right(s,iv(parent),iv(side),iv(7),iv(principal),
                  actions(scope),rv(1000),iv(depth),root=root))
        return d
    def initial_source(self,src,root):
        c=scalar(self.s['cap_n']);anchor=1000+src;scope=self.geometry.valid
        cap,bundle=p.initial_capability(p.fixture_key('master:'+str(src)),label(src),label(7),label(9),
                   label(anchor),label(c),scope,self.geometry)
        cs=self.cap_scope(src,scope)
        self.step('declare_source_'+str(src),lambda s:k.declare_source(s,iv(src),iv(4),iv(7),iv(9),iv(anchor),iv(root)))
        self.step('catalog_initial_'+str(src),lambda s:k.add_cap(s,iv(-1),iv(root),iv(src),cs,root=True))
        self.step('issue_'+str(src),lambda s:k.issue(s,iv(src),iv(c),iv(src+10),z.StringVal('initial:'+str(src)),rv(self.now)))
        self.caps[c]=cap;self.bundles[c]=bundle;self.endpoints[src]=p.EndpointPCDF(cap,bundle)
        return c
    def cap_scope(self,src,points):
        out=z.K(k.U,k.FALSE)
        for point in sorted(points):
            action,slot=divmod(point,4);out=k.put(out,[k.U.unit(src,slot),iv(action)],bv(True))
        return out
    def child_caps(self,d,parents,slots,actionset):
        result={}
        for src,parent in sorted(parents.items()):
            c=scalar(self.s['cap_n']);scope=frozenset(self.geometry.point(a,i) for a in actionset for i in slots)
            cap,bundle=p.derive_child(self.caps[parent],self.bundles[parent],label(c),scope)
            self.step('catalog_child_cap_'+str(c),lambda s:k.add_cap(s,iv(parent),iv(d),iv(src),self.cap_scope(src,scope)))
            self.caps[c]=cap;self.bundles[c]=bundle;result[src]=c
        return result
    def transfer_args(self,d,childcaps,ell):
        selected=z.K(k.U,bv(False));targets=z.K(k.U,iv(-1));preceding=z.K(k.U,iv(-1));groups=[]
        for src,c in sorted(childcaps.items()):
            cap=self.caps[c];entries=[]
            for slot in sorted({x%4 for x in cap.scope}):
                u=k.U.unit(src,slot);old=self.value('cur_record',u)
                selected=z.Store(selected,u,bv(True));targets=z.Store(targets,u,iv(c));preceding=z.Store(preceding,u,iv(old))
                entries.append(p.enc(p.u64(src),p.u64(slot),p.u64(old)))
            groups.append(p.enc(p.u64(src),cap.anchor,cap.gamma,cap.parent,
                                p.enc(*(p.u64(x) for x in sorted(cap.scope))),p.enc(*entries)))
        parent=self.value('right_parent',d);principal=self.value('right_principal',parent)
        body=p.enc(b'delegation',p.u64(d),p.u64(parent),p.u64(self.value('right_principal',d)),
                   p.u64(7),p.u64(9),p.u64(ell),p.u64(1000),
                   p.u64(self.value('right_depth',d)),p.enc(*groups))
        assert self.signed(principal,body)
        return selected,targets,preceding,z.StringVal(body.hex())
    def transfer(self,name,d,childcaps,ell,args=None,expect=True):
        selected,targets,preceding,body=args or self.transfer_args(d,childcaps,ell)
        self.step(name,lambda s:k.sync_group(s,iv(d),selected,targets,preceding,iv(ell),body,rv(self.now)),expect)
        if expect:
            for src,c in childcaps.items():self.endpoints[src].register(self.caps[c])
    def service(self,d,ell):
        self.step('service_register_'+str(d),lambda s:k.sync_service(s,iv(d),iv(ell),z.StringVal('service:'+str(d)),rv(self.now)))
    def request(self,da,dr,rho,slot,action=0,payload='body',bundle_override=None):
        caller=self.value('right_principal',da);service=self.value('right_principal',dr)
        entries=[];units=z.K(k.I,k.U.unit(-1,-1));anchors=k.NEG;caps=k.NEG;records=k.NEG
        for src in (100,101):
            u=k.U.unit(src,slot);c=self.value('cur_cap',u);ell=self.value('cur_record',u);anchor=self.value('cap_anchor',c)
            entries.append((label(src),slot,label(anchor),label(c),label(ell)))
            units=z.Store(units,iv(src),u);anchors=z.Store(anchors,iv(src),iv(anchor));caps=z.Store(caps,iv(src),iv(c));records=z.Store(records,iv(src),iv(ell))
        message=p.encode_request(label(rho),label(7),label(300),label(caller),label(service),label(da),label(dr),action,payload.encode(),entries)
        reqsrc=table(k.I,bv(False),[(iv(src),bv(True)) for src in (100,101)])
        m=k.M.request(rho,7,300,caller,service,da,dr,action,z.StringVal(payload),reqsrc,units,anchors,caps,records)
        act=k.ACT.act(caller,service,da,dr,7,300,rv(1000))
        actbytes=p.enc(b'act',label(caller),label(service),label(da),label(dr),label(7),label(300),p.u64(1000))
        actsig=self.identity(service).sign(actbytes)
        self.identity(service).public_key().verify(actsig,actbytes)
        tags=[];valid=True
        for src in (100,101):
            c=scalar(k.get(caps,iv(src)));chosen=(bundle_override or {}).get(src,c)
            point=self.geometry.point(action,slot)
            try:t=p.local_tag(self.caps[chosen],self.bundles[chosen],point,message)
            except ValueError:t=b'outside-scope'
            expected=self.endpoints[src].tag(label(c),point,message)
            tags.append(t);valid=valid and t==expected
        return {'m':m,'act':act,'caller':caller,'service':service,'bytes':message,'tags':tags,
                'valid':valid,'actbytes':actbytes,'actsig':actsig}
    def canonical(self,m):
        fields=[label(scalar(getattr(k.M,name)(m))) for name in (
          'rq_id','rq_context','rq_session','rq_caller','rq_service','rq_caller_auth','rq_service_auth')]
        entries=[]
        for src in (100,101):
            unit=z.simplify(k.get(k.M.rq_units(m),iv(src)))
            entries.append((label(src),scalar(k.U.unit_slot(unit)),
              label(scalar(k.get(k.M.rq_anchors(m),iv(src)))),
              label(scalar(k.get(k.M.rq_caps(m),iv(src)))),
              label(scalar(k.get(k.M.rq_records(m),iv(src))))))
        return p.encode_request(*fields,scalar(k.M.rq_action(m)),z.simplify(k.M.rq_payload(m)).as_string().encode(),entries)
    def verify_request(self,req):
        """Recompute at this commit, with the same message and current cap rows."""
        m=req['m'];message=self.canonical(m)
        valid=message==req['bytes']
        for n,src in enumerate((100,101)):
            unit=z.simplify(k.get(k.M.rq_units(m),iv(src)))
            current=self.value('cur_cap',unit)
            try:
                point=self.geometry.point(scalar(k.M.rq_action(m)),scalar(k.U.unit_slot(unit)))
                expected=self.endpoints[src].tag(label(current),point,message)
                valid=valid and req['tags'][n]==expected
            except (ValueError,KeyError):valid=False
        act=req['act']
        expiry=z.simplify(k.ACT.act_until(act))
        if not z.is_rational_value(expiry) or expiry.denominator_as_long()!=1:
            return False,False # This finite wire profile uses integral deadlines.
        actbytes=p.enc(b'act',*(label(scalar(getattr(k.ACT,f)(act))) for f in (
          'act_caller','act_service','act_caller_auth','act_service_auth','act_context','act_session')),
          p.u64(expiry.numerator_as_long()))
        authentic=actbytes==req['actbytes']
        try:self.identity(req['service']).public_key().verify(req['actsig'],actbytes)
        except InvalidSignature:authentic=False
        return authentic,valid
    def admission(self,name,req,expect=True):
        authentic,valid=self.verify_request(req)
        self.step(name,lambda s:k.admit(s,req['m'],req['act'],iv(req['caller']),iv(req['service']),iv(9),rv(self.now),
             authentic=bv(authentic),tags_valid=bv(valid)),expect)
    def count(self,slot):return [self.value('charges',k.U.unit(src,slot)) for src in (100,101)]

def run():
    t=Trace();O=t.right(-1,10,0,{0,1},5,'caller_root',True);R=t.right(-1,20,1,{0,1},5,'service_root',True)
    roots={src:t.initial_source(src,O) for src in (100,101)}
    # Prepare a correctly signed, locally derived transfer before ownership changes.
    late=t.right(O,13,0,{0},4,'offline_late_authorization')
    latecaps=t.child_caps(late,roots,{2},{0});lateargs=t.transfer_args(late,latecaps,800)
    A=t.right(O,11,0,{0,1},4,'caller_A');Acaps=t.child_caps(A,roots,{0,1,2},{0,1})
    t.transfer('transfer_root_to_A',A,Acaps,801)
    S=t.right(R,21,1,{0,1},4,'service_S');t.service(S,802)
    AA=t.right(A,12,0,{0},3,'caller_AA');AAcaps=t.child_caps(AA,Acaps,{0,1,2},{0})
    t.transfer('transfer_A_to_AA',AA,AAcaps,803)
    SS=t.right(S,22,1,{0},3,'service_SS');t.service(SS,804)

    first=t.request(AA,SS,400,0,payload='dialogue chunk one');assert first['valid']
    t.admission('bilateral_multisource_first',first);assert t.count(0)==[1,1]
    second=t.request(AA,SS,401,1,payload='dialogue chunk two');t.admission('same_ACT_second_chunk',second)
    assert t.count(1)==[1,1]
    t.admission('known_key_cannot_respend_position',t.request(AA,SS,402,0),False)
    forged_act_fields=[first['act'].arg(i) for i in range(first['act'].num_args())]
    forged_act_fields[-1]=rv(2000)
    assert not t.verify_request(dict(first,act=k.ACT.act(*forged_act_fields)))[0]
    t.step('exact_retry_no_second_delivery',lambda s:k.retry(s,first['m'],iv(first['caller'])))
    fields=[first['m'].arg(i) for i in range(first['m'].num_args())]
    fields[10]=z.Store(fields[10],iv(999),k.U.unit(999,999))
    same_wire=k.M.request(*fields)
    assert t.canonical(same_wire)==first['bytes']
    t.step('retry_ignores_nonencoded_array_entries',lambda s:k.retry(s,same_wire,iv(first['caller'])))
    assert t.count(0)==[1,1]
    # Parent knows the child's keys, but that is not ownership of those units.
    t.admission('known_child_secret_wrong_current_holder',t.request(A,SS,403,2),False)
    # Pooled valid tags over two different complete messages cannot be mixed.
    left=t.request(AA,SS,404,2,payload='left');right=t.request(AA,SS,404,2,payload='right')
    assert left['tags'][0]!=right['tags'][0] and left['tags'][1]!=right['tags'][1]
    mixed=dict(right,tags=[left['tags'][0],right['tags'][1]])
    t.admission('cross_message_tag_splice',mixed,False)
    old=t.request(AA,SS,405,2,payload='pending old request')
    t.step('revoke_A_cascades_to_AA',lambda s:k.revoke(s,iv(A),iv(O),rv(t.now)))
    t.admission('old_valid_tag_after_revoke_before_return',old,False)
    parents=z.K(k.U,iv(O))
    t.step('return_exact_unused_to_original_root_caps',lambda s:k.recover(s,iv(A),parents,iv(805),z.StringVal('return exact units slot2'),rv(t.now)))
    for src in (100,101):
        assert t.value('cur_cap',k.U.unit(src,2))==roots[src]
        assert t.value('cur_record',k.U.unit(src,2))==805
        assert t.value('cur_cap',k.U.unit(src,0))==AAcaps[src]
        t.check('inherited_action_one_stays_forbidden_'+str(src),k.get(t.s['hard_scope'],k.U.unit(src,2),iv(1)),False)
    assert t.count(0)==[1,1] and t.count(1)==[1,1] and t.count(2)==[0,0]
    t.transfer('ABA_delayed_transfer_rejected',late,latecaps,800,lateargs,False)
    sel,targets,oldpred,body=lateargs
    weakened=k.sync_group(t.s,iv(late),sel,targets,t.s['cur_record'],iv(800),body,rv(t.now))[0]
    t.check('NEGATIVE_ignoring_signed_predecessor_enables_ABA',weakened)
    broad=t.request(O,R,450,2,action=1,payload='try widening inherited policy')
    t.admission('inherited_restriction_blocks_parent_broad_key',broad,False)
    weakstate=dict(t.s)
    weakstate['hard_scope']=z.K(k.U,actions({0,1}))
    auth,tagok=t.verify_request(broad)
    weakguard=k.admission_guard(weakstate,broad['m'],broad['act'],iv(broad['caller']),iv(broad['service']),iv(9),rv(t.now),bv(auth),bv(tagok))
    t.check('NEGATIVE_erasing_H_enables_forbidden_action',weakguard)
    t.admission('old_tag_after_return_rejected',old,False)
    B=t.right(O,14,0,{0},4,'replacement_caller_B');Bcaps=t.child_caps(B,roots,{2},{0})
    t.transfer('replacement_uses_fresh_return_record',B,Bcaps,806)
    replacement=t.request(B,SS,406,2,payload='replacement work')
    oldsecret=t.request(B,SS,406,2,payload='replacement work',bundle_override=AAcaps)
    assert replacement['valid'] and not oldsecret['valid']
    t.admission('old_descendant_secret_cannot_auth_new_branch',oldsecret,False)
    for src in (100,101):
        target=t.endpoints[src].path(label(Bcaps[src]),t.geometry.point(0,2))
        oldpaths=[t.endpoints[src].block_path(label(AAcaps[src]),q) for q in t.caps[AAcaps[src]].prefixes]
        rootpaths=[t.endpoints[src].block_path(label(roots[src]),q) for q in t.caps[roots[src]].prefixes]
        assert not p.in_closure(oldpaths,target)
        assert p.in_closure(rootpaths,target) # negative condition: leaked parent defeats secrecy
    t.admission('replacement_success_same_anchor',replacement);assert t.count(2)==[1,1]
    t.step('post_revoke_exact_historical_query',lambda s:k.retry(s,first['m'],iv(first['caller'])))

    t.step('revoke_service_subtree',lambda s:k.revoke(s,iv(S),iv(R),rv(t.now)))
    oldservice=t.request(O,SS,407,3);t.admission('caller_valid_service_revoked',oldservice,False)
    NewS=t.right(R,23,1,{0,1},4,'replacement_service');t.service(NewS,807)
    unchanged_before={slot:t.count(slot) for slot in range(4)}
    final=t.request(O,NewS,408,3,action=1,payload='unrelated caller root survives')
    t.admission('unrelated_authorization_and_new_service_success',final)
    assert unchanged_before[3]==[0,0] and t.count(3)==[1,1]
    assert all(t.count(slot)==[1,1] for slot in range(4))
    result={'status':'passed','classification':'finite joint-interface witness, not unbounded proof',
      'bilateral_depth':2,'sources':2,'slots_per_source':4,'new_admissions':4,
      'source_charge_totals':{'100':4,'101':4},'same_anchor_recovery':True,
      'monotone_time_final':t.now,'negative_controls':['ignore signed predecessor','erase inherited restrictions','leak actual parent secret'],
      'uses_same_state_transition_module':str((ROOT/'state'/'kernel.py').relative_to(ROOT)),
      'checks':t.rows,'sha256':{str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest()
        for f in (Path(__file__),ROOT/'state'/'kernel.py',ROOT/'crypto'/'reference.py')}}
    (ROOT/'integration'/'RESULTS.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('status','bilateral_depth','sources','new_admissions','source_charge_totals')},indent=2))
    print('checked guards:',len(t.rows))
if __name__=='__main__':run()
