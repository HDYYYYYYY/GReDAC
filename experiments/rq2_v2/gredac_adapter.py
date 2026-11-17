"""RQ2 facade over the existing participant-owned TCP protocol.

The two preparation methods split deployment from task identity preparation.
They call the same Mesh/bootstrap and Node.setup APIs once each. All rights,
derivation, delivery, directory use, admission, revocation and return continue
through the existing Client APIs, without driver-side ledger decisions.
"""
import os,time
from . import timing,business


class Adapter:
    def __init__(self,run,cfg):
        self.run,self.cfg=run,cfg;self.trace=timing.TRACE;self.holdings={};self.wallet=None;self.receipts=[]
        self.service='S1';self.current=None;self.replacement=False;self.first=True;self.material=[]

    def infrastructure(self):
        from .gredac_hooks import enable_driver
        enable_driver(self.trace)
        from experiments.network_client import Mesh,Client
        lab=self.lab=Client.__new__(Client)
        lab.run,lab.case=self.run,'protocol';lab.path=self.run.out/'protocol';lab.path.mkdir()
        lab.mesh=Mesh(lab.path/'network');lab.own_mesh=True
        lab.endpoint_id,lab.authority_id,lab.contact_seconds='G','Authority',3600
        lab.rights={};lab.chains={};lab.holdings={};lab.initialized=set();lab.service_ids=[];lab.frozen=False
        lab.deadline=time.monotonic()+7200;lab.identities=lab.mesh.registrations
        lab.commit_delay_bound=float(os.environ.get('GREDAC_COMMIT_DELAY_BOUND','.05'))
        # No business participant/authorization is created before infra_ready.
        for name in ('Authority','G'):lab.mesh.add(name)
        public=lab.mesh.call('Authority','setup',kind='authority')
        lab.endpoint_public=lab.mesh.call('G','setup',kind='endpoint',authority_public=public,
            contact_seconds=3600,commit_delay_bound=lab.commit_delay_bound)
        lab.mesh.configure(endpoint='G',authority='Authority',authority_public=public,endpoint_public=lab.endpoint_public)
        self.run.manifest.update(transport='independent processes / TLS1.3 / loopback TCP',
            measurement='physical monotonic clocks; task excludes infrastructure startup, includes required identity work')

    def identities(self,names):
        prepared=['O','R'] if self.cfg['block']=='flow' else ['UO','UR','O','R',*names]
        for name in dict.fromkeys(prepared):
            with self.trace.span('identity.prepare.'+name,'identity'):
                self.lab.ensure(name)
        for name in [x for x in prepared if x.startswith('S')]:
            self.lab.mesh.call(name,'handler',kind='fixed',target='rq2')

    def users(self,names):
        # GReDAC assumes authenticated users; this prototype provisions their
        # test CA identities. It does not invent a password/account protocol.
        for name in ('UO','UR'):
            with self.trace.span('authenticated_user.prepare.'+name):self.lab.ensure(name)

    def dynamic_identity(self,name):
        if self.cfg['block']=='flow':
            assert name not in self.lab.mesh.processes,'member must not be precreated'
            with self.trace.span('identity.dynamic.'+name):self.lab.ensure(name)
            self.trace.event('dynamic_identity_ready',member=name)
            if name.startswith('S'):self.lab.mesh.call(name,'handler',kind='fixed',target='rq2')

    def setup(self,total):
        from gredac.crypto import domain_for
        lab=self.lab
        with self.trace.span('authorization_setup','I',display_phase=True):
            lab.context('c',['budget']);lab.source('budget',total,['c'])
            self.root=lab.right('O-c','O','c',actions=['query'])
            self.sroot=lab.right('R-c','R','c',side='service',actions=['query'])
            self.holdings['O']=lab.seed(self.root,{'budget':list(range(total))},
                domains={'budget':domain_for(['query'],range(total))})
            lab.freeze_setup()
        # Root setup contains no service-member grant. This belongs to II.
        self.service_member('S1')

    def service_member(self,name):
        lab=self.lab
        # Client.right auto-publishes at the end. Close II exactly when that
        # call begins, then time the same call as III. No operation is moved.
        publish=lab.publish_service;phase=self.trace.span('service_member_authorization','II',display_phase=True,member=name)
        phase.__enter__();closed=False
        def observed(*args,**kwargs):
            nonlocal closed
            phase.__exit__(None,None,None);closed=True
            with self.trace.span('service_directory_publication','III.first',display_phase=True):return publish(*args,**kwargs)
        lab.publish_service=observed
        try:
            self.dynamic_identity(name)
            rid=lab.right(name+'-c',name,'c',self.sroot,side='service',actions=['query'])
        except BaseException:
            if not closed:
                import sys
                phase.__exit__(*sys.exc_info());closed=True
            raise
        finally:
            if not closed:phase.__exit__(None,None,None)
            lab.publish_service=publish
        self.service=rid

    def handoff(self,parent,child,slots):
        lab=self.lab
        with self.trace.span('delegation','II',display_phase=True,parent_agent=parent,child_agent=child,units=len(slots)):
            self.dynamic_identity(child)
            rid=lab.right(child+'-c',child,'c',self.holdings[parent].right,actions=['query'])
            self.holdings[child]=lab.delegate(self.holdings[parent],rid,{'budget':slots},actions=['query'])
        self.current=child;self.slots=slots

    def conversation(self,begin,count,slots):
        from experiments.network_client import WalletRef
        old=self.wallet.id if getattr(self,'recontact_required',False) else None
        value=self.lab.mesh.call(self.current,'rq2_conversation',right=self.holdings[self.current].right,
            service=self.service,slots=slots,begin=begin,count=count,old_wallet=old,replacement=self.replacement)
        assert value['completed']==count and value['pid']!=os.getpid()
        self.wallet=WalletRef(value['wallet'],self.holdings[self.current]);assert self.wallet.service==self.service
        self.replacement=False;self.recontact_required=False

    def replace(self,side,remaining,parent='A1'):
        lab=self.lab;self.trace.event('replacement_trigger',side=side)
        if side=='caller':
            with self.trace.span('revoke_and_return','IV',display_phase=True):
                lab.call(parent,'revoke',dict(id=self.holdings[self.current].right))
                self.trace.event('revocation_acknowledged')
                returned,slots=lab.recovery(self.wallet,self.holdings[parent].right,actor=parent)
                # Signed receipt rows follow ledger key order, not numeric
                # slot order. Compare complete sets and detect duplicates.
                assert sorted(slots['budget'])==remaining,'unexpected returned units'
                self.holdings[parent]=returned;self.trace.event('return_verified')
            self.handoff(parent,'Anew',remaining)
        else:
            with self.trace.span('service_revoke','IV',display_phase=True):
                lab.call('R','revoke',dict(id=self.service));self.trace.event('revocation_acknowledged')
            self.service_member('S2')
            self.recontact_required=True
            # No return/reissue or old-ACT retargeting; next conversation opens
            # a fresh contact to the currently published service member.
        self.replacement=True

    def finish(self):
        # There is no native termination message in this profile. Do not add
        # a fake protocol teardown; shared transport teardown follows audit.
        with self.trace.span('task_end','end',display_phase=True):pass
        self.trace.event('task_finish')

    def audit_close(self):
        from experiments.support import write_json
        from gredac.crypto import canonical
        try:
            with self.trace.span('post_task_material_observation','audit'):
                for name,h in self.holdings.items():
                    size=self.lab.mesh.call(name,'material_size',right=h.right)
                    chain=self.lab.mesh.call(name,'holding_chain',right=h.right)
                    self.material.append(dict(participant=name,material_bytes=size,chain=chain,
                        chain_records=len(chain),chain_bytes=len(canonical(chain))))
                    evidence=self.lab.mesh.call(name,'rq2_evidence')
                    assert evidence['pid']!=os.getpid();self.receipts+=evidence['results']
            assert len(self.receipts)==self.cfg['requests']
            assert len({r['index'] for r in self.receipts})==self.cfg['requests']
            audit=self.lab.close();assert audit['new_requests']==self.cfg['requests']
            write_json(self.run.out/'protocol_audit.json',audit)
            write_json(self.run.out/'business_results.json',self.receipts)
            write_json(self.run.out/'materials.json',self.material)
            # Offline audit after all role processes have closed. This read
            # supplies only result diagnostics, never a runtime decision.
            import sqlite3
            path=self.lab.path/'network/actors/G/guard.sqlite'
            with sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True) as db:
                counts=dict(db.execute('SELECT kind,count(*) FROM records GROUP BY kind'))
            write_json(self.run.out/'storage_counts.json',dict(scope='offline post-task audit only',records_by_kind=counts))
        finally:
            if not self.lab.mesh.closed:self.lab.mesh.close()

    def cleanup(self):
        if hasattr(self,'lab') and hasattr(self.lab,'mesh') and not self.lab.mesh.closed:self.lab.mesh.close()
