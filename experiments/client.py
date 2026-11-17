"""公共协议客户端，只装配真实API，不生成实验工作负载。

权利/位置变化走签名Authority接口，消费走真实TLS MemoryBIO和Guard。
measure包含API执行；事务观察点位于SQL COMMIT返回后。close检查持久
请求/effect及永久位置唯一性，各实验自行定义业务成功与预期拒绝。
"""
import json
import time
from collections import Counter
from pathlib import Path
from gredac.authority import AgentAuthority
from gredac.contact import establish
from gredac.crypto import SCHEME, Signer, by_slot, canonical, digest, domain_for
from gredac.guard import InteractionGuard, Holding, Wallet
from gredac.pki import PKI
from gredac.storage import MonotonicClock, Store, position_key
from .support import stats, write_json


class Client:
    def __init__(self, run, case, lease=5, contact_seconds=30):
        self.run, self.case = run, case
        self.path = run.out/case
        self.path.mkdir(parents=True, exist_ok=False)
        self.clock, self.ids, self.holdings, self.transactions = MonotonicClock(), {}, {}, []
        self.install_metrics = []
        self.admission_commits = {}
        self.deadline = self.clock.now()+3600
        self.pki = PKI(self.path/'pki')
        self.a = Store(self.path/'authority.sqlite', self.observe)
        self.g = Store(self.path/'guard.sqlite', self.observe)
        self.authority = AgentAuthority(self.a, self.clock, self.pki, 'joint',
                                       lease_seconds=lease,contact_seconds=contact_seconds)
        for name, owner in [('UO','UO'),('UR','UR'),('O','UO'),('R','UR'),('G','UO'),('Authority','UO')]:
            self.measure('bootstrap_identity', lambda n=name,o=owner:self.authority.bootstrap_identity(self.actor(n),o))
        self.guard = InteractionGuard(self.g, self.authority, self.clock, self.pki, 'joint')

    def observe(self, row):
        span = getattr(self.run.local, 'span', None) or {}
        self.transactions.append({**row, 'case': self.case, 'span': span.get('id'),
                                  'label': span.get('label'), 'phase':span.get('phase'),
                                  'request_id': span.get('request_id')})
        # 每请求第一次Guard COMMIT就是核销持久点。O(1)记录避免在高负载下
        # 每请求扫描全部历史事务，从而人为制造二次方测量开销。
        if row['committed'] and row['store']=='guard.sqlite' and span.get('label')=='guard.charge':
            self.admission_commits.setdefault(span.get('request_id'),row['end_ns'])

    def measure(self, label, fn, **metadata):
        return self.run.measure(self.case, label, fn, **metadata)

    def actor(self, name):
        if name not in self.ids:
            self.ids[name] = Signer(name)
        return self.ids[name]

    def call(self, actor, operation, args):
        return self.measure('authority.'+operation,
                            lambda:self.authority.call(self.actor(actor), operation, args))

    def context(self, cid, sources, tasks=None, cooperation='g'):
        body = {'id':cid, 'tasks':tasks or [cid], 'cooperation':cooperation,
            'caller_approver':'UO','service_approver':'UR','caller_root':'O-'+cid,'service_root':'R-'+cid,
            'req':{op:sources for op in ('query','summary')},
            'basis':{s:s for s in sources},'deadline':self.deadline,'scheme':SCHEME}
        self.call('UO','context',{'body':body,'approvals':{o:self.actor(o).sign(body) for o in ('UO','UR')}})

    def source(self, source, size, contexts):
        self.call('UO','source',{'id':source,'issuer':'UO','controller':'UO',
            'approval':'issue-'+source,'size':size,'contexts':contexts,'basis':source,
            'actions':['query','summary'],'deadline':self.deadline})

    def right(self, rid, holder, cid, parent=None, side='caller', actions=None):
        par = self.authority.right(parent) if parent else None
        child = self.actor(holder)
        body = {'id':rid,'owner':holder,'context':cid,'side':side,'parent':parent,
            'actions':actions or ['query','summary'],'public_key':child.public,
            'deadline':self.deadline,'depth':par['depth']-1 if par else 32}
        actor = par['owner'] if par else ('UO' if side=='caller' else 'UR')
        self.call(actor,'right',{**body,'proof':child.sign(body)})
        if parent and not self.a.get('registrations',holder):
            challenge = self.call(actor,'challenge',{'right':rid})
            csr = self.pki.csr(child)
            reg = {'agent_id':holder,'right':rid,'public_key':child.public,
                'contact_public_key':child.contact.public_key().public_bytes_raw().hex(),
                'challenge':challenge['id'],'csr_ref':digest(csr)}
            result = self.call(actor,'register',{'body':reg,'proof':child.sign(reg),'csr':csr})
            self.pki.materialize(child,result)
        self.holdings.setdefault(rid,Holding(rid))
        return rid

    def receive(self, rid, caps, parent=None):
        holding = self.holdings.setdefault(rid,Holding(rid))
        for cap in caps:
            holding.caps[cap['gid']] = cap
            if parent is not None:
                bundle = self.measure('client.derive',lambda c=cap:parent.bundles[c['key_parent']['id']].child(c['gid'],c['domain']))
            else:
                bundle = self.measure('authority.rebuild',lambda c=cap:self.authority.forest.rebuild(c['gid']))
            holding.bundles[cap['gid']] = bundle
        return holding

    def parents(self, domains):
        return {s:{str(i):self.a.get('positions',position_key(s,i))['current_cap']['gid']
                   for i in by_slot(d)} for s,d in domains.items()}

    def seed(self, rid, selections):
        domains = {s:domain_for(['query','summary'],v) for s,v in selections.items()}
        return self.receive(rid,self.call('UO','seed',{'right':rid,'domains':domains}))

    def delegate(self, parent, rid, selections, actions=None):
        domains = {s:domain_for(actions or ['query','summary'],v) for s,v in selections.items()}
        caps = self.call(self.authority.right(parent.right)['owner'],'delegate',
            {'parent':parent.right,'child':rid,'domains':domains,'parents':self.parents(domains)})
        return self.receive(rid,caps,parent)

    def reserve(self, holding, service, selections):
        """四个联系接口+reserve+验证材料交付，再本地安装、握手和会话。
        编码字节在各操作计时外记录；不等于套接字流量。
        """
        owner = self.authority.right(holding.right)['owner']
        receiver = self.authority.right(service)['owner']
        act,key,_ = self.measure('contact',lambda:establish(self.authority,self.actor(owner),self.actor(receiver),holding.right,service))
        command = self.call(owner,'reserve',{'caller':holding.right,'service':service,'slots':selections,'act':act['body']['id']})
        material = self.measure('verifier_delivery',lambda:self.authority.verifier_delivery(command))
        self.measure('guard.install',lambda:self.guard.install(command,material))
        lane = command['body']['lane']
        link = self.measure('tls.handshake',lambda:self.pki.link(owner,'G'))
        session = self.measure('guard.session',lambda:self.guard.session(lane,self.actor(owner),self.actor(receiver),key,link))
        self.install_metrics.append({'phase':getattr(self.run.local,'phase','setup'),
            'lane':lane['id'],'lane_bytes':len(canonical(lane)),
            'command_bytes':len(canonical(command)), 'verifier_bytes':len(canonical(material)),
            'cap_bytes':sum(len(canonical(c)) for c in lane['caps'].values()),
            'rows':len(lane['rows'])})
        return Wallet(lane,holding,session,key,link)

    def charge(self, wallet, selections, request_id, operation='query', payload=None):
        packet = self.measure('client.packet',lambda:wallet.packet(operation,request_id,selections,payload),request_id=request_id)
        return self.measure('guard.charge',lambda:self.guard.charge(packet,operation,wallet.link),request_id=request_id)

    def renew(self, wallet):
        command = self.call(wallet.lane['caller']['owner'],'renew',{'lane':wallet.lane['id']})
        self.measure('guard.renew',lambda:self.guard.engine.renew(command))
        return command['body']['lease']

    def seal(self, wallet):
        command = self.call('UO','prepare_seal',{'lane':wallet.lane['id']})
        return self.measure('guard.seal',lambda:self.guard.engine.seal(command))

    def recovery(self, wallet, receiver):
        receipt = self.seal(wallet)
        returned = self.call('UO','reclaim',{'receipt':receipt})
        slots = {}
        for row in returned:
            slots.setdefault(row['source'],[]).append(row['slot'])
        assert slots and all(slots.values())
        caps = self.call('UO','recover',{'right':receiver,'slots':slots})
        return self.receive(receiver,caps),slots

    def setup(self, slots, source_count=2, depth=1, cid='c', issued_size=None):
        """issued_size是发行全集，slots是获批活动集合，必须分别控制。"""
        sources = [f'S{i}' for i in range(source_count)]
        self.context(cid,sources)
        for s in sources:
            self.source(s,issued_size or max(slots)+1,[cid])
        root = self.right('O-'+cid,'O',cid)
        service = self.right('R-'+cid,'R',cid,side='service')
        service = self.right('service-'+cid,'R1',cid,parent=service,side='service')
        holding = self.seed(root,{s:slots for s in sources})
        for level in range(depth):
            rid = self.right(f'A{level}-{cid}',f'A{level}',cid,parent=holding.right)
            holding = self.delegate(holding,rid,{s:slots for s in sources})
        return holding,service,sources,root

    def admission_commit(self, request_id):
        return self.admission_commits[request_id]

    def close(self):
        # Independent, read-only conservation audit over durable output records.
        requests = self.g.all('requests')
        seen, counts = set(),Counter()
        for record in requests.values():
            decision = record['decision']
            assert len(decision['sources']) == len({s for s,_ in decision['sources']})
            for source,slot in decision['sources']:
                assert (source,slot) not in seen
                seen.add((source,slot)); counts[source]+=1
                assert self.g.get('live',position_key(source,slot))['state'] in ('spent','closed-spent')
        assert len(self.g.all('effects')) == len(requests)
        for source,spec in self.a.all('sources').items():
            assert counts[source] <= spec['size']
        summary = {'new_requests':len(requests),'spent_by_source':dict(counts),
            'authority_calls':dict(self.authority.calls), 'audit':'PASS',
            'transaction_metrics_ms': {k:stats([t[k]/1e6 for t in self.transactions])
                for k in ('lock_wait_ns','begin_ns','body_ns','commit_or_rollback_ns')},
            'transactions':len(self.transactions)}
        with (self.path/'transactions.jsonl').open('w') as f:
            for t in self.transactions: f.write(json.dumps(t)+'\n')
        for store in (self.a,self.g):
            store.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            store.close()
        summary['database_bytes'] = sum(p.stat().st_size for p in self.path.glob('*.sqlite'))
        write_json(self.path/'case.json',summary)
        return summary
