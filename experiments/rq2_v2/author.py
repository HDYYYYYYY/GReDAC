"""Lifecycle adapter for gsiros/saga@7372111, not a mechanism reproduction.

Fresh native MongoDB, CA HTTP distribution and Provider HTTPS are real child
processes. Each user and Agent owns its original state in its own process.
Only addresses/workdirs, documented quota constants and LocalAgent business
are adapted. Author .py files are verified byte-for-byte before each run.
"""
import hashlib,json,multiprocessing,os,shutil,socket,subprocess,time,zipfile
from pathlib import Path
from . import timing

SOURCE=Path(__file__).with_name('author_source.zip')


def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]


class Adapter:
    def __init__(self,run,cfg):
        self.run,self.cfg,self.trace=run,cfg,timing.TRACE;self.children={};self.links={};self.actors={};self.handovers=[]
        self.service='S1';self.current=None;self.replacement=False;self.logs=[]
        self.runtime_roles={}
        self.ctx=multiprocessing.get_context('spawn');self.options=dict(out=str(run.out),timing=str(run.out/'timing'),run_id=run.out.name)

    def spawn(self,role,**extra):
        from .author_worker import process_main
        parent,child=self.ctx.Pipe();p=self.ctx.Process(target=process_main,args=(role,str(self.root),child,{**self.options,**extra}),name='author-'+role)
        p.start();child.close();self.children[role]=p;self.links[role]=parent
        assert parent.poll(60),'author role bootstrap timeout: '+role
        result=parent.recv();assert 'error' not in result,result
        self.runtime_roles[role]=dict(pid=p.pid,source_file=result.get('source_file'))
        return result

    def call(self,role,**cmd):
        self.links[role].send(cmd);assert self.links[role].poll(1500),'author operation timeout: '+role
        value=self.links[role].recv();assert 'error' not in value,value;return value

    def infrastructure(self):
        import yaml
        manifest=json.loads(SOURCE.with_suffix('.json').read_text());assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()==manifest['archive_sha256']
        self.root=self.run.out/'author-work';self.root.mkdir(mode=0o700)
        with zipfile.ZipFile(SOURCE) as z:
            for name,sha in manifest['files'].items():
                target=(self.root/name).resolve();assert target.is_relative_to(self.root.resolve())
                data=z.read(name);assert hashlib.sha256(data).hexdigest()==sha
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        self.options.update(provider_port=port(),mongo_port=port(),ca_port=port())
        self.options['mongo_uri']=f"mongodb://127.0.0.1:{self.options['mongo_port']}/saga"
        config=yaml.safe_load((self.root/'config.yaml').read_text())
        config['ca']['endpoint']=f"http://127.0.0.1:{self.options['ca_port']}"
        config['provider']['endpoint']=f"https://127.0.0.1:{self.options['provider_port']}"
        config['provider']['config'].update(COMMON_NAME='127.0.0.1',IP='127.0.0.1')
        config['mongo_uri_for_tools']=self.options['mongo_uri']
        (self.root/'config.yaml').write_text(yaml.safe_dump(config))
        # CA creation uses the author's actual crypto functions. Config is
        # generated before import; the committed Python source is unchanged.
        import sys
        sys.path.insert(0,str(self.root))
        from saga.common import crypto
        (self.root/'ca-distribution').mkdir()
        crypto.save_ca(str(self.root/'ca-distribution'),'ca',*crypto.generate_ca(config['ca']['config']))
        from .author_worker import ca_main
        parent,child=self.ctx.Pipe();p=self.ctx.Process(target=ca_main,args=(str(self.root/'ca-distribution'),self.options['ca_port'],child),name='author-CA')
        p.start();child.close();self.children['CA']=p;assert parent.poll(30);parent.recv();parent.close()
        db=self.root/'mongo';db.mkdir()
        binary=os.environ.get('RQ2_MONGOD') or shutil.which('mongod') or 'mongod'
        self.mongo_command=[binary,'--dbpath',str(db),'--bind_ip','127.0.0.1','--port',str(self.options['mongo_port']),
            '--wiredTigerCacheSizeGB','0.25','--logpath',str(self.run.out/'mongod.log')]
        self.mongo=subprocess.Popen(self.mongo_command,stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
        from pymongo import MongoClient
        self.mongo_client=MongoClient(self.options['mongo_uri'],serverSelectionTimeoutMS=500)
        until=time.monotonic()+60
        while True:
            try:self.mongo_client.admin.command('ping');break
            except Exception:
                assert time.monotonic()<until and self.mongo.poll() is None,'MongoDB not ready';time.sleep(.05)
        self.spawn('Provider')
        until=time.monotonic()+30
        while True:
            try:
                with socket.create_connection(('127.0.0.1',self.options['provider_port']),timeout=.2):break
            except OSError:assert time.monotonic()<until,'Provider not listening';time.sleep(.02)
        self.run.manifest.update(system='SAGA-author-source@7372111',author_source=manifest,
            transport='original Provider HTTPS/mTLS and original Agent TLS sockets; loopback',
            author_settings=dict(Q_MAX=2049,MAX_QUERIES=4096,ACT_seconds=3600,mongodb_command=self.mongo_command,
                note='original storage/writeConcern retained, not equivalent to GReDAC WAL/FULL ledger'))

    def edges(self,names):
        # Only actual incoming first-contact edges consume OTKs. A root that
        # only initiates contacts receives zero OTKs, not an artificial batch.
        edges=[('O','A1')]
        if 'A2' in names:edges.append(('A1','A2'))
        final='A2' if 'A2' in names else 'A1';edges.append((final,'S1'))
        if 'Anew' in names:edges += [('A1','Anew'),('Anew','S1')]
        if 'S2' in names:edges += [(final,'S2')]
        self.planned_edges=edges

    def users(self,names):
        self.edges(names)
        for owner in ('UO','UR'):
            phase='prerequisite' if self.cfg['block']=='flow' else 'identity'
            with self.trace.span('identity.user.'+owner,phase):self.spawn(owner,identity_phase=phase)

    def prepare_agent(self,name,phase):
        assert name not in self.actors,'member must not be precreated'
        owner='UR' if name.startswith('S') else 'UO';incoming=sum(b==name for _,b in self.planned_edges)
        with self.trace.span('identity.agent.'+name,phase):
            material=self.call(owner,op='register_agent',name=name,port=port(),incoming=incoming,phase=phase)
            self.actors[name]=material;self.spawn(name,material_path=material['material_path'],identity_phase=phase)
        if phase=='II':self.trace.event('dynamic_identity_ready',member=name)

    def identities(self,names):
        if self.cfg['block']!='flow':self.users(names)
        for name in dict.fromkeys(['O'] if self.cfg['block']=='flow' else ['O',*names]):self.prepare_agent(name,'identity')

    def setup(self,total):
        # No invented bilateral capability or root quota step for SAGA.
        self.trace.event('native_setup_not_applicable',reason='no root capability tree / shared quota setup')
        if self.cfg['block']=='flow':
            with self.trace.span('native_service_participant_prepare','II',display_phase=True):self.prepare_agent('S1','II')

    def handoff(self,parent,child,slots):
        if self.cfg['block']=='flow':
            with self.trace.span('native_task_handoff','II',display_phase=True,parent_agent=parent,child_agent=child):
                self.prepare_agent(child,'II')
                self.call(parent,op='connect',kind='handoff',target=self.actors[child]['aid'],recipient_name=child)
        else:self.call(parent,op='connect',kind='handoff',target=self.actors[child]['aid'],recipient_name=child)
        self.handovers.append((parent,child));self.current=child

    def conversation(self,begin,count,slots):
        self.call(self.current,op='connect',kind='service',target=self.actors[self.service]['aid'],recipient_name=self.service,
            begin=begin,count=count,replacement=self.replacement)
        self.replacement=False

    def replace(self,side,remaining,parent='A1'):
        self.trace.event('replacement_trigger',side=side)
        # Business replacement only. No deactivate, ledger edits, credential
        # wiping, process kill, shared-quota return, or fictional strong revoke.
        if side=='caller':self.handoff(parent,'Anew',remaining)
        else:
            if self.cfg['block']=='flow':
                with self.trace.span('native_service_replacement_prepare','II',display_phase=True):self.prepare_agent('S2','II')
            self.service='S2'
        self.replacement=True
        self.trace.event('native_revocation_not_applicable',reason='paper describes Provider deactivation; pinned official artifact has no callable interface')

    def finish(self):self.trace.event('task_finish')

    def audit_close(self):
        from experiments.support import write_json
        rows={name:self.call(name,op='evidence') for name in self.actors}
        completed=[v for row in rows.values() for v in row['completed'] if 'index' in v]
        received=[v for row in rows.values() for v in row['received'] if v['payload']['kind']=='query']
        assert len(completed)==len(received)==self.cfg['requests']
        assert len({r['index'] for r in completed})==self.cfg['requests']
        assert len({r['pid'] for r in rows.values()})==len(rows),'roles share a process'
        # Audit the actual per-token quota observed by the original validators.
        token_checks={}
        for row in rows.values():
            for v in row['counters']['validations']:
                if v['check']=='token_is_valid':token_checks.setdefault(v['token_hash'],[]).append(v)
        expected=len(self.handovers)+1+(self.cfg.get('replacement') in ('caller','service'))
        assert len(token_checks)==expected
        for items in token_checks.values():
            assert all(v['valid'] and v['quota_before']==2049-i for i,v in enumerate(items))
        assert sum(len(v) for v in token_checks.values())==self.cfg['requests']+len(self.handovers)+expected
        assert sum(r['counters']['generated_tokens'] for r in rows.values())==expected
        # MongoDB read is post-task audit only. Native collection state is
        # never consulted by the driver to synthesize an authorization.
        db=self.mongo_client.get_default_database();counts={n:db[n].count_documents({}) for n in ('users','agents')}
        assert counts==dict(users=2,agents=len(self.actors))
        from bson.json_util import dumps
        (self.run.out/'mongo-audit.json').write_text(dumps({n:list(db[n].find()) for n in ('users','agents')},indent=2))
        write_json(self.run.out/'protocol_audit.json',dict(audit='PASS',author_native=True,contacts=expected,
            business_requests=len(completed),terminal_messages=expected,handoffs=len(self.handovers),
            generated_otks=len(self.planned_edges),unused_otks=sum(r['remaining_otks'] for r in rows.values()),
            strong_revoke=None,safe_return=None,shared_quota=None,storage_counts=counts,
            storage_write_concern=db.write_concern.document,mongodb_build=self.mongo_client.admin.command('buildInfo')))
        write_json(self.run.out/'author_role_evidence.json',rows);write_json(self.run.out/'business_results.json',completed)
        source=json.loads(SOURCE.with_suffix('.json').read_text())
        runtime_hashes={name:hashlib.sha256((self.root/name).read_bytes()).hexdigest()
            for name in source['files'] if name.endswith('.py')}
        assert all(source['files'][name]==sha for name,sha in runtime_hashes.items())
        write_json(self.run.out/'author_runtime_provenance.json',dict(commit=source['commit'],
            python_files=runtime_hashes,roles=self.runtime_roles,source_modified=False))
        self.cleanup()

    def cleanup(self):
        for role,link in self.links.items():
            p=self.children[role]
            if p.is_alive():
                try:link.send(dict(op='stop'))
                except (OSError,BrokenPipeError):pass
        for role,p in self.children.items():
            if role!='CA':p.join(10)
            if p.is_alive():p.terminate();p.join(10)
        if hasattr(self,'mongo_client'):self.mongo_client.close()
        if hasattr(self,'mongo') and self.mongo.poll() is None:self.mongo.terminate();self.mongo.wait(timeout=30)
