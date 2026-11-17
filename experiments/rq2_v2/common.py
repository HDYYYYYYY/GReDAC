"""Shared lifecycle, telemetry and result schema; no experiment matrix here."""
import argparse,json,os,resource,shutil,threading,time,traceback
from pathlib import Path
from . import timing

PACKAGE=Path(__file__).resolve().parent


def parser(description):
    p=argparse.ArgumentParser(description=description)
    p.add_argument('--out',required=True);p.add_argument('--case-json',required=True)
    p.add_argument('--repeat-index',type=int,default=0)
    return p


def configure():
    os.umask(0o077)
    # The author artifact passes naive datetime.now() to X.509. Run both
    # methods in UTC so its unchanged certificate code has correct validity.
    os.environ['TZ']='UTC';time.tzset()
    os.environ['GREDAC_SLOT_BITS']='15'
    os.environ['GREDAC_BUFFER_DIAGNOSTICS']='1'
    available=sorted(os.sched_getaffinity(0));os.sched_setaffinity(0,available[:8])
    soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE,(min(65536,hard),hard))


class Resources:
    def __init__(self,out):
        self.out=out;self.rows=[];self.stop=threading.Event();self.thread=threading.Thread(target=self.loop,daemon=True);self.thread.start()
    def sample(self):
        from gredac.metrics import process_snapshot
        pids={os.getpid()}
        for p in Path('/proc/self/task').glob('*/children'):
            try:pids.update(map(int,p.read_text().split()))
            except FileNotFoundError:pass
        roles={p:process_snapshot(p) for p in pids}
        row=dict(time_ns=time.monotonic_ns(),processes=roles,sampled_total_rss_kib=sum(v.get('rss_kib',0) for v in roles.values()))
        for name in ('cpu','io','memory'):row[name+'_pressure']=Path('/proc/pressure',name).read_text()
        row['diskstats']=Path('/proc/diskstats').read_text();self.rows.append(row)
    def loop(self):
        while not self.stop.is_set():self.sample();self.stop.wait(1)
    def close(self):
        self.stop.set();self.thread.join();self.sample()
        (self.out/'resources.json').write_text(json.dumps(self.rows,indent=2))


class Task:
    live=[]
    def __init__(self,run,cfg,names,total):
        self.run,self.cfg=run,cfg;self.trace=timing.TRACE;self.backend=None
        self.live.append(self)
        if cfg['method']=='GReDAC':from .gredac_adapter import Adapter
        else:from .author import Adapter
        self.backend=Adapter(run,cfg)
        if cfg['block']=='flow':
            # Group 1: deployment is not an experimental timing stage.
            self.backend.infrastructure();self.trace.event('infrastructure_ready')
            self.trace.event('user_prerequisites_begin')
            with self.trace.span('user_prerequisites','prerequisite',display_phase=True):self.backend.users(names)
            self.trace.event('user_prerequisites_ready')
        else:
            self.trace.event('infrastructure_start_begin')
            with self.trace.span('infrastructure_start','environment',display_phase=True):self.backend.infrastructure()
            self.trace.event('infrastructure_ready')
        self.trace.event('task_participant_prepare_begin')
        with self.trace.span('participant_preparation','identity',display_phase=True):self.backend.identities(names)
        self.trace.event('task_authorization_or_handoff_begin')
        self.backend.setup(total)
    def handoff(self,parent,child,slots):return self.backend.handoff(parent,child,slots)
    def conversation(self,begin,count,slots):return self.backend.conversation(begin,count,slots)
    def replace(self,side,remaining):return self.backend.replace(side,remaining)
    def finish(self):self.backend.finish();self.backend.audit_close()


def run_case(args,experiment,execute):
    configure()
    # Run's old top-level glob does not include this new package. Snapshot it
    # explicitly; RQ2 and author source hashes use the recursive freeze list.
    from experiments.support import Run,write_json
    args.repeats=1;args.slot_bits=15;cfg=json.loads(args.case_json)
    run=Run(args,'rq2_v2_'+experiment)
    shutil.copytree(PACKAGE,run.out/'source/experiments/rq2_v2',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    import hashlib
    for p in PACKAGE.rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:
            key='experiments/rq2_v2/'+p.relative_to(PACKAGE).as_posix();run.manifest['source_sha256'][key]=hashlib.sha256(p.read_bytes()).hexdigest()
    run.manifest['code_fingerprint']=hashlib.sha256(json.dumps(run.manifest['source_sha256'],sort_keys=True).encode()).hexdigest()
    os.environ['RQ2_TIMING_DIR']=str(run.out/'timing');os.environ['RQ2_RUN_ID']=run.out.name
    trace=timing.start(run.out/'timing',cfg['method'],'Driver',run.out.name)
    assert time.get_clock_info('perf_counter').implementation==time.get_clock_info('monotonic').implementation
    run.manifest.update(rq2_method=cfg['method'],clock_implementation=time.get_clock_info('monotonic').implementation,
        timezone='UTC',case=cfg,per_request_controller_roundtrip=False)
    monitor=Resources(run.out);task=None
    try:
        task=execute(run,cfg);task.finish()
        trace.flush();monitor.close()
        from .results import summarize
        result=summarize(run.out,cfg)
        result.update(repeat=args.repeat_index,measurement_scope='real independent-process loopback TCP/TLS; no LLM or simulated think time')
        run.finish([result])
    except BaseException as e:
        # Cleanup is outside task timing; preserve every failure and incomplete
        # span. No synthetic response and no automatic replacement run.
        for active in Task.live:
            if active.backend:
                try:active.backend.cleanup()
                except Exception:pass
        from experiments.network_client import Mesh
        for mesh in Mesh.live:
            if not mesh.closed:
                try:mesh.close()
                except Exception:pass
        trace.flush();monitor.close();run.save_samples()
        run.manifest.update(status='FAIL',error=repr(e),traceback=traceback.format_exc())
        write_json(run.out/'manifest.json',run.manifest);raise
