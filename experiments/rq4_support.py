"""Shared assembly/measurement only; each RQ4 entry owns its workload.

No driver imports another driver's schedule or outputs. Nested spans are
reported separately, never added as if they were disjoint wall-clock time.
"""
import os,time,threading,resource,json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from .support import stats,write_json


def configure(cpus=8):
    allowed=sorted(os.sched_getaffinity(0));os.sched_setaffinity(0,allowed[:cpus])
    # K independent SQLite/WAL stores require multiple descriptors each. Use
    # a recorded host setting, so the default 1024-descriptor shell limit is
    # not mistaken for a protocol scaling limit. Never exceed the hard limit.
    soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE,(min(65536,hard),hard))


class CapacityLimit(RuntimeError):
    """A predeclared experimental budget was reached, not a protocol rejection."""


def request_stats(rows):
    """Success throughput and latency are separate; failed attempts stay in rows."""
    good=[r for r in rows if r['error'] is None]
    return dict(attempted=len(rows),completed=len(good),failed=len(rows)-len(good),
        response_ms=stats([(r['end']-r['release'])*1000 for r in good]),
        attempt_response_ms=stats([(r['end']-r['release'])*1000 for r in rows]),
        processing_ms=stats([(r['end']-r['start'])*1000 for r in rows]),
        queue_ms=stats([(r['start']-r['submitted'])*1000 for r in rows]),
        worker_queue_ms=stats([(r['thread_start']-r['submitted'])*1000 for r in rows]),
        service_lock_ms=stats([(r['start']-r['thread_start'])*1000 for r in rows]),
        submission_late_ms=stats([(r['submitted']-r['release'])*1000 for r in rows]))


class Monitor:
    def __init__(self,run,filename='resources.json',available_memory=False):
        self.run=run;self.filename=filename;self.rows=[];self.stop=threading.Event();self.lock=threading.Lock()
        self.available_memory=available_memory
        self.thread=threading.Thread(target=self.loop,daemon=True);self.thread.start()
    def loop(self):
        while not self.stop.is_set():
            self.sample();self.stop.wait(2)
    def sample(self):
        # All owned role PIDs are sampled in the same sweep. This is a sampled
        # simultaneous footprint, not the sum of each PID's lifetime maximum.
        with self.lock:
            row=dict(time=time.monotonic(),cpu=time.process_time(),max_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
            for name in ('io','status'):
                with open('/proc/self/'+name) as f:row[name]=f.read()
            for name in ('cpu','io','memory'):
                try:
                    with open('/proc/pressure/'+name) as f:row[name+'_pressure']=f.read()
                except FileNotFoundError:pass
            for name in ('stat','diskstats','loadavg'):
                with open('/proc/'+name) as f:row['system_'+name]=f.read()
            if self.available_memory:
                row['system_memory_kib']={k:int(v.split()[0]) for k,v in
                    (line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
                    if k in ('MemTotal','MemAvailable','MemFree','SwapTotal','SwapFree')}
            children=set()
            for path in Path('/proc/self/task').glob('*/children'):
                try:children.update(int(x) for x in path.read_text().split())
                except FileNotFoundError:pass
            row['child_processes']={}
            from gredac.metrics import process_snapshot
            for pid in children:
                row['child_processes'][pid]=process_snapshot(pid)
            row['simultaneous_sampled_rss_kib']=sum(v.get('rss_kib',0) for v in row['child_processes'].values())+process_snapshot()['rss_kib']
            self.rows.append(row)
            return row
    def memory(self):
        with self.lock:
            return max((r['simultaneous_sampled_rss_kib'] for r in self.rows),default=0)
    def close(self):
        self.stop.set();self.thread.join();self.sample();write_json(self.run.out/self.filename,self.rows)
        return dict(sampled_peak_total_rss_kib=self.memory(),memory_metric='maximum simultaneous PID-sweep RSS sum; sampling may miss short peaks',resource_file=self.filename)


class Federation:
    """One real A signer, K independent service identities and budgets."""
    def __init__(self,run,k,units=128,workers=32,prefix='f',monitor=None,memory_budget_gib=8,optimize_initial_config=False,shared_authority=False):
        from .network_federation import Cooperation
        from .network_client import Mesh
        from gredac.crypto import canonical
        assert k>0 and workers>0
        self.run=run;self.members=[];self.k=k;self.rows=[];self.monitor=monitor
        self.memory_budget_gib=memory_budget_gib
        self.artifacts=run.out/(prefix+'-metrics');self.artifacts.mkdir()
        self.contact_rows=[];self.closed=False
        assert not shared_authority or optimize_initial_config,'shared preparation requires scoped incremental configuration'
        self.start=time.monotonic();self.mesh=Mesh(run.out/(prefix+'-network'),optimize_initial_config=optimize_initial_config,
            shared_authority='Authority-'+prefix if shared_authority else None)
        try:
            for i in range(k):
                self.members.append(Cooperation(run,prefix+str(i),units,'G'+prefix+str(i),self.mesh,
                    caller='A'+prefix,service='S'+prefix+str(i),connect=False))
                self.check_preparation()
        finally:
            # Default remains the original full-distribution path. Even an
            # opted-in A/B run returns to it before contact or any recovery.
            self.mesh.finish_initial_configuration()
            if shared_authority:
                write_json(self.artifacts/'initialization.json',dict(requested=k,completed=len(self.members),
                    seconds=time.monotonic()-self.start,role_processes=len(self.mesh.processes),
                    shared_authority=self.mesh.shared_authority,authority_scopes=[x.lab.endpoint_id for x in self.members],
                    memory_budget_gib=memory_budget_gib,units_per_cooperation=units,workers=workers,
                    signing_keys='independent persistent Authority-control key in each cooperation SQLite database'))
        self.setup_seconds=time.monotonic()-self.start
        self.pool=ThreadPoolExecutor(max_workers=workers);self.locks=[threading.Lock() for _ in range(k)]
        # Registrations are public metadata. Do not call ensure/configure K
        # extra times solely to measure that the same caller is being reused.
        self.identities=dict(caller=self.mesh.registrations['A'+prefix]['public_key'],
            endpoints=[x.lab.endpoint_id for x in self.members],services=[x.lab.rights[x.service]['owner'] for x in self.members])
        assert len(set(self.identities['services']))==k
        if monitor:monitor.sample()

    def check_preparation(self):
        elapsed=time.monotonic()-self.start;rss=self.monitor.memory() if self.monitor else 0
        if elapsed>600 or rss>self.memory_budget_gib*1024**2:
            write_json(self.artifacts/'capacity_stop.json',dict(elapsed_seconds=elapsed,sampled_rss_kib=rss,
                memory_budget_gib=self.memory_budget_gib,initialized_services=len(self.members),requested_services=self.k))
            raise CapacityLimit(f'preparation exceeded 600 seconds or sampled total RSS exceeded {self.memory_budget_gib} GiB')

    def contacts(self,wait_plan=None):
        # Only A supplies a pre-generated business-wait plan. Sleep happens
        # outside the real contact protocol, with separate timestamps. B/D
        # use their own inter-round waits and do not duplicate A's waits.
        if wait_plan is not None:assert len(wait_plan)==self.k
        start=time.monotonic()
        def connect(i):
            thread_start=time.monotonic();wait=None
            if wait_plan is not None:
                from .rq4_waits import sleep_selected
                wait=sleep_selected(wait_plan[i])
            began=time.monotonic();error=None
            try:self.members[i].connect()
            except Exception as exc:error=repr(exc)
            self.contact_rows.append(dict(service=i,release=start,thread_start=thread_start,
                start=began,end=time.monotonic(),error=error,synthetic_wait=wait))
        fs=[self.pool.submit(connect,i) for i in range(self.k)]
        for f in fs:f.result()
        end=time.monotonic();write_json(self.artifacts/'contacts.json',self.contact_rows)
        assert all(r['error'] is None for r in self.contact_rows),'contact failures retained'
        if self.monitor:self.monitor.sample()
        self.check_preparation()
        return end-start

    def submit(self,i,slot,rid,release=None,phase='measurement'):
        submitted=time.monotonic();released=submitted if release is None else release
        def work():
            thread_start=time.monotonic()
            with self.locks[i]:
                start=time.monotonic();error=None
                try:
                    with self.run.phase(phase):self.members[i].request(slot,rid)
                except Exception as exc:error=type(exc).__name__+': '+str(exc)
                row=dict(service=i,slot=slot,request=rid,release=released,submitted=submitted,
                    thread_start=thread_start,start=start,end=time.monotonic(),error=error,phase=phase)
                self.rows.append(row);return row
        return self.pool.submit(work)

    def warmup(self):
        rows=[f.result() for f in [self.submit(i,0,'warmup',phase='warmup') for i in range(self.k)]]
        assert all(r['error'] is None for r in rows)

    def close(self):
        self.pool.shutdown()
        # Save each team's evidence BEFORE audits, in its own directory. A
        # subsequent audit failure must not erase the recorded failed attempts.
        write_json(self.artifacts/'requests.json',self.rows);write_json(self.artifacts/'identities.json',self.identities)
        self.material_bytes=sum(x.lab.mesh.call(x.lab.rights[x.holding.right]['owner'],'material_size',right=x.holding.right) for x in self.members)
        resources=[self.mesh.call(n,'stats') for n in self.mesh.processes]
        try:audits=[x.close() for x in self.members]
        finally:self.mesh.close();self.closed=True
        rows=[r for r in self.rows if r['phase']=='measurement']
        return dict(services=self.k,setup_seconds=self.setup_seconds,caller_material_bytes=self.material_bytes,
            initialization_completed=len(self.members),contacts_completed=sum(r['error'] is None for r in self.contact_rows),
            role_processes=len(self.mesh.processes),shared_authority=self.mesh.shared_authority,
            transport='independent processes / mutual TLS1.3 / loopback TCP; frame-byte traces, not TLS wire estimates',
            requests=len(rows),**request_stats(rows),
            max_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss+sum(x['max_rss_kib'] for x in resources),
            memory_metric='sum of parent/actor high-water RSS, conservative non-simultaneous upper bound; see periodic per-process samples',
            actor_resources=resources,audits=audits,artifacts=str(self.artifacts.relative_to(self.run.out)))
