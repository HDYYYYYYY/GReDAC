"""Buffered, real-clock observations; no protocol decisions or extra RPCs.

Each process writes its own file at shutdown. Parent spans are inclusive.
Unobserved work stays unassigned; a span sum is never called task latency.
"""
import contextvars,functools,json,os,socket,threading,time
from contextlib import contextmanager
from pathlib import Path

CURRENT=contextvars.ContextVar('rq2_span',default=None)
TRACE=None


class Trace:
    def __init__(self,directory,method,participant,run_id):
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=True)
        self.method,self.participant,self.run_id=method,participant,run_id
        self.rows=[];self.serial=0;self.lock=threading.Lock();self.counts={}
        # Each role constructs its own Trace after process start. These are
        # immutable metadata, not per-operation authorization or timing data.
        self.pid,self.host_id=os.getpid(),socket.gethostname()

    def allocate(self):
        with self.lock:self.serial+=1;return f'{os.getpid()}:{self.serial}'

    def next_message(self,source,target,method,direction):
        key=(source,target,method,direction)
        with self.lock:self.counts[key]=self.counts.get(key,0)+1;n=self.counts[key]
        return f'{source}>{target}:{method}:{n}'

    def base(self):
        return dict(run_id=self.run_id,method=self.method,participant=self.participant,pid=self.pid,
            host_id=self.host_id,clock_id='CLOCK_MONOTONIC/ns',thread_id=threading.get_ident())

    @contextmanager
    def span(self,operation,phase=None,**fields):
        parent=CURRENT.get();sid=self.allocate()
        row=dict(self.base(),kind='span',operation=operation,span_id=sid,
            parent_span_id=parent['span_id'] if parent else None,
            phase=phase or (parent['phase'] if parent else 'unassigned'),
            phase_instance_id=fields.pop('phase_instance_id',None) or (parent['phase_instance_id'] if parent else sid),
            start_ns=time.monotonic_ns(),end_ns=None,result='incomplete',**fields)
        self.rows.append(row);token=CURRENT.set(row);cpu=time.thread_time_ns()
        try:yield row;row['result']='ok'
        except BaseException as e:row.update(result='error',error=type(e).__name__+': '+str(e));raise
        finally:
            row.update(end_ns=time.monotonic_ns(),thread_cpu_ns=time.thread_time_ns()-cpu);CURRENT.reset(token)

    def event(self,name,**fields):
        row=dict(self.base(),kind='event',operation=name,time_ns=time.monotonic_ns(),**fields);self.rows.append(row);return row['time_ns']

    def interval(self,operation,phase,parent=None,**fields):
        """Measured business interval crossing callbacks, not a Python stack."""
        sid=self.allocate();row=dict(self.base(),kind='span',operation=operation,span_id=sid,
            parent_span_id=parent['span_id'] if parent else None,phase=phase,
            phase_instance_id=parent['phase_instance_id'] if parent else sid,
            start_ns=time.monotonic_ns(),end_ns=None,result='incomplete',observation='business_interval',**fields)
        self.rows.append(row);return row

    def end_interval(self,row):row.update(end_ns=time.monotonic_ns(),result='ok')

    def flush(self):
        path=self.directory/f'{os.getpid()}.jsonl'
        path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in self.rows),encoding='utf-8')


def start(directory,method,participant,run_id):
    global TRACE
    TRACE=Trace(directory,method,participant,run_id);return TRACE


def wrap(owner,name,operation=None):
    """Keep original callable and arguments. No generated result or retry."""
    original=getattr(owner,name)
    @functools.wraps(original)
    def measured(*args,**kwargs):
        with TRACE.span(operation or name) as row:
            answer=original(*args,**kwargs)
            if name=='child':
                row.update(unit_domain_size=len(answer.domain),cover=list(answer.seeds),seed_secret_bytes=32*len(answer.seeds))
            if name in ('transfer','receive_delegation'):
                holding=answer[0] if name=='transfer' else answer
                row.update(unit_records=len(holding.records),capability_records=len(holding.caps),
                    seed_secret_bytes=sum(32*len(b.seeds) for b in holding.bundles.values()),
                    prefix_cover={g:list(b.seeds) for g,b in holding.bundles.items()})
            if name=='encode' and isinstance(answer,bytes):row['serialized_bytes']=len(answer)
            return answer
    setattr(owner,name,measured);return original,measured


def load(directory):
    return [json.loads(line) for p in sorted(Path(directory).glob('*.jsonl')) for line in p.read_text().splitlines() if line]


def normalize(rows):
    """Link sender/receiver observations by per-peer method sequence.

    The sequential experiment uses one in-flight call per peer. Correlation
    stays in telemetry, never in the protocol payload. Missing sides remain
    missing rather than inferring a remote success.
    """
    spans={r['span_id']:r for r in rows if r['kind']=='span'}
    sends={r['correlation_id']:r for r in spans.values() if r.get('edge')=='send'}
    for row in spans.values():
        if row.get('edge')=='receive' and row.get('correlation_id') in sends:
            row['remote_parent_span_id']=sends[row['correlation_id']]['span_id']
            if row['operation'].startswith('rpc.handle.'):
                row['parent_span_id']=row['remote_parent_span_id']
    def resolve(r,seen):
        p=r.get('parent_span_id')
        if p in spans and p not in seen:
            parent=spans[p];resolve(parent,seen|{p})
            if r['phase']=='unassigned':r['phase']=parent['phase'];r['phase_instance_id']=parent['phase_instance_id']
    for r in spans.values():resolve(r,{r['span_id']})
    # Author connect() crosses callback-defined first/hot/end boundaries.
    # Keep that inclusive span unassigned if it straddles them. Only a fully
    # enclosed operation receives the matching measured business phase.
    intervals=[r for r in spans.values() if r.get('display_phase') and r.get('end_ns')]
    for r in spans.values():
        if r['phase']=='unassigned' and r.get('end_ns'):
            matches=[s for s in intervals if s['pid']==r['pid'] and s['start_ns']<=r['start_ns'] and r['end_ns']<=s['end_ns']]
            if matches:
                s=min(matches,key=lambda s:s['end_ns']-s['start_ns']);r['phase']=s['phase'];r['phase_instance_id']=s['phase_instance_id']
    return rows
