"""RQ4-only empirical timing input and reproducible synthetic waiting.

Calibration reads the selected latest RQ3 task trajectories, never calls an
LLM. A samples completed API-attempt durations; B/D sample inter-business
gaps minus the UNION of intersecting protocol spans. These are alternative
wait definitions, never added together. Scenes have equal sampling weight;
observations within a scene are sampled uniformly with replacement.
"""
import argparse,hashlib,json,math,random,time
from pathlib import Path
from .support import stats,write_json

SCENES=('travel','academic','calendar')
DEFAULT_WAIT=str(Path(__file__).parent/'data/rq4_rq3_wait_v2.json')


def union_seconds(intervals,lo=None,hi=None):
    """Measured interval union; no nested-span double subtraction."""
    values=[]
    for start,end in intervals:
        assert math.isfinite(start) and math.isfinite(end) and end>=start
        start=max(start,lo) if lo is not None else start
        end=min(end,hi) if hi is not None else end
        if end>start:values.append((start,end))
    total=0.;last=None
    for start,end in sorted(values):
        if last is None:last=(start,end)
        elif start<=last[1]:last=(last[0],max(last[1],end))
        else:total+=last[1]-last[0];last=(start,end)
    return total+(last[1]-last[0] if last else 0.)


def calibrate(combined,out):
    """Read current task evidence, including explicitly labelled retests.

    Do not read overwritten case directories by guessing a batch path. The
    selected row's evidence_directory is authoritative. Parent API logs are
    read once and filtered by case, so replaced earlier attempts are excluded.
    HTTP/format retries with a recorded duration remain in the calibration;
    unfinished attempts cannot supply a measured duration and are reported.
    """
    combined=Path(combined).resolve();out=Path(out)
    assert not out.exists(),'calibration output must be new'
    hashes={};cache={}
    def read(path):
        path=Path(path);raw=path.read_bytes();hashes[str(path)]=hashlib.sha256(raw).hexdigest()
        return json.loads(raw)
    rows=read(combined);assert len(rows)==150 and len({r['case'] for r in rows})==150
    data=dict(version=2,source=str(combined),source_sha256=hashes,
        label='synthetic waits calibrated from latest selected RQ3 r4 trajectories',
        selected_episodes=len(rows),selected_complete=sum(r['flow_complete'] for r in rows),
        retested_cases=[r['case'] for r in rows if r.get('attempt_number',1)>1],
        sampling='equal probability per scene, then uniform recorded observation; with replacement; no clipping',
        weighting='observation-weighted within each scene; both arms included; not an independent new LLM evaluation',
        scenes={s:dict(api=[],business=[],episodes=0,with_system=0,without_system=0,
                      api_status_counts={},unconfirmed_attempts=0) for s in SCENES})
    for row in rows:
        scene=row['scene'];case=row['case'];bucket=data['scenes'][scene]
        bucket['episodes']+=1;bucket['with_system' if row['with_system'] else 'without_system']+=1
        directory=Path(row['evidence_directory']);log=directory.parent/'api_calls.jsonl'
        if str(log) not in cache:
            raw=log.read_bytes();hashes[str(log)]=hashlib.sha256(raw).hexdigest();grouped={}
            for line in raw.splitlines():
                item=json.loads(line);grouped.setdefault(item['case'],[]).append(item)
            cache[str(log)]=grouped
        calls=cache[str(log)].get(case,[]);assert len(calls)==row['api_calls'],case
        for i,item in enumerate(calls):
            seconds=float(item['seconds']);assert math.isfinite(seconds) and seconds>=0
            status=str(item.get('status','unknown'))
            bucket['api_status_counts'][status]=bucket['api_status_counts'].get(status,0)+1
            bucket['api'].append(dict(case=case,index=i,seconds=seconds,status=status,
                model=item.get('response',{}).get('model') if isinstance(item.get('response'),dict) else None))
        bucket['unconfirmed_attempts']+=row.get('api_attempts_unconfirmed',0)
        requests=sorted(read(directory/'business_requests.json'),key=lambda r:r['start'])
        spans=read(directory/'protocol_spans.json') if row['with_system'] else []
        # The no-system arm has business delivery but no protocol to subtract.
        intervals=[(x['start'],x['end']) for x in spans] if row['with_system'] else []
        for i,(left,right) in enumerate(zip(requests,requests[1:])):
            lo,hi=left['end'],right['start'];assert hi>=lo,(case,i,'overlapping business requests')
            occupied=union_seconds(intervals,lo,hi);gap=hi-lo;seconds=gap-occupied
            assert seconds>=-1e-8,(case,i,'negative residual')
            bucket['business'].append(dict(case=case,index=i,seconds=max(0.,seconds),
                start=lo,end=hi,raw_gap_seconds=gap,protocol_union_seconds=occupied,
                with_system=row['with_system']))
    for scene,bucket in data['scenes'].items():
        assert bucket['episodes']==50 and bucket['with_system']==bucket['without_system']==25
        assert bucket['api'] and bucket['business']
        bucket['api_seconds']=stats([x['seconds'] for x in bucket['api']])
        bucket['business_seconds']=stats([x['seconds'] for x in bucket['business']])
    data['business_scope']='Consecutive business-request end to next start, minus clipped protocol-span union; includes real model/tool/orchestration/retry time. Not pure API latency.'
    write_json(out,data)
    print(json.dumps(dict(out=str(out),episodes=150,retested_cases=data['retested_cases'],
        scenes={s:{k:b[k] for k in ('api_seconds','business_seconds','api_status_counts','unconfirmed_attempts')} for s,b in data['scenes'].items()}),ensure_ascii=False,indent=2))


class Waits:
    def __init__(self,run,path):
        raw=Path(path).read_bytes();self.data=json.loads(raw)
        assert self.data['version']==2 and set(self.data['scenes'])==set(SCENES)
        for bucket in self.data['scenes'].values():
            for kind in ('api','business'):
                assert bucket[kind] and all(math.isfinite(x['seconds']) and x['seconds']>=0 for x in bucket[kind])
        run.manifest['wait_calibration']=dict(sha256=hashlib.sha256(raw).hexdigest(),
            source=self.data['source'],label=self.data['label'],sampling=self.data['sampling'])
        write_json(run.out/'wait_calibration.json',self.data)

    def plan(self,group,repeat,count,team=0):
        # No K or fault condition in the seed: larger K extends A's sequence;
        # D's fault and control arms get the same per-team schedule.
        seed=f'rq4-wait-v2:{group}:{repeat}:{team}';rng=random.Random(seed)
        kind='api' if group=='A' else 'business';out=[]
        for index in range(count):
            scene=rng.choice(SCENES);values=self.data['scenes'][scene][kind]
            source_index=rng.randrange(len(values));sample=values[source_index]
            out.append(dict(sequence_index=index,seed=seed,scene=scene,kind=kind,
                sample_index=source_index,source_case=sample['case'],source_index=sample['index'],
                requested_wait_s=sample['seconds']))
        return out


def sleep_selected(sample):
    """Actual sleep is observed separately from both processing and queueing."""
    start=time.monotonic();time.sleep(sample['requested_wait_s']);end=time.monotonic()
    return dict(**sample,sleep_start=start,sleep_end=end,actual_wait_s=end-start)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--combined',required=True);p.add_argument('--out',required=True)
    a=p.parse_args();calibrate(a.combined,a.out)


if __name__=='__main__':main()
