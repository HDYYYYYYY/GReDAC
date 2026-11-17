"""RQ4-B: parallel query/aggregate rounds with post-completion waiting.

One round requests each of K independent services and waits for all results.
Only then wait according to a pre-generated latest RQ3 business-gap sample. Waits
are not measured LLM latency. Each K uses identical seeded round waits.
Request-processing, scheduler delay, whole-round time and waits stay separate.
"""
import random,time
from .support import parser,numbers,stats,write_json
from .rq4_matrix import matrix
from .rq4_waits import Waits,DEFAULT_WAIT,sleep_selected

def execute(run,a,cfg,rep):
    from .rq4_support import Federation,Monitor
    dist=Waits(run,a.wait_file);schedule=dist.plan('B',rep,a.rounds-1)
    write_json(run.out/'wait_schedule.json',schedule)
    monitor=Monitor(run,available_memory=True);waits=[];rounds=[]
    try:
        f=Federation(run,cfg['services'],workers=a.workers,monitor=monitor,memory_budget_gib=40,
            optimize_initial_config=a.optimize_initial_config,shared_authority=a.optimize_initial_config)
        contact=f.contacts();f.warmup()
        begin=time.monotonic()
        for r in range(1,a.rounds+1):
            start=time.monotonic()
            jobs=[f.submit(i,r,'round-'+str(r),release=start) for i in range(f.k)]
            rows=[j.result() for j in jobs];end=time.monotonic()
            rounds.append(dict(round=r,start=start,end=end,completed=sum(x['error'] is None for x in rows)))
            if r<a.rounds:waits.append(dict(round=r,**sleep_selected(schedule[r-1])))
        wall=time.monotonic()-begin;result=f.close()
    finally:
        memory=monitor.close();write_json(run.out/'rounds.json',rounds);write_json(run.out/'synthetic_waits.json',waits)
    result.update(memory)
    durations=[(r['end']-r['start'])*1000 for r in rounds]
    result.update(repeat=rep,round_ms=stats(durations),formal_wall_seconds=wall,
        round_processing_seconds=sum(durations)/1000,synthetic_wait_seconds=sum(w['actual_wait_s'] for w in waits),
        business_rate_rps=result['completed']/wall,contact_all_seconds=contact,formal_begin=begin,formal_end=begin+wall)
    result['memory_budget_gib']=40
    result['within_budget']=(not result['failed'] and result['round_ms']['p95']<=2000 and
        result['response_ms']['p95']<=1000 and f.setup_seconds+contact<=600 and result['sampled_peak_total_rss_kib']<=40*1024**2)
    assert not result['failed'],'request failures retained'
    return result

def main():
    from .rq4_support import configure
    p=parser(__doc__);p.set_defaults(repeats=3,slot_bits=15)
    p.add_argument('--services',default='1,8,32,128,256');p.add_argument('--workers',type=int,default=32)
    p.add_argument('--rounds',type=int,default=12);p.add_argument('--wait-file',default=DEFAULT_WAIT)
    p.add_argument('--optimize-initial-config',action='store_true',help='A/B opt-in preparation: shared Authority process with independent cooperation stores, no unused R, relevant full/delta configuration; default off')
    a=p.parse_args();configure();assert 0<a.rounds<128
    matrix(a,__spec__.name,[dict(services=k) for k in numbers(a.services)],execute)
if __name__=='__main__':main()
