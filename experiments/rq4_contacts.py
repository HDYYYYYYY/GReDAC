"""RQ4-A: fresh same-identity one-to-many preparation and contacts.

Identity/initial issuance/derivation are timed as preparation. Each contact
worker first waits for a frozen RQ3 API-duration sample, outside the protocol.
Processing intervals and synthetic waiting are separate, not subtracted to
invent a counterfactual no-wait parallel wall time. One real service delivery per
target follows the contact timer and validates every established relation.
"""
from .support import parser,numbers,stats,write_json
from .rq4_matrix import matrix
from .rq4_waits import Waits,DEFAULT_WAIT,union_seconds

def execute(run,a,cfg,rep):
    from .rq4_support import Federation,Monitor
    dist=Waits(run,a.wait_file);schedule=dist.plan('A',rep,cfg['services'])
    write_json(run.out/'wait_schedule.json',schedule)
    monitor=Monitor(run,available_memory=True)
    try:
        f=Federation(run,cfg['services'],workers=a.workers,monitor=monitor,memory_budget_gib=40,
            optimize_initial_config=a.optimize_initial_config,shared_authority=a.optimize_initial_config)
        contact=f.contacts(schedule);f.warmup();result=f.close()
    finally:memory=monitor.close()
    result.update(memory)
    result.update(contact_all_seconds=contact,ready_seconds=contact+f.setup_seconds,repeat=rep)
    result.update(contact_all_with_wait_seconds=contact,
        contact_protocol_ms=stats([(r['end']-r['start'])*1000 for r in f.contact_rows]),
        contact_queue_ms=stats([(r['thread_start']-r['release'])*1000 for r in f.contact_rows]),
        contact_synthetic_wait_seconds=stats([r['synthetic_wait']['actual_wait_s'] for r in f.contact_rows]),
        contact_protocol_busy_union_seconds=union_seconds([(r['start'],r['end']) for r in f.contact_rows]),
        timing_scope='ready_seconds includes sampled business waits; contact protocol intervals exclude sleeps. Union is busy wall coverage, not no-wait critical path.')
    result['memory_budget_gib']=40
    result['within_budget']=result['ready_seconds']<=600 and result['sampled_peak_total_rss_kib']<=40*1024**2
    return result

def main():
    from .rq4_support import configure
    p=parser(__doc__);p.set_defaults(repeats=3,slot_bits=15)
    p.add_argument('--services',default='1,8,32,128,256');p.add_argument('--workers',type=int,default=32)
    p.add_argument('--wait-file',default=DEFAULT_WAIT)
    p.add_argument('--optimize-initial-config',action='store_true',help='A/B opt-in preparation: shared Authority process with independent cooperation stores, no unused R, relevant full/delta configuration; default off')
    a=p.parse_args();configure();matrix(a,__spec__.name,[dict(services=k) for k in numbers(a.services)],execute)
if __name__=='__main__':main()
