"""RQ4-D: one team's real B-process outage in a one-to-many workload.

Each team has one caller, K services and separate B processes/stores. Only
the target team's B processes exit; callers keep exact pending bytes. The
control thread wakes on a wall-clock deadline, independently of think time.
It waits for the target's in-flight round to finish to select a precise commit
boundary. This measured wait is never called an exactly-on-deadline crash.
"""
import json,random,time,threading,traceback
from concurrent.futures import ThreadPoolExecutor
from .support import parser,numbers,write_json,until
from .rq4_matrix import matrix
from .rq4_waits import Waits,DEFAULT_WAIT,sleep_selected


def execute(run,a,cfg,rep):
    from .rq4_support import Federation,Monitor
    from gredac.crypto import Denied
    dist=Waits(run,a.wait_file)
    schedules=[dist.plan('D',rep,a.rounds-1,team=t) for t in range(a.teams)]
    write_json(run.out/'wait_schedule.json',schedules)
    monitor=Monitor(run);teams=[];locks=[];rows=[];management=[];waits=[];errors=[]
    event={};pool=None;audits=[];status='control_or_recovery_failure'
    try:
        for t in range(a.teams):
            # D's eight teams must not inherit A/B's one-team 8-GiB
            # acceptance criterion. This is a whole-run safety budget only;
            # exceeding it yields capacity_budget, not a recovery result.
            f=Federation(run,cfg['services'],workers=a.workers,prefix='t'+str(t)+'s',monitor=monitor,memory_budget_gib=24)
            f.contacts();f.warmup();teams.append(f);locks.append(threading.Lock())
        begin=time.monotonic()
        def traffic(t):
            until(begin+t*.05)
            for r in range(1,a.rounds+1):
                desired=time.monotonic()
                # Target traffic pauses explicitly during controlled recovery.
                # Other teams have independent locks and continue their work.
                with locks[t]:
                    acquired=time.monotonic()
                    if r in (2,4,8,12):
                        member=teams[t].members[(r-1)%cfg['services']];start=time.monotonic()
                        try:member.lab.discover(member.holding,member.service);error=None
                        except Exception as exc:error=repr(exc)
                        management.append(dict(team=t,round=r,start=start,end=time.monotonic(),error=error,operation='authenticated_directory_query'))
                    start=time.monotonic()
                    answers=[j.result() for j in [teams[t].submit(i,r,'round-'+str(r),release=start) for i in range(cfg['services'])]]
                    rows.append(dict(team=t,round=r,desired=desired,lock_acquired=acquired,start=start,end=time.monotonic(),
                        failed=sum(x['error'] is not None for x in answers)))
                if r<a.rounds:waits.append(dict(team=t,round=r,**sleep_selected(schedules[t][r-1])))
        pool=ThreadPoolExecutor(max_workers=a.teams);futures=[pool.submit(traffic,t) for t in range(a.teams)]
        event['scheduled']=begin+a.inject_at;until(event['scheduled']);event['control_woke']=time.monotonic()
        with locks[0]:
            target=teams[0].members[0];lab=target.lab;event['start']=time.monotonic()
            event['target_round_wait_seconds']=event['start']-event['control_woke']
            if cfg['point']!='none':lab.mesh.call(lab.endpoint_id,'arm_fault',point=cfg['point'])
            event['probe_begin']=time.monotonic()
            try:lab.charge(target.wallet,{'budget':100},'fault-probe',payload={'diagnostic':'fixed'})
            except (ConnectionError,OSError,RuntimeError):
                assert cfg['point']!='none';event['detected']=time.monotonic()
            else:assert cfg['point']=='none'
            if cfg['point']!='none':
                process=teams[0].mesh.processes[lab.endpoint_id];process.join(3)
                assert process.exitcode==73,'expected real commit-boundary exit'
                for member in teams[0].members[1:]:
                    p=teams[0].mesh.processes[member.lab.endpoint_id];p.terminate();p.join(3);assert not p.is_alive()
                event['all_target_endpoints_stopped']=time.monotonic();status='safely_stopped'
                event['uncertain_check_start']=time.monotonic()
                # Public protocol API, no internal Holding/ledger shortcut.
                rid=lab.right('uncertain-child','Uncertain',target.name,target.holding.right)
                try:lab.delegate(target.holding,rid,{'budget':[100]})
                except Denied as e:assert e.code=='LOCAL_OUTCOME_UNCERTAIN'
                else:raise AssertionError('unconfirmed unit transferred')
                event['uncertain_transfer_rejected']=time.monotonic()
                # Real process exit is the fault. There is NO artificial
                # post-fault delay. The explicit uncertainty check above is
                # measured diagnostic work, not hidden detection latency.
                event['uncertain_check_seconds']=event['uncertain_transfer_rejected']-event['uncertain_check_start']
                event['injected_downtime']=0
                event['restart_start']=time.monotonic();event['endpoint_ready']=[]
                for member in teams[0].members:
                    ts=time.monotonic();member.lab.restart_endpoint()
                    event['endpoint_ready'].append(dict(endpoint=member.lab.endpoint_id,start=ts,end=time.monotonic()))
                event['worker_ready']=time.monotonic()
                replay=lab.retry(target.wallet,'fault-probe');event['retry_resolved']=time.monotonic()
                assert bool(replay['replay'])==(cfg['point']=='after_commit');event['replay']=bool(replay['replay'])
            else:event.update(detected=None,injected_downtime=0,restart_start=None,worker_ready=None,retry_resolved=time.monotonic())
            rid=lab.right('recovery-child','Recovered',target.name,target.holding.right)
            child=lab.delegate(target.holding,rid,{'budget':[101]});event['new_delegation_complete']=time.monotonic()
            wallet=lab.reserve(child,target.service,{'budget':[101]})
            lab.charge(wallet,{'budget':101},'post-recovery',payload={'diagnostic':'fresh'})
            event['new_delegation_and_consumption']=time.monotonic();status='recovered' if cfg['point']!='none' else 'normal_control'
        for future in futures:
            try:future.result()
            except Exception:errors.append(traceback.format_exc())
        traffic_end=time.monotonic();pool.shutdown();pool=None
        # Read the experiment timestamp after traffic, never to decide protocol state.
        if cfg['point']!='none':
            path=teams[0].mesh.path/'actors'/lab.endpoint_id/'cooperations'/lab.endpoint_id/'events.jsonl'
            crashes=[json.loads(line) for line in path.read_text().splitlines() if line]
            event['actual_crash']=next(x['time'] for x in crashes if x['kind']=='injected_process_exit' and x['time']>=event['start'])
            event['scheduled_to_crash_seconds']=event['actual_crash']-event['scheduled']
            event['crash_to_ready_seconds']=event['worker_ready']-event['actual_crash']
            event['crash_to_new_success_seconds']=event['new_delegation_and_consumption']-event['actual_crash']
            event['restart_seconds']=event['worker_ready']-event['restart_start']
            event['crash_to_detected_seconds']=event['detected']-event['actual_crash']
            event['detected_to_restart_seconds']=event['restart_start']-event['detected']
            event['ready_to_retry_seconds']=event['retry_resolved']-event['worker_ready']
            event['ready_to_new_success_seconds']=event['new_delegation_and_consumption']-event['worker_ready']
        for t,f in enumerate(teams):
            report=f.close()
            assert sum(x['new_requests'] for x in report['audits'])==cfg['services']*(a.rounds+1)+(2 if t==0 else 0)
            audits.append(report)
        assert not errors and all(r['failed']==0 for r in rows) and all(m['error'] is None for m in management),(errors,rows)
        assert len(rows)==a.teams*a.rounds,'missing scheduled team rounds'
        return dict(**cfg,repeat=rep,teams=a.teams,event=event,audits=audits,
            traffic_begin=begin,traffic_end=traffic_end,recovery_status=status,sampled_peak_total_rss_kib=monitor.memory(),
            memory_budget_gib=24,recovery_scope='B-process group outage; caller/service identities and retry state survive; loopback mutual TLS',
            impact_measurement='raw per-team requests and queries; same-repeat fault-free windows aligned by rq4_report')
    finally:
        if pool:pool.shutdown()
        monitor.close()
        for f in teams:write_json(f.artifacts/'requests.json',f.rows)
        for name,value in [('team_rounds',rows),('event',event),('management_operations',management),
                           ('synthetic_waits',waits),('failure_evidence',dict(status=status,traffic_errors=errors))]:
            write_json(run.out/(name+'.json'),value)


def main():
    from .rq4_support import configure
    p=parser(__doc__);p.set_defaults(repeats=3,slot_bits=15)
    p.add_argument('--services',default='8');p.add_argument('--teams',type=int,default=8)
    p.add_argument('--workers',type=int,default=8);p.add_argument('--rounds',type=int,default=12)
    p.add_argument('--points',default='none,before_commit,after_commit');p.add_argument('--inject-at',type=float,default=6)
    p.add_argument('--wait-file',default=DEFAULT_WAIT)
    a=p.parse_args();assert a.teams>=2 and 1<=a.rounds<100 and a.inject_at>=0
    configure();matrix(a,__spec__.name,[dict(services=k,point=v) for k in numbers(a.services) for v in a.points.split(',')],execute)
if __name__=='__main__':main()
