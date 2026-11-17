"""RQ4-only case runner: retain every attempted case and classify its failure.

The individual experiments own their workload. This module owns process
isolation, a fixed 1800 s case timeout and error evidence, never a protocol.
The suite also uses the same --case-json entry so a case is independently runnable.
"""
import json,os,random,signal,subprocess,sys,time,traceback
from pathlib import Path
from .support import Run,write_json


def matrix(args,module,cases,execute):
    if args.case_json:
        run=Run(args,module.rsplit('.',1)[-1])
        try:run.finish([execute(run,args,json.loads(args.case_json),args.repeat_index)])
        except BaseException as exc:
            from .rq4_support import CapacityLimit
            run.save_samples()
            run.manifest.update(status='FAIL',failure_kind='capacity_budget' if isinstance(exc,CapacityLimit) else 'execution_or_audit_failure',
                error=repr(exc),traceback=traceback.format_exc())
            write_json(run.out/'manifest.json',run.manifest);raise
        finally:
            from .network_client import Mesh
            for mesh in Mesh.live:
                if not mesh.closed:
                    try:mesh.close()
                    except Exception:pass # Original failure already retained; no retry/replacement.
        return
    out=Path(args.out).resolve();out.mkdir(parents=True,exist_ok=False)
    jobs=[(c,r) for c in cases for r in range(args.repeats)];random.Random(args.order_seed).shuffle(jobs)
    write_json(out/'plan.json',dict(module=module,config=vars(args),jobs=jobs,repeat_unit='independent process/state'))
    attempts=[];results=[]
    for i,(cfg,rep) in enumerate(jobs):
        dest=out/f'run-{i:03d}';argv=sys.argv[1:].copy();argv[argv.index('--out')+1]=str(dest)
        cmd=[sys.executable,'-m',module,*argv,'--case-json',json.dumps(cfg),'--repeat-index',str(rep)]
        begin=time.monotonic();timed_out=False
        with (out/f'run-{i:03d}.log').open('w') as log:
            process=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:code=process.wait(timeout=1800)
            except subprocess.TimeoutExpired:timed_out=True;os.killpg(process.pid,signal.SIGKILL);code=process.wait()
        attempts.append(dict(case=cfg,repeat=rep,directory=dest.name,command=cmd,exitcode=code,timed_out=timed_out,seconds=time.monotonic()-begin))
        if code==0:results.extend(dict(run_directory=dest.name,**r) for r in json.loads((dest/'summary.json').read_text())['results'])
        write_json(out/'attempts.json',attempts);write_json(out/'summary.json',dict(results=results,attempts=attempts))
    failed=sum(a['exitcode']!=0 for a in attempts)
    write_json(out/'manifest.json',dict(status='FAIL' if failed else 'PASS',attempted=len(attempts),failed=failed,llm_api_calls=0))
    if failed:raise RuntimeError('failed independent runs retained')
