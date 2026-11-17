"""A2A B1-B4 semantic checks. No performance measurement or warmup."""
import os,json,hashlib,shutil,traceback
from pathlib import Path
from .support import parser,Run,write_json

def main():
    p=parser(__doc__);p.set_defaults(slot_bits=10,repeats=1)
    p.add_argument('--suites',default='B1,B2,B3,B4')
    p.add_argument('--schedule-seeds',default='101,202,303')
    p.add_argument('--rounds',type=int,default=20)
    a=p.parse_args();os.environ['GREDAC_SLOT_BITS']=str(a.slot_bits)
    os.environ['GREDAC_A2A_TESTING']='1'
    run=Run(a,'a2a_regression');results=[]
    root=Path(__file__).resolve().parents[1]
    for path in sorted((root/'experiments/a2a_bridge').glob('*.py')):
        dest=run.out/'source'/path.relative_to(root);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dest)
        run.manifest['source_sha256'][str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
    run.manifest['code_fingerprint']=hashlib.sha256(json.dumps(run.manifest['source_sha256'],sort_keys=True).encode()).hexdigest()
    run.manifest.update(not_performance=True,llm_api_calls=0,external_business_api_calls=0,sdk='a2a-sdk==1.3.0')
    write_json(run.out/'manifest.json',run.manifest)
    try:
        for group in a.suites.split(','):
            print('START',group,flush=True)
            if group in ('B1','B2'):
                from .a2a_bridge.checks_basic import b1,b2
                rows=(b1 if group=='B1' else b2)(run)
                if group=='B2':
                    from .a2a_bridge.checks_boundary import boundary
                    rows+=boundary(run)
            elif group=='B3':
                from .a2a_bridge.checks_lifecycle import lifecycle,races
                rows=lifecycle(run)+races(run,[int(s) for s in a.schedule_seeds.split(',')],a.rounds)
            elif group=='B4':
                from .a2a_bridge.checks_workflows import workflows
                rows=workflows(run)
            else:raise ValueError(group)
            results.extend(dict(suite=group,**r) for r in rows)
            write_json(run.out/'partial_results.json',results)
            print('PASS',group,len(rows),flush=True)
        run.finish(results)
    except BaseException:
        run.manifest.update(status='FAIL',traceback=traceback.format_exc())
        write_json(run.out/'manifest.json',run.manifest);raise
    finally:
        from .network_client import Mesh
        for mesh in Mesh.live:mesh.close()

if __name__=='__main__':main()
