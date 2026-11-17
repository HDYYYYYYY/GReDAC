"""Replay manifest-listed SMT-LIB in fresh external Z3 processes."""
from pathlib import Path
import concurrent.futures,subprocess,json,hashlib,time,os,shutil
HERE=Path(__file__).resolve().parent
LOCAL_Z3=HERE.parents[1]/'tamarin-v3'/'.deps'/'bin'/'z3.exe'
Z3=Path(os.environ.get('GREDAC_Z3',str(LOCAL_Z3) if LOCAL_Z3.is_file() else (shutil.which('z3') or 'z3')))

def main():
    obligations=json.loads((HERE/'RESULTS.json').read_text())['results']
    witnesses=json.loads((HERE/'WITNESSES.json').read_text())
    tasks=[(HERE/'smt'/(r['name']+'.smt2'),'unsat',r['sha256']) for r in obligations]
    tasks += [(HERE/'witness_smt'/(r['name']+'.smt2'),r['expected'],r['sha256']) for r in witnesses]
    def run(task):
        path,expected,digest=task;raw=path.read_bytes()
        # Hash canonical text exactly as the generator did, independently of
        # platform CRLF/LF newline translation. Final manifest also hashes bytes.
        same=hashlib.sha256(path.read_text(encoding='utf-8').encode()).hexdigest()==digest
        start=time.monotonic()
        p=subprocess.run([str(Z3),'-T:45',str(path)],capture_output=True,text=True,timeout=50)
        result=p.stdout.strip().splitlines()
        answer=result[-1] if result else 'NO_OUTPUT'
        return {'file':str(path.relative_to(HERE)),'expected':expected,'result':answer,
          'sha256_matches':same,'returncode':p.returncode,'seconds':round(time.monotonic()-start,3),
          'ok':same and p.returncode==0 and answer==expected}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        rows=list(pool.map(run,tasks))
    version=subprocess.run([str(Z3),'-version'],capture_output=True,text=True).stdout.strip()
    report={'external_solver':version,'count':len(rows),'all_pass':all(r['ok'] for r in rows),'results':rows}
    (HERE/'REPLAY.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='results'}))
    for r in rows:
        if not r['ok']:print(r)
    return 0 if report['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
