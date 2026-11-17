"""Offline package verification only. No imports of experiment entry points."""
import ast, hashlib, json, re, sys, zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def verify():
    manifest=json.loads((ROOT/'CHECKSUMS.json').read_text(encoding='utf-8'))
    errors=[]
    for rel,digest in manifest['files_sha256'].items():
        p=ROOT/rel
        if not p.is_file() or sha(p)!=digest:errors.append('missing/changed: '+rel)
        elif p.suffix=='.py':
            try:ast.parse(p.read_text(encoding='utf-8-sig'),filename=rel)
            except SyntaxError:errors.append('syntax: '+rel)
    meta=json.loads((ROOT/'experiments/rq2_v2/author_source.json').read_text())
    zpath=ROOT/'experiments/rq2_v2/author_source.zip'
    if sha(zpath)!=meta['archive_sha256']:errors.append('SAGA archive hash')
    with zipfile.ZipFile(zpath) as z:
        for name,digest in meta['files'].items():
            if hashlib.sha256(z.read(name)).hexdigest()!=digest:errors.append('SAGA member: '+name)
    frozen=json.loads((ROOT/'studies/rq2_rtt/data/FREEZE.json').read_text())
    for name,digest in frozen['files_sha256'].items():
        if sha(ROOT/'studies/rq2_rtt/data'/name)!=digest:errors.append('RTT pool: '+name)
    for name in manifest['files_sha256']:
        p=ROOT/name
        if p.suffix in ('.py','.json','.md','.toml','.sh','.txt','.lock'):
            data=p.read_text(encoding='utf-8-sig')
            if re.search(r'\bsk-[A-Za-z0-9]{20,}\b',data):errors.append('possible credential: '+name)
    report=dict(status='PASS' if not errors else 'FAIL',files=len(manifest['files_sha256']),
        author_files=len(meta['files']),errors=errors,experiments_started=0,llm_calls=0,
        scope='file integrity, Python syntax, author archive and frozen RTT data; not an execution regression')
    print(json.dumps(report,indent=2));return not errors

if __name__=='__main__':sys.exit(0 if verify() else 1)
