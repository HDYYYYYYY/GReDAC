"""Materialize the optional A2A variant in a NEW directory; never patch in place."""
import argparse,hashlib,json,shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path);a=parser.parse_args()
    out=a.out.resolve()
    assert out!=ROOT and not out.is_relative_to(ROOT), 'Choose a sibling directory'
    assert not out.exists(), 'Output must be new'
    manifest=json.loads((ROOT/'CHECKSUMS.json').read_text())
    for rel,h in manifest['files_sha256'].items():assert sha(ROOT/rel)==h,rel
    patches=json.loads((ROOT/'integrations/a2a/CORE_PATCH.json').read_text())
    for patch in patches:assert sha(ROOT/patch['path'])==patch['baseline_sha256'],patch['path']
    out.mkdir(parents=True)
    for rel in manifest['files_sha256']:
        dest=out/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,dest)
    for patch in patches:
        path=out/patch['path'];text=path.read_text(encoding='utf-8')
        for change in patch['changes']:
            assert text.count(change['old'])==1,patch['path']
            text=text.replace(change['old'],change['new'],1)
        path.write_text(text,encoding='utf-8',newline='\n')
    overlay=ROOT/'integrations/a2a/overlay'
    for p in overlay.rglob('*.py'):
        dest=out/p.relative_to(overlay);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
    (out/'A2A_VARIANT.json').write_text(json.dumps(dict(
        variant='optional A2A bridge',baseline_checksum_manifest_sha256=sha(ROOT/'CHECKSUMS.json'),
        note='RQ2-RQ4 baseline freezes intentionally do not authorize this variant; run A2A-specific entry points.'),indent=2)+'\n')
    shutil.copy2(ROOT/'CHECKSUMS.json',out/'BASELINE_CHECKSUMS.json')
    files={p.relative_to(out).as_posix():sha(p) for p in sorted(out.rglob('*')) if p.is_file()}
    (out/'CHECKSUMS.json').write_text(json.dumps(dict(files_sha256=files,kind='materialized A2A variant'),indent=2)+'\n')
    print(json.dumps(dict(out=str(out),variant='A2A',experiments_started=0)))

if __name__=='__main__':main()
