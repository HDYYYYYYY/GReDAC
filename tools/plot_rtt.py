"""Plot measured task cost / N from two injected-wait batches; keep failures visible."""
import argparse,csv,json,statistics
from pathlib import Path

def load(root,profile):
    m=json.loads((root/'manifest.json').read_text())
    assert m['profile']==profile and m['injected_wait']
    assert len(m['attempts'])==len(m['plan']), 'Batch still incomplete'
    rows=[]
    for a in m['attempts']:
        ok=a['exitcode']==0 and a.get('wait_evidence_ok',False)
        s=a.get('measured_with_wait') or {}
        rows.append(dict(profile=profile,N=a['N'],repeat=a['repeat'],directory=a['directory'],
            success=ok,task_per_request_ms=s['T_task_ms']/a['N'] if ok else None))
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--west',type=Path,required=True);p.add_argument('--asia',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    rows=load(a.west,'distributed')+load(a.asia,'authority_asia')
    a.out.mkdir(parents=True,exist_ok=False)
    with (a.out/'runs.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,ax=plt.subplots(figsize=(7,4.5))
    for profile,label,color,marker in [('distributed','Authority: West US','#8e4499','s'),
                                      ('authority_asia','Authority: Asia','#d6792c','v')]:
        group=[r for r in rows if r['profile']==profile];xs=sorted({r['N'] for r in group});ys=[]
        for n in xs:
            valid=[r['task_per_request_ms'] for r in group if r['N']==n and r['success']]
            ys.append(statistics.median(valid) if valid else float('nan'))
            ax.scatter([n]*len(valid),valid,color=color,alpha=.25,s=18)
            failures=sum(not r['success'] for r in group if r['N']==n)
            if failures:ax.annotate(f'{failures} failed',(n,ys[-1] if valid else 1),fontsize=8)
        ax.plot(xs,ys,color=color,marker=marker,label=label+' (measured + RTT waits)')
    ax.set(xscale='log',yscale='log',xlabel='Business requests N',ylabel='Task cost / N (ms)')
    ax.set_xticks(xs,labels=[str(x) for x in xs]);ax.grid(alpha=.25);ax.legend(fontsize=8)
    fig.text(.5,.01,'Per-run points; medians. Injected waits, not measured WAN performance.',ha='center',fontsize=8)
    fig.tight_layout(rect=(0,.04,1,1));fig.savefig(a.out/'rtt_total_cost.png',dpi=200);fig.savefig(a.out/'rtt_total_cost.pdf')
    print(json.dumps(dict(attempts=len(rows),failed=sum(not r['success'] for r in rows),out=str(a.out))))

if __name__=='__main__':main()
