"""Targeted GReDAC regressions; correctness evidence, not performance.

Exercises non-Cartesian scope, ACT reuse with additional legitimate units,
same-key multi-cooperation identity, cross-endpoint rejection and recovery.
No LLM and no internal ledger reads by the simulated caller.
"""
from .support import parser,Run,write_json


def main():
    p=parser(__doc__);p.set_defaults(repeats=1,slot_bits=8);a=p.parse_args();run=Run(a,'gredac_regression')
    from .gredac_fixture import Cooperation
    from gredac.crypto import domain_for,Denied
    from gredac.pki import PKI
    pki=PKI(run.out/'shared-pki');signers={};results=[]
    x=Cooperation(run,'first',16,'G1',pki,signers,service='S1')
    y=Cooperation(run,'second',16,'G2',pki,signers,service='S2')
    assert x.lab.actor('A') is y.lab.actor('A')
    assert x.lab.identities['A']['certificate']==y.lab.identities['A']['certificate']
    x.request(0,'one');y.request(0,'one')
    try:y.lab.endpoint.charge(x.wallet.packet('query','cross',{'budget':1}),'query',y.wallet.link)
    except Denied:pass
    else:raise AssertionError('cross endpoint request accepted')
    results.append(dict(test='same_identity_distinct_endpoints',checks='PASS'))
    # Initial contact advertises one unit. A valid ACT remains usable with a
    # different owned unit; no contact/Authority roundtrip is hidden here.
    w=x.lab.reserve(x.holding,x.service,{'budget':[1]})
    before=dict(x.lab.endpoint.calls);sid=w.session['binding']['session']
    x.lab.charge(w,{'budget':2},'additional-unit')
    assert w.session['binding']['session']==sid and x.lab.endpoint.calls['session']==before['session']
    results.append(dict(test='ACT_independent_of_initial_unit_list',checks='PASS'))
    rid=x.lab.right('restricted','Child','first',x.holding.right)
    domain=domain_for(['query'],[3,4])+domain_for(['summary'],[5])
    child=x.lab.delegate(x.holding,rid,{'budget':[3,4,5]},domains={'budget':domain})
    cw=x.lab.reserve(child,x.service,{'budget':[3,4,5]})
    x.lab.charge(cw,{'budget':3},'query-3')
    x.lab.charge(cw,{'budget':5},'summary-5','summary')
    try:cw.packet('summary','wrong-action',{'budget':4})
    except Denied:pass
    else:raise AssertionError('joint domain widened')
    x.lab.call('A','revoke',{'id':rid})
    recovered,slots=x.lab.recovery(cw,x.holding.right,actor='A')
    assert slots=={'budget':[4]}
    fresh=x.lab.right('fresh','Replacement','first',x.holding.right,actions=['query'])
    fh=x.lab.delegate(recovered,fresh,slots,actions=['query'])
    x.lab.charge(x.lab.reserve(fh,x.service,slots),{'budget':4},'returned')
    results.append(dict(test='joint_domain_recursive_return_narrowing',checks='PASS'))
    results.append(dict(test='audits',first=x.close(),second=y.close()))
    run.finish(results)

if __name__=='__main__':main()
