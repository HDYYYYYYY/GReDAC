"""B4 exact, deterministic application judges: 3 scenarios x 3 instances."""
from .testing import Fixture,response
from .codec import classify_operation

def workflows(run):
    rows=[]
    for scenario in ['W01','W02','W03']:
        for instance in range(3):
            with Fixture(run,scenario+'-'+str(instance),size=8) as f:
                l=f.lab
                if scenario=='W01':
                    date='2027-01-'+str(11+instance)
                    busy_a=[[540,570+30*instance]];busy_b=[[600+30*instance,630+30*instance]]
                    ca=response(f.send(0,'calendar-a','calendar.read',dict(date=date,timezone='Asia/Shanghai',busy=busy_a)))
                    cb=response(f.send(1,'calendar-b','calendar.read',dict(date=date,timezone='Asia/Shanghai',busy=busy_b)))
                    c=l.right('C','C','c',f.a);hc=l.delegate(f.h,c,{'s1':[2,3],'s2':[2,3]})
                    wc=l.reserve(hc,f.srv,{'s1':[2,3],'s2':[2,3]})
                    args=dict(date=date,timezone='Asia/Shanghai',duration=30,window=[540,720],busy=ca['busy']+cb['busy'])
                    first=response(f.send(2,'calendar-check','calendar.check',args,w=wc))
                    l.call('A','revoke',{'id':c});returned,slots=l.recovery(wc,f.a,actor='A')
                    assert slots=={'s1':[3],'s2':[3]}
                    d=l.right('D','D','c',f.a);hd=l.delegate(returned,d,slots);wd=l.reserve(hd,f.srv,slots)
                    second=response(f.send(3,'calendar-replacement','calendar.check',args,w=wd))
                    expected=dict(date=date,timezone='Asia/Shanghai',duration=30,start=570+30*instance,end=600+30*instance)
                    assert first==second==expected
                    assert all(expected['end']<=lo or expected['start']>=hi for lo,hi in args['busy'])
                    expected_admissions=4;expected_spent={'s1':4,'s2':2}
                elif scenario=='W02':
                    data=[dict(id='expense-a',cents=101+instance),dict(id='expense-b',cents=2099+2*instance)]
                    recipients=['finance@example.invalid','owner@example.invalid','finance@example.invalid']
                    read=response(f.send(0,'expense-read','expense.read',dict(rows=data,recipients=recipients)))
                    c=l.right('C','C','c',f.a);hc=l.delegate(f.h,c,{'s1':[1,2,3],'s2':[1,2,3]})
                    wc=l.reserve(hc,f.srv,{'s1':[1,2,3],'s2':[1,2,3]})
                    first=response(f.send(1,'expense-sum','expense.calculate',read,w=wc))
                    p=f.payload('expense-delete','fixture.delete',{'id':'fixture'})
                    f.reject(lambda:f.send(2,'expense-delete',w=wc,payload=p,operation='query'),'A2A_OPERATION_BINDING')
                    l.call('R','revoke',{'id':f.srv})
                    f.reject(lambda:f.send(3,'old-service',w=wc),'KNOWN_REVOKED')
                    s2=l.right('srv2','S2','c',f.sroot,side='service')
                    w2=l.reserve(hc,s2,{'s1':[2,3],'s2':[2,3]})
                    second=response(f.send(2,'expense-new-service','expense.calculate',read,w=w2,srv=s2))
                    expected=dict(total_cents=2200+3*instance,ids=['expense-a','expense-b'],
                                  recipients=['finance@example.invalid','owner@example.invalid'])
                    assert first==second==expected
                    expected_admissions=3;expected_spent={'s1':3,'s2':2}
                else:
                    data=[dict(id='row-'+str(i),value=(i+1)*(instance+1),reference='ref-'+str(i)) for i in range(3)]
                    read=response(f.send(0,'research-read','echo.read',dict(rows=data)))
                    c=l.right('C','C','c',f.a);hc=l.delegate(f.h,c,{'s1':[1,2],'s2':[1,2]})
                    wc=l.reserve(hc,f.srv,{'s1':[1,2],'s2':[1,2]})
                    first=response(f.send(1,'research-aggregate','research.aggregate',read,w=wc))
                    l.call('O','revoke',{'id':f.a});returned,slots=l.recovery(f.w,f.root,actor='O')
                    assert 0 not in slots['s1'] and 1 not in slots['s1'] and 1 not in slots['s2']
                    d=l.right('D','D','c',f.root);hd=l.delegate(returned,d,slots);wd=l.reserve(hd,f.srv,slots)
                    second=response(f.send(2,'research-new-caller','research.aggregate',read,w=wd))
                    expected=dict(ids=['row-0','row-1','row-2'],count=3,total=6*(instance+1),
                        mean_numerator=6*(instance+1),mean_denominator=3,references=['ref-0','ref-1','ref-2'])
                    assert first==second==expected
                    expected_admissions=3;expected_spent={'s1':3,'s2':2}
                observed=f.snapshot()
                assert observed['requests']==expected_admissions and observed['spent']==expected_spent
                assert sum(observed['business'].values())==expected_admissions
                audit=f.close()
                rows.append(dict(id=scenario,instance=instance,passed=True,expected=expected,oracle=observed,
                    expected_admissions=expected_admissions,expected_spent=expected_spent,audit=audit,
                    llm_api_calls=0,external_business_api_calls=0))
    return rows
