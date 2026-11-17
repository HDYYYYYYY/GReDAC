"""Deterministic, isolated business functions. No LLM or external service."""
import time

def execute(data):
    action=data['action'];a=data['arguments']
    if action=='echo.read':
        if a.get('benchmark') is True:
            from gredac.crypto import canonical
            value=dict(target=data['_service'],value=data['_payload_digest'],padding='')
            value['padding']='x'*(256-len(canonical(value)))
            return value
        if a.get('fail'):raise ValueError('fixture rejected arguments')
        if a.get('delay_ms'):
            assert 0<=a['delay_ms']<=2000
            time.sleep(a['delay_ms']/1000)
        if 'response_bytes' in a:return {'padding':'x'*a['response_bytes']}
        return a
    if action in ('calendar.read','expense.read'):return a
    if action=='calendar.check':
        assert a['timezone']=='Asia/Shanghai' and a['duration']==30
        start,end=a['window'];busy=a['busy'];duration=a['duration']
        slot=next((t for t in range(start,end-duration+1,30)
            if all(t+duration<=lo or t>=hi for lo,hi in busy)),None)
        return dict(date=a['date'],timezone=a['timezone'],start=slot,
                    end=slot+duration if slot is not None else None,duration=duration)
    if action=='expense.calculate':
        rows=a['rows']
        assert all(isinstance(r['cents'],int) and not isinstance(r['cents'],bool) for r in rows)
        return dict(total_cents=sum(r['cents'] for r in rows),ids=[r['id'] for r in rows],
                    recipients=sorted(set(a['recipients'])))
    if action=='research.aggregate':
        rows=a['rows'];total=sum(r['value'] for r in rows)
        return dict(ids=[r['id'] for r in rows],count=len(rows),total=total,
                    mean_numerator=total,mean_denominator=len(rows),references=[r['reference'] for r in rows])
    if action=='fixture.delete':return dict(deleted=a.get('id'))
    raise ValueError('unknown fixture action')
