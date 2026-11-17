"""Public configuration distribution regressions; no LLM/performance workload.

Unit fixtures compare merged PUBLIC metadata with full distribution, including
in-place changes, new namespaces/processes and failed delivery. A tiny real
TCP/TLS fixture then checks independent actors, two cooperations, accounting,
revocation/return and a replacement. No caller reads an endpoint database.
"""
import copy,os,traceback
from types import SimpleNamespace
from .support import parser,Run,write_json


def unit_checks(run):
    # Run installs SLOT_BITS before importing protocol modules (also required
    # for spawned actor processes to use the identical address encoding).
    from .network_client import Mesh,ScopedMesh
    m=Mesh.__new__(Mesh);m.path=run.out/'public-unit';m.path.mkdir()
    m.routes={'A':{'port':1,'public':'a'}};m.registrations={'A':{'certificate':'public-a','endpoint':'tls://1'}}
    m.processes={'A':SimpleNamespace(pid=101,is_alive=lambda:True)}
    m.config={};m.scopes=[];m.frozen_authorities=set();m.shared_authority=None;m.optimize_initial_config=True;m._config_acked={}
    m.config_distribution=dict(full=0,delta=0,skipped=0,failed=0,route_entries=0,registration_entries=0,scalar_entries=0)
    sent=[];received={};reject=[False]
    def call(name,method,**args):
        assert method=='configure';sent.append(copy.deepcopy(args))
        if reject[0]:raise ConnectionError('test-only delivery failure')
        key=(name,m.processes[name].pid,args.get('_scope'))
        state=received.setdefault(key,dict(routes={},registrations={}))
        state['routes'].update(copy.deepcopy(args['routes']));state['registrations'].update(copy.deepcopy(args['registrations']))
        state.update(copy.deepcopy({k:v for k,v in args.items() if k not in ('routes','registrations','_scope')}))
        return {'pid':m.processes[name].pid}
    m.call=call
    m.configure(endpoint='G');assert len(sent)==1
    m.configure();assert len(sent)==1 and m.config_distribution['skipped']==1
    m.registrations['A']['endpoint']='tls://2';m.configure()
    assert sent[-1]==dict(routes={},registrations={'A':m.registrations['A']})
    m.routes['B']={'port':2,'public':'b'};m.registrations['B']={'certificate':'public-b'};m.configure()
    assert set(sent[-1]['routes'])=={'B'} and set(sent[-1]['registrations'])=={'B'}
    m.configure(endpoint='G2');assert sent[-1]==dict(routes={},registrations={},endpoint='G2')
    state=received[('A',101,None)];assert state==dict(routes=m.routes,registrations=m.registrations,endpoint='G2')
    scope=ScopedMesh(m,'cooperation-2');scope.members.add('A');scope.configure(endpoint='H')
    assert sent[-1]==dict(routes=m.routes,registrations=m.registrations,endpoint='H',_scope='cooperation-2')
    before=len(sent);scope.configure();assert len(sent)==before
    m.processes['A'].pid=102;m.configure()
    assert sent[-2]==dict(routes=m.routes,registrations=m.registrations,endpoint='G2')
    assert sent[-1]==dict(routes=m.routes,registrations=m.registrations,endpoint='H',_scope='cooperation-2')
    before=len(sent);m.frozen_authorities.add('A');m.configure();assert len(sent)==before;m.frozen_authorities.clear()
    m.routes['A']['port']=3;old=copy.deepcopy(m._config_acked);reject[0]=True
    try:m.configure()
    except ConnectionError:pass
    else:raise AssertionError('failed delivery swallowed')
    assert m._config_acked==old and len(sent)==before+1,'failed send must neither ACK nor auto-retry'
    reject[0]=False;m.configure();assert sent[-1]['routes']=={'A':m.routes['A']}
    m.finish_initial_configuration();assert not m.optimize_initial_config and not m._config_acked
    before=len(sent);m.configure();m.configure();assert len(sent)==before+4
    assert all(x['routes']==m.routes and x['registrations']==m.registrations for x in sent[-4:])
    write_json(run.out/'public-unit/sends.json',sent)
    return dict(test='public_deltas_full_init_scope_restart_ack_freeze_default_path',passed=True,simulated_public_messages=len(sent))


def tcp_checks(run):
    from .network_client import Mesh
    from .network_federation import Cooperation
    from gredac.crypto import Denied
    m=Mesh(run.out/'tcp',optimize_initial_config=True);calls=[];original=m.call
    def capture(dest,method,**args):
        if method=='configure':calls.append(dict(target=dest,pid=m.processes[dest].pid,**copy.deepcopy(args)))
        return original(dest,method,**args)
    m.call=capture
    try:
        x=Cooperation(run,'first',16,'G1',m,service='S1',connect=False)
        y=Cooperation(run,'second',16,'G2',m,service='S2',connect=False)
        # First successful message to every process/namespace is full. Check
        # the captured public messages, not participant private state.
        first={}
        for row in calls:
            key=(row['target'],row['pid'],row.get('_scope'))
            if key not in first:
                assert row['target'] in row['routes'] and row['target'] in row['registrations']
                assert 'Driver' in row['routes'];first[key]=row
        assert m.config_distribution['delta'] and m.config_distribution['skipped']
        # An actual clean process exit/restart during bootstrap requires full
        # configuration for the same identity with a new PID and endpoint.
        m.add('BootstrapOnly');old=m.processes['BootstrapOnly'].pid
        m.call('BootstrapOnly','stop');m.processes['BootstrapOnly'].join(5)
        before=len(calls);m.restart('BootstrapOnly');new=m.processes['BootstrapOnly'].pid
        assert old!=new
        row=next(r for r in calls[before:] if r['target']=='BootstrapOnly')
        assert row['routes']==m.routes and row['registrations']==m.registrations
        m.finish_initial_configuration();assert not m.optimize_initial_config
        x.connect();y.connect();y.request(0,'second')
        # Retry is defined for an uncertain request, not an already-resolved
        # local pending entry. Drop the actual endpoint response first.
        x.lab.mesh.call(x.lab.endpoint_id,'arm_fault',point='response_loss')
        try:x.request(0,'first')
        except (OSError,ConnectionError):pass
        else:raise AssertionError('injected response loss not observed')
        answer=x.lab.retry(x.wallet,'first');assert answer['replay']
        x.lab.call('O','revoke',{'id':x.holding.right})
        try:x.request(1,'old-after-revoke')
        except Denied:pass
        else:raise AssertionError('revoked branch accepted')
        recovered,slots=x.lab.recovery(x.wallet,x.root,actor='O')
        assert set(slots)=={'budget'} and sorted(slots['budget'])==list(range(1,16)),slots
        fresh=x.lab.right('replacement','Replacement','first',x.root)
        held=x.lab.delegate(recovered,fresh,slots)
        w=x.lab.reserve(held,x.service,slots);x.lab.charge(w,{'budget':1},'replacement-request')
        y.request(1,'unaffected-second')
        routes=m.routes;assert all(r['pid']!=os.getpid() for n,r in routes.items() if n!='Driver')
        assert len({r['pid'] for n,r in routes.items() if n!='Driver'})==len(routes)-1
        assert len({r['port'] for n,r in routes.items() if n!='Driver'})==len(routes)-1
        audits=[x.close(),y.close()];assert [a['new_requests'] for a in audits]==[2,2]
        write_json(run.out/'tcp/configure-public-messages.json',calls)
        return dict(test='real_tcp_scoped_preparation_restart_then_legacy_runtime',passed=True,audits=audits,
            independent_actor_processes=len(routes)-1,distribution=m.config_distribution)
    finally:m.finish_initial_configuration();m.close()


def main():
    p=parser(__doc__);p.set_defaults(repeats=1,slot_bits=8);a=p.parse_args();run=Run(a,'rq4_config_regression')
    try:run.finish([unit_checks(run),tcp_checks(run)])
    except BaseException:
        run.manifest.update(status='FAIL',traceback=traceback.format_exc());write_json(run.out/'manifest.json',run.manifest);raise


if __name__=='__main__':main()
