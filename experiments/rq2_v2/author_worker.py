"""A process actually runs the unmodified author's User/Provider/Agent code.

Pipe messages schedule a task or retrieve post-task evidence. Agent business
traffic uses only the author's connect/listen/send/recv TLS socket path. The
deterministic LocalAgent extension computes answers at the receiving Agent.
No SAGA security interface is reimplemented here.
"""
import contextlib,functools,hashlib,json,os,sys,threading,time,traceback
from pathlib import Path
from . import timing,business


def configure(root,options):
    sys.path.insert(0,str(root))
    import saga.config as c
    c.Q_MAX=2049
    import saga.agent as a
    a.MAX_QUERIES=4096
    return c,a


def instrument_author():
    import saga.common.crypto as crypto
    import saga.ca.CA as ca
    import requests
    for name in ('generate_ed25519_keypair','generate_x25519_keypair','generate_x509_certificate',
                 'verify_x509_certificate','encrypt_token','decrypt_token'):
        timing.wrap(crypto,name,'author.crypto.'+name)
    timing.wrap(ca.CA,'sign','author.ca.sign');timing.wrap(ca.CA,'verify','author.ca.verify')
    timing.wrap(requests.sessions.Session,'request','author.http.request')


def process_main(role,root,pipe,options):
    root=Path(root);log=Path(options['out'])/('author-'+role+'.log')
    with log.open('w') as stream,contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
        trace=timing.start(options['timing'],'SAGA-author-source@7372111',role,options['run_id'])
        try:
            config,module=configure(root,options);instrument_author()
            if role=='Provider':
                from saga.provider.provider import Provider
                p=Provider(str(root/'provider-state'),'provider','127.0.0.1',options['provider_port'],options['mongo_uri'])
                # Flask route wrappers only observe the existing route function.
                for name,fn in list(p.app.view_functions.items()):
                    def observed(*a,_fn=fn,_name=name,**kw):
                        with trace.span('author.provider.'+_name):return _fn(*a,**kw)
                    p.app.view_functions[name]=observed
                threading.Thread(target=p.run,daemon=True).start()
                pipe.send(dict(initialized=True,pid=os.getpid(),source_file=sys.modules[Provider.__module__].__file__))
                assert pipe.recv()['op']=='stop'
                (Path(options['out'])/'author-provider-cpu.json').write_text(json.dumps(p.monitor.elapsed_all(),indent=2));return
            if role in ('UO','UR'):
                directory=root/'users'/role;directory.mkdir(parents=True);os.chdir(directory)
                config.USER_WORKDIR=str(directory)
                from saga.user import user
                for name in ('register','login','register_agent'):timing.wrap(user,name,'author.user.'+name)
                uid=role.lower()+'@rq2.local'
                with trace.span('user_registration_and_login',options.get('identity_phase','identity'),display_phase=True):
                    user.register(uid,'lab-only-not-a-user-credential')
                    assert user.login(uid,'lab-only-not-a-user-credential'),'author login failed'
                pipe.send(dict(ready=True,pid=os.getpid(),source_file=user.__file__))
                registered=0
                while True:
                    cmd=pipe.recv()
                    if cmd['op']=='stop':break
                    assert cmd['op']=='register_agent'
                    with trace.span('agent_registration',cmd.get('phase','identity'),member=cmd['name']):
                        # Native Provider consumes the login JWT after each
                        # registration (provider.py $pull auth_tokens). Only
                        # subsequent registrations need a fresh native login.
                        if registered:
                            assert user.login(uid,'lab-only-not-a-user-credential')
                        user.register_agent(name=cmd['name'],device='loopback',IP='127.0.0.1',port=cmd['port'],
                            num_one_time_keys=cmd['incoming'],contact_rulebook=[dict(pattern='*',budget=max(1,cmd['incoming']))])
                        path=directory/(uid+':'+cmd['name'])/'agent.json';assert path.exists(),'author agent registration failed'
                        registered+=1
                    pipe.send(dict(material_path=str(path.parent),aid=uid+':'+cmd['name'],pid=os.getpid()))
                (Path(options['out'])/('author-'+role+'-cpu.json')).write_text(json.dumps(user.monitor.elapsed_all(),indent=2));return
            agent_main(role,root,pipe,options,module,trace)
        except BaseException as e:
            traceback.print_exc()
            try:pipe.send(dict(error=repr(e)))
            except (OSError,BrokenPipeError):pass
            raise
        finally:trace.flush();pipe.close()


def agent_main(role,root,pipe,options,module,trace):
    from saga.local_agent import LocalAgent
    from saga.common.logger import Logger
    completed=[];received=[];pending=None;count=0;start_index=0;kind=None;first_use=None;hot=None;request_span=None;conversation=None
    class Backend(LocalAgent):
        task_finished_token='<TASK_FINISHED>'
        def run(self,query,initiating_agent,agent_instance=None):
            nonlocal pending,count,request_span,first_use,hot
            if not initiating_agent:
                payload=json.loads(query)
                phase='II' if payload['kind']=='handoff' else ('III.first' if agent_instance is None else 'III.hot')
                with trace.span('business.execute',phase,request_id=payload.get('index')):
                    if payload['kind']=='query':answer=business.result(payload)
                    else:
                        assert payload['kind']=='handoff';answer=dict(accepted=payload['task'],recipient=role)
                    received.append(dict(payload=payload,result=answer,pid=os.getpid()))
                return self,business.encoded(answer).decode()
            answer=json.loads(query)
            if kind=='service':
                business.verify(pending,answer);completed.append(dict(index=pending,result=answer,pid=os.getpid()))
                trace.end_interval(request_span);request_span=None
                trace.event('result_verified',index=pending)
                if first_use:
                    trace.event('first_result_verified');trace.end_interval(first_use);first_use=None
                    if options.get('replacement_active'):trace.event('replacement_first_result_verified')
                    if count>1:hot=trace.interval('hot_request_sequence','III.hot',display_phase=True)
                if pending+1<start_index+count:
                    pending+=1;request_span=trace.interval('hot_request','III.hot',parent=hot,request_id=f'business-{pending}')
                    return self,business.encoded(business.request(pending)).decode()
                if hot:trace.end_interval(hot);hot=None
                trace.event('conversation_last_result_verified')
                return self,self.task_finished_token
            assert answer==dict(accepted='rq2',recipient=options['recipient_name'])
            completed.append(dict(handoff=True,recipient=options['recipient_name'],pid=os.getpid()))
            return self,self.task_finished_token

    # Preserve original author's listener. The existing log marks bind/listen
    # completion; this adds no readiness connection to the measured protocol.
    ready=threading.Event();old_log=Logger.log
    def log(*args,**kwargs):
        value=old_log(*args,**kwargs)
        if any(isinstance(x,str) and x.startswith('Listening on ') for x in args):ready.set()
        return value
    Logger.log=log
    with trace.span('agent_material_loading_and_listener',options.get('identity_phase','identity')):
        agent=module.Agent(options['material_path'],module.get_agent_material(options['material_path']),Backend())
        listener=threading.Thread(target=agent.listen,daemon=True);listener.start();assert ready.wait(30),'author listener not ready'
    counts=dict(generated_tokens=0,validations=[]);connection_done=threading.Event();connection_done.set()
    for name in ('access','connect','initiate_conversation','receive_conversation','store_received_token'):
        timing.wrap(module.Agent,name,'author.agent.'+name)
    class Meter:
        def __init__(self,conn):self.conn=conn;self.bytes=0
        def sendall(self,data):self.bytes+=len(data);return self.conn.sendall(data)
        def recv(self,n):
            value=self.conn.recv(n);self.bytes+=len(value);return value
        def __getattr__(self,name):return getattr(self.conn,name)
    for name in ('send','recv'):
        original=getattr(module.Agent,name)
        def observed_socket(self,conn,*a,_fn=original,_name=name,**kw):
            local,peer=conn.getsockname(),conn.getpeername()
            source,target=(local,peer) if _name=='send' else (peer,local)
            edge='send' if _name=='send' else 'receive'
            cid=trace.next_message(str(source),str(target),'author-frame',edge);meter=Meter(conn)
            with trace.span('author.agent.'+_name,correlation_id=cid,message_id=cid,edge=edge) as span:
                try:return _fn(self,meter,*a,**kw)
                finally:span['plaintext_frame_bytes']=meter.bytes
        setattr(module.Agent,name,observed_socket)
    old_generate=module.Agent.generate_token
    def generate(self,*a,**kw):
        with trace.span('author.agent.generate_token'):value=old_generate(self,*a,**kw)
        counts['generated_tokens']+=1;return value
    module.Agent.generate_token=generate
    for name in ('token_is_valid','received_token_is_valid'):
        original=getattr(module.Agent,name)
        def check(self,token,*a,_fn=original,_name=name,**kw):
            tokens=self.active_tokens if _name=='token_is_valid' else self.received_tokens
            before=tokens.get(token,{}).get('communication_quota')
            with trace.span('author.agent.'+_name) as span:
                value=_fn(self,token,*a,**kw)
                counts['validations'].append(dict(check=_name,token_hash=hashlib.sha256(token.encode()).hexdigest(),quota_before=before,valid=value))
                span['valid']=value;return value
        setattr(module.Agent,name,check)
    old_handle=module.Agent.handle_i_agent_connection
    def handle(self,*a,**kw):
        connection_done.clear()
        try:
            with trace.span('author.agent.handle_connection'):return old_handle(self,*a,**kw)
        finally:connection_done.set()
    module.Agent.handle_i_agent_connection=handle
    pipe.send(dict(ready=True,pid=os.getpid(),aid=agent.aid,source_file=module.__file__))
    while True:
        cmd=pipe.recv()
        if cmd['op']=='stop':break
        if cmd['op']=='evidence':
            assert connection_done.wait(30),'receiver conversation did not end'
            pipe.send(dict(completed=completed,received=received,counters=counts,
                active_tokens=len(agent.active_tokens),remaining_otks=len(agent.otks_dict),pid=os.getpid(),
                author_cpu_monitor=agent.monitor.elapsed_all(),business_backend_wall_monitor=agent.llm_monitor.elapsed_all()));continue
        assert cmd['op']=='connect';kind=cmd['kind'];before=len(completed)
        options['recipient_name']=cmd['recipient_name'];options['replacement_active']=cmd.get('replacement',False)
        count=cmd.get('count',1);start_index=cmd.get('begin',0);pending=start_index
        if kind=='service':
            first_use=trace.interval('service_first_use','III.first',display_phase=True)
            trace.event('service_first_use_begin');request_span=trace.interval('first_request','III.first',parent=first_use,request_id=f'business-{pending}')
            message=business.encoded(business.request(pending)).decode()
        else:
            conversation=trace.span('task_handoff','II',display_phase=True);conversation.__enter__()
            message=business.encoded(dict(kind='handoff',task='rq2',recipient=cmd['recipient_name'])).decode()
        agent.connect(cmd['target'],message)
        assert len(completed)-before==count,'author connect did not complete requested business'
        if kind=='handoff':conversation.__exit__(None,None,None)
        else:trace.event('conversation_termination_complete')
        pipe.send(dict(completed=len(completed)-before,pid=os.getpid()))
    # Listen loop is a daemon as in the author artifact; after native task
    # termination, process exit only tears down deployment, not revocation.


def ca_main(directory,port,pipe):
    from http.server import ThreadingHTTPServer,SimpleHTTPRequestHandler
    server=ThreadingHTTPServer(('127.0.0.1',port),functools.partial(SimpleHTTPRequestHandler,directory=directory))
    pipe.send(dict(ready=True,pid=os.getpid()));pipe.close();server.serve_forever()
