"""Private UDS SDK bridge. receive_admitted is called only by verified ServiceRole."""
import asyncio, concurrent.futures, copy, json, os, secrets, sqlite3, tempfile, threading, time
from pathlib import Path
import httpx, uvicorn
from google.protobuf.json_format import ParseDict, MessageToDict
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from a2a.types.a2a_pb2 import AgentCard, Message, SendMessageRequest
from a2a.server.agent_execution import AgentExecutor
from a2a.server.context import ServerCallContext
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.server.routes import create_jsonrpc_routes, create_agent_card_routes, ServerCallContextBuilder
from a2a.client.transports.jsonrpc import JsonRpcTransport
from a2a.client import ClientCallContext
from gredac.crypto import canonical,digest,require,Denied
from .codec import (PROFILE,URL,MAX_REQUEST,MAX_RESPONSE,loads,clean,fields,
                    normalize_send_request,validate_payload,classify_operation,make_card)

class ContextBuilder(ServerCallContextBuilder):
    def build(self,request):
        return ServerCallContext(state={'approved':request.scope['gredac_approved'],'headers':dict(request.headers)})

class Executor(AgentExecutor):
    def __init__(self,bridge):self.bridge=bridge
    async def execute(self,context,event_queue):
        b=self.bridge;a=context.call_context.state.get('approved')
        require(a is not None and a['seal'] is b.seal,'A2A_TRUSTED_CONTEXT')
        # Task/context fields added by SDK are never authorization inputs.
        data=copy.deepcopy(a['request']['message']['parts'][0]['data'])
        data['_admission_key']=a['key']
        data['_service']=a['service'];data['_payload_digest']=a['envelope_digest']
        with b.db_lock:
            b.db.execute('INSERT INTO business(key,request_digest,sdk_context,sdk_task,started) VALUES(?,?,?,?,?)',
                (a['key'],digest(a['request']),context.context_id,context.task_id,time.monotonic()))
        try:
            value=await asyncio.to_thread(b.business,data)
            result=dict(status='OK',value=value)
        except Exception as exc:
            result=dict(status='ERROR',code='BUSINESS_ARGUMENTS',detail=str(exc)[:256])
        with b.db_lock:
            b.db.execute('UPDATE business SET finished=?,result_digest=? WHERE key=?',(time.monotonic(),digest(result),a['key']))
        b.trip('after_business')
        response=clean(dict(messageId='reply-'+a['request']['message']['messageId'],role='ROLE_AGENT',
                            contextId=context.context_id,parts=[dict(data=result)]))
        require(len(canonical({'message':response}))<=MAX_RESPONSE,'A2A_RESPONSE_SIZE')
        await event_queue.enqueue_event(ParseDict(response,Message()))
    async def cancel(self,context,event_queue):raise Denied('A2A_METHOD')

class Gate:
    def __init__(self,app,bridge):self.app,self.bridge=app,bridge
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        b=self.bridge
        if scope['method']=='GET' and scope['path']=='/.well-known/agent-card.json':
            return await self.app(scope,receive,send)
        try:
            require(scope['method']=='POST' and scope['path']=='/rpc','A2A_ROUTE')
            raw=b''
            while True:
                event=await receive()
                require(event['type']=='http.request','A2A_HTTP')
                raw+=event.get('body',b'');require(len(raw)<=MAX_REQUEST+1024,'A2A_SIZE')
                if not event.get('more_body'):break
            rpc=loads(raw,MAX_REQUEST+1024);fields(rpc,['jsonrpc','id','method','params'])
            require(rpc['jsonrpc']=='2.0' and rpc['method']=='SendMessage','A2A_METHOD')
            request=normalize_send_request(rpc['params'])
            headers=dict(scope.get('headers',[]))
            token=headers.get(b'x-gredac-ticket',b'').decode('ascii',errors='ignore')
            approved=b.tickets.pop(token,None)
            require(approved is not None,'A2A_TICKET')
            require(approved['service']==b.name and approved['request_digest']==digest(request),'A2A_TICKET_BINDING')
            # The persisted starting record must predate creation of the ticket.
            with b.db_lock:
                row=b.db.execute('SELECT state,digest FROM inbox WHERE key=?',(approved['key'],)).fetchone()
            require(row is not None and row[0]=='starting' and row[1]==approved['payload_digest'],'A2A_INBOX')
            scope['gredac_approved']={**approved,'seal':b.seal}
            b.record('gate_accepted',key=approved['key'],rpc_id=rpc['id'],request_digest=digest(request))
            sent=False
            async def replay():
                nonlocal sent
                if not sent:sent=True;return {'type':'http.request','body':raw,'more_body':False}
                return await receive()
            return await self.app(scope,replay,send)
        except Denied as exc:
            b.record('gate_rejected',code=exc.code)
            return await JSONResponse({'error':exc.code},status_code=403)(scope,receive,send)

class BridgeService:
    def __init__(self,path,name,business,timeout=5,version='1'):
        self.path=Path(path);self.path.mkdir(parents=True,exist_ok=True)
        self.name,self.business,self.timeout=name,business,timeout
        self.card=make_card(name,version);self.tickets={};self.seal=object()
        self.db_lock=threading.Lock();self.log_lock=threading.Lock();self.fault=None;self.fault_mode='exit'
        self.db=sqlite3.connect(self.path/'bridge.sqlite',isolation_level=None,check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS inbox(key TEXT PRIMARY KEY,digest TEXT NOT NULL,state TEXT NOT NULL,body TEXT NOT NULL,response TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS business(key TEXT PRIMARY KEY,request_digest TEXT,sdk_context TEXT,sdk_task TEXT,started REAL,finished REAL,result_digest TEXT)')
        columns={r[1] for r in self.db.execute('PRAGMA table_info(business)')}
        for name,kind in [('finished','REAL'),('result_digest','TEXT')]:
            if name not in columns:self.db.execute('ALTER TABLE business ADD COLUMN '+name+' '+kind)
        self.socket_dir=Path(tempfile.mkdtemp(prefix='gredac-a2a-'));self.socket_dir.chmod(0o700)
        self.uds=str(self.socket_dir/'rpc.sock');self.loop=asyncio.new_event_loop()
        self.thread=threading.Thread(target=self._loop,daemon=True);self.thread.start()
        asyncio.run_coroutine_threadsafe(self._start(),self.loop).result(timeout=20)
    def record(self,kind,**kw):
        with self.log_lock:
            with (self.path/'bridge-events.jsonl').open('a') as f:
                f.write(json.dumps(dict(kind=kind,pid=os.getpid(),time=time.monotonic(),**kw),sort_keys=True)+'\n')
    def trip(self,where):
        if self.fault==where:
            self.fault=None;self.record('injected_fault',point=where,mode=self.fault_mode)
            if self.fault_mode=='exit':os._exit(74)
            raise ConnectionError('injected '+where)
    def _loop(self):
        asyncio.set_event_loop(self.loop);self.loop.run_forever()
    async def _start(self):
        card=ParseDict(self.card,AgentCard())
        handler=DefaultRequestHandler(Executor(self),InMemoryTaskStore(),card)
        app=Starlette(routes=create_jsonrpc_routes(handler,'/rpc',ContextBuilder(),enable_v0_3_compat=False)
                      +create_agent_card_routes(card))
        self.app=Gate(app,self)
        self.server=uvicorn.Server(uvicorn.Config(self.app,uds=self.uds,log_level='critical',
                                  access_log=False,lifespan='off',timeout_graceful_shutdown=1))
        self.server_task=asyncio.create_task(self.server.serve())
        for _ in range(1000):
            if self.server.started:break
            if self.server_task.done():await self.server_task
            await asyncio.sleep(.01)
        require(self.server.started,'A2A_STARTUP')
        self.http=httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=self.uds),timeout=self.timeout,
                                   headers={'A2A-Version':'1.0'},trust_env=False)
        self.transport=JsonRpcTransport(self.http,card,URL,is_shared_httpx=True)
        self.record('sdk_started',uds=self.uds,url=URL,profile=PROFILE)
    def description(self):
        with self.db_lock:
            counts=dict(self.db.execute('SELECT state,COUNT(*) FROM inbox GROUP BY state').fetchall())
            business=self.db.execute('SELECT COUNT(*) FROM business').fetchone()[0]
        return dict(card=self.card,uds=self.uds,pid=os.getpid(),inbox=counts,business_executions=business)
    def receive_admitted(self,body):
        # Node.business is reached after ACTServiceRole.receive checks G signature,
        # exact service/right/context and outer authenticated TLS endpoint.
        value=validate_payload(body['payload'])
        require(body['service']==self.name and value['service_right']==body['service_right'],'A2A_DELIVERY_TARGET')
        require(classify_operation(value)==body['operation'],'A2A_OPERATION_BINDING')
        key=canonical([body['endpoint'],body['key']]).decode();fp=digest(body)
        with self.db_lock:
            old=self.db.execute('SELECT digest,state,response FROM inbox WHERE key=?',(key,)).fetchone()
            if old:
                require(old[0]==fp,'A2A_DELIVERY_CONFLICT')
                if old[1]=='completed':return json.loads(old[2])
                return dict(a2a_response=None,business_status='UNKNOWN',bridge_error='INBOX_STARTING')
            self.db.execute('INSERT INTO inbox VALUES(?,?,?,?,NULL)',(key,fp,'starting',canonical(body).decode()))
        self.trip('after_starting')
        future=asyncio.run_coroutine_threadsafe(self._send(body,key,fp),self.loop)
        try:
            response=future.result(timeout=self.timeout+1)
            self.trip('before_completed')
            result=dict(a2a_response=response,business_status=response['message']['parts'][0]['data']['status'])
            with self.db_lock:
                self.db.execute("UPDATE inbox SET state='completed',response=? WHERE key=?",(canonical(result).decode(),key))
            self.trip('after_completed')
            return result
        except Exception as exc:
            future.cancel();self.record('bridge_unknown',key=key,error=type(exc).__name__)
            return dict(a2a_response=None,business_status='UNKNOWN',bridge_error=type(exc).__name__)
    async def _send(self,body,key,fp):
        request=body['payload']['request'];token=secrets.token_hex(32)
        self.tickets[token]=dict(key=key,request=copy.deepcopy(request),request_digest=digest(request),
             payload_digest=fp,envelope_digest=digest(body['payload']),service=body['service'],service_right=body['service_right'],operation=body['operation'])
        try:
            response=await self.transport.send_message(ParseDict(request,SendMessageRequest()),
                context=ClientCallContext(service_parameters={'X-GReDAC-Ticket':token,'A2A-Version':'1.0'},timeout=self.timeout))
            result=clean(MessageToDict(response))
            require(set(result)=={'message'} and result['message']['role']=='ROLE_AGENT','A2A_RESPONSE')
            require(len(canonical(result))<=MAX_RESPONSE,'A2A_RESPONSE_SIZE')
            self.record('sdk_response',key=key,response_digest=digest(result))
            return result
        finally:self.tickets.pop(token,None)
    async def _close(self):
        await self.http.aclose();self.server.should_exit=True
        await self.server_task
        pending=[t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
        for task in pending:task.cancel()
        if pending:await asyncio.gather(*pending,return_exceptions=True)
    def close(self):
        if self.loop.is_running():
            asyncio.run_coroutine_threadsafe(self._close(),self.loop).result(timeout=5)
            self.loop.call_soon_threadsafe(self.loop.stop);self.thread.join(5)
            require(not self.thread.is_alive(),'A2A_CLOSE_TIMEOUT')
            self.loop.close()
        self.db.close()
        # Only our own private empty socket directory is removed.
        Path(self.uds).unlink(missing_ok=True)
        self.socket_dir.rmdir()
