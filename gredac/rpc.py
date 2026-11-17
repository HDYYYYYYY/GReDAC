"""Small mutually authenticated TLS/TCP transport, shared by all role processes.

JSON frames only; no pickle over the network. Peer identity comes from the
verified certificate, never from a caller-supplied field. Connections are
reused per thread. No reconnect/replay, retries or production service manager.
Counters are plaintext frame bytes, NOT estimated TLS wire bytes. Loopback
uses real kernel sockets; it is not a measurement of wide-area networking.
"""
import hashlib,json,os,socket,socketserver,ssl,struct,threading,time
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from .crypto import Denied,require,canonical
from .pki import raw_public
from .material import pack,unpack

LIMIT=2**26


class DiagnosticLog:
    """Bounded optional JSONL buffering, never protocol persistence.

    Fault experiments retain immediate appends by default. RQ2 opts in.
    Audit/close flush all rows; a crash may lose a diagnostic suffix only.
    Serialize at append time to preserve the original object snapshot.
    """
    def __init__(self,path):
        self.path=Path(path);self.lock=threading.Lock();self.rows=[];self.size=0
        self.buffered=os.environ.get('GREDAC_BUFFER_DIAGNOSTICS')=='1'
        self.encoder=json.JSONEncoder(ensure_ascii=False,separators=(',',':'))
    def append(self,row):
        data=self.encoder.encode(row)+'\n'
        with self.lock:
            self.rows.append(data);self.size+=len(data)
            if not self.buffered or self.size>=1024*1024:self._flush()
    def _flush(self):
        if self.rows:
            with self.path.open('a',encoding='utf-8') as f:f.writelines(self.rows)
            self.rows.clear();self.size=0
    def flush(self):
        with self.lock:self._flush()

def encode(value):return json.dumps(pack(value),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()

def exact(conn,n):
    chunks=[]
    while n:
        data=conn.recv(n)
        if not data:raise ConnectionError('RPC peer closed before response')
        chunks.append(data);n-=len(data)
    return b''.join(chunks)

def receive(conn):
    n=struct.unpack('!I',exact(conn,4))[0];require(n<=LIMIT,'RPC_FRAME_LIMIT')
    return unpack(json.loads(exact(conn,n))),n+4

def send(conn,value):
    data=encode(value);require(len(data)<=LIMIT,'RPC_FRAME_LIMIT')
    conn.sendall(struct.pack('!I',len(data))+data);return len(data)+4

def context(directory,name,server=False):
    if (Path(directory)/'pq-profile.json').exists():
        raise ValueError('Unsupported transport profile: this release uses authenticated TLS 1.3')
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_3
    ctx.set_ecdh_curve('X25519');ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(Path(directory)/'ca.pem'))
    ctx.load_cert_chain(str(Path(directory)/(name+'.crt.pem')),str(Path(directory)/(name+'.key.pem')))
    return ctx

def peer(conn):
    cert=x509.load_der_x509_certificate(conn.getpeercert(binary_form=True))
    return dict(name=cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                public=hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest() if getattr(conn,'pq',False) else raw_public(cert.public_key()))

class AcceptedLink:
    """Core codec adapter AFTER authenticated network receive, not a transport.

    Existing core methods decode/encode through transfer(). At this boundary
    TLS and framing have already happened in Server; do not encrypt twice.
    The identity/public key fields are built exclusively from verified TLS.
    """
    def __init__(self,caller,receiver,caller_public='',receiver_public=''):
        self.caller,self.receiver=caller,receiver
        self.caller_public,self.receiver_public=caller_public,receiver_public
    def transfer(self,data,reply=False):return data


def json_message(link,value,reply=False):
    """Avoid a second codec roundtrip *inside* an authenticated TCP handler.

    AcceptedLink is only local peer metadata after RPC receive/JSON unpack;
    the outer RPC still serializes every reply and sends it over TLS/TCP.
    This never returns another participant's in-memory object. Legacy/local
    transports continue their real transfer/decode path, including MemoryBIO.
    The caller must not mutate a request or its returned response in place.
    """
    if type(link) is AcceptedLink:return value
    return json.loads(link.transfer(canonical(value),reply=reply))

class Client:
    def __init__(self,directory,name,routes,trace):
        self.directory,self.name,self.routes,self.trace=Path(directory),name,routes,Path(trace)
        self.local=threading.local();self.lock=threading.Lock();self.connections=[]
        self.diagnostics=DiagnosticLog(self.trace)
    def call(self,destination,method,**args):
        target=destination
        links=getattr(self.local,'links',None)
        if links is None:links={};self.local.links=links
        epochs=getattr(self.local,'epochs',None)
        if epochs is None:epochs={};self.local.epochs=epochs
        identity_epoch=(self.routes[target].get('pid'),self.routes[target]['port'],self.routes[target]['public'])
        if target in links and epochs.get(target)!=identity_epoch:
            links.pop(target).close()
        started=time.monotonic();cpu_started=time.thread_time();handshake=0.;sent=received=0;outcome='error'
        try:
            if target not in links:
                t=time.monotonic();route=self.routes[target]
                raw=socket.create_connection(('127.0.0.1',route['port']),timeout=120)
                raw.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                conn=context(self.directory,self.name).wrap_socket(raw,server_hostname='localhost')
                actual=peer(conn);require(actual['name']==target and actual['public']==route['public'],'RPC_SERVER_IDENTITY')
                links[target]=conn;self.connections.append(conn);handshake=time.monotonic()-t
                epochs[target]=identity_epoch
            conn=links[target]
            # A model action can contain three bounded 90 s API attempts.
            # This is a waiting bound, never an automatic RPC/API retry.
            if hasattr(conn,'settimeout'):conn.settimeout(300 if method=='ask' else 120)
            sent=send(conn,dict(method=method,args=args))
            result,received=receive(conn)
            if not result['ok']:
                error=result['error']
                if error['type']=='Denied':
                    exc=Denied(error['message'])
                    for k,v in error.get('attributes',{}).items():setattr(exc,k,v)
                    raise exc
                if error['type']=='BusinessToolError':
                    from experiments.task_backend import BusinessToolError
                    raise BusinessToolError(error['message'])
                # Preserve an upstream transport failure as such across role
                # boundaries. This reports uncertainty; it never retries.
                if error['type'] in ('ConnectionError','ConnectionResetError','BrokenPipeError','EOFError'):
                    raise ConnectionError(error['message'])
                if error['type'] in ('OSError','TimeoutError','SSLError','SSLEOFError'):
                    raise OSError(error['message'])
                raise RuntimeError(error['type']+': '+error['message'])
            outcome='ok';return result['value']
        except (OSError,ConnectionError):
            if target in links:links.pop(target).close()
            raise
        finally:
            row=dict(pid=os.getpid(),source=self.name,target=target,method=method,start=started,
                end=time.monotonic(),handshake_seconds=handshake,sent_frame_bytes=sent,
                received_frame_bytes=received,outcome=outcome,transport='TLS1.3/TCP/127.0.0.1')
            row['thread_cpu_seconds']=time.thread_time()-cpu_started
            self.diagnostics.append(row)
    def close(self):
        for c in self.connections:
            try:c.close()
            except OSError:pass
        self.diagnostics.flush()

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
    def __init__(self,node,port=0):
        self.node=node;self.ctx=context(node.directory,node.name,True)
        super().__init__(('127.0.0.1',port),Handler)
    def get_request(self):
        sock,address=super().get_request();sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        sock.settimeout(120)
        try:
            conn=self.ctx.wrap_socket(sock,server_side=True)
            # Long model reasoning must not expire unrelated idle channels.
            # Each client's operation has its own bounded response timeout.
            if hasattr(conn,'settimeout'):conn.settimeout(None)
            return conn,address
        except Exception:sock.close();raise
    def handle_error(self,request,address):pass # failed frames are recorded by Handler

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        node=self.server.node;identity=peer(self.request)
        while True:
            try:request,size=receive(self.request)
            except (ConnectionError,OSError,ssl.SSLError):return
            start=time.monotonic();cpu_start=time.thread_time();method=request.get('method');ok=False
            try:
                require(identity['name'] in node.routes and node.routes[identity['name']]['public']==identity['public'],'RPC_CLIENT_IDENTITY')
                value=node.dispatch(method,request['args'],identity);reply=dict(ok=True,value=value);ok=True
            except Exception as exc:
                attrs={k:getattr(exc,k) for k in ('directory','admission_rejected','admitted') if hasattr(exc,k)}
                reply=dict(ok=False,error=dict(type=type(exc).__name__,message=str(exc),attributes=attrs))
            if getattr(self.server,'drop_response_method',None)==method:
                self.server.drop_response_method=None
                node.record('injected_response_loss',dict(method=method,time=time.monotonic()))
                return # Socket closes without sending the completed response.
            try:sent=send(self.request,reply)
            except OSError:sent=0
            node.record('rpc-received',dict(peer=identity['name'],method=method,start=start,end=time.monotonic(),
                        frame_bytes=size+sent,ok=ok,handler_thread_cpu_seconds=time.thread_time()-cpu_start))
