"""Non-performance tests: fake transport/sleeper, no LLM or role processes."""
import json,os,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
from . import model,wait_hooks


class ModelTests(unittest.TestCase):
    def test_layouts(self):
        b=dict(west=1,east=2,europe=3,asia=4)
        self.assertEqual(model.path_key('A1','G','distributed',b),'2>3')
        self.assertEqual(model.path_key('A1','G','authority_asia',b),'2>3')
        self.assertEqual(model.path_key('UO','Authority','authority_asia',b),'1>4')
        self.assertIsNone(model.path_key('UO','Authority','distributed',b))
        self.assertIsNone(model.path_key('G','S1','distributed',b))
        self.assertIsNone(model.path_key('Driver','A1','distributed',b))
    def test_connection_factor_and_rng(self):
        self.assertEqual(model.rpc_multiplier(False),1);self.assertEqual(model.rpc_multiplier(True),3)
        d={'regions':{'west':[{'probe':1},{'probe':2}],'east':[{'probe':3},{'probe':4}]}}
        self.assertEqual(model.bindings(d,1,'r',0),model.bindings(d,1,'r',0))
    def test_real_and_requested_wait_separate(self):
        row={};times=iter((1000000000,1120000000));slept=[]
        wait_hooks.pause(row,'test',.1,sleep=slept.append,clock=lambda:next(times))
        self.assertEqual(slept,[.1]);self.assertEqual(row['waits'][0]['actual_seconds'],.12)


class HookTests(unittest.TestCase):
    def setUp(self):
        import gredac.rpc as rpc
        self.rpc=rpc;self.saved=(rpc.Client.call,rpc.send,rpc.receive,rpc.Client.close)
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.payloads=[];self.sleeps=[]
        self.sample=self.root/'samples.json';self.sample.write_text(json.dumps({'2>3':[100.,120.]}))
        cfg=dict(profile='distributed',seed=1,run='test',bindings=dict(west=1,east=2,europe=3,asia=4),runtime_samples=str(self.sample))
        self.config=self.root/'config.json';self.config.write_text(json.dumps(cfg))
        self.env=patch.dict(os.environ,{'RQ2_RTT_ENABLED':'1','RQ2_RTT_CONFIG':str(self.config)});self.env.start()
        outer=self
        class Conn:
            def __init__(self):self.timeouts=[]
            def settimeout(self,x):self.timeouts.append(x)
        def base_call(client,destination,method,**args):
            # Match the real transport signature; `target` is a legitimate
            # business/handler argument and must remain inside **args.
            target=destination
            links=client.local.links
            conn=links.setdefault(target,Conn());r=client.routes[target]
            client.local.epochs[target]=(r['pid'],r['port'],r['public']);conn.settimeout(120)
            rpc.send(conn,dict(method=method,args=args));return rpc.receive(conn)[0]
        rpc.Client.call=base_call;rpc.send=lambda conn,value:outer.payloads.append(value)
        rpc.receive=lambda conn:({'ok':True},4);rpc.Client.close=lambda self:None
        self.patcher=patch.object(wait_hooks,'pause',side_effect=lambda row,part,seconds:outer.sleeps.append((part,seconds)) if seconds else None);self.patcher.start()
        wait_hooks.INSTALLED=False
    def tearDown(self):
        self.rpc.Client.call,self.rpc.send,self.rpc.receive,self.rpc.Client.close=self.saved
        wait_hooks.INSTALLED=False;self.patcher.stop();self.env.stop();self.tmp.cleanup()
    def client(self,source='A1',target='G'):
        c=self.rpc.Client.__new__(self.rpc.Client);c.name=source;c.trace=self.root/(source+'.jsonl');c.local=threading.local()
        c.local.links={};c.local.epochs={};c.routes={target:dict(pid=1,port=1,public='pub')};return c
    def test_new_and_reused_connection(self):
        wait_hooks.install();c=self.client();body={'payload':{'ordered':[3,1],'bytes':'unchanged'}}
        c.call('G','endpoint_charge',**body);first=list(self.sleeps);self.sleeps.clear()
        c.call('G','endpoint_charge',**body);second=list(self.sleeps);c.close()
        self.assertEqual([p for p,s in first],['modeled_tcp_tls_setup','request_half_rtt','reply_half_rtt'])
        self.assertEqual([p for p,s in second],['request_half_rtt','reply_half_rtt'])
        self.assertEqual(first[0][1],4*first[1][1]);self.assertEqual(first[1][1],first[2][1])
        self.assertTrue(all(v=={'method':'endpoint_charge','args':body} for v in self.payloads))
        self.assertIsNone(wait_hooks.CURRENT.get())
        rows=[json.loads(l) for l in (self.root/'rtt-waits.jsonl').read_text().splitlines()]
        self.assertEqual([r['new_connection'] for r in rows],[True,False]);self.assertTrue(all(r['result']=='ok' for r in rows))
    def test_unknown_role_method_rejected(self):
        wait_hooks.install();c=self.client()
        with self.assertRaisesRegex(ValueError,'unmapped'):c.call('G','not_a_protocol_method')
        self.assertFalse(self.payloads)
    def test_local_and_diagnostics_have_no_wait(self):
        wait_hooks.install();c=self.client('G','S1');c.call('S1','service_receive');c.call('S1','audit');c.close()
        self.assertFalse(self.sleeps)
    def test_only_control_timeout_extended(self):
        wait_hooks.install();c=self.client('Driver','A1');c.call('A1','rq2_conversation')
        self.assertEqual(c.local.links['A1'].timeouts,[120,2400]);self.assertFalse(self.sleeps)
        d=self.client();d.call('G','endpoint_charge');d.close();self.assertEqual(d.local.links['G'].timeouts,[120])
    def test_disabled_by_default(self):
        os.environ.pop('RQ2_RTT_ENABLED');wait_hooks.install();c=self.client();c.call('G','arbitrary');c.close()
        self.assertFalse(self.sleeps);self.assertFalse((self.root/'rtt-waits.jsonl').exists())
    def test_dynamic_service_handler_target_argument(self):
        # Exact caller shape from Adapter.dynamic_identity('S1'). The delay
        # wrapper must not consume its `target='rq2'` payload field.
        wait_hooks.install();c=self.client('Driver','S1')
        c.call('S1','handler',kind='fixed',target='rq2');c.close()
        self.assertEqual(self.payloads,[dict(method='handler',args=dict(kind='fixed',target='rq2'))])
        self.assertFalse(self.sleeps)
    def test_role_rpc_target_payload_preserved(self):
        wait_hooks.install();c=self.client()
        c.call('G','endpoint_charge',target='business-resource');c.close()
        self.assertEqual(self.payloads,[dict(method='endpoint_charge',args=dict(target='business-resource'))])
        row=json.loads((self.root/'rtt-waits.jsonl').read_text())
        self.assertEqual(row['target'],'G')
    def test_disabled_target_payload_preserved(self):
        os.environ.pop('RQ2_RTT_ENABLED');wait_hooks.install();c=self.client('Driver','S1')
        c.call('S1','handler',kind='fixed',target='rq2');c.close()
        self.assertEqual(self.payloads,[dict(method='handler',args=dict(kind='fixed',target='rq2'))])
        self.assertFalse(self.sleeps)


if __name__=='__main__':unittest.main(verbosity=2)
