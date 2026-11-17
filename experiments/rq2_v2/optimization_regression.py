"""Functional checks of the optimization, not a performance experiment.

Exercise transaction cache invalidation/ownership, rollback, crash-boundary
durability and diagnostic buffering. Real protocol rejection/retry tests
remain in alignment_regression and gredac_regression; the six flow pilots
add actual cross-process dynamic identity and ledger audits.
"""
import argparse,json,os,sqlite3,threading,zipfile,ast
from pathlib import Path


def hot_checks(out):
    """Byte/semantic and rejection checks, never a claimed speed benchmark."""
    import copy
    from unittest.mock import patch
    import gredac.crypto as crypto
    from gredac.roles import verified,check_envelope
    from gredac.rpc import AcceptedLink,json_message,encode,receive
    from gredac.material import unpack
    from cryptography.exceptions import InvalidSignature
    # Count actual primitive verify executions, including after a cache hit.
    crypto._verification_key.cache_clear();native=crypto.Ed25519PublicKey;counts={'parse':0,'verify':0}
    class Parsed:
        def __init__(self,key):self.key=key
        def verify(self,*args):counts['verify']+=1;return self.key.verify(*args)
    class Parser:
        @staticmethod
        def from_public_bytes(value):counts['parse']+=1;return Parsed(native.from_public_bytes(value))
    signer=crypto.Signer('s');value={'nested':{'z':2,'a':[1,'中文']}};signed=signer.envelope(value)
    try:
        with patch.object(crypto,'Ed25519PublicKey',Parser):
            crypto.verify_signature(signer.public,value,signed['signature'])
            crypto.verify_signature(signer.public,value,signed['signature'])
            try:crypto.verify_signature(signer.public,{'tampered':True},signed['signature'])
            except crypto.Denied as e:assert e.code=='BAD_SIGNATURE'
            else:raise AssertionError('cache bypassed a signature check')
        assert counts=={'parse':1,'verify':3}
    finally:crypto._verification_key.cache_clear()
    # Check-only must execute the same signature and request-binding checks.
    assert check_envelope(signed,signer.public,nested=value['nested']) is None
    copied=verified(signed,signer.public);copied['nested']['a'].append(7);assert signed['body']==value
    for candidate,bindings in [(signed,{'nested':'wrong'}),({**signed,'signature':'00'*64},{})]:
        for fn in (check_envelope,verified):
            try:fn(candidate,signer.public,**bindings)
            except crypto.Denied:pass
            else:raise AssertionError('receipt check removed')
    # The fast adapter starts AFTER an actual RPC decode. A literal socket
    # roundtrip is separately covered by the original network regressions.
    packet={'body':'00ff','payload':{'z':[2,1],'a':'中文'},'act':signed,'proofs':{'s':'00'}}
    received=unpack(json.loads(encode(packet)))
    link=AcceptedLink('A','G','a','g')
    assert json_message(link,received) is received
    assert crypto.canonical(json_message(link,received))==crypto.canonical(json.loads(crypto.canonical(received)))
    assert unpack(json.loads(encode({'ok':True,'value':json_message(link,received,reply=True)})))=={'ok':True,'value':packet}
    class Legacy:
        def __init__(self):self.calls=[]
        def transfer(self,data,reply=False):self.calls.append(reply);return data
    legacy=Legacy();assert json_message(legacy,packet)==packet and json_message(legacy,packet,reply=True)==packet
    assert legacy.calls==[False,True]
    # Retry metadata copies intentionally remain: later wallet/ACT changes
    # cannot rewrite pending request/session information after response loss.
    (out/'hotpath_primitive_counts.json').write_text(json.dumps(counts,indent=2))
    return ['immutable_public_key_parse_reused_but_all_3_verifications_executed',
        'check_only_receipt_tampering_rejected_and_copy_consumers_still_isolated',
        'post_TCP_adapter_preserves_canonical_messages_and_legacy_transfers']


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False);checks=[]
    from gredac.storage import Store
    s=Store(a.out/'state.sqlite');queries=[];s.db.set_trace_callback(queries.append)
    s.put('rights','r',{'actions':['query']})
    with s.transaction():
        queries.clear();r=s.get('rights','r');r['actions'].append('book')
        assert s.get('rights','r')=={'actions':['query']}
        assert len([q for q in queries if q.startswith('SELECT value')])==1
        s.put('rights','r',r);r['actions'].append('unwritten')
        assert s.get('rights','r')=={'actions':['query','book']}
        assert s.get('revoked','missing',{'a':1})=={'a':1}
        assert s.get('revoked','missing',{'a':2})=={'a':2}
        s.put('revoked','missing',True);assert s.get('revoked','missing') is True
    checks.append('one_metadata_query_per_snapshot_copy_isolation_write_and_miss_invalidation')
    try:
        with s.transaction():
            s.get('rights','r');s.put('rights','r',{'rollback':True});raise ValueError('rollback')
    except ValueError:pass
    assert s.get('rights','r')=={'actions':['query','book']}
    with s.transaction():assert s.get('rights','r')=={'actions':['query','book']}
    checks.append('rollback_and_next_transaction_do_not_reuse_cached_state')
    def worker():
        with s.transaction():
            assert s.get('rights','r')=={'actions':['query','book']}
            s.put('rights','r',{'thread':True})
    t=threading.Thread(target=worker);t.start();t.join()
    with s.transaction():assert s.get('rights','r')=={'thread':True}
    checks.append('thread_local_cache_isolated_under_original_transaction_lock')
    for point,expected in [('before_commit',None),('after_commit',{'committed':True})]:
        def stop(where):
            if where==point:raise RuntimeError('injected')
        s.commit_hook=stop
        try:
            with s.transaction():s.put('rights',point,{'committed':True});s.event(point,{'committed':True})
        except RuntimeError:pass
        else:raise AssertionError('hook not reached')
        s.commit_hook=None
        with sqlite3.connect(a.out/'state.sqlite') as reader:
            row=reader.execute('SELECT value FROM records WHERE kind=? AND key=?',('rights',point)).fetchone()
            assert (json.loads(row[0]) if row else None)==expected
            assert reader.execute('SELECT count(*) FROM events WHERE kind=?',(point,)).fetchone()[0]==(expected is not None)
        assert s.get('rights',point)==expected
    assert s.db.execute('PRAGMA synchronous').fetchone()[0]==2
    assert s.db.execute('PRAGMA journal_mode').fetchone()[0]=='wal';s.close()
    checks.append('original_FULL_WAL_commit_and_event_atomicity_before_after_commit')
    from gredac.rpc import DiagnosticLog
    saved=os.environ.get('GREDAC_BUFFER_DIAGNOSTICS')
    try:
        os.environ.pop('GREDAC_BUFFER_DIAGNOSTICS',None)
        immediate=DiagnosticLog(a.out/'immediate.jsonl');immediate.append({'n':1});assert immediate.path.exists()
        os.environ['GREDAC_BUFFER_DIAGNOSTICS']='1';buffered=DiagnosticLog(a.out/'buffered.jsonl')
        value={'data':[1]};buffered.append(value);value['data'].append(2)
        assert not buffered.path.exists();buffered.flush();buffered.flush()
        assert [json.loads(x) for x in buffered.path.read_text().splitlines()]==[{'data':[1]}]
    finally:
        if saved is None:os.environ.pop('GREDAC_BUFFER_DIAGNOSTICS',None)
        else:os.environ['GREDAC_BUFFER_DIAGNOSTICS']=saved
    checks.append('diagnostic_snapshot_flush_no_duplicates_and_default_immediate')
    with zipfile.ZipFile(Path(__file__).with_name('author_source.zip')) as z:
        tree=ast.parse(z.read('saga/provider/provider.py'))
    routes=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='route':routes.append(ast.literal_eval(n.args[0]))
    assert sorted(routes)==sorted(['/','/certificate','/register','/login','/register_agent','/access'])
    checks.append('pinned_author_artifact_has_no_callable_deactivation_route')
    checks.extend(hot_checks(a.out))
    (a.out/'manifest.json').write_text(json.dumps(dict(status='PASS',tests=checks,llm_api_calls=0),indent=2))
    print('PASS',len(checks),'optimization checks')


if __name__=='__main__':main()
