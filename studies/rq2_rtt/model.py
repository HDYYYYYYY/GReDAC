"""Explicit geographic sensitivity model, NOT a WAN measurement.

The audited trace is synchronous (nested RPCs are sequential dependencies).
We add only link delays, once per send; measured inclusive spans are never
summed. One successful ICMP RTT represents request+reply propagation. A new
TCP/TLS1.3 connection adds two idealized RTTs (TCP then TLS), without modeling
loss, throughput, packet fragmentation, congestion, HRR or resumed TLS.
"""
import hashlib
import json
from pathlib import Path

PROFILES=('local','distributed','authority_asia')
REGIONS={'UO':'west','O':'west','A1':'east','UR':'europe','R':'europe',
         'S1':'europe','G':'europe','Authority':'west'}
# These are the genuine role-to-role operations present in the audited task.
# Unknown role-to-role operations fail closed in the standalone wait driver;
# diagnostics/control interfaces are excluded, not assigned arbitrary RTTs.
OPERATIONS={'authority_accept','initialize','initial_receive','install_right',
            'receive_task_info','endpoint_control','receive_delegation',
            'endpoint_discover','prove','sync','contact_respond','session',
            'endpoint_charge','service_receive'}
DIAGNOSTICS={'configure','configure_delta','stats','audit','close','shutdown','ping'}


def stable_seed(*parts):
    return int.from_bytes(hashlib.sha256(json.dumps(parts,separators=(',',':')).encode()).digest()[:8],'big')


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def load_data(directory,verify=True):
    directory=Path(directory);f=json.loads((directory/'FREEZE.json').read_text())
    if verify:
        for name,digest in f['files_sha256'].items():
            assert sha(directory/name)==digest,('RTT dataset changed',name)
    return json.loads((directory/'samples.json').read_text()),f


def bindings(data,seed,run,draw):
    import random
    # Draw endpoints once per simulated task, independent of its layout.
    return {region:random.Random(stable_seed(seed,run,draw,region)).choice(nodes)['probe']
            for region,nodes in data['regions'].items()}


def path_key(source,target,profile,bound):
    assert profile in PROFILES
    if profile=='local' or source=='Driver' or target=='Driver':return None
    regions=dict(REGIONS)
    if profile=='authority_asia':regions['Authority']='asia'
    a,b=regions[source],regions[target]
    # Same region explicitly means colocated at the SAME selected site.
    return None if a==b else f'{bound[a]}>{bound[b]}'


def rpc_multiplier(new_connection):
    return 1+2*int(new_connection)
