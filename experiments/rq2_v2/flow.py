"""Q2-1: three flows, each with 32 requests and dynamically created members.

Infrastructure and separately disclosed user prerequisites precede task time.
The timed identity stage prepares only native roots. Delegate/replacement
identity work is inside its actual stage. Issuance is 128; replacement is
16+16. SAGA uses the unchanged author source, which lacks a deactivate API
despite the paper's description. No invented revocation is executed.
"""
from .common import Task,parser,run_case


def execute(run,cfg):
    names=['A1','A2','S1']
    if cfg.get('replacement')=='caller':names.append('Anew')
    if cfg.get('replacement')=='service':names.append('S2')
    assert cfg['requests']==32 and cfg['units']==128
    task=Task(run,cfg,names,128);slots=list(range(128))
    task.handoff('O','A1',slots);task.handoff('A1','A2',slots)
    if cfg.get('replacement'):
        middle=cfg['requests']//2
        task.conversation(0,middle,slots)
        task.replace(cfg['replacement'],slots[middle:])
        task.conversation(middle,cfg['requests']-middle,slots[middle:])
    else:task.conversation(0,cfg['requests'],slots)
    return task

if __name__=='__main__':run_case(parser(__doc__).parse_args(),'flow',execute)
