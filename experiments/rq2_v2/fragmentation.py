"""Q2-3c: fixed 256 units; vary measured minimal GGM prefix-cover count.

Three ancestors always receive [0,512); only the final transfer changes.
The actual cover(), not interval-count terminology, validates each input.
"""
from .common import Task,parser,run_case


def selected(c):
    length=256//c
    return [i for j in range(c) for i in range(2*j*length,(2*j+1)*length)]


def execute(run,cfg):
    from gredac.crypto import cover,domain_for
    from experiments.support import write_json
    slots=selected(cfg['cover']);prefixes=cover(domain_for(['query'],slots))
    assert len(slots)==256 and len(prefixes)==cfg['cover'] and max(slots)<32768
    write_json(run.out/'selected_scope.json',dict(slots=slots,prefixes=prefixes,slot_bits=15,depth=4,issued=32768))
    task=Task(run,cfg,['A1','A2','A3','A4','S1'],32768);parent='O'
    for child in ('A1','A2','A3'):task.handoff(parent,child,list(range(512)));parent=child
    task.handoff('A3','A4',slots);task.conversation(0,9,slots);return task

if __name__=='__main__':run_case(parser(__doc__).parse_args(),'fragmentation',execute)
