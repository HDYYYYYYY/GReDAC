"""Step 3c: exactly 256 units; minimal cover=1/4/16/64/256, depth=4.

All three ancestors have [0,512); only the final scope changes. We validate
actual GGM prefix-cover count, not a count of textual intervals. No input or
result is imported from the depth/quota experiments.
"""
from .runtime import Task, parser, run_case


def selected(count):
    length = 256 // count
    return [i for j in range(count) for i in range(2*j*length, (2*j+1)*length)]


def execute(run, cfg):
    from gredac.crypto import cover, domain_for
    from experiments.support import write_json
    slots = selected(cfg['cover'])
    prefixes = cover(domain_for(['query'], slots))
    assert len(set(slots)) == 256 and len(prefixes) == cfg['cover']
    write_json(run.out / 'selected_scope.json', dict(slots=slots, prefixes=prefixes,
        slot_bits=15, depth=4, issued=32768))
    task = Task(run, cfg, ['A1', 'A2', 'A3', 'A4', 'S1'], cfg['issued'])
    parent = 'O'
    for child in ('A1', 'A2', 'A3'):
        task.handoff(parent, child, list(range(512)))
        parent = child
    task.handoff('A3', 'A4', slots)
    task.conversation(9, slots)
    return task


if __name__ == '__main__':
    run_case(parser(__doc__).parse_args(), execute)
