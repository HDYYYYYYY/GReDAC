"""Step 3a: transfer depth 1/2/4/8/16; fixed final query x [0,256).

All caller layers receive that same scope; only the final child contacts the
service. Root issuance=32768, slot encoding=15 bits, service chain=one layer.
Identity creation, each real transfer and full-chain synchronization are timed.
"""
from .runtime import Task, parser, run_case


def execute(run, cfg):
    from gredac.crypto import cover, domain_for
    slots = list(range(256))
    assert cfg['requests'] == 9 and len(cover(domain_for(['query'], slots))) == 1
    names = [f'A{i}' for i in range(1, cfg['depth'] + 1)]
    task = Task(run, cfg, names + ['S1'], cfg['issued'])
    parent = 'O'
    for child in names:
        task.handoff(parent, child, slots)
        parent = child
    task.conversation(9, slots)
    return task


if __name__ == '__main__':
    run_case(parser(__doc__).parse_args(), execute)
