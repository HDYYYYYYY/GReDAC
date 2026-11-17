"""Step 3b: 64/256/1024/4096 allowed units, fixed depth=4, cover=1.

Root issuance remains 32768. Only delegated scope size changes; nine requests
exercise the actual first-use and hot paths, not a throughput experiment.
"""
from .runtime import Task, parser, run_case


def execute(run, cfg):
    from gredac.crypto import cover, domain_for
    slots = list(range(cfg['units']))
    assert cfg['requests'] == 9 and len(cover(domain_for(['query'], slots))) == 1
    task = Task(run, cfg, ['A1', 'A2', 'A3', 'A4', 'S1'], cfg['issued'])
    parent = 'O'
    for child in ('A1', 'A2', 'A3', 'A4'):
        task.handoff(parent, child, slots)
        parent = child
    task.conversation(9, slots)
    return task


if __name__ == '__main__':
    run_case(parser(__doc__).parse_args(), execute)
