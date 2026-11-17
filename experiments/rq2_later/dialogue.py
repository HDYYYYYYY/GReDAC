"""Step 2: fixed 2048-unit grant, one contact and N consecutive real requests.

Each invocation has new identities, actor processes, databases and results.
N changes only business request count, never the granted capability or contact
scope. N=1 has no hot request: its hot metrics are N/A, not zero milliseconds.
"""
from .runtime import Task, parser, run_case


def execute(run, cfg):
    assert cfg['issued'] == cfg['units'] == 2048
    assert cfg['requests'] in (1, 8, 32, 128, 512, 2048)
    slots = list(range(2048))
    task = Task(run, cfg, ['A1', 'S1'], 2048)
    task.handoff('O', 'A1', slots)
    task.conversation(cfg['requests'], slots)
    return task


if __name__ == '__main__':
    run_case(parser(__doc__).parse_args(), execute)
