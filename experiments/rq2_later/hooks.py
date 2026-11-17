"""One additional observational span; no new RPC, message or protocol step.

The validated step-1 hooks and conversation loop are reused unchanged. This
package only times Node.reserve to distinguish contact from first consumption.
Its process target is installed only by the step-2/3 driver, never globally
persisted or imported by the first-group suite.
"""
import os
from experiments.rq2_v2 import timing, gredac_hooks


def install():
    from experiments.network_actor import Node
    gredac_hooks.install()
    timing.wrap(Node, 'reserve', 'contact.establish')


def process_main(name, directory, path, pipe):
    from experiments.network_actor import process_main as original
    timing.start(os.environ['RQ2_TIMING_DIR'], 'GReDAC', name, os.environ['RQ2_RUN_ID'])
    install()
    try:
        original(name, directory, path, pipe)
    finally:
        timing.TRACE.flush()


def enable_driver(trace):
    import experiments.network_actor as actor
    install()
    actor.process_main = process_main
