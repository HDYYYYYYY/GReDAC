"""Shared lifecycle and evidence collection, not an experiment's workload.

Only Authority/B are provisioned before infrastructure_ready. Authenticated
users are an explicitly measured prerequisite. O/R are prepared at task start;
S1 and each caller child are created by the validated dynamic-member adapter
at the actual grant/transfer point, including key/CSR, process/port and route
publication costs. Private state stays in its owner process.
"""
import hashlib
import json
import os
import shutil
import traceback
from pathlib import Path
from experiments.rq2_v2 import timing, gredac_hooks
from experiments.rq2_v2.common import Resources, configure, parser
from experiments.rq2_v2.gredac_adapter import Adapter

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parents[1]


class Task:
    live = []

    def __init__(self, run, cfg, names, issued):
        self.live.append(self)
        self.backend = None
        trace = timing.TRACE
        from .hooks import enable_driver
        gredac_hooks.enable_driver = enable_driver
        # In the existing adapter, block='flow' selects roots-only preparation
        # and dynamic identities. It changes no protocol or workload. Actual
        # experiment labels/parameters remain cfg in manifests and summaries.
        self.backend = Adapter(run, dict(cfg, block='flow'))
        self.backend.infrastructure()
        trace.event('infrastructure_ready')
        trace.event('user_prerequisites_begin')
        with trace.span('user_prerequisites', 'prerequisite', display_phase=True):
            self.backend.users(names)
        trace.event('user_prerequisites_ready')
        trace.event('task_participant_prepare_begin')
        with trace.span('participant_preparation', 'identity', display_phase=True):
            self.backend.identities(names)
        trace.event('task_authorization_or_handoff_begin')
        self.backend.setup(issued)

    def handoff(self, parent, child, slots):
        return self.backend.handoff(parent, child, slots)

    def conversation(self, count, slots):
        timing.TRACE.event('task_preparation_complete')
        self.backend.conversation(0, count, slots)

    def finish(self):
        self.backend.finish()
        # Post-task observations call existing public diagnostic interfaces;
        # the driver never reads a live participant DB to decide an action.
        self.backend.audit_close()


def run_case(args, execute):
    from experiments.support import Run, write_json
    from .suite import fingerprint
    configure()
    cfg = json.loads(args.case_json)
    assert cfg['method'] == 'GReDAC' and cfg['identity'] == 'roots-dynamic'
    args.repeats, args.slot_bits = 1, 15
    run = Run(args, 'rq2_later_' + cfg.get('axis', cfg['block']))
    frozen = fingerprint()
    # Copy all reused protocol/measurement code and new scripts into each run.
    # This is outside task timing; no dependence on any prior experiment output.
    for rel in frozen:
        dst = run.out / 'source' / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, dst)
    run.manifest.update(source_sha256=frozen,
        code_fingerprint=hashlib.sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest(),
        case=cfg, rq2_method='GReDAC', driver_revision='rq2-later-1',
        infrastructure_timed=False, per_request_controller_roundtrip=False,
        measurement_scope='independent processes / real loopback TCP/TLS / WAL FULL; no WAN or LLM')
    os.environ['RQ2_TIMING_DIR'] = str(run.out / 'timing')
    os.environ['RQ2_RUN_ID'] = run.out.name
    trace = timing.start(run.out / 'timing', 'GReDAC', 'Driver', run.out.name)
    monitor = Resources(run.out)
    try:
        task = execute(run, cfg)
        task.finish()
        trace.flush()
        monitor.close()
        from .results import summarize
        result = summarize(run.out, cfg)
        result['repeat'] = args.repeat_index
        run.finish([result])
    except BaseException as exc:
        for task in Task.live:
            if task.backend:
                try:
                    task.backend.cleanup()
                except Exception:
                    pass
        from experiments.network_client import Mesh
        for mesh in Mesh.live:
            if not mesh.closed:
                try:
                    mesh.close()
                except Exception:
                    pass
        trace.flush()
        monitor.close()
        run.save_samples()
        run.manifest.update(status='FAIL', error=repr(exc), traceback=traceback.format_exc())
        write_json(run.out / 'manifest.json', run.manifest)
        raise
