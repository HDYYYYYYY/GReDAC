"""One fresh task, using the unchanged existing dialogue workload/client."""
if __name__=='__main__':
    import json,os
    from pathlib import Path
    from experiments.rq2_later import hooks
    from .wait_hooks import enable_driver
    hooks.enable_driver=enable_driver
    from experiments.rq2_later.dialogue import execute
    from experiments.rq2_later.runtime import parser,run_case
    args=parser(__doc__).parse_args()
    try:run_case(args,execute)
    finally:
        # Only NEW output metadata is labeled; protocol/source/history files
        # are untouched. A copied per-run summary must not masquerade as an
        # undelayed measurement when separated from the batch manifest.
        injected=os.environ.get('RQ2_RTT_ENABLED')=='1'
        scope='Measured loopback TCP/TLS with sampled artificial RTT waits; NOT real WAN' if injected else 'Measured loopback TCP/TLS, no injected RTT'
        for name in ('manifest.json','summary.json'):
            path=Path(args.out)/name
            if path.exists():
                record=json.loads(path.read_text());record.update(measurement_scope=scope,injected_rtt_wait=injected)
                for result in record.get('results',[]):result.update(measurement_scope=scope,injected_rtt_wait=injected)
                path.write_text(json.dumps(record,indent=2)+'\n')
