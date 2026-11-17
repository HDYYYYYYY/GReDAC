"""Serial Linux correctness regressions; no LLM or performance batch.

Use a pristine source checkout and a new output directory. Optional A2A and
proof replays have their own dependencies and instructions.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    'experiments.rq2_v2.regression', 'experiments.rq2_v2.optimization_regression',
    'experiments.rq2_later.regression', 'experiments.allocation_policy.regression',
    'experiments.allocation_policy_v2.regression', 'experiments.gredac_regression',
    'experiments.alignment_regression', 'experiments.rq4_config_regression',
    'experiments.rq4_shared_setup_regression', 'experiments.rq4_regression',
    'experiments.rq3_current.regression',
)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--check-only', action='store_true')
    a = p.parse_args()
    out = a.out.resolve()
    commands = [
        ('integrity', ['tools/check_release.py']),
        ('core', ['-m', 'gredac', 'self-test', '--out', str(out/'core')]),
        ('rtt_offline', ['-m', 'studies.rq2_rtt.test_offline']),
    ]
    commands.extend((m, ['-m', m, '--out', str(out/m)]) for m in MODULES)
    if a.check_only:
        print(json.dumps(dict(commands=commands, llm_calls=0, formal_experiments=0), indent=2))
        return
    if not sys.platform.startswith('linux'):
        p.error('Use Linux/WSL; network regressions need Linux process/resource interfaces.')
    out.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', GREDAC_OFFLINE_REGRESSION='1')
    for key in list(env):
        if 'API_KEY' in key or key.startswith('DEEPSEEK'):
            env.pop(key)
    report = dict(scope='correctness only; not performance', python=sys.version,
                  llm_calls=0, formal_experiments=0, results=[])
    for name, args in commands:
        started = time.monotonic()
        log = out/(name+'.log')
        print('START', name, flush=True)
        with log.open('w') as f:
            proc = subprocess.run([sys.executable, *args], cwd=ROOT, env=env,
                                  stdout=f, stderr=subprocess.STDOUT)
        report['results'].append(dict(name=name, exitcode=proc.returncode, log=log.name,
                                      seconds=time.monotonic()-started))
        report['status'] = 'FAIL' if any(r['exitcode'] for r in report['results']) else 'PASS'
        (out/'validation.json').write_text(json.dumps(report, indent=2)+'\n')
        print('PASS' if proc.returncode == 0 else 'FAIL', name, flush=True)
        if proc.returncode:
            print(log.read_text()[-4000:])
    raise SystemExit(0 if report['status'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
