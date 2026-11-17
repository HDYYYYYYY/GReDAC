"""GReDAC deterministic demo: real cryptography and in-memory TLS records."""
import argparse
import json
import sys
from pathlib import Path
from .crypto import MODES, Denied, require
from .scenarios import demo
from .verify import verify_run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    run = sub.add_parser('demo')
    run.add_argument('--mode', choices=(*MODES, 'all'), default='all')
    run.add_argument('--scenario', choices=('bilateral', 'multitask', 'all'), default='all')
    run.add_argument('--out', type=Path, required=True)
    test = sub.add_parser('self-test')
    test.add_argument('--out', type=Path, required=True)
    verify = sub.add_parser('verify')
    verify.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.command == 'verify':
        paths = sorted(args.directory.rglob('manifest.json'))
        require(paths, 'NO_SAVED_RUNS')
        results = [verify_run(p.parent) for p in paths]
        print(json.dumps({'status': 'PASS', 'verified_runs': len(results),
                          'oracle_checks': sum(r['oracle_checks'] for r in results), 'results': results}, indent=2))
        return
    require(not args.out.exists(), 'OUTPUT_ALREADY_EXISTS')
    args.out.mkdir(parents=True)
    if args.command == 'self-test':
        from .tests import self_test
        report = self_test(args.out)
    else:
        results = []
        for mode in MODES if args.mode == 'all' else (args.mode,):
            for scenario in ('bilateral', 'multitask') if args.scenario == 'all' else (args.scenario,):
                result = demo(args.out/mode/scenario, mode, scenario)
                results.append(result)
                print('PASS', mode, scenario, {s: b['spent'] for s, b in result['sources'].items()})
        report = {'status': 'PASS', 'runs': len(results), 'results': results}
    (args.out/'summary.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('Evidence:', args.out.resolve())


if __name__ == '__main__':
    try:
        main()
    except (Denied, AssertionError) as error:
        print('FAIL:', error, file=sys.stderr)
        sys.exit(1)
