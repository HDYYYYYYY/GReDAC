"""公共测量工具，不包含任何一组实验的业务调度。

matrix把一个参数点×一次重复放入全新Python进程，按固定种子打乱执行顺序；
Run负责物理计时、phase标记、源码/环境留档。跨实验不共享输入或结果。
"""
import argparse
import hashlib
import json
import os
import platform
import resource
import shutil
import sqlite3
import ssl
import statistics
import threading
import time
import random
import subprocess
import sys
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path


def parser(description):
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--out', required=True)
    p.add_argument('--repeats', type=int, default=5, help='每参数点的新进程重复次数')
    p.add_argument('--slot-bits', type=int, default=12)
    p.add_argument('--order-seed', type=int, default=43101, help='参数执行顺序的固定种子')
    p.add_argument('--case-json', help=argparse.SUPPRESS)
    p.add_argument('--repeat-index', type=int, default=0, help=argparse.SUPPRESS)
    return p


def matrix(args, module, cases, execute):
    """独立子进程重复；失败保留样本并停止，不自动改变条件重试。"""
    if args.case_json:
        run = Run(args, module.rsplit('.', 1)[-1])
        try:
            result = execute(run, args, json.loads(args.case_json), args.repeat_index)
            run.finish([result])
        except BaseException:
            run.save_samples()
            run.manifest.update(status='FAIL', traceback=traceback.format_exc())
            write_json(run.out/'manifest.json', run.manifest)
            raise
        return
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    jobs = [(c, rep) for c in cases for rep in range(args.repeats)]
    random.Random(args.order_seed).shuffle(jobs)
    write_json(out/'plan.json', {'module':module, 'config':vars(args), 'jobs':jobs,
                               'repeat_unit':'new Python process and new database'})
    manifest = {'status':'RUNNING','module':module,'system':'joint','llm_api_calls':0,
                'started_utc':datetime.now(timezone.utc).isoformat(), 'config':vars(args)}
    write_json(out/'manifest.json',manifest)
    results = []
    started = time.monotonic()
    for index,(case,rep) in enumerate(jobs):
        dest = out/f'run-{index:03d}'
        argv = sys.argv[1:].copy()
        argv[argv.index('--out')+1] = str(dest)
        command = [sys.executable,'-m',module,*argv,'--case-json',json.dumps(case),
                   '--repeat-index',str(rep)]
        print(f'START {index+1}/{len(jobs)} {case} repeat={rep}',flush=True)
        with (out/f'run-{index:03d}.log').open('w') as log:
            process = subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
        if process.returncode:
            manifest.update(status='FAIL',failed_run=dest.name)
            write_json(out/'manifest.json',manifest)
            raise RuntimeError(f'{dest} failed; inspect its log, original evidence retained')
        summary = json.loads((dest/'summary.json').read_text())
        results.extend({**r,'run_directory':dest.name} for r in summary['results'])
        write_json(out/'summary.json',{'results':results,'wall_seconds':time.monotonic()-started})
        print(f'PASS {index+1}/{len(jobs)} {dest.name}',flush=True)
    manifest.update(status='PASS',ended_utc=datetime.now(timezone.utc).isoformat(),runs=len(results))
    write_json(out/'manifest.json',manifest)


def numbers(text, cast=int):
    return [cast(v) for v in text.split(',')]


def stats(values):
    values = sorted(values)
    if not values:
        return {'n': 0}
    def q(p):
        i = (len(values)-1)*p
        lo = int(i)
        return values[lo] + (values[min(lo+1,len(values)-1)]-values[lo])*(i-lo)
    return {'n': len(values), 'mean': statistics.mean(values), 'median': q(.5),
            'p95': q(.95), 'p99': q(.99), 'min': values[0], 'max': values[-1]}


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')


class Run:
    def __init__(self, args, experiment):
        # Pre-GReDAC end-to-end drivers encode a different protocol and used
        # direct/MemoryBIO calls. Keep their source for provenance, but never
        # silently emit new local samples under the network version. Local
        # correctness regressions remain runnable; active RQ2-4 and scene
        # runners install the common network adapter below their public API.
        retired = {'operations','dialogue','tasks','throughput','scalability',
            'fault_tolerance','control_faults','team_isolation','thinktime',
            'empirical_scale','empirical_control','empirical_crashes','empirical_isolation',
            'v31_operations','v31_dialogue','v31_tasks','v31_throughput',
            'v31_scalability','v31_crashes','v31_control','v31_thinktime',
            'v31_empirical_scale','v31_empirical_isolation','travel_llm','travel_paired'}
        if experiment in retired:
            raise RuntimeError('Retired local end-to-end driver: '+experiment+
                '. Use current rq2_*, rq3_retest, rq4_* TCP/TLS entries; '
                'historical reproduction requires the preserved 0.4.0 source snapshot.')
        assert args.repeats > 0 and 1 <= args.slot_bits <= 24
        os.environ['GREDAC_SLOT_BITS'] = str(args.slot_bits)
        from gredac import __version__
        self.out = Path(args.out).resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        self.local, self.lock = threading.local(), threading.Lock()
        self.samples = []
        self.start_ns, self.cpu_start = time.perf_counter_ns(), time.process_time_ns()
        root = Path(__file__).resolve().parents[1]
        files = sorted(list((root/'gredac').glob('*.py')) + list((root/'experiments').glob('*.py'))+
            list((root/'experiments/data').glob('*.json'))+[root/'pyproject.toml']+
            [p for p in (root/'vendor').rglob('*') if p.is_file() and '.git' not in p.parts
             and (p.suffix in ('.c','.h','.so','.json') or p.name in ('LICENSE','README.md','Makefile'))])
        hashes = {}
        for path in files:
            rel = path.relative_to(root)
            hashes[str(rel)] = hashlib.sha256(path.read_bytes()).hexdigest()
            dest = self.out/'source'/rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
        self.manifest = {'experiment': experiment, 'config': vars(args), 'system': 'joint', 'code_version': __version__,
            'started_utc': datetime.now(timezone.utc).isoformat(),
            'source_sha256': hashes,
            'code_fingerprint': hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(),
            'git': 'project has no Git repository; exact source snapshot and SHA256 supplied',
            'environment': {'python': platform.python_version(), 'platform': platform.platform(),
                'hostname': platform.node(), 'python_executable': sys.executable,
                'sqlite': sqlite3.sqlite_version, 'cryptography': version('cryptography'),
                'openssl': ssl.OPENSSL_VERSION, 'cpu_count': os.cpu_count(),
                'cpu_model': next((l.split(':',1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines()
                                   if l.startswith('model name')), 'unknown'),
                'clock': vars(time.get_clock_info('monotonic')),
                'pid':os.getpid(), 'load_average':os.getloadavg(),
                'affinity':sorted(os.sched_getaffinity(0)),
                'nofile_limits':resource.getrlimit(resource.RLIMIT_NOFILE),
                # 运行平台可为WSL或服务器；真实挂载/磁盘信息由运行前环境清单记录。
                'storage': 'SQLite WAL, synchronous=FULL', 'storage_path': str(self.out)},
            'measurement': 'actual local measurements, no estimated network results',
            'transport': 'local regression/microbenchmark unless overridden by the TCP/TLS adapter; not network performance',
            'lease_clock': 'time.monotonic physical clock',
            'llm_api_calls': 0, 'status': 'RUNNING'}
        write_json(self.out/'manifest.json', self.manifest)

    def measure(self, case, label, fn, **metadata):
        previous = getattr(self.local, 'span', None)
        with self.lock:
            sid = len(self.samples)
            row = {'id': sid, 'case': case, 'label': label,
                   'phase':getattr(self.local,'phase','setup'), **metadata}
            self.samples.append(row)
        self.local.span = row
        start, cpu = time.perf_counter_ns(), time.thread_time_ns()
        row['start_ns'] = start
        try:
            value = fn()
            row['status'] = 'ok'
            return value
        except BaseException as exc:
            row['status'], row['error'] = 'error', str(exc)
            raise
        finally:
            end = time.perf_counter_ns()
            row.update(end_ns=end, wall_ns=end-start, thread_cpu_ns=time.thread_time_ns()-cpu)
            self.local.span = previous

    @contextmanager
    def phase(self, name):
        """线程局部阶段标签，不改变协议语义和计时起止。"""
        old = getattr(self.local,'phase','setup')
        self.local.phase = name
        try:
            yield
        finally:
            self.local.phase = old

    def save_samples(self):
        with (self.out/'samples.jsonl').open('w') as f:
            for row in self.samples:
                f.write(json.dumps(row)+'\n')

    def finish(self, results):
        by_label = {}
        for row in self.samples:
            by_label.setdefault(row['label'], []).append(row['wall_ns']/1e6)
        self.save_samples()
        processes={};resource_files=[]
        for path in self.out.rglob('process_resources.json'):
            resource_files.append(str(path.relative_to(self.out)))
            for sample in json.loads(path.read_text())['samples']:
                for role,row in sample['roles'].items():
                    if not row.get('exited') and sample['time']>=processes.get(row['pid'],{}).get('sample_time',-1):
                        processes[row['pid']]={**row,'role':role,'sample_time':sample['time']}
        accounting=dict(files=resource_files,processes=processes,
            sampled_lifetime_cpu_seconds=sum(p['cpu_user_seconds']+p['cpu_system_seconds'] for p in processes.values()),
            sampled_storage_read_bytes=sum(p['io']['read_bytes'] for p in processes.values()),
            sampled_storage_write_bytes=sum(p['io']['write_bytes'] for p in processes.values()),
            sum_process_high_water_rss_kib=sum(p['max_rss_kib'] for p in processes.values()),
            scope='unique participant/driver PIDs; cumulative sampled counters, exited-PID gaps are lower bounds; RSS is a sum of observed non-simultaneous high-water marks, not measured total peak; crash gaps remain unknown')
        write_json(self.out/'resource_accounting.json',accounting)
        write_json(self.out/'summary.json', {'results': results,
            'operation_wall_ms': {k:stats(v) for k,v in by_label.items()},
            'wall_seconds': (time.perf_counter_ns()-self.start_ns)/1e9,
            'driver_cpu_seconds': (time.process_time_ns()-self.cpu_start)/1e9,
            'driver_max_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'multiprocess_resources':'resource_accounting.json; per-role process_resources.json'})
        self.manifest.update(status='PASS', ended_utc=datetime.now(timezone.utc).isoformat())
        write_json(self.out/'manifest.json', self.manifest)
        print(json.dumps({'status':'PASS','out':str(self.out),'cases':len(results)}), flush=True)


def until(deadline):
    remaining = deadline-time.monotonic()
    if remaining > 0:
        time.sleep(remaining)
