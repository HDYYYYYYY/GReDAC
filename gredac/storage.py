"""Durable local records; adapted from the v2 prototype, no external imports."""
import copy
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from .crypto import canonical, require

class Clock:
    def __init__(self):
        self.t = 1000.0

    def now(self):
        return self.t

    def advance(self, seconds):
        require(seconds >= 0, 'CLOCK_BACKWARDS')
        self.t += seconds


class MonotonicClock:
    """Single-host physical time; never advanced by a driver."""
    def now(self):
        return time.monotonic()


class Store:
    """Small JSON-record SQLite store; one durable transaction per operation."""
    def __init__(self, path, transaction_observer=None):
        self.path = Path(path)
        self.transaction_observer = transaction_observer
        # Optional experiment-only crash point; unset on every normal run.
        self.commit_hook = None
        self.lock = threading.RLock()
        self.local=threading.local()
        self.open()

    def open(self):
        self.db = sqlite3.connect(self.path, isolation_level=None,
                                  check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS records (
            kind TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
            PRIMARY KEY(kind,key));
          CREATE TABLE IF NOT EXISTS events (
            seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL);
        ''')

    @contextmanager
    def transaction(self):
        observer = self.transaction_observer
        start = time.perf_counter_ns()
        with self.lock:
            acquired = time.perf_counter_ns()
            self.db.execute('BEGIN IMMEDIATE')
            begun = time.perf_counter_ns();before_commit=begun
            trace=dict(txid=uuid.uuid4().hex,store=self.path.name,thread=threading.get_ident(),start_ns=start)
            self.local.transaction=trace
            # Valid only under this transaction's lock/snapshot. Never share
            # state across processes or retain an authorization decision.
            self.local.reads={}
            committed = False
            try:
                yield trace
                if self.commit_hook:
                    self.commit_hook('before_commit')
                if '_deadline_clock' in trace:
                    now=trace['_deadline_clock'].now();trace['final_check_time']=now
                    require(now+trace['assumed_clock_error_seconds']+trace['assumed_commit_delay_seconds']<trace['deadline'],'FINAL_DEADLINE_CHECK')
                    trace['final_check_monotonic']=time.monotonic()
                if self.commit_hook:self.commit_hook('after_final_check')
                before_commit=time.perf_counter_ns();trace['sql_commit_start_monotonic']=time.monotonic()
                self.db.execute('COMMIT')
                committed = True
                trace['sql_commit_return_monotonic']=time.monotonic()
                if '_deadline_clock' in trace:
                    trace['observed_check_to_commit_seconds']=trace['sql_commit_return_monotonic']-trace['final_check_monotonic']
                    trace['assumed_delay_bound_held']=trace['observed_check_to_commit_seconds']<=trace['assumed_commit_delay_seconds']
                    trace['durable_before_deadline_observed']=(trace['sql_commit_return_monotonic']+trace['assumed_clock_error_seconds']<trace['deadline']) if trace['clock_scope']=='single-host-monotonic' else None
                if self.commit_hook:
                    self.commit_hook('after_commit')
            except BaseException:
                if not committed:
                    self.db.execute('ROLLBACK')
                raise
            finally:
                self.local.transaction=None
                self.local.reads=None
                if observer:
                    ended = time.perf_counter_ns()
                    observer({**{k:v for k,v in trace.items() if not k.startswith('_')},
                              'start_ns': start, 'end_ns': ended, 'committed': committed,
                              'lock_wait_ns': acquired-start, 'begin_ns': begun-acquired,
                              'body_ns': before_commit-begun, 'commit_or_rollback_ns': ended-before_commit})

    def guard_deadline(self,deadline,clock,delay_bound,clock_error=0.):
        """Record the strictest checked bound for a final pre-COMMIT recheck.

        The SQL return time is an observed upper bound on durable completion,
        not an in-transaction timestamp pretending to be the actual commit.
        A crash can leave committed state with no timing observation.
        """
        trace=getattr(self.local,'transaction',None)
        if trace is None:return
        trace.update(deadline=min(trace.get('deadline',deadline),deadline),_deadline_clock=clock,
            assumed_commit_delay_seconds=float(delay_bound),assumed_clock_error_seconds=float(clock_error),
            clock_scope='single-host-monotonic' if isinstance(clock,MonotonicClock) else 'logical-test-clock')

    def get(self, kind, key, default=None):
        with self.lock:
            # Cache frequently reread metadata, not large one-pass unit rows.
            cache=getattr(self.local,'reads',None) if kind in (
                'rights','contexts','revoked','registrations','sources') else None
            lookup=(kind,str(key))
            if cache is not None and lookup in cache:
                found,value=cache[lookup]
                return copy.deepcopy(value if found else default)
            row = self.db.execute('SELECT value FROM records WHERE kind=? AND key=?',
                                  (kind, str(key))).fetchone()
            value=json.loads(row[0]) if row else None
            if cache is not None:
                cache[lookup]=(row is not None,value)
                # Callers may mutate their result before put(). Such changes
                # must not become visible through another get() implicitly.
                return copy.deepcopy(value if row else default)
            return value if row else copy.deepcopy(default)

    def put(self, kind, key, value):
        with self.lock:
            self.db.execute('INSERT INTO records VALUES (?,?,?) '
                            'ON CONFLICT(kind,key) DO UPDATE SET value=excluded.value',
                            (kind, str(key), canonical(value).decode()))
            cache=getattr(self.local,'reads',None)
            if cache is not None:cache.pop((kind,str(key)),None)

    def all(self, kind):
        with self.lock:
            rows = self.db.execute('SELECT key,value FROM records WHERE kind=? ORDER BY key',
                                    (kind,)).fetchall()
        return {k: json.loads(v) for k, v in rows}

    def event(self, kind, value):
        with self.lock:
            self.db.execute('INSERT INTO events(kind,value) VALUES (?,?)',
                            (kind, canonical(value).decode()))

    def close(self):
        self.db.close()


def position_key(source, slot):
    return canonical([source, slot]).decode()


