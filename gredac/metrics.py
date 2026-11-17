"""Read-only Linux per-process counters, not estimates of network latency."""
import os,time
from pathlib import Path

def process_snapshot(pid=None):
    pid=os.getpid() if pid is None else pid;p=Path('/proc')/str(pid)
    try:
        stat=(p/'stat').read_text().rpartition(')')[2].split();hz=os.sysconf('SC_CLK_TCK')
        status={k:v.strip() for k,v in (line.split(':',1) for line in (p/'status').read_text().splitlines())}
        io={k:int(v) for k,v in (line.split(':',1) for line in (p/'io').read_text().splitlines())}
        return dict(pid=pid,time=time.monotonic(),cpu_user_seconds=int(stat[11])/hz,cpu_system_seconds=int(stat[12])/hz,
            rss_kib=int(status.get('VmRSS','0 kB').split()[0]),max_rss_kib=int(status.get('VmHWM','0 kB').split()[0]),
            voluntary_context_switches=int(status['voluntary_ctxt_switches']),involuntary_context_switches=int(status['nonvoluntary_ctxt_switches']),
            io=io,scope='Linux process counters; read/write_bytes are storage bytes, rchar/wchar include cached and IPC I/O')
    except (FileNotFoundError,ProcessLookupError):return dict(pid=pid,time=time.monotonic(),exited=True)
