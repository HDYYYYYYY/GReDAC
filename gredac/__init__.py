"""GReDAC research prototype."""
import hashlib
from pathlib import Path

__version__ = '0.5.3'


def source_manifest():
    root = Path(__file__).resolve().parent
    return {'gredac/'+p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.glob('*.py'))}
