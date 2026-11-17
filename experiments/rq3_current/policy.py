"""Frozen, arm-independent retry policy. No task replacement or answer repair."""
CAPS=dict(travel=80,academic=120,calendar=120)
TOKENS=dict(travel=2048,academic=6144,calendar=16384)
ROUNDS=6
RETRY=dict(max_action_attempts=5,max_transient_retries=2,backoff_seconds=[1,2])
LABEL='同一测试集上的当前实现与有界重试复测；非新独立测试集'


def fingerprint():
    import hashlib
    from pathlib import Path
    from experiments.evaluation_batch import hashes,ROOT
    result=hashes()
    for base in (Path(__file__).parent,ROOT/'docs/rq3-current'):
        for path in base.rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix in ('.py','.json','.sh'):
                result[path.relative_to(ROOT).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(sorted(result.items()))


def settings(model,inputs):
    from experiments.rq3_retest import settings as old_settings
    value=old_settings(model,inputs,['travel','academic','calendar'],True)
    import sys,platform,sqlite3,ssl,cryptography
    value['runtime_environment']=dict(python=sys.executable,version=platform.python_version(),platform=platform.platform(),
        sqlite=sqlite3.sqlite_version,openssl=ssl.OPENSSL_VERSION,cryptography=cryptography.__version__)
    value.update(label=LABEL,caps=CAPS,max_tokens=TOKENS,retry=RETRY,
        max_academic_revisions=ROUNDS,max_calendar_rounds_per_phase=ROUNDS,format_extra_attempts=4,
        source_sha256=fingerprint(),max_tokens_calendar_reason='user doubled calendar output budget from 8192 to 16384 after r3 truncation',
        calendar_reasoning_policy='concise by prompt; required string; no character-count rejection or truncation',
        retry_scope='LLM generation only; no protocol RPC retry, entire-task replay, answer filling or replacement')
    for prompt in value['prompts']['calendar']:
        value['prompts']['calendar'][prompt]+=(' Keep explanations concise. When proposing, supply exactly six meeting entries '
            'and a concise reasoning string. Do not narrate search, backtracking or draft alternatives. '
            'Use the checker and actual partner feedback to revise; do not automatically agree.')
    return value
