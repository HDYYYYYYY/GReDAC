"""Check only the algebraic VCs in CRYPTO_PROOF.md, not the RO proof.

Uses a supplied Z3 binary, or the executable on PATH.
Generated inputs and evidence are written only alongside this script.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import os
import shutil

HERE = Path(__file__).resolve().parent
VERIFICATION = HERE.parents[1]

DECLARATIONS = """(set-option :timeout 20000)
(set-logic QF_NRA)
(declare-const Q Real)
(declare-const T Real)
(declare-const V Real)
(declare-const D Real)
(assert (>= Q 0))
(assert (>= T 0))
(assert (>= V 0))
(define-fun N () Real (+ Q T))
(define-fun B () Real (+ Q T V 2))
"""

VCS = {
    "denominator": """; D > 16 B^2 implies D - 4 B > D/2.
(assert (> D (* 16 B B)))
(assert (not (> (- D (* 4 B)) (/ D 2))))
(check-sat)
""",
    "union_numerator": """; Deliberately loose joint bad-event union bound.
(assert (not (<= (+ (* N N) (* 2 Q T) (* 2 T (+ V 2))) (* 16 B B))))
(check-sat)
""",
    "exclusion_budget": """; Samples + oracle candidates + terminal guesses <= 4B.
(assert (not (<= (+ N Q V 2) (* 4 B))))
(check-sat)
""",
    "trivial_branch": """; In the other branch the advertised bound is at least 1.
(assert (> D 0))
(assert (<= D (* 16 B B)))
(assert (not (>= (/ (* 16 B B) D) 1)))
(check-sat)
""",
}


def run() -> None:
    parser = argparse.ArgumentParser()
    local = VERIFICATION/"tamarin-v3"/".deps"/"bin"/"z3.exe"
    default = os.environ.get('GREDAC_Z3',str(local) if local.is_file() else (shutil.which('z3') or 'z3'))
    parser.add_argument("--z3", type=Path, default=Path(default))
    args = parser.parse_args()
    binary = args.z3.resolve()
    if not binary.is_file():
        raise SystemExit(f"Z3 binary not found: {binary}; pass --z3 explicitly")
    version = subprocess.check_output([str(binary), "-version"], text=True).strip()
    results = []
    for name, body in VCS.items():
        path = HERE/f"bound_{name}.smt2"
        path.write_text(DECLARATIONS+body, encoding="utf-8")
        start = time.monotonic()
        check = subprocess.run([str(binary), "-smt2", str(path)], capture_output=True,
                               text=True, timeout=30, check=False)
        outcome = check.stdout.strip()
        results.append({"name":name,"expected":"unsat","actual":outcome,
                        "returncode":check.returncode,"stderr":check.stderr.strip(),
                        "seconds":round(time.monotonic()-start,6),
                        "input_sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
    evidence = {"status":"passed" if all(r["actual"]=="unsat" and r["returncode"]==0
                for r in results) else "failed", "solver":version,
                "solver_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),
                "kind":"algebraic verification conditions only",
                "does_not_mechanize_random_oracle_game":True,
                "script_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "results":results}
    (HERE/"BOUND_RESULTS.json").write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(evidence,indent=2))
    if evidence["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    run()
