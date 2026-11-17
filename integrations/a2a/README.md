# Optional A2A integration

This is the existing independent A2A branch, supplied as its actual bridge sources and the small `MINIMAL_CORE.patch`. It uses a synchronous SDK `SendMessage`/`DataPart` path inside the existing authenticated protocol transport, with a local SDK service over a Unix-domain socket. It does **not** claim general external HTTP A2A interoperability, streaming, push notifications or a complete A2A Tasks implementation.

Create a separate tree; do not overlay the measured RQ2–RQ4 baseline in place:

```bash
python tools/prepare_a2a.py --out ../GReDAC-a2a
cd ../GReDAC-a2a
python3.12 -m venv .venv-a2a
.venv-a2a/bin/pip install -r integrations/a2a/requirements.lock
.venv-a2a/bin/python -m experiments.a2a_regression --out results/a2a-regression --slot-bits 15 --suites B1,B2,B3,B4 --schedule-seeds 101 --rounds 2
.venv-a2a/bin/python -m experiments.a2a_faults --out results/a2a-faults --slot-bits 15 --repeats 1
.venv-a2a/bin/python -m experiments.a2a_supplement --out results/a2a-supplement --slot-bits 15 --acceptance-root results/a2a-regression --schedule-seeds 101 --rounds 2
```

The copy tool verifies baseline file hashes and each patch context. It copies only manifest-listed release files, not private results or virtual environments. The materialized tree is labelled as the A2A variant; main-tree RQ2/RQ3/RQ4 freezes intentionally no longer authorize it.

These commands are bounded functional checks. For the original larger race exploration, explicitly use `--schedule-seeds 101,202,303 --rounds 20` and new output directories. The supplementary check reads the completed regression directory directly and checks all its expected R06 schedules; it does not require an old folder name or silently accept missing evidence.

`a2a_bench --print-plan --out results/a2a-bench` displays the optional performance plan without running it; `--execute` is an explicit separate action. Its before/after performance experiment was not part of the existing RQ2–RQ4 measurements. See `docs/FINAL_CHECK_ZH.md` for final functional validation, including the retained timeout of the larger QA run.

Historical validation reports for this branch covered functional boundary/lifecycle/workflow and fault schedules. The release package does not ship their full databases or reinterpret those checks as a new published benchmark. Source provenance and upstream versions are in `third_party/README.md` and `provenance/FILES.json`.
