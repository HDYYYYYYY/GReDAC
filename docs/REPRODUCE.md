# Reproduction entry points

Run from the repository root on Linux, with Python 3.12. Use fresh output directories for every invocation. Nothing below chains a pilot into a full batch. Run only one performance group at a time. No old validation result is shipped to bypass the fresh regression/pilot gates.

Our implementation package is `gredac`. `python -m gredac --help` displays the small deterministic-demo CLI; those in-memory TLS demos are not the TCP/TLS performance experiments below. SAGA appears separately only as the upstream comparator.

## Installation

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python tools/check_release.py
```

On Debian/Ubuntu, install the distribution's `python3.12-venv` package first if `venv` reports missing `ensurepip`. Experiment reproduction uses this **source checkout**, including data, manifests and scripts; a wheel installs only the `gredac` core library and demo CLI, not the experimental artifact.

Run the shared correctness checks without model/API calls or a full experiment:

```bash
.venv/bin/python tools/test_release.py --out results/release-regression --check-only
.venv/bin/python tools/test_release.py --out results/release-regression
```

The RQ3 regression uses an explicit offline test fixture. Its successful output is not evidence of new real-model task completion. Do not use it as a real-model pilot.

Use a separate environment for the author SAGA comparison and RQ2 dependencies:

```bash
python3.12 -m venv .venv-rq2
.venv-rq2/bin/pip install -r requirements-rq2.txt
# Install MongoDB separately, then use its actual executable path:
export RQ2_MONGOD="$(command -v mongod)"
test -n "$RQ2_MONGOD"
export GREDAC_COMMIT_DELAY_BOUND=0.05
```

MongoDB is required by native SAGA, not by GReDAC-only groups. Its binary version/hash is recorded in each comparator run. The author's Python archive is extracted and verified per run. Dependency installation is outside all measurement windows. The pinned files specify relevant Python packages; they do not recreate an identical kernel, CPU, storage or solver installation.

## RQ2: current three parts

Part 1: three separate flows; 128 units, 32 requests (16 + 16 for replacement); two methods and six independent repeats: **36 full attempts**. Native SAGA keeps its native operations, with missing security guarantees marked N/A. No MAGIQ comparison.

```bash
.venv-rq2/bin/python -m experiments.rq2_v2.suite --stage regression --group flow --out results/rq2-regression
.venv-rq2/bin/python -m experiments.rq2_v2.suite --stage pilot --group flow --regression-results results/rq2-regression --out results/rq2-flow-pilot
# After inspecting that pilot:
.venv-rq2/bin/python -m experiments.rq2_v2.suite --stage full --group flow --pilot-results results/rq2-flow-pilot --confirm-pilot-reviewed --out results/rq2-flow-full
```

Parts 2/3 are GReDAC-only. Dialogue: N = 1/8/32/128/512/2048, 2048 issued units, six repeats (**36**). Structure: depth 1/2/4/8/16, units 64/256/1024/4096, cover 1/4/16/64/256, six repeats and nine requests (**84**).

```bash
.venv-rq2/bin/python -m experiments.rq2_later.suite --stage regression --out results/rq2-later-regression
.venv-rq2/bin/python -m experiments.rq2_later.suite --stage pilot --group dialogue --regression-results results/rq2-later-regression --out results/rq2-dialogue-pilot
.venv-rq2/bin/python -m experiments.rq2_later.suite --stage full --group dialogue --pilot-results results/rq2-dialogue-pilot --confirm-pilot-reviewed --out results/rq2-dialogue-full
.venv-rq2/bin/python -m experiments.rq2_later.suite --stage pilot --group structure --regression-results results/rq2-later-regression --out results/rq2-structure-pilot
.venv-rq2/bin/python -m experiments.rq2_later.suite --stage full --group structure --pilot-results results/rq2-structure-pilot --confirm-pilot-reviewed --out results/rq2-structure-full
```

Each command is independent. `--check-only` can be added, but pilot/full gates still require matching prerequisite records; it does not fabricate them. Infrastructure is outside task time; required dynamic member preparation remains included. Real nested spans are retained without adding overlapping intervals.

Allocation v2 is an optional RQ2 extension: whole/fragmented background × 20 frozen random instances × three policies = **120**. All four delegation levels use the selected policy. The fragmented background executes real consume/revoke/recover operations.

```bash
.venv-rq2/bin/python -m experiments.allocation_policy_v2.suite --stage regression --out results/allocation-regression
.venv-rq2/bin/python -m experiments.allocation_policy_v2.suite --stage pilot --regression-results results/allocation-regression --out results/allocation-pilot
.venv-rq2/bin/python -m experiments.allocation_policy_v2.suite --stage full --pilot-results results/allocation-pilot --confirm-pilot-reviewed --out results/allocation-full
```

## RQ2: sampled geographic waits

This is loopback TCP/TLS plus explicitly recorded injected waits, **not a WAN deployment**. The West-US and Asia cases differ only in the Authority's assigned region. Both are measured with injected waits when run using these commands. Offline estimates remain labelled estimates.

```bash
.venv-rq2/bin/python -m studies.rq2_rtt.test_offline
.venv-rq2/bin/python -m studies.rq2_rtt.run_wait --profile distributed --enable-rtt --out results/rtt-west --check-only
.venv-rq2/bin/python -m studies.rq2_rtt.run_wait --profile distributed --enable-rtt --out results/rtt-west
.venv-rq2/bin/python -m studies.rq2_rtt.run_wait --profile authority_asia --enable-rtt --out results/rtt-asia
.venv-rq2/bin/python tools/plot_rtt.py --west results/rtt-west --asia results/rtt-asia --out results/rtt-plot
```

Each full profile has 36 independent tasks. The plotting helper needs only the two new measured batches; it never substitutes an estimate for a missing measured task. The original detailed diagnostic analysis is also retained under `studies/rq2_rtt/`; its `--estimate` input refers to an explicitly separate historical estimate dataset, not a hidden runtime dependency.

## RQ3: real model tasks

Current flow-only evaluation, **not a claim of business-answer correctness**. Travel, academic analysis and calendar coordination retain their prompts, tools, role changes and independent protocol checks. Formal inputs are the existing 25 instances per scene; any rerun is a same-test-set retest. Pilot: 15 pairs/30 tasks, cap 3200 API attempts. Full: 75 pairs/150 tasks, cap 16000. Calendar output budget is 16384 tokens; bounded corrections/retries count toward caps. Failures remain in the sample.

Supply `DEEPSEEK_API_KEY` through your environment, or `DEEPSEEK_CREDENTIAL_FILE` pointing outside the repository. Do not place a key in a command committed to source. The historical default model label is `deepseek-flash`; availability and the actual returned model identity must be recorded, not silently replaced.

```bash
.venv/bin/python -m experiments.rq3_current.regression --out results/rq3-regression
.venv/bin/python -m experiments.rq3_current.run --stage pilot --model deepseek-flash --max-calls 3200 --out results/rq3-pilot --check-only
# The next two commands make real, paid API calls. Run only deliberately.
.venv/bin/python -m experiments.rq3_current.run --stage pilot --model deepseek-flash --max-calls 3200 --out results/rq3-pilot
# Inspect pilot protocol/flow results before explicitly launching full:
.venv/bin/python -m experiments.rq3_current.run --stage full --model deepseek-flash --max-calls 16000 --pilot-results results/rq3-pilot --confirm-pilot-reviewed --out results/rq3-full
```

## RQ4: A/B/D, no C

A: one-to-many setup/contact. B: sustained fanout with sampled business waits. D: one team's process failure, recovery and impact on other teams. Waiting distributions come from frozen real RQ3 logs but are simulated business waits here. A/B use K = 1/8/32/128/256, 32 workers, 128 units/cooperation, three repeats, 40 GiB stop budget. D uses eight teams × eight services, 8 workers, three fault points × three repeats, 24 GiB. Total **39** attempts. These budgets require a suitably provisioned Linux host; a resource stop is retained, not replaced by a fabricated successful run.

```bash
.venv/bin/python -m experiments.rq4_config_regression --out results/rq4-config-regression
.venv/bin/python -m experiments.rq4_shared_setup_regression --out results/rq4-shared-regression
bash docs/rq4-full-40g/RUN_FULL.sh results/rq4-full --check-only
PYTHON=.venv/bin/python bash docs/rq4-full-40g/RUN_FULL.sh results/rq4-full
```

Only the documented `rq4_full_40g` scheduler is the current full matrix. `rq4_suite` is retained for imported helpers; its legacy CLI is explicitly disabled. Summaries retain measurement warnings separately from protocol success. RQ4 scripts must not run concurrently with another performance group.

## Analysis and optional components

RQ2 flow/later/allocation suites generate their own reports. RQ3 writes per-task results and paired summaries; RQ4 invokes `experiments.rq4_report`. Raw outputs generated by a new run remain local. Install `requirements-plots.txt` where plotting is needed. Independent runs/instance pairs, not individual messages, are statistical units.

See [A2A](../integrations/a2a/README.md) and [proofs](../proofs/README.md). Neither is automatically run by the commands for another group. The packaging check itself invokes no protocols, LLMs or performance jobs.
