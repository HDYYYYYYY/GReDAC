<h1 align="center">GReDAC</h1>
<p align="center"><i>Branch Out, Stay in Bounds: Governing Recursive Delegation for Secure Multi-Agent Collaboration</i></p>

## Abstract

Multi-agent collaboration often extends beyond the agents initially authorized by their users. Both parties may delegate work, allocate budgets to new members, and replace agents while a task is running. GReDAC governs these changes through a **Refinable Delegation Forest (RDF)** that jointly represents permitted operations and budget units. Parent agents derive restricted capabilities for their children, which can delegate further within inherited limits. An authenticated protocol binds these capabilities to the participants and their authorizations, while the receiving endpoint enforces budget ownership, prevents repeated consumption, and supports revocation and the safe return of unused units.

This repository provides the GReDAC research implementation, collaborative agent tasks, evaluation drivers, an optional A2A integration, and proof artifacts accompanying the paper.

## Requirements

Use **Linux or WSL with Python 3.12**. Run the following commands from the repository root:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

On Debian/Ubuntu, install `python3.12-venv` if virtual-environment creation reports a missing `ensurepip` module.

The core implementation uses SQLite and the `cryptography` package. Additional dependencies for the SAGA comparison, plotting, A2A integration, and proof replay are documented in their respective instructions. A model API credential is needed only for the real-LLM tasks.

## Setup

A collaboration involves the following roles:

- **Authority:** establishes the initial approvals, root authorizations, and budget capabilities.
- **Caller team:** a root agent `O` and its delegated agents, such as `A1` and `A2`.
- **Service team:** a root agent `R` and authorized service members, such as `S1`.
- **Receiving endpoint `G`:** validates contacts and requests, records budget transfers and consumption, and commits revocations and returns.

The runnable drivers create the test identities, certificates, listening ports, and participant processes for each run. Agents communicate over mutually authenticated TCP/TLS and maintain their private state in their own processes. SQLite stores use WAL mode with `synchronous=FULL`. The standard deployment runs these processes on one host.

Check the downloaded files before starting:

```bash
.venv/bin/python tools/check_release.py
```

Each run requires a new output directory. The drivers create their own protocol state and stop their participant processes when finished.

## Delegation and Agent Communication

### Quickstart

The following example establishes bilateral cooperation, delegates from `O` to `A1` and then to `A2`, discovers the service member, establishes contact, and completes 32 requests using an initial budget of 128 units:

```bash
.venv/bin/python -m experiments.rq2_v2.flow \
  --out results/quickstart \
  --case-json '{"method":"GReDAC","block":"flow","flow":"F1","identity":"roots-dynamic","replacement":null,"requests":32,"units":128}'
```

The service team authorizes `S1` under `R`. Child members are created during delegation, and their capabilities are delivered through the protocol. After initial setup, delegation and communication proceed without contacting the Authority for each request. This example uses real local TCP/TLS communication and a deterministic service, with no LLM calls.

Results are written under `results/quickstart/`, including:

- `manifest.json`: configuration, source hashes, environment, and completion status.
- `summary.json`: operation costs and audit results.
- `timing/`: recorded operation intervals.
- `protocol/`: participant state, protocol traces, and persistent evidence.

For the implementation entry points, see [`experiments/network_client.py`](experiments/network_client.py), [`experiments/network_actor.py`](experiments/network_actor.py), and the [method-to-code mapping](docs/METHOD_MAPPING_ZH.md).

### Revocation and Recovery

The same driver supports two replacement flows. Change the indicated fields in `--case-json` and choose a new output directory:

| Flow | `flow` | `replacement` | Behavior |
|---|---|---|---|
| Basic collaboration | `F1` | `null` | Complete 32 requests with the initial delegated members |
| Caller replacement | `F2` | `"caller"` | Complete 16 requests, revoke the caller branch, recover eligible unused units, and complete 16 requests with a replacement |
| Service replacement | `F3` | `"service"` | Complete 16 requests, revoke and replace the service member, establish a new contact, and complete 16 requests |

Service replacement does not automatically return or reissue the caller's budget. The new service member uses a new identity-bound ACT.

## Experiments

### Collaborative Agent Tasks

Three scenarios exercise the protocol during continuous collaboration:

| Scenario | Task | Implementation |
|---|---|---|
| Travel planning | Coordinate a trip using the supplied travel options and constraints | [`travel_scene.py`](experiments/travel_scene.py) |
| Joint research report | Analyze supplied materials and data, exchange review feedback, and revise a report | [`academic_scene.py`](experiments/academic_scene.py) |
| Calendar coordination | Schedule shared resources across projects and resolve an injected availability change | [`calendar_scene.py`](experiments/calendar_scene.py) |

Each task covers initial bilateral cooperation, runtime delegation, shared budget use across tasks, caller replacement, and service replacement. Paired runs execute the same business task with and without GReDAC. The main acceptance criteria are workflow completion and protocol correctness; business-answer quality is a separate concern.

Inputs are provided in [`experiments/data/rq3_20261108_instances.json`](experiments/data/rq3_20261108_instances.json). The public pilot selects five existing instances per scenario and runs both conditions, for 30 task executions. The full evaluation uses 25 per scenario, for 150 executions.

Inspect the pilot configuration without making model calls:

```bash
.venv/bin/python -m experiments.rq3_current.run \
  --stage pilot \
  --model deepseek-flash \
  --max-calls 3200 \
  --out results/rq3-pilot \
  --check-only
```

To execute it, supply `DEEPSEEK_API_KEY` through the environment or set `DEEPSEEK_CREDENTIAL_FILE` to a credential file outside the repository, then run the command without `--check-only`. This makes real API calls. The driver records the returned model identity and enforces the call limit. Full runs require a completed matching pilot and explicit review; see the [reproduction instructions](docs/REPRODUCE.md#rq3-real-model-tasks).

### Protocol Cost and Scalability

| Evaluation | Scope | Entry points |
|---|---|---|
| RQ2: protocol cost | Complete flows against the pinned SAGA author implementation; GReDAC dialogue amortization and structure sensitivity | `experiments.rq2_v2.suite`, `experiments.rq2_later.suite` |
| Budget allocation | Compare subtree-first, random, and deliberately dispersed selection along recursive delegation | `experiments.allocation_policy_v2.suite` |
| Geographic delays | Sample public RTT observations and inject waits into dialogue execution | `studies.rq2_rtt.run_wait` |
| RQ4: scalability and recovery | One-to-many setup, sustained interaction, and the effect of one team's process failure on other teams | `experiments.rq4_full_40g` |

The SAGA comparison executes the bundled author-source archive at commit `7372111bea150e32cee390a616849316d2780bfc`. Its adapter uses SAGA's native operations without adding GReDAC's recursive control guarantees. MongoDB is required for this comparison; GReDAC itself uses SQLite.

See [REPRODUCE.md](docs/REPRODUCE.md) for dependencies, separate regression/pilot/full commands, parameters, and timing boundaries. Run performance groups serially. Injected RTT waits are sampled-delay experiments, not measurements of a deployed WAN system.

### Data

The repository includes synthetic task inputs, frozen allocation workloads, RQ3 timing samples used to generate RQ4 waits, public RTT samples, and proof-check artifacts. Full experiment databases and LLM conversation logs are not included. See the [data inventory](docs/DATA_INVENTORY_ZH.md) for sources and scope.

## Testing

Run the non-LLM correctness suite:

```bash
.venv/bin/python tools/test_release.py --out results/regression
```

It checks core operations, input presentation, participant communication, protocol accounting, revocation/recovery, and experiment configuration. RQ3 checks use explicit offline fixtures; they do not measure real-model task completion. See the [validation report](docs/FINAL_CHECK_ZH.md) for the checks performed on this release and their limits.

## A2A Integration

The optional A2A extension uses SDK `SendMessage`/`DataPart` messages within the authenticated GReDAC channel. Prepare it in a separate working tree:

```bash
.venv/bin/python tools/prepare_a2a.py --out ../GReDAC-a2a
```

Follow the [A2A instructions](integrations/a2a/README.md) to install its dependencies and run functional and fault checks. This is a controlled SDK bridge; external HTTP interoperability, streaming, and the complete A2A task lifecycle are outside its implemented scope.

## Security Proofs

The [`proofs/`](proofs/) directory contains the cryptographic reference construction, state-transition verification scripts, and Tamarin models and certificates. Follow the [proof replay instructions](proofs/README.md) for dependencies and commands. These artifacts state their model assumptions and version scope separately from implementation tests.

## Citation

This repository accompanies the manuscript:

> **Branch Out, Stay in Bounds: Governing Recursive Delegation for Secure Multi-Agent Collaboration**

Please use the bibliographic information supplied with the public manuscript when citing this work.

## License

The original GReDAC code and documentation are available under the [MIT License](LICENSE). Bundled SAGA code and external data retain their respective terms; see [third-party notices](third_party/README.md).
