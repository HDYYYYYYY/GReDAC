# GReDAC research artifact

This is a curated publication copy of the GReDAC research prototype (implementation version 0.5.3). It contains the protocol implementation, the current experiment drivers and their required inputs, an isolated A2A integration, and the existing GReDAC proof artifact. It is not a production service.

Paper: **Branch Out, Stay in Bounds: Governing Recursive Delegation for Secure Multi-Agent Collaboration**. The current system name is **GReDAC** and the derivation structure is **RDF**. The implementation version is separate from the manuscript revision. See [naming compatibility](docs/NAMING.md) for retained internal identifiers and proof scope.

This is **not a data-free source package**: it contains synthetic task inputs, measured RQ3 timing samples used by RQ4, and saved proof-check results. It does not contain the complete RQ2–RQ4 result archives, databases or model conversation logs. See [data inventory](docs/DATA_INVENTORY_ZH.md).

The main tree retains the measured RQ2–RQ4 protocol implementation. The A2A extension is supplied separately and is **not silently merged into that measured implementation**. See [scope](docs/OPEN_SOURCE_SCOPE_ZH.md), [reproduction](docs/REPRODUCE.md), and [packaging changes](docs/PORTABILITY_CHANGES.md).

| Path | Contents |
|---|---|
| `gredac/` | Cryptographic derivation, authority, delegation, admission, accounting, revocation/recovery, storage and TLS |
| `experiments/` | Independent processes and TCP/TLS transport; current RQ2–RQ4 drivers, scene tools, prompts, checks and required compatibility helpers |
| `studies/rq2_rtt/` | Explicit RTT modelling and injected-wait driver; frozen public measurement sample pool |
| `integrations/a2a/` | Optional SDK bridge, tests and a seven-line core-hook patch applied to a separate working copy |
| `proofs/` | Versioned cryptographic reference, SMT generators and Tamarin models/certificates |
| `tools/` | Offline integrity check, A2A working-copy preparation and RTT result plotting |
| `provenance/` | File hashes, source provenance and inclusion rationale |
| `third_party/` | Upstream notices; the pinned SAGA author archive is under `experiments/rq2_v2/` |

Use Linux, Python 3.12, independent local processes and TCP/TLS; SQLite remains WAL/FULL. These are loopback measurements, not a distributed deployment. Injected geographic waits remain artificial waits sampled from public RTT data. RQ3 makes paid API calls **only when explicitly launched**; credentials are supplied by the user and are never bundled.

Start with `python tools/check_release.py`. It checks files, not performance or protocol execution. Installation and separate regression/pilot/full commands are in [REPRODUCE.md](docs/REPRODUCE.md). New results must use new directories. Frozen publication checksums are packaging checksums, **not evidence that this relocated copy has already passed a new full experimental campaign**.

Use `python tools/test_release.py --out results/release-regression` on Linux for the non-LLM correctness suite. See [method-to-code mapping](docs/METHOD_MAPPING_ZH.md) and [final check](docs/FINAL_CHECK_ZH.md) for what is current, what is a local test fixture, and the actual validation scope.

Original project code and documentation are released under the [MIT License](LICENSE), selected by the author. Third-party software and external RTT data retain their own terms; see [third-party notices](third_party/README.md). This folder has been prepared locally and has not been published.
