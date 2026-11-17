# GReDAC naming and compatibility

Current public names were checked against the manuscript titled **Branch Out, Stay in Bounds: Governing Recursive Delegation for Secure Multi-Agent Collaboration**: system **GReDAC**, structure **RDF**. Public headings, descriptive text, Python comments/docstrings and experimental display/method labels use these names. The package distribution name is `gredac-prototype`; implementation version `0.5.3` is not a manuscript version.

The implementation package is now **`gredac/`**, imported with `import gredac` and invoked with `python -m gredac`. It is our implementation. The old package directory is no longer present in this release. Protocol clients, experiment imports, timing labels, source snapshots, A2A patch paths and integrity checks use the new package name consistently. The separately bundled author SAGA source remains a third-party comparison dependency.

All files were scanned, including metadata and the author-source ZIP. The remaining historical spellings have specific internal or provenance roles; they are not the public name:

| Retained identifier | Why it remains |
|---|---|
| `B0-v3…` encoding/HMAC domains, test CA name and SAN prefix | Historical wire/cryptographic format identifiers; changing authenticated bytes would be a protocol change |
| `fixed-endpoint-v3.1` | Existing authenticated protocol version identifier, not the paper or implementation release version |
| `sacred-wire-v1`, `saga-v3-core-0.1` | On-wire codec and stored-record schema identifiers, not branding |
| `SACReD-v1.2-PCDF-reference-v1` | Frozen reference-model domain-separation bytes; replacing these changes authenticated/derived bytes |
| `SACReD…` theory identifiers, `Sacred12…` SMT types, `EndpointPCDF`, `pcdf_knowledge` | Existing proof and replay identities; saved source/certificates remain paired and byte-identical where required |
| `BadPCDF`, `eps_pcdf`, `epsilon_PCDF` | Named terms in the archived proof; the surrounding explanatory text refers to RDF |
| Original relative source paths, dependency versions, original commit IDs and hashes in provenance | Truthful historical provenance; they must not be rewritten as if old artifacts had originally used the new name |
| SAGA in third-party files and comparator labels | It names the separate upstream system and must not be renamed to GReDAC |

The retained proof model was frozen on **2026-11-08**. The name cleanup does not claim that this older model has been newly checked against every revision of the current paper. Full original artifacts remain outside this public copy, with their original names and hashes.

Current helpers are `gredac_fixture`, `gredac_regression`, `rq2_v2.gredac_adapter`, `rq2_v2.gredac_hooks`, `local_client` and `endpoint_audit`. There are no old-name import aliases. Own runtime environment variables are `GREDAC_SLOT_BITS`, `GREDAC_BUFFER_DIAGNOSTICS`, `GREDAC_OFFLINE_REGRESSION`, `GREDAC_A2A_TESTING`, `GREDAC_COMMIT_DELAY_BOUND`, `GREDAC_Z3` and `GREDAC_SYMBOLIC_RESULTS`. External model and solver variables retain their service names.

`G`/`G1` in fixtures denotes a fixed endpoint identity. The current manuscript also uses **G**; earlier discussions and some experiment descriptions called the receiving role **B**. These are not two trusted roles. `joint` is the historical internal mode selector used by the current endpoint, not another system name. The old `native_*` self-written comparator modules are excluded; the only supported SAGA comparison executes the pinned author archive.

Experimental method labels in newly generated results use `GReDAC` consistently across configuration, dispatch, timing and reporting. This copy does not overwrite or relabel old measured results. Protocol operations, cryptographic domains, persisted wire records and the official SAGA source are unchanged.
