# Existing GReDAC proof artifact

This is a compact copy of the existing versioned artifact, not a newly derived proof of every subsequent implementation change. Read `MODEL_CONTRACT.md`, `COMPOSITION_PROOF.md`, and the component proof documents for assumptions and scope. Functional reference checks are not themselves a cryptographic security proof.

The public name is GReDAC and the structure name is RDF. The underlying model was frozen on **2026-11-08**; updating its displayed name does not revalidate all changes in the latest manuscript. Executable domain-separation constants, symbolic theory names and saved certificates retain their original identities. See `../docs/NAMING.md`. The retained `state/RESULTS.json` and `state/WITNESSES.json` are historical proof-check outputs, not newly measured results.

Use a separate environment with `proofs/requirements.txt`, and install Tamarin and Maude independently. The tested Linux Z3 wheel supplies its CLI in the environment's `bin` directory; set `GREDAC_Z3` to another installed Z3 executable if needed. Saved Tamarin models and certificates are retained byte-for-byte. State proof formulas are deterministically regenerated from the retained kernel/generator, avoiding approximately 400 MB of redundant intermediate SMT files.

```bash
python3.12 -m venv .venv-proofs
.venv-proofs/bin/pip install -r proofs/requirements.txt
export GREDAC_Z3="$PWD/.venv-proofs/bin/z3"
# Tamarin and Maude must be on PATH, or set TAMARIN/MAUDE to their paths.
.venv-proofs/bin/python proofs/crypto/check_reference.py
.venv-proofs/bin/python proofs/crypto/check_bound.py
.venv-proofs/bin/python proofs/state/verify.py
.venv-proofs/bin/python proofs/state/witnesses.py
.venv-proofs/bin/python proofs/state/replay.py
.venv-proofs/bin/python proofs/symbolic/replay.py
```

Set `GREDAC_Z3`, `TAMARIN` and `MAUDE` when the solver executables are not on `PATH`. Run state generation before replay. Generation writes new SMT files and result manifests in the proof directory; preserve a pristine release copy if comparing to its original checksums. `requirements.txt` includes the `setuptools` version needed by this older Z3 Python binding's `pkg_resources` import. Final replay was checked in an isolated copy; see `../docs/FINAL_CHECK_ZH.md`. This replays the retained model, not a new proof of the latest manuscript or all code.
