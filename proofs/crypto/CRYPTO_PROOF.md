> 开源副本范围说明：下文保留原 GReDAC 证明论述及历史证据说明。其中 inputs/paper/review、历史日志和生成型 SMT 文件指原完整归档，未全部随本最小副本分发。可重现步骤和本包实际内容以本目录 README.md 为准；不得把原记录理解为本轮重新证明的结果。

# RDF correctness and cumulative-exposure security for GReDAC

Date: 2026-11-08. Frozen specification: `../inputs/protocol_specification.tex`
and `../inputs/protocol_conditions.tex`. This file proves P0 and the RDF part
of P1; it supplies interfaces for the scenario composition, not a substitute
for that composition. It does not modify the protocol or manuscript.

**Result.** Canonical-cover delegation and endpoint reconstruction agree for
arbitrary finite scopes and delegation depths. In the classical random-oracle
model, the joint key-recovery/new-message-authentication experiment below has
advantage at most

\[
 \epsilon_{\rm RDF}(Q,T,V,\lambda)
   =\min\{1,16(Q+T+V+2)^2/2^\lambda\}.
\]

This is a deliberately loose, multi-target, cumulative-exposure bound. It is
not a standard-model theorem for SHA-256 and not a claim of key
indistinguishability in the presence of publicly checkable descendants.
The probabilistic proof is manual; the accompanying SMT checks verify only
its final arithmetic. Recovery preserves the original anchor. The stronger
historical theorem that assumed a new anchor is **not used**.

## 1. Exact objects and assumptions

Fix a security parameter lambda and let D = 2^lambda. Each source has an
independent uniform lambda-bit master. One global random function
H:{0,1}* -> {0,1}^lambda serves every source and endpoint. The function is
implemented by a lazy table: the first lookup of an input samples a uniform
output; subsequent lookups reuse it. All sampling and direct adversarial
oracle queries are classical. Public encoding E is injective and includes
operation type, field lengths, arity, and version. The five private-input
forms are exactly anchor, split, grant, spend, and auth from the frozen text;
each has **one** distinguished, fixed-width secret field. A malformed direct
oracle query is allowed but cannot equal a valid private input.

A formal secret node is a master, or the result of a legal typed
Anchor/Split/Grant/Spend path from a master. Paths include their complete
labels and source bindings; two references to the same path are the same
node. A legal capability record selects a particular path, not merely an
action--slot coordinate. Auth outputs are terminal public authenticators,
not KU secret targets. The graph has no cycles. Arbitrary finite delegation
histories are permitted, with polynomially many actually accessed nodes in
the computational experiment. There is no bound of one delegation level,
one source, one target, or one disclosure.

The Authority retains the master and anchor. The receiving stack starts from
the **restricted initial capability bundle** and reconstructs later bundles
along registered histories. Giving the stack the master is not required or
modeled by the reference reconstruction interface.

Public metadata and interface choices may adapt to everything the adversary
has observed. Honest generation may not inspect a hidden key and leak it
through a public identifier, branch choice, record length, or timing channel.
Keys delivered to an adversarial recipient count as exposed. A compromised
identity key that causes later delivery to the adversary must cause another
exposure; a replacement cannot be declared secure solely because it has a
new name. Signature, confidentiality, identity-possession, trusted-stack,
and state-correctness assumptions are separate interfaces.

### 1.1 Exposure and computation are cumulative

E_t contains every secret node whose value was disclosed by time t, including
historical bundles, individual internal nodes, and Spend secrets. Cl(E_t) is
the forward closure under public derivation operations. It includes future
nodes under a disclosed ancestor, whether or not a delegation was registered
when the disclosure occurred. It is not reduced by scope narrowing,
revocation, return, deletion from an honest cache, or loss of current
ownership. Multiple colluders contribute to one E_t.

For clarity, the closure is initially defined on typed path identities.
Bitstrings do not carry types: an unrelated public tag or off-grammar H
output can equal a hidden seed. The Collision event below explicitly covers
these equalities. Arbitrary attacker calculations, including using a Spend
value as a Split input or a public tag as a candidate seed, remain available
through the direct H oracle. They are not silently ruled out by path typing.
When an exposed path is an ancestor of a formal target, its future forward
computation belongs to the closure even before the corresponding H queries.

## 2. P0: exact cover and same-history correctness

For a fixed action/slot geometry of m bits, write R(p) for the depth-m leaves
under binary prefix p. For a scope S of valid action--slot leaves, C(S) is
the set of inclusion-maximal complete subtrees: R(p) subseteq S and no
strict ancestor of p has that property. Padding leaves are absent from S.
The scope is an arbitrary relation, not the product of its action and slot
projections. Several actions at one slot still name one state-level unit.

**P0.1 (canonical cover).** C(S) is unique, prefix-free, and its leaf union is
exactly S. For every nonempty S' subseteq S and q in C(S'), there exists a
unique p in C(S) with q = pv.

*Proof.* Each leaf of S has a unique highest complete ancestor, which gives
existence and exact coverage. Two maximal complete prefixes cannot be
comparable, giving prefix-freeness and uniqueness. Choose a leaf under q
and its unique covering p in C(S). Intersecting binary-prefix regions are
nested. If q were a strict ancestor of p, R(q) subseteq S' subseteq S would
contradict maximality of p in C(S). Thus p is a prefix of q. Two such p's
would violate prefix-freeness. Empty scopes have the empty cover. QED.

**P0.2 (same-history agreement).** Suppose a caller and receiving stack have
the same initial restricted bundle and authentic immutable capability
records. For every registered capability gamma, prefix q in its cover,
and leaf x in its scope, their reconstructed block seed, leaf secret,
Spend secret, and complete-message Auth value agree.

*Proof.* At the initial capability both hold exactly the supplied bundle.
Induct on capability depth. P0.1 gives the same unique parent block p for
each child q=pv. The induction hypothesis gives an equal parent seed.
Both apply the same ordered Split suffix v and Grant label gamma; a
deterministic function returns equal child seeds. Splitting to x and then
applying Spend and Auth with identical canonical M preserves equality.
Each finite depth has a predecessor, so the induction is unbounded in
depth. No random-oracle security assumption is needed for this equality.
QED.

**P0.3 (structural range and its limit).** Split only extends a geometric
prefix; Grant preserves that prefix. Formal descendants of disclosed
blocks therefore remain within the union of those blocks' regions and
histories. Claiming hardness of upward or cross-history computation
requires P1, not this structural observation. Conversely, a disclosed
parent can compute its children; Grant adds no secret entropy against it.

The child bundle has exactly |C(S')| seeds, independent of depth. This does
not bound the size of a fragmented scope or the separately maintained
history. Seeds from different Grant histories cannot be merged by geometric
adjacency. Split(Grant(k,gamma),b) and Grant(Split(k,b),gamma) use different
paths: the endpoint must replay the actual order. Distinct paths have
different values only outside the collision event, not deterministically.

## 3. P1 experiment: KU and UF in the same execution

The adversary selects public metadata, records, and targets adaptively and
may interleave the following interfaces. A legal path can be materialized
without registering its delegation. Registering a path never grants its
secret to the adversary by itself.

1. **Materialize(path):** construct the formal path and save its exact
   lazy-table values; return only public metadata. This includes the paths
   needed by endpoint reconstruction and target verification.
2. **Reveal(node/bundle):** return the stored values and add the named
   secrets to E. The interface permits more targeted disclosures than
   ordinary whole-member compromise. Old values are never resampled.
3. **Tag(z,M):** return H(E(auth,val(z),Canon(M))) and record the exact
   formal pair (z,M). z is a Spend node. No spending-state guard is imposed;
   unlimited within-budget chosen-message access strengthens the attack.
4. **H(w):** an arbitrary bitstring query, including unregistered local
   derivation, precomputation, malformed domains, or use of a public value
   as a seed. This is the adversary's only way to evaluate the ideal H.
5. **Verify(z,M,t):** return equality with the correct Auth output; this
   interface returns a bit, not the expected tag. It neither charges a unit
   nor changes ownership. Repeated failed guesses are permitted.

**KU event:** the final output (v,k) has v outside Cl(E_final) and
k=val(v). v can be a master, anchor, arbitrary internal node, leaf, or
Spend secret. A target first named at the end is materialized and counted
before checking. In particular, a hidden parent with all its children
revealed remains a valid KU target; no fresh descendant is assumed.

**UF event:** a Verify call or the final tuple (z,M,t) succeeds, z is
outside Cl(E) at that attempt, and Tag has never returned a tag for the
same formal pair (z,M). Same-node aliases share a Tag history. A successful
online forgery is recorded immediately: later disclosure cannot erase it.
Observed-tag replay and authenticators generated with a Spend secret already
in Cl(E) are not UF events. If the adversary first obtains the target secret through
a successful hidden guess, HiddenInput/KU has already identified the
cryptographic failure even if later tag construction is ordinary.

The joint experiment permits at most V Verify calls and one final KU and
one final UF candidate. It wins on either event. All sources, members,
colluders and targets share the same H, transcript, budget and exposure
set. We bound this joint event once when composing protocol theorems.

### 3.1 Resource accounting

- Q bounds all direct adversarial H calls; charging repeated calls is safe.
- T bounds source-master samples plus all distinct H entries touched by
  honest constructors, Tag, Verify, and final target materialization. It
  includes intermediate Split paths, Grant, Spend and Auth entries. Counting
  an entry already touched by the adversary again is conservative.
- V bounds all adversarial equality-verification attempts, including
  verification feedback obtained through protocol admission. The two final
  candidates are additional. Honest work performed on a malicious input
  counts in T, even when the request is later rejected.

Put N=Q+T and B=Q+T+V+2. The total number of independent samples (masters and
first-time oracle outputs) is at most N. There are at most T formal secrets
and honest terminal values actually used. A potential exponential tree is
not pre-created or charged; every traversed path does count. Polynomial
execution yields polynomial Q,T,V. Metadata length and parsing also have
polynomial bounds.

## 4. Proof of the joint ROM bound

### 4.1 Interning and the bad events

Maintain a lazy RO table and a table of formal nodes. The same typed path
reuses its previous node and value. A different formal path can accidentally
have an equal parent value; do not assume it cannot. Before any such
collision, injective encoding ensures that distinct incoming formal edges
use distinct oracle inputs unless they are the same typed edge.

**BadColl:** two different independent samples are equal. Samples include
masters, public Tag outputs, malformed/direct-query outputs and undisclosed
secrets. Repeated calls to the same oracle input are one sample. By the
ordinary pairwise bound, Pr[BadColl] <= N(N-1)/(2D) <= N^2/D, even for
adaptively chosen inputs, since each genuinely new table entry is sampled
uniformly independently of the previous samples.

**BadInput:** a well-formed direct H query has its distinguished secret
field equal to a formal secret currently outside the cumulative closure.
This event compares a candidate with *every* protected node, not just the
query's eventual target. It is also checked when a later-created formal
node equals a previously submitted secret-field candidate. Each ordered
pair (query candidate, formal node) is tested once, when both exist. A
query whose parent is already exposed is ordinary forward computation,
and its descendants are not fresh targets. There are at most QT pairs.

Prequery handling is essential. If an honest operation would find its
exact private input already queried while its parent is protected, the
corresponding parent/candidate comparison has triggered BadInput. There
is no permission to overwrite or reprogram an output that was already
observed. When a parent is later disclosed, honest operations still reuse
the existing table; they do not start a new experiment.

**BadGuess:** before the first two events, a fresh KU candidate equals a
protected secret, or a fresh Verify/final-UF candidate equals its not
previously published Auth output. A direct H query to that Auth input
would already trigger BadInput. There are at most (V+2)T candidate/target
pairs; this overcounts a single final KU target to allow adaptive target
choice without guessing its identity in advance.

An off-grammar computed value equal to a protected formal seed is covered:
if it was a distinct H output it is BadColl; if it is a raw guessed string
used in the secret position it is BadInput; if submitted as the final key
it is BadGuess. The same formal seed learned by querying its actual private
input requires a hidden-parent hit, or lies in the disclosure closure.

### 4.2 Hidden-value lemma (the probabilistic step)

Consider a finite prefix just before the first bad event. Conditional on its
public transcript and on avoiding the earlier bad events, a protected
formal seed, or an unpublished fresh Auth output being guessed, has point
probability at most 1/(D-4B). This claim is used only when D>16B^2, so the
denominator is positive. A target may be chosen from all currently or later
materialized nodes; the subsequent pair count handles that choice.

Here is the conditional-distribution argument, rather than assuming that
all publicly related keys are independent. Fix the adversary's coins, the
transcript prefix, the formal paths so far, and every other sampled label.
Let x be the protected value. For a secret node, the earlier good event
excludes the other at most N-1 sampled labels and the at most Q submitted
secret-field candidates. For an unpublished Auth output, collision freedom
excludes the other samples and failed comparisons exclude at most V+2
terminal guesses; secret-field guesses are not exclusions for this terminal
output, which has no private outgoing edges. These are the relevant
exclusions, totaling at most 4B in either case. For any two remaining
values x and y, replace the selected label x by y and relocate
the private oracle entries having that node in their distinguished secret
field, retaining their outputs. Change its incoming table output from x
to y; for a master change the independent master sample instead. Keep all
other sampled labels and public metadata fixed.

This replacement is a bijection on the consistent collision-free lazy
tables, with inverse y-to-x. No public oracle location changes: an already
queried affected location would have supplied the excluded secret-field
candidate. No private location merges with another: operation/length
encoding is injective and y is not another sampled seed. A private incoming
edge cannot be publicly fixed while its parent is protected without a
BadInput event; if its parent were in the closure then the selected node
would not be protected. Public descendants and Tags keep their returned
values because outgoing table outputs are retained. Reveal of a descendant
does not reveal this ancestor. An exposure of this node or an ancestor
would instead remove the node from the protected set. Verification bits
stay unchanged, except for a guessed terminal value explicitly excluded.
Public identifiers chosen as a function of the transcript stay unchanged;
the no-hidden-key-side-channel condition from Section 1 is used here.

Every lazy-table assignment related by this bijection has the same
probability (the same number of independent uniform samples). Thus each
nonexcluded candidate has the same conditional weight after fixing the
other labels; averaging over them gives the point-probability bound. The
argument conditions only on the prefix, not on a future event of remaining
safe. For a candidate that predates creation of its target, creation samples
the target freshly unless its exact input already exists. A publicly
queried existing input is the hidden-parent BadInput case; a private
existing input is the same interned node. This establishes the same bound
for the opposite temporal order, without programming a previously observed
oracle value.

The bijection concerns the distribution of completions for analysis. The
real experiment never changes a saved value, and adaptive disclosures
return the original value. It also explains why this is a key-recovery
argument rather than a claim that a supplied challenge key cannot be
checked against a revealed descendant: such checking uses oracle inputs
and is precisely what Q counts.

### 4.3 Probability accounting and theorem

If D <= 16B^2 the asserted bound is 1. Otherwise B>=2 and 4B<D/2, so each
candidate/target comparison in Section 4.2 has conditional success
probability less than 2/D. By a first-bad-event union bound,

\[
 \Pr[\mathsf{BadColl}\lor\mathsf{BadInput}\lor\mathsf{BadGuess}]
 \le {N^2+2QT+2T(V+2)\over D}
 \le {16B^2\over D}.
\]

The numerator is intentionally overcounted. Both temporal orders of a
query/node pair count once; public samples are included in N; all roots and
all targets are already in T. There is no missing factor for sources,
disclosures, endpoints, or target selection. A successful fresh KU or UF
without one of these events is impossible: the former guesses a protected
stored value; the latter either queries its hidden Auth input or guesses an
unpublished tag. This proves the stated joint P1 bound. QED.

The final inequality and the denominator side condition are separately
checked in `check_bound.py`. They do **not** mechanically verify the
conditional-distribution lemma, the experiment, or its protocol refinement.
For illustration only, B<=2^40 and lambda=256 give epsilon<=2^-172 in this
ideal model. This is not a measured security level for SHA-256.

## 5. Conditional same-anchor recovery isolation

Let P be the actual capability parent used after return, with the original
anchor a. For each new child-cover block q=pv define the **actual input**
d_q = Split*(k_{P,p},v). The replacement has a fresh child identifier
gamma_new, so its block seed is Grant(d_q,gamma_new). Distinguish the
authorization parent used for control from the capability parent used here.

**P1-R (per-block new-branch condition).** Suppose for a selected replacement
block q: (i) the actual node d_q is outside the union of all cumulative
exposures' forward closures, (ii) gamma_new is fresh and its binding cannot
be rebound, (iii) the replacement's secret material and relevant
descendants are not separately exposed, including through an insecure
delivery or compromised recipient. Then the replacement block and its
selected Spend descendants are outside that closure. KU or fresh-UF
success on them is bounded by the same joint epsilon_PCDF, with all such
blocks counted in the common T budget.

*Proof.* The final incoming edge is Grant(d_q,gamma_new). A forward path
from previously disclosed material reaching this new edge must reach d_q,
contrary to (i), unless it begins with a separate disclosure in the new
subtree, excluded by (iii). A path from a different old branch cannot
switch Grant histories. Freshness (ii) prevents reuse of an old identical
edge. Equality of the actual bitstrings from unrelated paths is not
excluded by syntax; it is included in BadColl and hence in epsilon_PCDF.
Apply P1 to every selected protected target in the one common experiment.
QED.

Conditions are target-specific: some cover blocks may satisfy them while
others do not. A leaked parent block containing q reveals d_q by forward
Split and defeats (i). A parent who can derive the new child's keys is not
isolated from that child. Merely issuing a new public identifier or ownership
record creates no hidden entropy. Restoring a parent's state authorization
does not establish secrecy of its keys. Disclosure of the new recipient
later widens the closure and removes the corresponding freshness claim.

The result does not erase old keys or prevent valid old tags. Rejection
after revocation, rejection of delayed transfers referencing old ownership
records, no double consumption, the nearest eligible return recipient,
and preservation of inherited restrictions are state theorems. Possession
of a replacement tag secret also does not by itself supply its identity
private key or matching ACT. Those are distinct premises of composition.

## 6. Precise interface to P2--P5 and scenarios

For any new-admission target the composition must demonstrate all of these
facts for the **same** execution and request:

1. Its verification node is selected from the immutable registered
   capability history tied to that current unit, rather than a path chosen
   by an unauthenticated request. P0 relates it to the caller's key.
2. The leaf encodes the actual business action and permanent (source,slot)
   unit. The vector's source set equals Req(chi,action), with no duplicates.
3. Every tag authenticates the same injectively encoded complete M, including
   both identities/authorizations, session, payload, vector and current
   ownership records. ACT is outside M: P2/P5 must check that it agrees
   with M and with the authenticated participants.
4. Actual disclosures and observable oracle/verification behavior map to
   the experiment above. No inferred secrecy follows from current nominal
   scope after a broader historic bundle was disclosed.
5. Successful verification still passes current bilateral eligibility,
   inherited restrictions, record, expiry, and unused-unit checks before
   one atomic state transition. A tag alone proves none of these.

S1 and S2 use different exposure sets in this same P1 experiment. Their
end-to-end conclusion additionally requires P0, P2, the P3 state invariants,
and P5's same-request connection. S3 additionally needs P4 revocation and
return, the per-block P1-R condition, identity/ACT binding, and P3's preserved
unit history. The scenarios are therefore not renamed P1 corollaries.

For a common execution, define BadPCDF as the union bounded in Section 4.
The combination may use Pr[BadPCDF union BadControl union BadChannel]
<= epsilon_PCDF + epsilon_control + epsilon_channel, conditional on the
exact encoding/uniqueness/state/refinement obligations being correct. No
general-purpose computational soundness theorem for arbitrary Tamarin
models is asserted. The trusted stack can itself compute tags; this
protocol gives no nonrepudiable metering against a malicious stack.

## 7. Executed evidence and limits

`reference.py` is an explicit byte-encoding/SHA-256 functional profile.
Its endpoint accepts only the restricted initial bundle, and reconstructs
the rest recursively. `register` checks derivation metadata consistency;
it is not an authorization, transfer, or spending-state implementation.
The reference uses public deterministic fixture roots, not production keys.

`check_reference.py` records its executed results and source hashes in
`REFERENCE_RESULTS.json`: all 256 scopes of an 8-leaf geometry, all 6,305
nonempty nested-scope pairs, 17,496 local/endpoint leaf equalities, depth
1--64 examples, 14 full-request field mutations, canonical-encoding and
negative-condition checks. These include same-anchor restoration, parent
leakage invalidating isolation, future descendants in disclosure closure,
copyable bundles, exact-tag replay, and a small-domain witness that public
outputs can equal unrelated secret values. They are finite functional
checks, not security experiments or a proof by sampling.

The old arbitrary-depth cover argument and typed construction ideas are
reused. The current proof restates the security game, explicitly includes
all sampled outputs and adaptive target/disclosure orders, supplies the
conditional-distribution bijection, uses a more conservative constant 16
instead of 8, and replaces the inapplicable fresh-anchor recovery claim.
The formula's arithmetic is machine-checked; its probabilistic argument
remains an auditable mathematical proof. No HMAC reduction is claimed:
the frozen GReDAC construction is the typed classical-RO construction.
