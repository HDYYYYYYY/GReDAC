> 开源副本范围说明：下文保留原 GReDAC 证明论述及历史证据说明。其中 inputs/paper/review、历史日志和生成型 SMT 文件指原完整归档，未全部随本最小副本分发。可重现步骤和本包实际内容以本目录 README.md 为准；不得把原记录理解为本轮重新证明的结果。

# P5: common-execution composition and scenario proof

Status: mathematical argument under the frozen protocol and the explicit
contract in `MODEL_CONTRACT.md`. Companion proof artifacts provide evidence for
the component obligations. This is not a claim of an automatic compiler proof
from the manuscript or a deployed program to Tamarin/Z3.

## A. Single experiment and observation boundary

Run the actual operations of the frozen protocol with a single classical PPT
adversary. The challenger maintains (i) the typed random-oracle table, (ii)
approved identity/control records, (iii) authenticated-channel sessions, and
(iv) the receiving endpoint's durable state. The adversary chooses scheduling,
malicious Agent messages, registered adversarial identities, adaptive Agent
compromises, and arbitrary oracle queries. It can cache and combine every
obtained value. Local derivation and signing do not write the endpoint state.
The challenger delivers messages and executes atomic commits according to the
frozen guards. This defines a joint experiment, rather than three independently
sampled protocol executions whose conclusions are later combined.

The endpoint is trusted to execute those guards. We do not prove that a buggy
implementation executes them. Any finite prefix has a total commit order. A
failed transaction, local derivation, or network delivery with no commit is a
stuttering step of the abstract ledger. A decision lookup has an observable
response but is also a stuttering step for debits and initial delivery.

Let `New(rho,M)` denote the unique commit that records a new positive admission
and its exact source debits. Let `Deliver(rho,R,M)` denote its initial delivery
record, not an external service's eventual business effect. `Revoke(d)` and
`Return(d,U,P,ell)` refer to their committed events. Events from messages sent
but not committed have no such semantics. This event boundary is essential
when acknowledgements are lost, or revocation and consumption race.

## B. Exception events and their bounds

Define the following events in this *same* experiment.

1. `BadSig`: verification accepts a new typed signed message under a key whose
   protected/honest signing interface has never emitted it, while that key has
   not been exposed before acceptance. A signature issued by a compromised
   member, or by an honest member on the same bytes earlier, is not this event.
2. `BadChan`: the authenticated-channel interface delivers an accepted peer
   identity or protected secret not allowed by its security guarantee and the
   actual exposure history. No secrecy is asserted for a compromised endpoint.
   Exposure of a particular session's authentication secret is an allowed
   origin exception, not automatically `BadChan`. The interface indexes it by
   both peers, collaboration and session. An honest-process origin claim
   therefore additionally excludes relevant identity-key and session-secret
   exposure; accepted identity labels alone do not imply an honest process.
3. `BadPCDF`: the common `BadColl | BadInput | BadGuess` event in
   `crypto/CRYPTO_PROOF.md` Section 4, which contains key-recovery or fresh
   authentication success outside cumulative exposure. Freshness and query
   budgets are exactly those of that proof. Reusing an observed tag for the identical request is
   not fresh authentication. Reusing a tag on different encoded bytes is a
   fresh attempt unless it was legitimately obtained on those bytes too.

Write their bounds as `eps_sig`, `eps_chan`, and `eps_pcdf`, respectively.
For signatures one may use a multi-user EUF-CMA advantage directly, or the sum
of the individual-key reductions over polynomially many honest keys; an
adaptive first-forgery key guess must be included in that accounting. We do not
silently identify a single-key advantage with a multi-user one. Channel
security remains an assumed interface here, not a newly proved TLS theorem.
The ROM proof supplies `eps_pcdf=min(1,16*(Q+T+V+2)^2/2^lambda)`. These are
global budgets for the entire execution. V counts individual tag equality
attempts/feedback, conservatively one per source tag rather than one per
multisource request; T includes reconstruction and verification on rejected
requests too. No additional source/target factor is then needed.

For any attack event shown below to imply their union,

`Pr[attack] <= eps_pcdf + eps_sig + eps_chan` (capped at one).

This union bound requires no independence. A first-failure proof avoids
conditioning any primitive reduction on a favorable state trajectory: simulate
the entire trace and stop at the first exceptional event of the relevant type.
Every honestly generated request tag is also recorded in the experiment's Tag
history, including honest-to-honest deliveries; exposing these tags to that
experiment only strengthens its adversary. Honest signers' outputs are recorded by the signing interface; their keys may
be exposed adaptively except for the successful target key before acceptance.
The RO experiment includes all protocol-side oracle calls, observed tags,
verification attempts and compromises, so neither endpoint verification nor a
locally prepared delegation is omitted from its query accounting.

## C. Abstraction relation

Map a concrete prefix `tau` to an abstract state `alpha(tau)` as follows.

**Approvals and identities.** Keep the immutable approved collaboration and
source records, both role-specific authorization forests, key identities,
expiry/depth/scope restrictions, tombstones and cancellation records. For a
non-root authorization, its parent is the signed authorization parent, not a
guessed capability ancestor. The signature transcript records the exact bytes
and signer. Outside `BadSig`, an unexposed signer either emitted those bytes or
did not authenticate the record; exposed signers may emit arbitrary bytes, all
of which still face eligibility checks.

**Capability interpretation.** Each registered cap maps to its unique parent,
geometry and exact joint scope, immutable source/anchor/collaboration/endpoint
binding, holder authorization and transfer description. Its interpretation
`K(gamma,x)` is the recursively specified sequence of Split and Grant calls,
starting from the certified restricted initial bundle. The recursion is on
creation order and has finite depth. No inversion or commutation is used.
P0 gives equality to honest local derivation. A maliciously delivered wrong
bundle can prevent its recipient from spending; it cannot change this stack
interpretation. Honest-generation is therefore a premise for availability,
not for refusal of invalid requests.

**Unit interpretation.** Preserve every permanent `(s,i)`, current
`(a,gamma,d,ell)`, confirmed-use state, inherited relation/deadline, and history.
A current unit's `gamma` is registered and holds the corresponding unit in
its scope. The capability ancestry retains a corresponding cap for each
authorization ancestor needed for recovery. This last fact is proved by
induction on issuance/transfer/return; it is not supplied as an arbitrary
oracle during return.

**Request interpretation.** Decode all of `Canon(M)`, consuming the entire
input. The vector has a fixed sorted domain equal to `Req(chi,o)`; each entry
maps to exactly the source, unit, anchor, cap and record used by the current
unit checks and the tag reconstruction. Other vector-array indices in a
mathematical model are unobserved, not extra charged sources. Payload is
preserved exactly. ACT and authenticated peer identities are separate inputs
whose named fields are compared to that same decoded `M`.

Injectivity gives: two accepted canonical messages are byte-equal iff all
their typed scalar fields, payload, ordered source domain and in-domain vector
entries are equal. Duplicate sources, noncanonical ordering, padding leaves,
trailing bytes or rebinding an identifier have no well-formed abstraction and
are rejected. A semantic representation must preserve this equivalence; a
numeric uninterpreted message fingerprint alone would not suffice.

**History interpretation.** Preserve decisions by request ID and their whole
decoded message, original authenticated participants, exact debits and initial
delivery. This relation is independent of later revocation and is immutable.
The same trace also maintains cumulative exposure `E_t`; taking its public
closure includes all branches and every historical disclosure.

## D. Transition simulation lemma

### Symbolic projections used by the lemma

The Tamarin theories do not share a running ledger. Their connection is a
documented projection of this single experiment:

- The bilateral-delegation theory's `Right` is a **structurally available
  signed-chain ghost**, not the endpoint's activation flag. Local verification
  of a parent chain may establish this ghost before any SyncBatch. Removing
  signature/activation gates overapproximates structural executions; the
  separate control-signature theorem authenticates each actual signed edge.
  This avoids adding an online-before-redelegation requirement to the protocol.
- The message-authentication projection imports the common fields
  `(d, chi, endpoint, side, holder, public_key)` from such a chain. Its local
  root field, where represented as `root=d`, is a dummy: the projection erases
  the original root identifier. It does **not** equate the two theories' full
  `Right` terms. Original-root provenance is established by the structural
  theory and authorization-state induction, not by the dummy field.
- A generic control-signature theorem applies to the exact typed full bytes
  of each approval/delegation/ACT/control message. A sender's compromise is
  an explicit origin exception, not a way to avoid subsequent policy checks.
- ACT, authenticated-message and tag verification facts join only on the
  same identities/context and complete message. `CryptoVerified` is an
  intermediate event, never an admission. The state transition subsequently
  determines eligibility and actual debit. Ideal per-leaf credentials are
  connected to actual RDF paths by P0/P1, not by assuming a Tamarin free
  constructor is already a computationally secure hash.
- Session-secret exposure is represented independently of identity-key
  compromise. Channel-origin theorems permit either a matching honest send,
  an exposed sender identity key, or an exposed matching peer/context/session
  credential. They do not claim a TLS handshake or perfect forward secrecy.

Thus the claimed mechanization consists of checked projections and state
obligations plus this explicit mathematical refinement. There is no claim
that running the separate theories mechanically proves their composition.

**Lemma P5.1.** Starting from the approved initial state, every finite concrete
prefix that executes the frozen guards admits the above abstraction, and its
ledger projection is a sequence of the state model's transitions or stutters.
Outside `BadSig` and `BadChan`, the records also have the authenticated origins
and participant bindings claimed in P2. The derivation interpretation and
message relation persist through every transition.

**Proof.** Induct on the number of commits, with local/network actions inserted
as stutters. The cases are exhaustive for the frozen protocol:

- **Issue.** A new approved source creates precisely its numbered units and
  initial current record. Existing approving-record/source keys cannot reissue
  or reset units. The Authority gives caller and stack identical restricted
  initial keys, establishing P0 at the root. Immutable approval/cap bindings
  initialize the ancestry correspondence.
- **Publish a local delegation.** It may extend the local derivation and
  exposure transcripts, but leaves ownership unchanged. Thus it cannot enable
  a state admission before synchronization. A malformed/wrong-key bundle is
  allowed attacker behavior; it creates no altered verification interpretation.
- **SyncBatch.** For each new signed description in parent-to-child order,
  compare every unit in the *full projection* of its scope with the actual
  parent cap, holder and preceding record in the provisional state. Checks
  also ensure child authorization and cap ancestry link to their respective
  actual parents. The cap recursion extends by exactly the public recorded
  Split/Grant steps. Per-unit ownership moves once, restrictions intersect
  existing restrictions, and the corresponding-cap map for original ancestors
  is copied and extended. All registered prefixes are equality/validity
  checks, with no transfer. Finite induction over batch entries preserves the
  relation; one final atomic commit publishes all of them. Any failure
  discards the provisional state. This is also why a partial scope check is
  insufficient.
- **New Admit.** Compare ACT and authenticated peers with decoded `M`; verify
  both current authorization paths and all dependencies. For each required
  source, the same vector entry selects the current unit, cap, record and
  leaf used in tag verification. Enforce `H_u`, scope, expiry, known-unused,
  current ownership and exact source set. Atomically record the decision,
  all selected debits and ACT-bound initial delivery. The abstraction has
  precisely those rows and message. Several actions on a unit still update
  its one use bit, so they cannot increase the count. The sender need not be
  honest for this correspondence; a known-secret tag is simply a possible
  valid input.
- **Reject/retry.** A failure changes none of the debit state. A successful
  exact decision lookup checks the original peer and canonical bytes and
  returns the stored result without new debits or initial delivery. ID reuse
  with unequal bytes is rejected. The history maps are consequently preserved.
- **Revoke/cancel.** Record the authenticated authorized target and dependency
  closure. For an unregistered target, verify the signed ancestor chain before
  recording the tombstone; no transfer is performed. All future activation
  and new-admission checks consult these persistent dependencies. Merely
  delivering a message, or replacing service contact information, is not this
  event and does not change the prior trace.
- **Return.** Recompute the exact current unused/unexpired target-subtree set;
  uncertain or spent units cannot be returned. Follow the original
  authorization parent chain to the nearest policy-eligible parent. The
  ancestry invariant supplies each group's actual corresponding cap. Return
  updates only these units to that existing cap/holder under a fresh record;
  it preserves the anchor, consumed history, inherited restrictions and
  tombstones. The stored cap history remains immutable, so reconstruction
  yields the original parent keys. Cap depth is allowed to decrease. Fresh
  records and preservation of restrictions are necessary to the induction;
  new roots or erased revocations are never introduced. If no eligible parent
  exists, escrow makes no new spendable ownership. A later legitimate return
  cycle is a different state transition, not a replay of this one.
- **Replacement/contact/time/approval.** A new ACT/contact has no issuance
  effect and cannot reset a unit. Time advances only the deadline predicate.
  New approvals outside the original policy create a distinct approved
  setup, never migrate old units. Root identity rebinding is not authorized
  by the old exposed identity key alone. Ineligible cases are rejected or
  escrowed according to the same policy.

These cases establish the induction. Cryptography justifies authenticated
origins or outside-closure secrecy; it is not used to claim that a signature
by an authorized-looking but revoked key is currently authorized. QED.

## E. Admission composition theorem

**Theorem P5.2.** In the joint experiment, outside the exceptional union, every
new admission has all of the following simultaneously:

1. Applicable bilateral authorization paths from their protected approvals,
   matching authenticated key identities and ACT session/context.
2. The exact complete message used for each source tag, key reconstruction,
   ownership check, stored decision and initial service delivery.
3. Exactly one previously unused unit from each approved required source,
   no extra/missing source, no previous debit of any selected unit, and no
   reset or increase of issuance through delegation, return or replay.
4. Valid current record and inherited limits for each unit, no committed
   revoked/cancelled dependency, and no unauthorized relaxation by recovery.
5. For each tag, either (a) its secret was derivable from actual cumulative
   disclosures at the attempt, or (b) that exact tag/message was legitimately
   obtained, or (c) the protected fresh authentication bound is violated.
   On the complement of `BadPCDF`, case (c) is absent. An honestly submitted
   request is included in (b); copying it cannot produce a second debit.

**Proof.** P5.1 establishes a single trace and unique object mapping. P2 applies
to the actual checked credentials, and P3/P4 to that trace's actual current
units and dependencies. If a tag for an outside-closure secret was neither
legitimately obtained on the same bytes nor generated by its honest sender for
this operation, feed the same key history, exposure history and canonical
bytes to P1's online authentication game. This is a fresh winning attempt.
If it was obtained earlier on the same bytes, it is a replay and P3's decision
and use-state induction applies instead. Thus no uncovered case remains. P0
provides the common key interpretation needed to use P1 on the selected
current cap. QED.

This theorem does **not** say all admissions are initiated by honest Agents,
or that possession of an ancestor seed is harmless. It says which capabilities
and current approved units a malicious but authenticated holder may use.

## F. Three composed scenario theorems

The following are scenario-specific conjunctions with explicit failure-event
partitions. They share detailed lemmas, but none is a relabeling of P1 alone.

### S1: one compromised member

The attacker compromises one Agent (which may hold several authorizations),
retains all its historical materials, and controls the network. Let `E_t`
include everything actually exposed by that compromise, earlier disclosures,
and allowed local computations. The protected target is any key outside this
closure, or any new admission violating one of the following four conditions:
applicable bilateral permission/context, current ownership/limits, exact
approved debit, and no repeated consumption. The attacker is allowed to spend
remaining legitimately held units and derive ordinary descendants.

**Theorem S1.** Protected-key recovery, fresh outside-closure authentication,
or any such admission violation has probability at most the exceptional
union bound. Honest feasible requests remain executable under P0 and the
state preconditions, including a request using multiple required sources.

**Proof by first successful attack.**

- Recovering an ancestor or other protected secret, or inventing a fresh tag
  outside the accumulated derivation closure, instantiates P1. P0 establishes
  which exact derivation history that target denotes.
- Using the acquired identity key to sign is not a forgery. If such a request
  changes the collaboration, service identity, authorization, action, payload
  or source vector, P2/P5 bind the exact changed context and require its
   applicable bilateral paths. An unseen control signature under an unexposed
   key triggers `BadSig`; an unauthorized channel context under unexposed
   relevant identity/session credentials triggers `BadChan`. An exposed
   session may produce packets, but cannot avoid the same state checks.
- Even with enough secrets to make every tag, a copied/transferred/consumed
  unit fails the P3 current-owner/record/use invariant. A replay of a valid
  request is either rejected or returns its one existing decision. It cannot
  debit again, omit a required source, or mint a new position.
- P5 makes the key target, changed message and charged units the same objects
  at the same commit; separate successes in unrelated abstractions are not
  being combined. P0's correctness and an enabled honest state transition
  exclude the explanation that every request is rejected.

All cases of the defined attack are exhausted. QED. No promise is made to
hide a descendant from a compromised member that once held its ancestor.

### S2: joint cross-branch compromise and sharing

Now the attacker controls a coalition, pools *all* present/historical secrets,
and interleaves requests, transfers and local derivations. The target closure
is `Cl(union E_t^j)`, not the intersection of individual rights and not a
conjunction of independent single-member security experiments. Permitted
collaborative use of owned rights is not an attack success.

**Theorem S2.** Except within the same exceptional union bound (using the
coalition's total budgets/exposures), the coalition cannot recover a target
outside its joint closure or turn pooled materials into an admission that
violates bilateral context, a single caller's actual current holdings, exact
multisource accounting, or single consumption.

**Proof by attack mechanism.**

1. Combining seeds from different branches to recover an unseen parent or
   branch is the *joint* P1 game. P0's relation cover prevents interpreting
   different action/slot projections as an invented Cartesian product;
   ordinary parent derivation remains allowed when a parent really is known.
2. Pooling tags from different requests cannot authenticate a new mixed
   request: every tag covers the identical full canonical `M`. If a necessary
   secret is unknown and no such full-message tag was obtained, P1 applies.
   If all relevant secrets are known, this is not a crypto failure; proceed
   to the state checks instead of incorrectly invoking unforgeability.
3. P2 compares the chosen caller/service authorizations and ACT with that
   same `M`. A valid key belonging to another colluder, or two authorizations
   belonging to one Agent, does not bypass those exact bindings. P3 requires
   all selected units to belong to the named current caller authorization.
   Units held under different authorizations must first undergo an allowed
   state transfer; secret sharing itself performs no transfer.
4. P3 counts positions, not tags or actions. Cloning a bundle, issuing
   competing descriptions or using another action at the same position
   cannot create a second successful debit. The serial commit order chooses
   a valid first transition and makes the conflicting later one fail.
5. P5 carries these facts through arbitrary interleavings in one trace;
   P0 preserves legitimate joint-source functionality.

These alternatives cover both unknown-key and all-keys-known coalitions.
The latter are precisely why P1 alone is insufficient. QED.

### S3: revocation, return and replacement

The attacker retains revoked descendants' history and controls network
delivery, possibly in coalition. Let `t_rev` be the endpoint's committed
revocation. The safety target is a *new* admission or activation after that
commit; exact old-decision queries are excluded. Distinguish the unconditional
state claims from the conditional new-branch confidentiality claim.

**Theorem S3.** Outside `BadSig`/`BadChan`, after `t_rev` no new admission or
activation can depend on the revoked authorization or its descendants. Return
does not revive earlier ownership records, add units, refund spent units, or
widen inherited restrictions. A replacement must match its own eligible
authorization and authenticated identity/ACT. In addition, for every protected
new capability block whose *actual parent derivation input* remains outside
the coalition's cumulative closure, and whose new keys are securely delivered
to an eligible uncompromised recipient, key recovery or fresh authentication
for that block is bounded by P1. Successful honest use after recovery follows
from P0 with the new current state, not from generating a new anchor.

**Proof, following the attack opportunities.**

1. **Race with revocation.** A request committed before `t_rev` may be valid.
   A later commit observes the persistent tombstone and whole authorization
   path, including unregistered late descendants. P4 rejects that dependency.
   Replaying a previously admitted request invokes P3's lookup only; it does
   not create a post-revocation new admission.
2. **Abuse return.** P4 recomputes the unused/unexpired subset and original
   nearest eligible ancestor at the return commit. P3 ensures that consumed
   units are excluded and cannot be reset. P5's ancestry correspondence maps
   the returned cap to an actual original ancestor. Preserved `H_u` constrains
   that parent's broader keys; cap restoration alone does not relax policy.
3. **Exploit the restored cap (ABA).** A delayed old description may again
   name the correct parent cap after return, but its preceding ownership
   record differs from fresh `ell_ret`. P3/P4's compare of all current fields
   blocks activation. Old tombstones remain effective. A subsequent honest
   transfer names `ell_ret` and a fresh child cap, so it can pass; P0/P5 show
   its keys agree with stack reconstruction under the unchanged anchor.
4. **Derive the replacement's secret.** Old descendant keys do not traverse
   back through Grant/Split. P1, not that syntactic observation alone, bounds
   recovering the actual secret parent input or new branch. For a union of
   new cover blocks, apply the joint P1 budget/event bound to all protected
   targets; do not silently infer secrecy merely from the parent's continued
   authorization. If a relevant parent input is in the accumulated closure,
   the claim for that block is deliberately absent.
5. **Use leaked parent secrets anyway.** Even when item 4's condition fails,
   possessing the new branch key does not provide a different unexposed
   identity key or change its authorization/ACT. The protected impersonation
   claim also requires the replacement's relevant session-authentication
   secrets to remain unexposed. P2 checks the authenticated identity labels
   and both paths; P3/P4 still reject old records, revoked holders and spent
   units. A legitimately compromised new recipient can of course spend its
   current units; this is outside the protected-replacement premise.
6. **Replace the service.** The caller must establish matching new contact
   and ACT with an eligible replacement service identity. An old service key
   cannot sign as an unexposed new identity outside `BadSig`; forging a
   protected replacement channel additionally requires unexposed relevant
   session credentials or else falls within the exposure exception. Signing
   as itself does not bypass P4. P3 preserves caller issuance/use state because
   contact replacement has no such state write. Previously admitted work is
   not silently redirected to the new member.

P5 places all six steps in one trace; their crypto, identity and state objects
coincide. The result combines P0, P1, P2, P3 and P4 rather than using any one
as a substitute for the others. QED.

## G. Necessity checks and claim limits

The following removals invalidate different portions of the composition:

- Omit full-message binding: independently valid per-source tags can be
  transplanted across payloads or contexts.
- Omit current-holder/record checking: shared or historical keys can create
  new spending rights without a transfer.
- Omit persistent used bits or exact retries: tag cloning permits another
  debit even though every primitive is ideal.
- Omit fresh return records: a delayed pre-return description can match the
  restored parent cap/holder (ABA).
- Omit persistent inherited restrictions: restoring a broad parent cap can
  re-enable actions forbidden by a prior committed narrowing.
- Expose the actual parent input: compute the fresh child's Grant directly;
  public fresh identifiers cannot heal this exposure.
- Collapse caller and service eligibility: a valid caller credential can
  mask an ineligible service, defeating the bilateral claim.

Executable negative controls and component countermodels are supporting
evidence for these necessities, not replacements for the preceding proofs.
This document proves a protocol-model composition under explicit interfaces.
It does not claim UC security, computational soundness of arbitrary Tamarin
equational theories, concrete SHA-256 pseudorandomness, identity recovery after
all approved recovery keys leak, or liveness under indefinite packet loss.
