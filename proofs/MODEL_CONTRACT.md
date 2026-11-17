> 开源副本范围说明：下文保留原 GReDAC 证明论述及历史证据说明。其中 inputs/paper/review、历史日志和生成型 SMT 文件指原完整归档，未全部随本最小副本分发。可重现步骤和本包实际内容以本目录 README.md 为准；不得把原记录理解为本轮重新证明的结果。

# Shared proof contract

This is a formalization of the frozen inputs, not a new protocol. The original
plan's phrase “scenario corollaries” is superseded by the user's clarification:
S1, S2 and S3 must each have an end-to-end attack definition and a composition
proof using several detailed results.

## 1. Execution and trust

A trace is any finite prefix of a locally serialized receiving-stack execution.
The number of members, sources, units, sessions, roots, and delegation steps is
arbitrary and finite, subject to approved finite limits; a computational
execution is polynomially bounded in the security parameter. Each source has
one immutable collaboration and receiving endpoint. Joint charging of multiple
sources occurs at that endpoint. There is no cross-endpoint transaction theorem.

The receiving stack executes the specified guards and commits atomically and
durably, retaining records and rejecting rollback. Authority and user approval
keys are protected. Agent identity/session keys and capability material may be
adaptively compromised. Authenticated confidential delivery is an explicit
cryptographic interface assumption; an Agent compromise does not expose the
stack's restricted verification material. Time is the trusted local comparison
used at a commit. Real clock accuracy, implementation refinement, crash recovery
and external business-effect exactly-once execution are outside the claim.

C1–C5 permit arbitrary malicious descriptions, known-key signing, cloning,
sharing, retained secrets, local pre-registration derivation, and network
suppression/reordering. Messages being signed does not make their sender
authorized. A compromised identity key authenticates the corresponding key
identity; the protocol cannot distinguish its legitimate process from the
attacker holding that key. Indefinite network suppression defeats progress, not
the safety claims below.

## 2. Common objects and encodings

An independently exposed session-authentication secret also permits origin
exceptions for that peer pair, collaboration and session, even without
identity-key compromise. Claims excluding replacement impersonation require
both relevant identity and session credentials to remain unexposed. The
protocol still checks current authorization and units for exposed sessions.

- A unit is `u=(source,slot)`, not an action–slot pair. Different actions at a
  position share one consumption bit.
- Authorization records form two same-side forests. Each immutable record
  binds identity, collaboration, role, scope, expiry, remaining delegation
  depth and a unique parent (or protected approval for a root).
- Capability records form a separate forest. Each immutable record binds
  source, collaboration, endpoint, anchor, geometry, exact action–slot scope,
  one derivation parent, and its holder authorization/transfer record.
- A current unit points to an issued source, registered capability, holder
  authorization, and current ownership record; its inherited restrictions,
  use history, and revocation dependencies persist through return.
- Request `M=(rho,chi,sid,A,R,dA,dR,action,payload,V)` uses the frozen ordered,
  duplicate-free vector `V=[(source,slot,anchor,capability,record)]`. Its domain
  equals the approved required-source set. Typed length-delimited canonical
  encoding is injective. ACT is separate and must agree with `M` and the
  authenticated participants at the same admission.
- A public identifier is a name, not entropy. Registration checks uniqueness
  and rejects inconsistent rebinding. Honest choices must not disclose secrets.

The proof may use mathematical arrays for vectors and histories. The
refinement argument must relate only in-domain vector entries and every
semantically relevant field to the exact encoded request; a free numeric
“message hash” cannot substitute for this obligation.

## 3. State transitions and effect points

| Operation | Effect point | Obligations |
|---|---|---|
| Approve/issue | First durable setup commit | Protected approval; immutable bindings; no reissuance/reset on replay |
| Construct/send delegation | No ledger effect | May be malicious; possession alone gives no current ownership |
| SyncBatch | One successful durable batch commit | Verify full descriptions and both applicable authorization paths; process new parents before children; compare every projected unit's current parent cap/holder/record; preserve narrower inherited restrictions; registered prefixes are not retransferred; failure leaves state unchanged |
| Issue/use ACT | Signature creates a credential; admission decides applicability | Both identities, authorizations, collaboration, session and expiry match; no per-request ACT reissuance required |
| Admit new request | Guard evaluation and all debits/decision/initial delivery in one commit | Current bilateral eligibility; exact message/tag and current ownership; one unused unit per required distinct source; failure has no debit |
| Retry | Lookup of immutable decision | Original authenticated participants and identical request/bytes; same ID with different request rejected; no second debit or initial delivery |
| Revoke | Durable tombstone commit | Authorized control; authorization-descendant closure, including late registration; no retroactive cancellation of prior decisions |
| Return | Durable rechecked recovery commit | Exact currently owned, confirmed-unused, unexpired subset; original nearest eligible authorization ancestor with corresponding cap; same anchor; fresh record; preserve consumption/restrictions/revocation; absent parent means escrow |
| Service replacement | New eligible contact/ACT | No issuance, consumption reset, or return of caller units |

The default request-ID interpretation is endpoint-scoped uniqueness with exact
conflict rejection, as in the frozen text. A history lookup is not a new
admission and is excluded from post-revocation new-admission claims.

## 4. Crypto/state interfaces

RDF uses the frozen typed `anchor`, `split`, `grant`, `spend`, and `auth` RO
domains. Canonical covers represent exact relations, not products of action
and slot projections. Split and Grant do not commute. The stack reconstructs
from restricted initial bundles along registered derivation records; it is
never given the source master or anchor seed by this proof's interface.

Let `E_t` contain all actually exposed secrets up to time t, including prior
wide bundles and locally derived material. `Cl(E_t)` is their public-operation
closure, including all colluding principals. A current nominal authorization
does not reduce this set. Key recovery freshness is checked at experiment end;
online fresh-tag forgery freshness is checked at the attempted success.
Observed valid tags authorize no new message. Known-tag replay is handled by
state rules, not counted as a cryptographic forgery.

Key agreement (P0) maps each registered `(anchor,capability,action,slot)` to
the same concrete derivation path at caller and stack. P1 bounds success
outside exposure closure. P2 authenticates the approved/signed records and
context. P3/P4 restrict which cryptographically valid requests can create a
new admission. P5 must show that these refer to the **same** request, records,
unit history and commit; it cannot multiply unrelated model successes.

For return, the corresponding parent cap must be obtained from actual capability
ancestry linked to the original authorization ancestry. Its existence and the
preservation of that linkage are proof obligations, not new recovery guards
assumed true. Cap depth can decrease on return; no monotonic-depth invariant
is valid. A unit can legitimately be returned in more than one distinct cycle.

## 5. What each proof can establish

1. Mathematical induction proves arbitrary-depth cover/reconstruction facts.
2. A classical-RO game proof bounds cumulative-exposure key recovery and fresh
   tag forgery; reference SHA-256 tests do not establish the RO assumption.
3. Tamarin checks specific symbolic all-traces and exists-trace formulae for
   its exact model. Abstract eligibility/ledger premises remain interfaces.
4. SMT checks base and transition-preservation VCs. The manual trace induction,
   operation completeness and abstraction relation must be supplied. `unknown`
   or timeout is not evidence of validity.
5. An integrated witness/negative control supports executability and interface
   consistency for concrete traces. It is not an unbounded theorem.
6. Scenario theorems combine attack-event partitions with all necessary
   interfaces. Conditional new-branch secrecy must not be upgraded to recovery
   from a leaked parent seed.

No single count of solver successes establishes a top-venue standard. The
deliverable must expose premises, theorem statements, proofs, replay inputs,
negative controls, unresolved limitations and independent audit observations.

## 6. Symbolic projection clarification after cross-review

The structural bilateral model's chain-availability event is a proof ghost,
which can occur on local verification before endpoint activation. The model
overapproximates structure; separate generic signature-origin results supply
authentication. The credential projection retains
`(d,chi,endpoint,side,holder,public_key)` and erases the structural root field;
a local dummy `root=d` is not a claim that all real authorizations are roots.
Only state registration flags authorize spending. These projections preserve
offline recursive delegation and do not add per-delegation online contact.
