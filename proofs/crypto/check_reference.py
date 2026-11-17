"""Reproducible functional and negative-condition checks for the RDF profile."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import hashlib
import itertools
import json
import random

from reference import (Bundle, EndpointPCDF, Geometry, cover, dec, derive_child, enc,
                       encode_request, fixture_key, h, in_closure,
                       initial_capability, local_leaf, local_tag, region, split)

HERE = Path(__file__).resolve().parent


def all_subsets(values):
    values = tuple(values)
    for mask in range(1 << len(values)):
        yield frozenset(v for j, v in enumerate(values) if mask & (1 << j))


def independent_cover(scope, width):
    # Enumerate every candidate region; retain complete regions with no complete
    # immediate parent. This is independent of the recursive cover algorithm.
    out = []
    for depth in range(width + 1):
        for bits in itertools.product("01", repeat=depth):
            p = "".join(bits)
            if region(p, width) <= scope and (not p or not region(p[:-1], width) <= scope):
                out.append(p)
    return tuple(sorted(out))


def run():
    counts = {"cover_scopes": 0, "nested_scope_pairs": 0,
              "local_endpoint_leaf_equalities": 0, "recursive_depth_cases": 0,
              "request_mutations": 0, "negative_conditions": 0,
              "encoding_checks": 0}
    named = []

    def record(name, value=True):
        assert value, name
        named.append(name)

    def rejects(name, function):
        try:
            function()
        except (ValueError, KeyError):
            counts["negative_conditions"] += 1
            named.append(name)
        else:
            raise AssertionError(name)

    geo = Geometry(1, 2, frozenset({0, 1}), 4)
    initial, initial_bundle = initial_capability(fixture_key("master"), b"s", b"chi", b"G",
                                                 b"a", b"root", geo.valid, geo)
    for scope in all_subsets(range(8)):
        assert cover(scope, 3) == independent_cover(scope, 3)
        covered = frozenset().union(*(region(p, 3) for p in cover(scope, 3)))
        assert covered == scope
        counts["cover_scopes"] += 1
    for parent_scope in all_subsets(range(8)):
        if not parent_scope:
            continue
        parent, pb = derive_child(initial, initial_bundle, b"parent", parent_scope)
        endpoint = EndpointPCDF(initial, initial_bundle)
        endpoint.register(parent)
        for child_scope in all_subsets(sorted(parent_scope)):
            if not child_scope:
                continue
            gamma = enc(b"child", bytes(sorted(child_scope)))
            child, cb = derive_child(parent, pb, gamma, child_scope)
            endpoint.register(child)
            for q in child.prefixes:
                ancestors = [p for p in parent.prefixes if q.startswith(p)]
                assert len(ancestors) == 1
            for point in child_scope:
                assert local_leaf(child, cb, point) == endpoint.leaf_key(child.gamma, point)
                counts["local_endpoint_leaf_equalities"] += 1
            counts["nested_scope_pairs"] += 1

    cap, bundle = initial, initial_bundle
    endpoint = EndpointPCDF(initial, initial_bundle)
    for depth in range(1, 65):
        scope = cap.scope if depth % 3 else frozenset(x for x in cap.scope if x % 2 == 0)
        cap, bundle = derive_child(cap, bundle, b"depth-"+str(depth).encode(), scope)
        endpoint.register(cap)
        for point in scope:
            assert local_leaf(cap, bundle, point) == endpoint.leaf_key(cap.gamma, point)
        counts["recursive_depth_cases"] += 1

    # A non-Cartesian joint scope: action 0 permits position 0, action 1 permits 3.
    joint = frozenset({geo.point(0, 0), geo.point(1, 3)})
    child, cb = derive_child(initial, initial_bundle, b"joint", joint)
    rejects("joint-scope-not-product", lambda: local_leaf(child, cb, geo.point(0, 3)))
    rejects("parent-scope-widening", lambda: derive_child(child, cb, b"wider", geo.valid))
    rejects("noncanonical-seed-package", lambda: derive_child(initial,
            Bundle(initial.gamma, (("0", split(initial_bundle.seed(""), "0")),
                                   ("1", split(initial_bundle.seed(""), "1")))), b"bad", joint))
    narrow_geometry = Geometry(2, 2, frozenset({0, 2}), 3)
    rejects("padding-position", lambda: narrow_geometry.point(0, 3))
    rejects("unapproved-action-code", lambda: narrow_geometry.point(1, 0))

    # Same geometric region, different delegation histories: returned parent
    # seed is reused, but a fresh child capability has a new Grant edge.
    A, Ab = derive_child(initial, initial_bundle, b"A", frozenset({0, 1}))
    C, Cb = derive_child(initial, initial_bundle, b"C", frozenset({0, 1}))
    endpoint = EndpointPCDF(initial, initial_bundle)
    endpoint.register(A)
    endpoint.register(C)
    ap = [endpoint.block_path(A.gamma, p) for p in A.prefixes]
    cp = endpoint.path(C.gamma, 0)
    parentp = [endpoint.block_path(initial.gamma, p) for p in initial.prefixes]
    record("old-descendant-not-an-ancestor-of-new-branch", not in_closure(ap, cp))
    record("same-anchor-restoration", A.anchor == C.anchor == initial.anchor)
    record("fresh-child-functional-key-difference", local_leaf(A, Ab, 0) != local_leaf(C, Cb, 0))
    record("parent-disclosure-defeats-new-branch-closure-condition", in_closure(parentp, cp))
    D, Db = derive_child(C, Cb, b"C-child-later", frozenset({0}))
    endpoint.register(D)
    record("disclosure-closure-includes-later-descendants",
           in_closure(parentp, endpoint.path(D.gamma, 0)))
    record("old-and-new-child-bundles-are-copyable", Bundle(A.gamma, Ab.blocks) == Ab)
    seed = initial_bundle.seed("")
    record("split-and-grant-do-not-commute-in-profile",
           h(b"grant", split(seed, "0"), b"g") != split(h(b"grant", seed, b"g"), "0"))
    counts["negative_conditions"] += 3  # broad-parent disclosure, copying, noncommutation

    base = dict(rho=b"r1", chi=b"chi", sid=b"sid", caller=b"A", service=b"Rj",
                caller_auth=b"dA", service_auth=b"dR", action=0, payload=b"question",
                vector=((b"s", 0, b"a", b"A", b"ell1"),))
    message = encode_request(**base)
    tag = local_tag(A, Ab, 0, message)
    record("endpoint-and-caller-request-tag-equality", tag == endpoint.tag(A.gamma, 0, message))
    for field in ("rho", "chi", "sid", "caller", "service", "caller_auth", "service_auth", "payload"):
        changed = dict(base)
        changed[field] = base[field] + b"-changed"
        assert local_tag(A, Ab, 0, encode_request(**changed)) != tag
        counts["request_mutations"] += 1
    changed = dict(base, action=1)
    assert local_tag(A, Ab, 0, encode_request(**changed)) != tag
    counts["request_mutations"] += 1
    for index in range(5):
        vector = list(base["vector"][0])
        vector[index] = 1 if index == 1 else vector[index] + b"-changed"
        changed = dict(base, vector=(tuple(vector),))
        assert local_tag(A, Ab, 0, encode_request(**changed)) != tag
        counts["request_mutations"] += 1
    rejects("duplicate-required-source", lambda: encode_request(**dict(base, vector=base["vector"]*2)))
    rejects("noncanonical-source-order", lambda: encode_request(**dict(base,
            vector=((b"z",0,b"a",b"A",b"ell1"),(b"s",0,b"a",b"A",b"ell1")))))
    rejects("capability-identifier-rebinding", lambda: endpoint.register(replace(A, scope=frozenset({0}))))
    rejects("cross-endpoint-derivation-rebinding", lambda: endpoint.register(replace(C, gamma=b"C2", endpoint=b"other")))
    record("replaying-tag-is-not-new-cryptographic-forgery", local_tag(A, Ab, 0, message) == tag)
    # No assertion calls this a new spend. The state model owns that decision.

    alphabet = (b"", b"0", b"1", b"\x00", b"a\x00b")
    encodings = {}
    for arity in range(4):
        for fields in itertools.product(alphabet, repeat=arity):
            raw = enc(*fields)
            assert dec(raw, arity) == fields
            assert raw not in encodings or encodings[raw] == fields
            encodings[raw] = fields
            counts["encoding_checks"] += 1
    rejects("trailing-canonical-message-bytes", lambda: dec(message+b"\x00"))
    rejects("truncated-framing", lambda: dec(message[:-1]))

    # A deterministic four-bit toy collision exhibits why symbolic path closure
    # alone is not computational secrecy. It is not a security experiment.
    toy = lambda raw: hashlib.sha256(raw).digest()[0] & 15
    secret_value = toy(b"independent-hidden-seed")
    public_inputs = [b"public-tag-"+str(i).encode() for i in range(128)]
    collision_input = next(x for x in public_inputs if toy(x) == secret_value)
    record("toy-public-value-can-collide-with-unrelated-secret", toy(collision_input) == secret_value)
    counts["negative_conditions"] += 1

    result = {"status":"passed", "kind":"functional checks and negative-condition witnesses",
              "not_a_security_proof":True, "counts":counts, "named_checks":named,
              "source_sha256":{n:hashlib.sha256((HERE/n).read_bytes()).hexdigest()
                               for n in ("reference.py","check_reference.py")},
              "fixture_message_hex":message.hex(),"fixture_tag_hex":tag.hex()}
    (HERE/"REFERENCE_RESULTS.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"status":result["status"],"counts":counts},sort_keys=True))


if __name__ == "__main__":
    run()
