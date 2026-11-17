"""Functional GReDAC RDF reference, not production cryptography.

This is an executable encoding profile for the frozen Section IV syntax.
All keys used by the accompanying checks are public deterministic fixtures.
The endpoint starts from restricted initial bundles; no master/anchor secret is
required for endpoint reconstruction. SHA-256 computations are functional
checks, not evidence that SHA-256 implements a random oracle.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable, Mapping

VERSION = b"SACReD-v1.2-PCDF-reference-v1"
KEY_BYTES = 32


def enc(*parts: bytes) -> bytes:
    """Injective typed-profile framing with an explicit field count."""
    if len(parts) >= 2**32 or any(not isinstance(p, bytes) or len(p) >= 2**32 for p in parts):
        raise ValueError("byte fields and U32 lengths required")
    return (len(VERSION).to_bytes(4, "big") + VERSION + len(parts).to_bytes(4, "big")
            + b"".join(len(p).to_bytes(4, "big") + p for p in parts))


def dec(raw: bytes, arity: int | None = None) -> tuple[bytes, ...]:
    def take_u32(off: int) -> tuple[int, int]:
        if off + 4 > len(raw):
            raise ValueError("truncated length")
        return int.from_bytes(raw[off:off+4], "big"), off + 4
    version_len, off = take_u32(0)
    if off + version_len > len(raw) or raw[off:off+version_len] != VERSION:
        raise ValueError("version")
    off += version_len
    count, off = take_u32(off)
    if arity is not None and count != arity:
        raise ValueError("arity")
    parts = []
    for _ in range(count):
        n, off = take_u32(off)
        if off + n > len(raw):
            raise ValueError("truncated field")
        parts.append(raw[off:off+n])
        off += n
    if off != len(raw):
        raise ValueError("trailing bytes")
    return tuple(parts)


def u64(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**64:
        raise ValueError("U64 integer required")
    return value.to_bytes(8, "big")


def h(kind: bytes, seed: bytes, label: bytes = b"") -> bytes:
    if kind not in (b"anchor", b"split", b"grant", b"spend", b"auth"):
        raise ValueError("operation domain")
    if len(seed) != KEY_BYTES:
        raise ValueError("seed width")
    if kind == b"split" and label not in (b"\x00", b"\x01"):
        raise ValueError("split bit")
    if kind == b"grant" and not label:
        raise ValueError("capability identifier")
    if kind == b"spend" and label:
        raise ValueError("spend label")
    return sha256(enc(kind, seed, label)).digest()


def split(seed: bytes, suffix: str) -> bytes:
    if any(bit not in "01" for bit in suffix):
        raise ValueError("binary suffix")
    for bit in suffix:
        seed = h(b"split", seed, bytes([int(bit)]))
    return seed


def region(prefix: str, width: int) -> frozenset[int]:
    if width < 0 or len(prefix) > width or any(bit not in "01" for bit in prefix):
        raise ValueError("prefix geometry")
    first = int(prefix or "0", 2) << (width-len(prefix))
    return frozenset(range(first, first + 2**(width-len(prefix))))


def cover(scope: frozenset[int], width: int, prefix: str = "") -> tuple[str, ...]:
    """Maximal complete subtree cover, sorted left-to-right."""
    if not scope <= region("", width):
        raise ValueError("out-of-domain leaf")
    leaves = region(prefix, width)
    if not leaves.intersection(scope):
        return ()
    if leaves <= scope:
        return (prefix,)
    return cover(scope, width, prefix+"0") + cover(scope, width, prefix+"1")


@dataclass(frozen=True)
class Geometry:
    action_bits: int
    slot_bits: int
    actions: frozenset[int]
    capacity: int

    def __post_init__(self):
        if self.action_bits < 1 or self.slot_bits < 1 or not 0 < self.capacity <= 2**self.slot_bits:
            raise ValueError("geometry")
        if not self.actions or any(not 0 <= a < 2**self.action_bits for a in self.actions):
            raise ValueError("action domain")

    @property
    def width(self) -> int:
        return self.action_bits + self.slot_bits

    @property
    def valid(self) -> frozenset[int]:
        return frozenset(self.point(o, i) for o in self.actions for i in range(self.capacity))

    def point(self, action: int, slot: int) -> int:
        if action not in self.actions or not 0 <= slot < self.capacity:
            raise ValueError("padding/action/position")
        return action * 2**self.slot_bits + slot

    def address(self, point: int) -> str:
        if point not in self.valid:
            raise ValueError("invalid leaf")
        return format(point, f"0{self.width}b")


@dataclass(frozen=True)
class Capability:
    gamma: bytes
    parent: bytes | None
    source: bytes
    chi: bytes
    endpoint: bytes
    anchor: bytes
    geometry: Geometry
    scope: frozenset[int]

    @property
    def prefixes(self) -> tuple[str, ...]:
        return cover(self.scope, self.geometry.width)


@dataclass(frozen=True)
class Bundle:
    gamma: bytes
    blocks: tuple[tuple[str, bytes], ...]

    def seed(self, prefix: str) -> bytes:
        return dict(self.blocks)[prefix]


def validate_bundle_shape(cap: Capability, bundle: Bundle) -> None:
    if bundle.gamma != cap.gamma or tuple(p for p, _ in bundle.blocks) != cap.prefixes:
        raise ValueError("noncanonical/mismatched bundle")
    if any(len(seed) != KEY_BYTES for _, seed in bundle.blocks):
        raise ValueError("seed length")


def initial_capability(master: bytes, source: bytes, chi: bytes, endpoint: bytes,
                       anchor: bytes, gamma: bytes, scope: frozenset[int],
                       geometry: Geometry) -> tuple[Capability, Bundle]:
    if not all((source, chi, endpoint, anchor, gamma)) or not scope or not scope <= geometry.valid:
        raise ValueError("initial binding/scope")
    binding = enc(source, chi, endpoint, VERSION, b"action-before-slot",
                  u64(geometry.action_bits), u64(geometry.slot_bits))
    kappa = h(b"anchor", master, enc(anchor, binding))
    cap = Capability(gamma, None, source, chi, endpoint, anchor, geometry, scope)
    bundle = Bundle(gamma, tuple((p, h(b"grant", split(kappa, p), gamma)) for p in cap.prefixes))
    return cap, bundle


def derive_child(parent: Capability, parent_bundle: Bundle, gamma: bytes,
                 scope: frozenset[int]) -> tuple[Capability, Bundle]:
    validate_bundle_shape(parent, parent_bundle)
    if not gamma or gamma == parent.gamma or not scope or not scope <= parent.scope:
        raise ValueError("child identifier/scope")
    child = Capability(gamma, parent.gamma, parent.source, parent.chi, parent.endpoint,
                       parent.anchor, parent.geometry, scope)
    blocks = []
    for q in child.prefixes:
        parents = [p for p in parent.prefixes if q.startswith(p)]
        if len(parents) != 1:
            raise ValueError("unique parent cover ancestor")
        p = parents[0]
        blocks.append((q, h(b"grant", split(parent_bundle.seed(p), q[len(p):]), gamma)))
    return child, Bundle(gamma, tuple(blocks))


def local_leaf(cap: Capability, bundle: Bundle, point: int) -> bytes:
    validate_bundle_shape(cap, bundle)
    if point not in cap.scope:
        raise ValueError("leaf outside capability")
    address = cap.geometry.address(point)
    prefix, = [p for p in cap.prefixes if address.startswith(p)]
    return split(bundle.seed(prefix), address[len(prefix):])


def local_tag(cap: Capability, bundle: Bundle, point: int, message: bytes) -> bytes:
    return h(b"auth", h(b"spend", local_leaf(cap, bundle, point)), message)


class EndpointPCDF:
    """Reconstruction from certified initial restricted material only.

    register() checks public derivation consistency, not authorization or budget
    validity. The state proof must justify which records may be registered.
    """
    def __init__(self, initial: Capability, bundle: Bundle):
        if initial.parent is not None:
            raise ValueError("initial capability required")
        validate_bundle_shape(initial, bundle)
        self.initial = initial.gamma
        self.initial_bundle = bundle
        self.records: dict[bytes, Capability] = {initial.gamma: initial}

    def register(self, child: Capability) -> None:
        if child.gamma in self.records:
            if self.records[child.gamma] != child:
                raise ValueError("identifier rebinding")
            return
        parent = self.records[child.parent]
        if (not child.scope or not child.scope <= parent.scope or
            (child.source, child.chi, child.endpoint, child.anchor, child.geometry) !=
            (parent.source, parent.chi, parent.endpoint, parent.anchor, parent.geometry)):
            raise ValueError("scope or source binding")
        self.records[child.gamma] = child

    def block(self, gamma: bytes, prefix: str) -> bytes:
        cap = self.records[gamma]
        if prefix not in cap.prefixes:
            raise ValueError("not a canonical block")
        if gamma == self.initial:
            return self.initial_bundle.seed(prefix)
        parent = self.records[cap.parent]
        p, = [p for p in parent.prefixes if prefix.startswith(p)]
        return h(b"grant", split(self.block(parent.gamma, p), prefix[len(p):]), gamma)

    def leaf_key(self, gamma: bytes, point: int) -> bytes:
        cap = self.records[gamma]
        if point not in cap.scope:
            raise ValueError("out-of-scope target")
        address = cap.geometry.address(point)
        p, = [p for p in cap.prefixes if address.startswith(p)]
        return split(self.block(gamma, p), address[len(p):])

    def tag(self, gamma: bytes, point: int, message: bytes) -> bytes:
        return h(b"auth", h(b"spend", self.leaf_key(gamma, point)), message)

    def path(self, gamma: bytes, point: int) -> tuple[tuple[bytes, bytes], ...]:
        """An ideal typed path rooted at an initial restricted block."""
        cap = self.records[gamma]
        if point not in cap.scope:
            raise ValueError("out-of-scope point")
        addr = cap.geometry.address(point)
        q, = [p for p in cap.prefixes if addr.startswith(p)]
        return self.block_path(gamma, q) + tuple((b"split", bytes([int(b)])) for b in addr[len(q):])

    def block_path(self, gamma: bytes, q: str) -> tuple[tuple[bytes, bytes], ...]:
        cap = self.records[gamma]
        if q not in cap.prefixes:
            raise ValueError("block")
        if gamma == self.initial:
            return ((b"initial", enc(cap.source, cap.anchor, cap.gamma, q.encode())),)
        parent = self.records[cap.parent]
        p, = [p for p in parent.prefixes if q.startswith(p)]
        return (self.block_path(parent.gamma, p)
                + tuple((b"split", bytes([int(b)])) for b in q[len(p):])
                + ((b"grant", gamma),))


def in_closure(exposed: Iterable[tuple], target: tuple) -> bool:
    """Ideal path reachability; real bitstring collisions belong to ROM Bad."""
    return any(len(p) <= len(target) and target[:len(p)] == p for p in exposed)


def encode_request(rho: bytes, chi: bytes, sid: bytes, caller: bytes, service: bytes,
                   caller_auth: bytes, service_auth: bytes, action: int, payload: bytes,
                   vector: Iterable[tuple[bytes, int, bytes, bytes, bytes]]) -> bytes:
    """Exactly the Section IV M fields, with sorted distinct source entries.

    vector entries are (source, slot, anchor, capability, ownership_record).
    ACT is outside M; its matching context is checked by the admission model.
    """
    entries = tuple(vector)
    if any(entries[i][0] >= entries[i+1][0] for i in range(len(entries)-1)):
        raise ValueError("sources must be strictly ordered and duplicate-free")
    if not all((rho, chi, sid, caller, service, caller_auth, service_auth)):
        raise ValueError("empty request identifier/binding")
    encoded = tuple(enc(s, u64(i), a, g, ell) for s, i, a, g, ell in entries)
    return enc(rho, chi, sid, caller, service, caller_auth, service_auth, u64(action), payload,
               enc(*encoded))


def fixture_key(label: str) -> bytes:
    return sha256(b"PUBLIC-NONSECRET-TEST-FIXTURE:" + label.encode()).digest()
