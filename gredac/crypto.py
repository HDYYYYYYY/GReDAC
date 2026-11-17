"""GReDAC RDF typed SHA-256 research instance; NOT HMAC or a standard-model proof.

E and Anchor/Split/Grant/Spend/Auth implement the typed derivation construction.
See docs/METHOD_MAPPING_ZH.md and proofs/crypto/CRYPTO_PROOF.md for scope.
HMAC below is used only for the independent channel / ordinary baseline.
"""
from __future__ import annotations
import copy
import hashlib
import hmac
import json
import os
import secrets
import struct
from functools import lru_cache
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Historical authenticated format/domain version, not the current system name.
# Keep the bytes stable; naming exceptions are documented in docs/NAMING.md.
SCHEME = 'B0-v3-ROM-SHA256-256'
CODEC = 'fixed-op-first-v1'
ACTIONS = {'query': 0, 'summary': 1, 'delete': 2}
# Fixed for the lifetime of a process; default preserves the 8-slot fixture.
ACTION_BITS, SLOT_BITS = 2, int(os.environ.get('GREDAC_SLOT_BITS', '3'))
if not 1 <= SLOT_BITS <= 24:
    raise ValueError('GREDAC_SLOT_BITS must be in [1,24]')
WIDTH = ACTION_BITS + SLOT_BITS
MODES = ('joint', 'signed-local', 'online-authority')
FIELDS = ('scheme', 'context', 'rule_snapshot', 'cooperation', 'guard', 'lane',
          'act', 'caller_identity', 'caller_key_version', 'service_identity',
          'service_key_version', 'caller_right', 'service_right', 'session',
          'request_id', 'actual_operation', 'full_payload')


class Denied(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise Denied(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def ident():
    return secrets.token_hex(32)


def identifier(value):
    require(isinstance(value, str) and len(value) == 64, 'ID_LENGTH')
    try:
        result = bytes.fromhex(value)
    except ValueError:
        raise Denied('ID_ENCODING') from None
    require(result.hex() == value and len(result) == 32, 'ID_ENCODING')
    return result


def E(*parts):
    require(all(isinstance(p, bytes) and len(p) < 2**32 for p in parts), 'E_BYTES')
    return b'B0-v3' + b''.join(struct.pack('>I', len(p)) + p for p in parts)


def parse_e(data):
    require(data.startswith(b'B0-v3'), 'E_HEADER')
    pos, values = 5, []
    while pos < len(data):
        require(pos + 4 <= len(data), 'E_TRUNCATED')
        size = struct.unpack('>I', data[pos:pos+4])[0]
        pos += 4
        require(pos + size <= len(data), 'E_TRUNCATED')
        values.append(data[pos:pos+size])
        pos += size
    require(E(*values) == data, 'E_NONCANONICAL')
    return values


def H(kind, key, payload=b''):
    require(isinstance(key, bytes) and len(key) == 32, 'SECRET_LENGTH')
    require(kind in ('anchor', 'split', 'grant', 'spend', 'auth'), 'HASH_TYPE')
    if kind == 'split':
        require(payload in (b'\x00', b'\x01'), 'BINARY_BIT')
    if kind == 'grant':
        require(len(payload) == 32, 'GID_LENGTH')
    if kind == 'spend':
        require(payload == b'', 'SPEND_EMPTY')
    return hashlib.sha256(E(kind.encode(), key, payload)).digest()


def anchor_secret(master, aid, source, context, guard='G'):
    # slot_width is frozen as U16BE, matching the earlier B0 reference fixture.
    binding = E(source.encode(), context.encode(), guard.encode(), b'B0-v3',
                CODEC.encode(), struct.pack('>H', SLOT_BITS))
    return H('anchor', master, E(identifier(aid), binding))


def split(key, suffix):
    require(all(bit in '01' for bit in suffix), 'GEOMETRIC_PATH')
    for bit in suffix:
        key = H('split', key, bytes([int(bit)]))
    return key


def point(action, slot):
    require(action in ACTIONS and isinstance(slot, int) and 0 <= slot < 2**SLOT_BITS,
            'POINT_RANGE')
    return (ACTIONS[action] << SLOT_BITS) | slot


def bits(value):
    require(isinstance(value, int) and 0 <= value < 2**WIDTH, 'POINT_RANGE')
    return f'{value:0{WIDTH}b}'


def cover(domain):
    nodes = {bits(p) for p in domain}
    require(bool(nodes), 'EMPTY_DOMAIN')
    for width in range(WIDTH, 0, -1):
        for node in sorted(tuple(nodes)):
            if len(node) == width and node.endswith('0') and node[:-1]+'1' in nodes:
                nodes.remove(node)
                nodes.remove(node[:-1]+'1')
                nodes.add(node[:-1])
    return tuple(sorted(nodes))


def domain_for(actions, slots):
    return sorted(point(action, slot) for action in actions for slot in slots)


def by_slot(domain):
    result = {}
    names = {v: k for k, v in ACTIONS.items()}
    for p in domain:
        require(p >> SLOT_BITS in names, 'INVALID_ACTION_CODE')
        result.setdefault(p % 2**SLOT_BITS, []).append(names[p >> SLOT_BITS])
    return {slot: sorted(set(actions)) for slot, actions in result.items()}


@dataclass
class Bundle:
    gid: str
    anchor: str
    domain: tuple[int, ...]
    seeds: dict[str, bytes]

    def leaf(self, p):
        path = bits(p)
        for prefix, key in self.seeds.items():
            if path.startswith(prefix):
                return split(key, path[len(prefix):])
        raise Denied('KEY_OUTSIDE_HELD_DOMAIN')

    def child(self, new_gid, domain):
        identifier(new_gid)
        requested = tuple(sorted(set(domain)))
        require(requested and set(requested) <= set(self.domain), 'CHILD_OUTSIDE_PARENT')
        require(tuple(sorted(self.seeds)) == cover(self.domain), 'NONCANONICAL_PARENT_SEEDS')
        seeds = {}
        for q in cover(requested):
            parents = [p for p in self.seeds if q.startswith(p)]
            require(len(parents) == 1, 'MISSING_CANONICAL_PARENT_SEED')
            p = parents[0]
            seeds[q] = H('grant', split(self.seeds[p], q[len(p):]), identifier(new_gid))
        return Bundle(new_gid, self.anchor, requested, seeds)

    @classmethod
    def initial(cls, gid, aid, root, domain):
        requested = tuple(sorted(set(domain)))
        return cls(gid, aid, requested,
                   {p: H('grant', split(root, p), identifier(gid)) for p in cover(requested)})

    def public_secrets(self):
        # Private transport representation, never public protocol metadata.
        return {p: key.hex() for p, key in self.seeds.items()}

    def tag(self, p, body):
        return H('auth', H('spend', self.leaf(p)), body).hex()


def encode(fields, slots):
    require(set(fields) == set(FIELDS), 'MESSAGE_FIELDS')
    ordered = sorted(slots, key=lambda row: row[0])
    require(len({r[0] for r in slots}) == len(slots), 'DUPLICATE_SOURCE')
    rows = [E(source.encode(), struct.pack('>Q', slot), identifier(aid), identifier(gid),
              install.encode()) for source, slot, aid, gid, install in ordered]
    return E(b'message', *(fields[name] for name in FIELDS), E(b'slots', *rows))


def decode(body):
    values = parse_e(body)
    require(len(values) == len(FIELDS)+2 and values[0] == b'message', 'MESSAGE_FIELDS')
    fields = dict(zip(FIELDS, values[1:-1]))
    vector = parse_e(values[-1])
    require(vector and vector[0] == b'slots' and len(vector) <= 65, 'SOURCE_VECTOR')
    slots = []
    for packed in vector[1:]:
        row = parse_e(packed)
        require(len(row) == 5 and len(row[1]) == 8
                and len(row[2]) == len(row[3]) == 32, 'SOURCE_ROW')
        slots.append((row[0].decode(), struct.unpack('>Q', row[1])[0],
                      row[2].hex(), row[3].hex(), row[4].decode()))
    require(encode(fields, slots) == body, 'NONCANONICAL_MESSAGE')
    return fields, slots


def channel_mac(key, body):
    return hmac.digest(key, b'B0-v3/channel\x00'+body, 'sha256').hex()


class Signer:
    def __init__(self, name):
        self.name = name
        self.private = Ed25519PrivateKey.generate()
        self.contact = X25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    @classmethod
    def persistent(cls, store, name):
        """Retain a control identity across process restarts, like source masters.

        Prototype database contains test private keys; this is not a key vault.
        Only control signing is persisted here; PKI/client keys are external.
        """
        signer = cls(name)
        with store.transaction():
            saved = store.get('control_keys', name)
            if saved is None:
                saved = signer.private.private_bytes(serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
                store.put('control_keys', name, saved)
        signer.private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(saved))
        signer.public = signer.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        return signer

    @property
    def key_ref(self):
        return hashlib.sha256(bytes.fromhex(self.public)).hexdigest()

    def sign(self, value):
        return self.private.sign(E(b'signature', canonical(value))).hex()

    def envelope(self, value):
        return {'body': copy.deepcopy(value), 'signature': self.sign(value)}


@lru_cache(maxsize=256)
def _verification_key(public_bytes):
    # Immutable PUBLIC key parsing only. Every message still executes verify;
    # no signature, identity authorization or revocation result is cached.
    return Ed25519PublicKey.from_public_bytes(public_bytes)


def verify_signature(public, value, signature):
    try:
        _verification_key(bytes.fromhex(public)).verify(
            bytes.fromhex(signature), E(b'signature', canonical(value)))
    except (InvalidSignature, ValueError, TypeError):
        raise Denied('BAD_SIGNATURE') from None
