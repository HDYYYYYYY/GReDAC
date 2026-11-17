"""Compact SAGA-inspired contact profile, not a reproduction of its full wire protocol.

Authority-signed one-time permit + receiver ACT, X25519 + HKDF-SHA256 session
key, identity signatures and key confirmation; no new resource issuance.
"""
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .crypto import E, canonical, channel_mac, ident, require, verify_signature


def establish(authority, caller, receiver, caller_right, service_right):
    otk_private = X25519PrivateKey.generate()
    otk_id = ident()
    authority.call(receiver, 'otk', {'id': otk_id, 'public': otk_private.public_key().public_bytes_raw().hex()})
    signed_permit = authority.call(caller, 'permit', {
        'caller': caller_right, 'service': service_right, 'otk': otk_id})
    permit = signed_permit['body']
    verify_signature(authority.signer.public, permit, signed_permit['signature'])
    ephemeral = X25519PrivateKey.generate()
    init = {'permit': permit['id'], 'session': ident(),
            'ephemeral': ephemeral.public_key().public_bytes_raw().hex()}
    proof = caller.sign(init)
    authority.call(receiver, 'redeem', {'permit': permit['id'], 'init': init, 'proof': proof})
    caller_shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(permit['otk_public'])))
    receiver_shared = otk_private.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(init['ephemeral'])))
    info = E(b'contact-app-key', permit['context'].encode(), b'G', init['session'].encode())
    salt = hashlib.sha256(canonical(permit)).digest()

    def kdf(shared):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared)

    caller_key, receiver_key = kdf(caller_shared), kdf(receiver_shared)
    body = {'id': ident(), 'kind': 'ACT', 'permit': permit['id'], 'session': init['session'],
            'context': permit['context'], 'caller': permit['caller'], 'receiver': permit['receiver'],
            'caller_right': permit['caller_right'], 'service_right': permit['service_right'],
            'caller_key': permit['caller_key'], 'receiver_key': permit['receiver_key'],
            'expires': permit['expires']}
    require(channel_mac(caller_key, canonical(body)) == channel_mac(receiver_key, canonical(body)),
            'CONTACT_KEY_CONFIRMATION')
    signed_act = receiver.envelope(body)
    authority.call(receiver, 'act', signed_act)
    return signed_act, caller_key, {'permit': signed_permit, 'init': init, 'proof': proof}
