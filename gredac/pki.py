"""Private direct-root X.509 profile and real OpenSSL TLS 1.3 memory-BIO links.

RFC5280, RFC8410/9295, RFC8032 and PKCS#10 (RFC2986). This is a restricted
prototype profile, not an arbitrary PKIX path builder or a public Web PKI.
TLS uses actual OpenSSL handshakes/records, without an HTTP/socket deployment.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import ssl
import struct
import threading
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ExtensionOID
from .crypto import Signer, Denied, require


def utc_now():
    return datetime.now(timezone.utc)


def raw_public(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


class PKI:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True)
        self.ca = Signer('prototype-CA')
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'B0-v3 private test CA')])
        now = utc_now()
        self.root = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                     .public_key(self.ca.private.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=7))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                     .add_extension(x509.KeyUsage(False, False, False, False, False,
                                                  True, False, False, False), True)
                     .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca.private.public_key()), False)
                     .sign(self.ca.private, algorithm=None))
        self.ca_path = self.directory / 'ca.pem'
        self.ca_path.write_bytes(self.root.public_bytes(serialization.Encoding.PEM))
        self.identities = {}
        self.traffic={'wire_bytes':0,'application_bytes':0,'handshake_bytes':0,'connections':0}
        self.traffic_lock=threading.Lock()

    def count_traffic(self,**values):
        with self.traffic_lock:
            for k,v in values.items():self.traffic[k]+=v

    def csr(self, actor):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, actor.name)])
        csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(actor.private, None)
        return csr.public_bytes(serialization.Encoding.PEM).decode()

    def issue(self, actor_name, public, csr_pem, owner):
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        require(csr.is_signature_valid, 'CSR_PROOF_OF_POSSESSION')
        require(raw_public(csr.public_key()) == public, 'CSR_KEY_MISMATCH')
        require(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == actor_name,
                'CSR_SUBJECT')
        now = utc_now()
        certificate = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self.root.subject)
                       .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                       .add_extension(x509.KeyUsage(True, False, False, False, False,
                                                    False, False, False, False), True)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                                                            ExtendedKeyUsageOID.SERVER_AUTH]), False)
                       .add_extension(x509.SubjectAlternativeName([
                           x509.UniformResourceIdentifier('urn:b0-v3:agent:' + actor_name),
                           x509.DNSName('localhost')]), False)
                       .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), False)
                       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                           self.ca.private.public_key()), False)
                       .sign(self.ca.private, algorithm=None))
        return {'agent_id': actor_name, 'owner': owner, 'public_key': public,
                'key_ref': hashlib.sha256(bytes.fromhex(public)).hexdigest(),
                'key_version': '1', 'certificate': certificate.public_bytes(
                    serialization.Encoding.PEM).decode(),
                'certificate_ref': certificate.fingerprint(hashes.SHA256()).hex(),
                'endpoint': 'memory-tls://localhost/' + actor_name}

    def validate(self, pem, registration, now=None):
        try:
            cert = x509.load_pem_x509_certificate(pem.encode() if isinstance(pem, str) else pem)
            self.root.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        except Exception as error:
            raise Denied('CERTIFICATE_SIGNATURE') from error
        require(cert.issuer == self.root.subject, 'CERTIFICATE_ISSUER')
        moment = now or utc_now()
        before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
        after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
        require(before <= moment < after, 'CERTIFICATE_TIME')
        allowed = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
                   ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                   ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
        require(all(not ext.critical or ext.oid in allowed for ext in cert.extensions),
                'UNKNOWN_CRITICAL_EXTENSION')
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        require(not basic.ca and usage.digital_signature and not usage.key_cert_sign
                and not usage.key_agreement and not usage.key_encipherment, 'CERTIFICATE_PROFILE')
        require(ExtendedKeyUsageOID.CLIENT_AUTH in eku and ExtendedKeyUsageOID.SERVER_AUTH in eku,
                'CERTIFICATE_EKU')
        require('urn:b0-v3:agent:' + registration['agent_id']
                in san.get_values_for_type(x509.UniformResourceIdentifier), 'CERTIFICATE_IDENTITY')
        require(raw_public(cert.public_key()) == registration['public_key'], 'CERTIFICATE_KEY')
        return cert

    def materialize(self, actor, registration):
        require(actor.name.replace('-', '').replace('_', '').isalnum(), 'IDENTITY_PATH')
        cert_path, key_path = (self.directory / (actor.name + suffix)
                              for suffix in ('.crt.pem', '.key.pem'))
        cert_path.write_text(registration['certificate'], encoding='ascii')
        key_path.write_bytes(actor.private.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        self.identities[actor.name] = (cert_path, key_path, registration)

    def link(self, caller_name, receiver_name, present_as=None):
        require(caller_name in self.identities and receiver_name in self.identities
                and (present_as or caller_name) in self.identities, 'TLS_IDENTITY_UNPUBLISHED')
        return TLSLink(self, caller_name, receiver_name, present_as=present_as)


class TLSLink:
    def __init__(self, pki, caller, receiver, present_as=None):
        self.pki=pki;self.wire_bytes=0
        actual = present_as or caller
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        for ctx, name in ((client_context, actual), (server_context, receiver)):
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_ecdh_curve('X25519')
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=str(pki.ca_path))
            cert, key, _ = pki.identities[name]
            ctx.load_cert_chain(str(cert), str(key))
        self.c_in, self.c_out, self.s_in, self.s_out = (ssl.MemoryBIO() for _ in range(4))
        self.client = client_context.wrap_bio(self.c_in, self.c_out, server_side=False,
                                               server_hostname='localhost')
        self.server = server_context.wrap_bio(self.s_in, self.s_out, server_side=True)
        done = set()
        try:
            for _ in range(100):
                for label, endpoint in (('client', self.client), ('server', self.server)):
                    if label in done:
                        continue
                    try:
                        endpoint.do_handshake()
                        done.add(label)
                    except ssl.SSLWantReadError:
                        pass
                self.pump()
                if len(done) == 2:
                    break
        except ssl.SSLError as error:
            raise Denied('TLS_HANDSHAKE') from error
        require(len(done) == 2, 'TLS_HANDSHAKE_INCOMPLETE')
        pki.count_traffic(handshake_bytes=self.wire_bytes,connections=1)
        client_cert = x509.load_der_x509_certificate(self.server.getpeercert(binary_form=True))
        server_cert = x509.load_der_x509_certificate(self.client.getpeercert(binary_form=True))
        pki.validate(client_cert.public_bytes(serialization.Encoding.PEM), pki.identities[caller][2])
        pki.validate(server_cert.public_bytes(serialization.Encoding.PEM), pki.identities[receiver][2])
        require(not self.client.session_reused and self.client.version() == 'TLSv1.3', 'TLS_PROFILE')
        self.caller, self.receiver = caller, receiver
        # Public peer keys extracted from validated TLS certificates. Roles may
        # bind received public descriptions to these without fixture lookups.
        self.caller_public, self.receiver_public = raw_public(client_cert.public_key()), raw_public(server_cert.public_key())
        self.info = {'version': self.client.version(), 'cipher': self.client.cipher()[0],
                     'client': caller, 'server': receiver, 'session_reused': False,'forced_only_group':'X25519'}

    def pump(self):
        for outgoing, incoming in ((self.c_out, self.s_in), (self.s_out, self.c_in)):
            if outgoing.pending:
                data=outgoing.read();self.wire_bytes+=len(data)
                self.pki.count_traffic(wire_bytes=len(data));incoming.write(data)

    def transfer(self, data, reply=False):
        # Experimental framing bound, not a protocol quota. A 2048-unit signed
        # delegation can exceed the former 1MiB cap because explicit ownership
        # records accompany compact seeds. Measure these bytes honestly.
        require(len(data) <= 2**24, 'TLS_FRAME_LIMIT')
        self.pki.count_traffic(application_bytes=len(data))
        writer, reader = (self.server, self.client) if reply else (self.client, self.server)
        wire = struct.pack('>I', len(data)) + data
        writer.write(wire)
        self.pump()
        result = b''
        for _ in range(max(100,len(wire)//16384+16)):
            try:
                result += reader.read(2**20+4)
            except ssl.SSLWantReadError:
                self.pump()
            if len(result) >= 4 and len(result) == 4 + struct.unpack('>I', result[:4])[0]:
                return result[4:]
        raise Denied('TLS_FRAME_INCOMPLETE')
