"""TLS for the witness protocol: development certificates and SSL contexts.

`create_dev_pki` writes a private certificate authority plus a server and a
client certificate signed by it, enough to run witnesses over HTTPS with
mutual authentication in a lab. Production deployments should use their own CA.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def _certificate(subject: str, key, issuer_name, issuer_key, *, ca: bool, usage=None, hosts=()) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(issuer_name or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if usage is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    if hosts:
        names = []
        for host in hosts:
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(host)))
            except ValueError:
                names.append(x509.DNSName(host))
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def create_dev_pki(out_dir: Path, hosts: list[str]) -> dict[str, str]:
    """Write ca.pem, server.pem/server-key.pem (for `hosts`) and client.pem/client-key.pem."""
    out_dir.mkdir(parents=True, exist_ok=True)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = _certificate("B-SCAF development CA", ca_key, None, ca_key, ca=True)
    files = {"ca": out_dir / "ca.pem"}
    files["ca"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(out_dir / "ca-key.pem", ca_key)
    for role, usage, names in (("server", ExtendedKeyUsageOID.SERVER_AUTH, hosts), ("client", ExtendedKeyUsageOID.CLIENT_AUTH, ())):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _certificate(f"bscaf-{role}", key, ca_cert.subject, ca_key, ca=False, usage=usage, hosts=names)
        files[role] = out_dir / f"{role}.pem"
        files[f"{role}_key"] = out_dir / f"{role}-key.pem"
        files[role].write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        _write_key(files[f"{role}_key"], key)
    return {name: str(path) for name, path in files.items()}


def server_context(cert_file: str, key_file: str, client_ca: str | None = None) -> ssl.SSLContext:
    """HTTPS for a witness; with client_ca, only clients holding a certificate from that CA may connect."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    if client_ca:
        context.load_verify_locations(client_ca)
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def client_context(ca_file: str | None = None, cert_file: str | None = None, key_file: str | None = None) -> ssl.SSLContext | None:
    """Context for https:// witness URLs: trust ca_file, present a client certificate for mutual TLS."""
    if not (ca_file or cert_file):
        return None
    context = ssl.create_default_context(cafile=ca_file)
    if cert_file:
        context.load_cert_chain(cert_file, key_file)
    return context
