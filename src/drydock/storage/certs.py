"""Pinned TLS certificates for WebDAV storage.

WebDAV storage is https only: over plain http a server (or anyone on the path) could
redirect rclone's requests, method and all, to the Docker socket proxy, and rclone refuses
only redirects from https to http. A server whose certificate no public authority signed
(a NAS with a self-signed one) can be trusted by pinning its certificate: a superadmin
fetches it, compares its fingerprint and saves it with the target.

A pinned certificate is that target's only trust anchor. rclone gets it per call as
_config CaCert (a file drydock writes), which replaces the system roots for the connections
that call makes, and still checks the name in the URL and the validity dates. rclone
caches a connection by its options, so the target's fs carries the fingerprint (as the
"description" option): another certificate means another connection.
"""

import hashlib
import ipaddress
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

TIMEOUT = 10.0
MAX_NAMES = 20  # names shown for one certificate
BEGIN = "-----BEGIN CERTIFICATE-----"


class CertificateError(Exception):
    """The message is safe to show."""


def load(text: str) -> x509.Certificate:
    """The one certificate in text (PEM). Raises CertificateError."""
    if text.count(BEGIN) != 1:
        raise CertificateError("Paste exactly one certificate, in PEM format.")
    try:
        return readable(x509.load_pem_x509_certificate(text.strip().encode()))
    except ValueError:
        raise CertificateError("The certificate is not a valid PEM certificate.") from None


def readable(cert: x509.Certificate) -> x509.Certificate:
    """cert, once every part drydock reads parses: cryptography parses extensions lazily,
    and refuses some that OpenSSL accepts (a repeated extension, say). Raises ValueError."""
    try:
        cert.subject.rfc4514_string()
        cert.issuer.rfc4514_string()
        _ = cert.extensions, cert.not_valid_before_utc, cert.not_valid_after_utc
        names(cert)
    except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType) as exc:
        raise ValueError(str(exc)) from None
    return cert


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(Encoding.PEM).decode()


def fingerprint(cert: x509.Certificate) -> str:
    """The SHA-256 fingerprint as plain hex, for file names and rclone."""
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def shown_fingerprint(cert: x509.Certificate) -> str:
    """The SHA-256 fingerprint as openssl and browsers show it."""
    digest = fingerprint(cert).upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def alt_names(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """The DNS names and the IP addresses the certificate is for. rclone (Go) ignores the
    common name."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], []
    return san.get_values_for_type(x509.DNSName), [
        str(ip) for ip in san.get_values_for_type(x509.IPAddress)
    ]


def names(cert: x509.Certificate) -> list[str]:
    dns, ips = alt_names(cert)
    return dns + ips


def matches(cert: x509.Certificate, host: str) -> bool:
    """Whether the certificate is for host, as Go checks it: an IP address only against
    the IP addresses listed, a name only against the DNS names, a wildcard covering exactly
    one leftmost label."""
    dns, ips = alt_names(cert)
    try:
        return str(ipaddress.ip_address(host)) in ips
    except ValueError:
        pass
    host = host.lower().rstrip(".")
    for name in dns:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def problem(cert: x509.Certificate, host: str) -> str | None:
    """Why rclone would refuse this certificate for host, or None."""
    now = datetime.now(UTC)
    if cert.not_valid_after_utc < now:
        return f"The certificate expired on {cert.not_valid_after_utc:%Y-%m-%d}."
    if cert.not_valid_before_utc > now:
        return f"The certificate is not valid until {cert.not_valid_before_utc:%Y-%m-%d}."
    if not matches(cert, host):
        listed = ", ".join(names(cert)[:MAX_NAMES]) or "no host names"
        return (
            f"The certificate is not for {host}: it lists {listed}. rclone checks the name, "
            "so give the server a certificate that lists the host in the URL."
        )
    return None


def details(cert: x509.Certificate) -> dict[str, Any]:
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "names": names(cert)[:MAX_NAMES],
        "not_before": f"{cert.not_valid_before_utc:%Y-%m-%d}",
        "not_after": f"{cert.not_valid_after_utc:%Y-%m-%d}",
        "fingerprint": shown_fingerprint(cert),
    }


def fetch(host: str, port: int) -> tuple[x509.Certificate, bool]:
    """The certificate the server at host:port presents, and whether the system's
    authorities already trust it there. Raises CertificateError."""
    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    try:
        cert = readable(x509.load_der_x509_certificate(handshake(unverified, host, port)))
    except ValueError:
        raise CertificateError("The server's certificate cannot be read.") from None
    try:
        handshake(ssl.create_default_context(), host, port)
    except CertificateError:
        return cert, False
    return cert, True


def handshake(context: ssl.SSLContext, host: str, port: int) -> bytes:
    try:
        with (
            socket.create_connection((host, port), timeout=TIMEOUT) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except socket.gaierror:
        raise CertificateError("The host name cannot be resolved.") from None
    except TimeoutError:
        raise CertificateError("The server did not answer in time.") from None
    except ConnectionRefusedError:
        raise CertificateError("The server refused the connection. Check the URL.") from None
    except ssl.SSLError:
        raise CertificateError("The server did not complete a TLS handshake.") from None
    except OSError:
        raise CertificateError("The server cannot be reached.") from None
    if not der:
        raise CertificateError("The server presented no certificate.")
    return der
