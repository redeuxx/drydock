"""Secret encryption, signing and passphrase derivation.

Every key in the list (newest first) yields independent HKDF subkeys, so no
purpose ever uses the raw secret key directly. Writes always use the newest
key; reads and verification try every key, which keeps rotation painless.
"""

import base64
import hashlib
import hmac
import uuid

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO_SECRETS = b"drydock/v1/secrets"
INFO_MANIFEST_HMAC = b"drydock/v1/manifest-hmac"
INFO_JOB_PASSPHRASE = b"drydock/v1/job-passphrase/"
INFO_PRESESSION_CSRF = b"drydock/v1/presession-csrf"


class CryptoError(Exception):
    """Raised when a value cannot be decrypted with any configured key."""


def derive(key: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(key)


class Crypto:
    def __init__(self, keys: tuple[bytes, ...]) -> None:
        if not keys:
            raise ValueError("at least one key is required")
        self._keys = keys
        self._fernet = MultiFernet(
            [Fernet(base64.urlsafe_b64encode(derive(k, INFO_SECRETS))) for k in keys]
        )
        self._hmac_keys = [derive(k, INFO_MANIFEST_HMAC) for k in keys]
        self._csrf_key = derive(keys[0], INFO_PRESESSION_CSRF)

    # SECRETS

    def encrypt(self, plaintext: str) -> str:
        """Always encrypts with the newest key, so every write re-encrypts."""
        return self._fernet.encrypt(plaintext.encode()).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode()
        except InvalidToken, UnicodeError:
            raise CryptoError("value cannot be decrypted with any configured key") from None

    def encrypt_bytes(self, data: bytes) -> bytes:
        """A Fernet token for data, made with the newest key (staged restore metadata)."""
        return self._fernet.encrypt(data)

    def decrypt_bytes(self, token: bytes) -> bytes:
        try:
            return self._fernet.decrypt(token)
        except InvalidToken:
            raise CryptoError("value cannot be decrypted with any configured key") from None

    # SIGNING

    def sign(self, data: bytes) -> str:
        return hmac.new(self._hmac_keys[0], data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature: str) -> bool:
        given = signature.encode()
        ok = False
        for key in self._hmac_keys:
            expected = hmac.new(key, data, hashlib.sha256).hexdigest().encode()
            ok |= hmac.compare_digest(expected, given)
        return ok

    # JOB PASSPHRASES

    def job_passphrases(self, job_id: uuid.UUID) -> list[str]:
        """Candidate passphrases for a job archive, newest key first."""
        info = INFO_JOB_PASSPHRASE + str(job_id).encode()
        return [base64.urlsafe_b64encode(derive(k, info)).decode().rstrip("=") for k in self._keys]

    def job_passphrase(self, job_id: uuid.UUID) -> str:
        return self.job_passphrases(job_id)[0]

    # PRE-SESSION CSRF

    def presession_tag(self, cookie_value: str) -> str:
        """Form token bound to the pre-session cookie, so an injected cookie is useless."""
        return hmac.new(self._csrf_key, cookie_value.encode(), hashlib.sha256).hexdigest()
