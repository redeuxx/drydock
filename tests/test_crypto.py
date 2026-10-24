import base64
import os
import uuid

import pytest

from drydock.crypto import Crypto, CryptoError

SENTINEL = "SENTINEL-6f1c9a2e-do-not-leak"


def key() -> bytes:
    return os.urandom(32)


def test_round_trip_never_contains_plaintext() -> None:
    crypto = Crypto((key(),))
    token = crypto.encrypt(SENTINEL)
    assert SENTINEL not in token
    assert base64.b64encode(SENTINEL.encode()).decode()[:16] not in token
    assert crypto.decrypt(token) == SENTINEL


def test_wrong_key_raises() -> None:
    token = Crypto((key(),)).encrypt(SENTINEL)
    with pytest.raises(CryptoError):
        Crypto((key(),)).decrypt(token)
    with pytest.raises(CryptoError):
        Crypto((key(),)).decrypt("garbage")


def test_old_key_still_decrypts_and_writes_use_newest() -> None:
    old, new = key(), key()
    old_token = Crypto((old,)).encrypt(SENTINEL)
    rotated = Crypto((new, old))
    assert rotated.decrypt(old_token) == SENTINEL
    new_token = rotated.encrypt(SENTINEL)
    assert Crypto((new,)).decrypt(new_token) == SENTINEL
    with pytest.raises(CryptoError):
        Crypto((old,)).decrypt(new_token)


def test_hmac_from_old_key_verifies_after_rotation() -> None:
    old, new = key(), key()
    data = b"checksums.json contents"
    signature = Crypto((old,)).sign(data)
    assert Crypto((new, old)).verify(data, signature)
    assert not Crypto((new,)).verify(data, signature)
    assert not Crypto((new, old)).verify(data + b"x", signature)
    assert not Crypto((new, old)).verify(data, "é" * 64)
    assert Crypto((new, old)).sign(data) == Crypto((new,)).sign(data)


def test_job_passphrase_is_derived_from_key_and_job_only() -> None:
    old, new = key(), key()
    job = uuid.uuid4()
    first = Crypto((new, old)).job_passphrase(job)
    assert first == Crypto((new,)).job_passphrase(job)  # survives losing the DB
    assert first != Crypto((new,)).job_passphrase(uuid.uuid4())
    assert Crypto((new, old)).job_passphrases(job) == [first, Crypto((old,)).job_passphrase(job)]
    assert len(first) >= 43


def test_subkeys_are_independent() -> None:
    k = key()
    crypto = Crypto((k,))
    tags = {crypto.sign(b"x"), crypto.presession_tag("x")}
    assert len(tags) == 2
    assert k.hex() not in tags
