"""Labeled vulnerable fixture: 6 expected crypto findings."""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec

legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

ec_key = ec.generate_private_key(ec.SECP256R1())

broken_digest = hashlib.md5(b"payload")

session_keys = hashlib.sha1(b"session-material")


def weak_random_token() -> bytes:
    import os

    return hashlib.md5(os.urandom(8)).digest()
