from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator

from .models import AssetFinding

CRYPTO_LIBRARIES: dict[str, dict[str, list[str]]] = {
    # Rust
    "ring": {"algorithms": ["AES", "ChaCha20", "ECDSA", "RSA", "SHA256", "SHA384", "SHA512"], "category": "rust"},
    "rustls": {"algorithms": ["TLS"], "category": "rust"},
    "openssl": {"algorithms": ["RSA", "AES", "ECDSA", "HMAC", "SHA256", "SHA512", "PBKDF2"], "category": "rust"},
    "openssl-sys": {"algorithms": ["RSA", "AES", "ECDSA", "HMAC", "SHA256", "SHA512", "PBKDF2"], "category": "rust"},
    "ed25519-dalek": {"algorithms": ["Ed25519", "EdDSA"], "category": "rust"},
    "x25519-dalek": {"algorithms": ["X25519", "ECDH"], "category": "rust"},
    "aes-gcm": {"algorithms": ["AES-GCM", "AES"], "category": "rust"},
    "chacha20poly1305": {"algorithms": ["ChaCha20-Poly1305"], "category": "rust"},
    "pqc-kyber": {"algorithms": ["Kyber", "ML-KEM", "PQC"], "category": "rust"},
    "pqc-dilithium": {"algorithms": ["Dilithium", "ML-DSA", "PQC"], "category": "rust"},
    "pqcrypto-kyber": {"algorithms": ["Kyber", "ML-KEM", "PQC"], "category": "rust"},
    "pqcrypto-dilithium": {"algorithms": ["Dilithium", "ML-DSA", "PQC"], "category": "rust"},
    "sphincs-plus": {"algorithms": ["SPHINCS+", "SLH-DSA", "PQC"], "category": "rust"},
    "zeroize": {"algorithms": ["MemoryZeroing"], "category": "rust"},
    "blake3": {"algorithms": ["BLAKE3", "SHA3"], "category": "rust"},
    "sha2": {"algorithms": ["SHA256", "SHA384", "SHA512", "SHA2"], "category": "rust"},
    "sha3": {"algorithms": ["SHA3-256", "SHA3-512", "Keccak"], "category": "rust"},
    "hmac": {"algorithms": ["HMAC"], "category": "rust"},
    "aes": {"algorithms": ["AES", "AES-128", "AES-256"], "category": "rust"},
    "block-modes": {"algorithms": ["CBC", "CTR", "ECB", "CFB"], "category": "rust"},
    "argon2": {"algorithms": ["Argon2", "Argon2id", "Argon2i", "Argon2d"], "category": "rust"},
    "bcrypt-pbkdf": {"algorithms": ["bcrypt", "PBKDF2"], "category": "rust"},
    "hkdf": {"algorithms": ["HKDF"], "category": "rust"},
    "hmac-drbg": {"algorithms": ["HMAC-DRBG"], "category": "rust"},
    "pem-rfc7468": {"algorithms": ["PEM"], "category": "rust"},
    "der-parser": {"algorithms": ["DER", "ASN.1"], "category": "rust"},
    "x509-parser": {"algorithms": ["X.509"], "category": "rust"},
    "rsa": {"algorithms": ["RSA", "RSA-PSS", "RSA-OAEP"], "category": "rust"},
    "p256": {"algorithms": ["ECDSA", "ECDH", "P-256"], "category": "rust"},
    "p384": {"algorithms": ["ECDSA", "ECDH", "P-384"], "category": "rust"},
    "p521": {"algorithms": ["ECDSA", "ECDH", "P-521"], "category": "rust"},
    "k256": {"algorithms": ["ECDSA", "ECDH", "secp256k1"], "category": "rust"},
    "curve25519-dalek": {"algorithms": ["X25519", "Ed25519", "Curve25519"], "category": "rust"},
    "subtle": {"algorithms": ["ConstantTime"], "category": "rust"},
    "snow": {"algorithms": ["Noise", "TLS"], "category": "rust"},
    "tls13": {"algorithms": ["TLS1.3"], "category": "rust"},
    "rc4": {"algorithms": ["RC4", "ARC4"], "category": "rust"},
    "des": {"algorithms": ["DES", "3DES", "TripleDES"], "category": "rust"},
    "tripledes": {"algorithms": ["3DES", "TripleDES"], "category": "rust"},
    "cfb-mode": {"algorithms": ["CFB"], "category": "rust"},
    "ctr": {"algorithms": ["CTR"], "category": "rust"},
    "cbc-mode": {"algorithms": ["CBC"], "category": "rust"},
    "ofb-mode": {"algorithms": ["OFB"], "category": "rust"},
    # Python
    "pycryptodome": {"algorithms": ["AES", "RSA", "DES", "3DES", "Blowfish", "ChaCha20", "ECDSA", "HMAC", "SHA256", "SHA512", "PBKDF2", "RC4"], "category": "python"},
    "cryptography": {"algorithms": ["AES", "RSA", "ECDSA", "Ed25519", "X25519", "ChaCha20", "HMAC", "SHA256", "SHA512", "PBKDF2", "HKDF", "Blowfish", "TripleDES", "CAST5"], "category": "python"},
    "paramiko": {"algorithms": ["SSH", "RSA", "Ed25519", "ECDSA", "AES", "ChaCha20", "HMAC", "SHA256"], "category": "python"},
    "pyca": {"algorithms": ["RSA", "ECDSA", "Ed25519", "AES", "HMAC"], "category": "python"},
    "pyopenssl": {"algorithms": ["RSA", "AES", "ECDSA", "HMAC", "SHA256", "SHA512"], "category": "python"},
    "pynacl": {"algorithms": ["Ed25519", "X25519", "XSalsa20", "Poly1305", "ChaCha20"], "category": "python"},
    "bcrypt": {"algorithms": ["bcrypt", "PBKDF2"], "category": "python"},
    "argon2-cffi": {"algorithms": ["Argon2", "Argon2id", "Argon2i", "Argon2d"], "category": "python"},
    "passlib": {"algorithms": ["bcrypt", "scrypt", "PBKDF2", "Argon2", "SHA256", "SHA512", "MD5"], "category": "python"},
    "hashlib": {"algorithms": ["SHA256", "SHA512", "MD5", "SHA1", "SHA3"], "category": "python"},
    "hmac": {"algorithms": ["HMAC"], "category": "python"},
    "rsa": {"algorithms": ["RSA", "RSA-PSS", "RSA-OAEP"], "category": "python"},
    "ecdsa": {"algorithms": ["ECDSA", "ECDH"], "category": "python"},
    "cose": {"algorithms": ["COSE", "AES", "HMAC", "ECDSA", "EdDSA"], "category": "python"},
    "jwt": {"algorithms": ["JWT", "HMAC", "RSA", "ECDSA", "EdDSA"], "category": "python"},
    "pyjwt": {"algorithms": ["JWT", "HMAC", "RSA", "ECDSA", "EdDSA"], "category": "python"},
    "python-jose": {"algorithms": ["JWT", "HMAC", "RSA", "ECDSA", "EdDSA", "AES"], "category": "python"},
    "pyotp": {"algorithms": ["HOTP", "TOTP", "HMAC-SHA1"], "category": "python"},
    "fido2": {"algorithms": ["FIDO2", "WebAuthn", "ECDSA", "EdDSA", "RSA"], "category": "python"},
    "pysodium": {"algorithms": ["libsodium", "Ed25519", "X25519", "ChaCha20", "Poly1305"], "category": "python"},
    "M2Crypto": {"algorithms": ["RSA", "AES", "DES", "ECDSA", "HMAC", "SHA256", "SHA512", "EVP"], "category": "python"},
    "certifi": {"algorithms": ["X.509", "PKI"], "category": "python"},
    "truststore": {"algorithms": ["X.509", "PKI", "TLS"], "category": "python"},
    "tls-client": {"algorithms": ["TLS"], "category": "python"},
    "httpx": {"algorithms": ["TLS"], "category": "python"},
    "requests": {"algorithms": ["TLS"], "category": "python"},
    "urllib3": {"algorithms": ["TLS"], "category": "python"},
    "pysnmp": {"algorithms": ["SNMP", "DES", "AES"], "category": "python"},
    "aiosmtpd": {"algorithms": ["SMTP", "TLS"], "category": "python"},
    "aiosmtp": {"algorithms": ["SMTP", "TLS"], "category": "python"},
    "keyring": {"algorithms": ["AES", "SecretStorage"], "category": "python"},
    "cryptography-hazmat": {"algorithms": ["AES", "RSA", "ECDSA", "ChaCha20", "HMAC", "PBKDF2", "HKDF"], "category": "python"},
    # JavaScript / Node.js
    "crypto-js": {"algorithms": ["AES", "DES", "3DES", "HMAC", "SHA256", "SHA512", "MD5", "PBKDF2", "RC4", "Rabbit", "Blowfish"], "category": "javascript"},
    "node-forge": {"algorithms": ["RSA", "AES", "DES", "3DES", "ECDSA", "X.509", "PKCS", "HMAC", "SHA256", "SHA512", "PBKDF2", "RC2"], "category": "javascript"},
    "tweetnacl": {"algorithms": ["Ed25519", "X25519", "AES256-GCM", "Poly1305", "SHA-512"], "category": "javascript"},
    "nacl": {"algorithms": ["Ed25519", "X25519", "SecretBox", "Poly1305"], "category": "javascript"},
    "libsodium-wrappers": {"algorithms": ["libsodium", "Ed25519", "X25519", "ChaCha20", "Poly1305", "AES-GCM"], "category": "javascript"},
    "bcrypt": {"algorithms": ["bcrypt"], "category": "javascript"},
    "scrypt": {"algorithms": ["scrypt"], "category": "javascript"},
    "argon2": {"algorithms": ["Argon2", "Argon2id", "Argon2i", "Argon2d"], "category": "javascript"},
    "jsonwebtoken": {"algorithms": ["JWT", "HMAC", "RSA", "ECDSA", "EdDSA"], "category": "javascript"},
    "jose": {"algorithms": ["JWT", "JWE", "JWS", "HMAC", "RSA", "ECDSA", "EdDSA", "AES"], "category": "javascript"},
    "webcrypto": {"algorithms": ["WebCrypto", "AES", "RSA", "ECDSA", "Ed25519", "HMAC", "SHA256", "PBKDF2", "HKDF"], "category": "javascript"},
    "openpgp": {"algorithms": ["OpenPGP", "RSA", "ECDSA", "EdDSA", "AES", "3DES", "SHA256", "SHA512"], "category": "javascript"},
    "crypto": {"algorithms": ["AES", "RSA", "ECDSA", "HMAC", "SHA256", "SHA512", "PBKDF2", "HKDF", "ECDH"], "category": "javascript"},
    "electron-keytar": {"algorithms": ["SecretStorage", "AES"], "category": "javascript"},
    "keytar": {"algorithms": ["SecretStorage", "AES"], "category": "javascript"},
    "ursa-optional": {"algorithms": ["RSA", "RSA-PKCS1", "RSA-OAEP"], "category": "javascript"},
    "secp256k1": {"algorithms": ["ECDSA", "ECDH", "secp256k1"], "category": "javascript"},
    "elliptic": {"algorithms": ["ECDSA", "ECDH", "EdDSA", "secp256k1", "P-256", "P-384"], "category": "javascript"},
    "bn.js": {"algorithms": ["BigNumber"], "category": "javascript"},
    "cipher-base": {"algorithms": ["Cipher"], "category": "javascript"},
    "create-hash": {"algorithms": ["MD5", "SHA1", "SHA256", "RIPEMD160"], "category": "javascript"},
    "create-hmac": {"algorithms": ["HMAC"], "category": "javascript"},
    "pbkdf2": {"algorithms": ["PBKDF2"], "category": "javascript"},
    "scrypt-js": {"algorithms": ["scrypt"], "category": "javascript"},
    "ripemd160": {"algorithms": ["RIPEMD160"], "category": "javascript"},
    "sha.js": {"algorithms": ["SHA256", "SHA512", "SHA1"], "category": "javascript"},
    "sm-crypto": {"algorithms": ["SM2", "SM3", "SM4", "ShangMi"], "category": "javascript"},
    "futoin-hkdf": {"algorithms": ["HKDF"], "category": "javascript"},
    "otplib": {"algorithms": ["HOTP", "TOTP", "HMAC-SHA1", "HMAC-SHA256"], "category": "javascript"},
    "speakeasy": {"algorithms": ["HOTP", "TOTP", "HMAC-SHA1"], "category": "javascript"},
    "paseto": {"algorithms": ["PASETO", "Ed25519", "X25519", "AES-256-CTR", "HMAC-SHA256"], "category": "javascript"},
    # Go
    "crypto": {"algorithms": ["AES", "RSA", "ECDSA", "Ed25519", "HMAC", "SHA256", "SHA512", "ChaCha20", "Poly1305", "X25519", "PBKDF2", "HKDF"], "category": "go"},
    "golang.org/x/crypto": {"algorithms": ["AES", "RSA", "ECDSA", "Ed25519", "HMAC", "SHA256", "SHA512", "ChaCha20", "Poly1305", "X25519", "PBKDF2", "HKDF", "bcrypt", "scrypt", "argon2", "nacl", "curve25519", "ssh"], "category": "go"},
    "filippo.io/edwards25519": {"algorithms": ["Ed25519", "EdDSA", "Curve25519"], "category": "go"},
    "github.com/bwesterb/go-ristretto": {"algorithms": ["Ristretto", "Curve25519", "Ed25519"], "category": "go"},
    "github.com/cloudflare/circl": {"algorithms": ["PQC", "Kyber", "Dilithium", "Sapphire", "FrodoKEM", "SIKE", "Ed25519", "P-256"], "category": "go"},
    "github.com/martinlindhe/gcm": {"algorithms": ["GCM", "AES-GCM"], "category": "go"},
    "github.com/thales-e-security/krypto": {"algorithms": ["RSA", "HSM", "PKCS11"], "category": "go"},
    "github.com/ThalesIgnite/crypto11": {"algorithms": ["PKCS11", "RSA", "ECDSA", "AES"], "category": "go"},
    "github.com/miekg/pkcs11": {"algorithms": ["PKCS11"], "category": "go"},
    "go.mozilla.org/pkcs7": {"algorithms": ["PKCS7", "X.509"], "category": "go"},
    "go.mozilla.org/s3": {"algorithms": ["S3", "AES", "HMAC"], "category": "go"},
    "software.sslmate.com/src/go-pkcs12": {"algorithms": ["PKCS12", "X.509", "AES", "3DES"], "category": "go"},
    "github.com/youmark/pkcs8": {"algorithms": ["PKCS8", "RSA", "ECDSA", "Ed25519"], "category": "go"},
    "gopkg.in/square/go-jose.v2": {"algorithms": ["JWE", "JWS", "JWK", "RSA", "ECDSA", "AES", "HMAC"], "category": "go"},
    "github.com/go-jose/go-jose/v3": {"algorithms": ["JWE", "JWS", "JWK", "RSA", "ECDSA", "AES", "HMAC"], "category": "go"},
    "github.com/go-jose/go-jose/v4": {"algorithms": ["JWE", "JWS", "JWK", "RSA", "ECDSA", "AES", "HMAC"], "category": "go"},
    "github.com/golang-jwt/jwt": {"algorithms": ["JWT", "HMAC", "RSA", "ECDSA", "EdDSA"], "category": "go"},
    "github.com/dgrijalva/jwt-go": {"algorithms": ["JWT", "HMAC", "RSA", "ECDSA"], "category": "go"},
    "github.com/pquerna/otp": {"algorithms": ["HOTP", "TOTP", "HMAC-SHA1"], "category": "go"},
    "github.com/nicholasgasior/guhn": {"algorithms": ["HOTP", "TOTP"], "category": "go"},
    "github.com/segmentio/ksuid": {"algorithms": ["KSUID"], "category": "go"},
    "github.com/google/uuid": {"algorithms": ["UUID"], "category": "go"},
    "github.com/satori/go.uuid": {"algorithms": ["UUID"], "category": "go"},
    "github.com/gofrs/uuid": {"algorithms": ["UUID"], "category": "go"},
    # Java
    "bouncycastle": {"algorithms": ["RSA", "AES", "DES", "3DES", "ECDSA", "EdDSA", "ChaCha20", "Poly1305", "HMAC", "SHA256", "SHA512", "PBKDF2", "Argon2", "Kyber", "Dilithium", "BLAKE2", "PKCS"], "category": "java"},
    "bcprov-jdk": {"algorithms": ["RSA", "AES", "DES", "3DES", "ECDSA", "EdDSA", "ChaCha20", "Poly1305", "HMAC", "SHA256", "SHA512", "PBKDF2", "PKCS"], "category": "java"},
    "bctls-jdk": {"algorithms": ["TLS", "RSA", "ECDSA", "AES", "ChaCha20"], "category": "java"},
    "bcmail-jdk": {"algorithms": ["S/MIME", "OpenPGP", "RSA", "ECDSA"], "category": "java"},
    "bcpg-jdk": {"algorithms": ["OpenPGP", "RSA", "ECDSA", "DSA"], "category": "java"},
    "bcutil-jdk": {"algorithms": ["ASN.1", "DER", "BER", "PEM"], "category": "java"},
    "bc-fips": {"algorithms": ["FIPS", "RSA", "AES", "DES", "ECDSA", "HMAC", "SHA256", "SHA512", "PBKDF2"], "category": "java"},
    "tls13-netty": {"algorithms": ["TLS1.3", "ChaCha20", "AES-GCM", "X25519"], "category": "java"},
    "tink": {"algorithms": ["AES", "RSA", "ECDSA", "Ed25519", "HMAC", "ChaCha20", "AES-GCM", "AES-CTR", "AES-CBC", "PBKDF2", "HKDF"], "category": "java"},
    "google-tink": {"algorithms": ["AES", "RSA", "ECDSA", "Ed25519", "HMAC", "ChaCha20", "AES-GCM", "AES-CTR", "AES-CBC", "PBKDF2", "HKDF"], "category": "java"},
    "vault-java-driver": {"algorithms": ["Vault", "AES", "RSA", "HMAC"], "category": "java"},
    "nimbus-jose-jwt": {"algorithms": ["JWE", "JWS", "JWT", "RSA", "ECDSA", "EdDSA", "AES", "HMAC", "PBES2"], "category": "java"},
    "java-security-suite": {"algorithms": ["RSA", "AES", "ECDSA", "HMAC", "SHA256"], "category": "java"},
    "java-crypto-extensions": {"algorithms": ["RSA", "AES", "ECDSA", "HMAC", "SHA256"], "category": "java"},
    "spongy-castle": {"algorithms": ["RSA", "AES", "DES", "3DES", "ECDSA", "HMAC", "SHA256", "SHA512", "PBKDF2"], "category": "java"},
    "conceal": {"algorithms": ["AES", "SHA256", "HMAC", "KeyDerivation"], "category": "java"},
    "google-crypto": {"algorithms": ["AES", "RSA", "ECDSA", "HMAC", "SHA256"], "category": "java"},
    "libsodium": {"algorithms": ["libsodium", "Ed25519", "X25519", "ChaCha20", "Poly1305", "AES-GCM"], "category": "java"},
    "nacl-java": {"algorithms": ["NaCl", "Ed25519", "X25519", "SecretBox", "Poly1305"], "category": "java"},
    "kse": {"algorithms": ["KeyStore", "RSA", "AES", "ECDSA", "DSA"], "category": "java"},
    "keystore-explorer": {"algorithms": ["KeyStore", "RSA", "AES", "ECDSA", "DSA"], "category": "java"},
    "conscrypt": {"algorithms": ["TLS", "AES", "RSA", "ECDSA", "ChaCha20"], "category": "java"},
    "netty-tcnative": {"algorithms": ["TLS", "AES", "RSA", "ECDSA"], "category": "java"},
    "wildfly-elytron": {"algorithms": ["TLS", "SASL", "RSA", "ECDSA", "AES", "HMAC"], "category": "java"},
    # .NET
    "system.security.cryptography": {"algorithms": ["AES", "RSA", "ECDSA", "ECDH", "HMAC", "SHA256", "SHA512", "HMACSHA256", "AesGcm", "ChaCha20Poly1305", "ECDiffieHellman"], "category": "dotnet"},
    "bouncy-castle": {"algorithms": ["RSA", "AES", "DES", "3DES", "ECDSA", "EdDSA", "ChaCha20", "Poly1305", "HMAC", "SHA256", "SHA512", "PBKDF2", "PKCS"], "category": "dotnet"},
    "bouncy-cryptography": {"algorithms": ["RSA", "AES", "DES", "ECDSA", "HMAC", "SHA256", "SHA512"], "category": "dotnet"},
    "portable.bouncy castle": {"algorithms": ["RSA", "AES", "DES", "ECDSA", "EdDSA", "HMAC", "SHA256", "SHA512", "PBKDF2"], "category": "dotnet"},
    "newtonsoft.json.security": {"algorithms": ["HMAC", "SHA256", "AES"], "category": "dotnet"},
    "jose-jwt": {"algorithms": ["JWE", "JWS", "JWT", "RSA", "ECDSA", "EdDSA", "AES", "HMAC"], "category": "dotnet"},
    "jose-pinkjam": {"algorithms": ["JWT", "RSA", "ECDSA", "EdDSA", "AES", "HMAC"], "category": "dotnet"},
    "microsoft.identitymodel": {"algorithms": ["RSA", "ECDSA", "HMAC", "SHA256", "SHA512", "AES", "PBKDF2"], "category": "dotnet"},
    "identitymodel": {"algorithms": ["RSA", "ECDSA", "HMAC", "SHA256", "AES"], "category": "dotnet"},
    "microsoft.identity.web": {"algorithms": ["RSA", "ECDSA", "HMAC", "SHA256", "AES"], "category": "dotnet"},
    "azure.security.keyvault.keys": {"algorithms": ["RSA", "ECDSA", "HMAC", "AES"], "category": "dotnet"},
    "azure.security.keyvault.secrets": {"algorithms": ["AES", "RSA"], "category": "dotnet"},
    "azure.security.keyvault.certificates": {"algorithms": ["RSA", "ECDSA", "X.509"], "category": "dotnet"},
    "skia.sharp": {"algorithms": ["Hash", "SHA256"], "category": "dotnet"},
    "bouncycastle.crypto": {"algorithms": ["RSA", "AES", "ECDSA", "HMAC", "SHA256", "SHA512", "PBKDF2"], "category": "dotnet"},
    "hashids": {"algorithms": ["HashIds"], "category": "dotnet"},
    "bcrypt.net": {"algorithms": ["bcrypt"], "category": "dotnet"},
    "konsolern.pkcs11": {"algorithms": ["PKCS11"], "category": "dotnet"},
    "pemutils": {"algorithms": ["PEM"], "category": "dotnet"},
    "certes": {"algorithms": ["ACME", "RSA", "ECDSA", "X.509", "LetEncrypt"], "category": "dotnet"},
    "letsencrypt": {"algorithms": ["ACME", "RSA", "ECDSA", "X.509", "LetEncrypt"], "category": "dotnet"},
    "arcface": {"algorithms": ["AES", "RSA", "ECDSA"], "category": "dotnet"},
    "dotnetcore.nacl": {"algorithms": ["NaCl", "Ed25519", "X25519", "SecretBox"], "category": "dotnet"},
    # Ruby
    "openssl": {"algorithms": ["RSA", "AES", "DES", "3DES", "ECDSA", "Ed25519", "HMAC", "SHA256", "SHA512", "PBKDF2", "PKCS5", "PKCS7", "X.509"], "category": "ruby"},
    "ruby-openssl": {"algorithms": ["RSA", "AES", "DES", "3DES", "ECDSA", "Ed25519", "HMAC", "SHA256", "SHA512", "PBKDF2"], "category": "ruby"},
    "rbnacl": {"algorithms": ["libsodium", "Ed25519", "X25519", "ChaCha20", "Poly1305", "AES-GCM", "SecretBox", "HMAC-SHA512"], "category": "ruby"},
    "rbnacl-libsodium": {"algorithms": ["libsodium", "Ed25519", "X25519", "ChaCha20", "Poly1305"], "category": "ruby"},
    "bcrypt": {"algorithms": ["bcrypt"], "category": "ruby"},
    "bcrypt-pbkdf": {"algorithms": ["bcrypt", "PBKDF2"], "category": "ruby"},
    "argon2": {"algorithms": ["Argon2", "Argon2id", "Argon2i", "Argon2d"], "category": "ruby"},
    "scrypt": {"algorithms": ["scrypt"], "category": "ruby"},
    "rack_csrf": {"algorithms": ["HMAC", "SHA256"], "category": "ruby"},
    "jwt": {"algorithms": ["JWT", "HMAC", "RSA", "ECDSA", "EdDSA"], "category": "ruby"},
    "ruby-jwt": {"algorithms": ["JWT", "HMAC", "RSA", "ECDSA", "EdDSA", "AES"], "category": "ruby"},
    "devise": {"algorithms": ["HMAC", "SHA256", "bcrypt"], "category": "ruby"},
    "doorkeeper": {"algorithms": ["OAuth", "RSA", "ECDSA", "HMAC", "JWT"], "category": "ruby"},
    "rack-oauth2": {"algorithms": ["OAuth2", "RSA", "ECDSA", "HMAC", "JWT", "AES"], "category": "ruby"},
    "rotp": {"algorithms": ["HOTP", "TOTP", "HMAC-SHA1", "HMAC-SHA256"], "category": "ruby"},
    "virtus": {"algorithms": ["AES", "RSA"], "category": "ruby"},
    "fido2": {"algorithms": ["FIDO2", "WebAuthn", "ECDSA", "EdDSA", "RSA"], "category": "ruby"},
    "webauthn": {"algorithms": ["WebAuthn", "ECDSA", "EdDSA", "RSA"], "category": "ruby"},
    "gpg": {"algorithms": ["OpenPGP", "GPG", "RSA", "DSA", "AES", "3DES"], "category": "ruby"},
    "ruby-gpg": {"algorithms": ["OpenPGP", "GPG"], "category": "ruby"},
    "sshkey": {"algorithms": ["SSH", "RSA", "Ed25519", "ECDSA", "DSA"], "category": "ruby"},
    "net-ssh": {"algorithms": ["SSH", "RSA", "Ed25519", "ECDSA", "AES", "ChaCha20", "HMAC"], "category": "ruby"},
    "x509": {"algorithms": ["X.509", "RSA", "ECDSA", "DSA"], "category": "ruby"},
    "cert_parser": {"algorithms": ["X.509", "RSA", "ECDSA"], "category": "ruby"},
}

MANIFEST_PATTERNS = [
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "pyproject.toml",
    "Cargo.toml",
    "package.json",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "composer.json",
    "*.csproj",
]


def _detect_language(manifest_path: str) -> str:
    filename = Path(manifest_path).name.lower()
    if filename in ("requirements.txt", "setup.py", "setup.cfg", "pipfile", "pyproject.toml"):
        return "python"
    if filename == "cargo.toml":
        return "rust"
    if filename == "package.json":
        return "javascript"
    if filename in ("go.mod", "go.sum"):
        return "go"
    if filename in ("pom.xml", "build.gradle", "build.gradle.kts"):
        return "java"
    if filename == "gemfile":
        return "ruby"
    if filename == "composer.json":
        return "php"
    if filename.endswith(".csproj"):
        return "dotnet"
    return "unknown"


def _parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=~<>!]+\s*([^\s;#]+)', line)
        if match:
            deps.append((match.group(1).lower(), match.group(2)))
        else:
            match = re.match(r'^([a-zA-Z0-9_.-]+)', line)
            if match:
                deps.append((match.group(1).lower(), "*"))
    return deps


def _parse_pipfile(content: str) -> list[tuple[str, str]]:
    deps = []
    in_packages = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[packages]"):
            in_packages = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_packages = False
            continue
        if in_packages and "=" in stripped:
            parts = stripped.split("=", 1)
            name = parts[0].strip().strip('"').strip("'")
            version = parts[1].strip().strip('"').strip("'").lstrip("*").lstrip("=").strip()
            if name and not name.startswith("_"):
                deps.append((name.lower(), version if version else "*"))
    return deps


def _parse_pyproject_toml(content: str) -> list[tuple[str, str]]:
    deps = []
    in_deps = False
    in_dev = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("dependencies = [", "[tool.poetry.dependencies]", "dependencies = ["):
            in_deps = True
            continue
        if stripped in ("[tool.poetry.dev-dependencies]", "dev-dependencies = [", "[project.optional-dependencies]"):
            in_dev = True
            continue
        if stripped.startswith("[") and stripped.endswith("]") and not stripped.startswith('["'):
            in_deps = False
            in_dev = False
            continue
        if in_deps or in_dev:
            match = re.match(r'^["\']?([a-zA-Z0-9_.-]+)["\']?\s*[=~<>!]*\s*["\']?([^"\'\s,]+)', stripped)
            if match:
                name = match.group(1).lower()
                version = match.group(2).strip().strip("*").strip().strip("\"'")
                deps.append((name, version if version else "*"))
            else:
                match = re.match(r'^([a-zA-Z0-9_.-]+)\s*$', stripped)
                if match:
                    deps.append((match.group(1).lower(), "*"))
    return deps


def _parse_cargo_toml(content: str) -> list[tuple[str, str]]:
    deps = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]", "[workspace.dependencies]"):
            in_deps = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deps = False
            continue
        if in_deps:
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*"([^"]*)"', stripped)
            if match:
                deps.append((match.group(1).lower(), match.group(2)))
                continue
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]*)"', stripped)
            if match:
                deps.append((match.group(1).lower(), match.group(2)))
                continue
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*\{[^}]*git\s*=', stripped)
            if match:
                deps.append((match.group(1).lower(), "git"))
                continue
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*\{', stripped)
            if match:
                deps.append((match.group(1).lower(), "*"))
    return deps


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, version in data.get(section, {}).items():
            clean_version = re.sub(r'^[\^~>=<]*', '', str(version)).strip()
            deps.append((name.lower(), clean_version if clean_version else "*"))
    return deps


def _parse_go_mod(content: str) -> list[tuple[str, str]]:
    deps = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if stripped.startswith("require ") and "(" not in stripped:
            match = re.match(r'^require\s+(\S+)\s+(\S+)', stripped)
            if match:
                deps.append((match.group(1).lower(), match.group(2)))
            continue
        if stripped == ")":
            in_require = False
            continue
        if in_require:
            match = re.match(r'^(\S+)\s+(\S+)', stripped)
            if match:
                deps.append((match.group(1).lower(), match.group(2)))
    return deps


def _parse_pom_xml(content: str) -> list[tuple[str, str]]:
    deps = []
    pattern = re.compile(
        r'<groupId>\s*([^<]+)</groupId>\s*<artifactId>\s*([^<]+)</artifactId>\s*(?:<version>\s*([^<]+)</version>)?',
        re.DOTALL
    )
    for match in pattern.finditer(content):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        version = match.group(3).strip() if match.group(3) else "*"
        full_name = f"{group_id}.{artifact_id}".lower()
        deps.append((full_name, version))
    return deps


def _parse_build_gradle(content: str) -> list[tuple[str, str]]:
    deps = []
    pattern = re.compile(r'''(?:implementation|compileOnly|testImplementation|api|runtimeOnly)\s+['"]([^'"]+):([^'"]+):([^'"]+)['"]''')
    for match in pattern.finditer(content):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        version = match.group(3).strip()
        full_name = f"{group_id}.{artifact_id}".lower()
        deps.append((full_name, version))
    return deps


def _parse_gemfile(content: str) -> list[tuple[str, str]]:
    deps = []
    for line in content.splitlines():
        stripped = line.strip()
        match = re.match(r"""^gem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]""", stripped)
        if match:
            deps.append((match.group(1).lower(), match.group(2)))
            continue
        match = re.match(r"""^gem\s+['"]([^'"]+)['"]""", stripped)
        if match:
            deps.append((match.group(1).lower(), "*"))
    return deps


def _parse_composer_json(content: str) -> list[tuple[str, str]]:
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in ("require", "require-dev"):
        for name, version in data.get(section, {}).items():
            clean_version = re.sub(r'^[\^~>=<]*', '', str(version)).strip()
            deps.append((name.lower(), clean_version if clean_version else "*"))
    return deps


def _parse_csproj(content: str) -> list[tuple[str, str]]:
    deps = []
    pattern = re.compile(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"')
    for match in pattern.finditer(content):
        deps.append((match.group(1).lower(), match.group(2)))
    pattern2 = re.compile(r'<PackageReference\s+Version="([^"]+)"\s+Include="([^"]+)"')
    for match in pattern2.finditer(content):
        deps.append((match.group(2).lower(), match.group(1)))
    return deps


def _parse_setup_py(content: str) -> list[tuple[str, str]]:
    deps = []
    in_install = False
    for line in content.splitlines():
        stripped = line.strip()
        if "install_requires" in stripped and "[" in stripped:
            in_install = True
            continue
        if in_install:
            if stripped.startswith("]"):
                in_install = False
                continue
            match = re.match(r"""['"]([a-zA-Z0-9_.-]+)['"]\s*[=~<>!]*\s*['"]?([^"',\s]+)""", stripped)
            if match:
                deps.append((match.group(1).lower(), match.group(2).strip().strip("\"'")))
            else:
                match = re.match(r"""['"]([a-zA-Z0-9_.-]+)['"]""", stripped)
                if match:
                    deps.append((match.group(1).lower(), "*"))
    return deps


def _parse_setup_cfg(content: str) -> list[tuple[str, str]]:
    deps = []
    in_install = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[options]") or stripped == "install_requires":
            in_install = True
            continue
        if stripped.startswith("[") and in_install:
            in_install = False
            continue
        if in_install and stripped:
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=~<>!]+\s*([^\s,]+)', stripped)
            if match:
                deps.append((match.group(1).lower(), match.group(2)))
            else:
                match = re.match(r'^([a-zA-Z0-9_.-]+)', stripped)
                if match:
                    deps.append((match.group(1).lower(), "*"))
    return deps


def _parse_go_sum(content: str) -> list[tuple[str, str]]:
    deps = []
    seen = set()
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            module = parts[0].lower()
            version = parts[1]
            if module not in seen:
                seen.add(module)
                deps.append((module, version))
    return deps


CRYPTO_PATTERNS = {
    "requirements.txt": _parse_requirements_txt,
    "Pipfile": _parse_pipfile,
    "pyproject.toml": _parse_pyproject_toml,
    "Cargo.toml": _parse_cargo_toml,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "pom.xml": _parse_pom_xml,
    "build.gradle": _parse_build_gradle,
    "build.gradle.kts": _parse_build_gradle,
    "Gemfile": _parse_gemfile,
    "composer.json": _parse_composer_json,
    "csproj": _parse_csproj,
    "setup.py": _parse_setup_py,
    "setup.cfg": _parse_setup_cfg,
    "go.sum": _parse_go_sum,
}


def _match_library(dep_name: str) -> tuple[str, dict[str, list[str]]] | None:
    clean_name = dep_name.split("/")[-1].lower()
    clean_name = re.sub(r'[-_](?:js|node|python|java|rb|go|rs|net|php|dotnet)$', '', clean_name)
    if clean_name in CRYPTO_LIBRARIES:
        return clean_name, CRYPTO_LIBRARIES[clean_name]
    for lib_name in CRYPTO_LIBRARIES:
        if clean_name == lib_name.lower():
            return lib_name, CRYPTO_LIBRARIES[lib_name]
        if clean_name.replace("-", "_") == lib_name.lower().replace("-", "_"):
            return lib_name, CRYPTO_LIBRARIES[lib_name]
    return None


def scan_manifest(
    manifest: str | dict | Path,
    manifest_type: str | None = None,
) -> list[AssetFinding]:
    """Scan a package manifest for crypto dependencies.

    Args:
        manifest: Either a directory path to scan, a manifest string, or a manifest dict.
        manifest_type: Force manifest type (e.g., "package.json", "requirements.txt").

    Returns:
        List of AssetFinding for each crypto dependency found.
    """
    findings: list[AssetFinding] = []

    if isinstance(manifest, dict):
        if manifest_type is None:
            manifest_type = "package.json"
        deps = _parse_package_json(json.dumps(manifest))
        findings.extend(_process_deps(deps, manifest_type, "<dict>"))
        return findings

    if isinstance(manifest, str) and not Path(manifest).exists():
        if manifest_type is None:
            manifest_type = "requirements.txt"
        parser = CRYPTO_PATTERNS.get(manifest_type)
        if parser is None:
            return findings
        deps = parser(manifest)
        if not deps or (len(deps) == 1 and deps[0][0] == "dependencies"):
            parser = CRYPTO_PATTERNS.get("pyproject.toml")
            if parser:
                deps = parser(manifest)
        findings.extend(_process_deps(deps, manifest_type, "<inline>"))
        return findings

    base = Path(manifest)
    if not base.exists():
        return findings

    for pattern in MANIFEST_PATTERNS:
        for manifest_path in base.rglob(pattern):
            try:
                content = manifest_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            filename = manifest_path.name
            if filename.endswith(".csproj"):
                parser = _parse_csproj
            elif filename == "go.sum":
                parser = _parse_go_sum
            else:
                parser = CRYPTO_PATTERNS.get(filename)
            if parser is None:
                continue

            deps = parser(content)
            language = _detect_language(filename)
            manifest_str = str(manifest_path.relative_to(base))

            findings.extend(_process_deps(deps, manifest_str, manifest_str))

    return findings


def _process_deps(
    deps: list[tuple[str, str]],
    manifest_str: str,
    host: str,
) -> list[AssetFinding]:
    findings: list[AssetFinding] = []
    for dep_name, version in deps:
        match = _match_library(dep_name)
        if match is None:
            continue

        lib_name, lib_info = match
        algorithms = lib_info["algorithms"]
        is_pqc = any(
            algo in ("Kyber", "ML-KEM", "Dilithium", "ML-DSA", "SPHINCS+", "SLH-DSA", "FALCON", "FRODOKEM")
            for algo in algorithms
        )

        findings.append(AssetFinding(
            asset_type="dependency_crypto_library",
            host=host,
            algorithm=algorithms[0],
            key_type="dependency",
            criticality="high" if is_pqc else "medium",
            metadata={
                "package_name": dep_name,
                "library": lib_name,
                "version": version,
                "algorithms": algorithms,
                "manifest": manifest_str,
            },
        ))
    return findings
