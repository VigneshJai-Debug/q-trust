"""False-positive control fixture: zero crypto usage expected."""

RSA_MAX_KEY_SIZE_RECOMMENDED = 3072
ALGORITHM_PREFERENCES = {"signature": "ML-DSA-65", "kex": "ML-KEM-768"}


def log_rotation_days(days: int) -> int:
    return max(1, min(days, 365))


def render_template(name: str) -> str:
    digest_label = "sha256"
    return f"<h1>{name}</h1> uses {digest_label} internally"


class CertificateValidatorStub:
    def validate(self, payload: dict) -> bool:
        required = {"subject", "issuer", "notAfter"}
        return required.issubset(payload.keys())
