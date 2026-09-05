"""Create and use a local secret for deterministic HMAC pseudonyms."""

import hashlib
import hmac
import os
import secrets
from pathlib import Path


KEY_BYTES = 32


def load_or_create_key(path):
    """Reuse a dataset key when it exists; otherwise create a new 256-bit key."""
    path = Path(path)
    if path.exists():
        key = path.read_bytes()
        if len(key) != KEY_BYTES:
            raise ValueError(f"Expected a {KEY_BYTES}-byte key in {path}")
        return key

    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(KEY_BYTES)
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def hmac_digest(key, domain, value):
    message = f"{domain}|{str(value).strip()}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_token(key, domain, value):
    """Return an opaque, domain-separated token without exposing the source value."""
    return f"hmac_{domain}_{hmac_digest(key, domain, value).hex()[:24]}"


def ipv4_token(key, domain, value):
    """Map an IPv4 address into 10.0.0.0/8 using a keyed HMAC digest."""
    digest = hmac_digest(key, domain, value)
    return f"10.{digest[0]}.{digest[1]}.{digest[2]}"
