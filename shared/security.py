from __future__ import annotations

import hashlib
import hmac
import secrets


def hash_custom_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(32)
    h = hashlib.pbkdf2_hmac("sha512", password.encode(), salt.encode(), 100000)
    return h.hex(), salt


def verify_custom_password(password: str, hash_hex: str, salt: str) -> bool:
    h = hashlib.pbkdf2_hmac("sha512", password.encode(), salt.encode(), 100000)
    return hmac.compare_digest(h.hex(), hash_hex)


def hash_api_key(key: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha512", key.encode(), salt.encode(), 100000).hex()


def mask_code(code: str) -> str:
    if len(code) <= 8:
        return code[:2] + "***" + code[-2:]
    return code[:4] + "***" + code[-4:]


def host_matches(pattern: str, host: str) -> bool:
    pattern = pattern.lower().strip()
    host = host.lower().strip().split(":")[0]
    if pattern == "*.*/*" or pattern == "*.*":
        return True
    p = pattern.split("/")[0]
    if p == "*.*":
        return True
    if p.startswith("*."):
        apex = p[2:]
        return host == apex or host.endswith("." + apex)
    return host == p


def path_matches(pattern: str, path: str) -> bool:
    pat = pattern.split("?")[0]
    if pat.endswith("/*"):
        prefix = pat[:-1]
        if prefix == "/":
            return True
        if path == prefix.rstrip("/"):
            return True
        return path.startswith(prefix)
    return path == pat


def is_valid_host(host: str) -> bool:
    import re

    if not host:
        return False
    if host == "*.*/*" or host == "*.*":
        return True
    h = host.split("/")[0].lower()
    return bool(re.match(r"^(\*\.)?[a-z0-9-]+(\.[a-z0-9.-]+)?$", h))


def apex_domain(host: str) -> str:
    host = host.split(":")[0].lower()
    parts = host.split(".")
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])
