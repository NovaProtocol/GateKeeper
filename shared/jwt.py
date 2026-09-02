from __future__ import annotations

import uuid
import datetime as dt
from typing import Any

import jwt

from shared.config import get_config

ISS = "gatekeeper"
AUD = "projectnova.download"
ALG = "HS256"

# Grace fallback window for old itsdangerous cookies — one deploy cycle
_FALLBACK_ENABLED = True


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _secret(secret: str | None = None) -> str:
    if secret:
        return secret
    return get_config().SECRET_KEY


def create_access_token(cid: int, name: str, secret: str | None = None, expires_hours: int = 12) -> str:
    sec = _secret(secret)
    now = _now()
    payload = {
        "sub": str(cid),
        "cid": cid,
        "name": name,
        "iss": ISS,
        "aud": AUD,
        "iat": now,
        "exp": now + dt.timedelta(hours=expires_hours),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, sec, algorithm=ALG)


def verify_access_token(token: str, secret: str | None = None) -> dict[str, Any] | None:
    sec = _secret(secret)
    try:
        data = jwt.decode(token, sec, algorithms=[ALG], audience=AUD, issuer=ISS)
        return data
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        if _FALLBACK_ENABLED:
            fb = _fallback_load(token)
            if fb is not None:
                try:
                    import logging

                    logging.getLogger("jwt").info("jwt_fallback_used", extra={"fallback": "access"})
                except Exception:
                    pass
                return {"cid": None, "name": "", "code": fb, "fallback": True, "sub": fb}
        return None
    except Exception:
        return None


def create_manage_token(secret: str | None = None, expires_hours: int = 8) -> str:
    sec = _secret(secret)
    now = _now()
    payload = {
        "sub": "manage",
        "role": "manage",
        "iss": ISS,
        "aud": AUD,
        "iat": now,
        "exp": now + dt.timedelta(hours=expires_hours),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, sec, algorithm=ALG)


def verify_manage_token(token: str, secret: str | None = None) -> dict[str, Any] | None:
    sec = _secret(secret)
    try:
        data = jwt.decode(token, sec, algorithms=[ALG], audience=AUD, issuer=ISS)
        if data.get("sub") != "manage":
            return None
        return data
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        if _FALLBACK_ENABLED:
            fb = _fallback_load(token)
            if fb is not None and fb == "manage-ok":
                try:
                    import logging

                    logging.getLogger("jwt").info("jwt_fallback_used", extra={"fallback": "manage"})
                except Exception:
                    pass
                return {"sub": "manage", "role": "manage", "fallback": True}
        return None
    except Exception:
        return None


def create_custom_token(rid: int, secret: str | None = None, expires_hours: int = 12) -> str:
    sec = _secret(secret)
    now = _now()
    payload = {
        "sub": f"custom-{rid}",
        "rid": rid,
        "iss": ISS,
        "aud": AUD,
        "iat": now,
        "exp": now + dt.timedelta(hours=expires_hours),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, sec, algorithm=ALG)


def verify_custom_token(token: str, rid: int, secret: str | None = None) -> bool:
    sec = _secret(secret)
    try:
        data = jwt.decode(token, sec, algorithms=[ALG], audience=AUD, issuer=ISS)
        return int(data.get("rid", -1)) == int(rid)
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        if _FALLBACK_ENABLED:
            # old per-rule itsdangerous with salt f"custom-{rid}"
            try:
                from itsdangerous import URLSafeSerializer

                ser = URLSafeSerializer(sec, salt=f"custom-{rid}")
                ser.loads(token)
                try:
                    import logging

                    logging.getLogger("jwt").info("jwt_fallback_used", extra={"fallback": f"custom-{rid}"})
                except Exception:
                    pass
                return True
            except Exception:
                return False
        return False
    except Exception:
        return False


def _fallback_load(token: str) -> str | None:
    try:
        from itsdangerous import BadSignature, URLSafeSerializer

        ser = URLSafeSerializer(_secret(), salt="cookie")
        return ser.loads(token)
    except Exception:
        return None


def decode_without_verify(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None
