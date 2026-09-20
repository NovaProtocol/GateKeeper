"""Shared test setup.

House style: every environment variable the app reads is set here *before*
``shared.config`` (and therefore any app module) is imported, and the run gets
its own throwaway SQLite database under ``/tmp``, never the real
``/data/gatekeeper.db``.

``shared.config.get_config`` is ``lru_cache``d, so the environment below is read
exactly once. Anything tweaked per-test has to go through ``monkeypatch`` on the
cached ``Settings`` object instead of through the environment.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

# A per-run database so repeated runs cannot collide, and so a previous run's
# leftover file can never be mistaken for fixture data.
DB_PATH = (Path("/tmp") / f"gatekeeper_test_{uuid.uuid4().hex}.db").resolve()

# `SECRET_KEY` has a 32-char minimum; the rest are the compose-required set.
os.environ["SECRET_KEY"] = "test-secret-key-at-least-32-characters"
os.environ["MANAGE_PASSWORD"] = "test-manage-password"
os.environ["BACKUP_CODE"] = "test-backup-code"
os.environ["INTERNAL_API_KEY"] = "test-internal-api-key"
os.environ["DEPLOYMENT_TYPE"] = "debug"
os.environ["DB_DIR"] = str(DB_PATH.parent)
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{DB_PATH}"
os.environ["API_HTTP_ADDR"] = "http://api.invalid:8002"

# Imported only after the environment is in place.
from api.app import app as api_app  # noqa: E402
from management.app import app as manage_app  # noqa: E402


def _load_gateway_app():
    """Load ``auth-gateway/app.py`` under the name the container gives it.

    The image symlinks ``auth-gateway`` to ``auth_gateway`` so it can be run as
    ``app:app``; that link does not exist in a checkout, and the directory name
    is not importable, so load the module from its path instead of leaving a
    symlink in the repo.
    """
    path = BASE / "auth-gateway" / "app.py"
    spec = importlib.util.spec_from_file_location("auth_gateway.app", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["auth_gateway.app"] = module
    spec.loader.exec_module(module)
    return module.app


gateway_app = _load_gateway_app()

TEST_INTERNAL_API_KEY = os.environ["INTERNAL_API_KEY"]
TEST_SECRET_KEY = os.environ["SECRET_KEY"]


def _build_request(
    headers: dict[str, str] | None = None,
    client: tuple[str, int] | None = ("1.2.3.4", 1234),
) -> Request:
    """Build a real Starlette request so header lookup stays case-insensitive.

    A stub holding a plain dict for ``.headers`` would hide case handling, and
    the header names in ``shared.client_ip`` are mixed-case on purpose.
    """
    raw: list[tuple[bytes, bytes]] = [(b"host", b"example.test")]
    for name, value in (headers or {}).items():
        raw.append((name.lower().encode("latin-1"), value.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "root_path": "",
        "headers": raw,
        "client": client,
        "server": ("example.test", 80),
    }
    return Request(scope)  # type: ignore[arg-type]


@pytest.fixture(scope="session", autouse=True)
def _clean_test_db() -> Iterator[None]:
    """Remove the throwaway SQLite files before and after the run."""
    for suffix in ("", "-wal", "-shm"):
        Path(f"{DB_PATH}{suffix}").unlink(missing_ok=True)
    yield
    for suffix in ("", "-wal", "-shm"):
        Path(f"{DB_PATH}{suffix}").unlink(missing_ok=True)


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    """TestClient for the internal API service, with lifespan running."""
    with TestClient(api_app) as c:
        yield c


@pytest.fixture(scope="module")
def gateway_client() -> Iterator[TestClient]:
    """TestClient for the auth gateway (the forward-auth contract)."""
    with TestClient(gateway_app) as c:
        yield c


@pytest.fixture(scope="module")
def manage_client() -> Iterator[TestClient]:
    """TestClient for the management UI service."""
    with TestClient(manage_app) as c:
        yield c


@pytest.fixture()
def request_factory() -> Callable[..., Request]:
    """Expose the request builder so tests need not import this module."""
    return _build_request
