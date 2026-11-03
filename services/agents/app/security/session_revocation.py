"""Is this console session still valid, according to the user record?

GHSA-8cpf-mchw-jpf2, F16. ``verify_console_token`` checks the signature, the
algorithm, the token type, expiry and that a tenant is present -- and consults
no user record. So a token minted before an operator deactivated that user, or
revoked their sessions, stayed valid on this service until it expired, while
the API refused the very same token: ``token_is_revoked`` there compares the
token's ``iat`` against ``users.sessions_revoked_at``.

That gap is the whole reason revoking a session is a control. An operator who
deactivates somebody and sees them disappear from the console reasonably
believes they are out; on these routes they were not, and these routes create
and run response playbooks.

Why this lives here and not in ``tenant_scope``
-----------------------------------------------
``tenant_scope.py`` is vendored into nine services, most of which hold no
database connection and would have to grow one to satisfy a control they do
not need. It exposes a hook; this module is the answer for the one service
that both needs it and can give it.

What happens when the database is unreachable
----------------------------------------------
The request is **refused with 503**, not allowed. The token is valid and the
question is unanswered, so the honest statement is "this service cannot tell",
and an unknown that counts as a pass is the defect shape this repository has
recorded several times. The blast radius of that choice is bounded: it refuses
this service's own routes, and the console's other surfaces go through the
API, which answers the question from its own session.

The cache is what stops this being a database round trip per request. It is
small and short-lived on purpose -- a revocation that takes up to
``_TTL_SECONDS`` to bite is a real cost, and it is the cost of not putting a
query on every call. A *negative* answer is cached for the same window; a
positive one is not re-read at all, because access does not come back.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from app.security.tenant_scope import RevocationUnavailable

logger = logging.getLogger("aisoc.agents.session_revocation")

#: How long a "this user is fine" answer is reused.
_TTL_SECONDS = 30.0

#: user_id -> (expires_at_monotonic, sessions_revoked_at_epoch | None, is_active)
_CACHE: dict[str, tuple[float, float | None, bool]] = {}

_POOL: Any = None

_SQL = """
    SELECT is_active,
           EXTRACT(EPOCH FROM sessions_revoked_at) AS revoked_epoch
      FROM users
     WHERE id = $1::uuid
"""


def reset_for_tests() -> None:
    """Drop the cache and the pool handle."""
    global _POOL
    _CACHE.clear()
    _POOL = None


async def _pool() -> Any:
    global _POOL
    if _POOL is not None:
        return _POOL
    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        return None
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if dsn.startswith(prefix):
            dsn = "postgresql://" + dsn[len(prefix) :]
            break
    try:
        import asyncpg
    except ImportError as exc:  # pragma: no cover - the lock ships it
        raise RevocationUnavailable("asyncpg is not installed") from exc
    try:
        _POOL = await asyncpg.create_pool(dsn, min_size=1, max_size=4, timeout=3.0)
    except Exception as exc:  # noqa: BLE001
        raise RevocationUnavailable(f"could not connect: {exc}") from exc
    return _POOL


async def check(claims: dict) -> str | None:
    """``None`` if the session stands, else a short reason it does not.

    Raises :class:`RevocationUnavailable` when the user record cannot be read.
    """
    subject = str(claims.get("sub") or "").strip()
    if not subject:
        # A token with no subject names nobody, so there is no record to
        # consult. `verify_console_token` already requires a tenant; a
        # missing `sub` is left to the tenant scope rather than refused here,
        # because inventing a second place that rejects tokens is how two
        # authorities come to disagree.
        return None

    now = time.monotonic()
    cached = _CACHE.get(subject)
    if cached is not None and cached[0] > now:
        return _verdict(claims, revoked_epoch=cached[1], is_active=cached[2])

    pool = await _pool()
    if pool is None:
        # No DATABASE_URL at all. This is a configuration, not a read
        # failure: a deployment with no database cannot have a user table to
        # revoke in, and refusing every request there would make the service
        # unusable rather than safe. Distinguished from an unreachable
        # database, which does raise.
        return None

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(_SQL, subject)
    except Exception as exc:  # noqa: BLE001
        raise RevocationUnavailable(str(exc)) from exc

    if row is None:
        # The token names a user this deployment does not have. That is not a
        # revocation, it is a token for somewhere else, and it is refused.
        return "the principal named by this token does not exist"

    is_active = bool(row["is_active"])
    revoked_epoch = float(row["revoked_epoch"]) if row["revoked_epoch"] is not None else None
    _CACHE[subject] = (now + _TTL_SECONDS, revoked_epoch, is_active)
    return _verdict(claims, revoked_epoch=revoked_epoch, is_active=is_active)


def _verdict(claims: dict, *, revoked_epoch: float | None, is_active: bool) -> str | None:
    if not is_active:
        return "the account has been deactivated"
    if revoked_epoch is None:
        return None
    issued_at = claims.get("iat")
    if not isinstance(issued_at, int | float):
        # A token with no `iat` cannot be placed on either side of a
        # revocation. Treated as predating it, which fails closed -- the same
        # reading `token_is_revoked` in services/api gives, and for the same
        # reason: the alternative lets a token escape a revocation by
        # omitting the claim that would have caught it.
        return "this session predates a session revocation"
    if float(issued_at) < revoked_epoch:
        return "this session predates a session revocation"
    return None
