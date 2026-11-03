"""A deactivated user's token stops working here too.

GHSA-8cpf-mchw-jpf2, F16. `verify_console_token` checks the signature, the
algorithm, the token type, expiry and that a tenant is present -- and consults
no user record. So a token minted before an operator deactivated that user, or
revoked their sessions, stayed valid on these routes until it expired, while
the API refused the very same token (`token_is_revoked` there compares `iat`
against `users.sessions_revoked_at`).

Measured before the fix: `verify_console_token` accepted a token issued two
hours earlier with no lookup of any kind, and a route answered 200.

That gap is the whole reason revoking a session is a control. An operator who
deactivates somebody and watches them vanish from the console reasonably
believes they are out; on these routes they were not, and these routes create
and run response playbooks.

The three states, and why the third is a refusal
-------------------------------------------------
* **in good standing** -- proceed.
* **withdrawn** -- 401, naming which of the two withdrawals it was.
* **unreadable** -- 503, *not* a pass. The token is valid and the question is
  unanswered, so the honest statement is "this service cannot tell". An
  unknown that counts as a pass is the defect shape this repository has
  recorded several times over; the cost is bounded, because it refuses this
  service's own routes and the console's other surfaces go through the API.
"""

from __future__ import annotations

import time

import pytest
from app.security import session_revocation
from app.security.tenant_scope import RevocationUnavailable, require_console_or_service_auth, set_revocation_check
from fastapi import HTTPException

SECRET = "agents-revocation-test-secret-at-least-32-characters"


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_CONSOLE_JWT_SECRET", SECRET)
    monkeypatch.setenv("ENVIRONMENT", "production")
    session_revocation.reset_for_tests()
    yield
    set_revocation_check(None)
    session_revocation.reset_for_tests()


def _claims(*, iat: float | None = None) -> dict:
    out: dict = {"sub": "11111111-1111-1111-1111-111111111111", "tenant_id": "22222222-2222-2222-2222-222222222222"}
    if iat is not None:
        out["iat"] = iat
    return out


class TestTheVerdictItself:
    """`_verdict` is the decision; the lookup around it is plumbing."""

    def test_a_deactivated_account_is_refused(self) -> None:
        assert session_revocation._verdict(_claims(iat=time.time()), revoked_epoch=None, is_active=False)

    def test_a_token_older_than_the_revocation_is_refused(self) -> None:
        now = time.time()
        assert session_revocation._verdict(_claims(iat=now - 3600), revoked_epoch=now, is_active=True)

    def test_a_token_newer_than_the_revocation_still_works(self) -> None:
        """Positive control, and the one that matters.

        Revoking a session signs everybody out and then lets them sign back
        in. A check that refused every token after any revocation would pass
        the test above and lock the user out permanently -- the fail-closed
        shape this repository has shipped before.
        """
        now = time.time()
        assert session_revocation._verdict(_claims(iat=now), revoked_epoch=now - 3600, is_active=True) is None

    def test_an_account_with_no_revocation_is_untouched(self) -> None:
        """Second positive control: the common case, which must cost nothing."""
        assert session_revocation._verdict(_claims(iat=time.time()), revoked_epoch=None, is_active=True) is None

    def test_a_token_with_no_iat_is_treated_as_predating_the_revocation(self) -> None:
        """Fails closed, matching `token_is_revoked` in services/api.

        The alternative lets a token escape a revocation by omitting the
        claim that would have caught it.
        """
        assert session_revocation._verdict(_claims(), revoked_epoch=time.time(), is_active=True)


class TestTheDependencyActsOnIt:
    @pytest.mark.asyncio
    async def test_a_withdrawn_session_is_refused_with_401(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def withdrawn(_claims: dict) -> str:
            return "the account has been deactivated"

        set_revocation_check(withdrawn)
        with pytest.raises(HTTPException) as exc:
            await require_console_or_service_auth(authorization=f"Bearer {_signed()}", x_aisoc_tenant_id=None)
        assert exc.value.status_code == 401
        assert "deactivated" in exc.value.detail

    @pytest.mark.asyncio
    async def test_an_unreadable_record_is_a_503_and_not_a_pass(self) -> None:
        async def unreadable(_claims: dict) -> str | None:
            raise RevocationUnavailable("connection refused")

        set_revocation_check(unreadable)
        with pytest.raises(HTTPException) as exc:
            await require_console_or_service_auth(authorization=f"Bearer {_signed()}", x_aisoc_tenant_id=None)
        assert exc.value.status_code == 503, "an unanswerable revocation question was treated as 'not revoked'"

    @pytest.mark.asyncio
    async def test_a_principal_in_good_standing_is_admitted(self) -> None:
        """Positive control for the dependency.

        A hook that refused everything would satisfy both tests above and
        lock every console user out of this service.
        """

        async def fine(_claims: dict) -> None:
            return None

        set_revocation_check(fine)
        principal = await require_console_or_service_auth(authorization=f"Bearer {_signed()}", x_aisoc_tenant_id=None)
        assert not principal.is_empty

    @pytest.mark.asyncio
    async def test_with_no_hook_registered_nothing_changes(self) -> None:
        """The eight other services that vendor this module are unaffected.

        They hold no database connection and would have to grow one to
        satisfy a control they do not need.
        """
        set_revocation_check(None)
        principal = await require_console_or_service_auth(authorization=f"Bearer {_signed()}", x_aisoc_tenant_id=None)
        assert not principal.is_empty


class TestWhatCountsAsUnreadable:
    @pytest.mark.asyncio
    async def test_no_database_url_is_a_configuration_not_a_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A deployment with no database has no user table to revoke in.

        Raising here would make the service unusable rather than safe, and it
        is a different fact from a database that exists and cannot be read.
        """
        monkeypatch.delenv("DATABASE_URL", raising=False)
        assert await session_revocation.check(_claims(iat=time.time())) is None

    # `touches_database` because it drives the real asyncpg client at a DSN
    # the test sets itself. That is the point: the refusal has to come from a
    # genuine connection failure, not from a stub that was told to raise.
    @pytest.mark.touches_database
    @pytest.mark.asyncio
    async def test_an_unreachable_database_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DATABASE_URL", "postgresql://nobody@127.0.0.1:1/none")
        with pytest.raises(RevocationUnavailable):
            await session_revocation.check(_claims(iat=time.time()))


def _signed() -> str:
    import base64
    import hashlib
    import hmac
    import json
    import uuid

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    now = int(time.time())
    payload = b64(
        json.dumps(
            {
                "sub": str(uuid.uuid4()),
                "tenant_id": str(uuid.uuid4()),
                "role": "tenant_admin",
                "type": "access",
                "iat": now,
                "exp": now + 3600,
            },
            separators=(",", ":"),
        ).encode()
    )
    sig = hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64(sig)}"
