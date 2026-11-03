"""A ChatOps verification prompt gets one reply, across a restart.

GHSA-vf98-8367-45mp, F04. Replay protection for these prompts was a
module-level ``set[str]`` in ``api/router.py``, under a comment saying
"anything more durable belongs in Redis once we move off the in-memory action
store" -- a future that had already arrived, since the store has been
Postgres-backed for several versions.

A set in process memory is not replay protection. It is empty after every
restart and was never populated on the second replica, so the same signed
payload -- inside its own expiry window, so the HMAC and the expiry both still
pass -- was accepted again. A single-use control enforced nothing across
either boundary.
"""

from __future__ import annotations

import importlib

import pytest
from app.services import action_store


@pytest.fixture(autouse=True)
def _clean():
    action_store.clear()
    yield
    action_store.clear()


async def _seed(action_id: str) -> None:
    await action_store.save(
        {
            "id": action_id,
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "tenant_id": "22222222-2222-2222-2222-222222222222",
            "action_type": "notify_slack",
            "target": "#soc",
            "rationale": "verification prompt",
            "status": "awaiting_approval",
        }
    )


@pytest.mark.asyncio
async def test_the_first_reply_is_claimed():
    """Positive control, and it is the one that matters most here.

    Replay protection that refuses the *first* reply would pass every test
    below and silently discard every genuine answer an analyst gives -- which
    reads to them as a broken link rather than as a control.
    """
    await _seed("act-1")
    assert await action_store.claim_chatops_reply("act-1") is True


@pytest.mark.asyncio
async def test_a_second_reply_to_the_same_prompt_is_refused():
    await _seed("act-2")
    assert await action_store.claim_chatops_reply("act-2") is True
    assert await action_store.claim_chatops_reply("act-2") is False


@pytest.mark.asyncio
async def test_two_different_prompts_do_not_collide():
    """Second positive control: the claim is per action, not a global latch."""
    await _seed("act-3")
    await _seed("act-4")
    assert await action_store.claim_chatops_reply("act-3") is True
    assert await action_store.claim_chatops_reply("act-4") is True


@pytest.mark.asyncio
async def test_the_claim_survives_the_router_module_being_reimported():
    """The restart, as far as a test can reach it.

    The defect was that the record of a reply lived in the module's own
    globals, so re-importing it -- which is what a process restart does to
    every module -- lost it. Re-importing `api.router` here and finding the
    claim still refused is the property; the durable half is proved against
    real Postgres by the row predicate in `claim_chatops_reply`.

    Note the direction of the check: `_chatops_replied` must not come back.
    A reimported module that re-creates the set would pass a test that only
    asked "is the second reply refused", because the *store* would refuse it
    anyway -- so this asserts the weak path is gone as well as that the
    strong one works.
    """
    await _seed("act-5")
    assert await action_store.claim_chatops_reply("act-5") is True

    router_module = importlib.import_module("app.api.router")
    importlib.reload(router_module)
    assert not hasattr(router_module, "_chatops_replied"), (
        "the in-memory replay set is back; it is empty after a restart and was never populated on the second replica"
    )

    assert await action_store.claim_chatops_reply("act-5") is False
