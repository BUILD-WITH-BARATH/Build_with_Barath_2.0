import httpx
import pytest
import respx

from cyberaccess_sdk import CyberAccessClient, AsyncCyberAccessClient, CyberAccessBlocked

BASE = "https://api.example.test"


@respx.mock
def test_authorize_allow():
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={"decision": "allow", "score": 0, "category": "Normal", "signals": []})
    )
    client = CyberAccessClient(api_key="sk_test", base_url=BASE)
    result = client.authorize("alice", "record-1", authorized=True)
    assert result.allowed
    assert not result.blocked
    assert result.score == 0


@respx.mock
def test_authorize_deny():
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={"decision": "deny", "score": 0, "category": "Normal", "signals": []})
    )
    client = CyberAccessClient(api_key="sk_test", base_url=BASE)
    result = client.authorize("bob", "record-2", authorized=False)
    assert result.decision == "deny"
    assert not result.allowed
    assert not result.blocked


@respx.mock
def test_authorize_block_overrides_authorized_true():
    """The whole point of the product: caller says authorized=True, but the
    behavioral engine can still override to block on an attack pattern."""
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={
            "decision": "block", "score": 100, "category": "Attack",
            "signals": ["unauthorized_unique_object_pressure"],
        })
    )
    client = CyberAccessClient(api_key="sk_test", base_url=BASE)
    result = client.authorize("attacker", "record-3", authorized=True)
    assert result.blocked
    assert result.score == 100


@respx.mock
def test_invalid_api_key_raises_value_error():
    respx.post(f"{BASE}/v1/authorize").mock(return_value=httpx.Response(401, json={"detail": "Invalid API key"}))
    client = CyberAccessClient(api_key="sk_bad", base_url=BASE)
    with pytest.raises(ValueError):
        client.authorize("alice", "record-1", authorized=True)


@respx.mock
def test_fail_open_on_network_error_allows_authorized_true():
    respx.post(f"{BASE}/v1/authorize").mock(side_effect=httpx.ConnectError("unreachable"))
    client = CyberAccessClient(api_key="sk_test", base_url=BASE, fail_open=True)
    result = client.authorize("alice", "record-1", authorized=True)
    assert result.decision == "allow"


@respx.mock
def test_fail_open_on_network_error_denies_authorized_false():
    respx.post(f"{BASE}/v1/authorize").mock(side_effect=httpx.ConnectError("unreachable"))
    client = CyberAccessClient(api_key="sk_test", base_url=BASE, fail_open=True)
    result = client.authorize("alice", "record-1", authorized=False)
    assert result.decision == "deny"


@respx.mock
def test_fail_closed_on_network_error_always_denies():
    respx.post(f"{BASE}/v1/authorize").mock(side_effect=httpx.ConnectError("unreachable"))
    client = CyberAccessClient(api_key="sk_test", base_url=BASE, fail_open=False)
    result = client.authorize("alice", "record-1", authorized=True)
    assert result.decision == "deny"
    assert not result.blocked  # fail-closed is a deny, never a fabricated "block"


@respx.mock
def test_authorize_or_raise_raises_on_block():
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={"decision": "block", "score": 100, "category": "Attack", "signals": []})
    )
    client = CyberAccessClient(api_key="sk_test", base_url=BASE)
    with pytest.raises(CyberAccessBlocked):
        client.authorize_or_raise("attacker", "record-1", authorized=True)


@respx.mock
def test_authorize_or_raise_does_not_raise_on_deny():
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={"decision": "deny", "score": 0, "category": "Normal", "signals": []})
    )
    client = CyberAccessClient(api_key="sk_test", base_url=BASE)
    result = client.authorize_or_raise("bob", "record-1", authorized=False)
    assert result.decision == "deny"


@respx.mock
def test_authorize_mutation_passes_http_verb():
    route = respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={"decision": "block", "score": 75, "category": "Attack", "signals": ["unauthorized_write_delete_attempt"]})
    )
    client = CyberAccessClient(api_key="sk_test", base_url=BASE)
    result = client.authorize_mutation("attacker", "record-1", authorized=False, http_verb="DELETE")
    assert result.blocked
    assert result.score == 75
    assert "unauthorized_write_delete_attempt" in result.signals


@respx.mock
def test_authorize_batch_evaluates_items():
    respx.post(f"{BASE}/v1/authorize-batch").mock(
        return_value=httpx.Response(200, json={
            "total": 2, "blocked_mid_batch": False,
            "results": [{"resource_id": "1", "decision": "allow", "score": 0, "signals": []},
                        {"resource_id": "2", "decision": "deny", "score": 25, "signals": []}]
        })
    )
    client = CyberAccessClient(api_key="sk_test", base_url=BASE)
    batch_res = client.authorize_batch("alice", [{"resource_id": "1", "authorized": True}, {"resource_id": "2", "authorized": False}])
    assert batch_res["total"] == 2
    assert len(batch_res["results"]) == 2
    assert batch_res["results"][0]["decision"] == "allow"


@pytest.mark.anyio
@respx.mock
async def test_async_authorize_allow():
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={"decision": "allow", "score": 0, "category": "Normal", "signals": []})
    )
    async with AsyncCyberAccessClient(api_key="sk_test", base_url=BASE) as client:
        result = await client.authorize("alice", "record-1", authorized=True)
        assert result.allowed
        assert not result.blocked


@pytest.mark.anyio
@respx.mock
async def test_async_authorize_mutation():
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={"decision": "block", "score": 80, "category": "Attack", "signals": ["unauthorized_write_delete_attempt"]})
    )
    async with AsyncCyberAccessClient(api_key="sk_test", base_url=BASE) as client:
        result = await client.authorize_mutation("attacker", "record-1", authorized=False, http_verb="DELETE")
        assert result.blocked
        assert result.score == 80


@pytest.mark.anyio
@respx.mock
async def test_async_authorize_batch():
    respx.post(f"{BASE}/v1/authorize-batch").mock(
        return_value=httpx.Response(200, json={
            "total": 1, "blocked_mid_batch": False,
            "results": [{"resource_id": "10", "decision": "allow", "score": 0, "signals": []}]
        })
    )
    async with AsyncCyberAccessClient(api_key="sk_test", base_url=BASE) as client:
        batch_res = await client.authorize_batch("alice", [{"resource_id": "10", "authorized": True}])
        assert batch_res["total"] == 1
        assert batch_res["results"][0]["resource_id"] == "10"

