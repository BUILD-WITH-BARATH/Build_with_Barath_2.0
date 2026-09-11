import httpx
import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from cyberaccess_sdk import CyberAccessClient
from cyberaccess_sdk.fastapi import enforce

BASE = "https://api.example.test"

guard = CyberAccessClient(api_key="sk_test", base_url=BASE)
app = FastAPI()


@app.get("/records/{record_id}")
def get_record(record_id: str, subject: str = "alice", is_owner: bool = True):
    result = enforce(guard, subject=subject, resource_id=record_id, authorized=is_owner)
    return {"record_id": record_id, "risk_score": result.score}


client = TestClient(app)


@respx.mock
def test_route_allows_when_engine_allows():
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={"decision": "allow", "score": 0, "category": "Normal", "signals": []})
    )
    res = client.get("/records/1")
    assert res.status_code == 200
    assert res.json()["risk_score"] == 0


@respx.mock
def test_route_returns_403_when_engine_blocks_despite_is_owner_true():
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={
            "decision": "block", "score": 100, "category": "Attack", "signals": ["sequential_id_enumeration"],
        })
    )
    res = client.get("/records/1?is_owner=true")
    assert res.status_code == 403
    assert res.json()["detail"]["outcome"] == "blocked"


@respx.mock
def test_route_returns_403_when_denied():
    respx.post(f"{BASE}/v1/authorize").mock(
        return_value=httpx.Response(200, json={"decision": "deny", "score": 0, "category": "Normal", "signals": []})
    )
    res = client.get("/records/1?is_owner=false")
    assert res.status_code == 403
    assert res.json()["detail"]["outcome"] == "denied"
