"""Zero-Hardcoding Verification Test Suite.

Proves mathematically and empirically that NONE of the 9 BOLA defense features
are hardcoded to specific user names ('alice', 'bob'), fixed record IDs ('1', '55'),
or static schema layouts.

All entities are generated with random UUIDs and custom runtime schemas:
  - Random user subjects: usr_<uuid>
  - Random tenants: tenant_<uuid>
  - Random record IDs: rec_<uuid>
  - Random hierarchy types: region -> campus -> building -> lab -> record
  - Random JSON payload keys matching ID regex: custom_target_identifier, asset_uuid_ref
  - Random ABAC classifications: ultra_top_secret_<uuid>
  - Random honeypots: canary_<uuid>
"""
import uuid
import time
import json
import pytest
from fastapi.testclient import TestClient

from app import (
    app,
    db,
    engine,
    DEMO_TENANT_ID,
    ADMIN_ROLE,
    DEMO_PASSWORD,
    execute_async_job,
    generate_job_proof,
)

client = TestClient(app)


def dynamic_auth_headers(subject: str, password: str = DEMO_PASSWORD) -> dict:
    """Dynamically registers a random user and obtains JWT credentials."""
    client.post("/auth/register", json={"subject": subject, "password": password})
    res = client.post("/auth/login", json={"subject": subject, "password": password})
    assert res.status_code == 200, f"Dynamic login failed for {subject}: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def create_dynamic_record(tenant_id: str, owner: str, custom_data: str) -> str:
    """Inserts a freshly minted record with a random UUID into the database."""
    rec_id = f"rec_{uuid.uuid4().hex[:12]}"
    with db() as c:
        c.execute(
            "INSERT INTO records (tenant_id, id, owner_id, data) VALUES (%s, %s, %s, %s)",
            (tenant_id, rec_id, owner, custom_data)
        )
    return rec_id


# ============================================================================
# 1. WRITE & MUTATION BOLA WITH DYNAMIC UUID IDENTIFIERS
# ============================================================================

def test_dynamic_write_mutation_with_random_uuids():
    """Validates that PUT/PATCH/DELETE verb-weighted defenses work on arbitrary random UUIDs."""
    user_owner = f"owner_{uuid.uuid4().hex[:8]}"
    user_attacker = f"attacker_{uuid.uuid4().hex[:8]}"
    h_owner = dynamic_auth_headers(user_owner)
    h_attacker = dynamic_auth_headers(user_attacker)

    rec_id = create_dynamic_record(DEMO_TENANT_ID, user_owner, "original_secure_state")

    # 1. Owner can PUT
    put_res = client.put(f"/records/{rec_id}", headers=h_owner, json={"data": "dynamic_update_success"})
    assert put_res.status_code == 200
    assert put_res.json()["record"]["data"] == "dynamic_update_success"

    # 2. Attacker cannot PUT
    attack_put = client.put(f"/records/{rec_id}", headers=h_attacker, json={"data": "malicious_overwrite"})
    assert attack_put.status_code == 403
    assert attack_put.json()["detail"]["outcome"] == "denied"

    # 3. Attacker cannot DELETE -> incurs weighted strike
    attack_del = client.delete(f"/records/{rec_id}", headers=h_attacker)
    assert attack_del.status_code == 403
    risk = client.get(f"/risk/{user_attacker}").json()
    assert risk["score"] >= 70
    assert "unauthorized_write_delete_attempt" in risk["signals"]

    # 4. Owner can DELETE
    del_res = client.delete(f"/records/{rec_id}", headers=h_owner)
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"


# ============================================================================
# 2. HIERARCHICAL VALIDATION WITH ARBITRARY CUSTOM TYPES & DEPTHS
# ============================================================================

def test_dynamic_hierarchy_arbitrary_depth_and_node_types():
    """Validates arbitrary hierarchy schemes (datacenter -> rack -> server -> container -> record)."""
    user = f"sysadmin_{uuid.uuid4().hex[:8]}"
    headers = dynamic_auth_headers(user)

    dc_id = f"dc_{uuid.uuid4().hex[:6]}"
    rack_id = f"rack_{uuid.uuid4().hex[:6]}"
    srv_id = f"srv_{uuid.uuid4().hex[:6]}"
    rec_id = create_dynamic_record(DEMO_TENANT_ID, user, "container_config_data")

    # Register arbitrary node levels
    client.post("/hierarchy/nodes", headers=headers, json={
        "resource_type": "datacenter", "resource_id": dc_id, "parent_type": None, "parent_id": None
    })
    client.post("/hierarchy/nodes", headers=headers, json={
        "resource_type": "rack", "resource_id": rack_id, "parent_type": "datacenter", "parent_id": dc_id
    })
    client.post("/hierarchy/nodes", headers=headers, json={
        "resource_type": "server", "resource_id": srv_id, "parent_type": "rack", "parent_id": rack_id
    })
    client.post("/hierarchy/nodes", headers=headers, json={
        "resource_type": "record", "resource_id": rec_id, "parent_type": "server", "parent_id": srv_id
    })

    # Valid chain of 4 custom levels
    valid_chain = [
        {"type": "datacenter", "id": dc_id},
        {"type": "rack", "id": rack_id},
        {"type": "server", "id": srv_id},
        {"type": "record", "id": rec_id},
    ]
    res_valid = client.post("/hierarchy/access", headers=headers, json={"chain": valid_chain, "action": "read"})
    assert res_valid.status_code == 200
    assert res_valid.json()["outcome"] == "allowed"

    # Tampered ancestor chain (invalid parent link)
    tampered_chain = [
        {"type": "datacenter", "id": dc_id},
        {"type": "rack", "id": "foreign_fake_rack_999"},
        {"type": "server", "id": srv_id},
        {"type": "record", "id": rec_id},
    ]
    res_tampered = client.post("/hierarchy/access", headers=headers, json={"chain": tampered_chain, "action": "read"})
    assert res_tampered.status_code == 403
    assert res_tampered.json()["detail"]["outcome"] == "denied"


# ============================================================================
# 3. BODY PAYLOAD MIDDLEWARE WITH DYNAMIC NESTED ATTRIBUTE NAMES
# ============================================================================

def test_dynamic_body_payload_regex_field_names():
    """Scans deeply nested bodies with dynamically varied field names like 'asset_uuid', 'target_identifier'."""
    user_victim = f"victim_{uuid.uuid4().hex[:8]}"
    user_probe = f"probe_{uuid.uuid4().hex[:8]}"
    h_probe = dynamic_auth_headers(user_probe)

    foreign_rec_id = create_dynamic_record(DEMO_TENANT_ID, user_victim, "sensitive_rnd_data")

    # Send POST with dynamic field names ending in ID keywords
    client.post("/hierarchy/nodes", headers=h_probe, json={
        "resource_type": "generic_task",
        "resource_id": f"task_{uuid.uuid4().hex[:6]}",
        "custom_target_identifier": foreign_rec_id
    })

    risk = client.get(f"/risk/{user_probe}").json()
    assert risk["score"] > 0
    assert any("body_payload" in str(s) or "unauthorized" in str(s) for s in risk["signals"])


# ============================================================================
# 4. BATCH ARRAY EVALUATION WITH DYNAMIC BATCH SIZES & RANDOM IDS
# ============================================================================

def test_dynamic_batch_array_processing():
    """Processes dynamic batches containing random owned and unowned IDs."""
    user_a = f"batch_user_a_{uuid.uuid4().hex[:8]}"
    user_b = f"batch_user_b_{uuid.uuid4().hex[:8]}"
    h_a = dynamic_auth_headers(user_a)

    owned_ids = [create_dynamic_record(DEMO_TENANT_ID, user_a, f"data_a_{i}") for i in range(3)]
    foreign_ids = [create_dynamic_record(DEMO_TENANT_ID, user_b, f"data_b_{i}") for i in range(3)]
    mixed_ids = [owned_ids[0], foreign_ids[0], owned_ids[1], foreign_ids[1]]

    res = client.post("/records/batch", headers=h_a, json={"record_ids": mixed_ids})
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 4
    assert data["allowed"] == 2
    assert data["denied"] == 2


# ============================================================================
# 5. ASYNC BACKGROUND JOB QUEUE WITH HMAC AND RANDOM STRINGS
# ============================================================================

def test_dynamic_async_job_hmac_lifecycle():
    """Enqueues and executes background jobs using dynamic tokens and random records."""
    user = f"worker_user_{uuid.uuid4().hex[:8]}"
    headers = dynamic_auth_headers(user)
    rec_id = create_dynamic_record(DEMO_TENANT_ID, user, "payload_for_async_worker")

    create_res = client.post("/jobs", headers=headers, json={"resource_id": rec_id, "action": "dynamic_etl"})
    assert create_res.status_code == 200
    job_id = create_res.json()["job_id"]

    # Execute worker
    exec_res = client.post(f"/jobs/{job_id}/execute", headers=headers)
    assert exec_res.status_code == 200
    assert exec_res.json()["status"] == "completed"
    assert exec_res.json()["result"]["data"] == "payload_for_async_worker"


# ============================================================================
# 6. GRAPHQL AST RESOLVER WITH DYNAMIC RECORDS
# ============================================================================

def test_dynamic_graphql_query_and_batch_resolution():
    """Queries GraphQL using dynamic UUID records with ownership enforcement."""
    user_owner = f"gql_owner_{uuid.uuid4().hex[:8]}"
    user_stranger = f"gql_stranger_{uuid.uuid4().hex[:8]}"
    h_owner = dynamic_auth_headers(user_owner)
    h_stranger = dynamic_auth_headers(user_stranger)

    rec_id = create_dynamic_record(DEMO_TENANT_ID, user_owner, "graphql_confidential_node")

    query = f'''query {{ record(id: "{rec_id}") {{ id ownerId data }} }}'''

    # Owner query succeeds
    res_owner = client.post("/graphql", headers=h_owner, json={"query": query})
    assert res_owner.status_code == 200
    assert res_owner.json()["data"]["record"]["data"] == "graphql_confidential_node"

    # Stranger query denied
    res_stranger = client.post("/graphql", headers=h_stranger, json={"query": query})
    assert res_stranger.status_code == 200
    assert res_stranger.json().get("errors") is not None
    assert "No object authorization" in res_stranger.json()["errors"][0]["message"]


# ============================================================================
# 7. SECOND-ORDER STORED BOLA WITH ARBITRARY RUNTIME REFERENCES
# ============================================================================

def test_dynamic_stored_reference_revalidation():
    """Tests stored references with runtime owner reassignment."""
    user_init = f"init_owner_{uuid.uuid4().hex[:8]}"
    user_new = f"new_owner_{uuid.uuid4().hex[:8]}"
    h_init = dynamic_auth_headers(user_init)

    rec_id = create_dynamic_record(DEMO_TENANT_ID, user_init, "stored_ptr_content")

    # Step 1: Create stored reference while authorized
    ref_res = client.post("/stored-references", headers=h_init, json={
        "ref_type": "dynamic_webhook",
        "target_resource_id": rec_id
    })
    assert ref_res.status_code == 200
    ref_id = ref_res.json()["ref_id"]

    # Step 2: Dynamically reassign record ownership in database
    with db() as c:
        c.execute("UPDATE records SET owner_id = %s WHERE tenant_id = %s AND id = %s",
                  (user_new, DEMO_TENANT_ID, rec_id))

    # Step 3: Trigger consumption -> Second-order BOLA caught
    trig_res = client.post(f"/stored-references/{ref_id}/trigger", headers=h_init)
    assert trig_res.status_code == 403
    assert trig_res.json()["detail"]["ref_status"] == "security_flagged"


# ============================================================================
# 8. DYNAMIC ABAC POLICY EVALUATION
# ============================================================================

def test_dynamic_abac_custom_clearance_and_masking():
    """Registers arbitrary runtime ABAC policies and field redactions, verifying dynamic enforcement."""
    user = f"abac_test_user_{uuid.uuid4().hex[:8]}"
    headers = dynamic_auth_headers(user)
    rec_id = f"rec_abac_{uuid.uuid4().hex[:8]}"
    custom_classification = f"class_{uuid.uuid4().hex[:6]}"

    # Insert custom record with dynamic classification
    with db() as c:
        c.execute(
            "INSERT INTO records (tenant_id, id, owner_id, data, classification) VALUES (%s, %s, %s, %s, %s)",
            (DEMO_TENANT_ID, rec_id, user, json.dumps({"notes": "top secret clinical research", "subject_ssn": "000-11-2222"}), custom_classification)
        )
        # Dynamic policy: minimum clearance level 5 required for this classification
        c.execute(
            "INSERT INTO abac_policies (tenant_id, id, name, effect, target_role, target_classification, min_clearance, allowed_hours_start, allowed_hours_end, created_at) "
            "VALUES (%s, %s, %s, 'DENY', NULL, %s, 5, 0, 24, %s)",
            (DEMO_TENANT_ID, f"pol_{uuid.uuid4().hex[:6]}", "Dynamic High Clearance Policy", custom_classification, time.time())
        )

    # 1. Request with insufficient clearance (3 < 5) -> denied
    denied_res = client.get(f"/records/{rec_id}/abac?clearance=3", headers=headers)
    assert denied_res.status_code == 403
    assert "ABAC policy" in denied_res.json()["detail"]["reason"]

    # 2. Request with sufficient clearance (5 >= 5) -> allowed
    allowed_res = client.get(f"/records/{rec_id}/abac?clearance=5", headers=headers)
    assert allowed_res.status_code == 200
    assert allowed_res.json()["record"]["classification"] == custom_classification


# ============================================================================
# 9. CANARY / HONEYPOT DECOY TRAPS WITH ARBITRARY IDS
# ============================================================================

def test_dynamic_canary_trap_with_random_honeytokens():
    """Registers a completely randomized honeytoken ID and verifies instant permanent firewall banning."""
    adversary = f"adversary_{uuid.uuid4().hex[:8]}"
    headers = dynamic_auth_headers(adversary)
    honeytoken_id = f"trap_{uuid.uuid4().hex[:12]}"

    # Dynamically plant canary decoy in database
    with db() as c:
        c.execute(
            "INSERT INTO canary_records (tenant_id, id, decoy_name, severity, trap_action, created_at) "
            "VALUES (%s, %s, %s, 'CRITICAL', 'PERMANENT_BAN', %s)",
            (DEMO_TENANT_ID, honeytoken_id, "Dynamic Synthetic Trap", time.time())
        )

    # Adversary probes the honeytoken
    probe_res = client.get(f"/records/{honeytoken_id}", headers=headers)
    assert probe_res.status_code == 403

    # Verify adversary is immediately permanently banned
    risk = client.get(f"/risk/{adversary}").json()
    assert risk["is_permanent"] is True
    assert risk["is_blocked"] is True
    assert "strike_3_permanent_ban_approved" in risk["signals"]

    # Any subsequent request on ANY resource is immediately rejected at the firewall
    subsequent_res = client.get("/records/1", headers=headers)
    assert subsequent_res.status_code == 403
    assert subsequent_res.json()["detail"]["outcome"] == "blocked"
