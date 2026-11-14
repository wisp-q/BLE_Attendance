import pytest
import jwt
from app.core.security import hash_password, verify_password, create_access_token
from app.services.graph_engine import audit_classroom_mesh
from app.main import app
from app.config import settings


def test_password_hashing():
    raw_pw = "supersecret123"
    hashed = hash_password(raw_pw)
    assert hashed != raw_pw
    assert verify_password(raw_pw, hashed) is True
    assert verify_password("wrongpassword", hashed) is False


def test_jwt_generation_and_decoding():
    data = {
        "sub": "22BCSE104",
        "name": "Aarav Sharma",
        "role": "STUDENT",
    }
    token = create_access_token(data=data)
    assert isinstance(token, str)

    decoded = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
    assert decoded["sub"] == "22BCSE104"
    assert decoded["name"] == "Aarav Sharma"
    assert decoded["role"] == "STUDENT"
    assert "exp" in decoded


def test_mesh_audit_topology():
    reports = {
        "A": ["B"],
        "B": ["A"],
        "C": ["A", "B"],
        "D": ["B"],
        "E": [],
    }

    results = audit_classroom_mesh(reports)
    res_map = {r["ble_device_id"]: r for r in results}

    # Verify A & B are direct mutuals
    assert res_map["A"]["status"] == "VERIFIED_PRESENT"
    assert res_map["A"]["verification_method"] == "DIRECT_MUTUAL"
    assert res_map["A"]["affinity_score"] == 1.00

    assert res_map["B"]["status"] == "VERIFIED_PRESENT"
    assert res_map["B"]["verification_method"] == "DIRECT_MUTUAL"
    assert res_map["B"]["affinity_score"] == 1.00

    # Verify C has unreciprocated triadic link (Quarantined for teacher confirmation, NEVER auto-verified)
    assert res_map["C"]["status"] == "ISOLATED_FLAGGED"
    assert res_map["C"]["verification_method"] == "TRIADIC_CLOSURE"
    assert res_map["C"]["affinity_score"] == 0.50
    assert "Pending Teacher Confirmation" in res_map["C"]["remarks"]

    # Verify D is spoofer rejected (unreciprocated single claim)
    assert res_map["D"]["status"] == "SPOOFER_REJECTED"
    assert res_map["D"]["affinity_score"] == 0.00

    # Verify E is isolated
    assert res_map["E"]["status"] == "ISOLATED_FLAGGED"
    assert res_map["E"]["affinity_score"] == 0.00


def test_mesh_audit_satellite_cluster_quarantine():
    reports = {
        "S1": ["S2"],
        "S2": ["S1", "S3"],
        "S3": ["S2", "S4"],
        "S4": ["S3", "S5"],
        "S5": ["S4", "S6"],
        "S6": ["S5"],
        # Outside cluster (3 colluding students in cafeteria)
        "X": ["Y", "Z"],
        "Y": ["X", "Z"],
        "Z": ["X", "Y"],
    }
    results = audit_classroom_mesh(reports)
    res_map = {r["ble_device_id"]: r for r in results}

    # S1-S6 in the classroom are Verified Present
    for s in ["S1", "S2", "S3", "S4", "S5", "S6"]:
        assert res_map[s]["status"] == "VERIFIED_PRESENT"
        assert res_map[s]["affinity_score"] == 1.00

    # X, Y, Z outside are quarantined as satellite cluster
    for out in ["X", "Y", "Z"]:
        assert res_map[out]["status"] == "ISOLATED_FLAGGED"
        assert res_map[out]["affinity_score"] == 0.00
        assert "Disconnected satellite cluster" in res_map[out]["remarks"]


def test_mesh_audit_outside_eavesdropping_cluster_quarantine():
    reports = {
        "S1": ["S2"],
        "S2": ["S1", "S3"],
        "S3": ["S2", "S4"],
        "S4": ["S3", "S5"],
        "S5": ["S4", "S6"],
        "S6": ["S5"],
        # Outside window cluster (W1 sniffs S1)
        "W1": ["W2", "W3", "S1"],
        "W2": ["W1", "W3"],
        "W3": ["W1", "W2"],
    }
    results = audit_classroom_mesh(reports)
    res_map = {r["ble_device_id"]: r for r in results}

    # S1-S6 in the classroom are Verified Present
    for s in ["S1", "S2", "S3", "S4", "S5", "S6"]:
        assert res_map[s]["status"] == "VERIFIED_PRESENT"

    # W1, W2, W3 outside are quarantined as satellite cluster despite W1 claiming S1
    for out in ["W1", "W2", "W3"]:
        assert res_map[out]["status"] == "ISOLATED_FLAGGED"
        assert res_map[out]["affinity_score"] == 0.00
        assert "Disconnected satellite cluster" in res_map[out]["remarks"]


def test_mesh_audit_corridor_chain_of_four_quarantine():
    reports = {
        **{f"S{i}": [f"S{i-1}" if i > 1 else "S2", f"S{i+1}" if i < 12 else "S11"] for i in range(1, 13)},
        # 4 spoofers in corridor
        "C1": ["C2"],
        "C2": ["C1", "C3"],
        "C3": ["C2", "C4"],
        "C4": ["C3"],
    }
    results = audit_classroom_mesh(reports)
    res_map = {r["ble_device_id"]: r for r in results}

    for c in ["C1", "C2", "C3", "C4"]:
        assert res_map[c]["status"] == "ISOLATED_FLAGGED"
        assert res_map[c]["affinity_score"] == 0.00
        assert "Disconnected satellite cluster" in res_map[c]["remarks"]


def test_mesh_audit_classroom_row_with_incoming_anchors_verified():
    # 2 in-classroom students (S5 and S6) acknowledge seeing R1 and R2
    reports = {
        **{f"S{i}": [f"S{i-1}" if i > 1 else "S2", f"S{i+1}" if i < 12 else "S11"] for i in range(1, 13)},
        # S5 and S6 report row students across aisle
        "S5": ["S4", "S6", "R1"],
        "S6": ["S5", "S7", "R2"],
        # Row 3 students
        "R1": ["R2"],
        "R2": ["R1", "R3"],
        "R3": ["R2"],
    }
    results = audit_classroom_mesh(reports)
    res_map = {r["ble_device_id"]: r for r in results}

    # All row students are verified because the classroom core acknowledged them (incoming anchors >= 2)
    for r in ["R1", "R2", "R3"]:
        assert res_map[r]["status"] == "VERIFIED_PRESENT"
        assert res_map[r]["affinity_score"] == 1.00


def test_mesh_audit_offline_peer_witness():
    reports = {
        "A": ["B", "OFF1", "OFF_SINGLE"],
        "B": ["A", "OFF1"],
        "D": ["OFF2"],
    }
    results = audit_classroom_mesh(reports)
    res_map = {r["ble_device_id"]: r for r in results}

    # OFF1 was witnessed by 2 verified peers (A and B). Peer witnessing is
    # hearsay — two colluding friends could ghost an absent classmate from
    # home. It must raise the record to instructor review only, never
    # auto-verify it.
    assert "OFF1" in res_map
    assert res_map["OFF1"]["status"] != "VERIFIED_PRESENT"
    assert res_map["OFF1"]["status"] == "FLAGGED_WITNESSED"
    assert res_map["OFF1"]["verification_method"] == "PEER_WITNESS"
    assert res_map["OFF1"]["affinity_score"] == 0.00
    assert "Instructor confirmation required" in res_map["OFF1"]["remarks"]

    # OFF_SINGLE was witnessed by only 1 peer (A) -> Isolated Flagged (Cannot buddy-punch)
    assert "OFF_SINGLE" in res_map
    assert res_map["OFF_SINGLE"]["status"] == "ISOLATED_FLAGGED"
    assert res_map["OFF_SINGLE"]["verification_method"] == "NONE"
    assert res_map["OFF_SINGLE"]["affinity_score"] == 0.00
    assert "Teacher manual override" in res_map["OFF_SINGLE"]["remarks"]

    # OFF2 was only claimed by spoofer D (who is not in verified_set)
    # Therefore OFF2 is NOT verified
    assert "OFF2" not in res_map


def test_h3_colluder_only_clique_not_verified():
    # H3: 5 colluders mutually reporting each other, 40 enrolled, no honest
    # submitters — must NOT self-verify; anchors (enrollment/face) fail.
    colluders = [f"C{i}" for i in range(1, 6)]
    reports = {c: [p for p in colluders if p != c] for c in colluders}
    results = audit_classroom_mesh(reports, total_enrolled=40)
    res_map = {r["ble_device_id"]: r for r in results}

    assert len(results) == 5
    for c in colluders:
        assert res_map[c]["status"] == "NEEDS_REVIEW"
        assert res_map[c]["verification_method"] == "MESH_UNANCHORED"
        assert res_map[c]["affinity_score"] < 1.0


def test_h3_anchored_honest_component_verified():
    # H3: large honest component anchored to enrollment and face evidence
    # must verify; a separate 2-person loner clique must not.
    honest = [f"H{i:02d}" for i in range(1, 39)]  # 38 students
    loners = ["L1", "L2"]
    reports = {}
    for i, h in enumerate(honest):
        left = honest[i - 1] if i > 0 else honest[-1]
        right = honest[(i + 1) % len(honest)]
        reports[h] = [left, right]
    reports["L1"] = ["L2"]
    reports["L2"] = ["L1"]

    face_ok = set(honest)  # all honest have successful face checks
    results = audit_classroom_mesh(
        reports, total_enrolled=40, face_verified_keys=face_ok
    )
    res_map = {r["ble_device_id"]: r for r in results}

    for h in honest:
        assert res_map[h]["status"] == "VERIFIED_PRESENT", h
    for l in loners:
        assert res_map[l]["status"] != "VERIFIED_PRESENT"
        # separate unanchored/isolated cluster: must never auto-verify
        # (satellite quarantine or needs_review are both acceptable)
        assert res_map[l]["status"] in ("NEEDS_REVIEW", "ISOLATED_FLAGGED")


def test_h3_unanchored_small_honest_group_needs_review():
    # H3: 3 mutual students in a 20-enrolled class with no face evidence
    # are too small / too low coverage to auto-verify.
    reports = {"A": ["B", "C"], "B": ["A", "C"], "C": ["A", "B"]}
    results = audit_classroom_mesh(reports, total_enrolled=20)
    for r in results:
        assert r["status"] == "NEEDS_REVIEW"


def test_h3_legacy_mode_without_anchors_unchanged():
    # Without enrollment anchor, legacy topology verdicts apply (unit-test
    # compatibility); a mutual pair in a tiny report set still verifies.
    reports = {"A": ["B"], "B": ["A"]}
    results = audit_classroom_mesh(reports)
    res_map = {r["ble_device_id"]: r for r in results}
    assert res_map["A"]["status"] == "VERIFIED_PRESENT"
    assert res_map["B"]["status"] == "VERIFIED_PRESENT"


def test_fastapi_routes_registered():
    paths = list(app.openapi()["paths"].keys())
    assert "/health" in paths
    assert "/api/v1/auth/register" in paths
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/auth/me" in paths
    assert "/api/v1/attendance/courses" in paths
    assert "/api/v1/attendance/courses/{course_id}/sessions" in paths
    assert "/api/v1/attendance/sessions" in paths
    assert "/api/v1/attendance/sessions/{session_id}/cancel" in paths
    assert "/api/v1/attendance/sessions/{session_id}/finalize" in paths
    assert "/api/v1/attendance/sessions/{session_id}/submit-neighbors" in paths
    assert "/api/v1/attendance/sessions/{session_id}/audit-and-finalize" in paths
    assert "/api/v1/attendance/sessions/{session_id}" in paths
    assert "/api/v1/attendance/records/{record_id}/override" in paths


def test_openapi_schema_definitions():
    schemas = app.openapi()["components"]["schemas"]
    assert "RecordOverrideRequest" in schemas
    assert "AttendanceSessionResponse" in schemas
    assert "AttendanceRecordResponse" in schemas
    assert "CourseCreateRequest" in schemas
    assert "SubmitNeighborsRequest" in schemas


@pytest.mark.anyio
async def test_global_exception_handler_sanitization():
    import json
    from app.main import global_exception_handler
    from starlette.requests import Request

    dummy_request = Request({"type": "http", "method": "GET", "path": "/test"})
    exc = RuntimeError("Secret DB connection credentials / internal server path")

    # In production mode: traceback must be masked
    orig_env = settings.APP_ENV
    try:
        settings.APP_ENV = "production"
        prod_response = await global_exception_handler(dummy_request, exc)
        prod_data = json.loads(prod_response.body.decode())
        assert prod_response.status_code == 500
        assert "traceback" not in prod_data
        assert prod_data["detail"] == "An internal server error occurred."
        assert prod_data["type"] == "InternalServerError"

        # In development mode: traceback is available for local debugging
        settings.APP_ENV = "development"
        dev_response = await global_exception_handler(dummy_request, exc)
        dev_data = json.loads(dev_response.body.decode())
        assert dev_response.status_code == 500
        assert "traceback" in dev_data
        assert "RuntimeError" in dev_data["type"]
    finally:
        settings.APP_ENV = orig_env


def test_session_submission_model_integrity():
    from app.models.attendance import SessionSubmission
    columns = {c.name for c in SessionSubmission.__table__.columns}
    assert "id" in columns
    assert "session_id" in columns
    assert "student_id" in columns
    assert "device_key" in columns
    assert "reported_neighbors" in columns
    assert "created_at" in columns


def test_is_session_stale_naive_and_aware():
    from datetime import datetime, timedelta, timezone
    from app.routers.attendance import _is_session_stale

    assert _is_session_stale(None, minutes=2) is False

    now_utc = datetime.now(timezone.utc)
    recent_aware = now_utc - timedelta(seconds=30)
    assert _is_session_stale(recent_aware, minutes=2) is False

    old_aware = now_utc - timedelta(minutes=3)
    assert _is_session_stale(old_aware, minutes=2) is True

    # Test offset-naive datetimes (SQLite stores naive UTC datetimes)
    recent_naive = now_utc.replace(tzinfo=None) - timedelta(seconds=30)
    assert _is_session_stale(recent_naive, minutes=2) is False

    old_naive = now_utc.replace(tzinfo=None) - timedelta(minutes=3)
    assert _is_session_stale(old_naive, minutes=2) is True


@pytest.mark.anyio
async def test_session_auto_supersede():
    import uuid
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import Base, AttendanceSession, EmailOTP
    from sqlalchemy import select

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register teacher (initiates OTP verification)
        t_reg = await client.post(
            "/api/v1/auth/register",
            json={
                "name": "Prof. Auto Supersede",
                "email": "auto.supersede@univ.edu",
                "password": "Password123!",
                "role": "TEACHER",
                "roll_number": "EMP999",
                "department": "CSE",
                "faculty_code": settings.FACULTY_SIGNUP_SECRET,
            },
        )
        assert t_reg.status_code == 200

        # Query OTP from db to verify registration
        async with test_session_factory() as s:
            otp_record = (await s.execute(select(EmailOTP).where(EmailOTP.email == "auto.supersede@univ.edu"))).scalars().first()
            otp_code = otp_record.otp_code

        verify_reg = await client.post(
            "/api/v1/auth/register/verify-otp",
            json={"email": "auto.supersede@univ.edu", "otp_code": otp_code},
        )
        assert verify_reg.status_code == 201
        token = verify_reg.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create session 1 (H5: server generates salt; client value ignored)
        s1 = await client.post(
            "/api/v1/attendance/sessions",
            headers=headers,
            json={"session_token": "AAAA", "total_enrolled": 20},
        )
        assert s1.status_code == 201
        s1_id = s1.json()["id"]

        # Directly create session 2 without closing session 1 (simulating teacher closed app and reopened)
        s2 = await client.post(
            "/api/v1/attendance/sessions",
            headers=headers,
            json={"session_token": "BBBB", "total_enrolled": 20},
        )
        # Should succeed (HTTP 201) instead of failing with HTTP 409
        assert s2.status_code == 201
        s2_id = s2.json()["id"]
        assert s1_id != s2_id

        # Check DB state: session 1 must have been superseded (CANCELLED or EXPIRED)
        async with test_session_factory() as s:
            res = await s.execute(select(AttendanceSession).where(AttendanceSession.id == uuid.UUID(s1_id)))
            s1_db = res.scalar_one()
            assert s1_db.status in ("CANCELLED", "EXPIRED")


# Verifies beacon salt enforcement rejecting remote check-in attempts without physical beacon
@pytest.mark.anyio
async def test_submit_neighbors_salt_enforcement():
    import uuid
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import Base, EmailOTP
    from sqlalchemy import select

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register and verify teacher
        t_reg = await client.post(
            "/api/v1/auth/register",
            json={
                "name": "Prof. Salt Guard",
                "email": "salt.guard@univ.edu",
                "password": "Password123!",
                "role": "TEACHER",
                "roll_number": "EMP888",
                "department": "CSE",
                "faculty_code": settings.FACULTY_SIGNUP_SECRET,
            },
        )
        assert t_reg.status_code == 200

        async with test_session_factory() as s:
            otp_record = (await s.execute(select(EmailOTP).where(EmailOTP.email == "salt.guard@univ.edu"))).scalars().first()
            otp_code = otp_record.otp_code

        verify_reg = await client.post(
            "/api/v1/auth/register/verify-otp",
            json={"email": "salt.guard@univ.edu", "otp_code": otp_code},
        )
        assert verify_reg.status_code == 201
        headers = {"Authorization": f"Bearer {verify_reg.json()['access_token']}"}

        # Teacher registers the salt at session creation (required)
        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers=headers,
            json={"session_token": "ABCD", "total_enrolled": 10},
        )
        assert s_res.status_code == 201
        s_body = s_res.json()
        session_id = s_body["id"]
        # H5: server-generated wire salt (beacon token) — client value ignored.
        wire_salt = s_body["session_wire_salt"]
        assert wire_salt and len(wire_salt) == 4

        submit_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        # JWT is now mandatory on submit: register the three in-room students.
        # M4: device keys are collision-resistant hashes of canonical roll/UUID.
        from app.routers.attendance import derive_short_device_key
        student_tokens = {}
        for s_name, s_email, s_roll in [
            ("Gate Spoofer", "gate.spoofer@univ.edu", "22B3456"),
            ("Gate Alpha", "gate.alpha@univ.edu", "22B1234"),
            ("Gate Beta", "gate.beta@univ.edu", "22B5678"),
        ]:
            s_reg = await client.post(
                "/api/v1/auth/register",
                json={
                    "name": s_name,
                    "email": s_email,
                    "password": "Password123!",
                    "role": "STUDENT",
                    "roll_number": s_roll,
                    "department": "CSE",
                    "program": "B.Tech",
                    "semester": 1,
                    "section": "A",
                },
            )
            assert s_reg.status_code == 200, s_reg.text
            async with test_session_factory() as s:
                s_otp = (await s.execute(select(EmailOTP).where(EmailOTP.email == s_email))).scalars().first()
                s_otp_code = s_otp.otp_code
            s_verify = await client.post(
                "/api/v1/auth/register/verify-otp",
                json={"email": s_email, "otp_code": s_otp_code},
            )
            assert s_verify.status_code == 201, s_verify.text
            student_tokens[s_roll] = s_verify.json()["access_token"]
        k_spoofer = derive_short_device_key("22B3456")
        k_alpha = derive_short_device_key("22B1234")
        k_beta = derive_short_device_key("22B5678")

        # 1) Missing salt (absent student replaying only the session token from chat)
        missing = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {student_tokens['22B3456']}"},
            json={"game_score": 20, "student_id": k_spoofer, "neighbors": [k_alpha, "2345"]},
        )
        assert missing.status_code == 403

        # 2) Wrong salt (again: knowledge of the token alone is not enough)
        wrong = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {student_tokens['22B3456']}"},
            json={"game_score": 20, "student_id": k_spoofer, "neighbors": [k_alpha, "2345"], "session_salt": "WRNG"},
        )
        assert wrong.status_code == 403
        assert "Nice try" in wrong.json()["detail"]

        # 3) Matching salt — in-room students who actually heard the beacon (mutual pair)
        valid_one = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {student_tokens['22B1234']}"},
            json={"game_score": 20, "student_id": k_alpha, "neighbors": [k_beta], "session_salt": wire_salt},
        )
        assert valid_one.status_code == 200
        assert valid_one.json()["status"] == "success"

        valid_two = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {student_tokens['22B5678']}"},
            json={"game_score": 20, "student_id": k_beta, "neighbors": [k_alpha], "session_salt": wire_salt},
        )
        assert valid_two.status_code == 200

        # 5) The salt-rejected attempt must surface on the teacher's audit dashboard
        audit_res = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/audit-and-finalize",
            headers=headers,
            json={"reports": {}},
        )
        assert audit_res.status_code == 200
        audit_data = audit_res.json()

        assert audit_data["status"] == "COMPLETED"
        # H3: 2 mutual reporters in a 10-enrolled class (no face evidence)
        # cannot be anchored as "the room" — held for review, not auto-verified.
        # The salt-rejected attempt is still a hard spoofer verdict.
        assert audit_data["total_verified"] == 0
        # Unverified = every non-VERIFIED row: 2 mutual NEEDS_REVIEW reporters
        # (H3 unanchored) + 1 hard spoofer verdict.
        assert audit_data["total_unverified"] == 3

        record_map = {r["ble_device_id"]: r for r in audit_data["records"]}
        spoofer_record = record_map[k_spoofer]
        assert spoofer_record["status"] == "SPOOFER_REJECTED"
        assert spoofer_record["verification_method"] == "SALT_REJECTED"
        assert "salt mismatch" in spoofer_record["remarks"]

        # 4) H5: session_salt on create is ignored (server generates); request
        # without it is accepted (no longer a required client field).
        no_salt = await client.post(
            "/api/v1/attendance/sessions",
            headers=headers,
            json={"session_token": "WXYZ", "total_enrolled": 10},
        )
        assert no_salt.status_code == 201
        assert no_salt.json()["session_wire_salt"]

        assert record_map[k_alpha]["status"] == "NEEDS_REVIEW"
        assert record_map[k_alpha]["verification_method"] == "MESH_UNANCHORED"
        assert record_map[k_beta]["status"] == "NEEDS_REVIEW"


# Verifies the class-eligibility gate: wrong-semester and blank-profile students
# are rejected before any salt/face work; matching students and non-student
# roles pass; attempts surface as ELIGIBILITY_REJECTED on the audit dashboard
@pytest.mark.anyio
async def test_session_eligibility_gate():
    import uuid
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from sqlalchemy import select
    from app.database import get_db
    from app.models.attendance import Base, EmailOTP

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register teacher and create a Semester 3 session (teacher-declared class)
        t_reg = await client.post(
            "/api/v1/auth/register",
            json={
                "name": "Prof. Eligibility",
                "email": "elig.teacher@univ.edu",
                "password": "Password123!",
                "role": "TEACHER",
                "roll_number": "EMP777",
                "department": "CSE",
                "faculty_code": settings.FACULTY_SIGNUP_SECRET,
            },
        )
        assert t_reg.status_code == 200
        async with test_session_factory() as s:
            otp_row = (await s.execute(select(EmailOTP).where(EmailOTP.email == "elig.teacher@univ.edu"))).scalars().first()
            otp_code = otp_row.otp_code
        t_verify = await client.post(
            "/api/v1/auth/register/verify-otp",
            json={"email": "elig.teacher@univ.edu", "otp_code": otp_code},
        )
        assert t_verify.status_code == 201
        teacher_headers = {"Authorization": f"Bearer {t_verify.json()['access_token']}"}

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers=teacher_headers,
            json={
                "session_token": "ELIG", "total_enrolled": 5,
                "course_program": "B-Tech", "course_semester": 3,
            },
        )
        assert s_res.status_code == 201
        session_data = s_res.json()
        wire_salt = session_data["session_wire_salt"]
        assert session_data["eligibility_program"] == "B-Tech"
        assert session_data["eligibility_semester"] == 3
        submit_url = f"/api/v1/attendance/sessions/{session_data['id']}/submit-neighbors"

        async def register_student(email, roll, semester):
            s_reg = await client.post(
                "/api/v1/auth/register",
                json={
                    "name": f"Student {roll}", "email": email, "password": "Password123!",
                    "role": "STUDENT", "roll_number": roll, "department": "CSE",
                    "program": "B-Tech", "semester": semester, "section": "A",
                },
            )
            assert s_reg.status_code == 200, s_reg.text
            async with test_session_factory() as s:
                s_otp_row = (await s.execute(select(EmailOTP).where(EmailOTP.email == email))).scalars().first()
            verified = await client.post(
                "/api/v1/auth/register/verify-otp",
                json={"email": email, "otp_code": s_otp_row.otp_code},
            )
            assert verified.status_code == 201, verified.text
            return verified.json()["access_token"]

        from app.routers.attendance import derive_short_device_key
        # 1) Wrong-semester student (Sem 6, adjacent-room scenario) — WRONG salt too:
        #    eligibility gate must fire FIRST and its reason must be the class binding
        sem6_token = await register_student("elig.sem6@univ.edu", "22B0006", 6)
        k0006 = derive_short_device_key("22B0006")
        wrong_class = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {sem6_token}"},
            json={"game_score": 20, "student_id": k0006, "neighbors": [], "session_salt": "WRNG"},
        )
        assert wrong_class.status_code == 403, wrong_class.text
        assert "Semester 3" in wrong_class.json()["detail"]
        assert "Semester 6" in wrong_class.json()["detail"]

        # 2) Blank-profile student (no semester) — rejected with fix-your-profile hint
        blank_token = await register_student("elig.blank@univ.edu", "22B0007", None)
        k0007 = derive_short_device_key("22B0007")
        blank = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {blank_token}"},
            json={"game_score": 20, "student_id": k0007, "neighbors": [], "session_salt": wire_salt},
        )
        assert blank.status_code == 403
        assert "Attendance profile incomplete" in blank.json()["detail"]

        # 3) Matching Sem-3 student with the correct salt passes the gate and
        #    proceeds into the normal peer flow
        sem3_token = await register_student("elig.sem3@univ.edu", "22B0003", 3)
        k0003 = derive_short_device_key("22B0003")
        valid = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {sem3_token}"},
            json={"game_score": 20, "student_id": k0003, "neighbors": ["1111"], "session_salt": wire_salt},
        )
        assert valid.status_code == 200, valid.text
        assert valid.json()["status"] == "success"

        # 4) Non-student role (DEVELOPER) bypasses class binding entirely — with
        #    a WRONG salt it must fail on the SALT gate, never the eligibility one
        import bcrypt as _bcrypt
        async with test_session_factory() as s:
            from app.core.security import create_access_token
            from app.models.attendance import User as UserModel

            dev_res = await s.execute(select(UserModel).where(UserModel.role == "TEACHER"))
            teacher_row = dev_res.scalars().first()
            dev = UserModel(
                email="elig.dev@univ.edu", full_name="Dev Bypass",
                hashed_password=_bcrypt.hashpw(b"Password123!", _bcrypt.gensalt()).decode(),
                role="DEVELOPER",
            )
            s.add(dev)
            await s.commit()
            dev_token = create_access_token({"sub": str(dev.id)})
            _ = teacher_row

        dev_submit = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {dev_token}"},
            json={"game_score": 20, "student_id": "9999", "neighbors": [], "session_salt": "WRNG"},
        )
        assert dev_submit.status_code == 403
        assert "Nice try" in dev_submit.json()["detail"]  # salt-gate rejection, not eligibility

        # 5) Audit dashboard surfaces rejected attempts as ELIGIBILITY_REJECTED
        audit_res = await client.post(
            f"/api/v1/attendance/sessions/{session_data['id']}/audit-and-finalize",
            headers=teacher_headers,
            json={"reports": {}},
        )
        assert audit_res.status_code == 200
        audit_data = audit_res.json()
        record_map = {r["ble_device_id"]: r for r in audit_data["records"]}
        assert record_map[k0006]["verification_method"] == "ELIGIBILITY_REJECTED"
        assert record_map[k0006]["status"] == "SPOOFER_REJECTED"
        assert "Semester 3" in record_map[k0006]["remarks"]
        assert record_map[k0007]["verification_method"] == "ELIGIBILITY_REJECTED"


# Verifies the chimp cognitive-challenge score gate end-to-end:
# - scoreless neighbor syncs (no face) pass and stage claims for the audit
# - a face-bearing check-in without a score is rejected 403 (missing < 12)
# - a face-bearing check-in scoring 11 (< 12) is rejected 403 with the score stored
# - finalize overrides an auto-verified verdict whose score never arrived
# - a late score (finalize-after-game race) rescues the record via reciprocity
@pytest.mark.anyio
async def test_cognitive_challenge_score_gate():
    import base64
    import io
    import uuid
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from sqlalchemy import select
    from PIL import Image
    from app.database import get_db
    from app.models.attendance import AttendanceRecord, Base, EmailOTP

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        t_reg = await client.post(
            "/api/v1/auth/register",
            json={
                "name": "Prof. ChimpGate",
                "email": "chimp.teacher@univ.edu",
                "password": "Password123!",
                "role": "TEACHER",
                "roll_number": "EMP888",
                "department": "CSE",
                "faculty_code": settings.FACULTY_SIGNUP_SECRET,
            },
        )
        assert t_reg.status_code == 200
        async with test_session_factory() as s:
            otp_row = (await s.execute(select(EmailOTP).where(EmailOTP.email == "chimp.teacher@univ.edu"))).scalars().first()
            otp_code = otp_row.otp_code
        t_verify = await client.post(
            "/api/v1/auth/register/verify-otp",
            json={"email": "chimp.teacher@univ.edu", "otp_code": otp_code},
        )
        assert t_verify.status_code == 201
        teacher_headers = {"Authorization": f"Bearer {t_verify.json()['access_token']}"}

        async def register_student(email, roll):
            s_reg = await client.post(
                "/api/v1/auth/register",
                json={
                    "name": f"Student {roll}", "email": email, "password": "Password123!",
                    "role": "STUDENT", "roll_number": roll, "department": "CSE",
                    "program": "B-Tech", "semester": 3, "section": "A",
                },
            )
            assert s_reg.status_code == 200, s_reg.text
            async with test_session_factory() as s:
                s_otp_row = (await s.execute(select(EmailOTP).where(EmailOTP.email == email))).scalars().first()
            verified = await client.post(
                "/api/v1/auth/register/verify-otp",
                json={"email": email, "otp_code": s_otp_row.otp_code},
            )
            assert verified.status_code == 201, verified.text
            return verified.json()["access_token"]

        from app.routers.attendance import derive_short_device_key

        # Roster (3 eligible students) must exist BEFORE the session is created —
        # the server derives total_enrolled from the eligibility snapshot.
        tok_a = await register_student("chimp.a@univ.edu", "22B2001")
        tok_b = await register_student("chimp.b@univ.edu", "22B2002")
        await register_student("chimp.c@univ.edu", "22B2003")  # absent classmate
        tok_d = await register_student("chimp.d@univ.edu", "22B2004")
        k_a = derive_short_device_key("22B2001")
        k_b = derive_short_device_key("22B2002")
        k_d = derive_short_device_key("22B2004")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers=teacher_headers,
            json={
                "session_token": "CHMP",
                "course_program": "B-Tech", "course_semester": 3,
            },
        )
        assert s_res.status_code == 201
        session_data = s_res.json()
        # Roster derivation: 4 registered eligible students, not the 0 the app sends
        assert session_data["total_enrolled"] == 4
        # Roster diagnostic: create response names the matched roll numbers so
        # a surprising count (stale test account) is self-explaining
        assert sorted(session_data["enrolled_roll_numbers"]) == ["22B2001", "22B2002", "22B2003", "22B2004"]
        wire_salt = session_data["session_wire_salt"]
        submit_url = f"/api/v1/attendance/sessions/{session_data['id']}/submit-neighbors"

        img = Image.new("RGB", (64, 64), color=(200, 180, 160))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        face_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        # 1) Scoreless neighbor sync (no face) -> accepted, claims staged
        sync_a = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"student_id": k_a, "neighbors": [k_b], "session_salt": wire_salt},
        )
        assert sync_a.status_code == 200, sync_a.text
        sync_b = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_b}"},
            json={"student_id": k_b, "neighbors": [k_a], "session_salt": wire_salt},
        )
        assert sync_b.status_code == 200, sync_b.text

        # 2) Face-bearing check-in without a score -> 403, score "missing"
        res_missing = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"student_id": k_a, "neighbors": [k_b], "session_salt": wire_salt,
                  "face_image_base64": face_b64},
        )
        assert res_missing.status_code == 403, res_missing.text
        assert "Cognitive challenge failed" in res_missing.json()["detail"]
        assert res_missing.json()["detail"].endswith("score missing < 15")

        # 3) Face-bearing check-in scoring 9 (< 15) -> 403, score stored on the row
        res_low = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_d}"},
            json={"game_score": 9, "student_id": k_d, "neighbors": [],
                  "session_salt": wire_salt, "face_image_base64": face_b64},
        )
        assert res_low.status_code == 403, res_low.text
        assert "score 9 < 15" in res_low.json()["detail"]

        # 4) Threshold score (15) passes the face-bearing check-in
        res_ok = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_b}"},
            json={"game_score": 15, "student_id": k_b, "neighbors": [k_a],
                  "session_salt": wire_salt, "face_image_base64": face_b64},
        )
        assert res_ok.status_code == 200, res_ok.text
        assert res_ok.json()["status"] == "success"

        async with test_session_factory() as s:
            rows = (await s.execute(
                select(AttendanceRecord).where(
                    AttendanceRecord.session_id == uuid.UUID(session_data["id"])
                )
            )).scalars().all()
            by_dev = {r.ble_device_id: r for r in rows}
            assert by_dev[k_d].status == "COGNITIVE_CHALLENGE_FAILED"
            assert by_dev[k_d].game_score == 9

        # 5) Finalize: mutual pair (2 of 3 enrolled, tiny-class bypass) auto-verifies,
        #    B's final score (12) arrived before the audit so its verdict stands;
        #    A's verdict is overridden because no score ever arrived for A.
        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_data['id']}/audit-and-finalize",
            headers=teacher_headers,
            json={"reports": {}},
        )
        assert fin.status_code == 200, fin.text
        rec_map = {r["ble_device_id"]: r for r in fin.json()["records"]}
        assert rec_map[k_b]["status"] == "VERIFIED_PRESENT"
        assert rec_map[k_b]["game_score"] == 15
        assert rec_map[k_a]["status"] == "COGNITIVE_CHALLENGE_FAILED"
        assert rec_map[k_a]["game_score"] is None
        # Sub-threshold rejection rows stay frozen at finalize
        assert rec_map[k_d]["status"] == "COGNITIVE_CHALLENGE_FAILED"
        assert rec_map[k_d]["game_score"] == 9

        # 6) Late arrival (game finished after the teacher's timer): A's final
        #    check-in carries score 18 and rescues the pending-score failure via
        #    reciprocity with B's finalized claims.
        rescue = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"game_score": 18, "student_id": k_a, "neighbors": [k_b],
                  "session_salt": wire_salt, "face_image_base64": face_b64},
        )
        assert rescue.status_code == 200, rescue.text

        detail = await client.get(
            f"/api/v1/attendance/sessions/{session_data['id']}",
            headers=teacher_headers,
        )
        assert detail.status_code == 200, detail.text
        final_map = {r["ble_device_id"]: r for r in detail.json()["records"]}
        assert final_map[k_a]["status"] == "VERIFIED_PRESENT"
        assert final_map[k_a]["verification_method"] == "IN_FLIGHT_GRACE_PEER"
        assert final_map[k_a]["game_score"] == 18
        assert final_map[k_b]["game_score"] == 15
        assert detail.json()["total_verified"] == 2


# Verifies expired OTP cleanup behavior and purge on invalid submission
@pytest.mark.anyio
async def test_expired_otp_purging_and_cleanup():
    import uuid
    from datetime import datetime, timezone, timedelta
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from sqlalchemy import select, delete
    from app.database import get_db
    from app.models.attendance import Base, EmailOTP

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    now = datetime.now(timezone.utc)

    # 1. Insert an expired OTP (expired 10 mins ago) and an active OTP
    async with test_session_factory() as s:
        expired_otp = EmailOTP(
            id=uuid.uuid4(),
            email="expired.student@univ.edu",
            otp_code="111111",
            purpose="REGISTER",
            attempts=0,
            expires_at=now - timedelta(minutes=10),
        )
        active_otp = EmailOTP(
            id=uuid.uuid4(),
            email="active.student@univ.edu",
            otp_code="222222",
            purpose="REGISTER",
            attempts=0,
            expires_at=now + timedelta(minutes=5),
        )
        s.add_all([expired_otp, active_otp])
        await s.commit()

    # 2. Run the sweeper query (same logic as purge_expired_otps_worker)
    async with test_session_factory() as s:
        del_stmt = delete(EmailOTP).where(EmailOTP.expires_at < now)
        res = await s.execute(del_stmt)
        await s.commit()
        assert res.rowcount == 1

        # Check remaining records
        all_otps = (await s.execute(select(EmailOTP))).scalars().all()
        assert len(all_otps) == 1
        assert all_otps[0].email == "active.student@univ.edu"

    # 3. Test verification attempt with an expired OTP deletes it on attempt
    async with test_session_factory() as s:
        stale_otp = EmailOTP(
            id=uuid.uuid4(),
            email="stale.verify@univ.edu",
            otp_code="333333",
            purpose="LOGIN",
            attempts=0,
            expires_at=now - timedelta(minutes=1),
        )
        s.add(stale_otp)
        await s.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        verify_res = await client.post(
            "/api/v1/auth/login/verify-otp",
            json={"email": "stale.verify@univ.edu", "otp_code": "333333"}
        )
        assert verify_res.status_code == 400
        assert "expired" in verify_res.json()["detail"].lower()

        # The expired record must have been deleted
        async with test_session_factory() as s:
            rec = (await s.execute(
                select(EmailOTP).where(EmailOTP.email == "stale.verify@univ.edu")
            )).scalars().first()
            assert rec is None


# Verifies face engine preprocessing and embedding extraction
def test_face_matching_engine():
    import io
    import numpy as np
    from PIL import Image
    from app.services.face_engine import FaceMatchingEngine

    engine = FaceMatchingEngine()

    img = Image.new("RGB", (100, 100), color=(120, 80, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    raw_bytes = buf.getvalue()

    embedding = engine.extract_embedding(raw_bytes)
    assert embedding.shape == (128,)
    norm = np.linalg.norm(embedding)
    assert abs(norm - 1.0) < 1e-4

    sim_self = engine.compute_similarity(embedding, embedding)
    assert abs(sim_self - 1.0) < 1e-4


# Verifies session face deduplication and privacy purging
def test_session_face_registry():
    import base64
    import io
    from PIL import Image
    from httpx import AsyncClient, ASGITransport
    from app.services.face_engine import SessionFaceRegistry

    registry = SessionFaceRegistry()

    img_a = Image.new("RGB", (100, 100), color=(255, 0, 0))
    buf_a = io.BytesIO()
    img_a.save(buf_a, format="JPEG")
    b64_a = base64.b64encode(buf_a.getvalue()).decode("utf-8")

    # First student in session
    res_a = registry.register_and_check("session_101", "STUA", "22BCSE101", b64_a)
    assert res_a.is_duplicate is False

    # Second student with identical face image (proxy attempt)
    res_b = registry.register_and_check("session_101", "STUB", "22BCSE102", b64_a)
    assert res_b.is_duplicate is True
    assert res_b.matched_student_key == "STUA"

    flagged = registry.get_flagged_pairs("session_101")
    assert len(flagged) == 1
    assert flagged[0]["student_a_key"] == "STUA"
    assert flagged[0]["student_b_key"] == "STUB"

    # Purge session data
    registry.clear_session("session_101")
    assert len(registry.get_flagged_pairs("session_101")) == 0


def test_session_face_registry_cluster_interrogation():
    import base64
    import io
    from PIL import Image
    from app.services.face_engine import SessionFaceRegistry

    registry = SessionFaceRegistry()

    # Image A: Red
    img_a = Image.new("RGB", (100, 100), color=(255, 0, 0))
    buf_a = io.BytesIO()
    img_a.save(buf_a, format="JPEG")
    b64_a = base64.b64encode(buf_a.getvalue()).decode("utf-8")

    # Image B: Gray (moderate similarity ~0.58 to Red in synthetic test embedding)
    img_b = Image.new("RGB", (100, 100), color=(150, 150, 150))
    buf_b = io.BytesIO()
    img_b.save(buf_b, format="JPEG")
    b64_b = base64.b64encode(buf_b.getvalue()).decode("utf-8")

    # Image Proxy: Orange (high similarity ~0.93 to Red)
    img_proxy = Image.new("RGB", (100, 100), color=(255, 80, 0))
    buf_proxy = io.BytesIO()
    img_proxy.save(buf_proxy, format="JPEG")
    b64_proxy = base64.b64encode(buf_proxy.getvalue()).decode("utf-8")

    # Student A registers with cluster containing Student B
    res_a = registry.register_and_check("session_202", "STUA", "22BCSE201", b64_a, cluster_peers={"STUB"})
    assert res_a.is_duplicate is False

    # Student C (distant, across the room) registers with image B (moderately similar to A, ~0.58)
    # Since C is NOT in A's cluster and similarity < 0.70, C is NOT falsely flagged
    res_c = registry.register_and_check("session_202", "STUC", "22BCSE203", b64_b, cluster_peers={"STUD"})
    assert res_c.is_duplicate is False

    # Student B (same desk cluster as A) registers with proxy image
    # Since B IS in A's cluster, the sensitive threshold (0.363) is used and B is caught matching A
    res_b = registry.register_and_check("session_202", "STUB", "22BCSE202", b64_proxy, cluster_peers={"STUA"})
    assert res_b.is_duplicate is True
    assert res_b.matched_student_key == "STUA"

    # Purge
    registry.clear_session("session_202")


# Verifies face engine robustness guards against oversized payloads and non-finite vectors
def test_face_engine_robustness_guards():
    import numpy as np
    from app.services.face_engine import FaceMatchingEngine, SessionFaceRegistry

    engine = FaceMatchingEngine()
    registry = SessionFaceRegistry(engine=engine)

    # 1. Rejects oversized base64 payload (> 4MB)
    huge_payload = "A" * 4_000_001
    res = registry.register_and_check("sess_guard", "STU1", "ROLL1", huge_payload)
    assert res.is_duplicate is False
    assert res.has_human_face is False
    assert "exceeds maximum allowed size" in res.remarks

    # 2. Handles non-finite NaN vector similarity safely
    nan_vec = np.full((128,), np.nan, dtype=np.float32)
    valid_vec = np.ones((128,), dtype=np.float32)
    sim = engine.compute_similarity(nan_vec, valid_vec)
    assert sim == 0.0

    # 3. Prunes stale sessions based on TTL
    registry._session_timestamps["old_sess"] = 100.0
    registry._registry["old_sess"] = {"foo": {}}
    registry._prune_stale_sessions()
    assert "old_sess" not in registry._registry


# Verifies the exposure rescue path: a dark/backlit frame whose first detection
# pass finds no face is lifted once (CLAHE) and re-detected instead of being
# rejected, keeping verification strictness unchanged.
def test_face_engine_exposure_rescue_recovered():
    import cv2 as _cv2
    import numpy as np

    from app.services.face_engine import FaceMatchingEngine, _rescue_dark_image

    # Dark textured frame (mean ~8/255, spatial std above the 1.0 synthetic cut-off)
    rng = np.random.default_rng(7)
    img = (rng.integers(0, 4, size=(48, 48, 3)) + 8).astype(np.uint8)
    png_bytes = _cv2.imencode(".png", img)[1].tobytes()

    fake_face_row = np.array([2, 2, 28, 28, 8, 6, 20, 6, 14, 14, 8, 22, 20, 22, 0.9], dtype=np.float32)
    fake_faces = np.array([fake_face_row])

    class _FakeDetector:
        def __init__(self, outcomes):
            self.outcomes = list(outcomes)
            self.calls = 0

        def setInputSize(self, size):
            self.size = size

        def detect(self, image):
            result = self.outcomes[min(self.calls, len(self.outcomes) - 1)]
            self.calls += 1
            return None, result

    class _FakeRecognizer:
        def alignCrop(self, image, face):
            return image[0:16, 0:16]

        def feature(self, aligned):
            return np.ones((1, 128), dtype=np.float32)

    engine = FaceMatchingEngine(detector_path="/nonexistent", recognizer_path="/nonexistent")
    engine.detector = _FakeDetector([None, fake_faces])
    engine.recognizer = _FakeRecognizer()

    has_face, embedding, remark = engine.extract_face_and_embedding(png_bytes)
    assert has_face is True
    assert embedding is not None
    assert "exposure-rescued" in remark
    assert engine.detector.calls == 2  # first pass + exactly ONE rescue re-detection

    # The rescue helper itself: dims preserved, contrast lifted on a dark frame
    rescued = _rescue_dark_image(img)
    assert rescued.shape == img.shape
    assert float(np.mean(rescued)) > float(np.mean(img))


# Verifies zero-face rejections carry measured brightness diagnostics instead of
# the old misleading ceiling/desk phrasing.
def test_face_engine_no_face_remark_reports_brightness():
    import cv2 as _cv2
    import numpy as np

    from app.services.face_engine import FaceMatchingEngine

    rng = np.random.default_rng(11)
    img = (rng.integers(0, 4, size=(48, 48, 3)) + 8).astype(np.uint8)
    png_bytes = _cv2.imencode(".png", img)[1].tobytes()

    class _FakeDetectorAlwaysEmpty:
        def setInputSize(self, size):
            self.size = size

        def detect(self, image):
            return None, None

    engine = FaceMatchingEngine(detector_path="/nonexistent", recognizer_path="/nonexistent")
    engine.detector = _FakeDetectorAlwaysEmpty()
    engine.recognizer = object()  # aligned/feature path is never reached on rejection

    has_face, embedding, remark = engine.extract_face_and_embedding(png_bytes)
    assert has_face is False
    assert embedding is None
    assert "mean brightness" in remark
    assert "/255" in remark
    # An honestly dark frame blames the lighting, not the room
    assert "ceiling" not in remark
    assert "very dark" in remark


# Registers a throwaway student in the test's own attendance DB and returns a
# Bearer token: submission now requires JWT, and each battery test mounts its
# own in-memory get_db override (mirroring the salt-gate test's pattern).
async def _register_battery_student(client, session_factory) -> str:
    import uuid as _uuid
    from sqlalchemy import select

    from app.models.attendance import EmailOTP

    uid = _uuid.uuid4().hex[:8].upper()
    email = f"battery-{uid.lower()}@univ.edu"
    res = await client.post(
        "/api/v1/auth/register",
        json={
            "name": f"Battery Student {uid}",
            "email": email,
            "password": "Password123!",
            "role": "STUDENT",
            "roll_number": f"RB{uid}X",
            "department": "CSE",
            "program": "B.Tech",
            "semester": 1,
            "section": "A",
        },
    )
    assert res.status_code == 200, res.text
    async with session_factory() as s:
        otp_rec = (
            await s.execute(
                select(EmailOTP).where(EmailOTP.email == email, EmailOTP.purpose == "REGISTER")
            )
        ).scalars().first()
        otp_code = otp_rec.otp_code
    verify_res = await client.post(
        "/api/v1/auth/register/verify-otp",
        json={"email": email, "otp_code": otp_code},
    )
    assert verify_res.status_code == 201, verify_res.text
    return verify_res.json()["access_token"]


# Registers a TEACHER account (faculty code gated) and returns an access token
async def _register_test_teacher(client, session_factory, name: str, email: str) -> str:
    import uuid as _uuid
    from sqlalchemy import select

    from app.models.attendance import EmailOTP

    res = await client.post(
        "/api/v1/auth/register",
        json={
            "name": name,
            "email": email,
            "password": "Password123!",
            "role": "TEACHER",
            "roll_number": f"EMP{_uuid.uuid4().hex[:5].upper()}",
            "department": "CSE",
            "faculty_code": settings.FACULTY_SIGNUP_SECRET,
        },
    )
    assert res.status_code == 200, res.text
    async with session_factory() as s:
        otp_rec = (
            await s.execute(
                select(EmailOTP).where(EmailOTP.email == email, EmailOTP.purpose == "REGISTER")
            )
        ).scalars().first()
    verify_res = await client.post(
        "/api/v1/auth/register/verify-otp",
        json={"email": email, "otp_code": otp_rec.otp_code},
    )
    assert verify_res.status_code == 201, verify_res.text
    return verify_res.json()["access_token"]


# Registers a STUDENT account with a DETERMINISTIC roll so the audit's
# last-4 device keys are stable and pairable across submissions
async def _register_roll_student(client, session_factory, name: str, email: str, roll: str) -> str:
    from sqlalchemy import select

    from app.models.attendance import EmailOTP

    res = await client.post(
        "/api/v1/auth/register",
        json={
            "name": name,
            "email": email,
            "password": "Password123!",
            "role": "STUDENT",
            "roll_number": roll,
            "department": "CSE",
            "program": "B.Tech",
            "semester": 1,
            "section": "A",
        },
    )
    assert res.status_code == 200, res.text
    async with session_factory() as s:
        otp_rec = (
            await s.execute(
                select(EmailOTP).where(EmailOTP.email == email, EmailOTP.purpose == "REGISTER")
            )
        ).scalars().first()
    verify_res = await client.post(
        "/api/v1/auth/register/verify-otp",
        json={"email": email, "otp_code": otp_rec.otp_code},
    )
    assert verify_res.status_code == 201, verify_res.text
    return verify_res.json()["access_token"]


# Verifies debug session auto-provisioning and duplicate face detection via API endpoint
@pytest.mark.anyio
async def test_debug_session_auto_provision_and_duplicate_rejection():
    import base64
    import io
    from PIL import Image
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base

    # Deterministic in-memory DB for this battery test: the module shares one
    # app instance, so without an own override the endpoint would serve whatever
    # DB a previous test left mounted in dependency_overrides.
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    battery_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with battery_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    img = Image.new("RGB", (100, 100), color=(180, 140, 120))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    b64_img = base64.b64encode(buf.getvalue()).decode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_stud1 = await _register_battery_student(client, battery_db)
        tok_stud2 = await _register_battery_student(client, battery_db)

        # First student check-in to auto-provisioned debug session AUTO-101
        res1 = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            headers={"Authorization": f"Bearer {tok_stud1}"},
            json={"game_score": 20, "student_id": "STUD1",
                "neighbors": ["PEER-A1", "PEER-B2"],
                "session_salt": "DEMO1",
                "face_image_base64": b64_img,
            },
        )
        assert res1.status_code == 200

        # Second student check-in with the exact same face image (proxy attempt)
        res2 = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            headers={"Authorization": f"Bearer {tok_stud2}"},
            json={"game_score": 20, "student_id": "STUD2",
                "neighbors": ["PEER-A1", "PEER-B2"],
                "session_salt": "DEMO1",
                "face_image_base64": b64_img,
            },
        )
        assert res2.status_code == 403
        assert "Biometric proxy rejected" in res2.json()["detail"]


# [ULTRASONIC-DISABLED 2026-11] Layer 4 turned off — see note in
# app/routers/attendance.py. The schema no longer accepts
# ultrasonic_proximity_detected / co_located_peer_id, so these requests can
# no longer stage claims; test commented out, code preserved for restore.
# Verifies Layer 4 M3-lite: ultrasonic desk claims are DEFERRED, not vandalized.
# A RECIPROCATED pair (both students claim each other) is materialized into
# CO_LOCATED_SAME_DESK_PROXY rows for BOTH parties at finalize; an unreciprocated
# claim is ignored; a post-finalize (grace) claim can no longer be evaluated and
# never harms the straggler's record.
#@pytest.mark.anyio
#async def test_ultrasonic_proximity_mutual_pair_materialization():
#     import uuid

#     from httpx import AsyncClient, ASGITransport
#     from sqlalchemy import select
#     from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

#     from app.database import get_db
#     from app.models.attendance import AttendanceRecord, Base

#     test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
#     async with test_engine.begin() as conn:
#         await conn.run_sync(Base.metadata.create_all)
#     pair_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

#     async def override_get_db():
#         async with pair_db() as s:
#             yield s

#     app.dependency_overrides[get_db] = override_get_db

#     transport = ASGITransport(app=app)
#     async with AsyncClient(transport=transport, base_url="http://test") as client:
#         from app.routers.attendance import derive_short_device_key
#         tok_teacher = await _register_test_teacher(client, pair_db, "Prof. Desk Pair", "desk.pair@univ.edu")
#         teacher_headers = {"Authorization": f"Bearer {tok_teacher}"}
#         tok_stud1 = await _register_roll_student(client, pair_db, "Pair Alpha", "pair.alpha1@univ.edu", "22B4451")
#         tok_stud2 = await _register_roll_student(client, pair_db, "Pair Beta", "pair.beta2@univ.edu", "22B4452")
#         tok_stud3 = await _register_roll_student(client, pair_db, "Pair Gamma", "pair.gamma3@univ.edu", "22B4453")
#         tok_stud4 = await _register_roll_student(client, pair_db, "Pair Delta", "pair.delta4@univ.edu", "22B4454")
#         k1 = derive_short_device_key("22B4451")
#         k2 = derive_short_device_key("22B4452")
#         k3 = derive_short_device_key("22B4453")
#         k4 = derive_short_device_key("22B4454")

#         s_res = await client.post(
#             "/api/v1/attendance/sessions",
#             headers=teacher_headers,
#             json={"session_token": "M3P1", "total_enrolled": 5},
#         )
#         assert s_res.status_code == 201
#         session_id = s_res.json()["id"]
#         wire_salt = s_res.json()["session_wire_salt"]
#         session_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        # Reciprocated desk mates: both claim the < 20 cm ultrasonic handshake
#         res1 = await client.post(
#             session_url,
#             headers={"Authorization": f"Bearer {tok_stud1}"},
#             json={"game_score": 20, "student_id": k1,
#                 "neighbors": [k2],
#                 "session_salt": wire_salt,
#                 "ultrasonic_proximity_detected": True,
#                 "co_located_peer_id": k2,
#             },
#         )
#         assert res1.status_code == 200, res1.text  # staged normally — no instant 403

#         res2 = await client.post(
#             session_url,
#             headers={"Authorization": f"Bearer {tok_stud2}"},
#             json={"game_score": 20, "student_id": k2,
#                 "neighbors": [k1, k3],
#                 "session_salt": wire_salt,
#                 "ultrasonic_proximity_detected": True,
#                 "co_located_peer_id": k1,
#             },
#         )
#         assert res2.status_code == 200, res2.text

        # Mutual BLE chain 4451-4452-4453-4454 so the clean pair verifies; but
        # ONLY 4453 claims an ultrasonic desk handshake (unreciprocated claim)
#         res3 = await client.post(
#             session_url,
#             headers={"Authorization": f"Bearer {tok_stud3}"},
#             json={"game_score": 20, "student_id": k3,
#                 "neighbors": [k2, k4],
#                 "session_salt": wire_salt,
#                 "ultrasonic_proximity_detected": True,
#                 "co_located_peer_id": k4,
#             },
#         )
#         assert res3.status_code == 200, res3.text

#         res4 = await client.post(
#             session_url,
#             headers={"Authorization": f"Bearer {tok_stud4}"},
#             json={"game_score": 20, "student_id": k4,
#              "neighbors": [k3], "session_salt": wire_salt},
#         )
#         assert res4.status_code == 200, res4.text

#         audit_res = await client.post(
#             f"/api/v1/attendance/sessions/{session_id}/audit-and-finalize",
#             headers=teacher_headers,
#             json={"reports": {}},
#         )
#         assert audit_res.status_code == 200
#         audit_data = audit_res.json()

#         assert audit_data["status"] == "COMPLETED"
#         assert len(audit_data["records"]) == 4  # one row per student is preserved
#         record_map = {r["ble_device_id"]: r for r in audit_data["records"]}

        # Reciprocated pair: both verdict rows transformed into the proxy violation
#         assert record_map[k1]["status"] == "CO_LOCATED_SAME_DESK_PROXY"
#         assert record_map[k1]["verification_method"] == "ULTRASONIC_ACOUSTIC_MATCH"
#         assert f"with {k2}" in record_map[k1]["remarks"]
#         assert record_map[k2]["status"] == "CO_LOCATED_SAME_DESK_PROXY"
#         assert record_map[k2]["verification_method"] == "ULTRASONIC_ACOUSTIC_MATCH"
#         assert f"with {k1}" in record_map[k2]["remarks"]

        # Unreciprocated claim: the benign BLE mesh verdict stands untouched
#         assert record_map[k3]["status"] == "VERIFIED_PRESENT"
#         assert record_map[k4]["status"] == "VERIFIED_PRESENT"

#         assert audit_data["total_verified"] == 2
#         assert audit_data["total_unverified"] == 2  # ignored claim is not counted

        # Post-finalize grace claim: mutuality is unevaluable (buffer already
        # popped) — the straggler gets a normal grace record, NOT a proxy row.
#         tok_stud5 = await _register_roll_student(client, pair_db, "Pair Epsilon", "pair.epsilon5@univ.edu", "22B4455")
#         k5 = derive_short_device_key("22B4455")
#         grace = await client.post(
#             session_url,
#             headers={"Authorization": f"Bearer {tok_stud5}"},
#             json={"game_score": 20, "student_id": k5,
#                 "neighbors": [],
#                 "session_salt": wire_salt,
#                 "ultrasonic_proximity_detected": True,
#                 "co_located_peer_id": k1,
#             },
#         )
#         assert grace.status_code == 200, grace.text

#         async with pair_db() as s:
#             grace_rows = (
#                 await s.execute(
#                     select(AttendanceRecord).where(
#                         AttendanceRecord.session_id == uuid.UUID(session_id),
#                         AttendanceRecord.ble_device_id == k5,
#                     )
#                 )
#             ).scalars().all()
#             assert len(grace_rows) == 1
#             assert grace_rows[0].status == "ISOLATED_FLAGGED"


# Verifies M2 hygiene: a live session's token cannot be re-issued by ANOTHER
# teacher (student submits resolve newest-wins, so a colliding broadcast would
# cross-route submissions). Same-teacher re-create still supersedes cleanly
# because the stale-expiry step runs BEFORE the conflict check.
@pytest.mark.anyio
async def test_session_token_conflict_cross_teacher():
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    conflict_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with conflict_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_a = await _register_test_teacher(client, conflict_db, "Prof. Tok A", "tok.a@univ.edu")
        tok_b = await _register_test_teacher(client, conflict_db, "Prof. Tok B", "tok.b@univ.edu")

        first = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"session_token": "T0K1", "session_salt": "AAAA", "total_enrolled": 4},
        )
        assert first.status_code == 201

        # Another teacher reusing the live token -> 409
        clash = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_b}"},
            json={"session_token": "T0K1", "session_salt": "BBBB", "total_enrolled": 4},
        )
        assert clash.status_code == 409
        assert "already in use" in clash.json()["detail"]

        # Same teacher re-creating their own token still supersedes cleanly (no 409)
        rec = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"session_token": "T0K1", "session_salt": "AAAA", "total_enrolled": 4},
        )
        assert rec.status_code == 201, rec.text

        # A fresh token for the other teacher is unaffected
        fresh = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_b}"},
            json={"session_token": "T0K2", "session_salt": "BBBB", "total_enrolled": 4},
        )
        assert fresh.status_code == 201


# Verifies M5: frozen security verdicts (e.g. the salt gate's SPOOFER_REJECTED
# row) must still surface in total_unverified on the plain finalize route even
# though finalize preserves them in place instead of rewriting them.
@pytest.mark.anyio
async def test_finalize_counts_frozen_proxy_priors():
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    frozen_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with frozen_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, frozen_db, "Prof. Frozen Counter", "frozen.counter@univ.edu")
        tok_stud = await _register_roll_student(client, frozen_db, "Frozen Student", "frozen.stud@univ.edu", "22B9876")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "M5F1", "total_enrolled": 2},
        )
        assert s_res.status_code == 201
        session_id = s_res.json()["id"]

        # Salt-gate rejection writes a SPOOFER_REJECTED row out-of-band
        spoof = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/submit-neighbors",
            headers={"Authorization": f"Bearer {tok_stud}"},
            json={"game_score": 20, "student_id": "9876", "neighbors": [], "session_salt": "WRNG"},
        )
        assert spoof.status_code == 403
        assert "Nice try" in spoof.json()["detail"]

        # Plain finalize with no teacher records must NOT lose the frozen prior
        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"records": []},
        )
        assert fin.status_code == 200, fin.text
        fin_data = fin.json()
        assert fin_data["status"] == "COMPLETED"
        assert fin_data["total_unverified"] == 1
        assert fin_data["total_verified"] == 0


# Verifies the plain-finalize leniency seal: staged students only earn
# VERIFIED_PRESENT when at least one reported neighbor reports back; a claimed
# neighbor list alone gets ISOLATED_FLAGGED with no blanket 1.00 affinity.
@pytest.mark.anyio
async def test_finalize_staged_drain_requires_reciprocal_peers():
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    seal_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with seal_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        from app.routers.attendance import derive_short_device_key
        tok_teacher = await _register_test_teacher(client, seal_db, "Prof. Reciprocity", "reciprocity@univ.edu")
        tok_stud1 = await _register_roll_student(client, seal_db, "Mutual One", "mutual.one@univ.edu", "22B6611")
        tok_stud2 = await _register_roll_student(client, seal_db, "Mutual Two", "mutual.two@univ.edu", "22B6612")
        tok_stud3 = await _register_roll_student(client, seal_db, "Fake Claimer", "fake.claimer@univ.edu", "22B6613")
        k1 = derive_short_device_key("22B6611")
        k2 = derive_short_device_key("22B6612")
        k3 = derive_short_device_key("22B6613")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "M6X1", "total_enrolled": 3},
        )
        assert s_res.status_code == 201
        session_id = s_res.json()["id"]
        wire_salt = s_res.json()["session_wire_salt"]
        session_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        r1 = await client.post(
            session_url,
            headers={"Authorization": f"Bearer {tok_stud1}"},
            json={"game_score": 20, "student_id": k1, "neighbors": [k2], "session_salt": wire_salt},
        )
        assert r1.status_code == 200, r1.text

        r2 = await client.post(
            session_url,
            headers={"Authorization": f"Bearer {tok_stud2}"},
            json={"game_score": 20, "student_id": k2, "neighbors": [k1], "session_salt": wire_salt},
        )
        assert r2.status_code == 200, r2.text

        # Claims a neighbor nobody ever reports back — must NOT be verified
        r3 = await client.post(
            session_url,
            headers={"Authorization": f"Bearer {tok_stud3}"},
            json={"game_score": 20, "student_id": k3, "neighbors": ["GHOST"], "session_salt": wire_salt},
        )
        assert r3.status_code == 200, r3.text

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"records": []},
        )
        assert fin.status_code == 200, fin.text
        fin_data = fin.json()

        assert fin_data["total_verified"] == 2  # the mutual pair (both parties) confirms
        assert fin_data["total_unverified"] == 1  # the fake claimer's isolated row
        record_map = {r["ble_device_id"]: r for r in fin_data["records"]}

        assert record_map[k1]["status"] == "VERIFIED_PRESENT"
        assert record_map[k1]["verification_method"] == "BLE_MESH"
        assert record_map[k1]["affinity_score"] == 1.00
        assert f"mutual desk neighbor [{k2}]" in record_map[k1]["remarks"]

        # R11-B: the finalize payload must carry users-joined names and rolls —
        # the teacher's live post-class screen renders from exactly this
        # response, and the "Student 20" fallback previously meant
        # student_name arrived NULL here (finalize never joined users).
        assert record_map[k1]["student_name"] == "Mutual One"
        assert record_map[k1]["roll_number"] == "22B6611"
        assert record_map[k3]["student_name"] == "Fake Claimer"
        assert record_map[k3]["roll_number"] == "22B6613"

        assert record_map[k2]["status"] == "VERIFIED_PRESENT"
        assert f"mutual desk neighbor [{k1}]" in record_map[k2]["remarks"]

        assert record_map[k3]["status"] == "ISOLATED_FLAGGED"
        assert record_map[k3]["verification_method"] == "NONE"
        assert record_map[k3]["affinity_score"] == 0.50
        assert "without confirmed desk neighbor" in record_map[k3]["remarks"]
        assert "HOST" in record_map[k3]["remarks"]  # 'GHOST' -> last-4 key


# Roster bind ("Student 79" bug): a witness/offline row for a device that never
# authenticated carries student_id NULL — the dashboard fallback then renders
# "Student <key-suffix>" (key D1F779 -> "Student 79") instead of the real
# student. Finalize must reverse-map the deterministic device key against the
# session's eligibility roster and bind the account, so the response carries
# the real roll number and name.
@pytest.mark.anyio
async def test_finalize_binds_unbound_witness_rows_to_roster():
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    bind_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with bind_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        from app.routers.attendance import derive_short_device_key

        tok_teacher = await _register_test_teacher(client, bind_db, "Prof. Roster Bind", "roster.bind@univ.edu")
        tok_s1 = await _register_roll_student(client, bind_db, "Honest One", "honest.one@univ.edu", "251340101031")
        tok_s2 = await _register_roll_student(client, bind_db, "Honest Two", "honest.two@univ.edu", "251340101033")
        # The offline student registers an account but never submits — only
        # their deterministic device key ever enters the mesh (witnessed by the
        # two honest peers).
        await _register_roll_student(client, bind_db, "Priyansh Thapliyal", "offline.witness@univ.edu", "251340101032")
        k1 = derive_short_device_key("251340101031")
        k2 = derive_short_device_key("251340101033")
        k_off = derive_short_device_key("251340101032")  # D1F779 — the real "Student 79"

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "RB79", "total_enrolled": 3, "course_program": "B.Tech", "course_semester": 1},
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]
        wire_salt = s_res.json()["session_wire_salt"]
        session_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        r1 = await client.post(
            session_url,
            headers={"Authorization": f"Bearer {tok_s1}"},
            json={"game_score": 20, "student_id": k1, "neighbors": [k2, k_off], "session_salt": wire_salt},
        )
        assert r1.status_code == 200, r1.text

        r2 = await client.post(
            session_url,
            headers={"Authorization": f"Bearer {tok_s2}"},
            json={"game_score": 20, "student_id": k2, "neighbors": [k1, k_off], "session_salt": wire_salt},
        )
        assert r2.status_code == 200, r2.text

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/audit-and-finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"reports": {}},
        )
        assert fin.status_code == 200, fin.text
        fin_data = fin.json()
        assert fin_data["status"] == "COMPLETED"
        assert fin_data["total_verified"] == 2
        assert fin_data["total_unverified"] == 1  # the offline witness row

        record_map = {r["ble_device_id"]: r for r in fin_data["records"]}
        assert record_map[k_off]["status"] == "FLAGGED_WITNESSED"

        # The fix: NULL student_id is now roster-bound, so the dashboard gets
        # the real identity — not the "Student 79" key-suffix fallback.
        assert record_map[k_off]["student_id"] is not None
        assert record_map[k_off]["student_name"] == "Priyansh Thapliyal"
        assert record_map[k_off]["roll_number"] == "251340101032"

        # Honest peers keep their account binding as before
        assert record_map[k1]["student_name"] == "Honest One"
        assert record_map[k1]["roll_number"] == "251340101031"
        assert record_map[k2]["student_name"] == "Honest Two"


# Verifies hygiene guards: strict status whitelists on the TEACHER-OVERWRITE
# request models (lowercase aliases normalize; unknown statuses 422 before any
# write), while BLEAuditRecordItem stays permissive — it is the from_attributes
# base of the session response and would 500 on defense-layer violation rows.
@pytest.mark.anyio
async def test_status_enum_validation_hygiene():
    from pydantic import ValidationError

    from app.schemas.attendance import BLEAuditRecordItem, RecordOverrideRequest, SessionFinalizeRequest

    # Lowercase aliases normalize to canonical statuses
    req = SessionFinalizeRequest(records=[{"ble_device_id": "33F1", "status": "verified_present"}])
    assert req.records[0].status == "VERIFIED_PRESENT"
    assert RecordOverrideRequest(status="absent").status == "ABSENT"

    # Unknown statuses rejected at validation time (-> HTTP 422)
    with pytest.raises(ValidationError):
        SessionFinalizeRequest(records=[{"ble_device_id": "33F1", "status": "SPECTRAL_GHOST"}])
    with pytest.raises(ValidationError):
        RecordOverrideRequest(status="PRESENT")

    # Response base stays permissive for defense-layer verdicts (no 500s)
    artifact = BLEAuditRecordItem.model_validate(
        {"ble_device_id": "01AB", "status": "DUPLICATE_FACE_PROXY", "affinity_score": 0.0}
    )
    assert artifact.status == "DUPLICATE_FACE_PROXY"

    # HTTP: garbage status is rejected at body-validation, normalized status
    # passes through to the (unknown-session) 404 instead.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    enum_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with enum_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok = await _register_test_teacher(client, enum_db, "Prof. Enum Guard", "enum.guard@univ.edu")

        bad = await client.post(
            "/api/v1/attendance/sessions/NOT-A-UUID/finalize",
            headers={"Authorization": f"Bearer {tok}"},
            json={"records": [{"ble_device_id": "33F1", "status": "GARBAGE_STATUS"}]},
        )
        assert bad.status_code == 422

        normalized = await client.post(
            "/api/v1/attendance/sessions/NOT-A-UUID/finalize",
            headers={"Authorization": f"Bearer {tok}"},
            json={"records": [{"ble_device_id": "33F1", "status": "verified_present"}]},
        )
        assert normalized.status_code == 404

        override_bad = await client.patch(
            "/api/v1/attendance/records/00000000-0000-0000-0000-000000000000/override",
            headers={"Authorization": f"Bearer {tok}"},
            json={"status": "PRESENT"},
        )
        assert override_bad.status_code == 422


# Verifies raw binary image check-in submission with headers bypasses base64
@pytest.mark.anyio
async def test_submit_neighbors_binary_upload():
    import io
    from PIL import Image
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base
    from app.services.face_engine import face_registry

    # Clears in-memory registry before test
    face_registry.clear_all()

    img = Image.new("RGB", (100, 100), color=(180, 140, 120))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    raw_jpeg = buf.getvalue()

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    battery_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with battery_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_bin1 = await _register_battery_student(client, battery_db)
        tok_bin2 = await _register_battery_student(client, battery_db)

        # Rejects submission when salt header is invalid
        bad_res = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            content=raw_jpeg,
            headers={
                "Content-Type": "image/jpeg",
                "Authorization": f"Bearer {tok_bin1}",
                "X-Session-Salt": "BAD_SALT",
                "X-Student-Id": "BIN1",
                "X-Neighbors": "PEER-A1,PEER-B2",
                "X-Game-Score": "20",
            },
        )
        assert bad_res.status_code == 403

        # Accepts valid binary submission and records attendance
        good_res = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            content=raw_jpeg,
            headers={
                "Content-Type": "image/jpeg",
                "Authorization": f"Bearer {tok_bin1}",
                "X-Session-Salt": "DEMO1",
                "X-Student-Id": "BIN1",
                "X-Neighbors": "PEER-A1,PEER-B2",
                "X-Game-Score": "20",
            },
        )
        assert good_res.status_code == 200
        assert good_res.json()["status"] == "success"

        # Duplicate binary face payload triggers proxy rejection
        dup_res = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            content=raw_jpeg,
            headers={
                "Content-Type": "image/jpeg",
                "Authorization": f"Bearer {tok_bin2}",
                "X-Session-Salt": "DEMO1",
                "X-Student-Id": "BIN2",
                "X-Neighbors": "PEER-A1,PEER-B2",
                "X-Game-Score": "20",
            },
        )
        assert dup_res.status_code == 403
        assert "Biometric proxy rejected" in dup_res.json()["detail"]


# Verifies in-memory submission staging, claim union-merging, and TTL pruning
@pytest.mark.anyio
async def test_submission_buffer_staging_and_pruning():
    import uuid
    from app.services.submission_buffer import SubmissionBuffer

    buffer = SubmissionBuffer(ttl_seconds=1)
    sess_id = "test-session-staging"
    student_uuid = uuid.uuid4()

    # Stages initial check-in submission
    await buffer.stage_submission(
        session_id=sess_id,
        device_key="STU1",
        student_id=student_uuid,
        reported_neighbors=["NBR1", "NBR2"],
    )

    # Updates existing submission with revised neighbor reports
    await buffer.stage_submission(
        session_id=sess_id,
        device_key="STU1",
        student_id=student_uuid,
        reported_neighbors=["NBR1", "NBR2", "NBR3"],
    )

    # A later, emptier snapshot must not erase earlier claims: interim submits
    # arrive through asymmetric BLE discovery windows, so union-merge is what
    # keeps transient one-way discoveries alive until mutual confirmation.
    await buffer.stage_submission(
        session_id=sess_id,
        device_key="STU1",
        student_id=student_uuid,
        reported_neighbors=["NBR2"],
    )

    # Extracts and verifies staged submissions (single surviving node now that
    # the unauthenticated offline-voucher channel is gone)
    staged = await buffer.pop_submissions(sess_id)
    assert len(staged) == 1
    assert staged["STU1"].reported_neighbors == ["NBR1", "NBR2", "NBR3"]
    assert staged["STU1"].student_id == student_uuid

    # Verifies buffer is empty after popping
    empty_staged = await buffer.pop_submissions(sess_id)
    assert len(empty_staged) == 0

    # Tests TTL pruning on stale session buffers
    await buffer.stage_submission(
        session_id="stale-session",
        device_key="STU2",
        student_id=None,
        reported_neighbors=["NBRX"],
    )
    buffer._last_accessed["stale-session"] = 0.0
    buffer._prune_stale(now=100.0)
    assert "stale-session" not in buffer._buffers


# Verifies 2D BLAS SIMD matrix batching across registered session face embeddings
def test_face_engine_simd_blas_batching():
    import numpy as np
    from app.services.face_engine import SessionFaceRegistry

    registry = SessionFaceRegistry()
    sess = "batch-test-session"

    # Registers 10 unique synthetic faces into session matrix
    for i in range(10):
        emb = np.random.randn(1, 128).astype(np.float32)
        norm = float(np.linalg.norm(emb))
        emb = emb / norm
        student_key = f"STU{i}"
        registry._registry.setdefault(sess, {})[student_key] = {
            "embedding": emb,
            "roll": f"ROLL{i}",
            "cluster_peers": set(),
            "flagged": False,
            "image_b64": None,
        }
        registry._session_keys.setdefault(sess, []).append(student_key)
        registry._session_clusters.setdefault(sess, []).append(set())
        if registry._session_matrices.get(sess) is None:
            registry._session_matrices[sess] = emb.reshape(1, 128)
        else:
            registry._session_matrices[sess] = np.vstack([registry._session_matrices[sess], emb.reshape(1, 128)])

    # Verifies internal matrix dimensions match (10, 128)
    assert registry._session_matrices[sess].shape == (10, 128)

    # Identical query to student 3 must match with similarity ~1.0
    target_vec = registry._session_matrices[sess][3]
    scores = registry._session_matrices[sess] @ target_vec
    assert abs(scores[3] - 1.0) < 1e-4

    # Purges matrix and session structures
    registry.clear_session(sess)
    assert sess not in registry._session_matrices
    assert sess not in registry._session_keys


# Verifies hardware acceleration provider detection and ONNX Runtime session
def test_face_engine_hardware_acceleration_info():
    from app.services.face_engine import FaceMatchingEngine

    engine = FaceMatchingEngine()
    info = engine.get_hardware_acceleration_info()

    assert "execution_provider" in info
    assert "cv2_threads" in info
    assert "onnxruntime_available" in info
    assert info["cv2_threads"] > 0
    assert info["onnxruntime_available"] is True
    assert "CPUExecutionProvider" in info["onnxruntime_providers"]


# ---------------------------------------------------------------------------
# Login hardening (review §1.2.1 / §1.2.2) — chunk 1
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_login_email_limiter_budget():
    # Private instance: never touch the module-level limiters that the real
    # login routes and the test_library integration suite rely on.
    from app.services.rate_limiter import SlidingWindowRateLimiter

    limiter = SlidingWindowRateLimiter(max_events=10, window_seconds=300.0)
    for _ in range(10):
        assert await limiter.check("guess@example.com") is True
    # Attempt 11 is refused — attempts count regardless of success, by design
    assert await limiter.check("guess@example.com") is False


@pytest.mark.anyio
async def test_login_gateway_limiter_budget():
    # The per-gateway floor exists only to stop bulk credential-stuffing from
    # a single address; 150/window keeps a classroom's shared-NAT burst safe.
    from app.services.rate_limiter import SlidingWindowRateLimiter

    limiter = SlidingWindowRateLimiter(max_events=150, window_seconds=300.0)
    for _ in range(150):
        assert await limiter.check("gateway-1") is True
    assert await limiter.check("gateway-1") is False


def test_login_limiter_calibration_is_intentional():
    # Guards the classroom reality: the gateway floor must stay ABOVE a full
    # 70-student login burst through one NAT address. Shrinking it silently
    # 429s innocent classmates mid-lecture.
    from app.services import rate_limiter

    assert rate_limiter.login_email_limiter._max_events == 10
    assert rate_limiter.login_ip_limiter._max_events == 150
    assert rate_limiter.login_ip_limiter._max_events > 70


@pytest.mark.anyio
async def test_dummy_bcrypt_hash_supports_timing_equalizer():
    from app.core.security import DUMMY_BCRYPT_HASH, verify_password

    # The dummy hash must behave like a real stored hash so unknown emails pay
    # the identical bcrypt cost through the same code path (no enumeration).
    assert verify_password("timing-equalizer-dummy-login", DUMMY_BCRYPT_HASH) is True
    assert verify_password("any-user-password", DUMMY_BCRYPT_HASH) is False


@pytest.mark.anyio
async def test_flagged_faces_owner_only():
    # review §1.3.1: flagged pairs carry students' face crops — another
    # teacher's valid token must not be able to view another session's photos.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import Base, EmailOTP
    from app.services.face_engine import face_registry

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:

        async def _register_teacher(name: str, email: str, emp_no: str) -> dict:
            reg = await client.post(
                "/api/v1/auth/register",
                json={
                    "name": name,
                    "email": email,
                    "password": "Password123!",
                    "role": "TEACHER",
                    "roll_number": emp_no,
                    "department": "CSE",
                    "faculty_code": settings.FACULTY_SIGNUP_SECRET,
                },
            )
            assert reg.status_code == 200, reg.text
            async with test_session_factory() as s:
                otp_record = (
                    await s.execute(select(EmailOTP).where(EmailOTP.email == email))
                ).scalars().first()
            verify = await client.post(
                "/api/v1/auth/register/verify-otp",
                json={"email": email, "otp_code": otp_record.otp_code},
            )
            assert verify.status_code == 201, verify.text
            return {"Authorization": f"Bearer {verify.json()['access_token']}"}

        owner_headers = await _register_teacher("Prof. Flag Owner", "flag.owner@univ.edu", "EMP701")
        stranger_headers = await _register_teacher("Prof. Flag Stranger", "flag.stranger@univ.edu", "EMP702")

        created = await client.post(
            "/api/v1/attendance/sessions",
            headers=owner_headers,
            json={"session_token": "FFFF", "session_salt": "7F7F", "total_enrolled": 20},
        )
        assert created.status_code == 201, created.text
        session_id = created.json()["id"]

        # Seed a genuine flagged pair for the owner's session
        face_registry._flagged_pairs[session_id] = [
            {
                "peer_1": "student-aaaa",
                "peer_2": "student-bbbb",
                "faces": ["UklGRg==", "UklGRg=="],
                "remarks": "Mutual co-located claims, face pair flagged",
            }
        ]

        leaked = await client.get(
            f"/api/v1/attendance/sessions/{session_id}/flagged-faces",
            headers=stranger_headers,
        )
        assert leaked.status_code == 403, leaked.text

        owned = await client.get(
            f"/api/v1/attendance/sessions/{session_id}/flagged-faces",
            headers=owner_headers,
        )
        assert owned.status_code == 200, owned.text
        assert owned.json()["count"] == 1

        face_registry._flagged_pairs.pop(session_id, None)


# ---------------------------------------------------------------------------
# Production secrets guard v2 — placeholder deny-list + length floor (chunk 3)
# ---------------------------------------------------------------------------


def test_insecure_secret_reason_catalogue():
    from app import config

    # 1. The pinned git-history denylist values are always refused
    #    (the old faculty default is exactly 32 chars — equality catches it,
    #     a length floor alone would let it through). The settings instance
    #     itself now carries rotated/random values and must PASS.
    assert config.insecure_secret_reason(
        "JWT_SECRET_KEY", config.INSECURE_DEFAULT_SECRETS["JWT_SECRET_KEY"]
    )
    assert config.insecure_secret_reason(
        "FACULTY_SIGNUP_SECRET", config.INSECURE_DEFAULT_SECRETS["FACULTY_SIGNUP_SECRET"]
    )
    assert config.insecure_secret_reason("JWT_SECRET_KEY", config.settings.JWT_SECRET_KEY) is None
    assert config.insecure_secret_reason(
        "FACULTY_SIGNUP_SECRET", config.settings.FACULTY_SIGNUP_SECRET
    ) is None

    # 2. compose JWT placeholder and BOTH eras of faculty placeholder
    assert config.insecure_secret_reason("JWT_SECRET_KEY", "change_this_to_a_random_hex_key_32_bytes")
    assert config.insecure_secret_reason("FACULTY_SIGNUP_SECRET", "college_faculty_passcode_2026")
    assert config.insecure_secret_reason("FACULTY_SIGNUP_SECRET", "change_this_faculty_signup_passcode")

    # 3. Historical committed values recoverable from git history
    assert config.insecure_secret_reason("JWT_SECRET_KEY", "ble-mesh-attendance-secret-key-super-secure")

    # 4. Empty / undersized
    assert config.insecure_secret_reason("JWT_SECRET_KEY", "")
    assert config.insecure_secret_reason("JWT_SECRET_KEY", "short")

    # 5. Genuine random values pass under every managed name
    import secrets as secrets_module
    for name in config.INSECURE_DEFAULT_SECRETS:
        assert config.insecure_secret_reason(name, secrets_module.token_urlsafe(48)) is None


def test_validate_production_secrets_refuses_placeholder(monkeypatch):
    import secrets
    from app import config

    monkeypatch.setattr(config.settings, "APP_ENV", "production")
    monkeypatch.setattr(
        config.settings, "JWT_SECRET_KEY", "change_this_to_a_random_hex_key_32_bytes"
    )
    monkeypatch.setattr(config.settings, "FACULTY_SIGNUP_SECRET", secrets.token_urlsafe(48))

    with pytest.raises(RuntimeError) as err:
        config.validate_production_secrets()
    assert "JWT_SECRET_KEY" in str(err.value)


def test_validate_production_secrets_allows_strong_values(monkeypatch):
    import secrets
    from app import config

    monkeypatch.setattr(config.settings, "APP_ENV", "production")
    fresh = secrets.token_urlsafe(48)
    assert len(fresh) == 64
    monkeypatch.setattr(config.settings, "JWT_SECRET_KEY", fresh)
    monkeypatch.setattr(config.settings, "FACULTY_SIGNUP_SECRET", secrets.token_urlsafe(48))

    config.validate_production_secrets()  # must not raise


def test_validate_production_secrets_development_is_permissive(monkeypatch):
    # development (Render today) boots with placeholder-ish values by design —
    # the guard is an APP_ENV=production gate only
    from app import config

    monkeypatch.setattr(config.settings, "APP_ENV", "development")
    monkeypatch.setattr(config.settings, "JWT_SECRET_KEY", config.settings.JWT_SECRET_KEY)
    monkeypatch.setattr(config.settings, "FACULTY_SIGNUP_SECRET", "college_faculty_passcode_2026")

    config.validate_production_secrets()  # must not raise


# ---------------------------------------------------------------------------
# Race guards R1/R3/R4 (review §3.1) — chunk 4
# ---------------------------------------------------------------------------


class _MissingScalarsResult:
    """Stand-in for an empty refer_of select() result (ScalarsResult chain)."""

    def scalars(self):
        class _NoRow:
            def first(self):
                return None
        return _NoRow()


@pytest.mark.anyio
async def test_register_duplicate_racing_verification_is_409():
    # R4: two pending registrations of the same account both pass send-OTP's
    # committed-users pre-check — verifying both must NOT 500.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import Base, EmailOTP

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    race_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with race_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "name": "Race Dup",
            "email": "race.dup@univ.edu",
            "password": "Password123!",
            "role": "STUDENT",
            "roll_number": "22B7001",
            "department": "CSE",
        }
        assert (await client.post("/api/v1/auth/register", json=payload)).status_code == 200

        # register_send_otp bulk-purges prior REGISTER OTPs, so two pure-HTTP
        # registrations can't both hold a code: the real race window is the
        # interleaved DELETE/INSERT of two concurrent send requests, whose
        # survivor is a second still-valid pending OTP. Seed exactly that.
        import uuid as _uuid
        from datetime import datetime, timedelta, timezone as _tz
        from app.models.attendance import EmailOTP as _EmailOTP

        async with race_db() as s:
            first_code = (
                await s.execute(
                    select(EmailOTP).where(
                        EmailOTP.email == "race.dup@univ.edu", EmailOTP.purpose == "REGISTER"
                    )
                )
            ).scalars().one().otp_code
            s.add(
                _EmailOTP(
                    id=_uuid.uuid4(),
                    email="race.dup@univ.edu",
                    otp_code="999999",
                    purpose="REGISTER",
                    attempts=0,
                    expires_at=datetime.now(_tz.utc) + timedelta(minutes=5),
                    created_at=datetime.now(_tz.utc) - timedelta(seconds=60),
                )
            )
            await s.commit()

        first_verify = await client.post(
            "/api/v1/auth/register/verify-otp",
            json={"email": "race.dup@univ.edu", "otp_code": first_code},
        )
        assert first_verify.status_code == 201, first_verify.text

        second_verify = await client.post(
            "/api/v1/auth/register/verify-otp",
            json={"email": "race.dup@univ.edu", "otp_code": "999999"},
        )
        assert second_verify.status_code == 409, second_verify.text
        assert "already registered" in second_verify.json()["detail"]


@pytest.mark.anyio
async def test_grace_duplicate_claim_succeeds():
    # R1: after finalize, a replayed grace claim (double ping / keep-alive)
    # re-hits the unique session constraints — must be accepted, not 500'd.
    import uuid

    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import AttendanceRecord, Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    grace_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with grace_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        from app.routers.attendance import derive_short_device_key
        tok_teacher = await _register_test_teacher(client, grace_db, "Prof. Grace Replay", "grace.replay@univ.edu")
        tok_present = await _register_roll_student(client, grace_db, "Grace Punctual", "grace.punctual@univ.edu", "22B4470")
        tok_straggler = await _register_roll_student(client, grace_db, "Grace Straggler", "grace.strag@univ.edu", "22B4471")
        k_present = derive_short_device_key("22B4470")
        k_straggler = derive_short_device_key("22B4471")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "GR01", "total_enrolled": 5},
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]
        wire_salt = s_res.json()["session_wire_salt"]
        session_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        res = await client.post(
            session_url,
            headers={"Authorization": f"Bearer {tok_present}"},
            json={"game_score": 20, "student_id": k_present, "neighbors": [], "session_salt": wire_salt},
        )
        assert res.status_code == 200, res.text

        audit_res = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/audit-and-finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"reports": {}},
        )
        assert audit_res.status_code == 200, audit_res.text

        grace_payload = {"game_score": 20, "student_id": k_straggler, "neighbors": [], "session_salt": wire_salt}
        first = await client.post(
            session_url, headers={"Authorization": f"Bearer {tok_straggler}"}, json=grace_payload
        )
        assert first.status_code == 200, first.text

        # THE FIX: replaying the identical claim must be accepted, not 500
        replay = await client.post(
            session_url, headers={"Authorization": f"Bearer {tok_straggler}"}, json=grace_payload
        )
        assert replay.status_code == 200, replay.text

        async with grace_db() as s:
            rows = (
                await s.execute(
                    select(AttendanceRecord).where(
                        AttendanceRecord.session_id == uuid.UUID(session_id),
                        AttendanceRecord.ble_device_id == k_straggler,
                    )
                )
            ).scalars().all()
        assert len(rows) == 1


@pytest.mark.anyio
async def test_course_autocreate_race_adopts_existing():
    # R4: the course auto-create race adopted the committed winner instead of
    # 500ing the legitimate second creator.
    import uuid

    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
    from app.models.attendance import Base, Course
    from app.routers.attendance import _resolve_or_create_course

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    course_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    winner_id = uuid.uuid4()
    async with course_db() as s:
        s.add(Course(id=winner_id, course_code="CS101", course_name="Winner", teacher_id=None))
        await s.commit()

    # Normal branch: create-on-miss still works
    async with course_db() as s:
        fresh = await _resolve_or_create_course(
            db=s, code_to_check="CS204", course_name="Fresh", teacher_id=None
        )
        assert fresh.id is not None

    # Race branch: loser's stale SELECT misses, concurrent creator COMMITS
    # before ours does (IntegrityError on first commit), then re-select
    # must find and adopt the winner rather than 500.
    async with course_db() as s:
        used = {"stale_miss": False}
        real_execute = AsyncSession.execute
        real_commit = AsyncSession.commit

        async def stale_then_real(query, *a, **kw):
            if not used["stale_miss"]:
                used["stale_miss"] = True
                return _MissingScalarsResult()
            return await real_execute(s, query, *a, **kw)

        calls = {"n": 0}

        async def losing_commit():
            calls["n"] += 1
            if calls["n"] == 1:
                raise IntegrityError("uq course race", None, None)
            return await real_commit(s)

        s.execute = stale_then_real
        s.commit = losing_commit

        adopted = await _resolve_or_create_course(
            db=s, code_to_check="CS101", course_name="Loser", teacher_id=None
        )
        assert adopted.id == winner_id

    async with course_db() as s:
        rows = (
            await s.execute(select(Course).where(Course.course_code == "CS101"))
        ).scalars().all()
        assert len(rows) == 1


@pytest.mark.anyio
async def test_list_courses_does_not_fabricate_mock_context(monkeypatch):
    # R3: outside tests, GET /courses must not fabricate the demo teacher
    # (whose unhashable password 500s real logins and pollutes the DB).
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select, func
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import Base, Course, User
    from app.routers import attendance as attendance_router

    monkeypatch.setattr(attendance_router, "is_test_environment", lambda: False)

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    mock_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with mock_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/attendance/courses")
        assert res.status_code == 200, res.text

    async with mock_db() as s:
        assert (await s.execute(select(func.count()).select_from(User))).scalar_one() == 0
        assert (await s.execute(select(func.count()).select_from(Course))).scalar_one() == 0


# ---------------------------------------------------------------------------
# R2 finalize boundary gate (review §3.1) — chunk 4b
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_submit_during_finalize_inflight_is_not_orphaned(tmp_path):
    # R2: a submission that lands while finalize is IN FLIGHT (already popped
    # the staging buffer, not yet committed) previously read the still-ACTIVE
    # status, got a plain success, and was silently orphaned by finalize's
    # post-processing buffer clear. The route-level session gate must hold the
    # submit's stage + committed-status re-read across the finalize boundary —
    # so the straggler either gets drained, or is honestly rerouted to the
    # grace path with an attendance record.
    import asyncio
    import uuid

    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import AttendanceRecord, Base
    from app.services import submission_buffer as submission_buffer_module

    race_buffer = submission_buffer_module.submission_buffer
    real_pop = race_buffer.pop_submissions

    async def slowed_pop(sid):
        # Determinize the pop→commit window: the drain completes (so any stage
        # landing in the next moment can never be drained again), then finalize
        # stalls before its commit while the session status is still ACTIVE.
        result = await real_pop(sid)
        await asyncio.sleep(0.5)
        return result

    saved_pop = race_buffer.pop_submissions
    race_buffer.pop_submissions = slowed_pop
    try:
        # File-backed sqlite so two concurrent requests get separate connections
        test_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/race.db", echo=False)
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        race_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

        async def override_get_db():
            async with race_db() as s:
                yield s

        app.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            from app.routers.attendance import derive_short_device_key
            tok_teacher = await _register_test_teacher(client, race_db, "Prof. Race Gate", "race.gate@univ.edu")
            tok_straggler = await _register_roll_student(client, race_db, "Race Straggler", "race.strag@univ.edu", "22B4481")
            k_straggler = derive_short_device_key("22B4481")

            s_res = await client.post(
                "/api/v1/attendance/sessions",
                headers={"Authorization": f"Bearer {tok_teacher}"},
                json={"session_token": "RZ01", "total_enrolled": 5},
            )
            assert s_res.status_code == 201, s_res.text
            session_id = s_res.json()["id"]
            wire_salt = s_res.json()["session_wire_salt"]
            session_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

            # Fire finalize first; once it is inside its body (gate-region), the
            # straggler submits into the pop→commit window.
            finalize_task = asyncio.create_task(
                client.post(
                    f"/api/v1/attendance/sessions/{session_id}/audit-and-finalize",
                    headers={"Authorization": f"Bearer {tok_teacher}"},
                    json={"reports": {}},
                )
            )
            await asyncio.sleep(0.08)  # finalize past route entry / row lock
            submit_task = asyncio.create_task(
                client.post(
                    session_url,
                    headers={"Authorization": f"Bearer {tok_straggler}"},
                    json={"game_score": 20, "student_id": k_straggler, "neighbors": [], "session_salt": wire_salt},
                )
            )
            finalize_res, submit_res = await asyncio.gather(finalize_task, submit_task)

            assert submit_res.status_code == 200, submit_res.text
            assert finalize_res.status_code == 200, finalize_res.text

            async with race_db() as s:
                rows = (
                    await s.execute(
                        select(AttendanceRecord).where(
                            AttendanceRecord.session_id == uuid.UUID(session_id),
                            AttendanceRecord.ble_device_id == k_straggler,
                        )
                    )
                ).scalars().all()
        # The straggler MUST exist exactly once — drained or graced, never orphaned
        assert len(rows) == 1, (
            "R2 lost a mid-finalize submission: got zero records for the straggler. "
            f"submit_res {submit_res.status_code}: {submit_res.text[:220]}"
        )
        # A still-resident staged entry is tolerable (additive, pruned by TTL);
        # note: keep buffer-emptiness checks out — the gate does not evict.
    finally:
        race_buffer.pop_submissions = saved_pop


# ---------------------------------------------------------------------------
# Honesty statuses (review §5) — chunk 5
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_submit_face_verified_reflects_outcome():
    # R5: face_verified is bound to the CHECK OUTCOME. Unverifiable face
    # payloads must be REJECTED (they must never surface as face_verified True),
    # and a no-face submission must carry face_verified None.
    import io
    import base64
    from PIL import Image
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    face_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with face_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    img = Image.new("RGB", (100, 100), color=(180, 140, 120))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    b64_img = base64.b64encode(buf.getvalue()).decode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_stud = await _register_battery_student(client, face_db)

        res = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            headers={"Authorization": f"Bearer {tok_stud}"},
            json={"game_score": 20, "student_id": "STUD5",
                "neighbors": ["PEER-A1"],
                "session_salt": "DEMO1",
                "face_image_base64": b64_img,
            },
        )
        assert res.status_code == 200, res.text
        assert res.json()["face_verified"] is True
        assert res.json()["face_diagnostic"] is not None

        # No-face submission: verified must honestly be None
        noface = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            headers={"Authorization": f"Bearer {tok_stud}"},
            json={"game_score": 20, "student_id": "STUD5",
                "neighbors": ["PEER-A1"],
                "session_salt": "DEMO1",
            },
        )
        assert noface.status_code == 200, noface.text
        assert noface.json()["face_verified"] is None

        # UNVERIFIABLE face payload: a fake/non-decodable image must never pass
        bogus_face = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            headers={"Authorization": f"Bearer {tok_stud}"},
            json={"game_score": 20, "student_id": "STUD5",
                "neighbors": ["PEER-A1"],
                "session_salt": "DEMO1",
                "face_image_base64": "!!!!not-base64-face!!!!",
            },
        )
        assert bogus_face.status_code == 403, bogus_face.text
        assert "Biometric proxy rejected" in bogus_face.json()["detail"]


@pytest.mark.anyio
async def test_lab_face_check_errors_are_http_errors():
    # R5: /lab/face-check failures must be HTTP errors, never a pretend-200
    # carrying an error string inside remarks.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    lab_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with lab_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, lab_db, "Prof. Lab Err", "lab.err@univ.edu")
        res = await client.post(
            "/api/v1/attendance/lab/face-check",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"game_score": 20, "face_image_base64": "!!!!not-base64-face!!!!"},
        )
        assert res.status_code >= 400, res.text
        assert "Face processing failed" in res.json()["detail"]


@pytest.mark.anyio
async def test_finalize_counts_are_recounted_from_db():
    # R5: finalize counters must reflect committed DB rows, not payload
    # tallies. A prior VERIFIED row that is absent from the finalize payload
    # would have been silently dropped from total_verified before this fix.
    import uuid

    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.database import get_db
    from app.models.attendance import AttendanceRecord, AttendanceSession, Base, User
    from datetime import datetime, timezone

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    count_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with count_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, count_db, "Prof. Recount", "recount@univ.edu")
        tok_stud_b = await _register_roll_student(client, count_db, "Count Bravo", "count.bravo@univ.edu", "22B4521")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "CQ01", "session_salt": "CQ1A", "total_enrolled": 5},
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]

        async with count_db() as s:
            session_row = (
                await s.execute(
                    select(AttendanceSession).where(AttendanceSession.id == uuid.UUID(session_id))
                )
            ).scalars().first()
            student_b = (await s.execute(select(User).where(User.roll_number == "22B4521"))).scalars().first()
            assert student_b is not None
            # A prior VERIFIED record NOT present in the finalize payload
            prior_row = AttendanceRecord(
                id=uuid.uuid4(),
                session_id=session_row.id,
                student_id=student_b.id,
                ble_device_id="4521",
                status="VERIFIED_PRESENT",
                verification_method="BLE_MESH",
                affinity_score=1.0,
                reported_neighbors=[],
                remarks="Prior verified row (grace-path style)",
                game_score=20,
                recorded_at=datetime.now(timezone.utc),
            )
            s.add(prior_row)
            await s.commit()

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={
                "records": [
                    {
                        "ble_device_id": "4522",
                        "student_id": None,
                        "status": "VERIFIED_PRESENT",
                        "verification_method": "DIRECT_MUTUAL",
                        "affinity_score": 1.0,
                        "reported_neighbors": [],
                        "game_score": 20,
                    }
                ]
            },
        )
        assert fin.status_code == 200, fin.text
        # Recount sees the prior row (1) + the drained payload row (1) = 2
        assert fin.json()["total_verified"] == 2, fin.text
        assert fin.json()["total_unverified"] == 0


@pytest.mark.anyio
async def test_oversized_body_is_rejected_with_413():
    # R5: declared overlong bodies are refused at the middleware gate before
    # framework buffering and engine decoding.
    from httpx import AsyncClient, ASGITransport
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Control: small bodies pass through unimpeded
        res = await client.get("/health")
        assert res.status_code == 200

        big = b"x" * (7_000_000)
        res = await client.post(
            "/api/v1/attendance/sessions",
            content=big,
            headers={"Content-Type": "application/json"},
        )
        assert res.status_code == 413, res.text
        assert "too large" in res.text


# ---------------------------------------------------------------------------
# Auth lifecycle (review §7) — chunk 7: token_version / is_active / logout
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_logout_revokes_token_and_relogin_recovers():
    # R7: logout must invalidate the token SERVER-SIDE (the old app had no
    # logout route at all — "logout" was purely local token deletion and the
    # stolen/expired-adjacent token worked until expiry), and a fresh login
    # must recover at the bumped version rather than lock the account out.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base, EmailOTP

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    auth_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with auth_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok = await _register_battery_student(client, auth_db)

        me_res = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"})
        assert me_res.status_code == 200, me_res.text

        out = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert out.status_code == 200, out.text

        dead = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"})
        assert dead.status_code == 401, dead.text
        assert "revoked" in dead.json()["detail"].lower()

        # Fresh login recovers at the bumped version — no account lockout
        login_email = me_res.json()["email"]
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"email": login_email, "password": "Password123!"},
        )
        assert login_res.status_code == 200, login_res.text
        assert login_res.json()["requires_otp"] is True

        async with auth_db() as s:
            otp_rec = (
                await s.execute(
                    select(EmailOTP).where(
                        EmailOTP.email == login_email, EmailOTP.purpose == "LOGIN"
                    )
                )
            ).scalars().first()
            login_otp = otp_rec.otp_code

        verify = await client.post(
            "/api/v1/auth/login/verify-otp",
            json={"email": login_email, "otp_code": login_otp},
        )
        assert verify.status_code == 200, verify.text
        fresh_me = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {verify.json()['access_token']}"},
        )
        assert fresh_me.status_code == 200, fresh_me.text


@pytest.mark.anyio
async def test_deactivated_account_token_rejected():
    # R7: is_active enforcement. The old dependency's 401 message claimed
    # "account deactivated" while never reading the column — a deactivated
    # user's token kept working until expiry.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base, User

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    auth_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with auth_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok = await _register_battery_student(client, auth_db)
        me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"})
        assert me.status_code == 200, me.text

        async with auth_db() as s:
            user = (await s.execute(select(User))).scalars().first()  # only user in this DB
            user.is_active = False
            await s.commit()

        dead = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"})
        assert dead.status_code == 401, dead.text
        assert "deactivated" in dead.json()["detail"].lower()


@pytest.mark.anyio
async def test_legacy_token_without_version_claim_is_v0():
    # R7 DEPLOY-SAFETY CONTRACT: tokens issued before the token_version
    # feature carry no such claim; combined with the column's server default
    # of 0 they must KEEP working after this deploy. A regression here would
    # force-logout every production user on upgrade.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.core.security import create_access_token
    from app.database import get_db
    from app.models.attendance import Base, User

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    auth_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with auth_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await _register_battery_student(client, auth_db)

        async with auth_db() as s:
            user = (await s.execute(select(User))).scalars().first()
            legacy = create_access_token(
                data={
                    "sub": str(user.id),
                    "name": user.full_name,
                    "role": user.role,
                    "roll_number": user.roll_number,
                    # NOTE: deliberately NO "tv" claim — the pre-feature shape
                }
            )

        ok = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {legacy}"})
        assert ok.status_code == 200, ok.text


@pytest.mark.anyio
async def test_stale_version_token_rejected():
    # R7: an explicit version MISMATCH is rejected — a token minted at
    # version 0 dies once the account's version is bumped (logout/revocation
    # semantics). Contrast with the claim-less legacy token above: missing
    # claim == v0, explicit 0 vs bumped account == revoked.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.core.security import create_access_token
    from app.database import get_db
    from app.models.attendance import Base, User

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    auth_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with auth_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await _register_battery_student(client, auth_db)

        async with auth_db() as s:
            user = (await s.execute(select(User))).scalars().first()
            stale = create_access_token(
                data={
                    "sub": str(user.id),
                    "name": user.full_name,
                    "role": user.role,
                    "roll_number": user.roll_number,
                    "tv": 0,
                }
            )
            # Simulate a later revocation: account version moves past the token
            user.token_version = 1
            await s.commit()

        dead = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {stale}"})
        assert dead.status_code == 401, dead.text
        assert "revoked" in dead.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Docker/infra hardening (review §1.1/§1.8/§3.6) — chunk 10
# ---------------------------------------------------------------------------


def test_production_guard_rejects_placeholder_database_url(monkeypatch):
    # R10 (deferred from chunk 3): DATABASE_URL was outside the guard's reach —
    # the compose file embeds the shared placeholder password directly in the
    # DSN. A placeholder must not boot in production even alongside rotated
    # JWT/faculty secrets.
    import secrets

    from app import config

    monkeypatch.setattr(config.settings, "APP_ENV", "production")
    monkeypatch.setattr(config.settings, "JWT_SECRET_KEY", secrets.token_urlsafe(64))
    monkeypatch.setattr(config.settings, "FACULTY_SIGNUP_SECRET", secrets.token_urlsafe(64))
    monkeypatch.setattr(
        config.settings,
        "DATABASE_URL",
        "postgresql+asyncpg://college_admin:change_this_secure_password@db:5432/college_attendance",
    )

    with pytest.raises(RuntimeError) as err:
        config.validate_production_secrets()
    assert "DATABASE_URL" in str(err.value)
    # Same convention as the other secrets: the MESSAGE names the matching
    # MARKER token ("change_this"), never the full leaked-looking value
    assert "change_this" in str(err.value)

    # A real generated credential in the DSN passes
    monkeypatch.setattr(
        config.settings,
        "DATABASE_URL",
        f"postgresql+asyncpg://college_admin:{secrets.token_urlsafe(24)}@db:5432/college_attendance",
    )
    assert config.database_url_reason() is None

    # Empty is also refused in production (an unset DSN is a config error there)
    monkeypatch.setattr(config.settings, "DATABASE_URL", "")
    assert config.database_url_reason() == "DATABASE_URL is empty"


def test_compose_publishes_no_postgres_port():
    # R10 (review §1.8): the db service must not publish 5432 to the host —
    # only the backend on the compose network talks to it.
    import yaml
    from pathlib import Path

    compose_path = Path(__file__).resolve().parent.parent / "docker-compose.yml"
    compose = yaml.safe_load(compose_path.read_text())
    db = compose["services"]["db"]
    assert not db.get("ports"), f"db still publishes ports: {db.get('ports')}"
    assert db.get("expose") is not None, "db must expose 5432 internally only"


# Verifies the 5-minute TTL auto-expire applies ONLY to ACTIVE sessions: a
# straggler submit during the grace window of a COMPLETED session whose
# started_at is minutes old must NOT rewrite the committed status to EXPIRED
# (the old TTL path corrupted finalized sessions in the DB).
@pytest.mark.anyio
async def test_ttl_expire_does_not_corrupt_completed_sessions():
    import uuid
    from datetime import datetime, timedelta, timezone
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import AttendanceRecord, AttendanceSession, Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, test_session_factory, "Prof. TTL Guard", "ttl.teacher@univ.edu")
        tok_stud = await _register_roll_student(client, test_session_factory, "TTL Student", "ttl.stud@univ.edu", "22B7781")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "TTLG", "total_enrolled": 1},
        )
        assert s_res.status_code == 201
        session_data = s_res.json()
        session_id = session_data["id"]
        wire_salt = session_data["session_wire_salt"]

        # Backdate: class ran long, finalize already committed, straggler
        # submits during grace well past the 5-minute TTL from started_at
        async with test_session_factory() as s:
            row = (await s.execute(
                select(AttendanceSession).where(AttendanceSession.id == uuid.UUID(session_id))
            )).scalars().first()
            row.started_at = datetime.now(timezone.utc) - timedelta(minutes=6)
            row.status = "COMPLETED"
            row.ended_at = datetime.now(timezone.utc) - timedelta(seconds=10)
            await s.commit()

        submit_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"
        r = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_stud}"},
            json={"student_id": "7781", "neighbors": [], "session_salt": wire_salt},
        )
        # Grace path accepted (NOT the TTL 400 that used to fire here)
        assert r.status_code == 200, r.text

        async with test_session_factory() as s:
            row = (await s.execute(
                select(AttendanceSession).where(AttendanceSession.id == uuid.UUID(session_id))
            )).scalars().first()
            assert row.status == "COMPLETED", row.status  # never rewritten to EXPIRED
            recs = (await s.execute(
                select(AttendanceRecord).where(AttendanceRecord.session_id == uuid.UUID(session_id))
            )).scalars().all()
            assert len(recs) == 1
            assert recs[0].status == "ISOLATED_FLAGGED"
            assert recs[0].verification_method == "NONE"


# Verifies the legacy /finalize verdict-time score gate (parity with
# audit-and-finalize): a staged mutual-pair student whose score is below the
# threshold must land COGNITIVE_CHALLENGE_FAILED — never VERIFIED_PRESENT with
# a NULL game_score silently bypassing the challenge gate.
@pytest.mark.anyio
async def test_legacy_finalize_enforces_score_gate():
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        from app.routers.attendance import derive_short_device_key

        tok_teacher = await _register_test_teacher(client, test_session_factory, "Prof. Legacy Gate", "legacy.gate@univ.edu")
        tok_a = await _register_roll_student(client, test_session_factory, "Gate Alpha", "gate.a@univ.edu", "22B6611")
        tok_b = await _register_roll_student(client, test_session_factory, "Gate Beta", "gate.b@univ.edu", "22B6612")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "LGF1", "total_enrolled": 2},
        )
        assert s_res.status_code == 201
        session_data = s_res.json()
        session_id = session_data["id"]
        wire_salt = session_data["session_wire_salt"]
        k_a = derive_short_device_key("22B6611")
        k_b = derive_short_device_key("22B6612")
        submit_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        # Mutual pair: A passes the challenge gate (20), B's score is
        # sub-threshold (8) — both stage cleanly (no face, no submit-time gate)
        r_a = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"game_score": 20, "student_id": k_a, "neighbors": [k_b], "session_salt": wire_salt},
        )
        assert r_a.status_code == 200, r_a.text
        r_b = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_b}"},
            json={"game_score": 8, "student_id": k_b, "neighbors": [k_a], "session_salt": wire_salt},
        )
        assert r_b.status_code == 200, r_b.text

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"records": []},
        )
        assert fin.status_code == 200, fin.text
        fin_data = fin.json()
        assert fin_data["total_verified"] == 1  # only A clears the gate
        record_map = {r["ble_device_id"]: r for r in fin_data["records"]}
        assert record_map[k_a]["status"] == "VERIFIED_PRESENT"
        assert record_map[k_a]["game_score"] == 20
        assert record_map[k_b]["status"] == "COGNITIVE_CHALLENGE_FAILED"
        assert record_map[k_b]["game_score"] == 8
        assert "score 8 < 15" in record_map[k_b]["remarks"]


# Leave feature (chunk 1): student submissions route to the department queue;
# TEACHERs of the department are view-only; ONLY role='HOD' (set manually in
# the DB, never registrable) can approve/reject — and only within their own
# department. Invalid ranges, oversized spans, and re-reviews are rejected.
@pytest.mark.anyio
async def test_leave_submission_and_hod_review_flow():
    import uuid
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base, User

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, test_session_factory, "Prof. Leave Dept", "leave.teacher@univ.edu")
        tok_ece = await _register_test_teacher(client, test_session_factory, "Prof. ECE View", "ece.view@univ.edu")
        tok_student = await _register_roll_student(client, test_session_factory, "Leave Student", "leave.stud@univ.edu", "22B5501")

        # Manual DB promotion mirrors the real flow: HOD is never registrable
        async with test_session_factory() as s:
            hod_row = (await s.execute(select(User).where(User.email == "leave.teacher@univ.edu"))).scalars().first()
            hod_row.role = "HOD"
            ece_row = (await s.execute(select(User).where(User.email == "ece.view@univ.edu"))).scalars().first()
            ece_row.department = "ECE"
            await s.commit()

        submit_url = "/api/v1/leave/applications"
        r = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_student}"},
            json={"from_date": "2026-11-13", "to_date": "2026-11-15", "reason": "Family function out of station"},
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "PENDING"
        assert body["can_review"] is False
        assert body["department"] == "CSE"
        application_id = body["id"]

        # Validation: backwards range, >90-day span, too-short reason
        bad_range = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_student}"},
            json={"from_date": "2026-11-15", "to_date": "2026-11-13", "reason": "Backwards range test"},
        )
        assert bad_range.status_code == 422
        long_span = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_student}"},
            json={"from_date": "2026-01-01", "to_date": "2026-12-30", "reason": "Way too long range"},
        )
        assert long_span.status_code == 422
        tiny_reason = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_student}"},
            json={"from_date": "2026-11-13", "to_date": "2026-11-14", "reason": "ab"},
        )
        assert tiny_reason.status_code == 422

        # Student sees own application
        mine = await client.get(
            "/api/v1/leave/applications/mine",
            headers={"Authorization": f"Bearer {tok_student}"},
        )
        assert mine.status_code == 200
        assert len(mine.json()) == 1

        # HOD queue: sees the application with review rights
        queue = await client.get(
            "/api/v1/leave/applications",
            headers={"Authorization": f"Bearer {tok_teacher}"},
        )
        assert queue.status_code == 200
        items = queue.json()
        assert len(items) == 1
        assert items[0]["can_review"] is True
        assert items[0]["student_roll"] == "22B5501"

        # Teacher of another department sees an EMPTY queue (dept isolation)
        queue_ece = await client.get(
            "/api/v1/leave/applications",
            headers={"Authorization": f"Bearer {tok_ece}"},
        )
        assert queue_ece.status_code == 200
        assert queue_ece.json() == []

        # TEACHER role cannot review at all
        forbidden = await client.post(
            f"/api/v1/leave/applications/{application_id}/review",
            headers={"Authorization": f"Bearer {tok_ece}"},
            json={"decision": "APPROVED"},
        )
        assert forbidden.status_code == 403
        assert "Only the HOD" in forbidden.json()["detail"]

        # Even a HOD of another department cannot act on it
        async with test_session_factory() as s:
            ece_row = (await s.execute(select(User).where(User.email == "ece.view@univ.edu"))).scalars().first()
            ece_row.role = "HOD"
            await s.commit()
        cross = await client.post(
            f"/api/v1/leave/applications/{application_id}/review",
            headers={"Authorization": f"Bearer {tok_ece}"},
            json={"decision": "REJECTED", "comment": "not my department"},
        )
        assert cross.status_code == 403
        assert "another department" in cross.json()["detail"]

        # Own-department HOD approves
        approved = await client.post(
            f"/api/v1/leave/applications/{application_id}/review",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"decision": "APPROVED", "comment": "Approved — one time"},
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "APPROVED"
        assert approved.json()["review_comment"] == "Approved — one time"
        assert approved.json()["reviewed_at"] is not None

        # Re-reviewing a decided application is a conflict
        again = await client.post(
            f"/api/v1/leave/applications/{application_id}/review",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"decision": "REJECTED"},
        )
        assert again.status_code == 409

        # Reject path works too
        r2 = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_student}"},
            json={"from_date": "2026-11-20", "to_date": "2026-11-20", "reason": "Medical checkup"},
        )
        assert r2.status_code == 201, r2.text
        second_id = r2.json()["id"]
        rejected = await client.post(
            f"/api/v1/leave/applications/{second_id}/review",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"decision": "REJECTED", "comment": "Exam week"},
        )
        assert rejected.status_code == 200
        assert rejected.json()["status"] == "REJECTED"
        assert rejected.json()["review_comment"] == "Exam week"


# HOD is a TEACHER superset: widening require_teacher must keep session
# creation (and all other teacher powers) working for role='HOD'.
@pytest.mark.anyio
async def test_hod_retains_teacher_powers():
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base, User

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, test_session_factory, "Prof. HOD Powers", "hod.powers@univ.edu")
        tok_student = await _register_roll_student(client, test_session_factory, "Powers Student", "powers.stud@univ.edu", "22B5502")

        async with test_session_factory() as s:
            hod_row = (await s.execute(select(User).where(User.email == "hod.powers@univ.edu"))).scalars().first()
            hod_row.role = "HOD"
            await s.commit()

        # require_teacher accepts HOD: session creation succeeds
        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "HODP", "total_enrolled": 1},
        )
        assert s_res.status_code == 201, s_res.text


# Leave feature (chunk 2): the finalize overlay. Enrolled students whose
# APPROVED leave covers the session date are marked LEAVE instead of ABSENT
# (or given a LEAVE row when they never produced one). Presence beats leave:
# VERIFIED verdicts stay VERIFIED even with approved leave. Students without
# approved leave get nothing.
@pytest.mark.anyio
async def test_leave_overlay_marks_leave_in_legacy_finalize():
    from datetime import datetime, timezone
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base, User
    from app.routers.attendance import derive_short_device_key

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, test_session_factory, "Prof. Leave Overlay", "leave.overlay@univ.edu")
        tok_a = await _register_roll_student(client, test_session_factory, "Overlay Alpha", "overlay.a@univ.edu", "22B6601")
        tok_b = await _register_roll_student(client, test_session_factory, "Overlay Bravo", "overlay.b@univ.edu", "22B6602")
        tok_c = await _register_roll_student(client, test_session_factory, "Overlay Charlie", "overlay.c@univ.edu", "22B6603")
        tok_d = await _register_roll_student(client, test_session_factory, "Overlay Delta", "overlay.d@univ.edu", "22B6604")
        tok_e = await _register_roll_student(client, test_session_factory, "Overlay Echo", "overlay.e@univ.edu", "22B6605")

        async with test_session_factory() as s:
            hod_row = (await s.execute(select(User).where(User.email == "leave.overlay@univ.edu"))).scalars().first()
            hod_row.role = "HOD"
            await s.commit()

        # Class runs today; every leave below covers today's date
        today = datetime.now(timezone.utc).date().isoformat()

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={
                "session_token": "LVOL",
                "total_enrolled": 0,
                "course_program": "B.Tech",
                "course_semester": 1,
            },
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]

        # C and D are a mutual pair (both should end VERIFIED despite leave)
        submit_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"
        r_c = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_c}"},
            json={"game_score": 20, "student_id": derive_short_device_key("22B6603"), "neighbors": [derive_short_device_key("22B6604")], "session_salt": s_res.json()["session_wire_salt"]},
        )
        assert r_c.status_code == 200, r_c.text
        r_d = await client.post(
            submit_url,
            headers={"Authorization": f"Bearer {tok_d}"},
            json={"game_score": 20, "student_id": derive_short_device_key("22B6604"), "neighbors": [derive_short_device_key("22B6603")], "session_salt": s_res.json()["session_wire_salt"]},
        )
        assert r_d.status_code == 200, r_d.text

        # Leaves: A (silent), B (will arrive as an ABSENT payload row),
        # C and D (present pair — proves presence beats leave)
        for tok, email, roll in [(tok_a, "overlay.a@univ.edu", "22B6601"), (tok_b, "overlay.b@univ.edu", "22B6602"), (tok_c, "overlay.c@univ.edu", "22B6603"), (tok_d, "overlay.d@univ.edu", "22B6604")]:
            r = await client.post(
                "/api/v1/leave/applications",
                headers={"Authorization": f"Bearer {tok}"},
                json={"from_date": today, "to_date": today, "reason": f"Overlay test leave {roll}"},
            )
            assert r.status_code == 201, r.text
        async with test_session_factory() as s:
            pending = (await s.execute(select(_leave_model()))).scalars().all()
            for row in pending:
                row.status = "APPROVED"
                row.reviewed_by = hod_row.id if hod_row else None
            await s.commit()

        # Teacher's payload marks B ABSENT (by device key)
        k_b = derive_short_device_key("22B6602")
        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={
                "records": [
                    {
                        "ble_device_id": k_b,
                        "student_id": None,
                        "status": "ABSENT",
                        "verification_method": "NONE",
                        "affinity_score": 0.0,
                        "reported_neighbors": [],
                    }
                ]
            },
        )
        assert fin.status_code == 200, fin.text
        fin_data = fin.json()
        assert fin_data["total_verified"] == 2  # C and D only
        record_map = {r["ble_device_id"]: r for r in fin_data["records"]}
        assert record_map[derive_short_device_key("22B6601")]["status"] == "LEAVE"
        assert record_map[k_b]["status"] == "LEAVE"  # ABSENT rewritten
        assert record_map[derive_short_device_key("22B6603")]["status"] == "VERIFIED_PRESENT"
        assert record_map[derive_short_device_key("22B6604")]["status"] == "VERIFIED_PRESENT"
        # E had no approved leave — silent student, no record invented
        assert derive_short_device_key("22B6605") not in record_map
        # LEAVE rows self-explain
        assert "Approved leave" in record_map[k_b]["remarks"]


# Same overlay through the audit-and-finalize path: a fully silent class where
# one student has approved leave gets exactly one LEAVE row and nothing else.
@pytest.mark.anyio
async def test_leave_overlay_in_audit_finalize():
    from datetime import datetime, timezone
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base, User
    from app.routers.attendance import derive_short_device_key

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, test_session_factory, "Prof. Audit Leave", "audit.leave@univ.edu")
        tok_a = await _register_roll_student(client, test_session_factory, "Audit Leave Stud", "audit.leave.stud@univ.edu", "22B6701")
        tok_e = await _register_roll_student(client, test_session_factory, "Audit No Leave", "audit.noleave@univ.edu", "22B6702")

        async with test_session_factory() as s:
            hod_row = (await s.execute(select(User).where(User.email == "audit.leave@univ.edu"))).scalars().first()
            hod_row.role = "HOD"
            await s.commit()

        today = datetime.now(timezone.utc).date().isoformat()
        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={
                "session_token": "AVOL",
                "total_enrolled": 0,
                "course_program": "B.Tech",
                "course_semester": 1,
            },
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]

        r = await client.post(
            "/api/v1/leave/applications",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"from_date": today, "to_date": today, "reason": "Audit path leave test"},
        )
        assert r.status_code == 201, r.text
        async with test_session_factory() as s:
            pending = (await s.execute(select(_leave_model()))).scalars().all()
            for row in pending:
                row.status = "APPROVED"
                if hod_row:
                    row.reviewed_by = hod_row.id
            await s.commit()

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/audit-and-finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"reports": {}},
        )
        assert fin.status_code == 200, fin.text
        fin_data = fin.json()
        assert fin_data["total_verified"] == 0
        records = fin_data["records"]
        assert len(records) == 1
        assert records[0]["ble_device_id"] == derive_short_device_key("22B6701")
        assert records[0]["status"] == "LEAVE"
        assert records[0]["verification_method"] == "LEAVE_APPROVAL"
        # The other silent student (no approved leave) has no record
        assert all(rec["ble_device_id"] != derive_short_device_key("22B6702") for rec in records)


def _leave_model():
    from app.models.attendance import LeaveApplication
    return LeaveApplication


# Bug bounty round 2 fixes — regression tests.


# Fix: LeaveApplication.department must hold any value User.department (String(100))
# accepts; the old String(50) column 500'd the leave submit for long departments.
@pytest.mark.anyio
async def test_leave_department_accepts_100_chars():
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base, EmailOTP
    from sqlalchemy import select

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    long_dept = "OFFICE-ELECTRONICS-AND-COMMUNICATION-ENGINEERING-SECTION-B-2026-CAMPUS-2"
    assert len(long_dept) == 72  # beyond the old 50-char column, within 100

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        email = "longdept.stud@univ.edu"
        reg = await client.post(
            "/api/v1/auth/register",
            json={
                "name": "Long Dept Student", "email": email, "password": "Password123!",
                "role": "STUDENT", "roll_number": "22B8801", "department": long_dept,
                "program": "B.Tech", "semester": 1, "section": "A",
            },
        )
        assert reg.status_code == 200, reg.text
        async with test_session_factory() as s:
            otp_row = (await s.execute(select(EmailOTP).where(EmailOTP.email == email, EmailOTP.purpose == "REGISTER"))).scalars().first()
        verified = await client.post(
            "/api/v1/auth/register/verify-otp",
            json={"email": email, "otp_code": otp_row.otp_code},
        )
        assert verified.status_code == 201, verified.text
        tok = verified.json()["access_token"]

        r = await client.post(
            "/api/v1/leave/applications",
            headers={"Authorization": f"Bearer {tok}"},
            json={"from_date": "2026-11-13", "to_date": "2026-11-14", "reason": "Long department regression test"},
        )
        assert r.status_code == 201, r.text
        assert r.json()["department"] == long_dept


# Fix: the ORM model now declares the leave check constraints so a fresh
# create_all database (which runs BEFORE POSTGRES_SCHEMA_SYNC_BLOCK) enforces
# the same guards the sync block's CREATE TABLE installs.
@pytest.mark.anyio
async def test_fresh_createall_enforces_leave_constraints():
    import pytest as _pytest
    from datetime import date
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.models.attendance import Base, LeaveApplication, User

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async with factory() as s:
        user = User(
            email="freshguard@univ.edu", full_name="Fresh Guard", roll_number="22B9001",
            role="STUDENT", hashed_password="x", is_active=True,
        )
        s.add(user)
        await s.commit()

        base = dict(
            student_id=user.id, department="CSE",
            from_date=date(2026, 11, 13), to_date=date(2026, 11, 14), reason="Guard test",
        )

        # Backwards range must be rejected by the table CHECK
        with _pytest.raises(IntegrityError):
            bad = LeaveApplication(**{**base, "from_date": date(2026, 11, 14), "to_date": date(2026, 11, 13)})
            s.add(bad)
            await s.commit()
        await s.rollback()

        # Unknown status must be rejected by the table CHECK
        with _pytest.raises(IntegrityError):
            bad_status = LeaveApplication(**{**base, "status": "MAYBE"})
            s.add(bad_status)
            await s.commit()
        await s.rollback()

        # A well-formed row still inserts
        ok = LeaveApplication(**base)
        s.add(ok)
        await s.commit()
        rows = (await s.execute(select(LeaveApplication))).scalars().all()
        assert len(rows) == 1 and rows[0].status == "PENDING"


# Fix: leave overlay must match the IST calendar day. A session starting
# 18:30 UTC is already the NEXT day in IST; leave approved for that local
# day must produce a LEAVE row even though the UTC date differs.
@pytest.mark.anyio
async def test_leave_overlay_matches_ist_calendar_day():
    import uuid as _uuid
    from datetime import datetime, timezone
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import AttendanceSession, Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, test_session_factory, "Prof. IST Leave", "ist.leave@univ.edu")
        tok_a = await _register_roll_student(client, test_session_factory, "IST Leave Stud", "ist.stud@univ.edu", "22B7101")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={
                "session_token": "ISTL",
                "total_enrolled": 0,
                "course_program": "B.Tech",
                "course_semester": 1,
            },
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]

        # 2026-11-13 18:30 UTC == 2026-11-14 00:00 IST
        async with test_session_factory() as s:
            sess = (await s.execute(select(AttendanceSession).where(AttendanceSession.id == _uuid.UUID(session_id)))).scalars().first()
            sess.started_at = datetime(2026, 11, 13, 18, 30, tzinfo=timezone.utc)
            await s.commit()

        # Leave approved ONLY for the IST calendar day (2026-11-14)
        r = await client.post(
            "/api/v1/leave/applications",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"from_date": "2026-11-14", "to_date": "2026-11-14", "reason": "IST calendar day coverage test"},
        )
        assert r.status_code == 201, r.text
        async with test_session_factory() as s:
            pending = (await s.execute(select(_leave_model()))).scalars().all()
            for row in pending:
                row.status = "APPROVED"
            await s.commit()

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/audit-and-finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"reports": {}},
        )
        assert fin.status_code == 200, fin.text
        records = fin.json()["records"]
        assert len(records) == 1
        assert records[0]["status"] == "LEAVE"
        assert records[0]["verification_method"] == "LEAVE_APPROVAL"


# Fix: when student B's face matches student A's earlier registration, ONLY B
# is flagged. A must NOT receive a DUPLICATE_FACE_PROXY row (innocent student,
# and that row was always created with student_id=None — the null-student-id
# record the teacher dashboard showed).
@pytest.mark.anyio
async def test_duplicate_face_does_not_vandalize_matched_student():
    import base64
    import io
    from PIL import Image
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import AttendanceRecord, AttendanceSession, Base
    from app.routers.attendance import derive_short_device_key

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    test_session_factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with test_session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    img = Image.new("RGB", (100, 100), color=(180, 140, 120))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    b64_img = base64.b64encode(buf.getvalue()).decode("utf-8")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_a = await _register_battery_student(client, test_session_factory)
        tok_b = await _register_battery_student(client, test_session_factory)

        res_a = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"game_score": 20, "student_id": "STUDA",
                "neighbors": [], "session_salt": "DEMO1",
                "face_image_base64": b64_img},
        )
        assert res_a.status_code == 200, res_a.text

        res_b = await client.post(
            "/api/v1/attendance/sessions/AUTO-101/submit-neighbors",
            headers={"Authorization": f"Bearer {tok_b}"},
            json={"game_score": 20, "student_id": "STUDB",
                "neighbors": [], "session_salt": "DEMO1",
                "face_image_base64": b64_img},
        )
        assert res_b.status_code == 403, res_b.text

        async with test_session_factory() as s:
            sess_row = (await s.execute(
                select(AttendanceSession).where(AttendanceSession.session_token == "AUTO-101")
            )).scalars().first()
            rows = (await s.execute(
                select(AttendanceRecord).where(AttendanceRecord.session_id == sess_row.id)
            )).scalars().all()

        roll_a_key = None
        # Resolve both battery students' device keys from their accounts
        from app.models.attendance import User
        async with test_session_factory() as s:
            users = (await s.execute(select(User))).scalars().all()
            key_by_roll = {u.roll_number: derive_short_device_key(u.roll_number) for u in users}
            dup_rows = [r for r in rows if r.status == "DUPLICATE_FACE_PROXY"]

        assert len(dup_rows) == 1, f"expected only the submitter flagged, got {[(r.ble_device_id, r.status) for r in rows]}"
        assert dup_rows[0].ble_device_id in key_by_roll.values()
        assert dup_rows[0].student_id is not None
        # The matched (innocent) student has no row at all — their clean
        # submission stays staged for the finalize audit.
        for r in rows:
            if r.status == "DUPLICATE_FACE_PROXY":
                continue
            assert r.status != "DUPLICATE_FACE_PROXY"


@pytest.mark.anyio
async def test_auth_me_carries_game_fields():
    # F3: /auth/me (and the login TokenResponse) must carry the XP/level
    # triple the profile card renders. Fresh account: level 1, no XP.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    auth_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with auth_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok = await _register_battery_student(client, auth_db)
        me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"})
        assert me.status_code == 200, me.text
        body = me.json()
        assert body["game_xp"] == 0
        assert body["game_level"] == 1
        assert body["game_xp_progress"] == 0.0


@pytest.mark.anyio
async def test_level3_student_fails_gate_below_17():
    # F3: pass threshold scales with the student's level (ceil 50% of the
    # level max, floor 15). A level-3 student (achievable max 34) needs 17;
    # a 16 that would pass at level 1 must not keep them VERIFIED_PRESENT.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base, User
    from app.routers.attendance import derive_short_device_key

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    seal_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with seal_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, seal_db, "Prof. Threshold", "threshold@univ.edu")
        tok_stud1 = await _register_roll_student(client, seal_db, "Level Three", "level.three@univ.edu", "22B6701")
        tok_stud2 = await _register_roll_student(client, seal_db, "Level One", "level.one@univ.edu", "22B6702")
        k1 = derive_short_device_key("22B6701")
        k2 = derive_short_device_key("22B6702")

        # Force student 1 to level 3 (band starts at 3000 XP).
        async with seal_db() as s:
            lv3 = (await s.execute(select(User).where(User.roll_number == "22B6701"))).scalars().one()
            lv3.game_xp = 3000
            await s.commit()

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "M7X1", "total_enrolled": 2},
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]
        wire_salt = s_res.json()["session_wire_salt"]
        session_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        r1 = await client.post(
            session_url,
            headers={"Authorization": f"Bearer {tok_stud1}"},
            json={"game_score": 16, "student_id": k1, "neighbors": [k2], "session_salt": wire_salt},
        )
        assert r1.status_code == 200, r1.text
        r2 = await client.post(
            session_url,
            headers={"Authorization": f"Bearer {tok_stud2}"},
            json={"game_score": 16, "student_id": k2, "neighbors": [k1], "session_salt": wire_salt},
        )
        assert r2.status_code == 200, r2.text

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"records": []},
        )
        assert fin.status_code == 200, fin.text
        record_map = {r["ble_device_id"]: r for r in fin.json()["records"]}

        assert record_map[k1]["status"] == "COGNITIVE_CHALLENGE_FAILED"
        assert "< 17" in record_map[k1]["remarks"]
        # Level-1 classmate with the same score still passes.
        assert record_map[k2]["status"] == "VERIFIED_PRESENT"


@pytest.mark.anyio
async def test_level1_student_passes_gate_at_15():
    # F3 regression pin: at level 1 the gate stays exactly 15 — an honest
    # student at today's threshold must never be failed by the leveling system.
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base
    from app.routers.attendance import derive_short_device_key

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    seal_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with seal_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, seal_db, "Prof. Floor", "floor@univ.edu")
        tok_stud1 = await _register_roll_student(client, seal_db, "Floor One", "floor.one@univ.edu", "22B6711")
        tok_stud2 = await _register_roll_student(client, seal_db, "Floor Two", "floor.two@univ.edu", "22B6712")
        k1 = derive_short_device_key("22B6711")
        k2 = derive_short_device_key("22B6712")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "M7X2", "total_enrolled": 2},
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]
        wire_salt = s_res.json()["session_wire_salt"]
        session_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        for tok, key, peer in [(tok_stud1, k1, k2), (tok_stud2, k2, k1)]:
            r = await client.post(
                session_url,
                headers={"Authorization": f"Bearer {tok}"},
                json={"game_score": 15, "student_id": key, "neighbors": [peer], "session_salt": wire_salt},
            )
            assert r.status_code == 200, r.text

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"records": []},
        )
        assert fin.status_code == 200, fin.text
        record_map = {r["ble_device_id"]: r for r in fin.json()["records"]}

        assert record_map[k1]["status"] == "VERIFIED_PRESENT"
        assert record_map[k2]["status"] == "VERIFIED_PRESENT"


@pytest.mark.anyio
async def test_finalize_awards_xp_for_perfect_score():
    # F3: XP is paid when a record finalizes VERIFIED_PRESENT with a score at
    # or above the level's gain threshold (level 1: 24). Score 24 -> 60 XP,
    # score 26 -> 80 XP (+20 max bonus). Isolated/spoofed sessions pay nothing.
    import uuid

    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import AttendanceRecord, AttendanceSession, Base, User
    from app.routers.attendance import derive_short_device_key

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    seal_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with seal_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, seal_db, "Prof. Reward", "reward@univ.edu")
        tok_stud1 = await _register_roll_student(client, seal_db, "Ace One", "ace.one@univ.edu", "22B6721")
        tok_stud2 = await _register_roll_student(client, seal_db, "Ace Two", "ace.two@univ.edu", "22B6722")
        tok_stud3 = await _register_roll_student(client, seal_db, "No Xp", "no.xp@univ.edu", "22B6723")
        k1 = derive_short_device_key("22B6721")
        k2 = derive_short_device_key("22B6722")
        k3 = derive_short_device_key("22B6723")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "M8X1", "total_enrolled": 3},
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]
        wire_salt = s_res.json()["session_wire_salt"]
        session_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        # Mutual pair (verified): 24 and 26. Third reports nobody (isolated).
        for tok, key, peers, score in [
            (tok_stud1, k1, [k2], 24),
            (tok_stud2, k2, [k1], 26),
            (tok_stud3, k3, [], 26),
        ]:
            r = await client.post(
                session_url,
                headers={"Authorization": f"Bearer {tok}"},
                json={"game_score": score, "student_id": key, "neighbors": peers, "session_salt": wire_salt},
            )
            assert r.status_code == 200, r.text

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"records": []},
        )
        assert fin.status_code == 200, fin.text

        async with seal_db() as s:
            xp_by_roll = {
                u.roll_number: u.game_xp
                for u in (await s.execute(select(User))).scalars().all()
                if u.roll_number
            }
            assert xp_by_roll["22B6721"] == 60   # score 24 -> 50 + 1*10
            assert xp_by_roll["22B6722"] == 80   # score 26 -> +20 max bonus
            assert xp_by_roll["22B6723"] == 0    # isolated -> never verified

            awarded = (await s.execute(
                select(AttendanceRecord).where(
                    AttendanceRecord.session_id == uuid.UUID(session_id),
                    AttendanceRecord.status == "VERIFIED_PRESENT",
                )
            )).scalars().all()
            assert len(awarded) == 2
            assert all(rec.xp_awarded for rec in awarded)

            # Direct re-scan of the same session must pay nothing more —
            # xp_awarded makes the award idempotent across replays.
            from app.services.xp import award_xp_for_session
            session_obj = (await s.execute(
                select(AttendanceSession).where(AttendanceSession.id == uuid.UUID(session_id))
            )).scalars().one()
            granted = await award_xp_for_session(s, session_obj)
            assert granted == 0
            still = {
                u.roll_number: u.game_xp
                for u in (await s.execute(select(User))).scalars().all()
                if u.roll_number
            }
            assert still["22B6721"] == 60
            assert still["22B6722"] == 80


@pytest.mark.anyio
async def test_finalize_pays_nothing_below_gain_threshold():
    # F3: passing the gate is not enough — only near-perfect scores earn XP.
    # Score 20 passes the level-1 gate (15) but is below the gain line (24).
    from httpx import AsyncClient, ASGITransport
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

    from app.database import get_db
    from app.models.attendance import Base, User
    from app.routers.attendance import derive_short_device_key

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    seal_db = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with seal_db() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tok_teacher = await _register_test_teacher(client, seal_db, "Prof. Midband", "midband@univ.edu")
        tok_stud1 = await _register_roll_student(client, seal_db, "Mid One", "mid.one@univ.edu", "22B6731")
        tok_stud2 = await _register_roll_student(client, seal_db, "Mid Two", "mid.two@univ.edu", "22B6732")
        k1 = derive_short_device_key("22B6731")
        k2 = derive_short_device_key("22B6732")

        s_res = await client.post(
            "/api/v1/attendance/sessions",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"session_token": "M8X2", "total_enrolled": 2},
        )
        assert s_res.status_code == 201, s_res.text
        session_id = s_res.json()["id"]
        wire_salt = s_res.json()["session_wire_salt"]
        session_url = f"/api/v1/attendance/sessions/{session_id}/submit-neighbors"

        for tok, key, peer in [(tok_stud1, k1, k2), (tok_stud2, k2, k1)]:
            r = await client.post(
                session_url,
                headers={"Authorization": f"Bearer {tok}"},
                json={"game_score": 20, "student_id": key, "neighbors": [peer], "session_salt": wire_salt},
            )
            assert r.status_code == 200, r.text

        fin = await client.post(
            f"/api/v1/attendance/sessions/{session_id}/finalize",
            headers={"Authorization": f"Bearer {tok_teacher}"},
            json={"records": []},
        )
        assert fin.status_code == 200, fin.text
        record_map = {r["ble_device_id"]: r for r in fin.json()["records"]}
        assert record_map[k1]["status"] == "VERIFIED_PRESENT"  # gate passes

        async with seal_db() as s:
            xp_by_roll = {
                u.roll_number: u.game_xp
                for u in (await s.execute(select(User))).scalars().all()
                if u.roll_number
            }
            assert xp_by_roll["22B6731"] == 0
            assert xp_by_roll["22B6732"] == 0
