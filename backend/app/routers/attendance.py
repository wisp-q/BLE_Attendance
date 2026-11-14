from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, Dict, List, Optional, Union

logger = logging.getLogger("uvicorn.error")

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy import delete, func, and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload


# R2 (review §3.1): request-scoped finalize gate. FastAPI acquires it BEFORE
# the route body starts and releases it in the dependency's finally, even on
# exceptions — so no early 4xx, audit crash, or crash-aborted commit can ever
# leave a submission stranded between drain and commit.
async def _session_gate_dependency(session_id: str) -> AsyncGenerator[None, None]:
    async with submission_buffer.session_gate(session_id):
        yield


def _is_session_stale(started_at: Optional[datetime], minutes: int) -> bool:
    if not started_at:
        return False
    now = datetime.now(timezone.utc)
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    return (now - started_at) > timedelta(minutes=minutes)

from app.core.security import (
    get_current_user,
    get_optional_user,
    is_test_environment,
    limiter_ip,
    require_teacher,
)
from app.database import get_db
from app.services.rate_limiter import submit_rate_limiter
from app.models.attendance import (
    AttendanceRecord,
    AttendanceSession,
    Course,
    CourseUnit,
    LeaveApplication,
    SessionSubmission,
    UnitTopic,
    User,
)
from app.schemas.attendance import (
    AttendanceRecordResponse,
    AttendanceSessionResponse,
    CourseCreateRequest,
    CourseResponse,
    CourseUnitCreate,
    CourseUnitResponse,
    MeshAuditRunRequest,
    RecordOverrideRequest,
    SessionCreateRequest,
    SessionFinalizeRequest,
    SubmitNeighborsRequest,
    UnitTopicCreate,
    UnitTopicResponse,
    FaceLabCheckRequest,
    FaceLabCheckResponse,
    FaceLabCompareRequest,
    FaceLabCompareResponse,
)
from app.services.face_engine import face_registry
from app.services.graph_engine import audit_classroom_mesh
from app.services.rate_limiter import face_lab_limiter
from app.services.submission_buffer import submission_buffer
from app.services.xp import award_xp_for_session, level_for_xp, pass_threshold

# --- H5: server-issued session salt helpers ---
# Canonical salt = high-entropy secret stored server-side (never on BLE wire).
# Wire salt = fixed 4-char token derived for the BLE beacon; deterministic so
# teacher (who receives canonical salt at create) and server compute the same
# value. Static per session today; epoch parameter reserved for rotation.
WIRE_SALT_EPOCH_SECONDS = 0  # 0 => static wire salt for session lifetime


def derive_wire_salt(canonical_salt: str, session_token: str, epoch: int = 0) -> str:
    if not canonical_salt:
        return ""
    msg = f"{session_token}:{epoch}".encode()
    return hmac.new(canonical_salt.encode(), msg, hashlib.sha256).hexdigest()[:4].upper()


# M4: collision-resistant 6-char BLE/device key derived from canonical identity.
# Must match Android (full roll preferred, else full user UUID string).
# 6 hex chars = 16.7M space: birthday collision odds drop from ~3.7% per
# 70-student class (4 chars = 65,536) to ~0.015% — two honest students can no
# longer share one attendance row. Key travels in JSON/neighbors only, never
# in the beacon payload, so the widened format costs no wire budget.
def derive_short_device_key(canonical: str) -> str:
    src = (canonical or "").strip().upper()
    if not src:
        return "000000"
    return hashlib.sha256(src.encode("utf-8")).hexdigest()[:6].upper()


def user_device_key(user: User) -> str:
    canonical = user.roll_number if getattr(user, "roll_number", None) else str(user.id)
    return derive_short_device_key(canonical)


def current_wire_epoch() -> int:
    # Rotation hook: when WIRE_SALT_EPOCH_SECONDS > 0, derive per epoch and
    # accept current + previous in valid_wire_salts during the grace window.
    return 0


def session_wire_salt(session_obj) -> str:
    token = getattr(session_obj, "session_token", "") or ""
    canonical = getattr(session_obj, "session_salt", "") or ""
    return derive_wire_salt(canonical, token, current_wire_epoch())


def valid_wire_salts(session_obj) -> list[str]:
    token = getattr(session_obj, "session_token", "") or ""
    canonical = getattr(session_obj, "session_salt", "") or ""
    if not canonical:
        return []
    epoch = current_wire_epoch()
    salts = [derive_wire_salt(canonical, token, epoch)]
    # Grace window: accept previous epoch during rotation handoff.
    if WIRE_SALT_EPOCH_SECONDS > 0 and epoch > 0:
        salts.append(derive_wire_salt(canonical, token, epoch - 1))
    # Test-only debug sessions: legacy fixed salt accepted for deterministic tests.
    if is_test_environment() and token.upper() in ("AUTO-101", "DEMO", "DEBUG-1"):
        salts.append("DEMO1")
    return salts


def _attach_wire_salt(session_obj):
    # Expose derived wire salt on the ORM object so SessionResponse
    # (from_attributes) can serialize it alongside the canonical salt.
    try:
        session_obj.session_wire_salt = session_wire_salt(session_obj)
    except Exception:
        session_obj.session_wire_salt = None
    return session_obj


router = APIRouter(prefix="/attendance", tags=["Attendance"])


# Resolve an AttendanceSession by UUID or session token
# Canonicalizes program strings so "B.Tech", "B-Tech" and "B Tech" compare equal
def _program_key(value: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


# Returns None when `user` may submit to `session_obj`, else the human-readable
# rejection reason. Pure in-memory comparison on objects both callers already
# hold — the gate costs no extra queries at check-in time. Non-student roles
# (TEACHER/STAFF/DEVELOPER) bypass class binding by design.
def student_eligibility_detail(session_obj: AttendanceSession, user: User) -> Optional[str]:
    if (user.role or "").upper() != "STUDENT":
        return None
    if user.semester is None or not (user.program or "").strip():
        return "Attendance profile incomplete — update your program and semester before checking in"
    if session_obj.eligibility_semester is None or not (session_obj.eligibility_program or "").strip():
        return None  # unknown class identity (legacy rows) — nothing to bind to
    semester_ok = user.semester == session_obj.eligibility_semester
    program_ok = _program_key(user.program) == _program_key(session_obj.eligibility_program)
    if semester_ok and program_ok:
        return None
    return (
        f"This session is for {session_obj.eligibility_program} Semester {session_obj.eligibility_semester}"
        f" — your profile says Semester {user.semester}"
    )


async def _resolve_session(session_id: str, db: AsyncSession) -> Optional[AttendanceSession]:
    load_opts = selectinload(AttendanceSession.records)

    # Allow debug sessions only during test execution
    if is_test_environment() and session_id.upper() in ("AUTO-101", "DEMO", "DEBUG-1"):
        debug_token = session_id.upper()
        debug_res = await db.execute(
            select(AttendanceSession).options(load_opts).where(AttendanceSession.session_token == debug_token)
        )
        debug_sess = debug_res.scalars().first()
        if not debug_sess:
            teacher, course = await _get_or_create_mock_context(db)
            debug_sess = AttendanceSession(
                id=uuid.uuid4(),
                course_id=course.id,
                teacher_id=teacher.id,
                session_token=debug_token,
                session_salt="DEMO1",
                status="ACTIVE",
                started_at=datetime.now(timezone.utc),
            )
            db.add(debug_sess)
            await db.commit()
            await db.refresh(debug_sess)
        else:
            debug_sess.status = "ACTIVE"
            debug_sess.session_salt = "DEMO1"
            debug_sess.started_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(debug_sess)
        return debug_sess

    # Query session by UUID or session token, preferring newest
    target_uuid = None
    try:
        target_uuid = uuid.UUID(session_id)
    except ValueError:
        pass

    if target_uuid:
        query = (
            select(AttendanceSession)
            .options(load_opts)
            .where(or_(AttendanceSession.id == target_uuid, AttendanceSession.session_token == session_id))
            .order_by(AttendanceSession.started_at.desc())
        )
    else:
        query = (
            select(AttendanceSession)
            .options(load_opts)
            .where(AttendanceSession.session_token == session_id)
            .order_by(AttendanceSession.started_at.desc())
        )
    result = await db.execute(query)
    return result.scalars().first()


# R4 (review §3.1): concurrent session creation pointing at the same course
# code raced the unique `courses.course_code` constraint and 500'd the
# legitimate second creator. Extracted as a helper so the adopt-the-winner
# race behavior is also unit-testable.
async def _resolve_or_create_course(
    db: AsyncSession,
    code_to_check: str,
    course_name: str,
    teacher_id: Optional[uuid.UUID],
    new_course_id: Optional[uuid.UUID] = None,
) -> Course:
    c_res = await db.execute(select(Course).where(func.upper(Course.course_code) == code_to_check))
    existing_c = c_res.scalars().first()
    if existing_c:
        return existing_c
    new_c = Course(
        id=new_course_id or uuid.uuid4(),
        course_code=code_to_check,
        course_name=course_name,
        teacher_id=teacher_id,
    )
    db.add(new_c)
    try:
        await db.commit()
    except IntegrityError:
        # The losing creator: someone committed the same code between our
        # SELECT and COMMIT. Adopt their row instead of failing.
        await db.rollback()
        re_res = await db.execute(select(Course).where(func.upper(Course.course_code) == code_to_check))
        winner = re_res.scalars().first()
        if winner is None:
            raise
        return winner
    await db.refresh(new_c)
    return new_c


# Ensure default teacher and course exist for development testing
async def _get_or_create_mock_context(db: AsyncSession):
    # R3 (review §3.1): this fabrication (a teacher with an unhashable stub
    # password plus a demo course) must never enter a real deployment DB —
    # production logins via that account 500 on `Invalid salt`. Unconditionally
    # gated on the test environment so every caller is safe.
    if not is_test_environment():
        return None, None
    result = await db.execute(select(User).limit(1))
    teacher = result.scalars().first()
    if not teacher:
        teacher = User(
            id=uuid.uuid4(),
            email="teacher@university.edu",
            hashed_password="mock_hashed_pw",
            full_name="Prof. Alan Turing",
            role="TEACHER",
        )
        db.add(teacher)
        await db.commit()
        await db.refresh(teacher)

    c_result = await db.execute(select(Course).order_by(Course.course_code.asc()).limit(1))
    course = c_result.scalars().first()
    if not course:
        course = Course(
            id=uuid.uuid4(),
            course_code="CST-003",
            course_name="Data Structures and Algorithms",
            teacher_id=teacher.id,
        )
        db.add(course)
        await db.commit()
        await db.refresh(course)

    return teacher, course


# Populate course code and name onto an attendance session
async def _populate_course_metadata(session_obj: AttendanceSession, db: AsyncSession) -> None:
    if not session_obj.course_id:
        return
    c_res = await db.execute(select(Course).where(Course.id == session_obj.course_id))
    course = c_res.scalars().first()
    if course:
        session_obj.course_code = course.course_code
        session_obj.course_name = course.course_name


# R5-consistent counter recompute, shared by both finalize paths and the
# manual override route: counters must reflect committed DB rows, not
# payload-computed tallies — prior VERIFIED rows absent from the current
# request (grace-path additions, out-of-band verdicts, later overrides) would
# otherwise be dropped from the visible counts. LEAVE rows count as neither
# verified nor unverified (approved-leave overlay output).
async def _recompute_session_counters(session_obj: AttendanceSession, db: AsyncSession) -> None:
    await db.flush()
    verified_res = await db.execute(
        select(func.count()).select_from(AttendanceRecord).where(
            AttendanceRecord.session_id == session_obj.id,
            AttendanceRecord.status == "VERIFIED_PRESENT",
        )
    )
    session_obj.total_verified = verified_res.scalar() or 0
    # Count every record that did not end VERIFIED — witnessed offline
    # students, isolated seats, spoofers, proxy flags, challenge failures.
    unverified_res = await db.execute(
        select(func.count()).select_from(AttendanceRecord).where(
            AttendanceRecord.session_id == session_obj.id,
            AttendanceRecord.status.not_in(["VERIFIED_PRESENT", "LEAVE"]),
        )
    )
    session_obj.total_unverified = unverified_res.scalar() or 0


# R11-B fix: the audit-and-finalize response is the teacher's LIVE post-class
# list (the app maps body.records straight onto finalizedRecords), but unlike
# the history/detail routes it returned raw AttendanceRecord rows — with no
# users join, so student_name/roll_number stayed NULL and the teacher screen
# degraded to "Student 20" fallback names. Same enrichment the other two read
# routes perform; records carry no persistent name column (name is never
# stored, always joined from users).
async def _populate_record_student_details(
    session_obj: AttendanceSession, db: AsyncSession
) -> None:
    if not session_obj.records:
        return
    student_ids = [r.student_id for r in session_obj.records if r.student_id]
    if not student_ids:
        return
    u_res = await db.execute(select(User).where(User.id.in_(student_ids)))
    user_map = {u.id: u for u in u_res.scalars().all()}
    for r in session_obj.records:
        u = user_map.get(r.student_id) if r.student_id else None
        if u is not None:
            r.roll_number = u.roll_number
            r.student_name = u.full_name


# Approved-leave overlay (leave feature): after finalize verdicts exist but
# BEFORE the finalize commit, enrolled students whose APPROVED leave covers
# the session date are marked "LEAVE" instead of "ABSENT" (or given a LEAVE
# row outright — both finalize paths only create records for students who
# participated). Presence beats leave: VERIFIED_PRESENT, challenge failures,
# and proxy verdicts are never overwritten — approved leave explains absence,
# not a student who showed up and failed the check. Roster is derived from
# the same eligibility snapshot the check-in gate uses (semester + program
# over active STUDENT accounts); legacy sessions without a snapshot have no
# derivable roster and are skipped.
async def _apply_approved_leave_overlay(
    session_obj: AttendanceSession, db: AsyncSession
) -> int:
    semester = session_obj.eligibility_semester
    program = (session_obj.eligibility_program or "").strip()
    started = session_obj.started_at
    session_date = started.date() if started else None
    if semester is None or not program or session_date is None:
        return 0
    # IST calendar day: started_at is stored in UTC, so a session beginning
    # 00:00–05:30 IST lands on the PREVIOUS UTC calendar day and slicing
    # .date() alone never matches a leave approved for the student's local
    # date. A leave covering EITHER calendar day now matches.
    session_date_ist = (started + timedelta(hours=5, minutes=30)).date()

    candidates = await db.execute(
        select(User).where(
            User.semester == semester,
            User.is_active.is_(True),
            User.role == "STUDENT",
        )
    )
    roster = [
        u for u in candidates.scalars().all()
        if u.roll_number and _program_key(u.program) == _program_key(program)
    ]
    if not roster:
        return 0

    roster_ids = [u.id for u in roster]
    coverage = [
        and_(
            LeaveApplication.from_date <= session_date,
            LeaveApplication.to_date >= session_date,
        )
    ]
    if session_date_ist != session_date:
        coverage.append(
            and_(
                LeaveApplication.from_date <= session_date_ist,
                LeaveApplication.to_date >= session_date_ist,
            )
        )
    leave_res = await db.execute(
        select(LeaveApplication)
        .where(
            LeaveApplication.student_id.in_(roster_ids),
            LeaveApplication.status == "APPROVED",
            or_(*coverage),
        )
        .order_by(LeaveApplication.created_at)
    )
    # Latest covering application wins if a student has several for this date
    leave_by_student: dict[uuid.UUID, LeaveApplication] = {}
    for leave_row in leave_res.scalars().all():
        leave_by_student[leave_row.student_id] = leave_row
    if not leave_by_student:
        return 0

    rec_res = await db.execute(
        select(AttendanceRecord).where(AttendanceRecord.session_id == session_obj.id)
    )
    existing_recs = rec_res.scalars().all()
    by_student = {r.student_id: r for r in existing_recs if r.student_id}
    by_device = {r.ble_device_id.upper(): r for r in existing_recs}

    created = 0
    for student in roster:
        leave_row = leave_by_student.get(student.id)
        if not leave_row:
            continue
        range_text = f"{leave_row.from_date.isoformat()}..{leave_row.to_date.isoformat()}"
        rec = by_student.get(student.id)
        if rec is None:
            # Unbound-but-keyed row (submitted without a resolvable account):
            # matching by the derived device key keeps one row per student.
            rec = by_device.get(derive_short_device_key(student.roll_number))
        if rec is None:
            db.add(
                AttendanceRecord(
                    id=uuid.uuid4(),
                    session_id=session_obj.id,
                    student_id=student.id,
                    ble_device_id=derive_short_device_key(student.roll_number),
                    status="LEAVE",
                    verification_method="LEAVE_APPROVAL",
                    affinity_score=0.00,
                    reported_neighbors=[],
                    remarks=f"Approved leave {range_text}",
                    recorded_at=datetime.now(timezone.utc),
                )
            )
            created += 1
        elif rec.status == "ABSENT":
            rec.status = "LEAVE"
            rec.verification_method = "LEAVE_APPROVAL"
            rec.remarks = f"Approved leave {range_text}"
    return created


# Binds unbound attendance records (student_id NULL) to roster accounts.
# Witness/offline rows (e.g. FLAGGED_WITNESSED) and legacy payload rows carry
# only the BLE device key — that device never authenticated, so no account
# was bound at check-in. Device keys are the DETERMINISTIC derivation
# derive_short_device_key(roll), so the server can reverse-map them against
# the session's eligibility roster (same snapshot the check-in gate uses).
# Without this the teacher dashboard shows "Student <key-suffix>" instead of
# the student's real name and roll number. 6-hex key collisions across a
# roster resolve last-wins (same policy as the leave overlay).
async def _bind_unbound_records_to_roster(
    session_obj: AttendanceSession, db: AsyncSession
) -> int:
    semester = session_obj.eligibility_semester
    program = (session_obj.eligibility_program or "").strip()
    if semester is None or not program:
        return 0

    candidates = await db.execute(
        select(User).where(
            User.semester == semester,
            User.is_active.is_(True),
            User.role == "STUDENT",
        )
    )
    key_to_student: dict[str, uuid.UUID] = {}
    for u in candidates.scalars().all():
        if u.roll_number:
            key_to_student[derive_short_device_key(u.roll_number)] = u.id
    if not key_to_student:
        return 0

    rec_res = await db.execute(
        select(AttendanceRecord).where(
            AttendanceRecord.session_id == session_obj.id,
            AttendanceRecord.student_id.is_(None),
        )
    )
    bound = 0
    for rec in rec_res.scalars().all():
        uid = key_to_student.get(rec.ble_device_id.upper())
        if uid:
            rec.student_id = uid
            bound += 1
            logger.info(
                f"[Roster Bind] Session {session_obj.id}: unbound record {rec.ble_device_id} -> student {uid}"
            )
    return bound


# Record or update a proxy violation record for a device
# Record proxy violation handling concurrent write races
async def _record_proxy_violation(
    db: AsyncSession,
    session_id: uuid.UUID,
    device_id: str,
    status: str,
    verification_method: str,
    remarks: str,
    student_id: Optional[uuid.UUID] = None,
    reported_neighbors: Optional[List[str]] = None,
    game_score: Optional[int] = None,
) -> Optional[AttendanceRecord]:
    stmt = select(AttendanceRecord).where(
        AttendanceRecord.session_id == session_id,
        AttendanceRecord.ble_device_id == device_id,
    )
    res = await db.execute(stmt)
    rec = res.scalars().first()
    if rec:
        rec.status = status
        rec.verification_method = verification_method
        rec.remarks = remarks
        if game_score is not None:
            rec.game_score = game_score if rec.game_score is None else max(rec.game_score, game_score)
        if student_id and not rec.student_id:
            rec.student_id = student_id
        if reported_neighbors is not None:
            rec.reported_neighbors = reported_neighbors
        return rec

    rec = AttendanceRecord(
        id=uuid.uuid4(),
        session_id=session_id,
        student_id=student_id,
        ble_device_id=device_id,
        status=status,
        verification_method=verification_method,
        affinity_score=0.00,
        reported_neighbors=reported_neighbors or [],
        remarks=remarks,
        game_score=game_score,
        recorded_at=datetime.now(timezone.utc),
    )
    try:
        async with db.begin_nested():
            db.add(rec)
            await db.flush()
    except IntegrityError as exc:
        logger.warning(f"Concurrent proxy insert collision for {device_id}: {exc}")
        res = await db.execute(stmt)
        rec = res.scalars().first()
        if rec:
            rec.status = status
            rec.verification_method = verification_method
            rec.remarks = remarks
            if game_score is not None:
                rec.game_score = game_score if rec.game_score is None else max(rec.game_score, game_score)
    return rec


# Commit proxy violations safely with error logging
async def _commit_proxy_violation(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        logger.warning(f"Concurrent proxy violation commit collision: {exc}")


# Serializes concurrent finalize calls (a teacher tap racing the auto-finalize timer):
# the second caller blocks on the session row until the first commits, then re-reads the
# committed status so a duplicate finalize exits idempotently instead of double-inserting.
# SQLite (test environment) ignores FOR UPDATE; PostgreSQL enforces it.
async def _lock_session_for_finalize(db: AsyncSession, session_obj: AttendanceSession) -> AttendanceSession:
    lock_res = await db.execute(
        select(AttendanceSession.id).where(AttendanceSession.id == session_obj.id).with_for_update()
    )
    lock_res.scalars().first()
    fresh_status = (
        await db.execute(select(AttendanceSession.status).where(AttendanceSession.id == session_obj.id))
    ).scalar_one()
    session_obj.status = fresh_status
    return _attach_wire_salt(session_obj)


# Course Endpoints
# List available courses
@router.get("/courses", response_model=List[CourseResponse])
async def list_courses(
    semester: Optional[int] = None,
    department: Optional[str] = None,
    program: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    await _get_or_create_mock_context(db)

    query = select(Course).options(
        selectinload(Course.units).selectinload(CourseUnit.topics)
    )
    if semester is not None:
        query = query.where(Course.semester == semester)
    if department is not None:
        query = query.where(Course.department.ilike(f"%{department.strip()}%"))
    if program is not None:
        query = query.where(Course.program.ilike(f"%{program.strip()}%"))
    result = await db.execute(query.order_by(Course.semester.asc(), Course.course_code.asc()))
    return list(result.scalars().all())


# Register a new course
@router.post("/courses", response_model=CourseResponse, status_code=status.HTTP_201_CREATED)
async def create_course(
    payload: CourseCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
):
    course = Course(
        id=uuid.uuid4(),
        course_code=payload.course_code.strip().upper(),
        course_name=payload.course_name.strip(),
        teacher_id=current_user.id,
        program=payload.program,
        department=payload.department,
        semester=payload.semester,
        category=payload.category,
        course_type=payload.course_type,
        credits=payload.credits,
        periods_l=payload.periods_l,
        periods_t=payload.periods_t,
        periods_p=payload.periods_p,
    )
    db.add(course)
    await db.commit()
    await db.refresh(course)
    return course


# Get full syllabus for a specific course
@router.get("/courses/{course_id}/syllabus", response_model=List[CourseUnitResponse])
async def get_course_syllabus(
    course_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    course_res = await db.execute(select(Course).where(Course.id == course_id))
    course = course_res.scalars().first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    res = await db.execute(
        select(CourseUnit)
        .where(CourseUnit.course_id == course_id)
        .order_by(CourseUnit.unit_number.asc())
    )
    return res.scalars().all()


# Add a syllabus unit to a course
@router.post(
    "/courses/{course_id}/units",
    response_model=CourseUnitResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_course_unit(
    course_id: uuid.UUID,
    payload: CourseUnitCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
):
    course_res = await db.execute(select(Course).where(Course.id == course_id))
    course = course_res.scalars().first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    if course.teacher_id != current_user.id and current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to modify this course syllabus",
        )

    existing = await db.execute(
        select(CourseUnit).where(
            CourseUnit.course_id == course_id,
            CourseUnit.unit_number == payload.unit_number,
        )
    )
    if existing.scalars().first():
        raise HTTPException(
            status_code=400,
            detail=f"Unit {payload.unit_number} already exists for this course",
        )

    unit = CourseUnit(
        id=uuid.uuid4(),
        course_id=course_id,
        unit_number=payload.unit_number,
        unit_title=payload.unit_title.strip(),
        teaching_hours=payload.teaching_hours,
    )
    db.add(unit)
    await db.flush()

    if payload.topics:
        for t in payload.topics:
            topic = UnitTopic(
                id=uuid.uuid4(),
                unit_id=unit.id,
                topic_order=t.topic_order,
                topic_name=t.topic_name.strip(),
            )
            db.add(topic)

    await db.commit()
    await db.refresh(unit)
    return unit


# Add a topic to an existing syllabus unit
@router.post(
    "/courses/{course_id}/units/{unit_id}/topics",
    response_model=UnitTopicResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_unit_topic(
    course_id: uuid.UUID,
    unit_id: uuid.UUID,
    payload: UnitTopicCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
):
    unit_res = await db.execute(
        select(CourseUnit).where(CourseUnit.id == unit_id, CourseUnit.course_id == course_id)
    )
    unit = unit_res.scalars().first()
    if not unit:
        raise HTTPException(status_code=404, detail="Unit not found for this course")

    course_res = await db.execute(select(Course).where(Course.id == course_id))
    course = course_res.scalars().first()
    if course.teacher_id != current_user.id and current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to modify this course syllabus",
        )

    topic = UnitTopic(
        id=uuid.uuid4(),
        unit_id=unit_id,
        topic_order=payload.topic_order,
        topic_name=payload.topic_name.strip(),
    )
    db.add(topic)
    try:
        await db.commit()
        await db.refresh(topic)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=400,
            detail=f"Topic with order {payload.topic_order} already exists in this unit",
        )
    return topic


# List all past attendance sessions for a specific course
@router.get("/courses/{course_id}/sessions", response_model=List[AttendanceSessionResponse])
async def list_course_sessions(
    course_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
):
    course_res = await db.execute(select(Course).where(Course.id == course_id))
    course = course_res.scalars().first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    if course.teacher_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view sessions for this course",
        )

    result = await db.execute(
        select(AttendanceSession)
        .where(AttendanceSession.course_id == course_id)
        .order_by(AttendanceSession.started_at.desc())
    )
    return result.scalars().all()


# List past attendance sessions for authenticated instructor
@router.get("/sessions/history", response_model=List[AttendanceSessionResponse])
async def list_teacher_sessions_history(
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    user_role = (current_user.role or "").upper()
    if user_role not in ("TEACHER", "HOD", "DEVELOPER", "STAFF", "FACULTY", "ADMIN"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only instructors can view session history")

    query = (
        select(AttendanceSession)
        .options(selectinload(AttendanceSession.records))
        .where(AttendanceSession.teacher_id == current_user.id)
        .order_by(AttendanceSession.started_at.desc())
    )

    result = await db.execute(query)
    sessions = list(result.scalars().all())

    # Populate course details on each session
    course_ids = [s.course_id for s in sessions if s.course_id]
    if course_ids:
        c_res = await db.execute(select(Course).where(Course.id.in_(course_ids)))
        course_map = {c.id: c for c in c_res.scalars().all()}
        for s in sessions:
            c = course_map.get(s.course_id)
            if c:
                s.course_code = c.course_code
                s.course_name = c.course_name

    # Populate student details on records
    student_ids = [r.student_id for s in sessions if s.records for r in s.records if r.student_id]
    if student_ids:
        u_res = await db.execute(select(User).where(User.id.in_(student_ids)))
        user_map = {u.id: u for u in u_res.scalars().all()}
        for s in sessions:
            if s.records:
                for r in s.records:
                    if r.student_id in user_map:
                        u = user_map[r.student_id]
                        r.roll_number = u.roll_number
                        r.student_name = u.full_name

    for s in sessions:
        _attach_wire_salt(s)
    return sessions


# Create an attendance session
@router.post(
    "/sessions",
    response_model=AttendanceSessionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_attendance_session(
    payload: SessionCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
):
    target_course_id = None
    target_uuid = None
    course_obj: Optional[Course] = None

    if payload.course_id:
        try:
            target_uuid = uuid.UUID(payload.course_id)
        except (ValueError, AttributeError):
            target_uuid = None

    if target_uuid:
        course_res = await db.execute(select(Course).where(Course.id == target_uuid))
        course = course_res.scalars().first()
        if course:
            course_obj = course
            target_course_id = course.id

    if not target_course_id:
        # Resolve or auto-create course
        raw_code = payload.course_code or (payload.course_id if not target_uuid else None) or "CS101"
        code_to_check = raw_code.strip()[:30].upper()
        course_obj = await _resolve_or_create_course(
            db,
            code_to_check,
            course_name=(payload.course_name or "General Lecture & Attendance")[:200],
            teacher_id=current_user.id,
            new_course_id=target_uuid,
        )
        target_course_id = course_obj.id

    # Eligibility snapshot: the teacher's declared class wins (their UI selection
    # is the class actually being taught), the course row is the fallback.
    eligibility_program = (payload.course_program or (course_obj.program if course_obj else None) or "").strip() or None
    eligibility_semester = payload.course_semester if payload.course_semester is not None else (course_obj.semester if course_obj else None)
    eligibility_department = course_obj.department if course_obj else None

    # Roster anchor: the audit engine weights collusion clusters against the
    # enrolled class size (graph_engine only anchors when total_enrolled > 0).
    # The teacher app sends no roster count, so derive it from the same
    # eligibility snapshot the student check-in gate uses (semester + program).
    roster_enrolled = payload.total_enrolled
    roster_roll_numbers: list[str] = []
    if (not roster_enrolled) and eligibility_semester is not None and (eligibility_program or "").strip():
        candidates = await db.execute(
            select(User).where(
                User.semester == eligibility_semester,
                User.is_active.is_(True),
                User.role == "STUDENT",
            )
        )
        matched_students = [
            u for u in candidates.scalars().all()
            if _program_key(u.program) == _program_key(eligibility_program)
        ]
        roster_enrolled = len(matched_students)
        roster_roll_numbers = [u.roll_number for u in matched_students if u.roll_number]

    # Expire previous active sessions for this course created by current teacher
    active_check = await db.execute(
        select(AttendanceSession).where(
            AttendanceSession.course_id == target_course_id,
            AttendanceSession.teacher_id == current_user.id,
            AttendanceSession.status == "ACTIVE",
        )
    )
    existing_active = active_check.scalars().all()
    now_utc = datetime.now(timezone.utc)
    for stale in existing_active:
        is_stale = _is_session_stale(stale.started_at, minutes=2)
        stale.status = "EXPIRED" if is_stale else "CANCELLED"
        stale.ended_at = now_utc
    if existing_active:
        await db.commit()

    # M2: after retiring this teacher's own prior ACTIVE sessions, any remaining
    # session using the same token belongs to ANOTHER teacher/class. Rejecting
    # here prevents asymmetric keys from cross-routing student submissions
    # (resolutions are newest-wins, so a colliding broadcast is harmful).
    token_conflict_res = await db.execute(
        select(AttendanceSession).where(
            AttendanceSession.session_token == payload.session_token,
            AttendanceSession.status == "ACTIVE",
        )
    )
    if token_conflict_res.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Session ID '{payload.session_token}' is already in use by an active session — pick a new session ID",
        )

    # Save new active attendance session (with eligibility snapshot for the
    # student class-binding gate). H5: server generates canonical salt;
    # client-supplied value is ignored. Wire salt is derived for the beacon.
    canonical_salt = secrets.token_hex(16)
    session = AttendanceSession(
        id=uuid.uuid4(),
        course_id=target_course_id,
        teacher_id=current_user.id,
        session_token=payload.session_token,
        session_salt=canonical_salt,
        eligibility_program=eligibility_program,
        eligibility_department=eligibility_department,
        eligibility_semester=eligibility_semester,
        status="ACTIVE",
        total_enrolled=roster_enrolled,
        started_at=datetime.now(timezone.utc),
    )
    db.add(session)
    try:
        await db.commit()
    except IntegrityError:
        # R-concurrency: a concurrent create committed the same ACTIVE token
        # between our pre-insert SELECT and this commit — the partial unique
        # index rejected us. Re-check to confirm the collision (any other
        # IntegrityError re-raises): same 409 the pre-insert check produces.
        await db.rollback()
        conflict_res = await db.execute(
            select(AttendanceSession).where(
                AttendanceSession.session_token == payload.session_token,
                AttendanceSession.status == "ACTIVE",
            )
        )
        if conflict_res.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Session ID '{payload.session_token}' is already in use by an active session — pick a new session ID",
            )
        raise
    await db.refresh(session)
    session.records = []

    await _populate_course_metadata(session, db)

    # M9 (audit): never log gate material — token/salt in container logs
    # defeats the BLE-range assumption (anyone with log access gets the gate).
    logger.info(f"[Session Created] ID: {session.id}, Course: {session.course_code}")
    # Roster diagnostic: the enrolled count is DERIVED from the eligibility
    # snapshot (semester + program) over active STUDENT accounts — the teacher
    # app sends no roster. Only the COUNT is logged: individual roll numbers
    # are PII and were sitting in Render's retained logs for no runtime
    # benefit. Surprising counts are debugged via enrolled_roll_numbers in the
    # session-create response (owner-visible), not via log dumps.
    if roster_roll_numbers:
        logger.info(
            "[Roster] Derived total_enrolled=%d for program=%r semester=%r (%d matched active STUDENT accounts)",
            roster_enrolled, eligibility_program, eligibility_semester,
            len(roster_roll_numbers),
        )
    session.enrolled_roll_numbers = roster_roll_numbers or None
    _attach_wire_salt(session)
    return session


# Cancel an attendance session
@router.post("/sessions/{session_id}/cancel", response_model=AttendanceSessionResponse)
async def cancel_attendance_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
):
    result = await db.execute(
        select(AttendanceSession).where(AttendanceSession.id == session_id)
    )
    session_obj = result.scalars().first()
    if not session_obj:
        raise HTTPException(status_code=404, detail="Attendance session not found")
    if session_obj.teacher_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only cancel your own attendance sessions",
        )

    # Serialize against concurrent finalize calls: a cancel racing an in-flight finalize must
    # observe the committed result instead of flipping a just-finalized session to CANCELLED
    session_obj = await _lock_session_for_finalize(db, session_obj)
    if session_obj.status == "COMPLETED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot cancel an attendance session that has already been finalized/completed",
        )
    if session_obj.status == "CANCELLED":
        # Idempotent: re-cancel of an already-cancelled session is a no-op success
        await db.refresh(session_obj)
        return _attach_wire_salt(session_obj)

    # Cancel session and remove ephemeral submissions
    session_obj.status = "CANCELLED"
    session_obj.ended_at = datetime.now(timezone.utc)
    await db.execute(
        delete(SessionSubmission).where(SessionSubmission.session_id == session_obj.id)
    )
    await db.commit()
    await db.refresh(session_obj)

    # Discard volatile in-RAM state so a cancelled session leaves nothing behind
    await submission_buffer.clear_session(str(session_obj.id))
    face_registry.clear_session(str(session_obj.id))

    await _populate_course_metadata(session_obj, db)
    logger.info(f"[Session Cancelled] Session: {session_obj.id}")
    return _attach_wire_salt(session_obj)


# Finalize attendance session with client-provided records
@router.post(
    "/sessions/{session_id}/finalize",
    response_model=AttendanceSessionResponse,
)
async def finalize_attendance_session(
    session_id: str,
    payload: SessionFinalizeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
    _finalize_gate: None = Depends(_session_gate_dependency),
):
    session_obj = await _resolve_session(session_id, db)

    if not session_obj:
        raise HTTPException(status_code=404, detail="Attendance session not found")
    user_role = (current_user.role or "").upper()
    if session_obj.teacher_id != current_user.id and user_role not in ("DEVELOPER", "ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only finalize your own attendance sessions",
        )
    if session_obj.status == "CANCELLED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot finalize a cancelled session",
        )
    # Serialize overlapping finalizes: block on the session row, then re-read committed status
    session_obj = await _lock_session_for_finalize(db, session_obj)

    if session_obj.status == "COMPLETED":
        # Idempotent exit: attach the finalized counters and records so the caller gets the
        # completed session rather than the stale pre-lock snapshot
        await db.refresh(session_obj)
        final_recs = await db.execute(
            select(AttendanceRecord).where(AttendanceRecord.session_id == session_obj.id)
        )
        session_obj.records = list(final_recs.scalars().all())
        await _populate_course_metadata(session_obj, db)
        await _populate_record_student_details(session_obj, db)
        return _attach_wire_salt(session_obj)

    # Load prior records to update existing entries and avoid duplicates
    prior_res = await db.execute(
        select(AttendanceRecord).where(AttendanceRecord.session_id == session_obj.id)
    )
    prior_records = prior_res.scalars().all()
    prior_device_map = {r.ble_device_id.upper(): r for r in prior_records}
    prior_student_map = {r.student_id: r for r in prior_records if r.student_id}
    seen_devices = set(prior_device_map.keys())
    seen_students = set(prior_student_map.keys())

    verified_count = 0
    # M5: frozen security verdicts (written out-of-band by the defense layers —
    # salt gate, face dedup, no-face) are preserved in place, but they must still
    # count toward total_unverified even though the finalize loop skips updating them.
    spoofer_count = sum(
        1 for r in prior_records
        if r.status in (
            "DUPLICATE_FACE_PROXY",
            "CO_LOCATED_SAME_DESK_PROXY",
            "NO_FACE_DETECTED",
            "SPOOFER_REJECTED",
        )
    )

    records_to_create = []
    for item in payload.records:
        device_id = item.ble_device_id.upper()
        prior_rec = prior_device_map.get(device_id) or (prior_student_map.get(item.student_id) if item.student_id else None)
        if prior_rec:
            if prior_rec.status in (
                "DUPLICATE_FACE_PROXY",
                "CO_LOCATED_SAME_DESK_PROXY",
                "NO_FACE_DETECTED",
                "SPOOFER_REJECTED",
            ):
                continue
            if item.status == "VERIFIED_PRESENT":
                verified_count += 1
            elif item.status == "SPOOFER_REJECTED":
                spoofer_count += 1
            prior_rec.status = item.status
            prior_rec.verification_method = item.verification_method
            prior_rec.affinity_score = item.affinity_score
            prior_rec.remarks = item.remarks
            prior_rec.reported_neighbors = item.reported_neighbors
            new_score = item.game_score
            if new_score is not None:
                prior_rec.game_score = (
                    new_score if prior_rec.game_score is None
                    else max(prior_rec.game_score, new_score)
                )
            continue

        if device_id in seen_devices or (item.student_id and item.student_id in seen_students):
            continue
        seen_devices.add(device_id)
        if item.student_id:
            seen_students.add(item.student_id)

        if item.status == "VERIFIED_PRESENT":
            verified_count += 1
        elif item.status == "SPOOFER_REJECTED":
            spoofer_count += 1

        records_to_create.append(
            AttendanceRecord(
                id=uuid.uuid4(),
                session_id=session_obj.id,
                student_id=item.student_id,
                ble_device_id=device_id,
                status=item.status,
                verification_method=item.verification_method,
                affinity_score=item.affinity_score,
                bridge_device_id=item.bridge_device_id.upper() if item.bridge_device_id else None,
                reported_neighbors=item.reported_neighbors,
                remarks=item.remarks,
                game_score=item.game_score,
                recorded_at=datetime.now(timezone.utc),
            )
        )

    # Read cloud-staged submissions (PEEK, not pop): the buffer is drained
    # only AFTER the durable commit below, so a failure between read and
    # commit leaves the staged check-ins intact for a finalize retry.
    staged = await submission_buffer.peek_submissions(str(session_obj.id))

    # [ULTRASONIC-DISABLED 2026-11] Layer 4 (ultrasonic co-location) is turned
    # OFF. Field testing showed the reciprocal handshake never fires (0%
    # efficacy), and phase-locked chimp-game rounds make dual-phone play
    # impossible anyway. ultrasonic_pairs is kept as an always-empty dict so
    # the override branches below compile; they are dead while disabled.
    # To restore: uncomment the pairing loop here, the override branches in
    # both finalize paths, the M3-lite claim staging in the submit endpoint,
    # the schema fields, and the app-side audio stack call sites.
    ultrasonic_pairs: dict[str, str] = {}
    # for claim_key, claim_sub in staged.items():
    #     claim_peer = claim_sub.claimed_ultrasonic
    #     if not claim_peer:
    #         continue
    #     peer_sub = staged.get(claim_peer)
    #     if peer_sub and peer_sub.claimed_ultrasonic == claim_key:
    #         ultrasonic_pairs[claim_key] = claim_peer
    #         ultrasonic_pairs[claim_peer] = claim_key
    #     else:
    #         logger.warning(f"[Layer 4] Unreciprocated ultrasonic claim ignored: {claim_key} -> {claim_peer}")

    # Leniency seal: a staged student earns VERIFIED_PRESENT only with at least
    # one RECIPROCATED BLE neighbor (mirrors the audit engine's direct-mutual
    # rule). A self-reported neighbor list alone can never verify anyone.
    drain_reports: dict[str, set[str]] = {}
    for rec_item in payload.records:
        drain_reports.setdefault(rec_item.ble_device_id.upper(), set()).update(
            n.strip().upper() for n in (rec_item.reported_neighbors or [])
        )
    for staged_key_extra, staged_sub_extra in staged.items():
        drain_reports.setdefault(staged_key_extra.upper(), set()).update(
            n.strip().upper() for n in staged_sub_extra.reported_neighbors
        )

    for staged_key, staged_sub in staged.items():
        dev_upper = staged_key.upper()
        if dev_upper in seen_devices or (staged_sub.student_id and staged_sub.student_id in seen_students):
            continue
        seen_devices.add(dev_upper)
        if staged_sub.student_id:
            seen_students.add(staged_sub.student_id)

        # [ULTRASONIC-DISABLED] pair override branch — dead while disabled
        # (ultrasonic_pairs is always empty).
        # pair_peer = ultrasonic_pairs.get(dev_upper)
        # if pair_peer:
        #     # Mutual ultrasonic confirmation overrides the benign staged verdict;
        #     # NO blanket 1.00 VERIFIED_PRESENT for desk co-located partners.
        #     spoofer_count += 1
        #     records_to_create.append(
        #         AttendanceRecord(
        #             id=uuid.uuid4(),
        #             session_id=session_obj.id,
        #             student_id=staged_sub.student_id,
        #             ble_device_id=dev_upper,
        #             status="CO_LOCATED_SAME_DESK_PROXY",
        #             verification_method="ULTRASONIC_ACOUSTIC_MATCH",
        #             affinity_score=0.00,
        #             reported_neighbors=staged_sub.reported_neighbors,
        #             remarks=f"Ultrasonic proximity rejected: Co-located on same desk (< 20 cm) with {pair_peer}",
        #             recorded_at=datetime.now(timezone.utc),
        #         )
        #     )
        #     continue

        confirmed_peers = [
            peer.strip().upper()
            for peer in staged_sub.reported_neighbors
            if dev_upper in drain_reports.get(peer.strip().upper(), set())
        ]
        is_ver = bool(confirmed_peers)
        if is_ver:
            verified_count += 1
            rec_status = "VERIFIED_PRESENT"
            verif_method = "BLE_MESH"
            rec_affinity = 1.00
            rec_remarks = f"Cloud staged check-in confirmed via mutual desk neighbor [{', '.join(confirmed_peers)}]"
        elif staged_sub.reported_neighbors:
            rec_status = "ISOLATED_FLAGGED"
            verif_method = "NONE"
            rec_affinity = 0.50
            rec_remarks = f"Cloud staged check-in without confirmed desk neighbor (Reported: [{', '.join(staged_sub.reported_neighbors)}]) - manual review recommended"
        else:
            rec_status = "ISOLATED_FLAGGED"
            verif_method = "NONE"
            rec_affinity = 0.00
            rec_remarks = "Zero desk neighbors detected (isolated seat)"
        records_to_create.append(
            AttendanceRecord(
                id=uuid.uuid4(),
                session_id=session_obj.id,
                student_id=staged_sub.student_id,
                ble_device_id=dev_upper,
                status=rec_status,
                verification_method=verif_method,
                affinity_score=rec_affinity,
                reported_neighbors=staged_sub.reported_neighbors,
                remarks=rec_remarks,
                game_score=staged_sub.game_score,
                recorded_at=datetime.now(timezone.utc),
            )
        )

    # Score gate at verdict time (parity with audit-and-finalize): a VERIFIED
    # verdict without a passing chimp score can never stand — the legacy path
    # previously produced VERIFIED rows with a NULL game_score, silently
    # bypassing the challenge gate.
    # F3: the threshold scales with the student's level (ceil 50% of the
    # level's achievable score, floor 15). Students with no bound account are
    # held to the level-1 floor.
    _student_ids = {
        rec.student_id for rec in [*prior_records, *records_to_create]
        if rec.student_id is not None
    }
    _level_by_student: dict[uuid.UUID, int] = {}
    if _student_ids:
        _xp_rows = await db.execute(
            select(User.id, User.game_xp).where(User.id.in_(_student_ids))
        )
        _level_by_student = {
            uid: level_for_xp(game_xp) for uid, game_xp in _xp_rows.all()
        }
    for rec in [*prior_records, *records_to_create]:
        _threshold = pass_threshold(_level_by_student.get(rec.student_id, 1))
        if rec.status == "VERIFIED_PRESENT" and (rec.game_score is None or rec.game_score < _threshold):
            rec.status = "COGNITIVE_CHALLENGE_FAILED"
            rec.verification_method = "COGNITIVE_CHALLENGE"
            rec.remarks = (
                f"Chimp challenge failed: score "
                f"{rec.game_score if rec.game_score is not None else 'missing'} < {_threshold}"
            )

    # Batch inserts all records and cleans staged submissions
    if records_to_create:
        db.add_all(records_to_create)
        await db.flush()

    # Bind unbound (witness/offline/legacy) rows to roster accounts so the
    # teacher dashboard shows real names/rolls, not "Student <key-suffix>".
    await _bind_unbound_records_to_roster(session_obj, db)

    # Approved-leave overlay: enrolled students with an APPROVED leave covering
    # the session date are marked LEAVE instead of ABSENT (or given a LEAVE
    # row). Runs after the verdict gate so the gate never sees LEAVE rows.
    await _apply_approved_leave_overlay(session_obj, db)

    # F3: pay XP now — after the verdict gate and leave overlay, so only
    # durable VERIFIED_PRESENT rows with a passing score earn anything.
    await award_xp_for_session(db, session_obj)

    session_obj.status = "COMPLETED"
    session_obj.ended_at = datetime.now(timezone.utc)

    # R5 (review §5 honesty): counters must reflect committed DB rows — see
    # _recompute_session_counters.
    await _recompute_session_counters(session_obj, db)

    await db.commit()
    await db.refresh(session_obj)
    # Staged buffer drained only now (it was peeked, never popped mid-flight):
    # a failure before this commit left the check-ins staged for a finalize
    # retry instead of losing them permanently.
    await submission_buffer.pop_submissions(str(session_obj.id))
    # H2: clear face biometrics only AFTER the commit (final grace-window dedup
    # must keep its registry until the records are durable) — see finalize path.
    face_registry.clear_session(str(session_obj.id))

    await _populate_course_metadata(session_obj, db)
    await _populate_record_student_details(session_obj, db)

    logger.info(f"[Legacy Finalized] Session: {session_obj.id}, Verified: {session_obj.total_verified}, Unverified: {session_obj.total_unverified}, Total Records: {len(payload.records)}")
    return _attach_wire_salt(session_obj)

@router.post(
    "/sessions/{session_id}/submit-neighbors",
    status_code=status.HTTP_200_OK,
)
async def submit_student_neighbors(
    session_id: str,
    request: Request,
    payload: Union[SubmitNeighborsRequest, bytes] = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Extracts binary face bytes and headers if request is raw image payload
    raw_face_bytes = None
    if isinstance(payload, bytes):
        raw_face_bytes = payload
        session_salt = request.headers.get("x-session-salt")
        student_id = request.headers.get("x-student-id")
        neighbors_raw = request.headers.get("x-neighbors", "")
        neighbors = [n.strip() for n in neighbors_raw.split(",") if n.strip()] if neighbors_raw else []
        close_raw = request.headers.get("x-close-neighbors", "")
        close_neighbors = [n.strip() for n in close_raw.split(",") if n.strip()] if close_raw else []
        # [ULTRASONIC-DISABLED] Layer 4 headers no longer parsed.
        # co_located_peer_id = request.headers.get("x-co-located-peer-id")
        # ultrasonic_proximity_str = request.headers.get("x-ultrasonic-proximity-detected")
        # ultrasonic_proximity = ultrasonic_proximity_str.lower() in ("true", "1") if ultrasonic_proximity_str is not None else False
        challenge_report_hdr = request.headers.get("x-challenge-report")
        challenge_report = None
        game_score = None
        game_score_hdr = request.headers.get("x-game-score") or request.headers.get("x-chimp-score")
        if game_score_hdr:
            try:
                game_score = int(game_score_hdr.strip())
            except ValueError:
                game_score = None
        if challenge_report_hdr:
            try:
                challenge_report = {
                    k.strip(): int(v)
                    for k, v in (p.split("=", 1) for p in challenge_report_hdr.split(",") if "=" in p)
                }
                if game_score is None:
                    for k in ("chimp_score", "score", "game_score"):
                        if k in challenge_report:
                            game_score = int(challenge_report[k])
                            break
            except Exception:
                challenge_report = {"raw": challenge_report_hdr}
                if game_score is None:
                    try:
                        game_score = int(challenge_report_hdr.strip())
                    except Exception:
                        pass

        payload = SubmitNeighborsRequest(
            student_id=student_id,
            neighbors=neighbors,
            close_neighbors=close_neighbors,
            session_salt=session_salt,
            face_image_base64=None,
            # [ULTRASONIC-DISABLED] Layer 4 fields dropped from the payload.
            # ultrasonic_proximity_detected=ultrasonic_proximity,
            # co_located_peer_id=co_located_peer_id,
            challenge_report=challenge_report,
            game_score=game_score,
        )

    session_obj = await _resolve_session(session_id, db)
    if not session_obj:
        raise HTTPException(status_code=404, detail="Attendance session not found")
    if session_obj.status == "CANCELLED":
        raise HTTPException(status_code=400, detail="Attendance session has been cancelled")
    if session_obj.status not in ("ACTIVE", "COMPLETED"):
        raise HTTPException(status_code=400, detail="Attendance session is not active")
    if session_obj.status == "COMPLETED":
        # Allow 90-second grace period for in-flight student game completions and biometric face deduplication
        if session_obj.ended_at:
            # Mirror _is_session_stale's naive/aware tolerance: SQLite (tests)
            # surfaces naive datetimes; Postgres (prod) surfaces tz-aware ones.
            grace_ended_at = session_obj.ended_at
            if grace_ended_at.tzinfo is None:
                grace_ended_at = grace_ended_at.replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - grace_ended_at).total_seconds() > 90:
                raise HTTPException(status_code=400, detail="Attendance session has expired")

    # TTL check: Auto-expire ACTIVE sessions older than 5 minutes. Status
    # guard: without it, a straggler submit during the grace window of a
    # COMPLETED session whose started_at is > 5 min old rewrote the committed
    # COMPLETED status to EXPIRED — status corruption plus a dead grace path
    # for long-running classes.
    if session_obj.status == "ACTIVE" and _is_session_stale(session_obj.started_at, minutes=5):
        session_obj.status = "EXPIRED"
        session_obj.ended_at = datetime.now(timezone.utc)
        await db.commit()
        raise HTTPException(status_code=400, detail="Attendance session has expired")

    # Class-eligibility gate: a student may only check in to the class the
    # session is FOR. Runs on objects already loaded (session + JWT user) and
    # before the rate limiter, so wrong-class attempts cost zero quota and no
    # face/neighbor work. Mirrors the salt gate's rejection + flag pattern so
    # the attempt stays visible on the teacher's audit dashboard.
    eligibility_detail = student_eligibility_detail(session_obj, current_user)
    if eligibility_detail:
        claimed_key = user_device_key(current_user)
        logger.warning(
            f"[Eligibility Gate] Session {session_obj.id}: submit rejected for key {claimed_key} "
            f"(authenticated) — {eligibility_detail}"
        )
        await _record_proxy_violation(
            db=db,
            session_id=session_obj.id,
            device_id=claimed_key,
            status="SPOOFER_REJECTED",
            verification_method="ELIGIBILITY_REJECTED",
            remarks=eligibility_detail,
            student_id=current_user.id,
            reported_neighbors=[
                n.strip().upper()[-6:] if len(n.strip()) >= 6 else n.strip().upper() for n in payload.neighbors
            ],
        )
        await _commit_proxy_violation(db)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=eligibility_detail,
        )

    # Per-(session, account) submit budget — deliberately NOT per-IP, the whole
    # classroom shares one Wi-Fi gateway address. Throttles salt brute-forcing
    # and resubmit floods for a single account without 429-ing its classmates.
    if not await submit_rate_limiter.check(str(session_obj.id), str(current_user.id)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many check-in submissions for this session; resubmit shortly",
        )

    # Layer 2 anti-remote-submission guard (H5): student must possess the
    # WIRE salt broadcast by the in-room teacher beacon. Server stores only the
    # canonical salt; valid wire tokens are derived (current + grace window)
    # and compared in constant time. Client-supplied value never chooses truth.
    provided_salt = (payload.session_salt or "").strip().upper()
    expected_salts = valid_wire_salts(session_obj)
    salt_ok = bool(provided_salt) and any(
        secrets.compare_digest(provided_salt, w) for w in expected_salts
    )
    if not salt_ok:
        # Flag the attempted remote submission so it surfaces on the teacher's
        # audit dashboard instead of vanishing as a silent rejection.
        # JWT identity only (auth is mandatory on submit): rejected keys always
        # belong to a real enrolled account — client-chosen keys are impossible,
        # so spoofer flags can no longer be framed onto honest classmates.
        claimed_key = user_device_key(current_user)
        logger.warning(
            f"[Salt Gate] Session {session_obj.id}: submit rejected for key {claimed_key} "
            f"(authenticated) — beacon salt mismatch"
        )

        # Record spoofer flag for beacon salt mismatch
        await _record_proxy_violation(
            db=db,
            session_id=session_obj.id,
            device_id=claimed_key,
            status="SPOOFER_REJECTED",
            verification_method="SALT_REJECTED",
            remarks="Remote check-in blocked: in-room beacon salt mismatch",
            student_id=current_user.id,
            reported_neighbors=[
                n.strip().upper()[-6:] if len(n.strip()) >= 6 else n.strip().upper() for n in payload.neighbors
            ],
        )
        await _commit_proxy_violation(db)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Nice try lil bro",
        )

    target_session_id = session_obj.id
    user_id = current_user.id

    # M4: bind submission identity to JWT account via collision-resistant key
    # (hash of full roll/UUID). Client-chosen keys cannot select another node.
    student_key = user_device_key(current_user)

    normalized_neighbors = [n.strip().upper()[-6:] if len(n.strip()) >= 6 else n.strip().upper() for n in payload.neighbors]
    normalized_close = [n.strip().upper()[-6:] if len(n.strip()) >= 6 else n.strip().upper() for n in (payload.close_neighbors or [])]

    # Observability-only: payload fingerprint, logged BEFORE the face/ultrasonic
    # gates so even rejected attempts are tracked. If the same fingerprint ever
    # appears twice near-simultaneously (seen once from 10.26.34.133), that is a
    # network-stack retry duplicating one check-in — not two real students.
    fingerprint_material = "|".join([
        student_key,
        hashlib.sha256((payload.session_salt or "").encode()).hexdigest()[:8],
        ",".join(sorted(normalized_neighbors)),
        # [ULTRASONIC-DISABLED] Layer 4 component removed.
        # f"ultra:{1 if payload.ultrasonic_proximity_detected else 0}:{(payload.co_located_peer_id or '-').upper()}",
        f"facebytes:{len(payload.face_image_base64) if payload.face_image_base64 else 0}",
    ])
    logger.info(
        f"[Check-In Fingerprint] Session: {target_session_id} Key: {student_key} "
        f"IP: {limiter_ip(request)} "
        f"FP: {hashlib.sha256(fingerprint_material.encode()).hexdigest()[:12]}"
    )

    # Challenge score gate (security): chimp score < 15 => unverified.
    challenge_score = payload.game_score
    if challenge_score is None and payload.challenge_report:
        for k in ("chimp_score", "score", "game_score"):
            if k in payload.challenge_report:
                try:
                    challenge_score = int(payload.challenge_report[k])
                except Exception:
                    challenge_score = None
                break
    if payload.challenge_report or challenge_score is not None:
        logger.info(
            f"[Challenge Telemetry] Session: {target_session_id} Key: {student_key} "
            f"Report: {payload.challenge_report} Score: {challenge_score}"
        )
    # Hard gate: real check-ins (face-bearing) must carry a passing score.
    # Scoreless mid-window neighbor syncs (no face) are telemetry only — they
    # stage claims for the finalize audit but can never self-verify: finalize
    # marks any VERIFIED verdict whose best score is missing/below threshold
    # COGNITIVE_CHALLENGE_FAILED, and the 90 s grace path re-evaluates late
    # arrivals that do carry a score.
    face_present = bool(payload.face_image_base64) or raw_face_bytes is not None
    # F3: gate at the caller's own level (ceil 50% of achievable, floor 15).
    _my_threshold = pass_threshold(level_for_xp(current_user.game_xp if current_user else 0))
    if face_present and (challenge_score is None or challenge_score < _my_threshold):
        score_val = challenge_score if challenge_score is not None else "missing"
        await _record_proxy_violation(
            db=db,
            session_id=target_session_id,
            device_id=student_key,
            status="COGNITIVE_CHALLENGE_FAILED",
            verification_method="COGNITIVE_CHALLENGE",
            remarks=f"Chimp challenge failed: score {score_val} < {_my_threshold}",
            student_id=current_user.id if current_user else None,
            reported_neighbors=normalized_neighbors,
            game_score=challenge_score,
        )
        await _commit_proxy_violation(db)
        detail_score = challenge_score if challenge_score is not None else "missing"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cognitive challenge failed: score {detail_score} < {_my_threshold}",
        )

    # Face deduplication check (Layer 3: Camera Face Biometric Deduplication)
    face_check_result = None
    if payload.face_image_base64 or raw_face_bytes:
        raw_roll = current_user.roll_number or student_key

        # Compile proximity cluster peers: close peers (RSSI >= -65), reported desk neighbors, and co-located peer
        cluster_peers = set(normalized_close)
        cluster_peers.update(normalized_neighbors)
        # [ULTRASONIC-DISABLED] co-located peer no longer joins the face cluster.
        # if payload.co_located_peer_id:
        #     co_key = payload.co_located_peer_id[-6:].upper() if len(payload.co_located_peer_id) >= 6 else payload.co_located_peer_id.upper()
        #     cluster_peers.add(co_key)

        # Run facial biometric matching in background thread pool
        face_check_result = await asyncio.to_thread(
            face_registry.register_and_check,
            session_id=str(session_obj.id),
            student_key=student_key,
            roll_number=raw_roll,
            face_base64=payload.face_image_base64,
            face_bytes=raw_face_bytes,
            cluster_peers=cluster_peers,
        )

        if not face_check_result.has_human_face:
            logger.warning(f"[Layer 3 Face Biometric] No face detected for {student_key}: {face_check_result.remarks}")
            await _record_proxy_violation(
                db=db,
                session_id=session_obj.id,
                device_id=student_key,
                status="NO_FACE_DETECTED",
                verification_method="FACE_BIOMETRIC_FAILED",
                remarks=face_check_result.remarks,
                student_id=current_user.id if current_user else None,
                reported_neighbors=normalized_neighbors,
            )
            await _commit_proxy_violation(db)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Biometric proxy rejected: {face_check_result.remarks}",
            )

        if face_check_result.is_duplicate:
            # Flag ONLY the submitting student. The matched earlier student is
            # innocent — writing them a DUPLICATE_FACE_PROXY row at submit time
            # (a) vandalized an honest classmate's record, (b) blocked their
            # audit verdict at finalize via the violation-status skip list, and
            # (c) created their row with student_id=None (no account binding on
            # a matched key). The registry already marks the matched student
            # flagged=True, which excludes them from finalize's face-anchor set
            # so the component falls to instructor review, and the flagged
            # pair (both images + similarity) stays available for that review.
            await _record_proxy_violation(
                db=db,
                session_id=session_obj.id,
                device_id=student_key,
                status="DUPLICATE_FACE_PROXY",
                verification_method="FACE_BIOMETRIC_MATCH",
                remarks=face_check_result.remarks,
                student_id=current_user.id if current_user else None,
                reported_neighbors=normalized_neighbors,
            )
            await _commit_proxy_violation(db)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Biometric proxy rejected: {face_check_result.remarks}",
            )

    # M3-lite: an ultrasonic desk handshake (Layer 4) is a CLAIM, not a verdict.
    # The claimant stages normally; only a RECIPROCATED pair (both students claim
    # each other) is materialized into CO_LOCATED_SAME_DESK_PROXY rows at finalize.
    # One-sided claims are logged and ignored, so a prankster can never vandalize
    # a classmate's record with a fake "we sat together" claim.
    # [ULTRASONIC-DISABLED] claim staging removed — stage_submission no longer
    # receives a claimed_ultrasonic value (defaults to None in the buffer).
    # ultrasonic_claim: Optional[str] = None
    # if payload.ultrasonic_proximity_detected:
    #     raw_claim = (payload.co_located_peer_id or "").strip()
    #     # Keys are already last-4-normalized everywhere on this route — mirror it
    #     # so the claim can pair against the partner's staged device key.
    #     normalized_claim = raw_claim[-6:].upper() if len(raw_claim) >= 6 else raw_claim.upper()
    #     if not normalized_claim or normalized_claim == "UNKNOWN" or normalized_claim == student_key:
    #         logger.warning(f"[Layer 4] Ultrasonic claim from {student_key} dropped: invalid co-located peer '{raw_claim}'")
    #     else:
    #         ultrasonic_claim = normalized_claim
    #         logger.info(f"[Layer 4] Ultrasonic claim received from {student_key}: co-located with {normalized_claim} (deferred to finalize for reciprocal confirmation)")

    # R2 (review §3.1): the gate MUST span both the stage and the post-stage
    # committed-status re-read — a stage entering between finalize's drain and
    # its commit otherwise reads the still-ACTIVE (uncommitted) status and is
    # silently orphaned moments later by finalize's buffer clear. Holding the
    # same per-session lock finalize holds makes intake atomic either way.
    async with submission_buffer.session_gate(str(target_session_id)):
        # Stage student check-in submission into in-memory buffer
        await submission_buffer.stage_submission(
            session_id=str(target_session_id),
            device_key=student_key,
            student_id=user_id,
            reported_neighbors=normalized_neighbors,
            # [ULTRASONIC-DISABLED] claim staging removed.
            # claimed_ultrasonic=ultrasonic_claim,
            game_score=challenge_score,
        )

        # Re-read session status after staging: if finalize committed while this submission was in
        # flight (the finalize already popped the buffer), reroute through the grace path below so
        # the straggler gets an attendance record instead of being silently orphaned.
        fresh_status_res = await db.execute(
            select(AttendanceSession.status).where(AttendanceSession.id == session_obj.id)
        )
        session_obj.status = fresh_status_res.scalar_one_or_none() or session_obj.status

    if session_obj.status == "CANCELLED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Attendance session has been cancelled",
        )

    # [ULTRASONIC-DISABLED] late-claim logging removed with claim staging.
    # if ultrasonic_claim and session_obj.status == "COMPLETED":
    #     # M3-lite: finalize already popped the staging buffer, so reciprocity for
    #     # this late claim can no longer be evaluated. Log only — never vandalize.
    #     logger.warning(f"[Layer 4] Post-finalize ultrasonic claim ignored (mutuality unevaluable): {student_key} -> {ultrasonic_claim}")

    # For in-flight submissions arriving during the grace period of an already COMPLETED session,
    # immediately evaluate and record their attendance so they don't get orphaned without an AttendanceRecord.
    if session_obj.status == "COMPLETED":
        rec_stmt = select(AttendanceRecord).where(
            AttendanceRecord.session_id == target_session_id,
            AttendanceRecord.ble_device_id == student_key,
        )
        rec_res = await db.execute(rec_stmt)
        existing_record = rec_res.scalars().first()

        if existing_record and challenge_score is not None:
            prev_score = existing_record.game_score
            existing_record.game_score = (
                challenge_score if prev_score is None else max(prev_score, challenge_score)
            )
            # Rescue (finalize-after-game race): the audit stamped this record
            # COGNITIVE_CHALLENGE_FAILED because no score had arrived when the
            # teacher's timer ended. A late legitimate score upgrades a
            # missing-score failure only — a stored sub-threshold score stays
            # frozen. Reciprocity reads the partner's claimed neighbors, not its
            # current status, so rescue order never matters.
            if (
                existing_record.status == "COGNITIVE_CHALLENGE_FAILED"
                and prev_score is None
                and challenge_score >= _my_threshold
            ):
                partner_stmt = select(AttendanceRecord).where(
                    AttendanceRecord.session_id == target_session_id,
                    AttendanceRecord.ble_device_id.in_(normalized_neighbors or []),
                )
                partner_res = await db.execute(partner_stmt)
                mutual = False
                hard_violations = {
                    "DUPLICATE_FACE_PROXY",
                    "CO_LOCATED_SAME_DESK_PROXY",
                    "DIVIDED_ATTENTION_PROXY",
                    "SPOOFER_REJECTED",
                    "NO_FACE_DETECTED",
                    "ELIGIBILITY_REJECTED",
                }
                for partner in partner_res.scalars().all():
                    if partner.status in hard_violations:
                        continue
                    partner_neighbors = partner.reported_neighbors or []
                    if student_key.upper() in {str(n).upper() for n in partner_neighbors}:
                        mutual = True
                        break
                if mutual:
                    existing_record.status = "VERIFIED_PRESENT"
                    existing_record.verification_method = "IN_FLIGHT_GRACE_PEER"
                    existing_record.affinity_score = 1.00
                    existing_record.remarks = (
                        f"In-flight check-in verified via mutual desk neighbor (score {challenge_score})"
                    )
                    # Atomic in-DB increment: two concurrent grace rescues
                    # racing a read-modify-write on the ORM attribute lost one
                    # increment (READ COMMITTED sees the old value twice).
                    await db.execute(
                        update(AttendanceSession)
                        .where(AttendanceSession.id == target_session_id)
                        .values(
                            total_verified=func.coalesce(AttendanceSession.total_verified, 0) + 1
                        )
                        .execution_options(synchronize_session=False)
                    )
                    logger.info(
                        f"[In-Flight Grace Audit] Rescued late arrival {student_key} "
                        f"-> VERIFIED_PRESENT (score {challenge_score}, mutual neighbor)"
                    )
                else:
                    existing_record.status = "ISOLATED_FLAGGED"
                    existing_record.verification_method = "IN_FLIGHT_GRACE"
                    existing_record.affinity_score = 0.50
                    existing_record.remarks = (
                        f"In-flight check-in after finalize without reciprocal neighbor "
                        f"(score {challenge_score}, Reported: [{', '.join(normalized_neighbors)}])"
                    )
                    logger.info(
                        f"[In-Flight Grace Audit] Late arrival {student_key} scored "
                        f"{challenge_score} but no reciprocal neighbor — ISOLATED_FLAGGED"
                    )
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()

        if not existing_record:
            verified_neighbors = []
            if normalized_neighbors:
                v_stmt = select(AttendanceRecord).where(
                    AttendanceRecord.session_id == target_session_id,
                    AttendanceRecord.ble_device_id.in_(normalized_neighbors),
                    AttendanceRecord.status == "VERIFIED_PRESENT",
                )
                v_res = await db.execute(v_stmt)
                verified_neighbors = [r.ble_device_id for r in v_res.scalars().all()]

            if verified_neighbors:
                rec_status = "VERIFIED_PRESENT"
                verif_method = "IN_FLIGHT_GRACE_PEER"
                affinity = 1.00
                bridge = None
                remarks = f"In-flight check-in verified via mutual desk neighbor [{', '.join(verified_neighbors)}]"
                # Atomic in-DB increment (see rescue path comment).
                await db.execute(
                    update(AttendanceSession)
                    .where(AttendanceSession.id == target_session_id)
                    .values(
                        total_verified=func.coalesce(AttendanceSession.total_verified, 0) + 1
                    )
                    .execution_options(synchronize_session=False)
                )
            elif normalized_neighbors:
                rec_status = "ISOLATED_FLAGGED"
                verif_method = "IN_FLIGHT_GRACE"
                affinity = 0.50
                bridge = None
                remarks = f"In-flight check-in during grace period without verified neighbor (Reported: [{', '.join(normalized_neighbors)}]) - manual review recommended"
            else:
                rec_status = "ISOLATED_FLAGGED"
                verif_method = "NONE"
                affinity = 0.00
                bridge = None
                remarks = "Zero desk neighbors detected (isolated seat)"

            # M5 (audit): identity is the JWT account ONLY. The old ilike
            # substring fallback could bind a crafted id prefix to another
            # student's row. user_id is always set for an authenticated
            # caller, so no fallback resolution is permitted.
            resolved_student_id = user_id

            new_record = AttendanceRecord(
                id=uuid.uuid4(),
                session_id=session_obj.id,
                student_id=resolved_student_id,
                ble_device_id=student_key,
                status=rec_status,
                verification_method=verif_method,
                affinity_score=affinity,
                bridge_device_id=bridge,
                reported_neighbors=normalized_neighbors,
                remarks=remarks,
                game_score=challenge_score,
                recorded_at=datetime.now(timezone.utc),
            )
            db.add(new_record)
            try:
                await db.commit()
            except IntegrityError:
                # R1 race guard (review §3.1): a valid retrying student — a
                # double grace claim or a replayed app keep-alive after their
                # check-in — re-hits one of the session's unique keys
                # (device/student/submission). Their attendance already
                # exists; treat the claim as accepted, never 500 them.
                await db.rollback()
                logger.info(
                    f"[In-Flight Grace Audit] Duplicate grace claim for late arrival {student_key} "
                    f"in session {session_obj.id} — attendance record already present."
                )
            logger.info(f"[In-Flight Grace Audit] Generated {rec_status} record for late arrival {student_key} in session {session_obj.id}")

    # F3: single idempotent award scan — any VERIFIED_PRESENT row this request
    # produced or rescued (face-verified path, in-flight grace) pays XP once.
    await award_xp_for_session(db, session_obj)

    logger.info(f"[Check-In] Student: {student_key} submitted {len(normalized_neighbors)} neighbors: {normalized_neighbors} for session: {target_session_id}")
    return {
        "status": "success",
        "student": student_key,
        "recorded_neighbors": normalized_neighbors,
        # R5 (review §5 honesty): bound to the CHECK OUTCOME, not to payload
        # presence — this can only be True after the biometric check both
        # detected a face and did not flag it as a duplicate (the no-face and
        # duplicate branches raise 403 above).
        "face_verified": (
            (face_check_result.has_human_face and not face_check_result.is_duplicate)
            if face_check_result else None
        ),
        "face_diagnostic": face_check_result.remarks if face_check_result else None,
    }


# Execute social-graph audit and finalize session
@router.post(
    "/sessions/{session_id}/audit-and-finalize",
    response_model=AttendanceSessionResponse,
)
async def audit_and_finalize_session(
    session_id: str,
    payload: MeshAuditRunRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
    _finalize_gate: None = Depends(_session_gate_dependency),
):
    session_obj = await _resolve_session(session_id, db)

    if not session_obj:
        raise HTTPException(status_code=404, detail="Attendance session not found")
    user_role = (current_user.role or "").upper()
    if session_obj.teacher_id != current_user.id and user_role not in ("DEVELOPER", "ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only finalize your own attendance sessions",
        )
    if session_obj.status == "CANCELLED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot finalize a cancelled session",
        )
    # Serialize overlapping finalizes: block on the session row, then re-read committed status
    session_obj = await _lock_session_for_finalize(db, session_obj)

    if session_obj.status == "COMPLETED":
        # Idempotent exit: attach the finalized counters and records so the caller gets the
        # completed session rather than the stale pre-lock snapshot
        await db.refresh(session_obj)
        final_recs = await db.execute(
            select(AttendanceRecord).where(AttendanceRecord.session_id == session_obj.id)
        )
        session_obj.records = list(final_recs.scalars().all())
        await _populate_course_metadata(session_obj, db)
        await _populate_record_student_details(session_obj, db)
        return _attach_wire_salt(session_obj)

    # Fetch all cloud-submitted student and relay reports from memory buffer and
    # fallback database. PEEK, not pop: the buffer is drained only AFTER the
    # durable commit below, so a failure between read and commit (DB blip,
    # flush error) leaves the staged check-ins intact for a finalize retry.
    staged = await submission_buffer.peek_submissions(str(session_obj.id))

    sub_stmt = select(SessionSubmission).where(SessionSubmission.session_id == session_obj.id)
    sub_res = await db.execute(sub_stmt)
    submissions = sub_res.scalars().all()
    if submissions:
        await db.execute(delete(SessionSubmission).where(SessionSubmission.session_id == session_obj.id))

    cloud_reports: dict[str, List[str]] = {s.device_key: s.reported_neighbors for s in submissions}
    user_map: dict[str, uuid.UUID] = {s.device_key: s.student_id for s in submissions if s.student_id}

    for dev_key, staged_sub in staged.items():
        cloud_reports[dev_key] = staged_sub.reported_neighbors
        if staged_sub.student_id:
            user_map[dev_key] = staged_sub.student_id

    # Normalize teacher-reported keys/neighbors to match the staged/cloud
    # convention (uppercased). graph_engine matches keys exactly, so a
    # mixed-case payload key would never pair with its peers' reports and the
    # honest node would land ISOLATED_FLAGGED.
    normalized_payload_reports = {
        k.strip().upper(): [n.strip().upper() for n in v]
        for k, v in payload.reports.items()
    }
    combined_reports = {**cloud_reports, **normalized_payload_reports}

    # H3 (audit): anchor mesh verdicts to enrolled class size and to
    # server-observed face evidence so a colluder-only clique cannot
    # self-verify as "the room". Face registry holds per-session unique
    # (non-duplicate) successful face checks — still populated here because
    # clear_session runs only after commit.
    face_verified_keys = None
    try:
        session_store = face_registry._registry.get(str(session_obj.id), {})
        if session_store:
            face_verified_keys = {
                k.upper() for k, v in session_store.items()
                if not v.get("flagged", False)
            }
    except Exception:
        face_verified_keys = None

    # Execute social-graph audit engine
    audit_results = audit_classroom_mesh(
        combined_reports,
        total_enrolled=session_obj.total_enrolled or 0,
        face_verified_keys=face_verified_keys,
    )

    # M3-lite: materialize RECIPROCATED ultrasonic desk claims. Both parties must
    # claim each other from their staged submissions; the matched pair's benign
    # audit verdict rows are transformed in place into the proxy violation row —
    # preserving the one-row-per-student shape. Unreciprocated claims are ignored.
    # [ULTRASONIC-DISABLED 2026-11] Layer 4 pairing loop off (see legacy path
    # note above). Kept as always-empty dict so the override block compiles.
    ultrasonic_pairs: dict[str, str] = {}
    # for claim_key, claim_sub in staged.items():
    #     claim_peer = claim_sub.claimed_ultrasonic
    #     if not claim_peer:
    #         continue
    #     peer_sub = staged.get(claim_peer)
    #     if peer_sub and peer_sub.claimed_ultrasonic == claim_key:
    #         ultrasonic_pairs[claim_key] = claim_peer
    #         ultrasonic_pairs[claim_peer] = claim_key
    #     else:
    #         logger.warning(f"[Layer 4] Unreciprocated ultrasonic claim ignored: {claim_key} -> {claim_peer}")

    # [ULTRASONIC-DISABLED] verdict override block — dead while disabled.
    # if ultrasonic_pairs:
    #     for item in audit_results:
    #         pair_peer = ultrasonic_pairs.get(item["ble_device_id"].upper())
    #         if pair_peer:
    #             item["status"] = "CO_LOCATED_SAME_DESK_PROXY"
    #             item["verification_method"] = "ULTRASONIC_ACOUSTIC_MATCH"
    #             item["remarks"] = f"Ultrasonic proximity rejected: Co-located on same desk (< 20 cm) with {pair_peer}"

    # Attach client-attested chimp challenge scores (best seen per device) so the
    # finalized attendance records carry them for instructor review.
    challenge_scores: dict[str, int] = {}
    for sub_key, staged_sub in staged.items():
        if staged_sub.game_score is not None:
            k = sub_key.upper()
            challenge_scores[k] = max(challenge_scores.get(k, 0), staged_sub.game_score)
    for item in audit_results:
        k = item["ble_device_id"].upper()
        if k in challenge_scores:
            item["game_score"] = challenge_scores[k]

    # Score gate at verdict time: a VERIFIED verdict without a passing challenge
    # score can never stand (syncs stage claims but carry no score — a student
    # who never plays must not auto-verify through mutual claims alone). The
    # 90 s grace path rescues late arrivals that do carry a legitimate score.
    # F3: the threshold scales with the student's level (ceil 50% of the
    # level's achievable score, floor 15); unresolvable students are held to
    # the level-1 floor.
    _audit_student_ids = set(user_map.values())
    _level_by_student: dict[uuid.UUID, int] = {}
    if _audit_student_ids:
        _xp_rows = await db.execute(
            select(User.id, User.game_xp).where(User.id.in_(_audit_student_ids))
        )
        _level_by_student = {
            uid: level_for_xp(game_xp) for uid, game_xp in _xp_rows.all()
        }
    for item in audit_results:
        score = item.get("game_score")
        _threshold = pass_threshold(
            _level_by_student.get(user_map.get(item["ble_device_id"].upper()), 1)
        )
        if item["status"] == "VERIFIED_PRESENT" and (score is None or score < _threshold):
            item["status"] = "COGNITIVE_CHALLENGE_FAILED"
            item["verification_method"] = "COGNITIVE_CHALLENGE"
            item["remarks"] = (
                f"Chimp challenge failed: score {score if score is not None else 'missing'} < {_threshold}"
            )

    # Log the verdict so manual classroom tests are self-explaining in server logs
    verdict_counts: dict[str, int] = {}
    for item in audit_results:
        verdict_counts[item["status"]] = verdict_counts.get(item["status"], 0) + 1
    logger.info(f"[Audit Verdict] Session: {session_obj.id} -> {verdict_counts}")
    for item in audit_results:
        if item["status"] != "VERIFIED_PRESENT":
            logger.info(
                f"[Audit Detail] Session: {session_obj.id} node {item['ble_device_id']} "
                f"-> {item['status']} :: {item['remarks']}"
            )

    # Batch load all prior attendance records for this session
    prior_records_res = await db.execute(
        select(AttendanceRecord).where(AttendanceRecord.session_id == session_obj.id)
    )
    prior_records = prior_records_res.scalars().all()
    prior_device_map = {r.ble_device_id.upper(): r for r in prior_records}
    prior_student_map = {r.student_id: r for r in prior_records if r.student_id}
    seen_devices = set(prior_device_map.keys())
    seen_students = set(prior_student_map.keys())

    # M5-consistent identity: only AUTHENTICATED submissions bind identities
    # (user_map is filled exclusively from staged/DB submissions that carried a
    # JWT account). The old ilike roll-suffix fallback tried to match 4-hex
    # device keys against roll numbers ending in those hex chars — it almost
    # never matched a real roll, and when it did it could bind an audit node to
    # the WRONG account. Unresolvable keys now simply keep student_id NULL.

    verified_count = 0
    spoofer_count = 0
    records_to_create = []

    for item in audit_results:
        device_id = item["ble_device_id"].upper()
        resolved_student_id = user_map.get(device_id)

        prior_rec = prior_device_map.get(device_id) or (prior_student_map.get(resolved_student_id) if resolved_student_id else None)
        if prior_rec:
            # Skip modifying existing security proxy violations
            if prior_rec.status in (
                "DUPLICATE_FACE_PROXY",
                "CO_LOCATED_SAME_DESK_PROXY",
                "DIVIDED_ATTENTION_PROXY",
                "COGNITIVE_CHALLENGE_FAILED",
                "NO_FACE_DETECTED",
                "SPOOFER_REJECTED",
            ):
                continue
            # Update existing record in place without duplicate insert
            if item["status"] == "VERIFIED_PRESENT":
                verified_count += 1
            elif item["status"] == "SPOOFER_REJECTED":
                spoofer_count += 1
            prior_rec.status = item["status"]
            prior_rec.verification_method = item["verification_method"]
            prior_rec.affinity_score = item["affinity_score"]
            prior_rec.remarks = item["remarks"]
            prior_rec.reported_neighbors = item["reported_neighbors"]
            new_score = item.get("game_score")
            if new_score is not None:
                prior_rec.game_score = (
                    new_score if prior_rec.game_score is None
                    else max(prior_rec.game_score, new_score)
                )
            if resolved_student_id and not prior_rec.student_id:
                prior_rec.student_id = resolved_student_id
            continue

        if device_id in seen_devices or (resolved_student_id and resolved_student_id in seen_students):
            continue
        seen_devices.add(device_id)
        if resolved_student_id:
            seen_students.add(resolved_student_id)

        if item["status"] == "VERIFIED_PRESENT":
            verified_count += 1
        elif item["status"] == "SPOOFER_REJECTED":
            spoofer_count += 1

        records_to_create.append(
            AttendanceRecord(
                id=uuid.uuid4(),
                session_id=session_obj.id,
                student_id=resolved_student_id,
                ble_device_id=device_id,
                status=item["status"],
                verification_method=item["verification_method"],
                affinity_score=item["affinity_score"],
                bridge_device_id=item["bridge_device_id"].upper() if item["bridge_device_id"] else None,
                reported_neighbors=item["reported_neighbors"],
                remarks=item["remarks"],
                game_score=item.get("game_score"),
                recorded_at=datetime.now(timezone.utc),
            )
        )

    # Batch insert all attendance records and flush to ensure visibility
    if records_to_create:
        db.add_all(records_to_create)
        await db.flush()

    # Bind unbound (witness/offline/legacy) rows to roster accounts so the
    # teacher dashboard shows real names/rolls, not "Student <key-suffix>".
    await _bind_unbound_records_to_roster(session_obj, db)

    # Approved-leave overlay: enrolled students with an APPROVED leave covering
    # the session date are marked LEAVE instead of ABSENT (or given a LEAVE
    # row). Runs after the verdict gate so the gate never sees LEAVE rows.
    await _apply_approved_leave_overlay(session_obj, db)

    # F3: pay XP now — after the verdict gate and leave overlay, so only
    # durable VERIFIED_PRESENT rows with a passing score earn anything.
    await award_xp_for_session(db, session_obj)

    session_obj.status = "COMPLETED"
    session_obj.ended_at = datetime.now(timezone.utc)

    # R5 (review §5 honesty): verified count is recounted from durable rows —
    # the payload-computed tally could be clobbered by grace-path increments.
    await _recompute_session_counters(session_obj, db)

    await db.commit()
    await db.refresh(session_obj)
    # Staged buffer drained only now (it was peeked, never popped mid-flight):
    # a failure before this commit left the check-ins staged for a finalize
    # retry instead of losing them permanently.
    await submission_buffer.pop_submissions(str(session_obj.id))
    # H2: clear face biometrics only AFTER the commit — clearing before commit
    # left a blind window during the 90s grace period where a duplicate-face
    # resubmission hit an empty registry and slipped past dedup.
    face_registry.clear_session(str(session_obj.id))

    await _populate_course_metadata(session_obj, db)
    await _populate_record_student_details(session_obj, db)

    logger.info(f"[Audit Finalized] Session: {session_obj.id}, Verified: {session_obj.total_verified}, Unverified: {session_obj.total_unverified}, Total Records: {len(audit_results)}")
    return _attach_wire_salt(session_obj)


# Retrieve detailed session information
@router.get("/sessions/{session_id}", response_model=AttendanceSessionResponse)
async def get_session_details(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    # Require authentication in production
    if not current_user and not is_test_environment():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    session_obj = await _resolve_session(session_id, db)
    if not session_obj:
        raise HTTPException(status_code=404, detail="Attendance session not found")

    # Ownership gate for non-students: TEACHER/STAFF/FACULTY/HOD callers may
    # only read their own sessions (privileged auditors excepted). Without
    # this, any authenticated instructor could read the full roster — names,
    # roll numbers, statuses — of every other teacher's session.
    user_role = (current_user.role or "").upper() if current_user else ""
    if user_role not in ("STUDENT", ""):
        if session_obj.teacher_id != current_user.id and user_role not in ("DEVELOPER", "ADMIN"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to view this attendance session",
            )

    await _populate_course_metadata(session_obj, db)

    # Attach student names and roll numbers to records
    if session_obj.records:
        rec_user_ids = [r.student_id for r in session_obj.records if r.student_id]
        if rec_user_ids:
            u_res = await db.execute(select(User).where(User.id.in_(rec_user_ids)))
            u_map = {u.id: u for u in u_res.scalars().all()}
            for r in session_obj.records:
                if r.student_id in u_map:
                    u = u_map[r.student_id]
                    r.roll_number = u.roll_number
                    r.student_name = u.full_name

        # Filter records for student callers to protect classmate privacy.
        # Own-key match uses the hashed device key derived from the JWT account
        # (the old roll[-4:] comparison never matched hashed keys, so rows with
        # an unbound student_id were invisible to the student they belonged to).
        if user_role == "STUDENT":
            own_key = user_device_key(current_user)
            session_obj.records = [
                r for r in session_obj.records
                if r.student_id == current_user.id
                or r.ble_device_id.upper() == own_key
            ]

    _attach_wire_salt(session_obj)
    # H5 gate material must not travel to student clients: the wire salt's
    # purpose is proving physical presence via the teacher's BLE beacon. The
    # student app derives the salt from the beacon packet only — it never
    # reads this route for it — so blanking both salts here raises the cost
    # of remote check-ins without breaking any client flow. (The gate remains
    # weak against two in-room colluders sharing the salt out-of-band.)
    user_role = (current_user.role or "").upper() if current_user else ""
    if user_role in ("STUDENT", ""):
        session_obj.session_salt = None
        session_obj.session_wire_salt = None
    return session_obj


# Return duplicate face pairs flagged during instructor session
@router.get("/sessions/{session_id}/flagged-faces")
async def get_flagged_faces(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
):
    session_obj = await _resolve_session(session_id, db)
    if not session_obj:
        raise HTTPException(status_code=404, detail="Attendance session not found")

    # Owner gate (review §1.3.1): flagged pairs carry students' face crops —
    # only the session's own teacher (or a privileged auditor) may view them.
    user_role = (current_user.role or "").upper()
    if session_obj.teacher_id != current_user.id and user_role not in ("DEVELOPER", "ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view flagged faces for your own attendance sessions",
        )

    flagged = face_registry.get_flagged_pairs(str(session_obj.id))
    return {
        "session_id": str(session_obj.id),
        "count": len(flagged),
        "flagged_pairs": flagged,
    }


# Override attendance record status manually
@router.patch("/records/{record_id}/override", response_model=AttendanceRecordResponse)
async def override_attendance_record(
    record_id: uuid.UUID,
    payload: RecordOverrideRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_teacher),
):
    result = await db.execute(
        select(AttendanceRecord, AttendanceSession)
        .join(AttendanceSession, AttendanceRecord.session_id == AttendanceSession.id)
        .where(AttendanceRecord.id == record_id)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Attendance record not found")

    record_obj, session_obj = row
    if session_obj.teacher_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to override records for this session",
        )

    record_obj.status = payload.status
    record_obj.verification_method = "MANUAL_OVERRIDE"
    if payload.remarks:
        record_obj.remarks = payload.remarks

    # Deliberate chimp-gate exemption: the instructor's manual verdict is the
    # trusted authority, so an override may set VERIFIED_PRESENT without a
    # passing game_score (the schema whitelist at RecordOverrideRequest bounds
    # what can be stamped). Counters are recomputed from durable rows (the
    # helper flushes) so the dashboard reflects the override immediately.
    await _recompute_session_counters(session_obj, db)
    await db.commit()
    await db.refresh(record_obj)
    return record_obj


# Verify human face presence in diagnostic image
@router.post("/lab/face-check", response_model=FaceLabCheckResponse)
async def lab_face_check(
    payload: FaceLabCheckRequest,
    current_user: User = Depends(require_teacher),
):
    # Per-teacher budget: decode + cv2 inference is the heaviest CPU work in
    # the app; the gate keeps a misbehaving client from pinning the worker.
    if not await face_lab_limiter.check(str(current_user.id)):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many face lab requests; slow down")
    if len(payload.face_image_base64) > 5 * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Image payload too large")
    try:
        clean_b64 = payload.face_image_base64
        if "," in clean_b64:
            clean_b64 = clean_b64.split(",", 1)[1]
        raw_bytes = base64.b64decode(clean_b64)
        has_face, _, remarks = await asyncio.to_thread(
            face_registry.engine.extract_face_and_embedding,
            raw_bytes
        )
        return FaceLabCheckResponse(has_face=has_face, remarks=remarks)
    except Exception as e:
        # R5 (review §5 honesty): failures are server errors, not a pretend
        # 200 carrying an error string in remarks.
        logger.error(f"[Face Lab] face-check failed: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Face processing failed")


# Compare two diagnostic face images
@router.post("/lab/face-compare", response_model=FaceLabCompareResponse)
async def lab_face_compare(
    payload: FaceLabCompareRequest,
    current_user: User = Depends(require_teacher),
):
    if not await face_lab_limiter.check(str(current_user.id)):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many face lab requests; slow down")
    if len(payload.image_a_base64) > 5 * 1024 * 1024 or len(payload.image_b_base64) > 5 * 1024 * 1024:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Image payload too large")
    try:
        clean_a = payload.image_a_base64.split(",", 1)[1] if "," in payload.image_a_base64 else payload.image_a_base64
        clean_b = payload.image_b_base64.split(",", 1)[1] if "," in payload.image_b_base64 else payload.image_b_base64
        bytes_a = base64.b64decode(clean_a)
        bytes_b = base64.b64decode(clean_b)

        has_face_a, has_face_b, similarity, is_duplicate, remarks = await asyncio.to_thread(
            face_registry.engine.compare_two_images,
            bytes_a,
            bytes_b
        )
        return FaceLabCompareResponse(
            has_face_a=has_face_a,
            has_face_b=has_face_b,
            similarity_score=similarity,
            is_duplicate=is_duplicate,
            remarks=remarks
        )
    except Exception as e:
        # R5 (review §5 honesty): failures are server errors, not a pretend
        # 200 carrying an error string in remarks.
        logger.error(f"[Face Lab] compare failed: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Image comparison failed")

