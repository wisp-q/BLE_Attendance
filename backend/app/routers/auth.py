import asyncio
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import (
    DUMMY_BCRYPT_HASH,
    create_access_token,
    get_current_user,
    hash_password,
    limiter_ip,
    verify_password,
)
from app.database import get_db
from app.models.attendance import EmailOTP, User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    OtpSentResponse,
    RegisterRequest,
    ResendOtpRequest,
    TokenResponse,
    UserResponse,
    VerifyOtpRequest,
)
from app.services.xp import level_for_xp, xp_progress
from app.services.email import dispatch_otp_email, generate_otp
from app.services.rate_limiter import (
    login_email_limiter,
    login_ip_limiter,
    otp_resend_email_limiter,
    otp_resend_ip_limiter,
    register_email_limiter,
    register_ip_limiter,
)

router = APIRouter(prefix="/auth", tags=["Auth"])


# Ensure datetime is timezone-aware UTC
def ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# Convert User model instance to UserResponse schema
def _to_user_response(user: User) -> UserResponse:
    level = level_for_xp(user.game_xp)
    return UserResponse(
        id=user.id,
        name=user.full_name,
        email=user.email,
        role=user.role,
        roll_number=user.roll_number,
        department=user.department,
        program=user.program,
        semester=user.semester,
        section=user.section,
        game_xp=user.game_xp,
        game_level=level,
        game_xp_progress=xp_progress(user.game_xp, level),
    )


# Initiate registration and send email OTP
@router.post(
    "/register",
    response_model=OtpSentResponse,
    status_code=status.HTTP_200_OK,
)
async def register_send_otp(
    payload: RegisterRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Registration budgets: the endpoint is unauthenticated and dispatches a
    # real email on every call, so without this it is a free inbox-bombing and
    # Brevo-plan-burn vector. Per-mailbox cap bounds flooding of one victim;
    # per-IP is a generous onboarding floor (whole classroom behind one NAT).
    # IP is checked FIRST: a pass on the email limiter records a stamp, so
    # checking the abundant per-day IP budget first keeps a denied request
    # from consuming a scarce per-mailbox slot.
    email = payload.email.strip().lower()
    client_ip = limiter_ip(request)
    if not await register_ip_limiter.check(client_ip) or not await register_email_limiter.check(email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later.",
        )

    # Validate requested role
    normalized_role = payload.role.strip().upper()
    if normalized_role not in ["STUDENT", "TEACHER", "STAFF"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role must be STUDENT, TEACHER, or STAFF",
        )

    # Enforce faculty or staff registration passcode
    if normalized_role in ["TEACHER", "STAFF"]:
        # H2/L7 (audit): constant-time compare — matches the OTP pattern.
        if not secrets.compare_digest(payload.faculty_code or "", settings.FACULTY_SIGNUP_SECRET):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid faculty or staff registration passcode",
            )

    # Reject common email typo domains
    email_clean = payload.email.strip().lower()
    if "@mgail.com" in email_clean or "@gamil.com" in email_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Did you mean @gmail.com? Please check your email address spelling.",
        )

    # Check if email or roll number is already registered
    existing = await db.execute(
        select(User).where(
            or_(User.email == payload.email, User.roll_number == payload.roll_number)
        )
    )
    if existing.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email or roll number already registered",
        )

    # Cooldown between registration codes for one mailbox (mirrors resend):
    # bounds Brevo dispatch rate beyond the count budget.
    recent = await db.execute(
        select(EmailOTP)
        .where(EmailOTP.email == email, EmailOTP.purpose == "REGISTER")
        .order_by(EmailOTP.created_at.desc())
    )
    last_otp = recent.scalars().first()
    if last_otp:
        elapsed = (datetime.now(timezone.utc) - ensure_utc(last_otp.created_at)).total_seconds()
        if elapsed < 45:
            wait_time = int(45 - elapsed)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {wait_time}s before requesting a new code.",
            )

    # Generate 6-digit OTP and expiration
    otp_code = generate_otp()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    # Package temporary registration details
    temp_data = {
        "name": payload.name.strip(),
        "email": payload.email.strip().lower(),
        "hashed_password": await asyncio.to_thread(hash_password, payload.password),
        "roll_number": payload.roll_number.strip(),
        "role": normalized_role,
        "department": payload.department.strip() if payload.department else None,
        "program": payload.program.strip() if payload.program else None,
        "semester": payload.semester,
        "section": payload.section.strip() if payload.section else None,
    }

    # Delete prior registration OTPs for this email in bulk
    await db.execute(
        delete(EmailOTP).where(
            EmailOTP.email == payload.email.strip().lower(),
            EmailOTP.purpose == "REGISTER",
        )
    )

    # Save new OTP with registration payload
    new_otp = EmailOTP(
        id=uuid.uuid4(),
        email=payload.email.strip().lower(),
        otp_code=otp_code,
        purpose="REGISTER",
        temp_payload=temp_data,
        attempts=0,
        expires_at=expires_at,
    )
    db.add(new_otp)
    await db.commit()

    # Dispatch verification email in background
    background_tasks.add_task(dispatch_otp_email, payload.email.strip().lower(), otp_code, purpose="REGISTER")

    return OtpSentResponse(
        message=f"Verification code sent to {payload.email}",
        email=payload.email.strip().lower(),
        expires_in_seconds=settings.OTP_EXPIRE_MINUTES * 60,
        requires_otp=True,
    )


# Verify registration OTP and create user account
@router.post(
    "/register/verify-otp",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_verify_otp(
    payload: VerifyOtpRequest,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.strip().lower()
    now = datetime.now(timezone.utc)

    # Find latest registration OTP record
    result = await db.execute(
        select(EmailOTP)
        .where(EmailOTP.email == email, EmailOTP.purpose == "REGISTER")
        .order_by(EmailOTP.created_at.desc())
    )
    otp_record = result.scalars().first()

    # Validate OTP record and expiration
    if not otp_record or now > ensure_utc(otp_record.expires_at):
        if otp_record:
            await db.delete(otp_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code is invalid or has expired. Please request a new code.",
        )

    # Enforce attempt rate limit
    if otp_record.attempts >= 5:
        await db.delete(otp_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many incorrect attempts. Please request a new code.",
        )

    # Check submitted OTP code against stored code using constant-time comparison
    # (encoded to bytes so non-ASCII input can't raise TypeError inside compare_digest)
    if not secrets.compare_digest(otp_record.otp_code.encode(), payload.otp_code.strip().encode()):
        otp_record.attempts += 1
        await db.commit()
        remaining = 5 - otp_record.attempts
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incorrect verification code ({remaining} attempts remaining).",
        )

    # R4 (review §3.1): two pending registrations of the same account can both
    # pass the send-OTP pre-check (it only sees committed users) and race into
    # verify — the loser would hit the unique constraints and 500. Re-check at
    # insert time with a precise conflict, consuming the now-void OTP record.
    data = otp_record.temp_payload or {}
    reg_email = (data.get("email", email) or "").strip().lower()
    reg_roll = data.get("roll_number")
    dup_query = select(User).where(User.email == reg_email)
    if reg_roll:
        dup_query = select(User).where(or_(User.email == reg_email, User.roll_number == reg_roll))
    if (await db.execute(dup_query)).scalars().first():
        await db.delete(otp_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email or roll number is already registered",
        )
    new_user = User(
        id=uuid.uuid4(),
        email=data.get("email", email),
        hashed_password=data["hashed_password"],
        full_name=data["name"],
        roll_number=data.get("roll_number"),
        role=data.get("role", "STUDENT"),
        department=data.get("department"),
        program=data.get("program"),
        semester=data.get("semester"),
        section=data.get("section"),
    )
    db.add(new_user)
    await db.delete(otp_record)
    try:
        await db.commit()
    except IntegrityError:
        # Belt-and-braces for the TOCTOU gap the pre-check cannot see
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email or roll number is already registered",
        )
    await db.refresh(new_user)

    # Generate JWT access token
    token_data = {
        "sub": str(new_user.id),
        "name": new_user.full_name,
        "role": new_user.role,
        "roll_number": new_user.roll_number,
        "tv": new_user.token_version or 0,
    }
    token = create_access_token(data=token_data)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=_to_user_response(new_user),
    )


# Verify password and send two-factor OTP
@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    payload: LoginRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.strip().lower()

    # Two-layer rate limit (review §1.2.1). Per-account: throttles online
    # password guessing of a single mailbox; attempts count regardless of
    # success — that is the point. Per-gateway floor: calibrated far above a
    # whole classroom logging in through one shared NAT address, so genuine
    # students never trip it (budget rationale in services/rate_limiter.py).
    # IP keyed on CF-Connecting-IP (edge-controlled; XFF is spoofable — see
    # limiter_ip). Attempts count regardless of success — that is the point.
    client_ip = limiter_ip(request)
    if not await login_email_limiter.check(email) or not await login_ip_limiter.check(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again shortly.",
        )

    # Look up user by email and verify password
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()
    # Unknown emails burn a full bcrypt check against a dummy hash so response
    # latency cannot reveal whether the mailbox exists (timing enumeration).
    # bcrypt itself is offloaded to a worker thread — it must never block the
    # event loop that every concurrent submit in the classroom waits on.
    pw_hash = user.hashed_password if user else DUMMY_BCRYPT_HASH
    password_ok = await asyncio.to_thread(verify_password, payload.password, pw_hash)
    if not user or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Generate 2FA OTP code and expiration
    otp_code = generate_otp()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    # Delete prior login OTPs in bulk
    await db.execute(
        delete(EmailOTP).where(
            EmailOTP.email == email,
            EmailOTP.purpose == "LOGIN",
        )
    )

    # Save new login OTP record
    new_otp = EmailOTP(
        id=uuid.uuid4(),
        email=email,
        otp_code=otp_code,
        purpose="LOGIN",
        attempts=0,
        expires_at=expires_at,
    )
    db.add(new_otp)
    await db.commit()

    # Dispatch 2FA email in background
    background_tasks.add_task(dispatch_otp_email, email, otp_code, purpose="LOGIN")

    return LoginResponse(
        requires_otp=True,
        message=f"Two-factor verification code sent to {email}",
        email=email,
    )


# Verify two-factor login OTP and issue token
@router.post("/login/verify-otp", response_model=TokenResponse)
async def login_verify_otp(
    payload: VerifyOtpRequest,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.strip().lower()
    now = datetime.now(timezone.utc)

    # Find latest login OTP record
    result = await db.execute(
        select(EmailOTP)
        .where(EmailOTP.email == email, EmailOTP.purpose == "LOGIN")
        .order_by(EmailOTP.created_at.desc())
    )
    otp_record = result.scalars().first()

    # Validate OTP record and expiration
    if not otp_record or now > ensure_utc(otp_record.expires_at):
        if otp_record:
            await db.delete(otp_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code is invalid or has expired. Please request a new code.",
        )

    # Enforce attempt rate limit
    if otp_record.attempts >= 5:
        await db.delete(otp_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many incorrect attempts. Please request a new code.",
        )

    # Check submitted OTP code against stored code using constant-time comparison
    # (encoded to bytes so non-ASCII input can't raise TypeError inside compare_digest)
    if not secrets.compare_digest(otp_record.otp_code.encode(), payload.otp_code.strip().encode()):
        otp_record.attempts += 1
        await db.commit()
        remaining = 5 - otp_record.attempts
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incorrect verification code ({remaining} attempts remaining).",
        )

    # Remove verified OTP record
    await db.delete(otp_record)
    await db.commit()

    # Look up authenticated user
    u_res = await db.execute(select(User).where(User.email == email))
    user = u_res.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Generate access token
    token_data = {
        "sub": str(user.id),
        "name": user.full_name,
        "role": user.role,
        "roll_number": user.roll_number,
        "tv": user.token_version or 0,
    }
    token = create_access_token(data=token_data)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=_to_user_response(user),
    )


# Resend OTP with cooldown check
@router.post("/otp/resend", response_model=OtpSentResponse)
async def resend_otp(
    request: Request,
    payload: ResendOtpRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.strip().lower()
    purpose = payload.purpose.strip().upper()
    now = datetime.now(timezone.utc)

    # M1 (security audit): purpose is client-supplied — an arbitrary string
    # would open a fresh (email, purpose) row, bypassing the 45s cooldown and
    # dispatching free SMTP to any address. Only the two real purposes may pass.
    if purpose not in ("REGISTER", "LOGIN"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid OTP purpose.",
        )

    # M1 (audit): the endpoint is unauthenticated, so budgets live here —
    # per-mailbox cap (inbox bombing / Brevo plan burning on one victim) and a
    # generous per-IP floor calibrated like login's: a shared campus NAT must
    # survive a burst of legitimate resends, so the IP layer only stops
    # distributed spraying. Rejected 429 attempts do not consume budget.
    client_ip = limiter_ip(request)
    if not await otp_resend_email_limiter.check(email) or not await otp_resend_ip_limiter.check(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many code requests. Please try again later.",
        )

    # Check recent OTP to enforce 45s cooldown
    recent = await db.execute(
        select(EmailOTP)
        .where(EmailOTP.email == email, EmailOTP.purpose == purpose)
        .order_by(EmailOTP.created_at.desc())
    )
    last_otp = recent.scalars().first()
    if last_otp:
        elapsed = (now - ensure_utc(last_otp.created_at)).total_seconds()
        if elapsed < 45:
            wait_time = int(45 - elapsed)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {wait_time}s before requesting a new code.",
            )

    # Generate new OTP code
    otp_code = generate_otp()
    expires_at = now + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    # Update existing OTP record or create new one
    if last_otp:
        last_otp.otp_code = otp_code
        # M1: do NOT zero attempts here — the 5-wrong-tries budget must survive
        # resends, otherwise an attacker refreshes it every 45s cooldown tick.
        # A user who mistyped still gets a fresh correct code with the
        # remaining budget until expiry.
        last_otp.expires_at = expires_at
        last_otp.created_at = now
    else:
        new_otp = EmailOTP(
            id=uuid.uuid4(),
            email=email,
            otp_code=otp_code,
            purpose=purpose,
            attempts=0,
            expires_at=expires_at,
        )
        db.add(new_otp)

    await db.commit()

    # Dispatch email in background
    background_tasks.add_task(dispatch_otp_email, email, otp_code, purpose=purpose)

    return OtpSentResponse(
        message=f"New verification code sent to {email}",
        email=email,
        expires_in_seconds=settings.OTP_EXPIRE_MINUTES * 60,
        requires_otp=True,
    )


# Retrieve profile of current authenticated user
@router.get("/me", response_model=UserResponse)
async def get_my_profile(current_user: User = Depends(get_current_user)):
    return _to_user_response(current_user)


# R7: server-side logout. Bumps the account's token_version so EVERY token
# ever issued for this user — including the caller's — is rejected from the
# next request on. The next successful login issues a token at the new
# version, so logout never locks the account out. (Client-side token deletion
# alone left "logged out" tokens valid until expiry; a stolen device copy of
# the token keeps a live session today.)
@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_user.token_version = (current_user.token_version or 0) + 1
    await db.commit()
    return {"status": "logged_out"}

