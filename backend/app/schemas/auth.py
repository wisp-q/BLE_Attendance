from typing import Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, field_validator


# Normalizes email address by trimming whitespace and lowercasing
def _normalize_email(val: Optional[str]) -> Optional[str]:
    if isinstance(val, str):
        return val.strip().lower()
    return val


# Request payload for user self-registration
class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=6)
    role: str = Field(default="STUDENT", description="STUDENT, TEACHER, or STAFF")
    roll_number: str = Field(..., min_length=2, max_length=50)
    department: str = Field(..., description="Academic department (e.g. CSE, CIVIL)")
    program: Optional[str] = Field(None, description="B.Tech or BCA")
    semester: Optional[int] = Field(None, ge=1, le=8)
    section: Optional[str] = Field(None, max_length=10)
    faculty_code: Optional[str] = Field(None, description="Faculty registration passcode")

    # Normalizes email address
    @field_validator("email", mode="before")
    @classmethod
    def clean_email(cls, v: str) -> str:
        return _normalize_email(v) or v

    # Normalizes roll number
    @field_validator("roll_number", mode="before")
    @classmethod
    def clean_roll_number(cls, v: str) -> str:
        if isinstance(v, str):
            return v.strip().upper()
        return v


# Request payload for logging in
class LoginRequest(BaseModel):
    email: str
    password: str

    # Normalizes email address
    @field_validator("email", mode="before")
    @classmethod
    def clean_email(cls, v: str) -> str:
        return _normalize_email(v) or v


# Public user response
class UserResponse(BaseModel):
    id: UUID
    name: str
    email: str
    role: str
    roll_number: Optional[str] = None
    department: Optional[str] = None
    program: Optional[str] = None
    semester: Optional[int] = None
    section: Optional[str] = None
    # F3: XP/level triple for the Pokemon trainer card. game_level and
    # game_xp_progress are derived here — the DB stores lifetime game_xp only.
    game_xp: int = 0
    game_level: int = 1
    game_xp_progress: float = 0.0

    model_config = ConfigDict(from_attributes=True)


# Token response with bearer token and user object
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# Request payload for verifying an email OTP
class VerifyOtpRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    otp_code: str = Field(..., min_length=4, max_length=10)

    # Normalizes email address
    @field_validator("email", mode="before")
    @classmethod
    def clean_email(cls, v: str) -> str:
        return _normalize_email(v) or v

    # Strips whitespace from OTP code
    @field_validator("otp_code", mode="before")
    @classmethod
    def clean_otp(cls, v: str) -> str:
        if isinstance(v, str):
            return v.strip()
        return v


# Request payload for resending an OTP code
class ResendOtpRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    purpose: str = Field(default="LOGIN", description="LOGIN or REGISTER")

    # Normalizes email address
    @field_validator("email", mode="before")
    @classmethod
    def clean_email(cls, v: str) -> str:
        return _normalize_email(v) or v


# Generic response when OTP is dispatched
class OtpSentResponse(BaseModel):
    message: str
    email: str
    expires_in_seconds: int = 600
    requires_otp: bool = True


# Flexible login response returning either an OTP requirement or session token directly
class LoginResponse(BaseModel):
    requires_otp: bool = True
    message: str = "Verification code sent to your email"
    email: str
    access_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    user: Optional[UserResponse] = None
