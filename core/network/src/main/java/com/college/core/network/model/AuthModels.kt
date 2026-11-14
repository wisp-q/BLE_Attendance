package com.college.core.network.model

import com.google.gson.annotations.SerializedName

data class LoginRequest(
    val email: String,
    val password: String
)

data class LoginResponse(
    @SerializedName("requires_otp") val requiresOtp: Boolean = true,
    val message: String,
    val email: String,
    @SerializedName("access_token") val accessToken: String? = null,
    @SerializedName("token_type") val tokenType: String? = "bearer",
    val user: UserResponse? = null
)

data class VerifyOtpRequest(
    val email: String,
    @SerializedName("otp_code") val otpCode: String
)

data class ResendOtpRequest(
    val email: String,
    val purpose: String = "LOGIN"
)

data class OtpSentResponse(
    val message: String,
    val email: String,
    @SerializedName("expires_in_seconds") val expiresInSeconds: Int = 600,
    @SerializedName("requires_otp") val requiresOtp: Boolean = true
)

data class RegisterRequest(
    val name: String,
    val email: String,
    val password: String,
    val role: String,
    @SerializedName("roll_number") val rollNumber: String,
    val department: String,
    val program: String? = null,
    val semester: Int? = null,
    val section: String? = null,
    @SerializedName("faculty_code") val facultyCode: String? = null
)

data class UserResponse(
    val id: String,
    val name: String,
    val email: String,
    val role: String,
    @SerializedName("roll_number") val rollNumber: String? = null,
    val department: String? = null,
    val program: String? = null,
    val semester: Int? = null,
    val section: String? = null,
    // F3: XP/level triple for the trainer card. Defaults keep legacy cached
    // user JSON (no game_* keys) parseable after an app update.
    @SerializedName("game_xp") val gameXp: Int = 0,
    @SerializedName("game_level") val gameLevel: Int = 1,
    @SerializedName("game_xp_progress") val gameXpProgress: Float = 0f
)

data class TokenResponse(
    @SerializedName("access_token") val accessToken: String,
    @SerializedName("token_type") val tokenType: String,
    val user: UserResponse
)
