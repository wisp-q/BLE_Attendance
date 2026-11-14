package com.college.core.model

data class User(
    val id: String,
    val name: String,
    val email: String,
    val roles: Set<Role>,
    val avatarUrl: String? = null,
    val rollNumber: String? = null,
    val department: String? = null,
    val year: String? = null,
    val program: String? = null,
    val semester: Int? = null,
    val section: String? = null,
    // F3: chimp-game XP/level from the server. Defaults match a fresh
    // account and keep Gson lenient over older cached payloads.
    val gameXp: Int = 0,
    val gameLevel: Int = 1,
    val gameXpProgress: Float = 0f
) {
    val primaryRole: Role? get() = roles.maxByOrNull { it.priority }

    fun hasRole(role: Role): Boolean = role in roles
    fun isDeveloper(): Boolean = roles.any { it.isDeveloper() }
    fun canAccessStaffTools(): Boolean = roles.any { it.canAccessStaffTools() }
    fun canTakeAttendance(): Boolean = roles.any { it.canTakeAttendance() }
}
