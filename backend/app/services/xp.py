"""F3 XP/level system for the chimp memory game (docs/f3_xp_levels.md).

Single home of every F3 tunable: level table, XP caps, gain/pass fractions
and the gain curve. Logic elsewhere must import from here — never restate
these numbers.

Design summary:
- Level 1 is the current game (rounds 5/6/7/8, max 26). Each level adds +1 to
  every round's count up to level 5 (9/10/11/12, max 42; grid is 4x4 = 16).
- Gain threshold: score >= ceil(GAIN_FRACTION * max) qualifies for XP
  (level 1 -> 24, the user's original "24 or more /26").
- Pass threshold: max(PASS_FLOOR, ceil(PASS_FRACTION * max)) — scales so the
  gate never becomes trivially easy as grids grow (future_plans.md F3 rule 1).
- Gain curve (user formula): threshold score earns XP_BASE + level *
  XP_LEVEL_STEP; the max earns +XP_SPAN bonus; linear between. Lifetime XP
  accumulates; caps to leave a level are LEVEL_CAPS (1000 x level).
"""

import math

# Achievable chimp score per level (sum of the 4 round counts).
LEVEL_MAX_SCORES = [26, 30, 34, 38, 42]

# XP required to leave each level (1000 x level). Level 5 is the cap.
LEVEL_CAPS = [1000, 2000, 3000, 4000]

# Cumulative XP at which each level begins (prefix sums of LEVEL_CAPS;
# the last entry is where the level-5 cap band starts, 10000 total).
CUMULATIVE_ENTRIES = [0, 1000, 3000, 6000, 10000]

# Qualify for XP at ceil(0.9 x max) of the level's achievable score.
GAIN_FRACTION = 0.9

# Pass the attendance gate at ceil(0.5 x max), floored at today's 15.
PASS_FRACTION = 0.5
PASS_FLOOR = 15

# Gain curve: threshold -> 50 + level*10; max -> +20 more; linear between.
XP_BASE = 50
XP_LEVEL_STEP = 10
XP_SPAN = 20


def level_for_xp(xp: int) -> int:
    """1-based level for a lifetime XP total; caps at 5."""
    level = 1
    for entry in CUMULATIVE_ENTRIES:
        if xp >= entry:
            level = CUMULATIVE_ENTRIES.index(entry) + 1
    return level


def level_max(level: int) -> int:
    """Achievable chimp score at the given 1-based level."""
    return LEVEL_MAX_SCORES[min(max(level, 1), len(LEVEL_MAX_SCORES)) - 1]


def gain_threshold(level: int) -> int:
    """Minimum score that earns XP at this level (ceil 90% of max)."""
    return math.ceil(GAIN_FRACTION * level_max(level))


def pass_threshold(level: int) -> int:
    """Minimum score that keeps VERIFIED_PRESENT at this level (floor 15)."""
    return max(PASS_FLOOR, math.ceil(PASS_FRACTION * level_max(level)))


def xp_gain(level: int, score: int) -> int:
    """XP earned for a session score at the given level; 0 below threshold."""
    max_score = level_max(level)
    clamped = min(score, max_score)
    threshold = gain_threshold(level)
    if clamped < threshold:
        return 0
    base = XP_BASE + level * XP_LEVEL_STEP
    span = max_score - threshold
    fraction = (clamped - threshold) / span if span > 0 else 1.0
    return round(base + XP_SPAN * fraction)


def xp_progress(xp: int, level: int) -> float:
    """Band progress 0..1 for the profile-card bar; 1.0 at the level cap."""
    if level >= len(LEVEL_CAPS) + 1:
        return 1.0
    entry = CUMULATIVE_ENTRIES[level - 1]
    cap = LEVEL_CAPS[level - 1]
    return max(0.0, min(1.0, (xp - entry) / cap))


async def award_xp_for_session(db, session_obj) -> int:
    """Award XP for this session's VERIFIED_PRESENT records.

    One award per record, guarded by AttendanceRecord.xp_awarded so finalize
    replays and re-scans never double-pay. Spoofed, unverified and leave rows
    never qualify (status filter); teacher manual overrides are deliberately
    excluded — they grant attendance, not skill XP. Returns total XP granted.
    """
    from sqlalchemy import select

    from app.models.attendance import AttendanceRecord, User

    res = await db.execute(
        select(AttendanceRecord).where(
            AttendanceRecord.session_id == session_obj.id,
            AttendanceRecord.status == "VERIFIED_PRESENT",
            AttendanceRecord.xp_awarded.is_(False),
            AttendanceRecord.student_id.is_not(None),
            AttendanceRecord.game_score.is_not(None),
        )
    )
    eligible = res.scalars().all()
    if not eligible:
        return 0

    user_ids = {rec.student_id for rec in eligible}
    users = {
        u.id: u
        for u in (await db.execute(select(User).where(User.id.in_(user_ids)))).scalars().all()
    }

    granted = 0
    for rec in eligible:
        user = users.get(rec.student_id)
        if user is None:
            continue
        # Level at award time = the level the student played at (levels only
        # advance at finalize, so this is the played level, not post-award).
        gain = xp_gain(level_for_xp(user.game_xp), rec.game_score)
        if gain <= 0:
            continue
        user.game_xp += gain
        rec.xp_awarded = True
        granted += gain
    return granted
