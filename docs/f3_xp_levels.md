# F3 — XP & Level System for the Chimp Memory Game

Status: approved (rev 2 — XP curve revised per user, 2026-11-14)
Date: 2026-11-14
Owner: F3 from `docs/future_plans.md` (user proposal + doc hard rules reconciled)

## Goal

Reward students for playing the chimp memory game near-perfectly with an
XP/level system styled after Pokemon:

- XP is earned when a session's chimp score is near the achievable maximum.
- Level is shown on the profile card (Pokemon trainer card) as a level pill and
  an XP progress bar.
- Level scales the game's difficulty: higher levels see more numbers per round.
- All XP/level state lives server-side, consistent with `future_plans.md` §F3
  hard rule #2 ("client-derived config is forgeable").

## Non-goals (explicitly out of scope for v1)

- Per-round telemetry retention and server-side validation of round sequences
  (the doc's open question — score remains client-attested, same trust level as
  today's ≥15 gate).
- Personal-baseline anomaly detection (doc's F3 "cheat-detection unlock" — the
  level history this feature creates is its groundwork).
- Demotion logic. Bad days simply earn no XP; a student is never trapped
  (doc's "or hold" branch).
- Term reset of XP (doc open question — default: XP is lifetime).
- Any change to the ultrasonic/HOD-Leave surfaces (P0 guardrail).

## Current state (verified)

- Round counts are fixed in `ChimpGridGame.kt:81-86`: rounds give 5/6/7/8
  numbers, achievable max = 26. The user's "24 or more /26" is exactly the
  current game at level 1.
- Score flow: client computes score and sends it as `x-game-score` header
  (`routers/attendance.py:1401`); server gates `VERIFIED_PRESENT` at a fixed
  `score >= 15` (sites at lines 1328, 1598, 1766, 2060).
- `main.py:25-34` already schema-syncs `users` with
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` — the established migration
  pattern.
- `/auth/me` (`routers/auth.py:540`) returns `UserResponse`
  (`schemas/auth.py:54`), mapped by `_to_user_response` (auth.py:52) into the
  client `User` DTO (`core/model/User.kt`) via SessionManager.
- `PokemonTrainerCard` (`core/ui/.../AppComponents.kt:232-419`) is already
  Pokemon-styled with a semester badge row; the XP bar slots in above it.

## Design

### Data model

One new column, level is derived (no dual source of truth):

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS game_xp INTEGER NOT NULL DEFAULT 0;
```

- Added to the existing schema-sync block in `main.py` (same pattern as
  `token_version`).
- ORM: `User.game_xp` (`models/attendance.py`), `Integer`, NOT NULL, default 0.
- `level_for_xp(xp)` derives the level from the cap table below.

### Level table (user's table, verified feasible)

Grid is 4×4 = 16 cells; every count fits.

| Level | Rounds | Max | XP-gain score (ceil 90%) | Pass gate (ceil 50%, floor 15) |
|-------|-----------|----|--------------------------|-------------------------------|
| 1 | 5-6-7-8 | 26 | 24 | 15 |
| 2 | 6-7-8-9 | 30 | 27 | 15 |
| 3 | 7-8-9-10 | 34 | 31 | 17 |
| 4 | 8-9-10-11 | 38 | 35 | 19 |
| 5 | 9-10-11-12 | 42 | 38 | 21 |

Notes:

- Level 1 is bit-for-bit the current game, so existing tests and honest level-1
  players are unaffected.
- The pass gate scales per the doc's hard rule #1 ("fixed 15 against larger
  counts would fail honest weak students" is the stated concern; the table uses
  ceil(50% of achievable) with a floor of 15, which reproduces today's 15 for
  levels 1-2 exactly).
- The XP-gain threshold generalizes the user's "≥24/26": score ≥
  ceil(0.9 × level max). At level 1 this is exactly 24.
- Level 5 is the cap. Beyond it XP still accumulates (lifetime total), the bar
  shows MAX.

### XP gain and caps (user-specified formula, 2026-11-14 revision)

User's formula: XP when the score hits the level's gain threshold =
`50 + (level × 10)`; bonus at the level max = +20. Generalized as a linear
ramp between the level's gain threshold and its max:

```
xp_gain = round((50 + level * 10) + 20 * (score - gain_thr) / (max - gain_thr))
```

Level 1: 24 → 60, 25 → 70, 26 → 80 (user's anchors: 60 at score 24, +20 bonus
at the max of 26). At any level: qualifying score → 50 + level×10, max → 20
more. This replaces the earlier approved draft (caps [1000, 1500, 2200, 3000]
with a gain×level multiplier) wholesale.

Caps are `1000 × level` (user-specified):

| Level band | Cap to leave level | Cumulative XP at level entry |
|------------|--------------------|------------------------------|
| 1 → 2 | 1000 | 0 |
| 2 → 3 | 2000 | 1000 |
| 3 → 4 | 3000 | 3000 |
| 4 → 5 | 4000 | 6000 |
| 5 (cap) | — | 10000 |

Pacing (honest math): a qualifying session at level L earns 50+10L to 70+10L
XP. Per band that is roughly 13-17 near-perfect sessions (L1), 22-29 (L2),
30-38 (L3), 36-44 (L4); the full ladder is ~100-128 near-perfect sessions —
a whole-degree progression, consistent with the doc's "honest students develop
skill slowly over the term" intent. With ~30-40 class sessions per term and
only near-perfect sessions paying, expect roughly one level-up per term for a
consistent student.

All constants (thresholds, caps, base 50, level step 10, span 20) live in one
module so the curve can be retuned without touching logic.

### Award placement and idempotency

- XP is awarded inside the same code paths that flip an attendance record to
  `VERIFIED_PRESENT` (`routers/attendance.py`: staged finalize ~line 1293,
  teacher bulk confirm ~1840, in-flight grace rescue ~1790). A spoofed or
  unverified session never pays XP.
- A single helper (`app/services/xp.py`, new) does: level lookup for the
  student, score clamp to `min(score, level max)`, gain-threshold check, XP
  computation, `UPDATE users SET game_xp = game_xp + :gain`.
- Idempotency: award only on *transition* into `VERIFIED_PRESENT` (previous
  status was not already `VERIFIED_PRESENT`). The existing per-session unique
  constraint `(session_id, student_id)` plus this guard prevents double awards
  from repeated submissions/finalize replays.
- Accepted v1 simplification: if a record is later downgraded by audit, XP is
  not clawed back. Documented as known behavior.

### Pass-gate change

The four fixed `< 15` comparisons (`routers/attendance.py:1328, 1598, 1766,
2060`) become `score < pass_threshold(student_level)`, with the student's level
looked up from `users` at the gate site. Levels 1-2 keep threshold 15, so
today's behavior is preserved for the default population.

### API / DTO changes

- `UserResponse` (`schemas/auth.py`) gains `game_xp: int` and
  `game_level: int`; `_to_user_response` computes the level via the xp service.
- Client `User` DTO (`core/model/User.kt`) gains `gameXp: Int = 0` and
  `gameLevel: Int = 1` (defaults keep old cached payloads parseable), mapped in
  SessionManager/AuthRepository.

### Client changes

- `PokemonTrainerCard`: for STUDENT users, a row between the info block and the
  badge row — "Lv N" pill + progress bar (band progress = xp − cumulative entry
  ÷ band cap), styled to the existing monospace/rounded theme. Non-students
  show nothing (no game → no bar).
- `ChimpGridGame` gains `level: Int = 1`:
  - `countForRound(round, level)` per the table above.
  - `viewWindowMs`/`tapWindowMs` extended for counts 9-12 with new explicit
    constants (the current `when(n)` else-branch silently reuses R4 windows;
    larger grids need their own, tunable, values).
  - `possibleSoFar` (mood HUD, line 592) updated for the level-aware counts.
- `StudentSection.kt` passes the level from the session's `User` object. Score
  submission path is unchanged (the header already carries the score).
- Profile freshness: the card shows XP as of the last `/auth/me` fetch (app
  start). XP earned in today's class appears on next launch/refresh — same
  freshness model as the rest of the card.

### Trust boundary (honesty note)

The score is client-attested today (header); XP inherits that trust level. A
modified APK can claim high scores — this is pre-existing behavior, not made
worse by XP. Server-side clamping to level max and the level-aware pass gate
bound the damage. The real fix (round-sequence telemetry validated against the
seed-derived schedule) is the doc's parked open question and is explicitly out
of scope here.

## Edge cases

- New student: xp 0 → level 1 → exactly today's game and gate. (Answers the
  doc's "minimum history" open question.)
- Grace-window path: rescue to VERIFIED_PRESENT awards XP normally.
- Teacher manual confirm with NULL game_score: no XP (gain requires a score).
- Repeated submissions / re-finalize: transition guard, no double award.
- Score above level max (modded client): clamped to level max before any
  comparison.

## Test plan

- Unit (`tests/`): `level_for_xp` band boundaries; gain formula (24→50, 26→70,
  clamp at max); pass thresholds per level; award idempotency (double finalize
  pays once); score clamping.
- Router: finalize awards XP for a qualifying score; non-qualifying score pays
  nothing; spoofed re-submission doesn't double-pay; level-aware gate accepts
  15 at level 1 and rejects 16 at level 3 (17 required).
- API: `/auth/me` includes `game_xp`/`game_level`.
- Regression: full existing suite (87 tests) stays green — level 1 behavior is
  unchanged by construction.

## Tunables (single module: `backend/app/services/xp.py`)

| Constant | Value | Meaning |
|---|---|---|
| `LEVEL_MAX_SCORES` | [26, 30, 34, 38, 42] | achievable per level |
| `LEVEL_CAPS` | [1000, 2000, 3000, 4000] | XP to leave each level (1000 × level) |
| `GAIN_FRACTION` | 0.9 | qualify at ceil(0.9 × max) |
| `PASS_FRACTION` | 0.5 | pass at ceil(0.5 × max) |
| `PASS_FLOOR` | 15 | minimum pass score |
| `XP_BASE` / `XP_LEVEL_STEP` / `XP_SPAN` | 50 / 10 / 20 | gain = (50 + level×10) at threshold, +20 at max, linear between |
