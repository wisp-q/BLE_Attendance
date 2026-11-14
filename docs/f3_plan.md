# F3 — XP & Level System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Server-side XP/level system for the chimp memory game: XP awarded at finalize for near-perfect scores, level shown as a bar on the Pokemon trainer card, level scales per-round number counts.

**Architecture:** One new DB column (`users.game_xp`) plus one award flag (`attendance_records.xp_awarded`); level derived from a constants table in a new `app/services/xp.py`. XP is awarded by a single DB-scan helper called at the tail of the three endpoints that can produce `VERIFIED_PRESENT`. Pass gate becomes level-aware. Client reads xp/level from `/auth/me` and threads a `level` param into `ChimpGridGame`.

**Tech Stack:** FastAPI + SQLAlchemy async (existing patterns), Compose (existing theme), Gson on client.

**Spec:** `docs/f3_xp_levels.md` (approved design — read together with this plan; exact numbers below come from it)

## Global Constraints

- P0 guardrail: do NOT touch ultrasonic code paths or HOD/Leave workflows (`docs/finalized_changes.md`). The `[ULTRASONIC-DISABLED]` comment blocks in `routers/attendance.py` stay exactly as they are.
- All XP/level constants live ONLY in `backend/app/services/xp.py`. No duplicated tables client-side: client receives `game_xp_progress` (0..1) from the server.
- Level 1 must be bit-for-bit today's game and today's pass gate (floor 15): the existing 87-test suite stays green without modification to its assertions.
- Exact constants: `LEVEL_MAX_SCORES = [26, 30, 34, 38, 42]`, `LEVEL_CAPS = [1000, 2000, 3000, 4000]` (1000 × level), cumulative level-start entries `[0, 1000, 3000, 6000, 10000]`, `GAIN_FRACTION = 0.9`, `PASS_FRACTION = 0.5`, `PASS_FLOOR = 15`, gain base `50 + level * 10`, `XP_SPAN = 20` (user formula 2026-11-14: threshold score → `50 + level*10`, max score → `+20` bonus, linear between).
- Naming: backend snake_case (`game_xp`, `game_level`, `game_xp_progress`, `xp_awarded`), Kotlin camelCase with `@SerializedName` for the snake_case wire names.
- Backend tests run on `.venv` (CPython 3.12.14) from `backend/`: `.venv/bin/python -m pytest -q`. Android verification is compilation (`./gradlew :app:assembleDebug`), no Compose test infra exists in this repo.

## Review Focus

- Re-finalize double-award: a session finalized twice must pay XP once. Test: `test_finalize_double_award_guard` (Task 4).
- Spoofed score above the level max: clamp `score = min(score, level_max)` before gain. Test: `test_xp_gain_clamps_to_level_max` (Task 1).
- LEAVE overlay rows must never award (award scan runs after `_apply_approved_leave_overlay` and filters `status == "VERIFIED_PRESENT"`). Covered by placement anchors in Task 4; assert in `test_finalize_awards_xp_for_perfect_score` that a leave-covered student gains nothing.
- Old cached client user JSON without game fields: Gson must fall back to defaults (fields declared `= 0 / = 1 / = 0f`), no crash. Task 5 declares defaults; verify by compiling and parsing a legacy-shaped JSON string in a scratch check.
- Non-student accounts: no bar on the trainer card, level stays 1, award helper never sees them (no game → no record). Card check in Task 7; award filter in Task 4.

---

### Task 1: XP service (pure functions + unit tests)

**Files:**
- Create: `backend/app/services/xp.py`
- Test: `backend/tests/test_xp.py` (new file)

**Interfaces:**
- Produces (used by Tasks 2-4):
  - `LEVEL_MAX_SCORES: list[int]`, `LEVEL_CAPS: list[int]`, `CUMULATIVE_ENTRIES: list[int]` (module constants, values verbatim from Global Constraints)
  - `def level_for_xp(xp: int) -> int` — 1-based level; `xp >= CUMULATIVE_ENTRIES[k]` selects level k+1; caps at 5
  - `def level_max(level: int) -> int`
  - `def gain_threshold(level: int) -> int` — `ceil(GAIN_FRACTION * level_max(level))`
  - `def pass_threshold(level: int) -> int` — `max(PASS_FLOOR, ceil(PASS_FRACTION * level_max(level)))`
  - `def xp_gain(level: int, score: int) -> int` — clamps score to `level_max(level)`; returns 0 below `gain_threshold`; else `round((50 + level * 10) + XP_SPAN * (score - thr) / (max - thr))`
  - `def xp_progress(xp: int, level: int) -> float` — band progress 0..1; 1.0 at level 5

- [ ] **Step 1: Write failing tests in `backend/tests/test_xp.py`**

```python
from app.services.xp import (
    level_for_xp, level_max, gain_threshold, pass_threshold, xp_gain, xp_progress,
)

def test_level_for_xp_band_boundaries():
    assert level_for_xp(0) == 1
    assert level_for_xp(999) == 1
    assert level_for_xp(1000) == 2
    assert level_for_xp(2999) == 2
    assert level_for_xp(3000) == 3
    assert level_for_xp(5999) == 3
    assert level_for_xp(6000) == 4
    assert level_for_xp(10000) == 5
    assert level_for_xp(10**9) == 5

def test_gain_threshold_per_level():
    assert [gain_threshold(l) for l in range(1, 6)] == [24, 27, 31, 35, 38]

def test_pass_threshold_per_level():
    assert [pass_threshold(l) for l in range(1, 6)] == [15, 15, 17, 19, 21]

def test_xp_gain_level_1_matches_spec():
    assert xp_gain(1, 24) == 60
    assert xp_gain(1, 25) == 70
    assert xp_gain(1, 26) == 80
    assert xp_gain(1, 20) == 0      # below gain threshold
    assert xp_gain(1, 15) == 0      # passes gate but earns nothing

def test_xp_gain_clamps_to_level_max():
    assert xp_gain(1, 999) == 80    # spoofed overflow -> max -> 80
    assert xp_gain(3, 40) == 100    # max of level 3 is 34 -> 80 + 20

def test_xp_gain_base_scales_with_level():
    assert xp_gain(2, 27) == 70     # threshold: 50 + 2*10
    assert xp_gain(2, 30) == 90     # max: threshold gain + 20
    assert xp_gain(5, 38) == 100
    assert xp_gain(5, 42) == 120

def test_xp_progress_bands():
    assert xp_progress(0, 1) == 0.0
    assert xp_progress(1000, 2) == 0.0
    assert xp_progress(3000, 3) == 0.0
    assert xp_progress(999, 1) == 0.999
    assert xp_progress(7000, 4) == 0.25
    assert xp_progress(10**9, 5) == 1.0
```

- [ ] **Step 2: Run to verify failure**

Run: `cd /home/wink/Projects/ble_attendance/backend && .venv/bin/python -m pytest tests/test_xp.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.xp'`

- [ ] **Step 3: Implement `backend/app/services/xp.py`**

Module docstring states it is the single home of all F3 tunables (per Global Constraints). `math.ceil` for thresholds; `xp_progress` clamps to `[0.0, 1.0]`. Level cap 5 everywhere (`min(level, 5)`).

- [ ] **Step 4: Run to verify pass**

Run: `cd /home/wink/Projects/ble_attendance/backend && .venv/bin/python -m pytest tests/test_xp.py -q`
Expected: PASS (all)

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/xp.py backend/tests/test_xp.py
git commit -m "feat(xp): F3 xp service with level thresholds and gain curve"
```

---

### Task 2: DB columns, schema-sync, `/auth/me` fields

**Files:**
- Modify: `backend/app/models/attendance.py` — `User` gains `game_xp` (Integer, nullable=False, default 0, server_default "0") after `token_version`; `AttendanceRecord` gains `xp_awarded` (Boolean, nullable=False, default False, server_default "false") after `game_score`
- Modify: `backend/app/main.py` — schema-sync block (after line 34, the users-table section): two lines matching the existing `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` pattern for `users.game_xp INTEGER NOT NULL DEFAULT 0` and `attendance_records.xp_awarded BOOLEAN NOT NULL DEFAULT FALSE`
- Modify: `backend/app/schemas/auth.py` — `UserResponse` gains `game_xp: int = 0`, `game_level: int = 1`, `game_xp_progress: float = 0.0`
- Modify: `backend/app/routers/auth.py` — `_to_user_response` (line 52) fills the three fields via `level_for_xp`/`xp_progress`
- Test: `backend/tests/test_backend.py` (append one test)

**Interfaces:**
- Consumes: `level_for_xp`, `xp_progress` from Task 1
- Produces: `User.game_xp`, `AttendanceRecord.xp_awarded` ORM attributes; `/auth/me` and `TokenResponse.user` payloads carrying `game_xp`/`game_level`/`game_xp_progress`

- [ ] **Step 1: Write failing test** (append to `tests/test_backend.py`, same style as neighboring tests)

```python
async def test_auth_me_carries_game_fields():
    # register via the existing helper, then GET /api/v1/auth/me and assert
    # game_xp == 0, game_level == 1, game_xp_progress == 0.0
```

- [ ] **Step 2: Run to verify failure**

Run: `cd /home/wink/Projects/ble_attendance/backend && .venv/bin/python -m pytest tests/test_backend.py::test_auth_me_carries_game_fields -q`
Expected: FAIL (KeyError / missing key in response)

- [ ] **Step 3: Implement** the four file changes above.

- [ ] **Step 4: Run to verify pass** — same command, Expected: PASS. Also run the full suite once: `.venv/bin/python -m pytest -q` — Expected: 88 passed (87 prior + 1 new).

- [ ] **Step 5: Commit**

```bash
git add backend/app/models/attendance.py backend/app/main.py backend/app/schemas/auth.py backend/app/routers/auth.py backend/tests/test_backend.py
git commit -m "feat(xp): game_xp + xp_awarded columns, /me exposes xp level progress"
```

---

### Task 3: Level-aware pass gate

**Files:**
- Modify: `backend/app/routers/attendance.py` — four fixed `< 15` / `>= 15` comparisons become `pass_threshold(level)` calls:
  - Line ~1328 (legacy finalize gate loop over `[*prior_records, *records_to_create]`): prefetch `User.game_xp` for the set of `rec.student_id` values in one `select` before the loop; unbound/None student → level 1. Remarks text changes from `"< 15"` to `f"... < {threshold}"` (keep the existing remark prefix exactly).
  - Line ~2060 (audit gate loop over `audit_results`): resolve level per item via the existing `user_map` (device key → student id) + the same prefetch pattern; missing mapping → level 1.
  - Line ~1598: `if face_present and (challenge_score is None or challenge_score < pass_threshold(level_for_xp(current_user.game_xp)))`
  - Line ~1766: `... and challenge_score >= pass_threshold(level_for_xp(current_user.game_xp))`
- Test: `backend/tests/test_backend.py` (append two tests, modeled on `test_finalize_staged_drain_requires_reciprocal_peers` at line 1728: teacher + two roll students, mutual neighbors, `game_score` in the JSON bodies)

**Interfaces:**
- Consumes: `pass_threshold`, `level_for_xp` (Task 1); `User.game_xp` (Task 2)
- Produces: level-aware gate behavior relied on by Task 4's award tests

- [ ] **Step 1: Write failing tests**

```python
async def test_level3_student_fails_gate_below_17():
    # two students, mutual neighbors, score 16 -> mutual-verified verdict path;
    # first student's game_xp forced to 2500 (level 3) via session_factory
    # direct write; after finalize assert student's record status == "COGNITIVE_CHALLENGE_FAILED"
    # (pass threshold 17 at level 3)

async def test_level1_student_passes_gate_at_15():
    # same setup, score 15, level untouched (1) -> record status == "VERIFIED_PRESENT"
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_backend.py::test_level3_student_fails_gate_below_17 tests/test_backend.py::test_level1_student_passes_gate_at_15 -q`
Expected: first FAILS (currently 16 passes the fixed-15 gate), second PASSES already (that's fine — it's the regression pin)

- [ ] **Step 3: Implement** the four site changes above.

- [ ] **Step 4: Run to verify pass** — both tests PASS, then full suite `.venv/bin/python -m pytest -q` Expected: 90 passed (no prior test regressed; score-15/16 behavior at level 1 unchanged).

- [ ] **Step 5: Commit**

```bash
git add backend/app/routers/attendance.py backend/tests/test_backend.py
git commit -m "feat(xp): chimp pass gate scales with student level (floor 15)"
```

---

### Task 4: XP award at finalize

**Files:**
- Modify: `backend/app/services/xp.py` — add DB helper:

```python
async def award_xp_for_session(db, session_obj) -> int:
    """Award XP for VERIFIED_PRESENT records of this session that do not yet
    carry xp_awarded. One award per record; returns total XP granted."""
```

  Body sketch (algorithm, not verbatim): select `AttendanceRecord` where `session_id == session_obj.id`, `status == "VERIFIED_PRESENT"`, `xp_awarded.is_(False)`, `student_id.is_not(None)`, `game_score.is_not(None)`; prefetch their `User` rows in one select; per record compute `level = level_for_xp(user.game_xp)`, `gain = xp_gain(level, rec.game_score)`; if gain > 0: `user.game_xp += gain`, `rec.xp_awarded = True`.

- Modify: `backend/app/routers/attendance.py` — call `award_xp_for_session(db, session_obj)` at exactly three anchors, each placed AFTER `_apply_approved_leave_overlay` and BEFORE `session_obj.status = "COMPLETED"`:
  - Legacy finalize path: line ~1348 (after the overlay call, before line 1350)
  - Audit finalize path: line ~2176 (after the overlay call, before line 2178)
  - `submit_student_neighbors`: immediately before the endpoint's final `await db.commit()` (covers both the face-verified creation ~1873 and the in-flight grace rescue ~1790; idempotent flag makes repeat scans safe)
- Test: `backend/tests/test_backend.py` (append two tests)

**Interfaces:**
- Consumes: Task 1 functions, `AttendanceRecord.xp_awarded` (Task 2)
- Produces: award behavior consumed by no later task (terminal backend task)

- [ ] **Step 1: Write failing tests**

```python
async def test_finalize_awards_xp_for_perfect_score():
    # teacher + 3 roll students; two mutual-verified with game_score 24 and 26
    # (level 1 gains: 60 and 80), third isolated (no XP);
    # after finalize: users' game_xp == 60 and 80 respectively, third == 0;
    # records' xp_awarded True only for the two verified ones

async def test_finalize_double_award_guard():
    # same setup; call the finalize endpoint a second time (staged buffer is
    # drained; replay scans prior records) -> assert game_xp values unchanged
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_backend.py::test_finalize_awards_xp_for_perfect_score tests/test_backend.py::test_finalize_double_award_guard -q`
Expected: first FAILS (game_xp still 0), second PASSES trivially (0 == 0 — regression pin)

- [ ] **Step 3: Implement** the helper + three call sites.

- [ ] **Step 4: Run to verify pass** — both PASS, then full suite Expected: 92 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/app/services/xp.py backend/app/routers/attendance.py backend/tests/test_backend.py
git commit -m "feat(xp): award XP at VERIFIED_PRESENT finalize, idempotent per record"
```

---

### Task 5: Client DTO + mapping

**Files:**
- Modify: `core/network/src/main/java/com/college/core/network/model/AuthModels.kt` — `UserResponse` (line 49) gains:

```kotlin
@SerializedName("game_xp") val gameXp: Int = 0,
@SerializedName("game_level") val gameLevel: Int = 1,
@SerializedName("game_xp_progress") val gameXpProgress: Float = 0f,
```

- Modify: `core/model/src/main/java/com/college/core/model/User.kt` — data class gains `gameXp: Int = 0`, `gameLevel: Int = 1`, `gameXpProgress: Float = 0f`
- Modify: `core/network/src/main/java/com/college/core/network/repository/AuthRepository.kt` — `applyAuthenticatedSession` (line 58) maps the three fields into the domain `User`

**Interfaces:**
- Produces: `User.gameLevel` / `User.gameXp` / `User.gameXpProgress` used by Tasks 6-7

- [ ] **Step 1: Implement** the three edits (defaults are the Review-Focus pin: legacy cached JSON parses without crashing).
- [ ] **Step 2: Verify compile**

Run: `./gradlew :core:network:compileDebugKotlin :core:model:compileDebugKotlin`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add core/network/src/main/java/com/college/core/network/model/AuthModels.kt core/model/src/main/java/com/college/core/model/User.kt core/network/src/main/java/com/college/core/network/repository/AuthRepository.kt
git commit -m "feat(xp): client User carries gameXp/gameLevel/progress"
```

---

### Task 6: Level-aware chimp game

**Files:**
- Modify: `feature/attendance/src/main/java/com/college/feature/attendance/game/ChimpGridGame.kt`:
  - `ChimpGridGame` gains `level: Int = 1` (after `seed`, line 147)
  - `countForRound(round)` → `countForRound(round, level)` with body `3 + level + round` (replaces the fixed 5/6/7/8 `when`; verify: L1 r1 = 5 … L1 r4 = 8, L5 r1 = 9 … L5 r4 = 12)
  - `viewWindowMs`/`tapWindowMs` extended for counts 9-12 (new tunable constants next to lines 66-73): view `4700/5400/6100/6800`, tap `6500/7500/8500/9500`; counts 5-8 keep existing values; `else` branch keeps R4 as safety fallback
  - `possibleSoFar` (line ~592) and the mood-helper signature it lives in: thread `level` through, compute `(1..round).sumOf { countForRound(it, level) }`
- Modify: `feature/attendance/src/main/java/com/college/feature/attendance/StudentSection.kt` — `StudentSection` gains `gameLevel: Int = 1` param; `ChimpGridGame(...)` call (line 253) passes `level = gameLevel`
- Modify: `feature/attendance/src/main/java/com/college/feature/attendance/AttendanceScreen.kt` — the `StudentSection(...)` call at line 239 passes `gameLevel = user.gameLevel`

**Interfaces:**
- Consumes: `User.gameLevel` (Task 5)
- Produces: level-scaled game; UI unchanged at level 1 (default param)

- [ ] **Step 1: Implement** the edits.
- [ ] **Step 2: Verify compile**

Run: `./gradlew :feature:attendance:compileDebugKotlin`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add feature/attendance/src/main/java/com/college/feature/attendance/game/ChimpGridGame.kt feature/attendance/src/main/java/com/college/feature/attendance/StudentSection.kt feature/attendance/src/main/java/com/college/feature/attendance/AttendanceScreen.kt
git commit -m "feat(xp): chimp game scales round counts and windows with level"
```

---

### Task 7: Trainer-card XP bar

**Files:**
- Modify: `core/ui/src/main/java/com/college/core/ui/components/AppComponents.kt` — `PokemonTrainerCard` (line 232): between the info `Row` (ends ~line 379) and the `HorizontalDivider` (line 381), when `user?.hasRole(Role.STUDENT) == true`, add one `Row`: monospace `Lv N` pill (level from `user.gameLevel`) + progress bar — a rounded 6-8dp track `Box` filled to `gameXpProgress` fraction; fill color `gymBadgeColors[(gameLevel - 1).coerceIn(0, gymBadgeColors.lastIndex)]`; when `gameLevel >= 5` show full bar (progress 1.0, `MAX` instead of fraction text — no fraction text is required at all; keep it minimal per design doc). Non-students: no row.

**Interfaces:**
- Consumes: `User.gameLevel`, `User.gameXpProgress`, `User.hasRole` (Task 5)

- [ ] **Step 1: Implement** the row.
- [ ] **Step 2: Verify compile**

Run: `./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL (full app compiles with the card change)

- [ ] **Step 3: Commit**

```bash
git add core/ui/src/main/java/com/college/core/ui/components/AppComponents.kt
git commit -m "feat(xp): trainer card shows level pill and xp bar for students"
```

---

### Task 8: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Backend full suite**

Run: `cd /home/wink/Projects/ble_attendance/backend && .venv/bin/python -m pytest -q`
Expected: 92 passed, 0 failed

- [ ] **Step 2: Release build with R8 fullMode**

Run: `./gradlew :app:assembleRelease`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Report**

Report the two command results verbatim. Device smoke test (BLE → chimp at level 1 → submit → card bar) remains a human step, same as R8 fullMode.

---

## Self-review notes

- Spec coverage: data model (Task 2), XP rules incl. base scaling with level (Task 1), pass gate (Task 3), award placement + idempotency (Task 4), API/DTO (Tasks 2/5), trainer-card bar (Task 7), level-scaled game (Task 6), non-goals untouched (no telemetry/demotion/reset tasks exist).
- Type consistency: `level_for_xp`/`xp_progress`/`pass_threshold`/`xp_gain` names identical across Tasks 1/2/3/4; `User.gameLevel` identical across Tasks 5/6/7.
- Proportion: plan is signatures, values, anchors, test names — no transcribed bodies except the award algorithm sketch the tests do not fully determine.
