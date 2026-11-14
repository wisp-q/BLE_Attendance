"""F3 XP/level system: pure curve functions (docs/f3_xp_levels.md).

Anchor numbers come from the approved design:
- gain threshold = ceil(0.9 x level max)
- pass threshold = max(15, ceil(0.5 x level max))
- gain at threshold = 50 + level*10; at max = +20 bonus; linear between
- caps = 1000 x level; cumulative entries 0 / 1000 / 3000 / 6000
"""

from app.services.xp import (
    level_for_xp,
    level_max,
    gain_threshold,
    pass_threshold,
    xp_gain,
    xp_progress,
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


def test_level_max_per_level():
    assert [level_max(l) for l in range(1, 6)] == [26, 30, 34, 38, 42]


def test_gain_threshold_per_level():
    assert [gain_threshold(l) for l in range(1, 6)] == [24, 27, 31, 35, 38]


def test_pass_threshold_per_level():
    assert [pass_threshold(l) for l in range(1, 6)] == [15, 15, 17, 19, 21]


def test_xp_gain_level_1_matches_spec():
    assert xp_gain(1, 24) == 60
    assert xp_gain(1, 25) == 70
    assert xp_gain(1, 26) == 80
    assert xp_gain(1, 20) == 0      # below gain threshold
    assert xp_gain(1, 15) == 0      # passes the gate but earns nothing


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
