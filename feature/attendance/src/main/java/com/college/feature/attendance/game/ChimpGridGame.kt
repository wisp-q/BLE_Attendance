package com.college.feature.attendance.game

import androidx.compose.animation.Animatable as ColorAnimatable
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.keyframes
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ColorFilter
import androidx.compose.ui.graphics.ColorMatrix
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.college.feature.attendance.R
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.random.Random

// 4x4 grid packed in one 64-bit Long: 16 cells * 4 bits (nibble) = 64 bits.
// Nibble value 0 = empty, 1..15 = number shown in that cell.
private const val GRID = 4
private const val CELLS = 16
private const val MASK4 = 0xFL

// Hard per-round schedule (view + tap, fixed for EVERY student — round
// boundaries are synchronized class-wide, so no mid-game desync exists):
//   r1: 1.9 s view + 2.5 s tap | r2: 2.3 + 3.5 | r3: 3.3 + 4.5 | r4: 4.0 + 5.5
// Total 27.5 s exactly.
// F3 (levels 3-5): counts 9-12 need their own windows — the old else-branch
// silently reused the R4 pair for any n > 7. Growth continues the existing
// pattern: ~+700 ms view / +1000 ms tap per extra number (tunable).
private const val GRID_R1_VIEW = 1900L
private const val GRID_R1_TAP = 2500L
private const val GRID_R2_VIEW = 2300L
private const val GRID_R2_TAP = 3500L
private const val GRID_R3_VIEW = 3300L
private const val GRID_R3_TAP = 4500L
private const val GRID_R4_VIEW = 4000L
private const val GRID_R4_TAP = 5500L
private const val GRID_R5_VIEW = 4700L
private const val GRID_R5_TAP = 6500L
private const val GRID_R6_VIEW = 5400L
private const val GRID_R6_TAP = 7500L
private const val GRID_R7_VIEW = 6100L
private const val GRID_R7_TAP = 8500L
private const val GRID_R8_VIEW = 6800L
private const val GRID_R8_TAP = 9500L

private inline fun nibble(board: Long, idx: Int): Int = ((board ushr (idx * 4)) and MASK4).toInt()
private inline fun withNibble(board: Long, idx: Int, value: Int): Long {
    val shift = idx * 4
    return (board and (MASK4 shl shift).inv()) or ((value.toLong() and MASK4) shl shift)
}

// F3: round counts scale with the server-assigned level. Level 1 is today's
// game bit-for-bit (5/6/7/8, max 26); level 5 shows 9/10/11/12 (max 42, fits
// the 4x4 grid). Formula reproduces the approved table exactly.
private fun countForRound(round: Int, level: Int): Int = 3 + level + round

private fun viewWindowMs(n: Int): Long = when (n) {
    5 -> GRID_R1_VIEW
    6 -> GRID_R2_VIEW
    7 -> GRID_R3_VIEW
    8 -> GRID_R4_VIEW
    9 -> GRID_R5_VIEW
    10 -> GRID_R6_VIEW
    11 -> GRID_R7_VIEW
    12 -> GRID_R8_VIEW
    else -> GRID_R4_VIEW
}

private fun tapWindowMs(n: Int): Long = when (n) {
    5 -> GRID_R1_TAP
    6 -> GRID_R2_TAP
    7 -> GRID_R3_TAP
    8 -> GRID_R4_TAP
    9 -> GRID_R5_TAP
    10 -> GRID_R6_TAP
    11 -> GRID_R7_TAP
    12 -> GRID_R8_TAP
    else -> GRID_R4_TAP
}

// ---------------------------------------------------------------------------
// Presentation-only round palettes: every round repaints the board (empty /
// hidden / shown cells, borders, accent). Correct-tap green and mistake red
// stay FIXED across rounds — they are semantic feedback, not decoration.
// Round 1 reproduces the original colors exactly; rounds 2-4 rotate hue.
// ---------------------------------------------------------------------------
private data class RoundPalette(
    val emptyCell: Color,   // board cell with no number
    val emptyCellAlt: Color,// number cell whose reveal is exhausted (residual)
    val hiddenCell: Color,  // number present but hidden (tap phase)
    val shownCell: Color,   // number visible (view phase)
    val border: Color,      // 1 dp grid lines
    val accent: Color,      // HUD score + mascot glow
)

private val ROUND_PALETTES = listOf(
    // Round 1 — deep indigo (original look)
    RoundPalette(
        emptyCell = Color(0xFF0B1220), emptyCellAlt = Color(0xFF111827),
        hiddenCell = Color(0xFF243447), shownCell = Color(0xFF172554),
        border = Color(0xFF334155), accent = Color(0xFF60A5FA),
    ),
    // Round 2 — violet
    RoundPalette(
        emptyCell = Color(0xFF130B20), emptyCellAlt = Color(0xFF1A1130),
        hiddenCell = Color(0xFF3A2C55), shownCell = Color(0xFF2A1657),
        border = Color(0xFF5B4B8A), accent = Color(0xFFA78BFA),
    ),
    // Round 3 — teal
    RoundPalette(
        emptyCell = Color(0xFF071A18), emptyCellAlt = Color(0xFF0D2622),
        hiddenCell = Color(0xFF1D4E48), shownCell = Color(0xFF0F3D3A),
        border = Color(0xFF2F6B62), accent = Color(0xFF2DD4BF),
    ),
    // Round 4 — amber ember
    RoundPalette(
        emptyCell = Color(0xFF1C130A), emptyCellAlt = Color(0xFF271B10),
        hiddenCell = Color(0xFF4E3517), shownCell = Color(0xFF3D2A10),
        border = Color(0xFF6B5230), accent = Color(0xFFFBBF24),
    ),
)

@Composable
fun ChimpGridGame(
    modifier: Modifier = Modifier,
    seed: Int = 0,
    // F3: server-assigned level (1-5) from the student's profile. Scales the
    // per-round number counts and the view/tap windows. Level 1 = current game.
    level: Int = 1,
    // Synchronized start: all students in the room begin round 1 at the same
    // instant (teacher countdown beacon). The grid stays empty until then.
    startDelayMs: Long = 0L,
    onFinished: (score: Int) -> Unit = {},
) {
    val rng = remember(seed) { Random(seed) }

    var board by remember { mutableLongStateOf(0L) }          // 64-bit board (nibbles)
    var shownMask by remember { mutableIntStateOf(0) }        // 16-bit mask: untapped number cells
    var tappedMask by remember { mutableIntStateOf(0) }       // 16-bit mask: correctly tapped cells (green)
    var wrongCell by remember { mutableIntStateOf(-1) }       // the mistaken cell (red, round over)
    var nextExpected by remember { mutableIntStateOf(1) }
    var count by remember { mutableIntStateOf(5) }
    var round by remember { mutableIntStateOf(1) }
    var score by remember { mutableIntStateOf(0) }
    var running by remember { mutableStateOf(true) }
    var preStartLeftMs by remember { mutableLongStateOf(startDelayMs) }

    // Round lifecycle: view window shows the numbers, tap window hides them.
    // roundOver = the student is done for THIS round (completed all taps, made
    // one mistake, or the window ran out) — no further clicks until the next
    // round's fixed slot. Mistakes never advance the sequence: brute-forcing
    // by tapping every cell is dead. Tapped cells reveal their number (green
    // = correct, red = the mistaken one) only after being pressed.
    var phaseShow by remember { mutableStateOf(true) }
    var roundOver by remember { mutableStateOf(false) }
    var viewEndAtMs by remember { mutableLongStateOf(0L) }
    var roundEndAtMs by remember { mutableLongStateOf(0L) }

    // Animated dots for the pre-start countdown ("Starting in 7...")
    val dotTransition = rememberInfiniteTransition(label = "start_dots")
    val dotPhase by dotTransition.animateFloat(
        initialValue = 0f,
        targetValue = 3f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "start_dots_phase"
    )
    val startDots = ".".repeat(((dotPhase.toInt() % 3) + 1))

    fun newRound(r: Int, roundStart: Long) {
        round = r
        val n = countForRound(r, level)
        count = n
        // place 1..n into random distinct cells (bit ops on 64-bit board)
        val cells = IntArray(CELLS) { it }
        for (i in 0 until CELLS) { // Fisher-Yates shuffle
            val j = i + rng.nextInt(CELLS - i)
            val tmp = cells[i]; cells[i] = cells[j]; cells[j] = tmp
        }
        var b = 0L
        var mask = 0
        for (v in 1..n) {
            val idx = cells[v - 1]
            b = withNibble(b, idx, v)
            mask = mask or (1 shl idx)
        }
        board = b
        shownMask = mask
        tappedMask = 0
        wrongCell = -1
        phaseShow = true
        roundOver = false
        nextExpected = 1
        // Fixed schedule: rounds start at their cumulative slot, never early,
        // never late — the class stays in lockstep through all 4 rounds.
        viewEndAtMs = roundStart + viewWindowMs(n)
        roundEndAtMs = roundStart + viewWindowMs(n) + tapWindowMs(n)
    }

    LaunchedEffect(seed, startDelayMs) {
        // Pre-start hold: the visible countdown ticks down before round 1
        while (preStartLeftMs > 0L) {
            val step = minOf(200L, preStartLeftMs)
            delay(step)
            preStartLeftMs -= step
        }
        newRound(1, System.currentTimeMillis())
        while (running) {
            val now = System.currentTimeMillis()
            if (phaseShow && now >= viewEndAtMs) {
                phaseShow = false // hide numbers, recall phase
            }
            if (now >= roundEndAtMs) {
                if (round >= 4) {
                    running = false
                    onFinished(score)
                    break
                }
                // Next round starts at its fixed slot regardless of loop jitter
                newRound(round + 1, roundEndAtMs)
            }
            delay(30)
        }
    }

    // ---- Presentation-only state (no effect on game logic) -----------------
    // Per-round board colors, cross-faded on every new round.
    val palIdx = (round - 1).coerceIn(0, ROUND_PALETTES.lastIndex)
    val cellEmpty = remember { ColorAnimatable(ROUND_PALETTES[palIdx].emptyCell) }
    val cellEmptyAlt = remember { ColorAnimatable(ROUND_PALETTES[palIdx].emptyCellAlt) }
    val cellHidden = remember { ColorAnimatable(ROUND_PALETTES[palIdx].hiddenCell) }
    val cellShown = remember { ColorAnimatable(ROUND_PALETTES[palIdx].shownCell) }
    val cellBorder = remember { ColorAnimatable(ROUND_PALETTES[palIdx].border) }
    val cellAccent = remember { ColorAnimatable(ROUND_PALETTES[palIdx].accent) }
    LaunchedEffect(round) {
        val target = ROUND_PALETTES[(round - 1).coerceIn(0, ROUND_PALETTES.lastIndex)]
        launch { cellEmpty.animateTo(target.emptyCell, tween(600)) }
        launch { cellEmptyAlt.animateTo(target.emptyCellAlt, tween(600)) }
        launch { cellHidden.animateTo(target.hiddenCell, tween(600)) }
        launch { cellShown.animateTo(target.shownCell, tween(600)) }
        launch { cellBorder.animateTo(target.border, tween(600)) }
        launch { cellAccent.animateTo(target.accent, tween(600)) }
    }

    // Subtle pop each time a new round appears.
    val boardPop = remember { Animatable(0.94f) }
    LaunchedEffect(round) {
        boardPop.snapTo(0.94f)
        boardPop.animateTo(
            1f,
            spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessMediumLow)
        )
    }

    // Presentation layout: a fixed top slot (pre-start countdown, then the
    // chimp mascot + round/score HUD) floats ABOVE the board and never shifts
    // it — the board itself is always exactly centered in the play area.
    Box(modifier = modifier.fillMaxSize()) {
        BoxWithConstraints(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            // Square board sized to fit BOTH dimensions (keeps the original
            // phone footprint; degrades gracefully on short/landscape areas).
            val side = minOf(maxWidth * 0.96f, maxHeight - 124.dp).coerceAtLeast(220.dp)
            Box(
                modifier = Modifier
                    .width(side)
                    .height(side)
                    .graphicsLayer {
                        scaleX = boardPop.value
                        scaleY = boardPop.value
                    }
            ) {
                Column(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(0.dp)
                ) {
                    for (row in 0 until GRID) {
                        Row(
                            modifier = Modifier.fillMaxWidth().weight(1f),
                            horizontalArrangement = Arrangement.spacedBy(0.dp)
                        ) {
                            for (col in 0 until GRID) {
                                val idx = row * GRID + col
                                val value = nibble(board, idx) // read 4-bit nibble from 64-bit board
                                val hasNumber = value != 0
                                val active = hasNumber && ((shownMask and (1 shl idx)) != 0)
                                val isTapped = (tappedMask and (1 shl idx)) != 0
                                val isWrong = wrongCell == idx

                                // Juice on the resolved cells (correct tap / mistake).
                                val cellPop = remember(idx) { Animatable(1f) }
                                LaunchedEffect(isTapped, isWrong) {
                                    if (isTapped || isWrong) {
                                        cellPop.snapTo(1.14f)
                                        cellPop.animateTo(
                                            1f,
                                            spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessMedium)
                                        )
                                    }
                                }

                                Box(
                                    modifier = Modifier
                                        .weight(1f)
                                        .fillMaxSize()
                                        .graphicsLayer {
                                            scaleX = cellPop.value
                                            scaleY = cellPop.value
                                        }
                                        .background(
                                            when {
                                                !hasNumber -> cellEmpty.value
                                                isWrong -> Color(0xFF7F1D1D)              // mistaken cell red (fixed)
                                                isTapped -> Color(0xFF166534)             // correct tap green (fixed)
                                                phaseShow && active -> cellShown.value    // number shown (view)
                                                active && !phaseShow -> cellHidden.value  // hidden number cell
                                                else -> cellEmptyAlt.value
                                            }
                                        )
                                        .border(1.dp, cellBorder.value)
                                        .then(
                                            if (running && !phaseShow && !roundOver && active) {
                                                Modifier.clickable {
                                                    if (value == nextExpected) {
                                                        score += 1 // every correct tap scores
                                                        tappedMask = tappedMask or (1 shl idx) // green reveal
                                                        shownMask = shownMask and (1 shl idx).inv() // bit clear
                                                        nextExpected += 1
                                                        if (nextExpected > count) {
                                                            // Round complete.
                                                            roundOver = true
                                                        }
                                                    } else {
                                                        // One mistake ends the round: the mistaken
                                                        // cell turns red and reveals its number —
                                                        // no more clicks until the next round.
                                                        wrongCell = idx
                                                        roundOver = true
                                                    }
                                                }
                                            } else Modifier
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    if (hasNumber && (phaseShow || isTapped || isWrong)) {
                                        Text(
                                            text = value.toString(),
                                            color = Color.White,
                                            fontSize = 36.sp,
                                            fontWeight = FontWeight.ExtraBold
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Top slot: countdown before round 1, chimp mascot + HUD afterwards.
        // Fixed height so swapping contents never moves the centered board.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(120.dp)
                .align(Alignment.TopCenter),
            contentAlignment = Alignment.Center
        ) {
            if (preStartLeftMs > 0L) {
                Text(
                    text = "Starting in ${(preStartLeftMs + 999) / 1000}$startDots",
                    color = Color(0xFF93C5FD),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold
                )
            } else {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    ChimpMascot(
                        score = score,
                        round = round,
                        level = level,
                        gameStarted = true,
                        mistakeMade = wrongCell >= 0,
                        accentColor = cellAccent.value
                    )
                    Text(
                        text = "Score $score",
                        fontSize = 22.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = cellAccent.value
                    )
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chimp mascot — pure presentation, driven only by existing game state
// (round / score / wrongCell). Two reaction memes act out the performance:
//   GENIUS   (ratio >= 0.7): 😎 sunglasses emoji, confident bounce, accent
//            glow halo, twinkling ✨ sparkles.
//   CONFUSED (ratio <= 0.35, or a mistake sitting on the board): shocked
//            monkey, drained to grayscale, dizzy wobble, rising ❓ marks.
//   THINKING (in between): shocked monkey, slow pondering tilt, drifting 💭.
//   READY    (pre-start): shocked monkey, calm breathing.
// ---------------------------------------------------------------------------
private enum class ChimpMood { READY, THINKING, GENIUS, CONFUSED }

@Composable
private fun ChimpMoodPortrait(
    mood: ChimpMood,
    accentColor: Color,
    modifier: Modifier = Modifier
) {
    val transition = rememberInfiniteTransition(label = "chimp_idle")

    // Genius: confident little bounce.
    val bob by transition.animateFloat(
        initialValue = 0f,
        targetValue = -6f,
        animationSpec = infiniteRepeatable(
            animation = tween(650, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "chimp_bob"
    )
    // Confused: dizzy head-shake wobble.
    val wobble by transition.animateFloat(
        initialValue = 0f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = keyframes {
                0f at 0
                -12f at 140
                9f at 290
                -6f at 430
                4f at 570
                0f at 720
            }
        ),
        label = "chimp_wobble"
    )
    // Thinking: slow pondering tilt.
    val tilt by transition.animateFloat(
        initialValue = -4f,
        targetValue = 4f,
        animationSpec = infiniteRepeatable(
            animation = tween(1600, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "chimp_tilt"
    )
    // Ready: calm breathing scale.
    val breath by transition.animateFloat(
        initialValue = 1f,
        targetValue = 1.06f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "chimp_breath"
    )
    // Genius badge pulse is gone — the sunglasses emoji carries the look by itself.

    // Pop whenever the mood changes (confused ↔ genius reads as an act swap).
    val pop = remember { Animatable(0.7f) }
    LaunchedEffect(mood) {
        pop.snapTo(0.7f)
        pop.animateTo(
            1f,
            spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessMedium)
        )
    }

    // Glow halo color follows the mood; genius takes the round's accent.
    val glow = remember { ColorAnimatable(if (mood == ChimpMood.GENIUS) accentColor else Color(0xFF64748B)) }
    LaunchedEffect(mood, accentColor) {
        val target = when (mood) {
            ChimpMood.GENIUS -> accentColor
            ChimpMood.CONFUSED -> Color(0xFFF87171)
            ChimpMood.THINKING -> Color(0xFF93C5FD)
            ChimpMood.READY -> Color(0xFF64748B)
        }
        glow.animateTo(target, tween(500))
    }

    Box(modifier = modifier.size(112.dp), contentAlignment = Alignment.Center) {
        // Mood halo.
        Box(
            modifier = Modifier
                .size(112.dp)
                .background(
                    brush = Brush.radialGradient(
                        colors = listOf(
                            glow.value.copy(alpha = 0.32f),
                            glow.value.copy(alpha = 0.10f),
                            Color.Transparent
                        )
                    ),
                    shape = CircleShape
                )
        )

        // Reaction meme with the mood's motion personality: the sunglasses
        // emoji plays GENIUS, the shocked monkey plays everything else —
        // grayscale + dizzy shake when confused, pondering tilt when
        // thinking, calm breathing while waiting to start.
        val faceRes = if (mood == ChimpMood.GENIUS) R.drawable.meme_cool else R.drawable.meme_monkey_shocked
        Image(
            painter = painterResource(id = faceRes),
            contentDescription = null,
            contentScale = ContentScale.Fit,
            colorFilter = if (mood == ChimpMood.CONFUSED) {
                ColorFilter.colorMatrix(ColorMatrix().apply { setToSaturation(0f) })
            } else {
                null
            },
            modifier = Modifier
                .size(112.dp)
                .graphicsLayer {
                    val breathScale = if (mood == ChimpMood.READY) breath else 1f
                    // The sunglasses emoji is wide (OK-glove + thumbs-up);
                    // optically scale it up so both memes read at the same
                    // visual weight side by side across moods.
                    val faceScale = if (mood == ChimpMood.GENIUS) 1.12f else 1f
                    scaleX = pop.value * breathScale * faceScale
                    scaleY = pop.value * breathScale * faceScale
                    translationY = if (mood == ChimpMood.GENIUS) bob.dp.toPx() else 0f
                    rotationZ = when (mood) {
                        ChimpMood.CONFUSED -> wobble
                        ChimpMood.THINKING -> tilt
                        else -> 0f
                    }
                }
        )

        when (mood) {
            ChimpMood.GENIUS -> {
                FloatingParticle("✨", durationMs = 900, modifier = Modifier.align(Alignment.TopStart))
                FloatingParticle("✨", durationMs = 1250, modifier = Modifier.align(Alignment.BottomEnd))
            }
            ChimpMood.CONFUSED -> {
                FloatingParticle("❓", durationMs = 1100, modifier = Modifier.align(Alignment.TopStart))
                FloatingParticle("❓", durationMs = 1450, modifier = Modifier.align(Alignment.TopEnd))
            }
            ChimpMood.THINKING -> {
                FloatingParticle("💭", durationMs = 1800, modifier = Modifier.align(Alignment.TopEnd))
            }
            ChimpMood.READY -> Unit
        }
    }
}

@Composable
private fun ChimpMascot(
    score: Int,
    round: Int,
    level: Int,
    gameStarted: Boolean,
    mistakeMade: Boolean,
    accentColor: Color,
    modifier: Modifier = Modifier
) {
    // Performance ratio: correct taps over every number shown so far. A round
    // is counted as "claimable" the moment it starts, so a mistake instantly
    // drags the ratio down (confused act) and clean taps pull it back up.
    val possibleSoFar = (1..round).sumOf { countForRound(it, level) }
    val ratio = if (gameStarted && possibleSoFar > 0) score.toFloat() / possibleSoFar else 0.5f
    val mood = when {
        !gameStarted -> ChimpMood.READY
        mistakeMade -> ChimpMood.CONFUSED
        // Very start of the game: nothing judged yet — ponder, don't panic.
        round == 1 && score == 0 -> ChimpMood.THINKING
        ratio >= 0.7f -> ChimpMood.GENIUS
        ratio <= 0.35f -> ChimpMood.CONFUSED
        else -> ChimpMood.THINKING
    }
    ChimpMoodPortrait(mood = mood, accentColor = accentColor, modifier = modifier)
}

// Small looping glyph (✨ / ❓ / 💭): gentle fade + drift.
@Composable
private fun FloatingParticle(
    glyph: String,
    durationMs: Int,
    modifier: Modifier = Modifier
) {
    val transition = rememberInfiniteTransition(label = "particle")
    val pAlpha by transition.animateFloat(
        initialValue = 0.15f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMs, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "particle_alpha"
    )
    val pRise by transition.animateFloat(
        initialValue = 5f,
        targetValue = -5f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMs, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "particle_rise"
    )
    Text(
        text = glyph,
        fontSize = 13.sp,
        modifier = modifier.graphicsLayer {
            alpha = pAlpha
            translationY = pRise.dp.toPx()
        }
    )
}
