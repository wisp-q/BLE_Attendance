package com.college.feature.attendance

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import com.college.feature.attendance.network.LeaveApplicationResponse
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.college.core.model.User
import com.college.core.ui.theme.AppTheme
import com.college.feature.attendance.camera.PassiveFaceCaptureManager
import com.college.feature.attendance.game.ChimpGridGame
import com.college.feature.attendance.network.AttendanceRecordItem
import com.college.feature.attendance.viewmodel.StudentPhase

// Student attendance portal displaying instructions, probing, and completion
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun StudentSection(
    user: User,
    studentPhase: StudentPhase,
    detectedSessionId: String,
    sessionSalt: String = "",
    studentId: String = "",
    studentStatusMessage: String? = null,
    chimpStartDelayMs: Long = 0L,
    capturedFacePayload: String? = null,
    auditedRecord: AttendanceRecordItem? = null,
    onRefreshAudit: (() -> Unit)? = null,
    isRefreshingAudit: Boolean = false,
    onChimpScore: ((Int) -> Unit)? = null,
    onChimpChallengeActive: ((Boolean) -> Unit)? = null,
    onFaceCaptured: (String, ByteArray?) -> Unit = { _, _ -> },
    onStartScanning: () -> Unit,
    onStopScanning: () -> Unit,
    onNext: () -> Unit = {},
    onDone: () -> Unit = {},
    // Leave (student): optional, shown in standby
    myLeaveApplications: List<LeaveApplicationResponse> = emptyList(),
    isLoadingLeave: Boolean = false,
    isSubmittingLeave: Boolean = false,
    leaveMessage: String? = null,
    onLoadMyLeaves: () -> Unit = {},
    onSubmitLeave: (String, String, String) -> Unit = { _, _, _ -> },
) {
    // Passive face capture — headless front camera, sharpest frame
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val faceCaptureManager = remember { PassiveFaceCaptureManager(context, lifecycleOwner) }
    val gameScope = rememberCoroutineScope()

    val permissionsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { perms ->
        if (perms[Manifest.permission.CAMERA] == true && studentPhase == StudentPhase.PROBING_NEIGHBORS) {
            faceCaptureManager.startCapture(null)
        }
    }

    DisposableEffect(studentPhase) {
        if (studentPhase == StudentPhase.PROBING_NEIGHBORS) {
            val hasCamera = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED
            val missing = mutableListOf<String>()
            if (!hasCamera) missing.add(Manifest.permission.CAMERA)
            // [ULTRASONIC-DISABLED 2026-11] mic no longer required — do not gate
            // face capture on it while Layer 4 is off.
            // val hasAudio = ContextCompat.checkSelfPermission(
            //     context,
            //     Manifest.permission.RECORD_AUDIO
            // ) == PackageManager.PERMISSION_GRANTED
            // if (!hasAudio) missing.add(Manifest.permission.RECORD_AUDIO)

            if (missing.isNotEmpty()) {
                permissionsLauncher.launch(missing.toTypedArray())
            } else {
                faceCaptureManager.startCapture(null)
            }
        }
        onDispose {
            faceCaptureManager.release()
        }
    }

    val isScanning = studentPhase == StudentPhase.LISTENING_FOR_TEACHER ||
            studentPhase == StudentPhase.PROBING_NEIGHBORS

    val isVerified = studentPhase == StudentPhase.VERIFIED_PRESENT
    val isUnverified = studentPhase == StudentPhase.UNVERIFIED_FLAGGED
    var lastGameScore by remember { mutableStateOf<Int?>(null) }

    LaunchedEffect(studentPhase) {
        if (studentPhase == StudentPhase.STANDBY || studentPhase == StudentPhase.LISTENING_FOR_TEACHER) {
            lastGameScore = null
        }
    }
    DisposableEffect(studentPhase) {
        if (studentPhase == StudentPhase.PROBING_NEIGHBORS) {
            onChimpChallengeActive?.invoke(true)
        }
        onDispose {
            if (studentPhase == StudentPhase.PROBING_NEIGHBORS) {
                onChimpChallengeActive?.invoke(false)
            }
        }
    }

    // Animated dots for active checking in status
    val infiniteTransition = rememberInfiniteTransition(label = "checking_in_anim")
    val dotPhase by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 3f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "dots"
    )
    val dotCount = (dotPhase.toInt() % 3) + 1
    val animatedDots = ".".repeat(dotCount)

    // Main screen container with theme background color
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(AppTheme.colors.background)
            .systemBarsPadding()
    ) {
        // Navigation header with back arrow and screen title
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = {
                    onStopScanning()
                    onDone()
                }
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = "Back",
                    tint = AppTheme.colors.textPrimary,
                    modifier = Modifier.size(26.dp)
                )
            }

            Spacer(modifier = Modifier.width(6.dp))

            Text(
                text = "Attendance",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = AppTheme.colors.textPrimary,
                letterSpacing = (-0.5).sp
            )
        }

        when {
            // Probing: chimp memory challenge, then capture face and advance
            studentPhase == StudentPhase.PROBING_NEIGHBORS -> {
                ChimpGridGame(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    seed = "$detectedSessionId:$sessionSalt:$studentId".hashCode(),
                    // F3: level comes from the server via the profile; it
                    // scales round counts and windows (level 1 = today's game).
                    level = user.gameLevel,
                    startDelayMs = chimpStartDelayMs,
                    onFinished = { score ->
                        lastGameScore = score
                        onChimpScore?.invoke(score)
                        onChimpChallengeActive?.invoke(false)
                        gameScope.launch {
                            val lockedCandidate = faceCaptureManager.stopCameraAndTakeCandidate()
                            val faceResult = withContext(Dispatchers.Default) {
                                lockedCandidate?.let { faceCaptureManager.encodeCandidateResult(it) }
                            }
                            withContext(Dispatchers.Main) {
                                if (faceResult != null) {
                                    onFaceCaptured(faceResult.base64, faceResult.bytes)
                                }
                                onNext()
                            }
                        }
                    }
                )
            }

            // Waiting for teacher confirmation / final states
            studentPhase == StudentPhase.DISCOVERY_COMPLETE ||
                studentPhase == StudentPhase.WAITING_FOR_AUDIT ||
                isVerified ||
                isUnverified -> {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        if (lastGameScore != null) {
                            Text(
                                text = "Score ${lastGameScore}",
                                fontSize = 36.sp,
                                fontWeight = FontWeight.ExtraBold,
                                color = AppTheme.colors.textPrimary
                            )
                            Spacer(modifier = Modifier.height(12.dp))
                        }

                        if (isVerified) {
                            VerifiedStatusAnimation()
                        } else if (isUnverified) {
                            UnverifiedStatusAnimation()
                        } else {
                            Text(
                                text = "Waiting for teacher$animatedDots",
                                fontSize = 19.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = AppTheme.colors.textPrimary
                            )
                        }

                        if (isUnverified && !studentStatusMessage.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(16.dp))
                            Text(
                                text = studentStatusMessage,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Medium,
                                color = AppTheme.colors.textSecondary
                            )
                        }
                    }
                }
            }

            // Standby and scanning instruction view
            else -> {
                Spacer(modifier = Modifier.weight(1f))

                // Structured instruction island centered in the middle of the screen
                Surface(
                    shape = RoundedCornerShape(22.dp),
                    color = AppTheme.colors.surface,
                    border = null,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 20.dp, vertical = 20.dp)
                    ) {
                        // Step 1
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(
                                text = "1.",
                                fontSize = 17.sp,
                                fontWeight = FontWeight.Bold,
                                color = AppTheme.colors.accentOrange,
                                modifier = Modifier.width(26.dp)
                            )
                            Text(
                                text = "Hold your phone firmly with two hands.",
                                fontSize = 15.5.sp,
                                fontWeight = FontWeight.Medium,
                                color = AppTheme.colors.textPrimary,
                                lineHeight = 22.sp,
                                modifier = Modifier.weight(1f)
                            )
                        }

                        HorizontalDivider(
                            color = AppTheme.colors.surfaceBorder.copy(alpha = 0.5f),
                            thickness = 1.dp,
                            modifier = Modifier.padding(start = 26.dp, top = 14.dp, bottom = 14.dp)
                        )

                        // Step 2
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(
                                text = "2.",
                                fontSize = 17.sp,
                                fontWeight = FontWeight.Bold,
                                color = AppTheme.colors.accentOrange,
                                modifier = Modifier.width(26.dp)
                            )
                            Text(
                                text = "Numbers flash on the grid — memorize their positions. When they hide, tap the squares in order from 1 upward. Each correct tap counts; a wrong tap ends the round.",
                                fontSize = 15.5.sp,
                                fontWeight = FontWeight.Medium,
                                color = AppTheme.colors.textPrimary,
                                lineHeight = 22.sp,
                                modifier = Modifier.weight(1f)
                            )
                        }

                        HorizontalDivider(
                            color = AppTheme.colors.surfaceBorder.copy(alpha = 0.5f),
                            thickness = 1.dp,
                            modifier = Modifier.padding(start = 26.dp, top = 14.dp, bottom = 14.dp)
                        )

                        // Step 3
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(
                                text = "3.",
                                fontSize = 17.sp,
                                fontWeight = FontWeight.Bold,
                                color = AppTheme.colors.accentOrange,
                                modifier = Modifier.width(26.dp)
                            )
                            Text(
                                text = "Keep your face visible to the camera while checking in.",
                                fontSize = 15.5.sp,
                                fontWeight = FontWeight.Medium,
                                color = AppTheme.colors.textPrimary,
                                lineHeight = 22.sp,
                                modifier = Modifier.weight(1f)
                            )
                        }

                        HorizontalDivider(
                            color = AppTheme.colors.surfaceBorder.copy(alpha = 0.5f),
                            thickness = 1.dp,
                            modifier = Modifier.padding(start = 26.dp, top = 14.dp, bottom = 14.dp)
                        )

                        // Step 4
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(
                                text = "4.",
                                fontSize = 17.sp,
                                fontWeight = FontWeight.Bold,
                                color = AppTheme.colors.accentOrange,
                                modifier = Modifier.width(26.dp)
                            )
                            Text(
                                text = "One student, one device. Do not use someone else's phone or check in for anyone else.",
                                fontSize = 15.5.sp,
                                fontWeight = FontWeight.Medium,
                                color = AppTheme.colors.textPrimary,
                                lineHeight = 22.sp,
                                modifier = Modifier.weight(1f)
                            )
                        }

                        HorizontalDivider(
                            color = AppTheme.colors.surfaceBorder.copy(alpha = 0.5f),
                            thickness = 1.dp,
                            modifier = Modifier.padding(start = 26.dp, top = 14.dp, bottom = 14.dp)
                        )

                        // Step 5
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.Top
                        ) {
                            Text(
                                text = "5.",
                                fontSize = 17.sp,
                                fontWeight = FontWeight.Bold,
                                color = AppTheme.colors.accentOrange,
                                modifier = Modifier.width(26.dp)
                            )
                            Text(
                                text = "Keep your phone still while checking in.",
                                fontSize = 15.5.sp,
                                fontWeight = FontWeight.Medium,
                                color = AppTheme.colors.textPrimary,
                                lineHeight = 22.sp,
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.weight(1f))

                // Action button triggering scan and animating check-in state
                Surface(
                    onClick = {
                        if (isScanning) {
                            onStopScanning()
                        } else {
                            onStartScanning()
                        }
                    },
                    shape = CircleShape,
                    color = when {
                        isScanning -> AppTheme.colors.accentOrange
                        else -> AppTheme.colors.primaryPurple
                    },
                    shadowElevation = 4.dp,
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .padding(bottom = 28.dp)
                        .height(50.dp)
                        .defaultMinSize(minWidth = 160.dp)
                ) {
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier.padding(horizontal = 32.dp)
                    ) {
                        if (isScanning) {
                            Box(contentAlignment = Alignment.CenterStart) {
                                Text(
                                    text = "Checking in...",
                                    fontSize = 16.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.Transparent
                                )
                                Text(
                                    text = "Checking in$animatedDots",
                                    fontSize = 16.5.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White
                                )
                            }
                        } else {
                            Text(
                                text = "Ready",
                                fontSize = 16.5.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                        }
                    }
                }
            }
        }
    }
}

// Animated verified presentation with the sunglasses thumbs-up meme emoji
@Composable
private fun VerifiedStatusAnimation(key: Any? = null) {
    val scale = remember(key) { Animatable(0.2f) }
    val rotation = remember(key) { Animatable(-8f) }
    val textAlpha = remember(key) { Animatable(0f) }
    val textOffsetY = remember(key) { Animatable(8f) }

    val verifiedColor = AppTheme.colors.primaryPurple

    // Entrance: bouncy spring pop with swagger tilt settle
    LaunchedEffect(key) {
        launch {
            scale.animateTo(
                targetValue = 1f,
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioMediumBouncy,
                    stiffness = Spring.StiffnessLow
                )
            )
        }
        launch {
            rotation.animateTo(
                targetValue = 4f,
                animationSpec = tween(180, easing = FastOutSlowInEasing)
            )
            rotation.animateTo(
                targetValue = 0f,
                animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy)
            )
        }
        launch {
            delay(120L)
            launch { textAlpha.animateTo(1f, animationSpec = tween(240)) }
            launch { textOffsetY.animateTo(0f, animationSpec = spring(dampingRatio = Spring.DampingRatioLowBouncy)) }
        }
    }

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.graphicsLayer {
            scaleX = scale.value
            scaleY = scale.value
            rotationZ = rotation.value
        }
    ) {
        Box(
            contentAlignment = Alignment.Center
        ) {
            // Soft ambient glow halo contained behind meme
            Box(
                modifier = Modifier
                    .size(170.dp)
                    .background(
                        brush = Brush.radialGradient(
                            colors = listOf(
                                verifiedColor.copy(alpha = 0.32f),
                                verifiedColor.copy(alpha = 0.08f),
                                Color.Transparent
                            )
                        ),
                        shape = CircleShape
                    )
            )

            Image(
                painter = painterResource(id = R.drawable.meme_verified),
                contentDescription = "Verified Meme",
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .height(150.dp)
                    .wrapContentWidth()
            )
        }

        Spacer(modifier = Modifier.height(4.dp))

        // Clean bold verification typography
        Text(
            text = "Verified",
            fontSize = 40.sp,
            fontWeight = FontWeight.Black,
            color = verifiedColor,
            letterSpacing = (-0.5).sp,
            modifier = Modifier.graphicsLayer {
                alpha = textAlpha.value
                translationY = textOffsetY.value
            }
        )
    }
}

// Animated unverified presentation with the angry clenched-fists meme emoji
@Composable
private fun UnverifiedStatusAnimation(key: Any? = null) {
    val scale = remember(key) { Animatable(0.4f) }
    val shakeOffset = remember(key) { Animatable(0f) }
    val textAlpha = remember(key) { Animatable(0f) }
    val textOffsetY = remember(key) { Animatable(8f) }

    val unverifiedColor = AppTheme.colors.accentOrange

    // Entrance: punch-in impact followed by angry shake
    LaunchedEffect(key) {
        launch {
            scale.animateTo(1f, animationSpec = tween(180, easing = FastOutSlowInEasing))
        }

        delay(120L)
        launch {
            shakeOffset.animateTo(-16f, tween(35))
            shakeOffset.animateTo(14f, tween(35))
            shakeOffset.animateTo(-10f, tween(35))
            shakeOffset.animateTo(8f, tween(35))
            shakeOffset.animateTo(-4f, tween(35))
            shakeOffset.animateTo(0f, tween(35))
        }

        launch {
            textAlpha.animateTo(1f, animationSpec = tween(240))
            textOffsetY.animateTo(0f, animationSpec = spring(dampingRatio = Spring.DampingRatioLowBouncy))
        }
    }

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.graphicsLayer {
            scaleX = scale.value
            scaleY = scale.value
            translationX = shakeOffset.value
        }
    ) {
        Box(
            contentAlignment = Alignment.Center
        ) {
            // Soft ambient glow halo contained behind meme
            Box(
                modifier = Modifier
                    .size(170.dp)
                    .background(
                        brush = Brush.radialGradient(
                            colors = listOf(
                                unverifiedColor.copy(alpha = 0.32f),
                                unverifiedColor.copy(alpha = 0.08f),
                                Color.Transparent
                            )
                        ),
                        shape = CircleShape
                    )
            )

            Image(
                painter = painterResource(id = R.drawable.meme_unverified),
                contentDescription = "Unverified Meme",
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .height(150.dp)
                    .wrapContentWidth()
            )
        }

        Spacer(modifier = Modifier.height(4.dp))

        // Clean bold unverified typography
        Text(
            text = "Unverified",
            fontSize = 40.sp,
            fontWeight = FontWeight.Black,
            color = unverifiedColor,
            letterSpacing = (-0.5).sp,
            modifier = Modifier.graphicsLayer {
                alpha = textAlpha.value
                translationY = textOffsetY.value
            }
        )
    }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun LeaveStudentPanel(
    applications: List<LeaveApplicationResponse>,
    isLoading: Boolean,
    isSubmitting: Boolean,
    message: String?,
    onSubmit: (String, String, String) -> Unit,
    modifier: Modifier = Modifier
) {
    var reason by rememberSaveable { mutableStateOf("") }
    var fromMillis by rememberSaveable { mutableStateOf<Long?>(null) }
    var toMillis by rememberSaveable { mutableStateOf<Long?>(null) }
    var showFromPicker by remember { mutableStateOf(false) }
    var showToPicker by remember { mutableStateOf(false) }

    fun fmt(millis: Long?): String {
        if (millis == null) return "Select date"
        val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        sdf.timeZone = TimeZone.getTimeZone("UTC")
        return sdf.format(Date(millis))
    }

    val fromText = fmt(fromMillis)
    val toText = fmt(toMillis)
    val canSubmit = fromMillis != null && toMillis != null && reason.trim().length >= 3 && !isSubmitting

    Column(
        modifier = modifier
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = "New application",
            fontSize = 16.sp,
            fontWeight = FontWeight.SemiBold,
            color = AppTheme.colors.textPrimary
        )

        Surface(
            shape = RoundedCornerShape(16.dp),
            color = AppTheme.colors.surface,
            border = BorderStroke(1.dp, AppTheme.colors.surfaceBorder.copy(alpha = 0.5f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Surface(
                        onClick = { showFromPicker = true },
                        shape = RoundedCornerShape(12.dp),
                        color = AppTheme.colors.background,
                        border = BorderStroke(1.dp, AppTheme.colors.surfaceBorder),
                        modifier = Modifier.weight(1f)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text("From", fontSize = 12.sp, color = AppTheme.colors.textSecondary)
                            Text(
                                if (fromMillis == null) "Select" else fromText,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Medium,
                                color = if (fromMillis == null) AppTheme.colors.textMuted else AppTheme.colors.textPrimary
                            )
                        }
                    }
                    Surface(
                        onClick = { showToPicker = true },
                        shape = RoundedCornerShape(12.dp),
                        color = AppTheme.colors.background,
                        border = BorderStroke(1.dp, AppTheme.colors.surfaceBorder),
                        modifier = Modifier.weight(1f)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text("To", fontSize = 12.sp, color = AppTheme.colors.textSecondary)
                            Text(
                                if (toMillis == null) "Select" else toText,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Medium,
                                color = if (toMillis == null) AppTheme.colors.textMuted else AppTheme.colors.textPrimary
                            )
                        }
                    }
                }

                OutlinedTextField(
                    value = reason,
                    onValueChange = { reason = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Reason") },
                    minLines = 3,
                    maxLines = 5,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = AppTheme.colors.primaryPurple,
                        unfocusedBorderColor = AppTheme.colors.surfaceBorder,
                        focusedLabelColor = AppTheme.colors.primaryPurple,
                        cursorColor = AppTheme.colors.primaryPurple
                    )
                )

                if (!message.isNullOrBlank()) {
                    val ok = message.contains("submitted", ignoreCase = true)
                    Text(
                        text = message,
                        fontSize = 13.sp,
                        color = if (ok) AppTheme.colors.successGreen else AppTheme.colors.dangerRed
                    )
                }

                Surface(
                    onClick = {
                        if (canSubmit) {
                            onSubmit(fromText, toText, reason.trim())
                            reason = ""
                            fromMillis = null
                            toMillis = null
                        }
                    },
                    shape = RoundedCornerShape(12.dp),
                    color = if (canSubmit) AppTheme.colors.primaryPurple else AppTheme.colors.surfaceBorder,
                    modifier = Modifier.fillMaxWidth().height(46.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(
                            text = if (isSubmitting) "Submitting…" else "Submit application",
                            fontWeight = FontWeight.SemiBold,
                            color = if (canSubmit) Color.White else AppTheme.colors.textMuted
                        )
                    }
                }
            }
        }

        Text(
            text = "My applications",
            fontSize = 16.sp,
            fontWeight = FontWeight.SemiBold,
            color = AppTheme.colors.textPrimary
        )

        if (isLoading) {
            Text("Loading…", fontSize = 14.sp, color = AppTheme.colors.textSecondary)
        } else if (applications.isEmpty()) {
            Text("No applications yet.", fontSize = 14.sp, color = AppTheme.colors.textSecondary)
        } else {
            applications.forEach { app ->
                LeaveApplicationCard(app)
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
    }

    if (showFromPicker) {
        val state = rememberDatePickerState(initialSelectedDateMillis = fromMillis)
        DatePickerDialog(
            onDismissRequest = { showFromPicker = false },
            confirmButton = {
                TextButton(onClick = {
                    fromMillis = state.selectedDateMillis
                    showFromPicker = false
                }) { Text("OK") }
            },
            dismissButton = {
                TextButton(onClick = { showFromPicker = false }) { Text("Cancel") }
            }
        ) { DatePicker(state = state) }
    }
    if (showToPicker) {
        val state = rememberDatePickerState(initialSelectedDateMillis = toMillis)
        DatePickerDialog(
            onDismissRequest = { showToPicker = false },
            confirmButton = {
                TextButton(onClick = {
                    toMillis = state.selectedDateMillis
                    showToPicker = false
                }) { Text("OK") }
            },
            dismissButton = {
                TextButton(onClick = { showToPicker = false }) { Text("Cancel") }
            }
        ) { DatePicker(state = state) }
    }
}

@Composable
private fun LeaveApplicationCard(app: LeaveApplicationResponse) {
    val statusColor = when (app.status.uppercase()) {
        "APPROVED" -> AppTheme.colors.successGreen
        "REJECTED" -> AppTheme.colors.dangerRed
        else -> AppTheme.colors.accentOrange
    }
    val statusBg = statusColor.copy(alpha = 0.12f)
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = AppTheme.colors.surface,
        border = BorderStroke(1.dp, AppTheme.colors.surfaceBorder.copy(alpha = 0.5f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${app.fromDate} → ${app.toDate}",
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AppTheme.colors.textPrimary
                )
                Surface(shape = RoundedCornerShape(8.dp), color = statusBg) {
                    Text(
                        text = app.status,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = statusColor,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }
            if (app.reason.isNotBlank()) {
                Text(app.reason, fontSize = 13.sp, color = AppTheme.colors.textSecondary, maxLines = 3)
            }
            if (!app.reviewComment.isNullOrBlank()) {
                Text(
                    text = "HOD: ${app.reviewComment}",
                    fontSize = 12.sp,
                    color = AppTheme.colors.textMuted
                )
            }
        }
    }
}

