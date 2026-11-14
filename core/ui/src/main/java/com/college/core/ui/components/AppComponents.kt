package com.college.core.ui.components

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.scrollBy
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextFieldColors
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.IntRect
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Popup
import androidx.compose.ui.window.PopupPositionProvider
import androidx.compose.ui.window.PopupProperties
import com.college.core.model.Role
import com.college.core.model.User
import com.college.core.ui.theme.AppTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

// Centered header area displaying page title and optional subtitle
@Composable
fun AppHeader(
    title: String,
    modifier: Modifier = Modifier,
    subtitle: String? = null
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(top = 22.dp, bottom = 14.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = title,
            fontSize = 30.sp,
            fontWeight = FontWeight.Bold,
            color = AppTheme.colors.textPrimary,
            letterSpacing = (-0.6).sp
        )
        if (subtitle != null) {
            Spacer(modifier = Modifier.height(3.dp))
            Text(
                text = subtitle,
                fontSize = 13.sp,
                color = AppTheme.colors.textSecondary
            )
        }
    }
}

// User account card with title on left and avatar initial badge on right
@Composable
fun AppProfileCard(
    name: String,
    subtitle: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    initial: String? = null,
    avatarBg: Color = AppTheme.colors.accentOrange,
    avatarIcon: ImageVector? = null,
    border: BorderStroke? = BorderStroke(1.dp, AppTheme.colors.surfaceBorder)
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(22.dp),
        color = AppTheme.colors.surface,
        border = border,
        modifier = modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = name,
                    fontSize = 17.5.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = AppTheme.colors.textPrimary
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    fontSize = 13.sp,
                    color = AppTheme.colors.textSecondary
                )
            }

            Spacer(modifier = Modifier.width(14.dp))

            // Circular avatar container
            Box(
                modifier = Modifier
                    .size(46.dp)
                    .background(avatarBg, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                if (!initial.isNullOrBlank()) {
                    Text(
                        text = initial.take(1).uppercase(),
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                } else {
                    Icon(
                        imageVector = avatarIcon ?: Icons.Default.Person,
                        contentDescription = name,
                        tint = Color.White,
                        modifier = Modifier.size(24.dp)
                    )
                }
            }
        }
    }
}

// Formats department short forms (e.g. CSE, ME) to full names
fun formatDepartmentName(raw: String?): String {
    if (raw.isNullOrBlank()) return ""
    val trimmed = raw.trim()
    return when (trimmed.uppercase()) {
        "CSE", "CS", "C.S.E.", "C.S.E", "C.S." -> "Computer Science"
        "ME", "M.E.", "M.E" -> "Mechanical Engineering"
        "IT", "I.T.", "I.T" -> "Information Technology"
        "ECE", "E.C.E.", "E.C.E" -> "Electronics & Communication"
        "CE", "C.E.", "C.E", "CIVIL" -> "Civil Engineering"
        "EE", "E.E.", "E.E", "ELECTRICAL" -> "Electrical Engineering"
        "EEE", "E.E.E.", "E.E.E" -> "Electrical & Electronics"
        "BCA" -> "Computer Applications"
        "MCA" -> "Computer Applications"
        else -> {
            when {
                trimmed.equals("B-Tech CSE", ignoreCase = true) || trimmed.equals("B.Tech CSE", ignoreCase = true) -> "Computer Science"
                trimmed.equals("B-Tech ME", ignoreCase = true) || trimmed.equals("B.Tech ME", ignoreCase = true) -> "Mechanical Engineering"
                trimmed.equals("B-Tech IT", ignoreCase = true) || trimmed.equals("B.Tech IT", ignoreCase = true) -> "Information Technology"
                trimmed.equals("B-Tech ECE", ignoreCase = true) || trimmed.equals("B.Tech ECE", ignoreCase = true) -> "Electronics & Communication"
                trimmed.equals("B-Tech CE", ignoreCase = true) || trimmed.equals("B.Tech CE", ignoreCase = true) -> "Civil Engineering"
                trimmed.equals("B-Tech EE", ignoreCase = true) || trimmed.equals("B.Tech EE", ignoreCase = true) -> "Electrical Engineering"
                else -> trimmed
            }
        }
    }
}

// Pokemon 2D Game inspired Trainer Card profile component
@Composable
fun PokemonTrainerCard(
    user: User?,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    onRoleClick: (() -> Unit)? = null
) {
    val gymBadgeColors = listOf(
        Color(0xFF64748B), // 1: Boulder / Slate
        Color(0xFF0284C7), // 2: Cascade / Blue
        Color(0xFFF59E0B), // 3: Thunder / Amber
        Color(0xFF10B981), // 4: Rainbow / Green
        Color(0xFFEC4899), // 5: Soul / Pink
        Color(0xFFF97316), // 6: Marsh / Orange
        Color(0xFFEF4444), // 7: Volcano / Red
        Color(0xFF8B5CF6)  // 8: Earth / Violet
    )

    val currentSem = user?.semester ?: if (user != null) 4 else 0
    val primaryRole = user?.primaryRole
    val roleTitle = when {
        user == null -> null
        primaryRole != null -> primaryRole.name.uppercase()
        user.roles.isNotEmpty() -> user.roles.first().name.uppercase()
        else -> "STUDENT"
    }
    val avatarColor = when (primaryRole) {
        Role.TEACHER -> AppTheme.colors.primaryPurple
        Role.HOD -> AppTheme.colors.primaryPurple
        Role.DEVELOPER -> AppTheme.colors.warningAmber
        Role.STAFF -> AppTheme.colors.infoBlue
        else -> AppTheme.colors.accentOrange
    }

    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(20.dp),
        color = AppTheme.colors.surface,
        border = BorderStroke(1.5.dp, AppTheme.colors.surfaceBorder),
        shadowElevation = if (AppTheme.colors.isDark) 0.dp else 3.dp,
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Header: PROFILE CARD + ROLE pill
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(AppTheme.colors.primaryPurple)
                    )
                    Text(
                        text = "PROFILE CARD",
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Black,
                        fontSize = 14.sp,
                        letterSpacing = 2.2.sp,
                        color = AppTheme.colors.textPrimary
                    )
                }
                if (!roleTitle.isNullOrBlank() && roleTitle != "GUEST") {
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = AppTheme.colors.accentOrange,
                        modifier = if (onRoleClick != null) {
                            Modifier.clickable(onClick = onRoleClick)
                        } else {
                            Modifier
                        }
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.5.dp)
                        ) {
                            Text(
                                text = roleTitle,
                                fontSize = 9.5.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                color = Color.White
                            )
                            if (onRoleClick != null) {
                                Icon(
                                    imageVector = Icons.Default.SwapHoriz,
                                    contentDescription = "Change Role",
                                    tint = Color.White,
                                    modifier = Modifier.size(12.dp)
                                )
                            }
                        }
                    }
                }
            }

            // Middle: Sprite color box + Name, Roll, Dept
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(18.dp)
            ) {
                // Sprite color block sized to equal the height of the 3 text lines
                Box(
                    modifier = Modifier
                        .size(70.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .background(avatarColor)
                )

                // Info lines (no labels/prefixes)
                Column(
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        text = user?.name ?: "Student",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        color = AppTheme.colors.textPrimary
                    )
                    val roll = user?.rollNumber ?: user?.email
                    if (!roll.isNullOrBlank()) {
                        Text(
                            text = roll,
                            fontSize = 13.sp,
                            fontFamily = FontFamily.Monospace,
                            color = AppTheme.colors.textSecondary
                        )
                    }
                    val dept = formatDepartmentName(user?.department ?: user?.program)
                    if (dept.isNotBlank()) {
                        Text(
                            text = dept,
                            fontSize = 12.sp,
                            color = AppTheme.colors.textSecondary.copy(alpha = 0.75f)
                        )
                    }
                }
            }

            // F3: XP/level row — students only (no chimp game, no bar for
            // other roles). Fill uses the level's gym-badge color; level 5 is
            // the cap and shows MAX.
            if (user?.hasRole(Role.STUDENT) == true) {
                val level = user.gameLevel.coerceIn(1, 5)
                val xpColor = gymBadgeColors[level - 1]
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = xpColor
                    ) {
                        Text(
                            text = if (level >= 5) "LV $level MAX" else "LV $level",
                            fontSize = 9.5.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = Color.White,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.5.dp)
                        )
                    }
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .height(8.dp)
                            .clip(RoundedCornerShape(4.dp))
                            .background(AppTheme.colors.surfaceBorder)
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxHeight()
                                .fillMaxWidth(user.gameXpProgress.coerceIn(0f, 1f))
                                .clip(RoundedCornerShape(4.dp))
                                .background(xpColor)
                        )
                    }
                }
            }

            HorizontalDivider(color = AppTheme.colors.surfaceBorder, thickness = 1.dp)

            // Gym badge dots (semesters 1 to 8 with number inside)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                (1..8).forEach { sem ->
                    val isEarned = sem <= currentSem
                    val badgeColor = gymBadgeColors[sem - 1]

                    Box(
                        modifier = Modifier
                            .size(26.dp)
                            .background(
                                color = if (isEarned) badgeColor else AppTheme.colors.surface,
                                shape = CircleShape
                            )
                            .border(
                                width = 1.5.dp,
                                color = if (isEarned) badgeColor else AppTheme.colors.surfaceBorder,
                                shape = CircleShape
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "$sem",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = if (isEarned) Color.White else AppTheme.colors.textSecondary.copy(alpha = 0.4f)
                        )
                    }
                }
            }
        }
    }
}

// Rounded container for grouping menu rows
@Composable
fun AppCardGroup(
    modifier: Modifier = Modifier,
    border: BorderStroke? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    Surface(
        shape = RoundedCornerShape(22.dp),
        color = AppTheme.colors.surface,
        border = border,
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            content = content
        )
    }
}

// Menu row item with icon badge, title, subtitle, and chevron
@Composable
fun AppCardItem(
    icon: ImageVector,
    iconTint: Color,
    iconBg: Color,
    title: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    trailing: (@Composable () -> Unit)? = null
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = if (subtitle != null) 12.dp else 13.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Icon badge with tinted background
        Box(
            modifier = Modifier
                .size(36.dp)
                .background(iconBg, CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = iconTint,
                modifier = Modifier.size(19.dp)
            )
        }

        Spacer(modifier = Modifier.width(14.dp))

        // Title and optional subtitle
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 16.5.sp,
                fontWeight = FontWeight.SemiBold,
                color = AppTheme.colors.textPrimary
            )
            if (subtitle != null) {
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    fontSize = 12.sp,
                    color = AppTheme.colors.textSecondary
                )
            }
        }

        // Trailing content or arrow chevron
        if (trailing != null) {
            trailing()
        } else {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = AppTheme.colors.textMuted.copy(alpha = 0.6f),
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

// Inset divider separating row items using the main background color
@Composable
fun AppDivider(
    modifier: Modifier = Modifier
) {
    HorizontalDivider(
        color = AppTheme.colors.background,
        thickness = 1.dp,
        modifier = modifier.padding(start = 66.dp, end = 0.dp)
    )
}

// Floating interactive search pill pinned at bottom
@Composable
fun AppSearchPill(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = "Search",
    focusRequester: FocusRequester = remember { FocusRequester() },
    keyboardOptions: KeyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
    onSearch: (() -> Unit)? = null
) {
    val keyboardController = LocalSoftwareKeyboardController.current

    Surface(
        shape = RoundedCornerShape(24.dp),
        color = AppTheme.colors.surface,
        border = BorderStroke(1.dp, AppTheme.colors.surfaceBorder),
        shadowElevation = if (AppTheme.colors.isDark) 0.dp else 4.dp,
        modifier = modifier
            .imePadding()
            .padding(bottom = 16.dp)
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null
            ) {
                focusRequester.requestFocus()
            }
    ) {
        Row(
            modifier = Modifier
                .height(46.dp)
                .padding(horizontal = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Search icon on left
            Icon(
                imageVector = Icons.Default.Search,
                contentDescription = "Search",
                tint = AppTheme.colors.textSecondary,
                modifier = Modifier.size(18.dp)
            )

            Spacer(modifier = Modifier.width(8.dp))

            // Centered input field
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                modifier = Modifier
                    .widthIn(min = 52.dp, max = 240.dp)
                    .focusRequester(focusRequester),
                singleLine = true,
                keyboardOptions = keyboardOptions,
                keyboardActions = KeyboardActions(onSearch = {
                    onSearch?.invoke()
                    keyboardController?.hide()
                }),
                textStyle = TextStyle(
                    color = AppTheme.colors.textPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Normal,
                    textAlign = TextAlign.Center
                ),
                cursorBrush = SolidColor(AppTheme.colors.primaryPurple),
                decorationBox = { innerTextField ->
                    Box(contentAlignment = Alignment.Center) {
                        if (value.isEmpty()) {
                            Text(
                                text = placeholder,
                                color = AppTheme.colors.textSecondary,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Normal,
                                textAlign = TextAlign.Center,
                                maxLines = 1,
                                softWrap = false
                            )
                        }
                        innerTextField()
                    }
                }
            )

            // Right slot for clear button or symmetrical spacer
            if (value.isNotEmpty()) {
                Spacer(modifier = Modifier.width(6.dp))
                Box(
                    modifier = Modifier
                        .size(20.dp)
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null
                        ) {
                            onValueChange("")
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Clear",
                        tint = AppTheme.colors.textSecondary,
                        modifier = Modifier.size(16.dp)
                    )
                }
            } else {
                Spacer(modifier = Modifier.width(26.dp))
            }
        }
    }
}

// Text field color styling matching active theme
@Composable
fun appTextFieldColors(
    unfocusedBorderColor: Color = AppTheme.colors.surfaceBorder,
    focusedBorderColor: Color = AppTheme.colors.primaryPurple
) = OutlinedTextFieldDefaults.colors(
    focusedTextColor = AppTheme.colors.textPrimary,
    unfocusedTextColor = AppTheme.colors.textPrimary,
    focusedContainerColor = AppTheme.colors.surface,
    unfocusedContainerColor = AppTheme.colors.surface,
    focusedBorderColor = focusedBorderColor,
    unfocusedBorderColor = unfocusedBorderColor,
    focusedLabelColor = AppTheme.colors.primaryPurple,
    unfocusedLabelColor = AppTheme.colors.textSecondary,
    cursorColor = AppTheme.colors.primaryPurple
)

// Reusable dropdown popup field for selection forms
@Composable
fun AppDropdownField(
    label: String,
    selectedValue: String,
    options: List<String>,
    onSelect: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = "Select $label",
    allowEmpty: Boolean = true,
    colors: TextFieldColors = appTextFieldColors()
) {
    var expanded by remember { mutableStateOf(false) }
    var anchorWidthPx by remember { mutableStateOf(0) }

    val allOptions = remember(options, allowEmpty) {
        if (allowEmpty && !options.contains("")) listOf("") + options else options
    }

    Box(
        modifier = modifier.onGloballyPositioned { coordinates ->
            anchorWidthPx = coordinates.size.width
        }
    ) {
        OutlinedTextField(
            value = selectedValue,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            placeholder = { Text(placeholder, color = AppTheme.colors.textSecondary) },
            colors = colors,
            shape = RoundedCornerShape(12.dp),
            trailingIcon = {
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(
                        imageVector = Icons.Filled.ArrowDropDown,
                        contentDescription = "Select $label",
                        tint = AppTheme.colors.textSecondary,
                        modifier = Modifier.rotate(if (expanded) 180f else 0f)
                    )
                }
            },
            modifier = Modifier.fillMaxWidth()
        )

        // Transparent overlay consuming clicks
        Surface(
            onClick = { expanded = !expanded },
            color = Color.Transparent,
            modifier = Modifier.matchParentSize()
        ) {}

        if (expanded) {
            val density = LocalDensity.current
            val positionProvider = remember(density) {
                object : PopupPositionProvider {
                    override fun calculatePosition(
                        anchorBounds: IntRect,
                        windowSize: IntSize,
                        layoutDirection: LayoutDirection,
                        popupContentSize: IntSize
                    ): IntOffset {
                        val offsetDown = with(density) { 4.dp.roundToPx() }
                        return IntOffset(
                            x = anchorBounds.left,
                            y = anchorBounds.bottom + offsetDown
                        )
                    }
                }
            }

            Popup(
                popupPositionProvider = positionProvider,
                onDismissRequest = { expanded = false },
                properties = PopupProperties(
                    focusable = true,
                    dismissOnBackPress = true,
                    dismissOnClickOutside = true
                )
            ) {
                val anchorWidthDp = with(density) { anchorWidthPx.toDp() }
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = AppTheme.colors.surface,
                    shadowElevation = if (AppTheme.colors.isDark) 0.dp else 6.dp,
                    border = BorderStroke(1.dp, AppTheme.colors.textSecondary),
                    modifier = Modifier.width(if (anchorWidthDp > 0.dp) anchorWidthDp else 280.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 200.dp)
                            .verticalScroll(rememberScrollState())
                            .padding(vertical = 4.dp)
                    ) {
                        allOptions.forEach { option ->
                            val isSelected = option == selectedValue
                            Surface(
                                onClick = {
                                    onSelect(option)
                                    expanded = false
                                },
                                color = if (isSelected) AppTheme.colors.primaryPurpleBg else Color.Transparent,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 16.dp, vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = if (option.isEmpty()) "— None (Empty) —" else option,
                                        fontSize = 14.sp,
                                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                        color = if (option.isEmpty()) {
                                            AppTheme.colors.textSecondary
                                        } else if (isSelected) {
                                            AppTheme.colors.primaryPurple
                                        } else {
                                            AppTheme.colors.textPrimary
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// Text input field with smooth edge auto-scrolling when dragging cursor
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppTextField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    readOnly: Boolean = false,
    textStyle: TextStyle = LocalTextStyle.current.copy(
        color = AppTheme.colors.textPrimary,
        fontSize = 15.5.sp
    ),
    label: @Composable (() -> Unit)? = null,
    placeholder: @Composable (() -> Unit)? = null,
    leadingIcon: @Composable (() -> Unit)? = null,
    trailingIcon: @Composable (() -> Unit)? = null,
    isError: Boolean = false,
    supportingText: @Composable (() -> Unit)? = null,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    keyboardActions: KeyboardActions = KeyboardActions.Default,
    singleLine: Boolean = true,
    interactionSource: MutableInteractionSource = remember { MutableInteractionSource() },
    shape: Shape = RoundedCornerShape(12.dp),
    colors: TextFieldColors = appTextFieldColors()
) {
    // Track cursor selection state
    var textFieldValue by remember {
        mutableStateOf(TextFieldValue(text = value, selection = TextRange(value.length)))
    }

    // Synchronize selection when incoming text changes
    if (textFieldValue.text != value) {
        val newEnd = textFieldValue.selection.end.coerceIn(0, value.length)
        val newStart = textFieldValue.selection.start.coerceIn(0, value.length)
        textFieldValue = textFieldValue.copy(
            text = value,
            selection = TextRange(newStart, newEnd)
        )
    }

    val scrollState = rememberScrollState()
    var textLayoutResult by remember { mutableStateOf<TextLayoutResult?>(null) }
    var viewportWidthPx by remember { mutableIntStateOf(0) }
    val density = LocalDensity.current
    val edgeThresholdPx = with(density) { 36.dp.toPx() }

    // Auto-scroll when dragging cursor or typing near edges
    LaunchedEffect(textFieldValue.selection, textFieldValue.text, viewportWidthPx, textLayoutResult) {
        val layout = textLayoutResult ?: return@LaunchedEffect
        if (viewportWidthPx <= 0) return@LaunchedEffect

        // Guard against stale text layout result when typing fast
        val transformed = visualTransformation.filter(AnnotatedString(textFieldValue.text))
        val layoutLength = layout.layoutInput.text.length
        if (layoutLength != transformed.text.length) {
            return@LaunchedEffect
        }

        val rawCursor = textFieldValue.selection.start.coerceIn(0, textFieldValue.text.length)
        val transformedCursor = try {
            transformed.offsetMapping.originalToTransformed(rawCursor).coerceIn(0, layoutLength)
        } catch (_: Throwable) {
            rawCursor.coerceIn(0, layoutLength)
        }

        while (isActive) {
            val cursorRect = try {
                layout.getCursorRect(transformedCursor)
            } catch (_: Throwable) {
                break
            }
            val cursorX = cursorRect.left
            val viewStart = scrollState.value.toFloat()
            val viewEnd = viewStart + viewportWidthPx

            if (cursorX > viewEnd - edgeThresholdPx && scrollState.canScrollForward) {
                val distance = (cursorX - (viewEnd - edgeThresholdPx)).coerceAtLeast(1f)
                val step = (distance / edgeThresholdPx * 18f).coerceIn(6f, 28f)
                scrollState.scrollBy(step)
                delay(16L)
            } else if (cursorX < viewStart + edgeThresholdPx && scrollState.canScrollBackward) {
                val distance = ((viewStart + edgeThresholdPx) - cursorX).coerceAtLeast(1f)
                val step = (distance / edgeThresholdPx * 18f).coerceIn(6f, 28f)
                scrollState.scrollBy(-step)
                delay(16L)
            } else {
                break
            }
        }
    }

    // Input component wrapped in horizontal scroller
    BasicTextField(
        value = textFieldValue,
        onValueChange = { newValue ->
            val sanitized = if (singleLine) {
                newValue.copy(text = newValue.text.replace("\n", "").replace("\r", ""))
            } else {
                newValue
            }
            textFieldValue = sanitized
            if (sanitized.text != value) {
                onValueChange(sanitized.text)
            }
        },
        modifier = modifier,
        enabled = enabled,
        readOnly = readOnly,
        textStyle = textStyle,
        keyboardOptions = keyboardOptions,
        keyboardActions = keyboardActions,
        singleLine = false,
        maxLines = if (singleLine) 1 else Int.MAX_VALUE,
        visualTransformation = visualTransformation,
        onTextLayout = { textLayoutResult = it },
        interactionSource = interactionSource,
        cursorBrush = SolidColor(AppTheme.colors.primaryPurple),
        decorationBox = @Composable { innerTextField ->
            OutlinedTextFieldDefaults.DecorationBox(
                value = textFieldValue.text,
                innerTextField = {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .onGloballyPositioned { coordinates ->
                                viewportWidthPx = coordinates.size.width
                            }
                            .horizontalScroll(scrollState)
                    ) {
                        innerTextField()
                    }
                },
                enabled = enabled,
                singleLine = singleLine,
                visualTransformation = visualTransformation,
                interactionSource = interactionSource,
                isError = isError,
                label = label,
                placeholder = placeholder,
                supportingText = supportingText,
                leadingIcon = leadingIcon,
                trailingIcon = trailingIcon,
                colors = colors,
                container = {
                    OutlinedTextFieldDefaults.ContainerBox(
                        enabled = enabled,
                        isError = isError,
                        interactionSource = interactionSource,
                        colors = colors,
                        shape = shape
                    )
                }
            )
        }
    )
}

// Subtle vertical scrollbar indicator drawn on right edge when scrollable
fun Modifier.appScrollbar(
    state: ScrollState,
    color: Color = Color.Gray.copy(alpha = 0.35f),
    width: Dp = 4.dp
): Modifier = drawWithContent {
    drawContent()
    if (state.maxValue > 0) {
        val totalHeight = size.height
        val barHeight = (totalHeight * (totalHeight / (state.maxValue + totalHeight))).coerceAtLeast(32.dp.toPx())
        val barOffset = (state.value.toFloat() / state.maxValue) * (totalHeight - barHeight)
        drawRoundRect(
            color = color,
            topLeft = Offset(size.width - width.toPx() - 2.dp.toPx(), barOffset),
            size = Size(width.toPx(), barHeight),
            cornerRadius = CornerRadius(width.toPx() / 2, width.toPx() / 2)
        )
    }
}
