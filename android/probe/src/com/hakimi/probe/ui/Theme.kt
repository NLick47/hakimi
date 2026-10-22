package com.hakimi.probe.ui

import android.app.Activity
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.os.Build
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import com.hakimi.probe.R

/** Hand-built design tokens; no Material Components, no AndroidX. */
object Palette {
    val BG = 0xFFF6FAFC.toInt()
    val BG_SOFT = 0xFFF2F8FB.toInt()
    val SURFACE = 0xFFFFFFFF.toInt()
    val SURFACE_HI = 0xFFF8FCFE.toInt()
    val SURFACE_2 = 0xFFF1F7FA.toInt()
    val SURFACE_GLASS = 0xFFFFFFFF.toInt()
    val BORDER = 0xFFDDE9F0.toInt()
    val BORDER_STRONG = 0xFFCBDDE7.toInt()
    val HAIRLINE = 0xFFE7F0F5.toInt()
    val TEXT = 0xFF172A3A.toInt()
    val TEXT_2 = 0xFF486274.toInt()
    val MUTED = 0xFF7A8E9C.toInt()
    val ACCENT = 0xFF0E9FD8.toInt()
    val ACCENT_DIM = 0xFF0284C7.toInt()
    val ACCENT_SOFT = 0xFFE4F5FC.toInt()
    val MINT = 0xFF5EEAD4.toInt()
    val GREEN = 0xFF178F79.toInt()
    val AMBER = 0xFFB07A1E.toInt()
    val RED = 0xFFC25B5B.toInt()
    val PURPLE = 0xFF7C6BD6.toInt()
    val CYAN = 0xFF22D3EE.toInt()
    val GOLD = 0xFFD9AE4A.toInt()
    val DARK_TEXT = 0xFFFFFFFF.toInt()
}

fun Context.dp(value: Number): Int =
    (resources.displayMetrics.density * value.toFloat() + 0.5f).toInt()

fun Context.text(
    value: CharSequence,
    size: Float,
    color: Int = Palette.TEXT,
    medium: Boolean = false,
    letterSpacing: Float = 0f,
): TextView = TextView(this).apply {
    text = value
    setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
    setTextColor(color)
    includeFontPadding = false
    if (letterSpacing != 0f) this.letterSpacing = letterSpacing
    typeface = Typeface.create(
        if (medium) "sans-serif-medium" else "sans-serif",
        Typeface.NORMAL
    )
}

fun Context.monospace(value: CharSequence, size: Float, color: Int = Palette.TEXT_2): TextView =
    text(value, size, color).apply {
        typeface = Typeface.create("monospace", Typeface.NORMAL)
        letterSpacing = 0f
    }

fun Context.rounded(
    fill: Int,
    radius: Float,
    stroke: Int = Color.TRANSPARENT,
    strokeWidth: Float = 0f,
): GradientDrawable = GradientDrawable().apply {
    shape = GradientDrawable.RECTANGLE
    setColor(fill)
    cornerRadius = dp(radius).toFloat()
    if (strokeWidth > 0f) setStroke(dp(strokeWidth), stroke)
}

fun Context.roundedTop(fill: Int, radius: Float, stroke: Int = Color.TRANSPARENT): GradientDrawable =
    GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        setColor(fill)
        val r = dp(radius).toFloat()
        cornerRadii = floatArrayOf(r, r, r, r, 0f, 0f, 0f, 0f)
        setStroke(dp(1f), stroke)
    }

fun Context.gradient(
    colors: IntArray,
    radius: Float,
    orientation: GradientDrawable.Orientation = GradientDrawable.Orientation.TL_BR,
): GradientDrawable = GradientDrawable(orientation, colors).apply {
    shape = GradientDrawable.RECTANGLE
    cornerRadius = dp(radius).toFloat()
}

fun Context.ripple(
    fill: Int,
    radius: Float,
    rippleColor: Int = 0x33FFFFFF,
    stroke: Int = Color.TRANSPARENT,
    strokeWidth: Float = 0f,
): RippleDrawable = RippleDrawable(
    ColorStateList.valueOf(rippleColor),
    rounded(fill, radius, stroke, strokeWidth),
    null
)

fun Context.icon(res: Int, tint: Int = Palette.TEXT, size: Float = 22f): ImageView =
    ImageView(this).apply {
        setImageResource(res)
        setColorFilter(tint)
        scaleType = ImageView.ScaleType.FIT_CENTER
        layoutParams = LinearLayout.LayoutParams(dp(size), dp(size))
    }

fun Context.spacer(height: Float): View = View(this).apply {
    layoutParams = LinearLayout.LayoutParams(1, dp(height))
}

fun Context.divider(insetStart: Float = 0f): View = View(this).apply {
    setBackgroundColor(Palette.HAIRLINE)
    layoutParams = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        dp(1f)
    ).apply {
        marginStart = dp(insetStart)
    }
}

fun Context.column(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.VERTICAL
}

fun Context.row(): LinearLayout = LinearLayout(this).apply {
    orientation = LinearLayout.HORIZONTAL
    gravity = Gravity.CENTER_VERTICAL
}

fun Context.card(
    radius: Float = 24f,
    fill: Int = Palette.SURFACE,
    padding: Float = 18f,
    stroke: Int = Palette.BORDER,
): LinearLayout = column().apply {
    background = rounded(fill, radius, stroke, 1f)
    setPadding(dp(padding), dp(padding), dp(padding), dp(padding))
}

fun Context.pill(
    label: CharSequence,
    color: Int = Palette.TEXT_2,
    fill: Int = Palette.SURFACE_2,
    size: Float = 10f,
): TextView = text(label, size, color, medium = true).apply {
    setPadding(dp(9f), dp(4f), dp(9f), dp(4f))
    background = rounded(fill, 8f)
}

fun Context.primaryButton(label: CharSequence, action: () -> Unit): TextView =
    text(label, 14f, Palette.DARK_TEXT, medium = true).apply {
        gravity = Gravity.CENTER
        setPadding(dp(18f), dp(14f), dp(18f), dp(14f))
        background = ripple(Palette.ACCENT, 16f, 0x44FFFFFF)
        clickOnce { action() }
        isClickable = true
        isFocusable = true
    }.also { button ->
        button.background = RippleDrawable(
            ColorStateList.valueOf(0x44FFFFFF),
            gradient(intArrayOf(Palette.ACCENT, 0xFF38BDF8.toInt()), 12f),
            null
        )
    }

fun Context.ghostButton(label: CharSequence, action: () -> Unit): TextView =
    text(label, 13f, Palette.TEXT, medium = true).apply {
        gravity = Gravity.CENTER
        setPadding(dp(16f), dp(12f), dp(16f), dp(12f))
        background = ripple(Palette.SURFACE, 12f, 0x1A0EA5E9, Palette.BORDER_STRONG, 1f)
        clickOnce { action() }
        isClickable = true
        isFocusable = true
    }

fun Context.iconButton(res: Int, tint: Int = Palette.TEXT, size: Float = 44f, action: () -> Unit): View =
    android.widget.FrameLayout(this).apply {
        layoutParams = LinearLayout.LayoutParams(dp(size), dp(size))
        background = ripple(0x0A0EA5E9, size / 2f, 0x1A0EA5E9, Palette.BORDER, 1f)
        addView(icon(res, tint, 21f), android.widget.FrameLayout.LayoutParams(
            dp(21f), dp(21f), Gravity.CENTER
        ))
        clickOnce { action() }
        isClickable = true
        isFocusable = true
    }

fun Context.selectableBackground(): android.graphics.drawable.Drawable? {
    val value = TypedValue()
    theme.resolveAttribute(android.R.attr.selectableItemBackground, value, true)
    return if (value.resourceId != 0) getDrawable(value.resourceId) else null
}

fun Context.selectableBorderless(): android.graphics.drawable.Drawable? {
    val value = TypedValue()
    theme.resolveAttribute(android.R.attr.selectableItemBackgroundBorderless, value, true)
    return if (value.resourceId != 0) getDrawable(value.resourceId) else null
}

fun Context.nativePrimaryButton(label: CharSequence, action: () -> Unit): android.widget.Button =
    android.widget.Button(this).apply {
        text = label
        isAllCaps = false
        textSize = 14f
        setTextColor(Color.WHITE)
        backgroundTintList = ColorStateList.valueOf(Palette.ACCENT)
        clickOnce { action() }
        minHeight = dp(48f)
    }

fun Context.nativeTextButton(label: CharSequence, action: () -> Unit): android.widget.Button =
    android.widget.Button(this, null, android.R.attr.borderlessButtonStyle).apply {
        text = label
        isAllCaps = false
        textSize = 14f
        setTextColor(Palette.ACCENT)
        clickOnce { action() }
        minHeight = dp(48f)
    }

/** A tiny per-view click gate; prevents duplicate sheets and double actions. */
fun View.clickOnce(intervalMs: Long = 600L, action: () -> Unit) {
    setOnClickListener(object : View.OnClickListener {
        private var lastClick = 0L

        override fun onClick(v: View) {
            val now = android.os.SystemClock.elapsedRealtime()
            if (now - lastClick < intervalMs) return
            lastClick = now
            action()
        }
    })
}

private val SITE_ICONS = mapOf(
    "pixiv" to R.drawable.site_pixiv,
    "hitomi" to R.drawable.site_hitomi,
    "poipiku" to R.drawable.site_poipiku,
    "booth" to R.drawable.site_booth,
    "steam" to R.drawable.site_steam,
    "github" to R.drawable.site_github,
    "ao3" to R.drawable.site_ao3,
    "eh" to R.drawable.site_eh,
    "hanime" to R.drawable.site_hanime,
    "nhentai" to R.drawable.site_nhentai,
)

fun siteIconRes(id: String): Int {
    val key = SITE_ICONS.keys.firstOrNull {
        id.equals(it, ignoreCase = true) || id.startsWith("$it-", ignoreCase = true)
    }
    return key?.let(SITE_ICONS::get) ?: 0
}

private val TILE_COLORS = intArrayOf(
    0xFF5B7A9D.toInt(),
    0xFF4E9E6F.toInt(),
    0xFFC2913A.toInt(),
    0xFFB0685E.toInt(),
    0xFF7D6B9E.toInt(),
    0xFF3F8C8C.toInt(),
    0xFF96693F.toInt(),
    0xFF8A6A8A.toInt(),
)

fun tileColor(id: String): Int {
    if (id == "eh") return 0xFFB33A3A.toInt()
    val hash = id.toByteArray(Charsets.UTF_8).sumOf { it.toInt() and 0xff }
    return TILE_COLORS[hash % TILE_COLORS.size]
}

fun alpha(color: Int, value: Int): Int =
    (color and 0x00FFFFFF) or ((value.coerceIn(0, 255)) shl 24)

fun blend(from: Int, to: Int, fraction: Float): Int {
    val f = fraction.coerceIn(0f, 1f)
    val a = (Color.alpha(from) * (1 - f) + Color.alpha(to) * f).toInt()
    val r = (Color.red(from) * (1 - f) + Color.red(to) * f).toInt()
    val g = (Color.green(from) * (1 - f) + Color.green(to) * f).toInt()
    val b = (Color.blue(from) * (1 - f) + Color.blue(to) * f).toInt()
    return Color.argb(a, r, g, b)
}

@Suppress("DEPRECATION")
fun Activity.edgeToEdge() {
    window.setStatusBarColor(Color.TRANSPARENT)
    window.setNavigationBarColor(Color.TRANSPARENT)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        window.isStatusBarContrastEnforced = false
        window.isNavigationBarContrastEnforced = false
    }
    val lightBars = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or
        View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        window.setDecorFitsSystemWindows(false)
        window.decorView.windowInsetsController?.setSystemBarsAppearance(
            android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
            android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
        )
    } else {
        window.decorView.systemUiVisibility =
            View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION or
                lightBars
    }
}

fun View.padTopForSystemBars() {
    val base = paddingTop
    setOnApplyWindowInsetsListener { view, insets ->
        val top = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            insets.getInsets(WindowInsets.Type.systemBars()).top
        } else {
            @Suppress("DEPRECATION")
            insets.systemWindowInsetTop
        }
        view.setPadding(view.paddingLeft, base + top, view.paddingRight, view.paddingBottom)
        insets
    }
}

fun View.padBottomForSystemBars() {
    val base = paddingBottom
    setOnApplyWindowInsetsListener { view, insets ->
        val bottom = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            insets.getInsets(WindowInsets.Type.systemBars()).bottom
        } else {
            @Suppress("DEPRECATION")
            insets.systemWindowInsetBottom
        }
        view.setPadding(view.paddingLeft, view.paddingTop, view.paddingRight, base + bottom)
        insets
    }
}

fun View.fadeInUp(delay: Long = 0L, distance: Float = 14f) {
    alpha = 0f
    translationY = context.dp(distance).toFloat()
    animate().alpha(1f).translationY(0f).setStartDelay(delay).setDuration(260L).start()
}
