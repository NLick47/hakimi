package com.hakimi.probe.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.DashPathEffect
import android.graphics.LinearGradient
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.SweepGradient
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.util.AttributeSet
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.accessibility.AccessibilityNodeInfo
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.LinearInterpolator
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.hakimi.probe.R
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin

/** Soft gradient backdrop, drawn once per size change. */
class BackdropView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var base: Shader? = null

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        base = LinearGradient(
            0f, 0f, 0f, h.toFloat(),
            intArrayOf(Palette.BG_SOFT, Palette.BG),
            null, Shader.TileMode.CLAMP
        )
    }

    override fun onDraw(canvas: Canvas) {
        paint.shader = base
        canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), paint)
        paint.shader = null
    }
}

/** A quiet two-ring status indicator; the arc only moves when acceleration is on. */
class StatusRingView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val arcPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val iconPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val oval = RectF()
    private val iconRect = RectF()

    private var active = false
    private var rotation = 0f
    private var attached = false
    private var lastClick = 0L

    var onToggle: (() -> Unit)? = null

    private val spin = ValueAnimator.ofFloat(0f, 360f).apply {
        duration = 5600L
        repeatCount = ValueAnimator.INFINITE
        interpolator = LinearInterpolator()
        addUpdateListener {
            rotation = it.animatedValue as Float
            invalidate()
        }
    }

    init {
        isClickable = true
        isFocusable = true
        contentDescription = "开启或暂停加速"
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val desired = context.dp(96f)
        setMeasuredDimension(
            resolveSize(desired, widthMeasureSpec),
            resolveSize(desired, heightMeasureSpec)
        )
    }

    fun setActive(value: Boolean, animate: Boolean = true) {
        if (active == value) return
        active = value
        if (value) {
            if (attached) spin.start()
        } else {
            spin.cancel()
            if (animate) {
                animate().alpha(0.86f).setDuration(90L).withEndAction {
                    animate().alpha(1f).setDuration(180L).start()
                }.start()
            }
        }
        invalidate()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        attached = true
        if (active && !spin.isStarted) spin.start()
    }

    override fun onDetachedFromWindow() {
        attached = false
        spin.cancel()
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        val cx = width / 2f
        val cy = height / 2f
        val radius = min(width, height) / 2f - context.dp(4f)
        val accent = if (active) Palette.ACCENT else Palette.MUTED

        val ringRadius = radius - context.dp(4f)
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = context.dp(1.5f).toFloat()
        paint.color = Palette.BORDER
        canvas.drawCircle(cx, cy, ringRadius, paint)

        oval.set(
            cx - ringRadius, cy - ringRadius,
            cx + ringRadius, cy + ringRadius
        )
        arcPaint.style = Paint.Style.STROKE
        arcPaint.strokeCap = Paint.Cap.ROUND
        arcPaint.strokeWidth = context.dp(2.6f).toFloat()
        arcPaint.color = accent
        canvas.drawArc(oval, -90f + rotation, if (active) 238f else 110f, false, arcPaint)

        val inner = ringRadius - context.dp(12f)
        paint.style = Paint.Style.FILL
        paint.color = Palette.SURFACE
        canvas.drawCircle(cx, cy, inner, paint)
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = context.dp(1f).toFloat()
        paint.color = Palette.BORDER
        canvas.drawCircle(cx, cy, inner, paint)

        val glyphRadius = min(inner * 0.50f, context.dp(12f).toFloat())
        iconRect.set(
            cx - glyphRadius, cy - glyphRadius + context.dp(1.5f),
            cx + glyphRadius, cy + glyphRadius + context.dp(1.5f)
        )
        iconPaint.style = Paint.Style.STROKE
        iconPaint.strokeCap = Paint.Cap.ROUND
        iconPaint.strokeWidth = context.dp(2.1f).toFloat()
        iconPaint.color = if (active) Palette.TEXT else Palette.MUTED
        canvas.drawArc(iconRect, -56f, 292f, false, iconPaint)
        canvas.drawLine(
            cx, cy - glyphRadius - context.dp(1.5f), cx, cy + context.dp(1f), iconPaint
        )
    }

    override fun performClick(): Boolean {
        super.performClick()
        val now = android.os.SystemClock.elapsedRealtime()
        if (now - lastClick < 600L) return true
        lastClick = now
        animate().scaleX(0.95f).scaleY(0.95f).setDuration(80L).withEndAction {
            animate().scaleX(1f).scaleY(1f).setDuration(160L).start()
        }.start()
        onToggle?.invoke()
        return true
    }
}

/** Small custom switch, drawn instead of themed to keep the palette exact. */
class SwitchView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var fraction = 0f
    private var checked = false
    private var animator: ValueAnimator? = null

    var onCheckedChange: ((Boolean) -> Unit)? = null

    init {
        isClickable = true
        isFocusable = true
    }

    fun isChecked(): Boolean = checked

    fun setChecked(value: Boolean, animate: Boolean = true) {
        if (checked == value) {
            if (!animate) fraction = if (value) 1f else 0f
            return
        }
        checked = value
        animator?.cancel()
        if (animate) {
            animator = ValueAnimator.ofFloat(fraction, if (value) 1f else 0f).apply {
                duration = 180L
                interpolator = AccelerateDecelerateInterpolator()
                addUpdateListener {
                    fraction = it.animatedValue as Float
                    invalidate()
                }
                start()
            }
        } else {
            fraction = if (value) 1f else 0f
            invalidate()
        }
        contentDescription = if (value) "已启用" else "未启用"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            tooltipText = contentDescription
        }
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        setMeasuredDimension(
            resolveSize(context.dp(50f), widthMeasureSpec),
            resolveSize(context.dp(30f), heightMeasureSpec)
        )
    }

    override fun onDraw(canvas: Canvas) {
        val track = RectF(0f, 0f, width.toFloat(), height.toFloat())
        val radius = height / 2f
        paint.style = Paint.Style.FILL
        paint.shader = null
        paint.color = blend(0xFFD5EAF3.toInt(), Palette.ACCENT, fraction)
        canvas.drawRoundRect(track, radius, radius, paint)

        val padding = context.dp(4f).toFloat()
        val thumbRadius = radius - padding
        val thumbX = padding + thumbRadius + fraction * (width - padding * 2 - thumbRadius * 2)
        paint.color = Color.WHITE
        canvas.drawCircle(thumbX, height / 2f, thumbRadius, paint)
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = context.dp(1f).toFloat()
        paint.color = 0x22000000
        canvas.drawCircle(thumbX, height / 2f, thumbRadius, paint)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                isPressed = true
                return true
            }
            MotionEvent.ACTION_UP -> {
                isPressed = false
                if (event.x >= 0 && event.x <= width && event.y >= 0 && event.y <= height) {
                    performClick()
                }
                return true
            }
            MotionEvent.ACTION_CANCEL -> {
                isPressed = false
                return true
            }
        }
        return super.onTouchEvent(event)
    }

    override fun performClick(): Boolean {
        super.performClick()
        setChecked(!checked)
        onCheckedChange?.invoke(checked)
        return true
    }

    override fun onInitializeAccessibilityNodeInfo(info: AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        info.isCheckable = true
        info.isChecked = checked
    }
}

/** A quiet site row: real logo, name, one meta line, switch. */
class SiteRowView(
    context: Context,
    private val compact: Boolean = false,
) : LinearLayout(context) {
    private val iconFrame = FrameLayout(context)
    private val nameView: TextView
    private val summaryView: TextView
    private val toggle = android.widget.Switch(context)

    var onOpen: (() -> Unit)? = null
    var onToggle: ((Boolean) -> Unit)? = null

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(context.dp(16f), context.dp(12f), context.dp(12f), context.dp(12f))
        background = context.selectableBackground()
        isClickable = true
        isFocusable = true

        addView(iconFrame, LayoutParams(context.dp(38f), context.dp(38f)))

        val texts = context.column()
        texts.setPadding(context.dp(11f), 0, context.dp(8f), 0)
        addView(texts, LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f))

        nameView = context.text("", if (compact) 15f else 15.5f, Palette.TEXT, medium = true)
        nameView.maxLines = 1
        nameView.ellipsize = android.text.TextUtils.TruncateAt.END
        texts.addView(nameView)

        summaryView = context.text("", 12f, Palette.MUTED)
        summaryView.maxLines = 1
        summaryView.ellipsize = android.text.TextUtils.TruncateAt.END
        summaryView.setPadding(0, context.dp(3f), 0, 0)
        texts.addView(summaryView)

        toggle.setShowText(false)
        toggle.layoutParams = LayoutParams(
            LayoutParams.WRAP_CONTENT,
            LayoutParams.WRAP_CONTENT
        ).apply { marginStart = context.dp(4f) }
        addView(toggle)

        clickOnce { onOpen?.invoke() }
    }

    fun bind(site: SiteInfo) {
        iconFrame.removeAllViews()
        iconFrame.background = null
        val iconRes = siteIconRes(site.id)
        if (iconRes != 0 && site.id != "eh") {
            val image = ImageView(context).apply {
                setImageResource(iconRes)
                scaleType = ImageView.ScaleType.FIT_CENTER
            }
            iconFrame.addView(
                image,
                FrameLayout.LayoutParams(context.dp(30f), context.dp(30f), Gravity.CENTER)
            )
        } else {
            iconFrame.background = context.rounded(tileColor(site.id), 10f)
            val initial = context.text(
                if (site.id == "eh") "EH" else site.name.take(1).uppercase(),
                if (compact) 14f else 15f,
                Color.WHITE,
                medium = true
            )
            initial.gravity = Gravity.CENTER
            iconFrame.addView(initial, FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            ))
        }
        iconFrame.alpha = if (site.enabled) 1f else 0.7f

        nameView.text = site.name
        nameView.setTextColor(if (site.enabled) Palette.TEXT else Palette.MUTED)

        val meta = "${site.exactDomains.size} 个域名"
        val status = site.summary.substringAfter(" · ", "")
        val display = if (status.isEmpty() || status == site.summary) {
            meta
        } else {
            "$meta · $status"
        }
        val text = android.text.SpannableString(display)
        if (status.isNotEmpty() && status != site.summary) {
            val start = meta.length + 3
            text.setSpan(
                android.text.style.ForegroundColorSpan(site.summaryColor),
                start,
                display.length,
                android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }
        summaryView.text = text
        summaryView.setTextColor(Palette.MUTED)
        summaryView.alpha = if (site.enabled) 1f else 0.7f

        toggle.setOnCheckedChangeListener(null)
        toggle.isChecked = site.enabled
        toggle.setOnCheckedChangeListener { _, checked -> onToggle?.invoke(checked) }
        contentDescription = "${site.name}，${site.summary}"
    }
}

/** Fixed app bar: title, optional subtitle, text actions and a hairline. */
class TopBar(context: Context) : LinearLayout(context) {
    private val titleView: TextView
    private val subtitleView: TextView
    private val actionRow: LinearLayout

    init {
        orientation = VERTICAL
        background = context.rounded(Palette.SURFACE, 0f)

        val row = context.row()
        row.setPadding(context.dp(16f), 0, context.dp(8f), 0)
        val titles = context.column()
        titleView = context.text("", 20f, Palette.TEXT, medium = true)
        subtitleView = context.text("", 11.5f, Palette.MUTED).apply {
            setPadding(0, context.dp(2f), 0, 0)
            visibility = GONE
        }
        titles.addView(titleView)
        titles.addView(subtitleView)
        row.addView(titles, LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f))

        actionRow = context.row()
        row.addView(actionRow)
        addView(row, LayoutParams(LayoutParams.MATCH_PARENT, context.dp(56f)))
        addView(View(context).apply { setBackgroundColor(Palette.HAIRLINE) },
            LayoutParams(LayoutParams.MATCH_PARENT, context.dp(1f)))
    }

    fun setScreen(title: String, subtitle: String? = null, vararg actions: Pair<String, () -> Unit>) {
        titleView.text = title
        if (subtitle.isNullOrEmpty()) {
            subtitleView.visibility = GONE
        } else {
            subtitleView.text = subtitle
            subtitleView.visibility = VISIBLE
        }
        actionRow.removeAllViews()
        actions.forEach { (label, action) ->
            val item = context.text(label, 14f, Palette.ACCENT, medium = true).apply {
                setPadding(context.dp(10f), context.dp(10f), context.dp(10f), context.dp(10f))
                background = context.selectableBorderless()
                clickOnce { action() }
            }
            actionRow.addView(item)
        }
    }
}

/** Flat, native-feeling bottom navigation. */
class BottomNav(context: Context) : LinearLayout(context) {
    private class Item(
        val container: FrameLayout,
        val icon: ImageView,
        val label: TextView,
        val badge: View,
    )

    private val items = ArrayList<Item>()
    private val linePaint = Paint().apply { color = Palette.HAIRLINE }
    private var selected = 0

    var onSelected: ((Int) -> Unit)? = null

    init {
        orientation = HORIZONTAL
        background = context.rounded(Palette.SURFACE, 0f)
        setWillNotDraw(false)
        addItem(R.drawable.ic_home, "首页")
        addItem(R.drawable.ic_sites, "站点")
        addItem(R.drawable.ic_settings, "设置")
        select(0, false)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        linePaint.color = Palette.HAIRLINE
        canvas.drawRect(0f, 0f, width.toFloat(), 1f, linePaint)
    }

    private fun addItem(iconRes: Int, label: String) {
        val container = FrameLayout(context)
        container.background = context.selectableBorderless()
        val inner = context.column()
        inner.gravity = Gravity.CENTER
        val icon = ImageView(context).apply {
            setImageResource(iconRes)
            scaleType = ImageView.ScaleType.FIT_CENTER
        }
        inner.addView(icon, LayoutParams(context.dp(24f), context.dp(24f)))
        val labelView = context.text(label, 11.5f, Palette.MUTED, medium = true)
        labelView.gravity = Gravity.CENTER
        inner.addView(labelView, LayoutParams(
            LayoutParams.WRAP_CONTENT,
            LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(3f) })
        container.addView(inner, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.WRAP_CONTENT,
            FrameLayout.LayoutParams.WRAP_CONTENT,
            Gravity.CENTER
        ))
        val badge = View(context)
        badge.background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(Palette.RED)
        }
        badge.visibility = View.GONE
        container.addView(badge, FrameLayout.LayoutParams(context.dp(5f), context.dp(5f)).apply {
            gravity = Gravity.TOP or Gravity.END
            topMargin = context.dp(8f)
            marginEnd = context.dp(18f)
        })
        val index = items.size
        container.clickOnce {
            if (selected != index) select(index, true)
        }
        addView(container, LayoutParams(0, LayoutParams.MATCH_PARENT, 1f))
        items += Item(container, icon, labelView, badge)
    }

    fun select(index: Int, notify: Boolean = true) {
        selected = index.coerceIn(0, items.lastIndex)
        items.forEachIndexed { i, item ->
            val active = i == selected
            item.icon.setColorFilter(if (active) Palette.ACCENT else Palette.MUTED)
            item.label.setTextColor(if (active) Palette.ACCENT else Palette.MUTED)
        }
        if (notify) onSelected?.invoke(selected)
    }

    fun setBadge(index: Int, show: Boolean) {
        items.getOrNull(index)?.badge?.visibility = if (show) View.VISIBLE else View.GONE
    }
}

/** A text-only settings row; no icon tiles. */
class SettingRow(
    context: Context,
    title: String,
    subtitle: String,
) : LinearLayout(context) {
    private val valueView: TextView
    private val chevron: TextView

    init {
        orientation = HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(context.dp(16f), context.dp(14f), context.dp(14f), context.dp(14f))
        background = context.selectableBackground()

        val texts = context.column()
        addView(texts, LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f))
        texts.addView(context.text(title, 14.5f, Palette.TEXT, medium = true))
        val sub = context.text(subtitle, 12f, Palette.MUTED)
        sub.setPadding(0, context.dp(3f), 0, 0)
        texts.addView(sub)

        valueView = context.text("", 12.5f, Palette.TEXT_2)
        valueView.gravity = Gravity.END
        valueView.maxLines = 1
        valueView.maxWidth = (context.resources.displayMetrics.widthPixels * 0.42f).toInt()
        valueView.ellipsize = android.text.TextUtils.TruncateAt.END
        addView(valueView, LayoutParams(
            LayoutParams.WRAP_CONTENT,
            LayoutParams.WRAP_CONTENT
        ))

        chevron = context.text("›", 20f, Palette.MUTED).apply {
            setPadding(context.dp(7f), 0, 0, 0)
        }
        addView(chevron)
    }

    fun setValue(text: String, color: Int = Palette.TEXT_2) {
        valueView.text = text
        valueView.setTextColor(color)
    }

    fun hideChevron() {
        chevron.visibility = View.GONE
    }
}

/** ScrollView bounded by a fraction of the screen; used inside bottom sheets. */
class MaxHeightScrollView(context: Context) : ScrollView(context) {
    var maxHeight: Int = (resources.displayMetrics.heightPixels * 0.74f).toInt()

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val spec = MeasureSpec.makeMeasureSpec(maxHeight, MeasureSpec.AT_MOST)
        super.onMeasure(widthMeasureSpec, spec)
    }
}

fun Context.stateWordColor(state: String, enabled: Boolean): Int {
    if (!enabled) return Palette.MUTED
    return when (state) {
        "normal" -> Palette.GREEN
        "degraded" -> Palette.AMBER
        "failed" -> Palette.RED
        "checking" -> Palette.ACCENT
        else -> Palette.MUTED
    }
}
