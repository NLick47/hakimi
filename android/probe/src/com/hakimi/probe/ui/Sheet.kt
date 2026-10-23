package com.hakimi.probe.ui

import android.app.Dialog
import android.content.Context
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import com.hakimi.probe.R

/** A rounded, edge-to-edge bottom sheet built from framework views only. */
class Sheet(
    context: Context,
    title: String? = null,
    subtitle: String? = null,
    scrollable: Boolean = true,
) : Dialog(context, R.style.SheetDialog) {
    val body: LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, context.dp(16f), 0, 0)
    }

    private val root: LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(context.dp(20f), context.dp(10f), context.dp(20f), context.dp(20f))
        background = context.roundedTop(Palette.SURFACE, 20f, Palette.BORDER_STRONG)
    }

    private val scroll: MaxHeightScrollView = MaxHeightScrollView(context).apply {
        isFillViewport = false
        isVerticalScrollBarEnabled = false
        overScrollMode = View.OVER_SCROLL_NEVER
    }

    // The dialog window spans the whole screen so an outside tap is consumed
    // by this scrim instead of falling through to the activity and re-opening
    // the sheet that was just dismissed.
    private val overlay = FrameLayout(context).apply {
        isClickable = true
        importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        setOnClickListener { dismiss() }
    }

    // Sticky action bar. It lives outside the scroll view so save/cancel stays
    // reachable even when the sheet body is long or the keyboard is open.
    private val footer = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
    }
    private var footerContent: LinearLayout? = null
    private var hasFooter = false

    init {
        val handle = View(context).apply {
            background = context.rounded(0xFFD5E3EB.toInt(), 2f)
        }
        root.addView(handle, LinearLayout.LayoutParams(context.dp(32f), context.dp(3f)).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            bottomMargin = context.dp(14f)
        })

        if (title != null) {
            val header = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val texts = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
            }
            texts.addView(context.text(title, 18f, Palette.TEXT, medium = true))
            if (subtitle != null) {
                texts.addView(context.text(subtitle, 11.5f, Palette.TEXT_2).apply {
                    setPadding(0, context.dp(4f), 0, 0)
                })
            }
            header.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            val close = context.text("×", 22f, Palette.MUTED).apply {
                gravity = Gravity.CENTER
                background = context.ripple(Color.TRANSPARENT, 18f, 0x0D0E9FD8)
            }
            close.clickOnce { dismiss() }
            header.addView(close, LinearLayout.LayoutParams(context.dp(38f), context.dp(38f)))
            root.addView(header)
        }

        if (scrollable) {
            scroll.addView(body, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
            root.addView(scroll, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
        } else {
            // A sheet that hosts its own scrollable list must not be wrapped
            // in a ScrollView, or the outer scrollView steals the list's drags.
            root.addView(body, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
        }

        root.isClickable = true
        root.setOnClickListener { }
        overlay.addView(root, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.WRAP_CONTENT,
            Gravity.BOTTOM
        ))
        setContentView(overlay)
        setCanceledOnTouchOutside(true)
        window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setLayout(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT
            )
            setGravity(Gravity.TOP or Gravity.START)
            addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
            setDimAmount(0.30f)
            setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING)
        }
    }

    fun add(view: View, params: LinearLayout.LayoutParams? = null): Sheet {
        body.addView(
            view,
            params ?: LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        )
        return this
    }

    fun space(height: Float): Sheet {
        body.addView(View(context), LinearLayout.LayoutParams(1, context.dp(height)))
        return this
    }

    fun primary(label: String, action: () -> Unit): TextView {
        val button = context.primaryButton(label, action)
        add(button, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(48f)
        ).apply { topMargin = context.dp(14f) })
        return button
    }

    fun secondary(label: String, action: () -> Unit): TextView {
        val button = context.ghostButton(label, action)
        add(button, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(48f)
        ).apply { topMargin = context.dp(8f) })
        return button
    }

    fun buttons(
        primaryLabel: String,
        onPrimary: () -> Unit,
        secondaryLabel: String? = null,
        onSecondary: () -> Unit = {},
        danger: Boolean = false,
    ) {
        val content = ensureFooter()
        val row = context.row()
        if (secondaryLabel != null) {
            row.addView(
                context.ghostButton(secondaryLabel, onSecondary),
                LinearLayout.LayoutParams(0, context.dp(48f), 1f)
            )
            row.addView(View(context), LinearLayout.LayoutParams(context.dp(10f), 1))
        }
        val primary = if (danger) {
            context.dangerButton(primaryLabel, onPrimary)
        } else {
            context.primaryButton(primaryLabel, onPrimary)
        }
        row.addView(primary, LinearLayout.LayoutParams(0, context.dp(48f), 1f))
        content.addView(row, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))
    }

    private fun ensureFooter(): LinearLayout {
        footerContent?.let { return it }
        val content = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, context.dp(12f), 0, 0)
        }
        footer.addView(
            View(context).apply { setBackgroundColor(Palette.HAIRLINE) },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                context.dp(1f)
            )
        )
        footer.addView(content, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))
        root.addView(footer, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(14f) })
        footerContent = content
        hasFooter = true
        return content
    }

    fun textButton(label: String, color: Int = Palette.ACCENT, action: () -> Unit): TextView {
        val button = context.text(label, 14f, color, medium = true).apply {
            gravity = Gravity.CENTER
            setPadding(context.dp(12f), context.dp(12f), context.dp(12f), context.dp(12f))
            background = context.selectableBorderless()
            clickOnce { action() }
        }
        add(button)
        return button
    }

    override fun show() {
        super.show()
        window?.apply {
            setLayout(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT
            )
            setGravity(Gravity.TOP or Gravity.START)
            setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING)
        }
        val decor = window?.decorView ?: return
        decor.setOnApplyWindowInsetsListener { _, insets ->
            val nav = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                insets.getInsets(WindowInsets.Type.systemBars()).bottom
            } else {
                @Suppress("DEPRECATION")
                insets.systemWindowInsetBottom
            }
            val ime = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                insets.getInsets(WindowInsets.Type.ime()).bottom
            } else {
                0
            }
            root.setPadding(
                root.paddingLeft,
                root.paddingTop,
                root.paddingRight,
                context.dp(20f) + maxOf(nav, ime)
            )
            scroll.maxHeight = if (ime > 0) {
                val reserve = if (hasFooter) context.dp(220f) else context.dp(150f)
                (context.resources.displayMetrics.heightPixels - ime - reserve)
                    .coerceAtLeast(context.dp(220f))
            } else {
                val fraction = if (hasFooter) 0.64f else 0.74f
                (context.resources.displayMetrics.heightPixels * fraction).toInt()
            }
            scroll.requestLayout()
            insets
        }
        decor.requestApplyInsets()
        root.alpha = 0f
        root.translationY = context.dp(18f).toFloat()
        root.animate().alpha(1f).translationY(0f).setDuration(160L).start()
    }
}
