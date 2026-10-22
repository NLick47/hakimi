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

        setContentView(root)
        setCanceledOnTouchOutside(true)
        window?.apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setLayout(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.WRAP_CONTENT
            )
            setGravity(Gravity.BOTTOM)
            addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND)
            setDimAmount(0.30f)
            setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
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
        val button = context.nativePrimaryButton(label, action)
        add(button, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(48f)
        ).apply { topMargin = context.dp(14f) })
        return button
    }

    fun secondary(label: String, action: () -> Unit): TextView {
        val button = context.nativeTextButton(label, action)
        add(button, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(48f)
        ).apply { topMargin = context.dp(2f) })
        return button
    }

    fun buttons(primaryLabel: String, onPrimary: () -> Unit, secondaryLabel: String? = null, onSecondary: () -> Unit = {}) {
        val row = context.row()
        if (secondaryLabel != null) {
            val cancel = context.nativeTextButton(secondaryLabel, onSecondary)
            row.addView(cancel, LinearLayout.LayoutParams(0, context.dp(48f), 1f))
            row.addView(View(context), LinearLayout.LayoutParams(context.dp(8f), 1))
        }
        val confirm = context.nativePrimaryButton(primaryLabel, onPrimary)
        row.addView(confirm, LinearLayout.LayoutParams(0, context.dp(48f), 1f))
        add(row, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(16f) })
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
                WindowManager.LayoutParams.WRAP_CONTENT
            )
            setGravity(Gravity.BOTTOM)
            setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
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
                (context.resources.displayMetrics.heightPixels - ime - context.dp(150f))
                    .coerceAtLeast(context.dp(220f))
            } else {
                (context.resources.displayMetrics.heightPixels * 0.74f).toInt()
            }
            scroll.requestLayout()
            insets
        }
        decor.requestApplyInsets()
    }
}
