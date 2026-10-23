package com.hakimi.probe.ui

import android.content.Context
import android.text.InputType
import android.view.WindowManager
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

object Sheets {
    fun input(
        context: Context,
        title: String,
        subtitle: String,
        value: String,
        hint: String,
        numeric: Boolean = false,
        onSave: (String) -> Unit,
    ) {
        val sheet = Sheet(context, title, subtitle)
        val error = context.text("", 11f, Palette.RED).apply {
            setPadding(0, context.dp(8f), 0, 0)
            visibility = TextView.GONE
        }
        val edit = EditText(context).apply {
            setText(value)
            setHintTextColor(Palette.MUTED)
            this.hint = hint
            setTextColor(Palette.TEXT)
            textSize = 14f
            setSingleLine(true)
            setPadding(context.dp(4f), context.dp(12f), context.dp(4f), context.dp(12f))
            inputType = if (numeric) InputType.TYPE_CLASS_NUMBER else InputType.TYPE_CLASS_TEXT
            setSelection(text.length)
        }
        sheet.add(edit, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(50f)
        ).apply { topMargin = context.dp(14f) })
        sheet.add(error)
        sheet.buttons(
            "保存",
            {
                val next = edit.text.toString().trim()
                if (next.isEmpty()) {
                    error.text = "不能为空"
                    error.visibility = TextView.VISIBLE
                } else {
                    sheet.dismiss()
                    onSave(next)
                }
            },
            "取消",
            { sheet.dismiss() }
        )
        sheet.show()
        edit.requestFocus()
        sheet.window?.setSoftInputMode(
            WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE or
                WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING
        )
    }

    fun confirm(
        context: Context,
        title: String,
        message: String,
        confirmLabel: String,
        danger: Boolean = false,
        onConfirm: () -> Unit,
    ) {
        val sheet = Sheet(context, title)
        sheet.add(context.text(message, 13f, Palette.TEXT_2).apply {
            setLineSpacing(context.dp(4f).toFloat(), 1f)
        })
        sheet.buttons(
            confirmLabel,
            {
                sheet.dismiss()
                onConfirm()
            },
            "取消",
            { sheet.dismiss() },
            danger = danger,
        )
        sheet.show()
    }

    fun info(context: Context, title: String, message: String) {
        val sheet = Sheet(context, title)
        sheet.add(context.text(message, 13f, Palette.TEXT_2).apply {
            setLineSpacing(context.dp(4f).toFloat(), 1f)
            setTextIsSelectable(true)
        })
        sheet.primary("知道了") { sheet.dismiss() }
        sheet.show()
    }

    fun monospace(
        context: Context,
        title: String,
        subtitle: String?,
        content: String,
        copyLabel: String = "复制全部",
        onCopy: (String) -> Unit,
    ) {
        val sheet = Sheet(context, title, subtitle)
        val body = context.monospace(content, 11f, Palette.TEXT_2).apply {
            setTextIsSelectable(true)
            background = context.rounded(0xFFF7FCFE.toInt(), 16f, Palette.BORDER, 1f)
            setPadding(context.dp(14f), context.dp(14f), context.dp(14f), context.dp(14f))
        }
        sheet.add(body, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(14f) })
        sheet.buttons(
            "关闭",
            { sheet.dismiss() },
            copyLabel,
            { onCopy(content) },
        )
        sheet.show()
    }
}
