package com.hakimi.probe.ui

import android.content.Context
import com.hakimi.probe.UpdateInfo

/** Release notes plus the one action that leaves the app for the browser. */
class UpdateSheet(
    private val context: Context,
    private val host: Host,
    private val info: UpdateInfo,
) {
    private var sheet: Sheet? = null

    val isShowing: Boolean
        get() = sheet?.isShowing == true

    fun show() {
        if (isShowing) return
        val sheet = Sheet(
            context,
            "发现新版本",
            "当前 ${host.appVersion} · 最新 ${info.version}"
        )
        this.sheet = sheet

        val notes = context.text(
            info.notes.ifBlank { "前往 GitHub Releases 查看完整更新说明。" },
            12.5f,
            Palette.TEXT_2
        ).apply {
            setLineSpacing(context.dp(4f).toFloat(), 1f)
            setTextIsSelectable(true)
            setPadding(0, context.dp(4f), 0, context.dp(8f))
        }
        sheet.add(notes)
        sheet.buttons(
            "前往下载",
            {
                sheet.dismiss()
                host.openUpdate()
            },
            "稍后",
            { sheet.dismiss() }
        )
        sheet.setOnDismissListener {
            if (this.sheet === sheet) this.sheet = null
        }
        sheet.show()
    }
}
