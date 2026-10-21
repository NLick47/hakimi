package com.hakimi.probe.ui

import android.content.Context
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView

/** The one place the home screen still exposes detailed counters. */
class OverviewSheet(
    private val context: Context,
    private val host: Host,
) {
    fun show() {
        val data = host.core
        val sheet = Sheet(context, "运行概览", "本次运行 · ${data.uptimeText()}")

        val grid = context.card(radius = 20f, padding = 0f)
        grid.addView(metricRow(
            listOf(
                "站点" to data.siteCount.toLong(),
                "已启用" to data.enabledSites.toLong(),
                "域名" to data.domainTotal.toLong(),
                "正常" to data.normalDomains.toLong(),
            )
        ))
        grid.addView(context.divider(14f), LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(1f)
        ))
        grid.addView(metricRow(
            listOf(
                "较慢" to data.slowDomains.toLong(),
                "超时" to data.failedDomains.toLong(),
                "请求" to data.requests,
                "连接" to data.connections,
            )
        ))
        sheet.add(grid, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(12f) })

        val cache = context.text(
            "缓存条目  ${format(data.cacheEntries)}\n" +
                "HTTP/2    ${format(data.responsesH2)}\n" +
                "HTTP/1.1  ${format(data.responsesH1)}",
            10.5f,
            Palette.TEXT_2
        ).apply {
            typeface = android.graphics.Typeface.create("monospace", android.graphics.Typeface.NORMAL)
            background = context.rounded(0xFFF7FCFE.toInt(), 14f, Palette.BORDER, 1f)
            setPadding(context.dp(14f), context.dp(12f), context.dp(14f), context.dp(12f))
        }
        sheet.add(cache, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(10f) })

        sheet.primary("查看运行日志") {
            sheet.dismiss()
            host.showLog()
        }
        sheet.textButton("关闭") { sheet.dismiss() }
        sheet.show()
    }

    private fun metricRow(items: List<Pair<String, Long>>): View {
        val row = context.row()
        row.setPadding(
            context.dp(4f), context.dp(13f),
            context.dp(4f), context.dp(13f)
        )
        items.forEachIndexed { index, item ->
            if (index > 0) {
                row.addView(View(context).apply { setBackgroundColor(Palette.HAIRLINE) },
                    LinearLayout.LayoutParams(context.dp(1f), context.dp(30f)))
            }
            val cell = context.column()
            cell.gravity = Gravity.CENTER
            cell.addView(context.text(format(item.second), 19f, Palette.TEXT, medium = true).apply {
                gravity = Gravity.CENTER
                fontFeatureSettings = "tnum"
            })
            cell.addView(context.text(item.first, 9f, Palette.MUTED).apply {
                gravity = Gravity.CENTER
                setPadding(0, context.dp(4f), 0, 0)
            })
            row.addView(cell, LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
            ))
        }
        return row
    }

    private fun format(value: Long): String = when {
        value >= 1_000_000 -> "%.1fM".format(value / 1_000_000f)
        value >= 10_000 -> "%.0fk".format(value / 1000f)
        value >= 1_000 -> "%.1fk".format(value / 1000f)
        else -> value.toString()
    }
}
