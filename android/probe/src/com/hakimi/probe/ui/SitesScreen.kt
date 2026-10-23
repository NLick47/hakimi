package com.hakimi.probe.ui

import android.content.Context
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView

class SitesScreen(private val context: Context, private val host: Host) {
    val view: ScrollView = ScrollView(context).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = false
        overScrollMode = View.OVER_SCROLL_NEVER
    }

    private val content = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, context.dp(12f), 0, context.dp(104f))
    }

    private lateinit var listRows: LinearLayout
    private var signature = ""

    init {
        view.addView(content, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))

        listRows = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            background = context.rounded(Palette.SURFACE, 18f, Palette.BORDER, 1f)
            clipToOutline = true
        }
        content.addView(listRows, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            marginStart = context.dp(16f)
            marginEnd = context.dp(16f)
        })
        content.addView(context.text("本地处理 · 不收集浏览数据", 11f, Palette.MUTED).apply {
            gravity = android.view.Gravity.CENTER
            setPadding(0, context.dp(14f), 0, context.dp(14f))
        })
    }

    fun refresh(core: CoreData) {
        rebuild(core)
    }

    private fun rebuild(core: CoreData) {
        val sites = core.sites
        val sig = buildString {
            sites.forEach {
                append(it.id).append(':').append(it.enabled).append(':')
                    .append(it.summary).append(':').append(it.state).append(';')
            }
        }
        if (sig == signature) return
        signature = sig

        listRows.removeAllViews()
        if (sites.isEmpty()) {
            listRows.addView(context.text("还没有站点", 12f, Palette.MUTED).apply {
                gravity = android.view.Gravity.CENTER
                setPadding(0, context.dp(28f), 0, context.dp(28f))
            }, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
            return
        }

        sites.forEachIndexed { index, site ->
            if (index > 0) {
                listRows.addView(context.divider(58f), LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    context.dp(1f)
                ))
            }
            val row = SiteRowView(context, compact = false)
            row.bind(site)
            row.onOpen = { host.openSite(site) }
            row.onToggle = { host.setGroupEnabled(site, it) }
            listRows.addView(row, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
        }
    }

}
