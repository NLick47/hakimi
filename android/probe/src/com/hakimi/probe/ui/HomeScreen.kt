package com.hakimi.probe.ui

import android.content.Context
import android.graphics.Color
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.hakimi.probe.HakimiVpnService
import com.hakimi.probe.Prefs
import com.hakimi.probe.R

class HomeScreen(private val context: Context, private val host: Host) {
    val view: ScrollView = ScrollView(context).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = false
        overScrollMode = View.OVER_SCROLL_NEVER
    }

    private val content = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, context.dp(12f), 0, context.dp(104f))
    }

    private val hero = context.card(
        radius = 12f,
        fill = Palette.SURFACE,
        padding = 12f,
        stroke = Color.TRANSPARENT
    )
    private val ring = StatusRingView(context)
    private lateinit var heroTitle: TextView
    private lateinit var heroSubtitle: TextView
    private lateinit var heroAction: TextView

    private lateinit var warning: LinearLayout
    private lateinit var warningTitle: TextView
    private lateinit var warningSubtitle: TextView

    private lateinit var previewRows: LinearLayout
    private var previewSignature = ""
    private lateinit var overviewSub: TextView

    init {
        view.addView(content, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))

        buildHero()
        hero.elevation = context.dp(2f).toFloat()
        content.addView(hero, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            marginStart = context.dp(16f)
            marginEnd = context.dp(16f)
        })

        warning = buildWarning()
        content.addView(warning, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            topMargin = context.dp(10f)
            marginStart = context.dp(16f)
            marginEnd = context.dp(16f)
        })

        content.addView(buildSectionHeader())
        content.addView(buildListPanel(), LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))

        content.addView(space(16f))
        content.addView(buildFooter())
    }

    fun refresh(data: CoreData) {
        val vpnMode = Prefs.mode(context) == Prefs.MODE_VPN
        val vpnActive = vpnMode && HakimiVpnService.active
        ring.setActive(data.running || vpnActive)

        when {
            !host.caReady -> {
                heroTitle.text = "正在检查环境"
                heroSubtitle.text = "读取证书与核心状态"
                heroAction.text = ""
                heroAction.isEnabled = false
            }
            !data.userCaTrusted -> {
                if (!host.caLockReady) {
                    heroTitle.text = "需要设置锁屏"
                    heroSubtitle.text = "Android 11 及以上安装 CA 需要锁屏"
                    heroAction.text = "设置"
                } else {
                    heroTitle.text = "需要安装证书"
                    heroSubtitle.text = "安装本地 CA 后才能加速"
                    heroAction.text = "安装"
                }
                heroAction.isEnabled = true
                heroAction.clickOnce { host.openCaSetup() }
            }
            vpnMode && vpnActive -> {
                heroTitle.text = "VPN 已开启"
                heroSubtitle.text = if (data.running) {
                    "全部应用已接管"
                } else {
                    "核心重连中"
                }
                heroAction.text = "暂停"
                heroAction.isEnabled = true
                heroAction.clickOnce { host.toggleAcceleration() }
            }
            vpnMode -> {
                heroTitle.text = "VPN 已暂停"
                heroSubtitle.text = "浏览器自动接管"
                heroAction.text = "开启"
                heroAction.isEnabled = true
                heroAction.clickOnce { host.toggleAcceleration() }
            }
            data.running -> {
                heroTitle.text = "加速已开启"
                heroSubtitle.text = data.endpoint
                heroAction.text = "暂停"
                heroAction.isEnabled = true
                heroAction.clickOnce { host.toggleAcceleration() }
            }
            else -> {
                heroTitle.text = "加速已暂停"
                heroSubtitle.text = data.endpoint
                heroAction.text = "开启"
                heroAction.isEnabled = true
                heroAction.clickOnce { host.toggleAcceleration() }
            }
        }

        updateWarning(data)
        updatePreview(data)
        overviewSub.text = buildString {
            append(data.siteCount).append(" 个站点")
            if (data.failedDomains > 0) {
                append(" · ").append(data.failedDomains).append(" 个超时")
            } else if (data.normalDomains > 0) {
                append(" · ").append(data.normalDomains).append(" 个正常")
            }
        }
    }

    private fun buildHero() {
        val inner = context.row()
        hero.addView(inner, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))

        ring.onToggle = { host.toggleAcceleration() }
        inner.addView(ring, LinearLayout.LayoutParams(context.dp(84f), context.dp(84f)))

        val body = context.column()
        body.setPadding(context.dp(12f), 0, context.dp(6f), 0)
        heroTitle = context.text("加速已开启", 19f, Palette.TEXT, medium = true)
        body.addView(heroTitle)
        heroSubtitle = context.monospace("127.0.0.1:8443", 11f, Palette.MUTED)
        heroSubtitle.setPadding(0, context.dp(4f), 0, 0)
        body.addView(heroSubtitle)
        inner.addView(body, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

        heroAction = context.text("暂停", 13.5f, Palette.ACCENT, medium = true).apply {
            gravity = Gravity.CENTER
            setPadding(context.dp(12f), context.dp(9f), context.dp(12f), context.dp(9f))
            isClickable = true
            isFocusable = true
            background = context.selectableBorderless()
        }
        inner.addView(heroAction)
    }

    private fun buildWarning(): LinearLayout {
        val card = context.card(
            radius = 12f,
            fill = 0xFFFFF8EC.toInt(),
            padding = 12f,
            stroke = 0x33B07A1E
        )
        card.visibility = View.GONE
        val texts = context.column()
        warningTitle = context.text("", 12f, Palette.TEXT, medium = true)
        warningSubtitle = context.text("", 10f, 0xFF8A651D.toInt())
        warningSubtitle.setPadding(0, context.dp(3f), 0, 0)
        texts.addView(warningTitle)
        texts.addView(warningSubtitle)
        card.addView(texts)
        card.clickOnce { host.showLog() }
        return card
    }

    private fun updateWarning(data: CoreData) {
        val vpnMode = Prefs.mode(context) == Prefs.MODE_VPN
        val vpnActive = vpnMode && HakimiVpnService.active
        if (vpnMode && vpnActive && !data.running) {
            warningTitle.text = "核心未运行"
            warningSubtitle.text = "目标站点暂时直连，正在重试"
            warning.visibility = View.VISIBLE
        } else if (data.proxyError.isNotEmpty()) {
            warningTitle.text = "核心服务异常"
            warningSubtitle.text = data.proxyError
            warning.visibility = View.VISIBLE
        } else {
            warning.visibility = View.GONE
        }
    }

    private fun buildSectionHeader(): View {
        val row = context.row()
        row.setPadding(context.dp(16f), context.dp(20f), context.dp(16f), context.dp(8f))
        row.addView(context.text("站点", 14f, Palette.TEXT, medium = true))
        row.addView(View(context), LinearLayout.LayoutParams(0, 1, 1f))
        val more = context.text("全部", 13f, Palette.ACCENT, medium = true).apply {
            setPadding(context.dp(8f), context.dp(4f), 0, context.dp(4f))
            clickOnce { host.setTab(1) }
        }
        row.addView(more)
        return row
    }

    private fun buildListPanel(): View {
        val panel = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Palette.SURFACE)
        }
        previewRows = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
        panel.addView(previewRows, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))
        panel.addView(context.divider(0f), LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(1f)
        ))

        val overview = context.row()
        overview.setPadding(
            context.dp(14f), context.dp(12f),
            context.dp(14f), context.dp(12f)
        )
        overview.addView(context.text("运行概览", 14f, Palette.TEXT, medium = true))
        overviewSub = context.text("", 12f, Palette.MUTED).apply {
            gravity = Gravity.END
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        overview.addView(overviewSub, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
        ))
        overview.addView(context.text("›", 20f, Palette.MUTED).apply {
            setPadding(context.dp(7f), 0, 0, 0)
        })
        overview.isClickable = true
        overview.isFocusable = true
        overview.setBackgroundColor(Palette.SURFACE)
        overview.clickOnce { OverviewSheet(context, host).show() }
        panel.addView(overview, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))
        return panel
    }

    private fun updatePreview(data: CoreData) {
        val preview = (data.sites.filter { it.enabled }.ifEmpty { data.sites }).take(6)
        val signature = preview.joinToString("|") {
            "${it.id}:${it.enabled}:${it.summary}:${it.state}"
        }
        if (signature == previewSignature) return
        previewSignature = signature
        previewRows.removeAllViews()
        if (preview.isEmpty()) {
            val empty = context.text("还没有站点，前往站点页添加", 11.5f, Palette.MUTED).apply {
                gravity = Gravity.CENTER
                setPadding(0, context.dp(22f), 0, context.dp(22f))
            }
            previewRows.addView(empty, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
            return
        }
        preview.forEachIndexed { index, site ->
            if (index > 0) {
                previewRows.addView(context.divider(58f), LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    context.dp(1f)
                ))
            }
            val rowView = SiteRowView(context, compact = true)
            rowView.bind(site)
            rowView.onOpen = { host.openSite(site) }
            rowView.onToggle = { host.setGroupEnabled(site, it) }
            previewRows.addView(rowView, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
        }
    }

    private fun buildFooter(): View =
        context.text("本地处理 · 不收集浏览数据", 11f, Palette.MUTED).apply {
            gravity = Gravity.CENTER
            setPadding(0, context.dp(14f), 0, context.dp(14f))
        }

    private fun space(height: Float): View = View(context).apply {
        layoutParams = LinearLayout.LayoutParams(1, context.dp(height))
    }
}
