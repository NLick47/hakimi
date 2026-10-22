package com.hakimi.probe.ui

import android.content.Context
import android.os.PowerManager
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.hakimi.probe.Bootstrap
import com.hakimi.probe.Prefs

class SettingsScreen(private val context: Context, private val host: Host) {
    val view: ScrollView = ScrollView(context).apply {
        isFillViewport = true
        isVerticalScrollBarEnabled = false
        overScrollMode = View.OVER_SCROLL_NEVER
    }

    private val content = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, context.dp(12f), 0, context.dp(104f))
    }

    private val appVersion: String = runCatching {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName
    }.getOrNull().orEmpty().ifEmpty { "0.3" }

    private lateinit var envRow: SettingRow
    private lateinit var serviceRow: SettingRow
    private lateinit var proxyRow: SettingRow
    private lateinit var modeRow: SettingRow
    private lateinit var excludedRow: SettingRow
    private lateinit var certRow: SettingRow
    private lateinit var certInfo: TextView

    private lateinit var portRow: SettingRow
    private lateinit var ipCatalogRow: SettingRow
    private lateinit var dohCatalogRow: SettingRow
    private lateinit var alwaysOnRow: SettingRow
    private lateinit var batteryRow: SettingRow

    private lateinit var versionRow: SettingRow

    init {
        view.addView(content, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))
        content.addView(section("连接"))
        modeRow = SettingRow(context, "运行模式", "本地代理或 VPN 接管全部应用")
        modeRow.clickOnce { host.chooseMode() }
        excludedRow = SettingRow(context, "排除应用", "这些应用不经过 hakimi，直接连接网络")
        excludedRow.clickOnce { host.chooseExcludedApps() }
        envRow = SettingRow(context, "环境状态", "证书安装状态")
        envRow.clickOnce { if (!host.core.userCaTrusted) host.openCaSetup() else host.setTab(0) }
        serviceRow = SettingRow(context, "核心服务", "本地加速核心的运行状态")
        serviceRow.clickOnce { host.setTab(0) }
        proxyRow = SettingRow(context, "本地代理", "代理模式下浏览器流量进入核心的入口")
        proxyRow.clickOnce { host.copy(host.core.endpoint, "代理地址") }
        content.addView(rowsCard(modeRow, excludedRow, envRow, serviceRow, proxyRow))
        content.addView(space(8f))

        content.addView(section("证书"))
        certRow = SettingRow(context, "本地 CA", "ECH 与 SNI 修改的信任基础")
        certRow.clickOnce { host.openCaSetup() }
        val certCard = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            background = context.rounded(Palette.SURFACE, 0f)
        }
        certCard.addView(certRow)
        certCard.addView(context.divider(0f), LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(1f)
        ))
        certInfo = context.monospace("", 10.5f, Palette.TEXT_2).apply {
            setPadding(context.dp(16f), context.dp(10f), context.dp(16f), context.dp(12f))
            setTextIsSelectable(true)
        }
        certCard.addView(certInfo, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))
        val certActions = context.row()
        certActions.setPadding(context.dp(6f), 0, context.dp(16f), context.dp(8f))
        certActions.addView(textAction("导出证书") { host.exportCa() })
        certActions.addView(textAction("安装指引") { host.openCaSetup() })
        certCard.addView(certActions)
        content.addView(certCard)
        content.addView(space(8f))

        content.addView(section("网络"))
        portRow = SettingRow(context, "本地端口", "修改前需要先停止加速")
        portRow.clickOnce {
            host.editSetting("proxy.port", "本地端口", "1–65535，修改前需要先停止加速", host.core.port.toString())
        }
        ipCatalogRow = SettingRow(context, "IP 目录", "留空则停用远程 IP 目录")
        ipCatalogRow.clickOnce {
            host.editSetting(
                "catalogs.ip",
                "IP 目录",
                "远端 IP 目录地址，留空停用",
                configString("catalogs", "ip")
            )
        }
        dohCatalogRow = SettingRow(context, "DoH 目录", "留空则停用远程 DoH 列表")
        dohCatalogRow.clickOnce {
            host.editSetting(
                "catalogs.doh",
                "DoH 目录",
                "远端 DoH 目录地址，留空停用",
                configString("catalogs", "doh")
            )
        }
        content.addView(rowsCard(portRow, ipCatalogRow, dohCatalogRow))
        content.addView(space(8f))

        content.addView(section("后台"))
        alwaysOnRow = SettingRow(context, "始终开启", "系统在开机后恢复 VPN")
        alwaysOnRow.clickOnce { host.openVpnSettings() }
        batteryRow = SettingRow(context, "后台保活", "关闭电池优化，减少息屏回收")
        batteryRow.clickOnce { host.requestBatteryExemption() }
        content.addView(rowsCard(alwaysOnRow, batteryRow))
        content.addView(space(8f))

        content.addView(section("工具"))
        val probe = SettingRow(context, "检测全部站点", "逐域名探测可用线路与延迟")
        probe.clickOnce { host.runProbeSweep() }
        val catalogs = SettingRow(context, "刷新远程目录", "重新拉取 IP 与 DoH 目录")
        catalogs.clickOnce { host.refreshCatalogs() }
        val diagnose = SettingRow(context, "域名诊断", "查看单域名的完整路由尝试过程")
        diagnose.clickOnce { host.diagnosePrompt() }
        val log = SettingRow(context, "运行日志", "最近的核心日志，便于定位问题")
        log.clickOnce { host.showLog() }
        val export = SettingRow(context, "导出诊断包", "包含脱敏配置与运行状态")
        export.clickOnce { host.exportDiagnostics() }
        content.addView(rowsCard(probe, catalogs, diagnose, log, export))
        content.addView(space(8f))

        content.addView(section("关于"))
        versionRow = SettingRow(context, "版本", "Kotlin · 原生 View · Rust core")
        versionRow.hideChevron()
        val dataRow = SettingRow(context, "数据目录", "点击复制应用私有路径")
        dataRow.setValue(Bootstrap.dataDir(context).absolutePath)
        dataRow.clickOnce { host.copy(Bootstrap.dataDir(context).absolutePath, "数据目录") }
        content.addView(rowsCard(versionRow, dataRow))
        content.addView(space(16f))

        content.addView(context.text("hakimi for Android", 11f, Palette.MUTED).apply {
            gravity = Gravity.CENTER
            setPadding(0, context.dp(16f), 0, context.dp(16f))
        })
    }

    fun refresh(data: CoreData) {
        val trusted = data.userCaTrusted
        val vpn = Prefs.mode(context) == Prefs.MODE_VPN
        val excluded = Prefs.excludedApps(context)
        modeRow.setValue(
            if (vpn) "VPN · 全部应用" else "本地代理",
            if (vpn) Palette.ACCENT else Palette.TEXT_2
        )
        excludedRow.setValue(
            excludedSummary(excluded),
            if (excluded.isEmpty()) Palette.TEXT_2 else Palette.ACCENT
        )
        envRow.setValue(
            when {
                !host.caReady -> "检查中"
                !trusted -> "证书未安装"
                data.running -> "运行中"
                else -> "待开启"
            },
            when {
                !host.caReady -> Palette.MUTED
                !trusted -> Palette.AMBER
                data.running -> Palette.GREEN
                else -> Palette.MUTED
            }
        )
        serviceRow.setValue(
            if (data.running) "运行中" else "已停止",
            if (data.running) Palette.GREEN else Palette.MUTED
        )
        proxyRow.setValue(
            if (vpn) "VPN 接管" else data.endpoint,
            if (vpn) Palette.MUTED else Palette.ACCENT
        )
        certRow.setValue(if (trusted) "已信任" else "未信任", if (trusted) Palette.GREEN else Palette.AMBER)

        certInfo.text = buildString {
            append(data.caSubject.ifEmpty { "CN=hakimi Local CA" })
            if (data.caNotAfter.isNotEmpty()) {
                append("\n到期  ").append(data.caNotAfter.take(10))
            }
        }

        portRow.setValue(data.port.toString())
        ipCatalogRow.setValue(shorten(configString("catalogs", "ip")).ifEmpty { "未设置" })
        dohCatalogRow.setValue(shorten(configString("catalogs", "doh")).ifEmpty { "未设置" })

        val always = Prefs.systemAlwaysOn(context)
        alwaysOnRow.setValue(
            if (always) "已开启" else "未开启",
            if (always) Palette.GREEN else Palette.MUTED
        )
        val power = context.getSystemService(PowerManager::class.java)
        val exempt = power?.isIgnoringBatteryOptimizations(context.packageName) == true
        batteryRow.setValue(
            if (exempt) "已允许" else "受限制",
            if (exempt) Palette.GREEN else Palette.AMBER
        )
        versionRow.setValue(appVersion)
    }

    private fun excludedSummary(packages: Set<String>): String {
        if (packages.isEmpty()) return "未排除"
        val labels = packages.mapNotNull { pkg ->
            runCatching {
                val info = context.packageManager.getApplicationInfo(pkg, 0)
                context.packageManager.getApplicationLabel(info).toString()
            }.getOrNull()
        }
        return when {
            labels.isEmpty() -> "${packages.size} 个"
            labels.size == 1 -> labels.first()
            else -> "${labels.first()} 等 ${labels.size} 个"
        }
    }

    private fun rowsCard(vararg rows: View): LinearLayout {
        val card = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            background = context.rounded(Palette.SURFACE, 0f)
        }
        rows.forEachIndexed { index, row ->
            if (index > 0) {
                card.addView(context.divider(0f), LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    context.dp(1f)
                ))
            }
            card.addView(row)
        }
        return card
    }

    private fun section(title: String): TextView =
        context.text(title, 12f, Palette.MUTED, medium = true).apply {
            setPadding(context.dp(16f), context.dp(20f), context.dp(16f), context.dp(8f))
        }

    private fun textAction(label: String, action: () -> Unit): TextView =
        context.text(label, 13.5f, Palette.ACCENT, medium = true).apply {
            setPadding(context.dp(10f), context.dp(10f), context.dp(10f), context.dp(10f))
            background = context.selectableBorderless()
            clickOnce { action() }
        }

    private fun configString(group: String, key: String): String {
        val core = host.core
        return core.configJson.optJSONObject(group)?.optString(key).orEmpty()
    }

    private fun shorten(value: String): String = when {
        value.isEmpty() -> ""
        value.length <= 34 -> value
        else -> value.take(31) + "…"
    }

    private fun space(height: Float): View = View(context).apply {
        layoutParams = LinearLayout.LayoutParams(1, context.dp(height))
    }
}
