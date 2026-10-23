package com.hakimi.probe.ui

import android.content.Context
import android.os.PowerManager
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.hakimi.probe.Bootstrap
import com.hakimi.probe.CaTrust
import com.hakimi.probe.Prefs
import com.hakimi.probe.UpdateState

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

    private lateinit var envRow: SettingRow
    private lateinit var serviceRow: SettingRow
    private lateinit var modeRow: SettingRow
    private lateinit var excludedRow: SettingRow
    private lateinit var certRow: SettingRow
    private lateinit var certInfo: TextView

    private lateinit var portRow: SettingRow
    private lateinit var ipCatalogRow: SettingRow
    private lateinit var dohCatalogRow: SettingRow
    private lateinit var resetCatalogRow: SettingRow
    private lateinit var alwaysOnRow: SettingRow
    private lateinit var batteryRow: SettingRow
    private lateinit var refreshCatalogRow: SettingRow
    private lateinit var diagnoseRow: SettingRow
    private lateinit var logRow: SettingRow
    private lateinit var exportDiagnosticsRow: SettingRow

    private lateinit var updateRow: SettingRow

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
        envRow.hideChevron()
        serviceRow = SettingRow(context, "核心服务", "本地加速核心的运行状态")
        serviceRow.hideChevron()
        content.addView(rowsCard(modeRow, excludedRow, envRow, serviceRow))
        content.addView(space(10f))

        content.addView(section("证书"))
        certRow = SettingRow(context, "本地 CA", "浏览器信任后才能通过 hakimi 加速")
        certRow.clickOnce { host.openCaSetup() }
        val certCard = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            background = context.rounded(Palette.SURFACE, 18f, Palette.BORDER, 1f)
            clipToOutline = true
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
        certActions.addView(textAction("安装证书") { host.openCaSetup() })
        certActions.addView(textAction("导出备份") { host.exportCaBackup() })
        certCard.addView(certActions)
        content.addView(certCard, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            marginStart = context.dp(16f)
            marginEnd = context.dp(16f)
        })
        content.addView(space(10f))

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
        resetCatalogRow = SettingRow(context, "恢复默认目录", "把 IP/DoH 目录恢复为内置地址")
        resetCatalogRow.clickOnce { host.resetCatalogs() }
        content.addView(rowsCard(portRow, ipCatalogRow, dohCatalogRow, resetCatalogRow))
        content.addView(space(10f))

        content.addView(section("后台"))
        alwaysOnRow = SettingRow(context, "始终开启", "系统在开机后恢复 VPN")
        alwaysOnRow.clickOnce(1500L) { host.openVpnSettings() }
        batteryRow = SettingRow(context, "后台保活", "关闭电池优化，减少息屏回收")
        batteryRow.clickOnce(1500L) { host.requestBatteryExemption() }
        content.addView(rowsCard(alwaysOnRow, batteryRow))
        content.addView(space(10f))

        content.addView(section("工具"))
        refreshCatalogRow = SettingRow(context, "刷新远程目录", "重新拉取 IP 与 DoH 目录")
        refreshCatalogRow.clickOnce {
            refreshCatalogRow.setBusy(true)
            host.refreshCatalogs()
        }
        diagnoseRow = SettingRow(context, "域名诊断", "查看单域名的完整路由尝试过程")
        diagnoseRow.clickOnce { host.diagnosePrompt() }
        logRow = SettingRow(context, "运行日志", "最近的核心日志，便于定位问题")
        logRow.clickOnce {
            logRow.setBusy(true)
            host.showLog()
        }
        exportDiagnosticsRow = SettingRow(context, "导出诊断包", "包含脱敏配置与运行状态")
        exportDiagnosticsRow.clickOnce {
            exportDiagnosticsRow.setBusy(true)
            host.exportDiagnostics()
        }
        content.addView(rowsCard(refreshCatalogRow, diagnoseRow, logRow, exportDiagnosticsRow))
        content.addView(space(10f))

        content.addView(section("关于"))
        updateRow = SettingRow(context, "检查更新")
        updateRow.clickOnce(700L) {
            when (host.updateState) {
                UpdateState.Checking -> host.showSnack("正在检查更新，请稍候")
                is UpdateState.Available -> host.showUpdateSheet()
                else -> host.checkUpdate(manual = true)
            }
        }
        val dataRow = SettingRow(context, "数据目录", "点击复制应用私有路径")
        dataRow.setValue(Bootstrap.dataDir(context).absolutePath)
        dataRow.clickOnce(1200L) { host.copy(Bootstrap.dataDir(context).absolutePath, "数据目录") }
        content.addView(rowsCard(updateRow, dataRow))
        content.addView(space(16f))

        content.addView(context.text("本地处理 · 不收集浏览数据", 11f, Palette.MUTED).apply {
            gravity = Gravity.CENTER
            setPadding(0, context.dp(14f), 0, context.dp(14f))
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
                !trusted && !host.caLockReady -> "需设置锁屏"
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
        certRow.setValue(
            when {
                !host.caReady -> "检查中"
                trusted -> "已信任"
                !host.caLockReady -> "需锁屏"
                else -> "未安装"
            },
            when {
                !host.caReady -> Palette.MUTED
                trusted -> Palette.GREEN
                else -> Palette.AMBER
            }
        )

        certInfo.text = buildString {
            append(data.caSubject.ifEmpty { "—" })
            if (data.caFingerprintSha256.isNotEmpty()) {
                append("\nSHA-256  ").append(CaTrust.displaySha256(data.caFingerprintSha256))
            }
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

        portRow.setBusy(host.savingConfig)
        ipCatalogRow.setBusy(host.savingConfig)
        dohCatalogRow.setBusy(host.savingConfig)
        resetCatalogRow.setBusy(host.savingConfig)
        refreshCatalogRow.setBusy(host.refreshingCatalogs)
        diagnoseRow.setBusy(host.diagnosing)
        logRow.setBusy(host.loadingLog)
        exportDiagnosticsRow.setBusy(host.exportingDiagnostics)
        refreshCatalogRow.setValue(if (host.refreshingCatalogs) "刷新中…" else "", Palette.MUTED)
        diagnoseRow.setValue(if (host.diagnosing) "诊断中…" else "", Palette.MUTED)
        logRow.setValue(if (host.loadingLog) "读取中…" else "", Palette.MUTED)
        exportDiagnosticsRow.setValue(
            if (host.exportingDiagnostics) "导出中…" else "",
            Palette.MUTED
        )
        val coreVersion = host.coreVersion.ifEmpty { data.version }.ifEmpty { "—" }
        updateRow.setSubtitle("客户端版本 ${host.appVersion} · Rust Core $coreVersion")
        when (val update = host.updateState) {
            UpdateState.Idle -> {
                updateRow.setValue("尚未检查", Palette.MUTED)
                updateRow.setBusy(false)
            }
            UpdateState.Checking -> {
                updateRow.setValue("检查中…", Palette.MUTED)
                updateRow.setBusy(true)
            }
            UpdateState.UpToDate -> {
                updateRow.setValue("已是最新", Palette.GREEN)
                updateRow.setBusy(false)
            }
            is UpdateState.Available -> {
                updateRow.setValue("v${update.info.version}", Palette.ACCENT)
                updateRow.setBusy(false)
            }
            UpdateState.Failed -> {
                updateRow.setValue("暂时无法检查", Palette.AMBER)
                updateRow.setBusy(false)
            }
        }
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
            background = context.rounded(Palette.SURFACE, 18f, Palette.BORDER, 1f)
            clipToOutline = true
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                marginStart = context.dp(16f)
                marginEnd = context.dp(16f)
            }
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
