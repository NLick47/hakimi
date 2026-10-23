package com.hakimi.probe

import android.Manifest
import android.app.Activity
import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.provider.DocumentsContract
import android.provider.Settings
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.Toast
import com.hakimi.probe.ui.BackdropView
import com.hakimi.probe.ui.BottomNav
import com.hakimi.probe.ui.CaSetupSheet
import com.hakimi.probe.ui.CoreData
import com.hakimi.probe.ui.CoreParser
import com.hakimi.probe.ui.DiagnoseOutcome
import com.hakimi.probe.ui.DiagnoseResultSheet
import com.hakimi.probe.ui.ExcludedAppsSheet
import com.hakimi.probe.ui.HomeScreen
import com.hakimi.probe.ui.Host
import com.hakimi.probe.ui.Palette
import com.hakimi.probe.ui.SettingsScreen
import com.hakimi.probe.ui.Sheet
import com.hakimi.probe.ui.Sheets
import com.hakimi.probe.ui.SiteDetailSheet
import com.hakimi.probe.ui.SiteEditorSheet
import com.hakimi.probe.ui.SiteInfo
import com.hakimi.probe.ui.SitesScreen
import com.hakimi.probe.ui.TopBar
import com.hakimi.probe.ui.column
import com.hakimi.probe.ui.clickOnce
import com.hakimi.probe.ui.dp
import com.hakimi.probe.ui.edgeToEdge
import com.hakimi.probe.ui.gradient
import com.hakimi.probe.ui.monospace
import com.hakimi.probe.ui.padBottomForSystemBars
import com.hakimi.probe.ui.padTopForSystemBars
import com.hakimi.probe.ui.rounded
import com.hakimi.probe.ui.selectableBackground
import com.hakimi.probe.ui.text
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.util.concurrent.Executors

class MainActivity : Activity(), Host {
    companion object {
        private const val TAG = "Hakimi"
        private const val REQUEST_SAVE_CA = 42
        private const val REQUEST_NOTIFICATIONS = 43
        private const val REQUEST_VPN = 44
    }

    /** Trusted in either the user store or the system store. */
    @Volatile
    private var userCaTrusted = false

    @Volatile
    private var caChecked = false

    @Volatile
    private var resumed = false

    override val caReady: Boolean
        get() = caChecked

    override val caLockReady: Boolean
        get() = Build.VERSION.SDK_INT < Build.VERSION_CODES.R ||
            getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true

    private var lastCaExportName = ""

    override val caExportName: String
        get() = lastCaExportName.ifEmpty { Prefs.caExportName(this) }

    private var data: CoreData = CoreParser.parse("{}", "{}", false)

    override val core: CoreData
        get() = data

    @Volatile
    private var probeInFlight = false

    override val probing: Boolean
        get() = probeInFlight

    private val handler = Handler(Looper.getMainLooper())
    private val operations = Executors.newFixedThreadPool(3)
    private var pollInFlight = false
    private var syncingCa = false
    private val caCallbacks = ArrayList<() -> Unit>()
    private var caSheet: CaSetupSheet? = null
    private var pendingCaWrite: PendingCaWrite? = null
    private var awaitingCaInstall = false
    private var reopenCaSheet = false
    private var startAfterCaInstall = false
    private var starting = false
    private var lastAccelToggle = 0L
    private var exporting = false
    private var refreshingCatalogs = false
    private var diagnosing = false
    private var autoStartPending = false
    private var pendingVpnStart = false
    @Volatile private var staleProxyChecked = false
    private var tab = 0

    private enum class CaWriteKind { INSTALL, BACKUP }

    private data class PendingCaWrite(
        val der: ByteArray,
        val kind: CaWriteKind,
        val suggestedName: String,
        val openSettings: Boolean,
    )

    private lateinit var topBar: TopBar
    private lateinit var screenHost: FrameLayout
    private lateinit var nav: BottomNav
    private lateinit var home: HomeScreen
    private lateinit var sites: SitesScreen
    private lateinit var settings: SettingsScreen
    private lateinit var screens: Array<View>

    private val pollTask = object : Runnable {
        override fun run() {
            pollOnce()
            handler.postDelayed(this, 1500L)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lastCaExportName = Prefs.caExportName(this)
        awaitingCaInstall = Prefs.awaitingCaInstall(this)
        buildShell()
        edgeToEdge()
        buildScreens()
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        if (intent?.getBooleanExtra("stop", false) == true) {
            intent.removeExtra("stop")
            stopAcceleration()
            return
        }
        autoStartPending = intent?.getBooleanExtra("start", false) == true
        val url = intent?.getStringExtra("url")
        if (!url.isNullOrEmpty()) {
            handler.postDelayed({ openUrl(url) }, 1200L)
        }
    }

    private fun buildShell() {
        val root = FrameLayout(this)
        root.addView(BackdropView(this), FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        ))

        val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        topBar = TopBar(this).apply { padTopForSystemBars() }
        column.addView(topBar, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))
        screenHost = FrameLayout(this)
        column.addView(screenHost, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            0,
            1f
        ))
        root.addView(column, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        ))

        nav = BottomNav(this)
        nav.onSelected = { setTab(it) }
        val navWrap = FrameLayout(this).apply {
            padBottomForSystemBars()
        }
        navWrap.addView(nav, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            dp(72f),
            Gravity.BOTTOM
        ))
        root.addView(navWrap, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        ))

        setContentView(root)
    }

    private fun buildScreens() {
        home = HomeScreen(this, this)
        sites = SitesScreen(this, this)
        settings = SettingsScreen(this, this)
        screens = arrayOf(home.view, sites.view, settings.view)
        screens.forEach { screen ->
            screen.visibility = View.GONE
            screenHost.addView(screen, FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            ))
        }
        screens[0].visibility = View.VISIBLE
        nav.select(0, false)
        updateTopBar()
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        syncCaTrust {
            if (!resumed) return@syncCaTrust
            maybeAutoStart()
            afterCaSync()
        }
        handler.removeCallbacks(pollTask)
        handler.post(pollTask)
    }

    override fun onPause() {
        resumed = false
        handler.removeCallbacks(pollTask)
        super.onPause()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        operations.shutdown()
        super.onDestroy()
    }

    @Deprecated("Deprecated in Android 13, kept for API 26-32")
    override fun onBackPressed() {
        if (tab != 0) {
            setTab(0)
        } else {
            super.onBackPressed()
        }
    }

    private fun maybeAutoStart() {
        if (!autoStartPending) return
        autoStartPending = false
        if (userCaTrusted) {
            startAcceleration()
        } else {
            startAfterCaInstall = true
            openCaSetup()
        }
    }

    // -- polling -------------------------------------------------------------

    private fun pollOnce() {
        if (pollInFlight) return
        pollInFlight = true
        operations.execute {
            val status = runCatching { Native.status() }.getOrDefault("")
            val config = runCatching { Native.config() }.getOrDefault("")
            val parsed = runCatching {
                CoreParser.parse(status, config, userCaTrusted)
            }.getOrDefault(data)
            handler.post {
                pollInFlight = false
                if (isFinishing || isDestroyed) return@post
                if (parsed.siteCount == 0 && data.siteCount > 0 &&
                    status.contains("\"error\"")
                ) {
                    return@post
                }
                data = parsed
                if (parsed.running) starting = false
                if (!staleProxyChecked) {
                    staleProxyChecked = true
                    if (LegacyProxy.isOurs(this, parsed.port)) {
                        val cleared = LegacyProxy.clearIfOurs(this, parsed.port)
                        showSnack(
                            if (cleared) "已清除旧的系统代理设置" else "检测到旧系统代理，请手动清除",
                            error = !cleared
                        )
                    }
                }
                if (resumed) caSheet?.refresh()
                render()
            }
        }
    }

    private fun render() {
        if (!::home.isInitialized) return
        home.refresh(data)
        when (tab) {
            1 -> sites.refresh(data)
            2 -> settings.refresh(data)
        }
        nav.setBadge(1, data.failedDomains > 0)
        if (tab == 1) updateTopBar()
    }

    private fun updateTopBar() {
        when (tab) {
            1 -> topBar.setScreen(
                "站点",
                if (probeInFlight) "正在检测全部域名"
                else "${data.siteCount} 个站点 · ${data.enabledSites} 个启用",
                "检测" to { runProbeSweep() },
                "添加" to { openEditor(null) }
            )
            2 -> topBar.setScreen("设置")
            else -> topBar.setScreen("hakimi")
        }
    }

    private fun refreshNow() {
        pollOnce()
    }

    override fun setTab(index: Int) {
        val nextIndex = index.coerceIn(0, screens.lastIndex)
        if (nextIndex == tab && screens[nextIndex].visibility == View.VISIBLE) {
            nav.select(nextIndex, false)
            return
        }
        val previous = screens[tab]
        val next = screens[nextIndex]
        if (previous !== next) {
            previous.animate().alpha(0f).translationY(dp(8f).toFloat()).setDuration(150L)
                .withEndAction { previous.visibility = View.GONE }.start()
            next.animate().cancel()
            next.alpha = 0f
            next.translationY = dp(12f).toFloat()
            next.visibility = View.VISIBLE
            next.animate().alpha(1f).translationY(0f).setDuration(230L).start()
        }
        tab = nextIndex
        nav.select(nextIndex, false)
        updateTopBar()
        when (nextIndex) {
            1 -> sites.refresh(data)
            2 -> settings.refresh(data)
        }
    }

    // -- acceleration --------------------------------------------------------

    override fun toggleAcceleration() {
        if (!caChecked) {
            showSnack("正在检查环境，请稍候")
            return
        }
        val now = SystemClock.elapsedRealtime()
        if (now - lastAccelToggle < 800L) return
        lastAccelToggle = now
        if (data.running || HakimiVpnService.active) stopAcceleration() else startAcceleration()
    }

    private fun startAcceleration() {
        if (data.running || starting || HakimiVpnService.active) return
        if (!userCaTrusted) {
            startAfterCaInstall = true
            openCaSetup()
            return
        }
        startAfterCaInstall = false
        requestNotificationPermission()

        if (Prefs.mode(this) == Prefs.MODE_VPN) {
            if (Build.VERSION.SDK_INT < 33) {
                showSnack("VPN 模式需要 Android 13 及以上", error = true)
                return
            }
            val consent = VpnService.prepare(this)
            if (consent != null) {
                pendingVpnStart = true
                startActivityForResult(consent, REQUEST_VPN)
                return
            }
            launchVpn()
            return
        }

        starting = true
        try {
            startForegroundService(
                Intent(this, ProxyService::class.java).setAction(ProxyService.ACTION_START)
            )
            showSnack("正在启动本地核心…")
        } catch (error: Throwable) {
            starting = false
            showSnack("启动失败：${error.message}", error = true)
            return
        }
        watchdogStart()
        refreshNow()
    }

    private fun launchVpn() {
        starting = true
        try {
            startForegroundService(
                Intent(this, HakimiVpnService::class.java).setAction(HakimiVpnService.ACTION_START)
            )
            showSnack("正在建立 VPN…")
        } catch (error: Throwable) {
            starting = false
            showSnack("VPN 启动失败：${error.message}", error = true)
            return
        }
        watchdogStart()
        refreshNow()
    }

    private fun watchdogStart() {
        handler.postDelayed({
            if (isFinishing) return@postDelayed
            if (starting && !data.running && !HakimiVpnService.active) {
                val message = runCatching { Native.lastError() }.getOrDefault("")
                showSnack(message.ifEmpty { "启动超时，请查看运行日志" }, error = true)
            }
            if (starting) starting = false
            refreshNow()
        }, 8_000L)
    }

    private fun stopAcceleration() {
        starting = false
        startAfterCaInstall = false
        if (Prefs.mode(this) == Prefs.MODE_VPN) {
            if (Prefs.systemAlwaysOn(this)) {
                showAlwaysOnStop()
                return
            }
            try {
                startService(
                    Intent(this, HakimiVpnService::class.java)
                        .setAction(HakimiVpnService.ACTION_STOP)
                )
                showSnack("正在停止 VPN…")
            } catch (error: Throwable) {
                showSnack("停止失败：${error.message}", error = true)
            }
        } else {
            try {
                startService(
                    Intent(this, ProxyService::class.java).setAction(ProxyService.ACTION_STOP)
                )
                showSnack("已停止加速")
            } catch (error: Throwable) {
                showSnack("停止失败：${error.message}", error = true)
            }
        }
        handler.postDelayed({
            if (isFinishing || isDestroyed) return@postDelayed
            data = data.copy(running = false, listen = "")
            render()
            refreshNow()
        }, 700L)
    }

    private fun showAlwaysOnStop() {
        Sheets.confirm(
            this,
            "始终开启已启用",
            "系统会在后台恢复 hakimi VPN。请先在系统 VPN 设置中关闭「始终开启」，再停止加速。",
            "打开 VPN 设置"
        ) {
            openVpnSettings()
        }
    }

    override fun chooseMode() {
        val current = Prefs.mode(this)
        val sheet = Sheet(this, "运行模式", "浏览器流量进入核心的方式")
        sheet.add(modeOption(
            "本地代理",
            "浏览器手动配置代理地址",
            current == Prefs.MODE_PROXY
        ) {
            sheet.dismiss()
            applyMode(Prefs.MODE_PROXY)
        })
        sheet.add(divider(), LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            dp(1f)
        ))
        sheet.add(modeOption(
            "VPN · 全部应用",
            "自动接管所有应用，包括浏览器与 WebView（Android 13+）",
            current == Prefs.MODE_VPN
        ) {
            sheet.dismiss()
            applyMode(Prefs.MODE_VPN)
        })
        sheet.show()
    }

    private fun modeOption(
        title: String,
        subtitle: String,
        selected: Boolean,
        action: () -> Unit,
    ): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(4f), dp(14f), dp(4f), dp(14f))
            background = selectableBackground()
        }
        val texts = column()
        texts.addView(text(title, 14.5f, Palette.TEXT, medium = true))
        texts.addView(text(subtitle, 11.5f, Palette.MUTED).apply {
            setPadding(0, dp(3f), 0, 0)
        })
        row.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(text(if (selected) "✓" else "", 18f, Palette.ACCENT, medium = true).apply {
            gravity = Gravity.CENTER
            setPadding(dp(10f), 0, dp(4f), 0)
        })
        row.clickOnce { action() }
        return row
    }

    private fun divider(): View = View(this).apply {
        setBackgroundColor(Palette.BORDER)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            dp(1f)
        )
    }

    private fun applyMode(mode: String) {
        if (mode == Prefs.mode(this)) {
            render()
            return
        }
        if (mode == Prefs.MODE_VPN) {
            if (Build.VERSION.SDK_INT < 33) {
                Sheets.info(this, "VPN 模式", "VPN 模式需要 Android 13 及以上。")
                return
            }
            if (!userCaTrusted) {
                openCaSetup()
                return
            }
        } else if (Prefs.systemAlwaysOn(this)) {
            Sheets.confirm(
                this,
                "始终开启已启用",
                "请先在系统 VPN 设置中关闭「始终开启」，再切换到本地代理。",
                "打开 VPN 设置"
            ) {
                openVpnSettings()
            }
            return
        }

        if (data.running || HakimiVpnService.active) {
            Sheets.confirm(
                this,
                "切换运行模式",
                "切换会短暂中断当前加速。",
                "切换"
            ) {
                switchMode(mode)
            }
            return
        }

        Prefs.setMode(this, mode)
        showSnack(if (mode == Prefs.MODE_VPN) "已切换到 VPN 模式" else "已切换到本地代理")
        render()
    }

    private fun switchMode(mode: String) {
        val old = Prefs.mode(this)
        if (old == Prefs.MODE_VPN) {
            startService(
                Intent(this, HakimiVpnService::class.java)
                    .setAction(HakimiVpnService.ACTION_STOP)
            )
        } else {
            startService(
                Intent(this, ProxyService::class.java).setAction(ProxyService.ACTION_STOP)
            )
        }
        Prefs.setMode(this, mode)
        starting = false
        waitForStop(0) {
            data = data.copy(running = false, listen = "")
            render()
            startAcceleration()
        }
    }

    private fun waitForStop(attempt: Int, then: () -> Unit) {
        val busy = runCatching { Native.isProxyRunning() }.getOrDefault(false) ||
            HakimiVpnService.active
        if (busy && attempt < 30) {
            handler.postDelayed({ waitForStop(attempt + 1, then) }, 150L)
        } else {
            then()
        }
    }

    override fun chooseExcludedApps() {
        ExcludedAppsSheet(this, this).show()
    }

    override fun onExcludedAppsChanged() {
        if (Prefs.mode(this) == Prefs.MODE_VPN &&
            (HakimiVpnService.active || data.running)
        ) {
            showSnack("正在应用排除列表…")
            startService(
                Intent(this, HakimiVpnService::class.java)
                    .setAction(HakimiVpnService.ACTION_STOP)
            )
            waitForStop(0) {
                data = data.copy(running = false, listen = "")
                render()
                startAcceleration()
            }
        } else {
            render()
        }
    }

    override fun openVpnSettings() {
        try {
            startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
        } catch (_: Throwable) {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:$packageName")
                    )
                )
            } catch (error: Throwable) {
                showSnack("无法打开系统设置：${error.message}", error = true)
            }
        }
    }

    override fun requestBatteryExemption() {
        val power = getSystemService(PowerManager::class.java)
        if (power?.isIgnoringBatteryOptimizations(packageName) == true) {
            showSnack("已允许后台运行")
            return
        }
        try {
            startActivity(
                Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:$packageName")
                )
            )
        } catch (_: Throwable) {
            try {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            } catch (error: Throwable) {
                showSnack("无法打开电池优化设置：${error.message}", error = true)
            }
        }
    }

    // -- sites ---------------------------------------------------------------

    override fun setGroupEnabled(site: SiteInfo, enabled: Boolean) {
        operations.execute {
            val ok = runCatching { Native.setGroupEnabled(site.id, enabled) }.getOrDefault(false)
            val error = if (ok) "" else runCatching { Native.lastError() }.getOrDefault("")
            handler.post {
                if (!ok) {
                    showSnack(error.ifEmpty { "更新站点失败" }, error = true)
                }
                refreshNow()
            }
        }
    }

    override fun saveGroup(group: JSONObject, isNew: Boolean, done: (Boolean, String?) -> Unit) {
        operations.execute {
            val ok = runCatching { Native.upsertGroup(group.toString()) }.getOrDefault(false)
            val error = if (ok) null else runCatching { Native.lastError() }.getOrDefault("")
            handler.post {
                if (ok) {
                    showSnack(if (isNew) "站点已添加" else "站点已保存")
                    refreshNow()
                }
                done(ok, error?.ifEmpty { "保存失败" })
            }
        }
    }

    override fun deleteGroup(id: String, done: (Boolean, String?) -> Unit) {
        operations.execute {
            val ok = runCatching { Native.removeGroup(id) }.getOrDefault(false)
            val error = if (ok) null else runCatching { Native.lastError() }.getOrDefault("")
            handler.post {
                if (ok) {
                    showSnack("站点已删除")
                    refreshNow()
                }
                done(ok, error?.ifEmpty { "删除失败" })
            }
        }
    }

    override fun openSite(site: SiteInfo) {
        SiteDetailSheet(this, this, site).show()
    }

    override fun openEditor(site: SiteInfo?) {
        SiteEditorSheet(this, this, site).show()
    }

    // -- probing and diagnostics --------------------------------------------

    override fun runProbeSweep() {
        if (probeInFlight) return
        probeInFlight = true
        updateTopBar()
        sites.refresh(data)
        showSnack("正在检测全部站点…")
        operations.execute {
            val ok = runCatching { Native.probeSweep() }.getOrDefault(false)
            val error = if (ok) "" else runCatching { Native.lastError() }.getOrDefault("")
            handler.post {
                probeInFlight = false
                updateTopBar()
                showSnack(
                    if (ok) "检测完成" else error.ifEmpty { "检测失败" },
                    error = !ok
                )
                refreshNow()
            }
        }
    }

    override fun diagnosePrompt() {
        Sheets.input(
            this,
            "域名诊断",
            "探测该域名的 IP、TLS 策略与完整尝试记录",
            "",
            "例如 www.pixiv.net"
        ) { domain ->
            runDiagnose(domain) { outcome ->
                DiagnoseResultSheet(this, this, outcome).show()
            }
        }
    }

    override fun runDiagnose(domain: String, done: (DiagnoseOutcome) -> Unit) {
        if (diagnosing) return
        diagnosing = true
        operations.execute {
            val raw = runCatching { Native.diagnose(domain) }.getOrDefault("")
            val obj = runCatching { JSONObject(raw) }.getOrNull()
            fun string(key: String): String {
                val value = obj?.opt(key) ?: return ""
                return if (value == JSONObject.NULL) "" else value.toString()
            }
            val latency = if (obj?.opt("latencyMs") == null || obj?.opt("latencyMs") == JSONObject.NULL) {
                null
            } else {
                obj?.optLong("latencyMs")
            }
            val error = string("error")
            val state = string("state").ifEmpty {
                if (error.isEmpty()) "unknown" else "failed"
            }
            val outcome = DiagnoseOutcome(
                ok = raw.isNotEmpty() && error.isEmpty() && state != "failed",
                domain = domain,
                state = state,
                latencyMs = latency,
                ip = string("ip"),
                tls = string("strategy"),
                error = error.ifEmpty { string("detail") },
                raw = raw,
            )
            handler.post {
                diagnosing = false
                done(outcome)
            }
        }
    }

    // -- settings ------------------------------------------------------------

    override fun editSetting(key: String, title: String, subtitle: String, value: String) {
        if (key == "proxy.port" && (data.running || HakimiVpnService.active)) {
            showSnack("请先停止加速，再修改本地端口", error = true)
            return
        }
        Sheets.input(
            this,
            title,
            subtitle,
            value,
            if (key == "proxy.port") "8443" else "https://…",
            numeric = key == "proxy.port"
        ) { raw ->
            val next = runCatching { JSONObject(data.configJson.toString()) }.getOrNull()
            if (next == null) {
                showSnack("配置尚未就绪", error = true)
                return@input
            }
            val changed = when (key) {
                "proxy.port" -> {
                    val port = raw.toIntOrNull()
                    if (port == null || port !in 1..65535) {
                        showSnack("端口必须是 1–65535 之间的数字", error = true)
                        false
                    } else {
                        next.getJSONObject("proxy").put("port", port)
                        true
                    }
                }
                "doh.primary" -> {
                    if (raw.isBlank()) {
                        showSnack("DoH 地址不能为空", error = true)
                        false
                    } else {
                        next.getJSONObject("doh").put("primary", raw)
                        true
                    }
                }
                "doh.fallback" -> {
                    if (raw.isBlank()) {
                        showSnack("备用 DoH 地址不能为空", error = true)
                        false
                    } else {
                        next.getJSONObject("doh").put("fallback", raw)
                        true
                    }
                }
                "catalogs.ip", "catalogs.doh" -> {
                    val value = raw.trim()
                    if (value.isNotEmpty() &&
                        !value.startsWith("http://") &&
                        !value.startsWith("https://")
                    ) {
                        showSnack("目录地址必须以 http:// 或 https:// 开头", error = true)
                        false
                    } else {
                        next.getJSONObject("catalogs").put(key.substringAfter('.'), value)
                        true
                    }
                }
                else -> false
            }
            if (changed) {
                applyConfig(next) { ok, error ->
                    showSnack(
                        if (ok) "设置已保存" else (error ?: "保存失败"),
                        error = !ok
                    )
                }
            }
        }
    }

    override fun resetCatalogs() {
        Sheets.confirm(
            this,
            "恢复默认目录",
            "IP 目录和 DoH 目录将恢复为内置的 Gitee 地址。",
            "恢复"
        ) {
            val defaults = runCatching { JSONObject(Native.defaultCatalogUrls()) }.getOrNull()
            val next = runCatching { JSONObject(data.configJson.toString()) }.getOrNull()
            if (defaults == null || next == null) {
                showSnack("配置尚未就绪", error = true)
                return@confirm
            }
            val ip = defaults.optString("ip")
            val doh = defaults.optString("doh")
            if (ip.isEmpty() || doh.isEmpty()) {
                showSnack("默认目录不可用", error = true)
                return@confirm
            }
            val catalogs = next.getJSONObject("catalogs")
            catalogs.put("ip", ip)
            catalogs.put("doh", doh)
            applyConfig(next) { ok, error ->
                if (ok) {
                    showSnack("目录已恢复默认")
                    refreshCatalogs()
                } else {
                    showSnack(error ?: "恢复失败", error = true)
                }
            }
        }
    }

    override fun applyConfig(next: JSONObject, done: (Boolean, String?) -> Unit) {
        operations.execute {
            val ok = runCatching { Native.applyConfig(next.toString()) }.getOrDefault(false)
            val error = if (ok) null else runCatching { Native.lastError() }.getOrDefault("")
            handler.post {
                if (ok) refreshNow()
                done(ok, error?.ifEmpty { "配置保存失败" })
            }
        }
    }

    override fun refreshCatalogs() {
        if (refreshingCatalogs) return
        refreshingCatalogs = true
        showSnack("正在刷新远程目录…")
        operations.execute {
            val raw = runCatching { Native.refreshCatalogs(true) }.getOrDefault("[]")
            var updated = false
            val errors = ArrayList<String>()
            try {
                val array = JSONArray(raw)
                for (index in 0 until array.length()) {
                    val item = array.optJSONObject(index) ?: continue
                    if (item.optBoolean("ok")) {
                        val report = item.optJSONObject("report")
                        if (report?.optBoolean("updated") == true) updated = true
                    } else {
                        errors += item.optString("error", "未知错误")
                    }
                }
            } catch (_: Throwable) {
                // Keep the generic failure message below.
            }
            handler.post {
                refreshingCatalogs = false
                when {
                    errors.isNotEmpty() -> showSnack(errors.first(), error = true)
                    updated -> showSnack("远程目录已更新")
                    else -> showSnack("目录已是最新")
                }
                refreshNow()
            }
        }
    }

    override fun showLog() {
        operations.execute {
            val path = runCatching { Native.logPath() }.getOrDefault("")
            if (path.isEmpty()) {
                handler.post { showSnack("日志尚未生成", error = true) }
                return@execute
            }
            val content = try {
                val file = File(path)
                if (!file.exists()) "" else {
                    RandomAccessFile(file, "r").use { random ->
                        val length = random.length()
                        val start = (length - 48_000L).coerceAtLeast(0L)
                        random.seek(start)
                        val bytes = ByteArray((length - start).toInt())
                        random.readFully(bytes)
                        String(bytes, Charsets.UTF_8)
                    }
                }
            } catch (error: Throwable) {
                "读取日志失败：$error"
            }
            handler.post {
                if (content.isEmpty()) {
                    showSnack("日志尚未生成", error = true)
                } else {
                    Sheets.monospace(this, "运行日志", path, content) { text ->
                        copy(text, "日志")
                    }
                }
            }
        }
    }

    override fun exportDiagnostics() {
        operations.execute {
            val path = runCatching { Native.exportDiagnostics() }.getOrDefault("")
            val error = runCatching { Native.lastError() }.getOrDefault("")
            handler.post {
                if (path.isEmpty()) {
                    showSnack(error.ifEmpty { "诊断包导出失败" }, error = true)
                } else {
                    copy(path, "诊断包路径")
                    showSnack("诊断包已导出：$path")
                }
            }
        }
    }

    // -- certificate ---------------------------------------------------------

    override fun openCaSetup() {
        if (isFinishing || isDestroyed) return
        val current = caSheet
        if (current?.isShowing() == true) {
            current.refresh()
            return
        }
        caSheet = CaSetupSheet(this, this).also { it.show() }
    }

    override fun exportCaForInstall() = exportCa(openSettings = true)

    override fun saveCaForInstall() = exportCa(openSettings = false)

    override fun exportCaBackup() {
        if (exporting) return
        exporting = true
        operations.execute {
            val der = CaTrust.der(runCatching { Bootstrap.caPem(this) }.getOrDefault(""))
            handler.post {
                exporting = false
                if (der == null) {
                    showSnack("证书尚未准备好，请稍后重试", error = true)
                    return@post
                }
                val name = backupName()
                pendingCaWrite = PendingCaWrite(
                    der,
                    CaWriteKind.BACKUP,
                    name,
                    openSettings = false,
                )
                launchCaDocument(name)
            }
        }
    }

    /**
     * Writes the install copy. Android 10+ targets the single file in
     * Downloads; older systems (and MediaStore failures) use SAF. When
     * [openSettings] is true the security screen is opened right away and
     * [afterCaSync] checks the result on return.
     */
    private fun exportCa(openSettings: Boolean) {
        if (exporting) return
        exporting = true
        operations.execute {
            val pem = runCatching { Bootstrap.caPem(this) }.getOrDefault("")
            val der = CaTrust.der(pem)
            if (der == null) {
                handler.post {
                    exporting = false
                    showSnack("证书尚未准备好，请稍后重试", error = true)
                }
                return@execute
            }

            val saved = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                try {
                    CaStore.saveToDownloads(contentResolver, packageName, der, caExportName)
                } catch (error: Throwable) {
                    Log.w(TAG, "saving CA to Downloads failed", error)
                    null
                }
            } else {
                null
            }

            handler.post {
                exporting = false
                if (saved == null) {
                    pendingCaWrite = PendingCaWrite(
                        der,
                        CaWriteKind.INSTALL,
                        CaStore.INSTALL_NAME,
                        openSettings,
                    )
                    launchCaDocument(CaStore.INSTALL_NAME)
                    return@post
                }
                lastCaExportName = saved
                Prefs.setCaExportName(this, saved)
                if (openSettings) {
                    awaitingCaInstall = true
                    Prefs.setAwaitingCaInstall(this, true)
                    caSheet?.dismiss()
                    caSheet = null
                    val opened = openSecuritySettings()
                    showSnack(
                        if (opened) "已保存到 $saved，请继续安装"
                        else "已保存到 $saved，请手动打开系统设置安装",
                        error = !opened,
                    )
                    if (!opened) {
                        awaitingCaInstall = false
                        Prefs.setAwaitingCaInstall(this, false)
                    }
                } else {
                    showSnack("已保存到 $saved")
                    if (!isFinishing && !isDestroyed) caSheet?.refresh()
                }
            }
        }
    }

    override fun recheckCa() {
        syncCaTrust {
            val trusted = userCaTrusted
            showSnack(
                if (trusted) "证书已安装并受信任"
                else "还没有检测到证书，请确认安装时选择的是「${caFileName()}」",
                error = !trusted,
            )
            caSheet?.refresh()
        }
    }

    override fun openCaInstallSettings() {
        if (isFinishing || isDestroyed) return
        awaitingCaInstall = true
        Prefs.setAwaitingCaInstall(this, true)
        caSheet?.dismiss()
        caSheet = null
        if (!openSecuritySettings()) {
            awaitingCaInstall = false
            Prefs.setAwaitingCaInstall(this, false)
            showSnack("无法打开系统设置，请手动进入安全设置", error = true)
        }
    }

    override fun openCaLockSettings() {
        if (isFinishing || isDestroyed) return
        caSheet?.dismiss()
        caSheet = null
        reopenCaSheet = true
        if (!openSecuritySettings()) {
            reopenCaSheet = false
            showSnack("无法打开系统设置，请手动设置锁屏", error = true)
        }
    }

    private fun openSecuritySettings(): Boolean {
        val intents = listOf(
            Intent(Settings.ACTION_SECURITY_SETTINGS),
            Intent(Settings.ACTION_SETTINGS),
        )
        for (intent in intents) {
            try {
                startActivity(intent)
                return true
            } catch (_: Throwable) {
            }
        }
        return false
    }

    /** Runs after every CA probe; closes the loop with the system installer. */
    private fun afterCaSync() {
        caSheet?.refresh()
        var installed = false
        if (awaitingCaInstall) {
            awaitingCaInstall = false
            Prefs.setAwaitingCaInstall(this, false)
            if (!userCaTrusted) {
                reopenCaSheet = false
                showSnack(
                    "还没有检测到证书，请确认安装时选择的是「${caFileName()}」",
                    error = true,
                )
                openCaSetup()
                return
            }
            installed = true
        }
        if (startAfterCaInstall && userCaTrusted) {
            startAfterCaInstall = false
            showSnack("证书已安装，正在开启加速")
            startAcceleration()
        } else if (installed) {
            showSnack("证书已安装，可以开始加速了")
        } else if (reopenCaSheet) {
            if (userCaTrusted) {
                showSnack("证书已安装，可以开始加速了")
            } else {
                openCaSetup()
            }
        }
        reopenCaSheet = false
    }

    private fun syncCaTrust(then: (() -> Unit)? = null) {
        if (then != null) caCallbacks += then
        if (syncingCa) return
        syncingCa = true
        operations.execute {
            val initialized = runCatching { Bootstrap.init(this) }.getOrDefault(false)
            val pem = runCatching { Bootstrap.caPem(this) }.getOrDefault("")
            val trust = CaTrust.trust(pem)
            val trusted = trust.user || trust.system
            Log.i(
                TAG,
                "ca init=$initialized user=${trust.user} system=${trust.system} pem=${pem.length}",
            )
            try {
                File(filesDir, "ca-store.txt").writeText(CaTrust.listTrusted())
            } catch (error: Throwable) {
                Log.w(TAG, "CA store dump failed", error)
            }
            runCatching { Native.setCaTrusted(trusted) }
            userCaTrusted = trusted
            handler.post {
                syncingCa = false
                caChecked = true
                if (isFinishing || isDestroyed) return@post
                if (data.userCaTrusted != trusted) {
                    data = data.copy(userCaTrusted = trusted)
                }
                if (!resumed) {
                    caCallbacks.clear()
                    return@post
                }
                render()
                caSheet?.refresh()
                val callbacks = caCallbacks.toList()
                caCallbacks.clear()
                callbacks.forEach { callback ->
                    runCatching { callback() }
                }
                refreshNow()
            }
        }
    }

    private fun backupName(): String =
        "hakimi-ca-${LocalDate.now().format(DateTimeFormatter.BASIC_ISO_DATE)}.crt"

    private fun caFileName(): String = caExportName.ifEmpty { CaStore.INSTALL_NAME }

    private fun launchCaDocument(name: String) {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_TITLE, name)
            runCatching {
                putExtra(
                    DocumentsContract.EXTRA_INITIAL_URI,
                    DocumentsContract.buildRootUri(
                        "com.android.externalstorage.documents",
                        "downloads",
                    ),
                )
            }
        }
        try {
            startActivityForResult(intent, REQUEST_SAVE_CA)
        } catch (error: Throwable) {
            pendingCaWrite = null
            exporting = false
            showSnack("无法打开文件选择器：$error", error = true)
        }
    }

    @Deprecated("Deprecated in API 30")
    override fun onActivityResult(requestCode: Int, resultCode: Int, result: Intent?) {
        super.onActivityResult(requestCode, resultCode, result)
        if (requestCode == REQUEST_VPN) {
            val pending = pendingVpnStart
            pendingVpnStart = false
            if (resultCode == RESULT_OK && pending) {
                launchVpn()
            } else {
                showSnack("未授权 VPN", error = true)
            }
            return
        }
        if (requestCode != REQUEST_SAVE_CA) return
        val pending = pendingCaWrite
        val uri = if (resultCode == RESULT_OK) result?.data else null
        if (pending == null || uri == null) {
            pendingCaWrite = null
            exporting = false
            return
        }
        operations.execute {
            val ok = CaStore.writeDocument(contentResolver, uri, pending.der)
            val name = CaStore.displayName(contentResolver, uri)
                .ifEmpty { pending.suggestedName }
            handler.post {
                pendingCaWrite = null
                exporting = false
                if (!ok) {
                    showSnack("保存证书失败", error = true)
                    return@post
                }
                if (pending.kind == CaWriteKind.BACKUP) {
                    showSnack("证书备份已保存：$name")
                    return@post
                }
                lastCaExportName = name
                Prefs.setCaExportName(this, name)
                if (!pending.openSettings) {
                    showSnack("已保存到 $name")
                    if (!isFinishing && !isDestroyed) caSheet?.refresh()
                    return@post
                }
                awaitingCaInstall = true
                Prefs.setAwaitingCaInstall(this, true)
                caSheet?.dismiss()
                caSheet = null
                val opened = openSecuritySettings()
                showSnack(
                    if (opened) "已保存到 $name，请继续安装"
                    else "已保存到 $name，请手动打开系统设置安装",
                    error = !opened,
                )
                if (!opened) {
                    awaitingCaInstall = false
                    Prefs.setAwaitingCaInstall(this, false)
                }
            }
        }
    }

    // -- misc ----------------------------------------------------------------

    override fun openUrl(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (error: Throwable) {
            showSnack("没有可以打开该链接的应用", error = true)
        }
    }

    override fun copy(text: String, label: String) {
        val manager = getSystemService(ClipboardManager::class.java) ?: return
        manager.setPrimaryClip(ClipData.newPlainText(label, text))
        showSnack("已复制$label")
    }

    override fun showSnack(message: String, error: Boolean) {
        if (isFinishing) return
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_NOTIFICATIONS
            )
        }
    }
}
