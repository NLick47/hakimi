package com.hakimi.probe

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.NetworkCapabilities
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Production VPN mode.
 *
 * All applications are pointed at a static HTTP proxy on the core; the hakimi
 * app itself is excluded so its own catalog/DoH traffic cannot loop back into
 * the local proxy. A default `excludeRoute` makes every real destination fall
 * through to the underlying network, and no packet is read from the TUN. The
 * core only intercepts enabled groups; every other host is tunneled straight
 * through.
 *
 * The proxy is static rather than a PAC because WebView-based browsers ignore
 * a PAC delivered through the VPN network, and because every application must
 * be covered without asking the user to pick browsers. With a static proxy the
 * core sees every request and applies the same per-host policy itself.
 *
 * The tradeoff is that a stopped core also stops proxied browsing: a PAC could
 * fall back to DIRECT, while a static proxy has no fallback. The health check
 * restarts the core within seconds.
 */
class HakimiVpnService : VpnService() {
    companion object {
        private const val TAG = "HakimiVpn"
        private const val CHANNEL = "hakimi_vpn"
        private const val NOTIFICATION_ID = 1002
        const val ACTION_START = "com.hakimi.probe.vpn.START"
        const val ACTION_STOP = "com.hakimi.probe.vpn.STOP"

        @Volatile var active = false
        @Volatile var alwaysOn = false
        @Volatile var lockdown = false
        @Volatile var lastError = ""

        /**
         * The system grant was revoked, so `establish()` cannot succeed until an
         * Activity runs [prepare] again. Set here, cleared once a tunnel is up;
         * the UI reads it on resume to re-arm the consent dialog.
         */
        @Volatile var needsConsent = false
    }

    private val handler = Handler(Looper.getMainLooper())
    private val ownerToken = Prefs.token()

    private var tun: ParcelFileDescriptor? = null

    @Volatile private var starting = false
    @Volatile private var stopping = false
    @Volatile private var retryDelay = 3_000L
    private var lastNotice = ""

    private val health = object : Runnable {
        override fun run() {
            if (stopping) return
            alwaysOn = effectiveAlwaysOn()
            lockdown = isLockdownCompat()
            if (!Prefs.desired(this@HakimiVpnService) && !alwaysOn) return

            if (!active) {
                // A revoked grant cannot be repaired from a Service; hold the
                // retry loop until the UI re-arms the consent dialog.
                if (needsConsent) {
                    handler.postDelayed(this, 15_000L)
                } else if (starting) {
                    handler.postDelayed(this, 2_000L)
                } else {
                    startCoreAndVpn()
                }
                return
            }

            if (CoreController.isRunning()) {
                if (lastError.isNotEmpty()) {
                    lastError = ""
                    notice(
                        "hakimi VPN 加速中",
                        captureLabel()
                    )
                }
                handler.postDelayed(this, 15_000L)
            } else {
                lastError = "核心未运行，浏览器暂时无法上网"
                notice("hakimi VPN", "核心未运行，正在重试")
                if (starting) {
                    handler.postDelayed(this, 2_000L)
                } else {
                    startCoreOnly()
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(
                NotificationChannel(CHANNEL, "VPN 加速", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "按站点接管应用流量"
                    setShowBadge(false)
                    lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                }
            )
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Prefs.migrateScope(this)
        alwaysOn = effectiveAlwaysOn()
        lockdown = isLockdownCompat()
        if (alwaysOn) {
            // The system's always-on setting is an explicit request to run.
            Prefs.setDesired(this, true)
            Prefs.setMode(this, Prefs.MODE_VPN)
        }

        if (intent?.action == ACTION_STOP) {
            startForegroundCompat()
            if (alwaysOn) {
                notice("hakimi VPN", "始终开启已启用，请在系统 VPN 设置中关闭")
                handler.removeCallbacks(health)
                handler.postDelayed(health, 15_000L)
                return START_STICKY
            }
            Prefs.setDesired(this, false)
            stopInternal()
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_START) {
            Prefs.setDesired(this, true)
        }

        startForegroundCompat()
        if (!Prefs.desired(this)) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        stopping = false
        if (active) {
            notice("hakimi VPN 加速中", captureLabel())
            scheduleHealth(15_000L)
        } else {
            startCoreAndVpn()
        }
        return START_STICKY
    }

    private fun startCoreAndVpn() {
        if (starting || stopping || active) return
        // Checked before the core starts: a revoked grant (force-stop, another
        // VPN, reinstall) makes every establish() fail, and only an Activity may
        // show the consent dialog. Retrying here would leave a core with no
        // tunnel behind it, so flag the loss and wait for the UI to re-arm it.
        if (VpnService.prepare(this) != null) {
            needsConsent = true
            lastError = "VPN 授权已失效"
            notice("hakimi VPN", "请在 hakimi 中重新授权 VPN")
            scheduleHealth(15_000L)
            return
        }
        starting = true
        CoreController.start(this, ownerToken) { ok, error, trusted ->
            starting = false
            if (stopping) return@start
            if (!Prefs.desired(this) && !alwaysOn) {
                stopInternal()
                return@start
            }
            if (!ok) {
                retryDelay = (retryDelay * 2).coerceAtMost(30_000L)
                lastError = error.ifEmpty { "核心启动失败" }
                notice("hakimi VPN", lastError)
                scheduleHealth(retryDelay)
                return@start
            }

            runCatching { Native.setCaTrusted(trusted) }
            if (!trusted) {
                lastError = "证书未安装"
                notice("hakimi VPN", "本地 CA 尚未安装，暂不建立 VPN")
                scheduleHealth(15_000L)
                return@start
            }

            val status = runCatching { JSONObject(Native.status()) }.getOrNull()
            val proxy = status?.optJSONObject("proxy")
            val listen = proxy?.takeIf { !it.isNull("listen") }?.optString("listen").orEmpty()
            if (listen.isEmpty()) {
                lastError = "核心未提供监听地址"
                notice("hakimi VPN", lastError)
                scheduleHealth(15_000L)
                return@start
            }
            val port = listen.substringAfterLast(':').toIntOrNull() ?: 8443
            if (!LegacyProxy.clearIfOurs(this, port)) {
                Log.w(TAG, "legacy global proxy still points at the local listener")
            }

            try {
                establishVpn(port)
            } catch (error: Throwable) {
                lastError = "${error.javaClass.simpleName}: ${error.message}"
                Log.e(TAG, "establishing the VPN failed", error)
                notice("hakimi VPN", "建立失败: ${error.message}")
                scheduleHealth(15_000L)
            }
            if (!active && !stopping) {
                scheduleHealth(15_000L)
            }
        }
    }

    private fun establishVpn(port: Int) {
        if (Build.VERSION.SDK_INT < 33) {
            lastError = "VPN 模式需要 Android 13 及以上"
            notice("hakimi VPN", lastError)
            return
        }
        val builder = this.Builder()
            .setSession("hakimi")
            .addAddress("198.18.0.1", 32)
            .setMtu(1500)
            .setBlocking(false)
            .setMetered(false)
            .setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", port))
            .setConfigureIntent(
                PendingIntent.getActivity(
                    this,
                    3,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
            )

        // Captured apps that do not read the system proxy resolve names
        // through this network; with no servers they fail as "network
        // unavailable" while the core keeps resolving on its own.
        val dnsServers = underlyingDnsServers()
        dnsServers.forEach { server -> runCatching { builder.addDnsServer(server) } }

        // SCOPE_ONLY narrows the VPN to an explicit allowlist; every other
        // scope captures everything. Both paths keep the hakimi process itself
        // out so the core's catalog/DoH traffic cannot loop back into its own
        // proxy, plus every app the user opted out of. The builder rejects a
        // mixed allow/disallow set, so the allowlist is resolved first.
        val scopeOnly = Prefs.scope(this) == Prefs.SCOPE_ONLY
        val allowed = if (scopeOnly) {
            Prefs.allowedApps(this).filter { pkg ->
                pkg != packageName &&
                    runCatching { packageManager.getApplicationInfo(pkg, 0) }.isSuccess
            }
        } else {
            emptyList()
        }
        // A builder without an allowlist captures everything, so an empty
        // allowlist has to abort instead of quietly widening the scope.
        if (scopeOnly && allowed.isEmpty()) {
            lastError = "接管范围内还没有应用"
            notice("hakimi VPN", "请在「接管范围」里至少选择一个应用")
            return
        }
        if (scopeOnly) {
            allowed.forEach { pkg -> runCatching { builder.addAllowedApplication(pkg) } }
        } else if (runCatching { builder.addDisallowedApplication(packageName) }.isSuccess) {
            // Only the hakimi process stays out; the core talks to its catalogs
            // and must not loop back into its own proxy.
        }

        excludeAllTraffic(builder)
        if (stopping) return
        val next = builder.establish()
        if (next == null) {
            // establish() reports null both for a revoked grant and for a
            // rejected configuration; only the former can be fixed by consent.
            if (VpnService.prepare(this) != null) {
                needsConsent = true
                lastError = "VPN 授权已失效"
                notice("hakimi VPN", "请在 hakimi 中重新授权 VPN")
                return
            }
            lastError = "系统未建立 VPN 接口"
            notice("hakimi VPN", lastError)
            return
        }
        if (stopping) {
            runCatching { next.close() }
            return
        }
        tun = next
        active = true
        needsConsent = false
        lastError = ""
        retryDelay = 3_000L
        Log.i(TAG, "VPN established apps=${if (scopeOnly) "only:${allowed.size}" else "all"} dns=${dnsServers.size} proxy=127.0.0.1:$port")
        notice("hakimi VPN 加速中", captureLabel())
        scheduleHealth(15_000L)
    }

    private fun startCoreOnly() {
        if (starting || stopping) return
        starting = true
        CoreController.start(this, ownerToken) { ok, error, _ ->
            starting = false
            if (stopping) return@start
            if (ok) {
                retryDelay = 3_000L
                lastError = ""
                notice("hakimi VPN 加速中", captureLabel())
                scheduleHealth(15_000L)
            } else {
                retryDelay = (retryDelay * 2).coerceAtMost(30_000L)
                lastError = error.ifEmpty { "核心启动失败" }
                notice("hakimi VPN", "核心未运行，正在重试")
                scheduleHealth(retryDelay)
            }
        }
    }

    /**
     * DNS servers to hand to the VPN network, taken from whatever physical
     * network is up. Reading our own VPN network would return an empty list.
     */
    private fun underlyingDnsServers(): List<InetAddress> {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        fun serversOf(network: android.net.Network): List<InetAddress> {
            val capabilities = manager.getNetworkCapabilities(network) ?: return emptyList()
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return emptyList()
            return manager.getLinkProperties(network)?.dnsServers.orEmpty()
        }
        val active = manager.activeNetwork?.let { serversOf(it) }.orEmpty()
        val servers = if (active.isNotEmpty()) {
            active
        } else {
            manager.allNetworks.flatMap { serversOf(it) }
        }
        // IPv4 first: a stale IPv6 server on a v6-less carrier stalls every
        // lookup. Link-local servers are useless on a network with no routes.
        return servers
            .distinct()
            .filterNot { it.isLinkLocalAddress || it.isLoopbackAddress }
            .sortedBy { it is Inet6Address }
    }

    private fun excludeAllTraffic(builder: VpnService.Builder) {
        val v4 = runCatching {
            builder.excludeRoute(IpPrefix(InetAddress.getByName("0.0.0.0"), 0))
        }
        if (v4.isFailure) {
            builder.excludeRoute(IpPrefix(InetAddress.getByName("0.0.0.0"), 1))
            builder.excludeRoute(IpPrefix(InetAddress.getByName("128.0.0.0"), 1))
        }
        val v6 = runCatching {
            builder.excludeRoute(IpPrefix(InetAddress.getByName("::"), 0))
        }
        if (v6.isFailure) {
            builder.excludeRoute(IpPrefix(InetAddress.getByName("::"), 1))
            builder.excludeRoute(IpPrefix(InetAddress.getByName("8000::"), 1))
        }
        Log.i(TAG, "exclude all routes v4=${v4.isSuccess} v6=${v6.isSuccess}")
    }

    private fun scheduleHealth(delay: Long) {
        handler.removeCallbacks(health)
        handler.postDelayed(health, delay)
    }

    private fun stopInternal() {
        if (stopping) return
        stopping = true
        needsConsent = false
        handler.removeCallbacks(health)
        starting = false
        active = false
        runCatching { tun?.close() }
        tun = null
        CoreController.stop(ownerToken) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN revoked by the system or another VPN")
        stopping = true
        handler.removeCallbacks(health)
        active = false
        lastError = "VPN 被其他应用接管"
        runCatching { tun?.close() }
        tun = null
        CoreController.stop(ownerToken)
        notice("hakimi VPN", lastError)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        runCatching { tun?.close() }
        tun = null
        active = false
        if (!Prefs.desired(this) && !alwaysOn) {
            if (!stopping) CoreController.stop(ownerToken)
        } else {
            CoreController.detach(ownerToken)
        }
        super.onDestroy()
    }

    /** What the notification claims to cover; must match what establishVpn captured. */
    private fun captureLabel(): String {
        val count = Prefs.allowedApps(this).count { pkg ->
            runCatching { packageManager.getApplicationInfo(pkg, 0) }.isSuccess
        }
        return if (Prefs.scope(this) == Prefs.SCOPE_ONLY && count > 0) {
            "已接管 $count 个应用"
        } else {
            "已接管全部应用"
        }
    }

    private fun notice(title: String, text: String) {
        val next = "$title|$text"
        if (next == lastNotice) return
        lastNotice = next
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(NOTIFICATION_ID, buildNotification(title, text))
    }

    private fun notificationBuilder(): Notification.Builder =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL)
        } else {
            Notification.Builder(this)
        }

    private fun startForegroundCompat() {
        val notification = buildNotification("hakimi VPN", "正在准备浏览器接管…")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(title: String, text: String): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java)
                .putExtra("stop", true)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = notificationBuilder()
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(0xFF0EA5E9.toInt())
            .setContentIntent(open)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .addAction(
                Notification.Action.Builder(R.drawable.ic_close, "停止", stop).build()
            )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        }
        return builder.build()
    }

    private fun isAlwaysOnCompat(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            runCatching { isAlwaysOn }.getOrDefault(false)
        } else {
            false
        }

    /**
     * `VpnService.isAlwaysOn()` can stay true in a long-lived instance after the
     * user disables the system switch. The secure setting is the current user
     * intent, so require both before refusing an in-app stop.
     */
    private fun effectiveAlwaysOn(): Boolean =
        Prefs.systemAlwaysOn(this) && isAlwaysOnCompat()

    private fun isLockdownCompat(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            runCatching { isLockdownEnabled }.getOrDefault(false)
        } else {
            false
        }
}
