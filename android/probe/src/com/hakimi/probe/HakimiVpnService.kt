package com.hakimi.probe

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.IpPrefix
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
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
                if (starting) {
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
                        "已接管全部应用"
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
        val manager = getSystemService(NotificationManager::class.java)
        manager?.createNotificationChannel(
            NotificationChannel(CHANNEL, "VPN 加速", NotificationManager.IMPORTANCE_LOW).apply {
                description = "按站点接管应用流量"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
            notice("hakimi VPN 加速中", "已接管全部应用")
            scheduleHealth(15_000L)
        } else {
            startCoreAndVpn()
        }
        return START_STICKY
    }

    private fun startCoreAndVpn() {
        if (starting || stopping || active) return
        starting = true
        CoreController.start(this, ownerToken) { ok, error ->
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

            val trusted = runCatching { CaTrust.isUserTrusted(Native.caPem()) }.getOrDefault(false)
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

        // No allowed-application list: every app is captured. Exclude the
        // hakimi process itself so the core's catalog/DoH traffic cannot loop
        // back into its own proxy, plus every app the user opted out of.
        var excluded = 0
        if (runCatching { builder.addDisallowedApplication(packageName) }.isSuccess) {
            excluded++
        }
        Prefs.excludedApps(this).forEach { pkg ->
            if (pkg == packageName) return@forEach
            if (runCatching { packageManager.getApplicationInfo(pkg, 0) }.isFailure) {
                return@forEach
            }
            if (runCatching { builder.addDisallowedApplication(pkg) }.isSuccess) {
                excluded++
            }
        }

        excludeAllTraffic(builder)
        if (stopping) return
        val next = builder.establish()
        if (next == null) {
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
        lastError = ""
        retryDelay = 3_000L
        Log.i(TAG, "VPN established apps=all excluded=$excluded proxy=127.0.0.1:$port")
        notice("hakimi VPN 加速中", "已接管全部应用")
        scheduleHealth(15_000L)
    }

    private fun startCoreOnly() {
        if (starting || stopping) return
        starting = true
        CoreController.start(this, ownerToken) { ok, error ->
            starting = false
            if (stopping) return@start
            if (ok) {
                retryDelay = 3_000L
                lastError = ""
                notice("hakimi VPN 加速中", "已接管全部应用")
                scheduleHealth(15_000L)
            } else {
                retryDelay = (retryDelay * 2).coerceAtMost(30_000L)
                lastError = error.ifEmpty { "核心启动失败" }
                notice("hakimi VPN", "核心未运行，正在重试")
                scheduleHealth(retryDelay)
            }
        }
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

    private fun notice(title: String, text: String) {
        val next = "$title|$text"
        if (next == lastNotice) return
        lastNotice = next
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(NOTIFICATION_ID, buildNotification(title, text))
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
        val builder = Notification.Builder(this, CHANNEL)
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
