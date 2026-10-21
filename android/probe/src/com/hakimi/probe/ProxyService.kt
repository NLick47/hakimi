package com.hakimi.probe

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Color
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log

/**
 * Proxy-mode foreground service. It owns the core lifecycle through
 * [CoreController] and keeps retrying when the native listener disappears.
 */
class ProxyService : Service() {
    companion object {
        private const val TAG = "Hakimi"
        private const val CHANNEL = "hakimi_core"
        private const val NOTIFICATION_ID = 1001
        const val ACTION_START = "com.hakimi.probe.START"
        const val ACTION_STOP = "com.hakimi.probe.STOP"
    }

    private val handler = Handler(Looper.getMainLooper())
    private val ownerToken = Prefs.token()

    @Volatile private var starting = false
    @Volatile private var stopping = false
    @Volatile private var lastRunning = false
    @Volatile private var retryDelay = 3_000L
    @Volatile private var lastError = ""
    private var lastNotice = ""

    private val health = object : Runnable {
        override fun run() {
            if (stopping || !Prefs.desired(this@ProxyService)) return
            if (CoreController.isRunning()) {
                retryDelay = 3_000L
                if (!lastRunning) {
                    lastRunning = true
                    lastError = ""
                    notice("hakimi 加速中", "本地核心正在为浏览器提供加速")
                }
                handler.postDelayed(this, 15_000L)
                return
            }
            lastRunning = false
            notice("hakimi 正在重试", lastError.ifEmpty { "核心未运行" })
            if (starting) {
                handler.postDelayed(this, 2_000L)
            } else {
                startCore()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager?.createNotificationChannel(
            NotificationChannel(CHANNEL, "加速服务", NotificationManager.IMPORTANCE_LOW).apply {
                description = "保持本地加速核心在后台运行"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            startForegroundCompat()
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
        lastRunning = CoreController.isRunning()
        if (lastRunning) {
            notice("hakimi 加速中", "本地核心正在为浏览器提供加速")
            scheduleHealth(15_000L)
        } else {
            startCore()
        }
        return START_STICKY
    }

    private fun startCore() {
        if (starting || stopping) return
        starting = true
        CoreController.start(this, ownerToken) { ok, error ->
            starting = false
            if (stopping) return@start
            if (!Prefs.desired(this)) {
                stopInternal()
                return@start
            }
            if (ok) {
                retryDelay = 3_000L
                lastRunning = true
                lastError = ""
                notice("hakimi 加速中", "本地核心正在为浏览器提供加速")
                scheduleHealth(15_000L)
            } else {
                lastRunning = false
                lastError = error.ifEmpty { "核心启动失败" }
                notice("hakimi 正在重试", lastError)
                retryDelay = (retryDelay * 2).coerceAtMost(30_000L)
                scheduleHealth(retryDelay)
            }
        }
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
        CoreController.stop(ownerToken) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun notice(title: String, text: String) {
        val next = "$title|$text"
        if (next == lastNotice) return
        lastNotice = next
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(NOTIFICATION_ID, buildNotification(title, text))
    }

    private fun startForegroundCompat() {
        val notification = buildNotification("hakimi 加速中", "本地核心正在为浏览器提供加速")
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
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, ProxyService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = Notification.Builder(this, CHANNEL)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(Color.parseColor("#0EA5E9"))
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

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        if (!Prefs.desired(this)) {
            if (!stopping) CoreController.stop(ownerToken)
        } else {
            CoreController.detach(ownerToken)
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
