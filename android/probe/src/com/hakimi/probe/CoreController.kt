package com.hakimi.probe

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * The single writer of the native core lifecycle. Both foreground services and
 * the UI go through this object so a late stop from an old owner cannot kill a
 * core that a newer service instance is starting.
 */
object CoreController {
    private const val TAG = "HakimiCore"

    private val main = Handler(Looper.getMainLooper())
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "hakimi-core-control").apply { isDaemon = true }
    }

    @Volatile
    private var owner = ""

    fun start(context: Context, ownerToken: String, callback: (Boolean, String) -> Unit) {
        executor.execute {
            val app = context.applicationContext
            if (Native.isProxyRunning()) {
                owner = ownerToken
                clearLegacyProxy(app)
                main.post { callback(true, "") }
                return@execute
            }
            val initialized = runCatching { Bootstrap.init(app) }.getOrDefault(false)
            val trusted = initialized && runCatching {
                CaTrust.isUserTrusted(Native.caPem())
            }.getOrDefault(false)
            runCatching { Native.setCaTrusted(trusted) }
            clearLegacyProxy(app)
            val started = initialized && runCatching { Native.startProxy() }.getOrDefault(false)
            val error = if (started) "" else runCatching { Native.lastError() }.getOrDefault("")
            if (started) {
                owner = ownerToken
            } else {
                Log.w(TAG, "core start failed: $error")
            }
            main.post { callback(started, error) }
        }
    }

    /**
     * Stops the core only when [ownerToken] is still the active owner. A stop
     * left over from an old service therefore cannot tear down a new one.
     */
    fun stop(ownerToken: String, callback: (() -> Unit)? = null) {
        executor.execute {
            if (owner.isEmpty() || owner == ownerToken) {
                runCatching { Native.stopProxy() }
                owner = ""
            }
            main.post { callback?.invoke() }
        }
    }

    /** Leaves a running core in place for the next service instance to adopt. */
    fun detach(ownerToken: String) {
        executor.execute {
            if (owner == ownerToken) owner = ""
        }
    }

    fun isRunning(): Boolean =
        runCatching { Native.isProxyRunning() }.getOrDefault(false)

    fun proxyPort(): Int = runCatching {
        val config = JSONObject(Native.config())
        config.optJSONObject("proxy")?.optInt("port", 8443) ?: 8443
    }.getOrDefault(8443)

    private fun clearLegacyProxy(context: Context) {
        val port = proxyPort()
        if (!LegacyProxy.isOurs(context, port)) return
        if (LegacyProxy.clearIfOurs(context, port)) {
            Log.i(TAG, "cleared stale global proxy for port $port")
        } else {
            Log.w(TAG, "stale global proxy needs manual cleanup (port $port)")
        }
    }
}
