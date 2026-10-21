package com.hakimi.probe

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import android.util.Log

/**
 * Cleanup for the old probe-mode global proxy. The production app never writes
 * `Settings.Global.HTTP_PROXY`; this only removes a value that still points at
 * our own local listener, which would otherwise override the VPN PAC and send
 * every browser request to a possibly dead core.
 */
object LegacyProxy {
    private const val TAG = "Hakimi"
    private const val HTTP_PROXY = "http_proxy"
    private const val HOST = "global_http_proxy_host"
    private const val PORT = "global_http_proxy_port"
    private const val PAC = "global_proxy_pac_url"

    fun isOurs(context: Context, port: Int): Boolean {
        val resolver = context.contentResolver
        val raw = Settings.Global.getString(resolver, HTTP_PROXY).orEmpty()
        val host = Settings.Global.getString(resolver, HOST).orEmpty()
        val savedPort = Settings.Global.getString(resolver, PORT).orEmpty()
        val pac = Settings.Global.getString(resolver, PAC).orEmpty()
        return matches(raw, port) ||
            (isLoopback(host) && savedPort == port.toString()) ||
            pac.contains("127.0.0.1:$port") ||
            pac.contains("localhost:$port")
    }

    fun clearIfOurs(context: Context, port: Int): Boolean {
        if (!isOurs(context, port)) return true
        if (context.checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        return try {
            val resolver = context.contentResolver
            Settings.Global.putString(resolver, HTTP_PROXY, ":0")
            Settings.Global.putString(resolver, HOST, "")
            Settings.Global.putString(resolver, PORT, "")
            Settings.Global.putString(resolver, PAC, "")
            Log.i(TAG, "cleared stale global proxy on port $port")
            true
        } catch (error: Throwable) {
            Log.w(TAG, "clearing stale global proxy failed", error)
            false
        }
    }

    private fun matches(raw: String, port: Int): Boolean {
        val value = raw.trim()
        if (value.isEmpty() || value == ":0" || value == "null") return false
        val cleaned = value
            .removePrefix("http://")
            .removePrefix("https://")
            .trimEnd('/')
        val split = cleaned.lastIndexOf(':')
        if (split <= 0) return false
        val host = cleaned.substring(0, split).trim('[', ']')
        val saved = cleaned.substring(split + 1).toIntOrNull() ?: return false
        return isLoopback(host) && saved == port
    }

    private fun isLoopback(host: String): Boolean {
        val value = host.trim().trim('[', ']').lowercase()
        return value == "127.0.0.1" || value == "localhost" || value == "::1"
    }
}
