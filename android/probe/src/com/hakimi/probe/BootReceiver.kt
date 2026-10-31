package com.hakimi.probe

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/** Restores the user's chosen acceleration mode after boot or an app update. */
class BootReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "Hakimi"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }
        if (!Prefs.desired(context)) return

        val vpn = Prefs.mode(context) == Prefs.MODE_VPN
        val target = if (vpn) HakimiVpnService::class.java else ProxyService::class.java
        val action = if (vpn) HakimiVpnService.ACTION_START else ProxyService.ACTION_START
        try {
            val serviceIntent = Intent(context, target).setAction(action)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
            Log.i(TAG, "restored ${if (vpn) "VPN" else "proxy"} mode after system event")
        } catch (error: Throwable) {
            Log.w(TAG, "restore after boot failed", error)
        }
    }
}
