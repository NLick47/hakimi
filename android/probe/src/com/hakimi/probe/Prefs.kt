package com.hakimi.probe

import android.content.Context
import android.content.SharedPreferences
import android.provider.Settings
import java.util.UUID

/** Persistent control state shared by the UI and both foreground services. */
object Prefs {
    const val MODE_PROXY = "proxy"
    const val MODE_VPN = "vpn"

    private const val FILE = "hakimi"
    private const val DESIRED = "desired_running"
    private const val MODE = "run_mode"
    private const val EXCLUDED_APPS = "vpn_excluded_apps"

    fun get(context: Context): SharedPreferences =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun desired(context: Context): Boolean = get(context).getBoolean(DESIRED, false)

    /** Control flags are written synchronously: a sticky restart may read them immediately. */
    fun setDesired(context: Context, desired: Boolean) {
        get(context).edit().putBoolean(DESIRED, desired).commit()
    }

    fun mode(context: Context): String =
        get(context).getString(MODE, MODE_VPN) ?: MODE_VPN

    fun setMode(context: Context, mode: String) {
        get(context).edit().putString(MODE, if (mode == MODE_VPN) MODE_VPN else MODE_PROXY).commit()
    }

    /** Packages whose traffic bypasses the VPN entirely. Empty means none. */
    fun excludedApps(context: Context): Set<String> =
        get(context).getStringSet(EXCLUDED_APPS, null)?.toSet() ?: emptySet()

    fun setExcludedApps(context: Context, packages: Set<String>) {
        get(context).edit().putStringSet(EXCLUDED_APPS, packages.toSet()).commit()
    }

    fun systemAlwaysOn(context: Context): Boolean = runCatching {
        Settings.Secure.getString(context.contentResolver, "always_on_vpn_app") == context.packageName
    }.getOrDefault(false)

    fun token(): String = UUID.randomUUID().toString()
}
