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
    private const val CA_EXPORT_NAME = "ca_export_name"
    private const val AWAITING_CA_INSTALL = "awaiting_ca_install"
    private const val UPDATE_CHECKED_AT = "update_checked_at"
    private const val UPDATE_LATEST = "update_latest"
    private const val UPDATE_NOTIFIED = "update_notified"

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

    /** Last CA file this device exported, used to keep the install sheet honest. */
    fun caExportName(context: Context): String =
        get(context).getString(CA_EXPORT_NAME, "") ?: ""

    fun setCaExportName(context: Context, name: String) {
        get(context).edit().putString(CA_EXPORT_NAME, name).commit()
    }

    /** True while the user is away in the system certificate installer. */
    fun awaitingCaInstall(context: Context): Boolean =
        get(context).getBoolean(AWAITING_CA_INSTALL, false)

    fun setAwaitingCaInstall(context: Context, awaiting: Boolean) {
        get(context).edit().putBoolean(AWAITING_CA_INSTALL, awaiting).commit()
    }

    /** When the last update check finished (successful or not); 0 means never. */
    fun updateCheckedAt(context: Context): Long =
        get(context).getLong(UPDATE_CHECKED_AT, 0L)

    fun setUpdateCheckedAt(context: Context, at: Long) {
        get(context).edit().putLong(UPDATE_CHECKED_AT, at).apply()
    }

    /** Latest version known to be newer than this install; empty when up to date. */
    fun updateLatest(context: Context): String =
        get(context).getString(UPDATE_LATEST, "") ?: ""

    fun setUpdateLatest(context: Context, version: String) {
        get(context).edit().putString(UPDATE_LATEST, version).apply()
    }

    /** Last version the automatic check already announced, so it only toasts once. */
    fun updateNotified(context: Context): String =
        get(context).getString(UPDATE_NOTIFIED, "") ?: ""

    fun setUpdateNotified(context: Context, version: String) {
        get(context).edit().putString(UPDATE_NOTIFIED, version).apply()
    }

    fun systemAlwaysOn(context: Context): Boolean = runCatching {
        Settings.Secure.getString(context.contentResolver, "always_on_vpn_app") == context.packageName
    }.getOrDefault(false)

    fun token(): String = UUID.randomUUID().toString()
}
