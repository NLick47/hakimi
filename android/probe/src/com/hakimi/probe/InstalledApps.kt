package com.hakimi.probe

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager

/**
 * Launchable applications with network access. Used by the exclusion picker.
 * A launcher query keeps the app within normal package visibility while still
 * covering every app a user can open, including WebView-based browsers.
 */
object InstalledApps {
    data class Entry(val packageName: String, val label: String)

    fun launchable(context: Context): List<Entry> {
        val manager = context.packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        val resolved = manager.queryIntentActivities(intent, 0)
        return resolved.mapNotNull { info ->
            val pkg = info.activityInfo?.packageName ?: return@mapNotNull null
            if (pkg == context.packageName) return@mapNotNull null
            val hasInternet = runCatching {
                manager.checkPermission(Manifest.permission.INTERNET, pkg) ==
                    PackageManager.PERMISSION_GRANTED
            }.getOrDefault(false)
            if (!hasInternet) return@mapNotNull null
            val label = runCatching { info.loadLabel(manager).toString() }.getOrDefault(pkg)
            Entry(pkg, label)
        }.distinctBy { it.packageName }
            .sortedBy { it.label.lowercase() }
    }
}
