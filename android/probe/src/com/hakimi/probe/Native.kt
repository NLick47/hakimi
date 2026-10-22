package com.hakimi.probe

/**
 * JNI surface of the shared Rust core. The static native method names are
 * resolved against this class, so keep the package and class name stable when
 * the UI changes.
 */
object Native {
    init {
        System.loadLibrary("hakimi_android")
    }

    @JvmStatic external fun init(dataDir: String): Boolean

    @JvmStatic external fun startProxy(): Boolean

    @JvmStatic external fun stopProxy()

    /** Lock-free core listener health, safe to call from the main thread. */
    @JvmStatic external fun isProxyRunning(): Boolean

    @JvmStatic external fun shutdown()

    @JvmStatic external fun status(): String

    @JvmStatic external fun config(): String

    @JvmStatic external fun defaultCatalogUrls(): String

    @JvmStatic external fun applyConfig(json: String): Boolean

    @JvmStatic external fun setGroupEnabled(id: String, enabled: Boolean): Boolean

    @JvmStatic external fun upsertGroup(json: String): Boolean

    @JvmStatic external fun removeGroup(id: String): Boolean

    @JvmStatic external fun probeSweep(): Boolean

    @JvmStatic external fun refreshCatalogs(force: Boolean): String

    @JvmStatic external fun exportDiagnostics(): String

    @JvmStatic external fun caPem(): String

    @JvmStatic external fun logPath(): String

    @JvmStatic external fun setCaTrusted(trusted: Boolean)

    @JvmStatic external fun lastError(): String

    @JvmStatic external fun diagnose(domain: String): String
}
