package com.hakimi.probe

import android.content.Context
import android.util.Log
import java.io.File

/** Copies the bundled probe CA into the core data dir before the runtime starts. */
object Bootstrap {
    private const val TAG = "Hakimi"

    @Volatile
    private var mismatchLogged = false

    fun dataDir(context: Context): File = File(context.filesDir, "hakimi")

    @Synchronized
    fun init(context: Context): Boolean = try {
        val directory = dataDir(context)
        ensureCa(context, directory)
        Native.init(directory.absolutePath)
    } catch (error: Throwable) {
        Log.e(TAG, "native init failed", error)
        false
    }

    /**
     * Reads the CA the core will use without starting the native runtime. The
     * certificate is bundled in the APK and copied to [dataDir] on first use.
     */
    @Synchronized
    fun caPem(context: Context): String = try {
        val directory = dataDir(context)
        ensureCa(context, directory)
        File(directory, "ca/ca.pem").readText()
    } catch (error: Throwable) {
        Log.e(TAG, "reading bundled CA failed", error)
        ""
    }

    private fun ensureCa(context: Context, dataDir: File) {
        val caDir = File(dataDir, "ca")
        if (!caDir.exists() && !caDir.mkdirs()) {
            throw IllegalStateException("cannot create $caDir")
        }
        copyAsset(context, "ca/ca.pem", File(caDir, "ca.pem"))
        copyAsset(context, "ca/key.pem", File(caDir, "key.pem"))
    }

    private fun copyAsset(context: Context, asset: String, target: File) {
        if (target.exists() && target.length() > 0L) {
            // The APK is built around one long-lived CA: updates must keep the
            // same cert/key so users never have to reinstall it. A mismatch is
            // a build bug, not something to migrate silently at runtime.
            val existing = runCatching { target.readBytes() }.getOrNull()
            val bundled = runCatching {
                context.assets.open(asset).use { it.readBytes() }
            }.getOrNull()
            if (!mismatchLogged && existing != null && bundled != null &&
                !existing.contentEquals(bundled)
            ) {
                mismatchLogged = true
                Log.e(TAG, "bundled $asset differs from $target; keeping the existing CA")
            }
            return
        }
        context.assets.open(asset).use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        Log.i(TAG, "copied $asset to $target")
    }
}
