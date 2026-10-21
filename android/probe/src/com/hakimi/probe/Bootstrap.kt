package com.hakimi.probe

import android.content.Context
import android.util.Log
import java.io.File

/** Copies the bundled probe CA into the core data dir before the runtime starts. */
object Bootstrap {
    private const val TAG = "Hakimi"

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

    private fun ensureCa(context: Context, dataDir: File) {
        val caDir = File(dataDir, "ca")
        if (!caDir.exists() && !caDir.mkdirs()) {
            throw IllegalStateException("cannot create $caDir")
        }
        copyAsset(context, "ca/ca.pem", File(caDir, "ca.pem"))
        copyAsset(context, "ca/key.pem", File(caDir, "key.pem"))
    }

    private fun copyAsset(context: Context, asset: String, target: File) {
        if (target.exists() && target.length() > 0L) return
        context.assets.open(asset).use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        Log.i(TAG, "copied $asset to $target")
    }
}
