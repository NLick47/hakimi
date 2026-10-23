package com.hakimi.probe

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

data class UpdateInfo(
    val version: String,
    val url: String,
)

sealed class UpdateState {
    object Idle : UpdateState()
    object Checking : UpdateState()
    object UpToDate : UpdateState()
    data class Available(val info: UpdateInfo) : UpdateState()
    object Failed : UpdateState()
}

/**
 * Reads the update manifest attached to the newest GitHub Release. The app
 * never downloads an APK itself: [UpdateInfo.url] points at the release page,
 * which the browser opens, so a tampered manifest cannot trigger an install
 * inside hakimi.
 */
object UpdateChecker {
    private const val MANIFEST =
        "https://github.com/NLick47/hakimi/releases/latest/download/latest.json"
    const val RELEASES_URL = "https://github.com/NLick47/hakimi/releases"

    sealed class Result {
        object UpToDate : Result()
        data class Newer(val info: UpdateInfo) : Result()
    }

    fun check(current: String): Result {
        val connection = (URL(MANIFEST).openConnection() as HttpURLConnection).apply {
            connectTimeout = 8_000
            readTimeout = 8_000
            instanceFollowRedirects = true
            requestMethod = "GET"
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "hakimi/$current")
        }
        try {
            val code = connection.responseCode
            if (code == HttpURLConnection.HTTP_NOT_FOUND) return Result.UpToDate
            if (code !in 200..299) throw IOException("HTTP $code")

            val body = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            val manifest = JSONObject(body)
            if (manifest.optInt("schema", 0) != 1) {
                throw IOException("unsupported update manifest schema")
            }
            val android = manifest.optJSONObject("android") ?: return Result.UpToDate
            val version = android.optString("version").trim().removePrefix("v").trim()
            if (version.isEmpty()) throw IOException("update manifest has no Android version")
            if (!AppVersion.isNewer(version, current)) {
                return Result.UpToDate
            }

            val release = manifest.optString("release").trim()
            val fallback = if (safeTag(release)) {
                "$RELEASES_URL/tag/$release"
            } else {
                RELEASES_URL
            }
            val url = android.optString("url").trim()
                .takeIf { safeUrl(it) }
                ?: fallback
            return Result.Newer(UpdateInfo(version, url))
        } finally {
            connection.disconnect()
        }
    }

    /** The manifest is untrusted; only the project's release pages open. */
    private fun safeUrl(url: String): Boolean =
        url.startsWith("https://github.com/NLick47/hakimi/releases/")

    private fun safeTag(tag: String): Boolean =
        tag.isNotEmpty() && tag.all { it.isLetterOrDigit() || it == '-' || it == '_' || it == '.' }
}
