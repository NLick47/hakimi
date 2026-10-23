package com.hakimi.probe

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

data class UpdateInfo(
    val version: String,
    val url: String,
    val notes: String,
)

sealed class UpdateState {
    object Idle : UpdateState()
    object Checking : UpdateState()
    object UpToDate : UpdateState()
    data class Available(val info: UpdateInfo) : UpdateState()
    object Failed : UpdateState()
}

/**
 * Reads the newest published release from GitHub. The app never downloads an
 * APK itself: [UpdateInfo.url] points at the release page, which the browser
 * opens, so a tampered response cannot trigger an install inside hakimi.
 */
object UpdateChecker {
    private const val API = "https://api.github.com/repos/NLick47/hakimi/releases/latest"
    const val RELEASES_URL = "https://github.com/NLick47/hakimi/releases"
    private const val MAX_NOTES = 8000

    sealed class Result {
        object UpToDate : Result()
        data class Newer(val info: UpdateInfo) : Result()
    }

    fun releaseUrl(version: String): String =
        "$RELEASES_URL/tag/v${version.trim().removePrefix("v")}"

    fun check(current: String): Result {
        val connection = (URL(API).openConnection() as HttpURLConnection).apply {
            connectTimeout = 8_000
            readTimeout = 8_000
            instanceFollowRedirects = true
            requestMethod = "GET"
            setRequestProperty("Accept", "application/vnd.github+json")
            setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
            setRequestProperty("User-Agent", "hakimi/$current")
        }
        try {
            val code = connection.responseCode
            if (code == HttpURLConnection.HTTP_NOT_FOUND) return Result.UpToDate
            if (code !in 200..299) throw IOException("HTTP $code")

            val body = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            val release = JSONObject(body)
            val version = release.optString("tag_name").trim().removePrefix("v").trim()
            if (version.isEmpty()) throw IOException("release has no version tag")
            if (!AppVersion.isNewer(version, current)) {
                return Result.UpToDate
            }
            val url = release.optString("html_url").trim()
                .takeIf { safeUrl(it) }
                ?: releaseUrl(version)
            val notes = release.optString("body").trim().take(MAX_NOTES)
            return Result.Newer(UpdateInfo(version, url, notes))
        } finally {
            connection.disconnect()
        }
    }

    /** The API response is untrusted; only the project's release pages open. */
    private fun safeUrl(url: String): Boolean =
        url.startsWith("https://github.com/NLick47/hakimi/")
}
