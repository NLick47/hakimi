package com.hakimi.probe.ui

import org.json.JSONArray
import org.json.JSONObject
import java.time.Duration
import java.time.OffsetDateTime

data class DomainInfo(
    val host: String,
    val state: String,
    val stateText: String,
    val stateColor: Int,
    val latencyText: String,
    val latencyMs: Long?,
    val ip: String,
    val tls: String,
    val error: String,
    val detail: String,
)

data class SiteInfo(
    val id: String,
    val name: String,
    val enabled: Boolean,
    val strategy: String,
    val sni: String,
    val homepage: String,
    val domains: List<DomainInfo>,
    val exactDomains: List<String>,
    val rawDomainCount: Int,
    val summary: String,
    val summaryColor: Int,
    val state: String,
    val custom: Boolean,
    val experimental: Boolean,
    val echShared: Boolean,
)

data class CoreData(
    val running: Boolean,
    val paused: Boolean,
    val proxyError: String,
    val proxyApplied: Boolean?,
    val listen: String,
    val port: Int,
    val version: String,
    val startedAt: String,
    val userCaTrusted: Boolean,
    val caCoreInstalled: Boolean,
    val caSubject: String,
    val caFingerprint: String,
    val caNotAfter: String,
    val caError: String,
    val siteCount: Int,
    val enabledSites: Int,
    val domainTotal: Int,
    val normalDomains: Int,
    val slowDomains: Int,
    val failedDomains: Int,
    val requests: Long,
    val responsesH1: Long,
    val responsesH2: Long,
    val connections: Long,
    val cacheEntries: Long,
    val sites: List<SiteInfo>,
    val statusJson: JSONObject,
    val configJson: JSONObject,
    val rawStatus: String,
    val rawConfig: String,
    val warnings: List<String>,
) {
    val endpoint: String
        get() = listen.ifEmpty { "127.0.0.1:$port" }

    fun uptimeText(): String {
        if (startedAt.isEmpty()) return "—"
        return try {
            val started = OffsetDateTime.parse(startedAt)
            val seconds = Duration.between(started, OffsetDateTime.now()).seconds.coerceAtLeast(0)
            val hours = seconds / 3600
            val minutes = (seconds % 3600) / 60
            val secs = seconds % 60
            if (hours > 0) "%d:%02d:%02d".format(hours, minutes, secs)
            else "%02d:%02d".format(minutes, secs)
        } catch (_: Throwable) {
            "—"
        }
    }

    fun site(id: String): SiteInfo? = sites.firstOrNull { it.id == id }
}

object CoreParser {
    private val BUILTIN_IDS = setOf(
        "github", "pixiv", "ao3", "eh", "hitomi", "nhentai", "hanime", "steam", "poipiku"
    )

    fun parse(statusRaw: String, configRaw: String, userCaTrusted: Boolean): CoreData {
        val root = runCatching { JSONObject(statusRaw) }.getOrDefault(JSONObject())
        val config = runCatching { JSONObject(configRaw) }.getOrDefault(JSONObject())
        val proxy = root.optJSONObject("proxy")
        val ca = root.optJSONObject("ca")
        val upstream = root.optJSONObject("upstream")
        val cache = root.optJSONObject("cache")
        val proxyApplied = when {
            proxy == null || proxy.opt("applied") == null || proxy.opt("applied") == JSONObject.NULL -> null
            else -> proxy.optBoolean("applied")
        }

        val statusGroups = HashMap<String, JSONObject>()
        root.optJSONArray("groups")?.objects()?.forEach { group ->
            val id = group.str("id")
            if (id.isNotEmpty()) statusGroups[id] = group
        }
        val diagnostics = HashMap<String, JSONObject>()
        root.optJSONArray("domains")?.objects()?.forEach { record ->
            val host = record.str("domain")
            if (host.isNotEmpty()) diagnostics[host] = record
        }

        val sites = ArrayList<SiteInfo>()
        config.optJSONArray("groups")?.objects()?.forEach { group ->
            val id = group.str("id")
            if (id.isEmpty() || id == "echtest") return@forEach
            val name = group.str("name").ifEmpty { id }
            val enabled = group.optBoolean("enabled", true)
            val strategy = group.str("strategy").ifEmpty { "auto" }
            val rawDomains = group.optJSONArray("domains")?.strings().orEmpty()
            val exactDomains = rawDomains.filter { !it.startsWith("*.") }
            val displayDomains = exactDomains.take(24).map { host ->
                domainInfo(host, diagnostics[host], enabled)
            }

            var slow = 0
            var bad = 0
            var checking = 0
            var tested = 0
            displayDomains.forEach { domain ->
                when (domain.stateText) {
                    "超时" -> bad++
                    "较慢" -> slow++
                    "检测中" -> checking++
                }
                if (domain.stateText !in setOf("—", "未选择", "检测中", "待检测")) tested++
            }

            val summary: String
            val summaryColor: Int
            when {
                !enabled -> {
                    summary = "${exactDomains.size} 个域名 · 未选择"
                    summaryColor = Palette.MUTED
                }
                bad > 0 -> {
                    summary = when {
                        bad == exactDomains.size -> "${exactDomains.size} 个域名 · 全部超时"
                        slow > 0 -> "${exactDomains.size} 个域名 · $bad 个超时 · $slow 个较慢"
                        else -> "${exactDomains.size} 个域名 · $bad 个超时"
                    }
                    summaryColor = Palette.RED
                }
                slow > 0 -> {
                    summary = if (slow == exactDomains.size) {
                        "${exactDomains.size} 个域名 · 全部较慢"
                    } else {
                        "${exactDomains.size} 个域名 · $slow 个较慢"
                    }
                    summaryColor = Palette.AMBER
                }
                checking > 0 -> {
                    summary = "${exactDomains.size} 个域名 · 检测中"
                    summaryColor = Palette.MUTED
                }
                tested == 0 -> {
                    summary = "${exactDomains.size} 个域名 · 待检测"
                    summaryColor = Palette.MUTED
                }
                else -> {
                    summary = "${exactDomains.size} 个域名 · 全部正常"
                    summaryColor = Palette.GREEN
                }
            }

            val statusGroup = statusGroups[id]
            val state = when {
                !enabled -> "disabled"
                statusGroup != null && statusGroup.str("state").isNotEmpty() -> statusGroup.str("state")
                bad > 0 -> "failed"
                checking > 0 -> "checking"
                tested > 0 -> "normal"
                else -> "checking"
            }
            val primary = exactDomains.firstOrNull()
                ?: rawDomains.firstOrNull()?.removePrefix("*.")
                ?: "example.com"
            val homepage = group.str("homepage").ifEmpty { "https://$primary/" }

            sites += SiteInfo(
                id = id,
                name = name,
                enabled = enabled,
                strategy = strategy,
                sni = group.str("sni"),
                homepage = homepage,
                domains = displayDomains,
                exactDomains = exactDomains,
                rawDomainCount = rawDomains.size,
                summary = summary,
                summaryColor = summaryColor,
                state = state,
                custom = id !in BUILTIN_IDS,
                experimental = group.optBoolean("experimental", false),
                echShared = group.optBoolean("echShared", false),
            )
        }

        val normal = sites.sumOf { site ->
            site.domains.count { it.stateText == "正常" || it.stateText == "直连" }
        }
        val slow = sites.sumOf { site -> site.domains.count { it.stateText == "较慢" } }
        val failed = sites.sumOf { site -> site.domains.count { it.stateText == "超时" } }
        val domainTotal = sites.sumOf { it.exactDomains.size }
        val warnings = root.optJSONArray("warnings")?.strings().orEmpty()

        return CoreData(
            running = proxy?.optBoolean("running") == true,
            paused = root.optBoolean("paused"),
            proxyError = proxy?.str("error").orEmpty(),
            proxyApplied = proxyApplied,
            listen = proxy?.str("listen").orEmpty(),
            port = config.optJSONObject("proxy")?.optInt("port", 8443) ?: 8443,
            version = root.str("version"),
            startedAt = root.str("startedAt"),
            userCaTrusted = userCaTrusted,
            caCoreInstalled = ca?.optBoolean("installed") == true,
            caSubject = ca?.str("subject").orEmpty(),
            caFingerprint = ca?.str("fingerprintSha1").orEmpty(),
            caNotAfter = ca?.str("notAfter").orEmpty(),
            caError = ca?.str("error").orEmpty(),
            siteCount = sites.size,
            enabledSites = sites.count { it.enabled },
            domainTotal = domainTotal,
            normalDomains = normal,
            slowDomains = slow,
            failedDomains = failed,
            requests = upstream?.optLong("requests", 0L) ?: 0L,
            responsesH1 = upstream?.optLong("responsesH1", 0L) ?: 0L,
            responsesH2 = upstream?.optLong("responsesH2", 0L) ?: 0L,
            connections = upstream?.optLong("connectionsOpened", 0L) ?: 0L,
            cacheEntries = cache?.let {
                it.optLong("lastGood", 0L) + it.optLong("dohAnswers", 0L) +
                    it.optLong("echConfigs", 0L) + it.optLong("fakeSni", 0L)
            } ?: 0L,
            sites = sites,
            statusJson = root,
            configJson = config,
            rawStatus = statusRaw,
            rawConfig = configRaw,
            warnings = warnings,
        )
    }

    private fun domainInfo(host: String, record: JSONObject?, enabled: Boolean): DomainInfo {
        if (!enabled) {
            return DomainInfo(host, "disabled", "未选择", Palette.MUTED, "—", null, "", "", "", "")
        }
        if (record == null) {
            return DomainInfo(host, "", "待检测", Palette.MUTED, "—", null, "", "", "", "")
        }
        val state = record.str("state")
        val latency = if (record.opt("latencyMs") == null || record.opt("latencyMs") == JSONObject.NULL) {
            null
        } else {
            record.optLong("latencyMs")
        }
        val text: String
        val color: Int
        val latencyText: String
        when (state) {
            "failed" -> {
                text = "超时"; color = Palette.RED; latencyText = "—"
            }
            "checking" -> {
                text = "检测中"; color = Palette.MUTED; latencyText = "…"
            }
            "direct" -> {
                text = "直连"; color = Palette.MUTED
                latencyText = latency?.let { "$it ms" } ?: "—"
            }
            "normal" -> {
                text = if (latency != null && latency > 150) "较慢" else "正常"
                color = if (latency != null && latency > 150) Palette.AMBER else Palette.GREEN
                latencyText = latency?.let { "$it ms" } ?: "—"
            }
            "paused", "disabled" -> {
                text = "—"; color = Palette.MUTED; latencyText = "—"
            }
            else -> {
                text = "—"; color = Palette.MUTED; latencyText = "—"
            }
        }
        return DomainInfo(
            host = host,
            state = state,
            stateText = text,
            stateColor = color,
            latencyText = latencyText,
            latencyMs = latency,
            ip = record.str("ip"),
            tls = record.str("strategy"),
            error = record.str("error"),
            detail = record.str("detail"),
        )
    }

    private fun JSONObject.str(key: String): String {
        val value = opt(key) ?: return ""
        return if (value == JSONObject.NULL) "" else value.toString()
    }

    private fun JSONArray.objects(): List<JSONObject> =
        (0 until length()).mapNotNull { optJSONObject(it) }

    private fun JSONArray.strings(): List<String> =
        (0 until length()).mapNotNull { index ->
            val value = opt(index)
            if (value == null || value == JSONObject.NULL) null else value.toString()
        }
}
