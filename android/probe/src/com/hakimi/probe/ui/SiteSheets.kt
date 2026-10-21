package com.hakimi.probe.ui

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import com.hakimi.probe.R
import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.net.URI

private fun fieldLabel(context: Context, label: String): TextView =
    context.text(label, 10.5f, Palette.MUTED, medium = true).apply {
        setPadding(context.dp(2f), 0, 0, context.dp(6f))
    }

private fun inputField(
    context: Context,
    value: String,
    hint: String,
    multiline: Boolean = false,
    numeric: Boolean = false,
): EditText = EditText(context).apply {
    setText(value)
    this.hint = hint
    setHintTextColor(Palette.MUTED)
    setTextColor(Palette.TEXT)
    textSize = 13.5f
    setPadding(context.dp(4f), context.dp(10f), context.dp(4f), context.dp(10f))
    inputType = when {
        numeric -> InputType.TYPE_CLASS_NUMBER
        multiline -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        else -> InputType.TYPE_CLASS_TEXT
    }
    if (multiline) {
        minLines = 3
        gravity = Gravity.TOP or Gravity.START
        setSingleLine(false)
    } else {
        setSingleLine(true)
    }
    setSelection(text.length)
}

private fun fieldBlock(context: Context, label: String, field: View, top: Float = 12f): LinearLayout =
    context.column().apply {
        setPadding(0, context.dp(top), 0, 0)
        addView(fieldLabel(context, label))
        addView(field, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))
    }

private fun infoRow(context: Context, label: String, value: String, onClick: (() -> Unit)? = null): View {
    val row = context.row()
    row.setPadding(context.dp(14f), context.dp(11f), context.dp(14f), context.dp(11f))
    row.addView(context.text(label, 11.5f, Palette.MUTED), LinearLayout.LayoutParams(
        context.dp(66f), LinearLayout.LayoutParams.WRAP_CONTENT
    ))
    val valueView = context.text(value, 11.5f, Palette.TEXT_2).apply {
        maxLines = 1
        ellipsize = android.text.TextUtils.TruncateAt.END
    }
    row.addView(valueView, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
    if (onClick != null) {
        val action = onClick
        row.isClickable = true
        row.background = context.ripple(Color.TRANSPARENT, 12f, 0x140EA5E9)
        row.clickOnce { action() }
    }
    return row
}

class SiteEditorSheet(
    private val context: Context,
    private val host: Host,
    private val site: SiteInfo?,
) {
    private var selectedStrategy = site?.strategy?.lowercase() ?: "auto"

    fun show() {
        val sheet = Sheet(
            context,
            if (site == null) "添加站点" else "编辑站点",
            if (site == null) "填写名称和域名" else site.name
        )
        val name = inputField(context, site?.name.orEmpty(), "例如 Pixiv")
        val domains = inputField(
            context,
            site?.exactDomains?.joinToString("\n").orEmpty(),
            "每行一个，可粘贴网址\n例如 www.example.com",
            multiline = true
        )
        val homepage = inputField(
            context,
            site?.homepage.orEmpty(),
            "https://example.com/（可选）"
        )
        val chips = ArrayList<TextView>()
        val chipRow = context.row()
        val strategyNames = listOf("自动" to "auto", "ECH" to "ech", "SNI 修改" to "sni")
        lateinit var sniBlock: LinearLayout

        fun updateChips() {
            chips.forEachIndexed { index, chip ->
                val active = strategyNames[index].second == selectedStrategy
                chip.setTextColor(if (active) Palette.DARK_TEXT else Palette.TEXT_2)
                chip.background = if (active) {
                    context.rounded(Palette.ACCENT, 12f)
                } else {
                    context.ripple(Palette.SURFACE, 12f, 0x150EA5E9, Palette.BORDER, 1f)
                }
            }
        }

        strategyNames.forEachIndexed { index, pair ->
            val chip = context.text(pair.first, 11.5f, Palette.TEXT_2, medium = true).apply {
                gravity = Gravity.CENTER
                setPadding(context.dp(10f), context.dp(10f), context.dp(10f), context.dp(10f))
                clickOnce {
                    selectedStrategy = pair.second
                    updateChips()
                    sniBlock.visibility = if (selectedStrategy == "sni") View.VISIBLE else View.GONE
                }
            }
            chips += chip
            chipRow.addView(chip, LinearLayout.LayoutParams(0, context.dp(40f), 1f).apply {
                if (index > 0) marginStart = context.dp(8f)
            })
        }
        updateChips()

        val sni = inputField(context, site?.sni.orEmpty(), "留空则不发送 SNI")
        sniBlock = fieldBlock(context, "SNI 主机（可选）", sni)
        sniBlock.visibility = if (selectedStrategy == "sni") View.VISIBLE else View.GONE

        val error = context.text("", 11f, Palette.RED).apply {
            visibility = View.GONE
            setPadding(0, context.dp(10f), 0, 0)
        }

        sheet.add(fieldBlock(context, "名称", name, 4f))
        sheet.add(fieldBlock(context, "域名", domains, 14f))
        sheet.add(fieldBlock(context, "访问地址（可选）", homepage, 14f))
        sheet.add(context.column().apply {
            setPadding(0, context.dp(14f), 0, 0)
            addView(fieldLabel(context, "策略"))
            addView(chipRow)
        })
        sheet.add(sniBlock)
        sheet.add(error)

        sheet.buttons("保存", {
            val nameText = name.text.toString().trim()
            val domainList = parseDomains(domains.text.toString())
            if (domainList.isEmpty()) {
                error.text = "至少填写一个有效域名"
                error.visibility = View.VISIBLE
            } else {
                val strategy = selectedStrategy
                val sniText = sni.text.toString().trim()
                var homepageText = homepage.text.toString().trim()
                if (homepageText.isNotEmpty() &&
                    !homepageText.startsWith("http://") &&
                    !homepageText.startsWith("https://")
                ) {
                    homepageText = "https://$homepageText"
                }
                if (homepageText.isEmpty()) {
                    homepageText = "https://${domainList.first().removePrefix("*.")}/"
                }
                val group = JSONObject().apply {
                    put("id", site?.id ?: uniqueId(domainList.first()))
                    put("name", nameText.ifEmpty { domainList.first().removePrefix("*.") })
                    put("domains", JSONArray(domainList))
                    put("strategy", strategy)
                    put("enabled", site?.enabled ?: true)
                    put(
                        "sni",
                        if (strategy == "sni" && sniText.isNotEmpty()) sniText else JSONObject.NULL
                    )
                    put("experimental", site?.experimental ?: false)
                    put("homepage", homepageText)
                    put("echShared", site?.echShared ?: false)
                }
                host.saveGroup(group, site == null) { ok, message ->
                    if (ok) {
                        sheet.dismiss()
                    } else {
                        error.text = message ?: "保存失败"
                        error.visibility = View.VISIBLE
                    }
                }
            }
        }, "取消", { sheet.dismiss() })

        if (site != null && site.custom) {
            sheet.textButton("删除站点", Palette.RED) {
                sheet.dismiss()
                Sheets.confirm(
                    context,
                    "删除 ${site.name}",
                    "会从加速范围中移除该站点，已缓存的路由不会删除。",
                    "删除",
                    danger = true
                ) {
                    host.deleteGroup(site.id) { ok, message ->
                        if (!ok) host.showSnack(message ?: "删除失败", error = true)
                    }
                }
            }
        }
        sheet.show()
    }

    private fun parseDomains(raw: String): List<String> {
        val result = LinkedHashSet<String>()
        raw.lineSequence().forEach { line ->
            var value = line.trim()
            if (value.isEmpty() || value.startsWith("#")) return@forEach
            value = value.substringBefore('#').trim()
            if (value.contains("://")) {
                val host = runCatching { URI(value).host }.getOrNull()
                if (host != null) value = host
            } else {
                value = value.substringBefore('/').substringBefore('?').substringBefore('#')
                if (value.count { it == ':' } == 1) value = value.substringBefore(':')
            }
            var wildcard = false
            if (value.startsWith("*.")) {
                wildcard = true
                value = value.removePrefix("*.")
            }
            value = value.trim('.').lowercase()
            val ascii = runCatching { IDN.toASCII(value) }.getOrDefault(value)
            if (ascii.contains('.') && !ascii.startsWith('.') && !ascii.endsWith('.')) {
                result += if (wildcard) "*.$ascii" else ascii
            }
        }
        return result.toList()
    }

    private fun uniqueId(domain: String): String {
        val base = domain.removePrefix("*.")
            .lowercase()
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
            .take(28)
            .ifEmpty { "site" }
        val used = host.core.sites.map { it.id }.toHashSet()
        if (base !in used) return base
        var index = 2
        while ("$base-$index" in used) index++
        return "$base-$index"
    }
}

class SiteDetailSheet(
    private val context: Context,
    private val host: Host,
    private val site: SiteInfo,
) {
    fun show() {
        val sheet = Sheet(context, site.name, site.summary)
        val header = context.row()
        header.addView(siteTile(context, site, 54f))
        val texts = context.column()
        texts.gravity = Gravity.CENTER_VERTICAL
        texts.setPadding(context.dp(12f), 0, context.dp(8f), 0)
        val meta = context.row()
        meta.addView(context.pill(context.strategyLabel(site.strategy), Palette.TEXT_2, Palette.SURFACE_2, 9f))
        meta.addView(View(context), LinearLayout.LayoutParams(context.dp(6f), 1))
        meta.addView(context.pill("${site.exactDomains.size} 个域名", Palette.TEXT_2, Palette.SURFACE_2, 9f))
        if (site.experimental) {
            meta.addView(View(context), LinearLayout.LayoutParams(context.dp(6f), 1))
            meta.addView(context.pill("实验性", Palette.AMBER, 0x1FFFC66D, 9f))
        }
        texts.addView(meta)
        header.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        val toggle = android.widget.Switch(context).apply {
            setShowText(false)
            isChecked = site.enabled
            setOnCheckedChangeListener { _, checked ->
                host.setGroupEnabled(site, checked)
                host.showSnack(if (checked) "已启用 ${site.name}" else "已停用 ${site.name}")
            }
        }
        header.addView(toggle)
        sheet.add(header, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(10f) })

        val actions = context.row()
        actions.setPadding(0, context.dp(16f), 0, 0)
        val visit = context.nativePrimaryButton("访问主页") { host.openUrl(site.homepage) }
        actions.addView(visit, LinearLayout.LayoutParams(0, context.dp(48f), 1f))
        actions.addView(View(context), LinearLayout.LayoutParams(context.dp(8f), 1))
        val probe = context.nativeTextButton("立即检测") {
            site.exactDomains.firstOrNull()?.let { domain ->
                host.runDiagnose(domain) { outcome ->
                    DiagnoseResultSheet(context, host, outcome).show()
                }
            } ?: host.showSnack("没有可探测的精确域名", error = true)
        }
        actions.addView(probe, LinearLayout.LayoutParams(0, context.dp(48f), 1f))
        sheet.add(actions)

        if (site.domains.isNotEmpty()) {
            val title = context.text("域名与线路", 10.5f, Palette.MUTED, medium = true)
            title.setPadding(0, context.dp(18f), 0, context.dp(8f))
            sheet.add(title)
            val card = context.card(radius = 20f, padding = 0f)
            site.domains.forEachIndexed { index, domain ->
                if (index > 0) {
                    card.addView(context.divider(14f), LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        context.dp(1f)
                    ))
                }
                card.addView(buildDomainRow(domain))
            }
            sheet.add(card)
        } else {
            sheet.add(context.text("仅包含通配符域名，没有可单独探测的主机", 11.5f, Palette.MUTED).apply {
                setPadding(0, context.dp(18f), 0, 0)
            })
        }

        val info = context.card(radius = 20f, padding = 0f)
        info.addView(infoRow(context, "访问地址", site.homepage) { host.openUrl(site.homepage) })
        if (site.sni.isNotEmpty()) {
            info.addView(context.divider(14f), LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                context.dp(1f)
            ))
            info.addView(infoRow(context, "SNI", site.sni))
        }
        info.addView(context.divider(14f), LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(1f)
        ))
        info.addView(infoRow(context, "站点 ID", site.id))
        sheet.add(info, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(14f) })

        val edit = context.nativeTextButton("编辑站点") {
            sheet.dismiss()
            host.openEditor(site)
        }
        sheet.add(edit, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(48f)
        ).apply { topMargin = context.dp(6f) })

        sheet.textButton("关闭") { sheet.dismiss() }
        sheet.show()
    }

    private fun buildDomainRow(domain: DomainInfo): View {
        val row = context.row()
        row.setPadding(context.dp(14f), context.dp(11f), context.dp(14f), context.dp(11f))
        val left = context.column()
        left.addView(context.monospace(domain.host, 11.5f, Palette.TEXT))
        val detail = when {
            domain.error.isNotEmpty() -> domain.error
            domain.ip.isNotEmpty() -> "${domain.ip} · ${domain.tls.ifEmpty { "tls" }}"
            domain.detail.isNotEmpty() -> domain.detail
            else -> "等待首次连接"
        }
        left.addView(context.text(detail, 9.5f, Palette.MUTED).apply {
            setPadding(0, context.dp(3f), 0, 0)
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        })
        row.addView(left, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

        val right = context.column()
        right.gravity = Gravity.END
        val state = context.text(domain.stateText, 11.5f, domain.stateColor, medium = true)
        state.gravity = Gravity.END
        right.addView(state)
        val latency = context.monospace(domain.latencyText, 9.5f, Palette.MUTED)
        latency.gravity = Gravity.END
        latency.setPadding(0, context.dp(3f), 0, 0)
        right.addView(latency)
        row.addView(right, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { marginStart = context.dp(10f) })

        row.isClickable = true
        row.background = context.ripple(Color.TRANSPARENT, 14f, 0x140EA5E9)
        row.clickOnce {
            host.runDiagnose(domain.host) { outcome ->
                DiagnoseResultSheet(context, host, outcome).show()
            }
        }
        return row
    }

    private fun siteTile(context: Context, site: SiteInfo, size: Float): View {
        val tile = FrameLayout(context)
        tile.layoutParams = LinearLayout.LayoutParams(context.dp(size), context.dp(size))
        val iconRes = siteIconRes(site.id)
        if (iconRes != 0) {
            tile.background = context.rounded(0xFFF4FAFD.toInt(), 16f)
            val image = ImageView(context).apply {
                setImageResource(iconRes)
                scaleType = ImageView.ScaleType.FIT_CENTER
            }
            tile.addView(image, FrameLayout.LayoutParams(context.dp(32f), context.dp(32f), Gravity.CENTER))
        } else {
            tile.background = context.rounded(tileColor(site.id), 16f)
            val initial = context.text(site.name.take(1).uppercase(), 20f, Color.WHITE, medium = true)
            initial.gravity = Gravity.CENTER
            tile.addView(initial, FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            ))
        }
        return tile
    }
}

class CaSetupSheet(
    private val context: Context,
    private val host: Host,
) {
    fun show() {
        val data = host.core
        val trusted = data.userCaTrusted
        val sheet = Sheet(
            context,
            if (trusted) "证书已安装" else "安装证书",
            if (trusted) null else "按下面三步操作"
        )

        val status = context.card(
            radius = 12f,
            fill = if (trusted) 0xFFEAF7F2.toInt() else 0xFFFFF8EC.toInt(),
            padding = 14f,
            stroke = if (trusted) 0x33178F79 else 0x33B07A1E
        )
        status.addView(context.text(
            if (trusted) "已安装并受信任" else "尚未安装",
            13f,
            if (trusted) Palette.GREEN else Palette.AMBER,
            medium = true
        ))
        sheet.add(status, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(12f) })

        step(sheet, 1, "导出证书", "保存到下载目录")
        step(sheet, 2, "安装证书", "设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书")
        step(sheet, 3, "回来检查", "点下方「我已完成」")

        if (!trusted) {
            sheet.primary("导出证书") {
                host.exportCa()
            }
            sheet.secondary("打开系统设置") {
                openSecuritySettings()
            }
            sheet.textButton("我已完成，重新检查") {
                host.recheckCa()
                sheet.dismiss()
            }
        } else {
            sheet.add(context.monospace(
                "Subject  ${data.caSubject.ifEmpty { "CN=hakimi Local CA" }}\n" +
                    "SHA-1    ${data.caFingerprint.ifEmpty { "—" }}\n" +
                    "到期     ${data.caNotAfter.ifEmpty { "—" }}",
                10f,
                Palette.TEXT_2
            ).apply {
                background = context.rounded(0xFFF7FCFE.toInt(), 14f, Palette.BORDER, 1f)
                setPadding(context.dp(14f), context.dp(12f), context.dp(14f), context.dp(12f))
            }, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = context.dp(14f) })
            sheet.primary("导出证书备份") { host.exportCa() }
        }
        sheet.show()
    }

    private fun step(sheet: Sheet, number: Int, title: String, subtitle: String) {
        val row = context.row()
        row.setPadding(0, context.dp(14f), 0, 0)
        row.addView(context.text("$number", 11f, Palette.ACCENT, medium = true).apply {
            gravity = Gravity.CENTER
            setPadding(0, context.dp(2f), 0, 0)
        }, LinearLayout.LayoutParams(context.dp(22f), LinearLayout.LayoutParams.WRAP_CONTENT))
        val texts = context.column()
        texts.setPadding(context.dp(11f), 0, 0, 0)
        texts.addView(context.text(title, 12.5f, Palette.TEXT, medium = true))
        texts.addView(context.text(subtitle, 10.5f, Palette.MUTED).apply {
            setPadding(0, context.dp(3f), 0, 0)
        })
        row.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        sheet.add(row)
    }

    private fun openSecuritySettings() {
        val intent = Intent(Settings.ACTION_SECURITY_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            context.startActivity(intent)
        } catch (_: Throwable) {
            try {
                context.startActivity(
                    Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
            } catch (_: Throwable) {
                host.showSnack("无法打开系统设置，请手动进入安全设置", error = true)
            }
        }
    }
}

class DiagnoseResultSheet(
    private val context: Context,
    private val host: Host,
    private val outcome: DiagnoseOutcome,
) {
    fun show() {
        val sheet = Sheet(context, "诊断 · ${outcome.domain}", outcome.state)
        val stateColor = when (outcome.state) {
            "normal" -> Palette.GREEN
            "failed" -> Palette.RED
            "direct" -> Palette.TEXT_2
            else -> Palette.ACCENT
        }
        val summary = context.card(radius = 20f, padding = 14f)
        val grid = context.row()
        metric(grid, "状态", outcome.state.ifEmpty { "—" }, stateColor)
        metric(grid, "延迟", outcome.latencyMs?.let { "$it ms" } ?: "—", Palette.TEXT)
        metric(grid, "IP", outcome.ip.ifEmpty { "—" }, Palette.TEXT_2)
        metric(grid, "TLS", outcome.tls.ifEmpty { "—" }, Palette.ACCENT)
        summary.addView(grid)
        if (outcome.error.isNotEmpty()) {
            summary.addView(context.text(outcome.error, 10.5f, Palette.RED).apply {
                setPadding(0, context.dp(10f), 0, 0)
            })
        }
        sheet.add(summary, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { topMargin = context.dp(12f) })

        val obj = runCatching { JSONObject(outcome.raw) }.getOrNull()
        val attempts = obj?.optJSONArray("attempts")
        if (attempts != null && attempts.length() > 0) {
            val title = context.text("尝试记录", 10.5f, Palette.MUTED, medium = true)
            title.setPadding(0, context.dp(16f), 0, context.dp(8f))
            sheet.add(title)
            val card = context.card(radius = 20f, padding = 0f)
            for (index in 0 until attempts.length()) {
                if (index > 0) {
                    card.addView(context.divider(14f), LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        context.dp(1f)
                    ))
                }
                card.addView(attemptRow(attempts.optJSONObject(index) ?: JSONObject()))
            }
            sheet.add(card)
        }

        val row = context.row()
        row.setPadding(0, context.dp(16f), 0, 0)
        val copy = context.nativeTextButton("复制原始 JSON") { host.copy(pretty(outcome.raw), "诊断 JSON") }
        row.addView(copy, LinearLayout.LayoutParams(0, context.dp(48f), 1f))
        row.addView(View(context), LinearLayout.LayoutParams(context.dp(8f), 1))
        val close = context.nativePrimaryButton("关闭") { sheet.dismiss() }
        row.addView(close, LinearLayout.LayoutParams(0, context.dp(48f), 1f))
        sheet.add(row)
        sheet.show()
    }

    private fun metric(row: LinearLayout, label: String, value: String, color: Int) {
        val cell = context.column()
        cell.gravity = Gravity.CENTER
        val valueView = context.text(value, 12f, color, medium = true).apply {
            gravity = Gravity.CENTER
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
        cell.addView(valueView)
        cell.addView(context.text(label, 9f, Palette.MUTED).apply { gravity = Gravity.CENTER })
        row.addView(cell, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
    }

    private fun attemptRow(attempt: JSONObject): View {
        val row = context.row()
        row.setPadding(context.dp(14f), context.dp(10f), context.dp(14f), context.dp(10f))
        val left = context.column()
        val tls = attempt.optString("strategy").ifEmpty { "?" }
        left.addView(context.text(tls.uppercase(), 10.5f, Palette.ACCENT, medium = true))
        left.addView(context.monospace(
            attempt.optString("ip").ifEmpty { "—" } + " · " + attempt.optString("source").ifEmpty { "?" },
            9.5f,
            Palette.MUTED
        ))
        row.addView(left, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        val error = attempt.optString("error")
        val latency = if (attempt.opt("latencyMs") == null || attempt.opt("latencyMs") == JSONObject.NULL) {
            null
        } else {
            attempt.optLong("latencyMs")
        }
        val right = context.text(
            error.ifEmpty { latency?.let { "$it ms" } ?: "ok" },
            10.5f,
            if (error.isEmpty()) Palette.GREEN else Palette.RED,
            medium = true
        )
        right.gravity = Gravity.END
        row.addView(right)
        return row
    }

    private fun pretty(raw: String): String =
        runCatching { JSONObject(raw).toString(2) }.getOrDefault(raw)
}
