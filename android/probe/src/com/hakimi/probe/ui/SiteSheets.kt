package com.hakimi.probe.ui

import android.content.Context
import android.graphics.Color
import android.graphics.Rect
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupWindow
import android.widget.TextView
import com.hakimi.probe.CaStore
import com.hakimi.probe.CaTrust
import com.hakimi.probe.R
import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN
import java.net.URI
import java.util.Locale

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
    setPadding(context.dp(12f), context.dp(10f), context.dp(12f), context.dp(10f))
    background = context.rounded(Palette.SURFACE_HI, 10f, Palette.BORDER, 1f)
    minHeight = context.dp(44f)
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
        gravity = Gravity.CENTER_VERTICAL or Gravity.START
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

private val ROW_ROUTE_PRESETS = listOf("继承默认", "直连", "ECH", "SNI 伪装", "自定义")

private fun EditText.watchText(action: (String) -> Unit) {
    addTextChangedListener(object : TextWatcher {
        override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
        override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
        override fun afterTextChanged(s: Editable?) {
            action(s?.toString().orEmpty())
        }
    })
}

private fun subFieldLabel(context: Context, label: String): TextView =
    context.text(label, 10.5f, Palette.MUTED, medium = true).apply {
        setPadding(context.dp(2f), context.dp(8f), 0, context.dp(4f))
    }

class SiteEditorSheet(
    private val context: Context,
    private val host: Host,
    private val site: SiteInfo?,
) {
    private data class RowDraft(
        var pattern: String = "",
        var preset: Int = 0,
        var sni: String = "",
        var custom: String = "",
    )

    private var selectedPreset = routePresetIndex(site?.defaultRoute ?: "auto")
    private var routePopup: PopupWindow? = null

    fun show() {
        val sheet = Sheet(
            context,
            if (site == null) "添加站点" else "编辑站点",
            site?.name
        )
        val name = inputField(context, site?.name.orEmpty(), "例如 Pixiv")
        val homepage = inputField(
            context,
            site?.homepage.orEmpty(),
            "https://example.com"
        )

        val drafts = site?.domainRules
            ?.map(::draftFromRule)
            ?.toMutableList()
            ?: mutableListOf(RowDraft())
        val rowsContainer = context.column()

        fun renderRows() {
            rowsContainer.removeAllViews()
            drafts.forEachIndexed { index, draft ->
                val block = context.column()
                if (index > 0) block.setPadding(0, context.dp(10f), 0, 0)

                val line = context.row()
                val pattern = inputField(context, draft.pattern, "例如 www.pixiv.net")
                pattern.watchText { draft.pattern = it }
                line.addView(pattern, LinearLayout.LayoutParams(
                    0,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    1f
                ))

                val route = context.text(
                    "${ROW_ROUTE_PRESETS[draft.preset]}  ▾",
                    12f,
                    Palette.TEXT,
                    medium = true
                ).apply {
                    gravity = Gravity.CENTER
                    setPadding(context.dp(6f), context.dp(10f), context.dp(6f), context.dp(10f))
                    background = context.ripple(
                        Palette.SURFACE,
                        10f,
                        0x150E9FD8,
                        Palette.BORDER,
                        1f
                    )
                    isClickable = true
                    isFocusable = true
                    contentDescription = "线路：${ROW_ROUTE_PRESETS[draft.preset]}"
                }
                route.clickOnce {
                    openRouteMenu(route, draft.preset) { preset ->
                        draft.preset = preset
                        renderRows()
                    }
                }
                line.addView(route, LinearLayout.LayoutParams(
                    context.dp(92f),
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { marginStart = context.dp(6f) })

                if (drafts.size > 1) {
                    val remove = context.text("移除", 12f, Palette.TEXT_2, medium = true).apply {
                        gravity = Gravity.CENTER
                        setPadding(context.dp(6f), context.dp(10f), context.dp(6f), context.dp(10f))
                        background = context.selectableBorderless()
                        isClickable = true
                        isFocusable = true
                    }
                    remove.clickOnce {
                        drafts.removeAt(index)
                        renderRows()
                    }
                    line.addView(remove, LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { marginStart = context.dp(2f) })
                }
                block.addView(line)

                if (draft.preset == 3) {
                    block.addView(subFieldLabel(context, "伪装主机"))
                    val sni = inputField(
                        context,
                        draft.sni,
                        "多个用逗号分隔"
                    )
                    sni.watchText { draft.sni = it }
                    block.addView(sni, LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ))
                }
                if (draft.preset == 4) {
                    block.addView(subFieldLabel(context, "自定义线路"))
                    val custom = inputField(context, draft.custom, "例如 ech+direct")
                    custom.watchText { draft.custom = it }
                    block.addView(custom, LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ))
                }

                rowsContainer.addView(block)
            }
        }

        renderRows()

        val addDomain = context.text("+ 添加域名", 12.5f, Palette.ACCENT, medium = true).apply {
            setPadding(context.dp(2f), context.dp(10f), context.dp(8f), context.dp(2f))
            background = context.selectableBorderless()
            isClickable = true
            isFocusable = true
        }
        addDomain.clickOnce {
            drafts.add(RowDraft())
            renderRows()
        }

        val domainSection = context.column()
        domainSection.setPadding(0, context.dp(14f), 0, 0)
        domainSection.addView(fieldLabel(context, "域名"))
        domainSection.addView(rowsContainer)
        domainSection.addView(addDomain)

        val chips = ArrayList<TextView>()
        val chipRow = context.row()
        val presetNames = listOf("自动", "直连", "ECH", "SNI 伪装", "自定义")
        val custom = inputField(
            context,
            if (selectedPreset == 4) site?.defaultRoute.orEmpty() else "",
            "例如 ech+direct"
        )
        val customBlock = fieldBlock(context, "自定义线路", custom)

        fun updateChips() {
            chips.forEachIndexed { index, chip ->
                val active = index == selectedPreset
                chip.setTextColor(if (active) Palette.DARK_TEXT else Palette.TEXT_2)
                chip.background = if (active) {
                    context.rounded(Palette.ACCENT, 12f)
                } else {
                    context.ripple(Palette.SURFACE, 12f, 0x150EA5E9, Palette.BORDER, 1f)
                }
            }
            customBlock.visibility = if (selectedPreset == 4) View.VISIBLE else View.GONE
        }

        presetNames.forEachIndexed { index, label ->
            val chip = context.text(label, 11f, Palette.TEXT_2, medium = true).apply {
                gravity = Gravity.CENTER
                setPadding(context.dp(6f), context.dp(10f), context.dp(6f), context.dp(10f))
                clickOnce {
                    selectedPreset = index
                    updateChips()
                }
            }
            chips += chip
            chipRow.addView(chip, LinearLayout.LayoutParams(0, context.dp(40f), 1f).apply {
                if (index > 0) marginStart = context.dp(6f)
            })
        }
        updateChips()

        val error = context.text("", 11f, Palette.RED).apply {
            visibility = View.GONE
            setPadding(0, context.dp(10f), 0, 0)
        }

        sheet.add(fieldBlock(context, "名称", name, 4f))
        sheet.add(fieldBlock(context, "主页（可选）", homepage, 12f))
        sheet.add(domainSection)
        sheet.add(context.column().apply {
            setPadding(0, context.dp(16f), 0, 0)
            addView(fieldLabel(context, "默认线路"))
            addView(chipRow)
        })
        sheet.add(customBlock)
        sheet.add(error)

        sheet.buttons("保存", {
            val nameText = name.text.toString().trim()
            runCatching {
                val rules = buildRules(drafts)
                val defaultSpec = if (selectedPreset == 4) {
                    val text = custom.text.toString().trim()
                    if (text.isEmpty()) {
                        throw IllegalArgumentException("请填写自定义默认线路")
                    }
                    text
                } else {
                    routePresetSpec(selectedPreset)
                }
                val defaultRoute = parseRouteSpec(defaultSpec)
                var homepageText = homepage.text.toString().trim()
                if (homepageText.isNotEmpty() &&
                    !homepageText.startsWith("http://") &&
                    !homepageText.startsWith("https://")
                ) {
                    homepageText = "https://$homepageText"
                }
                val primary = rules.first().pattern.removePrefix("*.")
                if (homepageText.isEmpty()) {
                    homepageText = "https://$primary/"
                }
                JSONObject().apply {
                    put("id", site?.id ?: uniqueId(rules.first().pattern))
                    put("name", nameText.ifEmpty { primary })
                    put("domains", domainRulesJson(rules))
                    put("defaultRoute", defaultRoute)
                    put("enabled", site?.enabled ?: true)
                    put("homepage", homepageText)
                }
            }.onSuccess { group ->
                host.saveGroup(group, site == null) { ok, message ->
                    if (ok) {
                        sheet.dismiss()
                    } else {
                        error.text = message ?: "保存失败"
                        error.visibility = View.VISIBLE
                    }
                }
            }.onFailure { throwable ->
                error.text = throwable.message ?: "保存失败"
                error.visibility = View.VISIBLE
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
        sheet.setOnDismissListener { routePopup?.dismiss() }
        sheet.show()
    }

    private fun openRouteMenu(anchor: View, current: Int, onSelected: (Int) -> Unit) {
        routePopup?.dismiss()
        val width = context.dp(144f)
        val itemHeight = context.dp(42f)
        val itemGap = context.dp(2f)
        val popupPadding = context.dp(6f)
        val height = ROW_ROUTE_PRESETS.size * itemHeight +
            (ROW_ROUTE_PRESETS.size - 1) * itemGap + popupPadding * 2
        val content = context.column().apply {
            background = context.rounded(Palette.SURFACE, 14f, Palette.BORDER, 1f)
            setPadding(popupPadding, popupPadding, popupPadding, popupPadding)
            elevation = context.dp(8f).toFloat()
        }
        ROW_ROUTE_PRESETS.forEachIndexed { index, label ->
            val active = index == current
            val item = context.row().apply {
                background = if (active) {
                    context.rounded(Palette.ACCENT_SOFT, 9f)
                } else {
                    context.ripple(Color.TRANSPARENT, 9f, 0x160E9FD8)
                }
                setPadding(context.dp(12f), 0, context.dp(12f), 0)
                isClickable = true
                isFocusable = true
            }
            item.addView(
                context.text(
                    label,
                    13f,
                    if (active) Palette.ACCENT_DIM else Palette.TEXT,
                    medium = active
                ).apply { gravity = Gravity.CENTER_VERTICAL },
                LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, 1f)
            )
            if (active) {
                item.addView(
                    context.text("✓", 13f, Palette.ACCENT, medium = true).apply {
                        gravity = Gravity.CENTER
                    },
                    LinearLayout.LayoutParams(context.dp(20f), LinearLayout.LayoutParams.MATCH_PARENT)
                )
            }
            item.clickOnce {
                routePopup?.dismiss()
                onSelected(index)
            }
            content.addView(item, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                itemHeight
            ).apply { if (index > 0) topMargin = itemGap })
        }
        val popup = PopupWindow(content, width, height, true).apply {
            setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            isOutsideTouchable = true
            inputMethodMode = PopupWindow.INPUT_METHOD_NOT_NEEDED
            elevation = context.dp(10f).toFloat()
            setOnDismissListener {
                if (routePopup === this) routePopup = null
            }
        }
        routePopup = popup

        // Show above the trigger when there is no room below, so the last
        // options stay reachable inside the sheet.
        val location = IntArray(2)
        anchor.getLocationOnScreen(location)
        val frame = Rect()
        anchor.getWindowVisibleDisplayFrame(frame)
        val gap = context.dp(6f)
        val margin = context.dp(8f)
        var y = location[1] + anchor.height + gap
        if (y + height > frame.bottom - margin) {
            y = (location[1] - height - gap).coerceAtLeast(frame.top + margin)
        }
        val maxX = (frame.right - width - margin).coerceAtLeast(frame.left + margin)
        val x = (location[0] + anchor.width - width).coerceIn(frame.left + margin, maxX)
        popup.showAtLocation(anchor, Gravity.TOP or Gravity.START, x, y)
    }

    private fun draftFromRule(rule: DomainRuleInfo): RowDraft {
        val preset = rowPreset(rule.route)
        return RowDraft(
            pattern = rule.pattern,
            preset = preset,
            sni = if (preset == 3) sniHosts(rule.route).joinToString(", ") else "",
            custom = if (preset == 4) rule.route else "",
        )
    }

    /** The per-domain preset index; unlike [routePresetIndex], an SNI spec with hosts is still SNI. */
    private fun rowPreset(spec: String): Int = when {
        spec.isEmpty() -> 0
        spec == "direct" -> 1
        spec == "ech+direct" -> 2
        isSniSpec(spec) -> 3
        else -> 4
    }

    private fun isSniSpec(spec: String): Boolean {
        val parts = spec.split('+').map { it.trim() }.filter { it.isNotEmpty() }
        if (parts.isEmpty() || parts.size > 2) return false
        val head = parts.first()
        if (head != "sni" && !head.startsWith("sni:")) return false
        return parts.drop(1).all { it == "direct" }
    }

    private fun sniHosts(spec: String): List<String> =
        spec.split('+')
            .map { it.trim() }
            .firstOrNull { it.startsWith("sni:") }
            ?.substringAfter(':')
            ?.split(',')
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            .orEmpty()

    private fun rowRouteSpec(draft: RowDraft): String = when (draft.preset) {
        1 -> "direct"
        2 -> "ech+direct"
        3 -> {
            val hosts = draft.sni
                .split(',', '，', ';', '；', ' ', '\n', '\t')
                .map { it.trim().lowercase() }
                .filter { it.isNotEmpty() }
                .distinct()
            if (hosts.isEmpty()) "sni+direct" else "sni:${hosts.joinToString(",")}+direct"
        }
        4 -> {
            val text = draft.custom.trim()
            if (text.isEmpty()) throw IllegalArgumentException("请填写自定义线路")
            parseRouteSpec(text)
            text
        }
        else -> ""
    }

    private fun buildRules(drafts: List<RowDraft>): List<DomainRuleInfo> {
        val seen = HashSet<String>()
        val rules = ArrayList<DomainRuleInfo>()
        drafts.forEach { draft ->
            val normalized = normalizePattern(draft.pattern)
            if (normalized == null) {
                if (draft.pattern.isNotBlank()) {
                    throw IllegalArgumentException("域名写法无效：${draft.pattern.trim()}")
                }
            } else {
                if (!seen.add(normalized)) {
                    throw IllegalArgumentException("域名重复：$normalized")
                }
                rules += DomainRuleInfo(normalized, rowRouteSpec(draft))
            }
        }
        if (rules.isEmpty()) {
            throw IllegalArgumentException("至少填写一个有效域名")
        }
        if (rules.none { !it.pattern.startsWith("*.") }) {
            throw IllegalArgumentException("至少需要一个精确域名（不能只有 *. 通配）")
        }
        return rules
    }

    private fun normalizePattern(raw: String): String? {
        var value = raw.trim()
        if (value.isEmpty()) return null
        if (value.contains("://")) {
            value = runCatching { URI(value).host }.getOrNull() ?: return null
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
        if (!ascii.contains('.') || ascii.startsWith('.') || ascii.endsWith('.')) return null
        return if (wildcard) "*.$ascii" else ascii
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
        meta.addView(context.pill("${site.exactDomains.size} 个域名", Palette.TEXT_2, Palette.SURFACE_2, 9f))
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
        info.addView(context.divider(14f), LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            context.dp(1f)
        ))
        info.addView(infoRow(
            context,
            "默认线路",
            if (site.routeDetail.isEmpty()) {
                routeLabel(site.defaultRoute)
            } else {
                "${routeLabel(site.defaultRoute)} · ${site.routeDetail}"
            }
        ))
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
        val route = site.domainRules.firstOrNull { it.pattern == domain.host }?.route.orEmpty()
        left.addView(context.text(
            if (route.isEmpty()) detail else "$route · $detail",
            9.5f,
            Palette.MUTED
        ).apply {
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

private val CA_AMBER_FILL = 0xFFFFF8EC.toInt()
private val CA_AMBER_STROKE = 0x33B07A1E
private val CA_GREEN_FILL = 0xFFEAF7F2.toInt()
private val CA_GREEN_STROKE = 0x33178F79
private val CA_BLUE_FILL = 0xFFEAF6FC.toInt()
private val CA_BLUE_STROKE = 0x330E9FD8

class CaSetupSheet(
    private val context: Context,
    private val host: Host,
) {
    private enum class CaState { CHECKING, NO_LOCK, NOT_INSTALLED, SAVED, TRUSTED }

    private var sheet: Sheet? = null
    private var signature = ""

    fun show() {
        signature = currentSignature()
        sheet = when (currentState()) {
            CaState.CHECKING -> buildChecking()
            CaState.NO_LOCK -> buildNoLock()
            CaState.NOT_INSTALLED -> buildNotInstalled()
            CaState.SAVED -> buildSaved()
            CaState.TRUSTED -> buildTrusted()
        }.also { it.show() }
    }

    /** Rebuilds the sheet only when the trust/export/lock state actually changed. */
    fun refresh() {
        val current = sheet ?: return
        if (!current.isShowing || currentSignature() == signature) return
        current.dismiss()
        sheet = null
        show()
    }

    fun isShowing(): Boolean = sheet?.isShowing == true

    fun dismiss() {
        sheet?.dismiss()
        sheet = null
    }

    private fun currentState(): CaState = when {
        !host.caReady -> CaState.CHECKING
        host.core.userCaTrusted -> CaState.TRUSTED
        !host.caLockReady -> CaState.NO_LOCK
        host.caExportName.isNotEmpty() -> CaState.SAVED
        else -> CaState.NOT_INSTALLED
    }

    private fun currentSignature(): String =
        "${host.caReady}|${host.core.userCaTrusted}|${host.caLockReady}|" +
            "${host.caExportName}|${host.core.caFingerprintSha256}"

    private fun buildChecking(): Sheet {
        val sheet = Sheet(context, "证书", "读取本地 CA 与系统信任状态")
        addStatus(
            sheet,
            "正在检查证书…",
            null,
            Palette.ACCENT,
            CA_BLUE_FILL,
            CA_BLUE_STROKE,
        )
        return sheet
    }

    private fun buildNoLock(): Sheet {
        val saved = host.caExportName
        val detail = if (saved.isEmpty()) {
            "设置锁屏后再回来安装，否则系统可能不显示安装入口"
        } else {
            "已保存到 $saved；设置锁屏后再回来安装"
        }
        val sheet = Sheet(context, "先设置锁屏", "Android 11 及以上安装 CA 证书需要锁屏")
        addStatus(
            sheet,
            "需要锁屏密码",
            detail,
            Palette.AMBER,
            CA_AMBER_FILL,
            CA_AMBER_STROKE,
        )
        step(sheet, 1, "设置锁屏", "设置 → 安全（或「安全和隐私」）→ 屏幕锁定（密码、图案或 PIN）")
        step(sheet, 2, "回来继续", "设置完成后回到这里，会重新检查")
        sheet.primary("去设置锁屏") { host.openCaLockSettings() }
        sheet.secondary("仅保存证书") { host.saveCaForInstall() }
        return sheet
    }

    private fun buildNotInstalled(): Sheet {
        val sheet = Sheet(context, "安装证书", "保存到下载，然后在系统设置中安装")
        addStatus(
            sheet,
            "尚未安装",
            "浏览器需要信任这个 CA 才能通过 hakimi 加速",
            Palette.AMBER,
            CA_AMBER_FILL,
            CA_AMBER_STROKE,
        )
        step(sheet, 1, "保存证书", "点下方按钮保存；Android 10+ 会直接存到下载")
        step(
            sheet,
            2,
            "系统设置安装",
            installPath(),
            "选「CA 证书」→ 仍然安装 → 选择「${installFileName()}」",
        )
        step(sheet, 3, "返回自动检查", "安装完成回到 hakimi；若状态没有变化，点「重新检查」")
        addHint(sheet, "找不到入口？在设置顶部搜索「安装证书」。文件选择器若停在「最近」，切到「下载」。")
        sheet.primary("保存并去安装") { host.exportCaForInstall() }
        sheet.secondary("仅保存证书") { host.saveCaForInstall() }
        sheet.textButton("重新检查") { host.recheckCa() }
        return sheet
    }

    private fun buildSaved(): Sheet {
        val name = host.caExportName
        val sheet = Sheet(context, "安装证书", "证书已保存，继续在系统设置中安装")
        addStatus(
            sheet,
            "已保存，等待安装",
            "文件：$name",
            Palette.AMBER,
            CA_AMBER_FILL,
            CA_AMBER_STROKE,
        )
        step(
            sheet,
            1,
            "系统设置安装",
            installPath(),
            "选「CA 证书」→ 仍然安装 → 选择「$name」",
        )
        step(sheet, 2, "返回自动检查", "安装完成回到 hakimi；若状态没有变化，点「重新检查」")
        addHint(sheet, "找不到入口？在设置顶部搜索「安装证书」。文件选择器若停在「最近」，切到「下载」。")
        sheet.primary("打开系统设置") { host.openCaInstallSettings() }
        sheet.secondary("重新检查") { host.recheckCa() }
        sheet.textButton("重新保存") { host.saveCaForInstall() }
        return sheet
    }

    private fun buildTrusted(): Sheet {
        val data = host.core
        val sha = if (data.caFingerprintSha256.isEmpty()) {
            "—"
        } else {
            CaTrust.displaySha256(data.caFingerprintSha256)
        }
        val sheet = Sheet(context, "证书已安装")
        addStatus(
            sheet,
            "已安装并受信任",
            "升级 App 不需要重新安装；换机或重装系统时用备份恢复",
            Palette.GREEN,
            CA_GREEN_FILL,
            CA_GREEN_STROKE,
        )
        sheet.add(context.monospace(
            "Subject  ${data.caSubject.ifEmpty { "—" }}\n" +
                "SHA-256  $sha\n" +
                "到期     ${data.caNotAfter.take(10).ifEmpty { "—" }}",
            10f,
            Palette.TEXT_2,
        ).apply {
            background = context.rounded(0xFFF7FCFE.toInt(), 14f, Palette.BORDER, 1f)
            setPadding(context.dp(14f), context.dp(12f), context.dp(14f), context.dp(12f))
            setTextIsSelectable(true)
        }, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = context.dp(14f) })
        sheet.primary("完成") { dismiss() }
        sheet.secondary("导出备份") { host.exportCaBackup() }
        return sheet
    }

    private fun installPath(): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return "设置 → 安全 → 加密与凭据 → 安装证书（或「从存储设备安装」）→ CA 证书"
        }
        val maker = Build.MANUFACTURER.lowercase(Locale.ROOT)
        return when {
            maker.contains("xiaomi") || maker.contains("redmi") ->
                "设置 → 密码与安全 → 系统安全 → 加密与凭据 → 安装证书 → CA 证书"
            maker.contains("samsung") ->
                "设置 → 生物识别和安全 → 其他安全设置 → 从设备存储安装证书"
            else ->
                "设置 → 安全（或「安全和隐私」）→ 更多安全设置 → 加密与凭据 → 安装证书 → CA 证书"
        }
    }

    private fun installFileName(): String =
        host.caExportName.ifEmpty { CaStore.INSTALL_NAME }

    private fun addStatus(
        sheet: Sheet,
        title: String,
        detail: String?,
        color: Int,
        fill: Int,
        stroke: Int,
    ) {
        val card = context.card(radius = 12f, fill = fill, padding = 14f, stroke = stroke)
        card.addView(context.text(title, 13f, color, medium = true))
        if (!detail.isNullOrEmpty()) {
            card.addView(context.text(detail, 10.5f, Palette.TEXT_2).apply {
                setPadding(0, context.dp(4f), 0, 0)
            })
        }
        sheet.add(card, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = context.dp(12f) })
    }

    private fun addHint(sheet: Sheet, text: String) {
        sheet.add(context.text(text, 10f, Palette.MUTED).apply {
            setPadding(context.dp(2f), context.dp(10f), context.dp(2f), 0)
        })
    }

    private fun step(
        sheet: Sheet,
        number: Int,
        title: String,
        subtitle: String,
        detail: String? = null,
    ) {
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
        if (!detail.isNullOrEmpty()) {
            texts.addView(context.text(detail, 10f, Palette.TEXT_2).apply {
                setPadding(0, context.dp(4f), 0, 0)
            })
        }
        row.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        sheet.add(row)
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
