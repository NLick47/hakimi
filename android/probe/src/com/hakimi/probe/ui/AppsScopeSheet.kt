package com.hakimi.probe.ui

import android.content.Context
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.Drawable
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.Switch
import android.widget.TextView
import com.hakimi.probe.InstalledApps
import com.hakimi.probe.Prefs

/**
 * Picks which apps the VPN captures: everything, everything except a list, or
 * only a list. The exclusion list and the allowlist are edited independently,
 * so switching scope never reinterprets the other list's packages.
 */
class AppsScopeSheet(
    private val context: Context,
    private val host: Host,
) {
    private var sheet: Sheet? = null
    private var opening = false
    private var scope = Prefs.SCOPE_ALL
    private var allowed: MutableSet<String> = mutableSetOf()
    private val idle: MutableSet<String> = mutableSetOf()

    private lateinit var hint: TextView
    private lateinit var count: TextView
    private lateinit var saveButton: TextView
    private lateinit var adapter: AppAdapter
    private lateinit var list: ListView
    private val segments = LinkedHashMap<String, TextView>()
    private val icons = HashMap<String, Drawable?>()

    private var installed: List<InstalledApps.Entry> = emptyList()

    fun show() {
        if (opening || sheet?.isShowing == true) return
        opening = true
        try {
            installed = InstalledApps.launchable(context)
            scope = Prefs.scope(context)
            allowed = Prefs.allowedApps(context).toMutableSet()

            val sheet = Sheet(context, "接管范围", "哪些应用走加速", scrollable = false)
            this.sheet = sheet
            sheet.setOnDismissListener {
                if (this.sheet === sheet) this.sheet = null
                opening = false
            }

            val bar = buildSegments()
            sheet.add(bar, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = context.dp(14f) })

            hint = context.text("", 11.5f, Palette.MUTED).apply {
                setPadding(0, context.dp(10f), 0, 0)
            }
            sheet.add(hint)

            val search = buildSearch()
            sheet.add(search, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = context.dp(10f) })

            adapter = AppAdapter(installed)
            list = ListView(context).apply {
                adapter = this@AppsScopeSheet.adapter
                divider = ColorDrawable(Palette.HAIRLINE)
                dividerHeight = context.dp(1f)
                isVerticalScrollBarEnabled = false
                overScrollMode = View.OVER_SCROLL_NEVER
            }
            val listHeight = (context.resources.displayMetrics.heightPixels * 0.42f).toInt()
            sheet.add(list, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                listHeight
            ).apply { topMargin = context.dp(8f) })

            count = context.text("", 11.5f, Palette.MUTED).apply {
                setPadding(0, context.dp(10f), 0, 0)
            }
            sheet.add(count)

            saveButton = sheet.buttons("保存", { commit() }, "取消", { sheet.dismiss() })

            paintSegments()
            paintState()
            sheet.show()
        } catch (error: Throwable) {
            this.sheet = null
            host.showSnack("无法打开接管范围：${error.message}", error = true)
        } finally {
            opening = false
        }
    }

    private fun buildSegments(): LinearLayout {
        segments.clear()
        val bar = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            background = context.rounded(Palette.SURFACE_2, 12f, Palette.BORDER, 1f)
            setPadding(context.dp(3f), context.dp(3f), context.dp(3f), context.dp(3f))
        }
        listOf(
            Prefs.SCOPE_ALL to "全部",
            Prefs.SCOPE_ONLY to "只接管",
        ).forEach { (value, label) ->
            val cell = context.text(label, 12f, Palette.TEXT_2).apply {
                gravity = Gravity.CENTER
                setPadding(0, context.dp(8f), 0, context.dp(8f))
                clickOnce { selectScope(value) }
            }
            bar.addView(cell, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            segments[value] = cell
        }
        return bar
    }

    private fun buildSearch(): EditText = EditText(context).apply {
        hint = "搜索应用"
        setSingleLine(true)
        textSize = 14f
        setTextColor(Palette.TEXT)
        setHintTextColor(Palette.MUTED)
        setPadding(context.dp(12f), context.dp(9f), context.dp(12f), context.dp(9f))
        background = context.rounded(Palette.SURFACE_2, 12f, Palette.BORDER_STRONG, 1f)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_FILTER
        imeOptions = EditorInfo.IME_ACTION_DONE
        setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                clearFocus()
                context.getSystemService(InputMethodManager::class.java)
                    ?.hideSoftInputFromWindow(windowToken, 0)
                true
            } else {
                false
            }
        }
        addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                if (::adapter.isInitialized) adapter.filter(s?.toString().orEmpty())
            }
        })
    }

    private fun selectScope(value: String) {
        if (scope == value) return
        scope = value
        paintSegments()
        paintState()
    }

    private fun paintSegments() {
        segments.forEach { (value, cell) ->
            val active = value == scope
            cell.background = if (active) {
                context.rounded(Palette.SURFACE, 9f, Palette.BORDER_STRONG, 1f)
            } else {
                null
            }
            cell.setTextColor(if (active) Palette.ACCENT_DIM else Palette.TEXT_2)
        }
    }

    /** Hint, counter, save label and the list's editable state all follow the scope. */
    private fun paintState() {
        val editing = scope != Prefs.SCOPE_ALL
        hint.text = when (scope) {
            Prefs.SCOPE_ONLY -> if (allowed.isEmpty()) {
                "未选择应用，VPN 不会建立"
            } else {
                "只有这些应用走加速"
            }
            else -> "全部进入 VPN；不读代理的 App 可能断网"
        }
        val warn = scope == Prefs.SCOPE_ALL || (scope == Prefs.SCOPE_ONLY && allowed.isEmpty())
        hint.setTextColor(if (warn) Palette.AMBER else Palette.MUTED)
        count.text = when (scope) {
            Prefs.SCOPE_ONLY -> if (allowed.isEmpty()) {
                "还没选择应用"
            } else {
                "已选 ${allowed.size} 个"
            }
            else -> "共 ${installed.size} 个"
        }
        saveButton.text = "保存"
        list.alpha = if (editing) 1f else 0.4f
        if (::adapter.isInitialized) adapter.notifyDataSetChanged()
    }

    private fun selectedSet(): MutableSet<String> = when (scope) {
        Prefs.SCOPE_ONLY -> allowed
        else -> idle
    }

    private fun commit() {
        if (scope == Prefs.SCOPE_ONLY && allowed.isEmpty()) {
            host.showSnack("只接管模式至少要选择一个应用", error = true)
            return
        }
        Prefs.setScope(context, scope)
        Prefs.setAllowedApps(context, allowed)
        sheet?.dismiss()
        host.onAppScopeChanged()
    }

    private fun icon(packageName: String): Drawable? {
        if (icons.containsKey(packageName)) return icons[packageName]
        val drawable = runCatching {
            context.packageManager.getApplicationIcon(packageName)
        }.getOrNull()
        icons[packageName] = drawable
        return drawable
    }

    private inner class AppAdapter(installed: List<InstalledApps.Entry>) : BaseAdapter() {
        private val all = installed.sortedWith(
            compareByDescending<InstalledApps.Entry> {
                it.packageName in Prefs.allowedApps(context)
            }.thenBy { it.label.lowercase() }
        )
        private var visible: List<InstalledApps.Entry> = all

        fun filter(query: String) {
            val needle = query.trim().lowercase()
            visible = if (needle.isEmpty()) {
                all
            } else {
                all.filter {
                    it.label.lowercase().contains(needle) ||
                        it.packageName.lowercase().contains(needle)
                }
            }
            notifyDataSetChanged()
        }

        override fun getCount(): Int = visible.size

        override fun getItem(position: Int): InstalledApps.Entry = visible[position]

        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val app = visible[position]
            val selected = selectedSet()
            val editing = scope != Prefs.SCOPE_ALL
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(context.dp(16f), context.dp(9f), context.dp(16f), context.dp(9f))
                background = context.selectableBackground()
                alpha = if (editing) 1f else 0.55f
            }

            val drawable = icon(app.packageName)
            if (drawable != null) {
                row.addView(ImageView(context).apply {
                    setImageDrawable(drawable)
                    scaleType = ImageView.ScaleType.FIT_CENTER
                }, LinearLayout.LayoutParams(context.dp(30f), context.dp(30f)).apply {
                    marginEnd = context.dp(10f)
                })
            }

            val texts = context.column()
            texts.addView(context.text(app.label, 14.5f, Palette.TEXT, medium = true))
            texts.addView(context.text(app.packageName, 10.5f, Palette.MUTED).apply {
                setPadding(0, context.dp(3f), 0, 0)
            })
            row.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

            val toggle = Switch(context).apply {
                isChecked = app.packageName in selected
                isEnabled = editing
                setShowText(false)
                setOnCheckedChangeListener { _, checked ->
                    if (checked) selected += app.packageName else selected -= app.packageName
                    paintState()
                }
            }
            row.addView(toggle, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
            if (editing) {
                row.setOnClickListener { toggle.isChecked = !toggle.isChecked }
            }
            return row
        }
    }
}
