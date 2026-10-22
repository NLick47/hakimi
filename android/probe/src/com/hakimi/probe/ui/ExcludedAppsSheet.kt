package com.hakimi.probe.ui

import android.content.Context
import android.graphics.drawable.ColorDrawable
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
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.Switch
import com.hakimi.probe.InstalledApps
import com.hakimi.probe.Prefs

/**
 * Opt-out list for the all-apps VPN. Excluded packages are removed from the
 * VPN's UID range and connect directly, without the core or its CA.
 */
class ExcludedAppsSheet(
    private val context: Context,
    private val host: Host,
) {
    fun show() {
        val installed = InstalledApps.launchable(context)
        val sheet = Sheet(
            context,
            "排除应用",
            "被排除的应用不经过 hakimi，直接连接网络；可多选",
            scrollable = false
        )
        if (installed.isEmpty()) {
            sheet.add(context.text("没有找到可排除的应用", 13f, Palette.TEXT_2))
            sheet.primary("关闭") { sheet.dismiss() }
            sheet.show()
            return
        }

        val selected = Prefs.excludedApps(context).toMutableSet()
        val count = context.text("", 11.5f, Palette.MUTED)
        fun refreshCount() {
            count.text = if (selected.isEmpty()) {
                "未排除任何应用"
            } else {
                "已排除 ${selected.size} 个应用"
            }
        }
        refreshCount()

        val appAdapter = AppAdapter(installed, selected) { refreshCount() }

        val search = EditText(context).apply {
            hint = "搜索应用名或包名"
            setSingleLine(true)
            textSize = 14f
            setTextColor(Palette.TEXT)
            setHintTextColor(Palette.MUTED)
            setPadding(context.dp(12f), context.dp(9f), context.dp(12f), context.dp(9f))
            background = context.rounded(Palette.SURFACE_2, 12f, Palette.BORDER_STRONG)
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
        }
        search.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = appAdapter.filter(s?.toString().orEmpty())
        })

        val clear = context.text("清空", 12.5f, Palette.ACCENT).apply {
            setPadding(context.dp(12f), context.dp(8f), context.dp(2f), context.dp(8f))
            isClickable = true
            setOnClickListener {
                selected.clear()
                appAdapter.notifyDataSetChanged()
                refreshCount()
            }
        }

        val tools = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, context.dp(12f), 0, 0)
        }
        tools.addView(search, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        tools.addView(clear)
        sheet.add(tools)
        sheet.add(count.apply { setPadding(0, context.dp(6f), 0, context.dp(4f)) })

        // A fixed-height ListView keeps the search field and the save/cancel
        // row on screen no matter how many launchable apps the device has.
        val list = ListView(context).apply {
            adapter = appAdapter
            divider = ColorDrawable(Palette.BORDER)
            dividerHeight = context.dp(1f)
            isVerticalScrollBarEnabled = false
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        val listHeight = (context.resources.displayMetrics.heightPixels * 0.52f).toInt()
        sheet.add(list, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            listHeight
        ))

        sheet.buttons(
            "保存",
            {
                Prefs.setExcludedApps(context, selected)
                sheet.dismiss()
                host.onExcludedAppsChanged()
            },
            "取消",
            { sheet.dismiss() }
        )
        sheet.show()
    }

    /**
     * Adapter over launchable apps. Already excluded packages are pinned to
     * the top on open; toggling does not reorder rows under the user's finger.
     */
    private inner class AppAdapter(
        installed: List<InstalledApps.Entry>,
        private val selected: MutableSet<String>,
        private val onChanged: () -> Unit,
    ) : BaseAdapter() {
        private val all = installed.sortedWith(
            compareByDescending<InstalledApps.Entry> { it.packageName in selected }
                .thenBy { it.label.lowercase() }
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

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val app = visible[position]
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(context.dp(2f), context.dp(10f), context.dp(2f), context.dp(10f))
                background = context.selectableBackground()
            }
            val texts = context.column()
            texts.addView(context.text(app.label, 14.5f, Palette.TEXT, medium = true))
            texts.addView(context.text(app.packageName, 10.5f, Palette.MUTED).apply {
                setPadding(0, context.dp(3f), 0, 0)
            })
            row.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))

            val toggle = Switch(context).apply {
                isChecked = app.packageName in selected
                setShowText(false)
                setOnCheckedChangeListener { _, checked ->
                    if (checked) selected += app.packageName else selected -= app.packageName
                    onChanged()
                }
            }
            row.addView(toggle, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ))
            row.setOnClickListener { toggle.isChecked = !toggle.isChecked }
            return row
        }
    }
}
