package com.hakimi.probe.ui

import org.json.JSONObject

data class DiagnoseOutcome(
    val ok: Boolean,
    val domain: String,
    val state: String,
    val latencyMs: Long?,
    val ip: String,
    val tls: String,
    val error: String,
    val raw: String,
)

/** Everything a screen may ask the activity to do. */
interface Host {
    val core: CoreData
    val probing: Boolean
    val caReady: Boolean

    fun toggleAcceleration()
    fun setGroupEnabled(site: SiteInfo, enabled: Boolean)
    fun saveGroup(group: JSONObject, isNew: Boolean, done: (Boolean, String?) -> Unit)
    fun deleteGroup(id: String, done: (Boolean, String?) -> Unit)
    fun runProbeSweep()
    fun diagnosePrompt()
    fun runDiagnose(domain: String, done: (DiagnoseOutcome) -> Unit)
    fun applyConfig(next: JSONObject, done: (Boolean, String?) -> Unit)
    fun resetCatalogs()
    fun editSetting(key: String, title: String, subtitle: String, value: String)
    fun chooseMode()
    fun chooseExcludedApps()
    fun onExcludedAppsChanged()
    fun openVpnSettings()
    fun requestBatteryExemption()
    fun refreshCatalogs()
    fun showLog()
    fun exportDiagnostics()
    fun openCaSetup()
    fun exportCa()
    fun recheckCa()
    fun openUrl(url: String)
    fun copy(text: String, label: String)
    fun openSite(site: SiteInfo)
    fun openEditor(site: SiteInfo?)
    fun setTab(index: Int)
    fun showSnack(message: String, error: Boolean = false)
}
