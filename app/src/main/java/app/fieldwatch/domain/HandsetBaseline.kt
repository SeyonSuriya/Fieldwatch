package app.fieldwatch.domain

import kotlinx.serialization.Serializable
import java.time.LocalDate

@Serializable
enum class BaselinePermission { GRANTED, DENIED, NOT_APPLICABLE }

/** Local operator handset metadata, never a remote-target fingerprint or vulnerability result. */
@Serializable
data class HandsetBaseline(
    val format: String = "fieldwatch-operator-handset",
    val version: Int = 1,
    val capturedAt: Long,
    val manufacturer: String?,
    val model: String?,
    val androidRelease: String?,
    val sdk: Int,
    val securityPatch: String?,
    val buildDisplay: String?,
    val buildIncremental: String? = null,
    val appVersion: String,
    val appTargetSdk: Int,
    val hardwareReported: Map<String, Boolean>,
    val permissions: Map<String, BaselinePermission>,
) {
    fun validate() {
        require(format == "fieldwatch-operator-handset" && version == 1 && capturedAt > 0)
        require(sdk in 29..100 && appTargetSdk in 29..100)
        listOfNotNull(manufacturer, model, androidRelease, buildDisplay, buildIncremental).forEach {
            require(it.isNotBlank() && it.length <= 200 && it.none { char -> char.isISOControl() }) { "Invalid handset metadata." }
        }
        require(appVersion.isNotBlank() && appVersion.length <= 100 && appVersion.none { it.isISOControl() })
        if (securityPatch != null) {
            require(securityPatch.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}"))) { "Invalid patch date." }
            require(runCatching { LocalDate.parse(securityPatch) }.isSuccess) { "Invalid patch date." }
        }
        require(hardwareReported.keys == FEATURES && permissions.keys == PERMISSIONS) { "Unexpected baseline fields." }
        PERMISSION_MIN_SDK.forEach { (name, minimum) ->
            require((permissions[name] == BaselinePermission.NOT_APPLICABLE) == (sdk < minimum)) { "Permission applicability does not match SDK." }
        }
    }
    companion object {
        val FEATURES = setOf("wifi", "bluetooth_classic", "bluetooth_le", "usb_host")
        val PERMISSION_MIN_SDK = mapOf("bluetooth_scan" to 31, "bluetooth_connect" to 31, "nearby_wifi" to 33,
            "fine_location" to 29, "coarse_location" to 29, "notifications" to 33)
        val PERMISSIONS = PERMISSION_MIN_SDK.keys
        fun metadata(value: String?): String? = value?.trim()?.takeIf {
            it.isNotEmpty() && !it.equals("unknown", true) && it.length <= 200 && it.none { char -> char.isISOControl() }
        }
    }
}
