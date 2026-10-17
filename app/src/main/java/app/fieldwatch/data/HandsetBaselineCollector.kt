package app.fieldwatch.data

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import app.fieldwatch.BuildConfig
import app.fieldwatch.domain.BaselinePermission
import app.fieldwatch.domain.HandsetBaseline

object HandsetBaselineCollector {
    /** Public local APIs only: no identifiers, shell/root commands, radio activity or permission prompts. */
    fun capture(context: Context): HandsetBaseline {
        fun permission(name: String, minimumSdk: Int = 29): BaselinePermission =
            if (Build.VERSION.SDK_INT < minimumSdk) BaselinePermission.NOT_APPLICABLE
            else if (ContextCompat.checkSelfPermission(context, name) == PackageManager.PERMISSION_GRANTED) BaselinePermission.GRANTED
            else BaselinePermission.DENIED
        val features = mapOf("wifi" to PackageManager.FEATURE_WIFI, "bluetooth_classic" to PackageManager.FEATURE_BLUETOOTH,
            "bluetooth_le" to PackageManager.FEATURE_BLUETOOTH_LE, "usb_host" to PackageManager.FEATURE_USB_HOST)
        val patch = HandsetBaseline.metadata(Build.VERSION.SECURITY_PATCH)?.takeIf {
            runCatching { java.time.LocalDate.parse(it) }.isSuccess
        }
        return HandsetBaseline(capturedAt = System.currentTimeMillis(), manufacturer = HandsetBaseline.metadata(Build.MANUFACTURER),
            model = HandsetBaseline.metadata(Build.MODEL), androidRelease = HandsetBaseline.metadata(Build.VERSION.RELEASE), sdk = Build.VERSION.SDK_INT,
            securityPatch = patch, buildDisplay = HandsetBaseline.metadata(Build.DISPLAY), buildIncremental = HandsetBaseline.metadata(Build.VERSION.INCREMENTAL), appVersion = BuildConfig.VERSION_NAME,
            appTargetSdk = context.applicationInfo.targetSdkVersion, hardwareReported = features.mapValues { context.packageManager.hasSystemFeature(it.value) },
            permissions = mapOf("bluetooth_scan" to permission(Manifest.permission.BLUETOOTH_SCAN, 31),
                "bluetooth_connect" to permission(Manifest.permission.BLUETOOTH_CONNECT, 31),
                "nearby_wifi" to permission(Manifest.permission.NEARBY_WIFI_DEVICES, 33),
                "fine_location" to permission(Manifest.permission.ACCESS_FINE_LOCATION), "coarse_location" to permission(Manifest.permission.ACCESS_COARSE_LOCATION),
                "notifications" to permission(Manifest.permission.POST_NOTIFICATIONS, 33))).also { it.validate() }
    }
}
