package app.fieldwatch.ui

import android.app.Activity
import android.view.Window
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalView
import java.util.WeakHashMap

/** Reference counting keeps protection active while navigation transitions overlap two screens. */
private object AssessmentWindows {
    private data class Lease(var count: Int, val originallySecure: Boolean)
    private val leases = WeakHashMap<Window, Lease>()
    @Synchronized fun acquire(window: Window) {
        val current = leases[window]
        if (current != null) current.count++ else {
            val secure = window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
            leases[window] = Lease(1, secure)
        }
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
    @Synchronized fun release(window: Window) {
        val lease = leases[window] ?: return
        lease.count--
        if (lease.count == 0) {
            leases.remove(window)
            if (!lease.originallySecure) window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

@Composable
fun ProtectAssessmentScreen() {
    val view = LocalView.current
    DisposableEffect(view) {
        val window = (view.context as? Activity)?.window
        window?.let(AssessmentWindows::acquire)
        onDispose { window?.let(AssessmentWindows::release) }
    }
}
