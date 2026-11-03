package app.fieldwatch

import android.accessibilityservice.AccessibilityServiceInfo
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import java.util.UUID

/** Test-only system UI driver. No storage permission or production export hook. */
internal class SimulationDocumentPicker : AutoCloseable {
    private val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
    private val previousFlags = automation.serviceInfo.flags
    private val names = mutableListOf<String>()
    private val pickerPackages = setOf("com.google.android.documentsui", "com.android.documentsui")

    init {
        check(BuildConfig.BUILD_TYPE == "simulation")
        automation.serviceInfo = automation.serviceInfo.apply {
            flags = flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
        }
    }

    fun awaitOpen() {
        awaitNode { it.packageName?.toString() in pickerPackages && it.viewIdResourceName == "android:id/title" && it.isEditable }
        // Deliberately fail outside this observed local destination; never choose a cloud account.
        awaitNode { it.packageName?.toString() in pickerPackages && it.viewIdResourceName?.endsWith(":id/breadcrumb_text") == true && it.text?.toString() == "Downloads" }
    }

    fun setUniqueName(): String {
        val name = "fieldwatch-simulation-${UUID.randomUUID()}.json"
        names += name
        val input = awaitNode { it.viewIdResourceName == "android:id/title" && it.isEditable }
        check(input.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, name)
        })) { "Picker rejected filename input" }
        awaitNode { it.isEditable && it.text?.toString() == name }
        return name
    }

    fun save() {
        val button = awaitNode { it.packageName?.toString() in pickerPackages && it.viewIdResourceName == "android:id/button1" && it.isEnabled }
        check(button.performAction(AccessibilityNodeInfo.ACTION_CLICK)) { "Picker rejected Save" }
        awaitClosed()
    }

    fun cancel() {
        check(automation.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)) { "System Back action rejected" }
        awaitClosed()
    }

    fun exists(name: String): Boolean = shell("ls ${path(name)}").trim() == path(name)
    fun read(name: String): String {
        assertTrue("Picker did not create the requested local document", exists(name))
        // Shell reads only this synthetic test file to independently verify the app's SAF write.
        return shell("cat ${path(name)}")
    }

    private fun path(name: String): String {
        check(name in names && Regex("fieldwatch-simulation-[0-9a-f-]{36}\\.json").matches(name))
        return "/sdcard/Download/$name"
    }

    private fun shell(command: String): String = ParcelFileDescriptor.AutoCloseInputStream(
        automation.executeShellCommand(command)
    ).bufferedReader(Charsets.UTF_8).use { it.readText() }

    private fun awaitClosed() {
        val deadline = SystemClock.uptimeMillis() + 15000
        while (SystemClock.uptimeMillis() < deadline) {
            if (automation.rootInActiveWindow?.packageName?.toString() == BuildConfig.APPLICATION_ID) return
            SystemClock.sleep(100)
        }
        error("Document picker did not return to the simulation app")
    }

    private fun awaitNode(predicate: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo {
        val deadline = SystemClock.uptimeMillis() + 15000
        while (SystemClock.uptimeMillis() < deadline) {
            automation.rootInActiveWindow?.let { find(it, predicate) }?.let { return it }
            SystemClock.sleep(100)
        }
        error("Expected document-picker control unavailable; active package=${automation.rootInActiveWindow?.packageName}")
    }

    private fun find(node: AccessibilityNodeInfo, predicate: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        if (predicate(node)) return node
        for (index in 0 until node.childCount) {
            val child = node.getChild(index) ?: continue
            find(child, predicate)?.let { return it }
        }
        return null
    }

    override fun close() {
        try {
            try {
                if (automation.rootInActiveWindow?.packageName?.toString() in pickerPackages) cancel()
            } finally {
                for (name in names) {
                    shell("rm -f ${path(name)}")
                    assertFalse("Synthetic export cleanup failed", exists(name))
                }
            }
        } finally {
            automation.serviceInfo = automation.serviceInfo.apply { flags = previousFlags }
        }
    }
}
