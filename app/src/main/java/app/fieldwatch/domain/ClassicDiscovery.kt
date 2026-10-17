package app.fieldwatch.domain

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

interface ClassicDiscoveryPort {
    fun unavailableReason(): String?
    fun isDiscovering(): Boolean
    fun startDiscovery(): Boolean
    fun cancelDiscovery(): Boolean
    fun pairedDevices(): List<InventoryRadio>
}

enum class ClassicInquiryStatus { IDLE, STARTING, DISCOVERING, FINISHED, CANCELLED, TIMED_OUT, BLOCKED, ERROR }

data class ClassicDiscoveryState(
    val status: ClassicInquiryStatus = ClassicInquiryStatus.IDLE,
    val message: String = "Classic inquiry has not been started.",
    val ownsInquiry: Boolean = false,
    val radios: List<InventoryRadio> = emptyList(),
    val pairedReadAt: Long? = null,
    val dropped: Int = 0,
    val rejected: Int = 0,
)

/** Radio ownership and lifecycle can be tested without an Android controller. */
class ClassicDiscovery(
    private val port: ClassicDiscoveryPort,
    private val now: () -> Long = System::currentTimeMillis,
    capacity: Int = 500,
    private val elapsed: () -> Long = { System.nanoTime() / 1_000_000L },
) {
    companion object { const val TIMEOUT_MS = 30_000L }
    private val inventory = BluetoothInventory(capacity)
    private var active = false
    private var deadline = 0L
    private val mutableState = MutableStateFlow(ClassicDiscoveryState())
    val state = mutableState.asStateFlow()

    @Synchronized fun activate() { active = true; refreshPaired() }

    @Synchronized fun refreshPaired() {
        if (!active) return
        try {
            val reason = port.unavailableReason()
            if (reason != null) { unavailable(reason); return }
            inventory.refreshPaired(port.pairedDevices())
            publish(mutableState.value.copy(pairedReadAt = now(),
                status = if (mutableState.value.status == ClassicInquiryStatus.BLOCKED) ClassicInquiryStatus.IDLE else mutableState.value.status,
                message = if (mutableState.value.status == ClassicInquiryStatus.BLOCKED) "Ready. Start an inquiry to look for discoverable devices." else mutableState.value.message))
        } catch (_: SecurityException) { unavailable("Bluetooth permission is missing. Restore Nearby devices permission in Android settings.") }
        catch (_: Exception) { fail("Android could not read Bluetooth pairing history. Existing session observations remain visible.") }
    }

    @Synchronized fun start() {
        if (!active || mutableState.value.ownsInquiry) return
        try {
            port.unavailableReason()?.let { unavailable(it); return }
            if (port.isDiscovering()) {
                publish(mutableState.value.copy(status = ClassicInquiryStatus.BLOCKED,
                    message = "Bluetooth discovery is already running. Wait for it to finish before starting a Fieldwatch inquiry."))
                return
            }
            // Set ownership before asking Android, so an immediate callback belongs to this cycle.
            deadline = elapsed() + TIMEOUT_MS
            publish(mutableState.value.copy(ownsInquiry = true, status = ClassicInquiryStatus.STARTING,
                message = "Waiting for Android to start Classic inquiry."))
            if (!port.startDiscovery()) {
                publish(mutableState.value.copy(ownsInquiry = false, status = ClassicInquiryStatus.BLOCKED,
                    message = "Android refused the inquiry. Check Bluetooth, Location and scan permissions, then retry."))
            }
        } catch (_: SecurityException) { unavailable("Bluetooth scan permission is missing. Restore Nearby devices permission in Android settings.") }
        catch (_: Exception) { fail("Classic inquiry could not be started.") }
    }

    @Synchronized fun onStarted() {
        if (active && mutableState.value.ownsInquiry) publish(mutableState.value.copy(status = ClassicInquiryStatus.DISCOVERING,
            message = "Classic inquiry running. Only discoverable devices may respond."))
    }

    @Synchronized fun onFound(row: InventoryRadio) {
        if (!active || !mutableState.value.ownsInquiry) return
        inventory.observe(row)
        publish(mutableState.value)
    }

    @Synchronized fun onMalformedObservation() {
        if (active && mutableState.value.ownsInquiry) { inventory.reject(); publish(mutableState.value) }
    }

    @Synchronized fun onFinished() {
        if (active && mutableState.value.ownsInquiry) publish(mutableState.value.copy(ownsInquiry = false,
            status = ClassicInquiryStatus.FINISHED, message = "Inquiry finished. Results are observations, not proof of current presence."))
    }

    @Synchronized fun expire() {
        if (mutableState.value.ownsInquiry && elapsed() >= deadline) stop(ClassicInquiryStatus.TIMED_OUT,
            "Inquiry reached its 30-second limit. No automatic retry was started.")
    }

    @Synchronized fun stop() { stop(ClassicInquiryStatus.CANCELLED, "Fieldwatch inquiry cancelled.") }

    @Synchronized fun deactivate() {
        stop(ClassicInquiryStatus.CANCELLED, "Inquiry cancelled after leaving the inventory screen.")
        active = false
    }

    @Synchronized fun unavailable(reason: String) {
        if (mutableState.value.ownsInquiry) stop(ClassicInquiryStatus.BLOCKED, reason)
        else publish(mutableState.value.copy(status = ClassicInquiryStatus.BLOCKED, message = reason, ownsInquiry = false))
    }

    @Synchronized fun fail(message: String) {
        if (mutableState.value.ownsInquiry) stop(ClassicInquiryStatus.ERROR, message)
        else publish(mutableState.value.copy(status = ClassicInquiryStatus.ERROR, message = message, ownsInquiry = false))
    }

    @Synchronized fun clear() {
        if (mutableState.value.ownsInquiry) return
        inventory.clear()
        publish(ClassicDiscoveryState())
        refreshPaired()
    }

    private fun stop(status: ClassicInquiryStatus, message: String) {
        if (!mutableState.value.ownsInquiry) return
        val confirmed = try { port.cancelDiscovery() || !port.isDiscovering() } catch (_: Exception) { false }
        publish(mutableState.value.copy(ownsInquiry = false, status = status,
            message = if (confirmed) message else "$message Android did not confirm cancellation; its inquiry may continue until the cycle ends."))
    }

    private fun publish(state: ClassicDiscoveryState) {
        mutableState.value = state.copy(radios = inventory.snapshot(), dropped = inventory.dropped, rejected = inventory.rejected)
    }
}
