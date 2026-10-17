package app.fieldwatch.radio

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.core.content.ContextCompat
import app.fieldwatch.domain.*

/** Foreground-screen, single-cycle Classic inquiry. Never pairs, connects or repeats automatically. */
@SuppressLint("MissingPermission")
class ClassicRadio(context: Context) {
    private val context = context.applicationContext
    private val handler = Handler(Looper.getMainLooper())
    private val adapter: BluetoothAdapter?
        get() = this.context.getSystemService(BluetoothManager::class.java)?.adapter
    private var registered = false
    private val port = object : ClassicDiscoveryPort {
        override fun unavailableReason(): String? {
            val target = adapter ?: return "This phone does not report a Bluetooth adapter."
            val permissions = if (Build.VERSION.SDK_INT >= 31) listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
                else listOf(Manifest.permission.BLUETOOTH, Manifest.permission.BLUETOOTH_ADMIN)
            if (permissions.any { ContextCompat.checkSelfPermission(this@ClassicRadio.context, it) != PackageManager.PERMISSION_GRANTED }) {
                return "Nearby devices permission is missing. Restore Bluetooth permissions in Android settings."
            }
            if (!target.isEnabled) return "Bluetooth is off. Turn it on in Android settings."
            return null
        }
        override fun isDiscovering(): Boolean = adapter?.isDiscovering == true
        override fun startDiscovery(): Boolean = adapter?.startDiscovery() == true
        override fun cancelDiscovery(): Boolean = adapter?.cancelDiscovery() == true
        override fun pairedDevices(): List<InventoryRadio> = adapter?.bondedDevices.orEmpty().mapNotNull { device ->
            toRecord(device, observed = false, null, null)
        }
    }
    val discovery = ClassicDiscovery(port)
    val state = discovery.state
    private val timeout = Runnable { discovery.expire() }
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (!registered || intent == null) return
            try {
                when (intent.action) {
                    BluetoothAdapter.ACTION_DISCOVERY_STARTED -> discovery.onStarted()
                    BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> {
                        discovery.onFinished()
                        if (!state.value.ownsInquiry) handler.removeCallbacks(timeout)
                    }
                    BluetoothDevice.ACTION_FOUND -> {
                        if (!state.value.ownsInquiry) return
                        val device: BluetoothDevice? = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
                            else @Suppress("DEPRECATION") intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                        if (device != null) {
                            // Newer Android versions can include LE results in this broadcast.
                            val resultType = intent.getIntExtra("android.bluetooth.device.extra.DISCOVERY_RESULT_TYPE", device.type)
                            if (resultType == BluetoothDevice.DEVICE_TYPE_LE) return
                            val strength = if (intent.hasExtra(BluetoothDevice.EXTRA_RSSI))
                                intent.getShortExtra(BluetoothDevice.EXTRA_RSSI, Short.MIN_VALUE).toInt() else null
                            val row = toRecord(device, observed = true, strength, intent.getStringExtra(BluetoothDevice.EXTRA_NAME))
                            if (row == null) discovery.onMalformedObservation() else discovery.onFound(row)
                        } else discovery.onMalformedObservation()
                    }
                    BluetoothDevice.ACTION_BOND_STATE_CHANGED -> discovery.refreshPaired()
                    BluetoothAdapter.ACTION_STATE_CHANGED -> {
                        if (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR) != BluetoothAdapter.STATE_ON) {
                            discovery.unavailable("Bluetooth is off or changing state. Existing results are session history.")
                            handler.removeCallbacks(timeout)
                        } else discovery.refreshPaired()
                    }
                }
            } catch (_: SecurityException) {
                discovery.unavailable("Bluetooth permission changed. Restore permissions in Android settings.")
                handler.removeCallbacks(timeout)
            } catch (_: RuntimeException) {
                // A malformed optional broadcast must not crash scanning or create a target.
                if (intent.action == BluetoothDevice.ACTION_FOUND) discovery.onMalformedObservation()
            }
        }
    }

    fun activate() {
        if (registered) return
        try {
            val filter = IntentFilter().apply {
                addAction(BluetoothAdapter.ACTION_DISCOVERY_STARTED)
                addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
                addAction(BluetoothDevice.ACTION_FOUND)
                addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
                addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
            }
            // Bluetooth broadcasts originate from a privileged app, not necessarily the system UID.
            // Restrict this exported receiver to senders holding the Bluetooth platform permission.
            val senderPermission = if (Build.VERSION.SDK_INT >= 31) Manifest.permission.BLUETOOTH_CONNECT else Manifest.permission.BLUETOOTH
            ContextCompat.registerReceiver(context, receiver, filter, senderPermission, handler, ContextCompat.RECEIVER_EXPORTED)
            registered = true
            discovery.activate()
        } catch (_: Exception) { discovery.fail("Classic discovery could not register with Android. Retry when permissions are available.") }
    }

    fun startInquiry() {
        if (state.value.ownsInquiry) return
        try {
            val location = context.getSystemService(LocationManager::class.java)
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED ||
                location?.isLocationEnabled != true) {
                discovery.unavailable("Classic inquiry needs precise location permission and Android Location enabled.")
                return
            }
            discovery.start()
            if (state.value.ownsInquiry) handler.postDelayed(timeout, ClassicDiscovery.TIMEOUT_MS)
        } catch (_: SecurityException) {
            discovery.unavailable("Bluetooth permission changed. Restore permissions in Android settings.")
        } catch (_: Exception) {
            discovery.fail("Android could not start the Classic inquiry. Retry after checking radio settings.")
        }
    }

    fun stopInquiry() { handler.removeCallbacks(timeout); discovery.stop() }
    fun refreshPaired() = discovery.refreshPaired()
    fun clear() = discovery.clear()

    fun deactivate() {
        handler.removeCallbacks(timeout)
        discovery.deactivate()
        if (registered) {
            registered = false
            runCatching { context.unregisterReceiver(receiver) }
        }
    }

    private fun toRecord(device: BluetoothDevice, observed: Boolean, rssi: Int?, advertisedName: String?): InventoryRadio? {
        val address = device.address ?: return null
        if (!BluetoothAdapter.checkBluetoothAddress(address)) return null
        val type = device.type
        if (observed && type == BluetoothDevice.DEVICE_TYPE_LE) return null
        val timestamp = System.currentTimeMillis().takeIf { observed }
        return RadioInventory.normalized(InventoryRadio(
            identifier = address, name = advertisedName ?: device.name.orEmpty(),
            transport = if (type == BluetoothDevice.DEVICE_TYPE_LE) AssessmentTransport.BLE else AssessmentTransport.BLUETOOTH_CLASSIC,
            source = if (observed) InventorySource.CLASSIC_INQUIRY else InventorySource.BONDED_RECORD,
            firstSeen = timestamp, lastSeen = timestamp, rssi = rssi,
            paired = device.bondState == BluetoothDevice.BOND_BONDED,
            dualMode = type == BluetoothDevice.DEVICE_TYPE_DUAL,
            transportConfirmed = type != BluetoothDevice.DEVICE_TYPE_UNKNOWN,
            deviceClass = device.bluetoothClass?.deviceClass,
        ))
    }
}
