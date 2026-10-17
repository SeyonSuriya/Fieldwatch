package app.fieldwatch.radio

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.*
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import androidx.core.content.ContextCompat
import androidx.annotation.RequiresApi
import app.fieldwatch.domain.*
import kotlinx.coroutines.*
import java.util.IdentityHashMap
import java.util.UUID

/** Public Android APIs only. No hidden channels, pairing bypass or automatic reconnect. */
@SuppressLint("MissingPermission")
@RequiresApi(33)
class BluetoothToolClient(context: Context, target: BluetoothToolTarget, private val scope: CoroutineScope) {
    private val context = context.applicationContext
    private val target = target.validated()
    private val handler = Handler(Looper.getMainLooper())
    @Volatile private var token = -1L
    @Volatile private var gatt: BluetoothGatt? = null
    private var socket: BluetoothSocket? = null
    private var socketJob: Job? = null
    private var sendJob: Job? = null
    private var sdpReceiver: BroadcastReceiver? = null
    private val characteristics = linkedMapOf<String, BluetoothGattCharacteristic>()
    private val descriptors = linkedMapOf<String, BluetoothGattDescriptor>()
    private val characteristicKeys = IdentityHashMap<BluetoothGattCharacteristic, String>()
    private val descriptorKeys = IdentityHashMap<BluetoothGattDescriptor, String>()
    private var notificationChange: Triple<String, BluetoothGattCharacteristic, Boolean>? = null
    private data class Notification(val token: Long, val characteristic: BluetoothGattCharacteristic, val bytes: ByteArray, val original: Int)
    private val notificationLock = Any()
    private val notificationQueue = ArrayDeque<Notification>()
    private val notificationLosses = mutableMapOf<Long, Long>()
    private var drainPosted = false

    private val port: BluetoothToolPort = object : BluetoothToolPort {
        override fun close() = closeResources()
        override fun connectBle(session: Long): Boolean = guarded {
            val device = device(requireIdleRadio = true)
            if (device.type == BluetoothDevice.DEVICE_TYPE_CLASSIC) throw BluetoothToolFailure("Android reports a Classic-only device. Select its Classic record.")
            token = session
            gatt = device.connectGatt(context, false, callback(session), BluetoothDevice.TRANSPORT_LE)
            gatt != null
        }
        override fun discoverGatt(): Boolean = guarded { activeGatt().discoverServices() }
        override fun readCharacteristic(key: String): Boolean = guarded { activeGatt().readCharacteristic(characteristics.getValue(key)) }
        override fun readDescriptor(key: String): Boolean = guarded { activeGatt().readDescriptor(descriptors.getValue(key)) }
        override fun writeCharacteristic(key: String, bytes: ByteArray, withoutResponse: Boolean): Boolean = guarded {
            val type = if (withoutResponse) BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE else BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            checkStatus(activeGatt().writeCharacteristic(characteristics.getValue(key), bytes, type))
        }
        override fun notifications(key: String, enable: Boolean, indicate: Boolean): Boolean = guarded {
            val current = activeGatt()
            val characteristic = characteristics.getValue(key)
            val descriptor = characteristic.descriptors.filter { it.uuid.toString().equals(BluetoothToolValues.CCCD, true) }.singleOrNull()
                ?: throw BluetoothToolFailure("A unique client configuration descriptor is no longer available.")
            if (!current.setCharacteristicNotification(characteristic, enable)) return@guarded false
            notificationChange = Triple(key, characteristic, enable)
            val bytes = if (!enable) BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
                else if (indicate) BluetoothGattDescriptor.ENABLE_INDICATION_VALUE else BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            try {
                checkStatus(current.writeDescriptor(descriptor, bytes))
            } catch (e: Exception) {
                current.setCharacteristicNotification(characteristic, !enable)
                notificationChange = null
                throw e
            }
        }
        override fun requestMtu(): Boolean = guarded { activeGatt().requestMtu(247) }
        override fun cachedUuids(): List<String> = guarded { device(false).uuids.orEmpty().map { it.uuid.toString() } }
        override fun fetchSdp(session: Long): Boolean = guarded {
            val device = device(true)
            if (device.type == BluetoothDevice.DEVICE_TYPE_LE) throw BluetoothToolFailure("Android reports an LE-only device; Classic SDP is unavailable.")
            token = session
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    if (intent?.action != BluetoothDevice.ACTION_UUID || token != session) return
                    try {
                        val sender = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java) ?: return
                        if (!sender.address.equals(target.address, true)) return
                        val values = intent.getParcelableArrayExtra(BluetoothDevice.EXTRA_UUID, ParcelUuid::class.java).orEmpty()
                        unregisterSdp()
                        controller.sdpResult(session, values.map { it.uuid.toString() })
                    } catch (_: Exception) {
                        unregisterSdp()
                        controller.transportFailure(session, "Android's service discovery response could not be read.")
                    }
                }
            }
            sdpReceiver = receiver
            ContextCompat.registerReceiver(context, receiver, IntentFilter(BluetoothDevice.ACTION_UUID),
                Manifest.permission.BLUETOOTH_CONNECT, handler, ContextCompat.RECEIVER_EXPORTED)
            if (!device.fetchUuidsWithSdp()) { unregisterSdp(); false } else true
        }
        override fun connectRfcomm(session: Long, uuid: String, secure: Boolean): Boolean = guarded {
            val device = device(true)
            if (device.type == BluetoothDevice.DEVICE_TYPE_LE) throw BluetoothToolFailure("Android reports an LE-only device; RFCOMM is unavailable.")
            token = session
            val ownSocket = if (secure) device.createRfcommSocketToServiceRecord(UUID.fromString(uuid))
                else device.createInsecureRfcommSocketToServiceRecord(UUID.fromString(uuid))
            socket = ownSocket
            socketJob = scope.launch(Dispatchers.IO) {
                try {
                    ownSocket.connect()
                    withContext(Dispatchers.Main.immediate) {
                        if (token == session && socket === ownSocket) controller.connected(session)
                    }
                    val buffer = ByteArray(BluetoothToolValues.MAX_BYTES)
                    while (isActive) {
                        val count = ownSocket.inputStream.read(buffer)
                        if (count < 0) {
                            withContext(Dispatchers.Main.immediate) { controller.transportFailure(session, "RFCOMM peer closed the stream.") }
                            break
                        }
                        if (count > 0) {
                            val bytes = buffer.copyOf(count)
                            // Await the main consumer: no unbounded queue of incoming serial packets.
                            withContext(Dispatchers.Main.immediate) { controller.incoming(session, false, null, bytes) }
                        }
                    }
                } catch (e: CancellationException) { throw e }
                catch (_: Exception) {
                    withContext(Dispatchers.Main.immediate) { controller.transportFailure(session, "RFCOMM connection/read failed. Check pairing, service UUID, permissions and target state.") }
                } finally { runCatching { ownSocket.close() } }
            }
            true
        }
        override fun sendRfcomm(session: Long, bytes: ByteArray): Boolean {
            val ownSocket = socket ?: throw BluetoothToolFailure("RFCOMM is disconnected.")
            sendJob = scope.launch(Dispatchers.IO) {
                try {
                    ownSocket.outputStream.write(bytes)
                    ownSocket.outputStream.flush()
                    withContext(Dispatchers.Main.immediate) { controller.result(session, BluetoothToolOperation.SEND_RFCOMM, null, 0) }
                } catch (e: CancellationException) { throw e }
                catch (_: Exception) {
                    withContext(Dispatchers.Main.immediate) { controller.transportFailure(session, "RFCOMM send failed; partial transmission is possible.") }
                }
            }
            return true
        }
    }

    val controller: BluetoothToolSession = BluetoothToolSession(this.target, port)
    val state = controller.state

    fun close() = controller.disconnect("Disconnected after leaving the Bluetooth tools screen.")

    private fun device(requireIdleRadio: Boolean): BluetoothDevice {
        if (Build.VERSION.SDK_INT < 33) throw BluetoothToolFailure("Bluetooth assessment tools require Android 13 or newer.")
        if (listOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_SCAN).any {
                ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED }) {
            throw BluetoothToolFailure("Restore Nearby devices permission in Android settings.")
        }
        val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter ?: throw BluetoothToolFailure("No Bluetooth adapter is available.")
        if (!adapter.isEnabled) throw BluetoothToolFailure("Bluetooth is off.")
        if (requireIdleRadio && adapter.isDiscovering) throw BluetoothToolFailure("A Bluetooth inquiry is running. Stop or wait for it before connecting or requesting services.")
        return adapter.getRemoteDevice(target.address)
    }

    private fun activeGatt(): BluetoothGatt {
        device(false)
        return gatt ?: throw BluetoothToolFailure("BLE is disconnected.")
    }

    private fun checkStatus(status: Int): Boolean {
        if (status != BluetoothStatusCodes.SUCCESS) throw BluetoothToolFailure("Android rejected the GATT request (status $status).", status)
        return true
    }

    private inline fun <T> guarded(block: () -> T): T = try { block() }
        catch (e: BluetoothToolFailure) { throw e }
        catch (_: SecurityException) { throw BluetoothToolFailure("Bluetooth permission was denied or changed.") }
        catch (_: Exception) { throw BluetoothToolFailure("Android could not start this Bluetooth operation.") }

    private fun post(session: Long, owner: BluetoothGatt, block: () -> Unit) {
        handler.post {
            if (token == session && gatt === owner) {
                try { block() }
                catch (_: Exception) { controller.transportFailure(session, "Bluetooth callback could not be processed; session closed.") }
            }
        }
    }

    private fun callback(session: Long): BluetoothGattCallback = object : BluetoothGattCallback() {
        override fun onServiceChanged(owner: BluetoothGatt) = post(session, owner) {
            controller.transportFailure(session, "The remote GATT database changed. Reconnect and rediscover services before further operations.")
        }
        override fun onConnectionStateChange(owner: BluetoothGatt, status: Int, newState: Int) = post(session, owner) {
            if (status == BluetoothGatt.GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED) controller.connected(session)
            else if (status != BluetoothGatt.GATT_SUCCESS || newState == BluetoothProfile.STATE_DISCONNECTED) {
                controller.transportFailure(session, "BLE disconnected or connection failed (Android status $status).", status)
            }
        }
        override fun onServicesDiscovered(owner: BluetoothGatt, status: Int) = post(session, owner) {
            if (status != BluetoothGatt.GATT_SUCCESS) controller.result(session, BluetoothToolOperation.DISCOVER_GATT, null, status)
            else {
                val (services, omitted) = captureServices(owner)
                controller.gattDiscovered(session, services, omitted)
            }
        }
        override fun onCharacteristicRead(owner: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
            val captured = value.copyOf()
            post(session, owner) { controller.result(session, BluetoothToolOperation.READ_CHARACTERISTIC, characteristicKeys[characteristic], status, captured) }
        }
        override fun onDescriptorRead(owner: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int, value: ByteArray) {
            val captured = value.copyOf()
            post(session, owner) { controller.result(session, BluetoothToolOperation.READ_DESCRIPTOR, descriptorKeys[descriptor], status, captured) }
        }
        override fun onCharacteristicWrite(owner: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) = post(session, owner) {
            controller.result(session, BluetoothToolOperation.WRITE_CHARACTERISTIC, characteristicKeys[characteristic], status)
        }
        override fun onDescriptorWrite(owner: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) = post(session, owner) {
            val change = notificationChange
            if (change != null && descriptor.characteristic === change.second && descriptor.uuid.toString().equals(BluetoothToolValues.CCCD, true)) {
                notificationChange = null
                if (status != BluetoothGatt.GATT_SUCCESS) runCatching { owner.setCharacteristicNotification(change.second, !change.third) }
                controller.result(session, BluetoothToolOperation.SET_NOTIFICATIONS, change.first, status)
            }
        }
        override fun onMtuChanged(owner: BluetoothGatt, mtu: Int, status: Int) = post(session, owner) {
            controller.result(session, BluetoothToolOperation.REQUEST_MTU, null, status, mtu = mtu)
        }
        override fun onCharacteristicChanged(owner: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            if (token != session || gatt !== owner) return
            synchronized(notificationLock) {
                if (notificationQueue.size == 32) {
                    val lost = notificationQueue.removeFirst()
                    notificationLosses[lost.token] = (notificationLosses[lost.token] ?: 0) + 1
                }
                notificationQueue.addLast(Notification(session, characteristic, value.copyOf(minOf(value.size, BluetoothToolValues.MAX_BYTES)), value.size))
                if (!drainPosted) { drainPosted = true; handler.post { drainNotifications() } }
            }
        }
    }

    private fun drainNotifications() {
        val (batch, losses) = synchronized(notificationLock) {
            val data = notificationQueue.toList() to notificationLosses.toMap()
            notificationQueue.clear(); notificationLosses.clear(); drainPosted = false
            data
        }
        losses.forEach { (session, count) -> controller.notificationLoss(session, count) }
        batch.forEach { notification ->
            val key = characteristicKeys[notification.characteristic] ?: return@forEach
            controller.incoming(notification.token, true, key, notification.bytes, notification.original)
        }
    }

    private fun captureServices(owner: BluetoothGatt): Pair<List<GattServiceInfo>, Int> {
        characteristics.clear(); descriptors.clear(); characteristicKeys.clear(); descriptorKeys.clear()
        val all = owner.services.orEmpty()
        val total = all.sumOf { 1 + it.characteristics.sumOf { characteristic -> 1 + characteristic.descriptors.size } }
        var characterCount = 0
        var descriptorCount = 0
        val result = all.take(32).mapIndexed { serviceIndex, service ->
            val key = "s$serviceIndex"
            val chars = service.characteristics.take((128 - characterCount).coerceAtLeast(0)).mapIndexed { characteristicIndex, characteristic ->
                characterCount++
                val characteristicKey = "$key/c$characteristicIndex"
                characteristics[characteristicKey] = characteristic
                characteristicKeys[characteristic] = characteristicKey
                val desc = characteristic.descriptors.take((128 - descriptorCount).coerceAtLeast(0)).mapIndexed { descriptorIndex, descriptor ->
                    descriptorCount++
                    val descriptorKey = "$characteristicKey/d$descriptorIndex"
                    descriptors[descriptorKey] = descriptor
                    descriptorKeys[descriptor] = descriptorKey
                    GattDescriptorInfo(descriptorKey, descriptor.uuid.toString().uppercase())
                }
                GattCharacteristicInfo(characteristicKey, characteristic.uuid.toString().uppercase(), characteristic.properties, desc)
            }
            GattServiceInfo(key, service.uuid.toString().uppercase(), service.type == BluetoothGattService.SERVICE_TYPE_PRIMARY, chars)
        }
        return result to (total - result.size - characterCount - descriptorCount).coerceAtLeast(0)
    }

    private fun unregisterSdp() {
        sdpReceiver?.let { runCatching { context.unregisterReceiver(it) } }
        sdpReceiver = null
    }

    private fun closeResources() {
        token = -1L
        unregisterSdp()
        val oldGatt = gatt
        gatt = null
        runCatching { oldGatt?.disconnect() }; runCatching { oldGatt?.close() }
        val oldSocket = socket
        socket = null
        runCatching { oldSocket?.close() }
        socketJob?.cancel(); socketJob = null
        sendJob?.cancel(); sendJob = null
        notificationChange = null
        characteristics.clear(); descriptors.clear(); characteristicKeys.clear(); descriptorKeys.clear()
        synchronized(notificationLock) { notificationQueue.clear(); notificationLosses.clear() }
    }
}
