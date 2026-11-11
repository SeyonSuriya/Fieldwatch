package app.fieldwatch.domain

import kotlinx.serialization.Serializable

@Serializable
sealed interface BluetoothAccessObservation {
    @Serializable
    data class Ble(
        val services: Int,
        val characteristics: Int,
        val readable: Int,
        val writeWithResponse: Int,
        val writeWithoutResponse: Int,
        val subscriptions: Int,
        val omittedAttributes: Int,
        val authenticationRejections: Int,
        val encryptionRejections: Int,
        val omittedEvents: Long,
    ) : BluetoothAccessObservation

    @Serializable
    data class Classic(
        val recognizedServices: List<String>,
        val otherUuids: Int,
        val omittedUuids: Int,
        val source: String?,
        val observedAt: Long?,
    ) : BluetoothAccessObservation
}

object BluetoothEvidenceReview {
    // Bluetooth SIG Assigned Numbers, SDP Service Class and Profile Identifiers.
    private val classicServices = mapOf(
        "1101" to "Serial Port",
        "1105" to "OBEX Object Push",
        "1106" to "OBEX File Transfer",
        "110A" to "Audio Source",
        "110B" to "Audio Sink",
        "1115" to "Personal Area Networking User",
        "1116" to "Network Access Point",
        "1124" to "Human Interface Device",
    ).mapKeys { (uuid, _) -> BluetoothToolValues.uuid(uuid) }

    private val gattAccessOperations = listOf(
        BluetoothToolOperation.READ_CHARACTERISTIC,
        BluetoothToolOperation.READ_DESCRIPTOR,
        BluetoothToolOperation.WRITE_CHARACTERISTIC,
    )

    fun evaluate(report: BluetoothEvidenceReport, asset: AssessmentAsset): BluetoothAccessObservation {
        require(report.format == "fieldwatch-bluetooth-session" && report.formatVersion == 1) {
            "Unsupported Bluetooth evidence format."
        }
        val target = report.target.validated()
        require(asset.transport == target.transport && asset.identifier.equals(target.address, ignoreCase = true)) {
            "Bluetooth evidence target mismatch."
        }
        require(report.capturedAt > 0 && report.omittedAttributes >= 0 &&
            report.omittedEvents >= 0 && report.omittedUuids >= 0) { "Invalid Bluetooth capture metadata." }
        if (target.transport == AssessmentTransport.BLE) {
            val characteristics = report.services.flatMap { it.characteristics }
            fun count(bits: Int) = characteristics.count { it.properties and bits != 0 }
            fun rejections(status: Int) = report.events.count { event ->
                event.kind == BluetoothEventKind.ERROR && event.status == status &&
                    gattAccessOperations.any { event.message.startsWith("${it.name}: Android status $status (") }
            }
            return BluetoothAccessObservation.Ble(report.services.size, characteristics.size,
                count(BluetoothToolValues.READ), count(BluetoothToolValues.WRITE),
                count(BluetoothToolValues.WRITE_NO_RESPONSE), count(BluetoothToolValues.NOTIFY or BluetoothToolValues.INDICATE),
                report.omittedAttributes, rejections(5), rejections(15), report.omittedEvents)
        }

        val uuids = report.classicUuids.map { BluetoothToolValues.uuid(it) }.distinct()
        val recognized = uuids.mapNotNull(classicServices::get)
        val source = when (report.classicUuidSource) {
            "android-cache" -> "Android UUID cache"
            "android-sdp-response-possibly-cached" -> "Android SDP result, possibly cached"
            else -> null
        }
        return BluetoothAccessObservation.Classic(recognized, uuids.size - recognized.size,
            report.omittedUuids, source, report.classicUuidReadAt)
    }
}
