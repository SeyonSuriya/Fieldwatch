package app.fieldwatch.domain

import kotlinx.serialization.Serializable

@Serializable
enum class InventorySource { WIFI_SCAN, BLE_ADVERTISEMENT, CLASSIC_INQUIRY, BONDED_RECORD }

@Serializable
data class InventoryRadio(
    val identifier: String,
    val name: String,
    val transport: AssessmentTransport,
    val source: InventorySource,
    val firstSeen: Long? = null,
    val lastSeen: Long? = null,
    val rssi: Int? = null,
    val paired: Boolean = false,
    val dualMode: Boolean = false,
    val transportConfirmed: Boolean = true,
    /** Android's device-class bits only, not a complete Class of Device service bitmap. */
    val deviceClass: Int? = null,
    val vendor: String? = null,
) {
    val key: String get() = "${transport.name}:${identifier.uppercase()}"
    val label: String get() = name.trim().takeIf { it.isNotEmpty() && !it.equals(identifier, ignoreCase = true) }
        ?.take(100) ?: when (transport) {
            AssessmentTransport.WIFI -> "Unnamed Wi-Fi access point"
            AssessmentTransport.BLE -> "Unnamed BLE device"
            AssessmentTransport.BLUETOOTH_CLASSIC -> "Unnamed Classic Bluetooth device"
            AssessmentTransport.NETWORK -> "Unnamed network service"
        }
}

object RadioInventory {
    private val mac = Regex("(?:[0-9A-F]{2}:){5}[0-9A-F]{2}")

    fun normalized(row: InventoryRadio): InventoryRadio {
        val address = row.identifier.trim().uppercase()
        require(mac.matches(address)) { "Invalid radio address." }
        require(row.transport != AssessmentTransport.NETWORK) { "Network discovery is not part of this collector." }
        require((row.firstSeen == null) == (row.lastSeen == null)) { "Incomplete observation timestamps." }
        require(row.firstSeen == null || (row.firstSeen > 0 && row.lastSeen!! >= row.firstSeen)) { "Invalid observation timestamps." }
        require(row.source != InventorySource.BONDED_RECORD || (row.lastSeen == null && row.rssi == null)) {
            "Pairing history is not a current observation."
        }
        require(row.source == InventorySource.BONDED_RECORD || row.lastSeen != null) { "An observed radio needs a timestamp." }
        require(when (row.source) {
            InventorySource.WIFI_SCAN -> row.transport == AssessmentTransport.WIFI
            InventorySource.BLE_ADVERTISEMENT -> row.transport == AssessmentTransport.BLE
            InventorySource.CLASSIC_INQUIRY -> row.transport == AssessmentTransport.BLUETOOTH_CLASSIC
            InventorySource.BONDED_RECORD -> row.transport == AssessmentTransport.BLE || row.transport == AssessmentTransport.BLUETOOTH_CLASSIC
        }) { "Collector source and transport disagree." }
        return row.copy(identifier = address, name = row.name.trim().take(100),
            rssi = row.rssi?.takeIf { it in -127..20 }, vendor = row.vendor?.take(120),
            deviceClass = row.deviceClass?.and(0x1FFC))
    }

    fun fromSighting(sighting: Sighting): InventoryRadio = normalized(InventoryRadio(
        identifier = sighting.mac,
        name = sighting.name.takeUnless { it.equals(sighting.mac, true) }.orEmpty(),
        transport = if (sighting.kind == RadioKind.WIFI) AssessmentTransport.WIFI else AssessmentTransport.BLE,
        source = if (sighting.kind == RadioKind.WIFI) InventorySource.WIFI_SCAN else InventorySource.BLE_ADVERTISEMENT,
        firstSeen = sighting.firstSeen,
        lastSeen = sighting.lastSeen,
        rssi = sighting.rssi.takeIf { Rssi.measured(it) },
        vendor = sighting.vendor,
    ))

    /** Exact address+transport merge only; no inferred dual-mode identity or MAC de-randomization. */
    fun merge(live: List<InventoryRadio>, bluetooth: List<InventoryRadio>): List<InventoryRadio> {
        val rows = linkedMapOf<String, InventoryRadio>()
        (bluetooth + live).forEach { raw ->
            val row = normalized(raw)
            val previous = rows[row.key]
            if (previous == null) rows[row.key] = row else {
                val preferred = if ((row.lastSeen ?: 0L) >= (previous.lastSeen ?: 0L)) row else previous
                val other = if (preferred === row) previous else row
                rows[row.key] = preferred.copy(
                    name = preferred.name.ifBlank { other.name }, paired = row.paired || previous.paired,
                    dualMode = row.dualMode || previous.dualMode,
                    deviceClass = preferred.deviceClass ?: other.deviceClass,
                    vendor = preferred.vendor ?: other.vendor,
                    firstSeen = listOfNotNull(row.firstSeen, previous.firstSeen).minOrNull(),
                )
            }
        }
        return rows.values.sortedWith(compareByDescending<InventoryRadio> { it.lastSeen ?: 0L }
            .thenBy { it.transport.name }.thenBy { it.identifier })
    }

    fun filter(rows: List<InventoryRadio>, query: String, transport: AssessmentTransport?, observedOnly: Boolean,
        pairedOnly: Boolean): List<InventoryRadio> {
        val text = query.trim()
        return rows.filter { row ->
            (transport == null || row.transport == transport) && (!observedOnly || row.lastSeen != null) &&
                (!pairedOnly || row.paired) && (text.isBlank() || row.name.contains(text, true) ||
                row.identifier.contains(text, true) || row.vendor?.contains(text, true) == true)
        }
    }
}

/** A bounded session cache. Pairing refresh never invents an RSSI or observation timestamp. */
class BluetoothInventory(private val capacity: Int = 500) {
    init { require(capacity > 0) }
    private val rows = linkedMapOf<String, InventoryRadio>()
    var dropped: Int = 0
        private set
    var rejected: Int = 0
        private set

    fun refreshPaired(incoming: List<InventoryRadio>) {
        rows.replaceAll { _, row -> row.copy(paired = false) }
        incoming.forEach { raw ->
            val row = try { RadioInventory.normalized(raw.copy(source = InventorySource.BONDED_RECORD,
                firstSeen = null, lastSeen = null, rssi = null, paired = true)) }
            catch (_: IllegalArgumentException) { rejected++; return@forEach }
            val previous = rows[row.key]
            if (previous != null) rows[row.key] = previous.copy(paired = true,
                name = row.name.ifBlank { previous.name }, deviceClass = row.deviceClass ?: previous.deviceClass,
                dualMode = row.dualMode, transportConfirmed = row.transportConfirmed)
            else put(row)
        }
        rows.entries.removeAll { !it.value.paired && it.value.lastSeen == null }
    }

    fun observe(raw: InventoryRadio) {
        val row = try { RadioInventory.normalized(raw) }
        catch (_: IllegalArgumentException) { rejected++; return }
        if (row.source != InventorySource.CLASSIC_INQUIRY) { rejected++; return }
        val previous = rows[row.key]
        put(if (previous == null) row else row.copy(
            firstSeen = listOfNotNull(previous.firstSeen, row.firstSeen).minOrNull(),
            lastSeen = maxOf(previous.lastSeen ?: 0, row.lastSeen!!),
            name = row.name.ifBlank { previous.name },
            paired = row.paired || previous.paired,
            rssi = if ((row.lastSeen ?: 0) >= (previous.lastSeen ?: 0)) row.rssi else previous.rssi,
            deviceClass = row.deviceClass ?: previous.deviceClass,
        ))
    }

    fun snapshot(): List<InventoryRadio> = rows.values.toList()
    fun reject() { rejected++ }
    fun clear() { rows.clear(); dropped = 0; rejected = 0 }

    private fun put(row: InventoryRadio) {
        if (row.key !in rows && rows.size >= capacity) {
            val victim = rows.values.filterNot { it.paired }.minByOrNull { it.lastSeen ?: 0 }
            if (victim == null) { dropped++; return }
            rows.remove(victim.key)
            dropped++
        }
        rows[row.key] = row
    }
}
