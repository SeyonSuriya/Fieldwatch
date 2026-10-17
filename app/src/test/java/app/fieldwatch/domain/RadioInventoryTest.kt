package app.fieldwatch.domain

import org.junit.Assert.*
import org.junit.Test

class RadioInventoryTest {
    private fun observed(address: String = "AA:BB:CC:00:00:01", at: Long = 1000) = InventoryRadio(
        address, "Speaker", AssessmentTransport.BLUETOOTH_CLASSIC, InventorySource.CLASSIC_INQUIRY,
        firstSeen = at, lastSeen = at, rssi = -60,
    )
    private fun paired(address: String = "AA:BB:CC:00:00:01", transport: AssessmentTransport = AssessmentTransport.BLUETOOTH_CLASSIC) =
        InventoryRadio(address, "Paired device", transport, InventorySource.BONDED_RECORD, paired = true)

    @Test fun pairedHistoryHasNoInferredPresenceOrSignal() {
        val cache = BluetoothInventory()
        cache.refreshPaired(listOf(paired()))
        val row = cache.snapshot().single()
        assertTrue(row.paired)
        assertNull(row.firstSeen)
        assertNull(row.lastSeen)
        assertNull(row.rssi)
        assertEquals(InventorySource.BONDED_RECORD, row.source)
    }

    @Test fun freshInquiryPreservesFirstSeenWhileUpdatingMeasuredValues() {
        val cache = BluetoothInventory()
        cache.refreshPaired(listOf(paired()))
        cache.observe(observed(at = 1000))
        cache.observe(observed(at = 2000).copy(rssi = -45))
        val row = cache.snapshot().single()
        assertEquals(1000L, row.firstSeen)
        assertEquals(2000L, row.lastSeen)
        assertEquals(-45, row.rssi)
        assertTrue(row.paired)
        assertEquals(InventorySource.CLASSIC_INQUIRY, row.source)
    }

    @Test fun absentRssiDoesNotReuseAnOlderMeasurementAsCurrent() {
        val cache = BluetoothInventory()
        cache.observe(observed())
        cache.observe(observed(at = 2000).copy(rssi = null))
        assertNull(cache.snapshot().single().rssi)
        assertEquals(2000L, cache.snapshot().single().lastSeen)
    }

    @Test fun pairingRefreshDoesNotRefreshObservationTimestamps() {
        val cache = BluetoothInventory()
        cache.observe(observed())
        cache.refreshPaired(listOf(paired()))
        assertEquals(1000L, cache.snapshot().single().lastSeen)
        assertEquals(InventorySource.CLASSIC_INQUIRY, cache.snapshot().single().source)
        cache.refreshPaired(emptyList())
        assertFalse(cache.snapshot().single().paired)
        assertEquals(1000L, cache.snapshot().single().lastSeen)
    }

    @Test fun removedUnobservedPairingRecordsDisappearOnRefresh() {
        val cache = BluetoothInventory()
        cache.refreshPaired(listOf(paired()))
        cache.refreshPaired(emptyList())
        assertTrue(cache.snapshot().isEmpty())
    }

    @Test fun sameAddressDifferentTransportsAreNotMergedIntoOneDevice() {
        val classic = observed()
        val ble = classic.copy(transport = AssessmentTransport.BLE, source = InventorySource.BLE_ADVERTISEMENT)
        val wifi = classic.copy(transport = AssessmentTransport.WIFI, source = InventorySource.WIFI_SCAN)
        val merged = RadioInventory.merge(listOf(ble, wifi), listOf(classic))
        assertEquals(3, merged.size)
        assertEquals(3, merged.map { it.key }.toSet().size)
    }

    @Test fun pairedBleMetadataMergesWithObservedBleWithoutLosingProvenance() {
        val ble = observed(at = 2000).copy(transport = AssessmentTransport.BLE, source = InventorySource.BLE_ADVERTISEMENT)
        val merged = RadioInventory.merge(listOf(ble), listOf(paired(transport = AssessmentTransport.BLE))).single()
        assertTrue(merged.paired)
        assertEquals(2000L, merged.lastSeen)
        assertEquals(InventorySource.BLE_ADVERTISEMENT, merged.source)
    }

    @Test fun invalidAndMismatchedInputsAreRejected() {
        val cache = BluetoothInventory()
        cache.observe(observed("bad-address"))
        cache.observe(observed().copy(transport = AssessmentTransport.BLE))
        assertEquals(2, cache.rejected)
        assertTrue(cache.snapshot().isEmpty())
        assertThrows(IllegalArgumentException::class.java) {
            RadioInventory.normalized(paired().copy(rssi = -70))
        }
    }

    @Test fun addressNamesSignalAndDeviceClassAreNormalized() {
        val row = RadioInventory.normalized(observed("aa:bb:cc:00:00:01").copy(name = "  ${"x".repeat(200)} ", rssi = Short.MIN_VALUE.toInt(), deviceClass = 0xFFFFFF))
        assertEquals("AA:BB:CC:00:00:01", row.identifier)
        assertEquals(100, row.name.length)
        assertNull(row.rssi)
        assertEquals(0x1FFC, row.deviceClass)
    }

    @Test fun boundedCacheEvictsOldestUnpairedRecordAndReportsLoss() {
        val cache = BluetoothInventory(2)
        cache.observe(observed("AA:BB:CC:00:00:01", 1000))
        cache.observe(observed("AA:BB:CC:00:00:02", 2000))
        cache.observe(observed("AA:BB:CC:00:00:03", 3000))
        assertEquals(2, cache.snapshot().size)
        assertFalse(cache.snapshot().any { it.identifier.endsWith("01") })
        assertEquals(1, cache.dropped)
    }

    @Test fun fullPairedCacheDropsNewRowsWithoutUnboundedGrowth() {
        val cache = BluetoothInventory(1)
        cache.refreshPaired(listOf(paired()))
        cache.observe(observed("AA:BB:CC:00:00:02"))
        assertEquals(1, cache.snapshot().size)
        assertEquals(1, cache.dropped)
        assertTrue(cache.snapshot().single().paired)
    }

    @Test fun searchAndFiltersDoNotMistakePairingForAnObservation() {
        val rows = RadioInventory.merge(emptyList(), listOf(observed(), paired("AA:BB:CC:00:00:02")))
        assertEquals(1, RadioInventory.filter(rows, "speaker", null, false, false).size)
        assertEquals(1, RadioInventory.filter(rows, "", null, true, false).size)
        assertEquals(1, RadioInventory.filter(rows, "", null, false, true).size)
        assertTrue(RadioInventory.filter(rows, "", AssessmentTransport.WIFI, false, false).isEmpty())
    }

    @Test fun outOfOrderObservationDoesNotMoveLastSeenBackwards() {
        val cache = BluetoothInventory()
        cache.observe(observed(at = 2000).copy(rssi = -40))
        cache.observe(observed(at = 1000).copy(rssi = -90))
        val row = cache.snapshot().single()
        assertEquals(1000L, row.firstSeen)
        assertEquals(2000L, row.lastSeen)
        assertEquals(-40, row.rssi)
    }
}
