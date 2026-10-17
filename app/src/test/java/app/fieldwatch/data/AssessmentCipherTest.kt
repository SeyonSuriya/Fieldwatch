package app.fieldwatch.data

import org.junit.Assert.*
import org.junit.Test
import javax.crypto.spec.SecretKeySpec

class AssessmentCipherTest {
    private val key = SecretKeySpec(ByteArray(32) { 1 }, "AES")

    @Test fun repeatedEncryptionUsesDifferentNoncesAndRoundTrips() {
        val cipher = AesGcmAssessmentCipher { key }
        val plain = "Sensitive evidence".toByteArray()
        val first = cipher.encrypt(plain)
        val second = cipher.encrypt(plain)
        assertFalse(first.contentEquals(second))
        assertArrayEquals(plain, cipher.decrypt(first))
        assertArrayEquals(plain, cipher.decrypt(second))
    }

    @Test fun modificationTruncationAndWrongKeysAreRejected() {
        val cipher = AesGcmAssessmentCipher { key }
        val bytes = cipher.encrypt("Evidence".toByteArray())
        val modified = bytes.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { cipher.decrypt(modified) }
        assertThrows(Exception::class.java) { cipher.decrypt(bytes.copyOf(10)) }
        val wrong = AesGcmAssessmentCipher { SecretKeySpec(ByteArray(32) { 2 }, "AES") }
        assertThrows(Exception::class.java) { wrong.decrypt(bytes) }
    }

    @Test fun changingEnvelopeVersionFailsClosed() {
        val cipher = AesGcmAssessmentCipher { key }
        val bytes = cipher.encrypt("Evidence".toByteArray()).apply { this[7] = '2'.code.toByte() }
        assertThrows(IllegalArgumentException::class.java) { cipher.decrypt(bytes) }
    }
}
