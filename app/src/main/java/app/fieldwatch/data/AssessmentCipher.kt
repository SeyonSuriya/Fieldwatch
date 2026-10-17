package app.fieldwatch.data

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

interface AssessmentCipher {
    fun encrypt(plain: ByteArray): ByteArray
    fun decrypt(sealed: ByteArray): ByteArray
}

/** Versioned authenticated envelope. The JCA provider supplies a fresh IV for each encryption. */
class AesGcmAssessmentCipher(private val key: () -> SecretKey) : AssessmentCipher {
    private val header = "FWVAULT1".toByteArray(Charsets.US_ASCII)

    override fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(header)
        require(cipher.iv.size == 12) { "Unexpected encryption IV length." }
        return header + cipher.iv + cipher.doFinal(plain)
    }

    override fun decrypt(sealed: ByteArray): ByteArray {
        require(sealed.size >= header.size + 12 + 16 &&
            sealed.copyOfRange(0, header.size).contentEquals(header)) { "Invalid assessment vault envelope." }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed.copyOfRange(header.size, header.size + 12)))
        cipher.updateAAD(header)
        return cipher.doFinal(sealed, header.size + 12, sealed.size - header.size - 12)
    }
}
