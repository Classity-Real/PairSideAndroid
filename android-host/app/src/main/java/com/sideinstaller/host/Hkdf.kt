package com.sideinstaller.host

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF (RFC 5869) using HMAC-SHA512, matching Python's
 * cryptography.hazmat.primitives.kdf.hkdf.HKDF(algorithm=hashes.SHA512(), ...).
 *
 * Android's standard crypto providers do not ship a ready-made HKDF class,
 * so this implements the extract-then-expand construction directly via HMAC.
 */
object Hkdf {

    private const val HASH_LEN = 64 // SHA-512 output size in bytes
    private const val ALGORITHM = "HmacSHA512"

    /**
     * Derive [length] bytes of key material from [ikm] (input keying material),
     * using the given [salt] and [info].
     *
     * Matches: HKDF(algorithm=hashes.SHA512(), length=length, salt=salt, info=info).derive(ikm)
     */
    fun derive(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val actualSalt = salt ?: ByteArray(HASH_LEN) // RFC 5869: if salt is None, use HashLen zero bytes
        val prk = hmac(actualSalt, ikm)          // Extract
        return expand(prk, info, length)          // Expand
    }

    private fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val n = (length + HASH_LEN - 1) / HASH_LEN
        require(n <= 255) { "HKDF: requested length too large" }

        val output = ByteArray(n * HASH_LEN)
        var previousBlock = ByteArray(0)
        var offset = 0

        for (i in 1..n) {
            val input = previousBlock + info + byteArrayOf(i.toByte())
            val block = hmac(prk, input)
            block.copyInto(output, offset)
            offset += HASH_LEN
            previousBlock = block
        }

        return output.copyOfRange(0, length)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        // HMAC allows an empty key in RFC 2104, but Android's SecretKeySpec rejects
        // zero-length keys, so substitute a single zero byte in that edge case.
        val keyBytes = if (key.isEmpty()) ByteArray(1) else key
        mac.init(SecretKeySpec(keyBytes, ALGORITHM))
        return mac.doFinal(data)
    }
}
