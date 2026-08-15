package com.sideinstaller.host

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ChaCha20-Poly1305 AEAD, matching Python's
 * cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305 usage:
 * 12-byte nonce, empty associated data, 16-byte auth tag appended to ciphertext.
 * Supported natively on Android API 28+.
 */
object ChaChaCipher {

    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        return cipher.doFinal(plaintext)
    }

    fun decrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        return cipher.doFinal(ciphertext)
    }
}
