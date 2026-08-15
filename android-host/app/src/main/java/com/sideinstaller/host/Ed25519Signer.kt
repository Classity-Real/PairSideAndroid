package com.sideinstaller.host

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer as BcEd25519Signer
import java.security.SecureRandom

/** Thin wrapper around BouncyCastle's Ed25519 for accessory identity signing. */
class Ed25519KeyPair private constructor(
    private val privateKey: Ed25519PrivateKeyParameters
) {
    val publicKeyRaw: ByteArray by lazy { privateKey.generatePublicKey().encoded }

    fun sign(message: ByteArray): ByteArray {
        val signer = BcEd25519Signer()
        signer.init(true, privateKey)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    companion object {
        fun generate(): Ed25519KeyPair {
            val gen = Ed25519KeyPairGenerator()
            gen.init(Ed25519KeyGenerationParameters(SecureRandom()))
            val pair: AsymmetricCipherKeyPair = gen.generateKeyPair()
            return Ed25519KeyPair(pair.private as Ed25519PrivateKeyParameters)
        }
    }
}
