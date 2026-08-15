package com.sideinstaller.host

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * SRP-6a (RFC 2945 / RFC 5054) context, ported to match idlesign/srptools' exact
 * byte-level semantics (hash input encoding, padding rules) so it interoperates
 * with Apple's RemotePairing use of srptools on the host side.
 *
 * Only the "server" (accessory/responder) operations are implemented, since this
 * app always plays PairableHost's role, never the connecting client.
 */
class SrpContext(
    private val username: String,
    private val prime: BigInteger,
    private val generator: BigInteger,
) {
    // N's byte length; used for padding (PAD()) throughout.
    private val primeByteLen: Int = unsignedBytes(prime).size

    // k = H(N | PAD(g))  -- RFC 5054 multiplier
    private val multiplier: BigInteger = hashInt(unsignedBytes(prime), pad(generator))

    /** Returns the minimal big-endian unsigned byte representation of a non-negative BigInteger. */
    private fun unsignedBytes(v: BigInteger): ByteArray {
        val bytes = v.toByteArray()
        // BigInteger.toByteArray() may prepend a 0x00 sign byte; strip it if present and not needed.
        return if (bytes.size > 1 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
    }

    /** PAD(val): zero-pad val's unsigned bytes to N's byte length, matching SRPContext.pad(). */
    private fun pad(v: BigInteger): ByteArray {
        val raw = unsignedBytes(v)
        if (raw.size >= primeByteLen) return raw
        val out = ByteArray(primeByteLen)
        raw.copyInto(out, primeByteLen - raw.size)
        return out
    }

    /** Converts one hash() argument to bytes, matching SRPContext.hash()'s conv(). */
    private fun convArg(arg: Any): ByteArray = when (arg) {
        is BigInteger -> unsignedBytes(arg)
        is String -> arg.toByteArray(Charsets.UTF_8)
        is ByteArray -> arg
        else -> throw IllegalArgumentException("Unsupported hash arg type: ${arg::class}")
    }

    /** SHA-512 digest of the concatenation of args (each converted, joined by [joiner]). */
    private fun hashBytes(vararg args: Any, joiner: String = ""): ByteArray {
        val joinerBytes = joiner.toByteArray(Charsets.UTF_8)
        val parts = args.map { convArg(it) }
        val out = java.io.ByteArrayOutputStream()
        for ((i, part) in parts.withIndex()) {
            if (i > 0 && joinerBytes.isNotEmpty()) out.write(joinerBytes)
            out.write(part)
        }
        val md = MessageDigest.getInstance("SHA-512")
        return md.digest(out.toByteArray())
    }

    /** Same as hashBytes, but returns the digest interpreted as an unsigned big-endian int
     *  (matches SRPContext.hash()'s default as_bytes=False: int_from_hex(hexdigest())). */
    private fun hashInt(vararg args: Any, joiner: String = ""): BigInteger =
        BigInteger(1, hashBytes(*args, joiner = joiner))

    // ---- Server-side SRP operations ----

    /** x = H(s | H(I | ":" | P)) — salt as BigInteger (see PairableHost salt handling). */
    fun getCommonPasswordHash(salt: BigInteger, password: String): BigInteger {
        val inner = hashBytes(username, password, joiner = ":")
        return hashInt(salt, inner)
    }

    /** v = g^x % N */
    fun getCommonPasswordVerifier(passwordHash: BigInteger): BigInteger =
        generator.modPow(passwordHash, prime)

    /** b = random private value. srptools defaults to 1024 bits ("bits_random"); matched here. */
    fun generateServerPrivate(): BigInteger {
        val bytes = ByteArray(128) // 1024 bits
        SecureRandom().nextBytes(bytes)
        return BigInteger(1, bytes)
    }

    /** B = (k*v + g^b) % N */
    fun getServerPublic(passwordVerifier: BigInteger, serverPrivate: BigInteger): BigInteger {
        val term = (multiplier.multiply(passwordVerifier)).mod(prime)
        val gb = generator.modPow(serverPrivate, prime)
        return term.add(gb).mod(prime)
    }

    /** u = H(PAD(A) | PAD(B)) */
    fun getCommonSecret(clientPublic: BigInteger, serverPublic: BigInteger): BigInteger =
        hashInt(pad(clientPublic), pad(serverPublic))

    /** S = (A * v^u) ^ b % N */
    fun getServerPremasterSecret(
        passwordVerifier: BigInteger,
        serverPrivate: BigInteger,
        clientPublic: BigInteger,
        commonSecret: BigInteger
    ): BigInteger {
        val vu = passwordVerifier.modPow(commonSecret, prime)
        val base = clientPublic.multiply(vu).mod(prime)
        return base.modPow(serverPrivate, prime)
    }

    /** K = H(S) — NOTE: uses minimal (unpadded) bytes of S, matching srptools exactly. */
    fun getCommonSessionKey(premasterSecret: BigInteger): ByteArray =
        hashBytes(premasterSecret)

    /**
     * Compute the expected client proof M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K),
     * to compare against what the client actually sent.
     * salt must be the same BigInteger form used in getCommonPasswordHash.
     */
    fun computeSessionKeyProof(
        salt: BigInteger,
        clientPublic: BigInteger,
        serverPublic: BigInteger,
        sessionKey: ByteArray
    ): ByteArray {
        val hN = hashInt(unsignedBytes(prime))
        val hG = hashInt(unsignedBytes(generator))
        val xorVal = hN.xor(hG)
        val hUser = hashInt(username)
        return hashBytes(xorVal, hUser, salt, clientPublic, serverPublic, sessionKey)
    }

    /** M2 = H(A | M1 | K) — server's proof sent back to the client. */
    fun computeSessionKeyProofHash(
        clientPublic: BigInteger,
        sessionKeyProof: ByteArray,
        sessionKey: ByteArray
    ): ByteArray = hashBytes(clientPublic, sessionKeyProof, sessionKey)

    companion object {
        /**
         * RFC 5054 3072-bit MODP group prime, verified byte-for-byte against
         * idlesign/srptools' constants.py PRIME_3072.
         */
        private const val PRIME_3072_HEX =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6" +
            "3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411" +
            "7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08" +
            "CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
            "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8760273" +
            "3EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
            "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

        private const val PRIME_3072_GEN_HEX = "5"

        fun createPair3072(username: String): SrpContext {
            val n = BigInteger(PRIME_3072_HEX, 16)
            val g = BigInteger(PRIME_3072_GEN_HEX, 16)
            return SrpContext(username, n, g)
        }
    }
}
