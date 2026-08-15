package com.sideinstaller.host

import android.util.Log
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

/**
 * Responder side of Apple's rppairing protocol (device-initiated pairing).
 * Ported from pymobiledevice3's PairableHost (tunnel_service.py).
 */
class PairableHost(
    private val socket: Socket,
    private val identifier: String,
    private val hostName: String,
) {
    companion object {
        private const val TAG = "PairableHost"
        private const val SRP_USERNAME = "Pair-Setup"
    }

    private val input = DataInputStream(socket.getInputStream())
    private val output = DataOutputStream(socket.getOutputStream())
    private var sequenceNumber = 0

    var sessionKey: ByteArray? = null
        private set

    fun acceptHandshakeAndSrp(onPinReady: (String) -> Unit): SrpSetupResult {
        handshake()
        return pairSetupSrpPhase(onPinReady)
    }

    // ---- Handshake ----

    private fun handshake() {
        Log.d(TAG, "Waiting for device handshake request")
        val request = receivePlain()
        val handshakeReq = request
            .optJSONObject("request")?.optJSONObject("_0")?.optJSONObject("handshake")?.optJSONObject("_0")
            ?: throw PairingProtocolException("missing request._0.handshake._0 in device handshake")

        val hostOptions = handshakeReq.optJSONObject("hostOptions")
        if (hostOptions?.optBoolean("attemptPairVerify", false) == true) {
            throw PairingProtocolException("device requested pair-verify; only pair-setup is supported")
        }

        val peerDeviceInfo = JSONObject().apply {
            put("udid", "")
            put("deviceKVSIncludesSensitiveInfo", false)
            put("identifier", identifier)
            put("name", hostName)
            put("model", "Mac17,7")
        }

        val response = JSONObject().apply {
            put("response", JSONObject().apply {
                put("forRequestIdentifier", 0)
                put("_1", JSONObject().apply {
                    put("handshake", JSONObject().apply {
                        put("_0", JSONObject().apply {
                            put("wireProtocolVersion", 26)
                            put("minimumSupportedWireProtocolVersion", 8)
                            put("deviceOptions", JSONObject().apply {
                                put("allowsPairSetup", true)
                                put("allowsPinlessPairing", false)
                                put("allowsIncomingTunnelConnections", false)
                                put("allowsUpgradeOfLockdownPairings", false)
                                put("allowsSharingSensitiveInfo", false)
                            })
                            put("peerDeviceInfo", peerDeviceInfo)
                        })
                    })
                })
            })
        }
        sendPlain(response)
    }

    // ---- SRP pair-setup (M1-M4) ----

    data class SrpSetupResult(
        val srp: SrpContext,
        val sessionKey: ByteArray,
        val clientPublic: BigInteger
    )

    private fun pairSetupSrpPhase(onPinReady: (String) -> Unit): SrpSetupResult {
        Log.d(TAG, "Waiting for pair-setup M1")
        val m1 = TLV8.decode(receivePairingData())
        expectState(m1, 1)

        val saltBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        saltBytes[0] = (saltBytes[0].toInt() or 0x80).toByte()
        val saltInt = BigInteger(1, saltBytes)

        val pin = String.format("%06d", SecureRandom().nextInt(1_000_000))
        val srp = SrpContext.createPair3072(SRP_USERNAME)

        val passwordHash = srp.getCommonPasswordHash(saltInt, pin)
        val verifier = srp.getCommonPasswordVerifier(passwordHash)

        var serverPrivate: BigInteger
        var serverPublic: BigInteger
        while (true) {
            serverPrivate = srp.generateServerPrivate()
            serverPublic = srp.getServerPublic(verifier, serverPrivate)
            if (unsignedByteLength(serverPublic) == 384) break
        }

        onPinReady(pin)
        Log.i(TAG, "Enter this code on your device: $pin")

        val m2Items = mutableListOf(
            TLVItem(TLVType.STATE, byteArrayOf(2)),
            TLVItem(TLVType.SALT, saltBytes)
        )
        m2Items += TLV8.chunk(TLVType.PUBLIC_KEY, bigIntToUnsignedBytes(serverPublic))
        Log.d(TAG, "Sending pair-setup M2 (salt + B)")
        sendPairingData(TLV8.encode(m2Items))

        Log.d(TAG, "Waiting for pair-setup M3")
        val m3 = TLV8.decode(receivePairingData())
        ensureNoError(m3)
        expectState(m3, 3)
        val clientPublicBytes = m3[TLVType.PUBLIC_KEY]
            ?: throw PairingProtocolException("pair-setup M3 missing public key")
        val clientProof = m3[TLVType.PROOF]
            ?: throw PairingProtocolException("pair-setup M3 missing proof")
        val clientPublic = BigInteger(1, clientPublicBytes)

        val commonSecret = srp.getCommonSecret(clientPublic, serverPublic)
        val premaster = srp.getServerPremasterSecret(verifier, serverPrivate, clientPublic, commonSecret)
        val sessionKeyBytes = srp.getCommonSessionKey(premaster)

        val expectedClientProof = srp.computeSessionKeyProof(saltInt, clientPublic, serverPublic, sessionKeyBytes)
        if (!expectedClientProof.contentEquals(clientProof)) {
            Log.w(TAG, "SRP client proof verification failed (wrong PIN?)")
            sendPairingData(TLV8.encode(listOf(
                TLVItem(TLVType.STATE, byteArrayOf(4)),
                TLVItem(TLVType.ERROR, byteArrayOf(2))
            )))
            throw PairingProtocolException("SRP authentication failed (wrong PIN?)")
        }

        Log.d(TAG, "Sending pair-setup M4 (server proof)")
        val serverProof = srp.computeSessionKeyProofHash(clientPublic, clientProof, sessionKeyBytes)
        sendPairingData(TLV8.encode(listOf(
            TLVItem(TLVType.STATE, byteArrayOf(4)),
            TLVItem(TLVType.PROOF, serverProof)
        )))

        this.sessionKey = sessionKeyBytes
        return SrpSetupResult(srp, sessionKeyBytes, clientPublic)
    }

    // ---- M5/M6: identity exchange ----

    data class PeerDeviceInfo(
        val accountId: String,
        val altIrk: ByteArray,
        val model: String,
        val name: String,
        val udid: String
    )

    fun completeIdentityExchange(
        srpResult: SrpSetupResult,
        hostAltIrk: ByteArray,
        ed25519: Ed25519KeyPair
    ): PeerDeviceInfo {
        val sessionKey = srpResult.sessionKey

        val setupEncryptionKey = Hkdf.derive(
            ikm = sessionKey,
            salt = "Pair-Setup-Encrypt-Salt".toByteArray(Charsets.UTF_8),
            info = "Pair-Setup-Encrypt-Info".toByteArray(Charsets.UTF_8),
            length = 32
        )

        Log.d(TAG, "Waiting for pair-setup M5 (device identity)")
        val m5 = TLV8.decode(receivePairingData())
        ensureNoError(m5)
        expectState(m5, 5)
        val encryptedM5 = m5[TLVType.ENCRYPTED_DATA]
            ?: throw PairingProtocolException("pair-setup M5 missing encrypted data")

        val m5Nonce = "\u0000\u0000\u0000\u0000PS-Msg05".toByteArray(Charsets.US_ASCII)
        val m5Plaintext = ChaChaCipher.decrypt(setupEncryptionKey, m5Nonce, encryptedM5)
        val deviceTlv = TLV8.decode(m5Plaintext)

        val infoBytes = deviceTlv[TLVType.INFO]
            ?: throw PairingProtocolException("pair-setup M5 identity missing INFO field")
        @Suppress("UNCHECKED_CAST")
        val infoMap = OPackDecode.loads(infoBytes) as Map<String, Any>

        val altIrk = infoMap["altIRK"] as? ByteArray
            ?: throw PairingProtocolException("peer device info missing altIRK")
        val peerDevice = PeerDeviceInfo(
            accountId = infoMap["accountID"] as? String ?: "",
            altIrk = altIrk,
            model = infoMap["model"] as? String ?: "",
            name = infoMap["name"] as? String ?: "",
            udid = infoMap["remotepairing_udid"] as? String ?: ""
        )

        Log.d(TAG, "Sending pair-setup M6 (our identity)")
        val accessoryX = Hkdf.derive(
            ikm = sessionKey,
            salt = "Pair-Setup-Accessory-Sign-Salt".toByteArray(Charsets.UTF_8),
            info = "Pair-Setup-Accessory-Sign-Info".toByteArray(Charsets.UTF_8),
            length = 32
        )
        val ltpk = ed25519.publicKeyRaw
        val signBuf = accessoryX + identifier.toByteArray(Charsets.UTF_8) + ltpk
        val signature = ed25519.sign(signBuf)

        val deviceInfo = linkedMapOf<String, Any>(
            "altIRK" to hostAltIrk,
            "btAddr" to "11:22:33:44:55:66",
            "mac" to byteArrayOf(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
            "remotepairing_serial_number" to "AAAAAAAAAAAA",
            "accountID" to identifier,
            "model" to "Mac17,7",
            "name" to hostName
        )
        val infoEncoded = OPack.dumps(deviceInfo)

        val m6Plain = TLV8.encode(listOf(
            TLVItem(TLVType.IDENTIFIER, identifier.toByteArray(Charsets.UTF_8)),
            TLVItem(TLVType.PUBLIC_KEY, ltpk),
            TLVItem(TLVType.SIGNATURE, signature),
            TLVItem(TLVType.INFO, infoEncoded)
        ))

        val m6Nonce = "\u0000\u0000\u0000\u0000PS-Msg06".toByteArray(Charsets.US_ASCII)
        val m6Cipher = ChaChaCipher.encrypt(setupEncryptionKey, m6Nonce, m6Plain)

        val m6Items = mutableListOf<TLVItem>()
        m6Items += TLV8.chunk(TLVType.ENCRYPTED_DATA, m6Cipher)
        m6Items.add(TLVItem(TLVType.STATE, byteArrayOf(6)))
        sendPairingData(TLV8.encode(m6Items))

        return peerDevice
    }

    // ---- Low-level framing ----

    private fun sendPairingData(tlvData: ByteArray) {
        val payload = JSONObject().apply {
            put("data", android.util.Base64.encodeToString(tlvData, android.util.Base64.NO_WRAP))
            put("startNewSession", false)
            put("kind", "setupManualPairing")
        }
        val event = JSONObject().apply {
            put("event", JSONObject().apply {
                put("_0", JSONObject().apply {
                    put("pairingData", JSONObject().apply { put("_0", payload) })
                })
            })
        }
        sendPlain(event)
    }

    private fun receivePairingData(): ByteArray {
        val response = receivePlain()
        val event = response.optJSONObject("event")?.optJSONObject("_0")
            ?: throw PairingProtocolException("missing event._0 in response")
        if (event.has("pairingData")) {
            val dataB64 = event.getJSONObject("pairingData").getJSONObject("_0").getString("data")
            return android.util.Base64.decode(dataB64, android.util.Base64.NO_WRAP)
        }
        if (event.has("pairingRejectedWithError")) {
            throw PairingProtocolException("device rejected pairing: ${event.opt("pairingRejectedWithError")}")
        }
        throw PairingProtocolException("unknown state message: $response")
    }

    private fun sendPlain(value: JSONObject) {
        val envelope = JSONObject().apply {
            put("message", JSONObject().apply {
                put("plain", JSONObject().apply { put("_0", value) })
            })
            put("originatedBy", "device")
            put("sequenceNumber", sequenceNumber)
        }
        val bodyBytes = envelope.toString().toByteArray(StandardCharsets.UTF_8)
        output.write(RPPairingPacket.encode(bodyBytes))
        output.flush()
        sequenceNumber += 1
    }

    private fun receivePlain(): JSONObject {
        val magic = ByteArray(RPPairingPacket.MAGIC.size)
        input.readFully(magic)
        if (!magic.contentEquals(RPPairingPacket.MAGIC)) {
            throw PairingProtocolException("bad RPPairing magic")
        }
        val sizeBytes = ByteArray(2)
        input.readFully(sizeBytes)
        val size = ((sizeBytes[0].toInt() and 0xFF) shl 8) or (sizeBytes[1].toInt() and 0xFF)
        val body = ByteArray(size)
        input.readFully(body)
        val envelope = JSONObject(String(body, StandardCharsets.UTF_8))
        return envelope.getJSONObject("message").getJSONObject("plain").getJSONObject("_0")
    }

    fun close() {
        try { socket.close() } catch (_: Exception) {}
    }

    // ---- Small utils ----

    private fun bigIntToUnsignedBytes(v: BigInteger): ByteArray {
        val bytes = v.toByteArray()
        return if (bytes.size > 1 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
    }

    private fun unsignedByteLength(v: BigInteger): Int = bigIntToUnsignedBytes(v).size

    private fun expectState(tlv: Map<Int, ByteArray>, expected: Int) {
        val state = tlv[TLVType.STATE]
        if (state == null || state.isEmpty() || state[0].toInt() != expected) {
            throw PairingProtocolException("unexpected pair-setup state: expected $expected, got ${state?.toList()}")
        }
    }

    private fun ensureNoError(tlv: Map<Int, ByteArray>) {
        tlv[TLVType.ERROR]?.let {
            throw PairingProtocolException("device returned pairing error: ${it.toList()}")
        }
    }
}

class PairingProtocolException(message: String) : Exception(message)
