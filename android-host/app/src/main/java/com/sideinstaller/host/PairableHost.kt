package com.sideinstaller.host

import android.util.Log
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Responder side of Apple's rppairing protocol (device-initiated pairing).
 * Ported from pymobiledevice3's PairableHost (tunnel_service.py).
 *
 * This class handles the socket-level framing and the SRP pair-setup
 * handshake (M1-M4). Identity exchange (M5/M6, which needs opack encoding)
 * is wired in separately.
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

    // Populated once pair-setup completes.
    var sessionKey: ByteArray? = null
        private set

    /** Runs the handshake, then the full SRP pair-setup. Returns the 6-digit PIN shown to the user. */
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
        // M1: device starts pair-setup
        Log.d(TAG, "Waiting for pair-setup M1")
        val m1 = TLV8.decode(receivePairingData())
        expectState(m1, 1)

        // M2: send salt + server public (B)
        val saltBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
        saltBytes[0] = (saltBytes[0].toInt() or 0x80).toByte() // keep stable 16-byte representation
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
            // Match srptools' retry-until-full-width behavior for the 3072-bit group (384 bytes).
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

        // M3: device sends its public (A) and proof (M1 client proof)
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
                TLVItem(TLVType.ERROR, byteArrayOf(2)) // kTLVError_Authentication
            )))
            throw PairingProtocolException("SRP authentication failed (wrong PIN?)")
        }

        // M4: send server proof
        Log.d(TAG, "Sending pair-setup M4 (server proof)")
        val serverProof = srp.computeSessionKeyProofHash(clientPublic, clientProof, sessionKeyBytes)
        sendPairingData(TLV8.encode(listOf(
            TLVItem(TLVType.STATE, byteArrayOf(4)),
            TLVItem(TLVType.PROOF, serverProof)
        )))

        this.sessionKey = sessionKeyBytes
        return SrpSetupResult(srp, sessionKeyBytes, clientPublic)
    }

    // ---- Helpers used by M5/M6 (wired in next) ----

    fun sendPairingDataPublic(data: ByteArray) = sendPairingData(data)
    fun receivePairingDataPublic(): ByteArray = receivePairingData()

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
