package com.sideinstaller.host

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * TLV8 component types used in Apple's pairing protocol (HAP-style).
 * Mirrors PairingDataComponentType from pymobiledevice3/remote/tunnel_service.py
 */
object TLVType {
    const val METHOD: Int = 0x00
    const val IDENTIFIER: Int = 0x01
    const val SALT: Int = 0x02
    const val PUBLIC_KEY: Int = 0x03
    const val PROOF: Int = 0x04
    const val ENCRYPTED_DATA: Int = 0x05
    const val STATE: Int = 0x06
    const val ERROR: Int = 0x07
    const val RETRY_DELAY: Int = 0x08
    const val CERTIFICATE: Int = 0x09
    const val SIGNATURE: Int = 0x0A
    const val PERMISSIONS: Int = 0x0B
    const val FRAGMENT_DATA: Int = 0x0C
    const val FRAGMENT_LAST: Int = 0x0D
    const val SESSION_ID: Int = 0x0E
    const val TTL: Int = 0x0F
    const val EXTRA_DATA: Int = 0x10
    const val INFO: Int = 0x11
    const val ACL: Int = 0x12
    const val FLAGS: Int = 0x13
    const val VALIDATION_DATA: Int = 0x14
    const val MFI_AUTH_TOKEN: Int = 0x15
    const val MFI_PRODUCT_TYPE: Int = 0x16
    const val SERIAL_NUMBER: Int = 0x17
    const val MFI_AUTH_TOKEN_UUID: Int = 0x18
    const val APP_FLAGS: Int = 0x19
    const val OWNERSHIP_PROOF: Int = 0x1A
    const val SETUP_CODE_TYPE: Int = 0x1B
    const val PRODUCTION_DATA: Int = 0x1C
    const val APP_INFO: Int = 0x1D
    const val SEPARATOR: Int = 0xFF
}

/** A single TLV8 (type, data) component before encoding. */
data class TLVItem(val type: Int, val data: ByteArray)

/** Max bytes per single TLV8 fragment (length is a single unsigned byte). */
const val TLV_MAX_FRAGMENT_SIZE = 0xFF

object TLV8 {

    /**
     * Encode a list of TLVItem into the wire format: [type:1][len:1][data:len] repeated.
     * Caller is responsible for pre-chunking values longer than 255 bytes via [chunk].
     */
    fun encode(items: List<TLVItem>): ByteArray {
        val out = ByteArrayOutputStream()
        for (item in items) {
            require(item.data.size <= TLV_MAX_FRAGMENT_SIZE) {
                "TLV item type=${item.type} has ${item.data.size} bytes; must be chunked first"
            }
            out.write(item.type and 0xFF)
            out.write(item.data.size and 0xFF)
            out.write(item.data)
        }
        return out.toByteArray()
    }

    /**
     * Decode a raw TLV8 byte buffer into a map of type -> concatenated data.
     * Matches pymobiledevice3's decode_tlv: repeated components of the same type
     * are concatenated in order (this is how values >255 bytes are reassembled).
     */
    fun decode(buf: ByteArray): Map<Int, ByteArray> {
        val result = LinkedHashMap<Int, ByteArrayOutputStream>()
        var i = 0
        while (i < buf.size) {
            val type = buf[i].toInt() and 0xFF
            val len = buf[i + 1].toInt() and 0xFF
            val start = i + 2
            val end = start + len
            require(end <= buf.size) { "TLV8 truncated at offset $i" }
            val chunkData = buf.copyOfRange(start, end)
            val existing = result.getOrPut(type) { ByteArrayOutputStream() }
            existing.write(chunkData)
            i = end
        }
        return result.mapValues { it.value.toByteArray() }
    }

    /** Split a value longer than 255 bytes into multiple same-typed TLV items. */
    fun chunk(type: Int, data: ByteArray): List<TLVItem> {
        if (data.isEmpty()) return listOf(TLVItem(type, data))
        val items = mutableListOf<TLVItem>()
        var offset = 0
        while (offset < data.size) {
            val end = minOf(offset + TLV_MAX_FRAGMENT_SIZE, data.size)
            items.add(TLVItem(type, data.copyOfRange(offset, end)))
            offset = end
        }
        return items
    }
}

/**
 * RPPairing wire framing: magic "RPPairing" + 2-byte big-endian length + JSON body.
 * Mirrors RPPairingPacketData from pymobiledevice3/remote/tunnel_service.py
 */
object RPPairingPacket {
    val MAGIC: ByteArray = "RPPairing".toByteArray(Charsets.US_ASCII)

    fun encode(bodyJson: ByteArray): ByteArray {
        require(bodyJson.size <= 0xFFFF) { "RPPairing body too large: ${bodyJson.size} bytes" }
        val buf = ByteBuffer.allocate(MAGIC.size + 2 + bodyJson.size).order(ByteOrder.BIG_ENDIAN)
        buf.put(MAGIC)
        buf.putShort(bodyJson.size.toShort())
        buf.put(bodyJson)
        return buf.array()
    }

    /** Length of just the magic + 2-byte length prefix, i.e. how many header bytes to read first. */
    val HEADER_SIZE: Int = MAGIC.size + 2
}
