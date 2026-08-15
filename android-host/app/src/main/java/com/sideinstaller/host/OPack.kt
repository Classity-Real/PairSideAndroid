package com.sideinstaller.host

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal OPack encoder (Apple's binary dict/array/scalar format), ported from
 * doronz88/opack's opack_construct.py + object_types.py.
 *
 * Only encoding is implemented (decoding isn't needed for our use case: we only
 * ever build the M5/M6 identity INFO payload, never parse one from the device).
 * Supports the types PairableHost's device_info dict actually uses: String,
 * ByteArray, Boolean, Int, and Map<String, Any> (dict) - which covers altIRK,
 * btAddr, mac, remotepairing_serial_number, accountID, model, name, etc.
 */
object OPack {

    fun dumps(obj: Any?): ByteArray {
        val out = ByteArrayOutputStream()
        encodeValue(obj, out)
        return out.toByteArray()
    }

    private fun encodeValue(obj: Any?, out: ByteArrayOutputStream) {
        when (obj) {
            is Boolean -> encodeBool(obj, out)
            is Int -> encodeInt(obj.toLong(), out)
            is Long -> encodeInt(obj, out)
            is String -> encodeString(obj, out)
            is ByteArray -> encodeBytes(obj, out)
            is Map<*, *> -> encodeDict(obj, out)
            is List<*> -> encodeList(obj, out)
            null -> throw IllegalArgumentException("OPack: null values are not supported")
            else -> throw IllegalArgumentException("OPack: unsupported type ${obj::class}")
        }
    }

    // type tag 1 = true, 2 = false
    private fun encodeBool(v: Boolean, out: ByteArrayOutputStream) {
        out.write(if (v) 1 else 2)
    }

    // Matches _get_int_object_type: small ints (0..0x27) are packed directly into the tag byte;
    // larger ones get a tag (0x30/0x32/0x33) followed by the value in little-endian.
    private fun encodeInt(v: Long, out: ByteArrayOutputStream) {
        require(v >= 0) { "OPack: negative ints not supported by this minimal encoder" }
        when {
            v <= 0x27 -> out.write((v + 8).toInt())
            bitLength(v) <= 8 -> {
                out.write(0x30)
                out.write(v.toInt() and 0xFF)
            }
            bitLength(v) <= 32 -> {
                out.write(0x32)
                writeLE(out, v, 4)
            }
            bitLength(v) <= 64 -> {
                out.write(0x33)
                writeLE(out, v, 8)
            }
            else -> throw IllegalArgumentException("OPack: integer too large for uint64")
        }
    }

    private fun bitLength(v: Long): Int = 64 - java.lang.Long.numberOfLeadingZeros(v)

    private fun writeLE(out: ByteArrayOutputStream, v: Long, byteCount: Int) {
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array()
        out.write(buf, 0, byteCount)
    }

    // Matches _get_str_object_type: length <=0x20 -> inline tag (0x40+len) + raw utf8 bytes.
    // Longer strings use a separate length-prefixed tag (0x61/0x62/0x63/0x64); not needed for
    // our fixed device-info fields, so only the inline (<=0x20 byte) path is implemented.
    private fun encodeString(v: String, out: ByteArrayOutputStream) {
        val bytes = v.toByteArray(Charsets.UTF_8)
        val len = bytes.size
        if (len <= 0x20) {
            out.write(0x40 + len)
            out.write(bytes)
        } else if (len <= 0xFF) {
            out.write(0x61)
            out.write(len)
            out.write(bytes)
        } else {
            throw IllegalArgumentException("OPack: string too long for this minimal encoder ($len bytes)")
        }
    }

    // Matches _get_bytes_object_type: same scheme as strings but tag base 0x70 / 0x91.
    private fun encodeBytes(v: ByteArray, out: ByteArrayOutputStream) {
        val len = v.size
        if (len <= 0x20) {
            out.write(0x70 + len)
            out.write(v)
        } else if (len <= 0xFF) {
            out.write(0x91)
            out.write(len)
            out.write(v)
        } else if (len <= 0xFFFF) {
            out.write(0x92)
            val buf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort(len.toShort()).array()
            out.write(buf)
            out.write(v)
        } else {
            throw IllegalArgumentException("OPack: byte array too long for this minimal encoder ($len bytes)")
        }
    }

    // Matches _get_dict_object_type: <15 entries -> tag 0xE0+count, each entry as key+value pairs
    // inline (no length prefix per-entry - the tag's count says how many key/value pairs follow).
    private fun encodeDict(v: Map<*, *>, out: ByteArrayOutputStream) {
        val entries = v.entries.toList()
        if (entries.size < 15) {
            out.write(0xE0 + entries.size)
            for (entry in entries) {
                encodeValue(entry.key, out)
                encodeValue(entry.value, out)
            }
        } else {
            // Terminated form: tag 0xEF, then key/value pairs, ending with a type-3 terminator
            // pair. Not expected for our fixed ~8-field device_info dict, but implemented for
            // completeness.
            out.write(0xEF)
            for (entry in entries) {
                encodeValue(entry.key, out)
                encodeValue(entry.value, out)
            }
            out.write(3) // terminator key
            out.write(3) // terminator value
        }
    }

    // Matches _get_list_object_type: <15 items -> tag 0xD0+count, else terminated with tag 0xDF.
    private fun encodeList(v: List<*>, out: ByteArrayOutputStream) {
        if (v.size < 15) {
            out.write(0xD0 + v.size)
            for (item in v) encodeValue(item, out)
        } else {
            out.write(0xDF)
            for (item in v) encodeValue(item, out)
            out.write(3) // terminator
        }
    }
}
