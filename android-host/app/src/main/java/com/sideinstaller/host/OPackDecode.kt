package com.sideinstaller.host

/**
 * Minimal OPack decoder, complementing OPack.kt's encoder. Only handles the
 * shapes we expect back from a real device's M5 identity INFO field: a
 * short-form dict (tag 0xE0-0xEE) containing string keys and string/bytes/int
 * values - matches what PairableHost's own M6 encoder produces, and what
 * iOS is expected to send back.
 */
object OPackDecode {

    fun loads(data: ByteArray): Any {
        val (value, _) = decodeValue(data, 0)
        return value
    }

    private fun decodeValue(data: ByteArray, offset: Int): Pair<Any, Int> {
        val tag = data[offset].toInt() and 0xFF
        return when {
            tag == 1 -> true to (offset + 1)
            tag == 2 -> false to (offset + 1)
            tag in 8..0x27 -> (tag - 8).toLong() to (offset + 1)
            tag == 0x30 -> {
                val v = (data[offset + 1].toInt() and 0xFF).toLong()
                v to (offset + 2)
            }
            tag == 0x32 -> {
                var v = 0L
                for (i in 0 until 4) v = v or ((data[offset + 1 + i].toLong() and 0xFF) shl (8 * i))
                v to (offset + 5)
            }
            tag == 0x33 -> {
                var v = 0L
                for (i in 0 until 8) v = v or ((data[offset + 1 + i].toLong() and 0xFF) shl (8 * i))
                v to (offset + 9)
            }
            tag in 0x40..0x60 -> {
                val len = tag - 0x40
                val str = String(data, offset + 1, len, Charsets.UTF_8)
                str to (offset + 1 + len)
            }
            tag == 0x61 -> {
                val len = data[offset + 1].toInt() and 0xFF
                val str = String(data, offset + 2, len, Charsets.UTF_8)
                str to (offset + 2 + len)
            }
            tag in 0x70..0x90 -> {
                val len = tag - 0x70
                val bytes = data.copyOfRange(offset + 1, offset + 1 + len)
                bytes to (offset + 1 + len)
            }
            tag == 0x91 -> {
                val len = data[offset + 1].toInt() and 0xFF
                val bytes = data.copyOfRange(offset + 2, offset + 2 + len)
                bytes to (offset + 2 + len)
            }
            tag == 0x92 -> {
                val len = ((data[offset + 1].toInt() and 0xFF) shl 8) or (data[offset + 2].toInt() and 0xFF)
                val bytes = data.copyOfRange(offset + 3, offset + 3 + len)
                bytes to (offset + 3 + len)
            }
            tag in 0xE0..0xEF -> decodeDict(data, offset, tag)
            tag in 0xD0..0xDF -> decodeArray(data, offset, tag)
            else -> throw IllegalArgumentException("OPackDecode: unsupported tag 0x${tag.toString(16)}")
        }
    }

    private fun decodeDict(data: ByteArray, offset: Int, tag: Int): Pair<Map<String, Any>, Int> {
        val result = LinkedHashMap<String, Any>()
        var pos = offset + 1
        if (tag == 0xEF) {
            while (true) {
                if (data[pos].toInt() and 0xFF == 3) { pos += 1; break } // terminator key
                val (k, p1) = decodeValue(data, pos)
                val (v, p2) = decodeValue(data, p1)
                result[k as String] = v
                pos = p2
            }
        } else {
            val count = tag - 0xE0
            repeat(count) {
                val (k, p1) = decodeValue(data, pos)
                val (v, p2) = decodeValue(data, p1)
                result[k as String] = v
                pos = p2
            }
        }
        return result to pos
    }

    private fun decodeArray(data: ByteArray, offset: Int, tag: Int): Pair<List<Any>, Int> {
        val result = mutableListOf<Any>()
        var pos = offset + 1
        if (tag == 0xDF) {
            while (true) {
                if (data[pos].toInt() and 0xFF == 3) { pos += 1; break }
                val (v, p1) = decodeValue(data, pos)
                result.add(v)
                pos = p1
            }
        } else {
            val count = tag - 0xD0
            repeat(count) {
                val (v, p1) = decodeValue(data, pos)
                result.add(v)
                pos = p1
            }
        }
        return result to pos
    }
}
