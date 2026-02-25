package dev.ebpf.dsl.maps

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfType

data class MapDecl(
    val name: String,
    val mapType: MapType,
    val keyType: BpfType?,     // null for ringbuf
    val valueType: BpfType?,   // null for ringbuf
    val maxEntries: Int,
    val flags: Long = 0,
    val pinPath: String? = null,
) {
    val capabilities: MapCapabilities = MapCapabilities.forType(mapType)

    init {
        require(name.length <= 15) { "Map name '$name' exceeds 15 character BPF limit" }
        require(maxEntries > 0) { "maxEntries must be > 0, got $maxEntries" }

        if (mapType == MapType.RINGBUF) {
            require(maxEntries.countOneBits() == 1) {
                "Ring buffer maxEntries must be a power of 2, got $maxEntries"
            }
        }

        if (mapType == MapType.ARRAY || mapType == MapType.PERCPU_ARRAY) {
            require(keyType == BpfScalar.U32) {
                "Array map key must be U32, got ${keyType?.cName}"
            }
        }
    }
}
