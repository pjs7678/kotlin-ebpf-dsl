package dev.ebpf.dsl.maps

data class MapCapabilities(
    val canLookup: Boolean,
    val canUpdate: Boolean,
    val canDelete: Boolean,
    val canLookupOrInit: Boolean,
    val canReserve: Boolean, // ring buffer reserve/submit
    val canOutput: Boolean,  // perf event output
    val canGetStackId: Boolean,
) {
    companion object {
        fun forType(type: MapType): MapCapabilities = when (type) {
            MapType.HASH, MapType.LRU_HASH, MapType.PERCPU_HASH, MapType.LRU_PERCPU_HASH ->
                MapCapabilities(canLookup = true, canUpdate = true, canDelete = true, canLookupOrInit = true, canReserve = false, canOutput = false, canGetStackId = false)
            MapType.ARRAY, MapType.PERCPU_ARRAY ->
                MapCapabilities(canLookup = true, canUpdate = true, canDelete = false, canLookupOrInit = false, canReserve = false, canOutput = false, canGetStackId = false)
            MapType.RINGBUF ->
                MapCapabilities(canLookup = false, canUpdate = false, canDelete = false, canLookupOrInit = false, canReserve = true, canOutput = false, canGetStackId = false)
            MapType.PERF_EVENT_ARRAY ->
                MapCapabilities(canLookup = false, canUpdate = false, canDelete = false, canLookupOrInit = false, canReserve = false, canOutput = true, canGetStackId = false)
            MapType.STACK_TRACE ->
                MapCapabilities(canLookup = false, canUpdate = false, canDelete = false, canLookupOrInit = false, canReserve = false, canOutput = false, canGetStackId = true)
            MapType.LPM_TRIE ->
                MapCapabilities(canLookup = true, canUpdate = true, canDelete = true, canLookupOrInit = false, canReserve = false, canOutput = false, canGetStackId = false)
            else ->
                MapCapabilities(canLookup = true, canUpdate = true, canDelete = true, canLookupOrInit = false, canReserve = false, canOutput = false, canGetStackId = false)
        }
    }
}
