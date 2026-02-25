package dev.ebpf.dsl.api

import dev.ebpf.dsl.maps.MapDecl
import dev.ebpf.dsl.maps.MapType
import dev.ebpf.dsl.programs.ProgramType
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import kotlin.properties.ReadOnlyProperty
import kotlin.reflect.KProperty

fun ebpf(name: String, block: EbpfProgramBuilder.() -> Unit): BpfProgramModel {
    val builder = EbpfProgramBuilder(name)
    builder.block()
    return builder.build()
}

class EbpfProgramBuilder(private val name: String) {
    private var _license: String? = null
    private val _maps = mutableListOf<MapDecl>()
    private val _mapNames = mutableSetOf<String>()
    private val _programs = mutableListOf<ProgramDef>()
    private val _structs = mutableSetOf<BpfStruct>()

    fun license(license: String) {
        _license = license
    }

    // ── Map delegate factories ──────────────────────────────────────────

    fun lruHashMap(key: BpfStruct, value: BpfStruct, maxEntries: Int, mapName: String? = null) =
        MapDelegate(MapType.LRU_HASH, key, value, maxEntries, mapName)

    fun hashMap(key: BpfStruct, value: BpfStruct, maxEntries: Int, mapName: String? = null) =
        MapDelegate(MapType.HASH, key, value, maxEntries, mapName)

    fun percpuHashMap(key: BpfStruct, value: BpfStruct, maxEntries: Int, mapName: String? = null) =
        MapDelegate(MapType.PERCPU_HASH, key, value, maxEntries, mapName)

    fun array(value: BpfStruct, maxEntries: Int, mapName: String? = null) =
        MapDelegate(MapType.ARRAY, null, value, maxEntries, mapName)

    fun percpuArray(value: BpfStruct, maxEntries: Int, mapName: String? = null) =
        MapDelegate(MapType.PERCPU_ARRAY, null, value, maxEntries, mapName)

    fun ringBuf(maxEntries: Int, mapName: String? = null) =
        MapDelegate(MapType.RINGBUF, null, null, maxEntries, mapName)

    inner class MapDelegate(
        private val type: MapType,
        private val keyStruct: BpfStruct?,
        private val valueStruct: BpfStruct?,
        private val maxEntries: Int,
        private val explicitName: String?,
    ) {
        operator fun provideDelegate(thisRef: Any?, prop: KProperty<*>): ReadOnlyProperty<Any?, MapHandle> {
            val mapName = explicitName ?: BpfStruct.camelToSnake(prop.name)
            require(_mapNames.add(mapName)) { "Duplicate map name: '$mapName'" }

            val keyType = keyStruct ?: if (type in ARRAY_TYPES) BpfScalar.U32 else null
            val decl = MapDecl(mapName, type, keyType, valueStruct, maxEntries)
            _maps.add(decl)

            if (keyStruct != null) _structs.add(keyStruct)
            if (valueStruct != null) _structs.add(valueStruct)

            val handle = MapHandle(decl)
            return ReadOnlyProperty { _, _ -> handle }
        }
    }

    // ── Program registration methods ────────────────────────────────────

    fun tracepoint(category: String, name: String, block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.Tracepoint(category, name), "tp_${category}_$name", block)
    }

    fun rawTracepoint(name: String, block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.RawTracepoint(name), "raw_tp_$name", block)
    }

    fun kprobe(function: String, block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.Kprobe(function), "kprobe_$function", block)
    }

    fun kretprobe(function: String, block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.Kretprobe(function), "kretprobe_$function", block)
    }

    fun fentry(function: String, block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.Fentry(function), "fentry_$function", block)
    }

    fun fexit(function: String, block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.Fexit(function), "fexit_$function", block)
    }

    fun xdp(block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.Xdp, "xdp_prog", block)
    }

    fun tcClassifier(block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.TcClassifier, "tc_prog", block)
    }

    fun cgroupSkb(direction: String, block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.CgroupSkb(direction), "cgroup_skb_$direction", block)
    }

    fun lsm(hook: String, block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.Lsm(hook), "lsm_$hook", block)
    }

    fun sockOps(block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.SockOps, "sockops_prog", block)
    }

    fun socketFilter(block: ProgramBodyBuilder.() -> Unit) {
        addProgram(ProgramType.SocketFilter, "socket_filter", block)
    }

    private fun addProgram(type: ProgramType, name: String, block: ProgramBodyBuilder.() -> Unit) {
        val bodyBuilder = ProgramBodyBuilder(type, _license, _maps)
        bodyBuilder.block()
        _programs.add(ProgramDef(name, type, bodyBuilder.build()))
    }

    fun build(): BpfProgramModel = BpfProgramModel(
        name = name,
        license = _license,
        maps = _maps.toList(),
        programs = _programs.toList(),
        structs = _structs.toSet(),
    )

    companion object {
        private val ARRAY_TYPES = setOf(MapType.ARRAY, MapType.PERCPU_ARRAY)
    }
}
