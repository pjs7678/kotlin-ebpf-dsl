package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.ir.BpfStmt
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
    private var _preamble: String? = null
    private val _maps = mutableListOf<MapDecl>()
    private val _mapNames = mutableSetOf<String>()
    private val _programs = mutableListOf<ProgramDef>()
    private val _structs = mutableSetOf<BpfStruct>()

    @Deprecated(
        message = "Use license(BpfLicense.GPL) instead of license(\"GPL\")",
        replaceWith = ReplaceWith("license(BpfLicense.GPL)", "dev.ebpf.dsl.api.BpfLicense"),
        level = DeprecationLevel.WARNING,
    )
    fun license(license: String) {
        _license = license
    }

    fun license(license: BpfLicense) {
        _license = license.licenseString
    }

    fun preamble(code: String) {
        _preamble = code
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

    // ── Scalar map delegate factories ───────────────────────────────────

    fun scalarHashMap(keyType: BpfScalar, valueType: BpfScalar, maxEntries: Int, mapName: String? = null) =
        ScalarMapDelegate(MapType.HASH, keyType, valueType, maxEntries, mapName)

    fun scalarLruHashMap(keyType: BpfScalar, valueType: BpfScalar, maxEntries: Int, mapName: String? = null) =
        ScalarMapDelegate(MapType.LRU_HASH, keyType, valueType, maxEntries, mapName)

    inner class ScalarMapDelegate(
        private val type: MapType,
        private val keyType: BpfScalar,
        private val valueType: BpfScalar,
        private val maxEntries: Int,
        private val explicitName: String?,
    ) {
        operator fun provideDelegate(thisRef: Any?, prop: KProperty<*>): ReadOnlyProperty<Any?, MapHandle> {
            val mapName = explicitName ?: BpfStruct.camelToSnake(prop.name)
            require(_mapNames.add(mapName)) { "Duplicate map name: '$mapName'" }
            val decl = MapDecl(mapName, type, keyType, valueType, maxEntries)
            _maps.add(decl)
            val handle = MapHandle(decl)
            return ReadOnlyProperty { _, _ -> handle }
        }
    }

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

    /** Typed tracepoint: provides a [TracepointCtxHandle] for type-safe field access. */
    fun tracepoint(def: TracepointDef, block: ProgramBodyBuilder.(TracepointCtxHandle) -> Unit) {
        addProgram(ProgramType.Tracepoint(def.category, def.name), "tp_${def.category}_${def.name}") {
            val ctx = TracepointCtxHandle(def, this)
            block(ctx)
        }
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

    fun build(): BpfProgramModel {
        // Auto-inject log2l preamble if any program uses HistSlot
        val needsLog2l = _programs.any { prog -> prog.body.any { containsHistSlot(it) } }
        val preamble = if (needsLog2l && _preamble == null) LOG2L_PREAMBLE
            else _preamble

        return BpfProgramModel(
            name = name,
            license = _license,
            maps = _maps.toList(),
            programs = _programs.toList(),
            structs = _structs.toSet(),
            preamble = preamble,
        )
    }

    private fun containsHistSlot(stmt: BpfStmt): Boolean = when (stmt) {
        is BpfStmt.VarDecl -> exprContainsHistSlot(stmt.init)
        is BpfStmt.Assign -> exprContainsHistSlot(stmt.target) || exprContainsHistSlot(stmt.value)
        is BpfStmt.If -> {
            exprContainsHistSlot(stmt.cond) ||
                stmt.then.any { containsHistSlot(it) } ||
                stmt.elseIfs.any { (c, b) -> exprContainsHistSlot(c) || b.any { containsHistSlot(it) } } ||
                stmt.else_?.any { containsHistSlot(it) } == true
        }
        is BpfStmt.IfNonNull -> {
            exprContainsHistSlot(stmt.expr) ||
                stmt.body.any { containsHistSlot(it) } ||
                stmt.else_?.any { containsHistSlot(it) } == true
        }
        is BpfStmt.BoundedLoop -> exprContainsHistSlot(stmt.count) || stmt.body.any { containsHistSlot(it) }
        is BpfStmt.Return -> exprContainsHistSlot(stmt.value)
        is BpfStmt.AtomicOp -> exprContainsHistSlot(stmt.target) || exprContainsHistSlot(stmt.operand)
        is BpfStmt.ExprStmt -> exprContainsHistSlot(stmt.expr)
        is BpfStmt.MapDelete -> exprContainsHistSlot(stmt.key)
    }

    private fun exprContainsHistSlot(expr: BpfExpr): Boolean = when (expr) {
        is BpfExpr.HistSlot -> true
        is BpfExpr.BinaryOp -> exprContainsHistSlot(expr.left) || exprContainsHistSlot(expr.right)
        is BpfExpr.UnaryOp -> exprContainsHistSlot(expr.operand)
        is BpfExpr.FieldAccess -> exprContainsHistSlot(expr.base)
        is BpfExpr.ArrayIndex -> exprContainsHistSlot(expr.base) || exprContainsHistSlot(expr.index)
        is BpfExpr.HelperCall -> expr.args.any { exprContainsHistSlot(it) }
        is BpfExpr.Cast -> exprContainsHistSlot(expr.expr)
        is BpfExpr.Deref -> exprContainsHistSlot(expr.operand)
        is BpfExpr.Ternary -> exprContainsHistSlot(expr.cond) || exprContainsHistSlot(expr.then) || exprContainsHistSlot(expr.else_)
        is BpfExpr.StructArraySet -> exprContainsHistSlot(expr.structVar) || exprContainsHistSlot(expr.index) || exprContainsHistSlot(expr.value)
        is BpfExpr.CTypeCast -> exprContainsHistSlot(expr.operand)
        is BpfExpr.MapLookup -> exprContainsHistSlot(expr.key)
        is BpfExpr.MapUpdate -> exprContainsHistSlot(expr.key) || exprContainsHistSlot(expr.value)
        is BpfExpr.Literal, is BpfExpr.VarRef, is BpfExpr.Raw,
        is BpfExpr.TracepointField, is BpfExpr.KprobeParam, is BpfExpr.RawTpArg -> false
    }

    companion object {
        private val ARRAY_TYPES = setOf(MapType.ARRAY, MapType.PERCPU_ARRAY)

        private val LOG2L_PREAMBLE = """
            #define MAX_ENTRIES 10240
            #define MAX_SLOTS 27

            static __always_inline __u32 log2l(__u64 v) {
                __u32 r = 0;
                while (v > 1) {
                    v >>= 1;
                    r++;
                }
                return r;
            }
        """.trimIndent()
    }
}
