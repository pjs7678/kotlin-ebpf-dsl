package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.ir.BpfStmt
import dev.ebpf.dsl.ir.Variable
import dev.ebpf.dsl.maps.MapDecl
import dev.ebpf.dsl.programs.HelperRegistry
import dev.ebpf.dsl.programs.ProgramType
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import dev.ebpf.dsl.types.BpfType
import dev.ebpf.dsl.types.StructField

class ProgramBodyBuilder(
    private val programType: ProgramType,
    private val license: String?,
    private val maps: List<MapDecl>,
) {
    internal val stmts = mutableListOf<BpfStmt>()
    private var varCounter = 0

    internal fun addStmt(stmt: BpfStmt) {
        stmts.add(stmt)
    }

    internal fun build(): List<BpfStmt> = stmts.toList()

    // ── Literals ────────────────────────────────────────────────────────

    fun literal(value: Long, type: BpfScalar): ExprHandle =
        ExprHandle(BpfExpr.Literal(value, type), this)

    fun literal(value: ULong, type: BpfScalar): ExprHandle =
        ExprHandle(BpfExpr.Literal(value.toLong(), type), this)

    fun literal(value: Int, type: BpfScalar): ExprHandle =
        ExprHandle(BpfExpr.Literal(value.toLong(), type), this)

    fun literal(value: UInt, type: BpfScalar): ExprHandle =
        ExprHandle(BpfExpr.Literal(value.toLong(), type), this)

    // ── Variables ───────────────────────────────────────────────────────

    fun declareVar(name: String, init: ExprHandle, mutable: Boolean = false): ExprHandle {
        val v = Variable(name, init.type, mutable)
        addStmt(BpfStmt.VarDecl(v, init.expr))
        return ExprHandle(BpfExpr.VarRef(v), this)
    }

    // ── Stack variables (struct allocation) ─────────────────────────────

    fun stackVar(struct: BpfStruct, block: (StructInitializer) -> Unit): ExprHandle {
        val name = "var_${varCounter++}"
        val v = Variable(name, struct, false)
        val initializer = StructInitializer(struct, v, this)
        block(initializer)
        // Emit VarDecl with zero-init marker + field assignments
        addStmt(BpfStmt.VarDecl(v, BpfExpr.Literal(0, BpfScalar.U8)))
        for (assign in initializer.assignments) {
            addStmt(assign)
        }
        return ExprHandle(BpfExpr.VarRef(v), this)
    }

    // ── Binary ops (called by ExprHandle operators) ─────────────────────

    internal fun binaryOp(op: dev.ebpf.dsl.ir.Op, left: ExprHandle, right: ExprHandle): ExprHandle {
        val resultType = left.type // simplified: same type required
        return ExprHandle(BpfExpr.BinaryOp(op, left.expr, right.expr, resultType), this)
    }

    // ── Helper calls ────────────────────────────────────────────────────

    private fun helperCall(name: String, args: List<ExprHandle> = emptyList()): ExprHandle {
        val helper = HelperRegistry.findByName(name)
            ?: throw IllegalArgumentException("Unknown helper: $name")

        if (helper.gplOnly && license != "GPL") {
            throw IllegalStateException(
                "Helper '$name' requires license(\"GPL\"), but license is '${license}'"
            )
        }

        return ExprHandle(
            BpfExpr.HelperCall(helper.id, helper.name, args.map { it.expr }, helper.returnType),
            this
        )
    }

    fun getCurrentPidTgid() = helperCall("bpf_get_current_pid_tgid")
    fun getCurrentCgroupId() = helperCall("bpf_get_current_cgroup_id")
    fun ktimeGetNs() = helperCall("bpf_ktime_get_ns")
    fun smpProcessorId() = helperCall("bpf_get_smp_processor_id")
    fun getCurrentTask() = helperCall("bpf_get_current_task")
    fun getCurrentTaskBtf() = helperCall("bpf_get_current_task_btf")

    fun tracePrintk(fmt: String, vararg args: ExprHandle) =
        helperCall("bpf_trace_printk", args.toList())

    fun probeReadKernel(addr: ExprHandle, type: BpfScalar): ExprHandle =
        helperCall("bpf_probe_read_kernel", listOf(addr))

    // ── Map operations ──────────────────────────────────────────────────

    fun MapHandle.lookup(key: ExprHandle): ExprHandle {
        return ExprHandle(
            BpfExpr.MapLookup(this.name, key.expr, this.decl.valueType!!),
            this@ProgramBodyBuilder
        )
    }

    fun MapHandle.update(key: ExprHandle, value: ExprHandle, flags: Long = 0) {
        addStmt(BpfStmt.ExprStmt(BpfExpr.MapUpdate(this.name, key.expr, value.expr, flags)))
    }

    fun MapHandle.delete(key: ExprHandle) {
        addStmt(BpfStmt.MapDelete(this.name, key.expr))
    }

    fun MapHandle.lookupOrInit(key: ExprHandle, init: (StructInitializer) -> Unit): ExprHandle {
        val struct = this.decl.valueType as BpfStruct
        val initHelper = StructInitializer(struct, null, this@ProgramBodyBuilder)
        init(initHelper)
        // Store as a MapLookup; codegen will expand to lookup + conditional update + re-lookup
        return ExprHandle(
            BpfExpr.MapLookup(this.name, key.expr, struct),
            this@ProgramBodyBuilder
        )
    }

    // ── Control flow ────────────────────────────────────────────────────

    fun ifNonNull(expr: ExprHandle, block: (ExprHandle) -> Unit): IfNonNullBuilder {
        val v = Variable("entry_${varCounter++}", expr.type, false)
        val savedStmts = stmts.toList()
        stmts.clear()
        val handle = ExprHandle(BpfExpr.VarRef(v), this)
        block(handle)
        val bodyStmts = stmts.toList()
        stmts.clear()
        stmts.addAll(savedStmts)
        addStmt(BpfStmt.IfNonNull(expr.expr, v, bodyStmts))
        return IfNonNullBuilder(v, bodyStmts, expr.expr, this)
    }

    class IfNonNullBuilder(
        private val variable: Variable,
        private val body: List<BpfStmt>,
        private val expr: BpfExpr,
        private val builder: ProgramBodyBuilder,
    ) {
        fun elseThen(block: () -> Unit) {
            val saved = builder.stmts.toList()
            builder.stmts.clear()
            block()
            val elseStmts = builder.stmts.toList()
            builder.stmts.clear()
            builder.stmts.addAll(saved)
            // Replace last IfNonNull with version that has else
            val lastIndex = builder.stmts.indexOfLast { it is BpfStmt.IfNonNull }
            if (lastIndex >= 0) {
                builder.stmts[lastIndex] = BpfStmt.IfNonNull(expr, variable, body, elseStmts)
            }
        }
    }

    fun ifThen(cond: ExprHandle, block: () -> Unit): IfBuilder {
        val savedStmts = stmts.toList()
        stmts.clear()
        block()
        val thenStmts = stmts.toList()
        stmts.clear()
        stmts.addAll(savedStmts)
        return IfBuilder(cond.expr, thenStmts, this)
    }

    class IfBuilder(
        private val cond: BpfExpr,
        private val thenStmts: List<BpfStmt>,
        private val builder: ProgramBodyBuilder,
    ) {
        private val elseIfs = mutableListOf<Pair<BpfExpr, List<BpfStmt>>>()
        private var elseStmts: List<BpfStmt>? = null
        private var finished = false

        init {
            // Auto-add the If statement immediately. If elseIf/elseThen are chained,
            // they will modify the already-added statement in place by replacing it.
            emit()
        }

        fun elseIf(cond: ExprHandle, block: () -> Unit): IfBuilder {
            val saved = builder.stmts.toList()
            builder.stmts.clear()
            block()
            val body = builder.stmts.toList()
            builder.stmts.clear()
            builder.stmts.addAll(saved)
            elseIfs.add(cond.expr to body)
            reemit()
            return this
        }

        fun elseThen(block: () -> Unit) {
            val saved = builder.stmts.toList()
            builder.stmts.clear()
            block()
            elseStmts = builder.stmts.toList()
            builder.stmts.clear()
            builder.stmts.addAll(saved)
            reemit()
        }

        private fun emit() {
            builder.addStmt(BpfStmt.If(cond, thenStmts, elseIfs.toList(), elseStmts))
            finished = true
        }

        private fun reemit() {
            // Replace the last If statement with the updated version
            val lastIndex = builder.stmts.indexOfLast { it is BpfStmt.If }
            if (lastIndex >= 0) {
                builder.stmts[lastIndex] = BpfStmt.If(cond, thenStmts, elseIfs.toList(), elseStmts)
            }
        }
    }

    fun boundedLoop(count: ExprHandle, block: (ExprHandle) -> Unit) {
        val iterVar = Variable("i_${varCounter++}", BpfScalar.U32, false)
        val savedStmts = stmts.toList()
        stmts.clear()
        val handle = ExprHandle(BpfExpr.VarRef(iterVar), this)
        block(handle)
        val bodyStmts = stmts.toList()
        stmts.clear()
        stmts.addAll(savedStmts)
        addStmt(BpfStmt.BoundedLoop(count.expr, iterVar, bodyStmts))
    }

    fun forRange(start: Int, end: Int, block: (ExprHandle) -> Unit) {
        boundedLoop(literal(end - start, BpfScalar.U32), block)
    }

    // ── Return ──────────────────────────────────────────────────────────

    fun returnValue(value: ExprHandle) {
        addStmt(BpfStmt.Return(value.expr))
    }

    fun returnAction(action: Int) = returnValue(literal(action, BpfScalar.S32))

    // ── XDP action constants ────────────────────────────────────────────

    @Suppress("PropertyName")
    val XDP_ABORTED = 0
    @Suppress("PropertyName")
    val XDP_DROP = 1
    @Suppress("PropertyName")
    val XDP_PASS = 2
    @Suppress("PropertyName")
    val XDP_TX = 3
    @Suppress("PropertyName")
    val XDP_REDIRECT = 4

    // ── Raw escape hatch ────────────────────────────────────────────────

    fun raw(cCode: String, returnType: BpfType): ExprHandle {
        return ExprHandle(BpfExpr.Raw(cCode, returnType), this)
    }

    // ── Cast ────────────────────────────────────────────────────────────

    fun cast(expr: ExprHandle, target: BpfScalar): ExprHandle {
        return ExprHandle(BpfExpr.Cast(expr.expr, target), this)
    }
}

// ── Struct field initializer ────────────────────────────────────────────

class StructInitializer(
    val struct: BpfStruct,
    val variable: Variable?,
    val builder: ProgramBodyBuilder,
) {
    internal val assignments = mutableListOf<BpfStmt>()

    operator fun set(field: StructField, value: ExprHandle) {
        if (variable != null) {
            assignments.add(
                BpfStmt.Assign(
                    BpfExpr.FieldAccess(BpfExpr.VarRef(variable), field, field.type),
                    value.expr
                )
            )
        }
    }
}
