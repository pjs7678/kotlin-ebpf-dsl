package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar

/**
 * Type-safe definition of a kernel tracepoint, encoding its category,
 * name, and the C struct layout of its context.
 */
open class TracepointDef(
    val category: String,
    val name: String,
    val cStructName: String,
) {
    private val _fields = mutableListOf<TracepointFieldDef>()
    val fields: List<TracepointFieldDef> get() = _fields.toList()

    protected fun field(name: String, type: BpfScalar): TracepointFieldDef {
        val f = TracepointFieldDef(name, type)
        _fields.add(f)
        return f
    }
}

data class TracepointFieldDef(val fieldName: String, val type: BpfScalar)

/**
 * Handle for type-safe access to tracepoint context fields.
 */
class TracepointCtxHandle(
    private val def: TracepointDef,
    private val builder: ProgramBodyBuilder,
) {
    operator fun get(field: TracepointFieldDef): ExprHandle {
        return ExprHandle(
            BpfExpr.TracepointField(def.cStructName, field.fieldName, field.type),
            builder,
        )
    }
}
