package dev.ebpf.dsl.ir

import dev.ebpf.dsl.types.*

sealed class BpfExpr {
    abstract val type: BpfType

    data class Literal(val value: Long, override val type: BpfScalar) : BpfExpr()
    data class VarRef(val variable: Variable) : BpfExpr() {
        override val type get() = variable.type
    }
    data class BinaryOp(val op: Op, val left: BpfExpr, val right: BpfExpr, override val type: BpfType) : BpfExpr()
    data class UnaryOp(val op: Op, val operand: BpfExpr, override val type: BpfType) : BpfExpr()
    data class FieldAccess(val base: BpfExpr, val field: StructField, override val type: BpfType) : BpfExpr()
    data class ArrayIndex(val base: BpfExpr, val index: BpfExpr, override val type: BpfType) : BpfExpr()
    data class HelperCall(val helperId: Int, val helperName: String, val args: List<BpfExpr>, override val type: BpfType) : BpfExpr()
    data class Cast(val expr: BpfExpr, val target: BpfScalar) : BpfExpr() {
        override val type: BpfType get() = target
    }
    data class Raw(val cCode: String, override val type: BpfType) : BpfExpr()

    /** Dereference a pointer: `*expr` */
    data class Deref(val operand: BpfExpr) : BpfExpr() {
        override val type: BpfType get() = operand.type
    }

    /** Tracepoint field access: `((struct X *)ctx)->field` */
    data class TracepointField(val structName: String, val fieldName: String, override val type: BpfType) : BpfExpr()

    /** Kprobe parameter access: `(cast)PT_REGS_PARMn(ctx)` */
    data class KprobeParam(val index: Int, val castType: String, override val type: BpfType) : BpfExpr()

    /** Raw tracepoint argument access: `(cast)ctx->args[n]` */
    data class RawTpArg(val index: Int, val castType: String, override val type: BpfType) : BpfExpr()

    /** Histogram slot computation: `log2l(x) >= max ? max-1 : log2l(x)` */
    data class HistSlot(val value: BpfExpr, val maxSlots: Int) : BpfExpr() {
        override val type: BpfType get() = BpfScalar.U32
    }

    /** Ternary expression: `(cond) ? then : else` */
    data class Ternary(val cond: BpfExpr, val then: BpfExpr, val else_: BpfExpr) : BpfExpr() {
        override val type: BpfType get() = then.type
    }

    /** Struct array field set with comma expression: `(v.slots[i] = val, (__s32)0)` */
    data class StructArraySet(
        val structVar: BpfExpr,
        val field: StructField,
        val index: BpfExpr,
        val value: BpfExpr,
    ) : BpfExpr() {
        override val type: BpfType get() = BpfScalar.S32
    }

    /** C-type cast by name: `(cast)expr` — for casts not expressible via BpfScalar */
    data class CTypeCast(val cTypeName: String, val operand: BpfExpr, override val type: BpfType) : BpfExpr()

    data class MapLookup(val mapName: String, val key: BpfExpr, val valueType: BpfType) : BpfExpr() {
        override val type: BpfType get() = valueType
    }
    data class MapUpdate(val mapName: String, val key: BpfExpr, val value: BpfExpr, val flags: Long) : BpfExpr() {
        override val type: BpfType get() = BpfScalar.S32 // returns int
    }
}
