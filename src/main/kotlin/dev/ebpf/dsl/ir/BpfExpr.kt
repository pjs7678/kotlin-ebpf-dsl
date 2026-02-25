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
    data class MapLookup(val mapName: String, val key: BpfExpr, val valueType: BpfType) : BpfExpr() {
        override val type: BpfType get() = valueType
    }
    data class MapUpdate(val mapName: String, val key: BpfExpr, val value: BpfExpr, val flags: Long) : BpfExpr() {
        override val type: BpfType get() = BpfScalar.S32 // returns int
    }
}
