package dev.ebpf.dsl.ir

sealed class BpfStmt {
    data class VarDecl(val variable: Variable, val init: BpfExpr) : BpfStmt()
    data class Assign(val target: BpfExpr, val value: BpfExpr) : BpfStmt()
    data class If(val cond: BpfExpr, val then: List<BpfStmt>, val elseIfs: List<Pair<BpfExpr, List<BpfStmt>>>, val else_: List<BpfStmt>?) : BpfStmt()
    data class IfNonNull(val expr: BpfExpr, val variable: Variable, val body: List<BpfStmt>) : BpfStmt()
    data class BoundedLoop(val count: BpfExpr, val iterVar: Variable, val body: List<BpfStmt>) : BpfStmt()
    data class Return(val value: BpfExpr) : BpfStmt()
    data class AtomicOp(val op: AtomicOpKind, val target: BpfExpr, val operand: BpfExpr) : BpfStmt()
    data class ExprStmt(val expr: BpfExpr) : BpfStmt()
    data class MapDelete(val mapName: String, val key: BpfExpr) : BpfStmt()
}
