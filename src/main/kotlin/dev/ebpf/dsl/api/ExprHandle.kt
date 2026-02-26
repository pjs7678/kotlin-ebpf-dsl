package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.AtomicOpKind
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.ir.BpfStmt
import dev.ebpf.dsl.ir.Op
import dev.ebpf.dsl.types.BpfArrayType
import dev.ebpf.dsl.types.BpfType
import dev.ebpf.dsl.types.StructField

class ExprHandle(val expr: BpfExpr, private val builder: ProgramBodyBuilder) {
    val type: BpfType get() = expr.type

    // ── Arithmetic ──────────────────────────────────────────────────────

    operator fun plus(other: ExprHandle) = builder.binaryOp(Op.ADD, this, other)
    operator fun minus(other: ExprHandle) = builder.binaryOp(Op.SUB, this, other)
    operator fun times(other: ExprHandle) = builder.binaryOp(Op.MUL, this, other)
    operator fun div(other: ExprHandle) = builder.binaryOp(Op.DIV, this, other)
    operator fun rem(other: ExprHandle) = builder.binaryOp(Op.MOD, this, other)

    // ── Bitwise ─────────────────────────────────────────────────────────

    infix fun and(other: ExprHandle) = builder.binaryOp(Op.AND, this, other)
    infix fun or(other: ExprHandle) = builder.binaryOp(Op.OR, this, other)
    infix fun xor(other: ExprHandle) = builder.binaryOp(Op.XOR, this, other)
    infix fun shl(other: ExprHandle) = builder.binaryOp(Op.SHL, this, other)
    infix fun shr(other: ExprHandle) = builder.binaryOp(Op.SHR, this, other)

    // ── Comparison ──────────────────────────────────────────────────────

    infix fun eq(other: ExprHandle) = builder.binaryOp(Op.EQ, this, other)
    infix fun ne(other: ExprHandle) = builder.binaryOp(Op.NE, this, other)
    infix fun gt(other: ExprHandle) = builder.binaryOp(Op.GT, this, other)
    infix fun ge(other: ExprHandle) = builder.binaryOp(Op.GE, this, other)
    infix fun lt(other: ExprHandle) = builder.binaryOp(Op.LT, this, other)
    infix fun le(other: ExprHandle) = builder.binaryOp(Op.LE, this, other)

    // ── Atomic operations (for field access handles) ────────────────────

    fun atomicAdd(value: ExprHandle) {
        builder.addStmt(BpfStmt.AtomicOp(AtomicOpKind.ADD, expr, value.expr))
    }

    fun atomicSub(value: ExprHandle) {
        builder.addStmt(BpfStmt.AtomicOp(AtomicOpKind.SUB, expr, value.expr))
    }

    fun atomicOr(value: ExprHandle) {
        builder.addStmt(BpfStmt.AtomicOp(AtomicOpKind.OR, expr, value.expr))
    }

    fun atomicAnd(value: ExprHandle) {
        builder.addStmt(BpfStmt.AtomicOp(AtomicOpKind.AND, expr, value.expr))
    }

    fun atomicXor(value: ExprHandle) {
        builder.addStmt(BpfStmt.AtomicOp(AtomicOpKind.XOR, expr, value.expr))
    }

    fun atomicXchg(value: ExprHandle) {
        builder.addStmt(BpfStmt.AtomicOp(AtomicOpKind.XCHG, expr, value.expr))
    }

    fun atomicCmpxchg(value: ExprHandle) {
        builder.addStmt(BpfStmt.AtomicOp(AtomicOpKind.CMPXCHG, expr, value.expr))
    }

    // ── Array indexing ──────────────────────────────────────────────────

    fun at(index: ExprHandle): ExprHandle {
        val arrayType = expr.type
        val elementType = when (arrayType) {
            is BpfArrayType -> arrayType.elementType
            else -> throw IllegalStateException("at() requires an array type, got $arrayType")
        }
        return ExprHandle(BpfExpr.ArrayIndex(expr, index.expr, elementType), builder)
    }

    // ── Struct field access ─────────────────────────────────────────────

    operator fun get(field: StructField): ExprHandle {
        return ExprHandle(BpfExpr.FieldAccess(expr, field, field.type), builder)
    }

    // ── Pointer dereference ─────────────────────────────────────────────

    /** Dereference a pointer: `*this` */
    fun deref(): ExprHandle = ExprHandle(BpfExpr.Deref(expr), builder)
}
