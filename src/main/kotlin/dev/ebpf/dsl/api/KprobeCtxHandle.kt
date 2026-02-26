package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar

/**
 * Type-safe handle for accessing kprobe parameters via PT_REGS_PARMn macros.
 */
class KprobeCtxHandle(private val builder: ProgramBodyBuilder) {
    fun param(index: Int, castType: String = "unsigned long", type: BpfScalar = BpfScalar.U64): ExprHandle =
        ExprHandle(BpfExpr.KprobeParam(index, castType, type), builder)
}
