package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar

/**
 * Type-safe handle for accessing raw tracepoint arguments via ctx->args[n].
 */
class RawTpCtxHandle(private val builder: ProgramBodyBuilder) {
    fun arg(index: Int, castType: String, type: BpfScalar = BpfScalar.U64): ExprHandle =
        ExprHandle(BpfExpr.RawTpArg(index, castType, type), builder)
}
