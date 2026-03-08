package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar

class BufferHandle(
    val name: String,
    val size: Int,
    private val builder: ProgramBodyBuilder,
) {
    fun byte(index: Int): ExprHandle {
        require(index in 0 until size) { "Index $index out of bounds for buffer of size $size" }
        return ExprHandle(BpfExpr.BufferByte(name, index), builder)
    }

    fun u16be(offset: Int): ExprHandle {
        require(offset + 2 <= size) { "u16be at offset $offset exceeds buffer size $size" }
        return ExprHandle(BpfExpr.BufferMultiByte(name, offset, BpfScalar.U16, bigEndian = true), builder)
    }

    fun u16le(offset: Int): ExprHandle {
        require(offset + 2 <= size) { "u16le at offset $offset exceeds buffer size $size" }
        return ExprHandle(BpfExpr.BufferMultiByte(name, offset, BpfScalar.U16, bigEndian = false), builder)
    }

    fun u32be(offset: Int): ExprHandle {
        require(offset + 4 <= size) { "u32be at offset $offset exceeds buffer size $size" }
        return ExprHandle(BpfExpr.BufferMultiByte(name, offset, BpfScalar.U32, bigEndian = true), builder)
    }

    fun u32le(offset: Int): ExprHandle {
        require(offset + 4 <= size) { "u32le at offset $offset exceeds buffer size $size" }
        return ExprHandle(BpfExpr.BufferMultiByte(name, offset, BpfScalar.U32, bigEndian = false), builder)
    }
}
