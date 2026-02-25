package dev.ebpf.dsl.ir

import dev.ebpf.dsl.types.BpfType

data class Variable(
    val name: String,
    val type: BpfType,
    val mutable: Boolean,
)
