package dev.ebpf.dsl.types

data class StructField(
    val name: String,        // C name (snake_case)
    val type: BpfType,
    val offset: Int,
    val kotlinName: String,  // original Kotlin property name
)
