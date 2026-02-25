package dev.ebpf.dsl.types

sealed class BpfType {
    abstract val size: Int
    abstract val alignment: Int
    abstract val cName: String
}

sealed class BpfScalar(
    override val size: Int,
    val signed: Boolean,
    override val cName: String,
) : BpfType() {
    override val alignment: Int get() = size

    object U8 : BpfScalar(1, false, "__u8")
    object U16 : BpfScalar(2, false, "__u16")
    object U32 : BpfScalar(4, false, "__u32")
    object U64 : BpfScalar(8, false, "__u64")
    object S8 : BpfScalar(1, true, "__s8")
    object S16 : BpfScalar(2, true, "__s16")
    object S32 : BpfScalar(4, true, "__s32")
    object S64 : BpfScalar(8, true, "__s64")
    object Bool : BpfScalar(1, false, "bool")
}
