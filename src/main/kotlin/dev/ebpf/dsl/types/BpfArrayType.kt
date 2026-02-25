package dev.ebpf.dsl.types

class BpfArrayType(
    val elementType: BpfType,
    val length: Int,
) : BpfType() {
    init {
        require(length > 0) { "Array length must be > 0" }
    }

    override val size: Int = elementType.size * length
    override val alignment: Int = elementType.alignment
    override val cName: String = "${elementType.cName}[$length]"
}
