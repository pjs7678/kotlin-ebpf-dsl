package dev.ebpf.dsl.programs

import dev.ebpf.dsl.kernel.KernelVersion
import dev.ebpf.dsl.types.BpfType
import kotlin.reflect.KClass

data class BpfHelper(
    val id: Int,
    val name: String,
    val returnType: BpfType,
    val paramTypes: List<BpfType>,
    val gplOnly: Boolean,
    val availableIn: Set<KClass<out ProgramType>>,
    val minKernel: KernelVersion = KernelVersion.V4_18,
) {
    fun isAvailableIn(programType: KClass<out ProgramType>): Boolean =
        availableIn.isEmpty() || programType in availableIn
}
