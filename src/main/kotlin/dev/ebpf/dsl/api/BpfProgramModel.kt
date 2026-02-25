package dev.ebpf.dsl.api

import dev.ebpf.dsl.ir.BpfStmt
import dev.ebpf.dsl.maps.MapDecl
import dev.ebpf.dsl.programs.ProgramType
import dev.ebpf.dsl.types.BpfStruct

data class ProgramDef(
    val name: String,
    val type: ProgramType,
    val body: List<BpfStmt>,
)

data class BpfProgramModel(
    val name: String,
    val license: String?,
    val maps: List<MapDecl>,
    val programs: List<ProgramDef>,
    val structs: Set<BpfStruct>,
    val preamble: String? = null,
)
