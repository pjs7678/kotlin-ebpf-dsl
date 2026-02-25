package dev.ebpf.dsl.validation

enum class DiagnosticLevel { ERROR, WARNING, INFO }

data class Diagnostic(
    val level: DiagnosticLevel,
    val code: String,
    val message: String,
    val programName: String? = null,
)
