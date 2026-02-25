package dev.ebpf.dsl.api

import dev.ebpf.dsl.validation.SemanticAnalyzer
import dev.ebpf.dsl.validation.TypeChecker
import dev.ebpf.dsl.validation.ValidationResult

fun BpfProgramModel.validate(): ValidationResult {
    val typeResult = TypeChecker(this).check()
    val semanticResult = SemanticAnalyzer(this).analyze()
    val allDiagnostics = typeResult.diagnostics + semanticResult.diagnostics
    return ValidationResult.from(allDiagnostics)
}
