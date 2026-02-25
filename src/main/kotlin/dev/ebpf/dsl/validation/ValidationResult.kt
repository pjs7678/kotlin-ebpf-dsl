package dev.ebpf.dsl.validation

sealed class ValidationResult {
    abstract val diagnostics: List<Diagnostic>
    val errors: List<Diagnostic> get() = diagnostics.filter { it.level == DiagnosticLevel.ERROR }
    val warnings: List<Diagnostic> get() = diagnostics.filter { it.level == DiagnosticLevel.WARNING }

    data class Success(override val diagnostics: List<Diagnostic> = emptyList()) : ValidationResult()
    data class WithWarnings(override val diagnostics: List<Diagnostic>) : ValidationResult()
    data class Failed(override val diagnostics: List<Diagnostic>) : ValidationResult()

    fun throwOnError() {
        if (errors.isNotEmpty()) {
            throw ValidationException(errors)
        }
    }

    companion object {
        fun from(diagnostics: List<Diagnostic>): ValidationResult {
            val errors = diagnostics.filter { it.level == DiagnosticLevel.ERROR }
            val warnings = diagnostics.filter { it.level == DiagnosticLevel.WARNING }
            return when {
                errors.isNotEmpty() -> Failed(diagnostics)
                warnings.isNotEmpty() -> WithWarnings(diagnostics)
                else -> Success(diagnostics)
            }
        }
    }
}

class ValidationException(val errors: List<Diagnostic>) :
    RuntimeException("Validation failed with ${errors.size} error(s):\n${errors.joinToString("\n") { "  ${it.code}: ${it.message}" }}")
