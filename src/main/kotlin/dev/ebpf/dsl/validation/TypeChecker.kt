package dev.ebpf.dsl.validation

import dev.ebpf.dsl.api.BpfProgramModel
import dev.ebpf.dsl.api.ProgramDef
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.ir.BpfStmt
import dev.ebpf.dsl.programs.HelperRegistry

class TypeChecker(private val model: BpfProgramModel) {
    private val diagnostics = mutableListOf<Diagnostic>()

    fun check(): ValidationResult {
        for (program in model.programs) {
            checkProgram(program)
        }
        return ValidationResult.from(diagnostics)
    }

    private fun checkProgram(program: ProgramDef) {
        for (stmt in program.body) {
            checkStmt(stmt, program)
        }
    }

    private fun checkStmt(stmt: BpfStmt, program: ProgramDef) {
        when (stmt) {
            is BpfStmt.VarDecl -> checkExpr(stmt.init, program)
            is BpfStmt.Assign -> {
                checkExpr(stmt.target, program)
                checkExpr(stmt.value, program)
            }
            is BpfStmt.If -> {
                checkExpr(stmt.cond, program)
                stmt.then.forEach { checkStmt(it, program) }
                stmt.elseIfs.forEach { (cond, body) ->
                    checkExpr(cond, program)
                    body.forEach { checkStmt(it, program) }
                }
                stmt.else_?.forEach { checkStmt(it, program) }
            }
            is BpfStmt.IfNonNull -> {
                checkExpr(stmt.expr, program)
                stmt.body.forEach { checkStmt(it, program) }
            }
            is BpfStmt.BoundedLoop -> {
                checkExpr(stmt.count, program)
                stmt.body.forEach { checkStmt(it, program) }
            }
            is BpfStmt.Return -> checkExpr(stmt.value, program)
            is BpfStmt.AtomicOp -> {
                checkExpr(stmt.target, program)
                checkExpr(stmt.operand, program)
            }
            is BpfStmt.ExprStmt -> checkExpr(stmt.expr, program)
            is BpfStmt.MapDelete -> checkExpr(stmt.key, program)
        }
    }

    private fun checkExpr(expr: BpfExpr, program: ProgramDef) {
        when (expr) {
            is BpfExpr.HelperCall -> {
                val helper = HelperRegistry.findByName(expr.helperName)
                if (helper != null) {
                    if (!helper.isAvailableIn(program.type::class)) {
                        diagnostics.add(
                            Diagnostic(
                                DiagnosticLevel.ERROR,
                                "helper-unavailable",
                                "Helper '${expr.helperName}' is not available in ${program.type::class.simpleName} programs",
                                program.name,
                            )
                        )
                    }
                    if (helper.gplOnly && model.license != "GPL") {
                        diagnostics.add(
                            Diagnostic(
                                DiagnosticLevel.ERROR,
                                "gpl-required",
                                "Helper '${expr.helperName}' requires GPL license",
                                program.name,
                            )
                        )
                    }
                }
                expr.args.forEach { checkExpr(it, program) }
            }
            is BpfExpr.MapLookup -> checkExpr(expr.key, program)
            is BpfExpr.MapUpdate -> {
                checkExpr(expr.key, program)
                checkExpr(expr.value, program)
            }
            is BpfExpr.BinaryOp -> {
                checkExpr(expr.left, program)
                checkExpr(expr.right, program)
            }
            is BpfExpr.UnaryOp -> checkExpr(expr.operand, program)
            is BpfExpr.FieldAccess -> checkExpr(expr.base, program)
            is BpfExpr.ArrayIndex -> {
                checkExpr(expr.base, program)
                checkExpr(expr.index, program)
            }
            is BpfExpr.Cast -> checkExpr(expr.expr, program)
            is BpfExpr.Literal, is BpfExpr.VarRef, is BpfExpr.Raw -> { /* no sub-expressions */ }
        }
    }
}
