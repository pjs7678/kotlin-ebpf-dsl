package dev.ebpf.dsl.validation

import dev.ebpf.dsl.api.BpfProgramModel
import dev.ebpf.dsl.api.ProgramDef
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.ir.BpfStmt
import dev.ebpf.dsl.ir.Op
import dev.ebpf.dsl.maps.MapType
import dev.ebpf.dsl.types.BpfStruct

class SemanticAnalyzer(private val model: BpfProgramModel) {
    private val diagnostics = mutableListOf<Diagnostic>()

    fun analyze(): ValidationResult {
        checkKernelCompatibility()
        checkMapAntiPatterns()
        for (program in model.programs) {
            checkStackUsage(program)
            checkUnreachableCode(program.body, program.name)
            checkDivisionSafety(program)
            checkRawUsage(program)
        }
        return ValidationResult.from(diagnostics)
    }

    private fun checkStackUsage(program: ProgramDef) {
        var stackBytes = 0
        collectStackUsage(program.body) { bytes -> stackBytes += bytes }
        if (stackBytes > 512) {
            diagnostics.add(
                Diagnostic(
                    DiagnosticLevel.ERROR, "stack-overflow",
                    "Stack usage is $stackBytes bytes, exceeds 512-byte eBPF limit",
                    program.name,
                )
            )
        }
    }

    private fun collectStackUsage(stmts: List<BpfStmt>, accumulator: (Int) -> Unit) {
        for (stmt in stmts) {
            when (stmt) {
                is BpfStmt.VarDecl -> {
                    if (stmt.variable.type is BpfStruct) {
                        accumulator((stmt.variable.type as BpfStruct).sizeBytes)
                    }
                }
                is BpfStmt.If -> {
                    collectStackUsage(stmt.then, accumulator)
                    stmt.elseIfs.forEach { collectStackUsage(it.second, accumulator) }
                    stmt.else_?.let { collectStackUsage(it, accumulator) }
                }
                is BpfStmt.IfNonNull -> {
                    collectStackUsage(stmt.body, accumulator)
                    stmt.else_?.let { collectStackUsage(it, accumulator) }
                }
                is BpfStmt.BoundedLoop -> collectStackUsage(stmt.body, accumulator)
                else -> {}
            }
        }
    }

    private fun checkUnreachableCode(stmts: List<BpfStmt>, programName: String) {
        for (i in stmts.indices) {
            if (stmts[i] is BpfStmt.Return && i < stmts.size - 1) {
                diagnostics.add(
                    Diagnostic(
                        DiagnosticLevel.ERROR, "unreachable-code",
                        "Unreachable code after return statement",
                        programName,
                    )
                )
                break
            }
            // Recurse into nested blocks
            when (val stmt = stmts[i]) {
                is BpfStmt.If -> {
                    checkUnreachableCode(stmt.then, programName)
                    stmt.elseIfs.forEach { checkUnreachableCode(it.second, programName) }
                    stmt.else_?.let { checkUnreachableCode(it, programName) }
                }
                is BpfStmt.IfNonNull -> {
                    checkUnreachableCode(stmt.body, programName)
                    stmt.else_?.let { checkUnreachableCode(it, programName) }
                }
                is BpfStmt.BoundedLoop -> checkUnreachableCode(stmt.body, programName)
                else -> {}
            }
        }
    }

    private fun checkDivisionSafety(program: ProgramDef) {
        walkExprs(program.body, program.name) { expr, progName ->
            if (expr is BpfExpr.BinaryOp && (expr.op == Op.DIV || expr.op == Op.MOD)) {
                if (expr.right !is BpfExpr.Literal) {
                    diagnostics.add(
                        Diagnostic(
                            DiagnosticLevel.WARNING, "unchecked-divisor",
                            "Division by variable without zero-check",
                            progName,
                        )
                    )
                }
            }
        }
    }

    private fun checkRawUsage(program: ProgramDef) {
        walkExprs(program.body, program.name) { expr, progName ->
            if (expr is BpfExpr.Raw) {
                diagnostics.add(
                    Diagnostic(
                        DiagnosticLevel.WARNING, "raw-expr",
                        "raw() escape hatch used. Consider type-safe alternatives: tracepointField(), kprobeParam(), deref(), histSlot(), etc.",
                        progName,
                    )
                )
            }
        }
    }

    private fun checkKernelCompatibility() {
        for (map in model.maps) {
            if (map.mapType.minKernel > model.targetKernel) {
                diagnostics.add(
                    Diagnostic(
                        DiagnosticLevel.ERROR, "kernel-version",
                        "Map '${map.name}' uses ${map.mapType.name} which requires kernel ${map.mapType.minKernel}+, but target is ${model.targetKernel}",
                        null,
                    )
                )
            }
        }
        for (prog in model.programs) {
            if (prog.type.minKernel > model.targetKernel) {
                diagnostics.add(
                    Diagnostic(
                        DiagnosticLevel.ERROR, "kernel-version",
                        "Program '${prog.name}' uses ${prog.type::class.simpleName} which requires kernel ${prog.type.minKernel}+, but target is ${model.targetKernel}",
                        prog.name,
                    )
                )
            }
        }
    }

    private fun checkMapAntiPatterns() {
        for (map in model.maps) {
            if (map.mapType == MapType.HASH && map.maxEntries > 50000) {
                diagnostics.add(
                    Diagnostic(
                        DiagnosticLevel.WARNING, "prefer-lru-hash",
                        "Map '${map.name}' uses HASH with ${map.maxEntries} entries. Consider LRU_HASH for auto-eviction.",
                        null,
                    )
                )
            }
        }
    }

    private fun walkExprs(stmts: List<BpfStmt>, programName: String, visitor: (BpfExpr, String) -> Unit) {
        for (stmt in stmts) {
            when (stmt) {
                is BpfStmt.VarDecl -> walkExpr(stmt.init, programName, visitor)
                is BpfStmt.Assign -> {
                    walkExpr(stmt.target, programName, visitor)
                    walkExpr(stmt.value, programName, visitor)
                }
                is BpfStmt.If -> {
                    walkExpr(stmt.cond, programName, visitor)
                    walkExprs(stmt.then, programName, visitor)
                    stmt.elseIfs.forEach { (cond, body) ->
                        walkExpr(cond, programName, visitor)
                        walkExprs(body, programName, visitor)
                    }
                    stmt.else_?.let { walkExprs(it, programName, visitor) }
                }
                is BpfStmt.IfNonNull -> {
                    walkExpr(stmt.expr, programName, visitor)
                    walkExprs(stmt.body, programName, visitor)
                    stmt.else_?.let { walkExprs(it, programName, visitor) }
                }
                is BpfStmt.BoundedLoop -> {
                    walkExpr(stmt.count, programName, visitor)
                    walkExprs(stmt.body, programName, visitor)
                }
                is BpfStmt.Return -> walkExpr(stmt.value, programName, visitor)
                is BpfStmt.AtomicOp -> {
                    walkExpr(stmt.target, programName, visitor)
                    walkExpr(stmt.operand, programName, visitor)
                }
                is BpfStmt.ExprStmt -> walkExpr(stmt.expr, programName, visitor)
                is BpfStmt.MapDelete -> walkExpr(stmt.key, programName, visitor)
            }
        }
    }

    private fun walkExpr(expr: BpfExpr, programName: String, visitor: (BpfExpr, String) -> Unit) {
        visitor(expr, programName)
        when (expr) {
            is BpfExpr.BinaryOp -> {
                walkExpr(expr.left, programName, visitor)
                walkExpr(expr.right, programName, visitor)
            }
            is BpfExpr.UnaryOp -> walkExpr(expr.operand, programName, visitor)
            is BpfExpr.FieldAccess -> walkExpr(expr.base, programName, visitor)
            is BpfExpr.ArrayIndex -> {
                walkExpr(expr.base, programName, visitor)
                walkExpr(expr.index, programName, visitor)
            }
            is BpfExpr.HelperCall -> expr.args.forEach { walkExpr(it, programName, visitor) }
            is BpfExpr.MapLookup -> walkExpr(expr.key, programName, visitor)
            is BpfExpr.MapUpdate -> {
                walkExpr(expr.key, programName, visitor)
                walkExpr(expr.value, programName, visitor)
            }
            is BpfExpr.Cast -> walkExpr(expr.expr, programName, visitor)
            is BpfExpr.Deref -> walkExpr(expr.operand, programName, visitor)
            is BpfExpr.HistSlot -> walkExpr(expr.value, programName, visitor)
            is BpfExpr.Ternary -> {
                walkExpr(expr.cond, programName, visitor)
                walkExpr(expr.then, programName, visitor)
                walkExpr(expr.else_, programName, visitor)
            }
            is BpfExpr.StructArraySet -> {
                walkExpr(expr.structVar, programName, visitor)
                walkExpr(expr.index, programName, visitor)
                walkExpr(expr.value, programName, visitor)
            }
            is BpfExpr.CTypeCast -> walkExpr(expr.operand, programName, visitor)
            is BpfExpr.Literal, is BpfExpr.VarRef, is BpfExpr.Raw,
            is BpfExpr.TracepointField, is BpfExpr.KprobeParam, is BpfExpr.RawTpArg -> {}
        }
    }
}
