package dev.ebpf.dsl.ir

import dev.ebpf.dsl.types.BpfScalar
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AstTest {
    @Test
    fun `literal expression carries type`() {
        val lit = BpfExpr.Literal(42, BpfScalar.U64)
        assertThat(lit.type).isEqualTo(BpfScalar.U64)
        assertThat(lit.value).isEqualTo(42L)
    }

    @Test
    fun `binary op preserves result type`() {
        val left = BpfExpr.Literal(1, BpfScalar.U32)
        val right = BpfExpr.Literal(2, BpfScalar.U32)
        val add = BpfExpr.BinaryOp(Op.ADD, left, right, BpfScalar.U32)
        assertThat(add.type).isEqualTo(BpfScalar.U32)
        assertThat(add.op).isEqualTo(Op.ADD)
    }

    @Test
    fun `var ref tracks variable`() {
        val v = Variable("pid", BpfScalar.U64, mutable = false)
        val ref = BpfExpr.VarRef(v)
        assertThat(ref.type).isEqualTo(BpfScalar.U64)
        assertThat(ref.variable.name).isEqualTo("pid")
    }

    @Test
    fun `cast changes type`() {
        val expr = BpfExpr.Literal(256, BpfScalar.U64)
        val cast = BpfExpr.Cast(expr, BpfScalar.U32)
        assertThat(cast.type).isEqualTo(BpfScalar.U32)
    }

    @Test
    fun `if statement has then and optional else`() {
        val cond = BpfExpr.Literal(1, BpfScalar.Bool)
        val thenBlock = listOf(BpfStmt.Return(BpfExpr.Literal(0, BpfScalar.S32)))
        val stmt = BpfStmt.If(cond, thenBlock, emptyList(), null)
        assertThat(stmt.then).hasSize(1)
        assertThat(stmt.else_).isNull()
    }

    @Test
    fun `ifNonNull has variable and body`() {
        val lookupExpr = BpfExpr.MapLookup("mymap", BpfExpr.Literal(1, BpfScalar.U64), BpfScalar.U64)
        val v = Variable("entry", BpfScalar.U64, mutable = false)
        val stmt = BpfStmt.IfNonNull(lookupExpr, v, listOf())
        assertThat(stmt.variable.name).isEqualTo("entry")
    }

    @Test
    fun `bounded loop has count and iter var`() {
        val count = BpfExpr.Literal(27, BpfScalar.U32)
        val iterVar = Variable("i", BpfScalar.U32, mutable = false)
        val loop = BpfStmt.BoundedLoop(count, iterVar, listOf())
        assertThat(loop.iterVar.name).isEqualTo("i")
    }

    @Test
    fun `helper call has id name and args`() {
        val call = BpfExpr.HelperCall(80, "bpf_get_current_cgroup_id", emptyList(), BpfScalar.U64)
        assertThat(call.helperName).isEqualTo("bpf_get_current_cgroup_id")
        assertThat(call.type).isEqualTo(BpfScalar.U64)
    }

    @Test
    fun `raw expression embeds C code`() {
        val raw = BpfExpr.Raw("bpf_some_helper(ctx)", BpfScalar.U64)
        assertThat(raw.cCode).isEqualTo("bpf_some_helper(ctx)")
    }

    @Test
    fun `atomic op has target and operand`() {
        val target = BpfExpr.VarRef(Variable("count", BpfScalar.U64, true))
        val operand = BpfExpr.Literal(1, BpfScalar.U64)
        val atomic = BpfStmt.AtomicOp(AtomicOpKind.ADD, target, operand)
        assertThat(atomic.op).isEqualTo(AtomicOpKind.ADD)
    }
}
