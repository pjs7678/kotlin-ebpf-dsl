package dev.ebpf.dsl.ir

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class NewExprTest {

    @Test
    fun `Deref renders as star prefix`() {
        val c = ebpf("test_deref") {
            license("GPL")
            kprobe("test_fn") {
                val v = declareVar("v", literal(42u, BpfScalar.U64))
                val d = declareVar("d", deref(v))
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("__u64 d = *v;")
    }

    @Test
    fun `TracepointField renders struct cast field access`() {
        val c = ebpf("test_tp_field") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val pid = declareVar(
                    "pid",
                    tracepointField("trace_event_raw_sched_switch", "next_pid", BpfScalar.U32)
                )
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("((struct trace_event_raw_sched_switch *)ctx)->next_pid")
    }

    @Test
    fun `KprobeParam renders PT_REGS macro`() {
        val c = ebpf("test_kprobe_param") {
            license("GPL")
            kprobe("some_fn") {
                val arg = declareVar("arg", kprobeParam(1, "unsigned long"))
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("(unsigned long)PT_REGS_PARM1(ctx)")
    }

    @Test
    fun `RawTpArg renders ctx args access`() {
        val c = ebpf("test_rawtp_arg") {
            license("GPL")
            rawTracepoint("sys_enter") {
                val arg = declareVar("arg", rawTpArg(0, "__u64"))
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("(__u64)ctx->args[0]")
    }

    @Test
    fun `HistSlot renders log2l ternary`() {
        val c = ebpf("test_histslot") {
            license("GPL")
            kprobe("test_fn") {
                val ns = declareVar("ns", literal(1000u, BpfScalar.U64))
                val slot = declareVar("slot", histSlot(ns, 27))
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("log2l(ns) >= 27 ? 26 : log2l(ns)")
    }

    @Test
    fun `Ternary renders conditional expression`() {
        val c = ebpf("test_ternary") {
            license("GPL")
            kprobe("test_fn") {
                val a = declareVar("a", literal(10u, BpfScalar.U32))
                val b = declareVar("b", literal(20u, BpfScalar.U32))
                val r = declareVar("r", ternary(a gt b, a, b))
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("((a > b)) ? a : b")
    }

    object TestStruct : BpfStruct("test_struct") {
        val slots by array(BpfScalar.U64, 27)
    }

    @Test
    fun `StructArraySet renders comma expression`() {
        val c = ebpf("test_structarrayset") {
            license("GPL")
            val m by lruHashMap(TestStruct, TestStruct, 100)
            kprobe("test_fn") {
                val v = stackVar(TestStruct) { }
                val idx = declareVar("idx", literal(5u, BpfScalar.U32))
                val result = declareVar("_set", structArraySet(v, TestStruct.slots, idx, literal(1uL, BpfScalar.U64)))
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("(var_0.slots[idx] = 1ULL, (__s32)0)")
    }

    @Test
    fun `CTypeCast renders named cast`() {
        val c = ebpf("test_ctypecast") {
            license("GPL")
            kprobe("test_fn") {
                val v = declareVar("v", literal(42u, BpfScalar.U32))
                val wide = declareVar("wide", cTypeCast("__u64", v, BpfScalar.U64))
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("(__u64)v")
    }
}
