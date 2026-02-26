package dev.ebpf.dsl.api

import dev.ebpf.dsl.types.BpfScalar
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class TypedContextTest {

    @Test
    fun `typed tracepoint provides field access`() {
        val c = ebpf("test_typed_tp") {
            license("GPL")
            tracepoint(SchedSwitch) { ctx ->
                val pid = declareVar("pid", ctx[SchedSwitch.nextPid])
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("((struct trace_event_raw_sched_switch *)ctx)->next_pid")
        assertThat(c).contains("SEC(\"tp/sched/sched_switch\")")
    }

    @Test
    fun `typed tracepoint for inet_sock_set_state`() {
        val c = ebpf("test_inet_tp") {
            license("GPL")
            tracepoint(InetSockSetState) { ctx ->
                val newstate = declareVar("newstate", ctx[InetSockSetState.newstate])
                val sport = declareVar("sport", ctx[InetSockSetState.sport])
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("((struct trace_event_raw_inet_sock_set_state *)ctx)->newstate")
        assertThat(c).contains("((struct trace_event_raw_inet_sock_set_state *)ctx)->sport")
    }

    @Test
    fun `kprobeParam works in builder`() {
        val c = ebpf("test_kprobe_ctx") {
            license("GPL")
            kprobe("tcp_sendmsg") {
                val size = declareVar("size", kprobeParam(3, "size_t"))
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("(size_t)PT_REGS_PARM3(ctx)")
    }

    @Test
    fun `rawTpArg works in builder`() {
        val c = ebpf("test_rawtp_ctx") {
            license("GPL")
            rawTracepoint("sys_enter") {
                val syscallId = declareVar("syscall_id", rawTpArg(1, "__u64"))
                returnValue(literal(0, BpfScalar.S32))
            }
        }.generateC()
        assertThat(c).contains("(__u64)ctx->args[1]")
    }
}
