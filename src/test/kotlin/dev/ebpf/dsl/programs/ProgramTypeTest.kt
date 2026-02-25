package dev.ebpf.dsl.programs

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ProgramTypeTest {

    @Test
    fun `tracepoint section prefix`() {
        val tp = ProgramType.Tracepoint("oom", "mark_victim")
        assertThat(tp.sectionPrefix).isEqualTo("tp/oom/mark_victim")
    }

    @Test
    fun `raw tracepoint section prefix`() {
        val rtp = ProgramType.RawTracepoint("sched_switch")
        assertThat(rtp.sectionPrefix).isEqualTo("raw_tp/sched_switch")
    }

    @Test
    fun `kprobe section prefix`() {
        val kp = ProgramType.Kprobe("tcp_sendmsg")
        assertThat(kp.sectionPrefix).isEqualTo("kprobe/tcp_sendmsg")
    }

    @Test
    fun `kretprobe section prefix`() {
        val krp = ProgramType.Kretprobe("tcp_sendmsg")
        assertThat(krp.sectionPrefix).isEqualTo("kretprobe/tcp_sendmsg")
    }

    @Test
    fun `fentry section prefix`() {
        val fe = ProgramType.Fentry("tcp_sendmsg")
        assertThat(fe.sectionPrefix).isEqualTo("fentry/tcp_sendmsg")
    }

    @Test
    fun `fexit section prefix`() {
        val fx = ProgramType.Fexit("tcp_sendmsg")
        assertThat(fx.sectionPrefix).isEqualTo("fexit/tcp_sendmsg")
    }

    @Test
    fun `xdp section prefix`() {
        assertThat(ProgramType.Xdp.sectionPrefix).isEqualTo("xdp")
    }

    @Test
    fun `tc classifier section prefix`() {
        assertThat(ProgramType.TcClassifier.sectionPrefix).isEqualTo("tc")
    }

    @Test
    fun `cgroup skb section prefix`() {
        val cs = ProgramType.CgroupSkb("ingress")
        assertThat(cs.sectionPrefix).isEqualTo("cgroup_skb/ingress")
    }

    @Test
    fun `lsm section prefix`() {
        val lsm = ProgramType.Lsm("bprm_check_security")
        assertThat(lsm.sectionPrefix).isEqualTo("lsm/bprm_check_security")
    }

    @Test
    fun `sockops section prefix`() {
        assertThat(ProgramType.SockOps.sectionPrefix).isEqualTo("sockops")
    }

    @Test
    fun `socket filter section prefix`() {
        assertThat(ProgramType.SocketFilter.sectionPrefix).isEqualTo("socket")
    }

    @Test
    fun `iter section prefix`() {
        val iter = ProgramType.Iter("task")
        assertThat(iter.sectionPrefix).isEqualTo("iter/task")
    }

    @Test
    fun `sched classifier section prefix`() {
        val sc = ProgramType.SchedClassifier("sched_ext_ops")
        assertThat(sc.sectionPrefix).isEqualTo("struct_ops/sched_ext_ops")
    }

    @Test
    fun `tracepoint data class equality`() {
        val tp1 = ProgramType.Tracepoint("oom", "mark_victim")
        val tp2 = ProgramType.Tracepoint("oom", "mark_victim")
        assertThat(tp1).isEqualTo(tp2)
    }

    @Test
    fun `tracepoint data class inequality`() {
        val tp1 = ProgramType.Tracepoint("oom", "mark_victim")
        val tp2 = ProgramType.Tracepoint("sched", "switch")
        assertThat(tp1).isNotEqualTo(tp2)
    }
}
