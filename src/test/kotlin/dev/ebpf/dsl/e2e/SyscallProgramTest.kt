package dev.ebpf.dsl.e2e

import dev.ebpf.dsl.api.*
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test

class SyscallProgramTest {
    object SyscallKey : BpfStruct("syscall_key") {
        val cgroupId by u64()
        val syscallNr by u32()
        val pad by u32()  // padding
    }
    object SyscallStats : BpfStruct("syscall_stats") {
        val count by u64()
        val errorCount by u64()
        val latencySumNs by u64()
        val latencySlots by array(BpfScalar.U64, 27)
    }

    private fun buildSyscallProgram() = ebpf("syscall") {
        license("GPL")
        val syscallStatsMap by lruHashMap(SyscallKey, SyscallStats, maxEntries = 10240, mapName = "syscall_stats")

        rawTracepoint("sys_enter") {
            val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
            val ts = declareVar("ts", ktimeGetNs())
            returnValue(literal(0, BpfScalar.S32))
        }

        rawTracepoint("sys_exit") {
            val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            returnValue(literal(0, BpfScalar.S32))
        }
    }

    @Test
    fun `syscall program validates`() {
        assertThat(buildSyscallProgram().validate().errors).isEmpty()
    }

    @Test
    fun `generated C has composite key struct`() {
        val c = buildSyscallProgram().generateC()
        assertThat(c).contains("struct syscall_key")
        assertThat(c).contains("__u64 cgroup_id;")
        assertThat(c).contains("__u32 syscall_nr;")
        assertThat(c).contains("__u32 pad;")
    }

    @Test
    fun `generated C uses raw_tracepoint`() {
        val c = buildSyscallProgram().generateC()
        assertThat(c).contains("SEC(\"raw_tp/sys_enter\")")
        assertThat(c).contains("SEC(\"raw_tp/sys_exit\")")
    }

    @Test
    fun `syscall key struct has correct size`() {
        assertThat(SyscallKey.sizeBytes).isEqualTo(16) // 8 + 4 + 4
    }

    @Test
    fun `syscall stats has correct size`() {
        assertThat(SyscallStats.sizeBytes).isEqualTo(240) // 8 + 8 + 8 + 27*8
    }

    @Test
    fun `generated Kotlin has SyscallStats layout`() {
        val kt = buildSyscallProgram().generateKotlin("com.example.gen")
        assertThat(kt).contains("object SyscallStatsLayout")
        assertThat(kt).contains("const val SIZE = 240")
    }
}
