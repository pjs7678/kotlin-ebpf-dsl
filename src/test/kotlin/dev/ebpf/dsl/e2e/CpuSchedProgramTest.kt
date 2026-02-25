package dev.ebpf.dsl.e2e

import dev.ebpf.dsl.api.*
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test

class CpuSchedProgramTest {
    object HistKey : BpfStruct("hist_key") {
        val cgroupId by u64()
    }
    object HistValue : BpfStruct("hist_value") {
        val slots by array(BpfScalar.U64, 27)
        val count by u64()
        val sumNs by u64()
    }
    object CounterKey : BpfStruct("counter_key") {
        val cgroupId by u64()
    }
    object CounterValue : BpfStruct("counter_value") {
        val count by u64()
    }

    private fun buildCpuSchedProgram() = ebpf("cpu_sched") {
        license("GPL")

        // Note: wakeup_ts uses scalar key/value, but our DSL currently requires BpfStruct for hashMap.
        // For this test, use a simple struct wrapper.
        val runqLatency by lruHashMap(HistKey, HistValue, maxEntries = 10240)
        val ctxSwitches by lruHashMap(CounterKey, CounterValue, maxEntries = 10240)

        tracepoint("sched", "sched_wakeup") {
            val ts = declareVar("ts", ktimeGetNs())
            returnValue(literal(0, BpfScalar.S32))
        }

        tracepoint("sched", "sched_switch") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(CounterKey) {
                it[CounterKey.cgroupId] = cgroupId
            }
            val entry = ctxSwitches.lookup(key)
            ifNonNull(entry) { e ->
                e[CounterValue.count].atomicAdd(literal(1u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }
    }

    @Test
    fun `cpu sched validates successfully`() {
        val result = buildCpuSchedProgram().validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `generated C has histogram struct with array`() {
        val c = buildCpuSchedProgram().generateC()
        assertThat(c).contains("__u64 slots[27]")
        assertThat(c).contains("struct hist_value")
        assertThat(c).contains("struct hist_key")
    }

    @Test
    fun `generated C has multiple tracepoints`() {
        val c = buildCpuSchedProgram().generateC()
        assertThat(c).contains("SEC(\"tp/sched/sched_wakeup\")")
        assertThat(c).contains("SEC(\"tp/sched/sched_switch\")")
    }

    @Test
    fun `generated Kotlin handles histogram struct`() {
        val kt = buildCpuSchedProgram().generateKotlin("com.example.gen")
        assertThat(kt).contains("object HistValueLayout")
        assertThat(kt).contains("SLOTS_OFFSET")
        assertThat(kt).contains("const val SIZE = 232") // 27*8 + 8 + 8
    }
}
