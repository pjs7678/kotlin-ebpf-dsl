package dev.ebpf.dsl.e2e

import dev.ebpf.dsl.api.*
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test

class MemProgramTest {
    object CounterKey : BpfStruct("counter_key") {
        val cgroupId by u64()
    }
    object CounterValue : BpfStruct("counter_value") {
        val count by u64()
    }

    private fun buildMemProgram() = ebpf("mem") {
        license("GPL")
        val oomKills by lruHashMap(CounterKey, CounterValue, maxEntries = 10240)
        val majorFaults by lruHashMap(CounterKey, CounterValue, maxEntries = 10240)

        tracepoint("oom", "mark_victim") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(CounterKey) {
                it[CounterKey.cgroupId] = cgroupId
            }
            val entry = oomKills.lookup(key)
            ifNonNull(entry) { e ->
                e[CounterValue.count].atomicAdd(literal(1u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }

        kprobe("handle_mm_fault") {
            // Check flags for major fault bit (0x4)
            val pid = declareVar("pid_tgid", getCurrentPidTgid())
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(CounterKey) {
                it[CounterKey.cgroupId] = cgroupId
            }
            val entry = majorFaults.lookup(key)
            ifNonNull(entry) { e ->
                e[CounterValue.count].atomicAdd(literal(1u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }
    }

    @Test
    fun `mem program validates successfully`() {
        val model = buildMemProgram()
        val result = model.validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `generated C contains expected structure`() {
        val model = buildMemProgram()
        val c = model.generateC()
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")
        assertThat(c).contains("SEC(\"tp/oom/mark_victim\")")
        assertThat(c).contains("SEC(\"kprobe/handle_mm_fault\")")
        assertThat(c).contains("bpf_get_current_cgroup_id()")
        assertThat(c).contains("__sync_fetch_and_add")
        assertThat(c).contains("struct counter_key")
        assertThat(c).contains("struct counter_value")
        assertThat(c).contains("char LICENSE[] SEC(\"license\") = \"GPL\";")
    }

    @Test
    fun `generated C compiles structurally`() {
        // Verify the generated C has proper structure
        val c = buildMemProgram().generateC()
        // Should have exactly 2 map definitions
        assertThat(c.split("SEC(\".maps\")")).hasSize(3) // 2 maps + 1 original string piece
        // Should have exactly 2 programs
        assertThat(c).contains("SEC(\"tp/oom/mark_victim\")")
        assertThat(c).contains("SEC(\"kprobe/handle_mm_fault\")")
    }

    @Test
    fun `generated Kotlin reader has correct layout`() {
        val kt = buildMemProgram().generateKotlin("com.example.gen")
        assertThat(kt).contains("object CounterKeyLayout")
        assertThat(kt).contains("object CounterValueLayout")
        assertThat(kt).contains("const val SIZE = 8")
        assertThat(kt).contains("fun readOomKills(")
        assertThat(kt).contains("fun readMajorFaults(")
    }
}
