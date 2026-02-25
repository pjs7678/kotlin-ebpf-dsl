package dev.ebpf.dsl.codegen

import dev.ebpf.dsl.api.*
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class PreambleTest {

    object K : BpfStruct("k") { val id by u64() }
    object V : BpfStruct("v") { val count by u64() }

    @Test
    fun `preamble is emitted after includes and before structs`() {
        val program = ebpf("preamble_test") {
            license("GPL")
            preamble("""
static __always_inline __u32 log2l(__u64 v) {
    __u32 r = 0;
    while (v > 1) { v >>= 1; r++; }
    return r;
}
            """.trimIndent())
            val m by lruHashMap(K, V, maxEntries = 1024, mapName = "m")
            tracepoint("sched", "sched_switch") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        val includePos = c.indexOf("#include")
        val preamblePos = c.indexOf("log2l")
        val structPos = c.indexOf("struct k {")
        assertThat(preamblePos).isGreaterThan(includePos)
        assertThat(preamblePos).isLessThan(structPos)
    }

    @Test
    fun `no preamble when not set`() {
        val program = ebpf("no_preamble") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }

        val c = program.generateC()
        // Just verify it doesn't crash and generates normally
        assertThat(c).contains("SEC(\"tp/sched/sched_switch\")")
    }
}
