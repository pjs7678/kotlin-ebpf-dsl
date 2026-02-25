package dev.ebpf.dsl.codegen

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KotlinCodeGeneratorTest {
    object CK : BpfStruct("counter_key") { val cgroupId by u64() }
    object CV : BpfStruct("counter_value") { val count by u64() }

    @Test
    fun `generates layout objects with correct offsets`() {
        val model = ebpf("mem") {
            license("GPL")
            val oomKills by lruHashMap(CK, CV, maxEntries = 10240)
            tracepoint("oom", "mark_victim") { returnValue(literal(0, BpfScalar.S32)) }
        }
        val code = KotlinCodeGenerator(model, "com.example.gen").generate()
        assertThat(code).contains("object CounterKeyLayout")
        assertThat(code).contains("const val SIZE = 8")
        assertThat(code).contains("const val CGROUP_ID_OFFSET = 0")
    }

    @Test
    fun `generates decode methods`() {
        val model = ebpf("mem") {
            license("GPL")
            val oomKills by lruHashMap(CK, CV, maxEntries = 10240)
            tracepoint("oom", "mark_victim") { returnValue(literal(0, BpfScalar.S32)) }
        }
        val code = KotlinCodeGenerator(model, "com.example.gen").generate()
        assertThat(code).contains("fun decodeCount(bytes: ByteArray): Long")
        assertThat(code).contains("LITTLE_ENDIAN")
    }

    @Test
    fun `generates encode methods for key structs`() {
        val model = ebpf("mem") {
            license("GPL")
            val oomKills by lruHashMap(CK, CV, maxEntries = 10240)
            tracepoint("oom", "mark_victim") { returnValue(literal(0, BpfScalar.S32)) }
        }
        val code = KotlinCodeGenerator(model, "com.example.gen").generate()
        assertThat(code).contains("fun encode(")
    }

    @Test
    fun `generates reader method per map`() {
        val model = ebpf("mem") {
            license("GPL")
            val oomKills by lruHashMap(CK, CV, maxEntries = 10240)
            val majorFaults by lruHashMap(CK, CV, maxEntries = 10240)
            tracepoint("oom", "mark_victim") { returnValue(literal(0, BpfScalar.S32)) }
        }
        val code = KotlinCodeGenerator(model, "com.example.gen").generate()
        assertThat(code).contains("fun readOomKills(")
        assertThat(code).contains("fun readMajorFaults(")
    }

    @Test
    fun `generates data class for entries`() {
        val model = ebpf("mem") {
            license("GPL")
            val oomKills by lruHashMap(CK, CV, maxEntries = 10240)
            tracepoint("oom", "mark_victim") { returnValue(literal(0, BpfScalar.S32)) }
        }
        val code = KotlinCodeGenerator(model, "com.example.gen").generate()
        assertThat(code).contains("data class")
    }

    @Test
    fun `generates correct package`() {
        val model = ebpf("mem") {
            license("GPL")
            val m by lruHashMap(CK, CV, maxEntries = 100)
            tracepoint("oom", "mark_victim") { returnValue(literal(0, BpfScalar.S32)) }
        }
        val code = KotlinCodeGenerator(model, "com.example.gen").generate()
        assertThat(code).contains("package com.example.gen")
    }

    @Test
    fun `skips ringbuf maps in reader`() {
        val model = ebpf("test") {
            license("GPL")
            val events by ringBuf(maxEntries = 256 * 1024)
            tracepoint("sched", "sched_switch") { returnValue(literal(0, BpfScalar.S32)) }
        }
        val code = KotlinCodeGenerator(model, "com.example.gen").generate()
        assertThat(code).doesNotContain("readEvents")
    }
}
